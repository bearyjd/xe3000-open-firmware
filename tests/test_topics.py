"""Phase 2 topic runs: per-topic prompts, allowlist for unpacked rootfs, --topic selector."""
import json

import pytest

from conftest import REPO, Lazy
from fakes import FakeClient
from recon import cli
from test_analyze import always_good

prompts = Lazy("recon.prompts")
allowlist = Lazy("recon.allowlist")

TOPICS = {"at-commands", "gl-rpc-map", "modem-boot-flow", "fan-led-mcu-battery", "wifi-driver"}
U = "unpacked/stock-4.8.3/rootfs/"


def test_five_topics_each_with_prompt_and_globs():
    assert set(prompts.TOPICS) == TOPICS
    for name in TOPICS:
        blocks = prompts.system_blocks("rootfs-script", name)
        assert blocks[0] == prompts.SYSTEM_SHARED and prompts.TOPICS[name].focus in blocks[1]
        assert prompts.TOPICS[name].globs


def test_no_topic_keeps_phase1_prompts():
    assert prompts.system_blocks("init-script") == prompts.system_blocks("init-script", None)


def test_prompt_hash_depends_on_topic():
    hashes = {prompts.prompt_hash("rootfs-script", t) for t in [None, *TOPICS]}
    assert len(hashes) == len(TOPICS) + 1


def test_unknown_topic_raises():
    with pytest.raises(ValueError, match="unknown topic"):
        prompts.system_blocks("rootfs-script", "nope")


def test_rpc_topic_covers_network_access_control_methods():
    focus = prompts.TOPICS["gl-rpc-map"].focus.lower()
    for word in ("network access control", "client", "block", "schedule"):
        assert word in focus


def test_prompts_forbid_inventing_names_and_long_code():
    for name in TOPICS:
        focus = prompts.TOPICS[name].focus.lower()
        assert "literally" in focus or "only" in focus


ALLOWED = ["etc/init.d/gl_fan", "etc/hotplug.d/iface/10-modem", "usr/lib/lua/oui/rpc.lua",
           "usr/lib/oui-httpd/rpc/fan", "usr/sbin/modem_check.sh", "usr/share/acl.d/gl-fan.json",
           "usr/share/rpcd/acl.d/x.json", "etc/config/glfan", "etc/config/gl_led", "etc/config/mcu",
           "etc/config/glmodem", "etc/config/parental_control", "etc/config/gl_block",
           "etc/config/gl-black_white_list", "etc/config/gl_timer", "etc/modules.d/30-wifi", "lib/wifi/mt76.sh"]
DENIED = ["etc/shadow", "etc/config/wireless", "etc/config/network", "etc/config/rpcd", "etc/config/gl-cloud",
          "etc/config/ovpnclient", "etc/config/wireguard_server", "etc/config/tailscale", "etc/dropbear/x",
          "etc/AdGuardHome/AdGuardHome.yaml", "www/js/app.js", "etc/config/samba4"]


@pytest.mark.parametrize("rel", ALLOWED)
def test_unpacked_rootfs_paths_are_allowlisted(rel):
    assert allowlist.is_allowed(U + rel, allowlist.load_patterns(REPO / "containers" / "recon-allowlist.txt"))


@pytest.mark.parametrize("rel", DENIED)
def test_secret_bearing_unpacked_paths_stay_denied(rel):
    assert not allowlist.is_allowed(U + rel, allowlist.load_patterns(REPO / "containers" / "recon-allowlist.txt"))


def test_every_topic_glob_is_covered_by_the_allowlist_or_narrower():
    patterns = allowlist.load_patterns(REPO / "containers" / "recon-allowlist.txt")
    probe = {"at-commands": "etc/init.d/gl_modem", "gl-rpc-map": "usr/lib/oui-httpd/rpc/fan",
             "modem-boot-flow": "etc/hotplug.d/iface/10-modem", "fan-led-mcu-battery": "etc/config/glfan",
             "wifi-driver": "lib/wifi/mt76.sh"}
    for topic, rel in probe.items():
        assert allowlist.is_allowed(U + rel, prompts.TOPICS[topic].globs), topic
        assert allowlist.is_allowed(U + rel, patterns), topic


def _tree(root, stamp):
    base = root / "unpacked" / "stock" / "rootfs"
    for rel, text in {"etc/init.d/gl_modem": "start() {\n  echo INITD-MARK-LINE\n}\n",
                      "usr/lib/oui-httpd/rpc/fan": "M.set_test = function(p)\n  return RPC-MARK-LINE\nend\n",
                      "etc/config/wireless": "option key WIFI-MARK\n"}.items():
        (base / rel).parent.mkdir(parents=True, exist_ok=True)
        (base / rel).write_text(text)
    stamp(root)


def go(root, client, *extra):
    return cli.main(["--root", str(root), "--run-id", "t1", "--no-canary", "--max-usd", "5", *extra],
                    client_factory=lambda: client)


def test_topic_flag_narrows_inputs_and_sets_prompt_and_manifest(root, stamp):
    _tree(root, stamp)
    client = FakeClient(script=always_good)
    assert go(root, client, "--topic", "gl-rpc-map") == 0
    sent = json.dumps([c[2] for c in client.create_calls])
    assert "RPC-MARK-LINE" in sent and "INITD-MARK-LINE" not in sent and "WIFI-MARK" not in sent
    assert all(prompts.TOPICS["gl-rpc-map"].focus in c[1][1] for c in client.create_calls)
    manifest = json.loads((root / "findings/raw/t1/manifest.json").read_text())
    assert manifest["topic"] == "gl-rpc-map"
    reasons = {s["name"]: s["reason"] for s in manifest["skipped"]}
    assert reasons["unpacked/stock/rootfs/etc/init.d/gl_modem"] == "off-topic"
    assert "unpacked/stock/rootfs/etc/config/wireless" in manifest["denied"]


def test_without_topic_both_allowlisted_files_are_sent(root, stamp):
    _tree(root, stamp)
    client = FakeClient(script=always_good)
    assert go(root, client) == 0
    sent = json.dumps([c[2] for c in client.create_calls])
    assert "RPC-MARK-LINE" in sent and "INITD-MARK-LINE" in sent
    assert json.loads((root / "findings/raw/t1/manifest.json").read_text())["topic"] is None


def test_unknown_topic_is_rejected_by_the_parser(root, stamp, capsys):
    _tree(root, stamp)
    with pytest.raises(SystemExit):
        go(root, FakeClient(), "--topic", "nope")
    assert "invalid choice" in capsys.readouterr().err


def test_cache_key_differs_between_topics(root, stamp):
    _tree(root, stamp)
    assert go(root, FakeClient(script=always_good), "--topic", "gl-rpc-map") == 0
    c2 = FakeClient(script=always_good)
    assert cli.main(["--root", str(root), "--run-id", "t2", "--no-canary", "--max-usd", "5"],
                    client_factory=lambda: c2) == 0
    # same rpc file, different prompt: the topic response must not be served from cache
    assert any("RPC-MARK-LINE" in json.dumps(c[2]) for c in c2.create_calls)
