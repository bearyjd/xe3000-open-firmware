"""L1 wired into analyze: denied files are never sent and are listed in the manifest."""
import json

import pytest

from fakes import FakeClient, response
from recon import cli
from test_analyze import always_good, read_jsonl


def go(root, client, *extra, run_id="r1"):
    return cli.main(["--root", str(root), "--run-id", run_id, "--no-canary", "--max-usd", "5", *extra],
                    client_factory=lambda: client)


def sent_text(client):
    return json.dumps([c[2] for c in client.create_calls] + [c[2] for c in client.count_calls])


def mixed_tree(root, stamp):
    red = root / "harvest" / "redacted"
    (red / "etc" / "init.d").mkdir(parents=True)
    (red / "etc" / "config").mkdir(parents=True)
    (red / "etc" / "init.d" / "modem").write_text("start() {\n  echo modem-start-line\n}\n")
    (red / "etc" / "config" / "network").write_text("config interface wan\n  option proto dhcp-NETWORK-MARK\n")
    (red / "ps").write_text("PID COMMAND\n 1 init PS-MARK\n")
    (red / "logread").write_text("daemon.info LOGREAD-MARK\n")
    stamp(root)


def test_only_allowlisted_files_are_sent_and_the_rest_listed_as_denied(root, stamp):
    mixed_tree(root, stamp)
    client = FakeClient(script=always_good)
    assert go(root, client) == 0
    sent = sent_text(client)
    assert "modem-start-line" in sent
    for mark in ("NETWORK-MARK", "PS-MARK", "LOGREAD-MARK"):
        assert mark not in sent
    manifest = json.loads((root / "findings" / "raw" / "r1" / "manifest.json").read_text())
    assert set(manifest["denied"]) == {"redacted/etc/config/network", "redacted/ps", "redacted/logread"}
    assert manifest["allow_extra"] == []


def test_allow_extra_is_an_explicit_logged_opt_in(root, stamp, capsys):
    mixed_tree(root, stamp)
    client = FakeClient(script=always_good)
    assert go(root, client, "--allow-extra", "etc/config/network") == 0
    sent = sent_text(client)
    assert "NETWORK-MARK" in sent and "PS-MARK" not in sent
    out = capsys.readouterr().out
    assert "allow-extra" in out.lower() and "etc/config/network" in out
    manifest = json.loads((root / "findings" / "raw" / "r1" / "manifest.json").read_text())
    assert manifest["allow_extra"] == ["etc/config/network"]
    assert set(manifest["denied"]) == {"redacted/ps", "redacted/logread"}


def test_allow_extra_cannot_override_name_exclusions(root, stamp):
    mixed_tree(root, stamp)
    (root / "harvest" / "redacted" / "etc" / "shadow").write_text("root:SHADOW-MARK:0\n")
    stamp(root)
    client = FakeClient(script=always_good)
    assert go(root, client, "--allow-extra", "**") == 0
    assert "SHADOW-MARK" not in sent_text(client)


def test_nothing_allowed_means_nothing_sent(root, stamp, capsys):
    red = root / "harvest" / "redacted"
    red.mkdir(parents=True, exist_ok=True)
    (red / "ps").write_text("PS-MARK\n")
    stamp(root)
    client = FakeClient(script=always_good)
    assert go(root, client) == 0
    assert client.create_calls == [] and client.count_calls == []
    assert "no allowlisted" in capsys.readouterr().out.lower()


def test_missing_allowlist_file_refuses(root, stamp):
    mixed_tree(root, stamp)
    (root / "containers" / "recon-allowlist.txt").unlink()
    client = FakeClient(script=always_good)
    assert go(root, client) == 2 and client.count_calls == []


def test_ground_truth_comes_only_from_allowed_files(root, stamp):
    mixed_tree(root, stamp)
    (root / "harvest" / "redacted" / "etc" / "config" / "network").write_text("AT+DENIED-ONLY\n")
    stamp(root)
    client = FakeClient(script=lambda i, m: response([{"claim": "Uses AT+DENIED", "category": "other",
        "confidence": "low", "evidence": [{"file": "redacted/etc/init.d/modem", "line": 2,
                                           "excerpt": "echo modem-start-line"}]}]))
    assert go(root, client, "--allow-extra", "nothing/matches") == 0
    row = read_jsonl(root / "findings" / "raw" / "r1" / "findings.jsonl")[0]
    assert row["ungrounded"]
