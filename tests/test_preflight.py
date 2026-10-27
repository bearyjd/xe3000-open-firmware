import json
import os
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

from conftest import CFG, GITLEAKS_TOML, REPO
from recon import paths, preflight, redact
from secrets_gen import build_samples

SAMPLES = build_samples()
IMAGE_FILE = REPO / "containers" / "gitleaks.image"


def test_tree_hash_changes_with_content_and_name(root, fixture_tree):
    dirs = [root / "harvest" / "redacted", root / "unpacked"]
    h1 = preflight.tree_hash(dirs, root)
    assert h1 == preflight.tree_hash(dirs, root)
    (fixture_tree / "etc" / "config" / "network").write_text("changed\n")
    h2 = preflight.tree_hash(dirs, root)
    assert h2 != h1
    (fixture_tree / "new.txt").write_text("n\n")
    assert preflight.tree_hash(dirs, root) != h2


def test_tree_hash_refuses_raw_symlink(root, fixture_tree):
    (root / "harvest" / "raw" / "s").write_text("x")
    os.symlink(root / "harvest" / "raw" / "s", fixture_tree / "l")
    with pytest.raises(paths.PathRefused):
        preflight.tree_hash([root / "harvest" / "redacted"], root)


def test_stamp_lifecycle(root, fixture_tree):
    dirs = [root / "harvest" / "redacted", root / "unpacked"]
    assert not preflight.has_stamp(root, dirs)
    preflight.write_stamp(root, preflight.tree_hash(dirs, root))
    assert preflight.has_stamp(root, dirs)
    assert preflight.stamp_path(root, "abc").parent == root / "cache" / "preflight"
    (fixture_tree / "etc" / "config" / "network").write_text("changed\n")
    assert not preflight.has_stamp(root, dirs)


def test_pinned_image_is_digest_pinned_and_matches_containerfile():
    ref = preflight.read_image(IMAGE_FILE)
    assert "@sha256:" in ref and len(ref.split("sha256:")[1]) == 64
    containerfile = (REPO / "containers" / "recon.Containerfile").read_text()
    assert ref in containerfile


def test_podman_command_shape(tmp_path):
    cmd = preflight.build_command(tmp_path / "in", GITLEAKS_TOML, podman=["distrobox-host-exec", "podman"],
                                  image="img@sha256:" + "0" * 64, gitleaks_bin=None)
    assert cmd[:3] == ["distrobox-host-exec", "podman", "run"]
    joined = " ".join(cmd)
    assert "--redact" in cmd and "--network=none" in cmd
    assert f"{tmp_path / 'in'}:/scan:ro,z" in joined
    assert ":Z" not in joined
    assert str(tmp_path.parent) not in joined.replace(str(tmp_path), "")


def test_local_command_shape(tmp_path):
    cmd = preflight.build_command(tmp_path, GITLEAKS_TOML, podman=None, image="x", gitleaks_bin="/bin/gl")
    assert cmd[0] == "/bin/gl" and "--redact" in cmd and str(tmp_path) in cmd


def test_parse_report_keeps_only_file_line_rule():
    raw = json.dumps([{"RuleID": "r1", "StartLine": 3, "File": "/scan/etc/x", "Secret": "REDACTED",
                       "Match": "option k 'REDACTED"}])
    hits = preflight.parse_report(raw, "/scan", "redacted")
    assert hits == (preflight.Hit("redacted/etc/x", 3, "r1"),)
    assert preflight.parse_report("", "/scan", "redacted") == ()
    assert preflight.parse_report("[]\n", "/scan", "redacted") == ()
    with pytest.raises(preflight.PreflightError):
        preflight.parse_report("not json", "/scan", "redacted")


def _fake_runner(returncode, stdout="[]", stderr=""):
    def run(cmd, **kw):
        return subprocess.CompletedProcess(cmd, returncode, stdout, stderr)
    return run


def test_run_preflight_writes_stamp_on_clean(root, fixture_tree):
    res = preflight.run_preflight([root / "harvest" / "redacted"], root, config=GITLEAKS_TOML, podman=["p"],
                                  image="i@sha256:" + "0" * 64, gitleaks_bin=None, runner=_fake_runner(0))
    assert res.hits == () and res.stamp and res.stamp.exists()


def test_run_preflight_hit_no_stamp_and_no_value_in_output(root, fixture_tree, capsys):
    raw = json.dumps([{"RuleID": "r1", "StartLine": 2, "File": "/scan/etc/config/network", "Secret": "REDACTED"}])
    res = preflight.run_preflight([root / "harvest" / "redacted"], root, config=GITLEAKS_TOML, podman=["p"],
                                  image="i@sha256:" + "0" * 64, gitleaks_bin=None, runner=_fake_runner(7, raw))
    assert res.stamp is None and res.hits == (preflight.Hit("redacted/etc/config/network", 2, "r1"),)
    assert not list((root / "cache" / "preflight").glob("*.ok")) if (root / "cache" / "preflight").exists() else True


def test_run_preflight_error_exit_raises_without_leaking(root, fixture_tree):
    with pytest.raises(preflight.PreflightError) as ei:
        preflight.run_preflight([root / "harvest" / "redacted"], root, config=GITLEAKS_TOML, podman=["p"],
                                image="i@sha256:" + "0" * 64, gitleaks_bin=None,
                                runner=_fake_runner(2, "", "secret-ish stderr text"))
    assert "secret-ish" not in str(ei.value) and "2" in str(ei.value)


def test_cli_hit_prints_file_line_rule_only(root, fixture_tree, capsys, monkeypatch):
    raw = json.dumps([{"RuleID": "r1", "StartLine": 2, "File": "/scan/etc/config/network", "Secret": "REDACTED",
                       "Match": "option x 'LEAKME"}])
    monkeypatch.setattr(preflight, "_default_runner", lambda: _fake_runner(7, raw))
    monkeypatch.setenv("PODMAN", "podman")
    monkeypatch.delenv("RECON_GITLEAKS_BIN", raising=False)
    rc = preflight.main(["--root", str(root), "--config", str(GITLEAKS_TOML),
                          "--image-file", str(IMAGE_FILE)])
    out = capsys.readouterr()
    assert rc == 1 and "redacted/etc/config/network:2 r1" in out.out and "LEAKME" not in out.out + out.err


def test_cli_clean_writes_stamp(root, fixture_tree, capsys, monkeypatch):
    monkeypatch.setattr(preflight, "_default_runner", lambda: _fake_runner(0))
    monkeypatch.setenv("PODMAN", "podman")
    monkeypatch.delenv("RECON_GITLEAKS_BIN", raising=False)
    assert preflight.main(["--root", str(root), "--config", str(GITLEAKS_TOML),
                          "--image-file", str(IMAGE_FILE)]) == 0
    assert preflight.has_stamp(root, [root / "harvest" / "redacted", root / "unpacked"])


def test_config_is_independent_of_redactor_defaults():
    toml = GITLEAKS_TOML.read_text()
    assert "useDefault" not in toml
    for rule in ("uci-secret-option", "wifi-psk-line", "wg-key-line", "wg-key-option", "wg-base64-44",
                 "private-key-pem", "crypt-hash", "imei-like-digit-run", "iccid", "bearer-token", "api-key-sk"):
        assert f'id = "{rule}"' in toml


# ---- real gitleaks runs (independence of the pre-flight from the redactor) ----

def _scan(root, dirs):
    podman = shutil.which("podman")
    local = CFG["gitleaks_bin"]
    return preflight.run_preflight(dirs, root, config=GITLEAKS_TOML, podman=None if local else [podman],
                                   image=preflight.read_image(IMAGE_FILE), gitleaks_bin=local)


def _redacted_root(root, tmp_path, disabled):
    src = tmp_path / "plain"
    for s in SAMPLES:
        p = src / s.path
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(s.text)
    redact.redact_tree(src, root / "harvest" / "redacted", disabled=frozenset(disabled), salt="s")


@pytest.mark.requires_gitleaks
def test_preflight_clean_when_all_rules_enabled(root, tmp_path):
    _redacted_root(root, tmp_path, ())
    res = _scan(root, [root / "harvest" / "redacted"])
    assert res.hits == (), res.hits
    assert res.stamp and res.stamp.exists()


@pytest.mark.requires_gitleaks
@pytest.mark.parametrize("sample", [s for s in SAMPLES], ids=lambda s: s.name)
def test_preflight_aborts_on_exactly_the_unredacted_class(root, tmp_path, sample):
    _redacted_root(root, tmp_path, sample.disable)
    res = _scan(root, [root / "harvest" / "redacted"])
    assert res.stamp is None
    by_file = {}
    for h in res.hits:
        by_file.setdefault(h.file, set()).add(h.rule)
    assert f"redacted/{sample.path}" in by_file, res.hits
    assert by_file[f"redacted/{sample.path}"] & set(sample.gitleaks_rules), by_file
    exposed = {f"redacted/{s.path}" for s in SAMPLES if s.redact_rule in sample.disable}
    assert set(by_file) <= exposed, set(by_file) - exposed


@pytest.mark.requires_podman
def test_podman_container_path_catches_secret(root, tmp_path):
    _redacted_root(root, tmp_path, ("wifi-psk",))
    res = preflight.run_preflight([root / "harvest" / "redacted"], root, config=GITLEAKS_TOML,
                                  podman=[shutil.which("podman")], image=preflight.read_image(IMAGE_FILE),
                                  gitleaks_bin=None)
    assert any(h.rule == "wifi-psk-line" for h in res.hits)


def _stamp_file(root, dirs):
    return next((root / "cache" / "preflight").glob("*.ok"))


def test_stamp_is_json_bound_to_config_and_image(root, fixture_tree):
    dirs = [root / "harvest" / "redacted", root / "unpacked"]
    digest = preflight.tree_hash(dirs, root)
    preflight.write_stamp(root, digest)
    data = json.loads(_stamp_file(root, dirs).read_text())
    assert data["tree_sha256"] == digest and len(data["config_sha256"]) == 64 and "@sha256:" in data["image"]
    assert preflight.has_stamp(root, dirs)
    (root / "containers" / "gitleaks.toml").write_text("title = 'weakened'\n")
    assert not preflight.has_stamp(root, dirs)


def test_stamp_invalid_if_image_changes_or_contents_tampered(root, fixture_tree):
    dirs = [root / "harvest" / "redacted", root / "unpacked"]
    preflight.write_stamp(root, preflight.tree_hash(dirs, root))
    stamp = _stamp_file(root, dirs)
    original = stamp.read_text()
    stamp.write_text("ok\n")  # old-style / forged stamp
    assert not preflight.has_stamp(root, dirs)
    stamp.write_text(original)
    assert preflight.has_stamp(root, dirs)
    (root / "containers" / "gitleaks.image").write_text("docker.io/x/gitleaks@sha256:" + "1" * 64 + "\n")
    assert not preflight.has_stamp(root, dirs)


def test_missing_containers_files_means_no_stamp(root, fixture_tree):
    dirs = [root / "harvest" / "redacted", root / "unpacked"]
    preflight.write_stamp(root, preflight.tree_hash(dirs, root))
    shutil.rmtree(root / "containers")
    assert not preflight.has_stamp(root, dirs)


@pytest.mark.parametrize("raw", ["null", "{}", '"x"', "[1, 2]", "[null]"])
def test_parse_report_garbage_is_clean_abort(raw):
    with pytest.raises(preflight.PreflightError):
        preflight.parse_report(raw, "/scan", "redacted")


def test_leak_exit_with_unparseable_or_empty_report_never_stamps(root, fixture_tree):
    for stdout in ("", "[]", "null"):
        with pytest.raises(preflight.PreflightError):
            preflight.run_preflight([root / "harvest" / "redacted"], root, config=GITLEAKS_TOML, podman=["p"],
                                    image="i@sha256:" + "0" * 64, gitleaks_bin=None, runner=_fake_runner(7, stdout))
    assert not (root / "cache" / "preflight").exists()


@pytest.mark.requires_gitleaks
def test_entropy_rules_catch_what_the_redactor_does_not_know(root, tmp_path):
    src = tmp_path / "plain"
    (src / "etc").mkdir(parents=True)
    blob = "q8Xv2LmZ9aKd4TrYb7PwNc3Hs5Jf6"
    (src / "etc" / "quoted.txt").write_text(f'build_ref = "{blob}"\n')
    (src / "etc" / "assigned.txt").write_text(f"vendor_blob: {blob}Qz\n")
    redact.redact_tree(src, root / "harvest" / "redacted", salt="s")
    res = _scan(root, [root / "harvest" / "redacted"])
    rules = {h.file: h.rule for h in res.hits}
    assert set(rules) == {"redacted/etc/quoted.txt", "redacted/etc/assigned.txt"}, res.hits
    assert res.stamp is None


S1_LINES = ["token=aaaa1111.bbbb2222.cccc3333", 'secret: "Ab!cdefgh9"', "api_key = 'ab!cdef12'",
            'wep_key0="p@ss!x"', "password: hunter2xyz", "passwd: s3cretpw", "Authorization: Basic dXNlcjpwYXNz=="]
S1_BENIGN = ["option device 'eth1'", "key_mgmt=WPA-PSK", "keyboard=us", "password_policy:", "bypass=1", "hash_type=sha256"]


@pytest.mark.requires_gitleaks
@pytest.mark.parametrize("line", S1_LINES)
def test_gitleaks_has_its_own_rules_for_labelled_secrets(root, line):
    (root / "harvest" / "redacted" / "etc").mkdir(parents=True)
    (root / "harvest" / "redacted" / "etc" / "x.txt").write_text(line + "\n")  # NOT passed through the redactor
    res = _scan(root, [root / "harvest" / "redacted"])
    assert res.stamp is None and {h.file for h in res.hits} == {"redacted/etc/x.txt"}, res.hits


@pytest.mark.requires_gitleaks
def test_gitleaks_stays_quiet_on_benign_labels(root):
    (root / "harvest" / "redacted" / "etc").mkdir(parents=True)
    (root / "harvest" / "redacted" / "etc" / "x.txt").write_text("\n".join(S1_BENIGN) + "\n")
    assert _scan(root, [root / "harvest" / "redacted"]).hits == ()


def _urlpw():
    return "https://bob:" + "Zq7pw" + "xyQ9@ddns.example.com/nic"


R2_LINES = [
    _urlpw(),
    "curl -s -u root:" + "Zq7pw" + "xyQ9 http://192.168.8.1/rpc",
    "curl --user admin:" + "Zq7pw" + "xyQ9 https://x",
    "sshpass -p " + "Zq7pw" + "xyQ9 ssh root@h",
    "mosquitto_pub -h h -u bob -P " + "Zq7pw" + "xyQ9 -t x",
    "wget --password " + "Zq7pw" + "xyQ9 http://h",
    "pppd call x user bob password " + "Zq7pw" + "xyQ9",
    "echo 'root:" + "Zq7pw" + "xyQ9' | chpasswd",
    "state " + "ab" * 32,
    "password => '" + "Zq7pw" + "xyQ9'",
    "password:: " + "Zq7pw" + "xyQ9",
    "password：" + "Zq7pw" + "xyQ9",
    "password\t" + "Zq7pw" + "xyQ9",
    "wpa_passphrase=correct horse battery staple",
    ": PSK \"" + "Zq7pw" + "xyQ9\"",
    "00:11:22:33:44:55 " + "Zq7pw" + "xyQ9",
    "<PreSharedKey>" + "Zq7pw" + "xyQ9</PreSharedKey>",
    '<input type="password" name="pw" value="' + "Zq7pw" + 'xyQ9">',
    "AT+CPIN=\"4321\"",
    '{"pwd": "' + "Zq7pw" + 'xyQ9"}',
    '{"params":\n [ "' + "ab12" * 8 + '", "x"]}',
    "<secret>\n" + "ab12" * 8 + "\n</secret>",
    "-----BEGIN OpenVPN Static key V1-----\n" + "0123456789abcdef" * 2 + "\n-----END OpenVPN Static key V1-----",
    "data " + "cm9vdDpUcjB1YjRkb3ImM3h5ejEyMzQ1Njc4OTA" + "=",
]
R2_BENIGN = ["mkdir -p /tmp/x", "ps -p 123", "ssh -p 2222 host", "see https://example.com:8080/path", "AT+QGPIO=1,26",
             "sha1 " + "ab" * 20, "<ssid>Home</ssid>", "gpio-keys: gpio: 527", '"auth": {"key": "Integer"}',
             "ubus call modem get_info"]


@pytest.mark.requires_gitleaks
@pytest.mark.parametrize("line", R2_LINES, ids=[l[:30] for l in R2_LINES])
def test_gitleaks_has_independent_rules_for_the_review_forms(root, line):
    (root / "harvest" / "redacted" / "etc").mkdir(parents=True)
    (root / "harvest" / "redacted" / "etc" / "x.txt").write_text(line + "\n")  # raw, never redacted
    res = _scan(root, [root / "harvest" / "redacted"])
    assert res.stamp is None and {h.file for h in res.hits} == {"redacted/etc/x.txt"}, res.hits


@pytest.mark.requires_gitleaks
def test_gitleaks_stays_quiet_on_review_benign_lines(root):
    (root / "harvest" / "redacted" / "etc").mkdir(parents=True)
    (root / "harvest" / "redacted" / "etc" / "x.txt").write_text("\n".join(R2_BENIGN) + "\n")
    assert _scan(root, [root / "harvest" / "redacted"]).hits == ()


@pytest.mark.requires_gitleaks
def test_benign_fixture_tree_is_clean(root, fixture_tree):
    res = _scan(root, [root / "harvest" / "redacted"])
    assert res.hits == (), res.hits
