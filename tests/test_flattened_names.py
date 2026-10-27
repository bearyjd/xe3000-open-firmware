"""harvest.sh flattens frame names ('/' -> '%'). Every name-based decision downstream (exclusion, allowlist) must
see the un-flattened path, so flattened and plain forms behave identically."""
from pathlib import Path

import pytest

from conftest import REPO
from recon import allowlist, redact, runner

SECRET = "-".join(("hunter2", "SUPERSECRET"))

EXCLUDED_FORMS = [
    "etc/config/chap-secrets",
    "etc%config%chap-secrets",
    "frames/config/etc%config%chap-secrets",
    "frames/config/a%b%etc%config%pap-secrets",
    "frames/sys/etc%ppp%ipsec.secrets",
    "frames/sys/etc%ppp%peer.psk",
    "frames/sys/etc%ppp%vpn.secrets",
    "frames/sys/etc%ppp%login.auth",
    "frames/config/etc%hostapd%wpa_psk_file",
    "frames/config/etc%config%userpass.txt",
    "frames/sys/etc%shadow",
    "frames/sys/etc%dropbear%dropbear_rsa_host_key",
    "frames/sys/etc%dropbear%anything.txt",
    "frames/sys/etc%ssl%private%x.pem",
    "frames/sys/etc%ssl%server.key",
    "frames/hw/sys%bus%usb%devices%1-1%serial",
    "frames/hw/sys%class%power_supply%BAT0%serial_number",
    "frames/sys/etc%htpasswd",
    "frames/sys/etc%config%auth-user-pass",
    "etc/dropbear/x",
    "sys/bus/usb/devices/1-1/serial",
]

AMBIGUOUS_FORMS = [
    "frames/con%fig/etc",  # a '%' in a directory name is never produced by harvest.sh
    "frames/config/etc%%config%glmodem",  # empty segment
    "frames/config/etc%..%config%glmodem",
    "frames/config/%etc%glmodem",
    "frames/config/etc%config%",
    "frames/config/etc%.%glmodem",
]

BENIGN_FORMS = [
    "etc/config/glmodem",
    "frames/config/etc%config%glmodem",
    "frames/ident/proc%cpuinfo",
    "frames/sys/etc%init.d%gl_modem",
]


@pytest.mark.parametrize("name", EXCLUDED_FORMS)
def test_secret_file_names_are_excluded_in_every_form(name):
    assert redact._is_excluded(Path(name)), name


@pytest.mark.parametrize("name", AMBIGUOUS_FORMS)
def test_ambiguous_flattened_names_are_excluded(name):
    assert redact._is_excluded(Path(name)), name


@pytest.mark.parametrize("name", BENIGN_FORMS)
def test_benign_names_are_not_excluded(name):
    assert not redact._is_excluded(Path(name)), name


def test_redact_tree_drops_flattened_secret_files(tmp_path):
    src, dst = tmp_path / "src", tmp_path / "dst"
    (src / "frames" / "config").mkdir(parents=True)
    for name in ("etc%config%chap-secrets", "a%b%etc%config%pap-secrets", "etc%%config%x", "etc%config%glmodem"):
        (src / "frames" / "config" / name).write_text(f"user * {SECRET} *\n")
    (src / "frames" / "config" / "etc%dropbear%dropbear_ecdsa_host_key").write_text(SECRET)
    report = redact.redact_tree(src, dst, salt="s")
    out = {p.name: p.read_text() for p in dst.rglob("*") if p.is_file()}
    assert list(out) == ["etc%config%glmodem"]  # the benign file survives (redacted), nothing else
    excluded = sorted(r["file"] for r in report if r["rule"] == redact.EXCLUDED)
    assert len(excluded) == 4 and all(SECRET not in r["file"] for r in report)


def test_allowlist_matches_the_unflattened_path():
    patterns = allowlist.load_patterns(REPO / "containers" / "recon-allowlist.txt")
    ok = allowlist.is_allowed
    assert ok("redacted/etc/config/glmodem", patterns)
    assert ok("redacted/frames/config/etc%config%glmodem", patterns)
    assert ok("redacted/etc%config%glmodem", patterns)
    assert ok("redacted/frames/sys/etc%init.d%gl_modem", patterns)
    assert ok("redacted/frames/sys/etc%hotplug.d%iface%10-modem", patterns)
    assert not ok("redacted/frames/config/etc%config%wireless", patterns)
    assert not ok("redacted/frames/config/etc%config%chap-secrets", patterns)
    assert not ok("redacted/frames/config/con%fig/glmodem", patterns)
    assert not ok("redacted/frames/config/etc%%config%glmodem", patterns)
    assert not ok("redacted/frames/config/etc%..%config%glmodem", patterns)


def test_flattened_name_cannot_smuggle_a_path_past_a_directory_pattern():
    # 'etc/init.d/*' must not match a flattened name that un-flattens to a deeper path
    assert not allowlist.is_allowed("redacted/frames/sys/etc%init.d%a%b", ["etc/init.d/*"])
    assert allowlist.is_allowed("redacted/frames/sys/etc%init.d%a", ["etc/init.d/*"])


def test_runner_classifies_flattened_secret_files_as_excluded():
    patterns = allowlist.load_patterns(REPO / "containers" / "recon-allowlist.txt")
    data = f"user * {SECRET} *\n".encode()
    groups = [("redacted", [
        ("redacted/frames/config/etc%config%chap-secrets", data),
        ("redacted/etc/config/chap-secrets", data),
        ("redacted/frames/config/etc%config%glmodem", b"config modem 'm'\n"),
    ])]
    _files, skipped, denied, texts = runner._classify_inputs(groups, patterns)
    assert sorted(s["name"] for s in skipped if s["reason"] == "excluded") == [
        "redacted/etc/config/chap-secrets", "redacted/frames/config/etc%config%chap-secrets"]
    assert list(texts) == ["redacted/frames/config/etc%config%glmodem"] and not denied
    assert SECRET not in "".join(texts.values())
