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


# ---- review round: wrapper-only decoding, .PARTIAL, canonical list, canary markers ---------------------------------

from recon import canary, names  # noqa: E402


@pytest.mark.parametrize("rel, expected", [
    ("frames/sys/etc%init.d%x", "etc/init.d/x"),          # validated harvest wrapper frames/<kind>/
    ("sys/etc%init.d%x", "etc/init.d/x"),                 # raw/<ts>/frames used as the redaction root: <kind>/
    ("etc%init.d%x", "etc/init.d/x"),
    ("frames/hw-bin/sys%firmware%fdt", "sys/firmware/fdt"),
    ("private/etc%config%glmodem", "private/etc/config/glmodem"),   # unknown parents are kept, never discarded
    ("odd/etc%config%glmodem", "odd/etc/config/glmodem"),
    ("frames/bogus/etc%init.d%x", "frames/bogus/etc/init.d/x"),     # frames/<unknown kind>/ is not a wrapper
    ("frames/sys/extra/etc%init.d%x", "frames/sys/extra/etc/init.d/x"),
    ("etc/config/glmodem", "etc/config/glmodem"),
])
def test_only_validated_wrappers_are_dropped_when_decoding(rel, expected):
    assert names.unflattened_path(rel) == expected


def test_unknown_parent_directories_do_not_reach_the_allowlist():
    patterns = allowlist.load_patterns(REPO / "containers" / "recon-allowlist.txt")
    assert not allowlist.is_allowed("unpacked/private/etc%config%glmodem", patterns)
    assert not allowlist.is_allowed("unpacked/odd/etc%config%glmodem", patterns)
    assert not allowlist.is_allowed("redacted/frames/bogus/etc%config%glmodem", patterns)
    assert allowlist.is_allowed("redacted/frames/config/etc%config%glmodem", patterns)
    assert allowlist.is_allowed("redacted/config/etc%config%glmodem", patterns)
    assert redact._is_excluded(Path("private/etc%config%glmodem"))
    assert redact._is_excluded(Path("unpacked/private/etc/config/glmodem"))


PARTIAL_FORMS = [
    "frames/sys/etc%init.d%chap-secrets.PARTIAL",
    "frames/sys/etc%init.d%glmodem.PARTIAL",
    "etc/init.d/glmodem.PARTIAL",
    "frames/sys/etc%init.d%glmodem.partial",
]


@pytest.mark.parametrize("name", PARTIAL_FORMS)
def test_partial_frames_are_never_sent_or_redacted_through(name, tmp_path):
    assert redact._is_excluded(Path(name))
    assert not allowlist.is_allowed("redacted/" + name, ["etc/init.d/*", "**"])
    groups = [("redacted", [("redacted/" + name, b"x\n")])]
    _f, skipped, denied, texts = runner._classify_inputs(groups, ["etc/init.d/*"])
    assert [s["reason"] for s in skipped] == ["excluded"] and not texts and not denied


CANONICAL_EXCLUDED = [
    "etc/ssh/ssh_host_rsa_key", "etc%ssh%ssh_host_rsa_key", "etc/ssh/my_host_key_old", "root/.ssh/id_rsa",
    "root%.ssh%id_rsa", "root/.ssh/id_ed25519", "root/.ssh/id_dsa", "root%.ssh%id_ecdsa", "sys/board_serial",
    "sys%class%dmi%board_serial", "sys/class/x/product_serial_no", "etc/config/wg0.conf", "etc%config%wg0.conf",
    "etc/wireguard/wgvpn.conf", "etc/vpn/client.wg", "etc%vpn%client.wg", "etc/private/anything",
    "etc%private%anything", "etc/ssl/private/x", "etc/dropbear/x", "etc/gshadow", "etc/shadow-", "etc%shadow-",
]
CANONICAL_BENIGN = [
    "etc/config/glmodem", "etc%config%glmodem", "etc/config/network", "etc/config/wgsomething.cfg",
    "etc/init.d/gl_modem", "proc/cmdline", "etc%config%led",
]


@pytest.mark.parametrize("name", CANONICAL_EXCLUDED)
def test_canonical_exclusion_list_covers_collect_sh_names(name):
    assert redact._is_excluded(Path(name)), name


@pytest.mark.parametrize("name", CANONICAL_BENIGN)
def test_canonical_list_keeps_benign_names(name):
    assert not redact._is_excluded(Path(name)), name


def test_canary_marker_recognises_flattened_names():
    for n in ("redacted/frames/ident/etc%glversion", "redacted/frames/ident/etc%openwrt_release",
              "redacted/etc%glversion", "redacted/ident/etc%glversion", "unpacked/odd/etc%glversion"):
        assert canary.has_real_harvest_marker([n]), n
    assert canary.has_real_harvest_marker(["redacted/etc/glversion"])
    assert not canary.has_real_harvest_marker(["redacted/frames/ident/proc%cpuinfo"])
