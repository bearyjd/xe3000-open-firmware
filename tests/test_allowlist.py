"""L1: default-deny allowlist of what may be sent to the API."""
import json

import pytest

from conftest import REPO
from conftest import Lazy

allowlist = Lazy("recon.allowlist")

DEFAULT = REPO / "containers" / "recon-allowlist.txt"
ALLOWED = ["redacted/etc/init.d/modem", "redacted/etc/hotplug.d/iface/10-modem", "redacted/etc/hotplug.d/a/b/c",
           "redacted/etc/rc.d/S99modem", "redacted/etc/config/glmodem", "redacted/proc/cmdline", "redacted/proc/mtd",
           "redacted/sys/firmware/board.dts", "redacted/sys/a/b/board.dtsi", "redacted/var/dmesg.txt",
           "redacted/var/dmesg", "redacted/proc/modules", "redacted/proc/lsmod.txt", "unpacked/etc/init.d/x"]
DENIED = ["redacted/ps", "redacted/ps.txt", "redacted/logread", "redacted/var/log/messages",
          "redacted/etc/crontabs/root", "redacted/etc/config/wireless", "redacted/etc/config/network",
          "redacted/etc/config/rpcd", "redacted/etc/config/vpn_client", "redacted/etc/config/wireguard_wg0",
          "redacted/etc/config/ddns", "redacted/etc/config/openvpn", "redacted/etc/shadow", "redacted/proc/net/tcp",
          "redacted/etc/init.d/sub/deeper", "redacted/capture.har", "unpacked/usr/bin/tool.sh"]


def test_default_allowlist_file_is_committed_and_parses():
    pats = allowlist.load_patterns(DEFAULT)
    assert pats and all(p == p.strip() and not p.startswith("#") for p in pats)
    assert not any(p in ("**", "*") for p in pats)


@pytest.mark.parametrize("name", ALLOWED)
def test_default_allows(name):
    assert allowlist.is_allowed(name, allowlist.load_patterns(DEFAULT))


@pytest.mark.parametrize("name", DENIED)
def test_default_denies(name):
    assert not allowlist.is_allowed(name, allowlist.load_patterns(DEFAULT))


def test_glob_semantics():
    assert allowlist.is_allowed("redacted/a/b/c.txt", ["a/**"])
    assert allowlist.is_allowed("redacted/a/c.txt", ["a/*.txt"])
    assert not allowlist.is_allowed("redacted/a/b/c.txt", ["a/*.txt"])
    assert allowlist.is_allowed("unpacked/a/c", ["a/c"]) and allowlist.is_allowed("redacted/a/c", ["a/c"])
    assert allowlist.is_allowed("redacted/anything/at/all", ["**"])
    assert not allowlist.is_allowed("redacted/ab", ["a?x"]) and allowlist.is_allowed("redacted/abx", ["a?x"])
    assert not allowlist.is_allowed("redacted/x", [])


def test_load_ignores_comments_and_blanks(tmp_path):
    f = tmp_path / "a.txt"
    f.write_text("# c\n\n  etc/x  \netc/y/**\n")
    assert allowlist.load_patterns(f) == ("etc/x", "etc/y/**")


def test_missing_allowlist_is_an_error(tmp_path):
    with pytest.raises(allowlist.AllowlistError):
        allowlist.load_patterns(tmp_path / "nope.txt")


def test_patterns_cannot_escape_the_root(tmp_path):
    f = tmp_path / "a.txt"
    f.write_text("../etc/x\n/abs/path\n")
    with pytest.raises(allowlist.AllowlistError):
        allowlist.load_patterns(f)
