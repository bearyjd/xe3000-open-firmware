"""S1: labelled secrets are redacted whole; precise enough not to wipe benign lines."""
import pytest

from recon import redact


def _out(text):
    return redact.redact_text(text, salt="s")[0]


@pytest.mark.parametrize("line,leak", [
    ("token=aaaa1111.bbbb2222.cccc3333", "bbbb2222"),
    ("token=aaaa1111.bbbb2222.cccc3333", "cccc3333"),
    ('secret: "Ab!cdefgh9"', "cdefgh9"),
    ("api_key = 'ab!cdef12'", "cdef12"),
    ('wep_key0="p@ss!x"', "p@ss!x"),
    ("password: hunter2xyz", "hunter2xyz"),
    ("passwd: s3cretpw", "s3cretpw"),
    ("Authorization: Basic dXNlcjpwYXNz==", "dXNlcjpwYXNz"),
    ("Authorization: Digest abc123def456", "abc123def456"),
    ("Authorization: rawcredential99", "rawcredential99"),
    ("auth_key=a~b@c.d!e", "b@c.d!e"),
    ("sid: Ab.Cd-Ef~Gh", "Cd-Ef~Gh"),
    ("pin=1234", "1234"),
    ('secret: "has spaces inside"', "spaces inside"),
    ("hash=0123abcd.4567ef!89", "4567ef!89"),
])
def test_whole_value_is_redacted(line, leak):
    out = _out(line)
    assert leak not in out, out
    assert "REDACTED" in out


def test_quoted_value_runs_to_closing_quote_only():
    out = _out("password='a b c' next=thing")
    assert "a b c" not in out and "next=thing" in out


def test_auth_scheme_is_kept():
    assert _out("Authorization: Basic dXNlcjpwYXNz==").startswith("Authorization: Basic ")


@pytest.mark.parametrize("line", [
    "option device 'eth1'",
    "key_mgmt=WPA-PSK",
    "\tkey_mgmt=SAE",
    "keyboard=us",
    "password_policy:",
    "password_policy: strict",
    "keyboard layout: de",
    "bypass=1",
    "inside=lan",
    "compass: north",
    "hash_type=sha256",
    "pairwise=CCMP",
    "ssid=HomeNet",
    "proto=dhcp",
    "mapping: yes",
])
def test_benign_lines_untouched(line):
    assert _out(line) == line


def test_already_redacted_values_are_not_double_processed():
    out, counts = redact.redact_text("password=hunter2xyz\n", salt="s")
    assert out.count("<REDACTED:") == 1 and out.count("<REDACTED") == 1
    assert redact.redact_text(out, salt="s")[0] == out


@pytest.mark.parametrize("name", ["etc/shadow", "etc/serial", "etc/serial_number", "x/serial0", "etc/dropbear/k",
                                  "a/b_host_key", "a/c.pem", "a/c.key"])
def test_is_excluded_covers_serial_prefix_and_friends(name):
    from pathlib import Path
    assert redact._is_excluded(Path(name))


def test_is_excluded_not_overbroad():
    from pathlib import Path
    assert not redact._is_excluded(Path("etc/config/network"))
