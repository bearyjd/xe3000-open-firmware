"""Regression tests for the adversarial re-review: every case must come out without its secret."""
import pytest

from attack_data import CASES, SECRET_SETS, render
from recon import redact

PARAMS = []
for label, text, secret in CASES:
    if "@S@" in text and secret == "@S@":
        PARAMS += [pytest.param(text, secret, name, id=f"{label}|{name}") for name in SECRET_SETS]
    else:
        PARAMS.append(pytest.param(text, secret, "mid", id=label))


@pytest.mark.parametrize("text,secret,variant", PARAMS)
def test_adversarial_case_does_not_leak(text, secret, variant):
    s = SECRET_SETS[variant]
    raw, needle = render(text, s), render(secret, s)
    out, counts = redact.redact_text(raw, salt="x")
    assert needle not in out, out
    assert sum(counts.values()) >= 1


@pytest.mark.parametrize("text,secret,variant", PARAMS)
def test_redaction_is_idempotent(text, secret, variant):
    raw = render(text, SECRET_SETS[variant])
    once = redact.redact_text(raw, salt="x")[0]
    assert redact.redact_text(once, salt="x")[0] == once


# Lines that must come through byte-for-byte (the reviewer's over-redaction signals).
MUST_STAY = [
    '"session": {"login": {"username": "String", "password": "String", "timeout": "Integer"}}',
    '"rpc-sys": {"password_set": {"user": "String", "password": "String"}}',
    '"auth": {"key": "Integer", "token": "String"}',
    "\toption ssid 'GL-XE3000-a1b'", "\toption authoritative '1'", "\toption bypass '0'",
    "\toption passthrough '1'", "\toption ca_cert '/etc/ssl/ca.pem'", "\toption auth 'EAP'",
    "\toption keepalive '25'", "\toption key_mgmt 'WPA-PSK'", "\toption hotkey_gpio '512'",
    "key_mgmt=WPA-PSK", "auth_algs=1", "wpa_key_mgmt=SAE", "ieee80211w=2", "sae_pwe=2",
    "Key type id_resolver registered", "Dentry cache hash table entries: 16384 (order: 4)",
    "input: gpio-keys as /devices/platform/gpio-keys/input/input0",
    "AT+QGPIO=1,26", 'AT+QCFG="usbnet",1', 'AT+CGDCONT=1,"IP","internet"',
    "mtk_hnat 123456 0 - Live", '"method": "get_token"', "token_bucket: 10", "keyboard: us", "auth: 1",
    "sid: 0", "private: 0", "hash: crc32c", "cert: /etc/ssl/certs/ca.pem", "monkey_patch: true", "pass: 3",
    "sysupgrade.key: present", "ubus call system board", "imei_valid: 1",
    "gpio-keys: gpio: 527", "ubus call modem get_info", "insmod mhi_wwan_ctrl", "AT+CFUN=1", "echo 12 > /sys/class/gpio/export",
]


@pytest.mark.parametrize("line", MUST_STAY)
def test_benign_line_is_unchanged(line):
    assert redact.redact_text(line + "\n", salt="x")[0] == line + "\n"


def test_gpio_numbers_at_commands_and_names_survive_next_to_redactions():
    text = "gpio-keys: key: 'reset' gpio: 527\nAT+CPIN=\"4321\"\nubus call modem get_info\ninsmod mhi_wwan_ctrl\n"
    out = redact.redact_text(text, salt="x")[0]
    assert "gpio: 527" in out and "AT+CPIN" in out and "4321" not in out
    assert "ubus call modem get_info" in out and "insmod mhi_wwan_ctrl" in out
