"""Round 3: the reviewer's 65 cases, the H1/M probes and must-stay-unchanged signals."""
import pytest

from attack3_data import CASES
from recon import redact


@pytest.mark.parametrize("cid,text,secret,note", CASES, ids=[c[0] for c in CASES])
def test_round3_case_does_not_leak(cid, text, secret, note):
    out = redact.redact_text(text, salt="x")[0]
    assert secret not in out, out


@pytest.mark.parametrize("cid,text,secret,note", CASES, ids=[c[0] for c in CASES])
def test_round3_case_is_idempotent(cid, text, secret, note):
    once = redact.redact_text(text, salt="x")[0]
    assert redact.redact_text(once, salt="x")[0] == once


V = "Zq7pw" + "xyQ9Lm2" + "Rt5"   # 16-char fake value, assembled at runtime
TOK = "Bk4nT9" + "xQ2mZ7vL8" + "cR3wY6pD1sH5"  # 27 chars, high entropy


H1_LINES = [
    f"password {V}", f"passwd {V}", f"passphrase {V}", f"psk {V}", f"secret {V}", f"token {V}",
    f"  password {V}  ", f"password {V} with more words",
    f'json_add_string password "{V}"', f"json_add_string psk {V}", f'json_add_string token "{V}"',
    f'json_add_int pin "{V}"', f'uci_set glcloud main token "{V}"', f"uci_set net wan password {V}",
    f'uci set glcloud.main.token="{V}"', f'uci:set("glcloud","main","token","{V}")',
    f"echo {TOK} > /tmp/f", f"printf '%s' {TOK} | gl_tool --stdin", f"echo \"{TOK}\" >> /etc/x",
    f"cat <<EOF > /etc/x\n{TOK}\nEOF", f"cat <<'EOF'\nline one\n{TOK}\nEOF",
]


@pytest.mark.parametrize("line", H1_LINES, ids=[l.splitlines()[0][:36] for l in H1_LINES])
def test_h1_init_script_idioms(line):
    out = redact.redact_text(line + "\n", salt="x")[0]
    assert V not in out and TOK not in out, out


H1_BENIGN = ["password", "password -f /etc/pw", "token", "echo done", "echo starting modem now",
             "printf '%s' hello", "echo /usr/lib/lua/luci/controller/admin/network.lua",
             "cat <<EOF\nstart modem\nEOF", "json_add_string name wan", "json_add_int mtu 1500",
             "uci_set network wan proto dhcp", "uci set network.wan.proto=dhcp", "uci_set net wan key_mgmt WPA-PSK"]


@pytest.mark.parametrize("text", H1_BENIGN)
def test_h1_benign_stay(text):
    assert redact.redact_text(text + "\n", salt="x")[0] == text + "\n"


def test_m3_ppp_auth_enums_stay_but_password_goes():
    for line in ("\toption auth 'chap'", "\toption auth 'pap'", "\toption auth 'mschap'", "\toption auth 'mschapv2'",
                 "\toption auth 'eap'", "\toption auth 'none'", "\toption auth_type 'pap'", "auth_type=chap"):
        assert redact.redact_text(line + "\n", salt="x")[0] == line + "\n", line
    assert V not in redact.redact_text(f"\toption password '{V}'\n", salt="x")[0]


@pytest.mark.parametrize("name", ["secret_blob", "psk_hex", "key_material", "password_hash", "token_value",
                                  "pass_enc", "secret_data", "token_x"])
def test_m4_first_token_secret_names(name):
    for fmt in ("{n}={v}", "\toption {n} '{v}'", "{n}: {v}", '{{"{n}": "{v}"}}'):
        out = redact.redact_text(fmt.format(n=name, v=V) + "\n", salt="x")[0]
        assert V not in out, fmt


def test_m4_benign_suffix_exceptions_remain():
    for line in ("key_mgmt=WPA-PSK", "key_type: rsa", "secret_type: sha256", "token_bucket: 10",
                 "password_policy: strict", "hash_type=sha256", "auth_algs=1", "\toption key_len '32'"):
        assert redact.redact_text(line + "\n", salt="x")[0] == line + "\n", line
    assert V not in redact.redact_text(f"secret_type: {V}\n", salt="x")[0]


B64 = "Ab3dE9fGh1Jk5LmN7pQ" + "r2StUvWx4YzAb8Cd"  # 35 chars, mixed case + digits, no padding


@pytest.mark.parametrize("text", [f"blob {B64}", f"x={B64}", f"data {B64[:20]}/{B64[20:]}", f"data {B64[:20]}+{B64[20:]}",
                                  f"seed: {B64}XY"])
def test_m5_unpadded_and_slash_plus_base64(text):
    out = redact.redact_text(text + "\n", salt="x")[0]
    assert B64[:12] not in out and B64[-10:] not in out, out


def test_m5_long_benign_words_stay():
    for line in ("/usr/lib/lua/luci/controller/admin/network_status.lua", "abcdefghijklmnopqrstuvwxyzabcdefgh",
                 "sha256 " + "ab" * 16, "CONFIG_TARGET_ROOTFS_SQUASHFS_COMPRESSION_XZ"):
        assert redact.redact_text(line + "\n", salt="x")[0] == line + "\n", line


@pytest.mark.parametrize("text", [f"+QCCID: 89860012345678901234F", "ICCID 8901260123456789012F detected",
                                  "iccid: 89860012345678901234F", "sim 8986001234567890123F ok"])
def test_m5_iccid_with_trailing_f(text):
    out = redact.redact_text(text + "\n", salt="x")[0]
    assert "8986001234567890" not in out and "890126012345678" not in out and "8986001234567890123F" not in out


@pytest.mark.parametrize("text,leak", [
    ("console=ttyMSM0 androidboot.serialno=0123456789abcdef root=/dev/x", "0123456789abcdef"),
    ("serialno=0123456789abcdef", "0123456789abcdef"),
    ("usb 1-1: SerialNumber: 0123456789abcdef", "0123456789abcdef"),
    ("serial number: ABCD1234EFGH", "ABCD1234EFGH"),
    ("Serial number = ABCD1234EFGH", "ABCD1234EFGH"),
    ("Serial: ABCD1234EFGH", "ABCD1234EFGH"),
    ("serial_number=ABCD1234EFGH", "ABCD1234EFGH"),
])
def test_m6_serial_numbers(text, leak):
    assert leak not in redact.redact_text(text + "\n", salt="x")[0]


@pytest.mark.parametrize("line", ["Serial: 8250/16550 driver, 4 ports, IRQ sharing disabled", "serial8250: ttyS0 at MMIO",
                                  "the serial console is ttyMSM0", "console [ttyS0] enabled", "Serial number of the device",
                                  "serial_core: registered"])
def test_m6_serial_words_without_values_stay(line):
    assert redact.redact_text(line + "\n", salt="x")[0] == line + "\n"
