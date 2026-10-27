import json

import pytest

from recon import redact
from secrets_gen import MAC, build_samples

SAMPLES = build_samples()


def _tree(tmp_path):
    src = tmp_path / "src"
    for s in SAMPLES:
        p = src / s.path
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(s.text)
    (src / "etc" / "clients.txt").parent.mkdir(parents=True, exist_ok=True)
    (src / "etc" / "clients.txt").write_text(f"lease {MAC} host-a\nlease {MAC.upper()} host-a\n")
    return src


def _all_output(dst):
    return "\n".join(p.read_text() for p in sorted(dst.rglob("*")) if p.is_file())


def test_every_planted_secret_removed(tmp_path):
    src, dst = _tree(tmp_path), tmp_path / "dst"
    report = redact.redact_tree(src, dst, salt="s")
    out = _all_output(dst)
    for s in SAMPLES:
        for v in s.values:
            assert v not in out, s.name
    assert "<REDACTED:" in out
    rules = {r["rule"] for r in report}
    assert {s.redact_rule for s in SAMPLES} <= rules


@pytest.mark.parametrize("sample", SAMPLES, ids=lambda s: s.name)
def test_each_sample_hit_by_its_rule(sample):
    text, counts = redact.redact_text(sample.text)
    assert counts[sample.redact_rule] >= 1 or any(counts.values())
    assert all(v not in text for v in sample.values)


def test_report_has_only_file_rule_count(tmp_path):
    src, dst = _tree(tmp_path), tmp_path / "dst"
    report = redact.redact_tree(src, dst, salt="s")
    assert report and all(set(r) == {"file", "rule", "count"} for r in report)
    blob = json.dumps(report)
    for s in SAMPLES:
        for v in s.values:
            assert v not in blob


def test_mac_pseudonymized_stable_and_oui_kept():
    a, _ = redact.redact_text(f"{MAC} and {MAC}\n", salt="s1")
    first, second = a.split(" and ")
    assert first.strip() == second.strip()
    assert first.startswith("dc:a6:32:") and MAC not in a
    b, _ = redact.redact_text(f"{MAC}\n", salt="s2")
    assert b != first + "\n"
    c, _ = redact.redact_text(f"{MAC.upper()}\n", salt="s1")
    assert c.lower() == (first + "\n").lower()


def test_disabled_rule_leaves_value():
    text, _ = redact.redact_text("wpa_passphrase=correct-horse-battery-staple\n", disabled=frozenset({"wifi-psk"}))
    assert "correct-horse-battery-staple" in text


def test_benign_text_untouched():
    benign = "config interface 'lan'\n\toption proto 'static'\n\toption ipaddr '192.168.8.1'\n"
    text, counts = redact.redact_text(benign)
    assert text == benign and not sum(counts.values())


def test_binary_and_hard_exclusions_skipped(tmp_path):
    src, dst = tmp_path / "src", tmp_path / "dst"
    (src / "etc" / "dropbear").mkdir(parents=True)
    (src / "etc" / "dropbear" / "dropbear_rsa_host_key").write_text("x")
    (src / "etc" / "shadow").write_text("root:x\n")
    (src / "tls.pem").write_text("x")
    (src / "blob.bin").write_bytes(b"\x00\x01\x02")
    (src / "ok.txt").write_text("hello\n")
    report = redact.redact_tree(src, dst, salt="s")
    assert [p.name for p in dst.rglob("*") if p.is_file()] == ["ok.txt"]
    assert {r["rule"] for r in report} >= {"excluded", "skipped-binary"}


def test_cli_writes_report(tmp_path, monkeypatch):
    src = _tree(tmp_path)
    monkeypatch.setenv("RECON_MAC_SALT", "abc")
    rc = redact.main(["--src", str(src), "--dst", str(tmp_path / "d"), "--report", str(tmp_path / "rep.json")])
    assert rc == 0
    assert json.loads((tmp_path / "rep.json").read_text())


def test_cli_refuses_dst_inside_src(tmp_path):
    src = _tree(tmp_path)
    assert redact.main(["--src", str(src), "--dst", str(src / "out"), "--salt", "x"]) == 2


def _gone(text, *values):
    out, counts = redact.redact_text(text, salt="s")
    for v in values:
        assert v not in out, (text, out)
    assert sum(counts.values()) >= 1
    return out


@pytest.mark.parametrize("line,value", [
    ('{"password": "Hunt3rTwo"}', "Hunt3rTwo"),
    ('{"psk":"abcdefgh12"}', "abcdefgh12"),
    ('{"wifi": {"token": "tk-77aa"}}', "tk-77aa"),
    ('{"api_key": "kkkk1111"}', "kkkk1111"),
    ('{"secret" : "s3cr3tsecret"}', "s3cr3tsecret"),
    ('{"hash": "5f4dcc3b5aa765d61d8327deb882cf99"}', "5f4dcc3b5aa765d61d8327deb882cf99"),
    ('{"pin": "1234"}', "1234"),
    ('{"puk": 12345678}', "12345678"),
    ('{"sid": "abcDEF12345678"}', "abcDEF12345678"),
])
def test_json_key_value_rules(line, value):
    out = _gone(line, value)
    assert "<REDACTED:json-secret>" in out
    import json as _j
    _j.loads(out)  # still valid JSON


def test_json_rpc_positional_sid_and_login_hash():
    sid = "0123456789abcdef0123456789abcdef"
    out = _gone('{"method":"call","params":["%s","modem","get_info",{}]}' % sid, sid)
    assert '"modem","get_info"' in out
    login = "a" * 32
    _gone('{"params":["", "auth", "login", {"username":"root","hash":"%s"}]}' % login, login)


def test_json_benign_keys_untouched():
    benign = '{"mapping": "abcdefgh", "spinner": "xxxxyyyy", "name": "wan"}'
    assert redact.redact_text(benign)[0] == benign


@pytest.mark.parametrize("line,value", [
    ("ap_password=Pl4inTextPw", "Pl4inTextPw"),
    ("ROOT_PASSWORD=Hunter22xx", "Hunter22xx"),
    ("private_key_passwd=Zzzz9999", "Zzzz9999"),
    ("export WIFI_PSK='abcd1234'", "abcd1234"),
    ("SIM_PIN=4321", "4321"),
    ("puk=87654321", "87654321"),
])
def test_assignment_names_with_prefixes(line, value):
    _gone(line, value)


def test_uci_extra_names_and_shell_form():
    _gone("config sim\n\toption pin '4321'\n", "4321")
    _gone("config sim\n\toption pincode '4321'\n\toption puk '99887766'\n", "4321", "99887766")
    _gone("config x\n\toption passwd 'pw123456'\n", "pw123456")
    _gone("uci set wireless.radio0.key='Tr0ub4dorXYZ'", "Tr0ub4dorXYZ")
    _gone("uci -q set network.wan.password=abc12345 && uci commit", "abc12345")
    _gone("uci add_list x.y.psk=lst12345", "lst12345")
    benign = "uci set network.lan.ipaddr='192.168.8.1'\n"
    assert redact.redact_text(benign)[0] == benign


def test_pgp_and_unterminated_blocks_redacted_to_eof():
    body = "lQdGBF" + "x" * 58
    pgp = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" + body + "\n-----END PGP PRIVATE KEY BLOCK-----\ntail\n"
    out = _gone(pgp, body)
    assert out.endswith("tail\n")
    open_pem = "head\n-----BEGIN RSA PRIVATE KEY-----\n" + body + "\nmore body\n"
    out = _gone(open_pem, body, "more body")
    assert out.startswith("head\n")


def test_bare_imsi_and_dash_mac_and_eui64():
    from secrets_gen import not_luhn
    imsi = not_luhn("31015012345678")
    _gone(f"attached {imsi} now", imsi)
    out, _ = redact.redact_text("peer DC-A6-32-11-22-33 up", salt="s")
    assert "DC-A6-32-11-22-33" not in out and "dc-a6-32-" in out.lower()
    again, _ = redact.redact_text("peer DC-A6-32-11-22-33 up", salt="s")
    assert again == out
    v6 = "inet6 fe80::dca6:32ff:fe11:2233/64"
    out = _gone(v6, "dca6:32ff:fe11:2233")
    assert out.startswith("inet6 fe80::")


def test_short_labelled_tokens_are_redacted():
    _gone("session_token: ab12CD", "ab12CD")
    _gone("cookie=Zk9x7", "Zk9x7")
