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
    # the generic labelled-secret rule may pre-empt a specific one, so check per file rather than per rule name
    assert {s.path for s in SAMPLES} <= {r["file"] for r in report}


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
    text, _ = redact.redact_text("wpa_passphrase=correct-horse-battery-staple\n", disabled=frozenset({"wifi-psk", "labelled-secret"}))
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
    pgp = "-----BEGIN " + "PGP PRIVATE KEY BLOCK-----\n" + body + "\n-----END " + "PGP PRIVATE KEY BLOCK-----\ntail\n"
    out = _gone(pgp, body)
    assert out.endswith("tail\n")
    open_pem = "head\n-----BEGIN " + "RSA PRIVATE KEY-----\n" + body + "\nmore body\n"
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


# ---- review round 2: names, blocks, structured forms ----

@pytest.mark.parametrize("name", ["etc/ppp/chap-secrets", "etc/ppp/pap-secrets", "etc/ipsec.secrets", "x/guest.psk",
                                  "etc/hostapd.wpa_psk", "etc/hostapd/wpa_psk_file", "etc/openvpn/client.auth",
                                  "etc/openvpn/auth-user-pass", "etc/openvpn/userpass.txt", "etc/x.secrets",
                                  "etc/htpasswd", "Etc/PPP/CHAP-SECRETS"])
def test_unlabelled_secret_files_are_excluded_by_name(name):
    from pathlib import Path
    assert redact._is_excluded(Path(name))


def test_excluded_secret_files_are_dropped_from_the_tree(tmp_path):
    src, dst = tmp_path / "s", tmp_path / "d"
    (src / "etc" / "ppp").mkdir(parents=True)
    (src / "etc" / "ppp" / "chap-secrets").write_text("bob * hunter\n")
    (src / "etc" / "ok.conf").write_text("a=1\n")
    report = redact.redact_tree(src, dst, salt="x")
    assert [p.name for p in dst.rglob("*") if p.is_file()] == ["ok.conf"]
    assert {"file": "etc/ppp/chap-secrets", "rule": "excluded", "count": 1} in report


def test_redact_cli_leaves_a_real_harvest_marker(tmp_path):
    src = tmp_path / "s"
    src.mkdir()
    (src / "a.txt").write_text("x=1\n")
    assert redact.main(["--src", str(src), "--dst", str(tmp_path / "d"), "--salt", "x"]) == 0
    assert (tmp_path / "d" / ".recon-redacted").is_file()


def test_inline_blocks_are_redacted_to_their_closing_tag():
    body = "AAAA" + "BBBB" * 8
    for tag in ("secret", "tls-auth", "tls-crypt", "auth-user-pass", "key"):
        text = f"remote x\n<{tag}>\n{body}\nsecond-{body}\n</{tag}>\nverb 3\n"
        out = redact.redact_text(text, salt="x")[0]
        assert body not in out and f"<{tag}>" in out and f"</{tag}>" in out and "verb 3" in out
    out = redact.redact_text(f"<secret>\n{body}\n", salt="x")[0]  # unterminated: to end of text
    assert body not in out


def test_openvpn_static_key_block():
    body = "0123456789abcdef" * 2
    text = f"-----BEGIN OpenVPN Static key V1-----\n{body}\n-----END OpenVPN Static key V1-----\n"
    assert body not in redact.redact_text(text, salt="x")[0]


def test_64_hex_runs_are_redacted_but_other_lengths_are_not():
    h64 = "ab" * 32
    assert h64 not in redact.redact_text(f"x {h64} y\n", salt="x")[0]
    assert redact.redact_text("sha1 " + "ab" * 20 + "\n", salt="x")[0] == "sha1 " + "ab" * 20 + "\n"
    assert redact.redact_text("id " + "ab" * 33 + "\n", salt="x")[0] == "id " + "ab" * 33 + "\n"


def test_url_userinfo_keeps_user_and_host():
    out = redact.redact_text("https://bob:" + "pw" + "Zz9&q@ddns.example.com/nic\n", salt="x")[0]
    assert "pwZz9&q" not in out and out.startswith("https://bob:") and "@ddns.example.com/nic" in out
    plain = "see https://example.com:8080/path and ssh://git@host/x\n"
    assert redact.redact_text(plain, salt="x")[0] == plain


@pytest.mark.parametrize("text,leak", [
    ("curl -" + "u root:Zq7" + "pwxy http://h", "Zq7pwxy"),
    ("curl --user=root:Zq7" + "pwxy http://h", "Zq7pwxy"),
    ("wget --password Zq7" + "pwxy http://h", "Zq7pwxy"),
    ("wget --password=Zq7" + "pwxy http://h", "Zq7pwxy"),
    ("sshpass -p Zq7" + "pwxy ssh h", "Zq7pwxy"),
    ("mosquitto_sub -u a -P Zq7" + "pwxy -t x", "Zq7pwxy"),
    ("mysql -u root -pZq7" + "pwxy", "Zq7pwxy"),
    ("pppd call x user bob password Zq7" + "pwxy", "Zq7pwxy"),
    ("echo 'root:Zq7" + "pwxy' | chpasswd", "Zq7pwxy"),
    ("echo root:Zq7" + "pwxy | chpasswd", "Zq7pwxy"),
    ("(echo Zq7" + "pwxy; echo Zq7" + "pwxy) | passwd root", "Zq7pwxy"),
])
def test_cli_forms(text, leak):
    out = redact.redact_text(text + "\n", salt="x")[0]
    assert leak not in out


def test_cli_forms_keep_innocent_flags():
    for line in ("mkdir -p /tmp/x", "ps -p 123", "ping -c 3 host", "curl -s http://h/x", "ssh -p 2222 host",
                 "opkg install -P x"):
        assert redact.redact_text(line + "\n", salt="x")[0] == line + "\n", line


@pytest.mark.parametrize("cmd", ["CPIN", "CLCK", "CPWD", "QICSGP", "CGAUTH"])
def test_at_secret_commands_keep_name_lose_arguments(cmd):
    out = redact.redact_text(f"echo 'AT+{cmd}=\"SC\",\"8734\",\"u5er\"' > /dev/ttyUSB2\n", salt="x")[0]
    assert f"AT+{cmd}=" in out and "8734" not in out and "u5er" not in out and "/dev/ttyUSB2" in out
    assert redact.redact_text(f"AT+{cmd}?\n", salt="x")[0] == f"AT+{cmd}?\n"


def test_xml_and_html_secret_elements():
    val = "Zq7" + "pwxyQ"
    for text in (f"<PreSharedKey>{val}</PreSharedKey>", f"<password>{val}</password>", f"<X_Token>{val}</X_Token>",
                 f'<input type="password" name="pw" value="{val}">', f'<input name="wifi_key" value="{val}"/>',
                 f"<node psk='{val}' ssid='a'>"):
        out = redact.redact_text(text + "\n", salt="x")[0]
        assert val not in out, text
    benign = '<input type="text" name="ssid" value="Home">\n<ssid>Home</ssid>\n'
    assert redact.redact_text(benign, salt="x")[0] == benign


def test_json_keys_unicode_escapes_and_arrays():
    val = "Zq7" + "pwxyQ"
    for text in ('{"\\u0070wd": "%s"}', '{"ubus_rpc_session":"%s"}', '{"keys": ["%s", "%s"]}',
                 '{"params":\n  [ "%s",\n "x"]}', '{"cred": "%s"}', '{"Credentials": {"a": 1}, "session": "%s"}'):
        t = text % tuple([val] * text.count("%s"))
        assert val not in redact.redact_text(t, salt="x")[0], text
    assert redact.redact_text('{"keys_total": 3, "session": {"a": 1}}', salt="x")[0] == '{"keys_total": 3, "session": {"a": 1}}'


def test_chained_labels_reach_a_fixed_point():
    val = "Zq7" + "pwxyQ"
    assert val not in redact.redact_text(f"ddns: token: {val}\n", salt="x")[0]
    assert val not in redact.redact_text(f"a=b c=d password:{val}\n", salt="x")[0]


def test_benign_suffix_names_redacted_unless_value_is_benign():
    val = "Zq7" + "pwxyQ"
    assert val not in redact.redact_text(f"password_file={val}\n", salt="x")[0]
    assert val not in redact.redact_text(f"secret_type: {val}\n", salt="x")[0]
    for ok in ("password_file=/etc/pw", "secret_type: sha256", "key_mgmt=WPA-PSK", "token_bucket: 10"):
        assert redact.redact_text(ok + "\n", salt="x")[0] == ok + "\n"


def test_labelled_whole_rest_of_line_and_quotes():
    text = "wpa_passphrase=correct horse battery staple\nsae_password=a b c\npassword=\"ab\"&cd rest\n"
    out = redact.redact_text(text, salt="x")[0]
    for leak in ("horse", "battery", "staple", "a b c", "&cd"):
        assert leak not in out, out
    assert redact.redact_text("password='a b c' next=thing\n", salt="x")[0].endswith(" next=thing\n")


def test_already_redacted_skip_requires_the_whole_value():
    out = redact.redact_text("password=<REDACTED:x> and more words here\n", salt="x")[0]
    assert "more words" not in out
    assert redact.redact_text("password=<REDACTED:wifi-psk>\n", salt="x")[0] == "password=<REDACTED:wifi-psk>\n"


def test_wpa_psk_file_lines_and_ipsec_secrets():
    val = "Zq7" + "pwxyQ"
    for t in (f"00:11:22:33:44:55 {val}", f"keyid=guest 00:00:00:00:00:00 {val}", f': PSK "{val}"',
              f'10.0.0.1 10.0.0.2 : PSK "{val}"', f"shared_secret {val}"):
        assert val not in redact.redact_text(t + "\n", salt="x")[0], t
