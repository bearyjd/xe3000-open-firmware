"""Adversarial redaction cases from the PR1 re-review (reviewer harness cases.py and cases2.py).

Fake secrets are assembled at runtime (see render); the file itself holds only @MARKER@ placeholders.
"""
import base64
import hashlib

SECRET_SETS = {
    "mid": "Tr0ub4dor" + "&3xyz",
    "short": "Kx7mPq" + "2Lw9",
    "long": "aZ3kQ9pLm2Xv7Rt5" + "Wn8Yb4Hc6Jd1Fg0s",
}
TOKEN = "Tr0ub" + "4dor3xyz" + "ABCDEF"
B1 = base64.b64encode(b"root:Tr0ub4dor").decode()
B2 = base64.b64encode(b"root:Tr0ub4dor&3xyz1234567890").decode()
H64 = hashlib.sha256(b"pass" + b"word").hexdigest()
WG = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYU" + "IgJBgB3fBmk"
OV = "8f3c2a1b9d7e6f5a" + "4b3c2d1e0f9a8b7c"
SH = "Tr0ub4dor" + "#3xyz"


def render(text: str, s: str) -> str:
    for marker, value in (("@S@", s), ("@T@", TOKEN), ("@B2@", B2), ("@B1@", B1), ("@H64@", H64),
                          ("@WG@", WG), ("@OV@", OV), ("@SH@", SH)):
        text = text.replace(marker, value)
    return text


CASES = [
 ('curl -' + 'u user:pass', 'curl -s -' + 'u root:@S@ http://192.168.8.1/rpc', '@S@'),
 ('curl --user', 'curl --' + 'user admin:@S@ https://x', '@S@'),
 ('URL userinfo', "option url 'https://bob:@S@@ddns.example.com/nic/update'", '@S@'),
 ('URL userinfo plain text', 'fetching http://bob:@S@@10.0.0.1/', '@S@'),
 ('URL ?token=', 'GET /cgi-bin/api?token=@S@&x=1', '@S@'),
 ('URL &password=', "wget 'http://h/update?user=bob&password=@S@'", '@S@'),
 ('Cookie header', 'Cookie: sysauth=@T@', '@T@'),
 ('Cookie two', 'Cookie: lang=en; Admin-Token=@T@', '@T@'),
 ('Set-Cookie', 'Set-Cookie: sysauth=@T@; path=/cgi-bin/luci', '@T@'),
 ('X-Api-Key', 'X-Api-Key: @T@', '@T@'),
 ('Authorization Basic spaces', 'Authorization:   Basic   @B1@', '@B1@'),
 ('Proxy-Authorization', 'Proxy-Authorization: Basic @B1@', '@B1@'),
 ('wpa_psk_file content line', '00:11:22:33:44:55 @S@', '@S@'),
 ('hostapd wpa_psk_file keyid', 'keyid=guest 00:00:00:00:00:00 @S@', '@S@'),
 ('sae_password with id', 'sae_password=@S@|id=foo', '@S@'),
 ('passphrase spaces in value', 'wpa_passphrase=correct horse battery staple', 'horse battery staple'),
 ('UCI key with spaces value', "\toption key 'correct horse battery staple'", 'horse battery staple'),
 ('shared_secret', 'shared_secret @S@', '@S@'),
 ('pppd chap-secrets', '"bob"  *  "@S@"  *', '@S@'),
 ('pap-secrets unquoted', 'bob * @S@ *', '@S@'),
 ('ovpn auth-user-pass file', 'bob\n@S@\n', '@S@'),
 ('openvpn <tls-auth> static key', '<tls-auth>\n-----BEGIN OpenVPN Static key V1-----\n@OV@\n-----END OpenVPN Static key V1-----\n</tls-auth>', '@OV@'),
 ('openvpn askpass inline', 'askpass /etc/openvpn/pw\n<secret>\n@S@\n</secret>', '@S@'),
 ("wg showconf pubkey no '='", 'PrivateKey = @WG@', '@WG@'),
 ('wg key in yaml list', 'keys:\n  - @WG@=', '@WG@='),
 ('64-hex PSK bare', 'wpa_psk 1: @H64@', '@H64@'),
 ("64-hex PSK under 'psk' key via iw", 'PMK: @H64@', '@H64@'),
 ('export FOO_TOKEN', 'export FOO_TOKEN=@S@', '@S@'),
 ('export quoted with spaces', 'export API_SECRET="correct horse battery staple"', 'horse battery staple'),
 ('shell local var', 'local pass_word=@S@', '@S@'),
 ('YAML password: quoted with #', 'password: "@SH@"', '@SH@'),
 ('YAML block scalar', 'password: |\n  @S@\n', '@S@'),
 ('YAML key with space name', 'Admin Password: @S@', '@S@'),
 ('JSON escaped quote', '{"pass\\u0077ord": "@S@"}', '@S@'),
 ('JSON key unicode escape pwd', '{"\\u0070assword":"@S@"}', '@S@'),
 ('JSON numeric password', '{"password": 82736451}', '82736451'),
 ('JSON value array', '{"keys": ["@S@"]}', '@S@'),
 ('JSON nested secret obj', '{"wifi":{"ssid":"Home","encryption":"psk2","key":"@S@"}}', '@S@'),
 ("ubus JSON key 'pwd'", '{"pwd": "@S@"}', '@S@'),
 ("ubus JSON key 'pw'", '{"pw":"@S@"}', '@S@'),
 ("JSON 'credential'", '{"credential":"@S@"}', '@S@'),
 ("JSON 'secret_value' benign tail?", '{"secret_value":"@S@"}', '@S@'),
 ("JSON key 'sae_pwe' fine / 'wpa_key_mgmt'", '{"wpa_key_mgmt":"SAE","key":"@S@"}', '@S@'),
 ('UCI ddns password', "\toption password '@S@'", '@S@'),
 ('UCI glconfig hash', "\toption hash 'a1b2c3d4e5f6'", 'a1b2c3d4e5f6'),
 ('UCI auth_key name ok', "\toption auth_key '@S@'", '@S@'),
 ('ppp_pass', 'ppp_pass=@S@', '@S@'),
 ('ssid_password', 'ssid_password: @S@', '@S@'),
 ('pre-shared-key strongswan', 'pre-shared-key = @S@', '@S@'),
 ('ipsec.secrets PSK', ': PSK "@S@"', '@S@'),
 ('ipsec.secrets addr PSK', '10.0.0.1 10.0.0.2 : PSK "@S@"', '@S@'),
 ('PSK uppercase name file field', 'PSK=@S@', '@S@'),
 ('key name with digit tail key1', "\toption key1 '@S@'", '@S@'),
 ('wpa_supplicant multiline network', 'network={\n\tssid="Home"\n\tpsk="@S@"\n}', '@S@'),
 ('wep_key0', 'wep_key0=@S@', '@S@'),
 ('password_file benign suffix but inline value', 'password_file=@S@', '@S@'),
 ('key_type benign suffix with value', 'secret_type: @S@', '@S@'),
 ('value split continuation', 'PASSWORD="Tr0ub\\\n4dor&3xyz"', '4dor&3xyz'),
 ('space before = in key', 'password = @S@', '@S@'),
 ('arrow separator lua', "password => '@S@'", '@S@'),
 ('lua table', "local cfg = { password = '@S@' }", '@S@'),
 ('lua call arg', "luci.sys.user.setpasswd('root', '@S@')", '@S@'),
 ('chpasswd stdin', "echo 'root:@S@' | chpasswd", '@S@'),
 ('passwd -p', '(echo @S@; echo @S@) | passwd root', '@S@'),
 ('mqtt -P', 'mosquitto_pub -h h -u bob -P @S@ -t x', '@S@'),
 ('sshpass', 'sshpass -p @S@ ssh root@h', '@S@'),
 ('AT+CGAUTH', 'AT+CGAUTH=1,1,"bob","@S@"', '@S@'),
 ('AT+QICSGP', 'AT+QICSGP=1,1,"internet","bob","@S@",1', '@S@'),
 ('AT+CPIN', 'AT+CPIN="4321"', '4321'),
 ('AT+CLCK', 'AT+CLCK="SC",0,"4321"', '4321'),
 ('ubus call args', 'ubus call rpc-sys password_set \'{"user":"root","password":"@S@"}\'', '@S@'),
 ('GL sid in query', '/rpc?sid=@T@', '@T@'),
 ('GL JSON-RPC sid named', '{"jsonrpc":"2.0","method":"call","params":["@T@","system","get_info",{}]}', '@T@'),
 ('GL JSON-RPC sid whitespace newline', '"params": [\n  "@T@", "x"]', '@T@'),
 ('ubus session list dump', '"ubus_rpc_session": "@T@"', '@T@'),
 ('base64 blob unlabelled', 'data @B2@', '@B2@'),
 ('html input value', '<input type="password" name="pw" value="@S@">', '@S@'),
 ('XML element', '<password>@S@</password>', '@S@'),
 ('XML PreSharedKey tr069', '<PreSharedKey>@S@</PreSharedKey>', '@S@'),
 ('logread printed', 'daemon.info hostapd: wlan0: set psk to @S@', '@S@'),
 ('fullwidth colon', 'password：@S@', '@S@'),
 ('dash-case Password header', 'X-Password: @S@', '@S@'),
 ('uci show quoted', "wireless.default_radio0.key='@S@'", '@S@'),
 ('uci show key with space inside value', "wireless.default_radio0.key='correct horse battery'", 'horse battery'),
 ('nvram style', 'wl0_wpa_psk=@S@', '@S@'),
 ('password with leading quote mismatch', "password='Tr0ub4dor 3xyz", '3xyz'),
 ('logread tag: token:', 'Oct 26 user.notice ddns: token: @S@', '@S@'),
 ('tag: password: (colon chain)', 'Mon Oct 26 daemon.err openvpn[123]: password: @S@', '@S@'),
 ('k=v k2=secret chained no space', 'user=bob:password:@S@', '@S@'),
 ('dhcp opt then key', 'mode: ap key: @S@', '@S@'),
 ('multi labels on one line yaml flow', '{user: bob, password: @S@}', '@S@'),
 ('json unquoted js', "{password:'@S@'}", '@S@'),
 ('ini with semicolon', 'Password=Tr0ub4dor;3xyz', '3xyz'),
 ('trailing comma json-ish', 'password: @S@,', '@S@'),
 ('value starts with quote char inside', 'password="Tr0ub4dor"&3xyz', '&3xyz'),
 ('tab separated', 'password\t@S@', '@S@'),
 ('double colon', 'password:: @S@', '@S@'),
 ('JSON key with escaped quote value', '{"password":"Tr0ub\\"4dor&3xyz"}', '4dor&3xyz'),
 ("gl json 'passwd' in list", '{"wifi":[{"ssid":"a","passwd":"@S@"}]}', '@S@'),
]
