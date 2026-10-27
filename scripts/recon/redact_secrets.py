"""Secret-bearing text forms: key blocks, JSON, UCI, labelled values, URLs, command lines, markup, AT commands.

Each step is `(text, counts) -> text`. Values that are already a whole placeholder are never touched, so every
step is idempotent. This is a blacklist: it is one layer of several (see PRP 0001 section 5).
"""
from __future__ import annotations

import json
import re
from collections import Counter

from recon.redact_ids import WG_B64, Step, chain, sub_value, sub_whole
from recon.redact_names import classify, is_benign_value, is_placeholder, should_redact, tag

_I = re.IGNORECASE
_M = re.IGNORECASE | re.MULTILINE
PIN_WORDS = r"pin|pincode|puk"

# ---- key blocks -------------------------------------------------------------------------------------------
KEY_KIND = r"(?:[A-Za-z0-9 ]*PRIVATE KEY(?: BLOCK)?|OpenVPN Static key V1)"
PEM = re.compile(rf"-----BEGIN {KEY_KIND}-----.*?(?:-----END {KEY_KIND}-----|\Z)", re.DOTALL | _I)
INLINE_BLOCK = re.compile(r"(<(secret|tls-auth|tls-crypt|tls-crypt-v2|auth-user-pass|key|pkcs12)>)(.*?)(</\2>|\Z)",
                          re.DOTALL | _I)


def _inline_blocks(text: str, counts: Counter) -> str:
    def repl(m: re.Match) -> str:
        if is_placeholder(m.group(3)):
            return m.group(0)
        counts["pem-block"] += 1
        return m.group(1) + tag("pem-block") + m.group(4)
    return INLINE_BLOCK.sub(repl, text)


# ---- JSON --------------------------------------------------------------------------------------------------
JSON_KV = re.compile(
    r'("((?:[^"\\\n]|\\.)*)"[ \t\r\n]*:[ \t\r\n]*)'
    r'("(?:[^"\\\n]|\\.)*"|-?\d+(?:\.\d+)?|true|false|null|\[[^\[\]{}]*\])')
JSON_RPC_SID = re.compile(r'("params"\s*:\s*\[\s*")([^"\n]{8,})(")', _I)


def _decode_key(raw: str) -> str:
    try:
        return json.loads(f'"{raw}"')
    except ValueError:
        return raw


def _json_secret(text: str, counts: Counter) -> str:
    def kv(m: re.Match) -> str:
        key, value = _decode_key(m.group(2)), m.group(3)
        if not should_redact(key, value, json_mode=True):
            return m.group(0)
        counts["json-secret"] += 1
        replacement = f'"{tag("json-secret")}"'
        return m.group(1) + (f"[{replacement}]" if value.startswith("[") else replacement)

    def sid(m: re.Match) -> str:
        if is_placeholder(m.group(2)):
            return m.group(0)
        counts["json-secret"] += 1
        return m.group(1) + tag("json-secret") + m.group(3)
    return JSON_RPC_SID.sub(sid, JSON_KV.sub(kv, text))


# ---- UCI and shell -----------------------------------------------------------------------------------------
UCI = re.compile(r"^([ \t]*(?:option|list)[ \t]+)(\S+)([ \t]+)(.+?)([ \t]*)$", re.MULTILINE)
UCI_SHELL = re.compile(
    r"(\buci[ \t]+(?:-\S+[ \t]+)*(?:set|add_list)[ \t]+)([^\s=]+)(=)('[^'\n]*'|\"[^\"\n]*\"|[^\s;&|]+)")


def _uci(text: str, counts: Counter) -> str:
    def line(m: re.Match) -> str:
        if not should_redact(m.group(2), m.group(4)):
            return m.group(0)
        counts["uci-sensitive"] += 1
        return m.group(1) + m.group(2) + m.group(3) + tag("uci-sensitive") + m.group(5)

    def shell(m: re.Match) -> str:
        if not should_redact(m.group(2), m.group(4)):
            return m.group(0)
        counts["uci-sensitive"] += 1
        return m.group(1) + m.group(2) + m.group(3) + tag("uci-sensitive")
    return UCI_SHELL.sub(shell, UCI.sub(line, text))


_VALUE = (r"""((?:"(?:[^"\\\n]|\\[\s\S])*"|'(?:[^'\\\n]|\\[\s\S])*')\S*|\S(?:[^\n\\]|\\[\s\S])*)""")
WIFI = re.compile(
    r"(?<![A-Za-z0-9])((?:[A-Za-z0-9_.\-]*(?:psk|sae_password|wpa_passphrase|passw(?:or)?d|passphrase)|"
    rf"(?:[A-Za-z0-9_.\-]*[_.\-])?(?:{PIN_WORDS}))[ \t]*=[ \t]*)" + _VALUE, _M)
WG_LINE = re.compile(r"(?<![A-Za-z0-9])((?:PrivateKey|PresharedKey)[ \t]*=[ \t]*)" + _VALUE, _M)
WG_OPT = re.compile(r"^([ \t]*(?:option|list)[ \t]+(?:private_key|preshared_key)[ \t]+)(.+)$", _M)

# ---- labelled values (NAME = value, NAME: value, NAME => value, NAME:: value, NAME<TAB>value) -----------------
LABELLED = re.compile(
    r"(?<![A-Za-z0-9])([A-Za-z0-9_.\-]*[A-Za-z0-9_])"
    r"(?:[ \t]*(?:=>|::|[=:：])[ \t]*|\t+)"
    r"""(?:("(?:[^"\\\n]|\\[\s\S])*"|'(?:[^'\\\n]|\\[\s\S])*')(\S*)|((?:[^\n\\]|\\[\s\S])*))""")
NO_VALUE_START = "|>:="


def _labelled(text: str, counts: Counter) -> str:
    """Whole value (quoted to its closing quote, else the rest of the line). A name that is not secret does not
    hide a secret inside its value, so scanning resumes at the value start (ddns: token: X)."""
    out, pos = [], 0
    while True:
        m = LABELLED.search(text, pos)
        if m is None:
            break
        quoted, ext, rest = m.group(2), m.group(3), m.group(4)
        value = (quoted + ext) if quoted else rest.rstrip()
        start = m.start(2) if quoted else m.start(4)
        if (not value or value[0] in NO_VALUE_START
                or not should_redact(m.group(1), value)):
            out.append(text[pos:start])
            pos = start if start > pos else m.end()
            continue
        counts["labelled-secret"] += 1
        out.append(text[pos:start] + tag("labelled-secret"))
        pos = start + len(value)
    out.append(text[pos:])
    return "".join(out)


YAML_BLOCK = re.compile(r"^([ \t]*([\w.\-]+)[ \t]*:[ \t]*[|>][-+0-9]*[ \t]*\n)((?:[ \t]+[^\n]*(?:\n|\Z)|[ \t]*\n)+)",
                        re.MULTILINE)


def _yaml_block(text: str, counts: Counter) -> str:
    def repl(m: re.Match) -> str:
        body = m.group(3)
        if classify(m.group(2)) is None or is_placeholder(body):
            return m.group(0)
        counts["yaml-block"] += 1
        indent = re.match(r"[ \t]*", body).group(0) or "  "
        return m.group(1) + indent + tag("yaml-block") + "\n"
    return YAML_BLOCK.sub(repl, text)


# ---- URLs and command lines --------------------------------------------------------------------------------
URL_USERINFO = re.compile(r"(\b[A-Za-z][A-Za-z0-9+.\-]*://[^\s/:@'\"<>]+:)([^\s/@'\"<>]+)(@)")
CMD_SECRET = re.compile(
    r"((?<![\w-])(?:-u|--user)(?:[ \t]+|=)[^\s:]+:)(\S+)"
    r"|((?<![\w-])--(?:password|passwd|passphrase)(?![\w-])(?:[ \t]+|=))(?!-)(\S+)"
    r"|(\b(?:sshpass|mysql|mysqladmin|mosquitto_pub|mosquitto_sub|redis-cli|smbclient|ldapsearch|ldapadd|ldapmodify)"
    r"\b[^\n|;&]*?[ \t](?:-p|-P|-w)(?:[ \t]+|=)?)(?!-)(\S+)"
    r"|(\bpppd\b[^\n]*?\bpassword[ \t]+)(\S+)"
    r"|((?:\bsetpass(?:wd|word)|\bset_password)\([^,()\n]*,[ \t]*)(['\"][^'\"\n]*['\"])"
    r"|(\b(?:psk|passphrase|password|passwd|secret|token)[ \t]+(?:to|is|was)[ \t]+)(\S+)")
CHPASSWD = re.compile(r"((?:echo|printf)[ \t]+(?:-\w+[ \t]+)*['\"]?[\w.\-]+:)([^|\n'\"]*?)(['\"]?[ \t]*\|[ \t]*chpasswd\b)")
PASSWD_PIPE = re.compile(r"(\([ \t]*echo[ \t]+)([^;)\n]+?)([ \t]*;[ \t]*echo[ \t]+)([^;)\n]+?)([ \t]*\)[ \t]*\|[ \t]*passwd\b)")
BARE_SECRET = re.compile(r"^([ \t]*[A-Za-z0-9]*[_.\-][\w.\-]*(?:secret|psk|passwd|password|passphrase)[ \t]+)(?![=:])(\S.*)$",
                         _M)
AT_SECRET = re.compile(r"(\bAT\+(?:CPIN|CLCK|CPWD|QICSGP|CGAUTH)=)([^\s']+)", _I)
PPP_SECRETS = re.compile(r"^([ \t]*\"?[\w.@\-]+\"?[ \t]+\*[ \t]+)(\"[^\"\n]*\"|[^\s\"]+)([ \t]+\S+)?[ \t]*$", _M)
IPSEC = re.compile(r"(:[ \t]*(?:PSK|RSA|ECDSA|EAP|XAUTH|NTLM|PIN)[ \t]+)([\"'].*|0[sx]\S+)$", _M)
WPA_PSK_LINE = re.compile(r"^((?:keyid=\S+[ \t]+)?(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}[ \t]+)(\S+)[ \t]*$", _M)


def _cli(text: str, counts: Counter) -> str:
    def cmd(m: re.Match) -> str:
        pairs = [(m.group(i), m.group(i + 1)) for i in range(1, 13, 2) if m.group(i) is not None]
        prefix, secret = pairs[0]
        if is_placeholder(secret) or (prefix.rstrip().endswith(("to", "is", "was")) and is_benign_value(secret)):
            return m.group(0)
        counts["cli-secret"] += 1
        return prefix + tag("cli-secret")

    def chpasswd(m: re.Match) -> str:
        if is_placeholder(m.group(2)):
            return m.group(0)
        counts["cli-secret"] += 1
        return m.group(1) + tag("cli-secret") + m.group(3)

    def pipe(m: re.Match) -> str:
        if is_placeholder(m.group(2)):
            return m.group(0)
        counts["cli-secret"] += 1
        return m.group(1) + tag("cli-secret") + m.group(3) + tag("cli-secret") + m.group(5)
    text = PASSWD_PIPE.sub(pipe, CHPASSWD.sub(chpasswd, CMD_SECRET.sub(cmd, text)))
    return sub_value(BARE_SECRET, "cli-secret")(text, counts)


def _url(text: str, counts: Counter) -> str:
    def repl(m: re.Match) -> str:
        counts["url-userinfo"] += 1
        return m.group(1) + tag("url-userinfo") + m.group(3)
    return URL_USERINFO.sub(repl, text)


# ---- markup ------------------------------------------------------------------------------------------------
XML_ELEM = re.compile(r"(<([A-Za-z_][\w:.\-]*)\b[^<>]*>)([^<>\n]+)(</\2>)")
TAG = re.compile(r"<[A-Za-z][\w:-]*\b[^<>]*>")
ATTR = re.compile(r"""([\w:-]+)([ \t]*=[ \t]*)("[^"]*"|'[^']*')""")


def _markup(text: str, counts: Counter) -> str:
    def element(m: re.Match) -> str:
        if not should_redact(m.group(2), m.group(3)):
            return m.group(0)
        counts["markup-secret"] += 1
        return m.group(1) + tag("markup-secret") + m.group(4)

    def html(m: re.Match) -> str:
        attrs = {a.group(1).lower(): a.group(3).strip("'\"") for a in ATTR.finditer(m.group(0))}
        marked = (attrs.get("type") == "password"
                  or any(classify(attrs.get(k, "")) is not None for k in ("name", "id") if attrs.get(k)))

        def attr(a: re.Match) -> str:
            name, raw = a.group(1).lower(), a.group(3)
            secret_attr = should_redact(name, raw) if name != "value" else marked and not (
                is_placeholder(raw) or is_benign_value(raw))
            if not secret_attr:
                return a.group(0)
            counts["markup-secret"] += 1
            return a.group(1) + a.group(2) + raw[0] + tag("markup-secret") + raw[-1]
        return ATTR.sub(attr, m.group(0))
    return TAG.sub(html, XML_ELEM.sub(element, text))


SECRET_RULES: tuple[tuple[str, Step], ...] = (
    ("pem-block", chain(sub_whole(PEM, "pem-block"), _inline_blocks)),
    ("json-secret", _json_secret),
    ("auth-header", sub_value(re.compile(
        r"(\b(?:Proxy-)?Authorization[ \t]*[:=][ \t]*(?:[A-Za-z][\w-]*[ \t]+)?)(\S+)", _I), "auth-header")),
    ("wifi-psk", sub_value(WIFI, "wifi-psk")),
    ("wg-key", chain(sub_value(WG_LINE, "wg-key"), sub_value(WG_OPT, "wg-key"), sub_whole(WG_B64, "wg-key"))),
    ("uci-sensitive", _uci),
    ("url-userinfo", _url),
    ("cli-secret", _cli),
    ("yaml-block", _yaml_block),
    ("labelled-secret", _labelled),
    ("at-secret", sub_value(AT_SECRET, "at-secret")),
    ("markup-secret", _markup),
    ("wpa-psk-line", sub_value(WPA_PSK_LINE, "wpa-psk-line")),
    ("ipsec-secret", sub_value(IPSEC, "ipsec-secret")),
    ("ppp-secret", sub_value(PPP_SECRETS, "ppp-secret")),
)
