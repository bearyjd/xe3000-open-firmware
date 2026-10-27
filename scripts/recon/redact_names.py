"""Which names look like secrets, and which values are obviously not (shared by the redaction rules)."""
from __future__ import annotations

import re

PLACEHOLDER = "<REDACTED:{rule}>"
_PLACEHOLDER_RE = re.compile(r"""\s*["']?<REDACTED:[\w-]+>["']?\s*""")
# Tags this module emits. A value that merely STARTS with one of them (and then continues after whitespace) was
# redacted earlier in the same run, so it is left alone; an unknown tag followed by text is not trusted.
KNOWN_TAGS = ("pem-block", "json-secret", "auth-header", "wifi-psk", "wg-key", "uci-sensitive", "url-userinfo",
              "cli-secret", "yaml-block", "labelled-secret", "at-secret", "markup-secret", "wpa-psk-line",
              "ipsec-secret", "ppp-secret", "pw-hash", "imei", "imsi", "iccid", "token", "hex-psk", "b64-blob", "eui64",
              "serial", "entropy-word", "url-query")
STARTS_WITH_PLACEHOLDER = re.compile(r"""["']?<REDACTED:(?:%s)>["']?(?:\s|$)""" % "|".join(KNOWN_TAGS))
_CAMEL = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")

# Exact tokens that mark a secret; tails that mark one when a token ends with them.
EXACT = frozenset({"pass", "pw", "pwd", "sid", "pin", "puk", "pincode", "private", "cert", "username", "auth",
                   "cred", "credential", "credentials", "key"})
JSON_EXACT = frozenset({"session", "sessionid", "keys", "secrets", "tokens", "passwords", "hashes", "sids", "creds"})
TAILS = ("passwd", "password", "passphrase", "secret", "token", "psk", "hash", "cookie", "bindcode", "passcode",
         "authcode", "pairingcode")
# A name whose FIRST token is one of these is secret too (secret_blob, psk_hex, key_material, password_hash).
FIRST_SECRET = frozenset({"secret", "psk", "key", "password", "passwd", "passphrase", "token", "pass", "pwd", "pw",
                          "cred", "credential", "credentials"})
KEY_PREFIXES = ("api", "wep", "auth", "ssh", "enc", "private", "secret", "master", "shared", "session", "license",
                "access", "psk", "pre", "wpa", "tls", "aes", "priv", "sae", "vpn", "ftp", "app", "crypt", "sign")
VALUE_WORDS = frozenset({"value", "data", "str", "string", "text", "new", "old", "current"})
PUBLIC = frozenset({"pub", "public"})
# A secret-ish name that ends in one of these is only a secret when its value is not benign (password_file=/x).
WEAK_LAST = frozenset({"mgmt", "type", "mode", "policy", "len", "length", "size", "count", "file", "path", "enabled",
                       "timeout", "lifetime", "interval", "proto", "alg", "algs", "algo", "bucket", "id", "name"})

_ENUM = frozenset({"true", "false", "yes", "no", "on", "off", "present", "absent", "none", "null", "enabled",
                   "disabled", "string", "integer", "boolean", "object", "array", "number", "double", "int", "bool",
                   "crc32c", "crc32", "md5", "sha1", "sha224", "sha256", "sha384", "sha512", "eap", "sae", "psk",
                   "wpa", "open", "set", "unset", "auto", "default", "(hidden)", "(null)", "***", "required",
                   "invalid", "empty", "missing", "strict", "relaxed", "loose", "medium", "low", "high",
                   "complex", "simple", "basic", "legacy", "any", "all", "chap", "pap", "mschap", "mschapv2", "chap-md5",
                   "rsa", "ec", "ecdsa", "ed25519", "aes", "aes128", "aes256"})
_WPA = re.compile(r"(?:wpa\d?|sae|psk\d?|eap|owe|ccmp|tkip|none|open|ft|sha\d+)(?:[-+_ /]\w+)*", re.IGNORECASE)
_KEY_TOKEN = re.compile(rf"(?:{'|'.join(KEY_PREFIXES)})key")


def tag(rule: str) -> str:
    return PLACEHOLDER.format(rule=rule)


def is_placeholder(value: str) -> bool:
    """True only if the ENTIRE value is one redaction placeholder (optionally quoted)."""
    return bool(_PLACEHOLDER_RE.fullmatch(value))


def is_handled(value: str) -> bool:
    """Whole placeholder, or one of our own placeholders followed by text from a previous pass."""
    return is_placeholder(value) or bool(STARTS_WITH_PLACEHOLDER.match(value.lstrip()))


def is_benign_value(value: str) -> bool:
    v = value.strip().strip("'\"").strip()
    if not v or re.fullmatch(r"\d{1,2}", v) or v.lower() in _ENUM or _WPA.fullmatch(v):
        return True
    return v.startswith("/") and len(v) > 1 and " " not in v


def _secret_token(token: str, json_mode: bool) -> bool:
    return (token in EXACT or token.endswith(TAILS) or bool(_KEY_TOKEN.fullmatch(token))
            or (json_mode and token in JSON_EXACT))


def classify(name: str, json_mode: bool = False) -> str | None:
    """'strong', 'weak' (benign-suffix name such as password_file) or None."""
    parts = [p for p in re.split(r"[^a-z0-9]+", _CAMEL.sub(" ", name).lower()) if p]
    toks = [re.sub(r"\d+$", "", p) or p for p in parts]
    while len(toks) > 1 and toks[-1] in VALUE_WORDS:
        toks.pop()
    if not toks:
        return None
    weak, full = False, list(toks)
    if toks[-1] in WEAK_LAST and len(toks) > 1:
        toks, weak = toks[:-1], True
    if len(toks) > 1 and toks[-2] in PUBLIC:
        return None
    last = toks[-1]
    joined = toks[-2] + last if len(toks) > 1 else ""
    if _secret_token(last, json_mode) or (joined and _secret_token(joined, json_mode)):
        return "weak" if weak else "strong"
    if len(full) > 1 and full[0] in FIRST_SECRET:
        return "weak" if full[-1] in WEAK_LAST else "strong"
    return None


def should_redact(name: str, value: str, json_mode: bool = False) -> bool:
    return classify(name, json_mode) is not None and not is_handled(value) and not is_benign_value(value)
