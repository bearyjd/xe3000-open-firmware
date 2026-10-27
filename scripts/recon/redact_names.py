"""Which names look like secrets, and which values are obviously not (shared by the redaction rules).

Names fall in three tiers. `strong` names are credentials (password, token, psk...): their value is never exempt,
whatever it looks like. `medium` names are ambiguous (auth, sid, key, hash...): a plainly benign value is left alone.
`weak` names are metadata about a secret (password_file, key_mgmt): redacted only when the value is not benign.
"""
from __future__ import annotations

import re

# Inside one redact_text() call our own placeholders carry a private marker character after "<" (input containing the
# marker is stripped first), so a rule can tell its own earlier output from text that merely LOOKS like a placeholder.
SENTINEL = "\ue000"
PLACEHOLDER = "<" + SENTINEL + "REDACTED:{rule}>"
_PLACEHOLDER_RE = re.compile(rf"""\s*["']?<{SENTINEL}?REDACTED:[\w-]+>["']?\s*""")
_PLACEHOLDER_THEN_PUNCT = re.compile(r"""\s*["']?<REDACTED:[\w-]+>["']?[\s,;)}\]]*""")  # nothing secret can follow
_OWN_PLACEHOLDER_START = re.compile(rf"""["']?<{SENTINEL}REDACTED:[\w-]+>["']?(?:\s|$)""")
_CAMEL = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")

STRONG_EXACT = frozenset({"pw", "pwd", "cred", "credential", "credentials"})
STRONG_TAILS = ("passwd", "password", "passphrase", "secret", "token", "psk", "cookie", "bindcode", "passcode",
                "authcode", "pairingcode")
STRONG_FIRST = frozenset({"secret", "psk", "password", "passwd", "passphrase", "token", "pwd", "pw", "cred",
                          "credential", "credentials"})
MEDIUM_EXACT = frozenset({"pass", "sid", "pin", "puk", "pincode", "private", "cert", "username", "auth", "key"})
MEDIUM_TAILS = ("hash",)
JSON_STRONG = frozenset({"session", "sessionid", "keys", "secrets", "tokens", "passwords", "hashes", "sids", "creds"})
KEY_PREFIXES = ("api", "wep", "auth", "ssh", "enc", "private", "secret", "master", "shared", "session", "license",
                "access", "psk", "pre", "wpa", "tls", "aes", "priv", "sae", "vpn", "ftp", "app", "crypt", "sign")
VALUE_WORDS = frozenset({"value", "data", "str", "string", "text", "new", "old", "current"})
PUBLIC = frozenset({"pub", "public"})
# A secret-ish name that ends in one of these is metadata (password_file=/x, key_mgmt=WPA-PSK).
WEAK_LAST = frozenset({"mgmt", "type", "mode", "policy", "len", "length", "size", "count", "file", "path", "enabled",
                       "timeout", "lifetime", "interval", "proto", "alg", "algs", "algo", "bucket", "id", "name"})
TYPE_NAMES = frozenset({"string", "integer", "boolean", "number", "object", "array", "double", "int", "bool"})

_ENUM = frozenset({"true", "false", "yes", "no", "on", "off", "present", "absent", "none", "null", "enabled",
                   "disabled", "string", "integer", "boolean", "object", "array", "number", "double", "int", "bool",
                   "crc32c", "crc32", "md5", "sha1", "sha224", "sha256", "sha384", "sha512", "eap", "sae", "psk",
                   "wpa", "open", "set", "unset", "auto", "default", "(hidden)", "(null)", "***", "required",
                   "invalid", "empty", "missing", "strict", "relaxed", "loose", "medium", "low", "high",
                   "complex", "simple", "basic", "legacy", "any", "all", "chap", "pap", "mschap", "mschapv2",
                   "chap-md5", "rsa", "ec", "ecdsa", "ed25519", "aes", "aes128", "aes256"})
_WPA = re.compile(r"(?:wpa\d?|sae|psk\d?|eap|owe|ccmp|tkip|none|open|ft|sha\d+)(?:[-+_ /]\w+)*", re.IGNORECASE)
_KEY_TOKEN = re.compile(rf"(?:{'|'.join(KEY_PREFIXES)})key")


def tag(rule: str) -> str:
    return PLACEHOLDER.format(rule=rule)


def is_placeholder(value: str) -> bool:
    """True only if the ENTIRE value is one redaction placeholder (optionally quoted)."""
    return bool(_PLACEHOLDER_RE.fullmatch(value))


def is_handled(value: str) -> bool:
    """A whole-value placeholder, or one this call emitted itself followed by text. A plain `<REDACTED:x>` followed by
    text may be forged, so it does not count."""
    return (is_placeholder(value) or bool(_PLACEHOLDER_THEN_PUNCT.fullmatch(value))
            or bool(_OWN_PLACEHOLDER_START.match(value.lstrip())))


def is_benign_value(value: str) -> bool:
    v = value.strip().strip("'\"").strip()
    if not v or re.fullmatch(r"\d{1,2}", v) or v.lower() in _ENUM or _WPA.fullmatch(v):
        return True
    return v.startswith("/") and len(v) > 1 and " " not in v


def _tier(token: str, json_mode: bool) -> str | None:
    if token in STRONG_EXACT or token.endswith(STRONG_TAILS) or (json_mode and token in JSON_STRONG):
        return "strong"
    if token in MEDIUM_EXACT or token.endswith(MEDIUM_TAILS) or _KEY_TOKEN.fullmatch(token):
        return "medium"
    return None


def classify(name: str, json_mode: bool = False) -> str | None:
    """'strong', 'medium', 'weak' (metadata name such as password_file) or None."""
    parts = [p for p in re.split(r"[^a-z0-9]+", _CAMEL.sub(" ", name).lower()) if p]
    toks = [re.sub(r"\d+$", "", p) or p for p in parts]
    while len(toks) > 1 and toks[-1] in VALUE_WORDS:
        toks.pop()
    if not toks:
        return None
    full = list(toks)
    weak = False
    if toks[-1] in WEAK_LAST and len(toks) > 1:
        toks, weak = toks[:-1], True
    if len(toks) > 1 and toks[-2] in PUBLIC:
        return None
    last = toks[-1]
    tier = _tier(last, json_mode) or (_tier(toks[-2] + last, json_mode) if len(toks) > 1 else None)
    if tier is None and len(full) > 1:
        if full[0] in STRONG_FIRST:
            tier = "strong"
        elif full[0] in ("key", "pass"):
            tier = "medium"
    if tier is None:
        return None
    return "weak" if weak else tier


def should_redact(name: str, value: str, json_mode: bool = False) -> bool:
    kind = classify(name, json_mode)
    if kind is None or is_handled(value):
        return False
    if kind == "strong":  # credentials have no benign-value exemption, except ubus type names in JSON
        return not (json_mode and value.strip().strip("\"'").lower() in TYPE_NAMES)
    return not is_benign_value(value)
