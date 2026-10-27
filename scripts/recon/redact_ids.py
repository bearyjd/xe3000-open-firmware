"""Identifier-style redaction: crypt hashes, IMEI/IMSI/ICCID, tokens, key blobs, MACs and EUI-64 addresses."""
from __future__ import annotations

import hashlib
import re
from collections import Counter
from collections.abc import Callable

from recon.redact_names import is_handled, tag

Step = Callable[[str, Counter], str]
LABEL_SEP = r"""[\s:=\x27"]{0,6}"""
MAC_HASH_HEX_LEN = 6
PSEUDONYM_ALPHABET = "ghjkmnpqrstuvwxyz"  # no hex digits: a pseudonymized MAC is never matched (and re-hashed) again

PW_HASH = re.compile(r"\$(?:1|5|6|y|p)\$[./0-9A-Za-z$,=-]{6,}")
IMEI_LABEL = re.compile(rf"(\b(?:IMEI|MEID)\b{LABEL_SEP})([0-9A-Fa-f]{{14,18}})", re.IGNORECASE)
DIGITS15 = re.compile(r"(?<![0-9A-Za-z])\d{15}(?![0-9A-Za-z])")
IMSI_LABEL = re.compile(rf"(\bIMSI\b{LABEL_SEP})(\d{{6,15}})", re.IGNORECASE)
IMSI_BARE = re.compile(r"(?<![0-9A-Za-z])[2-7]\d{14}(?![0-9A-Za-z])")  # MCC 2xx-7xx
ICCID_BARE = re.compile(r"(?<![0-9A-Za-z])89\d{17,18}(?![0-9A-Za-z])")
ICCID_LABEL = re.compile(rf"(\bICCID\b{LABEL_SEP})(\d{{10,22}})", re.IGNORECASE)
BEARER = re.compile(r"(\bBearer\s+)[A-Za-z0-9._~+/=-]{8,}", re.IGNORECASE)
SK_KEY = re.compile(r"\bsk-[A-Za-z0-9_-]{16,}")
HEX64 = re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{64}(?![0-9A-Fa-f])")
B64_BLOB = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{23,}={1,2}(?![A-Za-z0-9+/=])")
WG_B64 = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{43}=(?![A-Za-z0-9+/=])")
MAC_COLON = re.compile(r"\b([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){2}):([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){2})\b")
MAC_DASH = re.compile(r"\b([0-9A-Fa-f]{2}(?:-[0-9A-Fa-f]{2}){2})-([0-9A-Fa-f]{2}(?:-[0-9A-Fa-f]{2}){2})\b")
EUI64 = re.compile(r"(?<![0-9A-Za-z:])((?:[0-9A-Fa-f]{0,4}:){1,8})[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{2}ff:fe[0-9A-Fa-f]{2}:"
                   r"[0-9A-Fa-f]{1,4}(?![0-9A-Za-z:])", re.IGNORECASE)


def luhn_ok(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch) * (2 if i % 2 else 1)
        total += d - 9 if d > 9 else d
    return total % 10 == 0


def sub_value(pattern: re.Pattern, rule: str) -> Step:
    """Replace group 2 (keeping group 1); values that are already a placeholder are left alone."""
    def apply(text: str, counts: Counter) -> str:
        def repl(m: re.Match) -> str:
            if m.lastindex and m.lastindex >= 2 and is_handled(m.group(2)):
                return m.group(0)
            counts[rule] += 1
            return m.group(1) + tag(rule)
        return pattern.sub(repl, text)
    return apply


def sub_whole(pattern: re.Pattern, rule: str) -> Step:
    def apply(text: str, counts: Counter) -> str:
        def repl(_m: re.Match) -> str:
            counts[rule] += 1
            return tag(rule)
        return pattern.sub(repl, text)
    return apply


def luhn_digits(text: str, counts: Counter) -> str:
    def repl(m: re.Match) -> str:
        if not luhn_ok(m.group(0)):
            return m.group(0)
        counts["imei"] += 1
        return tag("imei")
    return DIGITS15.sub(repl, text)


def chain(*steps: Step) -> Step:
    def apply(text: str, counts: Counter) -> str:
        for step in steps:
            text = step(text, counts)
        return text
    return apply


def pseudonymize_macs(text: str, counts: Counter, salt: str) -> str:
    """Keep the OUI; replace the device part with a stable salted pseudonym, in the same separator style."""
    def make(sep: str):
        def repl(m: re.Match) -> str:
            counts["mac"] += 1
            oui, rest = m.group(1), m.group(2)
            digest = hashlib.sha256(f"{salt}:{rest.lower().replace('-', ':')}".encode()).digest()
            tail = sep.join(
                "".join(PSEUDONYM_ALPHABET[b % len(PSEUDONYM_ALPHABET)] for b in digest[i:i + 2])
                for i in range(0, MAC_HASH_HEX_LEN, 2))
            return f"{oui.lower()}{sep}{tail}"
        return repl
    return MAC_DASH.sub(make("-"), MAC_COLON.sub(make(":"), text))


IDENTIFIER_RULES: tuple[tuple[str, Step], ...] = (
    ("pw-hash", sub_whole(PW_HASH, "pw-hash")),
    ("imei", chain(sub_value(IMEI_LABEL, "imei"), luhn_digits)),
    ("imsi", chain(sub_value(IMSI_LABEL, "imsi"), sub_whole(IMSI_BARE, "imsi"))),
    ("iccid", chain(sub_value(ICCID_LABEL, "iccid"), sub_whole(ICCID_BARE, "iccid"))),
    ("token", chain(sub_value(BEARER, "token"), sub_whole(SK_KEY, "token"))),
)
BLOB_RULES: tuple[tuple[str, Step], ...] = (
    ("hex-psk", sub_whole(HEX64, "hex-psk")),
    ("b64-blob", sub_whole(B64_BLOB, "b64-blob")),
    ("eui64", sub_value(EUI64, "eui64")),
)
