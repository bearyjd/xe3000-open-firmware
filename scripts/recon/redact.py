"""Rule-based redaction (PRP 0001 §5). Stdlib only: runs on the raw->redacted boundary.

The report lists {file, rule, count}; values never appear in it.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import sys
from collections import Counter
from collections.abc import Callable
from pathlib import Path

PLACEHOLDER = "<REDACTED:{rule}>"
MAC_SALT_ENV = "RECON_MAC_SALT"
DEFAULT_SALT_FILE = Path("cache") / "mac-salt"
SKIPPED_BINARY = "skipped-binary"
EXCLUDED = "excluded"
LUHN_LEN = 15
MAC_HASH_HEX_LEN = 6

MIN_LABELLED_TOKEN = 4
SENSITIVE = r"key|psk|pass|passwd|password|passphrase|secret|token|private|auth|sid|hash|cert|username"
PIN_WORDS = r"pin|pincode|puk"  # whole words only: 'mapping' and 'spinner' must survive
NOT_ALNUM = r"(?<![A-Za-z0-9])"
NAME_CH = r"[A-Za-z0-9_.\-]"
LABEL_SEP = r"""[\s:=\x27"]{0,6}"""

_FLAGS = re.IGNORECASE | re.MULTILINE
PEM = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY(?: BLOCK)?-----.*?(?:-----END [A-Z ]*PRIVATE KEY(?: BLOCK)?-----|\Z)",
                 re.DOTALL)
UCI = re.compile(rf"^([ \t]*(?:option|list)[ \t]+(?:\S*(?:{SENSITIVE})\S*|(?:\S*[_.\-])?(?:{PIN_WORDS})(?:[_.\-]\S*)?)[ \t]+)(.+)$",
                 _FLAGS)
UCI_SHELL = re.compile(
    rf"(\buci[ \t]+(?:-\S+[ \t]+)*(?:set|add_list)[ \t]+(?:[^\s=]*(?:{SENSITIVE})[^\s=]*|"
    rf"(?:[^\s=]*[_.\-])?(?:{PIN_WORDS})(?:[_.\-][^\s=]*)?)=)('[^'\n]*'|\"[^\"\n]*\"|[^\s;&|]+)", re.IGNORECASE)
WIFI = re.compile(
    rf"{NOT_ALNUM}((?:{NAME_CH}*(?:psk|sae_password|wpa_passphrase|passw(?:or)?d|passphrase)|"
    rf"(?:{NAME_CH}*[_.\-])?(?:{PIN_WORDS}))[ \t]*=[ \t]*)(\S.*)$", _FLAGS)
WG_LINE = re.compile(rf"{NOT_ALNUM}((?:PrivateKey|PresharedKey)[ \t]*=[ \t]*)(\S.*)$", _FLAGS)
WG_OPT = re.compile(r"^([ \t]*(?:option|list)[ \t]+(?:private_key|preshared_key)[ \t]+)(.+)$", _FLAGS)
WG_B64 = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{43}=(?![A-Za-z0-9+/=])")
JSON_KV = re.compile(
    rf'("(?:[^"\n]*(?:{SENSITIVE})[^"\n]*|(?:[^"\n]*[ _.\-])?(?:{PIN_WORDS})(?:[ _.\-][^"\n]*)?)"[ \t]*:[ \t]*)'
    r'("(?:[^"\\\n]|\\.)*"|\d+)', re.IGNORECASE)
JSON_RPC_SID = re.compile(r'("params"[ \t]*:[ \t]*\[[ \t]*")([^"\n]{8,})(")', re.IGNORECASE)
PW_HASH = re.compile(r"\$(?:1|5|6|y|p)\$[./0-9A-Za-z$,=-]{6,}")
IMEI_LABEL = re.compile(rf"(\b(?:IMEI|MEID)\b{LABEL_SEP})([0-9A-Fa-f]{{14,18}})", re.IGNORECASE)
DIGITS15 = re.compile(r"(?<![0-9A-Za-z])\d{15}(?![0-9A-Za-z])")
IMSI_LABEL = re.compile(rf"(\bIMSI\b{LABEL_SEP})(\d{{6,15}})", re.IGNORECASE)
IMSI_BARE = re.compile(r"(?<![0-9A-Za-z])[2-7]\d{14}(?![0-9A-Za-z])")  # MCC 2xx-7xx
ICCID_BARE = re.compile(r"(?<![0-9A-Za-z])89\d{17,18}(?![0-9A-Za-z])")
ICCID_LABEL = re.compile(rf"(\bICCID\b{LABEL_SEP})(\d{{10,22}})", re.IGNORECASE)
BEARER = re.compile(r"(\bBearer\s+)[A-Za-z0-9._~+/=-]{8,}", re.IGNORECASE)
SK_KEY = re.compile(r"\bsk-[A-Za-z0-9_-]{16,}")
TOKEN_LABEL = re.compile(
    rf"(\b\w*(?:token|secret|key|sid|cookie)\w*[ \t]*[:=][ \t]*[\x27\"]?)([A-Za-z0-9+/_=-]{{{MIN_LABELLED_TOKEN},}})",
    re.IGNORECASE,
)
MAC_COLON = re.compile(r"\b([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){2}):([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){2})\b")
MAC_DASH = re.compile(r"\b([0-9A-Fa-f]{2}(?:-[0-9A-Fa-f]{2}){2})-([0-9A-Fa-f]{2}(?:-[0-9A-Fa-f]{2}){2})\b")
EUI64 = re.compile(r"(?<![0-9A-Za-z:])((?:[0-9A-Fa-f]{0,4}:){1,8})[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{2}ff:fe[0-9A-Fa-f]{2}:"
                   r"[0-9A-Fa-f]{1,4}(?![0-9A-Za-z:])", re.IGNORECASE)

EXCLUDED_NAMES = frozenset({"shadow", "serial"})
EXCLUDED_SUFFIXES = (".pem", ".key")


def _tag(rule: str) -> str:
    return PLACEHOLDER.format(rule=rule)


def luhn_ok(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch) * (2 if i % 2 else 1)
        total += d - 9 if d > 9 else d
    return total % 10 == 0


def _sub_value(pattern: re.Pattern, rule: str) -> Callable[[str, Counter], str]:
    def apply(text: str, counts: Counter) -> str:
        def repl(m: re.Match) -> str:
            counts[rule] += 1
            return m.group(1) + _tag(rule)
        return pattern.sub(repl, text)
    return apply


def _sub_whole(pattern: re.Pattern, rule: str) -> Callable[[str, Counter], str]:
    def apply(text: str, counts: Counter) -> str:
        def repl(_m: re.Match) -> str:
            counts[rule] += 1
            return _tag(rule)
        return pattern.sub(repl, text)
    return apply


def _json_secret(text: str, counts: Counter) -> str:
    def kv(m: re.Match) -> str:
        counts["json-secret"] += 1
        return m.group(1) + '"' + _tag("json-secret") + '"'

    def sid(m: re.Match) -> str:
        counts["json-secret"] += 1
        return m.group(1) + _tag("json-secret") + m.group(3)
    return JSON_RPC_SID.sub(sid, JSON_KV.sub(kv, text))


def _luhn_digits(text: str, counts: Counter) -> str:
    def repl(m: re.Match) -> str:
        if not luhn_ok(m.group(0)):
            return m.group(0)
        counts["imei"] += 1
        return _tag("imei")
    return DIGITS15.sub(repl, text)


def _chain(*steps: Callable[[str, Counter], str]) -> Callable[[str, Counter], str]:
    def apply(text: str, counts: Counter) -> str:
        for step in steps:
            text = step(text, counts)
        return text
    return apply


# Order matters: multi-line and structured rules first, generic last. One entry per PRP rule.
RULES: tuple[tuple[str, Callable[[str, Counter], str]], ...] = (
    ("pem-block", _sub_whole(PEM, "pem-block")),
    ("json-secret", _json_secret),
    ("uci-sensitive", _chain(_sub_value(UCI, "uci-sensitive"), _sub_value(UCI_SHELL, "uci-sensitive"))),
    ("wifi-psk", _sub_value(WIFI, "wifi-psk")),
    ("wg-key", _chain(_sub_value(WG_LINE, "wg-key"), _sub_value(WG_OPT, "wg-key"), _sub_whole(WG_B64, "wg-key"))),
    ("pw-hash", _sub_whole(PW_HASH, "pw-hash")),
    ("imei", _chain(_sub_value(IMEI_LABEL, "imei"), _luhn_digits)),
    ("imsi", _chain(_sub_value(IMSI_LABEL, "imsi"), _sub_whole(IMSI_BARE, "imsi"))),
    ("iccid", _chain(_sub_value(ICCID_LABEL, "iccid"), _sub_whole(ICCID_BARE, "iccid"))),
    ("token", _chain(_sub_value(BEARER, "token"), _sub_whole(SK_KEY, "token"), _sub_value(TOKEN_LABEL, "token"))),
    ("eui64", _sub_value(EUI64, "eui64")),
)
RULE_NAMES = tuple(name for name, _ in RULES) + ("mac",)


def _pseudonymize_mac(text: str, counts: Counter, salt: str) -> str:
    """Keep the OUI; replace the device part with a stable salted hash, in the same separator style."""
    def make(sep: str):
        def repl(m: re.Match) -> str:
            counts["mac"] += 1
            oui, rest = m.group(1), m.group(2)
            digest = hashlib.sha256(f"{salt}:{rest.lower().replace('-', ':')}".encode()).hexdigest()[:MAC_HASH_HEX_LEN]
            tail = sep.join(digest[i:i + 2] for i in range(0, MAC_HASH_HEX_LEN, 2))
            return f"{oui.lower()}{sep}{tail}"
        return repl
    return MAC_DASH.sub(make("-"), MAC_COLON.sub(make(":"), text))


def redact_text(text: str, disabled: frozenset[str] = frozenset(), salt: str = "") -> tuple[str, Counter]:
    """Return (redacted text, per-rule counts). `disabled` is for tests of the independent pre-flight."""
    counts: Counter = Counter()
    for name, apply in RULES:
        if name not in disabled:
            text = apply(text, counts)
    if "mac" not in disabled:
        text = _pseudonymize_mac(text, counts, salt)
    return text, counts


def _is_excluded(rel: Path) -> bool:
    parts = {p.lower() for p in rel.parts}
    name = rel.name.lower()
    return (
        name in EXCLUDED_NAMES
        or "dropbear" in parts
        or name.endswith("_host_key")
        or name.endswith(EXCLUDED_SUFFIXES)
    )


def _read_text(path: Path) -> str | None:
    data = path.read_bytes()
    if b"\x00" in data:
        return None
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None


def redact_tree(src: Path, dst: Path, disabled: frozenset[str] = frozenset(), salt: str = "") -> list[dict]:
    """Redact every text file under src into dst; return report rows {file, rule, count}."""
    src, dst = Path(src), Path(dst)
    report: list[dict] = []
    for path in sorted(p for p in src.rglob("*") if p.is_file() and not p.is_symlink()):
        rel = path.relative_to(src)
        name = rel.as_posix()
        if _is_excluded(rel):
            report.append({"file": name, "rule": EXCLUDED, "count": 1})
            continue
        text = _read_text(path)
        if text is None:
            report.append({"file": name, "rule": SKIPPED_BINARY, "count": 1})
            continue
        clean, counts = redact_text(text, disabled, salt)
        target = dst / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(clean)
        report.extend({"file": name, "rule": rule, "count": n} for rule, n in sorted(counts.items()))
    return report


def _load_salt(arg: str | None, root: Path) -> str:
    if arg:
        return arg
    if os.environ.get(MAC_SALT_ENV):
        return os.environ[MAC_SALT_ENV]
    salt_file = root / DEFAULT_SALT_FILE
    if salt_file.exists():
        return salt_file.read_text().strip()
    salt_file.parent.mkdir(parents=True, exist_ok=True)
    salt = secrets.token_hex(16)
    salt_file.write_text(salt)
    salt_file.chmod(0o600)
    return salt


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Redact a raw text tree into harvest/redacted.")
    ap.add_argument("--src", required=True, type=Path)
    ap.add_argument("--dst", required=True, type=Path)
    ap.add_argument("--report", type=Path, help="write {file, rule, count} rows here (default: stdout)")
    ap.add_argument("--salt", help=f"MAC pseudonym salt (default: ${MAC_SALT_ENV} or cache/mac-salt)")
    ap.add_argument("--root", type=Path, default=Path(os.environ.get("RECON_ROOT", ".")))
    args = ap.parse_args(argv)
    src, dst = args.src.resolve(), args.dst.resolve()
    if not src.is_dir():
        print(f"redact: --src is not a directory: {args.src}", file=sys.stderr)
        return 2
    if dst == src or dst.is_relative_to(src) or src.is_relative_to(dst):
        print("redact: --dst and --src must not overlap", file=sys.stderr)
        return 2
    report = redact_tree(src, dst, salt=_load_salt(args.salt, args.root.resolve()))
    payload = json.dumps(report, indent=2, sort_keys=True)
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(payload + "\n")
    else:
        print(payload)
    print(f"redact: {len(report)} report rows, wrote {dst}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
