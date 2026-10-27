"""Rule-based redaction (PRP 0001 section 5). Stdlib only: runs on the raw->redacted boundary.

The report lists {file, rule, count}; values never appear in it. Regex redaction cannot be complete, so it is one of
several layers: name exclusions here, an independent gitleaks pre-flight, a default-deny API allowlist and known-secret
canaries (see the PRP).
"""
from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
from collections import Counter
from pathlib import Path

from recon.redact_ids import BLOB_RULES, IDENTIFIER_RULES, luhn_ok, pseudonymize_macs  # noqa: F401 (luhn_ok re-export)
from recon.redact_names import SENTINEL
from recon.redact_secrets import SECRET_RULES

MAC_SALT_ENV = "RECON_MAC_SALT"
DEFAULT_SALT_FILE = Path("cache") / "mac-salt"
SKIPPED_BINARY = "skipped-binary"
EXCLUDED = "excluded"
MARKER_NAME = ".recon-redacted"

# Order matters: key blocks, JSON and structured forms first, the generic labelled rule after the specific ones.
RULES = (*SECRET_RULES, *IDENTIFIER_RULES, *BLOB_RULES)
RULE_NAMES = tuple(dict.fromkeys(name for name, _ in RULES)) + ("mac",)

EXCLUDED_NAMES = frozenset({"shadow", "htpasswd", "chap-secrets", "pap-secrets", "ipsec.secrets", "auth-user-pass"})
EXCLUDED_SUFFIXES = (".pem", ".key", ".psk", ".secrets", ".auth", "_host_key")
EXCLUDED_FRAGMENTS = ("wpa_psk", "userpass", "auth-user-pass", "htpasswd")


def redact_text(text: str, disabled: frozenset[str] = frozenset(), salt: str = "") -> tuple[str, Counter]:
    """Return (redacted text, per-rule counts), one pass. Chained labels are handled inside the labelled rule
    (it rescans inside non-secret values). `disabled` is for tests of the independent pre-flight."""
    counts: Counter = Counter()
    text = text.replace(SENTINEL, "")  # the marker is private to this call
    for name, apply in RULES:
        if name not in disabled:
            text = apply(text, counts)
    if "mac" not in disabled:
        text = pseudonymize_macs(text, counts, salt)
    return text.replace(SENTINEL, ""), counts


def _is_excluded(rel: Path) -> bool:
    parts = {p.lower() for p in rel.parts}
    name = rel.name.lower()
    return (
        name in EXCLUDED_NAMES
        or name.startswith("serial")
        or "dropbear" in parts
        or name.endswith(EXCLUDED_SUFFIXES)
        or any(f in name for f in EXCLUDED_FRAGMENTS)
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
    dst.mkdir(parents=True, exist_ok=True)
    (dst / MARKER_NAME).write_text("redacted from a raw tree by redact.py; values are never listed\n")
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
