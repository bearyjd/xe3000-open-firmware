"""L2: known-secret canaries. Stdlib only (also used by the host pre-flight and `just canary-init`).

The canary file holds real secrets that must never reach the API (Wi-Fi key, admin password, PPPoE password...),
one per line. If one appears in ANY input file, in any common encoding, the run aborts and reports only file and
line number. Values are never printed, logged or copied anywhere.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import re
import stat
import sys
import urllib.parse
from collections.abc import Mapping, Sequence
from pathlib import Path

CANARY_ENV = "RECON_CANARY_FILE"
DEFAULT_REL = Path(".config") / "xe3000-open-firmware" / "canaries"
MIN_CANARY_LEN = 6  # shorter values (4-digit PINs) would match everywhere; they cannot be canaried
REAL_MARKER_NAMES = (".recon-redacted", "etc/glversion", "etc/openwrt_release")
INIT_TEXT = ("# One secret per line (Wi-Fi key, admin password, PPPoE password, ...). Lines starting with # are ignored.\n"
             "# This file must stay mode 0600. Values are never printed or logged; hits report file and line only.\n")


class CanaryError(RuntimeError):
    """The canary file is unusable. Messages never include canary values."""


def default_path() -> Path:
    override = os.environ.get(CANARY_ENV)
    return Path(override) if override else Path(os.path.expanduser("~")) / DEFAULT_REL


def init_file(path: Path) -> bool:
    """Create an empty 0600 canary file; never overwrite an existing one. True if created."""
    path = Path(path)
    if path.exists():
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as handle:
        handle.write(INIT_TEXT)
    return True


def load_canaries(path: Path) -> tuple[str, ...] | None:
    """Canary values, or None if the file does not exist."""
    path = Path(path)
    try:
        info = path.stat()
    except FileNotFoundError:
        return None
    if stat.S_IMODE(info.st_mode) & 0o077:
        raise CanaryError(f"canary file {path} must be mode 0600 (no group/other access)")
    values = []
    for number, raw in enumerate(path.read_text().splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if len(line) < MIN_CANARY_LEN:
            raise CanaryError(f"canary file {path} line {number} is shorter than {MIN_CANARY_LEN} characters")
        values.append(line)
    return tuple(values)


def has_real_harvest_marker(names: Sequence[str]) -> bool:
    return any(n.partition("/")[2] in REAL_MARKER_NAMES or n.endswith("/.recon-redacted") for n in names)


def _b64_fragments(data: bytes) -> set[str]:
    """Substrings of the base64 text that are stable wherever the secret sits in a larger encoded string."""
    out = set()
    for offset in range(3):
        encoded = base64.b64encode(b"\0" * offset + data).decode().rstrip("=")
        skip = (offset * 4 + 2) // 3
        core = encoded[skip:len(encoded) - 2] if len(encoded) - skip > 2 else ""
        if len(core) >= MIN_CANARY_LEN:
            out.add(core)
    return out


def variants(secret: str) -> tuple[frozenset[str], frozenset[str]]:
    """(case-insensitive variants, lowercase-compared; case-sensitive variants)."""
    data = secret.encode()
    insensitive = {secret, urllib.parse.quote(secret, safe=""), urllib.parse.quote_plus(secret), data.hex(),
                   "".join(f"%{b:02x}" for b in data),               # every byte percent-encoded (%57)
                   json.dumps(secret)[1:-1],                         # "\"-style JSON escaping
                   "".join(f"\\u{ord(ch):04x}" for ch in secret)}      # \uXXXX for every character
    sensitive = _b64_fragments(data)
    urlsafe = base64.urlsafe_b64encode(data).decode().rstrip("=")
    if len(urlsafe) - 2 >= MIN_CANARY_LEN:
        sensitive.add(urlsafe[:-2])
    return frozenset(v.lower() for v in insensitive), frozenset(sensitive)


def scan(files: Mapping[str, str], canaries: Sequence[str]) -> list[tuple[str, int]]:
    """[(file, line number)] for every line containing a canary in any variant. Values are never returned."""
    if not canaries:
        return []
    compiled = [variants(c) for c in canaries]
    hits = []
    for name in sorted(files):
        for number, line in enumerate(files[name].splitlines(), 1):
            lowered = line.lower()
            if any(any(v in lowered for v in ci) or any(v in line for v in cs) for ci, cs in compiled):
                hits.append((name, number))
    return hits


MASK = "<REDACTED:canary>"


class Sanitizer:
    """Removes known secrets (every transform) from text and nested data before anything is persisted."""

    def __init__(self, canaries: Sequence[str]) -> None:
        pairs = [variants(c) for c in canaries]
        ci = sorted({v for p in pairs for v in p[0]}, key=len, reverse=True)
        cs = sorted({v for p in pairs for v in p[1]}, key=len, reverse=True)
        self._ci = re.compile("|".join(re.escape(v) for v in ci), re.IGNORECASE) if ci else None
        self._cs = re.compile("|".join(re.escape(v) for v in cs)) if cs else None

    @classmethod
    def from_file(cls, path: Path | None = None) -> "Sanitizer":
        """Empty sanitiser when there is no canary file; CanaryError if the file is unusable."""
        return cls(load_canaries(path or default_path()) or ())

    def text(self, value: str) -> str:
        for rx in (self._ci, self._cs):
            if rx is not None:
                value = rx.sub(MASK, value)
        return value

    def obj(self, value):
        if isinstance(value, str):
            return self.text(value)
        if isinstance(value, dict):
            return {self.text(k) if isinstance(k, str) else k: self.obj(v) for k, v in value.items()}
        if isinstance(value, (list, tuple)):
            return [self.obj(v) for v in value]
        return value


def check(files: Mapping[str, str], *, skip: bool, path: Path | None = None) -> list[tuple[str, int]]:
    """Canary hits over every input file. Raises CanaryError if canaries are required but unusable."""
    if skip:
        return []
    where = path or default_path()
    values = load_canaries(where)
    if values is None:
        if has_real_harvest_marker(list(files)):
            raise CanaryError("no canary file and the input looks like a real harvest: create one with "
                              "`just canary-init` and add your real secrets, or pass --no-canary")
        return []
    return scan(files, values)


def format_hits(hits: Sequence[tuple[str, int]]) -> str:
    return ", ".join(f"{name}:{line}" for name, line in hits)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Create the (empty, 0600) known-secret canary file.")
    ap.add_argument("--init", action="store_true", required=True)
    ap.add_argument("--path", type=Path)
    args = ap.parse_args(argv)
    path = args.path or default_path()
    if init_file(path):
        print(f"created {path} (mode 0600, empty).")
    else:
        print(f"{path} already exists; left untouched.")
    print("Next: edit it and add one real secret per line (Wi-Fi key, admin password, PPPoE password...).\n"
          "Keep it outside the repo. analyze and preflight read it automatically; hits print file:line only.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
