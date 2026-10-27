"""L1: default-deny allowlist of the files that may be sent to the API (containers/recon-allowlist.txt).

Patterns are globs relative to an input root (harvest/redacted or unpacked): `*` matches within one path segment,
`**` across segments, `?` one character. A file that matches nothing is never sent.
"""
from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from functools import lru_cache
from pathlib import Path

ALLOWLIST_REL = Path("containers") / "recon-allowlist.txt"


class AllowlistError(ValueError):
    """The allowlist file is missing or contains an unsafe pattern."""


def load_patterns(path: Path) -> tuple[str, ...]:
    try:
        lines = Path(path).read_text().splitlines()
    except OSError as exc:
        raise AllowlistError(f"cannot read allowlist {path}: {exc.strerror}") from None
    patterns = tuple(line.strip() for line in lines if line.strip() and not line.strip().startswith("#"))
    for pattern in patterns:
        if pattern.startswith("/") or ".." in pattern.split("/"):
            raise AllowlistError(f"allowlist pattern escapes the input root: {pattern!r}")
    return patterns


@lru_cache(maxsize=512)
def _compile(pattern: str) -> re.Pattern:
    out, i = [], 0
    while i < len(pattern):
        if pattern.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif pattern.startswith("**", i):
            out.append(".*")
            i += 2
        elif pattern[i] == "*":
            out.append("[^/]*")
            i += 1
        elif pattern[i] == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(pattern[i]))
            i += 1
    return re.compile("".join(out))


def relative_name(display_name: str) -> str:
    """'redacted/etc/x' -> 'etc/x' (drop the input-root directory)."""
    return display_name.partition("/")[2]


def is_allowed(display_name: str, patterns: Iterable[str]) -> bool:
    rel = relative_name(display_name)
    return any(_compile(p).fullmatch(rel) for p in patterns)


def partition(names: Sequence[str], patterns: Sequence[str]) -> tuple[list[str], list[str]]:
    allowed = [n for n in names if is_allowed(n, patterns)]
    return allowed, [n for n in names if n not in set(allowed)]
