"""Un-flatten harvest.sh frame file names before any name-based decision.

harvest.sh stores frame `etc/config/chap-secrets` as `frames/<kind>/etc%config%chap-secrets`. Exclusion lists and the
allowlist are written against real paths, so they must see the un-flattened form too. A '%' in a directory name, or
an empty/'.'/'..' segment after splitting, is something harvest.sh never writes: callers treat it as ambiguous and
refuse the file (None).
"""
from __future__ import annotations

from collections.abc import Sequence

FLAT_SEP = "%"


def candidates(parts: Sequence[str]) -> tuple[tuple[str, ...], ...] | None:
    """Path-part tuples a file may stand for, or None when the name is ambiguous.

    A plain path yields itself. A flattened basename yields: the path as written, the directories followed by the
    un-flattened segments, and the un-flattened segments alone (directories dropped: they are only the frames/<kind>
    layout)."""
    parts = tuple(parts)
    if not parts or any(FLAT_SEP in p for p in parts[:-1]):
        return None if parts else (parts,)
    last = parts[-1]
    if FLAT_SEP not in last:
        return (parts,)
    segs = tuple(last.split(FLAT_SEP))
    if any(s in ("", ".", "..") for s in segs):
        return None
    return (parts, (*parts[:-1], *segs), segs)


def unflattened_path(rel: str) -> str | None:
    """'frames/config/etc%config%x' -> 'etc/config/x'; a plain path is returned unchanged; None when ambiguous."""
    cands = candidates(rel.split("/"))
    if cands is None:
        return None
    return "/".join(cands[-1]) if len(cands) > 1 else rel
