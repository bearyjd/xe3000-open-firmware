"""Minimal, bounds-checked flattened-device-tree reader and carver (stdlib only; never executes anything).

Used to find the kernel FIT and DTBs inside unpacked firmware. A node is {"props": {name: bytes}, "children": {name: node}}.
"""
from __future__ import annotations

import mmap
import struct
from dataclasses import dataclass
from pathlib import Path

MAGIC = b"\xd0\x0d\xfe\xed"
HEADER_LEN = 40
MAX_DEPTH = 64
MAX_NODES = 100_000
_BEGIN, _END_NODE, _PROP, _NOP, _END = 1, 2, 3, 4, 9


@dataclass(frozen=True)
class Blob:
    source: str
    offset: int
    data: bytes


def _header(data: bytes | mmap.mmap, off: int = 0):
    if off + HEADER_LEN > len(data) or data[off : off + 4] != MAGIC:
        return None
    return struct.unpack(">IIIIIIIII", data[off + 4 : off + HEADER_LEN])


def totalsize_at(data: bytes | mmap.mmap, off: int = 0) -> int | None:
    """Declared size of a plausible FDT at `off`, or None. Header checks only (parse_fdt validates the body)."""
    h = _header(data, off)
    if h is None:
        return None
    total, off_struct, off_strings, off_rsv, version, last_comp, _boot, size_strings, size_struct = h
    if not (HEADER_LEN <= total <= len(data) - off) or last_comp > 17 or version < last_comp or version < 16:
        return None
    if off_struct + size_struct > total or off_strings + size_strings > total or off_struct % 4 or off_rsv > total:
        return None
    return total


def _cstr(buf: bytes, start: int, limit: int) -> str | None:
    end = buf.find(b"\0", start, limit)
    if end < 0:
        return None
    try:
        return buf[start:end].decode("utf-8")
    except UnicodeDecodeError:
        return None


def parse_fdt(data: bytes) -> dict | None:
    """Parse one FDT blob into nested dicts; None if it is not a well-formed tree."""
    total = totalsize_at(data, 0)
    if total is None:
        return None
    h = _header(data, 0)
    off_struct, off_strings, size_strings, size_struct = h[1], h[2], h[7], h[8]
    struct_end = off_struct + size_struct
    strings_end = off_strings + size_strings
    pos, stack, nodes = off_struct, [], 0
    root = None
    while pos + 4 <= struct_end:
        (tok,) = struct.unpack_from(">I", data, pos)
        pos += 4
        if tok == _BEGIN:
            name = _cstr(data, pos, struct_end)
            if name is None or len(stack) >= MAX_DEPTH or nodes >= MAX_NODES:
                return None
            pos += (len(name.encode()) + 1 + 3) & ~3
            node = {"props": {}, "children": {}}
            nodes += 1
            if stack:
                stack[-1]["children"][name] = node
            elif root is None:
                root = node
            else:
                return None
            stack.append(node)
        elif tok == _END_NODE:
            if not stack:
                return None
            stack.pop()
        elif tok == _PROP:
            if not stack or pos + 8 > struct_end:
                return None
            length, nameoff = struct.unpack_from(">II", data, pos)
            pos += 8
            if pos + length > struct_end or nameoff >= size_strings:
                return None
            pname = _cstr(data, off_strings + nameoff, strings_end)
            if pname is None:
                return None
            stack[-1]["props"][pname] = bytes(data[pos : pos + length])
            pos += (length + 3) & ~3
        elif tok == _NOP:
            continue
        elif tok == _END:
            return root if root is not None and not stack else None
        else:
            return None
    return None


def is_fit(tree: dict) -> bool:
    return "images" in tree["children"] and "configurations" in tree["children"]


def fit_dtb_images(tree: dict) -> list[bytes]:
    """Embedded flat_dt images of a FIT whose data parses as an FDT."""
    found = []
    for image in tree["children"].get("images", {"children": {}})["children"].values():
        props = image["props"]
        if props.get("type", b"").rstrip(b"\0") == b"flat_dt" and parse_fdt(props.get("data", b"")) is not None:
            found.append(props["data"])
    return found


def carve_file(path: Path, source: str) -> list[tuple[Blob, dict]]:
    """Every well-formed FDT in a file, non-overlapping, as (blob, parsed tree)."""
    if path.stat().st_size < HEADER_LEN:
        return []
    out: list[tuple[Blob, dict]] = []
    with path.open("rb") as fh, mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ) as mm:
        pos = mm.find(MAGIC)
        while pos >= 0:
            total = totalsize_at(mm, pos)
            tree = parse_fdt(bytes(mm[pos : pos + total])) if total else None
            if tree is not None:
                out.append((Blob(source, pos, bytes(mm[pos : pos + total])), tree))
                pos = mm.find(MAGIC, pos + total)
            else:
                pos = mm.find(MAGIC, pos + 1)
    return out
