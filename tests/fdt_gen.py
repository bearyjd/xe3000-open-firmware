"""Tiny flattened-device-tree writer for tests: builds synthetic DTB/FIT blobs without dtc."""
from __future__ import annotations

import struct

MAGIC = 0xD00DFEED


def node(props: dict[str, bytes] | None = None, children: dict[str, dict] | None = None) -> dict:
    return {"props": dict(props or {}), "children": dict(children or {})}


def _pad(b: bytes) -> bytes:
    return b + b"\0" * (-len(b) % 4)


def make_fdt(root: dict) -> bytes:
    strings = bytearray()
    offsets: dict[str, int] = {}

    def name_off(name: str) -> int:
        if name not in offsets:
            offsets[name] = len(strings)
            strings.extend(name.encode() + b"\0")
        return offsets[name]

    def emit(name: str, n: dict) -> bytes:
        out = struct.pack(">I", 1) + _pad(name.encode() + b"\0")
        for pname, value in n["props"].items():
            out += struct.pack(">III", 3, len(value), name_off(pname)) + _pad(value)
        for cname, child in n["children"].items():
            out += emit(cname, child)
        return out + struct.pack(">I", 2)

    struct_block = emit("", root) + struct.pack(">I", 9)
    off_struct = 56
    off_strings = off_struct + len(struct_block)
    total = off_strings + len(strings)
    header = struct.pack(">IIIIIIIIII", MAGIC, total, off_struct, off_strings, 40, 17, 16, 0, len(strings), len(struct_block))
    return header + b"\0" * 16 + struct_block + bytes(strings)


def make_dtb(model: str = "synthetic,board") -> bytes:
    return make_fdt(node({"model": model.encode() + b"\0", "compatible": b"vendor,board\0"}))


def make_fit(kernel: bytes = b"KERNEL" * 20, dtb: bytes | None = None) -> bytes:
    images = {"kernel-1": node({"type": b"kernel\0", "data": kernel, "compression": b"none\0"})}
    if dtb is not None:
        images["fdt-1"] = node({"type": b"flat_dt\0", "data": dtb})
    return make_fdt(node({"description": b"fit\0"}, {"images": node(None, images), "configurations": node({"default": b"c1\0"})}))
