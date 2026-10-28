"""Phase 2 ground truth: deterministic inventories over an unpacked/redacted rootfs. No API, no network.

Five JSON documents (AT commands, ubus/RPC methods, GPIOs, kernel modules, init.d order) are written under
findings/raw/ground-truth/ (gitignored). Each entry carries file:line, never file content. Logs carry counts only.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from recon import groundtruth as gt
from recon import names, paths
from recon.paths import PathRefused, check_path
from recon.scrub import scrub

MAX_TEXT_BYTES = 4 * 1024 * 1024
MAX_BINARY_BYTES = 16 * 1024 * 1024
HEAD_BYTES = 8192
MIN_STRING_LEN = 4
OUT_REL = Path("findings") / "raw" / "ground-truth"
EXIT_OK, EXIT_REFUSED = 0, 2
DOCUMENTS = ("at-commands", "rpc-methods", "gpios", "kernel-modules", "initd-order")

_BINARY_AT_RE = re.compile(r"AT[+^$!&#%][A-Za-z0-9_]+")
_OBJECT_DOC_RE = re.compile(r"@object-name:\s*([\w.\-]+)")
_METHOD_DOC_RE = re.compile(r"@method-name:\s*([\w.\-]+)")
_LUA_TABLE_RES = (re.compile(r"^\s*M\.(\w+)\s*=\s*function"), re.compile(r"^\s*function\s+M[.:](\w+)\s*\("))
_EXAMPLE_RE = re.compile(r'params\\*"\s*:\s*\[\s*\\*"[^"\\]*\\*"\s*,\s*\\*"([\w.\-]+)\\*"\s*,\s*\\*"(\w+)\\*"')
_CALL_RE = re.compile(r"""call\(\s*["']([\w.\-]+)["']\s*,\s*["'](\w+)["']""")
_JS_ARRAY_RE = re.compile(r"""["']call["']\s*,\s*["']([\w.\-]+)["']\s*,\s*["'](\w+)["']""")
_SYSFS_WRITE_RE = re.compile(r"echo\s+(\S+)\s*>\s*/sys/class/gpio/gpio(\d+)/(\w+)")
_START_RE = re.compile(r"^\s*START=(\d+)", re.MULTILINE)
_STOP_RE = re.compile(r"^\s*STOP=(\d+)", re.MULTILINE)
_MODULE_LINE_RE = re.compile(r"^[\w-]+$")
_CODE_SUFFIXES = (".lua", ".js", ".js_extract", ".sh")


@dataclass(frozen=True)
class Tree:
    texts: Mapping[str, str]
    binaries: Mapping[str, bytes]
    paths: tuple[str, ...]
    skipped_oversize: tuple[str, ...] = ()


def printable_strings(data: bytes, min_len: int = MIN_STRING_LEN) -> list[str]:
    """What `strings` prints: runs of printable ASCII of at least min_len characters."""
    return [m.group().decode("ascii") for m in re.finditer(rb"[\x20-\x7e\t]{%d,}" % min_len, data)]


def _hit(file: str, line: int, **extra: object) -> dict:
    return {"file": file, "line": line, **extra}


def _lines(text: str) -> Iterable[tuple[int, str]]:
    return enumerate(text.splitlines(), start=1)


def _add(index: dict[str, list[dict]], key: str, hit: dict) -> None:
    index.setdefault(key, []).append(hit)


# ---- AT commands -----------------------------------------------------------------------------------------------

def at_commands(texts: Mapping[str, str], binaries: Mapping[str, bytes]) -> dict[str, list[dict]]:
    found: dict[str, list[dict]] = {}
    for name, text in sorted(texts.items()):
        for no, line in _lines(text):
            for m in gt.AT_RE.finditer(line):
                _add(found, m.group(1).upper(), _hit(name, no, via="text"))
    for name, data in sorted(binaries.items()):
        for no, s in enumerate(printable_strings(data), start=1):
            for m in _BINARY_AT_RE.finditer(s):  # bare ATZ/ATI-style words are noise inside binaries
                _add(found, m.group().upper(), _hit(name, no, via="strings"))
    return dict(sorted(found.items()))


# ---- ubus / RPC ------------------------------------------------------------------------------------------------

def _is_code(name: str) -> bool:
    lowered = name.lower()
    return lowered.endswith(_CODE_SUFFIXES) or "oui-httpd" in lowered or "/usr/bin/" in "/" + lowered


def _method(obj: str, method: str, source: str, file: str, line: int, **extra: object) -> dict:
    return {"object": obj, "method": method, "source": source, "file": file, "line": line, **extra}


def _acl_entries(node: object, access: str, out: list[tuple[str, str, str]]) -> None:
    if not isinstance(node, dict):
        return
    for key, value in node.items():
        if key == "ubus" and isinstance(value, dict):
            for obj, methods in value.items():
                out.extend((obj, str(m), access) for m in (methods if isinstance(methods, list) else []))
        else:
            _acl_entries(value, key if key in ("read", "write") else access, out)


def _acl_methods(name: str, text: str, errors: list[str]) -> list[dict]:
    try:
        doc = json.loads(text)
    except ValueError:
        errors.append(name)
        return []
    entries: list[tuple[str, str, str]] = []
    _acl_entries(doc, "unspecified", entries)
    lines = text.splitlines()
    result = []
    for obj, method, access in entries:
        line = next((no for no, raw in enumerate(lines, start=1) if f'"{obj}"' in raw), 1)
        result.append(_method(obj, method, "acl", name, line, access=access))
    return result


def _lua_methods(name: str, text: str) -> list[dict]:
    stem = name.rsplit("/", 1)[-1].rsplit(".", 1)[0]
    obj, out = stem, []
    for no, line in _lines(text):
        doc_obj = _OBJECT_DOC_RE.search(line)
        if doc_obj:
            obj = doc_obj.group(1)
        doc = _METHOD_DOC_RE.search(line)
        if doc:
            out.append(_method(obj, doc.group(1), "lua-doc", name, no))
        for rx in _LUA_TABLE_RES:
            table = rx.match(line)
            if table:
                out.append(_method(obj, table.group(1), "lua-table", name, no))
    return out


def _call_methods(name: str, text: str) -> list[dict]:
    out = []
    for no, line in _lines(text):
        for m in gt.UBUS_CALL_RE.finditer(line):
            out.append(_method(m.group(1), m.group(2), "ubus-call", name, no))
        if _is_code(name):
            for rx, source in ((_CALL_RE, "call"), (_JS_ARRAY_RE, "call"), (_EXAMPLE_RE, "example")):
                out.extend(_method(m.group(1), m.group(2), source, name, no) for m in rx.finditer(line))
    return out


def rpc_methods(texts: Mapping[str, str]) -> dict:
    methods: list[dict] = []
    errors: list[str] = []
    for name, text in sorted(texts.items()):
        lowered = name.lower()
        if "acl.d/" in lowered and lowered.endswith(".json"):
            methods += _acl_methods(name, text, errors)
            continue
        if "oui-httpd/rpc/" in lowered:
            methods += _lua_methods(name, text)
        methods += _call_methods(name, text)
    seen: set[tuple] = set()
    unique = []
    for m in methods:
        key = (m["object"], m["method"], m["source"], m.get("access"), m["file"], m["line"])
        if key not in seen:
            seen.add(key)
            unique.append(m)
    objects = sorted({m["object"] for m in unique})
    return {"methods": unique, "objects": objects, "parse_errors": sorted(errors)}


# ---- GPIO ------------------------------------------------------------------------------------------------------

def gpios(texts: Mapping[str, str]) -> dict:
    numbers: dict[str, list[dict]] = {}
    writes: list[dict] = []
    for name, text in sorted(texts.items()):
        for no, line in _lines(text):
            for rx in (gt.GPIO_WORD_RE, gt.GPIO_SYSFS_RE, gt.GPIO_EXPORT_RE, gt.GPIO_DTS_RE):
                for m in rx.finditer(line):
                    _add(numbers, str(int(m.group(1))), _hit(name, no))
            for m in _SYSFS_WRITE_RE.finditer(line):
                writes.append({"gpio": int(m.group(2)), "attr": m.group(3), "value": m.group(1), "file": name, "line": no})
            for m in gt.GPIO_EXPORT_RE.finditer(line):
                writes.append({"gpio": int(m.group(1)), "attr": "export", "value": m.group(1), "file": name, "line": no})
    return {"numbers": dict(sorted(numbers.items(), key=lambda kv: int(kv[0]))), "sysfs_writes": writes}


# ---- kernel modules --------------------------------------------------------------------------------------------

def kernel_modules(texts: Mapping[str, str], paths: Sequence[str]) -> dict[str, list[dict]]:
    found: dict[str, list[dict]] = {}
    for name, text in sorted(texts.items()):
        listing = "/modules.d/" in "/" + name or "/modules-boot.d/" in "/" + name
        for no, line in _lines(text):
            if listing:
                token = line.split("#", 1)[0].split()[:1]
                if token and _MODULE_LINE_RE.match(token[0]):
                    _add(found, gt._module_name(token[0]), _hit(name, no))
                continue
            for m in gt.MOD_CMD_RE.finditer(line):
                if m.group(1).lower() not in gt.PROSE_STOPWORDS:
                    _add(found, gt._module_name(m.group(1)), _hit(name, no))
            for m in gt.MOD_KO_RE.finditer(line):
                _add(found, gt._module_name(m.group(1)), _hit(name, no))
    for path in sorted(paths):
        if path.endswith(".ko"):
            _add(found, gt._module_name(path), _hit(path, 1))
    return dict(sorted(found.items()))


# ---- init.d order ----------------------------------------------------------------------------------------------

def initd_order(texts: Mapping[str, str]) -> dict:
    entries, unordered = [], []
    for name, text in sorted(texts.items()):
        if "/etc/init.d/" not in "/" + name:
            continue
        start, stop = _START_RE.search(text), _STOP_RE.search(text)
        base = name.rsplit("/", 1)[-1]
        if not start and not stop:
            unordered.append(base)
            continue
        entries.append({"name": base, "start": int(start.group(1)) if start else None,
                        "stop": int(stop.group(1)) if stop else None,
                        "procd": bool(re.search(r"^\s*USE_PROCD=1", text, re.MULTILINE)), "file": name})
    return {"start": sorted((e for e in entries if e["start"] is not None), key=lambda e: (e["start"], e["name"])),
            "stop": sorted((e for e in entries if e["stop"] is not None), key=lambda e: (e["stop"], e["name"])),
            "unordered": sorted(unordered)}


# ---- assembly --------------------------------------------------------------------------------------------------

def build(texts: Mapping[str, str], binaries: Mapping[str, bytes] | None = None,
          paths: Sequence[str] = ()) -> dict[str, object]:
    return {"at-commands": at_commands(texts, binaries or {}), "rpc-methods": rpc_methods(texts),
            "gpios": gpios(texts), "kernel-modules": kernel_modules(texts, paths), "initd-order": initd_order(texts)}


def _count(name: str, doc: object) -> int:
    if name == "rpc-methods":
        return len(doc["methods"])
    if name == "gpios":
        return len(doc["numbers"])
    if name == "initd-order":
        return len(doc["start"])
    return len(doc)


def write_all(inventory: Mapping[str, object], out_dir: Path) -> dict[str, int]:
    """Write one JSON file per document; return counts only (callers log these, never the content)."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    counts = {}
    for name in DOCUMENTS:
        (out_dir / f"{name}.json").write_text(json.dumps(inventory[name], indent=1, sort_keys=True) + "\n")
        counts[name] = _count(name, inventory[name])
    return counts


# ---- reading the tree ------------------------------------------------------------------------------------------

def _read(path: Path) -> tuple[bytes | None, bool, bool]:
    """(data, is_binary, oversize). Reads only as much as the size cap allows."""
    size = path.stat().st_size
    with path.open("rb") as handle:
        head = handle.read(HEAD_BYTES)
        binary = b"\0" in head
        if size > (MAX_BINARY_BYTES if binary else MAX_TEXT_BYTES):
            return None, binary, True
        return head + handle.read(), binary, False


def _inodes_under(directory: Path) -> frozenset[tuple[int, int]]:
    found: set[tuple[int, int]] = set()
    for dirpath, _dirs, filenames in os.walk(directory, followlinks=False):
        for filename in filenames:
            try:
                st = os.lstat(Path(dirpath) / filename)
            except OSError:
                continue
            found.add((st.st_dev, st.st_ino))
    return frozenset(found)


def load_tree(root: Path, prefix: str = "", raw_root: Path | None = None) -> Tree:
    """Regular files only: symlinks are never followed, credential-bearing names (names.is_excluded) are skipped and
    any file sharing an inode with a file under raw_root (a hardlink into harvest/raw) is never read."""
    root = Path(root)
    raw_inodes = _inodes_under(raw_root) if raw_root is not None and Path(raw_root).is_dir() else frozenset()
    texts: dict[str, str] = {}
    binaries: dict[str, bytes] = {}
    paths: list[str] = []
    oversize: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames.sort()
        for filename in sorted(filenames):
            full = Path(dirpath) / filename
            rel = full.relative_to(root)
            if full.is_symlink() or not full.is_file() or names.is_excluded(rel.parts):
                continue
            st = full.lstat()
            if (st.st_dev, st.st_ino) in raw_inodes:
                continue
            shown = f"{prefix}/{rel.as_posix()}" if prefix else rel.as_posix()
            data, binary, too_big = _read(full)
            paths.append(shown)
            if too_big:
                oversize.append(shown)
            elif binary:
                binaries[shown] = data
            else:
                texts[shown] = data.decode("utf-8", errors="replace")
    return Tree(texts, binaries, tuple(paths), tuple(oversize))


def _display_prefix(tree: Path, root: Path) -> str:
    real_root = Path(root).resolve()
    for base, label in ((real_root / "unpacked", "unpacked"), (real_root / "harvest" / "redacted", "redacted"),
                        (real_root / "build", "build")):
        if tree == base or tree.is_relative_to(base):
            rel = tree.relative_to(base).as_posix()
            return label if rel == "." else f"{label}/{rel}"
    return ""


def _staging_unpack(root: Path) -> Path | None:
    """build/unpack, only when neither build nor build/unpack escapes (symlinks) the real build/ directory."""
    build = root / "build"
    if build.is_symlink():
        return None
    unpack = (build / "unpack").resolve()
    real_build = build.resolve()
    return unpack if unpack.is_relative_to(real_build) else None


def _checked_tree(tree: Path, root: Path) -> Path:
    """unpacked/ and harvest/redacted (via check_path), plus build/unpack, the staging tree that still holds binaries.
    The inventories never leave the machine, so build/unpack is safe; harvest/raw and anything else stays refused."""
    candidate = tree if tree.is_absolute() else root / tree
    real = candidate.resolve()
    raw = paths._raw_root(root)
    if real == raw or real.is_relative_to(raw):
        raise PathRefused("refused: path is under harvest/raw")
    staging = _staging_unpack(root)
    if staging is not None and (real == staging or real.is_relative_to(staging)):
        return real
    return check_path(candidate, root)


def _out_dir(root: Path, out: Path | None) -> Path:
    target = (Path(out) if out else Path(root) / OUT_REL)
    target = target if target.is_absolute() else Path(root) / target
    allowed = Path(root).resolve() / "findings" / "raw"
    real = target.resolve()
    if real != allowed and not real.is_relative_to(allowed):
        raise PathRefused(f"refused: output must be under findings/raw, got {out}")
    return target


def main(argv: Sequence[str] | None = None, out: Callable[[str], None] = print) -> int:
    ap = argparse.ArgumentParser(description="Build deterministic Phase 2 ground-truth inventories (no API calls).")
    ap.add_argument("--root", type=Path, default=Path(os.environ.get("RECON_ROOT", ".")))
    ap.add_argument("--tree", required=True, type=Path, help="rootfs dir under unpacked/ or harvest/redacted")
    ap.add_argument("--out", type=Path, help="output dir under findings/raw (default: findings/raw/ground-truth)")
    args = ap.parse_args(argv)
    try:
        root = args.root.resolve()
        tree_dir = _checked_tree(args.tree, root)
        if not tree_dir.is_dir():
            raise PathRefused(f"refused: {args.tree} is not a directory")
        target = _out_dir(root, args.out)
        tree = load_tree(tree_dir, _display_prefix(tree_dir, root), paths._raw_root(root))
        counts = write_all(build(tree.texts, tree.binaries, tree.paths), target)
    except (PathRefused, OSError) as exc:
        print(scrub(f"inventory: refused: {exc}"), file=sys.stderr)
        return EXIT_REFUSED
    for name, n in counts.items():
        out(f"{name}: {n}")
    out(f"files: {len(tree.paths)} ({len(tree.texts)} text, {len(tree.binaries)} binary, "
        f"{len(tree.skipped_oversize)} oversize skipped)")
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
