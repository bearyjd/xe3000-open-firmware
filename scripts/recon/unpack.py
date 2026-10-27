"""Stock-firmware unpack pipeline: safe extraction -> sanitised staging tree (build/) -> redacted output (unpacked/).

Never executes anything from the image. Image files go through unblob (a parser) inside a network-less container;
tar inputs go through safe_extract_tar. Binaries stay in the staging tree; unpacked/ gets redacted text, the kernel FIT
and the DTBs only. Reports carry names and rule ids, never values.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tarfile
from dataclasses import dataclass
from pathlib import Path

from recon import fdt
from recon.fdt import Blob, parse_fdt
from recon.redact import EXCLUDED, MARKER_NAME, SKIPPED_BINARY, _load_salt, redact_tree
from recon.unpack_tar import UnpackError, safe_extract_tar, sanitize_tree

__all__ = ["UnpackError", "Artifacts", "parse_fdt", "safe_extract_tar", "sanitize_tree", "find_artifacts", "stage_output",
           "run_unblob", "neutralize_symlinks", "unpack_nested", "main"]

UNBLOB_TIMEOUT_S = 3600
ROOTFS_MARKERS = ("bin", "lib", "usr", "sbin")
MAX_SCAN_BYTES = 2 << 30


@dataclass(frozen=True)
class Artifacts:
    rootfs: Path | None
    fits: tuple[Blob, ...]
    dtbs: tuple[Blob, ...]


def _file_count(path: Path) -> int:
    return sum(len(files) for _d, _s, files in os.walk(path, followlinks=False))


def _find_rootfs(tree: Path) -> Path | None:
    best: tuple[int, Path] | None = None
    for dirpath, dirnames, _files in os.walk(tree, followlinks=False):
        here = Path(dirpath)
        real = {d for d in dirnames if not (here / d).is_symlink()}
        if "etc" in real and real & set(ROOTFS_MARKERS):
            score = _file_count(here)
            if best is None or score > best[0]:
                best = (score, here)
    return best[1] if best else None


def find_artifacts(tree: Path) -> Artifacts:
    """Locate the rootfs directory and carve kernel FITs / DTBs from every file outside it."""
    tree = Path(tree)
    rootfs = _find_rootfs(tree)
    fits: dict[str, Blob] = {}
    dtbs: dict[str, Blob] = {}

    def keep(into: dict[str, Blob], blob: Blob) -> None:
        into.setdefault(hashlib.sha256(blob.data).hexdigest(), blob)

    for dirpath, _dirs, files in os.walk(tree, followlinks=False):
        here = Path(dirpath)
        if rootfs is not None and (here == rootfs or rootfs in here.parents):
            continue
        for name in sorted(files):
            path = here / name
            if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_SCAN_BYTES:
                continue
            for blob, parsed in fdt.carve_file(path, path.relative_to(tree).as_posix()):
                if fdt.is_fit(parsed):
                    keep(fits, blob)
                    for i, data in enumerate(fdt.fit_dtb_images(parsed)):
                        keep(dtbs, Blob(blob.source, blob.offset, data))
                else:
                    keep(dtbs, blob)
    return Artifacts(rootfs, tuple(fits.values()), tuple(dtbs.values()))


def _model(blob: Blob) -> str:
    tree = parse_fdt(blob.data)
    raw = (tree or {"props": {}})["props"].get("model", b"")
    return raw.rstrip(b"\0").decode("utf-8", "replace")[:80]


def _write_blobs(blobs: tuple[Blob, ...], directory: Path, stem: str, suffix: str) -> list[dict]:
    rows = []
    for i, blob in enumerate(blobs):
        directory.mkdir(parents=True, exist_ok=True)
        name = f"{stem}-{i}{suffix}"
        (directory / name).write_bytes(blob.data)
        (directory / name).chmod(0o644)
        rows.append({"file": f"{directory.name}/{name}", "bytes": len(blob.data), "source": blob.source,
                     "offset": blob.offset, "sha256": hashlib.sha256(blob.data).hexdigest(), "model": _model(blob)})
    return rows


def _check_target(out: Path) -> None:
    if out.exists() and (not out.is_dir() or any(out.iterdir())):
        raise UnpackError("output directory exists and is not empty")


def stage_output(tree: Path, out: Path, salt: str = "") -> dict:
    """Write redacted rootfs text, kernel FIT(s) and DTB(s) under `out`; return the names-only layout."""
    tree, out = Path(tree), Path(out)
    _check_target(out)
    art = find_artifacts(tree)
    if art.rootfs is None and not art.fits and not art.dtbs:
        raise UnpackError("no rootfs, kernel FIT or DTB recognised in the image")
    out.mkdir(parents=True, exist_ok=True)
    report: list[dict] = []
    staged: list[str] = []
    withheld = 0
    top: list[str] = []
    if art.rootfs is not None:
        report = redact_tree(art.rootfs, out / "rootfs", salt=salt)
        withheld = len({r["file"] for r in report if r["rule"] in (EXCLUDED, SKIPPED_BINARY)})
        staged = sorted(f"rootfs/{p.relative_to(out / 'rootfs').as_posix()}" for p in (out / "rootfs").rglob("*") if p.is_file())
        for p in staged:
            (out / p).chmod(0o644)
        top = sorted(p.name for p in art.rootfs.iterdir())
    layout = {
        "rootfs_top_level": top,
        "rootfs_files_staged": len(staged),
        "rootfs_files_withheld": withheld,
        "rootfs_text_files": staged,
        "kernel": _write_blobs(art.fits, out / "kernel", "fit", ".itb"),
        "dtb": _write_blobs(art.dtbs, out / "dtb", "board", ".dtb"),
    }
    (out / "layout.json").write_text(json.dumps(layout, indent=2, sort_keys=True) + "\n")
    (out / "redaction-report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    (out / MARKER_NAME).write_text("unpacked and redacted by unpack.py; values are never listed\n")
    return layout


def run_unblob(image: Path, work: Path, tree: Path | None = None, tag: str = "") -> Path:
    """Run unblob on `image`, extracting under `tree` (default work/tree); its log and TMPDIR stay inside `work`."""
    exe = shutil.which("unblob")
    if exe is None:
        raise UnpackError("unblob is not installed (run this inside the unpack container)")
    tree, tmp = tree or work / "tree", work / "tmp"
    for d in (tree, tmp):
        d.mkdir(parents=True, exist_ok=True)
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "TMPDIR": str(tmp), "HOME": str(tmp), "LANG": "C.UTF-8"}
    argv = [exe, "-e", str(tree), "--log", str(work / f"unblob{tag}.log"), str(image)]
    try:
        res = subprocess.run(argv, cwd=tmp, env=env, capture_output=True, text=True, timeout=UNBLOB_TIMEOUT_S, check=False)
    except subprocess.TimeoutExpired as exc:
        raise UnpackError("unblob timed out") from exc
    if res.returncode != 0:
        raise UnpackError(f"unblob exited with status {res.returncode}")
    return tree


NESTED_MIN_BYTES = 1 << 20


def _unsafe_symlinks(tree: Path) -> list[Path]:
    """Symlinks nested extraction must not see: absolute, escaping the tree, or pointing at a directory."""
    root = tree.resolve()
    bad = []
    for dirpath, dirnames, filenames in os.walk(tree, followlinks=False):
        for name in dirnames + filenames:
            path = Path(dirpath) / name
            if not path.is_symlink():
                continue
            real = Path(os.path.realpath(path))
            if os.readlink(path).startswith("/") or not real.is_relative_to(root) or real.is_dir():
                bad.append(path)
    return bad


def neutralize_symlinks(tree: Path) -> list[dict]:
    """Remove every symlink a nested extractor could write through (absolute, escaping, or to a directory).
    Returns manifest rows {path, action: skipped, reason: symlink}."""
    rows = []
    for path in _unsafe_symlinks(tree):
        path.unlink()
        rows.append({"path": path.relative_to(tree).as_posix(), "action": "skipped", "reason": "symlink"})
    return rows


def unpack_nested(tree: Path, work: Path, rows: list[dict] | None = None) -> int:
    """A sysupgrade tar wraps the real kernel/rootfs images: when the tar yields no rootfs, run unblob over each large
    file in it (extracting beside it). Unsafe symlinks are removed first (recorded into `rows`) and extraction is
    refused if any remain. Returns how many files were tried."""
    if find_artifacts(tree).rootfs is not None or shutil.which("unblob") is None:
        return 0
    removed = neutralize_symlinks(tree)
    if rows is not None:
        rows.extend(removed)
    if _unsafe_symlinks(tree):
        raise UnpackError("unsafe symlinks remain in the staging tree; refusing nested extraction")
    files = sorted(p for p in tree.rglob("*") if p.is_file() and not p.is_symlink() and p.stat().st_size >= NESTED_MIN_BYTES)
    for i, path in enumerate(files):
        run_unblob(path, work, tree=tree, tag=f"-nested{i}")
    return len(files)


def _non_empty(p: Path) -> bool:
    return p.exists() and (not p.is_dir() or any(p.iterdir()))


def _validate(args: argparse.Namespace) -> str | None:
    inp, work, out = args.input, args.work, args.out
    if inp.is_symlink() or not inp.is_file():
        return "--input must be a regular file (not a symlink)"
    rw, ro, ri = work.resolve(), out.resolve(), inp.resolve()
    if rw == ro or rw.is_relative_to(ro) or ro.is_relative_to(rw):
        return "--work and --out must not overlap"
    if ri.is_relative_to(rw) or ri.is_relative_to(ro):
        return "--input must not live under --work or --out"
    if _non_empty(work) or _non_empty(out):
        return "--work and --out must be new or empty"
    return None


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Unpack a stock firmware image or rootfs tar into a redacted tree.")
    ap.add_argument("--input", required=True, type=Path)
    ap.add_argument("--work", required=True, type=Path, help="staging dir (unredacted; binaries kept; build/ only)")
    ap.add_argument("--out", required=True, type=Path, help="redacted output dir (unpacked/<name>)")
    ap.add_argument("--salt", help="MAC pseudonym salt (default: as redact.py)")
    ap.add_argument("--root", type=Path, default=Path(os.environ.get("RECON_ROOT", ".")))
    args = ap.parse_args(argv)
    problem = _validate(args)
    if problem:
        print(f"unpack: {problem}", file=sys.stderr)
        return 2
    try:
        args.work.mkdir(parents=True, exist_ok=True)
        if tarfile.is_tarfile(args.input):
            rows = safe_extract_tar(args.input, args.work / "tree")
            tree = args.work / "tree"
            nested_rows: list[dict] = []
            unpack_nested(tree, args.work, nested_rows)
            rows = rows + nested_rows
        else:
            tree, rows = run_unblob(args.input, args.work), []
        rows = rows + sanitize_tree(tree)
        layout = stage_output(tree, args.out, salt=_load_salt(args.salt, args.root.resolve()))
    except UnpackError as exc:
        print(f"unpack: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"unpack: filesystem error ({type(exc).__name__}, errno {exc.errno})", file=sys.stderr)
        return 1
    notable = [r for r in rows if r["action"] != "extracted"]
    (args.out / "extract-report.json").write_text(json.dumps(notable, indent=2, sort_keys=True) + "\n")
    print(f"unpack: rootfs files staged={layout['rootfs_files_staged']} withheld={layout['rootfs_files_withheld']} "
          f"fit={len(layout['kernel'])} dtb={len(layout['dtb'])} notable_extract_rows={len(notable)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
