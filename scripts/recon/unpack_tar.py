"""Safe tar extraction and post-extraction tree sanitising. Nothing from an archive is ever executed or followed.

Policy: a bad member is skipped and recorded (never aborts the whole archive); symlinks that escape the root lexically
are not created; absolute symlinks are kept (they are rootfs-relative, chroot semantics) and recorded, and are never
followed on the host; hardlinks are copied only when their target is a regular file already inside the root;
device nodes, fifos and sockets are skipped; setuid/setgid bits are stripped.
"""
from __future__ import annotations

import os
import posixpath
import shutil
import stat
import tarfile
from pathlib import Path

MAX_MEMBERS = 500_000
MAX_MEMBER_BYTES = 2 << 30
MAX_TOTAL_BYTES = 8 << 30
_SUID = stat.S_ISUID | stat.S_ISGID


class UnpackError(Exception):
    """A clean, user-facing failure (never carries file contents)."""


def _row(path: str, action: str, reason: str = "") -> dict:
    return {"path": path, "action": action, "reason": reason}


def _norm_member(name: str) -> str | None:
    """Archive-relative normalised name, or None if absolute / traversing."""
    if name.startswith("/"):
        return None
    clean = posixpath.normpath(name)
    if clean == "." or clean == "":
        return ""
    if clean == ".." or clean.startswith("../") or "/../" in f"/{clean}/":
        return None
    return clean


def _escapes(parent_rel: str, target: str) -> bool:
    joined = posixpath.normpath(posixpath.join(parent_rel, target))
    return joined == ".." or joined.startswith("../")


def _resolves_inside(root: Path, link: Path) -> bool:
    """True if `link` (fully resolved through every hop) stays inside `root`."""
    return Path(os.path.realpath(link)).is_relative_to(root)


def _parent_chain_ok(root: Path, rel: str) -> str | None:
    """None if every existing parent of `rel` is a real directory; otherwise the skip reason."""
    cur = root
    for part in rel.split("/")[:-1]:
        cur = cur / part
        if os.path.islink(cur):
            return "symlink-parent"
        if cur.exists() and not cur.is_dir():
            return "conflict"
    return None


def _replace_slot(target: Path) -> None:
    if os.path.lexists(target):
        if target.is_dir() and not target.is_symlink():
            raise UnpackError("archive member replaces a directory")
        target.unlink()


def _copy_member(tf: tarfile.TarFile, member: tarfile.TarInfo, target: Path) -> None:
    src = tf.extractfile(member)
    if src is None:
        raise UnpackError("unreadable archive member")
    with src, target.open("xb") as dst:
        shutil.copyfileobj(src, dst)
    target.chmod(0o755 if member.mode & 0o111 else 0o644)


def _extract_one(tf: tarfile.TarFile, member: tarfile.TarInfo, root: Path) -> dict:
    rel = _norm_member(member.name)
    if rel is None:
        return _row(member.name, "skipped", "traversal")
    if rel == "":
        return _row(member.name, "ignored", "root")
    bad = _parent_chain_ok(root, rel)
    if bad:
        return _row(rel, "skipped", bad)
    target = root / rel
    parent_rel = posixpath.dirname(rel)
    if member.isdir():
        if os.path.islink(target):
            return _row(rel, "skipped", "symlink-conflict")
        target.mkdir(parents=True, exist_ok=True)
        if os.path.islink(target) or not target.is_dir():
            return _row(rel, "skipped", "conflict")
        os.chmod(target, 0o755)
        return _row(rel, "extracted")
    if member.issym():
        if member.linkname.startswith("/"):
            target.parent.mkdir(parents=True, exist_ok=True)
            _replace_slot(target)
            os.symlink(member.linkname, target)
            return _row(rel, "recorded", "symlink-absolute")
        if _escapes(parent_rel, member.linkname):
            return _row(rel, "skipped", "symlink-escape")
        target.parent.mkdir(parents=True, exist_ok=True)
        _replace_slot(target)
        os.symlink(member.linkname, target)
        if not _resolves_inside(root, target):
            target.unlink()
            return _row(rel, "skipped", "symlink-escape")
        return _row(rel, "extracted")
    if member.islnk():
        link = _norm_member(member.linkname)
        if link is None or link == "":
            return _row(rel, "skipped", "hardlink-escape")
        src = root / link
        if _parent_chain_ok(root, link) or os.path.islink(src) or not src.is_file():
            return _row(rel, "skipped", "hardlink-missing")
        target.parent.mkdir(parents=True, exist_ok=True)
        _replace_slot(target)
        shutil.copyfile(src, target)
        target.chmod(0o755 if member.mode & 0o111 else 0o644)
        return _row(rel, "extracted")
    if member.isreg():
        if member.size > MAX_MEMBER_BYTES:
            return _row(rel, "skipped", "too-large")
        target.parent.mkdir(parents=True, exist_ok=True)
        _replace_slot(target)
        _copy_member(tf, member, target)
        return _row(rel, "extracted")
    return _row(rel, "skipped", "special-file")


def safe_extract_tar(archive: Path, dest: Path) -> list[dict]:
    """Extract `archive` under `dest` member by member; return rows {path, action, reason} (one summary row for the
    extracted ones). Raises UnpackError if `archive` is not a readable tar."""
    archive, dest = Path(archive), Path(dest)
    if not tarfile.is_tarfile(archive):
        raise UnpackError("input is not a tar archive")
    dest.mkdir(parents=True, exist_ok=True)
    root = dest.resolve()
    rows: list[dict] = []
    extracted = total = 0
    try:
        with tarfile.open(archive, "r:*") as tf:
            for count, member in enumerate(tf, 1):
                if count > MAX_MEMBERS:
                    raise UnpackError("archive has too many members")
                total += max(member.size, 0)
                if total > MAX_TOTAL_BYTES:
                    raise UnpackError("archive expands beyond the size cap")
                row = _extract_one(tf, member, root)
                if row["action"] == "extracted":
                    extracted += 1
                elif row["action"] != "ignored":
                    rows.append(row)
    except (tarfile.TarError, OSError, EOFError) as exc:
        raise UnpackError(f"tar extraction failed: {type(exc).__name__}") from exc
    rows.append({"path": "", "action": "extracted", "reason": "", "count": extracted})
    return rows


def sanitize_tree(root: Path) -> list[dict]:
    """Walk an extracted tree without following links: drop escaping symlinks and special files, strip setuid,
    make everything traversable. Returns rows {path, action, reason}."""
    root = Path(root)
    real_root = root.resolve()
    rows: list[dict] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        here = Path(dirpath)
        rel_dir = here.relative_to(root).as_posix()
        rel_dir = "" if rel_dir == "." else rel_dir
        if not rel_dir:
            here.chmod(here.stat().st_mode | 0o700)
        for name in sorted(dirnames + filenames):
            path = here / name
            rel = posixpath.join(rel_dir, name)
            mode = os.lstat(path).st_mode
            if stat.S_ISLNK(mode):
                target = os.readlink(path)
                if target.startswith("/"):
                    rows.append(_row(rel, "recorded", "symlink-absolute"))
                elif _escapes(rel_dir, target) or not _resolves_inside(real_root, path):
                    path.unlink()
                    rows.append(_row(rel, "removed", "symlink-escape"))
            elif stat.S_ISREG(mode):
                new = (mode | 0o600) & ~_SUID
                if new != mode & 0o7777:
                    path.chmod(new & 0o7777)
                if mode & _SUID:
                    rows.append(_row(rel, "stripped", "setuid"))
            elif stat.S_ISDIR(mode):
                path.chmod((mode | 0o700) & 0o7777 & ~_SUID)
            else:
                path.unlink()
                rows.append(_row(rel, "removed", "special-file"))
    return rows
