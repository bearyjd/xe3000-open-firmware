"""Link-chain and symlink-then-directory attacks against the safe tar extractor (synthetic tars built at test time)."""
from __future__ import annotations

import io
import os
import stat
import tarfile
from pathlib import Path

from conftest import Lazy

unpack = Lazy("recon.unpack")


def _tar(path: Path, members) -> Path:
    with tarfile.open(path, "w") as tf:
        for name, type_, link in members:
            ti = tarfile.TarInfo(name)
            ti.type = type_
            ti.mode = 0o755
            ti.linkname = link
            tf.addfile(ti, io.BytesIO(b"") if type_ == tarfile.REGTYPE else None)
    return path


def _mode(p: Path) -> int:
    return stat.S_IMODE(os.lstat(p).st_mode)


def _tree_links_inside(dest: Path) -> list[str]:
    root = dest.resolve()
    bad = []
    for dirpath, dirnames, filenames in os.walk(dest, followlinks=False):
        for name in dirnames + filenames:
            p = Path(dirpath) / name
            if p.is_symlink() and not os.readlink(p).startswith("/"):
                if not Path(os.path.realpath(p)).is_relative_to(root):
                    bad.append(p.relative_to(dest).as_posix())
    return bad


def test_relative_link_chain_cannot_escape_the_root(tmp_path):
    dest = tmp_path / "work" / "x"
    chain = [("a/", tarfile.DIRTYPE, ""), ("a/b", tarfile.SYMTYPE, ".."), ("L1", tarfile.SYMTYPE, "a/b/..")]
    for k in range(2, 5):
        chain.append((f"L{k}", tarfile.SYMTYPE, f"L{k - 1}/.."))
    rows = unpack.safe_extract_tar(_tar(tmp_path / "c.tar", chain), dest)
    assert _tree_links_inside(dest) == []
    assert any(r["reason"] == "symlink-escape" for r in rows)


def test_directory_member_on_escaping_link_chain_does_not_chmod_outside(tmp_path):
    outside = tmp_path / "work"
    dest = outside / "x"
    outside.mkdir()
    outside.chmod(0o700)
    members = [("a/", tarfile.DIRTYPE, ""), ("a/b", tarfile.SYMTYPE, ".."), ("L1", tarfile.SYMTYPE, "a/b/.."),
               ("L1/", tarfile.DIRTYPE, "")]
    unpack.safe_extract_tar(_tar(tmp_path / "c.tar", members), dest)
    assert _mode(outside) == 0o700
    assert _tree_links_inside(dest) == []


def test_directory_member_on_existing_symlink_does_not_chmod_target(tmp_path):
    victim = tmp_path / "victim"
    victim.mkdir()
    victim.chmod(0o700)
    dest = tmp_path / "work" / "x"
    members = [("d", tarfile.SYMTYPE, str(victim)), ("d/", tarfile.DIRTYPE, "")]
    rows = unpack.safe_extract_tar(_tar(tmp_path / "c.tar", members), dest)
    assert _mode(victim) == 0o700
    assert os.path.islink(dest / "d")
    assert any(r["path"] == "d" and r["action"] == "recorded" for r in rows)


def test_sanitize_tree_removes_link_chains_that_escape_via_realpath(tmp_path):
    root = tmp_path / "tree"
    (root / "a").mkdir(parents=True)
    os.symlink("..", root / "a" / "b")
    os.symlink("a/b/..", root / "L1")
    rows = unpack.sanitize_tree(root)
    assert not os.path.lexists(root / "L1")
    assert {"path": "L1", "action": "removed", "reason": "symlink-escape"} in rows
    assert os.path.islink(root / "a" / "b")


def _tree_contains(dest: Path, needle: bytes) -> bool:
    for dirpath, _dirs, files in os.walk(dest, followlinks=False):
        for name in files:
            p = Path(dirpath) / name
            if not p.is_symlink() and needle in p.read_bytes():
                return True
    return False


def test_hardlink_to_absolute_symlink_does_not_copy_outside_file(tmp_path):
    marker = b"outside-" + os.urandom(8).hex().encode()
    sentinel = tmp_path / "outside-file"
    sentinel.write_bytes(marker)
    dest = tmp_path / "work" / "x"
    members = [("s", tarfile.SYMTYPE, str(sentinel)), ("h", tarfile.LNKTYPE, "s")]
    rows = unpack.safe_extract_tar(_tar(tmp_path / "c.tar", members), dest)
    assert not os.path.lexists(dest / "h")
    assert {"path": "h", "action": "skipped", "reason": "hardlink-missing"}.items() <= next(r for r in rows if r["path"] == "h").items()
    assert not _tree_contains(dest, marker)


def test_hardlink_through_symlinked_parent_does_not_copy_outside_file(tmp_path):
    marker = b"outside-" + os.urandom(8).hex().encode()
    outdir = tmp_path / "outside-dir"
    outdir.mkdir()
    (outdir / "sentinel").write_bytes(marker)
    dest = tmp_path / "work" / "x"
    members = [("dl", tarfile.SYMTYPE, str(outdir)), ("h2", tarfile.LNKTYPE, "dl/sentinel")]
    rows = unpack.safe_extract_tar(_tar(tmp_path / "c.tar", members), dest)
    assert not os.path.lexists(dest / "h2")
    assert next(r for r in rows if r["path"] == "h2")["reason"] == "hardlink-missing"
    assert not _tree_contains(dest, marker)
