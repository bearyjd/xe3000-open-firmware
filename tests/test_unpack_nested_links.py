"""Nested unblob extraction must never write through symlinks planted by a crafted sysupgrade tar."""
from __future__ import annotations

import importlib
import os
from pathlib import Path

import pytest

from conftest import Lazy

unpack = Lazy("recon.unpack")
BIG = 1 << 20


def _tree(tmp_path: Path) -> Path:
    tree = tmp_path / "tree"
    (tree / "sysupgrade-x").mkdir(parents=True)
    (tree / "sysupgrade-x" / "root").write_bytes(b"\0" * BIG)
    return tree


def _install_fake_unblob(monkeypatch, tree: Path, calls: list) -> None:
    """A stand-in unblob that, like the real one, follows whatever links are in the tree when it writes."""
    monkeypatch.setattr(unpack.shutil, "which", lambda n: "/x/unblob")

    def fake(path, work, tree=tree, tag=""):
        calls.append(tag)
        for link in sorted(p for p in tree.rglob("*") if p.is_symlink()):
            if link.is_dir():
                (link / "pwned").write_text("x")
        return tree

    monkeypatch.setattr(importlib.import_module("recon.unpack"), "run_unblob", fake)


def _unsafe_links(tree: Path) -> list[str]:
    root = tree.resolve()
    return [p.relative_to(tree).as_posix() for p in tree.rglob("*")
            if p.is_symlink() and (os.readlink(p).startswith("/") or not Path(os.path.realpath(p)).is_relative_to(root))]


def test_absolute_symlink_chain_is_neutralised_before_nested_extraction(tmp_path, monkeypatch):
    victim = tmp_path / "victim"
    victim.mkdir()
    tree = _tree(tmp_path)
    os.symlink(str(victim), tree / "abs")
    os.symlink("../abs", tree / "sysupgrade-x" / "hop")
    os.symlink("hop", tree / "sysupgrade-x" / "hop2")
    calls: list = []
    _install_fake_unblob(monkeypatch, tree, calls)
    rows: list = []
    assert unpack.unpack_nested(tree, tmp_path / "work", rows) == 1
    assert calls and list(victim.iterdir()) == []
    assert _unsafe_links(tree) == []
    assert {r["path"] for r in rows if r["action"] == "skipped" and r["reason"] == "symlink"} >= {"abs", "sysupgrade-x/hop", "sysupgrade-x/hop2"}


def test_symlinked_directory_inside_the_tree_is_not_written_through(tmp_path, monkeypatch):
    tree = _tree(tmp_path)
    (tree / "real").mkdir()
    os.symlink("real", tree / "dirlink")
    calls: list = []
    _install_fake_unblob(monkeypatch, tree, calls)
    unpack.unpack_nested(tree, tmp_path / "work", [])
    assert calls
    assert not (tree / "real" / "pwned").exists()
    assert not os.path.islink(tree / "dirlink")


def test_nested_extraction_is_refused_if_an_unsafe_symlink_remains(tmp_path, monkeypatch):
    tree = _tree(tmp_path)
    os.symlink(str(tmp_path), tree / "abs")
    calls: list = []
    _install_fake_unblob(monkeypatch, tree, calls)
    monkeypatch.setattr(importlib.import_module("recon.unpack"), "neutralize_symlinks", lambda t: [])
    with pytest.raises(unpack.UnpackError):
        unpack.unpack_nested(tree, tmp_path / "work", [])
    assert calls == []


def test_symlinks_are_left_alone_when_no_nested_extraction_happens(tmp_path, monkeypatch):
    tree = tmp_path / "tree"
    (tree / "bin").mkdir(parents=True)
    (tree / "etc").mkdir()
    os.symlink("/bin/busybox", tree / "bin" / "sh")
    monkeypatch.setattr(unpack.shutil, "which", lambda n: "/x/unblob")
    assert unpack.unpack_nested(tree, tmp_path / "work", []) == 0
    assert os.path.islink(tree / "bin" / "sh")
