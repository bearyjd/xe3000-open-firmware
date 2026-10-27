import os

import pytest

from recon import paths


def test_accepts_redacted_and_unpacked(root, fixture_tree):
    files = paths.list_input_files(root / "harvest" / "redacted", root)
    names = {f.name for f in files}
    assert "redacted/etc/config/network" in names
    (root / "unpacked" / "a").mkdir()
    (root / "unpacked" / "a" / "x.sh").write_text("echo\n")
    assert [f.name for f in paths.list_input_files(root / "unpacked", root)] == ["unpacked/a/x.sh"]


def test_refuses_raw_direct(root):
    (root / "harvest" / "raw" / "t").mkdir()
    with pytest.raises(paths.PathRefused):
        paths.list_input_files(root / "harvest" / "raw" / "t", root)
    with pytest.raises(paths.PathRefused):
        paths.list_input_files(root / "harvest" / "raw", root)


def test_refuses_dotdot_traversal(root):
    sneaky = root / "harvest" / "redacted" / ".." / "raw"
    with pytest.raises(paths.PathRefused):
        paths.list_input_files(sneaky, root)
    with pytest.raises(paths.PathRefused):
        paths.check_path(root / "harvest" / "redacted" / ".." / ".." / "cache", root)


def test_refuses_symlink_file_into_raw(root):
    (root / "harvest" / "raw" / "secret.txt").write_text("raw\n")
    (root / "harvest" / "redacted" / "ok.txt").write_text("fine\n")
    os.symlink(root / "harvest" / "raw" / "secret.txt", root / "harvest" / "redacted" / "link.txt")
    with pytest.raises(paths.PathRefused):
        paths.list_input_files(root / "harvest" / "redacted", root)


def test_refuses_symlinked_dir_into_raw(root):
    (root / "harvest" / "raw" / "d").mkdir()
    os.symlink(root / "harvest" / "raw" / "d", root / "harvest" / "redacted" / "dlink")
    with pytest.raises(paths.PathRefused):
        paths.list_input_files(root / "harvest" / "redacted", root)


def test_symlink_within_allowed_is_ok(root):
    (root / "harvest" / "redacted" / "a.txt").write_text("x\n")
    os.symlink(root / "harvest" / "redacted" / "a.txt", root / "harvest" / "redacted" / "b.txt")
    assert len(paths.list_input_files(root / "harvest" / "redacted", root)) == 2


def test_refuses_allowed_root_that_is_symlink_to_raw(tmp_path):
    base = tmp_path / "r"
    (base / "harvest" / "raw").mkdir(parents=True)
    os.symlink(base / "harvest" / "raw", base / "harvest" / "redacted")
    with pytest.raises(paths.PathRefused):
        paths.list_input_files(base / "harvest" / "redacted", base)


def test_refuses_outside_tree(root, tmp_path):
    with pytest.raises(paths.PathRefused):
        paths.check_path(tmp_path / "elsewhere", root)
