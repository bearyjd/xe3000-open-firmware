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


# ---- round 3: symlink / hardlink bypass of name-based decisions ----

def test_file_symlinks_are_skipped_not_followed(root):
    red = root / "harvest" / "redacted"
    (red / "etc" / "config").mkdir(parents=True)
    (red / "etc" / "init.d").mkdir(parents=True)
    (red / "etc" / "config" / "wireless").write_text("WIRELESS-SECRET-BYTES\n")
    os.symlink("../config/wireless", red / "etc" / "init.d" / "gl_cloud")
    (red / "etc" / "init.d" / "real").write_text("ok\n")
    names = [f.name for f in paths.list_input_files(red, root)]
    assert "redacted/etc/init.d/gl_cloud" not in names and "redacted/etc/init.d/real" in names
    assert paths.list_symlinks(red, root) == ("redacted/etc/init.d/gl_cloud",)


def test_symlink_to_outside_the_root_is_still_refused(root, tmp_path):
    (tmp_path / "outside.txt").write_text("x\n")
    os.symlink(tmp_path / "outside.txt", root / "harvest" / "redacted" / "l")
    with pytest.raises(paths.PathRefused):
        paths.list_input_files(root / "harvest" / "redacted", root)


def test_hardlinks_are_refused_with_a_clear_message(root):
    red = root / "harvest" / "redacted"
    (red / "a").write_text("x\n")
    os.link(red / "a", red / "b")
    with pytest.raises(paths.PathRefused, match="hardlink"):
        paths.list_input_files(red, root)


def test_hardlink_to_a_file_outside_the_tree_is_refused(root, tmp_path):
    (tmp_path / "o.txt").write_text("x\n")
    os.link(tmp_path / "o.txt", root / "harvest" / "redacted" / "h")
    with pytest.raises(paths.PathRefused, match="hardlink"):
        paths.list_input_files(root / "harvest" / "redacted", root)


def test_real_path_must_match_the_candidate_path(root):
    red = root / "harvest" / "redacted"
    (red / "etc" / "config").mkdir(parents=True)
    (red / "etc" / "config" / "wireless").write_text("W\n")
    (red / "etc" / "init.d").symlink_to("config")  # directory link: etc/init.d/wireless is really etc/config/wireless
    names = [f.name for f in paths.list_input_files(red, root)]
    assert names == ["redacted/etc/config/wireless"]
