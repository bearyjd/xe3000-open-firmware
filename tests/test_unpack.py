"""Safe extraction and staging of a stock firmware tree (pure Python; synthetic tars built at test time)."""
from __future__ import annotations

import io
import json
import os
import stat
import tarfile
from pathlib import Path

import pytest

import fdt_gen
from conftest import Lazy

unpack = Lazy("recon.unpack")

PLANTED = "Tr0ub4dor" + "Pw42" + "xyz"  # assembled at runtime


def _add(tf: tarfile.TarFile, name: str, data: bytes = b"", *, type_=tarfile.REGTYPE, link: str = "", mode: int = 0o644) -> None:
    ti = tarfile.TarInfo(name)
    ti.type = type_
    ti.mode = mode
    ti.linkname = link
    if type_ == tarfile.REGTYPE:
        ti.size = len(data)
        tf.addfile(ti, io.BytesIO(data))
    else:
        tf.addfile(ti)


def _tar(path: Path, members) -> Path:
    with tarfile.open(path, "w") as tf:
        for m in members:
            _add(tf, m[0], *m[1:2], **(m[2] if len(m) > 2 else {}))
    return path


@pytest.fixture
def arena(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    sentinel = outside / "sentinel"
    sentinel.write_text("untouched")
    dest = tmp_path / "work" / "x"
    return tmp_path, outside, sentinel, dest


def _reasons(rows):
    return {r["reason"] for r in rows if r["action"] != "extracted"}


def test_plain_tar_extracts_and_strips_setuid(arena):
    tmp, _o, _s, dest = arena
    tar = _tar(tmp / "a.tar", [("etc/", b"", {"type_": tarfile.DIRTYPE, "mode": 0o755}), ("etc/hostname", b"router\n"),
                               ("bin/su", b"x", {"mode": 0o4755})])
    rows = unpack.safe_extract_tar(tar, dest)
    assert (dest / "etc" / "hostname").read_text() == "router\n"
    assert not (dest / "bin" / "su").stat().st_mode & (stat.S_ISUID | stat.S_ISGID)
    assert any(r["action"] == "extracted" for r in rows)


def test_not_a_tar_is_a_clean_error(arena):
    tmp, _o, _s, dest = arena
    (tmp / "junk").write_bytes(b"not a tar" * 100)
    with pytest.raises(unpack.UnpackError):
        unpack.safe_extract_tar(tmp / "junk", dest)


def test_dotdot_member_is_skipped(arena):
    tmp, outside, sentinel, dest = arena
    tar = _tar(tmp / "a.tar", [("../outside/pwn", b"x"), ("ok", b"y")])
    rows = unpack.safe_extract_tar(tar, dest)
    assert not (outside / "pwn").exists() and sentinel.read_text() == "untouched"
    assert (dest / "ok").exists() and "traversal" in _reasons(rows)


def test_absolute_member_is_skipped(arena):
    tmp, outside, sentinel, dest = arena
    target = str(outside / "abs-pwn")
    tar = _tar(tmp / "a.tar", [(target, b"x"), ("ok", b"y")])
    rows = unpack.safe_extract_tar(tar, dest)
    assert not (outside / "abs-pwn").exists() and sentinel.read_text() == "untouched"
    assert "traversal" in _reasons(rows) and (dest / "ok").exists()


@pytest.mark.parametrize("kind", ["relative", "absolute"])
def test_write_through_symlinked_directory_is_refused(arena, kind):
    tmp, outside, sentinel, dest = arena
    link = "../../outside" if kind == "relative" else str(outside)
    tar = _tar(tmp / "a.tar", [("d", b"", {"type_": tarfile.SYMTYPE, "link": link}), ("d/pwn", b"x")])
    unpack.safe_extract_tar(tar, dest)
    assert not (outside / "pwn").exists() and sentinel.read_text() == "untouched"
    assert list(outside.iterdir()) == [sentinel]


def test_escaping_relative_symlink_is_not_created_but_absolute_is_kept_and_recorded(arena):
    tmp, _o, _s, dest = arena
    tar = _tar(tmp / "a.tar", [("etc/", b"", {"type_": tarfile.DIRTYPE}),
                               ("etc/esc", b"", {"type_": tarfile.SYMTYPE, "link": "../../../etc/passwd"}),
                               ("etc/inside", b"", {"type_": tarfile.SYMTYPE, "link": "../bin/sh"}),
                               ("var", b"", {"type_": tarfile.SYMTYPE, "link": "/tmp"})])
    rows = unpack.safe_extract_tar(tar, dest)
    assert not os.path.lexists(dest / "etc" / "esc")
    assert os.readlink(dest / "etc" / "inside") == "../bin/sh"
    assert os.readlink(dest / "var") == "/tmp"  # chroot semantics: recorded, never followed on the host
    assert "symlink-escape" in _reasons(rows) and "symlink-absolute" in _reasons(rows)


def test_hardlinks_outside_are_refused_inside_are_copied(arena):
    tmp, outside, sentinel, dest = arena
    tar = _tar(tmp / "a.tar", [("real", b"data"),
                               ("h-abs", b"", {"type_": tarfile.LNKTYPE, "link": "/etc/passwd"}),
                               ("h-rel", b"", {"type_": tarfile.LNKTYPE, "link": "../outside/sentinel"}),
                               ("h-ok", b"", {"type_": tarfile.LNKTYPE, "link": "real"})])
    rows = unpack.safe_extract_tar(tar, dest)
    assert not (dest / "h-abs").exists() and not (dest / "h-rel").exists()
    assert (dest / "h-ok").read_text() == "data"
    assert sentinel.read_text() == "untouched" and sentinel.stat().st_nlink == 1
    assert "hardlink-escape" in _reasons(rows)


def test_device_nodes_and_fifos_are_skipped(arena):
    tmp, _o, _s, dest = arena
    tar = _tar(tmp / "a.tar", [("dev/null", b"", {"type_": tarfile.CHRTYPE}), ("dev/pipe", b"", {"type_": tarfile.FIFOTYPE}),
                               ("ok", b"y")])
    rows = unpack.safe_extract_tar(tar, dest)
    assert not (dest / "dev" / "null").exists() and not (dest / "dev" / "pipe").exists()
    assert "special-file" in _reasons(rows)


def test_sanitize_tree_removes_escaping_symlinks_and_special_files(tmp_path):
    root = tmp_path / "tree"
    (root / "etc").mkdir(parents=True)
    os.symlink("../../../etc/passwd", root / "etc" / "esc")
    os.symlink("/tmp", root / "var")
    os.symlink("hostname", root / "etc" / "ok")
    (root / "etc" / "hostname").write_text("r")
    os.mkfifo(root / "etc" / "fifo")
    suid = root / "etc" / "suid"
    suid.write_text("x")
    suid.chmod(0o4755)
    rows = unpack.sanitize_tree(root)
    assert not os.path.lexists(root / "etc" / "esc") and not os.path.lexists(root / "etc" / "fifo")
    assert os.readlink(root / "var") == "/tmp" and os.readlink(root / "etc" / "ok") == "hostname"
    assert not suid.stat().st_mode & stat.S_ISUID
    assert {"symlink-escape", "symlink-absolute", "special-file", "setuid"} <= _reasons(rows)


def test_parse_fdt_roundtrip_and_garbage():
    blob = fdt_gen.make_fit(dtb=fdt_gen.make_dtb())
    tree = unpack.parse_fdt(blob)
    assert tree is not None and set(tree["children"]) == {"images", "configurations"}
    assert tree["children"]["images"]["children"]["fdt-1"]["props"]["type"].rstrip(b"\0") == b"flat_dt"
    assert unpack.parse_fdt(b"\xd0\x0d\xfe\xed" + b"\xff" * 60) is None
    assert unpack.parse_fdt(blob[:50]) is None
    assert unpack.parse_fdt(b"") is None


def test_find_artifacts_classifies_rootfs_fit_and_dtb(tmp_path):
    tree = tmp_path / "t"
    (tree / "a" / "etc").mkdir(parents=True)
    (tree / "a" / "bin").mkdir()
    (tree / "a" / "etc" / "x").write_text("1")
    (tree / "a" / "bin" / "sh").write_text("2")
    (tree / "decoy" / "etc").mkdir(parents=True)
    (tree / "decoy" / "etc" / "only").write_text("3")
    inner_dtb = fdt_gen.make_dtb("inner,board")
    fit = fdt_gen.make_fit(dtb=inner_dtb)
    (tree / "0-100.unknown").write_bytes(b"\0" * 64 + fit + b"\0" * 12 + fdt_gen.make_dtb("loose,board") + b"\0" * 40)
    art = unpack.find_artifacts(tree)
    assert art.rootfs == tree / "a"
    assert len(art.fits) == 1 and art.fits[0].data == fit
    models = sorted(b"inner,board" in b.data or b"loose,board" in b.data for b in art.dtbs)
    assert len(art.dtbs) == 2 and all(models)


def test_find_artifacts_without_anything(tmp_path):
    (tmp_path / "x").write_bytes(b"nothing here")
    art = unpack.find_artifacts(tmp_path)
    assert art.rootfs is None and art.fits == () and art.dtbs == ()


def _rootfs(base: Path) -> Path:
    root = base / "raw" / "fs"
    for d in ("etc/config", "etc/dropbear", "bin", "usr/lib"):
        (root / d).mkdir(parents=True)
    (root / "etc/config/wireless").write_text(f"config wifi-iface\n\toption key '{PLANTED}'\n\toption ssid 'x'\n")
    (root / "etc/shadow").write_text("root:*:0:0:::\n")
    (root / "etc/dropbear/dropbear_rsa_host_key").write_bytes(b"\0\1binary-host-key")
    (root / "bin/busybox").write_bytes(b"\x7fELF\0\0")
    (root / "etc/banner").write_text("OpenWrt\n")
    return root


def test_stage_output_redacts_excludes_and_keeps_names_only(tmp_path):
    raw = _rootfs(tmp_path).parent
    fit = fdt_gen.make_fit(dtb=fdt_gen.make_dtb())
    (raw / "blob.unknown").write_bytes(fit)
    out = tmp_path / "unpacked" / "stock"
    layout = unpack.stage_output(raw, out, salt="s")
    wireless = (out / "rootfs/etc/config/wireless").read_text()
    assert PLANTED not in wireless and "<REDACTED" in wireless and "ssid" in wireless
    assert (out / "rootfs/etc/banner").read_text() == "OpenWrt\n"
    assert not (out / "rootfs/etc/shadow").exists() and not (out / "rootfs/etc/dropbear").exists()
    assert not (out / "rootfs/bin/busybox").exists()  # binaries stay in build/, never in unpacked/
    assert list((out / "kernel").glob("*.itb")) and list((out / "dtb").glob("*.dtb"))
    blob = json.dumps(layout) + (out / "layout.json").read_text()
    assert PLANTED not in blob and "rootfs/etc/banner" in blob
    for p in out.rglob("*"):
        if p.is_file():
            assert not p.stat().st_mode & 0o111, p  # nothing executable is produced


def test_stage_output_refuses_existing_nonempty_target(tmp_path):
    raw = _rootfs(tmp_path).parent
    out = tmp_path / "out"
    out.mkdir()
    (out / "old").write_text("x")
    with pytest.raises(unpack.UnpackError):
        unpack.stage_output(raw, out, salt="s")


def test_main_with_tar_input_end_to_end(tmp_path, capsys):
    raw = _rootfs(tmp_path).parent
    tar = tmp_path / "rom.tar"
    with tarfile.open(tar, "w") as tf:
        tf.add(raw, arcname=".")
    work, out = tmp_path / "work", tmp_path / "out"
    rc = unpack.main(["--input", str(tar), "--work", str(work), "--out", str(out), "--salt", "s"])
    assert rc == 0
    assert (out / "layout.json").exists() and PLANTED not in (out / "rootfs/etc/config/wireless").read_text()
    assert (work / "tree/fs/etc/config/wireless").exists()  # the unredacted staging copy lives only under the work dir
    assert PLANTED not in capsys.readouterr().out


def test_main_rejects_bad_arguments(tmp_path):
    img = tmp_path / "img"
    img.write_bytes(b"x")
    link = tmp_path / "link"
    link.symlink_to(img)
    assert unpack.main(["--input", str(link), "--work", str(tmp_path / "w"), "--out", str(tmp_path / "o")]) == 2
    assert unpack.main(["--input", str(tmp_path / "missing"), "--work", str(tmp_path / "w"), "--out", str(tmp_path / "o")]) == 2
    assert unpack.main(["--input", str(img), "--work", str(tmp_path / "w"), "--out", str(tmp_path / "w" / "o")]) == 2
    pre = tmp_path / "pre"
    pre.mkdir()
    (pre / "f").write_text("x")
    assert unpack.main(["--input", str(img), "--work", str(pre), "--out", str(tmp_path / "o")]) == 2


def test_unblob_is_invoked_without_a_shell_and_with_logs_inside_work(tmp_path, monkeypatch):
    calls = []

    def fake_run(argv, **kw):
        calls.append((argv, kw))
        (Path(argv[argv.index("-e") + 1]) / "img_extract").mkdir(parents=True)

        class R:
            returncode = 0
            stdout = ""
            stderr = ""

        return R()

    monkeypatch.setattr(unpack.subprocess, "run", fake_run)
    monkeypatch.setattr(unpack.shutil, "which", lambda n: "/usr/local/bin/unblob")
    img = tmp_path / "img.bin"
    img.write_bytes(b"x" * 100)
    work = tmp_path / "work"
    unpack.run_unblob(img, work)
    argv, kw = calls[0]
    assert isinstance(argv, list) and not kw.get("shell")
    assert argv[0].endswith("unblob") and str(img) == argv[-1]
    assert Path(argv[argv.index("--log") + 1]).resolve().is_relative_to(work.resolve())
    assert Path(kw["env"]["TMPDIR"]).resolve().is_relative_to(work.resolve())
    assert Path(kw["cwd"]).resolve().is_relative_to(work.resolve())


def test_missing_unblob_is_a_clean_error(tmp_path, monkeypatch):
    monkeypatch.setattr(unpack.shutil, "which", lambda n: None)
    img = tmp_path / "img.bin"
    img.write_bytes(b"x")
    with pytest.raises(unpack.UnpackError):
        unpack.run_unblob(img, tmp_path / "work")
