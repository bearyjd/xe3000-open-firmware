"""End to end in the unpack image: a synthetic squashfs plus FIT/DTB through real unblob (skipped without the tools).

Run with `just test-unpack` (the recon image has none of these tools, so `just test` skips this file)."""
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

import fdt_gen


class _Lazy:
    """Resolved on first use so a missing module fails its tests, not collection (conftest needs anthropic; this image has none)."""

    def __getattr__(self, attr):
        import importlib
        return getattr(importlib.import_module("recon.unpack"), attr)


unpack = _Lazy()

TOOLS = ("mksquashfs", "unblob", "dtc")
pytestmark = pytest.mark.skipif(any(shutil.which(t) is None for t in TOOLS), reason="needs mksquashfs, unblob, dtc (unpack image)")

PLANTED = "Tr0ub4dor" + "Pw42" + "xyz"


def _squashfs(tmp: Path) -> Path:
    root = tmp / "sqroot"
    for d in ("etc/config", "etc/dropbear", "bin"):
        (root / d).mkdir(parents=True)
    (root / "etc/config/wireless").write_text(f"config wifi-iface\n\toption key '{PLANTED}'\n")
    (root / "etc/shadow").write_text("root:*:0:0:::\n")
    (root / "etc/dropbear/dropbear_ed25519_host_key").write_bytes(b"\0hostkey")
    (root / "bin/sh").write_bytes(b"\x7fELF\0\0\0\0")
    (root / "etc/banner").write_text("OpenWrt\n")
    os.symlink("../../../../etc/passwd", root / "etc/escape")
    os.symlink("/tmp", root / "var")
    out = tmp / "fs.sqfs"
    subprocess.run(["mksquashfs", str(root), str(out), "-quiet", "-noappend"], check=True, capture_output=True)
    return out


def _fit_with_dtb(tmp: Path) -> bytes:
    """A real dtc-built FIT whose second image is a flat_dt, so the parser is checked against dtc, not just our writer."""
    (tmp / "k.bin").write_bytes(b"K" * 300)
    (tmp / "d.dts").write_text('/dts-v1/;\n/ { model = "embedded,board"; compatible = "a,b"; };\n')
    subprocess.run(["dtc", "-I", "dts", "-O", "dtb", "-o", str(tmp / "d.dtb"), str(tmp / "d.dts")], check=True, capture_output=True)
    (tmp / "f.dts").write_text(
        '/dts-v1/;\n/ { description = "fit"; #address-cells = <1>;\n'
        ' images { kernel-1 { data = /incbin/("k.bin"); type = "kernel"; arch = "arm64"; os = "linux"; compression = "none"; };\n'
        '          fdt-1 { data = /incbin/("d.dtb"); type = "flat_dt"; arch = "arm64"; compression = "none"; }; };\n'
        ' configurations { default = "c1"; c1 { kernel = "kernel-1"; fdt = "fdt-1"; }; }; };\n'
    )
    subprocess.run(["dtc", "-I", "dts", "-O", "dtb", "-o", str(tmp / "f.itb"), str(tmp / "f.dts")], check=True, cwd=tmp, capture_output=True)
    return (tmp / "f.itb").read_bytes()


def _pad(b: bytes) -> bytes:
    return b + b"\0" * (-len(b) % 4096)


def test_parse_fdt_agrees_with_dtc(tmp_path):
    fit = _fit_with_dtb(tmp_path)
    tree = unpack.parse_fdt(fit)
    assert tree is not None
    assert tree["children"]["images"]["children"]["kernel-1"]["props"]["data"] == b"K" * 300


def test_squashfs_fit_and_dtb_through_unblob(tmp_path):
    image = tmp_path / "stock.bin"
    image.write_bytes(_pad(_fit_with_dtb(tmp_path)) + _pad(fdt_gen.make_dtb("loose,board")) + _squashfs(tmp_path).read_bytes())
    work, out = tmp_path / "work", tmp_path / "out"
    rc = unpack.main(["--input", str(image), "--work", str(work), "--out", str(out), "--salt", "s"])
    assert rc == 0
    assert PLANTED not in (out / "rootfs/etc/config/wireless").read_text()
    assert (out / "rootfs/etc/banner").read_text() == "OpenWrt\n"
    assert not (out / "rootfs/etc/shadow").exists() and not (out / "rootfs/etc/dropbear").exists()
    assert not any(p.name == "escape" for p in out.rglob("*")) and not (out / "rootfs/bin/sh").exists()
    assert len(list((out / "kernel").glob("*.itb"))) == 1
    dtbs = [p.read_bytes() for p in (out / "dtb").glob("*.dtb")]
    assert any(b"embedded,board" in d for d in dtbs) and any(b"loose,board" in d for d in dtbs)
    # the unredacted staging tree keeps binaries but has no escaping symlink
    for p in work.rglob("*"):
        if p.is_symlink() and not os.readlink(p).startswith("/"):
            assert (p.parent / os.readlink(p)).resolve().is_relative_to(work.resolve()), p


def test_corrupt_image_is_a_clean_failure(tmp_path):
    image = tmp_path / "junk.bin"
    image.write_bytes(os.urandom(4096))
    rc = unpack.main(["--input", str(image), "--work", str(tmp_path / "w"), "--out", str(tmp_path / "o"), "--salt", "s"])
    assert rc == 1
    assert not (tmp_path / "o").exists()
