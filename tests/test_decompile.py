"""Bounded decompilation helper: target list rules, output shape, size caps, safety flags, container wiring.

A stub r2 (shell script) makes this run in the recon image; the real-radare2 test is at the bottom and runs only in the
decompile image (`just test-decompile`)."""
from __future__ import annotations

import hashlib
import re
import shutil
import stat
import subprocess
import textwrap
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent


class _Lazy:
    """Resolved on first use so a missing module fails its tests, not collection (the decompile image has no anthropic,
    so this file cannot import conftest)."""

    def __getattr__(self, attr):
        import importlib
        return getattr(importlib.import_module("recon.decompile"), attr)


decompile = _Lazy()

ELF = b"\x7fELF\x02\x01\x01" + b"\0" * 50


def _stub(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "r2stub"
    path.write_text("#!/bin/sh\necho \"$@\" >> \"" + str(tmp_path / "r2.argv") + "\"\n" + textwrap.dedent(body))
    path.chmod(path.stat().st_mode | stat.S_IEXEC)
    return path


def _rootfs(tmp_path: Path, names=("usr/bin/gl_modem",), content=ELF) -> Path:
    root = tmp_path / "rootfs"
    for n in names:
        (root / n).parent.mkdir(parents=True, exist_ok=True)
        (root / n).write_bytes(content)
    return root


def _targets(tmp_path: Path, *names: str) -> Path:
    path = tmp_path / "targets.txt"
    path.write_text("# comment\n\n" + "\n".join(names) + "\n")
    return path


def _run(tmp_path, stub, rootfs, targets, *extra):
    out = tmp_path / "out"
    code = decompile.main(["--rootfs", str(rootfs), "--targets", str(targets), "--out", str(out), "--r2", str(stub), *extra])
    return code, out


GOOD_STUB = """
printf '## strings\\n0x00001000 AT+CFUN=1\\n## disassembly\\n\\033[31msym.main\\033[0m:\\n  mov x0, 1\\n'
"""


def test_limits():
    assert decompile.MAX_BINARIES == 25


def test_parse_targets_skips_comments_and_blank_lines():
    assert decompile.parse_targets("# c\n\nusr/bin/gl_modem\n usr/bin/gl_fan \n") == ("usr/bin/gl_modem", "usr/bin/gl_fan")


@pytest.mark.parametrize("bad", ["/usr/bin/x", "../usr/bin/x", "usr/../etc/x", "etc/shadow", "etc/dropbear/dropbear_rsa_host_key",
                                 "etc/ssl/private/server.key", "usr/bin/a\0b", "usr/bin/x*"])
def test_parse_targets_refuses_unsafe_names(bad):
    with pytest.raises(decompile.DecompileError):
        decompile.parse_targets(bad + "\n")


def test_parse_targets_caps_the_list_at_25_and_refuses_duplicates():
    ok = "\n".join(f"usr/bin/b{i}" for i in range(25))
    assert len(decompile.parse_targets(ok)) == 25
    with pytest.raises(decompile.DecompileError, match="at most 25"):
        decompile.parse_targets(ok + "\nusr/bin/b25\n")
    with pytest.raises(decompile.DecompileError, match="duplicate"):
        decompile.parse_targets("usr/bin/a\nusr/bin/a\n")


def test_output_name_is_flat_and_collision_free():
    assert decompile.output_name("usr/bin/gl_modem") == "usr_bin_gl_modem.r2.txt"
    assert decompile.output_name("lib/modules/5.4.211/pwm-fan.ko") == "lib_modules_5.4.211_pwm-fan.ko.r2.txt"


def test_shipped_target_list_is_valid_and_bounded():
    targets = decompile.parse_targets((REPO / "scripts" / "decompile-targets.txt").read_text())
    assert 10 <= len(targets) <= 25
    assert len({decompile.output_name(t) for t in targets}) == len(targets)
    for needed in ("usr/bin/gl_modem", "usr/bin/modem_AT", "usr/bin/gl_fan", "usr/bin/mcu_update"):
        assert needed in targets


def test_writes_annotated_text_with_header_and_no_ansi(tmp_path):
    root = _rootfs(tmp_path)
    code, out = _run(tmp_path, _stub(tmp_path, GOOD_STUB), root, _targets(tmp_path, "usr/bin/gl_modem"))
    assert code == 0
    text = (out / "usr_bin_gl_modem.r2.txt").read_text()
    assert text.startswith("; decompiled text of usr/bin/gl_modem")
    assert f"sha256 {hashlib.sha256(ELF).hexdigest()}" in text
    assert "AT+CFUN=1" in text and "sym.main:" in text and "\x1b" not in text


def test_r2_is_never_given_write_or_debug_flags_and_runs_quiet(tmp_path):
    root = _rootfs(tmp_path)
    _run(tmp_path, _stub(tmp_path, GOOD_STUB), root, _targets(tmp_path, "usr/bin/gl_modem"))
    argv = (tmp_path / "r2.argv").read_text().split()
    assert "-q" in argv
    assert not {"-w", "-d", "-D", "-A"} & set(argv)


def test_missing_and_non_elf_targets_are_skipped_and_reported(tmp_path, capsys):
    root = _rootfs(tmp_path, ("usr/bin/gl_modem", "usr/bin/script"))
    (root / "usr/bin/script").write_text("#!/bin/sh\necho hi\n")
    code, out = _run(tmp_path, _stub(tmp_path, GOOD_STUB), root,
                     _targets(tmp_path, "usr/bin/gl_modem", "usr/bin/script", "usr/bin/missing"))
    assert code == 0
    assert sorted(p.name for p in out.iterdir()) == ["usr_bin_gl_modem.r2.txt"]
    printed = capsys.readouterr().out
    assert "skipped usr/bin/script (not an ELF file)" in printed and "skipped usr/bin/missing (not found)" in printed


def test_nothing_decompiled_is_a_failure(tmp_path):
    code, _out = _run(tmp_path, _stub(tmp_path, GOOD_STUB), _rootfs(tmp_path), _targets(tmp_path, "usr/bin/missing"))
    assert code == 2


def test_symlink_escaping_the_rootfs_is_refused(tmp_path, capsys):
    root = _rootfs(tmp_path, ())
    outside = tmp_path / "outside.bin"
    outside.write_bytes(ELF)
    (root / "usr/bin").mkdir(parents=True)
    (root / "usr/bin/evil").symlink_to(outside)
    code, out = _run(tmp_path, _stub(tmp_path, GOOD_STUB), root, _targets(tmp_path, "usr/bin/evil"))
    assert code == 2
    assert not out.exists() or not list(out.iterdir())
    assert "escapes the rootfs" in capsys.readouterr().out


def test_output_is_capped_and_the_endless_producer_is_stopped(tmp_path):
    root = _rootfs(tmp_path)
    stub = _stub(tmp_path, "echo '## strings'\nwhile :; do echo '  0x00001000 mov x0, x1 ; some endless instruction line'; done\n")
    code, out = _run(tmp_path, stub, root, _targets(tmp_path, "usr/bin/gl_modem"), "--max-bytes", "5000", "--timeout", "30")
    assert code == 0
    text = (out / "usr_bin_gl_modem.r2.txt").read_text()
    assert len(text.encode()) <= 5000 + 200
    assert text.rstrip().endswith("; TRUNCATED at 5000 bytes")


def test_timeout_keeps_partial_output_and_marks_it(tmp_path):
    root = _rootfs(tmp_path)
    stub = _stub(tmp_path, "echo '## strings'\necho 'AT+QPOWD=1'\nexec sleep 30\n")
    code, out = _run(tmp_path, stub, root, _targets(tmp_path, "usr/bin/gl_modem"), "--timeout", "1")
    text = (out / "usr_bin_gl_modem.r2.txt").read_text()
    assert code == 0 and "AT+QPOWD=1" in text and "; TIMED OUT after 1s" in text


def test_r2_failure_is_reported_not_swallowed(tmp_path, capsys):
    code, out = _run(tmp_path, _stub(tmp_path, "echo boom >&2\nexit 3\n"), _rootfs(tmp_path), _targets(tmp_path, "usr/bin/gl_modem"))
    assert code == 2
    assert "failed usr/bin/gl_modem (r2 exit 3)" in capsys.readouterr().out


# --- container wiring -------------------------------------------------------------------------------------------

def test_decompile_script_is_hardened_and_read_only_on_the_input():
    sh = (REPO / "scripts" / "decompile.sh").read_text()
    assert "set -euo pipefail" in sh
    assert "--network=none" in sh and '$HARDENING' in sh
    assert re.search(r'build/unpack[^"\n]*:/in:ro', sh)
    assert re.search(r'unpacked/decompiled:/out(?!:ro)', sh)
    assert "decompile.py" in sh and "harvest/raw" not in sh


def test_justfile_has_decompile_recipes():
    jf = (REPO / "justfile").read_text()
    for recipe in ("build-decompile:", "decompile ", "test-decompile:"):
        assert recipe in jf
    assert "xe3000-open-firmware-decompile" in jf


def test_containerfile_pins_base_and_radare2_by_digest():
    cf = (REPO / "containers" / "decompile.Containerfile").read_text()
    assert re.search(r"FROM docker\.io/library/python@sha256:[0-9a-f]{64}", cf)
    assert re.search(r"R2_SHA256=[0-9a-f]{64}", cf) and "sha256sum -c" in cf
    assert re.search(r"radare2/releases/download/\d+\.\d+\.\d+/", cf)


# --- real radare2 on a synthetic ELF built in the container ----------------------------------------------------

needs_r2 = pytest.mark.skipif(shutil.which("r2") is None or shutil.which("gcc") is None,
                              reason="needs radare2 and gcc (decompile image)")

C_SRC = r'''
#include <stdio.h>
static const char *CMD = "AT+SYNTHETIC=1";
int send_cmd(const char *s) { return printf("%s\r\n", s); }
int main(void) { return send_cmd(CMD) > 0 ? 0 : 1; }
'''


@needs_r2
def test_real_radare2_on_a_synthetic_elf(tmp_path):
    root = tmp_path / "rootfs" / "usr" / "bin"
    root.mkdir(parents=True)
    src = tmp_path / "t.c"
    src.write_text(C_SRC)
    subprocess.run(["gcc", "-O0", "-o", str(root / "synthetic"), str(src)], check=True)
    out = tmp_path / "out"
    code = decompile.main(["--rootfs", str(tmp_path / "rootfs"), "--targets", str(_targets(tmp_path, "usr/bin/synthetic")),
                           "--out", str(out), "--timeout", "120"])
    assert code == 0
    text = (out / "usr_bin_synthetic.r2.txt").read_text()
    assert "AT+SYNTHETIC=1" in text
    assert "send_cmd" in text and "main" in text
    assert "\x1b" not in text and len(text) < 150_000
