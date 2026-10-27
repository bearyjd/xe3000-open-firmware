"""Fail-closed behaviour of collect.sh: a file or crontab whose canonical target cannot be computed is never read,
and crontabs get the same canonical-target exclusion as every other file."""
import re
import subprocess  # noqa: F401  (kept for parity with test_harvest helpers)

import pytest

from test_harvest import SHELLS, needs_timeout, run_fn


def _shim(tmp_path, body):
    shim = tmp_path / "shim"
    shim.mkdir(exist_ok=True)
    (shim / "readlink").write_text("#!/bin/sh\n" + body + "\n")
    (shim / "readlink").chmod(0o755)
    return shim


READLINK_BROKEN = {
    "fails": "exit 1",
    "empty": "exit 0",
    "relative": "echo relative/path",
    "fails-with-output": "echo /tmp/ok.txt; exit 1",
}


def _canary():
    return "TOPSECRET" + "VALUE"


@pytest.mark.parametrize("shell", SHELLS)
@pytest.mark.parametrize("mode", sorted(READLINK_BROKEN))
def test_frame_file_fails_closed_when_readlink_is_unusable(tmp_path, shell, mode):
    f = tmp_path / "plain.txt"
    f.write_text(_canary() + "\n")
    out = run_fn('frame_file t "$1"', f, shell=shell, shim=_shim(tmp_path, READLINK_BROKEN[mode]))
    assert _canary() not in out and "@@BEGIN" not in out
    assert out.startswith("@@SKIPPED ")


@needs_timeout
def test_frame_file_fails_closed_when_readlink_times_out(tmp_path):
    f = tmp_path / "plain.txt"
    f.write_text(_canary() + "\n")
    out = run_fn('frame_file t "$1"', f, setup='TMO="timeout 1"', shim=_shim(tmp_path, "exec sleep 30"))
    assert _canary() not in out and "@@BEGIN" not in out and out.startswith("@@SKIPPED ")


@pytest.mark.parametrize("mode", sorted(READLINK_BROKEN))
def test_symlink_to_etc_shadow_is_never_read_when_readlink_is_unusable(tmp_path, mode):
    link = tmp_path / "link.txt"
    link.symlink_to("/etc/shadow")
    out = run_fn('frame_file t "$1"', link, shim=_shim(tmp_path, READLINK_BROKEN[mode]))
    assert "@@BEGIN" not in out and out.startswith("@@SKIPPED ")


def test_symlink_to_excluded_target_is_still_skipped_with_working_readlink(tmp_path):
    target = tmp_path / "serial_number"
    target.write_text(_canary())
    link = tmp_path / "link.txt"
    link.symlink_to(target)
    out = run_fn('frame_file t "$1"', link)
    assert _canary() not in out and "@@BEGIN" not in out and "excluded-target" in out


def _shadow_text():
    return "\n".join(f"{u}:" + "$6$" + "salt1234" + "$" + "H" * 20 + ":19000:0:99999:7:::" for u in ("root", "daemon")) + "\n"


def test_symlinked_crontab_to_a_shadow_file_is_not_read(tmp_path):
    cron = tmp_path / "cron"
    cron.mkdir()
    pwdb = tmp_path / "pwdb"
    pwdb.write_text(_shadow_text())
    (cron / "root").symlink_to(pwdb)
    out = run_fn("crontab_filtered", setup=f"CRONDIR={cron}")
    assert "H" * 20 not in out and "salt1234" not in out and "root:" not in out


def test_symlinked_crontab_to_etc_shadow_is_not_read(tmp_path):
    cron = tmp_path / "cron"
    cron.mkdir()
    (cron / "root").symlink_to("/etc/shadow")
    out = run_fn("crontab_filtered", setup=f"CRONDIR={cron}")
    assert "# file" not in out and ":" not in out.replace("# ", "")


def test_shadow_like_lines_in_a_regular_crontab_are_dropped_and_counted(tmp_path):
    cron = tmp_path / "cron"
    cron.mkdir()
    (cron / "root").write_text("*/5 * * * * /usr/bin/foo.sh\n" + _shadow_text() + "root:*:0:0:99999:7:::\n")
    out = run_fn("crontab_filtered", setup=f"CRONDIR={cron}")
    assert "H" * 20 not in out and "salt1234" not in out and "daemon:" not in out and "root:" not in out
    assert "/usr/bin/foo.sh" in out and re.search(r"# dropped 3 line\(s\)", out)


@pytest.mark.parametrize("mode", sorted(READLINK_BROKEN))
def test_crontab_is_skipped_when_canonicalization_fails(tmp_path, mode):
    cron = tmp_path / "cron"
    cron.mkdir()
    (cron / "root").write_text("*/5 * * * * /usr/bin/foo.sh\n")
    out = run_fn("crontab_filtered", setup=f"CRONDIR={cron}", shim=_shim(tmp_path, READLINK_BROKEN[mode]))
    assert "/usr/bin/foo.sh" not in out
