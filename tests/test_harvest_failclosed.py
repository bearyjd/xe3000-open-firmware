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


# ---- is_excluded must not fail open when `tr` is missing, failing or silent ----------------------------------------

import os  # noqa: E402

from test_harvest import COLLECT  # noqa: E402

TR_MODES = ["ok", "missing", "exit1", "silent"]
MUST_EXCLUDE = ["/etc/shadow", "/etc/ppp/chap-secrets", "/x/a.pem", "/x/SERIAL", "/x/PAP-SECRETS", "/x/Id_Rsa",
                "/etc/init.d/CLIENT.KEY", "/etc/SHADOW"]
MUST_PASS = ["/etc/init.d/network", "/etc/hotplug.d/iface/10-modem", "/etc/config/glmodem", "/proc/cpuinfo"]


def _is_excluded_rc(name, mode, tmp_path, shell="sh"):
    pre = ""
    if mode == "missing":
        pre = "PATH=/nonexistent; "
    elif mode in ("exit1", "silent"):
        shim = tmp_path / f"tr-{mode}"
        shim.mkdir(exist_ok=True)
        (shim / "tr").write_text("#!/bin/sh\n" + ("exit 1" if mode == "exit1" else "exit 0") + "\n")
        (shim / "tr").chmod(0o755)
        pre = f'PATH="{shim}:$PATH"; '
    env = {"PATH": os.environ["PATH"], "COLLECT_NO_MAIN": "1"}
    p = subprocess.run([shell, "-c", f'. "{COLLECT}"; {pre}is_excluded "$1"', "sh", name], env=env, capture_output=True)
    return p.returncode


@pytest.mark.parametrize("mode", TR_MODES)
@pytest.mark.parametrize("name", MUST_EXCLUDE)
def test_secret_names_stay_excluded_whatever_tr_does(tmp_path, mode, name):
    assert _is_excluded_rc(name, mode, tmp_path) == 0


@pytest.mark.parametrize("mode", TR_MODES)
@pytest.mark.parametrize("name", MUST_PASS)
def test_benign_lowercase_names_still_pass_whatever_tr_does(tmp_path, mode, name):
    assert _is_excluded_rc(name, mode, tmp_path) == 1


def test_canon_safe_refuses_an_uppercase_target_when_tr_is_broken(tmp_path):
    target = tmp_path / "SERIAL"
    target.write_text("x")
    link = tmp_path / "link.txt"
    link.symlink_to(target)
    shim = tmp_path / "trx"
    shim.mkdir()
    (shim / "tr").write_text("#!/bin/sh\nexit 1\n")
    (shim / "tr").chmod(0o755)
    env = {"PATH": os.environ["PATH"], "COLLECT_NO_MAIN": "1"}
    p = subprocess.run(["sh", "-c", f'. "{COLLECT}"; PATH="{shim}:$PATH"; canon_safe "$1"', "sh", str(link)],
                       env=env, capture_output=True)
    assert p.returncode == 2
