"""CI runs shellcheck over the shell scripts; keep them clean locally too."""
import shutil
import subprocess

import pytest

from conftest import REPO


@pytest.mark.skipif(shutil.which("shellcheck") is None, reason="shellcheck not installed")
def test_scripts_are_shellcheck_clean():
    files = sorted(str(p) for p in (REPO / "scripts").glob("*.sh")) + [str(REPO / "hooks" / "pre-commit")]
    r = subprocess.run(["shellcheck", *files], capture_output=True, text=True)
    assert r.returncode == 0, r.stdout


@pytest.mark.skipif(shutil.which("shellcheck") is None, reason="shellcheck not installed")
def test_remote_collector_is_shellcheck_clean_posix_sh():
    r = subprocess.run(
        ["shellcheck", "-s", "sh", str(REPO / "scripts" / "remote" / "collect.sh")],
        capture_output=True, text=True,
    )
    assert r.returncode == 0, r.stdout
