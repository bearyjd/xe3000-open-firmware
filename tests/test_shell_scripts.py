"""redact-container.sh / analyze-container.sh driven with a fake podman that only records its argv."""
import os
import subprocess
import textwrap

import pytest

from conftest import REPO

FAKE_PODMAN = "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$FAKE_LOG\"\n"


@pytest.fixture
def env(tmp_path):
    root = tmp_path / "root"
    (root / "harvest" / "raw" / "t1").mkdir(parents=True)
    (tmp_path / "elsewhere").mkdir()
    (root / ".env").write_text("ANTHROPIC_API_KEY=placeholder\nOTHER=1\n")
    podman = tmp_path / "fakepodman"
    podman.write_text(FAKE_PODMAN)
    podman.chmod(0o755)
    log = tmp_path / "log.txt"
    e = {**os.environ, "ROOT": str(root), "PODMAN": str(podman), "IMAGE": "img", "HARDENING": "--read-only",
         "FAKE_LOG": str(log)}
    return e, root, tmp_path, log


def redact(e, *args):
    return subprocess.run(["bash", str(REPO / "scripts" / "redact-container.sh"), *args], env=e,
                          capture_output=True, text=True)


def test_redact_accepts_dir_under_raw(env):
    e, root, tmp, log = env
    r = redact(e, str(root / "harvest" / "raw" / "t1"), "harvest/redacted", "rep.json")
    assert r.returncode == 0, r.stderr
    assert f"{root}/harvest/raw/t1:/in:ro,z" in log.read_text()


@pytest.mark.parametrize("bad", ["a:b", "a,b", "x:ro,Z"])
def test_redact_rejects_colon_or_comma(env, bad):
    e, root, tmp, log = env
    d = root / "harvest" / "raw" / bad
    d.mkdir()
    r = redact(e, "--allow-src-anywhere", str(d), "harvest/redacted", "rep.json")
    assert r.returncode != 0 and not log.exists()


def test_redact_rejects_src_outside_raw_unless_flagged(env):
    e, root, tmp, log = env
    outside = tmp / "elsewhere"
    r = redact(e, str(outside), "harvest/redacted", "rep.json")
    assert r.returncode != 0 and not log.exists() and "harvest/raw" in r.stderr
    r = redact(e, "--allow-src-anywhere", str(outside), "harvest/redacted", "rep.json")
    assert r.returncode == 0 and log.exists()


def test_redact_rejects_traversal_symlink_and_non_dirs(env):
    e, root, tmp, log = env
    assert redact(e, str(root / "harvest" / "raw" / ".." / ".." / ".."), "d", "r").returncode != 0
    os.symlink(tmp / "elsewhere", root / "harvest" / "raw" / "link")
    assert redact(e, str(root / "harvest" / "raw" / "link"), "d", "r").returncode != 0
    (root / "harvest" / "raw" / "file").write_text("x")
    assert redact(e, str(root / "harvest" / "raw" / "file"), "d", "r").returncode != 0
    assert redact(e, str(root / "harvest" / "raw" / "missing"), "d", "r").returncode != 0
    assert not log.exists()


def test_analyze_script_traps_signals_and_silences_grep_stderr():
    body = (REPO / "scripts" / "analyze-container.sh").read_text()
    assert "trap" in body and "EXIT" in body and "INT" in body and "TERM" in body
    grep_line = [l for l in body.splitlines() if l.lstrip().startswith("grep")][0]
    assert "2>/dev/null" in grep_line


def test_analyze_script_envfile_only_has_allowed_lines_and_is_removed(env):
    e, root, tmp, log = env
    podman = tmp / "fakepodman"
    podman.write_text("#!/bin/sh\nwhile [ $# -gt 0 ]; do [ \"$1\" = --env-file ] && cp \"$2\" \"$FAKE_ENVCOPY\" "
                      "&& echo \"$2\" > \"$FAKE_ENVPATH\"; shift; done\n")
    e = {**e, "FAKE_ENVCOPY": str(tmp / "envcopy"), "FAKE_ENVPATH": str(tmp / "envpath")}
    r = subprocess.run(["bash", str(REPO / "scripts" / "analyze-container.sh"), "run1"], env=e,
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert (tmp / "envcopy").read_text() == "ANTHROPIC_API_KEY=placeholder\n"
    assert not os.path.exists((tmp / "envpath").read_text().strip())


def test_justfile_quotes_root_paths():
    text = (REPO / "justfile").read_text()
    assert "-v {{ROOT}}" not in text and "mkdir -p {{ROOT}}" not in text
    assert 'python3 "{{ROOT}}/scripts/preflight.py"' in text
