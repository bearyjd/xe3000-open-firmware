"""The pre-commit hook, exercised in a throwaway git repo under tmp_path (never the real repo)."""
import os
import shutil
import subprocess

import pytest

from conftest import REPO

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git not available")
FAKE_KEY = "sk-" + "ant-" + "api03-" + "H" * 40


def _git(cwd, *args):
    env = {**os.environ, "HOME": str(cwd), "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_SYSTEM": "/dev/null"}
    return subprocess.run(["git", *args], cwd=cwd, env=env, capture_output=True, text=True, check=True)


@pytest.fixture
def repo(tmp_path):
    work = tmp_path / "throwaway"
    work.mkdir()
    _git(work, "init", "-q")
    shutil.copy(REPO / "hooks" / "pre-commit", work / "pre-commit-hook")
    return work


def _run_hook(work):
    return subprocess.run(["bash", str(work / "pre-commit-hook")], cwd=work, capture_output=True, text=True,
                          env={**os.environ, "HOME": str(work), "GIT_CONFIG_GLOBAL": "/dev/null"})


def _stage(work, rel, text="x\n"):
    path = work / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    _git(work, "add", "-f", rel)


@pytest.mark.parametrize("rel", [".env", "sub/.env", ".env.local", ".ENV", "Sub/.Env.Prod", "harvest/raw/a.txt",
                                 "cache/x.json", "findings/raw/r/f.jsonl", "unpacked/a", "harvest/redacted/a.txt",
                                 "harvest/raw/caf\u00e9/\u00fcber.txt", "unpacked/\u65e5\u672c.txt"])
def test_blocks_private_paths(repo, rel):
    _stage(repo, rel)
    result = _run_hook(repo)
    assert result.returncode == 1 and "BLOCKED" in result.stderr


def test_blocks_anthropic_key_without_printing_it(repo):
    _stage(repo, "notes.md", f"key {FAKE_KEY}\n")
    result = _run_hook(repo)
    assert result.returncode == 1
    assert FAKE_KEY not in result.stdout + result.stderr


def test_allows_benign_and_env_example(repo):
    _stage(repo, "README.md", "hello\n")
    _stage(repo, ".env.example", "ANTHROPIC_API_KEY=\n")
    result = _run_hook(repo)
    assert result.returncode == 0, result.stderr


def test_non_ascii_benign_path_passes_and_key_in_non_ascii_file_blocked(repo):
    _stage(repo, "docs/caf\u00e9.md", "fine\n")
    assert _run_hook(repo).returncode == 0
    _stage(repo, "docs/\u00fcber.md", f"k {FAKE_KEY}\n")
    assert _run_hook(repo).returncode == 1


def test_key_added_in_a_renamed_or_deleted_context_still_blocked(repo):
    _stage(repo, "a.txt", "one\n")
    _git(repo, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "base", "--no-verify")
    _git(repo, "mv", "a.txt", "b.txt")
    (repo / "b.txt").write_text(f"one\n{FAKE_KEY}\n")
    _git(repo, "add", "b.txt")
    assert _run_hook(repo).returncode == 1
