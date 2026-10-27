"""PRP 0004: no secret-looking literal may exist in tests/ source; fakes are assembled at runtime.

Two layers: a pure-Python scan (runs everywhere, including inside the offline test container) whose rules
mirror the gitleaks defaults that flag test fixtures, and the pinned gitleaks itself over tests/ (host/CI).
"""
from __future__ import annotations

import os
import re
import shlex
import shutil
import subprocess

import pytest

from conftest import CFG, REPO

TESTS = REPO / "tests"
IMAGE_FILE = REPO / "containers" / "gitleaks.image"

# Patterns are built from fragments so this file does not contain what it forbids.
_CURL_AUTH = re.compile(r"curl\b[^\n]*?\s-{1,2}(?:u|user)\s+[^\s'\":]+:[^\s'\"]+")
_PEM_HEADER = re.compile("-----BEGIN [A-Z ]*" + "PRIVATE KEY")
_NAMED_LITERAL = re.compile(
    r"(?i)^\s*\w*(?:token|secret|passw(?:or)?d|api_?key)\w*\s*=\s*[\"'][A-Za-z0-9+/_\-]{8,}[\"']")
RULES = {"curl-auth-user": _CURL_AUTH, "private-key-header": _PEM_HEADER, "named-secret-literal": _NAMED_LITERAL}


def _findings() -> list[str]:
    out = []
    for path in sorted(TESTS.glob("*.py")):
        if path.name == pathlib_name():
            continue
        for no, line in enumerate(path.read_text().splitlines(), 1):
            for rule, rx in RULES.items():
                if rx.search(line):
                    out.append(f"{path.name}:{no}: {rule}")
    return out


def pathlib_name() -> str:
    return os.path.basename(__file__)


def test_no_secret_looking_literals_in_test_sources():
    found = _findings()
    assert found == [], "secret-looking literals in tests/ (assemble at runtime): " + ", ".join(found)


def test_scanner_rules_detect_known_shapes():
    """Guard the guard: each rule must fire on a synthetic positive and stay quiet on assembled forms."""
    assert _CURL_AUTH.search("x = 'curl -s -u root:" + "abc123 http://h'")
    assert not _CURL_AUTH.search("x = 'curl -s -' + 'u root:@S@ http://h'")
    assert _PEM_HEADER.search("-----BEGIN " + "PGP PRIVATE KEY BLOCK-----")
    assert not _PEM_HEADER.search("'-----BEGIN ' + 'PGP PRIVATE KEY BLOCK-----'")
    assert _NAMED_LITERAL.search("    tok" + "en = \"Abcdef123456\"")
    assert not _NAMED_LITERAL.search("client(api_key=\"Abcdef123456\")")
    assert not _NAMED_LITERAL.search("token = RAW_VALUE + \"x\"")


def _gitleaks_cmd() -> list[str]:
    if CFG["gitleaks_bin"]:
        return [CFG["gitleaks_bin"], "dir", str(TESTS)]
    podman = shlex.split(os.environ.get("PODMAN", "podman"))
    image = IMAGE_FILE.read_text().strip()
    return [*podman, "run", "--rm", "--network=none", "-v", f"{REPO}:/repo:ro,z", image, "dir", "/repo/tests"]


@pytest.mark.requires_gitleaks
def test_pinned_gitleaks_default_rules_find_nothing_in_tests():
    if not CFG["gitleaks_bin"] and not shutil.which(shlex.split(os.environ.get("PODMAN", "podman"))[0]):
        pytest.skip("no gitleaks and no podman launcher")
    res = subprocess.run([*_gitleaks_cmd(), "--no-banner", "--redact", "--no-color", "-v"],
                         capture_output=True, text=True, timeout=300)
    hits = re.findall(r"^File:\s+(\S+)\nLine:\s+(\d+)", res.stdout + res.stderr, re.M)
    assert res.returncode == 0, f"gitleaks flagged tests/: {hits}"
