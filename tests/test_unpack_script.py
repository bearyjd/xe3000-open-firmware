"""Static guards for the unpack tooling: container recipe, wrapper script, justfile recipes, docs."""
from __future__ import annotations

import re

from conftest import REPO

CF = (REPO / "containers" / "unpack.Containerfile").read_text() if (REPO / "containers" / "unpack.Containerfile").exists() else ""
SH = (REPO / "scripts" / "unpack.sh").read_text() if (REPO / "scripts" / "unpack.sh").exists() else ""
JUST = (REPO / "justfile").read_text()
README = (REPO / "README.md").read_text()


def _recipe(name: str) -> str:
    m = re.search(rf"^{name}[^\n]*:.*?(?=^\S|\Z)", JUST, re.MULTILINE | re.DOTALL)
    assert m, name
    return m.group(0)


def test_containerfile_pins_base_unblob_and_verifies_sasquatch():
    assert re.search(r"FROM docker\.io/library/python@sha256:[0-9a-f]{64}", CF)
    assert re.search(r"unblob==\d+\.\d+\.\d+", CF)
    assert re.search(r"SASQUATCH_SHA256=[0-9a-f]{64}", CF) and "sha256sum -c" in CF
    assert "squashfs-tools" in CF and "device-tree-compiler" in CF
    assert "latest" not in CF.lower().replace("releases/download", "")


def test_unpack_script_is_hardened_and_offline():
    assert SH.startswith("#!/usr/bin/env bash") and "set -euo pipefail" in SH
    run_lines = [l for l in SH.splitlines() if "run --rm" in l]
    assert len(run_lines) == 1 and "$HARDENING" in run_lines[0]
    assert "--network=none" in SH
    assert ":/in/image:ro" in SH  # the image is mounted read-only, as a single file
    assert re.search(r"/work/build:[^\"\n]*noexec,nosuid,nodev", SH)  # extracted bytes can never be executed from the mount
    assert "rm -rf" not in SH and "--privileged" not in SH and "--env-file" not in SH


def test_unpack_script_validates_arguments():
    assert "[A-Za-z0-9._-]" in SH  # NAME whitelist
    assert re.search(r'-L "\$input"|\[ -L ', SH) and re.search(r'-f "\$input"|\[ ! -f ', SH)
    assert "*:*" in SH and "*,*" in SH  # no podman volume-option injection through the path
    assert "raw" in SH  # raw harvest inputs are staged only via the explicit file mount, never the raw tree


def test_justfile_recipes():
    assert "xe3000-open-firmware-unpack" in JUST
    for name in ("build-unpack", "unpack", "test-unpack"):
        assert re.search(rf"^{name}\b", JUST, re.MULTILINE), name
    assert "UNPACK_IMAGE={{quote(UNPACK_IMAGE)}}" in _recipe("unpack") and "HARDENING={{quote(hardening)}}" in _recipe("unpack")
    t = _recipe("test-unpack")
    assert "--network=none" in t and "{{hardening}}" in t and "test_unpack_e2e.py" in t and "--noconftest" in t
    assert 'unpack.Containerfile' in _recipe("build-unpack")


def test_readme_documents_unpack():
    assert "unpack.sh" in README and "just unpack" in README and "unpack.Containerfile" in README
    assert "build/" in README and "unpacked/" in README
