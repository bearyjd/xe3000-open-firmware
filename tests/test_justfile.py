import re

from conftest import REPO

TEXT = (REPO / "justfile").read_text() if (REPO / "justfile").exists() else ""


def _recipe(name):
    m = re.search(rf"^{name}[^\n]*:.*?(?=^\S|\Z)", TEXT, re.MULTILINE | re.DOTALL)
    assert m, name
    return m.group(0)


def test_image_renamed():
    assert "localhost/xe3000-open-firmware-recon" in TEXT and "passerelle-recon" not in TEXT


SCRIPTS = {n: (REPO / "scripts" / n).read_text() for n in ("analyze-container.sh", "redact-container.sh")}


def test_every_run_is_hardened():
    (line,) = [l for l in TEXT.splitlines() if l.startswith("hardening")]
    for flag in ("--cap-drop=ALL", "--security-opt no-new-privileges", "--pids-limit", "--read-only"):
        assert flag in line, flag
    runs = [l for l in TEXT.splitlines() if "run --rm" in l]
    assert len(runs) == 1 and "{{hardening}}" in runs[0]  # the test recipe
    for name, body in SCRIPTS.items():
        run_lines = [l for l in body.splitlines() if "run --rm" in l]
        assert run_lines and all("$HARDENING" in l for l in run_lines), name
    for name in ("analyze", "dry-run", "redact", "redact-unpacked"):
        assert "HARDENING={{quote(hardening)}}" in _recipe(name), name


def test_network_none_for_test_and_redact():
    assert "--network=none" in _recipe("test")
    assert "--network=none" in SCRIPTS["redact-container.sh"]
    assert "--network=none" not in SCRIPTS["analyze-container.sh"]  # analyze must reach the API


def test_analyze_mounts_and_env():
    body = SCRIPTS["analyze-container.sh"]
    assert "/tests" not in body and "/hooks" not in body
    assert "cache/preflight:/work/cache/preflight:ro" in body and "cache/responses:/work/cache/responses:z" in body
    assert "--env-file" in body and "mktemp" in body and "trap" in body
    assert "ANTHROPIC_API_KEY|LLM_MODEL|LLM_MODEL_CHEAP" in body
    assert "--env-file {{ROOT}}/.env" not in TEXT and "--env-file \"$ROOT/.env\"" not in body


def test_redact_recipes_exist_and_report_lands_in_a_mount():
    assert "redact-unpacked" in TEXT
    body = SCRIPTS["redact-container.sh"]
    assert '--report "/work/reports/' in body and "harvest/reports:/work/reports" in body


def test_arguments_are_quoted():
    assert "set positional-arguments" in TEXT and '"$@"' in TEXT and '"$1"' in TEXT


def test_base_image_pinned_by_digest():
    cf = (REPO / "containers" / "recon.Containerfile").read_text()
    assert re.search(r"FROM docker\.io/library/python@sha256:[0-9a-f]{64}", cf)


def test_no_old_image_name_anywhere():
    for path in ("justfile", "containers/recon.Containerfile", "containers/gitleaks.toml"):
        assert "passerelle-recon" not in (REPO / path).read_text(), path
    assert 'title = "xe3000-open-firmware recon pre-flight"' in (REPO / "containers" / "gitleaks.toml").read_text()


def test_docs_reflect_review_fixes():
    prp = (REPO / "docs" / "prp" / "0001-probes.md").read_text()
    assert "1.25" in prp and "cache-write" in prp
    assert "prompt hash" in prp and "max_tokens" in prp and "SCHEMA" in prp
    assert "synthesis.md" in prp and "batch-pending" in prp
    assert "pip" in prp and "hash" in prp and "accepted risk" in prp.lower()
    readme = (REPO / "README.md").read_text()
    assert "redact-unpacked" in readme and "`redact`" in readme
    assert "Phase 1" in readme and "planned" in readme.lower()
