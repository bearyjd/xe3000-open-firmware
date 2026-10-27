"""PRP 0003: the CI workflow is parsed and its safety properties asserted (no network, no act)."""
import json
import re

import pytest
import yaml

from conftest import REPO

WORKFLOW = REPO / ".github" / "workflows" / "ci.yml"
BASELINE = REPO / ".gitleaks-baseline.json"
PLAN = REPO / "docs" / "prp" / "0002-overnight-plan.md"


@pytest.fixture(scope="module")
def wf():
    assert WORKFLOW.exists(), "missing .github/workflows/ci.yml"
    return yaml.safe_load(WORKFLOW.read_text())


def _triggers(wf):
    return wf.get("on", wf.get(True))  # YAML 1.1 parses a bare `on` key as boolean True


def _steps(wf):
    return [s for job in wf["jobs"].values() for s in job["steps"]]


def _run_text(job):
    return "\n".join(s.get("run", "") for s in job["steps"])


def test_triggers_pull_request_and_push_to_main(wf):
    trig = _triggers(wf)
    assert "pull_request" in trig
    assert trig["push"]["branches"] == ["main"]


def test_permissions_are_read_only(wf):
    assert wf["permissions"] == {"contents": "read"}
    for name, job in wf["jobs"].items():
        for scope, level in (job.get("permissions") or {}).items():
            assert level in ("read", "none"), (name, scope)


def test_every_action_is_pinned_by_full_sha(wf):
    uses = [s["uses"] for s in _steps(wf) if "uses" in s]
    assert uses, "expected at least one action"
    for ref in uses:
        assert re.fullmatch(r"[\w.-]+/[\w./-]+@[0-9a-f]{40}", ref), ref


def test_required_jobs_exist(wf):
    assert {"tests", "shellcheck", "gitleaks", "hook-tests"} <= set(wf["jobs"])


def test_tests_job_runs_just_test_unweakened(wf):
    run = _run_text(wf["jobs"]["tests"])
    assert "just test" in run
    assert "--ignore" not in run and "-k " not in run and "|| true" not in run


def test_shellcheck_scope(wf):
    run = _run_text(wf["jobs"]["shellcheck"])
    assert "scripts/*.sh" in run and "hooks/pre-commit" in run
    assert re.search(r"shellcheck\s+-s\s+sh\s+scripts/remote/collect\.sh", run)
    assert "|| true" not in run


def test_gitleaks_job_uses_pinned_digest_and_baseline(wf):
    job = wf["jobs"]["gitleaks"]
    run = _run_text(job)
    assert "containers/gitleaks.image" in run
    assert ".gitleaks-baseline.json" in run
    assert "origin/main..HEAD" in run  # PR: only new commits
    assert "pull_request" in run  # event switch between PR range and full scan
    assert "|| true" not in run
    checkout = [s for s in job["steps"] if s.get("uses", "").startswith("actions/checkout@")]
    assert checkout and checkout[0]["with"]["fetch-depth"] == 0


def test_hook_tests_job_runs_hook_suite(wf):
    run = _run_text(wf["jobs"]["hook-tests"])
    assert "test_hook.py" in run


def test_baseline_has_the_six_known_findings_and_no_secret_material():
    data = json.loads(BASELINE.read_text())
    assert isinstance(data, list) and len(data) == 6
    for entry in data:
        assert entry["Fingerprint"]
        assert entry["Secret"] == "REDACTED"
    text = BASELINE.read_text()
    assert not re.search(r"sk-ant-[A-Za-z0-9_-]{20,}", text)
    assert "BEGIN" not in text


def test_overnight_plan_doc_summarises_stages_and_rules():
    text = PLAN.read_text()
    for stage in range(9):
        assert f"S{stage}" in text, stage
    for needle in ("60 USD", "read-only", "/rom", "harvest", "merge", "CI"):
        assert needle in text, needle


def test_justfile_mounts_github_dir_for_the_suite():
    assert ".github:/work/.github:ro" in (REPO / "justfile").read_text()


def test_container_has_pyyaml_pinned():
    text = (REPO / "containers" / "recon.Containerfile").read_text()
    assert re.search(r"pyyaml==\d+\.\d+\.\d+", text, re.I)


def test_scripts_avoid_and_or_chains():
    """SC2015: `A && B || C` is not if-then-else; CI's shellcheck rejects it. Guard it without needing shellcheck."""
    pattern = re.compile(r"&&[^#\n]*\|\|")
    offenders = []
    for path in sorted((REPO / "scripts").glob("*.sh")) + [REPO / "hooks" / "pre-commit"]:
        for no, line in enumerate(path.read_text().splitlines(), 1):
            if pattern.search(line):
                offenders.append(f"{path.relative_to(REPO)}:{no}")
    assert not offenders, f"A && B || C chains (SC2015): {offenders}"
