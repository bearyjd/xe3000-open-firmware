"""Phase 2 reports: turn findings/raw/<run-id>/ of a topic run into docs/findings/<topic>.md.

Same row format as recon.report (claim capped at 300 chars, evidence as file:line + engine hash, UNGROUNDED marked);
no excerpt is ever copied. The topic comes from the run manifest.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from recon import canary
from recon.report import GENERATED_NOTE, UNGROUNDED_LABEL, _row, load_findings

REPORT_FILES = {"at-commands": "at-commands.md", "gl-rpc-map": "gl-rpc-map.md", "modem-boot-flow": "modem-boot-flow.md"}
TITLES = {"at-commands": "AT commands", "gl-rpc-map": "GL RPC map", "modem-boot-flow": "Modem boot flow"}
TABLE_HEAD = ("| Claim | Confidence | Status | Evidence |", "|---|---|---|---|")
NAC_HEADING = "## Network access control"
OTHER_HEADING = "## Other RPC methods"
NAC_KEYWORDS = ("client", "block", "allow", "deny", "schedule", "parental", "black list", "blacklist", "white list",
                "whitelist", "access control", "mac filter", "timer", "device list", "kick")


def _topic(run_dir: Path) -> str:
    try:
        topic = json.loads((Path(run_dir) / "manifest.json").read_text()).get("topic")
    except (OSError, ValueError) as exc:
        raise ValueError(f"cannot read the topic from {run_dir}/manifest.json: {type(exc).__name__}") from None
    if not topic:
        raise ValueError(f"run {Path(run_dir).name} has no topic in its manifest; this is not a topic run")
    if topic not in REPORT_FILES:
        raise ValueError(f"no report is defined for topic {topic!r}")
    return topic


def _table(findings: list[dict]) -> list[str]:
    if not findings:
        return ["No findings."]
    return [*TABLE_HEAD, *(_row(f) for f in findings)]


def is_access_control(finding: dict) -> bool:
    claim = finding["claim"].lower()
    return any(k in claim for k in NAC_KEYWORDS)


def _sections(topic: str, findings: list[dict]) -> list[str]:
    if topic != "gl-rpc-map":
        return _table(findings)
    nac = [f for f in findings if is_access_control(f)]
    rest = [f for f in findings if not is_access_control(f)]
    return [NAC_HEADING, "", *_table(nac), "", OTHER_HEADING, "", *_table(rest)]


def render(topic: str, findings: list[dict], run_id: str) -> str:
    head = [GENERATED_NOTE, f"# {TITLES[topic]}", "",
            f"Run: `{run_id}`. Rows marked {UNGROUNDED_LABEL} name items absent from the deterministic ground truth "
            "and are unverified. Evidence is file:line plus the engine-computed excerpt hash; no excerpt is copied.", ""]
    return "\n".join([*head, *_sections(topic, findings)]) + "\n"


def generate(run_dir: Path, out_dir: Path, sanitizer: canary.Sanitizer | None = None) -> list[Path]:
    run_dir, out_dir = Path(run_dir), Path(out_dir)
    topic = _topic(run_dir)
    findings = load_findings(run_dir, sanitizer)
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / REPORT_FILES[topic]
    path.write_text(render(topic, findings, run_dir.name))
    return [path]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Generate the topic document from a Phase 2 topic run.")
    ap.add_argument("--run-dir", required=True, type=Path)
    ap.add_argument("--out", type=Path, default=Path("docs/findings"))
    args = ap.parse_args(argv)
    try:
        written = generate(args.run_dir, args.out)
    except ValueError as exc:
        print(f"topic_reports: refused: {exc}", file=sys.stderr)
        return 2
    for path in written:
        print(f"wrote {path}")
    return 0
