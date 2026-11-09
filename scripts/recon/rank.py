"""Triage ranking: turn a cheap-model topic run into a short list of the files worth a Sonnet pass.

Weight per grounded finding: high 3, medium 2, low 1, counted for every file the finding cites as evidence.
Ungrounded findings carry no weight (their names are absent from the deterministic ground truth). Ties break by
name so the ranking is deterministic. The output feeds `analyze.py --only-from`, which can only narrow.
"""
from __future__ import annotations

import argparse
import sys
from collections import Counter
from pathlib import Path

from recon.report import load_findings

WEIGHTS = {"high": 3, "medium": 2, "low": 1}


def rank_files(findings: list[dict], top_n: int) -> list[str]:
    score: Counter[str] = Counter()
    for f in findings:
        if f.get("ungrounded"):
            continue
        weight = WEIGHTS.get(f.get("confidence"), 1)
        for name in {e["file"] for e in f["evidence"]}:
            score[name] += weight
    ordered = sorted(score, key=lambda n: (-score[n], n))
    return ordered[:top_n]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Rank files by a triage run's findings.")
    ap.add_argument("--run-dir", required=True, type=Path)
    ap.add_argument("--top", required=True, type=int)
    ap.add_argument("--out", required=True, type=Path)
    args = ap.parse_args(argv)
    if args.top < 1:
        print("rank: refused: --top must be at least 1", file=sys.stderr)
        return 2
    names = rank_files(load_findings(args.run_dir), args.top)
    if not names:
        print("rank: refused: nothing to rank (no grounded findings)", file=sys.stderr)
        return 2
    args.out.write_text("".join(f"{n}\n" for n in names))
    print(f"wrote {args.out} ({len(names)} files)")
    return 0
