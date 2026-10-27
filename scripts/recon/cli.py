"""Argument handling for scripts/analyze.py. Every message shown is scrubbed of key material."""
from __future__ import annotations

import argparse
import math
import os
import sys
from collections.abc import Callable, Sequence
from pathlib import Path

from recon import canary, cost, runner
from recon.client import ReconClient, load_env
from recon.paths import PathRefused, allowed_roots
from recon.scrub import scrub

EXIT_OK, EXIT_REFUSED = 0, 2


def positive_float(raw: str) -> float:
    """A finite number greater than zero (rejects nan, inf, zero, negatives)."""
    try:
        value = float(raw)
    except ValueError:
        raise argparse.ArgumentTypeError(f"not a number: {raw!r}") from None
    if not math.isfinite(value) or value <= 0:
        raise argparse.ArgumentTypeError(f"must be a finite number greater than 0, got {raw!r}")
    return value


def positive_int(raw: str) -> int:
    try:
        value = int(raw)
    except ValueError:
        raise argparse.ArgumentTypeError(f"not an integer: {raw!r}") from None
    if value <= 0:
        raise argparse.ArgumentTypeError(f"must be an integer greater than 0, got {raw!r}")
    return value


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description="Analyse redacted router artifacts with the Claude API (capped).")
    ap.add_argument("--run-id", required=True)
    ap.add_argument("--input", type=Path, action="append",
                    help="input dir under harvest/redacted or unpacked (default: both)")
    ap.add_argument("--root", type=Path, default=Path(os.environ.get("RECON_ROOT", ".")))
    # String defaults pass through `type=` too, so RECON_MAX_* env values are validated like flags.
    ap.add_argument("--max-usd", type=positive_float, default=os.environ.get("RECON_MAX_USD", str(runner.DEFAULT_MAX_USD)))
    ap.add_argument("--max-input-tokens", type=positive_int,
                    default=os.environ.get("RECON_MAX_INPUT_TOKENS", str(runner.DEFAULT_MAX_INPUT_TOKENS)))
    ap.add_argument("--max-tokens", type=positive_int, default=runner.DEFAULT_MAX_TOKENS,
                    help="output cap per request")
    ap.add_argument("--dry-run", action="store_true", help="count tokens and print the estimate; send nothing")
    ap.add_argument("--batch", action="store_true", help="use the Batches API (50%% discount; unverified live)")
    ap.add_argument("--resume-batch", metavar="BATCH_ID",
                    help="poll an existing batch recorded in this run's manifest instead of creating one")
    ap.add_argument("--batch-timeout", type=positive_float, default=runner.DEFAULT_BATCH_TIMEOUT_SECONDS,
                    help="seconds to wait for a batch to end")
    ap.add_argument("--batch-poll", type=positive_float, default=20.0, help="seconds between batch status polls")
    ap.add_argument("--allow-extra", action="append", default=[], metavar="GLOB",
                    help="also send files matching GLOB (relative to the input root); explicit and logged")
    ap.add_argument("--no-canary", action="store_true", help="skip the known-secret canary check (fixture runs only)")
    ap.add_argument("--canary-file", type=Path, help="canary file (default: $RECON_CANARY_FILE or ~/.config/...)")
    ap.add_argument("--synthesize", action="store_true", help="final gap-report pass on the Opus model")
    ap.add_argument("--cheap", action="store_true", help="use LLM_MODEL_CHEAP (bulk triage)")
    ap.add_argument("--env-file", type=Path, help="dotenv file to load; contents are never printed")
    return ap


def _config(args: argparse.Namespace) -> runner.RunConfig:
    root = args.root.resolve()
    inputs = args.input or list(allowed_roots(root))
    resolved = tuple(p if p.is_absolute() else root / p for p in inputs)
    standard, cheap, _synth = cost.configured_models(os.environ)
    return runner.RunConfig(root=root, inputs=resolved, run_id=args.run_id,
                            model=cheap if args.cheap else standard, max_usd=args.max_usd,
                            max_input_tokens=args.max_input_tokens, max_tokens=args.max_tokens,
                            dry_run=args.dry_run, batch=args.batch or bool(args.resume_batch),
                            resume_batch_id=args.resume_batch, allow_extra=tuple(args.allow_extra),
                            no_canary=args.no_canary, canary_file=args.canary_file, batch_timeout_seconds=args.batch_timeout,
                            batch_poll_seconds=args.batch_poll, synthesize=args.synthesize)


def _lenient_sanitizer(args: argparse.Namespace) -> canary.Sanitizer:
    """Known-secret sanitiser for messages; an unusable canary file is reported by the run itself."""
    if args.no_canary:
        return canary.Sanitizer(())
    try:
        return canary.Sanitizer.from_file(args.canary_file)
    except (canary.CanaryError, OSError):
        return canary.Sanitizer(())


def main(argv: Sequence[str] | None = None, client_factory: Callable[[], object] | None = None,
         out: Callable[[str], None] = print) -> int:
    args = build_parser().parse_args(argv)
    san = _lenient_sanitizer(args)
    show = lambda line: san.text(scrub(line))  # noqa: E731 - one-line helper
    try:
        load_env(args.env_file)
        cfg = _config(args)
        factory = client_factory or ReconClient
        runner.run(cfg, factory, out=lambda line: out(show(line)))
    except (PathRefused, runner.RunRefused, cost.CapExceeded) as exc:
        print(show(f"analyze: refused: {exc}"), file=sys.stderr)
        return EXIT_REFUSED
    except Exception as exc:  # noqa: BLE001 - last line of defence: never show a raw SDK message
        print(show(f"analyze: failed: {type(exc).__name__}: {exc}"), file=sys.stderr)
        return EXIT_REFUSED
    return EXIT_OK
