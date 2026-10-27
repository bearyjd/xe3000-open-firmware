"""Finding schema (strict, no unsupported keywords) and the code-side validator (PRP 0001 §3.2-3.3)."""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass

import jsonschema

from recon.chunking import Chunk
from recon.groundtruth import GroundTruth, ungrounded_reasons

SCHEMA_VERSION = "1"
CATEGORIES = ("at-command", "rpc-method", "gpio", "modem-power", "sim", "battery-mcu", "fan", "led",
              "network", "wifi", "storage", "boot", "other")
CONFIDENCES = ("high", "medium", "low")

# Structured-output limits: additionalProperties:false everywhere; no length/pattern/range constraints.
FINDING_SCHEMA: dict = {
    "type": "object",
    "properties": {
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "claim": {"type": "string"},
                    "category": {"type": "string", "enum": list(CATEGORIES)},
                    "confidence": {"type": "string", "enum": list(CONFIDENCES)},
                    "evidence": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "file": {"type": "string"},
                                "line": {"type": "integer"},
                                "excerpt": {"type": "string"},
                            },
                            "required": ["file", "line", "excerpt"],
                            "additionalProperties": False,
                        },
                    },
                },
                "required": ["claim", "category", "confidence", "evidence"],
                "additionalProperties": False,
            },
        },
    },
    "required": ["findings"],
    "additionalProperties": False,
}

MIN_EXCERPT_CHARS = 8
_WS = re.compile(r"\s+")
_VALIDATOR = jsonschema.Draft202012Validator(FINDING_SCHEMA)


@dataclass(frozen=True)
class ValidationResult:
    accepted: tuple[dict, ...]
    rejected: tuple[dict, ...]  # {"reason": str, "finding": raw}


def normalize(text: str) -> str:
    return _WS.sub(" ", text).strip()


def excerpt_sha256(excerpt: str) -> str:
    """Computed by the engine over the whitespace-normalized excerpt; the model is never trusted to hash."""
    return hashlib.sha256(normalize(excerpt).encode()).hexdigest()


def schema_hash() -> str:
    return hashlib.sha256(json.dumps(FINDING_SCHEMA, sort_keys=True).encode()).hexdigest()


def raw_finding(accepted: dict) -> dict:
    """Strip engine-added fields so a stored finding can be re-validated like fresh model output."""
    return {"claim": accepted["claim"], "category": accepted["category"], "confidence": accepted["confidence"],
            "evidence": [{k: ev[k] for k in ("file", "line", "excerpt")} for ev in accepted["evidence"]]}


def _evidence_problem(ev: dict, chunk: Chunk) -> str | None:
    if len(_WS.sub("", ev["excerpt"])) < MIN_EXCERPT_CHARS:
        return f"excerpt too short: at least {MIN_EXCERPT_CHARS} non-space characters are required"
    if ev["file"] not in chunk.files:
        return f"evidence file {ev['file']!r} is not in this chunk's input set"
    window = chunk.window(ev["file"], ev["line"])
    if window is None:
        return f"line {ev['line']} of {ev['file']} is outside this chunk"
    if not normalize(ev["excerpt"]) or normalize(ev["excerpt"]) not in normalize(window):
        return f"excerpt not found within 2 lines of {ev['file']}:{ev['line']}"
    return None


def _check_finding(finding: dict, chunk: Chunk, truth: GroundTruth) -> tuple[dict | None, str | None]:
    if not finding["evidence"]:
        return None, "no evidence: at least one evidence item is required"
    for ev in finding["evidence"]:
        problem = _evidence_problem(ev, chunk)
        if problem:
            return None, problem
    accepted = {
        "claim": finding["claim"],
        "category": finding["category"],
        "confidence": finding["confidence"],
        "evidence": [{**ev, "excerpt_sha256": excerpt_sha256(ev["excerpt"])} for ev in finding["evidence"]],
        "ungrounded": ungrounded_reasons(finding["claim"], truth),
        "chunk_id": chunk.chunk_id,
    }
    return accepted, None


def validate_response(payload: object, chunk: Chunk, truth: GroundTruth) -> ValidationResult:
    """Schema validity first, then per-finding evidence and ground-truth checks."""
    errors = sorted(_VALIDATOR.iter_errors(payload), key=lambda e: list(e.path))
    if errors:
        where = "/".join(str(p) for p in errors[0].path) or "(root)"
        return ValidationResult((), ({"reason": f"schema: {errors[0].message[:200]} at {where}", "finding": None},))
    accepted, rejected = [], []
    for finding in payload["findings"]:
        ok, reason = _check_finding(finding, chunk, truth)
        if ok:
            accepted.append(ok)
        else:
            rejected.append({"reason": reason, "finding": finding})
    return ValidationResult(tuple(accepted), tuple(rejected))
