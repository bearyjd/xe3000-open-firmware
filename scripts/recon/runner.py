"""Orchestration for scripts/analyze.py: allowlist -> pre-flight stamp -> chunk -> estimate -> send -> validate."""
from __future__ import annotations

import hashlib
import json
import os
import re
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from recon import allowlist, canary, chunking, cost, groundtruth, paths, preflight, prompts, schema
from recon.cache import Cache, cache_key
from recon.chunking import Chunk
from recon.client import ModelResponse
from recon.redact import _is_excluded as is_excluded
from recon.redact import redact_text
from recon.scrub import scrub

RUN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
OUTPUT_FILES = ("findings.jsonl", "rejected.jsonl", "usage.json", "manifest.json")
BATCH_DONE = "ended"
FEEDBACK_MAX_CHARS = 2000
DEFAULT_MAX_USD = 0.25
DEFAULT_MAX_INPUT_TOKENS = 200_000
DEFAULT_MAX_TOKENS = 4096
DEFAULT_BATCH_TIMEOUT_SECONDS = 24 * 3600.0
ANALYZE_SALT = "recon-analyze"  # in-memory MAC pseudonyms for unpacked text; need not match redact.py's salt
BINARY_SUFFIXES = (".dtb",)  # decompile to dts text upstream; never sent raw
RESPONSES_DIR = Path("cache") / "responses"


class RunRefused(RuntimeError):
    """The run may not start (missing pre-flight stamp, bad run id, existing run dir)."""


class RunFailed(RuntimeError):
    """A send-phase failure; the message is already scrubbed."""


@dataclass(frozen=True)
class RunConfig:
    root: Path
    inputs: tuple[Path, ...]
    run_id: str
    model: str
    synth_model: str = cost.SYNTH_MODEL
    max_usd: float = DEFAULT_MAX_USD
    max_input_tokens: int = DEFAULT_MAX_INPUT_TOKENS
    max_tokens: int = DEFAULT_MAX_TOKENS
    max_retries: int = 2
    max_chunk_lines: int = chunking.DEFAULT_MAX_LINES
    dry_run: bool = False
    batch: bool = False
    synthesize: bool = False
    batch_poll_seconds: float = 20.0
    batch_timeout_seconds: float = DEFAULT_BATCH_TIMEOUT_SECONDS
    resume_batch_id: str | None = None  # poll this existing batch instead of creating one
    allow_extra: tuple[str, ...] = ()  # explicit, logged opt-in globs on top of the allowlist file
    no_canary: bool = False  # fixture runs only
    canary_file: Path | None = None
    topic: str | None = None  # Phase 2 topic run: narrows inputs and adds the topic prompt


@dataclass(frozen=True)
class RunResult:
    status: str
    estimate: cost.Estimate
    accepted: int
    rejected: int
    actual_usd: float
    run_dir: Path | None


def _no_checkpoint() -> None:
    return None


@dataclass
class _Ledger:
    """Worst-case dollars and input tokens committed so far (starts at the pre-send estimate) plus the call log.

    Every increase is checkpointed to disk BEFORE the paid request it covers, so a kill cannot make a resumed run
    forget a request whose outcome is unknown."""
    committed_usd: float
    committed_tokens: int
    calls: list
    max_usd: float = float("inf")
    max_tokens: int = 1 << 62
    checkpoint: Callable[[], None] = _no_checkpoint

    def reserve(self, usd: float, tokens: int) -> str | None:
        """None if reserved and durably recorded; otherwise the reason it does not fit."""
        if self.committed_usd + usd > self.max_usd:
            return "cost cap would be exceeded"
        if self.committed_tokens + tokens > self.max_tokens:
            return "input token cap would be exceeded"
        self.committed_usd += usd
        self.committed_tokens += tokens
        self.checkpoint()  # raises if the commitment cannot be made durable: the caller must not send
        return None


def _usage_row(chunk_id: str, attempt: int, model: str, resp: ModelResponse, batch: bool) -> dict:
    u = resp.usage
    usd = cost.actual_usd(model, input_tokens=u.input_tokens, output_tokens=u.output_tokens,
                          cache_read_tokens=u.cache_read_tokens, cache_creation_tokens=u.cache_creation_tokens,
                          batch=batch)
    return {"chunk_id": chunk_id, "attempt": attempt, "model": model, "batch": batch,
            "input_tokens": u.input_tokens, "output_tokens": u.output_tokens,
            "cache_read_tokens": u.cache_read_tokens, "cache_creation_tokens": u.cache_creation_tokens,
            "usd": round(usd, 6)}


def _parse(resp: ModelResponse) -> tuple[object | None, str | None]:
    if resp.stop_reason == "max_tokens":
        return None, "output truncated at max_tokens"
    try:
        return json.loads(resp.text), None
    except json.JSONDecodeError:
        return None, "output is not valid JSON"


def _feedback(rejected: tuple[dict, ...]) -> str:
    lines = []
    for r in rejected:
        claim = (r.get("finding") or {}).get("claim", "(whole response)")
        lines.append(f"- {str(claim)[:200]}: {r['reason']}")
    return "\n".join(lines)[:FEEDBACK_MAX_CHARS]


def _dedupe(findings: list[dict]) -> list[dict]:
    seen, unique = set(), []
    for f in findings:
        sig = (f["claim"], f["evidence"][0]["file"], f["evidence"][0]["line"])
        if sig not in seen:
            seen.add(sig)
            unique.append(f)
    return unique


def _row(chunk_id: str, attempt: int, reason: str, finding: dict | None = None) -> dict:
    return {"reason": reason, "finding": finding, "chunk_id": chunk_id, "attempt": attempt}


def _analyze_chunk(chunk: Chunk, truth, cfg: RunConfig, client, ledger: _Ledger,
                   first: ModelResponse | None, from_batch: bool) -> dict:
    """Validate/retry one chunk. `clean` is True only if the final attempt was fully accepted."""
    system = prompts.system_blocks(chunk.artifact_type, cfg.topic)
    accepted: list[dict] = []
    rejected: list[dict] = []  # rows from EVERY attempt
    feedback = None
    clean = False
    for attempt in range(cfg.max_retries + 1):
        if attempt == 0 and first is not None:
            resp, batch = first, from_batch
        else:
            messages = [{"role": "user", "content": prompts.user_message(chunk.render(), feedback)}]
            # Attempt 0 of a non-batch run is pre-paid by the estimate. Every other request is counted on its exact
            # messages, held against both caps and made durable before it is sent.
            if attempt > 0 or from_batch:
                n = client.count_tokens(cfg.model, system, messages)
                why = ledger.reserve(cost.worst_case_usd(cfg.model, n, cfg.max_tokens), n)
                if why:
                    base = ("batch result unavailable (errored/expired/missing); sync fallback skipped"
                            if attempt == 0 else "retry skipped")
                    rejected.append(_row(chunk.chunk_id, attempt, f"{base}: {why}"))
                    break
            resp, batch = client.create(cfg.model, system, messages, cfg.max_tokens), False
        ledger.calls.append(_usage_row(chunk.chunk_id, attempt, cfg.model, resp, batch))
        payload, problem = _parse(resp)
        result = (schema.ValidationResult((), ({"reason": problem, "finding": None},)) if problem
                  else schema.validate_response(payload, chunk, truth))
        accepted = _dedupe([*accepted, *result.accepted])
        rejected.extend(_row(chunk.chunk_id, attempt, r["reason"], r["finding"]) for r in result.rejected)
        if not result.rejected:
            clean = True
            break
        feedback = _feedback(result.rejected)
    return {"accepted": accepted, "rejected": rejected, "clean": clean}


def _from_cache(entry: dict, chunk: Chunk, truth) -> list[dict] | None:
    """Re-validate a stored result against the current chunk and ground truth; any doubt is a miss."""
    try:
        payload = {"findings": [schema.raw_finding(f) for f in entry["findings"]]}
        result = schema.validate_response(payload, chunk, truth)
    except (KeyError, TypeError, AttributeError, IndexError):
        return None
    return list(result.accepted) if not result.rejected else None


def _validate_run_id(run_id: str) -> None:
    if not RUN_ID_RE.match(run_id):
        raise RunRefused("run id must match [A-Za-z0-9._-] and start with a letter or digit")


def _format_estimate(est: cost.Estimate, cached: int, cfg: RunConfig) -> str:
    batch = " (batch, 50% factor; batch path unverified live)" if est.batch else ""
    return (f"estimate: model={est.model} chunks_to_send={est.chunks} cached={cached} "
            f"input_tokens={est.input_tokens} max_output_tokens={est.max_output_tokens} "
            f"worst_case_usd=${est.usd:.4f}{batch} | caps: ${cfg.max_usd:.4f}, {cfg.max_input_tokens} input tokens")


def _wait_batch(client, batch_id: str, sleep: Callable[[float], None], poll: float, timeout: float) -> None:
    waited = 0.0
    while client.batch_status(batch_id) != BATCH_DONE:
        if waited >= timeout:
            raise RunFailed(f"batch {batch_id} timed out after {waited:.0f}s")
        sleep(poll)
        waited += poll


def _submit_batch(pending, cfg, client, state, on_created, sleep) -> dict:
    if cfg.resume_batch_id:  # already created (and paid for): only poll and read results
        state["batch_id"] = cfg.resume_batch_id
        _wait_batch(client, state["batch_id"], sleep, cfg.batch_poll_seconds, cfg.batch_timeout_seconds)
        return client.batch_results(state["batch_id"])
    items = [(c.chunk_id, prompts.system_blocks(c.artifact_type, cfg.topic),
              [{"role": "user", "content": prompts.user_message(c.render())}]) for c in pending]
    state["batch_id"] = client.batch_create(cfg.model, items, cfg.max_tokens)
    on_created(state["batch_id"])  # persisted before waiting, so a crash cannot orphan paid work
    _wait_batch(client, state["batch_id"], sleep, cfg.batch_poll_seconds, cfg.batch_timeout_seconds)
    return client.batch_results(state["batch_id"])


def _synthesize(findings: list[dict], cfg: RunConfig, client, ledger: _Ledger, out) -> str | None:
    body = json.dumps([{"i": i, "claim": f["claim"], "category": f["category"], "ungrounded": f["ungrounded"],
                        "evidence": [f"{e['file']}:{e['line']}" for e in f["evidence"]]}
                       for i, f in enumerate(findings)], indent=1)
    messages = [{"role": "user", "content": body}]
    system = (prompts.SYNTHESIS_SYSTEM,)
    tokens = client.count_tokens(cfg.synth_model, system, messages)
    worst = cost.worst_case_usd(cfg.synth_model, tokens, cfg.max_tokens)
    why = ledger.reserve(worst, tokens)
    if why:
        out(f"synthesis skipped: worst-case ${worst:.4f}, {why}")
        return None
    resp = client.create_text(cfg.synth_model, system, messages, cfg.max_tokens)
    ledger.calls.append(_usage_row("synthesis", 0, cfg.synth_model, resp, False))
    return resp.text


def _jsonl(rows) -> str:
    return "".join(json.dumps(r, sort_keys=True) + "\n" for r in rows)


def _manifest(cfg: RunConfig, status: str, est: cost.Estimate, meta: dict, ledger: _Ledger, counts: dict,
              synthesis: bool, error: str | None = None) -> dict:
    totals = {k: sum(c[k] for c in ledger.calls) for k in ("input_tokens", "output_tokens", "cache_read_tokens",
                                                          "cache_creation_tokens")}
    actual = round(sum(c["usd"] for c in ledger.calls), 6)
    return {
        "run_id": cfg.run_id, "topic": cfg.topic, "status": status, "created_utc": datetime.now(timezone.utc).isoformat(),
        "model": cfg.model, "max_tokens": cfg.max_tokens, "synth_model": cfg.synth_model if synthesis else None,
        "prompt_version": prompts.PROMPT_VERSION, "schema_version": schema.SCHEMA_VERSION,
        "batch": cfg.batch, "batch_id": meta.get("batch_id"),
        "inputs": {"tree_sha256": meta["digest"], "files": meta["files"]}, "skipped": meta["skipped"],
        "denied": meta["denied"], "allow_extra": list(cfg.allow_extra),
        "chunks": counts["chunks"], "chunks_cached": counts["cached"],
        "accepted": counts["accepted"], "rejected": counts["rejected"],
        "estimate": {"input_tokens": est.input_tokens, "max_output_tokens": est.max_output_tokens,
                     "worst_case_usd": round(est.usd, 6)},
        "committed_usd": ledger.committed_usd, "committed_input_tokens": ledger.committed_tokens,
        "actual": {**totals, "usd": actual, "covers": "this invocation only"}, "error": scrub(error) if error else None,
    }


def _atomic_write(path: Path, text: str) -> None:
    """Write via a temp file in the same directory, fsync it, replace, then fsync the directory."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    with open(tmp, "w") as handle:
        handle.write(text)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp, path)
    dir_fd = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)


def _write_manifest(run_dir: Path, manifest: dict) -> None:
    _atomic_write(run_dir / "manifest.json", json.dumps(manifest, indent=2))


def _write_outputs(run_dir: Path, manifest: dict, findings: list[dict], rejected: list[dict], ledger: _Ledger,
                   synthesis: str | None) -> float:
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "findings.jsonl").write_text(scrub(_jsonl(findings)))
    (run_dir / "rejected.jsonl").write_text(scrub(_jsonl(rejected)))
    (run_dir / "usage.json").write_text(json.dumps({"calls": ledger.calls, "totals": manifest["actual"]}, indent=2))
    _write_manifest(run_dir, manifest)
    if synthesis is not None:
        (run_dir / "synthesis.md").write_text(scrub(synthesis))
    return manifest["actual"]["usd"]


def _prior_manifest(run_dir: Path) -> dict:
    try:
        data = json.loads((run_dir / "manifest.json").read_text())
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _check_resumable(prior: dict, cfg: RunConfig, digest: str) -> None:
    if not prior.get("batch_id"):
        raise RunRefused(f"nothing to resume: findings/raw/{cfg.run_id} has no recorded batch id")
    if prior["batch_id"] != cfg.resume_batch_id:
        raise RunRefused(f"batch id {cfg.resume_batch_id} does not match the one recorded for this run")
    if prior.get("status") != "batch-pending":
        raise RunRefused(f"cannot resume: prior status is {prior.get('status')!r}, expected 'batch-pending'")
    if (prior.get("inputs") or {}).get("tree_sha256") != digest:
        raise RunRefused("cannot resume: the input tree changed since the batch was created")
    if prior.get("model") != cfg.model:
        raise RunRefused(f"cannot resume: model differs (batch was created with {prior.get('model')!r})")
    if prior.get("topic") != cfg.topic:
        raise RunRefused(f"cannot resume: topic differs (batch was created with {prior.get('topic')!r})")
    if prior.get("max_tokens") != cfg.max_tokens:
        raise RunRefused(f"cannot resume: max_tokens differs (batch used {prior.get('max_tokens')!r})")


def _prepare_run_dir(run_dir: Path, cfg: RunConfig, digest: str) -> tuple[float, int]:
    """Create the run dir, or validate it for --resume-batch. Returns (usd, input tokens) already committed."""
    prior = _prior_manifest(run_dir) if run_dir.exists() else {}
    if cfg.resume_batch_id is None:
        if run_dir.exists():
            hint = f" (batch {prior['batch_id']} recorded; use --resume-batch {prior['batch_id']})" if prior.get("batch_id") else ""
            raise RunRefused(f"run directory already exists: findings/raw/{cfg.run_id}{hint}")
        run_dir.mkdir(parents=True)
        return 0.0, 0
    _check_resumable(prior, cfg, digest)
    return float(prior.get("committed_usd") or 0.0), int(prior.get("committed_input_tokens") or 0)


def _canary_gate(cfg: RunConfig, raw: dict[str, str]) -> None:
    try:
        hits = canary.check(raw, skip=cfg.no_canary, path=cfg.canary_file)
    except canary.CanaryError as exc:
        raise RunRefused(str(exc)) from None
    if hits:
        raise RunRefused(f"a known-secret canary was found at (file:line; value never printed): "
                         f"{canary.format_hits(hits)}; nothing was sent")


def _patterns(cfg: RunConfig, out) -> tuple[str, ...]:
    try:
        base = allowlist.load_patterns(cfg.root / allowlist.ALLOWLIST_REL)
    except allowlist.AllowlistError as exc:
        raise RunRefused(str(exc)) from None
    for pattern in cfg.allow_extra:
        if pattern.startswith("/") or ".." in pattern.split("/"):
            raise RunRefused(f"--allow-extra pattern escapes the input root: {pattern!r}")
    if cfg.allow_extra:
        out(f"allow-extra ENABLED (explicit opt-in, logged in the manifest): {', '.join(cfg.allow_extra)}")
    return (*base, *cfg.allow_extra)


def _topic_globs(cfg: RunConfig) -> tuple[str, ...] | None:
    if cfg.topic is None:
        return None
    try:
        return prompts.TOPICS[cfg.topic].globs
    except KeyError:
        raise RunRefused(f"unknown topic {cfg.topic!r}") from None


def _classify_inputs(groups, patterns, topic_globs: tuple[str, ...] | None = None):
    """Split files into sendable texts (redacted again in memory), skipped (excluded/binary/off-topic) and denied.
    Topic globs only narrow what the allowlist already permits."""
    files, skipped, denied, texts = [], [], [], {}
    for _dir, items in groups:
        for name, data in items:
            files.append({"name": name, "sha256": hashlib.sha256(data).hexdigest()})
            if is_excluded(Path(name)):  # shadow, serial*, dropbear, *.pem, *.key, *_host_key, secret files
                skipped.append({"name": name, "reason": "excluded"})
            elif b"\0" in data or name.lower().endswith(BINARY_SUFFIXES):
                skipped.append({"name": name, "reason": "binary"})
            elif not allowlist.is_allowed(name, patterns):
                denied.append(name)
            elif topic_globs is not None and not allowlist.is_allowed(name, topic_globs):
                skipped.append({"name": name, "reason": "off-topic"})
            else:
                texts[name] = redact_text(data.decode("utf-8", errors="replace"), salt=ANALYZE_SALT)[0]
    return files, skipped, sorted(denied), texts


def _load_inputs(cfg: RunConfig, out):
    """Read every file ONCE. Returns (digest, hashed files, skipped, denied, sendable texts)."""
    groups = preflight.read_groups(cfg.inputs, cfg.root)  # PathRefused on raw/traversal/symlink escape
    _canary_gate(cfg, {n: d.decode("utf-8", errors="replace") for _g, items in groups for n, d in items})
    digest = preflight.hash_tree(groups)
    if not preflight.stamp_valid(cfg.root, digest):
        raise RunRefused("no valid pre-flight stamp for the current input tree and gitleaks setup; "
                         "run `just preflight` first")
    files, skipped, denied, texts = _classify_inputs(groups, _patterns(cfg, out), _topic_globs(cfg))
    links = [n for d in cfg.inputs if Path(d).exists() for n in paths.list_symlinks(d, cfg.root)]
    skipped = [*skipped, *({"name": n, "reason": "symlink"} for n in links)]
    if not texts:
        out(f"no allowlisted files to send ({len(denied)} denied); nothing will be sent")
    return digest, files, skipped, denied, texts


def _write_failure(run_dir: Path, manifest: dict, ledger: _Ledger) -> None:
    """Record a failed invocation (best effort). Existing findings/rejected from an earlier invocation are kept."""
    try:
        for name in ("findings.jsonl", "rejected.jsonl"):
            if not (run_dir / name).exists():
                (run_dir / name).write_text("")
        (run_dir / "usage.json").write_text(json.dumps({"calls": ledger.calls, "totals": manifest["actual"]}, indent=2))
        _write_manifest(run_dir, manifest)
    except OSError:
        pass  # the checkpointed manifest (if any) already holds the commitments


def _plan(cfg: RunConfig, texts: dict, results: dict):
    """Chunk the inputs and satisfy what the cache can (re-validated). Returns (chunks, keys, truth, pending)."""
    trusted = {n: t for n, t in texts.items() if chunking.classify(n) in chunking.TRUSTED_TYPES}
    truth = groundtruth.extract(trusted)
    chunks = chunking.chunk_files(sorted(texts.items()), cfg.max_chunk_lines)
    cache = Cache(cfg.root / RESPONSES_DIR)
    keys = {c.chunk_id: cache_key(c.render(), prompts.PROMPT_VERSION, cfg.model, schema.SCHEMA_VERSION,
                                  schema_hash=schema.schema_hash(), prompt_hash=prompts.prompt_hash(c.artifact_type, cfg.topic),
                                  max_tokens=cfg.max_tokens) for c in chunks}
    for c in chunks:
        entry = cache.get(keys[c.chunk_id])
        hit = _from_cache(entry, c, truth) if entry is not None else None
        if hit is not None:
            results[c.chunk_id] = {"accepted": hit, "rejected": [], "clean": True}
    return chunks, keys, truth, [c for c in chunks if c.chunk_id not in results]


def _execute(cfg, client, pending, truth, keys, ledger, meta, results, on_created, sleep) -> None:
    cache = Cache(cfg.root / RESPONSES_DIR)
    firsts = _submit_batch(pending, cfg, client, meta, on_created, sleep) if cfg.batch and pending else {}
    for chunk in pending:  # each chunk is cached the moment it completes cleanly
        res = _analyze_chunk(chunk, truth, cfg, client, ledger, firsts.get(chunk.chunk_id), cfg.batch)
        results[chunk.chunk_id] = res
        if res["clean"]:
            cache.put(keys[chunk.chunk_id], meta["sanitizer"].obj({"findings": res["accepted"]}))


def _estimate(cfg, client, pending, out, cached):
    counts = {c.chunk_id: client.count_tokens(cfg.model, prompts.system_blocks(c.artifact_type, cfg.topic),
                                              [{"role": "user", "content": prompts.user_message(c.render())}])
              for c in pending}
    est = cost.estimate(cfg.model, list(counts.values()), max_tokens=cfg.max_tokens, batch=cfg.batch)
    out(_format_estimate(est, cached, cfg))
    cost.check_caps(est, max_usd=cfg.max_usd, max_input_tokens=cfg.max_input_tokens)  # before any send
    return counts, est


def _finish(cfg, client, chunks, results, run_dir, est, meta, ledger, tally, out) -> RunResult:
    san = meta["sanitizer"]
    findings = san.obj([f for c in chunks for f in results[c.chunk_id]["accepted"]])
    rejected = san.obj([r for c in chunks for r in results[c.chunk_id]["rejected"]])
    synthesis = None
    if cfg.synthesize and findings:
        try:
            synthesis = _synthesize(findings, cfg, client, ledger, out)
        except Exception as exc:  # noqa: BLE001 - findings are already paid for; never discard them
            out(san.text(scrub(f"synthesis failed: {type(exc).__name__}: {exc}")))
    tally = {**tally, "accepted": len(findings), "rejected": len(rejected)}
    manifest = _manifest(cfg, "ok", est, meta, ledger, tally, synthesis is not None)
    actual = _write_outputs(run_dir, manifest, findings, rejected, ledger, san.text(synthesis) if synthesis else synthesis)
    out(f"done: {len(findings)} accepted, {len(rejected)} rejected, actual ${actual:.4f} -> findings/raw/{cfg.run_id}")
    return RunResult("ok", est, len(findings), len(rejected), actual, run_dir)


def _sanitizer(cfg: RunConfig) -> canary.Sanitizer:
    if cfg.no_canary:
        return canary.Sanitizer(())
    try:
        return canary.Sanitizer.from_file(cfg.canary_file)
    except canary.CanaryError as exc:
        raise RunRefused(str(exc)) from None


def run(cfg: RunConfig, client_factory: Callable[[], object], out: Callable[[str], None] = print,
        sleep: Callable[[float], None] = time.sleep) -> RunResult:
    _validate_run_id(cfg.run_id)
    digest, files, skipped, denied, texts = _load_inputs(cfg, out)
    sanitizer = _sanitizer(cfg)
    results: dict[str, dict] = {}
    chunks, keys, truth, pending = _plan(cfg, texts, results)
    cached = len(chunks) - len(pending)
    client = client_factory()
    _counts, est = _estimate(cfg, client, pending, out, cached)
    if cfg.dry_run:
        out("dry run: nothing sent")
        return RunResult("dry-run", est, 0, 0, 0.0, None)
    run_dir = cfg.root / "findings" / "raw" / cfg.run_id
    prior_usd, prior_tokens = _prepare_run_dir(run_dir, cfg, digest)
    ledger = _Ledger(max(est.usd, prior_usd), max(est.input_tokens, prior_tokens), [],
                     max_usd=cfg.max_usd, max_tokens=cfg.max_input_tokens)
    meta = {"digest": digest, "files": files, "skipped": skipped, "denied": denied,
            "batch_id": cfg.resume_batch_id, "sanitizer": sanitizer}
    tally = {"chunks": len(chunks), "cached": cached, "accepted": 0, "rejected": 0}

    def checkpoint() -> None:
        status = "batch-pending" if meta["batch_id"] else "running"
        _write_manifest(run_dir, _manifest(cfg, status, est, meta, ledger, tally, False))
    ledger.checkpoint = checkpoint

    def on_created(batch_id: str) -> None:
        meta["batch_id"] = batch_id
        checkpoint()
    try:
        _execute(cfg, client, pending, truth, keys, ledger, meta, results, on_created, sleep)
    except Exception as exc:  # noqa: BLE001 - recorded scrubbed, original chain dropped
        message = sanitizer.text(scrub(f"{type(exc).__name__}: {exc}"))
        status = "batch-pending" if meta["batch_id"] else "error"  # a created batch stays resumable
        _write_failure(run_dir, _manifest(cfg, status, est, meta, ledger, tally, False, message), ledger)
        raise RunFailed(message) from None
    return _finish(cfg, client, chunks, results, run_dir, est, meta, ledger, tally, out)
