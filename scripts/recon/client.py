"""Anthropic SDK wrapper: structured outputs, cached system prefix, batches, token counting, error scrubbing.

Never sends temperature/top_p/top_k. The API key is read from the environment only and is never printed.
"""
from __future__ import annotations

import os
import time
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from recon.schema import FINDING_SCHEMA
from recon.scrub import scrub

MAX_TOKENS_DEFAULT = 4096
OUTPUT_CONFIG: dict = {"format": {"type": "json_schema", "schema": FINDING_SCHEMA}}
CACHE_CONTROL: dict = {"type": "ephemeral"}
# Free, idempotent calls (batch retrieve/results) may be retried; paid calls never are (max_retries=0).
FREE_CALL_TRIES = 5
FREE_CALL_TIMEOUT_SECONDS = 60.0
FREE_CALL_BACKOFF_SECONDS = 2.0
TRANSIENT_ERROR_NAMES = frozenset({"APITimeoutError", "APIConnectionError", "TimeoutError", "ConnectionError"})


class ReconApiError(RuntimeError):
    """SDK failure with the message scrubbed of key material."""


@dataclass(frozen=True)
class Usage:
    input_tokens: int
    output_tokens: int
    cache_read_tokens: int
    cache_creation_tokens: int


@dataclass(frozen=True)
class ModelResponse:
    text: str
    stop_reason: str | None
    usage: Usage


def load_env(env_file: Path | None) -> None:
    """Load KEY=VALUE pairs from an explicit .env path into the environment. Values are never echoed."""
    if env_file is None:
        return
    from dotenv import load_dotenv
    if not Path(env_file).is_file():
        raise ReconApiError(f"env file not found: {env_file}")
    load_dotenv(env_file, override=False)


def system_blocks(system: Sequence[str]) -> list[dict]:
    """Text blocks with cache_control on the last one (shared prompt + per-task instructions)."""
    blocks = [{"type": "text", "text": text} for text in system]
    if blocks:
        blocks[-1] = {**blocks[-1], "cache_control": CACHE_CONTROL}
    return blocks


def _usage(raw) -> Usage:
    return Usage(getattr(raw, "input_tokens", 0) or 0, getattr(raw, "output_tokens", 0) or 0,
                 getattr(raw, "cache_read_input_tokens", 0) or 0,
                 getattr(raw, "cache_creation_input_tokens", 0) or 0)


def _response(message) -> ModelResponse:
    text = "".join(getattr(b, "text", "") for b in message.content if getattr(b, "type", "text") == "text")
    return ModelResponse(text, message.stop_reason, _usage(message.usage))


class ReconClient:
    def __init__(self, sdk=None, api_key: str | None = None, sleep=time.sleep) -> None:
        self._sleep = sleep
        if sdk is None:
            import anthropic
            key = api_key or os.environ.get("ANTHROPIC_API_KEY")
            if not key:
                raise ReconApiError("ANTHROPIC_API_KEY is not set (use --env-file / --env)")
            sdk = anthropic.Anthropic(api_key=key, max_retries=0)  # retries would be unbudgeted spend
        self._sdk = sdk

    def _call(self, fn, **kwargs):
        try:
            return fn(**kwargs)
        except Exception as exc:  # noqa: BLE001 - re-raised scrubbed, original chain suppressed
            raise ReconApiError(scrub(f"{type(exc).__name__}: {exc}")) from None

    def _free_call(self, fn, **kwargs):
        """Retry transient timeouts/connection errors with backoff; anything else fails at once (scrubbed)."""
        for attempt in range(FREE_CALL_TRIES):
            try:
                return fn(timeout=FREE_CALL_TIMEOUT_SECONDS, **kwargs)
            except Exception as exc:  # noqa: BLE001 - re-raised scrubbed, original chain suppressed
                transient = any(k.__name__ in TRANSIENT_ERROR_NAMES for k in type(exc).__mro__)
                if not transient or attempt == FREE_CALL_TRIES - 1:
                    raise ReconApiError(scrub(f"{type(exc).__name__}: {exc}")) from None
                self._sleep(FREE_CALL_BACKOFF_SECONDS * 2 ** attempt)

    def _params(self, model, system, messages, max_tokens):
        return {"model": model, "max_tokens": max_tokens, "system": system_blocks(system),
                "messages": messages, "output_config": OUTPUT_CONFIG}

    def count_tokens(self, model: str, system: Sequence[str], messages: list[dict]) -> int:
        result = self._call(self._sdk.messages.count_tokens, model=model, system=system_blocks(system),
                            messages=messages, output_config=OUTPUT_CONFIG)
        return int(result.input_tokens)

    def create(self, model: str, system: Sequence[str], messages: list[dict],
               max_tokens: int = MAX_TOKENS_DEFAULT) -> ModelResponse:
        return _response(self._call(self._sdk.messages.create, **self._params(model, system, messages, max_tokens)))

    def create_text(self, model: str, system: Sequence[str], messages: list[dict],
                    max_tokens: int = MAX_TOKENS_DEFAULT) -> ModelResponse:
        """Plain text call (no structured output), used by --synthesize."""
        params = {"model": model, "max_tokens": max_tokens, "system": system_blocks(system), "messages": messages}
        return _response(self._call(self._sdk.messages.create, **params))

    def batch_create(self, model: str, items: Sequence[tuple[str, Sequence[str], list[dict]]],
                     max_tokens: int = MAX_TOKENS_DEFAULT) -> str:
        requests = [{"custom_id": cid, "params": self._params(model, system, messages, max_tokens)}
                    for cid, system, messages in items]
        return self._call(self._sdk.messages.batches.create, requests=requests).id

    def batch_status(self, batch_id: str) -> str:
        return self._free_call(self._sdk.messages.batches.retrieve, message_batch_id=batch_id).processing_status

    def batch_results(self, batch_id: str) -> dict[str, ModelResponse | None]:
        out: dict[str, ModelResponse | None] = {}
        entries = self._free_call(lambda **kw: list(self._sdk.messages.batches.results(**kw)), message_batch_id=batch_id)
        for entry in entries:
            ok = entry.result.type == "succeeded"
            out[entry.custom_id] = _response(entry.result.message) if ok else None
        return out
