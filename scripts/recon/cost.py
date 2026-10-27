"""Worst-case cost estimation and cap enforcement (PRP 0001 §3.4)."""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType

# Source: https://platform.claude.com/docs/en/about-claude/pricing, as of 2026-10-26 (USD per million tokens).
PRICE_SOURCE_URL = "https://platform.claude.com/docs/en/about-claude/pricing"
PRICE_AS_OF = "2026-10-26"
TOKENS_PER_MTOK = 1_000_000
BATCH_FACTOR = 0.5
CACHE_READ_FACTOR = 0.1
CACHE_WRITE_FACTOR = 1.25  # 5-minute ephemeral cache

DEFAULT_MODEL = "claude-sonnet-5-5"
DEFAULT_MODEL_CHEAP = "claude-haiku-5-5"
SYNTH_MODEL = "claude-opus-5-5"


class UnknownModel(KeyError):
    """No price entry for a configured model."""


class CapExceeded(RuntimeError):
    """The worst-case estimate is over a configured cap; nothing may be sent."""


@dataclass(frozen=True)
class Price:
    input_per_mtok: float
    output_per_mtok: float
    long_threshold: int | None = None  # prompt tokens above this use the long_* rates
    long_input_per_mtok: float | None = None
    long_output_per_mtok: float | None = None

    def rates(self, input_tokens: int) -> tuple[float, float]:
        if self.long_threshold is not None and input_tokens > self.long_threshold:
            return self.long_input_per_mtok, self.long_output_per_mtok
        return self.input_per_mtok, self.output_per_mtok


PRICES: Mapping[str, Price] = MappingProxyType({
    "claude-opus-5-5": Price(4.0, 20.0),
    "claude-sonnet-5-5": Price(2.0, 10.0),
    "claude-haiku-5-5": Price(0.10, 0.50, long_threshold=100_000,
                              long_input_per_mtok=0.50, long_output_per_mtok=2.50),
})


@dataclass(frozen=True)
class Estimate:
    model: str
    batch: bool
    chunks: int
    input_tokens: int
    max_output_tokens: int
    usd: float


def price_for(model: str) -> Price:
    try:
        return PRICES[model]
    except KeyError:
        raise UnknownModel(f"no price entry for model {model!r}; add it to cost.PRICES") from None


def configured_models(env: Mapping[str, str]) -> tuple[str, ...]:
    models = (env.get("LLM_MODEL") or DEFAULT_MODEL, env.get("LLM_MODEL_CHEAP") or DEFAULT_MODEL_CHEAP, SYNTH_MODEL)
    for m in models:
        price_for(m)
    return models


def worst_case_usd(model: str, input_tokens: int, max_tokens: int, *, batch: bool = False) -> float:
    """True upper bound: every counted input token at the base price WITH the cache-write premium (the system
    prefix is written to the cache on a miss; cache discounts are ignored) + max_tokens at the output price."""
    rate_in, rate_out = price_for(model).rates(input_tokens)
    usd = (input_tokens * rate_in * CACHE_WRITE_FACTOR + max_tokens * rate_out) / TOKENS_PER_MTOK
    return usd * BATCH_FACTOR if batch else usd


def estimate(model: str, counts: Sequence[int], *, max_tokens: int, batch: bool) -> Estimate:
    usd = sum(worst_case_usd(model, n, max_tokens, batch=batch) for n in counts)
    return Estimate(model, batch, len(counts), sum(counts), max_tokens * len(counts), usd)


def check_caps(est: Estimate, *, max_usd: float, max_input_tokens: int) -> None:
    if est.usd > max_usd:
        raise CapExceeded(f"worst-case ${est.usd:.4f} exceeds cap ${max_usd:.4f} USD; nothing sent")
    if est.input_tokens > max_input_tokens:
        raise CapExceeded(f"{est.input_tokens} input tokens exceed cap {max_input_tokens} input tokens; nothing sent")


def actual_usd(model: str, *, input_tokens: int, output_tokens: int, cache_read_tokens: int = 0,
               cache_creation_tokens: int = 0, batch: bool = False) -> float:
    rate_in, rate_out = price_for(model).rates(input_tokens + cache_read_tokens + cache_creation_tokens)
    usd = (input_tokens * rate_in + cache_read_tokens * rate_in * CACHE_READ_FACTOR
           + cache_creation_tokens * rate_in * CACHE_WRITE_FACTOR + output_tokens * rate_out) / TOKENS_PER_MTOK
    return usd * BATCH_FACTOR if batch else usd
