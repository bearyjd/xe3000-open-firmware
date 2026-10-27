import pytest

from recon import cost


def test_every_configured_model_has_a_price():
    for model in cost.configured_models({}):
        assert cost.price_for(model)
    env = {"LLM_MODEL": "claude-sonnet-5-5", "LLM_MODEL_CHEAP": "claude-haiku-5-5"}
    for model in cost.configured_models(env):
        assert cost.price_for(model)
    assert {cost.SYNTH_MODEL, cost.DEFAULT_MODEL, cost.DEFAULT_MODEL_CHEAP} <= set(cost.PRICES)


def test_unknown_model_is_an_error():
    with pytest.raises(cost.UnknownModel):
        cost.price_for("claude-mystery-9")
    with pytest.raises(cost.UnknownModel):
        cost.configured_models({"LLM_MODEL": "claude-mystery-9"})


def test_price_table_cites_source_and_date():
    assert cost.PRICE_SOURCE_URL.startswith("https://platform.claude.com/")
    assert cost.PRICE_AS_OF == "2026-10-26"


def test_worst_case_formula():
    # sonnet: $2 in / $10 out per MTok; input carries the 1.25x cache-write premium (true upper bound)
    assert cost.worst_case_usd("claude-sonnet-5-5", 1_000_000, 100_000) == pytest.approx(2.5 + 1.0)
    assert cost.worst_case_usd("claude-opus-5-5", 1_000_000, 1_000_000) == pytest.approx(5.0 + 20.0)
    assert cost.worst_case_usd("claude-sonnet-5-5", 1_000_000, 100_000, batch=True) == pytest.approx(1.75)


def test_haiku_tier_above_100k():
    low = cost.worst_case_usd("claude-haiku-5-5", 100_000, 1_000_000)
    assert low == pytest.approx(0.1 * 0.1 * 1.25 + 0.5)
    high = cost.worst_case_usd("claude-haiku-5-5", 100_001, 1_000_000)
    assert high == pytest.approx(0.100001 * 0.5 * 1.25 + 2.5)


def test_estimate_sums_chunks_and_caps():
    est = cost.estimate("claude-sonnet-5-5", [1000, 2000], max_tokens=4096, batch=False)
    assert est.input_tokens == 3000 and est.chunks == 2
    assert est.usd == pytest.approx(2 * (4096 * 10 / 1e6) + 3000 * 2 * 1.25 / 1e6)
    cost.check_caps(est, max_usd=1.0, max_input_tokens=10_000)
    with pytest.raises(cost.CapExceeded, match="USD"):
        cost.check_caps(est, max_usd=0.01, max_input_tokens=10_000)
    with pytest.raises(cost.CapExceeded, match="input tokens"):
        cost.check_caps(est, max_usd=1.0, max_input_tokens=2999)


def test_actual_cost_uses_cache_multipliers():
    u = cost.actual_usd("claude-sonnet-5-5", input_tokens=1_000_000, output_tokens=0,
                        cache_read_tokens=1_000_000, cache_creation_tokens=1_000_000)
    assert u == pytest.approx(2.0 + 0.2 + 2.5)


@pytest.mark.parametrize("model", sorted(cost.PRICES))
@pytest.mark.parametrize("batch", [False, True])
@pytest.mark.parametrize("n", [1, 5_000, 100_000, 100_001, 900_000])
def test_worst_case_bounds_any_actual_usage(model, batch, n):
    max_tokens = 4096
    bound = cost.worst_case_usd(model, n, max_tokens, batch=batch)
    for split in (dict(input_tokens=n), dict(cache_creation_tokens=n), dict(cache_read_tokens=n),
                  dict(input_tokens=n // 2, cache_creation_tokens=n - n // 2)):
        actual = cost.actual_usd(model, **{"input_tokens": 0, "output_tokens": max_tokens, "batch": batch, **split})
        assert actual <= bound + 1e-12, (split, actual, bound)
