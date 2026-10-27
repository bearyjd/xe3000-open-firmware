from types import SimpleNamespace as NS

import pytest

from recon import client as cl
from recon.schema import FINDING_SCHEMA

FAKE_KEY = "sk-" + "ant-" + "api03-" + "Q" * 40


class FakeSDK:
    """Mimics the parts of anthropic.Anthropic that the wrapper touches."""

    def __init__(self, fail=None):
        self.calls = []
        self.fail = fail
        self.messages = NS(create=self._create, count_tokens=self._count,
                           batches=NS(create=self._bcreate, retrieve=self._bretrieve, results=self._bresults))

    def _maybe_fail(self):
        if self.fail:
            raise self.fail

    def _create(self, **kw):
        self.calls.append(("create", kw))
        self._maybe_fail()
        usage = NS(input_tokens=10, output_tokens=5, cache_read_input_tokens=3, cache_creation_input_tokens=2)
        return NS(content=[NS(type="text", text='{"findings": []}')], stop_reason="end_turn", usage=usage)

    def _count(self, **kw):
        self.calls.append(("count", kw))
        self._maybe_fail()
        return NS(input_tokens=777)

    def _bcreate(self, **kw):
        self.calls.append(("bcreate", kw))
        return NS(id="batch_1")

    def _bretrieve(self, **kw):
        self.calls.append(("bretrieve", kw))
        return NS(processing_status="ended")

    def _bresults(self, **kw):
        self.calls.append(("bresults", kw))
        usage = NS(input_tokens=1, output_tokens=1, cache_read_input_tokens=0, cache_creation_input_tokens=0)
        ok = NS(type="succeeded", message=NS(content=[NS(type="text", text="{}")], stop_reason="end_turn", usage=usage))
        return iter([NS(custom_id="a", result=ok), NS(custom_id="b", result=NS(type="errored"))])


def test_create_params_shape():
    sdk = FakeSDK()
    resp = cl.ReconClient(sdk).create("claude-sonnet-5-5", ["shared", "task"], [{"role": "user", "content": "x"}], 123)
    _, kw = sdk.calls[0]
    assert kw["output_config"] == {"format": {"type": "json_schema", "schema": FINDING_SCHEMA}}
    assert kw["max_tokens"] == 123 and kw["model"] == "claude-sonnet-5-5"
    for banned in ("temperature", "top_p", "top_k", "output_format", "betas", "extra_headers"):
        assert banned not in kw
    assert [b["text"] for b in kw["system"]] == ["shared", "task"]
    assert "cache_control" not in kw["system"][0]
    assert kw["system"][-1]["cache_control"] == {"type": "ephemeral"}
    assert resp.text == '{"findings": []}' and resp.usage == cl.Usage(10, 5, 3, 2)


def test_count_tokens_uses_same_prefix_and_schema():
    sdk = FakeSDK()
    n = cl.ReconClient(sdk).count_tokens("m", ["a", "b"], [{"role": "user", "content": "x"}])
    kind, kw = sdk.calls[0]
    assert n == 777 and kind == "count"
    assert kw["output_config"]["format"]["type"] == "json_schema" and kw["system"][-1]["cache_control"]
    assert "max_tokens" not in kw and "temperature" not in kw


def test_create_text_has_no_structured_output():
    sdk = FakeSDK()
    cl.ReconClient(sdk).create_text("m", ["a"], [{"role": "user", "content": "x"}], 50)
    assert "output_config" not in sdk.calls[0][1] and "temperature" not in sdk.calls[0][1]


def test_batches():
    sdk = FakeSDK()
    c = cl.ReconClient(sdk)
    bid = c.batch_create("m", [("a", ["s"], [{"role": "user", "content": "x"}])], 99)
    assert bid == "batch_1"
    req = sdk.calls[0][1]["requests"][0]
    assert req["custom_id"] == "a" and req["params"]["output_config"]["format"]["type"] == "json_schema"
    assert "temperature" not in req["params"]
    assert c.batch_status("batch_1") == "ended"
    results = c.batch_results("batch_1")
    assert results["a"].text == "{}" and results["b"] is None


def test_errors_are_scrubbed_and_chain_suppressed():
    sdk = FakeSDK(fail=RuntimeError(f"401 invalid x-api-key {FAKE_KEY}"))
    c = cl.ReconClient(sdk)
    for call in (lambda: c.create("m", ["s"], [], 10), lambda: c.count_tokens("m", ["s"], [])):
        with pytest.raises(cl.ReconApiError) as ei:
            call()
        assert FAKE_KEY not in str(ei.value) and "sk-ant-" not in str(ei.value)
        assert ei.value.__cause__ is None and ei.value.__suppress_context__ is True


def test_scrub_masks_env_key_value(monkeypatch):
    from recon.scrub import scrub
    monkeypatch.setenv("ANTHROPIC_API_KEY", "plainvalue-123456")
    assert "plainvalue-123456" not in scrub("boom plainvalue-123456 boom")
    assert FAKE_KEY not in scrub(f"x {FAKE_KEY} y")


def test_load_env_reads_file_without_printing(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "placeholder")
    monkeypatch.delenv("ANTHROPIC_API_KEY")
    env = tmp_path / "e.env"
    env.write_text("ANTHROPIC_API_KEY=" + FAKE_KEY + "\n")
    cl.load_env(env)
    import os
    assert os.environ["ANTHROPIC_API_KEY"] == FAKE_KEY
    assert FAKE_KEY not in "".join(capsys.readouterr())
    monkeypatch.delenv("ANTHROPIC_API_KEY")
    cl.load_env(None)
    with pytest.raises(cl.ReconApiError):
        cl.load_env(tmp_path / "missing.env")


def test_missing_key_is_a_clear_error(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    with pytest.raises(cl.ReconApiError, match="ANTHROPIC_API_KEY"):
        cl.ReconClient()


def test_sdk_built_with_retries_disabled(monkeypatch):
    import anthropic
    seen = {}
    monkeypatch.setattr(anthropic, "Anthropic", lambda **kw: seen.update(kw) or FakeSDK())
    cl.ReconClient(api_key="placeholder-key-value")
    assert seen["max_retries"] == 0


def _timeout():
    import anthropic
    return anthropic.APITimeoutError(request=NS(method="GET", url="http://x"))


class FlakySDK(FakeSDK):
    """retrieve/results fail `n` times with a timeout before succeeding."""

    def __init__(self, n, exc=None):
        super().__init__()
        self.left = {"bretrieve": n, "bresults": n}
        self.exc = exc or _timeout()
        self.attempts = []

    def _bretrieve(self, **kw):
        self.attempts.append(("retrieve", kw))
        if self.left["bretrieve"] > 0:
            self.left["bretrieve"] -= 1
            raise self.exc
        return super()._bretrieve(**kw)

    def _bresults(self, **kw):
        self.attempts.append(("results", kw))
        if self.left["bresults"] > 0:
            self.left["bresults"] -= 1
            raise self.exc
        return super()._bresults(**kw)

    def __getattr__(self, name):
        raise AttributeError(name)


def _flaky(n, **kw):
    sdk = FlakySDK(n, **kw)
    sdk.messages = NS(create=sdk._create, count_tokens=sdk._count,
                      batches=NS(create=sdk._bcreate, retrieve=sdk._bretrieve, results=sdk._bresults))
    return sdk


def test_batch_polling_retries_transient_timeouts_with_backoff():
    sdk, naps = _flaky(2), []
    c = cl.ReconClient(sdk, sleep=naps.append)
    assert c.batch_status("b") == "ended"
    assert len([a for a in sdk.attempts if a[0] == "retrieve"]) == 3 and len(naps) == 2 and naps[1] > naps[0]
    assert all(kw["timeout"] == cl.FREE_CALL_TIMEOUT_SECONDS for _k, kw in sdk.attempts)
    assert c.batch_results("b")["a"].text == "{}"


def test_batch_polling_gives_up_after_five_tries_scrubbed():
    exc = _timeout()
    sdk, naps = _flaky(99, exc=exc), []
    with pytest.raises(cl.ReconApiError):
        cl.ReconClient(sdk, sleep=naps.append).batch_status("b")
    assert len(sdk.attempts) == 5 and len(naps) == 4


def test_non_transient_errors_are_not_retried():
    sdk, naps = _flaky(99, exc=RuntimeError("401 " + FAKE_KEY)), []
    with pytest.raises(cl.ReconApiError) as ei:
        cl.ReconClient(sdk, sleep=naps.append).batch_status("b")
    assert len(sdk.attempts) == 1 and FAKE_KEY not in str(ei.value)


def test_paid_calls_are_never_retried():
    sdk = FakeSDK(fail=_timeout())
    with pytest.raises(cl.ReconApiError):
        cl.ReconClient(sdk, sleep=lambda _s: None).create("m", ["s"], [], 10)
    assert len(sdk.calls) == 1
