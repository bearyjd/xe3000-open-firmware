import json
import os
from dataclasses import replace
import re

import pytest

from fakes import FakeClient, response
from recon import cli, cost

FAKE_KEY = "sk-" + "ant-" + "api03-" + "Z" * 40


def _first_evidence(messages):
    """Build a valid evidence item from the first numbered line of the chunk text."""
    text = messages[0]["content"]
    file = re.search(r"=== FILE: (\S+) ===", text).group(1)
    rows = [(len(m.group(2).strip()), int(m.group(1)), m.group(2).strip())
            for m in re.finditer(r"^ *(\d+)\| (.+)$", text.split("=== FILE:")[1], re.MULTILINE)]
    _, line, excerpt = max(rows)
    return {"file": file, "line": line, "excerpt": excerpt}


def good(messages, claim="Describes the artifact", **kw):
    return {"claim": claim, "category": "other", "confidence": "medium", "evidence": [_first_evidence(messages)], **kw}


def always_good(i, messages):
    return response([good(messages)])


def run_cli(root, client, *extra, run_id="r1"):
    # fixture runs opt in explicitly: allow everything and skip the canary (tests of the layers use cli.main directly)
    argv = ["--root", str(root), "--run-id", run_id, "--allow-extra", "**", "--no-canary", *extra]
    return cli.main(argv, client_factory=lambda: client)


def read_jsonl(path):
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def one_file_root(root, stamp, text="start() {\n  echo hi\n}\n"):
    (root / "harvest" / "redacted" / "etc" / "init.d").mkdir(parents=True)
    (root / "harvest" / "redacted" / "etc" / "init.d" / "modem").write_text(text)
    stamp(root)
    return root


# ---- test plan item 3: raw is refused ----

@pytest.mark.parametrize("target", ["harvest/raw", "harvest/redacted/../raw", "../elsewhere"])
def test_refuses_raw_and_traversal(stamped, target, capsys):
    (stamped / "harvest" / "raw" / "t.txt").write_text("raw\n")
    client = FakeClient()
    assert run_cli(stamped, client, "--input", target) == 2
    assert client.count_calls == [] and client.create_calls == []
    assert "refused" in capsys.readouterr().err


def test_refuses_symlink_from_redacted_to_raw(stamped, capsys):
    (stamped / "harvest" / "raw" / "secret.txt").write_text("raw\n")
    os.symlink(stamped / "harvest" / "raw" / "secret.txt", stamped / "harvest" / "redacted" / "link")
    client = FakeClient()
    assert run_cli(stamped, client) == 2
    assert client.count_calls == [] and client.create_calls == []
    assert not (stamped / "findings" / "raw" / "r1").exists()


def test_refuses_without_preflight_stamp(root, fixture_tree, capsys):
    client = FakeClient()
    assert run_cli(root, client) == 2
    assert "pre-flight" in capsys.readouterr().err and client.count_calls == []


def test_stamp_invalidated_by_tree_change(stamped, capsys):
    (stamped / "harvest" / "redacted" / "etc" / "config" / "network").write_text("changed\n")
    assert run_cli(stamped, FakeClient()) == 2


def test_bad_run_id(stamped):
    assert run_cli(stamped, FakeClient(), run_id="../x") == 2


# ---- test plan item 5: cost cap ----

def test_cost_cap_blocks_before_any_send(stamped, capsys):
    client = FakeClient(tokens=5_000_000)
    assert run_cli(stamped, client, "--max-usd", "0.25") == 2
    assert client.create_calls == [] and client.batches == {}
    err = capsys.readouterr()
    assert "estimate:" in err.out and "nothing sent" in err.err
    assert not (stamped / "findings" / "raw" / "r1").exists()


def test_input_token_cap_blocks(stamped):
    client = FakeClient(tokens=1000)
    assert run_cli(stamped, client, "--max-input-tokens", "10", "--max-usd", "100") == 2
    assert client.create_calls == []


def test_dry_run_prints_estimate_and_sends_nothing(stamped, capsys):
    client = FakeClient(tokens=1000)
    assert run_cli(stamped, client, "--dry-run", "--max-usd", "5") == 0
    assert client.create_calls == [] and client.count_calls
    assert "worst_case_usd" in capsys.readouterr().out
    assert not (stamped / "findings" / "raw" / "r1").exists()


# ---- happy path, outputs, cache ----

def test_full_run_writes_all_outputs(stamped, capsys):
    client = FakeClient(script=always_good)
    assert run_cli(stamped, client, "--max-usd", "5") == 0
    run_dir = stamped / "findings" / "raw" / "r1"
    for name in ("findings.jsonl", "rejected.jsonl", "usage.json", "manifest.json"):
        assert (run_dir / name).exists()
    findings = read_jsonl(run_dir / "findings.jsonl")
    assert len(findings) == len(client.create_calls) > 1
    assert all(len(e["excerpt_sha256"]) == 64 for f in findings for e in f["evidence"])
    manifest = json.loads((run_dir / "manifest.json").read_text())
    assert manifest["status"] == "ok" and manifest["model"] == cost.DEFAULT_MODEL
    assert manifest["prompt_version"] and manifest["inputs"]["files"] and manifest["estimate"]["worst_case_usd"] > 0
    usage = json.loads((run_dir / "usage.json").read_text())
    assert usage["totals"]["usd"] > 0 and len(usage["calls"]) == len(client.create_calls)
    out = capsys.readouterr().out
    assert 0 <= out.index("estimate:") < out.index("done:")


def test_request_shape_uses_cached_prefix_inputs(stamped):
    client = FakeClient(script=always_good)
    run_cli(stamped, client, "--max-usd", "5")
    model, system, messages, max_tokens = client.create_calls[0]
    assert len(system) == 2 and "=== FILE:" in messages[0]["content"] and max_tokens == 4096


def test_second_run_served_from_cache(stamped):
    first = FakeClient(script=always_good)
    assert run_cli(stamped, first, "--max-usd", "5", run_id="a") == 0
    second = FakeClient(script=always_good)
    assert run_cli(stamped, second, "--max-usd", "5", run_id="b") == 0
    assert second.create_calls == [] and second.count_calls == []
    assert len(read_jsonl(stamped / "findings" / "raw" / "b" / "findings.jsonl")) == len(first.create_calls)


def test_existing_run_dir_refused(stamped):
    assert run_cli(stamped, FakeClient(script=always_good), "--max-usd", "5") == 0
    assert run_cli(stamped, FakeClient(script=always_good), "--max-usd", "5") == 2


def test_cheap_flag_selects_cheap_model(stamped):
    client = FakeClient(script=always_good)
    run_cli(stamped, client, "--max-usd", "5", "--cheap")
    assert client.create_calls[0][0] == cost.DEFAULT_MODEL_CHEAP


# ---- test plan item 4: evidence validation, retries, ungrounded ----

def test_bad_then_good_is_retried_with_reason(root, stamp):
    one_file_root(root, stamp)
    def script(i, messages):
        if i == 0:
            return response([{"claim": "no evidence", "category": "other", "confidence": "low", "evidence": []}])
        return response([good(messages)])
    client = FakeClient(script=script)
    assert run_cli(root, client, "--max-usd", "5") == 0
    assert len(client.create_calls) == 2
    assert "no evidence" in client.create_calls[1][2][0]["content"]  # rejection reason fed back
    run_dir = root / "findings" / "raw" / "r1"
    assert len(read_jsonl(run_dir / "findings.jsonl")) == 1
    kept = read_jsonl(run_dir / "rejected.jsonl")  # attempt-0 rejection is kept for the record
    assert len(kept) == 1 and kept[0]["attempt"] == 0


@pytest.mark.parametrize("mutate", [
    lambda f: f.update(evidence=[]),
    lambda f: f["evidence"][0].update(excerpt="not in the file at all"),
    lambda f: f["evidence"][0].update(file="redacted/etc/init.d/other"),
])
def test_always_bad_is_rejected_after_two_retries(root, stamp, mutate):
    one_file_root(root, stamp)
    def script(i, messages):
        f = good(messages)
        mutate(f)
        return response([f])
    client = FakeClient(script=script)
    assert run_cli(root, client, "--max-usd", "5") == 0
    assert len(client.create_calls) == 3
    run_dir = root / "findings" / "raw" / "r1"
    assert read_jsonl(run_dir / "findings.jsonl") == []
    rejected = read_jsonl(run_dir / "rejected.jsonl")
    assert [r["attempt"] for r in rejected] == [0, 1, 2] and all(r["reason"] and r["chunk_id"] for r in rejected)


def test_truncated_and_non_json_output_is_rejected(root, stamp):
    one_file_root(root, stamp)
    client = FakeClient(script=lambda i, m: response([], stop="max_tokens"))
    assert run_cli(root, client, "--max-usd", "5") == 0
    assert "truncated" in read_jsonl(root / "findings" / "raw" / "r1" / "rejected.jsonl")[0]["reason"]


def test_ungrounded_at_command_is_flagged_not_dropped(root, stamp):
    one_file_root(root, stamp)
    client = FakeClient(script=lambda i, m: response([good(m, claim="Powers off the modem with AT+QPOWD")]))
    assert run_cli(root, client, "--max-usd", "5") == 0
    findings = read_jsonl(root / "findings" / "raw" / "r1" / "findings.jsonl")
    assert len(findings) == 1 and "AT+QPOWD" in findings[0]["ungrounded"][0]


def test_grounded_at_command_not_flagged(root, stamp):
    one_file_root(root, stamp, text="echo 'AT+CFUN=1' > /dev/ttyUSB2\n")
    client = FakeClient(script=lambda i, m: response([good(m, claim="Sets full functionality with AT+CFUN")]))
    run_cli(root, client, "--max-usd", "5")
    assert read_jsonl(root / "findings" / "raw" / "r1" / "findings.jsonl")[0]["ungrounded"] == []


def test_retry_skipped_when_cap_would_be_exceeded(root, stamp):
    one_file_root(root, stamp)
    client = FakeClient(script=lambda i, m: response([{"claim": "x", "category": "other", "confidence": "low", "evidence": []}]),
                        tokens=100)
    assert run_cli(root, client, "--max-usd", "0.05") == 0
    assert len(client.create_calls) == 1
    assert "retry skipped" in read_jsonl(root / "findings" / "raw" / "r1" / "rejected.jsonl")[-1]["reason"]


# ---- batch and synthesis ----

def test_batch_path(stamped):
    client = FakeClient(script=always_good)
    assert run_cli(stamped, client, "--max-usd", "5", "--batch") == 0
    assert client.create_calls == [] and client.batches
    manifest = json.loads((stamped / "findings" / "raw" / "r1" / "manifest.json").read_text())
    assert manifest["batch"] is True


def test_synthesize_uses_opus_text_call(stamped):
    client = FakeClient(script=always_good)
    assert run_cli(stamped, client, "--max-usd", "5", "--synthesize") == 0
    assert len(client.text_calls) == 1 and client.text_calls[0][0] == cost.SYNTH_MODEL
    assert (stamped / "findings" / "raw" / "r1" / "synthesis.md").exists()


def test_synthesis_skipped_over_cap(stamped, capsys):
    calls = {"n": 0}
    class Pricey(FakeClient):
        def count_tokens(self, model, system, messages):
            calls["n"] += 1
            return 10 if model != cost.SYNTH_MODEL else 4_000_000
    client = Pricey(script=always_good)
    assert run_cli(stamped, client, "--max-usd", "5", "--synthesize", "--max-input-tokens", "10000000") == 0
    assert client.text_calls == [] and "synthesis skipped" in capsys.readouterr().out


# ---- test plan item 6: key never surfaces ----

def test_forced_exception_with_key_never_surfaces(stamped, capsys):
    def boom(i, messages):
        return RuntimeError(f"401 invalid x-api-key: {FAKE_KEY} (request failed)")
    client = FakeClient(script=boom)
    assert run_cli(stamped, client, "--max-usd", "5") == 2
    seen = capsys.readouterr()
    assert FAKE_KEY not in seen.out + seen.err and "sk-ant-" not in seen.out + seen.err
    for path in stamped.rglob("*"):
        if path.is_file():
            assert FAKE_KEY not in path.read_text(errors="ignore"), path
    manifest = json.loads((stamped / "findings" / "raw" / "r1" / "manifest.json").read_text())
    assert manifest["status"] == "error" and FAKE_KEY not in json.dumps(manifest)


def test_model_output_containing_key_is_scrubbed_in_cache_and_findings(root, stamp):
    one_file_root(root, stamp)
    client = FakeClient(script=lambda i, m: response([good(m, claim=f"leak {FAKE_KEY}")]))
    run_cli(root, client, "--max-usd", "5")
    for path in root.rglob("*"):
        if path.is_file():
            assert FAKE_KEY not in path.read_text(errors="ignore"), path


def test_unknown_model_env_refused(stamped, monkeypatch, capsys):
    monkeypatch.setenv("LLM_MODEL", "claude-mystery-9")
    assert run_cli(stamped, FakeClient()) == 2
    assert "claude-mystery-9" in capsys.readouterr().err


# ================= review fixes =================

def cache_files(root):
    d = root / "cache" / "responses"
    return sorted(d.glob("*.json")) if d.exists() else []


def bad_finding(messages):
    return {"claim": "x", "category": "other", "confidence": "low", "evidence": []}


def test_cache_lives_in_responses_dir_and_stamps_stay_apart(root, stamp):
    one_file_root(root, stamp)
    run_cli(root, FakeClient(script=always_good), "--max-usd", "5")
    assert len(cache_files(root)) == 1
    assert not list((root / "cache").glob("*.json"))


@pytest.mark.parametrize("script", [
    lambda i, m: response([bad_finding(m)]),                       # rejected rows every attempt
    lambda i, m: response([], stop="max_tokens"),                  # truncation
    lambda i, m: response([{"nope": 1}]),                          # schema failure
])
def test_unclean_chunks_are_never_cached(root, stamp, script):
    one_file_root(root, stamp)
    run_cli(root, FakeClient(script=script), "--max-usd", "5")
    assert cache_files(root) == []


def test_cap_skipped_retry_is_not_cached(root, stamp):
    one_file_root(root, stamp)
    client = FakeClient(script=lambda i, m: response([bad_finding(m)]), tokens=100)
    run_cli(root, client, "--max-usd", "0.05")
    assert cache_files(root) == []


def test_clean_after_retry_is_cached(root, stamp):
    one_file_root(root, stamp)
    run_cli(root, FakeClient(script=lambda i, m: response([bad_finding(m)]) if i == 0 else response([good(m)])),
            "--max-usd", "5")
    assert len(cache_files(root)) == 1


def test_each_chunk_cached_as_it_completes_even_if_a_later_one_fails(stamped):
    def script(i, messages):
        return RuntimeError("network down") if i == 2 else response([good(messages)])
    assert run_cli(stamped, FakeClient(script=script), "--max-usd", "5") == 2
    assert len(cache_files(stamped)) == 2
    resumed = FakeClient(script=always_good)
    assert run_cli(stamped, resumed, "--max-usd", "5", run_id="again") == 0
    assert len(resumed.create_calls) == 4  # 6 chunks - 2 cached


def test_synthesis_failure_keeps_findings(stamped, capsys):
    class Boom(FakeClient):
        def create_text(self, *a, **k):
            raise RuntimeError("synth exploded " + FAKE_KEY)
    assert run_cli(stamped, Boom(script=always_good), "--max-usd", "5", "--synthesize") == 0
    run_dir = stamped / "findings" / "raw" / "r1"
    assert len(read_jsonl(run_dir / "findings.jsonl")) == 6
    out = capsys.readouterr()
    assert "synthesis failed" in out.out and FAKE_KEY not in out.out + out.err
    assert json.loads((run_dir / "manifest.json").read_text())["status"] == "ok"


def test_batch_id_persisted_before_waiting_and_in_final_manifest(stamped):
    seen = {}
    class Watch(FakeClient):
        def batch_status(self, batch_id):
            seen["manifest"] = json.loads((stamped / "findings" / "raw" / "r1" / "manifest.json").read_text())
            return "ended"
    assert run_cli(stamped, Watch(script=always_good), "--max-usd", "5", "--batch") == 0
    assert seen["manifest"]["batch_id"] == "b1" and seen["manifest"]["status"] == "batch-pending"
    final = json.loads((stamped / "findings" / "raw" / "r1" / "manifest.json").read_text())
    assert final["batch_id"] == "b1" and final["status"] == "ok"


def test_batch_wait_times_out(stamped):
    from recon import runner
    class Never(FakeClient):
        def batch_status(self, batch_id):
            return "in_progress"
    cfg = runner.RunConfig(root=stamped, inputs=(stamped / "harvest" / "redacted", stamped / "unpacked"),
                           run_id="t", model=cost.DEFAULT_MODEL, max_usd=5, batch=True,
                           batch_poll_seconds=10, batch_timeout_seconds=25, allow_extra=("**",), no_canary=True)
    slept = []
    with pytest.raises(runner.RunFailed, match="timed out"):
        runner.run(cfg, lambda: Never(script=always_good), out=lambda _l: None, sleep=slept.append)
    assert sum(slept) >= 25 and len(slept) < 10
    manifest = json.loads((stamped / "findings" / "raw" / "t" / "manifest.json").read_text())
    assert manifest["batch_id"] == "b1" and manifest["status"] == "batch-pending" and manifest["error"]


class NoneBatch(FakeClient):
    """Batch where every item errored/expired (client returns None)."""
    def batch_results(self, batch_id):
        return {cid: None for cid in self.batches[batch_id]}


def test_failed_batch_items_fall_back_through_the_budget(root, stamp):
    one_file_root(root, stamp)
    client = NoneBatch(script=always_good, tokens=100)
    assert run_cli(root, client, "--max-usd", "5", "--batch") == 0
    assert len(client.create_calls) == 1  # budgeted sync fallback
    manifest = json.loads((root / "findings" / "raw" / "r1" / "manifest.json").read_text())
    assert manifest["committed_usd"] > manifest["estimate"]["worst_case_usd"]


def test_failed_batch_items_without_budget_are_failed_not_sent(root, stamp):
    one_file_root(root, stamp)
    client = NoneBatch(script=always_good, tokens=100)
    # batch estimate ~= 0.0206; full-price fallback would push the commitment over 0.03
    assert run_cli(root, client, "--max-usd", "0.03", "--batch") == 0
    assert client.create_calls == []
    rejected = read_jsonl(root / "findings" / "raw" / "r1" / "rejected.jsonl")
    assert "batch" in rejected[0]["reason"] and cache_files(root) == []


def test_missing_batch_result_is_treated_like_a_failed_one(root, stamp):
    one_file_root(root, stamp)
    class Missing(FakeClient):
        def batch_results(self, batch_id):
            return {}
    client = Missing(script=always_good, tokens=100)
    assert run_cli(root, client, "--max-usd", "0.03", "--batch") == 0
    assert client.create_calls == []


def test_retries_accumulate_in_the_ledger(root, stamp):
    one_file_root(root, stamp)
    client = FakeClient(script=lambda i, m: response([bad_finding(m)]), tokens=100)
    # per-call worst case ~= 0.0412: attempt 0 + one retry fit under 0.09, the second retry does not
    assert run_cli(root, client, "--max-usd", "0.09") == 0
    assert len(client.create_calls) == 2
    manifest = json.loads((root / "findings" / "raw" / "r1" / "manifest.json").read_text())
    assert 0.08 < manifest["committed_usd"] <= 0.09


def test_cache_key_covers_schema_prompt_and_max_tokens(root, stamp):
    one_file_root(root, stamp)
    run_cli(root, FakeClient(script=always_good), "--max-usd", "5", run_id="a")
    other = FakeClient(script=always_good)
    run_cli(root, other, "--max-usd", "5", "--max-tokens", "2048", run_id="b")
    assert len(other.create_calls) == 1  # different max_tokens => cache miss


def test_cache_hit_is_revalidated_and_ungrounded_recomputed(root, stamp):
    one_file_root(root, stamp)
    run_cli(root, FakeClient(script=lambda i, m: response([good(m, claim="Plain claim")])), "--max-usd", "5", run_id="a")
    (path,) = cache_files(root)
    entry = json.loads(path.read_text())
    entry["findings"][0]["claim"] = "Now it uses AT+QPOWD"
    entry["findings"][0]["ungrounded"] = []  # tampered flag must be recomputed, not trusted
    path.write_text(json.dumps(entry))
    second = FakeClient(script=always_good)
    run_cli(root, second, "--max-usd", "5", run_id="b")
    assert second.create_calls == []
    row = read_jsonl(root / "findings" / "raw" / "b" / "findings.jsonl")[0]
    assert row["ungrounded"] and "AT+QPOWD" in row["ungrounded"][0]


@pytest.mark.parametrize("garbage", ['{"findings": "x"}', "[]", '{"findings": [{"claim": 1}]}', "{not json",
                                     '{"findings": [{"claim":"c","category":"other","confidence":"low","evidence":[{"file":"nope","line":1,"excerpt":"zzzzzzzzzz"}]}]}'])
def test_malformed_or_stale_cache_entries_are_misses(root, stamp, garbage):
    one_file_root(root, stamp)
    run_cli(root, FakeClient(script=always_good), "--max-usd", "5", run_id="a")
    (path,) = cache_files(root)
    path.write_text(garbage)
    again = FakeClient(script=always_good)
    assert run_cli(root, again, "--max-usd", "5", run_id="b") == 0
    assert len(again.create_calls) == 1


def test_sent_bytes_are_the_hashed_bytes(root, stamp):
    one_file_root(root, stamp)
    path = root / "harvest" / "redacted" / "etc" / "init.d" / "modem"
    path.write_bytes(b"start() {\n  echo caf\xc3\xa9 \xff\n}\n")
    stamp(root)
    client = FakeClient(script=always_good)
    run_cli(root, client, "--max-usd", "5")
    manifest = json.loads((root / "findings" / "raw" / "r1" / "manifest.json").read_text())
    import hashlib
    assert manifest["inputs"]["files"][0]["sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
    sent = client.create_calls[0][2][0]["content"]
    assert "caf\u00e9" in sent and "\ufffd" in sent


def test_file_changed_after_preflight_is_refused(root, stamp, monkeypatch):
    one_file_root(root, stamp)
    path = root / "harvest" / "redacted" / "etc" / "init.d" / "modem"
    path.write_text("start() {\n  echo swapped-after-preflight\n}\n")
    client = FakeClient(script=always_good)
    assert run_cli(root, client, "--max-usd", "5") == 2
    assert client.count_calls == []


def test_binary_files_are_never_sent(root, stamp):
    one_file_root(root, stamp)
    red = root / "harvest" / "redacted"
    (red / "blob.bin").write_bytes(b"AT+EVIL\x00\x01\x02")
    (red / "sys").mkdir()
    (red / "sys" / "board.dtb").write_text("looks like text AT+DTB")
    stamp(root)
    client = FakeClient(script=always_good)
    assert run_cli(root, client, "--max-usd", "5") == 0
    sent = json.dumps([c[2] for c in client.create_calls] + [c[2] for c in client.count_calls])
    assert "blob.bin" not in sent and "board.dtb" not in sent and "AT+EVIL" not in sent
    manifest = json.loads((root / "findings" / "raw" / "r1" / "manifest.json").read_text())
    assert {s["name"] for s in manifest["skipped"]} == {"redacted/blob.bin", "redacted/sys/board.dtb"}


def test_har_content_is_not_ground_truth(root, stamp):
    one_file_root(root, stamp, text="echo 'AT+CFUN=1'\n")
    (root / "harvest" / "redacted" / "capture.har").write_text('{"log": "AT+EVIL via GPIO 77"}\n')
    stamp(root)
    client = FakeClient(script=lambda i, m: response([good(m, claim="Uses AT+EVIL")]) if "modem" in m[0]["content"]
                        else response([]))
    run_cli(root, client, "--max-usd", "5")
    row = read_jsonl(root / "findings" / "raw" / "r1" / "findings.jsonl")[0]
    assert row["ungrounded"] and "AT+EVIL" in row["ungrounded"][0]


def test_unpacked_text_is_redacted_in_memory_before_sending(root, stamp):
    (root / "unpacked" / "usr" / "bin").mkdir(parents=True)
    secret = "Zq8xL" + "m2vTnPw"
    (root / "unpacked" / "usr" / "bin" / "setup.sh").write_text(f"echo start\nexport ap_password={secret}\n")
    stamp(root)
    client = FakeClient(script=always_good)
    assert run_cli(root, client, "--max-usd", "5") == 0
    everything = json.dumps([c[2] for c in client.create_calls] + [c[2] for c in client.count_calls])
    assert secret not in everything and "REDACTED" in everything
    for p in root.rglob("*"):
        if p.is_file() and "unpacked" not in p.parts:
            assert secret not in p.read_text(errors="ignore")


# ---- resume ----

class Gate(FakeClient):
    """Batch that only finishes once `done` is set; counts creates."""
    done = False
    batch_creates = 0

    def batch_create(self, model, items, max_tokens):
        Gate.batch_creates += 1
        return super().batch_create(model, items, max_tokens)

    def batch_status(self, batch_id):
        return "ended" if self.done else "in_progress"


def _cfg(root, **kw):
    from recon import runner
    return runner.RunConfig(root=root, inputs=(root / "harvest" / "redacted", root / "unpacked"), run_id="t",
                            model=cost.DEFAULT_MODEL, max_usd=5, batch=True, batch_poll_seconds=1,
                            batch_timeout_seconds=2, allow_extra=("**",), no_canary=True, **kw)


def test_resume_polls_existing_batch_without_creating_a_new_one(stamped):
    from recon import runner
    Gate.batch_creates = 0
    client = Gate(script=always_good)
    with pytest.raises(runner.RunFailed, match="timed out"):
        runner.run(_cfg(stamped), lambda: client, out=lambda _l: None, sleep=lambda _s: None)
    first = json.loads((stamped / "findings" / "raw" / "t" / "manifest.json").read_text())
    assert first["batch_id"] == "b1" and first["status"] == "batch-pending" and Gate.batch_creates == 1
    client.done = True
    res = runner.run(_cfg(stamped, resume_batch_id="b1"), lambda: client, out=lambda _l: None, sleep=lambda _s: None)
    assert Gate.batch_creates == 1 and client.create_calls == []
    assert res.status == "ok" and res.accepted == 6
    final = json.loads((stamped / "findings" / "raw" / "t" / "manifest.json").read_text())
    assert final["batch_id"] == "b1" and final["committed_usd"] >= first["committed_usd"]


def test_resume_results_use_normal_validation_and_budget(root, stamp):
    from recon import runner
    one_file_root(root, stamp)
    client = Gate(script=lambda i, m: response([bad_finding(m)]), tokens=100)
    with pytest.raises(runner.RunFailed):
        runner.run(_cfg(root), lambda: client, out=lambda _l: None, sleep=lambda _s: None)
    client.done = True
    res = runner.run(_cfg(root, resume_batch_id="b1"), lambda: client, out=lambda _l: None, sleep=lambda _s: None)
    assert res.rejected >= 1 and len(client.create_calls) == 2  # bad batch result -> 2 budgeted sync retries


def test_resume_refused_for_wrong_batch_or_missing_run(stamped):
    from recon import runner
    client = Gate(script=always_good)
    with pytest.raises(runner.RunRefused, match="nothing to resume"):
        runner.run(_cfg(stamped, resume_batch_id="b1"), lambda: client, out=lambda _l: None)
    with pytest.raises(runner.RunFailed):
        runner.run(_cfg(stamped), lambda: client, out=lambda _l: None, sleep=lambda _s: None)
    with pytest.raises(runner.RunRefused, match="does not match"):
        runner.run(_cfg(stamped, resume_batch_id="other"), lambda: client, out=lambda _l: None)


def test_existing_run_dir_with_batch_hints_resume(stamped, capsys):
    from recon import runner
    client = Gate(script=always_good)
    with pytest.raises(runner.RunFailed):
        runner.run(_cfg(stamped), lambda: client, out=lambda _l: None, sleep=lambda _s: None)
    with pytest.raises(runner.RunRefused, match="--resume-batch b1"):
        runner.run(_cfg(stamped), lambda: client, out=lambda _l: None)


def test_cli_resume_flag_implies_batch(stamped):
    args = cli.build_parser().parse_args(["--run-id", "x", "--resume-batch", "msgbatch_1"])
    assert args.resume_batch == "msgbatch_1"
    assert cli._config(args).batch is True and cli._config(args).resume_batch_id == "msgbatch_1"
    args = cli.build_parser().parse_args(["--run-id", "x", "--batch-timeout", "30", "--batch-poll", "2"])
    cfg = cli._config(args)
    assert cfg.batch_timeout_seconds == 30 and cfg.batch_poll_seconds == 2


# ================= PR1 final review =================

def _fail_first(root):
    from recon import runner
    client = Gate(script=always_good)
    Gate.done = False
    with pytest.raises(runner.RunFailed):
        runner.run(_cfg(root), lambda: client, out=lambda _l: None, sleep=lambda _s: None)
    client.done = True
    return client


def _resume(root, client, **kw):
    from recon import runner
    return runner.run(_cfg(root, resume_batch_id="b1", **kw), lambda: client, out=lambda _l: None,
                      sleep=lambda _s: None)


def _manifest(root, run_id="t"):
    return json.loads((root / "findings" / "raw" / run_id / "manifest.json").read_text())


def test_resume_refused_unless_prior_status_is_batch_pending(stamped):
    from recon import runner
    client = _fail_first(stamped)
    assert _resume(stamped, client).status == "ok"  # now the manifest says "ok"
    with pytest.raises(runner.RunRefused, match="batch-pending"):
        _resume(stamped, client)


def test_resume_refused_if_inputs_changed(stamped, stamp):
    from recon import runner
    client = _fail_first(stamped)
    (stamped / "harvest" / "redacted" / "etc" / "config" / "network").write_text("changed after the batch\n")
    stamp(stamped)
    with pytest.raises(runner.RunRefused, match="input"):
        _resume(stamped, client)


def test_resume_refused_if_model_or_max_tokens_differ(stamped):
    from recon import runner
    client = _fail_first(stamped)
    with pytest.raises(runner.RunRefused, match="model"):
        runner.run(replace(_cfg(stamped, resume_batch_id="b1"), model=cost.DEFAULT_MODEL_CHEAP), lambda: client,
                   out=lambda _l: None, sleep=lambda _s: None)
    with pytest.raises(runner.RunRefused, match="max_tokens"):
        _resume(stamped, client, max_tokens=2048)
    assert _manifest(stamped)["max_tokens"] == 4096


def test_excluded_files_are_never_sent_and_listed_as_skipped(root, stamp):
    one_file_root(root, stamp)
    up = root / "unpacked"
    (up / "etc" / "dropbear").mkdir(parents=True)
    (up / "etc" / "shadow").write_text("root:x:0:0\n")
    (up / "etc" / "dropbear" / "dropbear_ed25519_host_key").write_text("hostkeymaterial\n")
    (up / "etc" / "tls.pem").write_text("pemmaterialhere\n")
    (up / "etc" / "serial_number").write_text("SN1234567890\n")
    red = root / "harvest" / "redacted" / "etc"
    (red / "other.key").write_text("keymaterialhere\n")
    stamp(root)
    client = FakeClient(script=always_good)
    assert run_cli(root, client, "--max-usd", "5") == 0
    sent = json.dumps([c[2] for c in client.create_calls] + [c[2] for c in client.count_calls])
    for leak in ("root:x:0:0", "hostkeymaterial", "pemmaterialhere", "SN1234567890", "keymaterialhere"):
        assert leak not in sent
    skipped = {s["name"]: s["reason"] for s in _manifest(root, "r1")["skipped"]}
    assert {"unpacked/etc/shadow", "unpacked/etc/dropbear/dropbear_ed25519_host_key", "unpacked/etc/tls.pem",
            "unpacked/etc/serial_number", "redacted/etc/other.key"} <= set(skipped)
    assert set(skipped.values()) == {"excluded"}


def test_failed_resume_does_not_clobber_existing_outputs(stamped):
    from recon import runner
    client = _fail_first(stamped)
    run_dir = stamped / "findings" / "raw" / "t"
    (run_dir / "findings.jsonl").write_text('{"kept": 1}\n')
    (run_dir / "rejected.jsonl").write_text('{"kept": 2}\n')
    client.done = False
    with pytest.raises(runner.RunFailed):
        _resume(stamped, client)
    assert (run_dir / "findings.jsonl").read_text() == '{"kept": 1}\n'
    assert (run_dir / "rejected.jsonl").read_text() == '{"kept": 2}\n'
    assert _manifest(stamped)["status"] == "batch-pending"


def test_manifest_actual_covers_this_invocation_only(stamped):
    from recon import runner
    client = _fail_first(stamped)
    _resume(stamped, client)
    assert _manifest(stamped)["actual"]["covers"] == "this invocation only"


def test_resume_keeps_prior_sync_spend_in_committed_usd(root, stamp):
    """Pins max(est.usd, prior committed): a first run that already spent sync retries must not be forgotten."""
    from recon import runner
    one_file_root(root, stamp)
    state = {"fail": True}

    def script(i, messages):
        if "rejected findings" in messages[0]["content"] and state["fail"]:
            return RuntimeError("network down")
        return response([bad_finding(messages)])
    client = Gate(script=script, tokens=100)
    Gate.done = False
    client.done = True  # batch ends at once; the first run dies on its first sync retry
    with pytest.raises(runner.RunFailed):
        runner.run(_cfg(root), lambda: client, out=lambda _l: None, sleep=lambda _s: None)
    prior = _manifest(root)
    extra = prior["committed_usd"] - prior["estimate"]["worst_case_usd"]
    assert extra > 0 and prior["status"] == "batch-pending"
    state["fail"] = False
    _resume(root, client)
    final = _manifest(root)
    assert final["committed_usd"] >= prior["committed_usd"] + 1.9 * extra


def test_symlinked_denied_file_is_never_sent_under_an_allowed_name(root, stamp):
    red = root / "harvest" / "redacted"
    (red / "etc" / "config").mkdir(parents=True)
    (red / "etc" / "init.d").mkdir(parents=True)
    (red / "etc" / "config" / "wireless").write_text("option key 'WIRELESS-MARK'\n")
    (red / "etc" / "init.d" / "real").write_text("start() {\n  echo real-start\n}\n")
    os.symlink("../config/wireless", red / "etc" / "init.d" / "gl_cloud")
    stamp(root)
    client = FakeClient(script=always_good)
    argv = ["--root", str(root), "--run-id", "r1", "--no-canary", "--max-usd", "5"]
    assert cli.main(argv, client_factory=lambda: client) == 0
    sent = json.dumps([c[2] for c in client.create_calls] + [c[2] for c in client.count_calls])
    assert "real-start" in sent and "WIRELESS-MARK" not in sent
    skipped = {s["name"]: s["reason"] for s in _manifest(root, "r1")["skipped"]}
    assert skipped == {"redacted/etc/init.d/gl_cloud": "symlink"}


def test_hardlinked_input_refuses_the_run(root, stamp, capsys):
    red = root / "harvest" / "redacted"
    (red / "etc" / "init.d").mkdir(parents=True)
    (red / "etc" / "init.d" / "a").write_text("x\n")
    os.link(red / "etc" / "init.d" / "a", red / "etc" / "init.d" / "b")
    client = FakeClient(script=always_good)
    argv = ["--root", str(root), "--run-id", "r1", "--no-canary"]
    assert cli.main(argv, client_factory=lambda: client) == 2
    assert "hardlink" in capsys.readouterr().err and client.count_calls == []
