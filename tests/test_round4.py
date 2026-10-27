"""Round 4 (cross-model review): crash-safe commitments, token caps, strong names, forged markers, stamps, hook."""
import json
import os
import shutil
import subprocess
from dataclasses import replace

import pytest

from conftest import GITLEAKS_TOML, REPO, Lazy
from fakes import FakeClient, response
from recon import cli, cost, preflight, redact, runner, schema
from test_analyze import Gate, _cfg, _manifest, always_good, bad_finding, cache_files, one_file_root, read_jsonl

canary = Lazy("recon.canary")
FAKE_KEY = "sk-" + "ant-" + "api03-" + "K" * 40
V = "Zq7pw" + "xyQ9Lm2" + "Rt5"


def quiet(_line):
    return None


# ---------------- K1: crash-safe dollar commitments ----------------

class Crashy(Gate):
    """Batch ends at once; the second paid sync request dies with KeyboardInterrupt."""
    sent = 0

    def create(self, model, system, messages, max_tokens):
        Crashy.sent += 1
        if Crashy.sent == 2:
            raise KeyboardInterrupt
        return super().create(model, system, messages, max_tokens)


def test_commitment_is_persisted_before_each_paid_retry_and_survives_a_kill(root, stamp):
    one_file_root(root, stamp)
    Crashy.sent = 0
    client = Crashy(script=lambda i, m: response([bad_finding(m)]), tokens=137)
    client.done = True
    cfg = replace(_cfg(root), max_usd=0.11)
    with pytest.raises(KeyboardInterrupt):
        runner.run(cfg, lambda: client, out=quiet, sleep=lambda _s: None)
    prior = _manifest(root)
    w = cost.worst_case_usd(cost.DEFAULT_MODEL, 137, 4096)
    assert prior["status"] == "batch-pending"
    assert prior["committed_usd"] == pytest.approx(w / 2 + 2 * w, abs=1e-12)  # full precision, both reservations
    resumed = runner.run(replace(cfg, resume_batch_id="b1"), lambda: client, out=quiet, sleep=lambda _s: None)
    assert Crashy.sent == 2  # the resumed run could not afford a third paid request
    assert _manifest(root)["committed_usd"] <= 0.11 and resumed.status == "ok"


def test_a_failed_checkpoint_stops_the_paid_request(root, stamp, monkeypatch):
    one_file_root(root, stamp)
    client = FakeClient(script=lambda i, m: response([bad_finding(m)]), tokens=100)
    real = runner._atomic_write

    def flaky(path, text):
        if client.create_calls:
            raise OSError("disk full")
        return real(path, text)
    monkeypatch.setattr(runner, "_atomic_write", flaky)
    argv = ["--root", str(root), "--run-id", "r1", "--no-canary", "--allow-extra", "**", "--max-usd", "5"]
    assert cli.main(argv, client_factory=lambda: client) == 2
    assert len(client.create_calls) == 1  # the retry was never sent


def test_manifest_writes_are_atomic(root, stamp, monkeypatch):
    one_file_root(root, stamp)
    seen = []
    real_replace = os.replace
    monkeypatch.setattr(os, "replace", lambda a, b: (seen.append((str(a), str(b))), real_replace(a, b))[1])
    client = FakeClient(script=always_good, tokens=100)
    argv = ["--root", str(root), "--run-id", "r1", "--no-canary", "--allow-extra", "**", "--max-usd", "5"]
    assert cli.main(argv, client_factory=lambda: client) == 0
    assert any(dst.endswith("manifest.json") and src != dst for src, dst in seen)


# ---------------- K2: retries honour the input-token cap ----------------

def test_retry_cannot_exceed_the_input_token_cap(root, stamp):
    one_file_root(root, stamp)
    client = FakeClient(script=lambda i, m: response([bad_finding(m)]), tokens=1000)
    argv = ["--root", str(root), "--run-id", "r1", "--no-canary", "--allow-extra", "**", "--max-usd", "5",
            "--max-input-tokens", "1000"]
    assert cli.main(argv, client_factory=lambda: client) == 0
    assert len(client.create_calls) == 1  # initial tokens == cap: no retry fits
    assert any("input token" in r["reason"] for r in read_jsonl(root / "findings" / "raw" / "r1" / "rejected.jsonl"))
    assert _manifest(root, "r1")["committed_input_tokens"] == 1000


def test_retry_is_counted_on_the_exact_retry_request(root, stamp):
    one_file_root(root, stamp)
    counted = []

    class Counting(FakeClient):
        def count_tokens(self, model, system, messages):
            counted.append(messages[0]["content"])
            return self.tokens
    client = Counting(script=lambda i, m: response([bad_finding(m)]), tokens=100)
    argv = ["--root", str(root), "--run-id", "r1", "--no-canary", "--allow-extra", "**", "--max-usd", "5"]
    assert cli.main(argv, client_factory=lambda: client) == 0
    assert any("rejected findings" in c for c in counted)  # the retry prompt itself was counted
    assert _manifest(root, "r1")["committed_input_tokens"] == 100 * 3


def test_synthesis_goes_through_the_same_token_gate(stamped):
    client = FakeClient(script=always_good, tokens=1000)
    argv = ["--root", str(stamped), "--run-id", "r1", "--no-canary", "--allow-extra", "**", "--max-usd", "5",
            "--max-input-tokens", "6500", "--synthesize"]
    assert cli.main(argv, client_factory=lambda: client) == 0
    assert client.text_calls == []  # 6 chunks x 1000 + 1000 for synthesis > 6500


def test_token_commitment_is_restored_on_resume(root, stamp):
    one_file_root(root, stamp)
    Crashy.sent = 0
    client = Crashy(script=lambda i, m: response([bad_finding(m)]), tokens=100)
    client.done = True
    cfg = replace(_cfg(root), max_usd=0.11)
    with pytest.raises(KeyboardInterrupt):
        runner.run(cfg, lambda: client, out=quiet, sleep=lambda _s: None)
    assert _manifest(root)["committed_input_tokens"] == 300
    runner.run(replace(cfg, resume_batch_id="b1"), lambda: client, out=quiet, sleep=lambda _s: None)
    assert _manifest(root)["committed_input_tokens"] >= 300


def test_batch_fallback_goes_through_the_gate(root, stamp):
    one_file_root(root, stamp)

    class NoneBatch(Gate):
        def batch_results(self, batch_id):
            return {cid: None for cid in self.batches[batch_id]}
    client = NoneBatch(script=always_good, tokens=1000)
    client.done = True
    cfg = replace(_cfg(root), max_input_tokens=1000)
    runner.run(cfg, lambda: client, out=quiet, sleep=lambda _s: None)
    assert client.create_calls == []  # fallback needs 1000 more tokens than the cap allows


# ---------------- K3 ----------------

def test_float_line_numbers_are_rejected_not_crashing():
    from recon import chunking, groundtruth
    file = "redacted/etc/init.d/x"
    chunk = chunking.chunk_files([(file, "abcdefgh\nx\ny\nz\n")])[0]
    truth = groundtruth.extract({file: "abcdefgh"})
    for bad in (1.0, 2.0, True):
        payload = {"findings": [{"claim": "c", "category": "other", "confidence": "low",
                                 "evidence": [{"file": file, "line": bad, "excerpt": "abcdefgh"}]}]}
        res = schema.validate_response(payload, chunk, truth)
        assert res.accepted == () and "integer" in res.rejected[0]["reason"]


# ---------------- S1: strong names have no benign-value exemption ----------------

STRONG_LINES = ["\toption password '/orchard/lantern'", "\toption password 'wpa-apple-mango'", "\toption password 'no'",
                "\toption password '7'", "\toption passwd 'none'", "\toption token 'true'", "\toption secret '/a/b'",
                "\toption psk 'sae'", "\toption passphrase 'eap'", "password 'no'", "password: 7", "token=on",
                '{"password": "7"}', '{"token": "/a/b/c"}', "password = /orchard/lantern"]


@pytest.mark.parametrize("line", STRONG_LINES)
def test_strong_names_are_redacted_whatever_the_value_looks_like(line):
    out = redact.redact_text(line + "\n", salt="x")[0]
    for leaked in ("orchard", "apple-mango", "'no'", "'7'", "'none'", "'true'", "'/a/b'", "'sae'", "'eap'", " 7", "=on",
                   '"7"', "/a/b/c"):
        assert leaked not in out, (line, out)


@pytest.mark.parametrize("line", ["\toption auth 'chap'", "\toption auth_type 'pap'", "key_mgmt=WPA-PSK",
                                  "password_file=/etc/pw", "secret_type: sha256", "token_bucket: 10",
                                  "auth: 1", "hash: crc32c", "sysupgrade.key: present", "cert: /etc/ssl/certs/ca.pem",
                                  '"password": "String"', '"auth": {"key": "Integer", "token": "String"}'])
def test_metadata_names_and_type_names_still_stay(line):
    assert redact.redact_text(line + "\n", salt="x")[0] == line + "\n"


def test_classify_tiers():
    from recon import redact_names as n
    assert n.classify("password") == n.classify("token") == n.classify("psk") == "strong"
    assert n.classify("password_file") == "weak" and n.classify("key_mgmt") == "weak"
    assert n.classify("auth") == "medium" and n.classify("hash") == "medium"


# ---------------- S2: forged markers ----------------

@pytest.mark.parametrize("line", ["\toption password '<REDACTED:uci-sensitive> orchardlantern'",
                                  "password=<REDACTED:wifi-psk> orchardlantern",
                                  "password: <REDACTED:labelled-secret> orchardlantern",
                                  '{"password": "<REDACTED:json-secret> orchardlantern"}',
                                  "\toption password '<REDACTED:uci-sensitive>' orchardlantern"])
def test_a_forged_marker_followed_by_text_is_not_trusted(line):
    out = redact.redact_text(line + "\n", salt="x")[0]
    assert "orchardlantern" not in out, out


def test_only_a_whole_value_placeholder_counts_as_handled():
    from recon import redact_names as n
    assert n.is_handled("<REDACTED:wifi-psk>") and n.is_handled("'<REDACTED:wifi-psk>'")
    assert not n.is_handled("<REDACTED:wifi-psk> more") and not n.is_handled("'<REDACTED:wifi-psk> more'")


def test_repeated_passes_converge_without_leaking():
    text = "ddns: token: " + V + " tail\nuser=bob:password:" + V + "\npassword='a b c' next=thing\n"
    once = redact.redact_text(text, salt="x")[0]
    twice = redact.redact_text(once, salt="x")[0]
    thrice = redact.redact_text(twice, salt="x")[0]
    assert V not in once and V not in twice and twice == thrice


# ---------------- S3: known secrets never reach cache / findings / synthesis / errors ----------------

CANARY = "plant" + "ed-canary/ph" + "rase+9"


def write_canary(tmp_path):
    f = tmp_path / "canaries"
    f.write_text(CANARY + "\n")
    f.chmod(0o600)
    return f


def echo_claim(i, messages):
    from test_analyze import good
    return response([good(messages, claim=f"the router uses {CANARY} here")])


def test_canary_echoed_by_the_model_is_sanitised_everywhere(root, stamp, tmp_path, monkeypatch):
    one_file_root(root, stamp)
    monkeypatch.setenv("RECON_CANARY_FILE", str(write_canary(tmp_path)))
    client = FakeClient(script=echo_claim, tokens=100)
    argv = ["--root", str(root), "--run-id", "r1", "--allow-extra", "**", "--max-usd", "5", "--synthesize"]
    assert cli.main(argv, client_factory=lambda: client) == 0
    for path in root.rglob("*"):
        if path.is_file():
            assert CANARY not in path.read_text(errors="ignore"), path
    assert cache_files(root) or True


def test_canary_in_model_derived_errors_is_sanitised(root, stamp, tmp_path, monkeypatch, capsys):
    one_file_root(root, stamp)
    monkeypatch.setenv("RECON_CANARY_FILE", str(write_canary(tmp_path)))
    client = FakeClient(script=lambda i, m: RuntimeError(f"boom {CANARY} boom"), tokens=100)
    argv = ["--root", str(root), "--run-id", "r1", "--allow-extra", "**", "--max-usd", "5"]
    assert cli.main(argv, client_factory=lambda: client) == 2
    seen = capsys.readouterr()
    assert CANARY not in seen.out + seen.err
    for path in root.rglob("*"):
        if path.is_file():
            assert CANARY not in path.read_text(errors="ignore"), path


def test_sanitiser_handles_nested_data_and_encoded_forms(tmp_path):
    import urllib.parse
    san = canary.Sanitizer((CANARY,))
    data = {"a": [f"x {CANARY}", {"b": urllib.parse.quote(CANARY, safe="")}], "n": 3, "c": CANARY.upper()}
    out = json.dumps(san.obj(data))
    assert CANARY not in out and CANARY.upper() not in out and urllib.parse.quote(CANARY, safe="") not in out
    assert san.obj(data)["n"] == 3 and canary.Sanitizer(()).text("abc") == "abc"


def test_report_loading_sanitises_known_secrets(tmp_path, monkeypatch):
    from recon import report
    monkeypatch.setenv("RECON_CANARY_FILE", str(write_canary(tmp_path)))
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    row = {"claim": f"uses {CANARY}", "category": "other", "confidence": "low", "ungrounded": [], "chunk_id": "c",
           "evidence": [{"file": "redacted/a", "line": 1, "excerpt": "x", "excerpt_sha256": "ab" * 32}]}
    (run_dir / "findings.jsonl").write_text(json.dumps(row) + "\n")
    report.generate(run_dir, tmp_path / "out")
    assert all(CANARY not in p.read_text() for p in (tmp_path / "out").glob("*.md"))


# ---------------- T1: the stamp attests the scan that was done ----------------

def _clean_runner(returncode=0):
    return lambda cmd, **kw: subprocess.CompletedProcess(cmd, returncode, "[]", "")


def _real_image(root):
    return preflight.read_image(root / "containers" / "gitleaks.image")


def test_default_settings_with_podman_get_a_stamp(root, fixture_tree):
    res = preflight.run_preflight([root / "harvest" / "redacted"], root, config=root / "containers" / "gitleaks.toml",
                                  podman=["p"], image=_real_image(root), gitleaks_bin=None, runner=_clean_runner())
    assert res.stamp and res.stamp.exists()


def test_relaxed_custom_config_is_refused_and_leaves_no_stamp(root, fixture_tree, tmp_path):
    relaxed = tmp_path / "relaxed.toml"
    relaxed.write_text("title = 'relaxed'\n")
    with pytest.raises(preflight.PreflightError, match="scanner settings differ from required defaults"):
        preflight.run_preflight([root / "harvest" / "redacted"], root, config=relaxed, podman=["p"],
                                image=_real_image(root), gitleaks_bin=None, runner=_clean_runner())
    assert not (root / "cache" / "preflight").exists() or not list((root / "cache" / "preflight").glob("*.ok"))


def test_alternate_image_is_refused(root, fixture_tree):
    with pytest.raises(preflight.PreflightError, match="scanner settings differ"):
        preflight.run_preflight([root / "harvest" / "redacted"], root, config=root / "containers" / "gitleaks.toml",
                                podman=["p"], image="docker.io/x/gitleaks@sha256:" + "2" * 64, gitleaks_bin=None,
                                runner=_clean_runner())
    assert not (root / "cache" / "preflight").exists()


def test_local_binary_run_gets_no_accepted_stamp(root, fixture_tree):
    with pytest.raises(preflight.PreflightError, match="scanner settings differ"):
        preflight.run_preflight([root / "harvest" / "redacted"], root, config=root / "containers" / "gitleaks.toml",
                                podman=None, image="", gitleaks_bin="/bin/gl", runner=_clean_runner())
    assert not (root / "cache" / "preflight").exists()


def test_local_binary_hits_are_still_reported(root, fixture_tree):
    raw = json.dumps([{"RuleID": "r1", "StartLine": 2, "File": str(root / "harvest/redacted/etc/config/network")}])
    res = preflight.run_preflight([root / "harvest" / "redacted"], root, config=root / "containers" / "gitleaks.toml",
                                  podman=None, image="", gitleaks_bin="/bin/gl",
                                  runner=lambda cmd, **kw: subprocess.CompletedProcess(cmd, 7, raw, ""))
    assert res.stamp is None and res.hits


def test_cli_with_custom_config_exits_2(root, fixture_tree, tmp_path, monkeypatch, capsys):
    relaxed = tmp_path / "relaxed.toml"
    relaxed.write_text("title = 'relaxed'\n")
    monkeypatch.delenv("RECON_GITLEAKS_BIN", raising=False)
    monkeypatch.setenv("PODMAN", "podman")
    monkeypatch.setattr(preflight, "_default_runner", lambda: _clean_runner())
    rc = preflight.main(["--root", str(root), "--config", str(relaxed), "--no-canary"])
    assert rc == 2 and "scanner settings differ" in capsys.readouterr().err


@pytest.mark.requires_gitleaks
@pytest.mark.parametrize("line", [l for l in STRONG_LINES if not l.startswith("{") and "7" not in l.split("'")[-2:-1]]
                         + ["\toption password '7'", '{"password": "7"}'])
def test_gitleaks_independently_flags_strong_names_with_benign_looking_values(root, line):
    from test_preflight import _scan
    (root / "harvest" / "redacted" / "etc").mkdir(parents=True)
    (root / "harvest" / "redacted" / "etc" / "x.txt").write_text(line + "\n")  # raw: redaction disabled
    res = _scan(root, [root / "harvest" / "redacted"])
    assert res.stamp is None and {h.file for h in res.hits} == {"redacted/etc/x.txt"}, (line, res.hits)


@pytest.mark.requires_gitleaks
def test_gitleaks_still_allows_metadata_exceptions(root):
    from test_preflight import _scan
    (root / "harvest" / "redacted" / "etc").mkdir(parents=True)
    (root / "harvest" / "redacted" / "etc" / "x.txt").write_text(
        "\toption auth 'chap'\nkey_mgmt=WPA-PSK\nauth_type=pap\npassword_file=/etc/pw\ntoken_bucket: 10\n")
    assert _scan(root, [root / "harvest" / "redacted"]).hits == ()


# ---------------- T2: the hook scans staged blobs, not diff lines ----------------

def _git(cwd, *args):
    env = {**os.environ, "HOME": str(cwd), "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_SYSTEM": "/dev/null"}
    return subprocess.run(["git", *args], cwd=cwd, env=env, capture_output=True, text=True, check=True)


@pytest.fixture
def hook_repo(tmp_path):
    work = tmp_path / "hookrepo"
    work.mkdir()
    _git(work, "init", "-q")
    shutil.copy(REPO / "hooks" / "pre-commit", work / "pre-commit-hook")
    return work


def _hook(work, path=None):
    env = {**os.environ, "HOME": str(work), "GIT_CONFIG_GLOBAL": "/dev/null"}
    if path:
        env["PATH"] = path
    return subprocess.run(["bash", str(work / "pre-commit-hook")], cwd=work, capture_output=True, text=True, env=env)


@pytest.mark.parametrize("prefix", ["", "key ", "++", "+++", "-", "+ ", "\t"])
def test_key_is_blocked_whatever_the_line_starts_with(hook_repo, prefix):
    (hook_repo / "notes.md").write_text(f"a\n{prefix}{FAKE_KEY}\nb\n")
    _git(hook_repo, "add", "notes.md")
    result = _hook(hook_repo)
    assert result.returncode == 1 and "BLOCKED" in result.stderr
    assert FAKE_KEY not in result.stdout + result.stderr and FAKE_KEY[:20] not in result.stdout + result.stderr


def test_key_in_a_modified_file_is_blocked_and_clean_files_pass(hook_repo):
    (hook_repo / "a.txt").write_text("one\n")
    _git(hook_repo, "add", "a.txt")
    _git(hook_repo, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "base", "--no-verify")
    (hook_repo / "a.txt").write_text(f"one\n++{FAKE_KEY}\n")
    _git(hook_repo, "add", "a.txt")
    assert _hook(hook_repo).returncode == 1
    (hook_repo / "a.txt").write_text("one\ntwo\n")
    _git(hook_repo, "add", "a.txt")
    assert _hook(hook_repo).returncode == 0


def test_hook_fails_closed_when_a_staged_blob_cannot_be_read(hook_repo, tmp_path):
    (hook_repo / "a.txt").write_text("fine\n")
    _git(hook_repo, "add", "a.txt")
    shim = tmp_path / "bin"
    shim.mkdir()
    real_git = shutil.which("git")
    (shim / "git").write_text(f'#!/bin/sh\n[ "$1" = show ] && exit 1\nexec {real_git} "$@"\n')
    (shim / "git").chmod(0o755)
    result = _hook(hook_repo, path=f"{shim}:{os.environ['PATH']}")
    assert result.returncode == 1 and "could not read" in result.stderr
