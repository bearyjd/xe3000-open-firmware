import hashlib

import pytest

from recon import chunking, groundtruth, schema

FILE = "redacted/etc/init.d/modem"
TEXT = "start() {\n  echo 'AT+CFUN=1'   >   /dev/ttyUSB2\n  insmod mhi_wwan_ctrl\n}\n"


@pytest.fixture
def chunk():
    return chunking.chunk_files([(FILE, TEXT)])[0]


@pytest.fixture
def truth():
    return groundtruth.extract({FILE: TEXT})


def _f(claim="Powers modem with AT+CFUN", line=2, excerpt="echo 'AT+CFUN=1' > /dev/ttyUSB2", file=FILE, **kw):
    d = {"claim": claim, "category": "modem-power", "confidence": "high",
         "evidence": [{"file": file, "line": line, "excerpt": excerpt}]}
    d.update(kw)
    return d


def _walk(node):
    yield node
    for v in node.values() if isinstance(node, dict) else (node if isinstance(node, list) else ()):
        if isinstance(v, (dict, list)):
            yield from _walk(v)


def test_schema_is_strict_and_has_no_forbidden_keywords():
    banned = {"minLength", "maxLength", "minimum", "maximum", "pattern", "minItems", "maxItems", "format"}
    for node in _walk(schema.FINDING_SCHEMA):
        if isinstance(node, dict):
            assert not banned & set(node)
            if node.get("type") == "object":
                assert node["additionalProperties"] is False
    assert set(schema.CATEGORIES) >= {"at-command", "rpc-method", "gpio", "modem-power", "other"}


def test_accepts_valid_and_computes_hash_server_side(chunk, truth):
    res = schema.validate_response({"findings": [_f()]}, chunk, truth)
    assert not res.rejected and len(res.accepted) == 1
    ev = res.accepted[0]["evidence"][0]
    assert ev["excerpt_sha256"] == hashlib.sha256(b"echo 'AT+CFUN=1' > /dev/ttyUSB2").hexdigest()
    assert res.accepted[0]["ungrounded"] == []


def test_model_supplied_hash_is_ignored_and_extra_keys_rejected(chunk, truth):
    bad = _f()
    bad["evidence"][0]["excerpt_sha256"] = "deadbeef"
    res = schema.validate_response({"findings": [bad]}, chunk, truth)
    assert res.accepted == () and "schema" in res.rejected[0]["reason"]


def test_rejects_missing_evidence(chunk, truth):
    f = _f()
    f["evidence"] = []
    res = schema.validate_response({"findings": [f]}, chunk, truth)
    assert res.accepted == () and "evidence" in res.rejected[0]["reason"]


def test_rejects_wrong_file(chunk, truth):
    res = schema.validate_response({"findings": [_f(file="redacted/etc/other")]}, chunk, truth)
    assert "not in this chunk" in res.rejected[0]["reason"]


def test_rejects_bad_excerpt_and_far_line(chunk, truth):
    res = schema.validate_response({"findings": [_f(excerpt="rm -rf /")]}, chunk, truth)
    assert "excerpt" in res.rejected[0]["reason"]
    res = schema.validate_response({"findings": [_f(line=1, excerpt="insmod mhi_wwan_ctrl")]}, chunk, truth)
    assert res.accepted  # within +/-2 lines
    long_text = "x\n" * 10 + "echo hi\n"
    c2 = chunking.chunk_files([(FILE, long_text)])[0]
    res = schema.validate_response({"findings": [_f(line=1, excerpt="echo hi")]}, c2, truth)
    assert "excerpt" in res.rejected[0]["reason"]


def test_whitespace_normalized_match(chunk, truth):
    res = schema.validate_response({"findings": [_f(excerpt="echo   'AT+CFUN=1'\t>  /dev/ttyUSB2")]}, chunk, truth)
    assert res.accepted


def test_ungrounded_flagged_not_dropped(chunk, truth):
    res = schema.validate_response({"findings": [_f(claim="Uses AT+QPOWD to power off")]}, chunk, truth)
    assert not res.rejected and res.accepted[0]["ungrounded"]
    assert "AT+QPOWD" in res.accepted[0]["ungrounded"][0]


def test_invalid_structure_rejected_whole(chunk, truth):
    for payload in ({"nope": []}, {"findings": [{"claim": "x"}]}, [], {"findings": [_f(category="bogus")]}):
        res = schema.validate_response(payload, chunk, truth)
        assert res.accepted == () and res.rejected and "schema" in res.rejected[0]["reason"]


def test_partial_acceptance(chunk, truth):
    res = schema.validate_response({"findings": [_f(), _f(excerpt="nonsense")]}, chunk, truth)
    assert len(res.accepted) == 1 and len(res.rejected) == 1


def test_short_excerpt_rejected(chunk, truth):
    res = schema.validate_response({"findings": [_f(line=3, excerpt="}")]}, chunk, truth)
    assert "short" in res.rejected[0]["reason"]
    res = schema.validate_response({"findings": [_f(line=3, excerpt=" in sm ")]}, chunk, truth)
    assert "short" in res.rejected[0]["reason"]
