from recon import cache


def test_key_depends_on_all_parts():
    base = cache.cache_key("chunk", "1", "m", "1")
    assert len(base) == 64
    assert base != cache.cache_key("chunk2", "1", "m", "1")
    assert base != cache.cache_key("chunk", "2", "m", "1")
    assert base != cache.cache_key("chunk", "1", "m2", "1")
    assert base != cache.cache_key("chunk", "1", "m", "2")


def test_roundtrip_and_miss(tmp_path):
    c = cache.Cache(tmp_path / "cache")
    assert c.get("abc") is None
    c.put("abc", {"accepted": [], "rejected": []})
    assert c.get("abc") == {"accepted": [], "rejected": []}
    assert (tmp_path / "cache" / "abc.json").exists()


def test_corrupt_entry_is_a_miss(tmp_path):
    c = cache.Cache(tmp_path)
    (tmp_path / "bad.json").write_text("{not json")
    assert c.get("bad") is None


def test_put_scrubs_keys(tmp_path):
    fake = "sk-" + "ant-" + "api03-" + "A" * 30
    c = cache.Cache(tmp_path)
    c.put("k", {"claim": f"oops {fake}"})
    assert fake not in (tmp_path / "k.json").read_text()


def test_key_depends_on_schema_prompt_and_max_tokens():
    base = cache.cache_key("c", "1", "m", "1", schema_hash="s", prompt_hash="p", max_tokens=10)
    assert base != cache.cache_key("c", "1", "m", "1", schema_hash="s2", prompt_hash="p", max_tokens=10)
    assert base != cache.cache_key("c", "1", "m", "1", schema_hash="s", prompt_hash="p2", max_tokens=10)
    assert base != cache.cache_key("c", "1", "m", "1", schema_hash="s", prompt_hash="p", max_tokens=11)


def test_non_dict_entry_is_a_miss(tmp_path):
    (tmp_path / "k.json").write_text("[1, 2]")
    assert cache.Cache(tmp_path).get("k") is None
