import json

from recon import report


def _finding(claim, category="gpio", ungrounded=()):
    return {"claim": claim, "category": category, "confidence": "high", "ungrounded": list(ungrounded),
            "chunk_id": "c1", "evidence": [{"file": "redacted/etc/init.d/fan", "line": 7,
                                             "excerpt": "VERBATIM-EXCERPT-TEXT", "excerpt_sha256": "ab" * 32}]}


def _run(tmp_path, findings):
    run_dir = tmp_path / "findings" / "raw" / "run1"
    run_dir.mkdir(parents=True)
    (run_dir / "findings.jsonl").write_text("".join(json.dumps(f) + "\n" for f in findings))
    return run_dir


def test_generates_category_tables_with_evidence_links(tmp_path):
    run_dir = _run(tmp_path, [_finding("Fan on GPIO 7 | pipe"), _finding("Led thing", "led")])
    written = report.generate(run_dir, tmp_path / "docs" / "findings")
    names = {p.name for p in written}
    assert names == {"gpio.md", "led.md", "index.md"}
    md = (tmp_path / "docs" / "findings" / "gpio.md").read_text()
    assert "[`redacted/etc/init.d/fan:7`](<harvest/redacted/etc/init.d/fan#L7>)" in md
    assert "abababababab" in md and "Fan on GPIO 7 \\| pipe" in md
    assert "VERBATIM-EXCERPT-TEXT" not in md
    assert "[gpio](gpio.md)" in (tmp_path / "docs" / "findings" / "index.md").read_text()


def test_ungrounded_is_shown(tmp_path):
    run_dir = _run(tmp_path, [_finding("Uses AT+QPOWD", ungrounded=["AT command AT+QPOWD not in ground truth"])])
    report.generate(run_dir, tmp_path / "out")
    md = (tmp_path / "out" / "gpio.md").read_text()
    assert "UNGROUNDED" in md and "AT+QPOWD" in md


def test_rows_always_have_evidence(tmp_path):
    run_dir = _run(tmp_path, [_finding("a"), _finding("b")])
    report.generate(run_dir, tmp_path / "out")
    rows = [l for l in (tmp_path / "out" / "gpio.md").read_text().splitlines() if l.startswith("| ") and "---" not in l][1:]
    assert rows and all("](" in r for r in rows)


def test_report_main(tmp_path, capsys):
    run_dir = _run(tmp_path, [_finding("x")])
    assert report.main(["--run-dir", str(run_dir), "--out", str(tmp_path / "o")]) == 0
    assert "gpio.md" in capsys.readouterr().out


def _outside_code(md):
    import re
    return re.sub(r"`[^`\n]*`", "``", md)


def test_claims_are_neutralised(tmp_path):
    nasty = "<script>alert(1)</script> [click](http://evil.example) ![i](x) `tick` | pipe\nnewline " + "A" * 400
    run_dir = _run(tmp_path, [_finding(nasty)])
    report.generate(run_dir, tmp_path / "out")
    md = (tmp_path / "out" / "gpio.md").read_text()
    row = [l for l in md.splitlines() if "alert" in l][0]
    import re
    cell = re.match(r"\| (`[^`]*`) \| high", row)
    assert cell, row
    assert "<script>" not in row and "A" * 301 not in row and "\n" not in row
    outside = _outside_code(row)
    assert "](http://evil" not in outside and "![" not in outside and "<" not in outside.replace("<br>", "").replace("(<", "")


def test_evidence_file_names_cannot_inject_links(tmp_path):
    f = _finding("ok")
    f["evidence"][0]["file"] = "redacted/a](http://evil.example)b"
    run_dir = _run(tmp_path, [f])
    report.generate(run_dir, tmp_path / "out")
    md = _outside_code((tmp_path / "out" / "gpio.md").read_text())
    assert "evil.example" not in md.replace("http%3A//evil.example", "")
