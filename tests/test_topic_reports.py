import json

import pytest

from conftest import Lazy

topic_reports = Lazy("recon.topic_reports")


def _finding(claim, category="rpc-method", ungrounded=(), line=7, file="unpacked/stock/rootfs/usr/lib/oui-httpd/rpc/fan"):
    return {"claim": claim, "category": category, "confidence": "high", "ungrounded": list(ungrounded),
            "chunk_id": "c1", "evidence": [{"file": file, "line": line, "excerpt": "VERBATIM-EXCERPT-TEXT",
                                             "excerpt_sha256": "cd" * 32}]}


def _run(tmp_path, findings, topic="gl-rpc-map"):
    run_dir = tmp_path / "findings" / "raw" / "run1"
    run_dir.mkdir(parents=True)
    (run_dir / "findings.jsonl").write_text("".join(json.dumps(f) + "\n" for f in findings))
    (run_dir / "manifest.json").write_text(json.dumps({"run_id": "run1", "topic": topic}))
    return run_dir


def test_report_names_cover_three_documents():
    assert set(topic_reports.REPORT_FILES) == {"at-commands", "gl-rpc-map", "modem-boot-flow"}


@pytest.mark.parametrize("topic", ["at-commands", "gl-rpc-map", "modem-boot-flow"])
def test_generates_the_topic_document_from_the_manifest_topic(tmp_path, topic):
    run_dir = _run(tmp_path, [_finding("x doc")], topic)
    written = topic_reports.generate(run_dir, tmp_path / "docs" / "findings")
    assert [p.name for p in written] == [f"{topic}.md"]
    md = written[0].read_text()
    assert "<!-- generated" in md and "run1" in md and "cdcdcdcdcdcd" in md
    assert "VERBATIM-EXCERPT-TEXT" not in md


def test_rows_link_evidence_and_mark_ungrounded(tmp_path):
    run_dir = _run(tmp_path, [_finding("Calls fan.set_test"),
                              _finding("Uses AT+QPOWD", ungrounded=["AT command AT+QPOWD not in ground truth"])],
                   "at-commands")
    md = topic_reports.generate(run_dir, tmp_path / "o")[0].read_text()
    rows = [l for l in md.splitlines() if l.startswith("| `")]
    assert len(rows) == 2 and all("](<unpacked/stock/rootfs/usr/lib/oui-httpd/rpc/fan#L7>)" in r for r in rows)
    assert sum("UNGROUNDED" in r for r in rows) == 1 and "grounded" in rows[0]


def test_claims_are_capped_and_never_contain_raw_markup(tmp_path):
    run_dir = _run(tmp_path, [_finding("A" * 1000 + " <script>x</script> `tick`")], "at-commands")
    md = topic_reports.generate(run_dir, tmp_path / "o")[0].read_text()
    row = next(l for l in md.splitlines() if l.startswith("| `"))
    claim_cell = row.split("` |")[0]
    assert len(claim_cell) <= 300 + 4 and "<script>" not in md


def test_rpc_map_has_a_network_access_control_section(tmp_path):
    run_dir = _run(tmp_path, [
        _finding("Method clients.get_list returns connected client list"),
        _finding("Method parental_control.set_rule blocks a device on a schedule"),
        _finding("Method fan.set_test spins the fan"),
    ])
    md = topic_reports.generate(run_dir, tmp_path / "o")[0].read_text()
    head_nac, head_other = md.index("## Network access control"), md.index("## Other RPC methods")
    nac, other = md[head_nac:head_other] if head_nac < head_other else md[head_nac:], md[head_other:]
    assert "client list" in nac and "blocks a device" in nac and "fan.set_test" not in nac
    assert "fan.set_test" in other


def test_rpc_map_section_is_present_even_when_empty(tmp_path):
    md = topic_reports.generate(_run(tmp_path, [_finding("Method fan.set_test")]), tmp_path / "o")[0].read_text()
    assert "## Network access control" in md and "No findings" in md


def test_unknown_or_missing_topic_is_refused(tmp_path):
    run_dir = _run(tmp_path, [_finding("x")], "fan-led-mcu-battery")
    with pytest.raises(ValueError, match="no report"):
        topic_reports.generate(run_dir, tmp_path / "o")
    (run_dir / "manifest.json").write_text("{}")
    with pytest.raises(ValueError, match="topic"):
        topic_reports.generate(run_dir, tmp_path / "o")


def test_main_and_report_flag(tmp_path, capsys):
    run_dir = _run(tmp_path, [_finding("x")], "at-commands")
    assert topic_reports.main(["--run-dir", str(run_dir), "--out", str(tmp_path / "o")]) == 0
    assert "at-commands.md" in capsys.readouterr().out
