"""S6 deep-RE additions: decompiled text as an input type, triage ranking, --only-from, two more topic documents."""
import json

import pytest

from conftest import REPO, Lazy
from fakes import FakeClient
from recon import cli
from test_analyze import always_good

allowlist = Lazy("recon.allowlist")
chunking = Lazy("recon.chunking")
prompts = Lazy("recon.prompts")
rank = Lazy("recon.rank")
topic_reports = Lazy("recon.topic_reports")

D = "unpacked/decompiled/usr_bin_gl_modem.r2.txt"
ALL_TOPICS = ("at-commands", "gl-rpc-map", "modem-boot-flow", "fan-led-mcu-battery", "wifi-driver")


def test_decompiled_text_is_its_own_trusted_artifact_type():
    assert chunking.classify(D) == "disassembly"
    assert "disassembly" in chunking.TRUSTED_TYPES
    assert "disassembly" in prompts.task_prompt("disassembly").lower()
    assert prompts.task_prompt("disassembly") != prompts.task_prompt(chunking.OTHER)


def test_decompiled_text_is_allowlisted_and_stays_text_only():
    patterns = allowlist.load_patterns(REPO / "containers" / "recon-allowlist.txt")
    assert allowlist.is_allowed(D, patterns)
    assert not allowlist.is_allowed("unpacked/decompiled-extra/x.txt", patterns)
    assert not allowlist.is_allowed("unpacked/other/usr_bin_gl_modem.r2.txt", patterns)


@pytest.mark.parametrize("topic", ["at-commands", "modem-boot-flow", "fan-led-mcu-battery", "wifi-driver", "gl-rpc-map"])
def test_every_topic_can_select_decompiled_text(topic):
    assert allowlist.is_allowed(D, prompts.TOPICS[topic].globs), topic


def test_all_five_topics_have_a_report_document():
    assert set(topic_reports.REPORT_FILES) == set(ALL_TOPICS)
    assert topic_reports.REPORT_FILES["fan-led-mcu-battery"] == "fan-led-mcu-battery.md"
    assert topic_reports.REPORT_FILES["wifi-driver"] == "wifi-driver.md"
    assert set(topic_reports.TITLES) == set(ALL_TOPICS)


@pytest.mark.parametrize("topic", ["fan-led-mcu-battery", "wifi-driver"])
def test_new_topic_documents_render_from_the_manifest_topic(tmp_path, topic):
    run_dir = tmp_path / "findings" / "raw" / "r1"
    run_dir.mkdir(parents=True)
    finding = {"claim": "Fan speed is set through pwm", "category": "fan", "confidence": "high", "ungrounded": [],
               "chunk_id": "c", "evidence": [{"file": D, "line": 3, "excerpt": "SECRET-EXCERPT", "excerpt_sha256": "ab" * 32}]}
    (run_dir / "findings.jsonl").write_text(json.dumps(finding) + "\n")
    (run_dir / "manifest.json").write_text(json.dumps({"run_id": "r1", "topic": topic}))
    written = topic_reports.generate(run_dir, tmp_path / "docs")
    assert [p.name for p in written] == [f"{topic}.md"]
    assert "SECRET-EXCERPT" not in written[0].read_text()


def _finding(file, confidence="high", ungrounded=()):
    return {"claim": "c", "category": "other", "confidence": confidence, "ungrounded": list(ungrounded), "chunk_id": "x",
            "evidence": [{"file": file, "line": 1, "excerpt": "e", "excerpt_sha256": "00" * 32}]}


def test_rank_orders_files_by_weighted_findings_and_is_deterministic():
    findings = [_finding("unpacked/b"), _finding("unpacked/b", "low"), _finding("unpacked/a", "medium"),
                _finding("unpacked/c", "high"), _finding("unpacked/c", "high"), _finding("unpacked/a", "low")]
    assert rank.rank_files(findings, top_n=10) == ["unpacked/c", "unpacked/b", "unpacked/a"]
    assert rank.rank_files(findings, top_n=2) == ["unpacked/c", "unpacked/b"]
    assert rank.rank_files(list(reversed(findings)), top_n=10) == rank.rank_files(findings, top_n=10)


def test_rank_gives_ungrounded_findings_no_weight():
    findings = [_finding("unpacked/a", ungrounded=["AT command X not in ground truth"]), _finding("unpacked/b", "low")]
    assert rank.rank_files(findings, top_n=5) == ["unpacked/b"]


def test_rank_cli_writes_one_name_per_line(tmp_path):
    run_dir = tmp_path / "findings" / "raw" / "tri"
    run_dir.mkdir(parents=True)
    (run_dir / "findings.jsonl").write_text("".join(json.dumps(_finding(f)) + "\n" for f in ("unpacked/x", "unpacked/y")))
    out = run_dir / "top.txt"
    assert rank.main(["--run-dir", str(run_dir), "--top", "1", "--out", str(out)]) == 0
    assert out.read_text() == "unpacked/x\n"


def test_rank_cli_refuses_an_empty_ranking(tmp_path, capsys):
    run_dir = tmp_path / "findings" / "raw" / "tri"
    run_dir.mkdir(parents=True)
    (run_dir / "findings.jsonl").write_text("")
    assert rank.main(["--run-dir", str(run_dir), "--top", "3", "--out", str(run_dir / "top.txt")]) == 2
    assert not (run_dir / "top.txt").exists()
    assert "nothing to rank" in capsys.readouterr().err


def _tree(root, stamp):
    base = root / "unpacked" / "stock" / "rootfs"
    for rel, text in {"etc/init.d/gl_modem": "start() {\n  echo INITD-MARK-LINE\n}\n",
                      "etc/init.d/gl_fan": "start() {\n  echo FAN-MARK-LINE\n}\n"}.items():
        (base / rel).parent.mkdir(parents=True, exist_ok=True)
        (base / rel).write_text(text)
    dec = root / "unpacked" / "decompiled"
    dec.mkdir(parents=True)
    (dec / "usr_bin_gl_modem.r2.txt").write_text("; \"AT+CFUN=1\"\nmov x0, 1\n")
    stamp(root)


def go(root, client, *extra):
    return cli.main(["--root", str(root), "--run-id", "t1", "--no-canary", "--max-usd", "5", *extra],
                    client_factory=lambda: client)


def test_decompiled_files_are_sent_as_disassembly(root, stamp):
    _tree(root, stamp)
    client = FakeClient(script=always_good)
    assert go(root, client) == 0
    sent = json.dumps([c[2] for c in client.create_calls])
    assert "AT+CFUN=1" in sent
    assert any("disassembly" in json.dumps(c[1]).lower() for c in client.create_calls)


def test_only_from_narrows_to_the_listed_files_and_is_recorded(root, stamp):
    _tree(root, stamp)
    lst = root / "findings" / "raw" / "tri" / "top.txt"
    lst.parent.mkdir(parents=True)
    lst.write_text("unpacked/stock/rootfs/etc/init.d/gl_fan\n")
    client = FakeClient(script=always_good)
    assert go(root, client, "--only-from", "findings/raw/tri/top.txt") == 0
    sent = json.dumps([c[2] for c in client.create_calls])
    assert "FAN-MARK-LINE" in sent and "INITD-MARK-LINE" not in sent and "AT+CFUN" not in sent
    manifest = json.loads((root / "findings/raw/t1/manifest.json").read_text())
    assert manifest["only_from"] == {"files": 1}
    reasons = {s["name"]: s["reason"] for s in manifest["skipped"]}
    assert reasons["unpacked/stock/rootfs/etc/init.d/gl_modem"] == "not-ranked"


def test_only_from_never_widens_the_allowlist(root, stamp):
    _tree(root, stamp)
    (root / "unpacked" / "stock" / "rootfs" / "etc").mkdir(exist_ok=True)
    (root / "unpacked" / "stock" / "rootfs" / "etc" / "shadow").write_text("root:HASHMARK:0:0\n")
    lst = root / "findings" / "raw" / "tri" / "top.txt"
    lst.parent.mkdir(parents=True)
    lst.write_text("unpacked/stock/rootfs/etc/shadow\nunpacked/stock/rootfs/etc/init.d/gl_fan\n")
    stamp(root)
    client = FakeClient(script=always_good)
    assert go(root, client, "--only-from", "findings/raw/tri/top.txt") == 0
    assert "HASHMARK" not in json.dumps([c[2] for c in client.create_calls])


@pytest.mark.parametrize("bad", ["/etc/passwd", "../outside.txt", "harvest/redacted/x.txt"])
def test_only_from_must_live_under_findings_raw(root, stamp, bad, capsys):
    _tree(root, stamp)
    assert go(root, FakeClient(script=always_good), "--only-from", bad) == 2
    assert "only-from" in capsys.readouterr().err


def test_only_from_empty_list_is_refused(root, stamp, capsys):
    _tree(root, stamp)
    lst = root / "findings" / "raw" / "tri" / "top.txt"
    lst.parent.mkdir(parents=True)
    lst.write_text("\n# nothing\n")
    client = FakeClient(script=always_good)
    assert go(root, client, "--only-from", "findings/raw/tri/top.txt") == 2
    assert client.create_calls == [] and "empty" in capsys.readouterr().err
