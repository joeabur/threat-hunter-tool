import csv
import io
import json
from pathlib import Path
from typing import Any

import pytest

from linux_threat_hunter.reporting import build_results, load_results, write_reports
from linux_threat_hunter.reporting.writer import csv_cell, md, render_csv
from linux_threat_hunter.rules_engine import Engine
from linux_threat_hunter.utils.redact import Redactor

REQUIRED = [
    "id",
    "rule_id",
    "rule_version",
    "title",
    "explanation",
    "severity",
    "confidence",
    "observed_at",
    "timezone_context",
    "evidence_source",
    "artifact",
    "rationale",
    "attack",
    "false_positives",
    "investigation_steps",
    "ioc_matches",
    "classification",
]


@pytest.fixture()
def results(synthetic_result: Any, config: dict[str, Any]) -> dict[str, Any]:
    ev, hunt, diff = synthetic_result
    return build_results(ev, hunt, iocs=None, diff=diff, baseline_path="b.json", rules_dir="rules")


def test_every_finding_has_required_fields(results: dict[str, Any]) -> None:
    assert results["findings"]
    for f in results["findings"]:
        for key in REQUIRED:
            assert key in f and f[key] not in (None, ""), (f["rule_id"], key)
        assert f["timestamp_basis"] in {"event", "collection"}


def test_results_summary_sections(results: dict[str, Any]) -> None:
    for key in ("scope", "iocs", "baseline", "rules", "missing_telemetry", "limitations", "summary"):
        assert key in results
    assert results["scope"]["total_records"] > 0 and results["baseline"]["change_counts"]["added"] > 0
    assert any(m["kind"] == "collector_partial" for m in results["missing_telemetry"])
    assert sum(results["summary"]["by_severity"].values()) == results["summary"]["total_findings"]


def test_write_reports_all_formats_and_roundtrip(results: dict[str, Any], tmp_path: Path) -> None:
    out = tmp_path / "reports"
    files = write_reports(results, out, Redactor())
    assert {f.name for f in files} == {
        "results.json",
        "summary.md",
        "findings.md",
        "findings.csv",
        "attack_coverage.md",
    }
    (tmp_path / "res").mkdir()
    (tmp_path / "res/results.json").write_text((out / "results.json").read_text())
    assert load_results(tmp_path / "res")["tool"]["name"] == "linux-threat-hunter"
    summary = (out / "summary.md").read_text()
    for heading in (
        "Collection scope",
        "Findings by severity",
        "IOC matches",
        "Baseline changes",
        "Missing telemetry",
        "Rules executed and skipped",
        "Known limitations",
        "ATT&CK",
    ):
        assert heading in summary
    assert "not confirmed" in summary and "Synthetic data" in summary
    rows = list(csv.DictReader(io.StringIO((out / "findings.csv").read_text())))
    assert len(rows) == len(results["findings"]) and rows[0]["rule_id"] and rows[0]["severity"]


def test_secrets_are_redacted_in_every_format(results: dict[str, Any], tmp_path: Path) -> None:
    results = json.loads(json.dumps(results))
    results["findings"][0]["evidence"]["cmdline"] = "tool --password hunter2 token=abcd1234"
    results["findings"][0]["explanation"] = "leak password=SuperSecret99"
    out = tmp_path / "r"
    write_reports(results, out, Redactor())
    for f in out.iterdir():
        text = f.read_text()
        assert "hunter2" not in text and "SuperSecret99" not in text and "abcd1234" not in text, f.name


def test_csv_and_markdown_injection_hardening() -> None:
    assert csv_cell('=HYPERLINK("http://x")').startswith("'=")
    assert csv_cell("+1") == "'+1" and csv_cell("@cmd") == "'@cmd" and csv_cell("-2") == "'-2"
    assert csv_cell(["a", "b"]) == "a; b" and csv_cell(None) == ""
    assert "\n" not in csv_cell("a\nb")
    escaped = md("<script>alert(1)</script> | `x` [l](http://e)")
    assert "<script>" not in escaped and "\\|" in escaped and "\\[" in escaped
    row = dict.fromkeys(
        (
            "id",
            "rule_id",
            "rule_version",
            "title",
            "severity",
            "confidence",
            "classification",
            "observed_at",
            "timestamp_basis",
            "timezone_context",
            "evidence_source",
            "artifact",
            "explanation",
            "rationale",
        ),
        "x",
    )
    row.update(title="=cmd|' /C calc'!A0", ioc_matches=[], attack=[], false_positives=[], investigation_steps=[])
    assert "'=cmd" in render_csv([row])


def test_markdown_findings_do_not_break_out_of_code_fence(results: dict[str, Any], tmp_path: Path) -> None:
    results = json.loads(json.dumps(results))
    results["findings"][0]["evidence"]["x"] = "```\n# injected heading"
    write_reports(results, tmp_path / "r", Redactor())
    text = (tmp_path / "r/findings.md").read_text()
    assert "'''" in text  # the embedded fence was neutralised
    assert text.count("```json") == len(results["findings"])


def test_load_results_validation(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        load_results(tmp_path)
    (tmp_path / "results.json").write_text(json.dumps({"tool": {"name": "other"}}))
    with pytest.raises(ValueError):
        load_results(tmp_path)
    (tmp_path / "results.json").write_text(json.dumps({"tool": {"name": "linux-threat-hunter"}, "schema_version": 99}))
    with pytest.raises(ValueError):
        load_results(tmp_path)


def test_empty_results_say_clean_is_not_implied(
    make_evidence: Any, rules: list[Any], config: dict[str, Any], tmp_path: Path
) -> None:
    ev = make_evidence(processes=[])
    res = build_results(ev, Engine(rules, config).run(ev), iocs=None, diff=None, baseline_path=None, rules_dir="r")
    write_reports(res, tmp_path / "r", Redactor())
    text = (tmp_path / "r/findings.md").read_text()
    assert "does not mean the host is clean" in text
