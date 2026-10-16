from __future__ import annotations

import csv
import io
import json
from pathlib import Path

import pytest

from mac_threat_hunter.baseline.model import load_baseline
from mac_threat_hunter.config import Config, default_rules_dir, make_redactor
from mac_threat_hunter.detections.runner import result_to_dict, run_hunt
from mac_threat_hunter.evidence.loader import load_evidence
from mac_threat_hunter.ioc.loader import load_iocs
from mac_threat_hunter.reporting.render import (
    csv_safe,
    findings_csv,
    load_results,
    md_code,
    md_text,
    render_markdown,
    write_reports,
)
from mac_threat_hunter.rules_engine.loader import load_rules
from mac_threat_hunter.utils.errors import InputError


@pytest.fixture(scope="module")
def results() -> dict:
    root = Path(__file__).resolve().parents[2]
    cfg = Config  # noqa: F841
    from mac_threat_hunter.config import load_config

    c = load_config()
    rs = load_rules([default_rules_dir()], c)
    ev = load_evidence(root / "examples/synthetic-evidence", c)
    iocs = load_iocs(root / "examples/iocs.json")
    bl = load_baseline(root / "examples/baselines/clean-baseline.json")
    hunt = run_hunt(ev, rs, c, iocs=iocs, baseline=bl)
    return make_redactor(c).redact_obj(
        result_to_dict(
            ev,
            rs,
            hunt,
            c,
            iocs=iocs,
            baseline=bl,
            rule_dirs=["rules"],
            ioc_path="iocs.json",
            baseline_path="b.json",
        )
    )


class TestEscaping:
    def test_csv_injection_neutralised(self) -> None:
        for bad in ("=cmd|' /C calc'!A0", "+1+1", "-2+3", "@SUM(A1)", "\t=1"):
            assert csv_safe(bad).startswith("'")
        assert csv_safe("normal") == "normal"
        assert "\n" not in csv_safe("a\nb") and "\x00" not in csv_safe("a\x00b")

    def test_markdown_text_escaped(self) -> None:
        out = md_text("<script>alert(1)</script> | `x` [l](http://e) *b* #h")
        for raw in ("<", ">", "|", "`", "[", "*", "#"):
            assert "\\" + raw in out

    def test_code_span_survives_backticks(self) -> None:
        assert md_code("a`b") == "``a`b``"
        assert "\n" not in md_code("a\nb")


class TestReports:
    def test_required_finding_fields_present(self, results: dict) -> None:
        required = {"finding_id", "rule_id", "rule_version", "title", "explanation", "severity", "confidence",
                    "time_zone", "evidence_ref", "evidence", "rationale", "false_positives", "investigation",
                    "category", "attack", "host"}  # fmt: skip
        for f in results["findings"]:
            assert required <= set(f), required - set(f)
            assert f["false_positives"] and f["investigation"]

    def test_summary_sections_present(self, results: dict) -> None:
        md = render_markdown(results)
        for heading in ("Executive summary", "Scope and data sources analysed", "Collection errors and missing telemetry",
                        "MITRE ATT&CK summary", "Baseline changes", "Rules executed and skipped", "Known limitations",
                        "Heuristic detection", "IOC match", "Observed change vs baseline"):  # fmt: skip
            assert heading in md, heading
        assert "SYNTHETIC DATA" in md
        assert (
            "not proof" in md.lower()
            or "not a verdict" in md.lower()
            or "not verdicts" in md.lower()
        )

    def test_secrets_never_reach_reports(self, results: dict, tmp_path: Path, cfg: Config) -> None:
        out = write_reports(results, tmp_path, make_redactor(cfg), {"md", "json", "csv"})
        blob = "".join(p.read_text(encoding="utf-8") for p in out)
        assert "SyntheticSecret123" not in blob and "abc123synthetic" not in blob
        assert "[REDACTED]" in blob

    def test_report_redacts_even_if_results_file_contains_secrets(
        self, results: dict, tmp_path: Path, cfg: Config
    ) -> None:
        dirty = json.loads(json.dumps(results))
        dirty["findings"][0]["evidence"]["cmdline"] = "tool --password=topsecret99"
        out = write_reports(dirty, tmp_path, make_redactor(cfg), {"md", "csv", "json"})
        assert all("topsecret99" not in p.read_text(encoding="utf-8") for p in out)

    def test_csv_parses_and_has_every_finding(self, results: dict) -> None:
        rows = list(csv.DictReader(io.StringIO(findings_csv(results))))
        assert len(rows) == len(results["findings"])
        assert {"finding_id", "rule_id", "severity", "confidence", "attack", "evidence_ref"} <= set(
            rows[0]
        )

    def test_hostile_values_do_not_break_markdown_structure(self, results: dict) -> None:
        dirty = json.loads(json.dumps(results))
        dirty["findings"][0]["title"] = "evil | <img src=x onerror=alert(1)> `` \n# heading"
        md = render_markdown(dirty)
        assert "<img" not in md.replace("\\<", "") and "\n# heading" not in md

    def test_attack_summary_does_not_imply_absence(self, results: dict) -> None:
        md = render_markdown(results)
        assert "not necessarily absent" in md

    def test_load_results_validation(self, tmp_path: Path) -> None:
        (tmp_path / "results.json").write_text('{"x": 1}')
        with pytest.raises(InputError):
            load_results(tmp_path)
        (tmp_path / "bad.json").write_text("{")
        with pytest.raises(InputError):
            load_results(tmp_path / "bad.json")

    def test_ioc_and_baseline_sections_render_details(self, results: dict) -> None:
        md = render_markdown(results)
        assert "indicator `sha256`" in md and "matched field" in md and "Baseline change" in md
