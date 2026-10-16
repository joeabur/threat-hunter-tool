"""End-to-end analysis of the shipped synthetic evidence (runs on any OS, no root)."""

import json
from collections import Counter
from pathlib import Path
from typing import Any

from conftest import EXAMPLES, RULES
from linux_threat_hunter.baseline import compare, create_baseline, load_baseline
from linux_threat_hunter.evidence import load_evidence


def test_matches_expected_results(synthetic_result: Any, rules: list[Any]) -> None:
    _, hunt, _ = synthetic_result
    expected = json.loads((EXAMPLES / "expected-results/expected-findings.json").read_text())
    got = Counter(f.rule_id for f in hunt.findings)
    assert dict(sorted(got.items())) == expected["findings_by_rule"]
    assert len(hunt.findings) == expected["total_findings"]
    assert expected["rules_with_no_findings"] == []
    assert all(s.status == "executed" for s in hunt.statuses)


def test_committed_baseline_matches_clean_evidence(config: dict[str, Any]) -> None:
    committed = load_baseline(EXAMPLES / "baselines/clean-baseline.json")
    fresh = create_baseline(load_evidence(EXAMPLES / "synthetic-baseline-evidence", config))
    assert committed["entries"] == fresh["entries"]
    clean = load_evidence(EXAMPLES / "synthetic-baseline-evidence", config)
    assert compare(committed, clean).changes == []  # baseline evidence has no drift against itself


def test_exercise_traces(synthetic_result: Any) -> None:
    """The facts the walkthrough relies on."""
    _, hunt, _ = synthetic_result
    by = {}
    for f in hunt.findings:
        by.setdefault(f.rule_id, []).append(f)
    f = by["LTH-PROC-003"][0]
    assert f.entities["pid"] == 5100 and "nginx" in f.title
    assert f.evidence["record_ref"] == "processes.json#7" or f.evidence["record_ref"].startswith("processes.json#")
    assert by["LTH-AUTH-001"][0].evidence["count"] == 7
    assert by["LTH-AUTH-002"][0].entities["ip"] == "198.51.100.23"
    assert not any(x.entities.get("ip") == "203.0.113.99" for x in by["LTH-AUTH-001"])  # slow scanner: no burst
    assert not any(x.entities.get("ip") == "192.0.2.77" for x in by["LTH-AUTH-001"])  # 3 failures: below threshold
    ioc_values = {m["indicator"] for f in by["LTH-PERS-006"] for m in f.ioc_matches}
    assert {"/tmp/.cache/updater", "bad-update.example.test", "203.0.113.50"} & ioc_values
    cor = by["LTH-COR-002"]
    assert {c.entities["path"] for c in cor} == {"/etc/systemd/system/sys-update.service", "/etc/cron.d/sysupdate"}
    # false positive kept visible for the allowlist exercise
    assert any("AppRun" in x.title for x in by["LTH-PROC-001"])


def test_attack_summary_does_not_claim_absence(synthetic_result: Any, tmp_path: Path) -> None:
    from linux_threat_hunter.reporting import build_results, write_reports
    from linux_threat_hunter.utils.redact import Redactor

    ev, hunt, diff = synthetic_result
    res = build_results(ev, hunt, iocs=None, diff=diff, baseline_path="b", rules_dir=str(RULES))
    write_reports(res, tmp_path, Redactor())
    text = (tmp_path / "attack_coverage.md").read_text()
    assert "not thereby absent" in (tmp_path / "summary.md").read_text() or "not implied to be absent" in text
    assert "T1543.002" in text and "https://attack.mitre.org/techniques/T1543/002/" in text


def test_read_only_guarantee_no_remediation_code() -> None:
    """The package must not contain process-killing, service-changing or deletion calls."""
    src = Path(__file__).resolve().parents[2] / "src" / "linux_threat_hunter"
    forbidden = (
        "os.kill(",
        "os.remove(",
        "os.unlink(",
        "shutil.rmtree",
        "shell=True",
        "os.system(",
        "systemctl",
        "iptables",
        "userdel",
        "kill -9",
    )
    for py in src.rglob("*.py"):
        text = py.read_text()
        for needle in forbidden:
            assert needle not in text, f"{needle} found in {py}"
