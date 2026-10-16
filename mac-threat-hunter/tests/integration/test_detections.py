from __future__ import annotations

import json
import subprocess
import time
from collections import Counter
from pathlib import Path

import pytest

from helpers import make_evidence
from mac_threat_hunter.baseline.model import create_baseline, load_baseline
from mac_threat_hunter.config import Config, default_rules_dir, load_config
from mac_threat_hunter.detections.runner import result_to_dict, run_hunt
from mac_threat_hunter.evidence.loader import load_evidence
from mac_threat_hunter.ioc.loader import load_iocs
from mac_threat_hunter.rules_engine.loader import RuleSet


@pytest.fixture(scope="module")
def hunt_all(ruleset: RuleSet, cfg: Config, repo_root: Path):  # type: ignore[no-untyped-def]
    ev = load_evidence(repo_root / "examples/synthetic-evidence", cfg)
    return run_hunt(ev, ruleset, cfg, iocs=load_iocs(repo_root / "examples/iocs.json"),
                    baseline=load_baseline(repo_root / "examples/baselines/clean-baseline.json"))  # fmt: skip


def titles(hunt, rule_id: str) -> list[str]:  # type: ignore[no-untyped-def]
    return [f.title for f in hunt.findings if f.rule_id == rule_id]


class TestSyntheticScenario:
    def test_matches_committed_expected_results(self, hunt_all, repo_root: Path) -> None:  # type: ignore[no-untyped-def]
        expected = json.loads(
            (repo_root / "examples/expected-results/expected-rule-hits.json").read_text()
        )
        assert (
            dict(sorted(Counter(f.rule_id for f in hunt_all.findings).items()))
            == expected["rule_hits"]
        )
        assert len(hunt_all.findings) == expected["total_findings"]

    def test_false_positive_controls_stay_quiet(self, hunt_all) -> None:  # type: ignore[no-untyped-def]
        blob = json.dumps([f.to_dict() for f in hunt_all.findings])
        assert "zoom.us" not in blob  # AppTranslocation exception
        assert "/Users/alice/dev/analysis.py" not in blob  # script outside writable paths
        assert "192.0.2.77" not in blob  # two SSH failures stay below threshold of 5
        assert "tool-installer" not in blob  # old file in Downloads
        assert (
            "com.vendor.legit" not in blob and "com.microsoft.update" not in blob
        )  # allowlisted vendors
        assert "rapportd" not in blob and "ControlCenter" not in blob  # expected listeners
        assert "203.0.113.99" not in blob and "d4cdb2ba" not in blob  # decoy IOCs

    def test_process_rules_explain_themselves(self, hunt_all) -> None:  # type: ignore[no-untyped-def]
        f = next(f for f in hunt_all.findings if f.rule_id == "MTH-EXEC-003")
        assert f.evidence["parent_name"] == "Microsoft Word" and f.evidence["name"] == "sh"
        assert f.evidence_ref == "processes.json#9" and f.host == "synthetic-mac.example.test"
        assert {a["id"] for a in f.attack} == {"T1204", "T1059"}
        assert f.severity == "high" and f.confidence == "medium" and f.category == "heuristic"

    def test_persistence_findings_cite_the_plist(self, hunt_all) -> None:  # type: ignore[no-untyped-def]
        f = next(f for f in hunt_all.findings if f.rule_id == "MTH-PERS-001")
        assert f.artifact["path"].endswith("com.example.updater.plist")
        assert f.evidence["program_path"] == "/private/tmp/.updater"
        assert titles(hunt_all, "MTH-PERS-002")[0].endswith("com.example.old")

    def test_threshold_finding_summarises_window(self, hunt_all) -> None:  # type: ignore[no-untyped-def]
        f = next(f for f in hunt_all.findings if f.rule_id == "MTH-LOG-001")
        assert f.evidence["event_count"] == 6 and f.evidence["group_value"] == "192.0.2.50"
        assert (
            f.evidence["first_seen"] < f.evidence["last_seen"]
            and len(f.evidence["sample_refs"]) == 6
        )
        assert f.observed_at == "2026-03-10T14:10:00.123456Z" and f.time_zone == "explicit:+00:00"

    def test_ioc_findings_identify_indicator_and_source(self, hunt_all) -> None:  # type: ignore[no-untyped-def]
        iocs = [f for f in hunt_all.findings if f.category == "ioc_match"]
        assert iocs and all(
            f.ioc and f.ioc["value"] and f.evidence_ref and f.ioc["note"] for f in iocs
        )
        net = [f for f in iocs if f.rule_id == "MTH-IOC-003"]
        assert any(m["value"] == "198.51.100.23" for f in net for m in f.ioc["all_matches"])
        assert any(
            m["value"] == "c2.malicious.example.test" for f in net for m in f.ioc["all_matches"]
        )

    def test_baseline_findings_carry_before_and_after(self, hunt_all) -> None:  # type: ignore[no-untyped-def]
        f = next(f for f in hunt_all.findings if f.rule_id == "MTH-BASE-004")
        assert f.baseline_change["change"] == "modified" and f.baseline_change[
            "changed_attributes"
        ] == ["sha256"]
        assert f.baseline_change["before"]["sha256"] != f.baseline_change["after"]["sha256"]

    def test_secrets_redacted_in_findings(self, hunt_all) -> None:  # type: ignore[no-untyped-def]
        blob = json.dumps([f.to_dict() for f in hunt_all.findings])
        assert "SyntheticSecret123" not in blob and "abc123synthetic" not in blob

    def test_missing_context_is_stated(self, hunt_all) -> None:  # type: ignore[no-untyped-def]
        f = next(f for f in hunt_all.findings if f.rule_id == "MTH-EXEC-001")
        assert isinstance(
            f.missing_context, list
        )  # parent_name present here, so empty; list always exists

    def test_clean_evidence_has_no_findings_even_with_iocs_and_own_baseline(
        self, ruleset: RuleSet, cfg: Config, repo_root: Path
    ) -> None:
        ev = load_evidence(repo_root / "examples/synthetic-evidence-clean", cfg)
        hunt = run_hunt(
            ev,
            ruleset,
            cfg,
            iocs=load_iocs(repo_root / "examples/iocs.json"),
            baseline=create_baseline(ev),
        )
        assert hunt.findings == [] and hunt.changes == []

    def test_finding_ids_are_stable_between_runs(
        self, ruleset: RuleSet, cfg: Config, repo_root: Path, hunt_all
    ) -> None:  # type: ignore[no-untyped-def]
        ev = load_evidence(repo_root / "examples/synthetic-evidence", cfg)
        again = run_hunt(ev, ruleset, cfg, iocs=load_iocs(repo_root / "examples/iocs.json"),
                         baseline=load_baseline(repo_root / "examples/baselines/clean-baseline.json"))  # fmt: skip
        assert [f.finding_id for f in again.findings] == [f.finding_id for f in hunt_all.findings]
        assert len({f.finding_id for f in hunt_all.findings}) == len(hunt_all.findings)


class TestEveryRuleCanFire:
    """Rules not triggered by the demo scenario still need a positive test."""

    def test_login_hook_rule(self, tmp_path: Path, ruleset: RuleSet, cfg: Config) -> None:
        ev_dir = make_evidence(tmp_path / "ev", persistence=[{"path": "/var/root/Library/Preferences/com.apple.loginwindow.plist",
                               "kind": "login_hook", "label": "LoginHook", "program_path": "/Library/hook.sh"}])  # fmt: skip
        hunt = run_hunt(load_evidence(ev_dir, cfg), ruleset, cfg)
        assert [f.rule_id for f in hunt.findings if f.rule_id == "MTH-PERS-007"]

    def test_removed_persistence_baseline_rule(
        self, tmp_path: Path, ruleset: RuleSet, cfg: Config
    ) -> None:
        old = make_evidence(tmp_path / "old", persistence=[{"path": "/Library/LaunchAgents/a.plist", "kind": "launch_agent", "sha256": "1" * 64},
                                                           {"path": "/Library/LaunchAgents/b.plist", "kind": "launch_agent", "sha256": "2" * 64}])  # fmt: skip
        new = make_evidence(
            tmp_path / "new",
            persistence=[
                {
                    "path": "/Library/LaunchAgents/a.plist",
                    "kind": "launch_agent",
                    "sha256": "1" * 64,
                }
            ],
        )
        baseline = create_baseline(load_evidence(old, cfg))
        hunt = run_hunt(load_evidence(new, cfg), ruleset, cfg, baseline=baseline)
        removed = [f for f in hunt.findings if f.rule_id == "MTH-BASE-003"]
        assert len(removed) == 1 and removed[0].severity == "informational"
        assert removed[0].baseline_change["change"] == "removed"

    def test_all_shipped_rules_accounted_for(self, hunt_all, ruleset: RuleSet) -> None:  # type: ignore[no-untyped-def]
        hit = {f.rule_id for f in hunt_all.findings}
        assert {r.id for r in ruleset.rules} - hit == {"MTH-BASE-003", "MTH-PERS-007"}


class TestRuleStatusAndMissingTelemetry:
    def test_rules_skipped_when_telemetry_or_inputs_absent(
        self, tmp_path: Path, ruleset: RuleSet, cfg: Config
    ) -> None:
        ev_dir = make_evidence(
            tmp_path / "ev", processes=[{"pid": 1, "name": "launchd", "path": "/sbin/launchd"}]
        )
        hunt = run_hunt(load_evidence(ev_dir, cfg), ruleset, cfg)
        status = {s.rule_id: s for s in hunt.rule_stats}
        assert (
            status["MTH-PERS-001"].status == "skipped"
            and "persistence telemetry" in status["MTH-PERS-001"].reason
        )  # type: ignore[operator]
        assert (
            status["MTH-IOC-001"].status == "skipped" and "--iocs" in status["MTH-IOC-001"].reason
        )  # type: ignore[operator]
        assert (
            status["MTH-BASE-001"].status == "skipped"
            and "baseline" in status["MTH-BASE-001"].reason
        )  # type: ignore[operator]
        assert status["MTH-EXEC-001"].status == "executed"

    def test_no_parent_telemetry_means_no_parent_child_finding(
        self, tmp_path: Path, ruleset: RuleSet, cfg: Config
    ) -> None:
        ev_dir = make_evidence(
            tmp_path / "ev", processes=[{"pid": 5, "ppid": 4, "name": "sh", "path": "/bin/sh"}]
        )
        hunt = run_hunt(load_evidence(ev_dir, cfg), ruleset, cfg)
        assert not [f for f in hunt.findings if f.rule_id == "MTH-EXEC-003"]
        assert (
            next(s for s in hunt.rule_stats if s.rule_id == "MTH-EXEC-003").skipped_missing_fields
            == 1
        )

    def test_listener_without_process_attribution_is_not_flagged(
        self, tmp_path: Path, ruleset: RuleSet, cfg: Config
    ) -> None:
        ev_dir = make_evidence(
            tmp_path / "ev",
            network=[{"state": "LISTEN", "local_address": "0.0.0.0", "local_port": 9999}],
        )
        hunt = run_hunt(load_evidence(ev_dir, cfg), ruleset, cfg)
        assert not [f for f in hunt.findings if f.rule_id == "MTH-NET-001"]

    def test_overrides_disable_and_reseverity(
        self, ruleset: RuleSet, cfg: Config, repo_root: Path
    ) -> None:
        over = Config(
            **{
                **cfg.__dict__,
                "rule_overrides": {
                    "MTH-NET-001": {"enabled": False},
                    "MTH-EXEC-001": {"severity": "critical"},
                },
            }
        )
        # RuleSet rules are mutable objects; reload to avoid leaking the override into other tests.
        from mac_threat_hunter.rules_engine.loader import load_rules

        rs = load_rules([default_rules_dir()], over)
        ev = load_evidence(repo_root / "examples/synthetic-evidence", over)
        hunt = run_hunt(ev, rs, over)
        assert not [f for f in hunt.findings if f.rule_id == "MTH-NET-001"]
        assert next(s for s in hunt.rule_stats if s.rule_id == "MTH-NET-001").status == "disabled"
        assert [f.severity for f in hunt.findings if f.rule_id == "MTH-EXEC-001"] == ["critical"]


class TestSuppression:
    def make(self, cfg: Config, suppressions: list[dict]) -> Config:
        return Config(**{**cfg.__dict__, "suppressions": suppressions})

    def test_suppressed_findings_are_kept_visibly(
        self, ruleset: RuleSet, cfg: Config, repo_root: Path
    ) -> None:
        c = self.make(
            cfg,
            [
                {
                    "rule_id": "MTH-NET-001",
                    "reason": "Approved dev server on lab host",
                    "match": {"process_name": "python3"},
                }
            ],
        )
        hunt = run_hunt(load_evidence(repo_root / "examples/synthetic-evidence", c), ruleset, c)
        assert not [f for f in hunt.findings if f.rule_id == "MTH-NET-001"]
        sup = [f for f in hunt.suppressed if f.rule_id == "MTH-NET-001"]
        assert (
            len(sup) == 1
            and sup[0].suppressed
            and sup[0].suppression_reason == "Approved dev server on lab host"
        )

    def test_non_matching_suppression_does_nothing(
        self, ruleset: RuleSet, cfg: Config, repo_root: Path
    ) -> None:
        c = self.make(
            cfg,
            [
                {
                    "rule_id": "MTH-NET-001",
                    "reason": "Different process entirely",
                    "match": {"process_name": "nginx"},
                }
            ],
        )
        hunt = run_hunt(load_evidence(repo_root / "examples/synthetic-evidence", c), ruleset, c)
        assert [f for f in hunt.findings if f.rule_id == "MTH-NET-001"] and not hunt.suppressed

    def test_expired_suppression_ignored_with_warning(
        self, ruleset: RuleSet, cfg: Config, repo_root: Path
    ) -> None:
        c = self.make(
            cfg,
            [
                {
                    "rule_id": "MTH-NET-001",
                    "reason": "Was approved until 2020",
                    "expires": "2020-01-01",
                }
            ],
        )
        hunt = run_hunt(load_evidence(repo_root / "examples/synthetic-evidence", c), ruleset, c)
        assert [f for f in hunt.findings if f.rule_id == "MTH-NET-001"]
        assert any("expired" in w for w in hunt.warnings)


class TestSecurityBoundaries:
    def test_hunting_spawns_no_processes(
        self, ruleset: RuleSet, cfg: Config, repo_root: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def forbidden(*a, **k):  # type: ignore[no-untyped-def]
            raise AssertionError("hunt must not start subprocesses")

        monkeypatch.setattr(subprocess, "Popen", forbidden)
        monkeypatch.setattr(subprocess, "run", forbidden)
        ev = load_evidence(repo_root / "examples/synthetic-evidence", cfg)
        assert run_hunt(ev, ruleset, cfg, iocs=load_iocs(repo_root / "examples/iocs.json")).findings

    def test_event_data_is_never_executed(
        self, tmp_path: Path, ruleset: RuleSet, cfg: Config
    ) -> None:
        marker = tmp_path / "pwned"
        payload = f"sh -c 'touch {marker}' $(touch {marker}) `touch {marker}` ; touch {marker}"
        ev_dir = make_evidence(tmp_path / "ev", processes=[{"pid": 1, "name": "sh", "path": "/tmp/x", "cmdline": payload}],
                               logs=json.dumps({"timestamp": "2026-03-10T10:00:00Z", "eventMessage": payload}) + "\n")  # fmt: skip
        run_hunt(load_evidence(ev_dir, cfg), ruleset, cfg)
        assert not marker.exists()

    def test_large_input_is_fast_and_regex_input_bounded(
        self, tmp_path: Path, ruleset: RuleSet, cfg: Config
    ) -> None:
        procs = [
            {
                "pid": i,
                "ppid": 1,
                "name": "sh",
                "path": "/bin/sh",
                "cmdline": "sh -c " + "curl " * 5000,
            }
            for i in range(3000)
        ]
        ev_dir = make_evidence(tmp_path / "ev", processes=procs)
        ev = load_evidence(ev_dir, cfg)
        start = time.monotonic()
        run_hunt(ev, ruleset, cfg)
        assert time.monotonic() - start < 20

    def test_result_dict_shape(
        self, ruleset: RuleSet, cfg: Config, repo_root: Path, hunt_all
    ) -> None:  # type: ignore[no-untyped-def]
        ev = load_evidence(repo_root / "examples/synthetic-evidence", load_config())
        data = result_to_dict(
            ev,
            ruleset,
            hunt_all,
            cfg,
            iocs=None,
            baseline=None,
            rule_dirs=[],
            ioc_path=None,
            baseline_path=None,
        )
        assert data["summary"]["findings_total"] == len(hunt_all.findings)
        assert data["evidence"]["synthetic"] is True and data["limitations"]
        assert set(data["summary"]["by_severity"]) == {
            "critical",
            "high",
            "medium",
            "low",
            "informational",
        }
        assert {"T1059", "T1543.001"} <= set(data["summary"]["attack_techniques_observed"])
