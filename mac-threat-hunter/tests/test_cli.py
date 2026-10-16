from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from mac_threat_hunter.cli import main

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = str(ROOT / "examples" / "synthetic-evidence")
CLEAN = str(ROOT / "examples" / "synthetic-evidence-clean")
IOCS = str(ROOT / "examples" / "iocs.json")
BASELINE = str(ROOT / "examples" / "baselines" / "clean-baseline.json")


def run(capsys: pytest.CaptureFixture[str], *args: str) -> tuple[int, str, str]:
    code = main(list(args))
    out = capsys.readouterr()
    return code, out.out, out.err


class TestDocumentedCommands:
    def test_info(self, capsys) -> None:  # type: ignore[no-untyped-def]
        code, out, _ = run(capsys, "info")
        assert code == 0 and "mac-threat-hunter" in out and "rules_loaded: 36" in out
        code, out, _ = run(capsys, "info", "--json")
        assert json.loads(out)["rules_loaded"] == 36

    def test_doctor(self, capsys) -> None:  # type: ignore[no-untyped-def]
        code, out, _ = run(capsys, "doctor")
        assert code == 0 and "[PASS] 36 rules valid" in out and "read-only" in out

    def test_rules_list_show_validate(self, capsys) -> None:  # type: ignore[no-untyped-def]
        code, out, _ = run(capsys, "rules", "list")
        assert code == 0 and "MTH-EXEC-001" in out and "36 rules" in out
        code, out, _ = run(capsys, "rules", "list", "--source", "log", "--json")
        assert {r["id"] for r in json.loads(out)} >= {"MTH-LOG-001", "MTH-SCRIPT-001"}
        code, out, _ = run(capsys, "rules", "show", "MTH-NET-001")
        assert code == 0 and "id: MTH-NET-001" in out
        assert run(capsys, "rules", "show", "MTH-NOPE-999")[0] == 3
        code, out, _ = run(capsys, "rules", "validate")
        assert code == 0 and out.startswith("OK: 36 rules valid")

    def test_hunt_basic_ioc_baseline(self, capsys, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
        res = tmp_path / "results"
        code, out, _ = run(capsys, "hunt", "--input", EVIDENCE, "--output", str(res))
        assert code == 0 and "SYNTHETIC DATA" in out and (res / "results.json").exists()
        base = json.loads((res / "results.json").read_text())["summary"]["findings_total"]
        run(capsys, "hunt", "--input", EVIDENCE, "--iocs", IOCS, "--output", str(res), "--quiet")
        with_ioc = json.loads((res / "results.json").read_text())["summary"]
        assert with_ioc["ioc_matches"] == 10 and with_ioc["findings_total"] > base
        run(
            capsys,
            "hunt",
            "--input",
            EVIDENCE,
            "--iocs",
            IOCS,
            "--baseline",
            BASELINE,
            "--output",
            str(res),
            "--quiet",
        )
        full = json.loads((res / "results.json").read_text())
        assert full["summary"]["findings_total"] == 49 and full["summary"]["baseline_changes"] == 11

    def test_baseline_create_validate_compare(self, capsys, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
        b = tmp_path / "baseline.json"
        code, out, _ = run(capsys, "baseline", "create", "--input", CLEAN, "--output", str(b))
        assert code == 0 and "compromise" in out and b.exists()
        assert run(capsys, "baseline", "validate", "--baseline", str(b))[0] == 0
        code, out, _ = run(capsys, "baseline", "compare", "--input", CLEAN, "--baseline", str(b))
        assert code == 0 and "No differences" in out
        d = tmp_path / "diff.json"
        code, out, _ = run(
            capsys,
            "baseline",
            "compare",
            "--input",
            EVIDENCE,
            "--baseline",
            str(b),
            "--output",
            str(d),
        )
        assert code == 0 and "ADDED" in out and "MODIFIED" in out and "persistence" in out
        assert json.loads(d.read_text())["changes"]

    def test_report(self, capsys, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
        res, rep = tmp_path / "results", tmp_path / "reports"
        run(
            capsys,
            "hunt",
            "--input",
            EVIDENCE,
            "--iocs",
            IOCS,
            "--baseline",
            BASELINE,
            "--output",
            str(res),
            "--quiet",
        )
        code, out, _ = run(capsys, "report", "--input", str(res), "--output", str(rep))
        assert code == 0 and {p.name for p in rep.iterdir()} == {
            "report.md",
            "findings.json",
            "findings.csv",
        }
        code, _, _ = run(
            capsys,
            "report",
            "--input",
            str(res / "results.json"),
            "--output",
            str(tmp_path / "md"),
            "--formats",
            "md",
        )
        assert code == 0 and [p.name for p in (tmp_path / "md").iterdir()] == ["report.md"]


class TestCollectCommand:
    def test_dry_run_plans_and_writes_nothing(self, capsys, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
        out_dir = tmp_path / "evidence"
        code, out, _ = run(
            capsys, "collect", "--profile", "full", "--output", str(out_dir), "--dry-run"
        )
        assert code == 0 and "DRY RUN" in out and "/bin/ps" in out and "log show" in out
        assert "access:" in out and not out_dir.exists()

    def test_non_macos_reports_unsupported_and_exits_5(
        self, capsys, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:  # type: ignore[no-untyped-def]
        monkeypatch.setattr(sys, "platform", "linux")
        out_dir = tmp_path / "evidence"
        code, out, _ = run(capsys, "collect", "--profile", "basic", "--output", str(out_dir))
        assert code == 5 and "unsupported" in out
        manifest = json.loads((out_dir / "manifest.json").read_text())
        assert {c["status"] for c in manifest["collectors"]} == {"unsupported"} and manifest[
            "files"
        ] == []

    def test_log_import_works_off_macos(
        self, capsys, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:  # type: ignore[no-untyped-def]
        monkeypatch.setattr(sys, "platform", "linux")
        export = tmp_path / "export.ndjson"
        export.write_text(Path(EVIDENCE, "unified_log.ndjson").read_text())
        out_dir = tmp_path / "ev"
        code, out, _ = run(
            capsys,
            "collect",
            "--collectors",
            "logs",
            "--log-file",
            str(export),
            "--output",
            str(out_dir),
        )
        assert code == 0
        code, out, _ = run(capsys, "hunt", "--input", str(out_dir), "--output", str(tmp_path / "r"))
        assert code == 0 and "Findings:" in out
        found = json.loads((tmp_path / "r/results.json").read_text())
        assert {f["rule_id"] for f in found["findings"]} >= {"MTH-LOG-001", "MTH-SCRIPT-001"}

    def test_existing_evidence_not_overwritten(
        self, capsys, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:  # type: ignore[no-untyped-def]
        monkeypatch.setattr(sys, "platform", "linux")
        out_dir = tmp_path / "e"
        run(capsys, "collect", "--output", str(out_dir))
        code, _, err = run(capsys, "collect", "--output", str(out_dir))
        assert code == 2 and "--overwrite" in err
        assert run(capsys, "collect", "--output", str(out_dir), "--overwrite")[0] == 5

    @pytest.mark.parametrize("args", [["--profile", "nope"], ["--collectors", "system,evil"],
                                      ["--collectors", "logs", "--last", "9y"],
                                      ["--collectors", "logs", "--predicate", 'process == "a"; id']])  # fmt: skip
    def test_bad_collect_arguments(self, capsys, tmp_path: Path, args: list[str]) -> None:  # type: ignore[no-untyped-def]
        code, _, err = run(capsys, "collect", "--output", str(tmp_path / "x"), *args)
        assert code == 2, (code, err)


class TestExitCodesAndErrors:
    def test_usage_errors_exit_2(self, capsys) -> None:  # type: ignore[no-untyped-def]
        for args in (
            ["bogus"],
            [],
            ["hunt"],
            ["hunt", "--input"],
            ["rules"],
            ["baseline", "create"],
            ["hunt", "--input", "x", "--fail-on", "scary"],
        ):
            assert run(capsys, *args)[0] == 2, args

    def test_input_errors_exit_3(self, capsys, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
        code, _, err = run(capsys, "hunt", "--input", str(tmp_path / "missing"))
        assert code == 3 and "not found" in err
        assert (
            run(capsys, "hunt", "--input", EVIDENCE, "--iocs", str(tmp_path / "nope.json"))[0] == 3
        )
        assert run(capsys, "report", "--input", str(tmp_path))[0] == 3

    def test_validation_errors_exit_4(self, capsys, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
        bad = tmp_path / "rules"
        bad.mkdir()
        (bad / "r.yaml").write_text("id: nope\n")
        code, _, err = run(capsys, "rules", "validate", str(bad))
        assert code == 4 and "INVALID" in err
        code, _, err = run(
            capsys,
            "hunt",
            "--input",
            EVIDENCE,
            "--rules",
            str(bad),
            "--output",
            str(tmp_path / "o"),
        )
        assert code == 4 and "refusing to hunt" in err
        iocs = tmp_path / "i.json"
        iocs.write_text(json.dumps({"indicators": [{"type": "ip", "value": "bad"}]}))
        code, _, err = run(
            capsys,
            "hunt",
            "--input",
            EVIDENCE,
            "--iocs",
            str(iocs),
            "--output",
            str(tmp_path / "o"),
        )
        assert code == 4 and "ip" in err
        cfg = tmp_path / "c.yaml"
        cfg.write_text(
            "limits: {max_rules: -1}\nsuppressions: [{rule_id: MTH-NET-001}]\nbogus: 1\n"
        )
        code, _, err = run(capsys, "info", "--config", str(cfg))
        assert code == 4 and "unknown top-level key" in err and "reason is required" in err

    def test_fail_on_threshold(self, capsys, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
        out = str(tmp_path / "o")
        assert (
            run(
                capsys,
                "hunt",
                "--input",
                EVIDENCE,
                "--output",
                out,
                "--quiet",
                "--fail-on",
                "critical",
            )[0]
            == 0
        )
        assert (
            run(
                capsys, "hunt", "--input", EVIDENCE, "--output", out, "--quiet", "--fail-on", "high"
            )[0]
            == 1
        )
        assert (
            run(
                capsys,
                "hunt",
                "--input",
                CLEAN,
                "--output",
                out,
                "--quiet",
                "--fail-on",
                "informational",
            )[0]
            == 0
        )

    def test_tampered_baseline_rejected(self, capsys, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
        doc = json.loads(Path(BASELINE).read_text())
        doc["observations"]["files"]["/etc/hosts"]["sha256"] = "0" * 64
        bad = tmp_path / "b.json"
        bad.write_text(json.dumps(doc))
        code, _, err = run(capsys, "baseline", "validate", "--baseline", str(bad))
        assert code == 4 and "integrity hash mismatch" in err
        assert (
            run(
                capsys,
                "hunt",
                "--input",
                EVIDENCE,
                "--baseline",
                str(bad),
                "--output",
                str(tmp_path / "o"),
            )[0]
            == 4
        )

    def test_reports_flag_unknown_formats(self, capsys, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
        res = tmp_path / "r"
        run(capsys, "hunt", "--input", EVIDENCE, "--output", str(res), "--quiet")
        assert run(capsys, "report", "--input", str(res), "--formats", "html")[0] == 2

    def test_path_traversal_in_evidence_manifest(self, capsys, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
        ev = tmp_path / "ev"
        ev.mkdir()
        (ev / "manifest.json").write_text(
            json.dumps({"files": [{"name": "../../etc/passwd", "source": "process"}]})
        )
        code, out, _ = run(capsys, "hunt", "--input", str(ev), "--output", str(tmp_path / "o"))
        assert code == 0 and "WARNING" in out and "passwd" in out


class TestBaselineUpdateWorkflow:
    def test_never_silent(self, capsys, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
        b = tmp_path / "b.json"
        run(capsys, "baseline", "create", "--input", CLEAN, "--output", str(b))
        original = b.read_text()
        # create refuses to replace an existing baseline
        code, _, err = run(capsys, "baseline", "create", "--input", CLEAN, "--output", str(b))
        assert code == 2 and "never replaced silently" in err
        # update without --accept only reviews
        code, out, _ = run(
            capsys, "baseline", "update", "--input", EVIDENCE, "--baseline", str(b), "--in-place"
        )
        assert (
            code == 0
            and "REVIEW REQUIRED" in out
            and "Nothing was written" in out
            and b.read_text() == original
        )
        # --accept requires an explicit destination
        assert (
            run(
                capsys, "baseline", "update", "--input", EVIDENCE, "--baseline", str(b), "--accept"
            )[0]
            == 2
        )
        new = tmp_path / "new.json"
        code, out, _ = run(
            capsys,
            "baseline",
            "update",
            "--input",
            EVIDENCE,
            "--baseline",
            str(b),
            "--accept",
            "--output",
            str(new),
        )
        assert code == 0 and new.exists() and b.read_text() == original
        assert run(capsys, "baseline", "validate", "--baseline", str(new))[0] == 0
        # a second update onto the same path is refused
        assert (
            run(
                capsys,
                "baseline",
                "update",
                "--input",
                EVIDENCE,
                "--baseline",
                str(b),
                "--accept",
                "--output",
                str(new),
            )[0]
            == 2
        )
        # in-place keeps a backup
        code, out, _ = run(
            capsys,
            "baseline",
            "update",
            "--input",
            EVIDENCE,
            "--baseline",
            str(b),
            "--accept",
            "--in-place",
        )
        assert code == 0 and "Previous baseline kept" in out
        assert any(p.name.startswith("b.json.bak-") for p in tmp_path.iterdir())
        code, out, _ = run(capsys, "baseline", "compare", "--input", EVIDENCE, "--baseline", str(b))
        assert "No differences" in out
