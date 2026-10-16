"""CLI behaviour: documented commands, argument validation and exit codes."""

import json
import re
import sys
from pathlib import Path

import pytest

from conftest import EXAMPLES, RULES
from linux_threat_hunter.cli import main

EV = str(EXAMPLES / "synthetic-evidence")
BASE_EV = str(EXAMPLES / "synthetic-baseline-evidence")
IOCS = str(EXAMPLES / "iocs.json")


def run(capsys: pytest.CaptureFixture[str], *argv: str) -> tuple[int, str, str]:
    code = main(list(argv))
    out = capsys.readouterr()
    return code, out.out, out.err


def test_info_and_doctor(capsys: pytest.CaptureFixture[str]) -> None:
    code, out, _ = run(capsys, "info")
    assert code == 0 and "linux-threat-hunter" in out and "read-only" in out
    code, out, _ = run(capsys, "info", "--json")
    assert json.loads(out)["rules_loaded"] >= 30
    code, out, _ = run(capsys, "doctor")
    assert code == 0 and "doctor result" in out


def test_rules_list_and_validate(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    code, out, _ = run(capsys, "rules", "list")
    assert code == 0 and "LTH-AUTH-001" in out
    code, out, _ = run(capsys, "rules", "list", "--format", "json", "--source", "auth")
    assert {r["id"] for r in json.loads(out)} >= {"LTH-AUTH-001", "LTH-AUTH-002", "LTH-AUTH-004"}
    code, out, _ = run(capsys, "rules", "list", "--format", "markdown")
    assert out.startswith("| Rule |")
    code, out, _ = run(capsys, "rules", "validate")
    assert code == 0 and "0 problem" in out
    (tmp_path / "bad.yaml").write_text("id: nope\n")
    code, _, err = run(capsys, "rules", "validate", "--rules-dir", str(tmp_path))
    assert code == 2 and "INVALID" in err


def test_collect_dry_run_writes_nothing(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    out_dir = tmp_path / "evidence"
    code, out, _ = run(capsys, "collect", "--profile", "basic", "--output", str(out_dir), "--dry-run")
    assert code == 0 and "DRY RUN" in out and "never invokes sudo" in out and "process" in out
    assert not out_dir.exists()


@pytest.mark.skipif(sys.platform != "linux", reason="live collection is Linux-only")
@pytest.mark.linux_only
def test_collect_live_then_hunt(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    ev = tmp_path / "evidence"
    code, out, _ = run(capsys, "collect", "--profile", "basic", "--output", str(ev))
    assert code in (0, 4) and (ev / "manifest.json").exists() and (ev / "host.json").exists()
    code, out, _ = run(capsys, "collect", "--output", str(ev))
    assert code == 1  # refuses to overwrite existing evidence
    code, out, _ = run(capsys, "hunt", "--input", str(ev), "--output", str(tmp_path / "res"))
    assert code == 0 and (tmp_path / "res/results.json").exists()


def test_hunt_report_pipeline(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    base = tmp_path / "baseline.json"
    assert run(capsys, "baseline", "create", "--input", BASE_EV, "--output", str(base))[0] == 0
    res = tmp_path / "results"
    code, out, _ = run(capsys, "hunt", "--input", EV, "--iocs", IOCS, "--baseline", str(base), "--output", str(res))
    assert code == 0 and "Findings:" in out and (res / "results.json").exists()
    rep = tmp_path / "reports"
    code, out, _ = run(capsys, "report", "--input", str(res), "--output", str(rep))
    assert code == 0 and (rep / "summary.md").exists() and (rep / "findings.csv").exists()


def test_hunt_without_optional_inputs_skips_rules(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    res = tmp_path / "r"
    assert run(capsys, "hunt", "--input", EV, "--output", str(res))[0] == 0
    data = json.loads((res / "results.json").read_text())
    reasons = {r["rule_id"]: r["reason"] for r in data["rules"] if r["status"] == "skipped"}
    assert "no IOC file" in reasons["LTH-PROC-002"] and "no baseline" in reasons["LTH-PERS-001"]


def test_fail_on_exit_code(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    args = ["hunt", "--input", EV, "--iocs", IOCS, "--output", str(tmp_path / "r")]
    assert run(capsys, *args, "--fail-on", "critical")[0] == 0  # no baseline: nothing is critical
    assert run(capsys, *args, "--fail-on", "high")[0] == 3
    clean = tmp_path / "clean"
    clean.mkdir()
    assert run(capsys, "hunt", "--input", str(clean), "--output", str(tmp_path / "r2"), "--fail-on", "low")[0] == 0


@pytest.mark.parametrize(
    "argv",
    [
        [],
        ["bogus"],
        ["hunt"],
        ["rules"],
        ["collect", "--output", "x", "--profile", "nope"],
        ["hunt", "--input", "x", "--fail-on", "urgent"],
        ["baseline", "compare", "--input", "x"],
    ],
)
def test_invalid_usage_exits_2(argv: list[str], capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        main(argv)
    assert exc.value.code == 2
    capsys.readouterr()


def test_actionable_errors(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    code, _, err = run(capsys, "hunt", "--input", str(tmp_path / "missing"))
    assert code == 2 and "evidence directory not found" in err
    code, _, err = run(
        capsys, "hunt", "--input", EV, "--iocs", str(tmp_path / "nope.json"), "--output", str(tmp_path / "r")
    )
    assert code == 2 and "IOC file error" in err
    bad = tmp_path / "bad.yaml"
    bad.write_text("limits:\n  max_regex_length: 0\n")
    code, _, err = run(capsys, "info", "--config", str(bad))
    assert code == 2 and "configuration error" in err
    code, _, err = run(capsys, "report", "--input", str(tmp_path), "--output", str(tmp_path / "x"))
    assert code == 2 and "results.json" in err
    code, _, err = run(capsys, "baseline", "compare", "--input", EV, "--baseline", str(tmp_path / "nope.json"))
    assert code == 2 and "cannot read baseline" in err


def test_invalid_rules_block_hunt(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    (tmp_path / "bad.yaml").write_text("id: nope\n")
    code, _, err = run(capsys, "hunt", "--input", EV, "--rules-dir", str(tmp_path), "--output", str(tmp_path / "r"))
    assert code == 2 and "rule validation failed" in err


@pytest.mark.skipif(sys.platform == "win32", reason="symlinks")
def test_output_symlink_refused(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    link = tmp_path / "link"
    link.symlink_to(target)
    code, _, err = run(capsys, "hunt", "--input", EV, "--output", str(link))
    assert code == 1 and "symlink" in err and not list(target.iterdir())
    f = tmp_path / "file"
    f.write_text("x")
    assert run(capsys, "report", "--input", str(tmp_path), "--output", str(f))[0] in (1, 2)


def test_baseline_lifecycle(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    base = tmp_path / "b.json"
    assert run(capsys, "baseline", "create", "--input", BASE_EV, "--output", str(base))[0] == 0
    code, _, err = run(capsys, "baseline", "create", "--input", BASE_EV, "--output", str(base))
    assert code == 1 and "never replaced silently" in err
    code, out, _ = run(capsys, "baseline", "validate", "--baseline", str(base))
    assert code == 0 and "valid" in out
    diff_out = tmp_path / "diff.json"
    code, out, _ = run(capsys, "baseline", "compare", "--input", EV, "--baseline", str(base), "--output", str(diff_out))
    assert code == 0 and "added=" in out and json.loads(diff_out.read_text())["counts"]["added"] > 0
    before = base.read_text()
    code, out, _ = run(capsys, "baseline", "update", "--input", EV, "--baseline", str(base))
    assert code == 0 and "No changes were written" in out and base.read_text() == before  # review only
    code, out, _ = run(capsys, "baseline", "update", "--input", EV, "--baseline", str(base), "--approve")
    assert code == 0 and base.read_text() != before and Path(str(base) + ".bak").read_text() == before
    # after the explicit update, the same evidence has no changes
    code, out, _ = run(capsys, "baseline", "compare", "--input", EV, "--baseline", str(base))
    assert "added=0 removed=0 modified=0" in out
    tampered = json.loads(base.read_text())
    tampered["entries"]["persistence"]["/x"] = {}
    base.write_text(json.dumps(tampered))
    assert run(capsys, "baseline", "validate", "--baseline", str(base))[0] == 2


def test_example_configs_work(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    code, out, _ = run(
        capsys,
        "hunt",
        "--input",
        EV,
        "--config",
        str(EXAMPLES / "configs/auth-threshold-3.yaml"),
        "--output",
        str(tmp_path / "r"),
        "--show",
        "100",
    )
    assert code == 0
    data = json.loads((tmp_path / "r/results.json").read_text())
    ips = {f["entities"].get("ip") for f in data["findings"] if f["rule_id"] == "LTH-AUTH-002"}
    assert "192.0.2.77" in ips  # 3 failures now reach the lowered threshold
    code, _, _ = run(
        capsys,
        "hunt",
        "--input",
        EV,
        "--config",
        str(EXAMPLES / "configs/allowlist-appimage.yaml"),
        "--output",
        str(tmp_path / "r2"),
    )
    data2 = json.loads((tmp_path / "r2/results.json").read_text())
    assert not any("AppRun" in f["title"] for f in data2["findings"] if f["rule_id"] == "LTH-PROC-001")
    st = next(r for r in data2["rules"] if r["rule_id"] == "LTH-PROC-001")
    assert st["suppressed"] == 1


def test_module_entrypoint() -> None:
    import subprocess

    r = subprocess.run(
        [sys.executable, "-m", "linux_threat_hunter", "--version"], capture_output=True, text=True, check=False
    )
    assert r.returncode == 0 and "linux-threat-hunter" in r.stdout
    assert RULES.is_dir()


def test_show_and_trace(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    res = tmp_path / "r"
    assert run(capsys, "hunt", "--input", EV, "--iocs", IOCS, "--output", str(res))[0] == 0
    code, out, _ = run(capsys, "show", "--input", str(res), "--rule", "LTH-PROC-003")
    assert code == 0 and "nginx" in out and "false positives to rule out" in out and "T1059.004" in out
    ref = re.search(r'"record_ref": "([^"]+)"', out)
    assert ref
    code, out, _ = run(capsys, "trace", "--input", EV, "--ref", ref.group(1))
    assert code == 0 and '"pid": 5100' in out
    code, out, _ = run(capsys, "trace", "--input", EV, "--ref", "auth.log#14")
    assert code == 0 and "ssh_failed" in out
    assert run(capsys, "show", "--input", str(res), "--rule", "LTH-NOPE-001")[0] == 2
    assert run(capsys, "trace", "--input", EV, "--ref", "bogus")[0] == 2
    assert run(capsys, "trace", "--input", EV, "--ref", "processes.json#999")[0] == 2
