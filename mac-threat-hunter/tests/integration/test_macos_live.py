"""Live collection checks. These run only on macOS (CI uses a macos runner)."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from mac_threat_hunter.cli import main

pytestmark = [
    pytest.mark.macos,
    pytest.mark.skipif(sys.platform != "darwin", reason="requires macOS"),
]


def test_basic_collection_and_hunt_on_this_mac(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    ev = tmp_path / "evidence"
    code = main(["collect", "--profile", "basic", "--output", str(ev)])
    out = capsys.readouterr().out
    assert code == 0, out
    manifest = json.loads((ev / "manifest.json").read_text())
    by_name = {c["collector"]: c for c in manifest["collectors"]}
    assert by_name["system"]["status"] in {"ok", "partial"}
    assert by_name["processes"]["record_count"] > 0
    res = tmp_path / "results"
    assert main(["hunt", "--input", str(ev), "--output", str(res), "--quiet"]) == 0
    data = json.loads((res / "results.json").read_text())
    assert data["evidence"]["synthetic"] is False and data["evidence"]["total_records"] > 0
    assert main(["report", "--input", str(res), "--output", str(tmp_path / "rep")]) == 0


def test_system_record_has_macos_version(tmp_path: Path) -> None:
    ev = tmp_path / "evidence"
    assert main(["collect", "--collectors", "system", "--output", str(ev)]) == 0
    rec = json.loads((ev / "system.json").read_text())["records"][0]
    assert rec["os"]["product_name"] and rec["arch"] in {"arm64", "x86_64"}
