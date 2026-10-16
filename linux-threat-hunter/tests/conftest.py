"""Shared fixtures. Everything is synthetic: no root, no network, no real host data."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from linux_threat_hunter.baseline import compare, create_baseline
from linux_threat_hunter.config import load_config
from linux_threat_hunter.detections import load_catalog
from linux_threat_hunter.evidence import load_evidence
from linux_threat_hunter.ioc import load_iocs
from linux_threat_hunter.rules_engine import Engine

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples"
RULES = ROOT / "rules"


@pytest.fixture(scope="session")
def config() -> dict[str, Any]:
    return load_config()


@pytest.fixture(scope="session")
def rules(config: dict[str, Any]) -> list[Any]:
    loaded, errors = load_catalog(RULES, config)
    assert not errors, errors
    return loaded


@pytest.fixture()
def make_evidence(tmp_path: Path, config: dict[str, Any]) -> Callable[..., Any]:
    """Build an evidence directory from python objects and load it."""

    def _make(
        *,
        processes: list[dict[str, Any]] | None = None,
        persistence: list[dict[str, Any]] | None = None,
        network: list[dict[str, Any]] | None = None,
        files: list[dict[str, Any]] | None = None,
        events: list[dict[str, Any]] | None = None,
        auth: str | None = None,
        collected_at: str = "2025-10-14T09:00:00Z",
        timezone: str = "UTC",
        name: str = "ev",
    ) -> Any:
        d = tmp_path / name
        d.mkdir(exist_ok=True)
        (d / "manifest.json").write_text(
            json.dumps({"schema_version": 1, "collected_at": collected_at, "timezone": timezone, "synthetic": True})
        )
        for fname, data in (
            ("processes.json", processes),
            ("persistence.json", persistence),
            ("network.json", network),
            ("files.json", files),
            ("events.json", events),
        ):
            if data is not None:
                (d / fname).write_text(json.dumps(data))
        if auth is not None:
            (d / "auth.log").write_text(auth)
        return load_evidence(d, config)

    return _make


@pytest.fixture(scope="session")
def synthetic_result(config: dict[str, Any], rules: list[Any]) -> Any:
    ev = load_evidence(EXAMPLES / "synthetic-evidence", config)
    base_ev = load_evidence(EXAMPLES / "synthetic-baseline-evidence", config)
    baseline = create_baseline(base_ev)
    diff = compare(baseline, ev)
    iocs = load_iocs(EXAMPLES / "iocs.json", config["limits"])
    hunt = Engine(rules, config, iocs, diff).run(ev)
    return ev, hunt, diff
