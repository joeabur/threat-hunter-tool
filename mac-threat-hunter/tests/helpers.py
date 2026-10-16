"""Test helpers for building small evidence directories."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from mac_threat_hunter.evidence.manifest import write_evidence
from mac_threat_hunter.models import CollectorResult

COLLECTED = datetime(2026, 3, 10, 14, 30, tzinfo=UTC)


def make_evidence(
    out: Path,
    *,
    system: list[dict[str, Any]] | None = None,
    processes: list[dict[str, Any]] | None = None,
    network: list[dict[str, Any]] | None = None,
    persistence: list[dict[str, Any]] | None = None,
    files: list[dict[str, Any]] | None = None,
    logs: str | None = None,
) -> Path:
    results: list[CollectorResult] = []
    for name, recs in (
        ("system", system), ("processes", processes), ("network", network),
        ("persistence", persistence), ("files", files),
    ):  # fmt: skip
        if recs is not None:
            results.append(CollectorResult(name=name, status="ok", records=recs))
    if logs is not None:
        res = CollectorResult(name="logs", status="ok", raw_files={"unified_log.ndjson": logs})
        res.records = [{} for _ in logs.splitlines()]
        results.append(res)
    write_evidence(
        out, results, profile="test", host={"hostname": "test-mac.example.test"},
        started=COLLECTED, finished=COLLECTED, timezone_offset="+00:00", is_root=False,
        synthetic=True,
    )  # fmt: skip
    return out
