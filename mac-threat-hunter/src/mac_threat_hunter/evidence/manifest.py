from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from .. import SCHEMA_VERSION, __version__
from ..models import CollectorResult
from ..utils.paths import ensure_output_dir, sha256_bytes
from ..utils.timeutil import to_iso

MANIFEST_NAME = "manifest.json"

# Collector name -> (evidence file, source label)
COLLECTOR_FILES: dict[str, tuple[str, str]] = {
    "system": ("system.json", "system"),
    "processes": ("processes.json", "process"),
    "network": ("network.json", "network"),
    "persistence": ("persistence.json", "persistence"),
    "files": ("files.json", "file"),
    "logs": ("unified_log.ndjson", "log"),
}


def _dump(obj: Any) -> bytes:
    return (json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")


def write_evidence(
    out_dir: Path,
    results: list[CollectorResult],
    *,
    profile: str,
    host: dict[str, Any],
    started: datetime,
    finished: datetime,
    timezone_offset: str,
    is_root: bool,
    synthetic: bool = False,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    ensure_output_dir(out_dir)
    files: list[dict[str, Any]] = []
    for result in results:
        spec = COLLECTOR_FILES.get(result.name)
        if spec is None or result.status in {"unsupported", "skipped", "dry_run"}:
            continue
        name, source = spec
        if result.name == "logs":
            body = ("\n".join(result.raw_files.get(name, "").splitlines()) + "\n").encode("utf-8")
        else:
            body = _dump(
                {
                    "schema_version": SCHEMA_VERSION,
                    "source": source,
                    "collected_at": to_iso(finished),
                    "records": result.records,
                }
            )
        (out_dir / name).write_bytes(body)
        files.append(
            {"name": name, "source": source, "sha256": sha256_bytes(body), "size": len(body)}
        )
    manifest: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "tool": "mac-threat-hunter",
        "tool_version": __version__,
        "synthetic": synthetic,
        "profile": profile,
        "host": host,
        "collection": {
            "started_at": to_iso(started),
            "finished_at": to_iso(finished),
            "local_utc_offset": timezone_offset,
            "ran_as_root": is_root,
        },
        "collectors": [r.to_status() for r in results],
        "files": sorted(files, key=lambda f: f["name"]),
        "notes": [
            "Evidence may contain sensitive process, path and log data. Handle accordingly.",
            "Missing or failed collectors mean missing telemetry, not a clean host.",
        ],
    }
    if extra:
        manifest.update(extra)
    (out_dir / MANIFEST_NAME).write_bytes(_dump(manifest))
    return manifest
