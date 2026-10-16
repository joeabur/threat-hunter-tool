"""Safe loading of an evidence directory into normalised records."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from ..config import Config, make_redactor
from ..models import Record
from ..parsers.common import NormalizeContext
from ..parsers.files import normalize_files
from ..parsers.logs import parse_log_text
from ..parsers.network import normalize_network
from ..parsers.persistence import normalize_persistence
from ..parsers.process import normalize_processes
from ..parsers.system import normalize_system
from ..utils.errors import InputError, PathSafetyError
from ..utils.paths import read_bytes_bounded, resolve_within, sha256_bytes
from ..utils.timeutil import parse_timestamp
from .manifest import COLLECTOR_FILES, MANIFEST_NAME

_JSON_SOURCES = {"system", "process", "network", "persistence", "file"}


@dataclass
class EvidenceSet:
    path: Path
    manifest: dict[str, Any] | None
    host: dict[str, Any]
    collected_at: datetime | None
    records: dict[str, list[Record]] = field(default_factory=dict)
    raw_counts: dict[str, int] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    integrity_failures: list[str] = field(default_factory=list)
    collector_status: list[dict[str, Any]] = field(default_factory=list)
    files_loaded: list[str] = field(default_factory=list)
    malformed_log_lines: int = 0
    truncated_sources: list[str] = field(default_factory=list)
    sources_loaded: list[str] = field(default_factory=list)

    @property
    def hostname(self) -> str | None:
        value = self.host.get("hostname") if self.host else None
        return str(value) if value else None

    def total_records(self) -> int:
        return sum(len(v) for v in self.records.values())

    def files_loaded_sources(self) -> set[str]:
        """Sources for which an evidence file was actually loaded."""
        return set(self.sources_loaded)

    @property
    def synthetic(self) -> bool:
        return bool(self.manifest and self.manifest.get("synthetic"))


def _parse_offset(text: str | None) -> timezone | None:
    if not text or len(text) < 6:
        return None
    try:
        sign = -1 if text[0] == "-" else 1
        hours, minutes = int(text[1:3]), int(text[4:6])
        return timezone(sign * timedelta(hours=hours, minutes=minutes))
    except ValueError:
        return None


def _load_json_file(path: Path, limit: int) -> Any:
    data = read_bytes_bounded(path, limit)
    try:
        return json.loads(data.decode("utf-8", errors="replace")), data
    except json.JSONDecodeError as exc:
        raise InputError(f"{path.name}: invalid JSON ({exc.msg} at line {exc.lineno})") from exc


def load_evidence(directory: Path, config: Config) -> EvidenceSet:
    if directory.is_symlink():
        raise PathSafetyError(f"evidence directory must not be a symlink: {directory}")
    if not directory.is_dir():
        raise InputError(f"evidence directory not found: {directory}")
    limit = config.limit("max_evidence_file_mb") * 1024 * 1024
    max_records = config.limit("max_records_per_source")

    manifest: dict[str, Any] | None = None
    warnings: list[str] = []
    manifest_path = directory / MANIFEST_NAME
    if manifest_path.exists():
        manifest, _ = _load_json_file(manifest_path, limit)
        if not isinstance(manifest, dict) or not isinstance(manifest.get("files"), list):
            raise InputError("manifest.json is malformed (expected an object with a 'files' list)")
    else:
        warnings.append(
            "No manifest.json: file integrity cannot be verified and collection scope is unknown."
        )

    host = dict(manifest.get("host", {})) if manifest else {}
    collection = manifest.get("collection", {}) if manifest else {}
    finished = parse_timestamp(collection.get("finished_at")).utc if collection else None
    offset = _parse_offset(collection.get("local_utc_offset")) if collection else None

    # Decide which files to read: manifest entries (hash-checked) or conventional names.
    to_read: list[tuple[str, str, str | None]] = []  # (name, source, expected_sha)
    if manifest:
        source_by_name = dict(COLLECTOR_FILES.values())
        for entry in manifest["files"]:
            if not isinstance(entry, dict) or not isinstance(entry.get("name"), str):
                warnings.append("manifest contains a malformed file entry; ignored")
                continue
            name = entry["name"]
            source = entry.get("source") or source_by_name.get(name)
            if source not in _JSON_SOURCES | {"log"}:
                warnings.append(
                    f"manifest lists {name} with unsupported source {source!r}; ignored"
                )
                continue
            to_read.append((name, source, entry.get("sha256")))
    else:
        for name, source in COLLECTOR_FILES.values():
            if (directory / name).exists():
                to_read.append((name, source, None))
        if not to_read:
            raise InputError(
                f"{directory} has no manifest.json and no recognised evidence files "
                f"({', '.join(n for n, _ in COLLECTOR_FILES.values())})"
            )

    ev = EvidenceSet(
        path=directory,
        manifest=manifest,
        host=host,
        collected_at=finished,
        warnings=warnings,
        collector_status=list(manifest.get("collectors", [])) if manifest else [],
    )
    redactor = make_redactor(config)
    ctx = NormalizeContext(
        redactor=redactor,
        script_interpreters=config.allowlists.get("script_interpreters", []),
        collected_at=finished,
        assume_offset=offset,
    )

    raw_by_source: dict[str, list[dict[str, Any]]] = {}
    for name, source, expected in to_read:
        try:
            path = resolve_within(directory, name)
            if not path.exists():
                ev.warnings.append(f"{name}: listed in manifest but missing")
                continue
            data = read_bytes_bounded(path, limit)
        except InputError as exc:
            ev.warnings.append(f"{name}: skipped ({exc})")
            continue
        if expected and sha256_bytes(data) != expected:
            ev.integrity_failures.append(name)
            ev.warnings.append(
                f"{name}: SHA-256 does not match manifest; the file changed after collection. "
                "Treat results derived from it as unreliable."
            )
        ev.files_loaded.append(name)
        ev.sources_loaded.append(source)
        if source == "log":
            result = parse_log_text(data.decode("utf-8", errors="replace"), name, ctx, max_records)
            ev.records.setdefault("log", []).extend(result.records)
            ev.raw_counts["log"] = ev.raw_counts.get("log", 0) + result.total_lines
            ev.malformed_log_lines += result.malformed_lines
            if result.total_lines > len(result.records) + result.malformed_lines:
                ev.truncated_sources.append("log")
            continue
        try:
            doc = json.loads(data.decode("utf-8", errors="replace"))
        except json.JSONDecodeError as exc:
            ev.warnings.append(f"{name}: invalid JSON ({exc.msg}, line {exc.lineno}); skipped")
            continue
        records = doc.get("records") if isinstance(doc, dict) else doc
        if not isinstance(records, list):
            ev.warnings.append(f"{name}: expected a list of records; skipped")
            continue
        if len(records) > max_records:
            ev.truncated_sources.append(source)
            ev.warnings.append(
                f"{name}: {len(records)} records exceed max_records_per_source={max_records}; "
                "extra records ignored"
            )
            records = records[:max_records]
        bad = sum(1 for r in records if not isinstance(r, dict))
        if bad:
            ev.warnings.append(f"{name}: {bad} non-object records ignored")
        raw_by_source.setdefault(source, []).extend(r for r in records if isinstance(r, dict))
        ev.raw_counts[source] = ev.raw_counts.get(source, 0) + len(records)
        if ev.collected_at is None and isinstance(doc, dict):
            ev.collected_at = parse_timestamp(doc.get("collected_at")).utc
            ctx.collected_at = ev.collected_at

    # Normalise. Processes first so network records can join on pid.
    proc_file = next((n for n, s, _ in to_read if s == "process"), "processes.json")
    ev.records["process"] = normalize_processes(raw_by_source.get("process", []), proc_file, ctx)
    process_by_pid = {
        p["pid"]: p for p in raw_by_source.get("process", []) if isinstance(p.get("pid"), int)
    }
    file_for = {s: n for n, s, _ in to_read}
    ev.records["network"] = normalize_network(
        raw_by_source.get("network", []),
        file_for.get("network", "network.json"),
        ctx,
        process_by_pid,
    )
    ev.records["persistence"] = normalize_persistence(
        raw_by_source.get("persistence", []), file_for.get("persistence", "persistence.json"), ctx
    )
    ev.records["file"] = normalize_files(
        raw_by_source.get("file", []), file_for.get("file", "files.json"), ctx
    )
    ev.records["system"] = normalize_system(
        raw_by_source.get("system", []), file_for.get("system", "system.json"), ctx
    )
    ev.records.setdefault("log", [])
    if not ev.host and ev.records["system"]:
        ev.host = {"hostname": ev.records["system"][0].data.get("hostname")}
    return ev
