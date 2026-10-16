"""Evidence directory format: loading (with safety checks) and writing."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from linux_threat_hunter import __version__
from linux_threat_hunter.models import Record
from linux_threat_hunter.parsers.auth import parse_auth_log
from linux_threat_hunter.parsers.persistence import normalize_artifact
from linux_threat_hunter.utils.safe import (
    UnsafePathError,
    atomic_write_text,
    read_regular_file,
    sha256_bytes,
)
from linux_threat_hunter.utils.timeutil import get_tz, parse_iso, to_iso

JSON_SOURCES = {
    "processes.json": "process",
    "persistence.json": "persistence",
    "network.json": "network",
    "files.json": "file",
    "events.json": "event",
}
AUTH_FILE = "auth.log"
HOST_FILE = "host.json"
MANIFEST_FILE = "manifest.json"
ALL_FILES = [*JSON_SOURCES, AUTH_FILE, HOST_FILE]


class EvidenceError(ValueError):
    """Raised when the evidence directory is unusable."""


@dataclass
class EvidenceSet:
    root: Path
    manifest: dict[str, Any]
    host: dict[str, Any]
    records: dict[str, list[Record]] = field(default_factory=dict)
    available: set[str] = field(default_factory=set)
    warnings: list[str] = field(default_factory=list)
    collected_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    timezone_name: str = "UTC"
    file_hashes: dict[str, str] = field(default_factory=dict)
    parse_stats: dict[str, Any] = field(default_factory=dict)

    def of(self, source: str) -> list[Record]:
        return self.records.get(source, [])

    @property
    def total_records(self) -> int:
        return sum(len(v) for v in self.records.values())


def _load_json_list(root: Path, name: str, limit: int, max_records: int, warnings: list[str]) -> list[Any] | None:
    path = root / name
    if not path.exists() and not path.is_symlink():
        return None
    try:
        raw = read_regular_file(path, limit)
        data = json.loads(raw.decode("utf-8"))
    except (UnsafePathError, OSError, ValueError) as exc:
        warnings.append(f"{name}: unusable ({exc}); source treated as unavailable")
        return None
    if not isinstance(data, list):
        warnings.append(f"{name}: expected a JSON list; source treated as unavailable")
        return None
    if len(data) > max_records:
        warnings.append(f"{name}: truncated to {max_records} records (limit)")
        data = data[:max_records]
    return data


def load_evidence(path: str | Path, config: dict[str, Any]) -> EvidenceSet:
    """Load an evidence directory. Malformed or missing parts degrade to warnings."""
    root = Path(path)
    if not root.is_dir():
        raise EvidenceError(f"evidence directory not found: {root}")
    limits = config["limits"]
    warnings: list[str] = []
    manifest: dict[str, Any] = {}
    mpath = root / MANIFEST_FILE
    if mpath.exists():
        try:
            loaded = json.loads(read_regular_file(mpath, limits["max_evidence_file_bytes"]))
            manifest = loaded if isinstance(loaded, dict) else {}
            if not manifest:
                warnings.append("manifest.json: expected a JSON object")
        except (UnsafePathError, OSError, ValueError) as exc:
            warnings.append(f"manifest.json: unusable ({exc})")
    else:
        warnings.append("manifest.json missing: collection time/timezone unknown, using now/UTC")

    collected = parse_iso(str(manifest.get("collected_at", ""))) if manifest else None
    if collected is None:
        collected = datetime.now(UTC)
        if manifest:
            warnings.append("manifest.collected_at missing or not ISO-8601 with offset")
    tz_name = str(manifest.get("timezone", "UTC"))
    tz = get_tz(tz_name)

    host: dict[str, Any] = {}
    host_list = _load_json_obj(root, HOST_FILE, limits["max_evidence_file_bytes"], warnings)
    if host_list is not None:
        host = host_list

    ev = EvidenceSet(
        root=root,
        manifest=manifest,
        host=host,
        collected_at=collected,
        timezone_name=tz_name,
        warnings=warnings,
    )

    for name, rtype in JSON_SOURCES.items():
        items = _load_json_list(
            root,
            name,
            limits["max_evidence_file_bytes"],
            limits["max_records_per_source"],
            warnings,
        )
        if items is None:
            continue
        ev.available.add(rtype)
        recs: list[Record] = []
        for i, item in enumerate(items):
            if not isinstance(item, dict):
                warnings.append(f"{name}[{i}]: not an object, skipped")
                continue
            if rtype == "persistence":
                for j, d in enumerate(normalize_artifact(item)):
                    if j:
                        d["_derived_from"] = f"{name}#{i}"
                    recs.append(Record(rtype, d, name, i, None))
                continue
            ts = None
            if rtype == "event":
                ts = parse_iso(str(item.get("timestamp", "")))
                item["timezone_context"] = "offset from source timestamp"
                if ts is None:
                    item["timestamp_unparsed"] = True
            recs.append(Record(rtype, item, name, i, ts))
        ev.records[rtype] = recs

    _enrich(ev)
    _load_auth(ev, root, config, tz)
    _record_hashes(ev, root, limits["max_evidence_file_bytes"])
    return ev


def _load_json_obj(root: Path, name: str, limit: int, warnings: list[str]) -> dict[str, Any] | None:
    path = root / name
    if not path.exists():
        return None
    try:
        data = json.loads(read_regular_file(path, limit))
    except (UnsafePathError, OSError, ValueError) as exc:
        warnings.append(f"{name}: unusable ({exc})")
        return None
    return data if isinstance(data, dict) else None


def _load_auth(ev: EvidenceSet, root: Path, config: dict[str, Any], tz: Any) -> None:
    path = root / AUTH_FILE
    if not path.exists():
        return
    try:
        text = read_regular_file(path, config["limits"]["max_evidence_file_bytes"]).decode("utf-8", errors="replace")
    except (UnsafePathError, OSError) as exc:
        ev.warnings.append(f"{AUTH_FILE}: unusable ({exc}); source treated as unavailable")
        return
    events, stats = parse_auth_log(
        text,
        reference=ev.collected_at,
        tz=tz,
        max_lines=config["limits"]["max_records_per_source"],
        max_len=config["limits"]["max_line_length"],
    )
    ev.available.add("auth")
    ev.parse_stats["auth"] = stats
    if stats["truncated"]:
        ev.warnings.append("auth.log: line limit reached, remaining lines ignored")
    if stats["no_timestamp"]:
        ev.warnings.append(f"auth.log: {stats['no_timestamp']} events had unparseable timestamps")
    ev.records["auth"] = [
        Record(
            "auth",
            e,
            AUTH_FILE,
            e["line_no"],
            parse_iso(e["timestamp"]) if e["timestamp"] else None,
        )
        for e in events
    ]


def _enrich(ev: EvidenceSet) -> None:
    procs = {r.data.get("pid"): r.data for r in ev.of("process") if r.data.get("pid") is not None}
    for r in ev.of("process"):
        parent = procs.get(r.data.get("ppid"))
        if parent:
            r.data.setdefault("parent_name", parent.get("name"))
            r.data.setdefault("parent_exe", parent.get("exe"))
    for r in ev.of("network"):
        proc = procs.get(r.data.get("pid"))
        if proc:
            r.data.setdefault("process_exe", proc.get("exe"))
            r.data.setdefault("process_user", proc.get("user"))
            r.data.setdefault("process_sha256", proc.get("sha256"))


def _record_hashes(ev: EvidenceSet, root: Path, limit: int) -> None:
    expected = ev.manifest.get("files", {}) if isinstance(ev.manifest.get("files"), dict) else {}
    for name in ALL_FILES:
        p = root / name
        if p.is_file() and not p.is_symlink():
            try:
                digest = sha256_bytes(read_regular_file(p, limit))
            except (OSError, UnsafePathError):
                continue
            ev.file_hashes[name] = digest
            want = expected.get(name)
            if want and want != digest:
                ev.warnings.append(f"{name}: SHA-256 does not match manifest (evidence modified?)")


def write_evidence(out: Path, manifest: dict[str, Any], sources: dict[str, Any]) -> None:
    """Write evidence files + manifest (with per-file hashes). ``sources`` maps filename -> data."""
    out.mkdir(parents=True, exist_ok=True)
    hashes: dict[str, str] = {}
    for name, data in sources.items():
        text = data if isinstance(data, str) else json.dumps(data, indent=2, sort_keys=True) + "\n"
        atomic_write_text(out / name, text)
        hashes[name] = sha256_bytes(text.encode("utf-8"))
    manifest = dict(manifest)
    manifest["files"] = hashes
    manifest["tool_version"] = __version__
    manifest.setdefault("written_at", to_iso(datetime.now(UTC)))
    atomic_write_text(out / MANIFEST_FILE, json.dumps(manifest, indent=2, sort_keys=True) + "\n")
