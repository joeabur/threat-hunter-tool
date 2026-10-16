"""Baselines of selected observations, with added/removed/modified comparison.

A baseline is a point-in-time record. It can contain malicious state if the host was
already compromised, goes stale after legitimate updates, and its integrity hash only
detects accidental damage (anyone who can rewrite the file can recompute the hash).
"""

from __future__ import annotations

import hashlib
import json
import shutil
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from linux_threat_hunter import __version__
from linux_threat_hunter.evidence.store import EvidenceSet
from linux_threat_hunter.parsers.persistence import FILE_LEVEL_KINDS
from linux_threat_hunter.utils.safe import UnsafePathError, atomic_write_text, read_regular_file
from linux_threat_hunter.utils.timeutil import to_iso

SCHEMA_VERSION = 1
CATEGORIES = ("persistence", "files", "executables", "listeners", "privileged_users")
SOURCE_FOR = {
    "persistence": "persistence",
    "files": "file",
    "executables": "process",
    "listeners": "network",
    "privileged_users": "auth",
}


class BaselineError(ValueError):
    pass


def build_entries(ev: EvidenceSet) -> dict[str, dict[str, dict[str, Any]]]:
    """Derive baseline entries from evidence, only for sources that are present."""
    out: dict[str, dict[str, dict[str, Any]]] = {}
    if "persistence" in ev.available:
        pers: dict[str, dict[str, Any]] = {}
        for r in ev.of("persistence"):
            d = r.data
            if d.get("kind") in FILE_LEVEL_KINDS and d.get("path"):
                pers[d["path"]] = {k: d.get(k) for k in ("kind", "owner", "mode", "sha256", "exec_path")}
        out["persistence"] = pers
    if "file" in ev.available:
        out["files"] = {
            r.data["path"]: {k: r.data.get(k) for k in ("owner", "mode", "sha256")}
            for r in ev.of("file")
            if r.data.get("path") and not r.data.get("source_dir")
        }
    if "process" in ev.available:
        out["executables"] = {
            r.data["exe"]: {"sha256": r.data["sha256"]}
            for r in ev.of("process")
            if r.data.get("exe") and r.data.get("sha256")
        }
    if "network" in ev.available:
        out["listeners"] = {
            f"{r.data.get('proto')}/{r.data.get('local_addr')}:{r.data.get('local_port')}": {
                "process": r.data.get("process")
            }
            for r in ev.of("network")
            if r.data.get("listening")
        }
    if "auth" in ev.available:
        out["privileged_users"] = {
            str(r.data["user"]): {"seen": True}
            for r in ev.of("auth")
            if r.data.get("event") == "sudo_command" and r.data.get("user")
        }
    return out


def _digest(entries: dict[str, Any], categories: list[str]) -> str:
    blob = json.dumps(
        {"schema_version": SCHEMA_VERSION, "categories": categories, "entries": entries},
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(blob.encode()).hexdigest()


def create_baseline(ev: EvidenceSet) -> dict[str, Any]:
    entries = build_entries(ev)
    cats = [c for c in CATEGORIES if c in entries]
    return {
        "schema_version": SCHEMA_VERSION,
        "created_at": to_iso(datetime.now(UTC)),
        "tool_version": __version__,
        "source_hostname": ev.host.get("hostname") or ev.manifest.get("hostname"),
        "source_collected_at": to_iso(ev.collected_at),
        "categories": cats,
        "entries": entries,
        "integrity_sha256": _digest(entries, cats),
        "warning": (
            "A baseline records whatever state existed when it was created, including "
            "malicious state. Review it before trusting it and re-review after updates."
        ),
    }


def validate_baseline(data: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(data, dict):
        return ["baseline must be a JSON object"]
    if data.get("schema_version") != SCHEMA_VERSION:
        errors.append(f"schema_version must be {SCHEMA_VERSION}")
    cats, entries = data.get("categories"), data.get("entries")
    if not isinstance(cats, list) or not set(cats) <= set(CATEGORIES):
        errors.append(f"categories must be a subset of {list(CATEGORIES)}")
        return errors
    if not isinstance(entries, dict) or set(entries) != set(cats):
        errors.append("entries must contain exactly the listed categories")
        return errors
    for cat, items in entries.items():
        if not isinstance(items, dict) or not all(isinstance(v, dict) for v in items.values()):
            errors.append(f"entries.{cat}: must map keys to attribute objects")
    if not errors and data.get("integrity_sha256") != _digest(entries, cats):
        errors.append("integrity_sha256 mismatch: baseline was modified or corrupted")
    return errors


def load_baseline(path: str | Path, limit: int = 52428800) -> dict[str, Any]:
    try:
        data = json.loads(read_regular_file(Path(path), limit))
    except (OSError, UnsafePathError, ValueError) as exc:
        raise BaselineError(f"cannot read baseline {path}: {exc}") from exc
    errs = validate_baseline(data)
    if errs:
        raise BaselineError("invalid baseline: " + "; ".join(errs))
    return data


def save_baseline(path: Path, data: dict[str, Any], *, overwrite: bool = False) -> Path | None:
    """Write a baseline. An existing file is only replaced with ``overwrite=True`` and is
    first copied to ``<name>.bak``. Returns the backup path if one was made."""
    backup = None
    if path.exists():
        if not overwrite:
            raise BaselineError(f"{path} exists; baselines are never replaced silently")
        backup = path.with_name(path.name + ".bak")
        shutil.copy2(path, backup)
    path.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_text(path, json.dumps(data, indent=2, sort_keys=True) + "\n")
    return backup


@dataclass
class BaselineDiff:
    changes: list[dict[str, Any]] = field(default_factory=list)
    categories_compared: list[str] = field(default_factory=list)
    categories_skipped: dict[str, str] = field(default_factory=dict)

    def counts(self) -> dict[str, int]:
        out = {"added": 0, "removed": 0, "modified": 0}
        for c in self.changes:
            out[c["change"]] += 1
        return out


def compare(baseline: dict[str, Any], ev: EvidenceSet) -> BaselineDiff:
    current = build_entries(ev)
    diff = BaselineDiff()
    for cat in CATEGORIES:
        if cat not in baseline["categories"]:
            diff.categories_skipped[cat] = "category not in baseline"
            continue
        if cat not in current:
            diff.categories_skipped[cat] = f"no {SOURCE_FOR[cat]} telemetry in current evidence"
            continue
        diff.categories_compared.append(cat)
        old, new = baseline["entries"][cat], current[cat]
        for key in sorted(set(old) | set(new)):
            changed: list[str]
            if key not in old:
                change, attrs, changed = "added", new[key], []
            elif key not in new:
                change, attrs, changed = "removed", old[key], []
            else:
                changed = sorted(k for k in set(old[key]) | set(new[key]) if old[key].get(k) != new[key].get(k))
                if not changed:
                    continue
                change, attrs = "modified", new[key]
            diff.changes.append(
                {
                    "category": cat,
                    "key": key,
                    "change": change,
                    "changed_fields": changed,
                    "old": old.get(key),
                    "new": new.get(key),
                    "path": key,
                    **{k: v for k, v in attrs.items() if k not in {"path", "key", "change"}},
                }
            )
    return diff
