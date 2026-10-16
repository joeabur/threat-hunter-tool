from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .. import SCHEMA_VERSION, __version__
from ..evidence.loader import EvidenceSet
from ..utils.errors import InputError, ValidationError
from ..utils.paths import read_text_bounded
from ..utils.timeutil import to_iso, utc_now

CATEGORIES = ("persistence", "files", "listeners", "config")
WARNINGS = (
    "A baseline records what was observed, not what is safe: if the host was already "
    "compromised when the baseline was taken, the compromise is now part of the baseline.",
    "Routine updates (OS, apps, package managers) legitimately change many tracked items; "
    "review every difference before accepting it.",
    "The integrity hash detects accidental edits and corruption only. It is not a signature "
    "and does not authenticate who created the file; store baselines somewhere trusted.",
)
_MAX_BYTES = 64 * 1024 * 1024

_PERSISTENCE_ATTRS = (
    "kind", "label", "owner", "mode", "sha256", "program_path", "program_sha256",
    "program_exists", "run_at_load", "keep_alive", "program_arguments",
)  # fmt: skip
_FILE_ATTRS = ("kind", "owner", "mode", "sha256", "size", "is_executable")


@dataclass
class Baseline:
    observations: dict[str, dict[str, dict[str, Any]]]
    created_at: str
    host: dict[str, Any]
    tool_version: str
    source_evidence: dict[str, Any]
    integrity: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "kind": "mac-threat-hunter-baseline",
            "tool_version": self.tool_version,
            "created_at": self.created_at,
            "host": self.host,
            "source_evidence": self.source_evidence,
            "warnings": list(WARNINGS),
            "observations": self.observations,
            "integrity": {"algorithm": "sha256-of-canonical-observations", "value": self.integrity},
        }


def canonical_hash(observations: dict[str, Any]) -> str:
    blob = json.dumps(observations, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def _pick(data: dict[str, Any], keys: tuple[str, ...]) -> dict[str, Any]:
    return {k: data[k] for k in keys if k in data and data[k] is not None}


def observations_from_evidence(ev: EvidenceSet) -> dict[str, dict[str, dict[str, Any]]]:
    obs: dict[str, dict[str, dict[str, Any]]] = {c: {} for c in CATEGORIES}
    for rec in ev.records.get("persistence", []):
        path = rec.data.get("path")
        if isinstance(path, str):
            obs["persistence"][path] = _pick(rec.data, _PERSISTENCE_ATTRS)
    for rec in ev.records.get("file", []):
        path = rec.data.get("path")
        if isinstance(path, str):
            obs["files"][path] = _pick(rec.data, _FILE_ATTRS)
    for rec in ev.records.get("network", []):
        if not rec.data.get("is_listener"):
            continue
        key = f"{rec.data.get('proto')}/{rec.data.get('local_port')}/{rec.data.get('process_name')}"
        obs["listeners"][key] = _pick(
            rec.data,
            ("proto", "local_address", "local_port", "process_name", "process_path", "user"),
        )
    for rec in ev.records.get("system", []):
        for key, value in rec.data.items():
            if key.startswith("security_") and value is not None:
                obs["config"][key] = {"value": value}
        for key in ("os_version", "os_build"):
            if rec.data.get(key) is not None:
                obs["config"][key] = {"value": rec.data[key]}
    return obs


def create_baseline(ev: EvidenceSet) -> Baseline:
    obs = observations_from_evidence(ev)
    return Baseline(
        observations=obs,
        created_at=to_iso(utc_now()) or "",
        host=dict(ev.host),
        tool_version=__version__,
        source_evidence={
            "path_name": ev.path.name,
            "collected_at": to_iso(ev.collected_at),
            "synthetic": ev.synthetic,
            "files": ev.files_loaded,
            "counts": {c: len(v) for c, v in obs.items()},
        },
        integrity=canonical_hash(obs),
    )


def validate_baseline_dict(raw: Any) -> list[str]:
    problems: list[str] = []
    if not isinstance(raw, dict):
        return ["baseline must be a JSON object"]
    if raw.get("kind") != "mac-threat-hunter-baseline":
        problems.append("'kind' must be 'mac-threat-hunter-baseline'")
    if raw.get("schema_version") != SCHEMA_VERSION:
        problems.append(f"unsupported schema_version {raw.get('schema_version')!r}")
    obs = raw.get("observations")
    if not isinstance(obs, dict):
        problems.append("'observations' must be an object")
        return problems
    for cat, items in obs.items():
        if cat not in CATEGORIES:
            problems.append(f"unknown observation category {cat!r}")
        elif not isinstance(items, dict) or not all(isinstance(v, dict) for v in items.values()):
            problems.append(f"observations.{cat} must map keys to objects")
    integrity = raw.get("integrity")
    if not isinstance(integrity, dict) or "value" not in integrity:
        problems.append("missing integrity hash")
    elif not problems and integrity["value"] != canonical_hash(obs):
        problems.append(
            "integrity hash mismatch: the observations were modified after the baseline was "
            "created (accidental edit, corruption or tampering)"
        )
    return problems


def load_baseline(path: Path) -> Baseline:
    text = read_text_bounded(path, _MAX_BYTES)
    try:
        raw = json.loads(text)
    except json.JSONDecodeError as exc:
        raise InputError(f"{path}: invalid JSON: {exc.msg} (line {exc.lineno})") from exc
    problems = validate_baseline_dict(raw)
    if problems:
        raise ValidationError(f"baseline {path} failed validation", problems)
    obs = {c: dict(raw["observations"].get(c, {})) for c in CATEGORIES}
    return Baseline(
        observations=obs,
        created_at=str(raw.get("created_at", "")),
        host=dict(raw.get("host", {})),
        tool_version=str(raw.get("tool_version", "")),
        source_evidence=dict(raw.get("source_evidence", {})),
        integrity=str(raw["integrity"]["value"]),
    )
