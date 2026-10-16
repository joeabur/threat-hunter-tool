"""Configuration and allowlist loading with strict validation."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .models import SEVERITIES
from .utils.errors import InputError, ValidationError
from .utils.paths import read_text_bounded
from .utils.redact import REPLACEMENT

PACKAGE_DIR = Path(__file__).resolve().parent
_MAX_CONFIG_BYTES = 512 * 1024


def data_root() -> Path:
    """Locate shipped rules/configs: installed wheel data first, then the source checkout."""
    packaged = PACKAGE_DIR / "_data"
    if packaged.is_dir():
        return packaged
    return PACKAGE_DIR.parents[1]


def default_rules_dir() -> Path:
    return data_root() / "rules"


def default_config_path() -> Path:
    return data_root() / "configs" / "default.yaml"


def default_allowlists_path() -> Path:
    return data_root() / "configs" / "allowlists.yaml"


_LIMIT_KEYS = {
    "max_evidence_file_mb": (1, 2048),
    "max_records_per_source": (1, 5_000_000),
    "max_findings_per_rule": (1, 100_000),
    "max_regex_input_chars": (64, 1_000_000),
    "max_rules": (1, 5000),
    "max_rule_file_kb": (1, 4096),
    "max_ioc_indicators": (1, 5_000_000),
    "max_log_output_mb": (1, 2048),
    "subprocess_timeout_seconds": (1, 600),
}
_TOP_KEYS = {
    "schema_version",
    "limits",
    "collection",
    "redaction",
    "writable_locations",
    "rule_overrides",
    "suppressions",
}
_COLLECTION_KEYS = {
    "profiles",
    "include_cmdline",
    "hash_max_mb",
    "hash_skip_prefixes",
    "codesign_max_lookups",
    "persistence_dirs",
    "shell_startup_files",
    "login_hook_plist",
    "watch_directories",
    "watch_max_files_per_dir",
    "config_files",
    "config_dirs",
    "logs",
}
_COLLECTORS = {"system", "processes", "network", "persistence", "files", "logs"}


@dataclass
class Config:
    limits: dict[str, int] = field(default_factory=dict)
    collection: dict[str, Any] = field(default_factory=dict)
    redaction: dict[str, Any] = field(default_factory=dict)
    writable_locations: list[str] = field(default_factory=list)
    rule_overrides: dict[str, dict[str, Any]] = field(default_factory=dict)
    suppressions: list[dict[str, Any]] = field(default_factory=list)
    allowlists: dict[str, list[str]] = field(default_factory=dict)

    def limit(self, name: str) -> int:
        return int(self.limits[name])

    def named_list(self, name: str) -> list[str] | None:
        """Resolve ``$allowlist:`` / ``$setting:`` references."""
        if name in self.allowlists:
            return self.allowlists[name]
        if name == "writable_locations":
            return self.writable_locations
        return None


def _load_yaml(path: Path) -> Any:
    text = read_text_bounded(path, _MAX_CONFIG_BYTES)
    try:
        return yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise InputError(f"{path}: invalid YAML: {exc}") from exc


def _str_list(value: Any, where: str, problems: list[str]) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        problems.append(f"{where} must be a list of strings")
        return []
    return list(value)


def validate_config(raw: Any) -> list[str]:
    problems: list[str] = []
    if not isinstance(raw, dict):
        return ["configuration must be a mapping"]
    for key in raw:
        if key not in _TOP_KEYS:
            problems.append(f"unknown top-level key: {key}")
    if raw.get("schema_version", 1) != 1:
        problems.append("schema_version must be 1")
    limits = raw.get("limits", {})
    if not isinstance(limits, dict):
        problems.append("limits must be a mapping")
    else:
        for key, val in limits.items():
            if key not in _LIMIT_KEYS:
                problems.append(f"unknown limit: {key}")
                continue
            lo, hi = _LIMIT_KEYS[key]
            if isinstance(val, bool) or not isinstance(val, int) or not lo <= val <= hi:
                problems.append(f"limits.{key} must be an integer between {lo} and {hi}")
    coll = raw.get("collection", {})
    if not isinstance(coll, dict):
        problems.append("collection must be a mapping")
    else:
        for key in coll:
            if key not in _COLLECTION_KEYS:
                problems.append(f"unknown collection key: {key}")
        profiles = coll.get("profiles", {})
        if not isinstance(profiles, dict):
            problems.append("collection.profiles must be a mapping")
        else:
            for pname, members in profiles.items():
                if not isinstance(members, list) or not set(members) <= _COLLECTORS:
                    problems.append(
                        f"collection.profiles.{pname} must list collectors from {sorted(_COLLECTORS)}"
                    )
        if "include_cmdline" in coll and not isinstance(coll["include_cmdline"], bool):
            problems.append("collection.include_cmdline must be a boolean")
    red = raw.get("redaction", {})
    if not isinstance(red, dict):
        problems.append("redaction must be a mapping")
    else:
        for key in red:
            if key not in {"enabled", "extra_patterns", "replacement"}:
                problems.append(f"unknown redaction key: {key}")
    if "writable_locations" in raw:
        _str_list(raw["writable_locations"], "writable_locations", problems)
    overrides = raw.get("rule_overrides", {})
    if not isinstance(overrides, dict):
        problems.append("rule_overrides must be a mapping")
    else:
        for rid, ov in overrides.items():
            if not isinstance(ov, dict):
                problems.append(f"rule_overrides.{rid} must be a mapping")
                continue
            for key in ov:
                if key not in {"enabled", "severity", "confidence", "threshold"}:
                    problems.append(f"rule_overrides.{rid}: unknown key {key}")
            if "severity" in ov and ov["severity"] not in SEVERITIES:
                problems.append(f"rule_overrides.{rid}.severity must be one of {SEVERITIES}")
    sup = raw.get("suppressions", [])
    if not isinstance(sup, list):
        problems.append("suppressions must be a list")
    else:
        for i, entry in enumerate(sup):
            if not isinstance(entry, dict):
                problems.append(f"suppressions[{i}] must be a mapping")
                continue
            if not isinstance(entry.get("rule_id"), str):
                problems.append(f"suppressions[{i}].rule_id is required")
            reason = entry.get("reason")
            if not isinstance(reason, str) or len(reason.strip()) < 8:
                problems.append(f"suppressions[{i}].reason is required (at least 8 characters)")
            match = entry.get("match", {})
            if not isinstance(match, dict) or not all(
                isinstance(k, str) and isinstance(v, (str, int, bool)) for k, v in match.items()
            ):
                problems.append(f"suppressions[{i}].match must map field names to scalar values")
            for key in entry:
                if key not in {"rule_id", "reason", "match", "expires"}:
                    problems.append(f"suppressions[{i}]: unknown key {key}")
    return problems


def validate_allowlists(raw: Any) -> list[str]:
    problems: list[str] = []
    if not isinstance(raw, dict) or not isinstance(raw.get("lists"), dict):
        return ["allowlists file must contain a 'lists' mapping"]
    for key in raw:
        if key not in {"schema_version", "lists"}:
            problems.append(f"unknown top-level key: {key}")
    for name, items in raw["lists"].items():
        if not isinstance(name, str) or not name.replace("_", "").isalnum():
            problems.append(f"invalid allowlist name: {name!r}")
        if not isinstance(items, list) or not all(isinstance(i, str) for i in items):
            problems.append(f"allowlist {name} must be a list of strings")
    return problems


def _deep_merge(base: dict[str, Any], extra: dict[str, Any]) -> dict[str, Any]:
    out = dict(base)
    for key, val in extra.items():
        if isinstance(val, dict) and isinstance(out.get(key), dict):
            out[key] = _deep_merge(out[key], val)
        else:
            out[key] = val
    return out


def load_config(config_path: Path | None = None, allowlists_path: Path | None = None) -> Config:
    """Load defaults, then overlay ``config_path`` (if given). Raises ValidationError."""
    base = _load_yaml(default_config_path()) or {}
    merged = base
    if config_path is not None:
        extra = _load_yaml(config_path)
        if extra is None:
            extra = {}
        problems = validate_config(extra)
        if problems:
            raise ValidationError(f"invalid configuration {config_path}", problems)
        merged = _deep_merge(base, extra)
    problems = validate_config(merged)
    if problems:
        raise ValidationError("invalid configuration", problems)

    allow_raw = _load_yaml(allowlists_path or default_allowlists_path())
    allow_problems = validate_allowlists(allow_raw)
    if allow_problems:
        raise ValidationError("invalid allowlists", allow_problems)

    redaction = dict(merged.get("redaction", {}))
    redaction.setdefault("enabled", True)
    redaction.setdefault("extra_patterns", [])
    redaction.setdefault("replacement", REPLACEMENT)
    return Config(
        limits={k: int(v) for k, v in merged["limits"].items()},
        collection=merged.get("collection", {}),
        redaction=redaction,
        writable_locations=list(merged.get("writable_locations", [])),
        rule_overrides=dict(merged.get("rule_overrides", {})),
        suppressions=list(merged.get("suppressions", [])),
        allowlists={k: list(v) for k, v in allow_raw["lists"].items()},
    )


def make_redactor(config: Config):  # type: ignore[no-untyped-def]
    from .utils.redact import DEFAULT_PATTERNS, Redactor

    if not config.redaction.get("enabled", True):
        return Redactor([], config.redaction.get("replacement", REPLACEMENT))
    patterns = list(DEFAULT_PATTERNS) + list(config.redaction.get("extra_patterns", []))
    return Redactor(patterns, config.redaction.get("replacement", REPLACEMENT))
