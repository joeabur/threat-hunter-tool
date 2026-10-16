from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from ..config import Config
from ..models import Rule
from ..utils.errors import InputError
from ..utils.paths import read_text_bounded
from .schema import validate_rule

_SUFFIXES = {".yaml", ".yml", ".json"}


@dataclass
class RuleSet:
    rules: list[Rule] = field(default_factory=list)
    errors: dict[str, list[str]] = field(default_factory=dict)
    files_checked: int = 0

    @property
    def ok(self) -> bool:
        return not self.errors

    def by_id(self, rule_id: str) -> Rule | None:
        return next((r for r in self.rules if r.id == rule_id), None)


def known_list_names(config: Config) -> set[str]:
    return set(config.allowlists) | {"writable_locations"}


def _rule_from_dict(raw: dict[str, Any], path: str) -> Rule:
    rtype = raw.get("type", "pattern")
    category = {"pattern": "heuristic", "ioc": "ioc_match", "baseline": "baseline_change"}[rtype]
    src = raw["source"]
    attack = raw.get("attack") or {}
    return Rule(
        id=raw["id"],
        name=raw["name"],
        version=raw["version"],
        type=rtype,
        sources=[src] if isinstance(src, str) else list(src),
        description=raw["description"].strip(),
        rationale=raw["rationale"].strip(),
        severity=raw["severity"],
        confidence=raw["confidence"],
        category=category,
        techniques=list(attack.get("techniques", [])),
        attack_justification=str(attack.get("justification", "")).strip(),
        conditions=raw.get("conditions", {}),
        threshold=raw.get("threshold"),
        requires=list(raw.get("requires", [])),
        context_fields=list(raw.get("context_fields", [])),
        evidence_fields=list(raw.get("evidence_fields", [])),
        title=raw.get("title", raw["name"]),
        ioc=raw.get("ioc"),
        baseline=raw.get("baseline"),
        false_positives=list(raw["false_positives"]),
        investigation=list(raw["investigation"]),
        references=list(raw.get("references", [])),
        enabled=raw.get("enabled", True),
        path=path,
    )


def discover_rule_files(directory: Path) -> list[Path]:
    if not directory.is_dir():
        raise InputError(f"rules directory not found: {directory}")
    found: list[Path] = []
    for root, dirs, files in os.walk(directory, followlinks=False):
        dirs[:] = sorted(d for d in dirs if not (Path(root) / d).is_symlink())
        for name in sorted(files):
            p = Path(root) / name
            if p.suffix.lower() in _SUFFIXES and not p.is_symlink():
                found.append(p)
    return found


def load_rules(directories: list[Path], config: Config) -> RuleSet:
    result = RuleSet()
    seen: dict[str, str] = {}
    lists = known_list_names(config)
    max_bytes = config.limit("max_rule_file_kb") * 1024
    for directory in directories:
        for path in discover_rule_files(directory):
            result.files_checked += 1
            if result.files_checked > config.limit("max_rules"):
                result.errors[str(directory)] = [
                    f"more than {config.limit('max_rules')} rule files"
                ]
                return result
            label = str(path)
            try:
                text = read_text_bounded(path, max_bytes)
                raw = json.loads(text) if path.suffix == ".json" else yaml.safe_load(text)
            except (InputError, json.JSONDecodeError, yaml.YAMLError) as exc:
                result.errors[label] = [f"cannot parse: {exc}"]
                continue
            problems = validate_rule(raw, lists)
            if not problems and raw["id"] in seen:
                problems.append(f"duplicate rule id {raw['id']} (also in {seen[raw['id']]})")
            if problems:
                result.errors[label] = problems
                continue
            seen[raw["id"]] = label
            result.rules.append(_rule_from_dict(raw, label))
    result.rules.sort(key=lambda r: r.id)
    return result
