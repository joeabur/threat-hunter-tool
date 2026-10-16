"""Load rule files from a directory (YAML or JSON), validating before use."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from linux_threat_hunter.rules_engine.conditions import EvalContext
from linux_threat_hunter.rules_engine.schema import validate_rule
from linux_threat_hunter.utils.safe import UnsafePathError, read_regular_file


@dataclass
class Rule:
    data: dict[str, Any]
    path: str

    @property
    def id(self) -> str:
        return str(self.data["id"])

    @property
    def version(self) -> str:
        return str(self.data["version"])

    @property
    def type(self) -> str:
        return str(self.data["type"])

    @property
    def data_source(self) -> str:
        return str(self.data["data_source"])


def load_rules(directory: str | Path, config: dict[str, Any]) -> tuple[list[Rule], list[str]]:
    """Return (valid rules, error messages). Invalid rules are reported, never executed."""
    root = Path(directory)
    errors: list[str] = []
    rules: list[Rule] = []
    if not root.is_dir():
        return [], [f"rules directory not found: {root}"]
    limits = config["limits"]
    ctx = EvalContext(config["variables"], limits)
    seen: dict[str, str] = {}
    for path in sorted(p for p in root.rglob("*") if p.suffix in {".yaml", ".yml", ".json"}):
        try:
            raw = read_regular_file(path, limits["max_rule_file_bytes"]).decode("utf-8")
            data = json.loads(raw) if path.suffix == ".json" else yaml.safe_load(raw)
        except (OSError, UnsafePathError, ValueError, yaml.YAMLError) as exc:
            errors.append(f"{path}: cannot load: {exc}")
            continue
        items = data.get("rules") if isinstance(data, dict) and "rules" in data and "id" not in data else [data]
        if not isinstance(items, list):
            errors.append(f"{path}: 'rules' must be a list")
            continue
        for item in items:
            errs = validate_rule(item, ctx)
            rid = item.get("id", "?") if isinstance(item, dict) else "?"
            if rid in seen:
                errs.append(f"duplicate rule id (also defined in {seen[rid]})")
            if errs:
                errors.extend(f"{path}: {rid}: {e}" for e in errs)
                continue
            seen[rid] = str(path)
            rules.append(Rule(item, str(path)))
    return sorted(rules, key=lambda r: r.id), errors
