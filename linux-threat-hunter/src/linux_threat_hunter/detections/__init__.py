"""Locating and loading the versioned detection catalog (rules/ directory)."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from linux_threat_hunter.rules_engine.loader import Rule, load_rules


def default_rules_dir() -> Path:
    """Priority: $LTH_RULES_DIR, repository ``rules/`` (editable install), packaged ``_rules``."""
    env = os.environ.get("LTH_RULES_DIR")
    if env:
        return Path(env)
    here = Path(__file__).resolve()
    repo = here.parents[3] / "rules"
    if repo.is_dir():
        return repo
    return here.parents[1] / "_rules"


def load_catalog(directory: str | Path | None, config: dict[str, Any]) -> tuple[list[Rule], list[str]]:
    return load_rules(directory or default_rules_dir(), config)
