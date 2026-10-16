from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(Path(__file__).parent))

from mac_threat_hunter.config import Config, default_rules_dir, load_config  # noqa: E402
from mac_threat_hunter.rules_engine.loader import RuleSet, load_rules  # noqa: E402


@pytest.fixture(scope="session")
def repo_root() -> Path:
    return ROOT


@pytest.fixture(scope="session")
def cfg() -> Config:
    return load_config()


@pytest.fixture(scope="session")
def ruleset(cfg: Config) -> RuleSet:
    rs = load_rules([default_rules_dir()], cfg)
    assert rs.ok, rs.errors
    return rs


@pytest.fixture()
def synthetic(repo_root: Path) -> Path:
    return repo_root / "examples" / "synthetic-evidence"


@pytest.fixture()
def clean(repo_root: Path) -> Path:
    return repo_root / "examples" / "synthetic-evidence-clean"
