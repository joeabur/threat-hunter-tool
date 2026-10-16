import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from linux_threat_hunter.baseline import compare, create_baseline, load_baseline, save_baseline, validate_baseline
from linux_threat_hunter.baseline.core import BaselineError
from linux_threat_hunter.rules_engine import Engine


def unit(path: str, body: str = "[Service]\nExecStart=/usr/bin/a\n") -> dict[str, Any]:
    import hashlib

    return {
        "kind": "systemd_service",
        "path": path,
        "owner": "root",
        "mode": "0644",
        "content": body,
        "sha256": hashlib.sha256(body.encode()).hexdigest(),
    }


def test_create_and_validate(make_evidence: Callable[..., Any]) -> None:
    ev = make_evidence(
        persistence=[unit("/etc/systemd/system/a.service")],
        network=[{"proto": "tcp", "local_addr": "0.0.0.0", "local_port": 22, "listening": True, "process": "sshd"}],
    )
    b = create_baseline(ev)
    assert b["categories"] == ["persistence", "listeners"] and validate_baseline(b) == []
    assert "malicious state" in b["warning"]


def test_integrity_detects_tampering(make_evidence: Callable[..., Any], tmp_path: Path) -> None:
    b = create_baseline(make_evidence(persistence=[unit("/etc/systemd/system/a.service")]))
    b["entries"]["persistence"]["/etc/systemd/system/evil.service"] = {"kind": "systemd_service"}
    assert any("integrity" in e for e in validate_baseline(b))
    p = tmp_path / "b.json"
    p.write_text(json.dumps(b))
    with pytest.raises(BaselineError):
        load_baseline(p)


@pytest.mark.parametrize(
    "bad",
    [
        [],
        {"schema_version": 9},
        {"schema_version": 1, "categories": ["x"], "entries": {}},
        {"schema_version": 1, "categories": ["files"], "entries": {}},
    ],
)
def test_schema_validation(bad: Any) -> None:
    assert validate_baseline(bad)


def test_compare_added_removed_modified(make_evidence: Callable[..., Any]) -> None:
    old = make_evidence(
        name="old", persistence=[unit("/etc/systemd/system/a.service"), unit("/etc/systemd/system/gone.service")]
    )
    base = create_baseline(old)
    new = make_evidence(
        name="new",
        persistence=[
            unit("/etc/systemd/system/a.service", "[Service]\nExecStart=/tmp/x\n"),
            unit("/etc/systemd/system/new.service"),
        ],
    )
    diff = compare(base, new)
    got = {(c["key"].rsplit("/", 1)[1], c["change"]) for c in diff.changes}
    assert got == {("a.service", "modified"), ("gone.service", "removed"), ("new.service", "added")}
    mod = next(c for c in diff.changes if c["change"] == "modified")
    assert "sha256" in mod["changed_fields"]
    assert diff.counts() == {"added": 1, "removed": 1, "modified": 1}


def test_unchanged_has_no_diff_and_missing_sources_are_not_removals(make_evidence: Callable[..., Any]) -> None:
    ev = make_evidence(persistence=[unit("/etc/systemd/system/a.service")])
    base = create_baseline(ev)
    assert compare(base, ev).changes == []
    no_pers = make_evidence(name="n", processes=[{"pid": 1, "name": "x", "exe": "/x", "sha256": "a" * 64}])
    diff = compare(base, no_pers)
    assert diff.changes == [] and "persistence" in diff.categories_skipped  # absence of data != removal


def test_save_never_replaces_silently(make_evidence: Callable[..., Any], tmp_path: Path) -> None:
    b = create_baseline(make_evidence(persistence=[unit("/etc/systemd/system/a.service")]))
    p = tmp_path / "base.json"
    assert save_baseline(p, b) is None
    with pytest.raises(BaselineError):
        save_baseline(p, b)
    backup = save_baseline(p, b, overwrite=True)
    assert backup is not None and backup.exists()


def test_baseline_rules_fire_only_with_baseline(
    make_evidence: Callable[..., Any], rules: list[Any], config: dict[str, Any]
) -> None:
    base = create_baseline(make_evidence(name="o", persistence=[unit("/etc/systemd/system/a.service")]))
    ev = make_evidence(
        name="n", persistence=[unit("/etc/systemd/system/a.service"), unit("/etc/systemd/system/b.service")]
    )
    without = Engine(rules, config).run(ev)
    assert not [f for f in without.findings if f.rule_id == "LTH-PERS-001"]
    with_b = Engine(rules, config, None, compare(base, ev)).run(ev)
    hits = [f for f in with_b.findings if f.rule_id == "LTH-PERS-001"]
    assert len(hits) == 1 and hits[0].classification == "observation"
    assert hits[0].attack[0]["technique"] == "T1543.002"
