"""Rule schema, condition language, resource limits and ATT&CK mapping validation."""

import copy
import re
from pathlib import Path
from typing import Any

import pytest
import yaml

from conftest import ROOT, RULES
from linux_threat_hunter.attack import TECHNIQUES, technique_url, validate_mapping
from linux_threat_hunter.config import load_config
from linux_threat_hunter.rules_engine.conditions import (
    ConditionError,
    EvalContext,
    check_regex,
    evaluate,
    path_under,
    text_references_path_under,
)
from linux_threat_hunter.rules_engine.loader import load_rules
from linux_threat_hunter.rules_engine.schema import validate_rule


def ctx(config: dict[str, Any]) -> EvalContext:
    return EvalContext(config["variables"], config["limits"])


def good_rule() -> dict[str, Any]:
    return copy.deepcopy(yaml.safe_load((RULES / "process" / "lth-proc-001.yaml").read_text()))


def test_all_shipped_rules_valid_and_unique(rules: list[Any]) -> None:
    ids = [r.id for r in rules]
    assert len(ids) == len(set(ids)) >= 30
    for r in rules:
        d = r.data
        assert d["false_positives"] and d["investigation_steps"] and d["rationale"] and d["description"]
        assert d["severity"] in {"informational", "low", "medium", "high", "critical"}
        assert d["confidence"] in {"low", "medium", "high"}


def test_every_rule_id_is_documented(rules: list[Any]) -> None:
    text = (ROOT / "docs" / "detection-coverage.md").read_text()
    missing = [r.id for r in rules if r.id not in text]
    assert not missing, f"undocumented rules: {missing}"


def test_attack_mappings_valid_and_official_titles(rules: list[Any]) -> None:
    for tid, (title, tactics) in TECHNIQUES.items():
        assert re.fullmatch(r"T\d{4}(\.\d{3})?", tid) and title and tactics
        assert technique_url(tid).startswith("https://attack.mitre.org/techniques/T")
    assert technique_url("T1053.003") == "https://attack.mitre.org/techniques/T1053/003/"
    for r in rules:
        for m in r.data.get("attack", []):
            assert validate_mapping(m["tactic"], m["technique"]) == []


def test_attack_mapping_validation_errors() -> None:
    assert validate_mapping("execution", "T9999")  # unknown
    assert validate_mapping("execution", "1059.004")  # bad format
    assert validate_mapping("impact", "T1059.004")  # wrong tactic


@pytest.mark.parametrize(
    ("mutate", "needle"),
    [
        (lambda r: r.update(id="BAD-1"), "id:"),
        (lambda r: r.update(version="1"), "version"),
        (lambda r: r.update(severity="urgent"), "severity"),
        (lambda r: r.update(type="python"), "type"),
        (lambda r: r.update(unexpected=1), "unknown keys"),
        (lambda r: r.pop("false_positives"), "false_positives"),
        (lambda r: r.update(attack=[{"tactic": "execution", "technique": "T0000"}]), "registry"),
        (lambda r: r.update(attack=[{"tactic": "impact", "technique": "T1059.004"}]), "tactic"),
        (lambda r: r.update(references=["http://insecure.example"]), "https"),
        (lambda r: r["finding"].update(title="{a[0]}"), "placeholder"),
        (lambda r: r.update(conditions={"field": "x", "op": "exec", "value": "1"}), "unknown op"),
        (lambda r: r.update(conditions={"field": "x", "op": "regex", "value": "(a+)+$"}), "nested quantifier"),
        (lambda r: r.update(conditions={"field": "x", "op": "regex", "value": "a" * 300}), "longer than"),
        (lambda r: r.update(conditions={"field": "x", "op": "regex", "value": r"(a)\1"}), "backreferences"),
        (lambda r: r.update(conditions={"field": "x", "op": "equals", "value": "$nope"}), "unknown variable"),
        (lambda r: r.update(conditions={"all": []}), "non-empty"),
        (lambda r: r.update(conditions={"field": "x", "op": "in", "value": "notalist"}), "non-empty list"),
        (lambda r: r.update(conditions={"field": "x y", "op": "equals", "value": 1}), "dotted identifier"),
    ],
)
def test_invalid_rules_are_rejected(config: dict[str, Any], mutate: Any, needle: str) -> None:
    rule = good_rule()
    mutate(rule)
    errors = validate_rule(rule, ctx(config))
    assert any(needle in e for e in errors), errors


def test_condition_depth_limit(config: dict[str, Any]) -> None:
    node: dict[str, Any] = {"field": "x", "op": "equals", "value": 1}
    for _ in range(10):
        node = {"not": node}
    rule = good_rule()
    rule["conditions"] = node
    assert any("nested deeper" in e for e in validate_rule(rule, ctx(config)))


def test_type_specific_validation(config: dict[str, Any]) -> None:
    rule = yaml.safe_load((RULES / "authentication" / "lth-auth-001.yaml").read_text())
    rule["params"] = {"count": 0, "window_seconds": 300}
    assert any("params.count" in e for e in validate_rule(rule, ctx(config)))
    rule = yaml.safe_load((RULES / "correlation" / "lth-cor-001.yaml").read_text())
    rule["correlate"]["join_on"] = "everything"
    assert any("join_on" in e for e in validate_rule(rule, ctx(config)))
    rule = yaml.safe_load((RULES / "persistence" / "lth-pers-001.yaml").read_text())
    rule["baseline"]["categories"] = ["nothing"]
    assert any("baseline.categories" in e for e in validate_rule(rule, ctx(config)))


def test_loader_reports_errors_and_duplicates(tmp_path: Path, config: dict[str, Any]) -> None:
    good = (RULES / "process" / "lth-proc-001.yaml").read_text()
    (tmp_path / "a.yaml").write_text(good)
    (tmp_path / "b.yaml").write_text(good)  # duplicate id
    (tmp_path / "c.yaml").write_text("id: [unclosed")
    (tmp_path / "d.json").write_text("{not json")
    (tmp_path / "big.yaml").write_text("x: " + "y" * (config["limits"]["max_rule_file_bytes"] + 10))
    rules, errors = load_rules(tmp_path, config)
    assert len(rules) == 1
    joined = "\n".join(errors)
    assert "duplicate rule id" in joined and "cannot load" in joined
    _, missing = load_rules(tmp_path / "nope", config)
    assert "not found" in missing[0]


def test_yaml_cannot_execute_code(tmp_path: Path, config: dict[str, Any]) -> None:
    (tmp_path / "evil.yaml").write_text("!!python/object/apply:os.system ['echo pwned > pwned.txt']\n")
    rules, errors = load_rules(tmp_path, config)
    assert not rules and errors and not (tmp_path / "pwned.txt").exists()


# ----- condition language -----
def test_condition_operators(config: dict[str, Any]) -> None:
    c = ctx(config)
    d = {"exe": "/tmp/x/run", "n": 5, "name": "bash", "tags": ["a", "b"], "flag": False, "nested": {"k": "v"}}

    def ev(field: str, op: str, value: Any) -> bool:
        return evaluate({"field": field, "op": op, "value": value}, d, c)

    assert ev("name", "equals", "bash") and not ev("name", "equals", "sh")
    assert ev("name", "not_equals", "sh") and ev("name", "in", ["bash", "sh"]) and ev("name", "not_in", ["sh"])
    assert ev("exe", "startswith", "/tmp") and ev("exe", "endswith", "run") and ev("exe", "contains", "x/r")
    assert ev("tags", "contains", "a") and ev("exe", "contains_any", ["zzz", "tmp"])
    assert ev("n", "gt", 4) and ev("n", "gte", 5) and ev("n", "lt", 6) and ev("n", "lte", 5) and not ev("n", "gt", 5)
    assert ev("nested.k", "equals", "v") and ev("exe", "regex", r"^/tmp/.+/run$")
    assert ev("exe", "regex_any", ["nomatch", "run$"]) and ev("flag", "equals", False)
    assert ev("exe", "path_under", ["/tmp"]) and not ev("exe", "not_path_under", ["/tmp"])
    assert evaluate(
        {"all": [{"field": "n", "op": "gt", "value": 1}, {"not": {"field": "name", "op": "equals", "value": "x"}}]},
        d,
        c,
    )
    assert evaluate({"any": [{"field": "n", "op": "gt", "value": 99}, {"field": "n", "op": "lt", "value": 9}]}, d, c)


def test_missing_fields_never_match_except_exists(config: dict[str, Any]) -> None:
    c = ctx(config)
    d: dict[str, Any] = {"present": None}
    for op, val in (
        ("equals", "x"),
        ("not_equals", "x"),
        ("in", ["x"]),
        ("not_in", ["x"]),
        ("regex", "x"),
        ("path_under", ["/"]),
    ):
        assert not evaluate({"field": "absent", "op": op, "value": val}, d, c)
    assert evaluate({"field": "absent", "op": "exists", "value": False}, d, c)
    assert not evaluate({"field": "absent", "op": "exists", "value": True}, d, c)
    assert not evaluate({"field": "present", "op": "gt", "value": 1}, d, c)


def test_path_helpers() -> None:
    assert path_under("/tmp/a/b", ["/tmp"]) and not path_under("/tmpx/a", ["/tmp"])
    assert path_under("/home/bob/.cache/x/y", ["/home/*/.cache"]) and not path_under(
        "/home/bob/docs", ["/home/*/.cache"]
    )
    assert not path_under("/tmp/../etc/passwd", ["/tmp"])  # normalized: no traversal tricks
    assert text_references_path_under("sh -c 'cd /dev/shm && ./x'", ["/dev/shm"])
    assert not text_references_path_under("/usr/bin/tmpwatch /tmpfoo", ["/tmp"])


def test_regex_resource_limits(config: dict[str, Any]) -> None:
    assert check_regex("(a+)+$", 256)
    assert check_regex("x" * 257, 256)
    assert check_regex("[unclosed", 256)
    # Input is truncated before matching, so a huge value cannot stall evaluation
    c = ctx(config)
    big = "a" * 5_000_000
    assert not evaluate({"field": "v", "op": "regex", "value": r"a{10}b"}, {"v": big}, c)
    with pytest.raises(ConditionError):
        evaluate({"field": "v", "op": "regex", "value": "(a+)+$"}, {"v": "aaaa"}, c)


def test_config_validation(tmp_path: Path) -> None:
    from linux_threat_hunter.config import ConfigError

    bad = tmp_path / "c.yaml"
    bad.write_text("limits:\n  max_regex_length: -1\n")
    with pytest.raises(ConfigError):
        load_config(bad)
    bad.write_text("unknown_key: 1\n")
    with pytest.raises(ConfigError):
        load_config(bad)
    bad.write_text("redaction:\n  patterns: ['(']\n")
    with pytest.raises(ConfigError):
        load_config(bad)
    bad.write_text("rule_overrides:\n  LTH-X-001:\n    shell: rm -rf /\n")
    with pytest.raises(ConfigError):
        load_config(bad)
    ok = tmp_path / "ok.yaml"
    ok.write_text("limits:\n  max_findings_per_rule: 7\n")
    cfg = load_config(ok)
    assert cfg["limits"]["max_findings_per_rule"] == 7 and cfg["limits"]["max_regex_length"] == 256


def test_default_yaml_matches_builtin_defaults() -> None:
    from linux_threat_hunter.config import DEFAULT_CONFIG

    assert yaml.safe_load((ROOT / "configs" / "default.yaml").read_text()) == DEFAULT_CONFIG
    assert load_config(ROOT / "configs" / "default.yaml", ROOT / "configs" / "allowlists.yaml") == DEFAULT_CONFIG
