from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest
import yaml

from mac_threat_hunter.attack import TECHNIQUES, is_valid_id_format, resolve, technique_url
from mac_threat_hunter.config import Config
from mac_threat_hunter.models import EvidenceRef, Record, Rule
from mac_threat_hunter.rules_engine.conditions import eval_group, eval_leaf
from mac_threat_hunter.rules_engine.evaluator import (
    EvalContext,
    build_lists,
    evaluate_pattern_rule,
)
from mac_threat_hunter.rules_engine.loader import known_list_names, load_rules
from mac_threat_hunter.rules_engine.schema import validate_rule
from mac_threat_hunter.utils.redact import Redactor
from mac_threat_hunter.utils.timeutil import parse_timestamp

LISTS = {"names": ["a", "b"], "writable_locations": ["/tmp"]}


def good_rule() -> dict[str, Any]:
    return {
        "id": "MTH-TEST-001", "name": "Test rule", "version": 1, "source": "process",
        "description": "A test rule description", "rationale": "Because testing matters",
        "severity": "low", "confidence": "low",
        "conditions": {"all": [{"field": "name", "op": "equals", "value": "x"}]},
        "false_positives": ["none"], "investigation": ["look"],
    }  # fmt: skip


def check(rule: dict[str, Any]) -> list[str]:
    return validate_rule(rule, {"trusted_exec_prefixes", "writable_locations"})


class TestShippedRules:
    def test_all_shipped_rules_valid_and_unique(self, ruleset) -> None:  # type: ignore[no-untyped-def]
        ids = [r.id for r in ruleset.rules]
        assert len(ids) == len(set(ids)) >= 30

    def test_shipped_rules_match_json_schema(self, repo_root: Path) -> None:
        jsonschema = pytest.importorskip("jsonschema")
        schema = json.loads((repo_root / "schemas" / "rule.schema.json").read_text())
        jsonschema.Draft202012Validator.check_schema(schema)
        for path in (repo_root / "rules").rglob("*.yaml"):
            jsonschema.validate(yaml.safe_load(path.read_text()), schema)

    def test_json_schema_rejects_what_loader_rejects_structurally(self, repo_root: Path) -> None:
        jsonschema = pytest.importorskip("jsonschema")
        schema = json.loads((repo_root / "schemas" / "rule.schema.json").read_text())
        bad = good_rule()
        bad["severity"] = "catastrophic"
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(bad, schema)

    def test_every_rule_has_required_documentation_fields(self, ruleset) -> None:  # type: ignore[no-untyped-def]
        for r in ruleset.rules:
            assert r.false_positives and r.investigation and r.rationale and r.description
            assert r.severity and r.confidence and r.version >= 1

    def test_attack_mappings_are_catalogued_justified_and_linked(self, ruleset) -> None:  # type: ignore[no-untyped-def]
        mapped = 0
        for r in ruleset.rules:
            if r.techniques:
                mapped += 1
                assert len(r.attack_justification) >= 20, r.id
            for tid in r.techniques:
                m = resolve(tid)
                assert m is not None and m.url == technique_url(tid)
                assert m.url.startswith("https://attack.mitre.org/techniques/T")
        assert mapped >= 10

    def test_catalogue_ids_have_valid_format(self) -> None:
        assert all(is_valid_id_format(t) for t in TECHNIQUES)
        for t in ("T1", "t1059", "T1059.4", "T1059.0041", "1059"):
            assert not is_valid_id_format(t)

    def test_sub_technique_url(self) -> None:
        assert technique_url("T1059.004") == "https://attack.mitre.org/techniques/T1059/004/"

    def test_default_thresholds_documented_values(self, ruleset) -> None:  # type: ignore[no-untyped-def]
        r = ruleset.by_id("MTH-LOG-001")
        assert r.threshold == {"count": 5, "window_seconds": 300, "group_by": "src_ip"}


class TestSchemaValidation:
    def test_good_rule_is_valid(self) -> None:
        assert check(good_rule()) == []

    @pytest.mark.parametrize(
        ("mutate", "needle"),
        [
            (lambda r: r.pop("id"), "'id'"),
            (lambda r: r.update(id="bad id"), "'id'"),
            (lambda r: r.update(severity="urgent"), "severity"),
            (lambda r: r.update(confidence="certain"), "confidence"),
            (lambda r: r.update(version=0), "version"),
            (lambda r: r.update(source="registry"), "source"),
            (lambda r: r.update(unknown_key=1), "unknown key"),
            (lambda r: r.update(false_positives=[]), "false_positives"),
            (lambda r: r.pop("investigation"), "investigation"),
            (lambda r: r.pop("conditions"), "conditions"),
            (lambda r: r.update(conditions={"all": []}), "non-empty"),
            (
                lambda r: r.update(
                    conditions={"all": [{"field": "name", "op": "evil", "value": 1}]}
                ),
                "operator",
            ),
            (
                lambda r: r.update(
                    conditions={"all": [{"field": "Name!", "op": "equals", "value": 1}]}
                ),
                "field",
            ),
            (
                lambda r: r.update(
                    conditions={"all": [{"field": "name", "op": "regex", "value": "(a+)+"}]}
                ),
                "nested",
            ),
            (
                lambda r: r.update(
                    conditions={
                        "all": [{"field": "name", "op": "in", "value": "$allowlist:missing"}]
                    }
                ),
                "unknown list",
            ),
            (
                lambda r: r.update(
                    conditions={"all": [{"field": "name", "op": "equals", "value": 1, "code": "x"}]}
                ),
                "unknown keys",
            ),
            (
                lambda r: r.update(attack={"techniques": ["T9999"], "justification": "x" * 30}),
                "catalogue",
            ),
            (
                lambda r: r.update(attack={"techniques": ["bogus"], "justification": "x" * 30}),
                "valid ID",
            ),
            (lambda r: r.update(attack={"techniques": ["T1059"]}), "justification"),
            (
                lambda r: r.update(threshold={"count": 1, "window_seconds": 5, "group_by": "x"}),
                "count",
            ),
            (lambda r: r.update(threshold={"count": 3}), "threshold"),
            (lambda r: r.update(type="python"), "type"),
        ],
    )
    def test_invalid_rules_are_rejected(self, mutate, needle: str) -> None:  # type: ignore[no-untyped-def]
        rule = copy.deepcopy(good_rule())
        mutate(rule)
        problems = check(rule)
        assert problems and any(needle in p for p in problems), problems

    def test_rules_cannot_embed_code(self) -> None:
        for key in ("script", "python", "exec", "command", "eval"):
            rule = good_rule()
            rule[key] = "__import__('os').system('id')"
            assert check(rule)

    def test_depth_and_size_limits(self) -> None:
        rule = good_rule()
        node: dict[str, Any] = {"all": [{"field": "name", "op": "equals", "value": "x"}]}
        for _ in range(6):
            node = {"all": [node]}
        rule["conditions"] = node
        assert any("nested deeper" in p for p in check(rule))
        rule["conditions"] = {
            "all": [{"field": "name", "op": "equals", "value": str(i)} for i in range(80)]
        }
        assert any("more than" in p for p in check(rule))

    def test_ioc_and_baseline_rule_shapes(self) -> None:
        base = {k: v for k, v in good_rule().items() if k != "conditions"}
        assert check({**base, "type": "ioc"})  # missing ioc block
        assert (
            check(
                {
                    **base,
                    "type": "ioc",
                    "ioc": {"matches": [{"type": "ip", "fields": ["x"], "text": True}]},
                }
            )
            == []
        )
        assert check(
            {
                **base,
                "type": "ioc",
                "ioc": {"matches": [{"type": "sha256", "fields": ["x"], "text": True}]},
            }
        )
        assert (
            check(
                {**base, "type": "baseline", "baseline": {"category": "files", "change": "added"}}
            )
            == []
        )
        assert check(
            {**base, "type": "baseline", "baseline": {"category": "nope", "change": "added"}}
        )


class TestLoader:
    def test_invalid_files_reported_without_stopping(self, tmp_path: Path, cfg: Config) -> None:
        (tmp_path / "ok.yaml").write_text(yaml.safe_dump(good_rule()))
        bad = good_rule() | {"id": "MTH-TEST-002", "severity": "nope"}
        (tmp_path / "bad.yaml").write_text(yaml.safe_dump(bad))
        (tmp_path / "broken.yaml").write_text("a: [unclosed")
        (tmp_path / "dup.yaml").write_text(yaml.safe_dump(good_rule()))
        rs = load_rules([tmp_path], cfg)
        assert len(rs.rules) == 1
        assert len(rs.errors) == 3
        assert any("duplicate" in p for probs in rs.errors.values() for p in probs)

    def test_unsafe_yaml_tags_not_executed(self, tmp_path: Path, cfg: Config) -> None:
        (tmp_path / "evil.yaml").write_text("id: !!python/object/apply:os.system ['echo pwned']\n")
        rs = load_rules([tmp_path], cfg)
        assert rs.errors and not rs.rules

    def test_oversize_rule_file_rejected(self, tmp_path: Path, cfg: Config) -> None:
        (tmp_path / "big.yaml").write_text(
            "x: " + "a" * (cfg.limit("max_rule_file_kb") * 1024 + 10)
        )
        assert load_rules([tmp_path], cfg).errors

    def test_known_lists_include_setting_lists(self, cfg: Config) -> None:
        assert {"trusted_exec_prefixes", "writable_locations"} <= known_list_names(cfg)


class TestConditions:
    def leaf(self, field: str, op: str, value: Any, data: dict[str, Any]) -> bool:
        return eval_leaf({"field": field, "op": op, "value": value}, data, LISTS, 4096)

    def test_operators(self) -> None:
        d = {"name": "Safari", "n": 5, "path": "/tmp/x/y", "flag": True, "tags": ["a"]}
        assert self.leaf("name", "equals", "Safari", d)
        assert self.leaf("name", "iequals", "safari", d)
        assert self.leaf("name", "not_equals", "Mail", d)
        assert self.leaf("name", "in", ["Safari", "Mail"], d)
        assert self.leaf("name", "not_in", ["Mail"], d)
        assert self.leaf("name", "startswith", "Saf", d)
        assert self.leaf("name", "endswith", "ari", d)
        assert self.leaf("name", "contains", "far", d)
        assert self.leaf("name", "icontains", "FAR", d)
        assert self.leaf("name", "startswith_any", ["x", "Sa"], d)
        assert self.leaf("name", "contains_any", ["zz", "far"], d)
        assert self.leaf("name", "regex", r"^Saf\w+$", d)
        assert self.leaf("name", "iregex", r"^saf", d)
        assert self.leaf("n", "gt", 4, d) and self.leaf("n", "gte", 5, d)
        assert self.leaf("n", "lt", 6, d) and self.leaf("n", "lte", 5, d)
        assert self.leaf("path", "path_under", ["/tmp"], d)
        assert self.leaf("path", "glob", ["/tmp/*/y"], d)
        assert self.leaf("flag", "equals", True, d)
        assert self.leaf("name", "exists", True, d) and self.leaf("zzz", "exists", False, d)
        assert self.leaf("tags", "contains", "a", d)

    def test_path_under_requires_path_boundary_and_normalises(self) -> None:
        assert not self.leaf("path", "path_under", ["/tmp"], {"path": "/tmpfoo/x"})
        assert not self.leaf("path", "path_under", ["/tmp"], {"path": "/tmp/../etc/passwd"})
        assert self.leaf(
            "path", "path_under", ["/Users/*/Downloads"], {"path": "/Users/a/Downloads/x"}
        )

    def test_missing_fields_never_match_even_negative_ops(self) -> None:
        for op in (
            "equals",
            "not_equals",
            "in",
            "not_in",
            "startswith",
            "regex",
            "gt",
            "path_under",
        ):
            val: Any = ["x"] if op in {"in", "not_in", "path_under"} else (1 if op == "gt" else "x")
            assert not self.leaf("missing", op, val, {}), op

    def test_type_mismatch_does_not_raise(self) -> None:
        assert not self.leaf("n", "startswith", "x", {"n": 5})
        assert not self.leaf("n", "gt", 1, {"n": "text"})
        assert not self.leaf("n", "gt", 1, {"n": True})

    def test_list_references(self) -> None:
        assert self.leaf("x", "in", "$allowlist:names", {"x": "a"})
        assert self.leaf("p", "path_under", "$setting:writable_locations", {"p": "/tmp/q"})

    def test_groups(self) -> None:
        d = {"a": 1, "b": 2}
        eq = lambda f, v: {"field": f, "op": "equals", "value": v}  # noqa: E731
        assert eval_group({"all": [eq("a", 1), eq("b", 2)]}, d, LISTS, 100)
        assert not eval_group({"all": [eq("a", 1), eq("b", 3)]}, d, LISTS, 100)
        assert eval_group({"any": [eq("a", 9), eq("b", 2)]}, d, LISTS, 100)
        assert not eval_group({"all": [eq("a", 1)], "none": [eq("b", 2)]}, d, LISTS, 100)
        assert eval_group({"all": [eq("a", 1), {"any": [eq("b", 9), eq("b", 2)]}]}, d, LISTS, 100)

    def test_regex_input_is_bounded_by_config(self) -> None:
        item = {"field": "t", "op": "regex", "value": "needle"}
        assert not eval_leaf(item, {"t": "x" * 100 + "needle"}, LISTS, 50)
        assert eval_leaf(item, {"t": "x" * 100 + "needle"}, LISTS, 500)


def make_rule(**over: Any) -> Rule:
    base: dict[str, Any] = dict(
        id="MTH-TEST-001", name="t", version=1, type="pattern", sources=["log"], description="d",
        rationale="r", severity="medium", confidence="low", category="heuristic",
        conditions={"all": [{"field": "auth_result", "op": "equals", "value": "failed"}]},
        threshold={"count": 3, "window_seconds": 60, "group_by": "src_ip"},
    )  # fmt: skip
    base.update(over)
    return Rule(**base)


def log_rec(i: int, ts: str | None, ip: str | None = "10.0.0.1", **extra: Any) -> Record:
    data = {"auth_result": "failed", "process": "sshd", **extra}
    if ip:
        data["src_ip"] = ip
    parsed = parse_timestamp(ts)
    return Record("log", data, EvidenceRef("l.ndjson", i), parsed.utc, parsed.original, parsed.zone)


def run(rule: Rule, records: list[Record], cfg: Config):  # type: ignore[no-untyped-def]
    ctx = EvalContext(cfg, Redactor(), "h", build_lists(cfg))
    return evaluate_pattern_rule(rule, {"log": records}, ctx)


class TestThresholds:
    def test_fires_at_threshold_within_window(self, cfg: Config) -> None:
        recs = [log_rec(i, f"2026-03-10T10:00:{i * 10:02d}Z") for i in range(3)]
        findings, stats = run(make_rule(), recs, cfg)
        assert len(findings) == 1 and findings[0].evidence["event_count"] == 3
        assert stats.matched == 3

    def test_below_threshold_does_not_fire(self, cfg: Config) -> None:
        recs = [log_rec(i, f"2026-03-10T10:00:{i * 10:02d}Z") for i in range(2)]
        assert run(make_rule(), recs, cfg)[0] == []

    def test_events_outside_window_do_not_count(self, cfg: Config) -> None:
        recs = [log_rec(i, f"2026-03-10T10:{i * 5:02d}:00Z") for i in range(3)]  # 5 minutes apart
        assert run(make_rule(), recs, cfg)[0] == []

    def test_window_boundary_is_inclusive(self, cfg: Config) -> None:
        recs = [
            log_rec(0, "2026-03-10T10:00:00Z"),
            log_rec(1, "2026-03-10T10:00:30Z"),
            log_rec(2, "2026-03-10T10:01:00Z"),
        ]
        assert len(run(make_rule(), recs, cfg)[0]) == 1
        late = [*recs[:2], log_rec(2, "2026-03-10T10:01:01Z")]
        assert run(make_rule(), late, cfg)[0] == []

    def test_groups_are_independent(self, cfg: Config) -> None:
        recs = [
            log_rec(i, f"2026-03-10T10:00:{i:02d}Z", ip="1.1.1.1" if i % 2 else "2.2.2.2")
            for i in range(4)
        ]
        assert run(make_rule(), recs, cfg)[0] == []  # 2 each, below 3

    def test_records_without_timestamp_or_group_are_skipped_and_counted(self, cfg: Config) -> None:
        recs = [
            log_rec(0, None),
            log_rec(1, "2026-03-10T10:00:00Z", ip=None),
            log_rec(2, "2026-03-10T10:00:01Z"),
        ]
        findings, stats = run(make_rule(), recs, cfg)
        assert findings == [] and stats.skipped_missing_fields == 2

    def test_config_override_changes_threshold(self, cfg: Config) -> None:
        recs = [log_rec(i, f"2026-03-10T10:00:{i:02d}Z") for i in range(2)]
        over = Config(
            **{**cfg.__dict__, "rule_overrides": {"MTH-TEST-001": {"threshold": {"count": 2}}}}
        )
        assert len(run(make_rule(), recs, over)[0]) == 1

    def test_finding_ids_stable_across_runs(self, cfg: Config) -> None:
        recs = [log_rec(i, f"2026-03-10T10:00:{i:02d}Z") for i in range(3)]
        a = run(make_rule(), recs, cfg)[0][0].finding_id
        b = run(make_rule(), recs, cfg)[0][0].finding_id
        assert a == b and a.startswith("F-")

    def test_findings_per_rule_cap(self, cfg: Config) -> None:
        small = Config(**{**cfg.__dict__, "limits": {**cfg.limits, "max_findings_per_rule": 2}})
        rule = make_rule(threshold=None)
        recs = [log_rec(i, f"2026-03-10T10:00:{i:02d}Z") for i in range(10)]
        findings, stats = run(rule, recs, small)
        assert len(findings) == 2 and stats.capped


class TestRequiresAndContext:
    def test_requires_skips_records_and_never_infers(self, cfg: Config) -> None:
        rule = make_rule(threshold=None, requires=["parent_name"],
                         conditions={"all": [{"field": "auth_result", "op": "equals", "value": "failed"}]})  # fmt: skip
        findings, stats = run(rule, [log_rec(0, "2026-03-10T10:00:00Z")], cfg)
        assert findings == [] and stats.skipped_missing_fields == 1

    def test_missing_context_is_reported_on_finding(self, cfg: Config) -> None:
        rule = make_rule(threshold=None, context_fields=["parent_name"])
        findings, _ = run(rule, [log_rec(0, "2026-03-10T10:00:00Z")], cfg)
        assert findings[0].missing_context == ["parent_name not available in the telemetry"]
