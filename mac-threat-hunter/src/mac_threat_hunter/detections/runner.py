from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from typing import Any

from .. import SCHEMA_VERSION, __version__
from ..baseline.compare import Change, compare_to_baseline, covered_categories
from ..baseline.model import WARNINGS, Baseline
from ..config import Config, make_redactor
from ..evidence.loader import EvidenceSet
from ..ioc.loader import IocSet
from ..ioc.matcher import match_ioc_rule
from ..models import EvidenceRef, Finding, Record, severity_rank
from ..rules_engine.conditions import eval_group
from ..rules_engine.evaluator import (
    EvalContext,
    RuleStats,
    build_finding,
    build_lists,
    evaluate_pattern_rule,
    finding_sort_key,
)
from ..rules_engine.loader import RuleSet
from ..utils.timeutil import to_iso, utc_now

LIMITATIONS = (
    "Findings are leads for an analyst, not verdicts. A heuristic finding is not proof of "
    "malicious activity and an IOC match is not proof of compromise.",
    "Absence of findings does not mean the host is clean: only the telemetry listed under "
    "'data sources analysed' was examined, and unlisted or failed sources were not.",
    "Unprivileged collection cannot see other users' processes, sockets or files; "
    "see collection errors for what was inaccessible.",
    "ATT&CK mappings describe the behaviour a rule looks for. Techniques not listed were "
    "not detected by this tool, which is not the same as being absent.",
    "Timestamps without an explicit zone are assumed to use the collection host's UTC offset "
    "(or UTC when unknown); see each finding's time zone context.",
    "This tool is read-only and is not an EDR replacement; it performs no remediation.",
)

_CATEGORY_SOURCE = {
    "persistence": "persistence",
    "files": "file",
    "listeners": "network",
    "config": "system",
}


@dataclass
class HuntResult:
    findings: list[Finding] = field(default_factory=list)
    suppressed: list[Finding] = field(default_factory=list)
    rule_stats: list[RuleStats] = field(default_factory=list)
    changes: list[Change] = field(default_factory=list)
    skipped_categories: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def _suppress(
    findings: list[Finding], config: Config, warnings: list[str]
) -> tuple[list[Finding], list[Finding]]:
    today = datetime.now(UTC).date()
    active: list[dict[str, Any]] = []
    for entry in config.suppressions:
        exp = entry.get("expires")
        if exp:
            try:
                if date.fromisoformat(str(exp)) < today:
                    warnings.append(
                        f"suppression for {entry['rule_id']} expired on {exp} and was ignored"
                    )
                    continue
            except ValueError:
                warnings.append(
                    f"suppression for {entry['rule_id']} has an invalid expiry; ignored"
                )
                continue
        active.append(entry)
    kept: list[Finding] = []
    suppressed: list[Finding] = []
    for f in findings:
        pool = {**f.artifact, **f.evidence}
        if f.ioc:
            pool["ioc_value"] = f.ioc.get("value")
        for entry in active:
            match = entry.get("match", {})
            if entry["rule_id"] == f.rule_id and all(pool.get(k) == v for k, v in match.items()):
                f.suppressed = True
                f.suppression_reason = entry["reason"]
                suppressed.append(f)
                break
        else:
            kept.append(f)
    return kept, suppressed


def _baseline_record(ev: EvidenceSet, category: str, key: str, change: Change) -> Record:
    source = _CATEGORY_SOURCE[category]
    attrs = dict(change.after or change.before or {})
    attrs["key"] = key
    attrs["changed_attributes"] = change.changed_attributes
    if category in {"persistence", "files"}:
        attrs["path"] = key
    for rec in ev.records.get(source, []):
        if category in {"persistence", "files"} and rec.data.get("path") == key:
            return Record(
                source,
                {**rec.data, **attrs},
                rec.ref,
                rec.observed_at,
                rec.time_original,
                rec.time_zone,
            )
        if category == "listeners" and rec.data.get("is_listener"):
            k = f"{rec.data.get('proto')}/{rec.data.get('local_port')}/{rec.data.get('process_name')}"
            if k == key:
                return Record(source, {**rec.data, **attrs}, rec.ref)
        if category == "config":
            return Record(source, attrs, rec.ref)
    return Record(source, attrs, EvidenceRef(f"baseline:{category}/{key}"))


def run_hunt(
    ev: EvidenceSet,
    ruleset: RuleSet,
    config: Config,
    *,
    iocs: IocSet | None = None,
    baseline: Baseline | None = None,
) -> HuntResult:
    result = HuntResult()
    ctx = EvalContext(config=config, redactor=make_redactor(config), host=ev.hostname,
                      lists=build_lists(config))  # fmt: skip
    all_findings: list[Finding] = []
    changes: list[Change] = []
    covered: set[str] = set()
    if baseline is not None:
        changes = compare_to_baseline(baseline, ev)
        covered = covered_categories(ev)
        result.changes = changes
        result.skipped_categories = sorted(
            c for c in baseline.observations if c not in covered and baseline.observations[c]
        )

    for rule in ruleset.rules:
        override = config.rule_overrides.get(rule.id, {})
        if not rule.enabled or override.get("enabled") is False:
            result.rule_stats.append(
                RuleStats(rule.id, "disabled", "disabled by rule or configuration")
            )
            continue
        if override.get("severity"):
            rule.severity = override["severity"]
        if override.get("confidence"):
            rule.confidence = override["confidence"]

        if rule.type == "baseline":
            assert rule.baseline is not None  # nosec B101 - type narrowing
            if baseline is None:
                result.rule_stats.append(
                    RuleStats(rule.id, "skipped", "no baseline supplied (use --baseline)")
                )
                continue
            cat = rule.baseline["category"]
            if cat not in covered:
                result.rule_stats.append(
                    RuleStats(rule.id, "skipped", f"evidence has no telemetry covering '{cat}'")
                )
                continue
            stats = RuleStats(rule.id)
            for change in changes:
                if change.category != cat or change.change != rule.baseline["change"]:
                    continue
                stats.records_examined += 1
                rec = _baseline_record(ev, cat, change.key, change)
                if "filters" in rule.baseline and not eval_group(
                    rule.baseline["filters"],
                    rec.data,
                    ctx.lists,
                    config.limit("max_regex_input_chars"),
                ):
                    continue
                stats.matched += 1
                if stats.findings >= config.limit("max_findings_per_rule"):
                    stats.capped = True
                    continue
                all_findings.append(
                    build_finding(
                        rule, rec, ctx, group=f"{cat}:{change.change}:{change.key}",
                        baseline_change=change.to_dict(),
                        extra_evidence={"changed_attributes": change.changed_attributes},
                        title_data={**rec.data},
                    )
                )  # fmt: skip
                stats.findings += 1
            result.rule_stats.append(stats)
            continue

        missing = [s for s in rule.sources if not ev.records.get(s)]
        if len(missing) == len(rule.sources):
            result.rule_stats.append(
                RuleStats(
                    rule.id, "skipped", f"no {'/'.join(missing)} telemetry in the evidence set"
                )
            )
            continue
        if rule.type == "ioc":
            if iocs is None:
                result.rule_stats.append(
                    RuleStats(rule.id, "skipped", "no IOC file supplied (use --iocs)")
                )
                continue
            findings, stats = match_ioc_rule(rule, ev.records, iocs, ctx)
        else:
            findings, stats = evaluate_pattern_rule(rule, ev.records, ctx)
        all_findings.extend(findings)
        result.rule_stats.append(stats)

    all_findings.sort(key=finding_sort_key)
    kept, suppressed = _suppress(all_findings, config, result.warnings)
    result.findings = kept
    result.suppressed = suppressed
    return result


def result_to_dict(
    ev: EvidenceSet,
    ruleset: RuleSet,
    hunt: HuntResult,
    config: Config,
    *,
    iocs: IocSet | None,
    baseline: Baseline | None,
    rule_dirs: list[str],
    ioc_path: str | None,
    baseline_path: str | None,
) -> dict[str, Any]:
    by_sev = dict.fromkeys(reversed(["informational", "low", "medium", "high", "critical"]), 0)
    by_cat = {"heuristic": 0, "ioc_match": 0, "baseline_change": 0}
    techniques: dict[str, dict[str, Any]] = {}
    for f in hunt.findings:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
        by_cat[f.category] = by_cat.get(f.category, 0) + 1
        for a in f.attack:
            entry = techniques.setdefault(a["id"], {**a, "finding_ids": [], "rule_ids": []})
            entry["finding_ids"].append(f.finding_id)
            if f.rule_id not in entry["rule_ids"]:
                entry["rule_ids"].append(f.rule_id)
    collection_failures = [
        c
        for c in ev.collector_status
        if c.get("status") in {"failed", "partial", "unsupported", "skipped"}
    ]
    ordered_sev = dict(sorted(by_sev.items(), key=lambda kv: -severity_rank(kv[0])))
    return {
        "schema_version": SCHEMA_VERSION,
        "tool_version": __version__,
        "generated_at": to_iso(utc_now()),
        "host": ev.host,
        "evidence": {
            "directory_name": ev.path.name,
            "synthetic": ev.synthetic,
            "manifest_present": ev.manifest is not None,
            "profile": (ev.manifest or {}).get("profile"),
            "collection": (ev.manifest or {}).get("collection"),
            "collected_at": to_iso(ev.collected_at),
            "files_loaded": ev.files_loaded,
            "record_counts": {k: len(v) for k, v in ev.records.items()},
            "total_records": ev.total_records(),
            "integrity_failures": ev.integrity_failures,
            "warnings": ev.warnings,
            "malformed_log_lines": ev.malformed_log_lines,
            "truncated_sources": ev.truncated_sources,
            "collector_status": ev.collector_status,
        },
        "inputs": {
            "rule_dirs": rule_dirs,
            "rules_loaded": len(ruleset.rules),
            "ioc_file": ioc_path,
            "ioc_set": (
                {
                    "name": iocs.name,
                    "count": iocs.count(),
                    "by_type": iocs.counts_by_type(),
                    "synthetic": iocs.synthetic,
                }
                if iocs
                else None
            ),
            "baseline_file": baseline_path,
            "baseline": (
                {
                    "created_at": baseline.created_at,
                    "host": baseline.host,
                    "skipped_categories": hunt.skipped_categories,
                }
                if baseline
                else None
            ),
        },
        "summary": {
            "findings_total": len(hunt.findings),
            "by_severity": ordered_sev,
            "by_category": by_cat,
            "ioc_matches": by_cat["ioc_match"],
            "baseline_changes": len(hunt.changes),
            "suppressed": len(hunt.suppressed),
            "rules_executed": sum(1 for s in hunt.rule_stats if s.status == "executed"),
            "rules_skipped": sum(1 for s in hunt.rule_stats if s.status == "skipped"),
            "rules_disabled": sum(1 for s in hunt.rule_stats if s.status == "disabled"),
            "attack_techniques_observed": sorted(techniques),
        },
        "attack": sorted(techniques.values(), key=lambda t: t["id"]),
        "findings": [f.to_dict() for f in hunt.findings],
        "suppressed_findings": [f.to_dict() for f in hunt.suppressed],
        "baseline_changes": [c.to_dict() for c in hunt.changes],
        "baseline_warnings": list(WARNINGS) if baseline else [],
        "rules": [s.to_dict() for s in hunt.rule_stats],
        "collection_failures": collection_failures,
        "warnings": hunt.warnings,
        "limitations": list(LIMITATIONS),
    }
