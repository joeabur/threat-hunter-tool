"""Evaluation of pattern rules against normalised records."""

from __future__ import annotations

import hashlib
import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any

from ..attack import resolve
from ..config import Config
from ..models import Finding, Record, Rule
from ..utils.redact import Redactor
from ..utils.timeutil import to_iso
from .conditions import MISSING, eval_group, get_field

_PLACEHOLDER = re.compile(r"\{([a-z0-9_.]+)\}")
_MAX_VALUE_CHARS = 600


@dataclass
class RuleStats:
    rule_id: str
    status: str = "executed"  # executed | skipped | disabled
    reason: str | None = None
    records_examined: int = 0
    matched: int = 0
    skipped_missing_fields: int = 0
    findings: int = 0
    capped: bool = False

    def to_dict(self) -> dict[str, Any]:
        return self.__dict__.copy()


@dataclass
class EvalContext:
    config: Config
    redactor: Redactor
    host: str | None
    lists: dict[str, list[str]] = field(default_factory=dict)


def build_lists(config: Config) -> dict[str, list[str]]:
    lists = {k: list(v) for k, v in config.allowlists.items()}
    lists["writable_locations"] = list(config.writable_locations)
    return lists


def artifact_identity(record: Record) -> str:
    d = record.data
    if record.source in {"persistence", "file"}:
        return str(d.get("path") or record.ref)
    if record.source == "process":
        return f"{d.get('path')}|{d.get('cmdline')}"
    if record.source == "network":
        return "|".join(
            str(d.get(k))
            for k in ("proto", "local_address", "local_port", "remote_address", "remote_host",
                      "remote_port", "process_name")
        )  # fmt: skip
    if record.source == "log":
        return f"{d.get('process')}|{record.time_original}|{hashlib.sha256(str(d.get('message')).encode()).hexdigest()[:12]}"
    return str(record.ref)


_ARTIFACT_KEYS = {
    "process": ("pid", "name", "path", "user"),
    "persistence": ("kind", "path", "label", "program_path"),
    "network": ("proto", "state", "local_address", "local_port", "remote_address", "remote_host",
                "remote_port", "process_name", "pid"),
    "file": ("path", "kind", "sha256"),
    "log": ("process", "pid", "subsystem"),
    "system": ("hostname", "os_version"),
}  # fmt: skip


def make_finding_id(rule: Rule, identity: str, group: str = "") -> str:
    digest = hashlib.sha256(f"{rule.id}|{rule.version}|{identity}|{group}".encode()).hexdigest()
    return f"F-{digest[:12]}"


def _clip(value: Any, redactor: Redactor) -> Any:
    if isinstance(value, str):
        value = redactor.redact(value)
        return value if len(value) <= _MAX_VALUE_CHARS else value[:_MAX_VALUE_CHARS] + "…"
    if isinstance(value, list):
        return [_clip(v, redactor) for v in value[:20]]
    return value


def render_title(template: str, data: dict[str, Any]) -> str:
    def sub(match: re.Match[str]) -> str:
        value = get_field(data, match.group(1))
        return "?" if value is MISSING or value is None else str(value)[:80]

    return _PLACEHOLDER.sub(sub, template)[:200]


def build_finding(
    rule: Rule,
    record: Record,
    ctx: EvalContext,
    *,
    group: str = "",
    extra_evidence: dict[str, Any] | None = None,
    ioc: dict[str, Any] | None = None,
    baseline_change: dict[str, Any] | None = None,
    severity: str | None = None,
    title_data: dict[str, Any] | None = None,
) -> Finding:
    data = record.data
    evidence: dict[str, Any] = {}
    for fld in rule.evidence_fields:
        value = get_field(data, fld)
        if value is not MISSING and value is not None:
            evidence[fld] = _clip(value, ctx.redactor)
    if extra_evidence:
        evidence.update({k: _clip(v, ctx.redactor) for k, v in extra_evidence.items()})
    missing = [
        f"{fld} not available in the telemetry"
        for fld in rule.context_fields
        if get_field(data, fld) is MISSING or get_field(data, fld) is None
    ]
    artifact = {
        k: _clip(data[k], ctx.redactor) for k in _ARTIFACT_KEYS.get(record.source, ()) if k in data
    }
    attack = []
    for tid in rule.techniques:
        mapping = resolve(tid)
        if mapping:
            attack.append(
                {"id": mapping.technique_id, "name": mapping.name, "tactics": mapping.tactics,
                 "url": mapping.url}
            )  # fmt: skip
    observed = {k: evidence[k] for k in list(evidence)[:6]}
    summary = "; ".join(f"{k}={v}" for k, v in observed.items())
    explanation = rule.description + (f" Observed: {summary}." if summary else "")
    return Finding(
        finding_id=make_finding_id(rule, artifact_identity(record), group),
        rule_id=rule.id,
        rule_version=rule.version,
        rule_name=rule.name,
        title=render_title(rule.title, {**data, "source": record.source, **(title_data or {})}),
        explanation=explanation,
        category=rule.category,
        severity=severity or rule.severity,
        confidence=rule.confidence,
        source=record.source,
        evidence_ref=str(record.ref),
        observed_at=to_iso(record.observed_at),
        time_original=record.time_original,
        time_zone=record.time_zone,
        host=ctx.host,
        artifact=artifact,
        evidence=evidence,
        rationale=rule.rationale,
        attack=attack,
        ioc=ioc,
        baseline_change=baseline_change,
        missing_context=missing,
        false_positives=rule.false_positives,
        investigation=rule.investigation,
        references=rule.references,
    )


def effective_threshold(rule: Rule, config: Config) -> dict[str, Any] | None:
    thr = dict(rule.threshold) if rule.threshold else None
    override = config.rule_overrides.get(rule.id, {}).get("threshold")
    if thr and isinstance(override, dict):
        for key in ("count", "window_seconds"):
            if isinstance(override.get(key), int) and override[key] >= (2 if key == "count" else 1):
                thr[key] = override[key]
    return thr


def evaluate_pattern_rule(
    rule: Rule, records_by_source: dict[str, list[Record]], ctx: EvalContext
) -> tuple[list[Finding], RuleStats]:
    stats = RuleStats(rule.id)
    cap = ctx.config.limit("max_findings_per_rule")
    max_input = ctx.config.limit("max_regex_input_chars")
    matched: list[Record] = []
    for source in rule.sources:
        for rec in records_by_source.get(source, []):
            stats.records_examined += 1
            if any(get_field(rec.data, f) in (MISSING, None) for f in rule.requires):
                stats.skipped_missing_fields += 1
                continue
            if eval_group(rule.conditions, rec.data, ctx.lists, max_input):
                matched.append(rec)
    stats.matched = len(matched)
    findings: list[Finding] = []
    thr = effective_threshold(rule, ctx.config)
    if thr is None:
        for rec in matched:
            if len(findings) >= cap:
                stats.capped = True
                break
            findings.append(build_finding(rule, rec, ctx))
    else:
        findings = _threshold_findings(rule, matched, thr, ctx, stats, cap)
    stats.findings = len(findings)
    return findings, stats


def _threshold_findings(
    rule: Rule,
    matched: list[Record],
    thr: dict[str, Any],
    ctx: EvalContext,
    stats: RuleStats,
    cap: int,
) -> list[Finding]:
    groups: dict[str, list[Record]] = defaultdict(list)
    for rec in matched:
        key = get_field(rec.data, thr["group_by"])
        if key is MISSING or key is None or rec.observed_at is None:
            stats.skipped_missing_fields += 1  # cannot group or window without these
            continue
        groups[str(key)].append(rec)
    window = timedelta(seconds=thr["window_seconds"])
    findings: list[Finding] = []
    for key in sorted(groups):
        recs = sorted(groups[key], key=lambda r: r.observed_at)  # type: ignore[arg-type, return-value]
        best: tuple[int, int] | None = None
        lo = 0
        for hi in range(len(recs)):
            while recs[hi].observed_at - recs[lo].observed_at > window:  # type: ignore[operator]
                lo += 1
            if hi - lo + 1 >= thr["count"] and (best is None or hi - lo > best[1] - best[0]):
                best = (lo, hi)
        if best is None:
            continue
        if len(findings) >= cap:
            stats.capped = True
            break
        span = recs[best[0] : best[1] + 1]
        first = span[0]
        evidence = {
            "group_by": thr["group_by"],
            "group_value": key,
            "event_count": len(span),
            "threshold_count": thr["count"],
            "window_seconds": thr["window_seconds"],
            "first_seen": to_iso(span[0].observed_at),
            "last_seen": to_iso(span[-1].observed_at),
            "sample_refs": [str(r.ref) for r in span[:10]],
        }
        findings.append(
            build_finding(
                rule, first, ctx, group=key, extra_evidence=evidence,
                title_data={**first.data, "group_value": key, "event_count": len(span)},
            )
        )  # fmt: skip
    return findings


def finding_sort_key(f: Finding) -> tuple[Any, ...]:
    from ..models import severity_rank

    return (-severity_rank(f.severity), f.rule_id, f.finding_id)
