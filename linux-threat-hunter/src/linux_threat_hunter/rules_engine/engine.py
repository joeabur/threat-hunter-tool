"""Rule evaluation: match, threshold, sequence, baseline, IOC and correlation rules."""

from __future__ import annotations

import hashlib
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from linux_threat_hunter.attack.techniques import attack_entry
from linux_threat_hunter.baseline.core import BaselineDiff
from linux_threat_hunter.evidence.store import EvidenceSet
from linux_threat_hunter.ioc.matcher import IocSet
from linux_threat_hunter.models import Finding, Record, RuleStatus, severity_rank
from linux_threat_hunter.rules_engine.conditions import (
    ConditionError,
    EvalContext,
    evaluate,
    get_field,
    validate_condition,
)
from linux_threat_hunter.rules_engine.loader import Rule
from linux_threat_hunter.rules_engine.schema import PLACEHOLDER_RE
from linux_threat_hunter.utils.timeutil import to_iso

DEFAULT_ARTIFACT = {
    "process": "pid {pid} {exe}",
    "persistence": "{path}",
    "auth": "{program} event on line {line_no}",
    "network": "{proto} {local_addr}:{local_port} -> {remote_addr}:{remote_port} (pid {pid})",
    "file": "{path}",
    "event": "{command}",
    "baseline": "{category}: {key}",
    "findings": "{join_field}={join_value}",
}
SOURCE_FILE_HINT = {
    "process": "processes.json",
    "persistence": "persistence.json",
    "auth": "auth.log",
    "network": "network.json",
    "file": "files.json",
    "event": "events.json",
}
DROP_FROM_EVIDENCE = {
    "commands_text",
    "referenced_paths_exist",
    "has_user_field",
    "spool",
    "parent_sha256",
}


@dataclass
class HuntResult:
    findings: list[Finding] = field(default_factory=list)
    statuses: list[RuleStatus] = field(default_factory=list)
    stats: dict[str, Any] = field(default_factory=dict)


def render(template: str, data: dict[str, Any]) -> str:
    def sub(m: Any) -> str:
        val = get_field(data, m.group(1))
        if isinstance(val, list):
            return ", ".join(str(v) for v in val) or "none"
        return "unknown" if val is None else str(val)

    return PLACEHOLDER_RE.sub(sub, template)


def entities_from(data: dict[str, Any]) -> dict[str, Any]:
    ents = {
        "pid": data.get("pid"),
        "path": data.get("path") or data.get("exe") or data.get("process_exe"),
        "exec_path": data.get("exec_path"),
        "ip": data.get("src_ip") or data.get("remote_addr"),
        "user": data.get("user"),
        "sha256": data.get("sha256"),
    }
    return {k: v for k, v in ents.items() if v not in (None, "")}


def _view(data: dict[str, Any], limit: int = 500) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in data.items():
        if k in DROP_FROM_EVIDENCE or k.startswith("_"):
            continue
        if k == "content" and isinstance(v, str):
            out["content_excerpt"] = v[:600] + (" ..." if len(v) > 600 else "")
        elif isinstance(v, str) and len(v) > limit:
            out[k] = v[:limit] + " ..."
        elif isinstance(v, (str, int, float, bool, list, dict)) or v is None:
            out[k] = v
    return out


class Engine:
    def __init__(
        self,
        rules: list[Rule],
        config: dict[str, Any],
        iocs: IocSet | None = None,
        baseline_diff: BaselineDiff | None = None,
    ) -> None:
        self.rules = rules
        self.config = config
        self.iocs = iocs
        self.diff = baseline_diff
        self.ctx = EvalContext(config["variables"], config["limits"])
        errors: list[str] = []
        for key, nodes in config["allowlists"].items():
            if not isinstance(nodes, list):
                errors.append(f"allowlists.{key}: must be a list of conditions")
                continue
            for i, node in enumerate(nodes):
                validate_condition(node, f"allowlists.{key}[{i}]", errors, self.ctx)
        if errors:
            raise ConditionError("; ".join(errors))

    # ------------------------------------------------------------------ helpers
    def _override(self, rule: Rule) -> dict[str, Any]:
        return self.config["rule_overrides"].get(rule.id, {})

    def _params(self, rule: Rule) -> dict[str, Any]:
        return {**rule.data.get("params", {}), **self._override(rule).get("params", {})}

    def _allow_nodes(self, rule: Rule) -> list[dict[str, Any]]:
        al = self.config["allowlists"]
        return [*al.get("*", []), *al.get(rule.id, []), *rule.data.get("allowlist", [])]

    def _allowed(self, rule: Rule, data: dict[str, Any]) -> bool:
        return any(evaluate(n, data, self.ctx) for n in self._allow_nodes(rule))

    def _make(
        self,
        rule: Rule,
        ev: EvidenceSet,
        *,
        key: str,
        data: dict[str, Any],
        source: str,
        timestamp: datetime | None,
        evidence: dict[str, Any],
        entities: dict[str, Any],
        ioc_matches: list[dict[str, Any]] | None = None,
        severity: str | None = None,
        related: list[str] | None = None,
        missing: list[str] | None = None,
    ) -> Finding:
        d = rule.data
        ov = self._override(rule)
        fid = "LTH-F-" + hashlib.sha256(f"{rule.id}|{key}".encode()).hexdigest()[:12]
        artifact_tpl = d["finding"].get("artifact") or DEFAULT_ARTIFACT.get(d["data_source"], "{key}")
        return Finding(
            id=fid,
            rule_id=rule.id,
            rule_version=rule.version,
            rule_name=d["name"],
            title=render(d["finding"]["title"], data),
            explanation=render(d["finding"]["explanation"], data),
            severity=severity or ov.get("severity", d["severity"]),
            confidence=ov.get("confidence", d["confidence"]),
            classification=d["classification"],
            observed_at=to_iso(timestamp or ev.collected_at),
            timestamp_basis="event" if timestamp else "collection",
            timezone_context=(
                "UTC (normalized); " + str(data.get("timezone_context", "source offset preserved in raw timestamp"))
                if timestamp
                else f"collection time, UTC (host timezone: {ev.timezone_name})"
            ),
            evidence_source=source,
            artifact=render(artifact_tpl, data),
            rationale=d["rationale"].strip(),
            evidence=evidence,
            entities=entities,
            ioc_matches=ioc_matches or [],
            attack=[attack_entry(m["tactic"], m["technique"]) for m in d.get("attack", [])],
            false_positives=list(d["false_positives"]),
            investigation_steps=list(d["investigation_steps"]),
            missing_context=[*d.get("limitations", []), *(missing or [])],
            related_findings=related or [],
        )

    # ---------------------------------------------------------------------- run
    def run(self, ev: EvidenceSet) -> HuntResult:
        result = HuntResult()
        result.stats["records"] = {k: len(v) for k, v in ev.records.items()}
        ordered = sorted(self.rules, key=lambda r: (r.type == "correlation", r.id))
        by_rule: dict[str, list[Finding]] = {}
        skipped_reason: dict[str, str] = {}
        for rule in ordered:
            status = RuleStatus(rule.id, rule.version, rule.data["name"], "executed")
            result.statuses.append(status)
            reason = self._skip_reason(rule, ev)
            if reason:
                status.status, status.reason = "skipped", reason
                skipped_reason[rule.id] = reason
                continue
            try:
                found = self._dispatch(rule, ev, status, by_rule, skipped_reason)
            except ConditionError as exc:
                status.status, status.reason = "skipped", f"rule error at run time: {exc}"
                continue
            cap = self.config["limits"]["max_findings_per_rule"]
            if len(found) > cap:
                status.notes.append(
                    f"findings capped at {cap} (limits.max_findings_per_rule); {len(found) - cap} not shown"
                )
                found = found[:cap]
            status.findings = len(found)
            by_rule[rule.id] = found
            result.findings.extend(found)
        result.statuses.sort(key=lambda s: s.rule_id)
        return result

    def _skip_reason(self, rule: Rule, ev: EvidenceSet) -> str:
        ov = self._override(rule)
        if rule.id in self.config["disabled_rules"] or ov.get("enabled") is False:
            return "disabled by configuration"
        if rule.data.get("enabled") is False:
            return "disabled in rule definition"
        t, src = rule.type, rule.data_source
        if t == "baseline":
            if self.diff is None:
                return "no baseline supplied (use --baseline)"
            cats = rule.data["baseline"]["categories"]
            if not any(c in self.diff.categories_compared for c in cats):
                why = "; ".join(f"{c}: {self.diff.categories_skipped.get(c, 'n/a')}" for c in cats)
                return f"baseline category not comparable ({why})"
            return ""
        if t == "correlation":
            return ""
        if src not in ev.available:
            return f"no {src} telemetry in evidence"
        if t == "ioc" and self.iocs is None:
            return "no IOC file supplied (use --iocs)"
        return ""

    def _dispatch(
        self,
        rule: Rule,
        ev: EvidenceSet,
        status: RuleStatus,
        by_rule: dict[str, list[Finding]],
        skipped: dict[str, str],
    ) -> list[Finding]:
        handler = {
            "match": self._match,
            "threshold": self._threshold,
            "sequence": self._sequence,
            "baseline": self._baseline,
            "ioc": self._ioc,
        }.get(rule.type)
        if rule.type == "correlation":
            return self._correlate(rule, ev, status, by_rule, skipped)
        assert handler is not None
        return handler(rule, ev, status)

    # --------------------------------------------------------------- rule types
    def _match(self, rule: Rule, ev: EvidenceSet, status: RuleStatus) -> list[Finding]:
        out: list[Finding] = []
        for rec in ev.of(rule.data_source):
            if not evaluate(rule.data["conditions"], rec.data, self.ctx):
                continue
            if self._allowed(rule, rec.data):
                status.suppressed += 1
                continue
            out.append(
                self._make(
                    rule,
                    ev,
                    key=rec.ref,
                    data=rec.data,
                    source=rec.source,
                    timestamp=rec.timestamp,
                    evidence={"record_ref": rec.ref, **_view(rec.data)},
                    entities=entities_from(rec.data),
                )
            )
        return out

    def _timed(self, rule: Rule, ev: EvidenceSet, status: RuleStatus, cond: dict[str, Any] | None) -> list[Record]:
        recs = []
        for rec in ev.of(rule.data_source):
            if cond is not None and not evaluate(cond, rec.data, self.ctx):
                continue
            if self._allowed(rule, rec.data):
                status.suppressed += 1
                continue
            recs.append(rec)
        untimed = [r for r in recs if r.timestamp is None]
        if untimed:
            status.notes.append(f"{len(untimed)} matching records had no usable timestamp and were not counted")
        return sorted((r for r in recs if r.timestamp is not None), key=_ts)

    def _group(self, rule: Rule, recs: list[Record]) -> dict[tuple[Any, ...], list[Record]]:
        groups: dict[tuple[Any, ...], list[Record]] = defaultdict(list)
        for r in recs:
            vals = tuple(get_field(r.data, g) for g in rule.data["group_by"])
            if all(v is not None for v in vals):
                groups[vals].append(r)
        return groups

    def _threshold(self, rule: Rule, ev: EvidenceSet, status: RuleStatus) -> list[Finding]:
        p = self._params(rule)
        count, window = int(p["count"]), float(p["window_seconds"])
        out: list[Finding] = []
        recs = self._timed(rule, ev, status, rule.data["conditions"])
        for gvals, events in self._group(rule, recs).items():
            i = 0
            while i < len(events):
                j = i
                while j + 1 < len(events) and (_ts(events[j + 1]) - _ts(events[i])).total_seconds() <= window:
                    j += 1
                if j - i + 1 < count:
                    i += 1
                    continue
                k = j
                while k + 1 < len(events) and (_ts(events[k + 1]) - _ts(events[k])).total_seconds() <= window:
                    k += 1
                cluster = events[i : k + 1]
                out.append(self._threshold_finding(rule, ev, gvals, cluster, count, window))
                i = k + 1
        return out

    def _threshold_finding(
        self,
        rule: Rule,
        ev: EvidenceSet,
        gvals: tuple[Any, ...],
        cluster: list[Record],
        count: int,
        window: float,
    ) -> Finding:
        group = dict(zip(rule.data["group_by"], gvals, strict=True))
        users = sorted({str(r.data["user"]) for r in cluster if r.data.get("user")})
        first, last = cluster[0], cluster[-1]
        data = {
            **group,
            "count": len(cluster),
            "threshold": count,
            "window_seconds": int(window),
            "first_seen": to_iso(_ts(first)),
            "last_seen": to_iso(_ts(last)),
            "distinct_users": len(users),
            "users": ", ".join(users[:10]),
        }
        evidence = {
            **data,
            "group": group,
            "sample_refs": [r.ref for r in cluster[:5]],
            "sample_lines": [r.data.get("raw", "") for r in cluster[:3]],
        }
        ents = entities_from(group)
        if len(users) == 1:
            ents["user"] = users[0]
        return self._make(
            rule,
            ev,
            key=f"{gvals}|{first.ref}",
            data=data,
            source=first.source,
            timestamp=last.timestamp,
            evidence=evidence,
            entities=ents,
        )

    def _sequence(self, rule: Rule, ev: EvidenceSet, status: RuleStatus) -> list[Finding]:
        p = self._params(rule)
        count, window = int(p["count"]), float(p["window_seconds"])
        seq = rule.data["sequence"]
        recs = self._timed(rule, ev, status, None)
        out: list[Finding] = []
        for gvals, events in self._group(rule, recs).items():
            firsts = [r for r in events if evaluate(seq["first"], r.data, self.ctx)]
            for t in (r for r in events if evaluate(seq["then"], r.data, self.ctx)):
                prior = [f for f in firsts if 0 <= (_ts(t) - _ts(f)).total_seconds() <= window]
                if len(prior) < count:
                    continue
                group = dict(zip(rule.data["group_by"], gvals, strict=True))
                users = sorted({str(f.data["user"]) for f in prior if f.data.get("user")})
                data = {
                    **t.data,
                    **group,
                    "failures": len(prior),
                    "window_seconds": int(window),
                    "failed_users": ", ".join(users[:10]),
                    "first_failure": to_iso(_ts(prior[0])),
                    "threshold": count,
                }
                evidence = {
                    "record_ref": t.ref,
                    "success_line": t.data.get("raw"),
                    "failures": len(prior),
                    "window_seconds": int(window),
                    "failed_for_users": users,
                    "failure_refs": [f.ref for f in prior[:5]],
                    "failure_sample_lines": [f.data.get("raw", "") for f in prior[:3]],
                    "first_failure_at": to_iso(_ts(prior[0])),
                }
                out.append(
                    self._make(
                        rule,
                        ev,
                        key=f"{t.ref}|{gvals}",
                        data=data,
                        source=t.source,
                        timestamp=t.timestamp,
                        evidence=evidence,
                        entities=entities_from(t.data),
                    )
                )
        return out

    def _baseline(self, rule: Rule, ev: EvidenceSet, status: RuleStatus) -> list[Finding]:
        assert self.diff is not None
        spec = rule.data["baseline"]
        out: list[Finding] = []
        for ch in self.diff.changes:
            if ch["category"] not in spec["categories"] or ch["change"] not in spec["changes"]:
                continue
            if "where" in spec and not evaluate(spec["where"], ch, self.ctx):
                continue
            if self._allowed(rule, ch):
                status.suppressed += 1
                continue
            evidence = {k: ch[k] for k in ("category", "key", "change", "changed_fields", "old", "new")}
            src = {
                "persistence": "persistence.json",
                "files": "files.json",
                "executables": "processes.json",
                "listeners": "network.json",
                "privileged_users": "auth.log",
            }[ch["category"]]
            out.append(
                self._make(
                    rule,
                    ev,
                    key=f"{ch['category']}|{ch['key']}|{ch['change']}",
                    data=ch,
                    source=src,
                    timestamp=None,
                    evidence=evidence,
                    entities=entities_from(ch),
                    missing=[
                        "Baseline comparison shows a difference, not intent: updates and admin work also change state."
                    ],
                )
            )
        return out

    def _ioc(self, rule: Rule, ev: EvidenceSet, status: RuleStatus) -> list[Finding]:
        assert self.iocs is not None
        spec = rule.data["ioc"]
        wanted = set(spec["indicator_types"])
        group_by: list[str] = spec.get("group_by", [])
        out: list[Finding] = []
        seen: dict[tuple[Any, ...], tuple[Finding, list[str]]] = {}
        for rec in ev.of(rule.data_source):
            matches = [m for m in self.iocs.match_record(rule.data_source, rec.data) if m["indicator_type"] in wanted]
            if not matches:
                continue
            if self._allowed(rule, rec.data):
                status.suppressed += 1
                continue
            if group_by:
                gkey = (matches[0]["indicator"], *(get_field(rec.data, g) for g in group_by))
                if gkey in seen:
                    seen[gkey][1].append(rec.ref)
                    continue
            sevs = [m["severity"] for m in matches if m["severity"]]
            severity = max(sevs, key=severity_rank) if sevs else None
            data = {
                **rec.data,
                "indicator": matches[0]["indicator"],
                "indicator_type": matches[0]["indicator_type"],
                "matched_field": matches[0]["matched_field"],
                "match_count": len(matches),
            }
            finding = self._make(
                rule,
                ev,
                key=f"{rec.ref}|{matches[0]['indicator']}",
                data=data,
                source=rec.source,
                timestamp=rec.timestamp,
                evidence={"record_ref": rec.ref, **_view(rec.data)},
                entities=entities_from(rec.data),
                ioc_matches=matches,
                severity=severity,
            )
            out.append(finding)
            if group_by:
                seen[gkey] = (finding, [rec.ref])
        for finding, refs in seen.values():
            if len(refs) > 1:
                finding.evidence["occurrences"] = len(refs)
                finding.evidence["occurrence_refs"] = refs[:20]
        return out

    def _correlate(
        self,
        rule: Rule,
        ev: EvidenceSet,
        status: RuleStatus,
        by_rule: dict[str, list[Finding]],
        skipped: dict[str, str],
    ) -> list[Finding]:
        spec = rule.data["correlate"]
        join = spec["join_on"]
        window = self._params(rule).get("window_seconds")
        for rid in [*spec["a"], *spec["b"]]:
            if rid in skipped:
                status.notes.append(f"linked rule {rid} was skipped: {skipped[rid]}")
            elif rid not in by_rule and not any(r.id == rid for r in self.rules):
                status.notes.append(f"linked rule {rid} is not loaded")
        side_a = [f for rid in spec["a"] for f in by_rule.get(rid, [])]
        side_b = [f for rid in spec["b"] for f in by_rule.get(rid, [])]
        values = {f.entities[join] for f in side_a if join in f.entities}
        out: list[Finding] = []
        for value in sorted(values, key=str):
            linked_a: dict[str, Finding] = {}
            linked_b: dict[str, Finding] = {}
            for fa in (f for f in side_a if f.entities.get(join) == value):
                for fb in (f for f in side_b if f.entities.get(join) == value and f.id != fa.id):
                    both_timed = fa.timestamp_basis == "event" and fb.timestamp_basis == "event"
                    if spec.get("require_event_time") and not both_timed:
                        continue
                    if window and both_timed:
                        gap = abs((_parse(fa.observed_at) - _parse(fb.observed_at)).total_seconds())
                        if gap > float(window):
                            continue
                    linked_a[fa.id], linked_b[fb.id] = fa, fb
            if not linked_a:
                continue
            members = [*linked_a.values(), *linked_b.values()]
            rules_a = sorted({f.rule_id for f in linked_a.values()})
            rules_b = sorted({f.rule_id for f in linked_b.values()})
            data = {
                "join_field": join,
                "join_value": value,
                "rule_a": ", ".join(rules_a),
                "rule_b": ", ".join(rules_b),
            }
            evidence = {
                "join": {join: value},
                "window_seconds": window,
                "linked_findings": [
                    {
                        "id": f.id,
                        "rule_id": f.rule_id,
                        "title": f.title,
                        "observed_at": f.observed_at,
                        "timestamp_basis": f.timestamp_basis,
                    }
                    for f in members
                ],
            }
            timed = [f for f in members if f.timestamp_basis == "event"]
            latest = _parse(max(f.observed_at for f in timed)) if len(timed) == len(members) else None
            finding = self._make(
                rule,
                ev,
                key=f"{join}={value}",
                data=data,
                source="correlation",
                timestamp=latest,
                evidence=evidence,
                entities={join: value},
                related=[f.id for f in members],
            )
            for f in members:
                f.related_findings.append(finding.id)
            out.append(finding)
        return out


def _ts(rec: Record) -> datetime:
    assert rec.timestamp is not None  # callers only pass records filtered by _timed()
    return rec.timestamp


def _parse(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))
