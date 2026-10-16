"""Assemble the results document (the single source for all report formats)."""

from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime
from typing import Any

from linux_threat_hunter import __version__
from linux_threat_hunter.attack.techniques import TECHNIQUES, technique_url
from linux_threat_hunter.baseline.core import BaselineDiff
from linux_threat_hunter.evidence.store import EvidenceSet
from linux_threat_hunter.ioc.matcher import IocSet
from linux_threat_hunter.models import SEVERITIES, severity_rank
from linux_threat_hunter.rules_engine.engine import HuntResult
from linux_threat_hunter.utils.timeutil import to_iso

RESULTS_SCHEMA_VERSION = 1

LIMITATIONS = [
    "This is a hunting aid, not an EDR: it sees only the telemetry that was collected or supplied.",
    "A finding is a lead for an analyst. Severity and confidence are separate; neither proves compromise.",
    "Missing telemetry is not evidence of absence. Rules whose data was unavailable were skipped (see rules table).",
    "Process, network and file observations are point-in-time snapshots; short-lived activity can be missed.",
    "Syslog-format timestamps carry no year or zone; they are interpreted using the evidence manifest (timezone, collection time).",
    "Baselines record whatever state existed when created (including malicious state) and drift after legitimate updates.",
    "An ATT&CK mapping relates a rule's behavior to a technique. Techniques not listed were not necessarily absent, "
    "and coverage is partial.",
    "Collected data (command lines, usernames, log lines) can be sensitive; redaction is pattern-based and best-effort.",
]


def _missing_telemetry(ev: EvidenceSet, diff: BaselineDiff | None) -> list[dict[str, str]]:
    items: list[dict[str, str]] = []
    for c in ev.manifest.get("collectors", []) if isinstance(ev.manifest.get("collectors"), list) else []:
        if not isinstance(c, dict):
            continue
        status = c.get("status")
        if status in {"failed", "partial", "skipped"}:
            detail = "; ".join([*map(str, c.get("errors", [])[:5]), *map(str, c.get("notes", [])[:5])])
            items.append({"kind": f"collector_{status}", "source": str(c.get("name")), "detail": detail})
    for src in ("process", "persistence", "auth", "network", "file", "event"):
        if src not in ev.available:
            items.append(
                {
                    "kind": "source_unavailable",
                    "source": src,
                    "detail": "no usable data in this evidence set; dependent rules skipped",
                }
            )
    for w in ev.warnings:
        items.append({"kind": "evidence_warning", "source": "evidence", "detail": w})
    if diff:
        for cat, why in diff.categories_skipped.items():
            items.append({"kind": "baseline_category_skipped", "source": cat, "detail": why})
    return items


def build_results(
    ev: EvidenceSet,
    hunt: HuntResult,
    *,
    iocs: IocSet | None,
    diff: BaselineDiff | None,
    baseline_path: str | None,
    rules_dir: str,
) -> dict[str, Any]:
    findings = sorted(
        (f.to_dict() for f in hunt.findings),
        key=lambda f: (-severity_rank(f["severity"]), f["rule_id"], f["id"]),
    )
    sev = Counter(f["severity"] for f in findings)
    techniques: dict[str, dict[str, Any]] = {}
    for f in findings:
        for m in f["attack"]:
            t = techniques.setdefault(
                m["technique"],
                {
                    "technique": m["technique"],
                    "title": m["title"],
                    "url": m["url"],
                    "tactics": set(),
                    "finding_ids": [],
                },
            )
            t["tactics"].add(m["tactic"])
            t["finding_ids"].append(f["id"])
    for t in techniques.values():
        t["tactics"] = sorted(t["tactics"])
    return {
        "schema_version": RESULTS_SCHEMA_VERSION,
        "tool": {"name": "linux-threat-hunter", "version": __version__},
        "generated_at": to_iso(datetime.now(UTC)),
        "host": {k: ev.host.get(k) for k in ("hostname", "kernel", "architecture", "distribution", "init_system")},
        "evidence": {
            "path": str(ev.root),
            "collected_at": to_iso(ev.collected_at),
            "timezone": ev.timezone_name,
            "profile": ev.manifest.get("profile"),
            "synthetic": bool(ev.manifest.get("synthetic", False)),
            "collection_is_root": ev.manifest.get("collection_is_root"),
            "file_sha256": ev.file_hashes,
            "collectors": ev.manifest.get("collectors", []),
        },
        "scope": {
            "sources_analyzed": sorted(ev.available),
            "records_by_source": hunt.stats.get("records", {}),
            "total_records": ev.total_records,
            "rules_dir": rules_dir,
        },
        "iocs": {
            "file": iocs.path if iocs else None,
            "counts": iocs.counts if iocs else {},
            "matches": sum(len(f["ioc_matches"]) for f in findings),
        },
        "baseline": {
            "path": baseline_path,
            "categories_compared": diff.categories_compared if diff else [],
            "categories_skipped": diff.categories_skipped if diff else {},
            "change_counts": diff.counts() if diff else None,
        },
        "baseline_changes": diff.changes if diff else [],
        "rules": [s.to_dict() for s in hunt.statuses],
        "findings": findings,
        "summary": {
            "total_findings": len(findings),
            "by_severity": {s: sev.get(s, 0) for s in reversed(SEVERITIES)},
            "by_classification": dict(Counter(f["classification"] for f in findings)),
            "correlations": sum(1 for f in findings if f["classification"] == "correlation"),
            "rules_executed": sum(1 for s in hunt.statuses if s.status == "executed"),
            "rules_skipped": sum(1 for s in hunt.statuses if s.status == "skipped"),
            "attack_techniques_observed": sorted(techniques.values(), key=lambda t: t["technique"]),
        },
        "missing_telemetry": _missing_telemetry(ev, diff),
        "limitations": LIMITATIONS,
        "attack_registry": {tid: {"title": v[0], "url": technique_url(tid)} for tid, v in TECHNIQUES.items()},
    }
