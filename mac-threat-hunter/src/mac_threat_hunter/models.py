"""Typed data models shared across modules."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

SEVERITIES = ("informational", "low", "medium", "high", "critical")
CONFIDENCES = ("low", "medium", "high")
SOURCES = ("system", "process", "persistence", "network", "file", "log")
FINDING_CATEGORIES = ("heuristic", "ioc_match", "baseline_change")


def severity_rank(value: str) -> int:
    return SEVERITIES.index(value) if value in SEVERITIES else -1


@dataclass(frozen=True)
class EvidenceRef:
    """Pointer back to the source artifact: file within the evidence set plus record index."""

    file: str
    index: int | None = None

    def __str__(self) -> str:
        return f"{self.file}#{self.index}" if self.index is not None else self.file


@dataclass
class Record:
    """A normalised telemetry record (process, persistence artifact, connection, ...)."""

    source: str
    data: dict[str, Any]
    ref: EvidenceRef
    observed_at: datetime | None = None
    time_original: str | None = None
    time_zone: str = "unknown"


@dataclass
class AttackMapping:
    technique_id: str
    name: str
    tactics: list[str]
    url: str


@dataclass
class Rule:
    id: str
    name: str
    version: int
    type: str  # pattern | ioc | baseline
    sources: list[str]
    description: str
    rationale: str
    severity: str
    confidence: str
    category: str  # heuristic | ioc_match | baseline_change
    techniques: list[str] = field(default_factory=list)
    conditions: dict[str, Any] = field(default_factory=dict)
    threshold: dict[str, Any] | None = None
    requires: list[str] = field(default_factory=list)
    context_fields: list[str] = field(default_factory=list)
    attack_justification: str = ""
    evidence_fields: list[str] = field(default_factory=list)
    title: str = ""
    ioc: dict[str, Any] | None = None
    baseline: dict[str, Any] | None = None
    false_positives: list[str] = field(default_factory=list)
    investigation: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    enabled: bool = True
    path: str = ""


@dataclass
class Finding:
    finding_id: str
    rule_id: str
    rule_version: int
    rule_name: str
    title: str
    explanation: str
    category: str
    severity: str
    confidence: str
    source: str
    evidence_ref: str
    observed_at: str | None
    time_original: str | None
    time_zone: str
    host: str | None
    artifact: dict[str, Any]
    evidence: dict[str, Any]
    rationale: str
    attack: list[dict[str, Any]] = field(default_factory=list)
    ioc: dict[str, Any] | None = None
    baseline_change: dict[str, Any] | None = None
    missing_context: list[str] = field(default_factory=list)
    false_positives: list[str] = field(default_factory=list)
    investigation: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    suppressed: bool = False
    suppression_reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        from dataclasses import asdict

        return asdict(self)


@dataclass
class CollectorResult:
    name: str
    status: str  # ok | partial | failed | unsupported | skipped | dry_run
    records: list[dict[str, Any]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    privilege_note: str | None = None
    commands: list[str] = field(default_factory=list)
    raw_files: dict[str, str] = field(default_factory=dict)  # filename -> text (e.g. ndjson)

    def to_status(self) -> dict[str, Any]:
        return {
            "collector": self.name,
            "status": self.status,
            "record_count": len(self.records),
            "errors": self.errors,
            "notes": self.notes,
            "privilege_note": self.privilege_note,
        }
