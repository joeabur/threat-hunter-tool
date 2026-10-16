"""Typed data models shared across modules."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

SEVERITIES = ("informational", "low", "medium", "high", "critical")
CONFIDENCES = ("low", "medium", "high")
CLASSIFICATIONS = ("observation", "heuristic", "ioc_match", "correlation")
DATA_SOURCES = ("process", "persistence", "auth", "network", "file", "event")


def severity_rank(severity: str) -> int:
    return SEVERITIES.index(severity)


@dataclass
class Record:
    """One normalized observation (a process, a persistence artifact, an auth event...)."""

    type: str
    data: dict[str, Any]
    source: str  # evidence file the record came from
    index: int  # position (or line number) in that file
    timestamp: datetime | None = None  # event time (UTC) when the source records one

    @property
    def ref(self) -> str:
        return f"{self.source}#{self.index}"


@dataclass
class Finding:
    id: str
    rule_id: str
    rule_version: str
    rule_name: str
    title: str
    explanation: str
    severity: str
    confidence: str
    classification: str
    observed_at: str
    timestamp_basis: str  # "event" (from the source record) or "collection"
    timezone_context: str
    evidence_source: str
    artifact: str
    rationale: str
    evidence: dict[str, Any] = field(default_factory=dict)
    entities: dict[str, Any] = field(default_factory=dict)
    ioc_matches: list[dict[str, Any]] = field(default_factory=list)
    attack: list[dict[str, str]] = field(default_factory=list)
    false_positives: list[str] = field(default_factory=list)
    investigation_steps: list[str] = field(default_factory=list)
    missing_context: list[str] = field(default_factory=list)
    related_findings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return dict(self.__dict__)


@dataclass
class RuleStatus:
    rule_id: str
    version: str
    name: str
    status: str  # executed | skipped
    reason: str = ""
    findings: int = 0
    suppressed: int = 0
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return dict(self.__dict__)
