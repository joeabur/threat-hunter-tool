from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..evidence.loader import EvidenceSet
from .model import CATEGORIES, Baseline, observations_from_evidence


@dataclass
class Change:
    category: str
    key: str
    change: str  # added | removed | modified
    before: dict[str, Any] | None
    after: dict[str, Any] | None
    changed_attributes: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "key": self.key,
            "change": self.change,
            "changed_attributes": self.changed_attributes,
            "before": self.before,
            "after": self.after,
        }


def compare_observations(
    baseline_obs: dict[str, dict[str, dict[str, Any]]],
    current_obs: dict[str, dict[str, dict[str, Any]]],
) -> list[Change]:
    changes: list[Change] = []
    for cat in CATEGORIES:
        before_all = baseline_obs.get(cat, {})
        after_all = current_obs.get(cat, {})
        for key in sorted(set(before_all) | set(after_all)):
            before, after = before_all.get(key), after_all.get(key)
            if before is None and after is not None:
                changes.append(Change(cat, key, "added", None, after, sorted(after)))
            elif after is None and before is not None:
                changes.append(Change(cat, key, "removed", before, None, sorted(before)))
            elif before is not None and after is not None and before != after:
                attrs = sorted(k for k in set(before) | set(after) if before.get(k) != after.get(k))
                changes.append(Change(cat, key, "modified", before, after, attrs))
    return changes


def compare_to_baseline(baseline: Baseline, ev: EvidenceSet) -> list[Change]:
    """Compare only categories the current evidence actually covers.

    If the evidence set has no file telemetry, 'every baselined file was removed' would be a
    false statement; such categories are skipped and reported by the caller.
    """
    current = observations_from_evidence(ev)
    covered = covered_categories(ev)
    base = {c: v for c, v in baseline.observations.items() if c in covered}
    cur = {c: v for c, v in current.items() if c in covered}
    return compare_observations(base, cur)


def covered_categories(ev: EvidenceSet) -> set[str]:
    covered: set[str] = set()
    if "persistence" in ev.files_loaded_sources():
        covered.add("persistence")
    if "file" in ev.files_loaded_sources():
        covered.add("files")
    if "network" in ev.files_loaded_sources():
        covered.add("listeners")
    if "system" in ev.files_loaded_sources():
        covered.add("config")
    return covered
