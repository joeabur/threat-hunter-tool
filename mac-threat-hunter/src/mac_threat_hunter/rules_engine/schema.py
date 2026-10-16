"""Rule schema validation. See docs/rule-authoring.md and schemas/rule.schema.json."""

from __future__ import annotations

import re
from typing import Any

from ..attack import TECHNIQUES, is_valid_id_format
from ..models import CONFIDENCES, SEVERITIES, SOURCES
from .conditions import validate_conditions

RULE_ID_RE = re.compile(r"^MTH-[A-Z]{2,8}-\d{3}$")
RULE_TYPES = ("pattern", "ioc", "baseline")
IOC_TYPES = ("sha256", "process_name", "path", "ip", "domain")
BASELINE_CATEGORIES = ("persistence", "files", "listeners", "config")
BASELINE_CHANGES = ("added", "removed", "modified")
TOP_KEYS = {
    "id", "name", "version", "type", "source", "description", "rationale", "severity",
    "confidence", "attack", "conditions", "threshold", "requires", "context_fields",
    "evidence_fields", "title", "ioc", "baseline", "false_positives", "investigation",
    "references", "enabled",
}  # fmt: skip
_FIELD_OK = re.compile(r"^[a-z0-9_.]+$")


def _text(rule: dict[str, Any], key: str, problems: list[str], min_len: int = 8) -> None:
    val = rule.get(key)
    if not isinstance(val, str) or len(val.strip()) < min_len:
        problems.append(f"'{key}' is required (a descriptive string)")


def _str_list(rule: dict[str, Any], key: str, problems: list[str], required: bool) -> None:
    val = rule.get(key)
    if val is None:
        if required:
            problems.append(f"'{key}' is required (non-empty list of strings)")
        return
    if not isinstance(val, list) or not all(isinstance(v, str) and v.strip() for v in val):
        problems.append(f"'{key}' must be a list of non-empty strings")
    elif required and not val:
        problems.append(f"'{key}' must not be empty")


def validate_rule(rule: Any, known_lists: set[str]) -> list[str]:
    problems: list[str] = []
    if not isinstance(rule, dict):
        return ["rule must be a mapping"]
    for key in rule:
        if key not in TOP_KEYS:
            problems.append(f"unknown key {key!r}")
    rid = rule.get("id")
    if not isinstance(rid, str) or not RULE_ID_RE.match(rid):
        problems.append("'id' must look like MTH-EXEC-001")
    _text(rule, "name", problems, 4)
    version = rule.get("version")
    if isinstance(version, bool) or not isinstance(version, int) or version < 1:
        problems.append("'version' must be an integer >= 1")
    rtype = rule.get("type", "pattern")
    if rtype not in RULE_TYPES:
        problems.append(f"'type' must be one of {RULE_TYPES}")
    src = rule.get("source")
    sources = [src] if isinstance(src, str) else src
    if not isinstance(sources, list) or not sources or not all(s in SOURCES for s in sources):
        problems.append(f"'source' must be one source or a list drawn from {SOURCES}")
        sources = []
    _text(rule, "description", problems)
    _text(rule, "rationale", problems)
    if rule.get("severity") not in SEVERITIES:
        problems.append(f"'severity' must be one of {SEVERITIES}")
    if rule.get("confidence") not in CONFIDENCES:
        problems.append(f"'confidence' must be one of {CONFIDENCES}")
    _str_list(rule, "false_positives", problems, True)
    _str_list(rule, "investigation", problems, True)
    _str_list(rule, "references", problems, False)
    _str_list(rule, "requires", problems, False)
    _str_list(rule, "context_fields", problems, False)
    _str_list(rule, "evidence_fields", problems, False)
    for key in ("requires", "context_fields", "evidence_fields"):
        for fld in rule.get(key, []) or []:
            if isinstance(fld, str) and not _FIELD_OK.match(fld):
                problems.append(f"'{key}' field names must be lowercase dotted names: {fld!r}")
    if "enabled" in rule and not isinstance(rule["enabled"], bool):
        problems.append("'enabled' must be true or false")
    if "title" in rule and not isinstance(rule["title"], str):
        problems.append("'title' must be a string")

    attack = rule.get("attack", {})
    if attack:
        if not isinstance(attack, dict) or set(attack) - {"techniques", "justification"}:
            problems.append("'attack' must contain only 'techniques' and 'justification'")
        else:
            techniques = attack.get("techniques", [])
            if not isinstance(techniques, list):
                problems.append("attack.techniques must be a list")
            else:
                for tid in techniques:
                    if not isinstance(tid, str) or not is_valid_id_format(tid):
                        problems.append(
                            f"attack technique {tid!r} is not a valid ID (e.g. T1059.004)"
                        )
                    elif tid not in TECHNIQUES:
                        problems.append(
                            f"attack technique {tid} is not in the curated catalogue; add it to "
                            "attack/__init__.py with its official title"
                        )
                if techniques and (
                    not isinstance(attack.get("justification"), str)
                    or len(attack["justification"].strip()) < 20
                ):
                    problems.append(
                        "attack.justification (>= 20 characters) is required with techniques"
                    )

    if rtype == "pattern":
        if "conditions" not in rule:
            problems.append("pattern rules require 'conditions'")
        else:
            validate_conditions(rule["conditions"], known_lists, "conditions", problems)
        if "ioc" in rule or "baseline" in rule:
            problems.append("pattern rules must not define 'ioc' or 'baseline'")
        thr = rule.get("threshold")
        if thr is not None:
            if not isinstance(thr, dict) or set(thr) != {"count", "window_seconds", "group_by"}:
                problems.append("'threshold' needs exactly count, window_seconds and group_by")
            else:
                for k in ("count", "window_seconds"):
                    if isinstance(thr[k], bool) or not isinstance(thr[k], int) or thr[k] < 1:
                        problems.append(f"threshold.{k} must be a positive integer")
                if isinstance(thr.get("count"), int) and thr["count"] < 2:
                    problems.append("threshold.count must be at least 2")
                if not isinstance(thr["group_by"], str) or not _FIELD_OK.match(thr["group_by"]):
                    problems.append("threshold.group_by must be a field name")
    elif rtype == "ioc":
        block = rule.get("ioc")
        if "conditions" in rule:
            problems.append("ioc rules must not define 'conditions'")
        if not isinstance(block, dict) or set(block) != {"matches"}:
            problems.append("ioc rules need an 'ioc: {matches: [...]}' block")
        else:
            matches = block["matches"]
            if not isinstance(matches, list) or not matches:
                problems.append("ioc.matches must be a non-empty list")
            else:
                for i, m in enumerate(matches):
                    ok = isinstance(m, dict) and set(m) <= {"type", "fields", "text"}
                    if not ok or m.get("type") not in IOC_TYPES:
                        problems.append(
                            f"ioc.matches[{i}]: needs type from {IOC_TYPES}, fields[, text]"
                        )
                        continue
                    flds = m.get("fields")
                    if (
                        not isinstance(flds, list)
                        or not flds
                        or not all(isinstance(f, str) and _FIELD_OK.match(f) for f in flds)
                    ):
                        problems.append(
                            f"ioc.matches[{i}].fields must be a non-empty list of fields"
                        )
                    if m.get("text") and m["type"] not in {"ip", "domain"}:
                        problems.append(
                            f"ioc.matches[{i}]: text matching only applies to ip/domain"
                        )
    elif rtype == "baseline":
        block = rule.get("baseline")
        if not isinstance(block, dict) or not set(block) <= {"category", "change", "filters"}:
            problems.append("baseline rules need 'baseline: {category, change[, filters]}'")
        else:
            if block.get("category") not in BASELINE_CATEGORIES:
                problems.append(f"baseline.category must be one of {BASELINE_CATEGORIES}")
            if block.get("change") not in BASELINE_CHANGES:
                problems.append(f"baseline.change must be one of {BASELINE_CHANGES}")
            if "filters" in block:
                validate_conditions(block["filters"], known_lists, "baseline.filters", problems)
    return problems
