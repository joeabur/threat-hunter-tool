"""Rule schema validation (see docs/rule-authoring.md)."""

from __future__ import annotations

import re
from typing import Any

from linux_threat_hunter.attack.techniques import validate_mapping
from linux_threat_hunter.models import CLASSIFICATIONS, CONFIDENCES, DATA_SOURCES, SEVERITIES
from linux_threat_hunter.rules_engine.conditions import EvalContext, validate_condition

RULE_TYPES = {"match", "threshold", "sequence", "baseline", "ioc", "correlation"}
RULE_ID_RE = re.compile(r"^LTH-[A-Z]{3,5}-\d{3}$")
VERSION_RE = re.compile(r"^\d+\.\d+\.\d+$")
PLACEHOLDER_RE = re.compile(r"\{([^{}]*)\}")
FIELD_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.]*$")
BASELINE_CATEGORIES = {"persistence", "files", "executables", "listeners", "privileged_users"}
IOC_TYPES = {"sha256", "process_name", "file_path", "ip", "domain"}
REQUIRED_TEXT = ("name", "description", "rationale")
KNOWN_KEYS = {
    "id",
    "name",
    "version",
    "type",
    "data_source",
    "severity",
    "confidence",
    "classification",
    "description",
    "rationale",
    "conditions",
    "allowlist",
    "params",
    "group_by",
    "sequence",
    "baseline",
    "ioc",
    "correlate",
    "finding",
    "attack",
    "false_positives",
    "investigation_steps",
    "references",
    "limitations",
    "enabled",
}


def _check_template(text: Any, where: str, errors: list[str]) -> None:
    if not isinstance(text, str) or not text.strip():
        errors.append(f"{where}: must be a non-empty string")
        return
    for name in PLACEHOLDER_RE.findall(text):
        if not FIELD_NAME_RE.match(name):
            errors.append(f"{where}: invalid placeholder {{{name}}} (only {{field_name}} allowed)")


def _str_list(value: Any, where: str, errors: list[str], *, required: bool) -> None:
    if not isinstance(value, list) or (required and not value):
        errors.append(f"{where}: must be {'a non-empty ' if required else 'a '}list of strings")
        return
    if not all(isinstance(v, str) and v.strip() for v in value):
        errors.append(f"{where}: every entry must be a non-empty string")


def validate_rule(rule: Any, ctx: EvalContext) -> list[str]:
    """Return a list of human-readable errors (empty list means the rule is valid)."""
    errors: list[str] = []
    if not isinstance(rule, dict):
        return ["rule must be a mapping"]
    unknown = set(rule) - KNOWN_KEYS
    if unknown:
        errors.append(f"unknown keys: {sorted(unknown)}")
    rid = rule.get("id")
    if not isinstance(rid, str) or not RULE_ID_RE.match(rid):
        errors.append("id: must match LTH-<AREA>-<NNN>, e.g. LTH-PROC-001")
    if not isinstance(rule.get("version"), str) or not VERSION_RE.match(rule.get("version", "")):
        errors.append("version: must be semantic version text, e.g. '1.0.0'")
    for key in REQUIRED_TEXT:
        if not isinstance(rule.get(key), str) or not rule[key].strip():
            errors.append(f"{key}: required non-empty string")
    rtype = rule.get("type")
    if rtype not in RULE_TYPES:
        errors.append(f"type: must be one of {sorted(RULE_TYPES)}")
        return errors
    allowed_sources = {*DATA_SOURCES, "baseline", "findings"}
    if rule.get("data_source") not in allowed_sources:
        errors.append(f"data_source: must be one of {sorted(allowed_sources)}")
    if rule.get("severity") not in SEVERITIES:
        errors.append(f"severity: must be one of {list(SEVERITIES)}")
    if rule.get("confidence") not in CONFIDENCES:
        errors.append(f"confidence: must be one of {list(CONFIDENCES)}")
    if rule.get("classification") not in CLASSIFICATIONS:
        errors.append(f"classification: must be one of {list(CLASSIFICATIONS)}")
    _str_list(rule.get("false_positives"), "false_positives", errors, required=True)
    _str_list(rule.get("investigation_steps"), "investigation_steps", errors, required=True)
    if "limitations" in rule:
        _str_list(rule["limitations"], "limitations", errors, required=False)
    if "references" in rule:
        refs = rule["references"]
        _str_list(refs, "references", errors, required=False)
        if isinstance(refs, list):
            for r in refs:
                if isinstance(r, str) and not r.startswith("https://"):
                    errors.append(f"references: {r!r} must be an https:// URL")
    finding = rule.get("finding")
    if not isinstance(finding, dict):
        errors.append("finding: required mapping with 'title' and 'explanation'")
    else:
        _check_template(finding.get("title"), "finding.title", errors)
        _check_template(finding.get("explanation"), "finding.explanation", errors)
        if "artifact" in finding:
            _check_template(finding["artifact"], "finding.artifact", errors)
        extra = set(finding) - {"title", "explanation", "artifact"}
        if extra:
            errors.append(f"finding: unknown keys {sorted(extra)}")
    attack = rule.get("attack", [])
    if not isinstance(attack, list):
        errors.append("attack: must be a list")
    else:
        for i, m in enumerate(attack):
            if not isinstance(m, dict) or set(m) != {"tactic", "technique"}:
                errors.append(f"attack[{i}]: needs exactly 'tactic' and 'technique'")
                continue
            errors += [f"attack[{i}]: {e}" for e in validate_mapping(str(m["tactic"]), str(m["technique"]))]
    if "conditions" in rule:
        validate_condition(rule["conditions"], "conditions", errors, ctx)
    allow = rule.get("allowlist", [])
    if not isinstance(allow, list):
        errors.append("allowlist: must be a list of conditions")
    else:
        for i, node in enumerate(allow):
            validate_condition(node, f"allowlist[{i}]", errors, ctx)
    params = rule.get("params", {})
    if not isinstance(params, dict):
        errors.append("params: must be a mapping")
    _validate_type_specific(rule, rtype, params if isinstance(params, dict) else {}, errors, ctx)
    return errors


def _pos_int(params: dict[str, Any], name: str, errors: list[str], maximum: int) -> None:
    v = params.get(name)
    if not isinstance(v, int) or isinstance(v, bool) or not 1 <= v <= maximum:
        errors.append(f"params.{name}: required integer between 1 and {maximum}")


def _validate_type_specific(
    rule: dict[str, Any], rtype: str, params: dict[str, Any], errors: list[str], ctx: EvalContext
) -> None:
    if rtype == "match":
        if "conditions" not in rule:
            errors.append("conditions: required for type 'match'")
    elif rtype == "threshold":
        if "conditions" not in rule:
            errors.append("conditions: required for type 'threshold'")
        _pos_int(params, "count", errors, 1_000_000)
        _pos_int(params, "window_seconds", errors, 86_400 * 31)
        _group_by(rule, errors)
    elif rtype == "sequence":
        seq = rule.get("sequence")
        if not isinstance(seq, dict) or set(seq) != {"first", "then"}:
            errors.append("sequence: requires exactly 'first' and 'then' conditions")
        else:
            validate_condition(seq["first"], "sequence.first", errors, ctx)
            validate_condition(seq["then"], "sequence.then", errors, ctx)
        _pos_int(params, "count", errors, 1_000_000)
        _pos_int(params, "window_seconds", errors, 86_400 * 31)
        _group_by(rule, errors)
    elif rtype == "baseline":
        b = rule.get("baseline")
        if not isinstance(b, dict):
            errors.append("baseline: required mapping (categories, changes, optional where)")
            return
        cats, changes = b.get("categories"), b.get("changes")
        if not isinstance(cats, list) or not cats or not set(cats) <= BASELINE_CATEGORIES:
            errors.append(f"baseline.categories: non-empty subset of {sorted(BASELINE_CATEGORIES)}")
        if not isinstance(changes, list) or not changes or not set(changes) <= {"added", "removed", "modified"}:
            errors.append("baseline.changes: non-empty subset of added, removed, modified")
        if "where" in b:
            validate_condition(b["where"], "baseline.where", errors, ctx)
    elif rtype == "ioc":
        i = rule.get("ioc")
        types = i.get("indicator_types") if isinstance(i, dict) else None
        if not isinstance(types, list) or not types or not set(types) <= IOC_TYPES:
            errors.append(f"ioc.indicator_types: non-empty subset of {sorted(IOC_TYPES)}")
        if isinstance(i, dict):
            if set(i) - {"indicator_types", "group_by"}:
                errors.append("ioc: only indicator_types and group_by are allowed")
            if "group_by" in i:
                _group_by({"group_by": i["group_by"]}, errors)
    elif rtype == "correlation":
        c = rule.get("correlate")
        if not isinstance(c, dict) or set(c) - {"a", "b", "join_on", "require_event_time"}:
            errors.append("correlate: requires a, b, join_on (optional require_event_time)")
            return
        for side in ("a", "b"):
            ids = c.get(side)
            if not isinstance(ids, list) or not ids or not all(isinstance(x, str) and RULE_ID_RE.match(x) for x in ids):
                errors.append(f"correlate.{side}: non-empty list of rule IDs")
        if c.get("join_on") not in {"pid", "path", "exec_path", "ip", "user", "sha256"}:
            errors.append("correlate.join_on: one of pid, path, exec_path, ip, user, sha256")
        if "require_event_time" in c and not isinstance(c["require_event_time"], bool):
            errors.append("correlate.require_event_time: must be true/false")
        if "window_seconds" in params:
            _pos_int(params, "window_seconds", errors, 86_400 * 31)


def _group_by(rule: dict[str, Any], errors: list[str]) -> None:
    gb = rule.get("group_by")
    if not isinstance(gb, list) or not gb or not all(isinstance(g, str) and FIELD_NAME_RE.match(g) for g in gb):
        errors.append("group_by: required non-empty list of field names")
