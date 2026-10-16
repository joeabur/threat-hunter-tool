"""Condition syntax shared by validation and evaluation."""

from __future__ import annotations

import fnmatch
import posixpath
from typing import Any

from ..utils.regexsafe import UnsafePatternError, compile_safe

MAX_CONDITIONS = 60
MAX_DEPTH = 3
FIELD_RE_CHARS = set("abcdefghijklmnopqrstuvwxyz0123456789_.")

# operator -> accepted value kind: scalar | string | list | regex | bool | number
OPERATORS: dict[str, str] = {
    "equals": "scalar",
    "not_equals": "scalar",
    "iequals": "string",
    "in": "list",
    "not_in": "list",
    "startswith": "string",
    "endswith": "string",
    "contains": "string",
    "icontains": "string",
    "startswith_any": "list",
    "endswith_any": "list",
    "contains_any": "list",
    "regex": "regex",
    "iregex": "regex",
    "exists": "bool",
    "gt": "number",
    "gte": "number",
    "lt": "number",
    "lte": "number",
    "path_under": "list",
    "glob": "list",
}
NEGATIVE_OPS = {"not_equals", "not_in"}
MISSING = object()


def get_field(data: dict[str, Any], dotted: str) -> Any:
    current: Any = data
    for part in dotted.split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return MISSING
    return current


def validate_conditions(
    node: Any,
    known_lists: set[str],
    where: str,
    problems: list[str],
    depth: int = 0,
    count: list[int] | None = None,
) -> None:
    count = count if count is not None else [0]
    if depth > MAX_DEPTH:
        problems.append(f"{where}: conditions nested deeper than {MAX_DEPTH}")
        return
    if not isinstance(node, dict) or not node:
        problems.append(f"{where}: expected a mapping with all/any/none")
        return
    for key, items in node.items():
        if key not in {"all", "any", "none"}:
            problems.append(f"{where}: unknown group key {key!r} (use all, any or none)")
            continue
        if not isinstance(items, list) or not items:
            problems.append(f"{where}.{key}: must be a non-empty list")
            continue
        for i, item in enumerate(items):
            loc = f"{where}.{key}[{i}]"
            if isinstance(item, dict) and set(item) & {"all", "any", "none"}:
                validate_conditions(item, known_lists, loc, problems, depth + 1, count)
                continue
            count[0] += 1
            if count[0] > MAX_CONDITIONS:
                problems.append(f"{where}: more than {MAX_CONDITIONS} conditions")
                return
            _validate_leaf(item, known_lists, loc, problems)


def _validate_leaf(item: Any, known_lists: set[str], loc: str, problems: list[str]) -> None:
    if not isinstance(item, dict):
        problems.append(f"{loc}: condition must be a mapping")
        return
    extra = set(item) - {"field", "op", "value"}
    if extra:
        problems.append(f"{loc}: unknown keys {sorted(extra)}")
    fld = item.get("field")
    if not isinstance(fld, str) or not fld or not set(fld) <= FIELD_RE_CHARS:
        problems.append(f"{loc}: 'field' must be a lowercase dotted field name")
    op = item.get("op")
    if op not in OPERATORS:
        problems.append(f"{loc}: unknown operator {op!r}")
        return
    if "value" not in item:
        problems.append(f"{loc}: 'value' is required")
        return
    value = item["value"]
    kind = OPERATORS[op]
    if isinstance(value, str) and value.startswith("$"):
        if kind not in {"list"}:
            problems.append(f"{loc}: list references are only valid for list operators")
        else:
            ref = value.split(":", 1)
            if (
                len(ref) != 2
                or ref[0] not in {"$allowlist", "$setting"}
                or ref[1] not in known_lists
            ):
                problems.append(f"{loc}: unknown list reference {value!r}")
        return
    if kind == "scalar" and not isinstance(value, (str, int, float, bool)):
        problems.append(f"{loc}: value must be a scalar")
    elif kind == "string" and not isinstance(value, str):
        problems.append(f"{loc}: value must be a string")
    elif kind == "bool" and not isinstance(value, bool):
        problems.append(f"{loc}: value must be true or false")
    elif kind == "number" and (isinstance(value, bool) or not isinstance(value, (int, float))):
        problems.append(f"{loc}: value must be a number")
    elif kind == "list":
        if isinstance(value, str):
            return
        if not isinstance(value, list) or not value or not all(isinstance(v, str) for v in value):
            problems.append(f"{loc}: value must be a non-empty list of strings")
        elif len(value) > 500:
            problems.append(f"{loc}: list longer than 500 entries")
    elif kind == "regex":
        try:
            compile_safe(str(value), op == "iregex")
        except UnsafePatternError as exc:
            problems.append(f"{loc}: {exc}")


def collect_fields(node: dict[str, Any]) -> set[str]:
    fields: set[str] = set()
    for items in node.values():
        for item in items:
            if "field" in item:
                fields.add(item["field"])
            else:
                fields |= collect_fields(item)
    return fields


def _path_match(path: str, entry: str) -> bool:
    entry = entry.rstrip("/")
    norm = posixpath.normpath(path)
    if any(ch in entry for ch in "*?["):
        return fnmatch.fnmatchcase(norm, entry) or fnmatch.fnmatchcase(norm, entry + "/*")
    return norm == entry or norm.startswith(entry + "/")


def eval_leaf(
    item: dict[str, Any], data: dict[str, Any], lists: dict[str, list[str]], max_input: int
) -> bool:
    actual = get_field(data, item["field"])
    op = item["op"]
    value = item["value"]
    if op == "exists":
        return (actual is not MISSING and actual is not None) == bool(value)
    if actual is MISSING or actual is None:
        return False
    if isinstance(value, str) and value.startswith("$"):
        value = lists.get(value.split(":", 1)[1], [])
    if op == "equals":
        return bool(actual == value)
    if op == "not_equals":
        return bool(actual != value)
    if op == "iequals":
        return isinstance(actual, str) and actual.lower() == str(value).lower()
    if op in {"gt", "gte", "lt", "lte"}:
        if isinstance(actual, bool) or not isinstance(actual, (int, float)):
            return False
        if op == "gt":
            return bool(actual > value)
        if op == "gte":
            return bool(actual >= value)
        if op == "lt":
            return bool(actual < value)
        return bool(actual <= value)
    if op in {"in", "not_in"}:
        hit = actual in (value if isinstance(value, list) else [value])
        return hit if op == "in" else not hit
    if not isinstance(actual, str):
        if isinstance(actual, list) and op in {"contains", "icontains"}:
            return any(
                str(value).lower() == str(a).lower() if op == "icontains" else value == a
                for a in actual
            )
        return False
    if op == "startswith":
        return actual.startswith(value)
    if op == "endswith":
        return actual.endswith(value)
    if op == "contains":
        return value in actual
    if op == "icontains":
        return str(value).lower() in actual.lower()
    if op == "startswith_any":
        return any(actual.startswith(v) for v in value)
    if op == "endswith_any":
        return any(actual.endswith(v) for v in value)
    if op == "contains_any":
        return any(v in actual for v in value)
    if op in {"regex", "iregex"}:
        return compile_safe(str(value), op == "iregex").search(actual[:max_input]) is not None
    if op == "path_under":
        return any(_path_match(actual, e) for e in value)
    if op == "glob":
        return any(fnmatch.fnmatchcase(actual, e) for e in value)
    return False  # pragma: no cover


def eval_group(
    node: dict[str, Any], data: dict[str, Any], lists: dict[str, list[str]], max_input: int
) -> bool:
    def run(item: dict[str, Any]) -> bool:
        if "field" in item:
            return eval_leaf(item, data, lists, max_input)
        return eval_group(item, data, lists, max_input)

    if "all" in node and not all(run(i) for i in node["all"]):
        return False
    if "any" in node and not any(run(i) for i in node["any"]):
        return False
    return not ("none" in node and any(run(i) for i in node["none"]))
