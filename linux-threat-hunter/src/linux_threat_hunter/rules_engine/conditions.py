"""Declarative condition language. No code from rules or data is ever executed.

A condition is either a leaf ``{field, op, value}`` or a composite ``{all: [...]}``,
``{any: [...]}``, ``{not: {...}}``. Regexes are bounded (length, nesting heuristics, input
truncation). A missing field never matches (except ``exists: false``).
"""

from __future__ import annotations

import fnmatch
import posixpath
import re
from dataclasses import dataclass, field
from typing import Any

OPS = {
    "equals",
    "not_equals",
    "in",
    "not_in",
    "contains",
    "contains_any",
    "startswith",
    "endswith",
    "regex",
    "regex_any",
    "gt",
    "gte",
    "lt",
    "lte",
    "exists",
    "path_under",
    "not_path_under",
    "text_references_path_under",
}
LIST_OPS = {
    "in",
    "not_in",
    "contains_any",
    "regex_any",
    "path_under",
    "not_path_under",
    "text_references_path_under",
}
REGEX_OPS = {"regex", "regex_any"}
NUMERIC_OPS = {"gt", "gte", "lt", "lte"}
_NESTED_QUANT = re.compile(r"\((?:[^()\\]|\\.)*[+*](?:[^()\\]|\\.)*\)\s*(?:[+*]|\{\d*,\d*\})")
_BACKREF = re.compile(r"\\[1-9]")
TOKEN_SPLIT = re.compile(r"[\s'\"=;|&<>()]+")


class ConditionError(ValueError):
    pass


def check_regex(pattern: str, max_len: int) -> str | None:
    """Return an error message if the pattern is unacceptable, else None."""
    if len(pattern) > max_len:
        return f"regex longer than {max_len} characters"
    if _NESTED_QUANT.search(pattern):
        return "regex contains a nested quantifier (risk of catastrophic backtracking)"
    if _BACKREF.search(pattern):
        return "regex backreferences are not allowed"
    try:
        re.compile(pattern)
    except re.error as exc:
        return f"invalid regex: {exc}"
    return None


@dataclass
class EvalContext:
    variables: dict[str, Any]
    limits: dict[str, int]
    _rx: dict[str, re.Pattern[str]] = field(default_factory=dict)

    def resolve(self, value: Any) -> Any:
        if isinstance(value, str) and value.startswith("$"):
            name = value[1:]
            if name not in self.variables:
                raise ConditionError(f"unknown variable ${name}")
            return self.variables[name]
        return value

    def regex(self, pattern: str) -> re.Pattern[str]:
        rx = self._rx.get(pattern)
        if rx is None:
            err = check_regex(pattern, self.limits["max_regex_length"])
            if err:
                raise ConditionError(err)
            rx = self._rx[pattern] = re.compile(pattern)
        return rx


def get_field(data: dict[str, Any], dotted: str) -> Any:
    cur: Any = data
    for part in dotted.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def path_under(path: str, prefixes: list[str]) -> bool:
    norm = posixpath.normpath(path)
    for pre in prefixes:
        pre = posixpath.normpath(pre)
        if any(c in pre for c in "*?["):
            probe = norm
            while probe not in ("", "/", "."):
                if fnmatch.fnmatchcase(probe, pre):
                    return True
                probe = posixpath.dirname(probe)
        elif norm == pre or norm.startswith(pre.rstrip("/") + "/"):
            return True
    return False


def text_references_path_under(text: str, prefixes: list[str]) -> bool:
    return any(tok.startswith("/") and path_under(tok, prefixes) for tok in TOKEN_SPLIT.split(text))


def _num(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    return None


def _apply(op: str, actual: Any, expected: Any, ctx: EvalContext) -> bool:
    if op == "exists":
        return bool(expected) == (actual is not None)
    if actual is None:
        return False
    max_chars = ctx.limits["max_regex_input_chars"]
    if op == "equals":
        return bool(actual == expected)
    if op == "not_equals":
        return bool(actual != expected)
    if op == "in":
        return actual in expected
    if op == "not_in":
        return actual not in expected
    if op == "contains":
        if isinstance(actual, str):
            return str(expected) in actual
        return isinstance(actual, list) and expected in actual
    if op == "contains_any":
        if isinstance(actual, str):
            return any(str(e) in actual for e in expected)
        return isinstance(actual, list) and any(e in actual for e in expected)
    if op == "startswith":
        return isinstance(actual, str) and actual.startswith(str(expected))
    if op == "endswith":
        return isinstance(actual, str) and actual.endswith(str(expected))
    if op == "regex":
        return ctx.regex(str(expected)).search(str(actual)[:max_chars]) is not None
    if op == "regex_any":
        text = str(actual)[:max_chars]
        return any(ctx.regex(str(p)).search(text) for p in expected)
    if op in NUMERIC_OPS:
        a, e = _num(actual), _num(expected)
        if a is None or e is None:
            return False
        return {"gt": a > e, "gte": a >= e, "lt": a < e, "lte": a <= e}[op]
    if op == "path_under":
        return isinstance(actual, str) and path_under(actual, [str(p) for p in expected])
    if op == "not_path_under":
        return isinstance(actual, str) and not path_under(actual, [str(p) for p in expected])
    if op == "text_references_path_under":
        return isinstance(actual, str) and text_references_path_under(
            actual[: max_chars * 4], [str(p) for p in expected]
        )
    raise ConditionError(f"unsupported operator {op}")


def evaluate(node: dict[str, Any], data: dict[str, Any], ctx: EvalContext) -> bool:
    if "all" in node:
        return all(evaluate(n, data, ctx) for n in node["all"])
    if "any" in node:
        return any(evaluate(n, data, ctx) for n in node["any"])
    if "not" in node:
        return not evaluate(node["not"], data, ctx)
    expected = ctx.resolve(node.get("value"))
    return _apply(node["op"], get_field(data, node["field"]), expected, ctx)


def validate_condition(node: Any, where: str, errors: list[str], ctx: EvalContext, depth: int = 0) -> None:
    max_depth = ctx.limits["max_condition_depth"]
    if depth > max_depth:
        errors.append(f"{where}: conditions nested deeper than {max_depth}")
        return
    if not isinstance(node, dict):
        errors.append(f"{where}: condition must be a mapping")
        return
    composite = [k for k in ("all", "any", "not") if k in node]
    if composite:
        if len(node) != 1:
            errors.append(f"{where}: composite condition may only contain '{composite[0]}'")
            return
        key = composite[0]
        if key == "not":
            validate_condition(node["not"], f"{where}.not", errors, ctx, depth + 1)
        else:
            items = node[key]
            if not isinstance(items, list) or not items:
                errors.append(f"{where}.{key}: must be a non-empty list")
                return
            if len(items) > 50:
                errors.append(f"{where}.{key}: at most 50 sub-conditions")
            for i, sub in enumerate(items[:50]):
                validate_condition(sub, f"{where}.{key}[{i}]", errors, ctx, depth + 1)
        return
    extra = set(node) - {"field", "op", "value"}
    if extra:
        errors.append(f"{where}: unknown keys {sorted(extra)}")
    fld, op = node.get("field"), node.get("op")
    if not isinstance(fld, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.]*", fld or ""):
        errors.append(f"{where}: 'field' must be a dotted identifier")
    if op not in OPS:
        errors.append(f"{where}: unknown op {op!r} (allowed: {', '.join(sorted(OPS))})")
        return
    if "value" not in node:
        errors.append(f"{where}: 'value' is required")
        return
    try:
        value = ctx.resolve(node["value"])
    except ConditionError as exc:
        errors.append(f"{where}: {exc}")
        return
    if op in LIST_OPS:
        if not isinstance(value, list) or not value:
            errors.append(f"{where}: op {op} needs a non-empty list")
            return
        if len(value) > ctx.limits["max_list_values"]:
            errors.append(f"{where}: list longer than {ctx.limits['max_list_values']}")
            return
    if op in REGEX_OPS:
        for pat in value if isinstance(value, list) else [value]:
            if not isinstance(pat, str):
                errors.append(f"{where}: regex must be a string")
                continue
            err = check_regex(pat, ctx.limits["max_regex_length"])
            if err:
                errors.append(f"{where}: {err}: {pat[:60]!r}")
    if op in NUMERIC_OPS and _num(value) is None:
        errors.append(f"{where}: op {op} needs a number")
    if op == "exists" and not isinstance(value, bool):
        errors.append(f"{where}: op exists needs true or false")
    if op in {"equals", "not_equals"} and isinstance(value, (dict, list)):
        errors.append(f"{where}: {op} needs a scalar value")
