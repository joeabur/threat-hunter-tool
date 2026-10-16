"""Bounded regular expressions for rules.

Python's ``re`` has no execution timeout, so rules are restricted instead:
short patterns, no backreferences or lookarounds, no nested/ambiguous
quantifiers, bounded repetition counts, and inputs truncated before matching.
"""

from __future__ import annotations

import re
from functools import lru_cache
from re import _parser as sre_parse  # type: ignore[attr-defined]

MAX_PATTERN_LENGTH = 300
MAX_REPEAT = 200
DEFAULT_MAX_INPUT = 4096

_UNBOUNDED = sre_parse.MAXREPEAT


class UnsafePatternError(ValueError):
    pass


def _walk(parsed: object, in_repeat: bool, depth: int) -> None:
    if depth > 12:
        raise UnsafePatternError("pattern nesting too deep")
    for op, av in parsed:  # type: ignore[attr-defined]
        name = str(op)
        if name in ("GROUPREF", "GROUPREF_EXISTS"):
            raise UnsafePatternError("backreferences are not allowed")
        if name in ("ASSERT", "ASSERT_NOT"):
            raise UnsafePatternError("lookaround assertions are not allowed")
        if name in ("MAX_REPEAT", "MIN_REPEAT", "POSSESSIVE_REPEAT"):
            lo, hi, sub = av
            if hi != _UNBOUNDED and hi > MAX_REPEAT:
                raise UnsafePatternError(f"repetition bound over {MAX_REPEAT}")
            if lo > MAX_REPEAT:
                raise UnsafePatternError(f"repetition bound over {MAX_REPEAT}")
            unbounded = hi == _UNBOUNDED or hi > 1
            if in_repeat and unbounded:
                raise UnsafePatternError("nested quantifiers are not allowed")
            _walk(sub, in_repeat or unbounded, depth + 1)
        elif name == "SUBPATTERN":
            _walk(av[-1], in_repeat, depth + 1)
        elif name == "BRANCH":
            for branch in av[1]:
                _walk(branch, in_repeat, depth + 1)
        elif name == "ATOMIC_GROUP":
            _walk(av, in_repeat, depth + 1)


@lru_cache(maxsize=512)
def compile_safe(pattern: str, ignore_case: bool = False) -> re.Pattern[str]:
    if not isinstance(pattern, str) or not pattern:
        raise UnsafePatternError("pattern must be a non-empty string")
    if len(pattern) > MAX_PATTERN_LENGTH:
        raise UnsafePatternError(f"pattern longer than {MAX_PATTERN_LENGTH} characters")
    try:
        parsed = sre_parse.parse(pattern)
    except (re.error, RecursionError, OverflowError) as exc:
        raise UnsafePatternError(f"invalid regular expression: {exc}") from exc
    _walk(parsed, False, 0)
    flags = re.IGNORECASE if ignore_case else 0
    try:
        return re.compile(pattern, flags)
    except re.error as exc:  # pragma: no cover - parse() already validated
        raise UnsafePatternError(f"invalid regular expression: {exc}") from exc


def safe_search(
    pattern: str, text: str, *, ignore_case: bool = False, max_input: int = DEFAULT_MAX_INPUT
) -> bool:
    return compile_safe(pattern, ignore_case).search(text[:max_input]) is not None
