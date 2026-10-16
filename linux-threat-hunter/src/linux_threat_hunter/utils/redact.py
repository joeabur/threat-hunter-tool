"""Configurable redaction of sensitive values in strings and nested structures."""

from __future__ import annotations

import re
from typing import Any

DEFAULT_REDACTION_PATTERNS = [
    r"(?i)((?:--?)(?:password|passwd|pass|token|secret|api[-_]?key)\s+)[^\s'\"-][^\s'\"]*",
    r"(?i)(\b(?:password|passwd|pwd|token|secret|api[-_]?key|access[-_]?key)=)[^\s'\"&]+",
    r"(?i)(authorization:\s*(?:bearer|basic)\s+)[^\s'\"]+",
    r"(://[^/\s:@]+:)[^@\s]+(?=@)",
    r"\bAKIA[0-9A-Z]{16}\b",
]


class Redactor:
    def __init__(self, patterns: list[str] | None = None, replacement: str = "[REDACTED]") -> None:
        pats = DEFAULT_REDACTION_PATTERNS if patterns is None else patterns
        self.replacement = replacement
        self._compiled = [re.compile(p) for p in pats]

    def text(self, value: str) -> str:
        for pat in self._compiled:
            value = pat.sub(self._sub, value)
        return value

    def _sub(self, match: re.Match[str]) -> str:
        prefix = match.group(1) if match.re.groups else ""
        return prefix + self.replacement

    def obj(self, value: Any) -> Any:
        if isinstance(value, str):
            return self.text(value)
        if isinstance(value, list):
            return [self.obj(v) for v in value]
        if isinstance(value, dict):
            return {k: self.obj(v) for k, v in value.items()}
        return value
