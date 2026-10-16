"""Configurable redaction of sensitive values in command lines, logs and reports."""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any

DEFAULT_PATTERNS: tuple[str, ...] = (
    r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]{8,}",
    r"(?i)((?:pass(?:word|wd)?|pwd|token|secret|api[-_]?key|auth(?:orization)?|"
    r"access[-_]?key)\s*[=:]\s*)\S+",
    r"(?i)(--?(?:pass(?:word|wd)?|token|secret|api[-_]?key)\s+)\S+",
    r"(?i)(://[^/\s:@]+:)[^/\s@]+(?=@)",
    r"\bAKIA[0-9A-Z]{16}\b",
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
)
REPLACEMENT = "[REDACTED]"
_MAX_PATTERN_LEN = 300


class Redactor:
    def __init__(self, patterns: Iterable[str] | None = None, replacement: str = REPLACEMENT):
        self.replacement = replacement
        self._compiled: list[re.Pattern[str]] = []
        for pattern in patterns if patterns is not None else DEFAULT_PATTERNS:
            if len(pattern) > _MAX_PATTERN_LEN:
                raise ValueError("redaction pattern too long")
            self._compiled.append(re.compile(pattern))

    def redact(self, text: str) -> str:
        if not text:
            return text
        text = text[:200_000]
        for pattern in self._compiled:
            if pattern.groups:
                text = pattern.sub(lambda m: m.group(1) + self.replacement, text)
            else:
                text = pattern.sub(self.replacement, text)
        return text

    def redact_obj(self, value: Any) -> Any:
        """Recursively redact every string in a JSON-like structure."""
        if isinstance(value, str):
            return self.redact(value)
        if isinstance(value, list):
            return [self.redact_obj(v) for v in value]
        if isinstance(value, dict):
            return {k: self.redact_obj(v) for k, v in value.items()}
        return value
