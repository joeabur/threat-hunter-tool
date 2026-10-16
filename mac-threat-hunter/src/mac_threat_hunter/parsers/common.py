from __future__ import annotations

import posixpath
from datetime import datetime, timezone
from typing import Any

from ..models import EvidenceRef, Record
from ..utils.redact import Redactor
from ..utils.timeutil import parse_timestamp


class NormalizeContext:
    """Carries settings the parsers need: redaction, interpreters, collection time zone."""

    def __init__(
        self,
        redactor: Redactor,
        script_interpreters: list[str],
        collected_at: datetime | None,
        assume_offset: timezone | None = None,
    ) -> None:
        self.redactor = redactor
        self.script_interpreters = set(script_interpreters)
        self.collected_at = collected_at
        self.assume_offset = assume_offset


def basename(path: str | None) -> str | None:
    if not path:
        return None
    return posixpath.basename(path.rstrip("/")) or None


def mode_flags(mode: Any) -> dict[str, Any]:
    """Derive permission booleans from an octal mode string such as ``"0644"``."""
    out: dict[str, Any] = {}
    if isinstance(mode, int) and not isinstance(mode, bool):
        value: int | None = mode
    elif isinstance(mode, str):
        try:
            value = int(mode, 8)
        except ValueError:
            value = None
    else:
        value = None
    if value is not None:
        out["mode_octal"] = format(value & 0o7777, "04o")
        out["world_writable"] = bool(value & 0o002)
        out["group_writable"] = bool(value & 0o020)
        out["setuid"] = bool(value & 0o4000)
        out["setgid"] = bool(value & 0o2000)
    return out


def make_record(
    source: str,
    data: dict[str, Any],
    file: str,
    index: int | None,
    ctx: NormalizeContext,
    time_value: object = None,
) -> Record:
    parsed = parse_timestamp(time_value, assume_offset=ctx.assume_offset)
    return Record(
        source=source,
        data={k: v for k, v in data.items() if v is not None},
        ref=EvidenceRef(file, index),
        observed_at=parsed.utc,
        time_original=parsed.original,
        time_zone=parsed.zone,
    )
