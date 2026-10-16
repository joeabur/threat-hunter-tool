"""Timestamp normalisation to UTC while preserving the original string and zone context."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta, timezone

_LSTART = re.compile(r"^[A-Za-z]{3}\s+([A-Za-z]{3})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})\s+(\d{4})$")
_OFFSET_NO_COLON = re.compile(r"([+-])(\d{2})(\d{2})$")
_MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]


@dataclass(frozen=True)
class ParsedTime:
    utc: datetime | None
    original: str | None
    zone: str  # "explicit:+00:00", "assumed-local:+01:00", "assumed-utc", or "unknown"


def utc_now() -> datetime:
    return datetime.now(UTC)


def to_iso(dt: datetime | None) -> str | None:
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ") if dt else None


def local_offset_string(dt: datetime | None = None) -> str:
    local = (dt or datetime.now().astimezone()).astimezone()
    off = local.utcoffset() or timedelta(0)
    total = int(off.total_seconds())
    sign = "+" if total >= 0 else "-"
    total = abs(total)
    return f"{sign}{total // 3600:02d}:{(total % 3600) // 60:02d}"


def parse_timestamp(
    value: object, *, assume_offset: timezone | None = None, assume_label: str = "assumed-utc"
) -> ParsedTime:
    """Parse ISO-8601, unified-log, ``ps lstart`` and epoch timestamps.

    Naive timestamps are interpreted in ``assume_offset`` (default UTC) and labelled so.
    Unparseable values return ``utc=None`` with the original preserved.
    """
    if value is None or value == "":
        return ParsedTime(None, None, "unknown")
    if isinstance(value, bool):
        return ParsedTime(None, str(value), "unknown")
    if isinstance(value, (int, float)):
        try:
            seconds = float(value)
            if seconds > 1e12:  # milliseconds
                seconds /= 1000.0
            return ParsedTime(datetime.fromtimestamp(seconds, UTC), str(value), "epoch-utc")
        except (OverflowError, OSError, ValueError):
            return ParsedTime(None, str(value), "unknown")
    text = str(value).strip()
    m = _LSTART.match(text)
    if m and m.group(1) in _MONTHS:
        try:
            naive = datetime.strptime(
                f"{m.group(4)}-{_MONTHS.index(m.group(1)) + 1:02d}-{int(m.group(2)):02d} "
                f"{m.group(3)}",
                "%Y-%m-%d %H:%M:%S",
            )
        except ValueError:
            return ParsedTime(None, text, "unknown")
        return _attach(naive, text, assume_offset, assume_label)
    candidate = text.replace("Z", "+00:00") if text.endswith("Z") else text
    candidate = _OFFSET_NO_COLON.sub(r"\1\2:\3", candidate)
    if " " in candidate and "T" not in candidate:
        candidate = candidate.replace(" ", "T", 1)
    try:
        dt = datetime.fromisoformat(candidate)
    except ValueError:
        return ParsedTime(None, text, "unknown")
    if dt.tzinfo is None:
        return _attach(dt, text, assume_offset, assume_label)
    off = dt.utcoffset() or timedelta(0)
    secs = int(off.total_seconds())
    sign = "+" if secs >= 0 else "-"
    secs = abs(secs)
    label = f"explicit:{sign}{secs // 3600:02d}:{(secs % 3600) // 60:02d}"
    return ParsedTime(dt.astimezone(UTC), text, label)


def _attach(
    naive: datetime, original: str, assume_offset: timezone | None, label: str
) -> ParsedTime:
    tz = assume_offset or UTC
    aware = naive.replace(tzinfo=tz)
    if assume_offset is None:
        return ParsedTime(aware.astimezone(UTC), original, "assumed-utc")
    off = int((assume_offset.utcoffset(None) or timedelta(0)).total_seconds())
    sign = "+" if off >= 0 else "-"
    off = abs(off)
    zone = label if label != "assumed-utc" else "assumed-local"
    return ParsedTime(
        aware.astimezone(UTC), original, f"{zone}:{sign}{off // 3600:02d}:{(off % 3600) // 60:02d}"
    )
