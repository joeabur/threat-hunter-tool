"""Timestamp parsing and normalization to UTC, preserving the original context."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta, tzinfo
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

MONTHS = {
    m: i for i, m in enumerate(["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)
}


def get_tz(name: str | None) -> tzinfo:
    """Return a tzinfo for ``name``; fall back to UTC when unknown/unavailable."""
    if not name or name.upper() in {"UTC", "Z", "GMT"}:
        return UTC
    try:
        return ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError, OSError):
        return UTC


def parse_iso(value: str) -> datetime | None:
    """Parse an ISO-8601 timestamp. Naive values are rejected (timezone unknown)."""
    text = value.strip()
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is None:
        return None
    return dt.astimezone(UTC)


def parse_syslog_timestamp(month: str, day: str, clock: str, reference: datetime, tz: tzinfo) -> datetime | None:
    """Parse a traditional syslog stamp (no year, no zone).

    The year is inferred from ``reference`` (the collection time): if the result would be
    more than a day in the future, the previous year is used. ``tz`` is the zone the host
    wrote the log in (from the evidence manifest); it defaults to UTC.
    """
    m = MONTHS.get(month.capitalize())
    if m is None:
        return None
    try:
        hh, mm, ss = (int(x) for x in clock.split(":"))
        candidate = datetime(reference.year, m, int(day), hh, mm, ss, tzinfo=tz)
        if candidate.astimezone(UTC) > reference.astimezone(UTC) + timedelta(days=1):
            candidate = candidate.replace(year=reference.year - 1)
    except ValueError:
        return None
    return candidate.astimezone(UTC)


def to_iso(dt: datetime) -> str:
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
