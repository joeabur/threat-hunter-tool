"""Parse sshd / sudo lines from auth.log, /var/log/secure or journalctl short-iso output."""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any

from linux_threat_hunter.utils.timeutil import parse_iso, parse_syslog_timestamp, to_iso

LINE_RE = re.compile(
    r"^(?P<ts>(?:[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})|(?:\d{4}-\d{2}-\d{2}T\S+))\s+"
    r"(?P<host>\S+)\s+(?P<prog>[A-Za-z0-9_.\-/]+?)(?:\[(?P<pid>\d+)\])?:\s+(?P<msg>.*)$"
)
SYSLOG_TS_RE = re.compile(r"^([A-Z][a-z]{2})\s+(\d{1,2})\s(\d{2}:\d{2}:\d{2})$")

FAILED_RE = re.compile(
    r"^Failed (?P<method>\S+) for (?:invalid user )?(?P<user>\S+) from (?P<ip>[0-9A-Fa-f:.]+) port (?P<port>\d+)"
)
INVALID_RE = re.compile(r"^Invalid user (?P<user>\S*) from (?P<ip>[0-9A-Fa-f:.]+)(?: port (?P<port>\d+))?")
ACCEPTED_RE = re.compile(r"^Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>[0-9A-Fa-f:.]+) port (?P<port>\d+)")
SUDO_CMD_RE = re.compile(
    r"^\s*(?P<user>\S+)\s*:\s*(?:.*?;\s*)?TTY=(?P<tty>\S+)\s*;\s*PWD=(?P<pwd>.*?)\s*;\s*"
    r"USER=(?P<target>\S+)\s*;\s*COMMAND=(?P<command>.*)$"
)
SUDO_FAIL_RE = re.compile(r"authentication failure;.*?\buser=(?P<user>\S+)")


def parse_auth_line(
    line: str, *, reference: datetime, tz: Any, line_no: int, max_len: int = 4096
) -> dict[str, Any] | None:
    """Return a normalized event dict, or None if the line is unsupported / malformed."""
    line = line.rstrip("\n")[:max_len]
    m = LINE_RE.match(line)
    if not m:
        return None
    raw_ts = m.group("ts")
    ts: datetime | None
    sm = SYSLOG_TS_RE.match(raw_ts)
    if sm:
        ts = parse_syslog_timestamp(sm.group(1), sm.group(2), sm.group(3), reference, tz)
        tz_context = f"assumed {getattr(tz, 'key', 'UTC')} (syslog timestamp has no zone; year inferred)"
    else:
        ts = parse_iso(raw_ts)
        tz_context = "offset from source timestamp"
    prog, msg = m.group("prog"), m.group("msg")
    event: dict[str, Any] = {
        "program": prog,
        "pid": int(m.group("pid")) if m.group("pid") else None,
        "hostname": m.group("host"),
        "raw_timestamp": raw_ts,
        "timezone_context": tz_context,
        "timestamp": to_iso(ts) if ts else None,
        "line_no": line_no,
        "raw": line,
    }
    if prog.startswith("sshd"):
        for name, rx in (
            ("ssh_failed", FAILED_RE),
            ("ssh_invalid_user", INVALID_RE),
            ("ssh_accepted", ACCEPTED_RE),
        ):
            mm = rx.match(msg)
            if mm:
                gd = mm.groupdict()
                event.update(
                    event=name,
                    user=gd.get("user"),
                    src_ip=gd.get("ip"),
                    port=int(gd["port"]) if gd.get("port") else None,
                    method=gd.get("method"),
                )
                return event
        return None
    if prog == "sudo":
        mm = SUDO_CMD_RE.match(msg)
        if mm:
            gd = mm.groupdict()
            event.update(
                event="sudo_command",
                user=gd["user"],
                target_user=gd["target"],
                tty=gd["tty"],
                pwd=gd["pwd"],
                command=gd["command"].strip(),
            )
            return event
        mm = SUDO_FAIL_RE.search(msg)
        if mm:
            event.update(event="sudo_auth_failure", user=mm.group("user"))
            return event
    return None


def parse_auth_log(
    text: str, *, reference: datetime, tz: Any, max_lines: int = 200000, max_len: int = 4096
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """Parse a whole log. Returns (events, stats) where stats counts skipped/unparsed lines."""
    events: list[dict[str, Any]] = []
    stats = {"lines": 0, "parsed": 0, "unsupported": 0, "no_timestamp": 0, "truncated": 0}
    for no, line in enumerate(text.splitlines(), 1):
        if no > max_lines:
            stats["truncated"] = 1
            break
        stats["lines"] += 1
        ev = parse_auth_line(line, reference=reference, tz=tz, line_no=no, max_len=max_len)
        if ev is None:
            stats["unsupported"] += 1
            continue
        stats["parsed"] += 1
        if ev["timestamp"] is None:
            stats["no_timestamp"] += 1
        events.append(ev)
    return events, stats
