"""Unified log export parsing (``log show --style ndjson``/json, plus a loose syslog style)."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

from ..models import Record
from .common import NormalizeContext, basename, make_record

_FAILED_PW = re.compile(
    r"Failed (?:password|publickey|keyboard-interactive/pam) for (?:invalid user )?(\S+) from (\S+)"
)
_INVALID_USER = re.compile(r"Invalid user (\S+) from (\S+)")
_ACCEPTED = re.compile(
    r"Accepted (?:password|publickey|keyboard-interactive/pam) for (\S+) from (\S+)"
)
_SUDO_FAIL = re.compile(r"^\s*(\S+)\s*:.*(?:incorrect password attempts?|authentication failure)")
_SUDO_FAIL2 = re.compile(r"authentication failure.*\bruser=(\S+)")
_SYSLOG_LINE = re.compile(
    r"^(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:?\d{2}|Z)?)\s+\S+\s+"
    r"(?P<proc>[^\[\s:]+)(?:\[(?P<pid>\d+)\])?:\s+(?P<msg>.*)$"
)
_MAX_MESSAGE = 4000


@dataclass
class LogParseResult:
    records: list[Record] = field(default_factory=list)
    malformed_lines: int = 0
    total_lines: int = 0


def _auth_fields(process: str | None, message: str) -> dict[str, Any]:
    out: dict[str, Any] = {}
    m = _FAILED_PW.search(message) or _INVALID_USER.search(message)
    if m:
        out.update(auth_result="failed", auth_user=m.group(1), src_ip=m.group(2).strip("[]"))
        return out
    m = _ACCEPTED.search(message)
    if m:
        out.update(auth_result="accepted", auth_user=m.group(1), src_ip=m.group(2).strip("[]"))
        return out
    if process == "sudo":
        m = _SUDO_FAIL.search(message) or _SUDO_FAIL2.search(message)
        if m:
            out.update(auth_result="failed", auth_user=m.group(1))
    return out


def _from_ndjson_obj(obj: dict[str, Any], ctx: NormalizeContext) -> dict[str, Any]:
    image = obj.get("processImagePath") or obj.get("process_path")
    process = obj.get("process") or basename(image)
    message = str(obj.get("eventMessage") or obj.get("message") or "")[:_MAX_MESSAGE]
    message = ctx.redactor.redact(message)
    data: dict[str, Any] = {
        "process": process,
        "process_path": image,
        "pid": obj.get("processID") or obj.get("pid"),
        "message": message,
        "search_text": message,
        "subsystem": obj.get("subsystem") or None,
        "category": obj.get("category") or None,
        "message_type": obj.get("messageType"),
        "sender_path": obj.get("senderImagePath"),
        "_time": obj.get("timestamp"),
    }
    data.update(_auth_fields(process, message))
    return data


def parse_log_text(text: str, file: str, ctx: NormalizeContext, max_records: int) -> LogParseResult:
    result = LogParseResult()
    stripped = text.lstrip()
    items: list[tuple[int, dict[str, Any]]] = []
    if stripped.startswith("["):
        try:
            loaded = json.loads(text)
        except json.JSONDecodeError:
            result.malformed_lines += 1
            return result
        for i, obj in enumerate(loaded if isinstance(loaded, list) else []):
            result.total_lines += 1
            if isinstance(obj, dict):
                items.append((i, _from_ndjson_obj(obj, ctx)))
            else:
                result.malformed_lines += 1
    else:
        for i, line in enumerate(text.splitlines()):
            if not line.strip():
                continue
            result.total_lines += 1
            if len(items) >= max_records:
                break
            if line.lstrip().startswith("{"):
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    result.malformed_lines += 1
                    continue
                if not isinstance(obj, dict):
                    result.malformed_lines += 1
                    continue
                items.append((i, _from_ndjson_obj(obj, ctx)))
                continue
            m = _SYSLOG_LINE.match(line)
            if not m:
                result.malformed_lines += 1
                continue
            message = ctx.redactor.redact(m.group("msg")[:_MAX_MESSAGE])
            proc = m.group("proc")
            data: dict[str, Any] = {
                "process": proc,
                "pid": int(m.group("pid")) if m.group("pid") else None,
                "message": message,
                "search_text": message,
                "_time": m.group(1),
            }
            data.update(_auth_fields(proc, message))
            items.append((i, data))
    for index, data in items[:max_records]:
        time_value = data.pop("_time", None)
        result.records.append(make_record("log", data, file, index, ctx, time_value))
    return result
