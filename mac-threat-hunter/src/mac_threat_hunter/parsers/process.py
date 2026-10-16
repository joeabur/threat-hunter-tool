from __future__ import annotations

import shlex
from typing import Any

from ..models import Record
from .common import NormalizeContext, basename, make_record

_INLINE_FLAGS = {"-c", "-e", "-r", "-E", "-i"}


def derive_script_path(
    name: str | None, cmdline: str | None, ctx: NormalizeContext
) -> dict[str, Any]:
    """Extract the script argument of an interpreter invocation without executing anything."""
    if not name or not cmdline or name not in ctx.script_interpreters:
        return {}
    try:
        tokens = shlex.split(cmdline[:4096])
    except ValueError:
        tokens = cmdline[:4096].split()
    args = tokens[1:]
    if any(
        a in _INLINE_FLAGS
        or (
            a.startswith("-")
            and not a.startswith("--")
            and "c" in a[1:3]
            and name in {"sh", "bash", "zsh"}
        )
        for a in args
    ):
        return {"inline_script": True}
    for arg in args:
        if arg.startswith("-"):
            continue
        return {"script_path": arg, "inline_script": False}
    return {}


def normalize_processes(
    raw: list[dict[str, Any]], file: str, ctx: NormalizeContext
) -> list[Record]:
    by_pid: dict[int, dict[str, Any]] = {}
    for item in raw:
        pid = item.get("pid") if isinstance(item, dict) else None
        if isinstance(pid, int):
            by_pid[pid] = item
    records: list[Record] = []
    for index, item in enumerate(raw):
        if not isinstance(item, dict):
            continue
        path = item.get("path")
        name = item.get("name") or basename(path)
        cmdline = item.get("cmdline")
        cmdline = ctx.redactor.redact(cmdline) if isinstance(cmdline, str) else None
        codesign: dict[str, Any] = (
            item["codesign"] if isinstance(item.get("codesign"), dict) else {}
        )
        data: dict[str, Any] = {
            "pid": item.get("pid"),
            "ppid": item.get("ppid"),
            "user": item.get("user"),
            "name": name,
            "path": path,
            "cmdline": cmdline,
            "search_text": cmdline,
            "sha256": item.get("sha256"),
            "codesign_status": codesign.get("status"),
            "codesign_team_id": codesign.get("team_id"),
            "codesign_identifier": codesign.get("identifier"),
        }
        ancestors: list[str] = []
        seen: set[int] = set()
        cur = item.get("ppid")
        while isinstance(cur, int) and cur in by_pid and cur not in seen and len(ancestors) < 8:
            seen.add(cur)
            parent = by_pid[cur]
            ancestors.append(str(parent.get("name") or basename(parent.get("path")) or "?"))
            cur = parent.get("ppid")
        ppid_value = item.get("ppid")
        parent_item = by_pid.get(ppid_value) if isinstance(ppid_value, int) else None
        if parent_item is not None:
            data["parent_name"] = parent_item.get("name") or basename(parent_item.get("path"))
            data["parent_path"] = parent_item.get("path")
        if ancestors:
            data["ancestors"] = ancestors
        data.update(derive_script_path(name, cmdline, ctx))
        records.append(make_record("process", data, file, index, ctx, item.get("start_time")))
    return records
