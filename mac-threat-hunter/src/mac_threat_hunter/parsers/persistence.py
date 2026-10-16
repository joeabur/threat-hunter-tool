from __future__ import annotations

from typing import Any

from ..models import Record
from .common import NormalizeContext, make_record, mode_flags


def normalize_persistence(
    raw: list[dict[str, Any]], file: str, ctx: NormalizeContext
) -> list[Record]:
    records: list[Record] = []
    for index, item in enumerate(raw):
        if not isinstance(item, dict):
            continue
        data = dict(item)
        data.update(mode_flags(item.get("mode")))
        args = item.get("program_arguments")
        text_parts: list[str] = []
        if isinstance(args, list):
            text_parts.append(" ".join(str(a) for a in args))
        elif isinstance(item.get("program"), str):
            text_parts.append(item["program"])
        lines = item.get("lines_of_interest")
        if isinstance(lines, list):
            text_parts.extend(str(x) for x in lines)
        search_text = ctx.redactor.redact("\n".join(text_parts)) if text_parts else None
        if search_text:
            data["search_text"] = search_text
        if isinstance(args, list):
            data["program_arguments"] = [ctx.redactor.redact(str(a)) for a in args]
        if isinstance(lines, list):
            data["lines_of_interest"] = [ctx.redactor.redact(str(x)) for x in lines]
        cs = item.get("program_codesign")
        if isinstance(cs, dict):
            data["program_codesign_status"] = cs.get("status")
            data["program_codesign_team_id"] = cs.get("team_id")
        records.append(make_record("persistence", data, file, index, ctx, item.get("mtime")))
    return records
