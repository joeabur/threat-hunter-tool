from __future__ import annotations

from typing import Any

from ..models import Record
from ..utils.timeutil import parse_timestamp
from .common import NormalizeContext, make_record, mode_flags


def normalize_files(raw: list[dict[str, Any]], file: str, ctx: NormalizeContext) -> list[Record]:
    records: list[Record] = []
    for index, item in enumerate(raw):
        if not isinstance(item, dict):
            continue
        data = dict(item)
        data.update(mode_flags(item.get("mode")))
        mtime = parse_timestamp(item.get("mtime"), assume_offset=ctx.assume_offset)
        if mtime.utc and ctx.collected_at:
            data["age_days"] = round((ctx.collected_at - mtime.utc).total_seconds() / 86400, 2)
        records.append(make_record("file", data, file, index, ctx, item.get("mtime")))
    return records
