from __future__ import annotations

from typing import Any

from ..models import Record
from .common import NormalizeContext, make_record


def normalize_system(raw: list[dict[str, Any]], file: str, ctx: NormalizeContext) -> list[Record]:
    records: list[Record] = []
    for index, item in enumerate(raw):
        if not isinstance(item, dict):
            continue
        data: dict[str, Any] = {}
        security: dict[str, Any] = (
            item["security"] if isinstance(item.get("security"), dict) else {}
        )
        data.update({f"security_{k}": v for k, v in security.items()})
        for key in ("hostname", "arch", "uptime_seconds", "boot_time"):
            data[key] = item.get(key)
        osinfo: dict[str, Any] = item["os"] if isinstance(item.get("os"), dict) else {}
        data["os_version"] = osinfo.get("version")
        data["os_build"] = osinfo.get("build")
        data["interfaces"] = item.get("interfaces")
        data["routes"] = item.get("routes")
        data["sessions"] = item.get("sessions")
        records.append(make_record("system", data, file, index, ctx, item.get("boot_time")))
    return records
