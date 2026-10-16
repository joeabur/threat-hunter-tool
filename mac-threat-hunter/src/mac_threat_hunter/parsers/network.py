from __future__ import annotations

import ipaddress
from typing import Any

from ..models import Record
from .common import NormalizeContext, make_record


def _is_wildcard(addr: str | None) -> bool:
    return addr in {"*", "0.0.0.0", "::", "[::]"}  # noqa: S104  # nosec B104 - classification only, no bind


def _is_loopback(addr: str | None) -> bool:
    if not addr:
        return False
    try:
        return ipaddress.ip_address(addr.strip("[]")).is_loopback
    except ValueError:
        return addr == "localhost"


def normalize_network(
    raw: list[dict[str, Any]],
    file: str,
    ctx: NormalizeContext,
    process_by_pid: dict[int, dict[str, Any]] | None = None,
) -> list[Record]:
    records: list[Record] = []
    for index, item in enumerate(raw):
        if not isinstance(item, dict):
            continue
        data = dict(item)
        state = str(item.get("state") or "").upper()
        data["state"] = state or None
        data["is_listener"] = state == "LISTEN"
        data["local_is_wildcard"] = _is_wildcard(item.get("local_address"))
        data["local_is_loopback"] = _is_loopback(item.get("local_address"))
        remote = item.get("remote_address")
        if isinstance(remote, str) and remote not in {"*", ""}:
            try:
                ip = ipaddress.ip_address(remote.strip("[]"))
                data["remote_address"] = str(ip)
                data["remote_is_private"] = ip.is_private or ip.is_loopback or ip.is_link_local
            except ValueError:
                data["remote_host"] = data.get("remote_host") or remote.lower().rstrip(".")
                data.pop("remote_address", None)
        host = data.get("remote_host")
        if isinstance(host, str):
            data["remote_host"] = host.lower().rstrip(".")
        pid = item.get("pid")
        data.setdefault("process_association", "lsof" if pid is not None else "unavailable")
        if process_by_pid and isinstance(pid, int) and pid in process_by_pid:
            proc = process_by_pid[pid]
            if not data.get("process_path") and proc.get("path"):
                data["process_path"] = proc["path"]
                data["process_association"] = "joined-by-pid"
            if proc.get("sha256"):
                data.setdefault("process_sha256", proc["sha256"])
        data["search_text"] = (
            " ".join(str(x) for x in (data.get("remote_address"), data.get("remote_host")) if x)
            or None
        )
        records.append(make_record("network", data, file, index, ctx, item.get("observed_at")))
    return records
