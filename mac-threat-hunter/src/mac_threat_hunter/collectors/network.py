from __future__ import annotations

from ..models import CollectorResult
from . import parsing
from .base import CollectContext, Collector

_LSOF = ["/usr/sbin/lsof", "-nP", "-i", "-F", "pcLPnT"]


class NetworkCollector(Collector):
    name = "network"
    description = "Listening sockets and active connections with the owning process (via lsof)"
    privilege_note = (
        "Without root, lsof only shows sockets owned by your own processes; other users' and "
        "system sockets are invisible."
    )

    def planned(self, ctx: CollectContext) -> list[str]:
        return [" ".join(_LSOF)]

    def collect(self, ctx: CollectContext, result: CollectorResult) -> None:
        res = ctx.run(_LSOF, max_bytes=16 * 1024 * 1024)
        if res.error or res.timed_out:
            result.status = "failed"
            result.errors.append(f"lsof failed: {'timed out' if res.timed_out else res.error}")
            return
        if res.returncode not in (0, 1):  # lsof exits 1 when nothing matches
            result.errors.append(f"lsof exited {res.returncode}: {res.stderr.strip()[:200]}")
        if res.truncated:
            result.errors.append("lsof output exceeded the size limit and was truncated")
        records = parsing.parse_lsof_fields(res.stdout)
        for rec in records[: ctx.config.limit("max_records_per_source")]:
            rec["process_association"] = "lsof"
            result.records.append(rec)
        if not ctx.is_root:
            result.notes.append(
                "Collected without root: only this user's sockets are visible. Absence of a "
                "socket here does not mean it does not exist."
            )
