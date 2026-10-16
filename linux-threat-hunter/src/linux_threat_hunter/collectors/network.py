"""Network connections and listeners via `ss` (read-only)."""

from __future__ import annotations

from linux_threat_hunter.collectors.base import CollectContext, CollectorResult
from linux_threat_hunter.parsers.network import parse_ss


def collect_network(ctx: CollectContext) -> CollectorResult:
    res = CollectorResult("network", "ok")
    out = ctx.run(["ss", "-H", "-tunap"])
    if not out.ok:
        res.status = "failed"
        res.errors.append(f"`ss` unavailable or failed: {out.error}")
        res.notes.append("install iproute2 to enable network collection (the tool will not install it)")
        return res
    rows = parse_ss(out.stdout)
    res.outputs["network.json"] = rows
    res.counts = {"sockets": len(rows), "listening": sum(1 for r in rows if r["listening"])}
    if out.truncated:
        res.status = "partial"
        res.notes.append("ss output exceeded the output limit and was truncated")
    if not ctx.is_root and any(r["pid"] is None for r in rows):
        res.status = "partial"
        res.notes.append(
            "process-to-socket associations are only visible for your own processes unless run with elevated privileges"
        )
    return res
