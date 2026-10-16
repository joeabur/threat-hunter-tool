"""Host and OS context."""

from __future__ import annotations

import json
import os
import platform
import shutil
import socket
from typing import Any

from linux_threat_hunter.collectors.base import CollectContext, CollectorResult
from linux_threat_hunter.platform_info import (
    detect_distribution,
    detect_init_system,
    normalize_arch,
)
from linux_threat_hunter.utils.timeutil import to_iso


def _uptime(ctx: CollectContext) -> float | None:
    try:
        return float((ctx.proc_root / "uptime").read_text().split()[0])
    except (OSError, ValueError, IndexError):
        return None


def collect_host(ctx: CollectContext) -> CollectorResult:
    res = CollectorResult("host", "ok")
    uname = os.uname() if hasattr(os, "uname") else None
    host: dict[str, Any] = {
        "hostname": socket.gethostname(),
        "collected_at": to_iso(ctx.now),
        "kernel": uname.release if uname else platform.release(),
        "architecture": normalize_arch(uname.machine if uname else platform.machine()),
        "distribution": detect_distribution(ctx.fs_root),
        "init_system": detect_init_system(ctx.fs_root),
        "uptime_seconds": _uptime(ctx),
        "collector_is_root": ctx.is_root,
    }
    if host["uptime_seconds"] is None:
        res.notes.append("uptime unavailable (/proc/uptime unreadable)")
    # Logged-in users (utmp via `who`; may be empty in containers)
    who = ctx.run(["who"])
    if who.ok:
        host["logged_in"] = [ln.split()[:2] for ln in who.stdout.splitlines() if ln.split()]
    else:
        host["logged_in"] = None
        res.notes.append(f"logged-in users unavailable: {who.error}")
    # Interfaces / routes
    for key, argv in (("interfaces", ["ip", "-j", "addr"]), ("routes", ["ip", "-j", "route"])):
        out = ctx.run(argv)
        if out.ok:
            try:
                data = json.loads(out.stdout)
                if key == "interfaces":
                    data = [
                        {
                            "name": d.get("ifname"),
                            "state": d.get("operstate"),
                            "addresses": [a.get("local") for a in d.get("addr_info", [])],
                        }
                        for d in data
                    ]
                host[key] = data[:200]
            except ValueError:
                host[key] = None
                res.notes.append(f"{key}: could not parse `ip -j` output")
        else:
            host[key] = None
            res.notes.append(f"{key} unavailable: {out.error}")
    # Disk
    disks = []
    for mount in ("/", "/var", "/tmp", "/home"):
        try:
            u = shutil.disk_usage(ctx.host_path(mount))
            disks.append({"mount": mount, "total": u.total, "free": u.free})
        except OSError:
            continue
    host["disk"] = disks
    res.outputs["host.json"] = host
    res.counts["fields"] = len(host)
    if res.notes:
        res.status = "partial"
    return res
