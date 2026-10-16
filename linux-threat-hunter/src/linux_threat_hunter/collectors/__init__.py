"""Collector registry and orchestration (read-only; failures are isolated per collector)."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from linux_threat_hunter.collectors.auth import collect_auth
from linux_threat_hunter.collectors.base import (
    CollectContext,
    CollectorResult,
    CollectorSpec,
)
from linux_threat_hunter.collectors.files import collect_files
from linux_threat_hunter.collectors.host import collect_host
from linux_threat_hunter.collectors.network import collect_network
from linux_threat_hunter.collectors.persistence import collect_persistence
from linux_threat_hunter.collectors.process import collect_processes
from linux_threat_hunter.evidence.store import write_evidence
from linux_threat_hunter.utils.timeutil import to_iso

COLLECTORS: list[CollectorSpec] = [
    CollectorSpec(
        "host",
        "OS, kernel, uptime, users, interfaces, disk",
        ["/etc/os-release", "/proc/uptime", "who", "ip"],
        "no privileges needed",
        collect_host,
    ),
    CollectorSpec(
        "process",
        "Process inventory (PID, PPID, owner, exe, redacted cmdline, hash)",
        ["/proc/<pid>/{stat,status,exe,cmdline}"],
        "own processes without privileges; other users' exe/cmdline need elevated read access",
        collect_processes,
    ),
    CollectorSpec(
        "network",
        "TCP/UDP sockets and listeners with process association",
        ["ss -H -tunap"],
        "socket list without privileges; process names for other users need elevated access",
        collect_network,
    ),
    CollectorSpec(
        "persistence",
        "systemd units/timers, cron, shell startup, SSH config, rc, modules",
        ["/etc/systemd", "/etc/cron*", "/var/spool/cron", "~/.bashrc etc.", "/etc/ssh"],
        "most of /etc is world-readable; user crontabs and other homes need elevated access",
        collect_persistence,
    ),
    CollectorSpec(
        "auth",
        "SSH/sudo authentication events (bounded tail or journald)",
        ["/var/log/auth.log", "/var/log/secure", "journalctl"],
        "auth logs usually need membership of 'adm'/'systemd-journal' or elevated access",
        collect_auth,
    ),
    CollectorSpec(
        "files",
        "Hashes/permissions of selected files; executables in watched directories",
        ["file_integrity_paths", "executable_scan_dirs"],
        "mostly world-readable; /etc/sudoers needs elevated access",
        collect_files,
    ),
]

PROFILES = {"basic": [c.name for c in COLLECTORS], "full": [c.name for c in COLLECTORS]}


def _host_timezone(ctx: CollectContext) -> str:
    """Best-effort IANA zone of the host (syslog timestamps are written in local time)."""
    try:
        target = os.readlink(ctx.host_path("/etc/localtime"))
        if "zoneinfo/" in target:
            return target.split("zoneinfo/", 1)[1]
    except OSError:
        pass
    try:
        return ctx.host_path("/etc/timezone").read_text().strip() or "UTC"
    except OSError:
        return "UTC"


def plan(ctx: CollectContext) -> list[dict[str, Any]]:
    """Describe what would be collected (dry run); touches nothing."""
    rows = []
    for spec in COLLECTORS:
        rows.append(
            {
                "collector": spec.name,
                "description": spec.description,
                "sources": spec.sources,
                "access": spec.access_note,
            }
        )
    return rows


def collect(ctx: CollectContext, output: Path, *, force: bool = False) -> tuple[dict[str, Any], list[CollectorResult]]:
    if (output / "manifest.json").exists() and not force:
        raise FileExistsError(f"{output} already contains evidence; choose a new directory or pass --force")
    results: list[CollectorResult] = []
    sources: dict[str, Any] = {}
    for spec in COLLECTORS:
        if ctx.profile not in spec.profiles:
            results.append(CollectorResult(spec.name, "skipped", notes=["not in profile"]))
            continue
        try:
            res = spec.fn(ctx)
        except Exception as exc:  # collectors must never take down the run
            res = CollectorResult(spec.name, "failed", errors=[f"unexpected error: {type(exc).__name__}: {exc}"])
        results.append(res)
        sources.update(res.outputs)
    host = sources.get("host.json", {})
    manifest = {
        "schema_version": 1,
        "profile": ctx.profile,
        "collected_at": to_iso(ctx.now),
        "timezone": _host_timezone(ctx),
        "hostname": host.get("hostname"),
        "collection_is_root": ctx.is_root,
        "synthetic": False,
        "collectors": [r.summary() for r in results],
    }
    write_evidence(output, manifest, sources)
    return manifest, results


__all__ = ["COLLECTORS", "PROFILES", "CollectContext", "collect", "plan"]
