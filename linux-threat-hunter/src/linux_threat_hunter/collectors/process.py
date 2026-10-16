"""Process inventory from /proc (read-only; nothing is executed or signalled)."""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from linux_threat_hunter.collectors.base import CollectContext, CollectorResult
from linux_threat_hunter.utils.safe import sha256_file
from linux_threat_hunter.utils.timeutil import to_iso


def parse_stat(text: str) -> dict[str, Any] | None:
    """Parse /proc/<pid>/stat (the comm field may contain spaces and parentheses)."""
    lp, rp = text.find("("), text.rfind(")")
    if lp < 0 or rp < lp:
        return None
    rest = text[rp + 2 :].split()
    if len(rest) < 20:
        return None
    try:
        return {
            "name": text[lp + 1 : rp],
            "state": rest[0],
            "ppid": int(rest[1]),
            "starttime_ticks": int(rest[19]),
        }
    except ValueError:
        return None


def _passwd_map(ctx: CollectContext) -> dict[int, str]:
    mapping: dict[int, str] = {}
    try:
        for line in ctx.host_path("/etc/passwd").read_text(errors="replace").splitlines():
            parts = line.split(":")
            if len(parts) > 2 and parts[2].isdigit():
                mapping.setdefault(int(parts[2]), parts[0])
    except OSError:
        pass
    return mapping


def _boot_time(ctx: CollectContext) -> int | None:
    try:
        for line in (ctx.proc_root / "stat").read_text().splitlines():
            if line.startswith("btime"):
                return int(line.split()[1])
    except (OSError, ValueError, IndexError):
        pass
    return None


def collect_processes(ctx: CollectContext) -> CollectorResult:
    res = CollectorResult("process", "ok")
    users = _passwd_map(ctx)
    btime = _boot_time(ctx)
    try:
        hz = os.sysconf("SC_CLK_TCK")
    except (ValueError, OSError, AttributeError):
        hz = 100
    hashing = bool(ctx.config["collection"]["process_hashing"])
    max_hash = ctx.config["limits"]["max_hash_file_bytes"]
    cache: dict[str, str | None] = {}
    procs: list[dict[str, Any]] = []
    inaccessible = vanished = 0
    try:
        entries = [p for p in ctx.proc_root.iterdir() if p.name.isdigit()]
    except OSError as exc:
        res.status = "failed"
        res.errors.append(f"cannot list {ctx.proc_root}: {exc}")
        return res
    for entry in sorted(entries, key=lambda p: int(p.name)):
        try:
            stat = parse_stat((entry / "stat").read_text(errors="replace"))
        except (FileNotFoundError, ProcessLookupError):
            vanished += 1
            continue
        except OSError:
            inaccessible += 1
            continue
        if stat is None:
            continue
        rec: dict[str, Any] = {
            "pid": int(entry.name),
            "ppid": stat["ppid"],
            "name": stat["name"],
            "state": stat["state"],
        }
        try:
            for line in (entry / "status").read_text(errors="replace").splitlines():
                if line.startswith("Uid:"):
                    uid = int(line.split()[1])
                    rec["user"] = users.get(uid, str(uid))
                    break
        except OSError:
            rec["user"] = None
        if btime is not None:
            start = datetime.fromtimestamp(btime, UTC) + timedelta(seconds=stat["starttime_ticks"] / hz)
            rec["start_time"] = to_iso(start)
        exe: str | None = None
        try:
            exe = os.readlink(entry / "exe")
        except OSError:
            inaccessible += 1
        rec["exe"] = exe
        try:
            raw = (entry / "cmdline").read_bytes()[:8192]
            rec["cmdline"] = ctx.redactor.text(" ".join(raw.decode(errors="replace").split("\x00")).strip())
        except OSError:
            rec["cmdline"] = None
        rec["kernel_thread"] = exe is None and not rec.get("cmdline")
        if hashing and exe and not exe.endswith(" (deleted)"):
            if exe not in cache:
                cache[exe] = sha256_file(Path(entry / "exe"), max_hash)
            rec["sha256"] = cache[exe]
        elif exe and exe.endswith(" (deleted)"):
            rec["exe_deleted"] = True
        procs.append(rec)
    res.outputs["processes.json"] = procs
    res.counts = {
        "processes": len(procs),
        "inaccessible_attributes": inaccessible,
        "vanished": vanished,
    }
    if inaccessible and not ctx.is_root:
        res.status = "partial"
        res.notes.append(
            f"{inaccessible} process attributes were not readable as this user (executable path "
            "for other users' processes needs elevated access; the tool never escalates itself)"
        )
    return res
