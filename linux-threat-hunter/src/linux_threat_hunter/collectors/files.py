"""Selected file-integrity observations and executables in watched directories."""

from __future__ import annotations

import os
import stat as statmod
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from linux_threat_hunter.collectors.base import CollectContext, CollectorResult
from linux_threat_hunter.collectors.persistence import _owner_map
from linux_threat_hunter.utils.safe import is_sensitive_path, sha256_file
from linux_threat_hunter.utils.timeutil import to_iso


def _file_type(real: Path) -> str:
    try:
        with real.open("rb") as fh:
            head = fh.read(4)
    except OSError:
        return "unknown"
    if head == b"\x7fELF":
        return "elf"
    if head[:2] == b"#!":
        return "script"
    return "other"


def _describe(ctx: CollectContext, abs_path: str, real: Path, owners: dict[int, str]) -> dict[str, Any] | None:
    try:
        st = real.lstat()
    except OSError:
        return None
    if not statmod.S_ISREG(st.st_mode):
        return None
    mode = statmod.S_IMODE(st.st_mode)
    return {
        "path": abs_path,
        "owner": owners.get(st.st_uid, str(st.st_uid)),
        "mode": format(mode, "04o"),
        "world_writable": bool(mode & 0o002),
        "setuid": bool(mode & 0o4000),
        "is_executable": bool(mode & 0o111),
        "size": st.st_size,
        "mtime": to_iso(datetime.fromtimestamp(st.st_mtime, UTC)),
        "sha256": sha256_file(real, ctx.config["limits"]["max_hash_file_bytes"]),
    }


def collect_files(ctx: CollectContext) -> CollectorResult:
    res = CollectorResult("files", "ok")
    cfg = ctx.config["collection"]
    owners = _owner_map(ctx)
    records: list[dict[str, Any]] = []
    missing = denied = 0
    for path in cfg["file_integrity_paths"]:
        if is_sensitive_path(path):
            res.notes.append(f"{path}: skipped (sensitive file; never collected)")
            continue
        real = ctx.host_path(path)
        if not real.exists():
            missing += 1
            continue
        rec = _describe(ctx, path, real, owners)
        if rec is None:
            denied += 1
            continue
        records.append(rec)
    budget = cfg["executable_scan_max_entries"]
    for d in cfg["executable_scan_dirs"]:
        real_dir = ctx.host_path(d)
        if not real_dir.is_dir():
            continue
        for dirpath, dirnames, filenames in os.walk(real_dir, followlinks=False):
            if len(Path(dirpath).relative_to(real_dir).parts) >= 2:
                dirnames[:] = []
            for name in sorted(filenames):
                if budget <= 0:
                    res.notes.append(f"{d}: scan stopped at executable_scan_max_entries")
                    break
                full = Path(dirpath) / name
                abs_path = "/" + full.relative_to(ctx.fs_root).as_posix()
                rec = _describe(ctx, abs_path, full, owners)
                if rec and rec["is_executable"]:
                    rec["source_dir"] = d
                    rec["file_type"] = _file_type(full)
                    records.append(rec)
                    budget -= 1
    res.outputs["files.json"] = records
    res.counts = {"files": len(records), "missing": missing, "unreadable": denied}
    if denied:
        res.status = "partial"
    return res
