"""Persistence artifact inspection: systemd, cron, shell startup, SSH config, rc, modules.

Files are read (bounded), hashed and described. Nothing is executed or modified.
Private keys and password hashes are never read; authorized_keys is hashed only.
"""

from __future__ import annotations

import contextlib
import os
import stat as statmod
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from linux_threat_hunter.collectors.base import CollectContext, CollectorResult
from linux_threat_hunter.parsers.persistence import normalize_artifact
from linux_threat_hunter.utils.safe import is_sensitive_path, sha256_file
from linux_threat_hunter.utils.timeutil import to_iso

CONTENT_KINDS = {
    "systemd_service",
    "systemd_timer",
    "systemd_dropin",
    "cron_file",
    "cron_script",
    "rc_script",
    "shell_startup",
    "ssh_config",
}


def _owner_map(ctx: CollectContext) -> dict[int, str]:
    out: dict[int, str] = {}
    try:
        for line in ctx.host_path("/etc/passwd").read_text(errors="replace").splitlines():
            p = line.split(":")
            if len(p) > 2 and p[2].isdigit():
                out.setdefault(int(p[2]), p[0])
    except OSError:
        pass
    return out


def _home_dirs(ctx: CollectContext) -> list[tuple[str, Path]]:
    homes: list[tuple[str, Path]] = []
    limit = ctx.config["collection"]["max_users"]
    root_home = ctx.host_path("/root")
    if root_home.is_dir():
        homes.append(("/root", root_home))
    try:
        for p in sorted(ctx.host_path("/home").iterdir())[:limit]:
            if p.is_dir() and not p.is_symlink():
                homes.append((f"/home/{p.name}", p))
    except OSError:
        pass
    return homes


def describe_file(
    ctx: CollectContext,
    abs_path: str,
    real: Path,
    kind: str,
    owners: dict[int, str],
    errors: list[str],
    extra: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    """Build a persistence artifact record for a regular file (symlinks are skipped)."""
    if is_sensitive_path(abs_path):
        return None
    try:
        st = real.lstat()
    except OSError as exc:
        errors.append(f"{abs_path}: {exc.strerror}")
        return None
    if statmod.S_ISLNK(st.st_mode) or not statmod.S_ISREG(st.st_mode):
        return None
    rec: dict[str, Any] = {
        "kind": kind,
        "path": abs_path,
        "owner": owners.get(st.st_uid, str(st.st_uid)),
        "mode": format(statmod.S_IMODE(st.st_mode), "04o"),
        "mtime": to_iso(datetime.fromtimestamp(st.st_mtime, UTC)),
        "size": st.st_size,
        "sha256": sha256_file(real, ctx.config["limits"]["max_hash_file_bytes"]),
    }
    if extra:
        rec.update(extra)
    if kind in CONTENT_KINDS:
        limit = min(
            ctx.config["collection"]["max_unit_bytes"],
            ctx.config["collection"]["content_excerpt_bytes"],
        )
        try:
            with real.open("rb") as fh:
                text = fh.read(limit).decode("utf-8", errors="replace")
        except OSError as exc:
            errors.append(f"{abs_path}: cannot read ({exc.strerror})")
            text = ""
        rec["content"] = ctx.redactor.text(text)
        rec["content_truncated"] = st.st_size > limit
        if rec["content_truncated"]:
            rec["content"] += "\n# [truncated by collector]"
    # Record whether referenced absolute paths exist (a fact captured at collection time).
    exists: dict[str, bool] = {}
    for derived in normalize_artifact(rec):
        p = derived.get("exec_path")
        if p:
            exists[p] = os.path.exists(ctx.host_path(p))
    if exists:
        rec["referenced_paths_exist"] = exists
    return rec


def _iter_files(directory: Path, max_depth: int = 3, cap: int = 2000) -> list[Path]:
    found: list[Path] = []
    base_depth = len(directory.parts)
    for dirpath, dirnames, filenames in os.walk(directory, followlinks=False):
        if len(Path(dirpath).parts) - base_depth >= max_depth:
            dirnames[:] = []
        for name in sorted(filenames):
            found.append(Path(dirpath) / name)
            if len(found) >= cap:
                return found
    return found


def collect_persistence(ctx: CollectContext) -> CollectorResult:
    res = CollectorResult("persistence", "ok")
    cfg = ctx.config["collection"]
    owners = _owner_map(ctx)
    artifacts: list[dict[str, Any]] = []
    errors: list[str] = []

    def add(abs_path: str, kind: str, extra: dict[str, Any] | None = None) -> None:
        real = ctx.host_path(abs_path)
        if not real.exists() and not real.is_symlink():
            return
        rec = describe_file(ctx, abs_path, real, kind, owners, errors, extra)
        if rec:
            artifacts.append(rec)

    def to_abs(p: Path) -> str:
        return "/" + p.relative_to(ctx.fs_root).as_posix()

    systemd_dirs = list(cfg["systemd_dirs"])
    if ctx.profile == "full":
        systemd_dirs += cfg["systemd_vendor_dirs_full"]
    homes = _home_dirs(ctx)
    for _, h in homes:
        systemd_dirs.append(to_abs(h / ".config/systemd/user"))
    for d in systemd_dirs:
        real = ctx.host_path(d)
        if not real.is_dir():
            continue
        for f in _iter_files(real):
            name = f.name
            parent_is_dropin = f.parent.name.endswith(".d")
            if name.endswith(".service") and not parent_is_dropin:
                kind = "systemd_service"
            elif name.endswith(".timer") and not parent_is_dropin:
                kind = "systemd_timer"
            elif parent_is_dropin and name.endswith(".conf"):
                kind = "systemd_dropin"
            else:
                continue
            add(to_abs(f), kind, {"scope": "user" if "/user" in d or ".config" in d else "system"})

    for f in cfg["cron_files"]:
        add(f, "cron_file", {"has_user_field": True})
    for d in cfg["cron_dirs"]:
        real = ctx.host_path(d)
        if not real.is_dir():
            continue
        spool = d.startswith("/var/spool")
        for f in _iter_files(real, max_depth=1):
            kind = "cron_script" if d.startswith("/etc/cron.") and d != "/etc/cron.d" else "cron_file"
            add(to_abs(f), kind, {"has_user_field": d == "/etc/cron.d", "spool": spool})

    for f in cfg["shell_startup_files"]:
        add(f, "shell_startup")
    for d in cfg["shell_startup_dirs"]:
        real = ctx.host_path(d)
        if real.is_dir():
            for f in _iter_files(real, max_depth=1):
                add(to_abs(f), "shell_startup")
    for home, hp in homes:
        for name in cfg["user_shell_files"]:
            add(f"{home}/{name}", "shell_startup")
        ak = hp / ".ssh" / "authorized_keys"
        if ak.is_file():
            rec = describe_file(ctx, f"{home}/.ssh/authorized_keys", ak, "ssh_authorized_keys", owners, errors)
            if rec:  # hashed only: no key material is stored
                with contextlib.suppress(OSError):
                    rec["key_count"] = sum(
                        1 for ln in ak.read_text(errors="replace").splitlines() if ln.strip() and not ln.startswith("#")
                    )
                artifacts.append(rec)
    for f in cfg["ssh_config_files"]:
        add(f, "ssh_config")
    for d in cfg["ssh_config_dirs"]:
        real = ctx.host_path(d)
        if real.is_dir():
            for f in _iter_files(real, max_depth=1):
                add(to_abs(f), "ssh_config")
    for f in cfg["rc_files"]:
        add(f, "ld_preload" if f.endswith("ld.so.preload") else "rc_script")

    if ctx.profile == "full":
        try:
            for line in (ctx.proc_root / "modules").read_text(errors="replace").splitlines():
                parts = line.split()
                if len(parts) >= 3:
                    artifacts.append(
                        {
                            "kind": "kernel_module",
                            "path": f"module:{parts[0]}",
                            "name": parts[0],
                            "size": int(parts[1]) if parts[1].isdigit() else None,
                            "refcount": parts[2],
                            "owner": "root",
                            "mode": None,
                            "sha256": None,
                        }
                    )
        except OSError as exc:
            res.notes.append(f"kernel modules unavailable: {exc.strerror}")

    res.outputs["persistence.json"] = artifacts
    res.counts = {"artifacts": len(artifacts), "read_errors": len(errors)}
    if errors:
        res.status = "partial"
        res.errors.extend(errors[:50])
        if not ctx.is_root:
            res.notes.append("some locations need elevated read access (the tool never escalates itself)")
    return res
