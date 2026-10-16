from __future__ import annotations

import plistlib
import re
from pathlib import Path
from typing import Any

from ..models import CollectorResult
from ..utils.errors import InputError
from ..utils.paths import read_bytes_bounded, sha256_bytes
from .base import CollectContext, Collector, file_meta
from .codesign import FileEnricher

_MAX_PLIST = 1024 * 1024
_MAX_STARTUP = 256 * 1024
_INTEREST = re.compile(
    r"curl|wget|base64|eval\b|osascript|\bnc\s|ncat|bash\s+-i|/tmp/|/private/tmp/|"
    r"python[0-9.]*\s+-c|launchctl|nohup|chmod\s+\+x|xattr"
)
_KIND_BY_DIR = {"LaunchAgents": "launch_agent", "LaunchDaemons": "launch_daemon",
                "StartupItems": "startup_item"}  # fmt: skip


def _lines_of_interest(text: str, redact, limit: int = 10) -> list[str]:  # type: ignore[no-untyped-def]
    out: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if _INTEREST.search(stripped):
            out.append(redact(stripped[:300]))
            if len(out) >= limit:
                break
    return out


class PersistenceCollector(Collector):
    name = "persistence"
    description = (
        "LaunchAgents/Daemons, startup items, shell startup files, login hooks, user crontab"
    )
    privilege_note = (
        "System launch directories are readable by all users; other users' home directories, "
        "/var/root login hooks and /usr/lib/cron/tabs need elevated access and are reported as "
        "inaccessible when denied."
    )

    def planned(self, ctx: CollectContext) -> list[str]:
        cfg = ctx.config.collection
        dirs = list(cfg["persistence_dirs"]["system"]) + [
            "/Users/<each home>/" + d for d in cfg["persistence_dirs"]["per_user"]
        ]
        files = list(cfg["shell_startup_files"]["system"]) + [
            "/Users/<each home>/" + f for f in cfg["shell_startup_files"]["per_user"]
        ]
        return (
            [f"read directory {d}" for d in dirs]
            + [f"read file {f}" for f in files]
            + [f"read plist {cfg['login_hook_plist']}", "/usr/bin/crontab -l"]
        )

    def collect(self, ctx: CollectContext, result: CollectorResult) -> None:
        cfg = ctx.config.collection
        enrich = FileEnricher(ctx)
        dirs: list[str] = list(cfg["persistence_dirs"]["system"])
        for home in ctx.homes():
            dirs.extend(f"/Users/{home.name}/{d}" for d in cfg["persistence_dirs"]["per_user"])
        denied = 0
        for d in dirs:
            real = ctx.real_path(d)
            try:
                entries = sorted(real.iterdir())
            except FileNotFoundError:
                continue
            except PermissionError:
                denied += 1
                result.errors.append(f"permission denied reading {d}")
                continue
            except OSError as exc:
                result.errors.append(f"cannot read {d}: {exc.strerror or exc}")
                continue
            kind = _KIND_BY_DIR.get(Path(d).name, "launch_item")
            for entry in entries:
                if kind == "startup_item":
                    if entry.is_dir() and not entry.is_symlink():
                        result.records.append(self._startup_item(ctx, entry, f"{d}/{entry.name}"))
                    continue
                if entry.suffix != ".plist":
                    continue
                result.records.append(
                    self._launch_plist(ctx, enrich, entry, f"{d}/{entry.name}", kind, d)
                )
        self._shell_startup(ctx, result)
        self._login_hook(ctx, result)
        self._crontab(ctx, result)
        result.notes.extend(enrich.notes)
        if denied:
            result.notes.append(
                f"{denied} persistence directories were not readable with current privileges"
            )
        result.notes.append(
            "Login Items managed by the Background Task Management database are not collected "
            "(reading it requires admin rights); absence of login items here is unknown, not clean."
        )

    # -- individual artifact types -------------------------------------------------------

    def _launch_plist(self, ctx: CollectContext, enrich: FileEnricher, path: Path, display: str,
                      kind: str, directory: str) -> dict[str, Any]:  # fmt: skip
        meta = file_meta(path, display) or {"path": display}
        rec: dict[str, Any] = {
            **meta, "kind": kind,
            "scope": "user" if display.startswith("/Users/") else "system",
        }  # fmt: skip
        if meta.get("is_symlink"):
            rec["parse_error"] = "symlink not followed"
            return rec
        try:
            data = read_bytes_bounded(path, _MAX_PLIST)
        except InputError as exc:
            rec["parse_error"] = str(exc)[:200]
            return rec
        rec["sha256"] = sha256_bytes(data)
        try:
            plist = plistlib.loads(data)
        except Exception as exc:  # noqa: BLE001 - malformed plists are data, not crashes
            rec["parse_error"] = f"plist unreadable: {type(exc).__name__}"
            return rec
        if not isinstance(plist, dict):
            rec["parse_error"] = "plist root is not a dictionary"
            return rec
        rec["label"] = plist.get("Label") if isinstance(plist.get("Label"), str) else None
        program = plist.get("Program") if isinstance(plist.get("Program"), str) else None
        args = plist.get("ProgramArguments")
        args = [str(a) for a in args][:50] if isinstance(args, list) else None
        if args:
            rec["program_arguments"] = [ctx.redactor.redact(a) for a in args]
        exe = program or (args[0] if args else None)
        if exe:
            rec["program_path"] = exe
            if exe.startswith("/"):
                rec["program_exists"] = ctx.real_path(exe).exists()
                if rec["program_exists"]:
                    digest = enrich.sha256(exe)
                    if digest:
                        rec["program_sha256"] = digest
                    sign = enrich.codesign(exe)
                    if sign:
                        rec["program_codesign"] = sign
            else:
                rec["program_exists"] = None  # relative; resolved via PATH by launchd
        rec["run_at_load"] = bool(plist.get("RunAtLoad", False))
        ka = plist.get("KeepAlive")
        rec["keep_alive"] = bool(ka) if not isinstance(ka, dict) else True
        if isinstance(plist.get("StartInterval"), int):
            rec["start_interval"] = plist["StartInterval"]
        rec["has_calendar_interval"] = "StartCalendarInterval" in plist
        if isinstance(plist.get("WatchPaths"), list):
            rec["watch_paths"] = [str(p) for p in plist["WatchPaths"]][:20]
        if isinstance(plist.get("UserName"), str):
            rec["user_name"] = plist["UserName"]
        return rec

    def _startup_item(self, ctx: CollectContext, entry: Path, display: str) -> dict[str, Any]:
        meta = file_meta(entry, display) or {"path": display}
        return {**meta, "kind": "startup_item", "scope": "system"}

    def _shell_startup(self, ctx: CollectContext, result: CollectorResult) -> None:
        cfg = ctx.config.collection["shell_startup_files"]
        candidates = list(cfg["system"])
        for home in ctx.homes():
            candidates.extend(f"/Users/{home.name}/{f}" for f in cfg["per_user"])
        for display in candidates:
            real = ctx.real_path(display)
            meta = file_meta(real, display)
            if meta is None or meta.get("is_symlink"):
                continue
            rec: dict[str, Any] = {**meta, "kind": "shell_startup",
                                   "scope": "user" if display.startswith("/Users/") else "system"}  # fmt: skip
            try:
                data = read_bytes_bounded(real, _MAX_STARTUP)
            except InputError as exc:
                rec["parse_error"] = str(exc)[:200]
                result.records.append(rec)
                continue
            rec["sha256"] = sha256_bytes(data)
            rec["lines_of_interest"] = _lines_of_interest(
                data.decode("utf-8", errors="replace"), ctx.redactor.redact
            )
            result.records.append(rec)

    def _login_hook(self, ctx: CollectContext, result: CollectorResult) -> None:
        display = ctx.config.collection["login_hook_plist"]
        real = ctx.real_path(display)
        try:
            data = read_bytes_bounded(real, _MAX_PLIST)
        except InputError:
            result.notes.append(
                f"{display} not readable (needs root) or absent; login hooks unknown"
            )
            return
        try:
            plist = plistlib.loads(data)
        except Exception:  # noqa: BLE001
            result.errors.append(f"{display}: plist unreadable")
            return
        meta = file_meta(real, display) or {"path": display}
        for key in ("LoginHook", "LogoutHook"):
            value = plist.get(key) if isinstance(plist, dict) else None
            if isinstance(value, str):
                result.records.append(
                    {
                        **meta,
                        "kind": "login_hook",
                        "label": key,
                        "program_path": value,
                        "program_exists": ctx.real_path(value).exists()
                        if value.startswith("/")
                        else None,
                        "sha256": sha256_bytes(data),
                    }  # fmt: skip
                )

    def _crontab(self, ctx: CollectContext, result: CollectorResult) -> None:
        res = ctx.run(["/usr/bin/crontab", "-l"], max_bytes=256 * 1024)
        if res.error or res.timed_out:
            result.notes.append("crontab -l unavailable")
            return
        if res.returncode != 0:
            return  # "no crontab for user" exits non-zero
        lines = [
            ln.strip() for ln in res.stdout.splitlines() if ln.strip() and not ln.startswith("#")
        ]
        if lines:
            result.records.append(
                {
                    "path": "crontab:current-user",
                    "kind": "cron",
                    "scope": "user",
                    "lines_of_interest": [ctx.redactor.redact(ln[:300]) for ln in lines[:20]],
                    "sha256": sha256_bytes(res.stdout.encode()),
                }  # fmt: skip
            )
        result.notes.append(
            "Only the current user's crontab is read; /usr/lib/cron/tabs needs root."
        )
