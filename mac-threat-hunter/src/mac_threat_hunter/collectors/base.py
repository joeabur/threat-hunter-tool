from __future__ import annotations

import os
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from ..config import Config
from ..models import CollectorResult
from ..utils.errors import HunterError
from ..utils.proc import CommandResult, run_command
from ..utils.redact import Redactor
from ..utils.timeutil import utc_now

Runner = Callable[..., CommandResult]


@dataclass
class LogOptions:
    window: str | None = None
    predicate: str | None = None
    archive: Path | None = None
    import_file: Path | None = None


@dataclass
class CollectContext:
    config: Config
    redactor: Redactor
    root: Path = Path("/")
    platform: str = field(default_factory=lambda: sys.platform)
    runner: Runner = run_command
    now: datetime = field(default_factory=utc_now)
    is_root: bool = field(default_factory=lambda: hasattr(os, "geteuid") and os.geteuid() == 0)
    log: LogOptions = field(default_factory=LogOptions)

    @property
    def timeout(self) -> float:
        return float(self.config.limit("subprocess_timeout_seconds"))

    def real_path(self, path: str) -> Path:
        """Map an absolute macOS path onto ``root`` (``/`` on a real Mac)."""
        return self.root / path.lstrip("/")

    def run(self, argv: list[str], *, max_bytes: int = 4 * 1024 * 1024) -> CommandResult:
        return self.runner(argv, timeout=self.timeout, max_output_bytes=max_bytes)

    def homes(self) -> list[Path]:
        """Readable user home directories under /Users (excluding Shared and guest)."""
        users = self.real_path("/Users")
        try:
            return sorted(
                p for p in users.iterdir()
                if p.is_dir() and not p.is_symlink() and p.name not in {"Shared", "Guest"}
                and not p.name.startswith(".")
            )  # fmt: skip
        except OSError:
            return []

    def expand_home(self, spec: str) -> list[str]:
        """Expand ``~/x`` to one absolute macOS path per home directory."""
        if not spec.startswith("~/"):
            return [spec]
        return ["/Users/" + h.name + spec[1:] for h in self.homes()]


class Collector:
    name = ""
    description = ""
    privilege_note: str | None = None
    macos_only = True

    def planned(self, ctx: CollectContext) -> list[str]:
        return []

    def collect(self, ctx: CollectContext, result: CollectorResult) -> None:
        raise NotImplementedError

    def run(self, ctx: CollectContext, *, dry_run: bool = False) -> CollectorResult:
        result = CollectorResult(
            name=self.name, status="ok", privilege_note=self.privilege_note,
            commands=self.planned(ctx),
        )  # fmt: skip
        if dry_run:
            result.status = "dry_run"
            return result
        if self.macos_only and ctx.platform != "darwin":
            result.status = "unsupported"
            result.errors.append(
                f"{self.name} collection needs macOS (running on {ctx.platform}); nothing collected."
            )
            return result
        try:
            self.collect(ctx, result)
        except HunterError as exc:
            result.status = "failed"
            result.errors.append(str(exc))
            return result
        except Exception as exc:  # noqa: BLE001 - one collector must never stop the others
            result.status = "failed"
            result.errors.append(f"unexpected error: {type(exc).__name__}: {exc}")
            return result
        if result.status == "ok" and result.errors:
            result.status = "partial" if result.records or result.raw_files else "failed"
        return result


def stat_owner(st: os.stat_result) -> tuple[str, str]:
    owner, group = str(st.st_uid), str(st.st_gid)
    try:
        import grp
        import pwd

        owner = pwd.getpwuid(st.st_uid).pw_name
        group = grp.getgrgid(st.st_gid).gr_name
    except (ImportError, KeyError, OSError):
        pass
    return owner, group


def mode_string(st: os.stat_result) -> str:
    return format(st.st_mode & 0o7777, "04o")


def file_meta(path: Path, display: str) -> dict[str, Any] | None:
    """Metadata from lstat (never follows symlinks); ``None`` if the path is unreadable."""
    from datetime import UTC
    from datetime import datetime as _dt

    from ..utils.timeutil import to_iso

    try:
        st = os.lstat(path)
    except OSError:
        return None
    owner, group = stat_owner(st)
    return {
        "path": display,
        "owner": owner,
        "group": group,
        "mode": mode_string(st),
        "size": st.st_size,
        "mtime": to_iso(_dt.fromtimestamp(st.st_mtime, UTC)),
        "is_symlink": os.path.islink(path),
    }
