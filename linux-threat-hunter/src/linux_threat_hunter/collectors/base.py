"""Collector framework: read-only collectors that fail safely and independently."""

from __future__ import annotations

import os
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from linux_threat_hunter.utils.redact import Redactor
from linux_threat_hunter.utils.safe import CommandResult, run_command


@dataclass
class CollectContext:
    config: dict[str, Any]
    profile: str = "basic"
    fs_root: Path = Path("/")
    proc_root: Path = Path("/proc")
    runner: Callable[..., CommandResult] = run_command
    now: datetime = field(default_factory=lambda: datetime.now(UTC))
    redactor: Redactor = field(default_factory=Redactor)

    def host_path(self, absolute: str) -> Path:
        """Map an absolute host path under ``fs_root`` (tests point this at a temp dir)."""
        return self.fs_root / absolute.lstrip("/")

    def run(self, argv: list[str]) -> CommandResult:
        lim = self.config["limits"]
        return self.runner(argv, lim["subprocess_timeout_seconds"], lim["subprocess_max_output_bytes"])

    @property
    def is_root(self) -> bool:
        return hasattr(os, "geteuid") and os.geteuid() == 0


@dataclass
class CollectorResult:
    name: str
    status: str  # ok | partial | failed | skipped
    outputs: dict[str, Any] = field(default_factory=dict)  # filename -> data
    errors: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    counts: dict[str, int] = field(default_factory=dict)

    def summary(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status,
            "errors": self.errors,
            "notes": self.notes,
            "counts": self.counts,
            "outputs": sorted(self.outputs),
        }


@dataclass(frozen=True)
class CollectorSpec:
    name: str
    description: str
    sources: list[str]
    access_note: str
    fn: Callable[[CollectContext], CollectorResult]
    profiles: tuple[str, ...] = ("basic", "full")
