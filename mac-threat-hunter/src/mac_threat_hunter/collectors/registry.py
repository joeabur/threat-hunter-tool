from __future__ import annotations

from ..models import CollectorResult
from .base import CollectContext, Collector
from .files import FileCollector
from .logs import LogCollector
from .network import NetworkCollector
from .persistence import PersistenceCollector
from .processes import ProcessCollector
from .system import SystemCollector

COLLECTORS: dict[str, Collector] = {
    c.name: c
    for c in (
        SystemCollector(), ProcessCollector(), NetworkCollector(),
        PersistenceCollector(), FileCollector(), LogCollector(),
    )
}  # fmt: skip


def run_collectors(
    names: list[str], ctx: CollectContext, *, dry_run: bool = False
) -> list[CollectorResult]:
    results: list[CollectorResult] = []
    for name in names:
        results.append(COLLECTORS[name].run(ctx, dry_run=dry_run))
    return results
