"""Unified log collection via the native ``log`` utility, or import of exported logs."""

from __future__ import annotations

import json
import re
from pathlib import Path

from ..models import CollectorResult
from ..utils.errors import InputError, UsageError
from ..utils.paths import read_text_bounded
from .base import CollectContext, Collector

_WINDOW = re.compile(r"^(\d{1,4})([smhd])$")
_UNIT_SECONDS = {"s": 1, "m": 60, "h": 3600, "d": 86400}
_ALLOWED_FIELDS = {
    "process", "processImagePath", "subsystem", "category", "eventMessage", "messageType",
    "senderImagePath", "sender", "eventType", "processID",
}  # fmt: skip
_TOKEN = re.compile(
    r"\s*(?:(?P<lparen>\()|(?P<rparen>\))|(?P<bool>(?:AND|OR|NOT)\b|&&|\|\|)"
    r"|(?P<op>==|!=|(?:CONTAINS|BEGINSWITH|ENDSWITH|LIKE)(?:\[[cd]+\])?(?![A-Za-z0-9]))"
    r"|(?P<field>[A-Za-z][A-Za-z0-9]*)"
    r'|(?P<str>"(?:[^"\\\x00]|\\.)*")|(?P<num>\d+))'
)
_MAX_PREDICATE = 1024


def validate_window(window: str, max_window: str) -> str:
    m = _WINDOW.match(window)
    mx = _WINDOW.match(max_window)
    if not m or not mx:
        raise UsageError(f"invalid log window {window!r}; use a number and s/m/h/d, e.g. 30m or 2h")
    if int(m.group(1)) * _UNIT_SECONDS[m.group(2)] > int(mx.group(1)) * _UNIT_SECONDS[mx.group(2)]:
        raise UsageError(f"log window {window} exceeds the configured maximum {max_window}")
    return window


def validate_predicate(predicate: str) -> str:
    """Accept only simple field/operator/literal comparisons joined by AND/OR/NOT and parentheses."""
    if not predicate or len(predicate) > _MAX_PREDICATE or "\x00" in predicate:
        raise UsageError("log predicate is empty, too long, or contains NUL")
    pos, depth = 0, 0
    tokens: list[tuple[str, str]] = []
    text = predicate.strip()
    while pos < len(text):
        m = _TOKEN.match(text, pos)
        if not m or m.end() == pos:
            raise UsageError(f"unsupported syntax in log predicate near {text[pos : pos + 20]!r}")
        pos = m.end()
        kind = m.lastgroup or ""
        tokens.append((kind, m.group(kind)))
    state = "start"  # start -> field -> op -> value -> end
    for kind, val in tokens:
        if kind == "lparen":
            if state not in {"start"}:
                raise UsageError("unexpected '(' in log predicate")
            depth += 1
        elif kind == "rparen":
            if state != "end" or depth == 0:
                raise UsageError("unbalanced ')' in log predicate")
            depth -= 1
        elif kind == "bool":
            if val == "NOT":
                if state != "start":
                    raise UsageError("unexpected NOT in log predicate")
            elif state != "end":
                raise UsageError(f"unexpected {val} in log predicate")
            else:
                state = "start"
        elif kind == "field":
            if state != "start" or val not in _ALLOWED_FIELDS:
                raise UsageError(f"field {val!r} is not allowed in a log predicate")
            state = "field"
        elif kind == "op":
            if state != "field":
                raise UsageError("operator without a field in log predicate")
            state = "op"
        elif kind in {"str", "num"}:
            if state != "op":
                raise UsageError("value without an operator in log predicate")
            state = "end"
    if state != "end" or depth != 0:
        raise UsageError("incomplete log predicate")
    return predicate


class LogCollector(Collector):
    name = "logs"
    description = "Bounded `log show` query (or imported export/.logarchive) in ndjson form"
    privilege_note = (
        "Reading the unified log needs an admin account for full results; entries marked "
        "<private> stay redacted by macOS and cannot be recovered by this tool."
    )

    def planned(self, ctx: CollectContext) -> list[str]:
        try:
            win, pred = self._options(ctx)
        except UsageError as exc:
            return [f"(log options invalid: {exc})"]
        if ctx.log.import_file:
            return [f"read exported log file {ctx.log.import_file}"]
        base = ["/usr/bin/log", "show", "--style", "ndjson", "--last", win, "--predicate", pred]
        if ctx.log.archive:
            base += ["--archive", str(ctx.log.archive)]
        return [" ".join(base)]

    def _options(self, ctx: CollectContext) -> tuple[str, str]:
        logcfg = ctx.config.collection["logs"]
        window = validate_window(ctx.log.window or logcfg["default_window"], logcfg["max_window"])
        predicate = validate_predicate(
            " ".join(str(ctx.log.predicate or logcfg["default_predicate"]).split())
        )
        return window, predicate

    def run(self, ctx: CollectContext, *, dry_run: bool = False):  # type: ignore[no-untyped-def]
        if ctx.log.import_file and not dry_run:
            # Importing an export is pure parsing and works on any platform.
            result = CollectorResult(
                name=self.name, status="ok", privilege_note=self.privilege_note
            )
            try:
                self._import(ctx, result)
            except (InputError, UsageError) as exc:
                result.status = "failed"
                result.errors.append(str(exc))
            return result
        return super().run(ctx, dry_run=dry_run)

    def collect(self, ctx: CollectContext, result: CollectorResult) -> None:
        window, predicate = self._options(ctx)
        argv = [
            "/usr/bin/log",
            "show",
            "--style",
            "ndjson",
            "--last",
            window,
            "--predicate",
            predicate,
        ]
        if ctx.log.archive:
            archive = Path(ctx.log.archive)
            if archive.suffix != ".logarchive" or not archive.exists():
                raise UsageError(f"{archive} is not an existing .logarchive")
            argv += ["--archive", str(archive)]
        cap = ctx.config.limit("max_log_output_mb") * 1024 * 1024
        res = ctx.run(argv, max_bytes=cap)
        if res.error or res.timed_out:
            result.status = "failed"
            result.errors.append(f"log show failed: {'timed out' if res.timed_out else res.error}")
            return
        if res.returncode != 0:
            result.errors.append(f"log show exited {res.returncode}: {res.stderr.strip()[:200]}")
        if res.truncated:
            result.errors.append(f"log output exceeded {cap // (1024 * 1024)} MB and was truncated")
        self._store(ctx, result, res.stdout)
        result.notes.append(f"window={window}; predicate={predicate}")

    def _import(self, ctx: CollectContext, result: CollectorResult) -> None:
        assert ctx.log.import_file is not None  # nosec B101 - type narrowing; caller guarantees it
        cap = ctx.config.limit("max_log_output_mb") * 1024 * 1024
        text = read_text_bounded(Path(ctx.log.import_file), cap)
        self._store(ctx, result, text)
        result.notes.append(f"imported {ctx.log.import_file.name}; not collected live")

    def _store(self, ctx: CollectContext, result: CollectorResult, text: str) -> None:
        lines_out: list[str] = []
        bad = 0
        max_records = ctx.config.limit("max_records_per_source")
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            if not line.startswith("{"):
                bad += 1
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                bad += 1
                continue
            lines_out.append(
                json.dumps(ctx.redactor.redact_obj(obj), sort_keys=True, separators=(",", ":"))
            )
            if len(lines_out) >= max_records:
                result.errors.append(f"stopped at max_records_per_source={max_records} log records")
                break
        result.raw_files["unified_log.ndjson"] = "\n".join(lines_out)
        result.records = [
            {"_": i} for i in range(len(lines_out))
        ]  # count only; data is in raw_files
        if bad:
            result.errors.append(f"{bad} log lines were not valid ndjson and were skipped")
