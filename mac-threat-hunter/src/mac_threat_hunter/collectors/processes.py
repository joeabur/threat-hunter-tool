from __future__ import annotations

from datetime import timedelta, timezone

from ..models import CollectorResult
from ..utils.timeutil import parse_timestamp, to_iso
from . import parsing
from .base import CollectContext, Collector
from .codesign import FileEnricher

_PS_TABLE = ["/bin/ps", "-axww", "-o", "pid=,ppid=,uid=,user=,lstart=,comm="]
_PS_CMD = ["/bin/ps", "-axww", "-o", "pid=,command="]


class ProcessCollector(Collector):
    name = "processes"
    description = (
        "Running processes: pid, ppid, owner, path, start time, command line, hash, signature"
    )
    privilege_note = "Unprivileged ps lists all processes, but executable hashing may skip files you cannot read."

    def planned(self, ctx: CollectContext) -> list[str]:
        return [
            " ".join(_PS_TABLE),
            " ".join(_PS_CMD),
            "codesign -dv --verbose=2 <non-system executable>",
        ]

    def collect(self, ctx: CollectContext, result: CollectorResult) -> None:
        table = ctx.run(_PS_TABLE, max_bytes=16 * 1024 * 1024)
        if not table.ok:
            result.status = "failed"
            result.errors.append(
                f"ps failed: {'timed out' if table.timed_out else table.error or table.returncode}"
            )
            return
        if table.truncated:
            result.errors.append("ps output exceeded the size limit and was truncated")
        include_cmd = bool(ctx.config.collection.get("include_cmdline", True))
        cmds: dict[int, str] = {}
        if include_cmd:
            cmd_res = ctx.run(_PS_CMD, max_bytes=16 * 1024 * 1024)
            if cmd_res.ok:
                cmds = parsing.parse_ps_commands(cmd_res.stdout)
            else:
                result.errors.append("command lines unavailable (second ps call failed)")
        else:
            result.notes.append(
                "command lines omitted by configuration (collection.include_cmdline=false)"
            )
        local_off = timezone(timedelta(seconds=-__import__("time").timezone))
        enrich = FileEnricher(ctx)
        max_records = ctx.config.limit("max_records_per_source")
        for row in parsing.parse_ps_table(table.stdout)[:max_records]:
            comm = row["comm"]
            path = comm if comm.startswith("/") else None
            start = parse_timestamp(row["lstart"], assume_offset=local_off)
            record = {
                "pid": row["pid"], "ppid": row["ppid"], "uid": row["uid"], "user": row["user"],
                "name": comm.rsplit("/", 1)[-1], "path": path,
                "start_time": to_iso(start.utc), "start_time_original": row["lstart"],
            }  # fmt: skip
            if include_cmd and row["pid"] in cmds:
                record["cmdline"] = ctx.redactor.redact(cmds[row["pid"]])
            if path:
                digest = enrich.sha256(path)
                if digest:
                    record["sha256"] = digest
                sign = enrich.codesign(path)
                if sign:
                    record["codesign"] = sign
            result.records.append(record)
        result.notes.extend(enrich.notes)
        result.notes.append(
            "Executable hashes/signatures skip sealed system locations; processes may exit between "
            "the two ps calls, so command lines are best-effort."
        )
