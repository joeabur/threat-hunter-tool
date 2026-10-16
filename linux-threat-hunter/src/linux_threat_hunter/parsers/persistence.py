"""Normalize persistence artifacts (systemd units, cron files) into structured fields."""

from __future__ import annotations

import posixpath
import re
from typing import Any

EXEC_KEYS = ("ExecStart", "ExecStartPre", "ExecStartPost", "ExecStop", "ExecReload")
FILE_LEVEL_KINDS = {
    "systemd_service",
    "systemd_timer",
    "systemd_dropin",
    "cron_file",
    "cron_script",
    "shell_startup",
    "ssh_config",
    "ssh_authorized_keys",
    "ld_preload",
    "rc_script",
    "kernel_module",
}
ENV_ASSIGN_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
CRON_SCHEDULE_RE = re.compile(r"^(@\w+|(\S+\s+){4}\S+)\s+")


def parse_unit(content: str) -> dict[str, dict[str, list[str]]]:
    """Parse INI-like systemd unit text into {section: {key: [values]}} (no execution)."""
    sections: dict[str, dict[str, list[str]]] = {}
    current: dict[str, list[str]] | None = None
    pending = ""
    for raw in content.splitlines():
        line = (pending + raw).strip()
        pending = ""
        if raw.rstrip().endswith("\\"):
            pending = raw.rstrip()[:-1] + " "
            continue
        if not line or line[0] in "#;":
            continue
        if line.startswith("[") and line.endswith("]"):
            current = sections.setdefault(line[1:-1], {})
            continue
        if current is not None and "=" in line:
            key, _, val = line.partition("=")
            current.setdefault(key.strip(), []).append(val.strip())
    return sections


def _first(section: dict[str, list[str]], key: str) -> str | None:
    vals = section.get(key)
    return vals[0] if vals else None


def exec_path_of(command: str) -> str | None:
    """First token of a command line, after systemd prefixes / env assignments / env(1)."""
    cmd = command.strip().lstrip("@-:+!").strip()
    tokens = cmd.split()
    while tokens and ENV_ASSIGN_RE.match(tokens[0]):
        tokens.pop(0)
    if tokens and posixpath.basename(tokens[0]) == "env":
        tokens.pop(0)
        while tokens and (tokens[0].startswith("-") or ENV_ASSIGN_RE.match(tokens[0])):
            tokens.pop(0)
    if not tokens:
        return None
    first = tokens[0].strip("'\"")
    return first if first.startswith("/") else None


def parse_cron(content: str, *, has_user_field: bool) -> list[dict[str, Any]]:
    jobs: list[dict[str, Any]] = []
    for no, raw in enumerate(content.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#") or ENV_ASSIGN_RE.match(line):
            continue
        m = CRON_SCHEDULE_RE.match(line)
        if not m:
            continue
        schedule = m.group(1).strip()
        rest = line[m.end() :].strip()
        user = None
        if has_user_field:
            user, _, rest = rest.partition(" ")
            rest = rest.strip()
        if rest:
            jobs.append(
                {
                    "line_no": no,
                    "schedule": schedule,
                    "cron_user": user,
                    "command": rest,
                    "exec_path": exec_path_of(rest),
                }
            )
    return jobs


def normalize_artifact(raw: dict[str, Any]) -> list[dict[str, Any]]:
    """Return the file-level record (enriched) plus derived records (cron jobs)."""
    kind = raw.get("kind", "")
    content = raw.get("content") or ""
    exists_map = raw.get("referenced_paths_exist") or {}
    base = dict(raw)
    out: list[dict[str, Any]] = []

    def exists(path: str | None) -> bool | None:
        if path is None:
            return None
        val = exists_map.get(path)
        return val if isinstance(val, bool) else None

    if kind in {"systemd_service", "systemd_dropin"}:
        sections = parse_unit(content)
        service = sections.get("Service", {})
        commands = [v for k in EXEC_KEYS for v in service.get(k, [])]
        main = _first(service, "ExecStart")
        base["fields"] = {k: v for sect in sections.values() for k, v in sect.items()}
        base["commands"] = commands
        base["commands_text"] = "\n".join(commands)
        base["exec_path"] = exec_path_of(main) if main else None
        base["exec_exists"] = exists(base["exec_path"])
        base["user_directive"] = _first(service, "User")
    elif kind == "systemd_timer":
        sections = parse_unit(content)
        timer = sections.get("Timer", {})
        base["fields"] = {k: v for sect in sections.values() for k, v in sect.items()}
        base["commands"] = []
        base["commands_text"] = ""
        base["activates"] = _first(timer, "Unit")
        base["exec_path"] = None
        base["exec_exists"] = None
    elif kind == "cron_file":
        jobs = parse_cron(content, has_user_field=bool(raw.get("has_user_field")))
        base["commands"] = [j["command"] for j in jobs]
        base["commands_text"] = "\n".join(base["commands"])
        base["job_count"] = len(jobs)
        for j in jobs:
            out.append(
                {
                    "kind": "cron_job",
                    "path": raw.get("path"),
                    "owner": raw.get("owner"),
                    "line_no": j["line_no"],
                    "schedule": j["schedule"],
                    "cron_user": j["cron_user"],
                    "command": j["command"],
                    "commands_text": j["command"],
                    "exec_path": j["exec_path"],
                    "exec_exists": exists(j["exec_path"]),
                    "parent_sha256": raw.get("sha256"),
                }
            )
    elif kind in {"shell_startup", "rc_script", "cron_script"}:
        lines = [ln for ln in content.splitlines() if ln.strip() and not ln.strip().startswith("#")]
        base["commands"] = lines
        base["commands_text"] = "\n".join(lines)
        base["exec_path"] = None
        base["exec_exists"] = None
    else:
        base.setdefault("commands_text", "")
    out.insert(0, base)
    return out
