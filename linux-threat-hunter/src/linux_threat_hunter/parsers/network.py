"""Parse `ss -H -tunap` output."""

from __future__ import annotations

import re
from typing import Any

USERS_RE = re.compile(r'\("(?P<name>[^"]*)",pid=(?P<pid>\d+)')


def split_addr(value: str) -> tuple[str, int | None]:
    """Split ``addr:port`` forms including ``[::1]:22``, ``*:80`` and ``0.0.0.0%lo:53``."""
    if value.startswith("["):
        host, _, port = value[1:].partition("]:")
    else:
        host, _, port = value.rpartition(":")
    host = host.split("%", 1)[0]
    return host, int(port) if port.isdigit() else None


def parse_ss(text: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line in text.splitlines():
        parts = line.split(None, 6)
        if len(parts) < 6 or parts[0] not in {"tcp", "udp"}:
            continue
        proto, state = parts[0], parts[1]
        laddr, lport = split_addr(parts[4])
        raddr, rport = split_addr(parts[5])
        rest = parts[6] if len(parts) > 6 else ""
        row: dict[str, Any] = {
            "proto": proto,
            "state": state,
            "local_addr": laddr,
            "local_port": lport,
            "remote_addr": None if raddr in {"*", "0.0.0.0", "::", ""} else raddr,
            "remote_port": rport or None,
            "listening": state in {"LISTEN", "UNCONN"} and raddr in {"*", "0.0.0.0", "::", ""},
            "pid": None,
            "process": None,
        }
        um = USERS_RE.search(rest)
        if um:
            row["pid"] = int(um.group("pid"))
            row["process"] = um.group("name")
        rows.append(row)
    return rows
