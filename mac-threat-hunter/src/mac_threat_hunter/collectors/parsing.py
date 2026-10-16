"""Pure parsers for native macOS utility output (unit-tested with synthetic samples)."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any

from ..utils.timeutil import to_iso


def parse_sw_vers(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in text.splitlines():
        if ":" in line:
            key, _, val = line.partition(":")
            out[key.strip()] = val.strip()
    return {
        "product_name": out.get("ProductName", ""),
        "version": out.get("ProductVersion", ""),
        "build": out.get("BuildVersion", ""),
    }


def parse_boottime(text: str) -> str | None:
    m = re.search(r"sec\s*=\s*(\d+)", text)
    if not m:
        return None
    return to_iso(datetime.fromtimestamp(int(m.group(1)), UTC))


def parse_csrutil(text: str) -> str:
    low = text.lower()
    if "enabled" in low and "disabled" not in low:
        return "enabled"
    if "disabled" in low:
        return "disabled"
    return "unknown"


def parse_spctl(text: str) -> str:
    low = text.lower()
    if "assessments enabled" in low:
        return "enabled"
    if "assessments disabled" in low:
        return "disabled"
    return "unknown"


def parse_fdesetup(text: str) -> str:
    low = text.lower()
    if "filevault is on" in low:
        return "on"
    if "filevault is off" in low:
        return "off"
    return "unknown"


def parse_firewall(text: str) -> str:
    low = text.lower()
    if "enabled" in low or "state = 1" in low or "state = 2" in low:
        return "on"
    if "disabled" in low or "state = 0" in low:
        return "off"
    return "unknown"


def parse_who(text: str) -> list[dict[str, str]]:
    sessions = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 2:
            sessions.append({"user": parts[0], "tty": parts[1], "since": " ".join(parts[2:5])})
    return sessions


def parse_ifconfig(text: str) -> list[dict[str, Any]]:
    interfaces: list[dict[str, Any]] = []
    for line in text.splitlines():
        m = re.match(r"^(\S+): flags=\S+<([^>]*)>", line)
        if m:
            interfaces.append({"name": m.group(1), "flags": m.group(2).split(","), "addresses": []})
            continue
        m = re.match(r"^\s+inet6?\s+(\S+)", line)
        if m and interfaces:
            interfaces[-1]["addresses"].append(m.group(1).split("%")[0])
    return interfaces


def parse_netstat_routes(text: str, limit: int = 100) -> list[dict[str, str]]:
    routes = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 4 and (parts[0] == "default" or re.match(r"^[\d.:a-f/]+$", parts[0])):
            routes.append({"destination": parts[0], "gateway": parts[1], "interface": parts[-1]})
        if len(routes) >= limit:
            break
    return routes


_PS_LINE = re.compile(
    r"^\s*(\d+)\s+(\d+)\s+(\d+)\s+(\S+)\s+"
    r"([A-Za-z]{3}\s+[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\d{4})\s+(.*\S)\s*$"
)
_PS_CMD = re.compile(r"^\s*(\d+)\s+(.*\S)\s*$")


def parse_ps_table(text: str) -> list[dict[str, Any]]:
    rows = []
    for line in text.splitlines():
        m = _PS_LINE.match(line)
        if m:
            rows.append(
                {
                    "pid": int(m.group(1)),
                    "ppid": int(m.group(2)),
                    "uid": int(m.group(3)),
                    "user": m.group(4),
                    "lstart": m.group(5),
                    "comm": m.group(6),
                }  # fmt: skip
            )
    return rows


def parse_ps_commands(text: str) -> dict[int, str]:
    out: dict[int, str] = {}
    for line in text.splitlines():
        m = _PS_CMD.match(line)
        if m:
            out[int(m.group(1))] = m.group(2)
    return out


def _split_endpoint(text: str) -> tuple[str | None, int | None]:
    text = text.strip()
    if not text:
        return None, None
    host, sep, port = text.rpartition(":")
    if not sep:
        return text, None
    host = host.strip("[]")
    return (host or None), (int(port) if port.isdigit() else None)


def parse_lsof_fields(text: str) -> list[dict[str, Any]]:
    """Parse ``lsof -F pcLPnT`` output into one record per network file descriptor."""
    records: list[dict[str, Any]] = []
    proc: dict[str, Any] = {}
    current: dict[str, Any] | None = None

    def flush() -> None:
        nonlocal current
        if current and current.get("name"):
            records.append(current)
        current = None

    for line in text.splitlines():
        if not line:
            continue
        tag, val = line[0], line[1:]
        if tag == "p":
            flush()
            proc = {"pid": int(val) if val.isdigit() else None}
        elif tag == "c":
            proc["process_name"] = val
        elif tag == "L":
            proc["user"] = val
        elif tag == "f":
            flush()
            current = dict(proc)
        elif current is not None and tag == "P":
            current["proto"] = val.lower()
        elif current is not None and tag == "n":
            current["name"] = val
        elif current is not None and tag == "T" and val.startswith("ST="):
            current["state"] = val[3:]
    flush()

    out: list[dict[str, Any]] = []
    for rec in records:
        name = rec.pop("name")
        local, _, remote = name.partition("->")
        laddr, lport = _split_endpoint(local)
        raddr, rport = _split_endpoint(remote) if remote else (None, None)
        state = rec.get("state") or ("LISTEN" if not remote else "")
        if rec.get("proto") == "udp" and not remote:
            state = state or "UNCONN"
        out.append(
            {
                **rec,
                "state": state,
                "local_address": laddr,
                "local_port": lport,
                "remote_address": raddr,
                "remote_port": rport,
            }
        )
    return out


def parse_codesign(stderr: str) -> dict[str, str | None]:
    if "not signed at all" in stderr:
        return {"status": "unsigned", "team_id": None, "identifier": None}
    ident = re.search(r"^Identifier=(.+)$", stderr, re.M)
    team = re.search(r"^TeamIdentifier=(.+)$", stderr, re.M)
    if "Signature=adhoc" in stderr:
        status = "adhoc"
    elif "Authority=" in stderr or (team and team.group(1) != "not set") or ident:
        status = "signed"
    else:
        status = "unknown"
    team_id = team.group(1).strip() if team and team.group(1) != "not set" else None
    return {
        "status": status,
        "team_id": team_id,
        "identifier": ident.group(1).strip() if ident else None,
    }
