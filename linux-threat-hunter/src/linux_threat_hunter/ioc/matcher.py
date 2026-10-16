"""Local IOC files: validation, normalization and exact matching.

Matching is exact by default. Domain suffix matching exists only if the IOC file sets
``options.match_subdomains: true`` explicitly.
"""

from __future__ import annotations

import ipaddress
import json
import posixpath
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from linux_threat_hunter.models import SEVERITIES
from linux_threat_hunter.utils.safe import UnsafePathError, read_regular_file

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$")
TOKEN_RE = re.compile(r"[A-Za-z0-9._:/@\-\[\]]+")
KEYS = {
    "sha256": "sha256",
    "process_names": "process_name",
    "file_paths": "file_path",
    "ips": "ip",
    "domains": "domain",
}


class IocError(ValueError):
    pass


@dataclass
class IocEntry:
    type: str
    value: str
    description: str = ""
    severity: str | None = None
    references: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.type,
            "value": self.value,
            "description": self.description,
            "severity": self.severity,
            "references": self.references,
        }


def normalize(kind: str, value: str) -> str:
    v = value.strip()
    if kind == "sha256":
        v = v.lower()
        if not SHA256_RE.match(v):
            raise IocError(f"invalid SHA-256: {value!r}")
    elif kind == "ip":
        try:
            v = str(ipaddress.ip_address(v))
        except ValueError as exc:
            raise IocError(f"invalid IP address: {value!r}") from exc
    elif kind == "domain":
        v = v.lower().rstrip(".")
        if not DOMAIN_RE.match(v):
            raise IocError(f"invalid domain: {value!r} (ASCII/punycode names only)")
    elif kind == "file_path":
        if not v.startswith("/") or "\x00" in v:
            raise IocError(f"file path must be absolute: {value!r}")
        v = posixpath.normpath(v)
    elif kind == "process_name":
        if not v or "/" in v or "\x00" in v or len(v) > 255:
            raise IocError(f"process name must be a bare name without '/': {value!r}")
    return v


@dataclass
class IocSet:
    entries: dict[str, dict[str, IocEntry]] = field(default_factory=lambda: {k: {} for k in KEYS.values()})
    match_subdomains: bool = False
    path: str = ""

    @property
    def counts(self) -> dict[str, int]:
        return {k: len(v) for k, v in self.entries.items()}

    def _hit(self, kind: str, value: Any) -> IocEntry | None:
        if not isinstance(value, str) or not value:
            return None
        try:
            norm = normalize(kind, value) if kind != "process_name" else value
        except IocError:
            return None
        hit = self.entries[kind].get(norm)
        if hit is None and kind == "domain" and self.match_subdomains:
            parts = norm.split(".")
            for i in range(1, len(parts) - 1):
                hit = self.entries[kind].get(".".join(parts[i:]))
                if hit:
                    break
        return hit

    def match_record(self, source: str, data: dict[str, Any]) -> list[dict[str, Any]]:
        """Return IOC matches for one record: [{indicator, field, observed, ...}]."""
        candidates: list[tuple[str, str, Any]] = []  # (ioc type, field, observed value)

        def add(kind: str, fld: str, val: Any) -> None:
            if val:
                candidates.append((kind, fld, val))

        if source == "process":
            add("sha256", "sha256", data.get("sha256"))
            add("process_name", "name", data.get("name"))
            add("file_path", "exe", data.get("exe"))
        elif source == "persistence":
            add("sha256", "sha256", data.get("sha256"))
            add("file_path", "path", data.get("path"))
            add("file_path", "exec_path", data.get("exec_path"))
            add("sha256", "exec_sha256", data.get("exec_sha256"))
            ep = data.get("exec_path")
            if ep:
                add("process_name", "exec_path", posixpath.basename(ep))
            # cron_file records are matched by hash/path only; their jobs are matched individually
            text = (
                ""
                if data.get("kind") == "cron_file"
                else "\n".join(str(data.get(k) or "") for k in ("commands_text", "content"))
            )
            for tok in set(TOKEN_RE.findall(text)):
                for t in {tok, tok.strip(".:/"), tok.split("://")[-1].split("/")[0].split(":")[0]}:
                    add("ip", "commands", t)
                    add("domain", "commands", t)
                if tok.startswith("/"):
                    add("file_path", "commands", tok)
        elif source == "network":
            add("ip", "remote_addr", data.get("remote_addr"))
            add("domain", "remote_host", data.get("remote_host"))
            add("process_name", "process", data.get("process"))
            add("file_path", "process_exe", data.get("process_exe"))
            add("sha256", "process_sha256", data.get("process_sha256"))
        elif source == "auth":
            add("ip", "src_ip", data.get("src_ip"))
        elif source == "file":
            add("sha256", "sha256", data.get("sha256"))
            add("file_path", "path", data.get("path"))
        elif source == "event":
            add("ip", "src_ip", data.get("src_ip"))
            add("sha256", "sha256", data.get("sha256"))
        matches: list[dict[str, Any]] = []
        seen: set[tuple[str, str, str]] = set()
        for kind, fld, val in candidates:
            entry = self._hit(kind, val)
            if entry is None:
                continue
            key = (kind, entry.value, fld)
            if key in seen:
                continue
            seen.add(key)
            matches.append(
                {
                    "indicator_type": kind,
                    "indicator": entry.value,
                    "matched_field": fld,
                    "observed_value": str(val),
                    "description": entry.description,
                    "severity": entry.severity,
                    "references": entry.references,
                    "match_mode": "exact" if str(val) == entry.value else "normalized/subdomain",
                }
            )
        return matches


def load_iocs(path: str | Path, limits: dict[str, int]) -> IocSet:
    p = Path(path)
    try:
        raw = read_regular_file(p, limits["max_rule_file_bytes"]).decode("utf-8")
        data = json.loads(raw) if p.suffix == ".json" else yaml.safe_load(raw)
    except (OSError, UnsafePathError, ValueError, yaml.YAMLError) as exc:
        raise IocError(f"cannot read IOC file {p}: {exc}") from exc
    if not isinstance(data, dict) or data.get("schema_version") != 1:
        raise IocError("IOC file must be a mapping with schema_version: 1")
    unknown = set(data) - {"schema_version", "description", "options", "indicators"}
    if unknown:
        raise IocError(f"unknown top-level keys: {sorted(unknown)}")
    options = data.get("options") or {}
    if not isinstance(options, dict) or set(options) - {"match_subdomains"}:
        raise IocError("options: only 'match_subdomains' is supported")
    ind = data.get("indicators")
    if not isinstance(ind, dict):
        raise IocError("indicators: required mapping")
    unknown = set(ind) - set(KEYS)
    if unknown:
        raise IocError(f"indicators: unknown keys {sorted(unknown)} (allowed: {sorted(KEYS)})")
    out = IocSet(match_subdomains=bool(options.get("match_subdomains", False)), path=str(p))
    total = 0
    for key, kind in KEYS.items():
        items = ind.get(key, [])
        if not isinstance(items, list):
            raise IocError(f"indicators.{key}: must be a list")
        for item in items:
            total += 1
            if total > limits["max_list_values"] * 10:
                raise IocError("too many indicators")
            meta = item if isinstance(item, dict) else {"value": item}
            if not isinstance(meta.get("value"), str):
                raise IocError(f"indicators.{key}: each entry needs a string 'value'")
            sev = meta.get("severity")
            if sev is not None and sev not in SEVERITIES:
                raise IocError(f"indicators.{key}: severity must be one of {list(SEVERITIES)}")
            refs = meta.get("references", [])
            if not isinstance(refs, list) or not all(isinstance(r, str) for r in refs):
                raise IocError(f"indicators.{key}: references must be a list of strings")
            value = normalize(kind, meta["value"])
            out.entries[kind][value] = IocEntry(kind, value, str(meta.get("description", "")), sev, refs)
    return out
