"""IOC file parsing. Indicators are normalised so matching can be exact."""

from __future__ import annotations

import ipaddress
import json
import posixpath
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from ..models import SEVERITIES
from ..utils.errors import InputError, ValidationError
from ..utils.paths import read_text_bounded

IOC_TYPES = ("sha256", "process_name", "path", "ip", "domain")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
_MAX_FILE_BYTES = 32 * 1024 * 1024


@dataclass(frozen=True)
class Indicator:
    type: str
    value: str  # normalised value
    original: str
    description: str = ""
    severity: str | None = None
    source: str = ""
    references: tuple[str, ...] = ()
    case_insensitive: bool = False
    include_subdomains: bool = False

    def describe(self) -> dict[str, Any]:
        return {
            "type": self.type,
            "value": self.value,
            "description": self.description,
            "severity": self.severity,
            "source": self.source,
            "references": list(self.references),
        }


@dataclass
class IocSet:
    indicators: list[Indicator] = field(default_factory=list)
    name: str = ""
    synthetic: bool = False
    by_type: dict[str, dict[str, list[Indicator]]] = field(default_factory=dict)

    def index(self) -> None:
        self.by_type = {t: {} for t in IOC_TYPES}
        for ind in self.indicators:
            key = ind.value.lower() if ind.case_insensitive else ind.value
            self.by_type[ind.type].setdefault(key, []).append(ind)

    def count(self) -> int:
        return len(self.indicators)

    def counts_by_type(self) -> dict[str, int]:
        out = dict.fromkeys(IOC_TYPES, 0)
        for ind in self.indicators:
            out[ind.type] += 1
        return out


def normalize_value(ioc_type: str, value: str) -> str:
    """Normalise one indicator value or raise ValueError describing the problem."""
    value = value.strip()
    if not value or "\x00" in value or "*" in value or "?" in value:
        raise ValueError("empty value or wildcard characters (wildcards are not supported)")
    if ioc_type == "sha256":
        value = value.lower()
        if not _SHA256.match(value):
            raise ValueError("sha256 must be 64 hexadecimal characters")
        return value
    if ioc_type == "ip":
        try:
            return str(ipaddress.ip_address(value.strip("[]")))
        except ValueError as exc:
            raise ValueError("not a valid IPv4/IPv6 address") from exc
    if ioc_type == "domain":
        value = value.lower().rstrip(".")
        if len(value) > 253 or "." not in value:
            raise ValueError("domain must be a fully qualified name such as bad.example.test")
        if not all(_LABEL.match(label) for label in value.split(".")):
            raise ValueError("domain contains an invalid label")
        try:
            ipaddress.ip_address(value)
        except ValueError:
            return value
        raise ValueError("an IP address was given as a domain")
    if ioc_type == "path":
        if not value.startswith("/"):
            raise ValueError("path indicators must be absolute macOS paths")
        if ".." in value.split("/"):
            raise ValueError("path indicators must not contain '..'")
        return posixpath.normpath(value)
    if ioc_type == "process_name":
        if "/" in value:
            raise ValueError("process_name must be a bare name; use type 'path' for paths")
        return value
    raise ValueError(f"unknown indicator type {ioc_type!r}")


def parse_iocs(raw: Any, *, max_indicators: int) -> IocSet:
    problems: list[str] = []
    if not isinstance(raw, dict):
        raise ValidationError("IOC file must be a mapping", ["top level must be an object"])
    for key in raw:
        if key not in {"schema_version", "name", "synthetic", "description", "indicators"}:
            problems.append(f"unknown top-level key: {key}")
    if raw.get("schema_version", 1) != 1:
        problems.append("schema_version must be 1")
    items = raw.get("indicators")
    if not isinstance(items, list):
        raise ValidationError("IOC file has no 'indicators' list", ["'indicators' must be a list"])
    if len(items) > max_indicators:
        raise ValidationError(f"too many indicators ({len(items)} > {max_indicators})")
    result = IocSet(name=str(raw.get("name", "")), synthetic=bool(raw.get("synthetic", False)))
    seen: set[tuple[str, str]] = set()
    for i, item in enumerate(items):
        loc = f"indicators[{i}]"
        if not isinstance(item, dict):
            problems.append(f"{loc}: must be a mapping")
            continue
        extra = set(item) - {
            "type", "value", "description", "severity", "source", "references",
            "case_insensitive", "include_subdomains",
        }  # fmt: skip
        if extra:
            problems.append(f"{loc}: unknown keys {sorted(extra)}")
        itype, value = item.get("type"), item.get("value")
        if itype not in IOC_TYPES or not isinstance(value, str):
            problems.append(f"{loc}: needs type in {IOC_TYPES} and a string value")
            continue
        try:
            norm = normalize_value(itype, value)
        except ValueError as exc:
            problems.append(f"{loc} ({itype}): {exc}")
            continue
        sev = item.get("severity")
        if sev is not None and sev not in SEVERITIES:
            problems.append(f"{loc}: severity must be one of {SEVERITIES}")
            continue
        refs = item.get("references", [])
        if not isinstance(refs, list) or not all(isinstance(r, str) for r in refs):
            problems.append(f"{loc}: references must be a list of strings")
            continue
        ci = bool(item.get("case_insensitive", False))
        sub = bool(item.get("include_subdomains", False))
        if ci and itype != "process_name":
            problems.append(f"{loc}: case_insensitive only applies to process_name")
            continue
        if sub and itype != "domain":
            problems.append(f"{loc}: include_subdomains only applies to domain")
            continue
        dedupe = (itype, norm.lower() if ci else norm)
        if dedupe in seen:
            continue
        seen.add(dedupe)
        result.indicators.append(
            Indicator(
                type=itype,
                value=norm,
                original=value,
                description=str(item.get("description", "")),
                severity=sev,
                source=str(item.get("source", "")),
                references=tuple(refs),
                case_insensitive=ci,
                include_subdomains=sub,
            )
        )
    if problems:
        raise ValidationError(f"{len(problems)} problem(s) in IOC file", problems)
    result.index()
    return result


def load_iocs(path: Path, *, max_indicators: int = 100_000) -> IocSet:
    text = read_text_bounded(path, _MAX_FILE_BYTES)
    try:
        raw = json.loads(text) if path.suffix.lower() == ".json" else yaml.safe_load(text)
    except (json.JSONDecodeError, yaml.YAMLError) as exc:
        raise InputError(f"{path}: cannot parse IOC file: {exc}") from exc
    return parse_iocs(raw, max_indicators=max_indicators)
