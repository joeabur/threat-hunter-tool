"""Exact IOC matching. Broader matching (subdomains, text tokens) is explicit and labelled."""

from __future__ import annotations

import ipaddress
import posixpath
import re
from typing import Any

from ..models import Finding, Record, Rule, severity_rank
from ..rules_engine.conditions import MISSING, get_field
from ..rules_engine.evaluator import EvalContext, RuleStats, build_finding
from .loader import Indicator, IocSet

_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_DOMAIN = re.compile(r"(?<![A-Za-z0-9-])(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}(?![A-Za-z0-9-])")
_MAX_TEXT = 4096


def _text_tokens(text: str) -> tuple[set[str], set[str]]:
    text = text[:_MAX_TEXT]
    ips: set[str] = set()
    for m in _IPV4.findall(text):
        try:
            ips.add(str(ipaddress.ip_address(m)))
        except ValueError:
            continue
    domains = {d.lower() for d in _DOMAIN.findall(text)}
    return ips, domains


def _domain_hits(iocs: IocSet, host: str) -> list[tuple[Indicator, str]]:
    hits: list[tuple[Indicator, str]] = []
    domains = iocs.by_type["domain"]
    if host in domains:
        hits.extend((i, "exact") for i in domains[host])
    parts = host.split(".")
    for n in range(1, len(parts) - 1):
        parent = ".".join(parts[n:])
        for ind in domains.get(parent, []):
            if ind.include_subdomains:
                hits.append((ind, "subdomain (include_subdomains=true)"))
    return hits


def _lookup(
    iocs: IocSet, itype: str, value: Any, text_mode: bool
) -> list[tuple[Indicator, str, str]]:
    """Return (indicator, match_mode, matched_value) tuples."""
    if not isinstance(value, str) or not value:
        return []
    table = iocs.by_type[itype]
    out: list[tuple[Indicator, str, str]] = []
    if itype == "sha256":
        out.extend((i, "exact", value.lower()) for i in table.get(value.lower(), []))
    elif itype == "process_name":
        out.extend((i, "exact", value) for i in table.get(value, []))
        low = value.lower()
        out.extend(
            (i, "exact (case-insensitive by indicator)", value)
            for i in table.get(low, [])
            if i.case_insensitive and i.value != value
        )
    elif itype == "path":
        norm = posixpath.normpath(value)
        out.extend((i, "exact", norm) for i in table.get(norm, []))
    elif itype == "ip":
        if text_mode:
            ips, _ = _text_tokens(value)
            for ip in sorted(ips):
                out.extend((i, "exact token in text", ip) for i in table.get(ip, []))
        else:
            try:
                norm_ip = str(ipaddress.ip_address(value.strip("[]")))
            except ValueError:
                return []
            out.extend((i, "exact", norm_ip) for i in table.get(norm_ip, []))
    elif itype == "domain":
        if text_mode:
            _, doms = _text_tokens(value)
            for d in sorted(doms):
                out.extend((i, f"{mode} token in text", d) for i, mode in _domain_hits(iocs, d))
        else:
            host = value.lower().rstrip(".")
            out.extend((i, mode, host) for i, mode in _domain_hits(iocs, host))
    return out


def match_ioc_rule(
    rule: Rule, records_by_source: dict[str, list[Record]], iocs: IocSet, ctx: EvalContext
) -> tuple[list[Finding], RuleStats]:
    stats = RuleStats(rule.id)
    findings: list[Finding] = []
    cap = ctx.config.limit("max_findings_per_rule")
    assert rule.ioc is not None  # nosec B101 - type narrowing
    for source in rule.sources:
        for rec in records_by_source.get(source, []):
            stats.records_examined += 1
            hits: dict[tuple[str, str], dict[str, Any]] = {}
            for spec in rule.ioc["matches"]:
                for fld in spec["fields"]:
                    value = get_field(rec.data, fld)
                    if value is MISSING:
                        continue
                    for ind, mode, matched_value in _lookup(
                        iocs, spec["type"], value, bool(spec.get("text"))
                    ):
                        key = (ind.type, ind.value)
                        if key in hits:
                            continue
                        detail = ind.describe()
                        detail.update(
                            matched_field=fld, matched_value=matched_value, match_mode=mode
                        )
                        hits[key] = detail
            if not hits:
                continue
            stats.matched += 1
            if len(findings) >= cap:
                stats.capped = True
                continue
            details = [hits[k] for k in sorted(hits)]
            best = max(details, key=lambda d: severity_rank(d["severity"] or rule.severity))
            primary = dict(best)
            primary["all_matches"] = details
            primary["note"] = "An IOC match is an indicator hit, not confirmation of compromise."
            first = details[0]["value"]
            label = (first if len(first) <= 40 else first[:37] + "...") + (
                f" (+{len(details) - 1} more)" if len(details) > 1 else ""
            )
            findings.append(
                build_finding(
                    rule, rec, ctx, group="|".join(f"{t}:{v}" for t, v in sorted(hits)),
                    ioc=primary, severity=best["severity"] or rule.severity,
                    extra_evidence={"matched_indicators": [d["value"] for d in details]},
                    title_data={**rec.data, "indicator": label},
                )
            )  # fmt: skip
    stats.findings = len(findings)
    return findings, stats
