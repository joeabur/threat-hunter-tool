"""Write JSON, CSV and Markdown reports (redacted, with CSV/Markdown injection hardening)."""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path
from typing import Any

from linux_threat_hunter.models import SEVERITIES
from linux_threat_hunter.utils.redact import Redactor
from linux_threat_hunter.utils.safe import (
    UnsafePathError,
    atomic_write_text,
    read_regular_file,
    validate_output_dir,
)

CLASS_LABEL = {
    "observation": "Observation (a recorded fact; its significance needs analyst validation)",
    "heuristic": "Heuristic detection (needs analyst validation)",
    "ioc_match": "IOC match (an indicator matched; not proof of compromise)",
    "correlation": "Correlation of findings (needs analyst validation)",
}
FORMULA_CHARS = ("=", "+", "-", "@", "\t", "\r")


def load_results(directory: str | Path) -> dict[str, Any]:
    path = Path(directory) / "results.json"
    try:
        data = json.loads(read_regular_file(path, 256 * 1024 * 1024))
    except (OSError, UnsafePathError, ValueError) as exc:
        raise ValueError(f"cannot read {path}: {exc}") from exc
    if not isinstance(data, dict) or data.get("tool", {}).get("name") != "linux-threat-hunter":
        raise ValueError(f"{path} is not a linux-threat-hunter results file")
    if data.get("schema_version") != 1:
        raise ValueError(f"unsupported results schema_version: {data.get('schema_version')}")
    return data


def md(text: Any) -> str:
    """Escape text for inline Markdown / table use."""
    s = str(text).replace("\r", " ").replace("\n", " ")
    for ch in ("\\", "`", "|", "<", ">", "*", "_", "[", "]"):
        s = s.replace(ch, "\\" + ch)
    return s


def _fence(obj: Any) -> str:
    body = json.dumps(obj, indent=2, sort_keys=True, default=str).replace("```", "'''")
    return "```json\n" + body + "\n```"


def csv_cell(value: Any) -> str:
    s = "; ".join(map(str, value)) if isinstance(value, list) else str(value if value is not None else "")
    s = s.replace("\r", " ").replace("\n", " ")
    return "'" + s if s.startswith(FORMULA_CHARS) else s


def render_csv(findings: list[dict[str, Any]]) -> str:
    cols = [
        "finding_id",
        "rule_id",
        "rule_version",
        "title",
        "severity",
        "confidence",
        "classification",
        "observed_at",
        "timestamp_basis",
        "timezone_context",
        "evidence_source",
        "artifact",
        "ioc_indicators",
        "attack_techniques",
        "explanation",
        "rationale",
        "false_positives",
        "investigation_steps",
    ]
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(cols)
    for f in findings:
        w.writerow(
            [
                csv_cell(x)
                for x in (
                    f["id"],
                    f["rule_id"],
                    f["rule_version"],
                    f["title"],
                    f["severity"],
                    f["confidence"],
                    f["classification"],
                    f["observed_at"],
                    f["timestamp_basis"],
                    f["timezone_context"],
                    f["evidence_source"],
                    f["artifact"],
                    [m["indicator"] for m in f["ioc_matches"]],
                    [m["technique"] for m in f["attack"]],
                    f["explanation"],
                    f["rationale"],
                    f["false_positives"],
                    f["investigation_steps"],
                )
            ]
        )
    return buf.getvalue()


def render_summary(r: dict[str, Any]) -> str:
    s, ev = r["summary"], r["evidence"]
    L: list[str] = ["# Linux Threat Hunter: Executive Summary", ""]
    L += [
        "> **Read this first.** Findings are leads for an analyst to validate. They are not confirmed "
        "compromise, and skipped rules or missing telemetry are not evidence that a host is clean.",
        "",
    ]
    if ev.get("synthetic"):
        L += [
            "> **Synthetic data.** This evidence set is simulated for training; it is not from a real host.",
            "",
        ]
    host = r["host"]
    L += [
        "## Collection scope",
        "",
        f"- Host: `{md(host.get('hostname'))}`" if host.get("hostname") else "- Host: unknown",
        f"- Evidence: `{md(ev['path'])}` (collected {md(ev['collected_at'])}, timezone {md(ev['timezone'])}, "
        f"profile {md(ev.get('profile'))})",
        f"- Data sources analyzed: {', '.join(r['scope']['sources_analyzed']) or 'none'}",
        f"- Records/artifacts processed: {r['scope']['total_records']} "
        f"({', '.join(f'{k}: {v}' for k, v in sorted(r['scope']['records_by_source'].items()))})",
        f"- Report generated: {r['generated_at']} by linux-threat-hunter {r['tool']['version']}",
        "",
    ]
    L += ["## Findings by severity", "", "| Severity | Count |", "|---|---|"]
    L += [f"| {k} | {s['by_severity'].get(k, 0)} |" for k in reversed(SEVERITIES)]
    L += ["", f"Total findings: **{s['total_findings']}**", ""]
    L += ["## Findings by kind", "", "| Kind | Count | Meaning |", "|---|---|---|"]
    for k, label in CLASS_LABEL.items():
        L.append(f"| {k} | {s['by_classification'].get(k, 0)} | {md(label)} |")
    L.append("")
    top = [f for f in r["findings"] if f["severity"] in {"critical", "high"}][:10]
    if top:
        L += ["## Highest-severity findings", ""]
        L += [
            f"- **{f['severity']}** / confidence {f['confidence']}: {md(f['title'])} (`{f['id']}`, {f['rule_id']})"
            for f in top
        ]
        L.append("")
    L += ["## IOC matches", ""]
    ioc = r["iocs"]
    L.append(
        f"IOC file: `{md(ioc['file'])}`; indicators loaded: {', '.join(f'{k}={v}' for k, v in sorted(ioc['counts'].items()))}; matches: **{ioc['matches']}**"
        if ioc["file"]
        else "No IOC file was supplied; IOC rules were skipped."
    )
    L += ["", "## Correlations", ""]
    corr = [f for f in r["findings"] if f["classification"] == "correlation"]
    L += [f"- {md(f['title'])} (`{f['id']}` links {', '.join(f['related_findings'])})" for f in corr] or [
        "No correlations were produced."
    ]
    L += ["", "## Baseline changes", ""]
    b = r["baseline"]
    if b["path"]:
        c = b["change_counts"] or {}
        L.append(
            f"Baseline `{md(b['path'])}`: added {c.get('added', 0)}, removed {c.get('removed', 0)}, "
            f"modified {c.get('modified', 0)}. Compared: {', '.join(b['categories_compared']) or 'none'}."
        )
        for ch in r["baseline_changes"][:30]:
            L.append(
                f"- {ch['change']} `{md(ch['category'])}`: `{md(ch['key'])}`"
                + (f" (changed: {', '.join(ch['changed_fields'])})" if ch["changed_fields"] else "")
            )
    else:
        L.append("No baseline supplied; baseline rules were skipped.")
    L += ["", "## Missing telemetry and collection problems", ""]
    L += [f"- **{md(m['kind'])}** `{md(m['source'])}`: {md(m['detail'])}" for m in r["missing_telemetry"]] or [
        "None recorded."
    ]
    L += [
        "",
        "## Rules executed and skipped",
        "",
        f"Executed: {s['rules_executed']}; skipped: {s['rules_skipped']}.",
        "",
        "| Rule | Status | Findings | Suppressed | Note |",
        "|---|---|---|---|---|",
    ]
    for ru in r["rules"]:
        note = ru["reason"] or "; ".join(ru["notes"])
        L.append(
            f"| {ru['rule_id']} v{ru['version']} | {ru['status']} | {ru['findings']} | {ru['suppressed']} | {md(note)} |"
        )
    L += [
        "",
        "## ATT&CK techniques related to findings",
        "",
        "Mappings relate a rule's behavior to a technique. They do not prove the technique was used, and "
        "techniques not listed are not thereby absent.",
        "",
    ]
    L += [
        f"- [{t['technique']} {md(t['title'])}]({t['url']}) ({', '.join(t['tactics'])}): "
        f"{len(t['finding_ids'])} finding(s)"
        for t in s["attack_techniques_observed"]
    ] or ["No findings carried an ATT&CK mapping."]
    L += ["", "## Known limitations", ""] + [f"- {md(x)}" for x in r["limitations"]]
    return "\n".join(L) + "\n"


def render_findings(r: dict[str, Any]) -> str:
    L = [
        "# Linux Threat Hunter: Detailed Findings",
        "",
        "Every finding lists its rule, evidence source and artifact so it can be traced back to the "
        "collected evidence. Severity (impact if real) and confidence (likelihood the rule's "
        "condition is meaningful) are independent.",
        "",
    ]
    if not r["findings"]:
        L.append(
            "No findings. This does not mean the host is clean: see skipped rules and missing telemetry in the summary."
        )
    for f in r["findings"]:
        L += [
            f"## {md(f['title'])}",
            "",
            f"- **Finding ID:** `{f['id']}`",
            f"- **Rule:** `{f['rule_id']}` v{f['rule_version']} ({md(f['rule_name'])})",
            f"- **Severity:** {f['severity']}  |  **Confidence:** {f['confidence']}",
            f"- **Kind:** {md(CLASS_LABEL.get(f['classification'], f['classification']))}",
            f"- **Observed:** {f['observed_at']} ({md(f['timezone_context'])}; time basis: {f['timestamp_basis']})",
            f"- **Evidence source:** `{md(f['evidence_source'])}`; artifact: `{md(f['artifact'])}`",
            "",
            "**What was observed**",
            "",
            md(f["explanation"]),
            "",
            "**Why this rule fires (detection rationale)**",
            "",
            md(f["rationale"]),
            "",
        ]
        if f["ioc_matches"]:
            L += ["**IOC match details**", ""]
            L += [
                f"- {m['indicator_type']} `{md(m['indicator'])}` matched field `{m['matched_field']}` "
                f"(observed `{md(m['observed_value'])}`, {m['match_mode']}). "
                f"{md(m['description'])}"
                for m in f["ioc_matches"]
            ]
            L += ["", "An IOC match is not automatically a confirmed compromise.", ""]
        if f["attack"]:
            L += ["**ATT&CK mapping** (related technique, not proof of use)", ""]
            L += [f"- [{a['technique']} {md(a['title'])}]({a['url']}) ({a['tactic']})" for a in f["attack"]]
            L.append("")
        L += [
            "**Evidence**",
            "",
            _fence(f["evidence"]),
            "",
            "**False-positive considerations**",
            "",
        ] + [f"- {md(x)}" for x in f["false_positives"]]
        L += ["", "**Recommended investigative steps**", ""] + [
            f"{i}. {md(x)}" for i, x in enumerate(f["investigation_steps"], 1)
        ]
        if f["missing_context"]:
            L += ["", "**Missing context / limitations**", ""] + [f"- {md(x)}" for x in f["missing_context"]]
        if f["related_findings"]:
            L += ["", "Related findings: " + ", ".join(f"`{x}`" for x in f["related_findings"])]
        L.append("")
    return "\n".join(L) + "\n"


def render_attack(r: dict[str, Any]) -> str:
    L = [
        "# ATT&CK Coverage Summary",
        "",
        "**Detection vs. technique:** a detection rule looks for specific evidence; an ATT&CK technique is a "
        "general adversary behavior. A mapping says the rule's behavior is *related* to the technique. It does "
        "not prove the technique was used, and unmapped or unlisted techniques are not implied to be absent. "
        "This tool covers only a small part of ATT&CK for Linux.",
        "",
        "## Techniques related to findings in this run",
        "",
    ]
    obs = r["summary"]["attack_techniques_observed"]
    L += [f"- [{t['technique']} {md(t['title'])}]({t['url']}): {len(t['finding_ids'])} finding(s)" for t in obs] or [
        "None."
    ]
    L += ["", "## Techniques referenced by the loaded rules", ""]
    rules_with = {ru["rule_id"]: ru for ru in r["rules"]}
    L.append(f"{len(rules_with)} rules were loaded; see docs/detection-coverage.md for the per-rule table.")
    return "\n".join(L) + "\n"


def write_reports(results: dict[str, Any], out_dir: str | Path, redactor: Redactor) -> list[Path]:
    out = validate_output_dir(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    data = redactor.obj(results)
    files = {
        "results.json": json.dumps(data, indent=2, sort_keys=True) + "\n",
        "summary.md": render_summary(data),
        "findings.md": render_findings(data),
        "findings.csv": render_csv(data["findings"]),
        "attack_coverage.md": render_attack(data),
    }
    written = []
    for name, text in files.items():
        atomic_write_text(out / name, text)
        written.append(out / name)
    return written
