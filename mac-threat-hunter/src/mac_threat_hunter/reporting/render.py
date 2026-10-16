from __future__ import annotations

import csv
import io
import json
import re
from pathlib import Path
from typing import Any

from .. import __version__
from ..models import SEVERITIES
from ..utils.errors import InputError
from ..utils.paths import ensure_output_dir, read_text_bounded
from ..utils.redact import Redactor

CSV_COLUMNS = (
    "finding_id", "rule_id", "rule_version", "title", "category", "severity", "confidence",
    "source", "host", "observed_at_utc", "time_zone", "evidence_ref", "artifact", "attack",
    "ioc_type", "ioc_value", "suppressed", "explanation",
)  # fmt: skip
CATEGORY_LABELS = {
    "heuristic": "Heuristic detection (rule inference; needs analyst validation)",
    "ioc_match": "IOC match (indicator hit; not proof of compromise)",
    "baseline_change": "Observed change vs baseline (confirmed difference; significance unknown)",
}
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


def _clean(text: Any) -> str:
    return _CONTROL.sub("", str(text))


def csv_safe(value: Any) -> str:
    """Neutralise spreadsheet formula injection and control characters."""
    text = _clean(value).replace("\r", " ").replace("\n", " ")
    if text and text[0] in "=+-@\t":
        return "'" + text
    return text


def md_text(value: Any) -> str:
    """Escape text for inline Markdown/HTML contexts."""
    text = _clean(value).replace("\r", " ").replace("\n", " ")
    for ch in ("\\", "`", "*", "_", "|", "[", "]", "<", ">", "#"):
        text = text.replace(ch, "\\" + ch)
    return text


def md_code(value: Any) -> str:
    if isinstance(value, (list, dict)):
        value = json.dumps(value, sort_keys=True, ensure_ascii=False)
    text = _clean(value).replace("\r", " ").replace("\n", " ")
    fence = "`" * (max((len(m) for m in re.findall(r"`+", text)), default=0) + 1)
    pad = " " if text.startswith("`") or text.endswith("`") else ""
    return f"{fence}{pad}{text}{pad}{fence}"


def load_results(path: Path) -> dict[str, Any]:
    target = path / "results.json" if path.is_dir() else path
    text = read_text_bounded(target, 256 * 1024 * 1024)
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise InputError(f"{target}: invalid JSON: {exc.msg}") from exc
    if not isinstance(data, dict) or "findings" not in data or "summary" not in data:
        raise InputError(f"{target} does not look like a mac-threat-hunter results file")
    return data


def findings_csv(results: dict[str, Any]) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow(CSV_COLUMNS)
    for f in results["findings"] + results.get("suppressed_findings", []):
        ioc = f.get("ioc") or {}
        writer.writerow(
            [
                csv_safe(v)
                for v in (
                    f["finding_id"], f["rule_id"], f["rule_version"], f["title"], f["category"],
                    f["severity"], f["confidence"], f["source"], f.get("host") or "",
                    f.get("observed_at") or "", f.get("time_zone") or "", f["evidence_ref"],
                    json.dumps(f.get("artifact", {}), sort_keys=True),
                    ";".join(a["id"] for a in f.get("attack", [])),
                    ioc.get("type", ""), ioc.get("value", ""), str(bool(f.get("suppressed"))).lower(),
                    f["explanation"],
                )
            ]
        )  # fmt: skip
    return buf.getvalue()


def _finding_md(f: dict[str, Any]) -> list[str]:
    lines = [f"#### {md_text(f['title'])}", ""]
    lines.append(
        f"- **Finding ID:** {md_code(f['finding_id'])}  \n"
        f"- **Rule:** {md_code(f['rule_id'])} v{f['rule_version']} ({md_text(f['rule_name'])})  \n"
        f"- **Severity:** {f['severity']} · **Confidence:** {f['confidence']}  \n"
        f"- **Class:** {CATEGORY_LABELS.get(f['category'], f['category'])}  \n"
        f"- **Host:** {md_text(f.get('host') or 'unknown')} · **Source:** {f['source']}  \n"
        f"- **Observed:** {md_code(f.get('observed_at') or 'no event timestamp')}"
        f" (original {md_code(f.get('time_original') or 'n/a')}, zone context: "
        f"{md_text(f.get('time_zone') or 'unknown')})  \n"
        f"- **Evidence reference:** {md_code(f['evidence_ref'])}"
    )
    if f.get("suppressed"):
        lines.append(f"- **Suppressed:** {md_text(f.get('suppression_reason'))}")
    lines += ["", f"**Why this was flagged.** {md_text(f['explanation'])}", ""]
    lines += [f"**Detection rationale.** {md_text(f['rationale'])}", ""]
    if f.get("artifact"):
        lines.append("**Artifact**")
        lines += [f"- {md_text(k)}: {md_code(v)}" for k, v in f["artifact"].items()]
        lines.append("")
    if f.get("evidence"):
        lines.append("**Evidence**")
        lines += [f"- {md_text(k)}: {md_code(v)}" for k, v in f["evidence"].items()]
        lines.append("")
    if f.get("ioc"):
        ioc = f["ioc"]
        lines.append("**IOC match**")
        for m in ioc.get("all_matches") or [ioc]:
            lines.append(
                f"- indicator {md_code(m.get('type'))} {md_code(m.get('value'))}"
                f" (severity {md_text(m.get('severity') or 'rule default')}); matched field "
                f"{md_code(m.get('matched_field'))} = {md_code(m.get('matched_value'))}; "
                f"mode: {md_text(m.get('match_mode'))}"
            )
            if m.get("description"):
                lines.append(f"  - indicator description: {md_text(m['description'])}")
            if m.get("source"):
                lines.append(f"  - indicator source: {md_text(m['source'])}")
        lines.append(f"- note: {md_text(ioc.get('note', ''))}")
        lines.append("")
    if f.get("baseline_change"):
        bc = f["baseline_change"]
        lines.append("**Baseline change**")
        lines.append(f"- {md_text(bc['category'])} / {md_code(bc['key'])}: {md_text(bc['change'])}")
        lines.append(f"- changed attributes: {md_code(', '.join(bc['changed_attributes']))}")
        lines.append("")
    if f.get("attack"):
        lines.append("**ATT&CK mapping**")
        lines += [
            f"- [{md_text(a['id'])} {md_text(a['name'])}]({a['url']}) — {md_text(', '.join(a['tactics']))}"
            for a in f["attack"]
        ]
        lines.append("")
    if f.get("missing_context"):
        lines.append("**Missing context**")
        lines += [f"- {md_text(m)}" for m in f["missing_context"]]
        lines.append("")
    lines.append("**Known false-positive considerations**")
    lines += [f"- {md_text(x)}" for x in f["false_positives"]]
    lines += ["", "**Suggested next steps**"]
    lines += [f"{i}. {md_text(x)}" for i, x in enumerate(f["investigation"], 1)]
    lines.append("")
    return lines


def render_markdown(results: dict[str, Any]) -> str:
    s = results["summary"]
    ev = results["evidence"]
    host = results.get("host") or {}
    out: list[str] = ["# macOS Threat Hunter report", ""]
    if ev.get("synthetic"):
        out += [
            "> **SYNTHETIC DATA.** This report was produced from fabricated demonstration "
            "evidence. Nothing here was observed on a real endpoint.",
            "",
        ]
    out += [
        "Findings are investigation leads for an analyst. They are not verdicts, and this tool "
        "does not confirm compromise.",
        "",
        "## Executive summary",
        "",
        f"- **Host:** {md_text(host.get('hostname') or 'unknown')}",
        f"- **Evidence collected:** {md_code(ev.get('collected_at') or 'unknown')}"
        f" (profile {md_code(ev.get('profile') or 'unknown')})",
        f"- **Report generated:** {md_code(results.get('generated_at'))} by mac-threat-hunter "
        f"{md_code(results.get('tool_version', __version__))}",
        f"- **Records analysed:** {ev.get('total_records', 0)}",
        f"- **Findings:** {s['findings_total']} "
        f"({s['by_category'].get('heuristic', 0)} heuristic, {s['ioc_matches']} IOC, "
        f"{s['by_category'].get('baseline_change', 0)} baseline)",
        f"- **Baseline changes observed:** {s['baseline_changes']}",
        f"- **Suppressed findings:** {s['suppressed']}",
        f"- **Rules:** {s['rules_executed']} executed, {s['rules_skipped']} skipped, "
        f"{s['rules_disabled']} disabled",
        "",
        "| Severity | Findings |",
        "|---|---|",
    ]
    out += [f"| {sev} | {s['by_severity'].get(sev, 0)} |" for sev in reversed(SEVERITIES)]
    out.append("")
    top = [f for f in results["findings"] if f["severity"] in {"critical", "high"}][:5]
    if top:
        out += ["**Highest-severity findings**", ""]
        out += [
            f"- {f['severity']}: {md_text(f['title'])} ({md_code(f['finding_id'])})" for f in top
        ]
        out.append("")

    out += ["## Scope and data sources analysed", ""]
    out.append("| Source | Records |")
    out.append("|---|---|")
    out += [f"| {md_text(k)} | {v} |" for k, v in sorted(ev.get("record_counts", {}).items())]
    out.append("")
    out.append(f"Evidence files loaded: {md_code(', '.join(ev.get('files_loaded', [])) or 'none')}")
    out.append("")
    if results["inputs"].get("ioc_set"):
        i = results["inputs"]["ioc_set"]
        out.append(
            f"IOC set: {md_text(i['name'] or 'unnamed')} — {i['count']} indicators "
            f"{md_code(json.dumps(i['by_type']))}{' (synthetic)' if i.get('synthetic') else ''}"
        )
        out.append("")

    out += ["## Collection errors and missing telemetry", ""]
    problems: list[str] = []
    for c in results.get("collection_failures", []):
        detail = "; ".join(c.get("errors", []) + c.get("notes", []))
        problems.append(
            f"- **{md_text(c.get('collector'))}**: {md_text(c.get('status'))}"
            + (f" — {md_text(detail)}" if detail else "")
            + (f" (needs: {md_text(c['privilege_note'])})" if c.get("privilege_note") else "")
        )
    problems += [f"- {md_text(w)}" for w in ev.get("warnings", [])]
    if ev.get("integrity_failures"):
        problems.append(
            "- **Integrity failure:** "
            + md_text(", ".join(ev["integrity_failures"]))
            + " no longer match the manifest hashes."
        )
    if ev.get("malformed_log_lines"):
        problems.append(
            f"- {ev['malformed_log_lines']} log lines could not be parsed and were ignored."
        )
    out += problems or ["No collection errors were recorded in the evidence set."]
    out += [
        "",
        "Missing telemetry is not evidence of a clean host.",
        "",
    ]

    findings = results["findings"]
    for cat in ("heuristic", "ioc_match", "baseline_change"):
        group = [f for f in findings if f["category"] == cat]
        out += [f"## {CATEGORY_LABELS[cat]}", ""]
        if not group:
            out += ["None.", ""]
            continue
        for f in group:
            out += _finding_md(f)

    if results.get("suppressed_findings"):
        out += ["## Suppressed findings", ""]
        out += [
            f"- {md_code(f['finding_id'])} {md_text(f['title'])} — reason: "
            f"{md_text(f.get('suppression_reason'))}"
            for f in results["suppressed_findings"]
        ]
        out.append("")

    out += ["## MITRE ATT&CK summary", ""]
    if results.get("attack"):
        out += [
            "Techniques below are those mapped to rules that produced findings in this run. "
            "A mapping describes the behaviour the rule looks for; it does not prove the "
            "technique was used, and techniques not listed were not necessarily absent.",
            "",
            "| Technique | Tactics | Rules | Findings |",
            "|---|---|---|---|",
        ]
        for a in results["attack"]:
            out.append(
                f"| [{md_text(a['id'])} {md_text(a['name'])}]({a['url']}) | "
                f"{md_text(', '.join(a['tactics']))} | {md_text(', '.join(a['rule_ids']))} | "
                f"{len(a['finding_ids'])} |"
            )
    else:
        out.append(
            "No findings with ATT&CK mappings. This does not imply the techniques are absent."
        )
    out.append("")

    out += ["## Baseline changes", ""]
    if results["inputs"].get("baseline_file") is None:
        out.append("No baseline was supplied.")
    else:
        for w in results.get("baseline_warnings", []):
            out.append(f"> {md_text(w)}")
        out.append("")
        skipped = (results["inputs"].get("baseline") or {}).get("skipped_categories")
        if skipped:
            out.append(
                "Categories not compared because the evidence set lacks that telemetry: "
                + md_text(", ".join(skipped))
                + "."
            )
            out.append("")
        changes = results.get("baseline_changes", [])
        if changes:
            out += ["| Category | Item | Change | Attributes |", "|---|---|---|---|"]
            out += [
                f"| {md_text(c['category'])} | {md_code(c['key'])} | {md_text(c['change'])} | "
                f"{md_text(', '.join(c['changed_attributes']))} |"
                for c in changes
            ]
        else:
            out.append("No differences from the baseline in the compared categories.")
    out.append("")

    out += [
        "## Rules executed and skipped",
        "",
        "| Rule | Status | Matched | Findings | Note |",
        "|---|---|---|---|---|",
    ]
    for r in results.get("rules", []):
        note = r.get("reason") or ""
        if r.get("capped"):
            note += " (findings capped by max_findings_per_rule)"
        if r.get("skipped_missing_fields"):
            note += f" ({r['skipped_missing_fields']} records lacked required fields)"
        out.append(
            f"| {md_text(r['rule_id'])} | {r['status']} | {r.get('matched', 0)} | "
            f"{r.get('findings', 0)} | {md_text(note.strip())} |"
        )
    out += ["", "## Known limitations", ""]
    out += [f"- {md_text(x)}" for x in results.get("limitations", [])]
    out.append("")
    return "\n".join(out)


def write_reports(
    results: dict[str, Any], out_dir: Path, redactor: Redactor, formats: set[str]
) -> list[Path]:
    """Write requested reports ('md', 'json', 'csv'); redaction is applied again here."""
    ensure_output_dir(out_dir)
    safe = redactor.redact_obj(results)
    written: list[Path] = []
    if "md" in formats:
        p = out_dir / "report.md"
        p.write_text(render_markdown(safe), encoding="utf-8")
        written.append(p)
    if "json" in formats:
        p = out_dir / "findings.json"
        p.write_text(json.dumps(safe, indent=2, sort_keys=True, ensure_ascii=False) + "\n", "utf-8")
        written.append(p)
    if "csv" in formats:
        p = out_dir / "findings.csv"
        p.write_text(findings_csv(safe), encoding="utf-8", newline="")
        written.append(p)
    return written
