"""Command-line interface.

Exit codes: 0 success; 1 runtime error; 2 invalid usage, configuration, rules or input;
3 findings at or above ``--fail-on``; 4 collection finished with failed collectors (``--strict``).
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from linux_threat_hunter import __version__
from linux_threat_hunter.baseline.core import (
    BaselineError,
    compare,
    create_baseline,
    load_baseline,
    save_baseline,
)
from linux_threat_hunter.collectors import COLLECTORS, CollectContext, collect, plan
from linux_threat_hunter.config import ConfigError, load_config
from linux_threat_hunter.detections import default_rules_dir, load_catalog
from linux_threat_hunter.evidence.store import EvidenceError, load_evidence
from linux_threat_hunter.ioc.matcher import IocError, IocSet, load_iocs
from linux_threat_hunter.models import SEVERITIES, severity_rank
from linux_threat_hunter.platform_info import platform_summary
from linux_threat_hunter.reporting import build_results, load_results, write_reports
from linux_threat_hunter.rules_engine import Engine
from linux_threat_hunter.rules_engine.conditions import ConditionError
from linux_threat_hunter.utils.redact import Redactor
from linux_threat_hunter.utils.safe import SAFE_PATH, UnsafePathError, validate_output_dir

OK, ERROR, USAGE, FINDINGS, INCOMPLETE = 0, 1, 2, 3, 4


class CliError(Exception):
    def __init__(self, message: str, code: int = ERROR) -> None:
        super().__init__(message)
        self.code = code


def _redactor(cfg: dict[str, Any]) -> Redactor:
    return Redactor(cfg["redaction"]["patterns"], cfg["redaction"]["replacement"])


def _config(args: argparse.Namespace) -> dict[str, Any]:
    try:
        return load_config(getattr(args, "config", None), getattr(args, "allowlists", None))
    except ConfigError as exc:
        raise CliError(f"configuration error: {exc}", USAGE) from exc


def _p(out: str = "") -> None:
    print(out)


# ----------------------------------------------------------------------- info/doctor
def cmd_info(args: argparse.Namespace) -> int:
    cfg = _config(args)
    rules, errors = load_catalog(args.rules_dir, cfg)
    info: dict[str, Any] = {
        "name": "linux-threat-hunter",
        "version": __version__,
        "platform": platform_summary(),
        "rules_dir": str(args.rules_dir or default_rules_dir()),
        "rules_loaded": len(rules),
        "rule_errors": len(errors),
        "collectors": [c.name for c in COLLECTORS],
        "safety": "read-only: never kills processes, edits services, changes firewall rules or remediates",
    }
    if args.json:
        _p(json.dumps(info, indent=2))
        return OK
    plat: dict[str, Any] = platform_summary()
    _p(f"linux-threat-hunter {__version__}")
    _p(f"  python        : {plat['python']}")
    _p(f"  system / arch : {plat['system']} / {plat['architecture']}")
    if plat["distribution"]:
        d = plat["distribution"]
        _p(f"  distribution  : {d['pretty_name']} (documented support: {d['documented_support']})")
        _p(f"  init system   : {plat['init_system']}")
    _p(f"  running as root: {plat['is_root']}")
    _p(f"  rules         : {len(rules)} loaded from {info['rules_dir']} ({len(errors)} invalid)")
    _p(f"  collectors    : {', '.join(info['collectors'])}")
    _p(f"  safety        : {info['safety']}")
    return OK


def cmd_doctor(args: argparse.Namespace) -> int:
    cfg = _config(args)
    problems = 0
    plat = platform_summary()

    def row(level: str, msg: str) -> None:
        _p(f"[{level:<4}] {msg}")

    row("ok", f"Python {plat['python']}") if sys.version_info >= (3, 11) else row("FAIL", "Python 3.11+ required")
    if not plat["is_linux"]:
        row(
            "warn",
            f"{plat['system']} detected: analysis of evidence works, live collection is Linux-only",
        )
    else:
        d = plat["distribution"]
        row(
            "ok" if d["documented_support"] else "warn",
            f"distribution: {d['pretty_name']}"
            + ("" if d["documented_support"] else " (not in documented support list)"),
        )
        row(
            "ok" if plat["init_system"] == "systemd" else "warn",
            f"init system: {plat['init_system']}",
        )
        row(
            "ok" if plat["architecture_supported"] else "warn",
            f"architecture: {plat['architecture']}",
        )
        row(
            "info",
            "running as root (read-only collection still applies)"
            if plat["is_root"]
            else "running unprivileged: some collectors will be partial (the tool never escalates itself)",
        )
        for tool in ("ss", "ip", "journalctl", "who"):
            found = shutil.which(tool, path=SAFE_PATH)
            row(
                "ok" if found else "warn",
                f"tool {tool}: {found or 'not found (related collection will be skipped)'}",
            )
        for src in (
            "/proc",
            "/etc/systemd/system",
            "/etc/cron.d",
            "/var/log/auth.log",
            "/var/log/secure",
            "/etc/ssh/sshd_config",
        ):
            if os.path.exists(src):
                row(
                    "ok" if os.access(src, os.R_OK) else "warn",
                    f"{src}: {'readable' if os.access(src, os.R_OK) else 'exists but NOT readable (needs additional access)'}",
                )
            else:
                row("info", f"{src}: not present on this system")
    rules, errors = load_catalog(args.rules_dir, cfg)
    if errors:
        problems += 1
        row("FAIL", f"{len(errors)} rule problem(s); run `rules validate`")
    else:
        row("ok", f"{len(rules)} detection rules valid")
    _p("")
    _p("doctor result: " + ("problems found" if problems else "ready (warnings are informational)"))
    return ERROR if problems else OK


# --------------------------------------------------------------------------- rules
def cmd_rules_list(args: argparse.Namespace) -> int:
    cfg = _config(args)
    rules, errors = load_catalog(args.rules_dir, cfg)
    if args.source:
        rules = [r for r in rules if r.data_source == args.source]
    if args.format == "json":
        _p(
            json.dumps(
                [
                    {
                        k: r.data[k]
                        for k in (
                            "id",
                            "name",
                            "version",
                            "type",
                            "data_source",
                            "severity",
                            "confidence",
                            "classification",
                        )
                    }
                    for r in rules
                ],
                indent=2,
            )
        )
    elif args.format == "markdown":
        _p("| Rule | Name | Type | Source | Severity | Confidence | ATT&CK |")
        _p("|---|---|---|---|---|---|---|")
        for r in rules:
            att = ", ".join(sorted({m["technique"] for m in r.data.get("attack", [])})) or "none"
            _p(
                f"| {r.id} | {r.data['name']} | {r.type} | {r.data_source} | {r.data['severity']} | "
                f"{r.data['confidence']} | {att} |"
            )
    else:
        _p(f"{'ID':<15}{'TYPE':<12}{'SOURCE':<12}{'SEV':<14}{'CONF':<8}NAME")
        for r in rules:
            d = r.data
            _p(f"{r.id:<15}{r.type:<12}{r.data_source:<12}{d['severity']:<14}{d['confidence']:<8}{d['name']}")
        _p(f"\n{len(rules)} rule(s)")
    if errors:
        for e in errors:
            print(f"warning: {e}", file=sys.stderr)
    return OK


def cmd_rules_validate(args: argparse.Namespace) -> int:
    cfg = _config(args)
    rules, errors = load_catalog(args.rules_dir, cfg)
    for e in errors:
        print(f"INVALID {e}", file=sys.stderr)
    _p(f"{len(rules)} rule(s) valid, {len(errors)} problem(s)")
    return USAGE if errors else OK


# ------------------------------------------------------------------------- collect
def cmd_collect(args: argparse.Namespace) -> int:
    cfg = _config(args)
    ctx = CollectContext(config=cfg, profile=args.profile)
    ctx.redactor = _redactor(cfg)
    if args.dry_run:
        _p(f"DRY RUN: nothing will be read beyond this plan and nothing is written (profile: {args.profile})")
        for row in plan(ctx):
            _p(f"- {row['collector']}: {row['description']}")
            _p(f"    sources: {', '.join(row['sources'])}")
            _p(f"    access : {row['access']}")
        _p(f"Would write to: {args.output}")
        _p("The tool never invokes sudo; run it with the access you are authorized to use.")
        return OK
    if platform.system() != "Linux":
        raise CliError(
            "live collection is only supported on Linux (use --dry-run to see the plan, "
            "or analyze existing evidence with `hunt`)"
        )
    try:
        out = validate_output_dir(args.output)
        manifest, results = collect(ctx, out, force=args.force)
    except (UnsafePathError, FileExistsError, OSError) as exc:
        raise CliError(str(exc)) from exc
    failed = [r for r in results if r.status == "failed"]
    for r in results:
        _p(f"{r.name:<12} {r.status:<8} {r.counts or ''}")
        for line in [*r.errors[:3], *r.notes[:3]]:
            _p(f"    - {line}")
    _p(f"Evidence written to {out} ({len(results) - len(failed)} of {len(results)} collectors produced data)")
    _p("Evidence may contain sensitive command lines, usernames and log lines. Handle it accordingly.")
    if len(failed) == len(results):
        return ERROR
    return INCOMPLETE if (failed and args.strict) else OK


# --------------------------------------------------------------------------- hunt
def _load_evidence(args: argparse.Namespace, cfg: dict[str, Any]) -> Any:
    try:
        return load_evidence(args.input, cfg)
    except EvidenceError as exc:
        raise CliError(str(exc), USAGE) from exc


def _load_iocs(path: str | None, cfg: dict[str, Any]) -> IocSet | None:
    if not path:
        return None
    try:
        return load_iocs(path, cfg["limits"])
    except IocError as exc:
        raise CliError(f"IOC file error: {exc}", USAGE) from exc


def _load_baseline(path: str | None, cfg: dict[str, Any]) -> dict[str, Any] | None:
    if not path:
        return None
    try:
        return load_baseline(path, cfg["limits"]["max_evidence_file_bytes"])
    except BaselineError as exc:
        raise CliError(str(exc), USAGE) from exc


def cmd_hunt(args: argparse.Namespace) -> int:
    cfg = _config(args)
    ev = _load_evidence(args, cfg)
    iocs = _load_iocs(args.iocs, cfg)
    baseline = _load_baseline(args.baseline, cfg)
    rules, errors = load_catalog(args.rules_dir, cfg)
    if errors:
        for e in errors:
            print(f"INVALID {e}", file=sys.stderr)
        raise CliError("rule validation failed; fix the rules (see `rules validate`)", USAGE)
    diff = compare(baseline, ev) if baseline else None
    try:
        hunt = Engine(rules, cfg, iocs, diff).run(ev)
    except ConditionError as exc:
        raise CliError(f"invalid allowlist or rule condition: {exc}", USAGE) from exc
    results = build_results(
        ev,
        hunt,
        iocs=iocs,
        diff=diff,
        baseline_path=args.baseline,
        rules_dir=str(args.rules_dir or default_rules_dir()),
    )
    try:
        out = validate_output_dir(args.output)
        out.mkdir(parents=True, exist_ok=True)
        from linux_threat_hunter.utils.safe import atomic_write_text

        atomic_write_text(
            out / "results.json",
            json.dumps(_redactor(cfg).obj(results), indent=2, sort_keys=True) + "\n",
        )
    except (UnsafePathError, OSError) as exc:
        raise CliError(str(exc)) from exc
    s = results["summary"]
    _p(
        f"Analyzed {results['scope']['total_records']} records from {', '.join(results['scope']['sources_analyzed']) or 'no sources'}"
    )
    _p(f"Rules: {s['rules_executed']} executed, {s['rules_skipped']} skipped")
    _p("Findings: " + ", ".join(f"{k}={v}" for k, v in s["by_severity"].items()) + f"  (total {s['total_findings']})")
    for f in results["findings"][: args.show]:
        _p(f"  [{f['severity']:<8}|{f['confidence']:<6}] {f['rule_id']}  {f['title']}")
    if s["total_findings"] > args.show:
        _p(f"  ... {s['total_findings'] - args.show} more (see results)")
    _p(f"Results written to {out / 'results.json'}")
    _p("Next: python -m linux_threat_hunter report --input " + str(out) + " --output ./reports")
    if args.fail_on and any(severity_rank(f["severity"]) >= severity_rank(args.fail_on) for f in results["findings"]):
        return FINDINGS
    return OK


def cmd_report(args: argparse.Namespace) -> int:
    cfg = _config(args)
    try:
        results = load_results(args.input)
        files = write_reports(results, args.output, _redactor(cfg))
    except (ValueError, UnsafePathError, OSError) as exc:
        raise CliError(str(exc), USAGE if isinstance(exc, ValueError) else ERROR) from exc
    for f in files:
        _p(f"wrote {f}")
    return OK


# ------------------------------------------------------------------- show / trace
def cmd_show(args: argparse.Namespace) -> int:
    cfg = _config(args)
    try:
        results = load_results(args.input)
    except ValueError as exc:
        raise CliError(str(exc), USAGE) from exc
    red = _redactor(cfg)
    picked = [
        f
        for f in results["findings"]
        if (not args.rule or f["rule_id"] == args.rule)
        and (not args.id or f["id"] == args.id)
        and (not args.severity or severity_rank(f["severity"]) >= severity_rank(args.severity))
    ]
    if not picked:
        raise CliError("no findings match the given filters", USAGE)
    for f in red.obj(picked)[: args.limit]:
        _p("=" * 78)
        _p(f"{f['title']}")
        _p(f"  finding   : {f['id']}   rule: {f['rule_id']} v{f['rule_version']}")
        _p(f"  severity  : {f['severity']}   confidence: {f['confidence']}   kind: {f['classification']}")
        _p(f"  observed  : {f['observed_at']} ({f['timezone_context']})")
        _p(f"  source    : {f['evidence_source']}  artifact: {f['artifact']}")
        _p(f"  explains  : {f['explanation']}")
        _p(f"  rationale : {f['rationale']}")
        if f["ioc_matches"]:
            for m in f["ioc_matches"]:
                _p(
                    f"  IOC match : {m['indicator_type']} {m['indicator']} (field {m['matched_field']}, {m['match_mode']})"
                )
        for a in f["attack"]:
            _p(f"  ATT&CK    : {a['technique']} {a['title']} ({a['tactic']}) {a['url']}")
        _p("  evidence  : " + json.dumps(f["evidence"], sort_keys=True))
        _p("  false positives to rule out:")
        for x in f["false_positives"]:
            _p(f"    - {x}")
        _p("  next steps:")
        for i, x in enumerate(f["investigation_steps"], 1):
            _p(f"    {i}. {x}")
        if f["related_findings"]:
            _p("  related   : " + ", ".join(f["related_findings"]))
    return OK


def cmd_trace(args: argparse.Namespace) -> int:
    """Print the evidence record a finding's ``record_ref`` (e.g. processes.json#7) points to."""
    cfg = _config(args)
    ev = _load_evidence(args, cfg)
    source, _, idx = args.ref.partition("#")
    if not idx.isdigit():
        raise CliError("--ref must look like processes.json#7 or auth.log#12", USAGE)
    red = _redactor(cfg)
    n = int(idx)
    if source == "auth.log":
        rec = next((r for r in ev.of("auth") if r.index == n), None)
        if rec is None:
            raise CliError(f"no parsed auth event at line {n} (unsupported lines are not parsed)", USAGE)
        _p(f"{source} line {n} (parsed event):")
        _p(json.dumps(red.obj(rec.data), indent=2, sort_keys=True))
        return OK
    matches = [r for rs in ev.records.values() for r in rs if r.source == source and r.index == n]
    if not matches:
        raise CliError(f"no record {args.ref} in {args.input}", USAGE)
    for r in matches:
        _p(f"{r.ref}" + (f"  (derived from {r.data['_derived_from']})" if r.data.get("_derived_from") else ""))
        _p(json.dumps(red.obj(r.data), indent=2, sort_keys=True))
    return OK


# ------------------------------------------------------------------------ baseline
def cmd_baseline_create(args: argparse.Namespace) -> int:
    cfg = _config(args)
    ev = _load_evidence(args, cfg)
    data = create_baseline(ev)
    try:
        save_baseline(Path(args.output), data, overwrite=args.force)
    except (BaselineError, OSError, UnsafePathError) as exc:
        raise CliError(str(exc)) from exc
    counts = {c: len(v) for c, v in data["entries"].items()}
    _p(f"Baseline written to {args.output}: {counts}")
    _p(
        "WARNING: a baseline captures the host as it is now, including any malicious state. Review it, and "
        "expect legitimate changes after updates."
    )
    return OK


def _print_diff(diff: Any, limit: int = 100) -> None:
    c = diff.counts()
    _p(f"Compared categories: {', '.join(diff.categories_compared) or 'none'}")
    for cat, why in diff.categories_skipped.items():
        _p(f"Not compared: {cat} ({why})")
    _p(f"Changes: added={c['added']} removed={c['removed']} modified={c['modified']}")
    for ch in diff.changes[:limit]:
        extra = f" fields={','.join(ch['changed_fields'])}" if ch["changed_fields"] else ""
        _p(f"  {ch['change']:<9} {ch['category']:<17} {ch['key']}{extra}")


def cmd_baseline_compare(args: argparse.Namespace) -> int:
    cfg = _config(args)
    ev = _load_evidence(args, cfg)
    base = _load_baseline(args.baseline, cfg)
    assert base is not None
    diff = compare(base, ev)
    _print_diff(diff)
    if args.output:
        try:
            from linux_threat_hunter.utils.safe import atomic_write_text

            atomic_write_text(
                Path(args.output),
                json.dumps(
                    {
                        "counts": diff.counts(),
                        "changes": diff.changes,
                        "compared": diff.categories_compared,
                        "skipped": diff.categories_skipped,
                    },
                    indent=2,
                    sort_keys=True,
                )
                + "\n",
            )
        except (OSError, UnsafePathError) as exc:
            raise CliError(str(exc)) from exc
        _p(f"Diff written to {args.output}")
    return OK


def cmd_baseline_validate(args: argparse.Namespace) -> int:
    _load_baseline(args.baseline, load_config())
    _p(f"{args.baseline}: valid (schema and integrity hash OK)")
    return OK


def cmd_baseline_update(args: argparse.Namespace) -> int:
    cfg = _config(args)
    ev = _load_evidence(args, cfg)
    base = _load_baseline(args.baseline, cfg)
    assert base is not None
    diff = compare(base, ev)
    _p("REVIEW the changes below before accepting them as the new normal:")
    _print_diff(diff)
    if not args.approve:
        _p(
            "\nNo changes were written. Re-run with --approve to replace the baseline "
            "(the old file is kept as <name>.bak)."
        )
        return OK
    data = create_baseline(ev)
    backup = save_baseline(Path(args.baseline), data, overwrite=True)
    _p(f"Baseline updated; previous version saved to {backup}")
    return OK


# --------------------------------------------------------------------------- parser
def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="linux-threat-hunter",
        description="Read-only Linux threat hunting for authorized analysts. Findings are leads to "
        "validate, not proof of compromise. See docs/security-and-limitations.md.",
    )
    ap.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = ap.add_subparsers(dest="command", required=True, metavar="COMMAND")

    def common(p: argparse.ArgumentParser, rules: bool = True) -> None:
        p.add_argument("--config", help="YAML configuration file overriding defaults")
        p.add_argument("--allowlists", help="YAML file with an 'allowlists' mapping")
        if rules:
            p.add_argument("--rules-dir", help="directory of rule files (default: bundled rules/)")

    p = sub.add_parser("info", help="show version, platform and rule catalog")
    common(p)
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_info)

    p = sub.add_parser("doctor", help="check the environment and what can be collected")
    common(p)
    p.set_defaults(func=cmd_doctor)

    rules = sub.add_parser("rules", help="list or validate detection rules")
    rsub = rules.add_subparsers(dest="rules_command", required=True, metavar="ACTION")
    p = rsub.add_parser("list", help="list rules")
    common(p)
    p.add_argument("--format", choices=["table", "json", "markdown"], default="table")
    p.add_argument(
        "--source",
        choices=[
            "process",
            "persistence",
            "auth",
            "network",
            "file",
            "event",
            "baseline",
            "findings",
        ],
    )
    p.set_defaults(func=cmd_rules_list)
    p = rsub.add_parser("validate", help="validate every rule against the schema (exit 2 if invalid)")
    common(p)
    p.set_defaults(func=cmd_rules_validate)

    p = sub.add_parser("collect", help="collect read-only Linux telemetry into an evidence directory")
    common(p, rules=False)
    p.add_argument("--profile", choices=["basic", "full"], default="basic")
    p.add_argument("--output", required=True, help="evidence directory to create")
    p.add_argument("--dry-run", action="store_true", help="print the collection plan; read and write nothing")
    p.add_argument("--force", action="store_true", help="allow writing into a directory with existing evidence")
    p.add_argument("--strict", action="store_true", help="exit 4 if any collector failed")
    p.set_defaults(func=cmd_collect)

    p = sub.add_parser("hunt", help="run detection rules over an evidence directory")
    common(p)
    p.add_argument("--input", required=True, help="evidence directory")
    p.add_argument("--iocs", help="local IOC file (JSON or YAML)")
    p.add_argument("--baseline", help="baseline file for baseline-comparison rules")
    p.add_argument("--output", default="./results", help="results directory (default ./results)")
    p.add_argument("--fail-on", choices=SEVERITIES, help="exit 3 if any finding has at least this severity")
    p.add_argument("--show", type=int, default=25, help="findings to print to the terminal")
    p.set_defaults(func=cmd_hunt)

    p = sub.add_parser("report", help="generate Markdown, JSON and CSV reports from hunt results")
    common(p, rules=False)
    p.add_argument("--input", required=True, help="results directory containing results.json")
    p.add_argument("--output", required=True, help="reports directory")
    p.set_defaults(func=cmd_report)

    p = sub.add_parser("show", help="print findings from a results directory in readable form")
    common(p, rules=False)
    p.add_argument("--input", required=True, help="results directory containing results.json")
    p.add_argument("--rule", help="only this rule ID, e.g. LTH-PROC-003")
    p.add_argument("--id", help="only this finding ID")
    p.add_argument("--severity", choices=SEVERITIES, help="only findings at or above this severity")
    p.add_argument("--limit", type=int, default=20)
    p.set_defaults(func=cmd_show)

    p = sub.add_parser("trace", help="print the evidence record a finding refers to (for example processes.json#7)")
    common(p, rules=False)
    p.add_argument("--input", required=True, help="evidence directory")
    p.add_argument("--ref", required=True, help="record reference from a finding's evidence.record_ref")
    p.set_defaults(func=cmd_trace)

    bl = sub.add_parser("baseline", help="create, validate, compare and (explicitly) update baselines")
    bsub = bl.add_subparsers(dest="baseline_command", required=True, metavar="ACTION")
    p = bsub.add_parser("create", help="create a baseline from an evidence directory")
    common(p, rules=False)
    p.add_argument("--input", required=True)
    p.add_argument("--output", required=True, help="baseline file to write")
    p.add_argument("--force", action="store_true", help="replace an existing baseline (old one kept as .bak)")
    p.set_defaults(func=cmd_baseline_create)
    p = bsub.add_parser("compare", help="compare evidence with a baseline (added/removed/modified)")
    common(p, rules=False)
    p.add_argument("--input", required=True)
    p.add_argument("--baseline", required=True)
    p.add_argument("--output", help="optional JSON file for the diff")
    p.set_defaults(func=cmd_baseline_compare)
    p = bsub.add_parser("validate", help="validate a baseline's schema and integrity hash")
    p.add_argument("--baseline", required=True)
    p.set_defaults(func=cmd_baseline_validate)
    p = bsub.add_parser("update", help="review changes, then replace the baseline only with --approve")
    common(p, rules=False)
    p.add_argument("--input", required=True)
    p.add_argument("--baseline", required=True)
    p.add_argument("--approve", action="store_true", help="actually replace the baseline")
    p.set_defaults(func=cmd_baseline_update)
    return ap


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except CliError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return exc.code
    except BrokenPipeError:
        return OK
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return ERROR
    except (OSError, UnsafePathError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return ERROR
