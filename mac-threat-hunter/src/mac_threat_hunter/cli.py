"""Command-line interface. Exit codes are documented in docs/user-guide.md."""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

from . import __version__
from .baseline.compare import compare_to_baseline, covered_categories
from .baseline.model import WARNINGS, create_baseline, load_baseline
from .collectors.base import CollectContext, LogOptions
from .collectors.registry import COLLECTORS, run_collectors
from .config import (
    Config,
    data_root,
    default_allowlists_path,
    default_config_path,
    default_rules_dir,
    load_config,
    make_redactor,
)
from .detections.runner import result_to_dict, run_hunt
from .evidence.loader import load_evidence
from .evidence.manifest import MANIFEST_NAME, write_evidence
from .ioc.loader import load_iocs
from .models import SEVERITIES, severity_rank
from .reporting.render import load_results, write_reports
from .rules_engine.loader import RuleSet, load_rules
from .utils.errors import (
    EXIT_FINDINGS,
    EXIT_INPUT,
    EXIT_NO_TELEMETRY,
    EXIT_OK,
    EXIT_USAGE,
    EXIT_VALIDATION,
    HunterError,
    UsageError,
    ValidationError,
)
from .utils.paths import ensure_output_dir
from .utils.timeutil import local_offset_string, utc_now


def _out(text: str = "") -> None:
    sys.stdout.write(text + "\n")


def _err(text: str) -> None:
    sys.stderr.write(text + "\n")


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:  # type: ignore[override]
        self.print_usage(sys.stderr)
        _err(f"{self.prog}: error: {message}")
        raise SystemExit(EXIT_USAGE)


def _add_common(p: argparse.ArgumentParser) -> None:
    p.add_argument("--config", type=Path, help="YAML configuration overlaying configs/default.yaml")
    p.add_argument(
        "--allowlists", type=Path, help="YAML allowlists file (default: configs/allowlists.yaml)"
    )


def _add_rules(p: argparse.ArgumentParser) -> None:
    p.add_argument(
        "--rules", type=Path, action="append", metavar="DIR",
        help="rules directory (repeatable; default: the shipped rules/ directory)",
    )  # fmt: skip


def build_parser() -> argparse.ArgumentParser:
    parser = _Parser(
        prog="mac-threat-hunter",
        description="Read-only, explainable threat hunting for authorized macOS endpoints and "
        "offline evidence. Findings are investigation leads, not verdicts.",
        epilog="Exit codes: 0 ok, 1 findings at/above --fail-on, 2 usage error, 3 input/evidence "
        "error, 4 validation failure, 5 no telemetry could be collected.",
    )
    parser.add_argument("--version", action="version", version=f"mac-threat-hunter {__version__}")
    sub = parser.add_subparsers(dest="command", metavar="COMMAND", parser_class=_Parser)
    sub.required = True

    p = sub.add_parser("info", help="show version, platform and configuration locations")
    _add_common(p)
    _add_rules(p)
    p.add_argument("--json", action="store_true", help="machine-readable output")

    p = sub.add_parser("doctor", help="check environment readiness (analysis and live collection)")
    _add_common(p)
    _add_rules(p)

    rules = sub.add_parser("rules", help="list, show or validate detection rules")
    rsub = rules.add_subparsers(dest="rules_command", metavar="SUBCOMMAND", parser_class=_Parser)
    rsub.required = True
    p = rsub.add_parser("list", help="list loaded rules")
    _add_common(p)
    _add_rules(p)
    p.add_argument("--source", help="only rules using this data source")
    p.add_argument("--json", action="store_true")
    p = rsub.add_parser("show", help="show one rule in full")
    _add_common(p)
    _add_rules(p)
    p.add_argument("rule_id")
    p = rsub.add_parser("validate", help="validate rule files against the schema")
    _add_common(p)
    p.add_argument("paths", nargs="*", type=Path, help="rule directories (default: shipped rules)")

    p = sub.add_parser("collect", help="collect read-only live telemetry on this Mac")
    _add_common(p)
    p.add_argument(
        "--profile", default="basic", help="basic, persistence, logs or full (default: basic)"
    )
    p.add_argument("--collectors", help="comma-separated collectors overriding the profile")
    p.add_argument("--output", type=Path, default=Path("./evidence"), help="evidence directory")
    p.add_argument("--dry-run", action="store_true", help="show what would run; collect nothing")
    p.add_argument(
        "--overwrite", action="store_true", help="replace an existing evidence directory manifest"
    )
    p.add_argument("--last", help="unified log window, e.g. 30m, 2h (default from config)")
    p.add_argument("--predicate", help="unified log predicate (validated; simple comparisons only)")
    p.add_argument("--logarchive", type=Path, help="query this .logarchive instead of the live log")
    p.add_argument(
        "--log-file", type=Path, help="import an exported ndjson unified log instead of querying"
    )

    p = sub.add_parser("hunt", help="run detection rules over an evidence directory")
    _add_common(p)
    _add_rules(p)
    p.add_argument("--input", type=Path, required=True, help="evidence directory")
    p.add_argument("--iocs", type=Path, help="IOC JSON/YAML file")
    p.add_argument("--baseline", type=Path, help="baseline file to compare against")
    p.add_argument("--output", type=Path, default=Path("./results"), help="results directory")
    p.add_argument(
        "--fail-on", choices=SEVERITIES, help="exit 1 if a finding at/above this severity exists"
    )
    p.add_argument("--quiet", action="store_true", help="suppress the console summary")

    base = sub.add_parser("baseline", help="create, validate, compare or update a baseline")
    bsub = base.add_subparsers(dest="baseline_command", metavar="SUBCOMMAND", parser_class=_Parser)
    bsub.required = True
    p = bsub.add_parser("create", help="create a baseline from an evidence directory")
    _add_common(p)
    p.add_argument("--input", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--force", action="store_true", help="replace an existing baseline file")
    p = bsub.add_parser("validate", help="validate a baseline's schema and integrity hash")
    _add_common(p)
    p.add_argument("--baseline", type=Path, required=True)
    p = bsub.add_parser("compare", help="report added, removed and modified observations")
    _add_common(p)
    p.add_argument("--input", type=Path, required=True)
    p.add_argument("--baseline", type=Path, required=True)
    p.add_argument("--output", type=Path, help="also write the differences as JSON")
    p = bsub.add_parser(
        "update", help="review differences and, only with --accept, write a new baseline"
    )
    _add_common(p)
    p.add_argument("--input", type=Path, required=True)
    p.add_argument("--baseline", type=Path, required=True)
    p.add_argument(
        "--output", type=Path, help="new baseline path (default: required unless --in-place)"
    )
    p.add_argument(
        "--in-place", action="store_true", help="replace --baseline (a timestamped backup is kept)"
    )
    p.add_argument("--accept", action="store_true", help="confirm you reviewed the differences")

    p = sub.add_parser("report", help="render Markdown, JSON and CSV reports from hunt results")
    _add_common(p)
    p.add_argument("--input", type=Path, required=True, help="results directory or results.json")
    p.add_argument("--output", type=Path, default=Path("./reports"))
    p.add_argument("--formats", default="md,json,csv", help="comma-separated: md,json,csv")
    return parser


# -- helpers -------------------------------------------------------------------------------


def _load_cfg(args: argparse.Namespace) -> Config:
    return load_config(getattr(args, "config", None), getattr(args, "allowlists", None))


def _rule_dirs(args: argparse.Namespace) -> list[Path]:
    return list(getattr(args, "rules", None) or [default_rules_dir()])


def _load_ruleset(args: argparse.Namespace, cfg: Config) -> RuleSet:
    return load_rules(_rule_dirs(args), cfg)


def _print_rule_errors(rs: RuleSet) -> None:
    for path, problems in rs.errors.items():
        _err(f"INVALID {path}")
        for problem in problems:
            _err(f"  - {problem}")


# -- commands ------------------------------------------------------------------------------


def cmd_info(args: argparse.Namespace) -> int:
    cfg = _load_cfg(args)
    rs = _load_ruleset(args, cfg)
    info: dict[str, Any] = {
        "version": __version__,
        "python": sys.version.split()[0],
        "platform": sys.platform,
        "live_collection_supported": sys.platform == "darwin",
        "data_root": str(data_root()),
        "default_config": str(default_config_path()),
        "default_allowlists": str(default_allowlists_path()),
        "rules_dirs": [str(p) for p in _rule_dirs(args)],
        "rules_loaded": len(rs.rules),
        "rule_errors": len(rs.errors),
        "collectors": sorted(COLLECTORS),
        "profiles": cfg.collection["profiles"],
    }
    if args.json:
        _out(json.dumps(info, indent=2, sort_keys=True))
    else:
        _out(f"mac-threat-hunter {info['version']}")
        for key in ("python", "platform", "live_collection_supported", "data_root", "rules_loaded",
                    "rule_errors"):  # fmt: skip
            _out(f"  {key}: {info[key]}")
        _out(f"  collectors: {', '.join(info['collectors'])}")
        _out(
            "  profiles: " + "; ".join(f"{k}=[{','.join(v)}]" for k, v in info["profiles"].items())
        )
        if sys.platform != "darwin":
            _out(
                "  note: not macOS; offline analysis of evidence works, live collection is unavailable."
            )
    return EXIT_OK


def cmd_doctor(args: argparse.Namespace) -> int:
    failures = 0

    def line(level: str, text: str) -> None:
        _out(f"[{level}] {text}")

    if sys.version_info >= (3, 11):  # noqa: UP036 - kept so a too-old interpreter gets a clear message
        line("PASS", f"Python {sys.version.split()[0]} (3.11+ required)")
    else:
        line("FAIL", f"Python {sys.version.split()[0]} is older than 3.11")
        failures += 1
    try:
        import yaml  # noqa: F401

        line("PASS", "PyYAML available")
    except ImportError:
        line("FAIL", "PyYAML missing; run: python -m pip install PyYAML")
        failures += 1
    try:
        cfg = _load_cfg(args)
        line("PASS", "configuration and allowlists valid")
    except ValidationError as exc:
        line("FAIL", f"configuration invalid: {exc}")
        for p in exc.problems:
            _err(f"   - {p}")
        return EXIT_VALIDATION
    rs = _load_ruleset(args, cfg)
    if rs.ok and rs.rules:
        line("PASS", f"{len(rs.rules)} rules valid")
    else:
        line("FAIL", f"rule problems: {len(rs.errors)} invalid file(s), {len(rs.rules)} valid")
        _print_rule_errors(rs)
        failures += 1
    if sys.platform == "darwin":
        line("PASS", "running on macOS: live collection supported")
        for tool in ("/bin/ps", "/usr/sbin/lsof", "/usr/bin/log", "/usr/bin/codesign", "/usr/bin/sw_vers",
                     "/usr/bin/csrutil", "/usr/sbin/spctl"):  # fmt: skip
            line(
                "PASS" if Path(tool).exists() else "WARN",
                f"{tool} {'found' if Path(tool).exists() else 'missing; related collector will degrade'}",
            )
        import os

        if hasattr(os, "geteuid") and os.geteuid() != 0:
            line(
                "INFO",
                "not root: this tool never invokes sudo; other users' sockets/files will be invisible",
            )
        line(
            "INFO",
            "Full Disk Access is not required; items it would unlock are reported as inaccessible",
        )
    else:
        line(
            "WARN",
            f"running on {sys.platform}: live collection unavailable; offline/synthetic analysis works",
        )
    line("INFO", "all collectors are read-only; discovered files are never executed")
    return EXIT_OK if failures == 0 else EXIT_VALIDATION


def cmd_rules(args: argparse.Namespace) -> int:
    cfg = _load_cfg(args)
    if args.rules_command == "validate":
        dirs = args.paths or [default_rules_dir()]
        rs = load_rules(dirs, cfg)
        if rs.errors:
            _print_rule_errors(rs)
            _err(f"{len(rs.errors)} invalid rule file(s); {len(rs.rules)} valid")
            return EXIT_VALIDATION
        _out(f"OK: {len(rs.rules)} rules valid ({rs.files_checked} files checked)")
        return EXIT_OK
    rs = _load_ruleset(args, cfg)
    if rs.errors:
        _print_rule_errors(rs)
        return EXIT_VALIDATION
    if args.rules_command == "show":
        rule = rs.by_id(args.rule_id)
        if rule is None:
            _err(f"no rule {args.rule_id}")
            return EXIT_INPUT
        _out(Path(rule.path).read_text(encoding="utf-8"))
        return EXIT_OK
    rules = [r for r in rs.rules if not args.source or args.source in r.sources]
    if args.json:
        _out(
            json.dumps(
                [
                    {
                        "id": r.id,
                        "name": r.name,
                        "version": r.version,
                        "type": r.type,
                        "sources": r.sources,
                        "severity": r.severity,
                        "confidence": r.confidence,
                        "attack": r.techniques,
                    }
                    for r in rules
                ],
                indent=2,
            )
        )
        return EXIT_OK
    _out(f"{'ID':<15} {'TYPE':<9} {'SOURCE':<24} {'SEV':<13} {'CONF':<7} NAME")
    for r in rules:
        _out(
            f"{r.id:<15} {r.type:<9} {','.join(r.sources):<24} {r.severity:<13} {r.confidence:<7} {r.name}"
        )
    _out(f"{len(rules)} rules")
    return EXIT_OK


def cmd_collect(args: argparse.Namespace) -> int:
    cfg = _load_cfg(args)
    profiles = cfg.collection["profiles"]
    if args.collectors:
        names = [n.strip() for n in args.collectors.split(",") if n.strip()]
        unknown = [n for n in names if n not in COLLECTORS]
        if unknown:
            raise UsageError(
                f"unknown collector(s): {', '.join(unknown)}; choose from {', '.join(COLLECTORS)}"
            )
        profile = "custom"
    else:
        profile = args.profile
        if profile not in profiles:
            raise UsageError(f"unknown profile {profile!r}; choose from {', '.join(profiles)}")
        names = list(profiles[profile])
    if args.log_file and "logs" not in names:
        names.append("logs")
    ctx = CollectContext(
        config=cfg, redactor=make_redactor(cfg),
        log=LogOptions(window=args.last, predicate=args.predicate, archive=args.logarchive,
                       import_file=args.log_file),
    )  # fmt: skip
    if "logs" in names:  # reject bad windows/predicates before anything runs
        from .collectors.logs import LogCollector

        LogCollector()._options(ctx)
    if args.dry_run:
        _out("DRY RUN: nothing will be collected or written. Planned read-only operations:")
        for res in run_collectors(names, ctx, dry_run=True):
            _out(f"\n[{res.name}] {COLLECTORS[res.name].description}")
            if res.privilege_note:
                _out(f"  access: {res.privilege_note}")
            for cmd in res.commands:
                _out(f"  - {cmd}")
        if sys.platform != "darwin":
            _out(
                f"\nNote: this is {sys.platform}; a real run would report these collectors as unsupported."
            )
        return EXIT_OK
    out_dir: Path = args.output
    if (out_dir / MANIFEST_NAME).exists() and not args.overwrite:
        raise UsageError(
            f"{out_dir} already holds evidence; choose a new --output or pass --overwrite"
        )
    started = utc_now()
    results = run_collectors(names, ctx)
    finished = utc_now()
    host: dict[str, Any] = {}
    for r in results:
        if r.name == "system" and r.records:
            rec = r.records[0]
            host = {"hostname": rec.get("hostname"), "os": rec.get("os"), "arch": rec.get("arch")}
    manifest = write_evidence(
        out_dir, results, profile=profile, host=host, started=started, finished=finished,
        timezone_offset=local_offset_string(), is_root=ctx.is_root,
    )  # fmt: skip
    _out(f"Evidence directory: {out_dir} ({len(manifest['files'])} files, manifest.json)")
    for r in results:
        extra = f" — {'; '.join(r.errors)}" if r.errors else ""
        _out(f"  {r.name:<12} {r.status:<12} {len(r.records):>6} records{extra}")
    _out("Evidence may contain sensitive process, path and log data; protect it accordingly.")
    usable = [r for r in results if r.status in {"ok", "partial"}]
    return EXIT_OK if usable else EXIT_NO_TELEMETRY


def _print_summary(data: dict[str, Any]) -> None:
    s = data["summary"]
    _out(
        f"Host: {data['host'].get('hostname') or 'unknown'}"
        f"{'  [SYNTHETIC DATA]' if data['evidence']['synthetic'] else ''}"
    )
    _out(
        f"Records analysed: {data['evidence']['total_records']}  "
        f"Rules: {s['rules_executed']} executed, {s['rules_skipped']} skipped, {s['rules_disabled']} disabled"
    )
    _out(
        f"Findings: {s['findings_total']} "
        f"(heuristic {s['by_category']['heuristic']}, IOC {s['ioc_matches']}, "
        f"baseline {s['by_category']['baseline_change']}); suppressed {s['suppressed']}"
    )
    _out("By severity: " + ", ".join(f"{k}={v}" for k, v in s["by_severity"].items() if v))
    for f in data["findings"][:25]:
        _out(
            f"  [{f['severity']:<8}|{f['confidence']:<6}] {f['rule_id']} {f['finding_id']} {f['title']}"
        )
    if s["findings_total"] > 25:
        _out(f"  ... {s['findings_total'] - 25} more in results.json")
    for w in data["evidence"]["warnings"][:5]:
        _out(f"WARNING: {w}")


def cmd_hunt(args: argparse.Namespace) -> int:
    cfg = _load_cfg(args)
    rs = _load_ruleset(args, cfg)
    if rs.errors:
        _print_rule_errors(rs)
        _err("refusing to hunt with invalid rules; fix them or run 'rules validate'")
        return EXIT_VALIDATION
    ev = load_evidence(args.input, cfg)
    iocs = (
        load_iocs(args.iocs, max_indicators=cfg.limit("max_ioc_indicators")) if args.iocs else None
    )
    baseline = load_baseline(args.baseline) if args.baseline else None
    hunt = run_hunt(ev, rs, cfg, iocs=iocs, baseline=baseline)
    data = result_to_dict(
        ev, rs, hunt, cfg, iocs=iocs, baseline=baseline,
        rule_dirs=[str(p) for p in _rule_dirs(args)],
        ioc_path=args.iocs.name if args.iocs else None,
        baseline_path=args.baseline.name if args.baseline else None,
    )  # fmt: skip
    ensure_output_dir(args.output)
    data = make_redactor(cfg).redact_obj(data)
    (args.output / "results.json").write_text(
        json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    if not args.quiet:
        _print_summary(data)
        _out(f"Results written to {args.output / 'results.json'} (run 'report' for Markdown/CSV)")
    if args.fail_on:
        threshold = severity_rank(args.fail_on)
        if any(severity_rank(f["severity"]) >= threshold for f in data["findings"]):
            return EXIT_FINDINGS
    return EXIT_OK


def _print_changes(changes: list[Any], skipped: list[str]) -> None:
    if not changes:
        _out("No differences from the baseline in the compared categories.")
    for c in changes:
        _out(
            f"  {c.change.upper():<9} {c.category:<12} {c.key}"
            + (f"  (changed: {', '.join(c.changed_attributes)})" if c.change == "modified" else "")
        )
    counts: dict[str, int] = {}
    for c in changes:
        counts[c.change] = counts.get(c.change, 0) + 1
    _out("Totals: " + (", ".join(f"{k}={v}" for k, v in sorted(counts.items())) or "none"))
    if skipped:
        _out("Not compared (evidence lacks this telemetry): " + ", ".join(skipped))


def cmd_baseline(args: argparse.Namespace) -> int:
    cfg = _load_cfg(args)
    cmd = args.baseline_command
    if cmd == "validate":
        bl = load_baseline(args.baseline)
        _out(
            f"OK: {args.baseline} schema and integrity hash valid "
            f"({sum(len(v) for v in bl.observations.values())} observations, created {bl.created_at})"
        )
        return EXIT_OK
    ev = load_evidence(args.input, cfg)
    if cmd == "create":
        if args.output.exists() and not args.force:
            raise UsageError(
                f"{args.output} exists; baselines are never replaced silently (use --force)"
            )
        bl = create_baseline(ev)
        ensure_output_dir(args.output.parent)
        args.output.write_text(json.dumps(bl.to_dict(), indent=2, sort_keys=True) + "\n", "utf-8")
        _out(
            f"Baseline written to {args.output}: "
            + ", ".join(f"{k}={len(v)}" for k, v in bl.observations.items())
        )
        for w in WARNINGS:
            _out(f"WARNING: {w}")
        return EXIT_OK
    baseline = load_baseline(args.baseline)
    changes = compare_to_baseline(baseline, ev)
    covered = covered_categories(ev)
    skipped = sorted(c for c, v in baseline.observations.items() if v and c not in covered)
    if cmd == "compare":
        _print_changes(changes, skipped)
        if args.output:
            ensure_output_dir(args.output.parent)
            args.output.write_text(
                json.dumps(
                    {"changes": [c.to_dict() for c in changes], "not_compared": skipped}, indent=2
                )
                + "\n",
                "utf-8",
            )
            _out(f"Differences written to {args.output}")
        _out("Review these before treating any difference as benign or malicious.")
        return EXIT_OK
    # update
    _out("REVIEW REQUIRED. Differences between the current baseline and the new evidence:")
    _print_changes(changes, skipped)
    for w in WARNINGS:
        _out(f"WARNING: {w}")
    if not args.accept:
        _out("Nothing was written. Re-run with --accept after reviewing to write the new baseline.")
        return EXIT_OK
    if args.in_place == bool(args.output):
        raise UsageError("give exactly one of --output PATH or --in-place with --accept")
    target = args.baseline if args.in_place else args.output
    if not args.in_place and target.exists():
        raise UsageError(
            f"{target} exists; refusing to overwrite (choose a new path or use --in-place)"
        )
    if args.in_place:
        stamp = datetime.now().strftime("%Y%m%dT%H%M%S")
        backup = target.with_name(f"{target.name}.bak-{stamp}")
        shutil.copy2(target, backup)
        _out(f"Previous baseline kept as {backup}")
    new = create_baseline(ev)
    for cat in skipped:  # keep categories the new evidence cannot speak to
        new.observations[cat] = baseline.observations[cat]
    from .baseline.model import canonical_hash

    new.integrity = canonical_hash(new.observations)
    target.write_text(json.dumps(new.to_dict(), indent=2, sort_keys=True) + "\n", "utf-8")
    _out(f"New baseline written to {target}")
    return EXIT_OK


def cmd_report(args: argparse.Namespace) -> int:
    cfg = _load_cfg(args)
    formats = {f.strip() for f in args.formats.split(",") if f.strip()}
    if not formats or not formats <= {"md", "json", "csv"}:
        raise UsageError("--formats must be a comma-separated subset of md,json,csv")
    results = load_results(args.input)
    written = write_reports(results, args.output, make_redactor(cfg), formats)
    for p in written:
        _out(f"wrote {p}")
    return EXIT_OK


_DISPATCH = {
    "info": cmd_info, "doctor": cmd_doctor, "rules": cmd_rules, "collect": cmd_collect,
    "hunt": cmd_hunt, "baseline": cmd_baseline, "report": cmd_report,
}  # fmt: skip


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
        return _DISPATCH[args.command](args)
    except SystemExit as exc:
        return int(exc.code) if isinstance(exc.code, int) else EXIT_OK
    except ValidationError as exc:
        _err(f"validation error: {exc}")
        for p in exc.problems[:50]:
            _err(f"  - {p}")
        return exc.exit_code
    except HunterError as exc:
        _err(f"error: {exc}")
        return exc.exit_code
    except KeyboardInterrupt:  # pragma: no cover
        _err("interrupted")
        return 130
