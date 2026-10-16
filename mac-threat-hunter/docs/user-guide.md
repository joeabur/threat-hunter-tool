# User guide and CLI reference

Run as `python -m mac_threat_hunter <command>` (or the `mac-threat-hunter` entry point).
Every command accepts `--config FILE` (overlay on `configs/default.yaml`) and `--allowlists FILE`.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success (findings may exist) |
| 1 | `hunt --fail-on SEVERITY` and a finding at or above that severity exists |
| 2 | Usage error (bad arguments, refusing to overwrite) |
| 3 | Input or evidence error (missing/unreadable/oversized file, path-safety refusal) |
| 4 | Validation failure (invalid rules, configuration, IOC file or baseline) |
| 5 | `collect` produced no usable telemetry (for example on non-macOS) |

## Commands

| Command | Purpose |
|---|---|
| `info [--json]` | Version, platform, paths, rule count, collectors, profiles |
| `doctor` | Checks Python, PyYAML, config, rules; on macOS also the native tools |
| `rules list [--source S] [--json]` | List rules |
| `rules show RULE_ID` | Print a rule file |
| `rules validate [DIR ...]` | Validate rule files (default: shipped rules) |
| `collect` | Read-only live collection into an evidence directory |
| `hunt --input DIR` | Evaluate rules; writes `results/results.json` |
| `baseline create/validate/compare/update` | Baseline lifecycle |
| `report --input RESULTS` | Render `report.md`, `findings.json`, `findings.csv` |

### collect

```bash
python -m mac_threat_hunter collect --profile basic --output ./evidence
python -m mac_threat_hunter collect --profile full --dry-run
python -m mac_threat_hunter collect --collectors logs --last 2h --output ./evidence-logs
python -m mac_threat_hunter collect --collectors logs --log-file ./export.ndjson --output ./evidence-logs
```

Profiles (`configs/default.yaml`): `basic` (system, processes, network, persistence),
`persistence` (system, persistence, files), `logs`, `full`. `--collectors a,b` overrides.
`--dry-run` prints the exact read-only operations and the access each needs, and writes nothing.
The tool never invokes `sudo`; a collector that lacks access records the reason and the others
continue. Log options: `--last` (e.g. `30m`, `2h`, max from config), `--predicate` (validated:
only `field == "x"`, `CONTAINS`, `BEGINSWITH`, `ENDSWITH`, `LIKE`, `AND/OR/NOT`, parentheses and an
allowlist of fields), `--logarchive PATH.logarchive`, `--log-file FILE` (imports ndjson from
`log show --style ndjson`, works on any OS). An existing evidence directory is not overwritten
without `--overwrite`.

### hunt

```bash
python -m mac_threat_hunter hunt --input ./evidence
python -m mac_threat_hunter hunt --input ./evidence --iocs ./examples/iocs.json --baseline ./baseline.json --output ./results --fail-on high
```

Options: `--rules DIR` (repeatable, replaces the shipped rules), `--iocs`, `--baseline`,
`--output` (default `./results`), `--fail-on`, `--quiet`. Rules whose telemetry is absent are
reported as skipped with a reason; they are never treated as "no findings". Evidence files that no
longer match `manifest.json` produce a warning and are flagged in the report.

### baseline

```bash
python -m mac_threat_hunter baseline create   --input ./evidence --output ./baseline.json
python -m mac_threat_hunter baseline validate --baseline ./baseline.json
python -m mac_threat_hunter baseline compare  --input ./evidence --baseline ./baseline.json [--output diff.json]
python -m mac_threat_hunter baseline update   --input ./evidence --baseline ./baseline.json --output ./baseline-new.json            # review only
python -m mac_threat_hunter baseline update   --input ./evidence --baseline ./baseline.json --output ./baseline-new.json --accept   # writes
```

`create` refuses to replace an existing file (`--force` to override). `update` always prints the
differences and the caveats first and writes nothing without `--accept`; `--accept` needs either a
new `--output` path or `--in-place` (which keeps a timestamped `.bak-` copy). Categories the new
evidence has no telemetry for are neither compared nor dropped on update. Recorded categories:
`persistence`, `files`, `listeners`, `config`.

### report

```bash
python -m mac_threat_hunter report --input ./results --output ./reports --formats md,json,csv
```

## Reading a finding

- **Severity** is impact if the finding is real; **confidence** is how sure the rule is that the
  observation means what it says. They are independent.
- **Class:** `heuristic` (rule inference), `ioc_match` (indicator hit), `baseline_change`
  (confirmed difference from the baseline; significance unknown).
- **Evidence reference** `processes.json#9` is file and zero-based record index (or line index for
  logs) inside the evidence directory.
- **Time zone context:** `explicit:+00:00` came with the source timestamp; `assumed-utc` or
  `assumed-local:+hh:mm` was inferred. The original string is kept.
- **Missing context** lists optional fields the telemetry did not provide.
