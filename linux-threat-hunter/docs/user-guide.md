# User guide: CLI reference

Invoke as `python -m linux_threat_hunter <command>` (or the `linux-threat-hunter` console script after installation). All commands accept `--help`.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | success |
| 1 | runtime error (unreadable path, refused overwrite, all collectors failed, unsafe output path) |
| 2 | invalid usage, configuration, rules, IOC file, baseline or evidence input (also raised by argparse for bad arguments) |
| 3 | `hunt --fail-on <severity>`: at least one finding at or above that severity |
| 4 | `collect --strict`: collection finished but at least one collector failed |

## Command summary

| Command | Purpose |
|---|---|
| `info` | version, platform, rule catalog and safety statement (`--json` for machine output) |
| `doctor` | check Python, distribution, init system, tools (`ss`, `ip`, `journalctl`, `who`), readability of key sources and rule validity |
| `rules list` | list rules (`--format table\|json\|markdown`, `--source`) |
| `rules validate` | validate every rule file; exit 2 if any is invalid |
| `collect` | read-only live collection into an evidence directory (Linux only) |
| `hunt` | run rules over an evidence directory and write `results.json` |
| `show` | print findings from a results directory in readable form |
| `trace` | print the evidence record a finding refers to |
| `report` | write Markdown, CSV and JSON reports from results |
| `baseline create\|validate\|compare\|update` | manage baselines |

Common options: `--config FILE` (YAML overrides, see [configuration](configuration.md)), `--allowlists FILE`, and for rule-using commands `--rules-dir DIR` (default: the repository's `rules/`, or `$LTH_RULES_DIR`).

## `info`, `doctor`

```bash
python -m linux_threat_hunter info
python -m linux_threat_hunter info --json
python -m linux_threat_hunter doctor
```

`doctor` never fails because a tool is missing; it reports which collectors will be partial. It exits 1 only if rules are invalid.

## `rules`

```bash
python -m linux_threat_hunter rules list
python -m linux_threat_hunter rules list --source auth --format json
python -m linux_threat_hunter rules list --format markdown
python -m linux_threat_hunter rules validate
python -m linux_threat_hunter rules validate --rules-dir ./my-rules
```

## `collect`

```bash
python -m linux_threat_hunter collect --profile basic --output ./evidence --dry-run
python -m linux_threat_hunter collect --profile basic --output ./evidence
python -m linux_threat_hunter collect --profile full --output ./evidence-full --strict
```

| Option | Meaning |
|---|---|
| `--profile basic\|full` | `full` adds vendor systemd unit directories and kernel module metadata |
| `--output DIR` | evidence directory to create. Refuses to write into a directory that already has evidence unless `--force` |
| `--dry-run` | print each collector, its sources and the access it needs; read and write nothing |
| `--strict` | exit 4 if any collector failed |

Evidence layout: `manifest.json` (profile, collection time, timezone, per-collector status, SHA-256 of each file), `host.json`, `processes.json`, `persistence.json`, `network.json`, `files.json`, `auth.log`. A collector that cannot run records why (`manifest.json` → `collectors`) and the others continue. The tool never invokes `sudo`.

Linux only: on other systems `--dry-run` still works, a real run exits 1 with an explanatory message.

## `hunt`

```bash
python -m linux_threat_hunter hunt --input ./evidence
python -m linux_threat_hunter hunt --input ./evidence --iocs ./examples/iocs.json
python -m linux_threat_hunter hunt --input ./evidence --iocs iocs.json --baseline baseline.json --output ./results --fail-on high
```

| Option | Meaning |
|---|---|
| `--input DIR` | evidence directory (required). Missing or malformed pieces become warnings and skipped rules |
| `--iocs FILE` | IOC file (JSON/YAML). Without it, IOC rules are skipped |
| `--baseline FILE` | baseline file. Without it, baseline rules are skipped |
| `--output DIR` | results directory (default `./results`); writes `results.json` |
| `--fail-on SEVERITY` | exit 3 if any finding is at or above this severity |
| `--show N` | findings to print on the terminal (default 25) |

Evidence may also contain `events.json` (imported command events, see [examples](examples.md)).

## `show` and `trace`

```bash
python -m linux_threat_hunter show --input ./results --rule LTH-PROC-003
python -m linux_threat_hunter show --input ./results --severity high --limit 10
python -m linux_threat_hunter trace --input ./evidence --ref processes.json#7
python -m linux_threat_hunter trace --input ./evidence --ref auth.log#14
```

`show` filters by `--rule`, `--id` (finding ID) and `--severity` (at or above). `trace` takes the `record_ref` from a finding's evidence: `<file>#<index>` (zero-based position in a JSON file, or the line number for `auth.log`). Both redact configured secret patterns on display.

## `report`

```bash
python -m linux_threat_hunter report --input ./results --output ./reports
```

Writes `summary.md`, `findings.md`, `findings.csv`, `results.json` and `attack_coverage.md`. The output directory is created if needed; a symlink or an existing file at that path is refused.

## `baseline`

```bash
python -m linux_threat_hunter baseline create --input ./evidence --output ./baseline.json
python -m linux_threat_hunter baseline validate --baseline ./baseline.json
python -m linux_threat_hunter baseline compare --input ./evidence --baseline ./baseline.json
python -m linux_threat_hunter baseline compare --input ./evidence --baseline ./baseline.json --output ./diff.json
python -m linux_threat_hunter baseline update --input ./evidence --baseline ./baseline.json
python -m linux_threat_hunter baseline update --input ./evidence --baseline ./baseline.json --approve
```

- `create` refuses to overwrite an existing file (use `--force`, which keeps `<name>.bak`).
- `validate` checks schema and an integrity hash. The hash detects accidental damage or naive edits; someone who can rewrite the file can recompute it, so protect baselines with file permissions and review.
- `compare` reports **added / removed / modified** per category (`persistence`, `files`, `executables`, `listeners`, `privileged_users`). Categories without telemetry in the current evidence are listed as *not compared*; a missing data source is never reported as "removed".
- `update` always prints the review first. It only writes with `--approve`, keeping the previous file as `.bak`.

**Baseline cautions.** A baseline captures whatever state existed when it was created (including malicious state), becomes stale, and legitimate updates create changes. Create baselines from trusted, freshly built hosts when possible.

## IOC file format

```json
{
  "schema_version": 1,
  "options": { "match_subdomains": false },
  "indicators": {
    "sha256":        [ { "value": "<64 hex>", "description": "...", "severity": "high", "references": ["https://..."] } ],
    "process_names": [ "name-without-slash" ],
    "file_paths":    [ "/absolute/path" ],
    "ips":           [ "203.0.113.5" ],
    "domains":       [ "bad.example.test" ]
  }
}
```

Entries are strings or objects with `value` plus optional `description`, `severity` (`informational`..`critical`) and `references`. Values are validated and normalized (hashes lowercased, IPs canonicalized, domains lowercased, paths normalized). Matching is exact; subdomain matching must be enabled explicitly. The IOC's `severity`, if given, sets the finding severity. YAML is accepted too (`.yaml`/`.yml`).
