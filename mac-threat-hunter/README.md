# macOS Threat Hunter

Read-only, explainable threat hunting for **authorized** macOS endpoints and offline evidence.
Collect point-in-time telemetry on a Mac, or analyse exported evidence anywhere, then run
transparent YAML detection rules, match analyst-supplied IOCs, compare against a baseline and
produce evidence-backed reports.

> It is a hunting aid, not an EDR. Findings are investigation leads, never verdicts: a heuristic
> hit is not proof of malice and an IOC match is not proof of compromise. It does not detect all
> macOS malware, performs no remediation, and never executes discovered files.

## Features

- **Collectors (macOS only, read-only):** system context and protections, processes, network
  sockets (`lsof`), LaunchAgents/Daemons, startup items, shell startup files, login hooks,
  current-user crontab, watched executables and config-file metadata/hashes, and bounded
  unified-log queries (`log show`) or imports of exported logs / `.logarchive`.
- **Declarative rules (36 shipped):** `all`/`any`/`none` conditions, 20 operators, allowlists,
  thresholds with time windows, bounded regexes, and a documented schema. Rules contain no code.
- **IOC engine:** SHA-256, exact process name, exact path, IP, domain from local JSON/YAML.
  Exact matching by default; subdomain and text-token matching are explicit and labelled.
- **Baselines:** create, validate (integrity hash), compare (added/removed/modified) and
  *explicitly* update after review. Never silently replaced.
- **ATT&CK mapping:** curated catalogue with official IDs/titles and links; mappings carry a
  written justification. Reports say what a mapping does not mean.
- **Evidence manager:** manifest with SHA-256 per file, collector status and errors, integrity
  checks on load, path-traversal and symlink protection.
- **Reports:** Markdown, JSON and CSV with severity and confidence as separate fields, time-zone
  context, evidence references, false-positive notes, next steps, redaction and output escaping.

## Quick start (no Mac, no root, no network needed for the demo)

```bash
git clone https://github.com/joeabur/threat-hunter-tool.git
cd threat-hunter-tool/mac-threat-hunter
python3 -m venv .venv && source .venv/bin/activate
python -m pip install -e ".[dev]"

python -m mac_threat_hunter doctor
python -m mac_threat_hunter rules validate
bash scripts/run-demo.sh        # fully synthetic end-to-end hunt
```

Hunt your own evidence:

```bash
python -m mac_threat_hunter collect --profile basic --dry-run      # see what would run
python -m mac_threat_hunter collect --profile basic --output ./evidence   # on a Mac you own/are authorised to assess
python -m mac_threat_hunter hunt --input ./evidence --iocs ./examples/iocs.json
python -m mac_threat_hunter report --input ./results --output ./reports
```

## Example output (synthetic data)

Produced by `python -m mac_threat_hunter hunt --input examples/synthetic-evidence --iocs examples/iocs.json --baseline examples/baselines/clean-baseline.json` on Linux:

```text
Host: synthetic-mac.example.test  [SYNTHETIC DATA]
Records analysed: 53  Rules: 36 executed, 0 skipped, 0 disabled
Findings: 49 (heuristic 29, IOC 10, baseline 10); suppressed 0
  [high    |medium] MTH-EXEC-003 F-a7650e9dddbd Microsoft Word spawned sh
```

## Supported platforms

| Capability | macOS (Apple Silicon / Intel) | Linux / Windows |
|---|---|---|
| Live `collect` | Supported by design; only the unit-level behaviour is covered by tests here (see below) | Collectors report `unsupported` |
| `hunt`, `report`, `baseline`, `rules`, IOCs, log-export import | Yes | Yes (tested on Linux) |

Python 3.11+. **Tested versions:** automated tests run on Linux with Python 3.13 in this
repository's development environment. The CI matrix (`.github/workflows/mac-threat-hunter-tests.yml`)
targets Ubuntu, Windows and macOS runners with Python 3.11-3.13, and macOS-only integration tests
run on macOS runners. Live collection has **not** been validated by the author on any specific
macOS release or on Intel versus Apple Silicon hardware; treat the macOS architecture/version
matrix as untested until CI or your own run confirms it, and report differences.

## Architecture

```text
collectors -> evidence (manifest + hashes) -> parsers (normalise) -> rules engine + IOC + baseline -> findings -> reporting
```

See [docs/architecture.md](docs/architecture.md).

## Limitations

Point-in-time snapshots, partial visibility without root, redacted unified-log fields, heuristic
rules that need tuning, and no coverage of many macOS techniques. Details:
[docs/security-and-limitations.md](docs/security-and-limitations.md) and
[docs/detection-coverage.md](docs/detection-coverage.md).

## Documentation

- [Getting started](docs/getting-started.md)
- [Walkthrough (hands-on exercises)](docs/walkthrough.md)
- [User guide / CLI reference](docs/user-guide.md)
- [Rule authoring](docs/rule-authoring.md)
- [Configuration](docs/configuration.md)
- [Troubleshooting](docs/troubleshooting.md)
- [Security and limitations](docs/security-and-limitations.md)
- [Architecture](docs/architecture.md)
- [Detection coverage](docs/detection-coverage.md)
- [Examples](docs/examples.md)
- [Contributing](CONTRIBUTING.md) · [Security policy](SECURITY.md) · [Code of conduct](CODE_OF_CONDUCT.md) · [Changelog](CHANGELOG.md)

## License

MIT. See [LICENSE](LICENSE).
