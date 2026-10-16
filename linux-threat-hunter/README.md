# Linux Threat Hunter

A **read-only** command-line tool that helps authorized analysts hunt for suspicious activity on Linux hosts. It collects host telemetry (processes, systemd/cron persistence, authentication logs, sockets, selected files), runs **transparent, declarative detection rules**, matches **analyst-supplied IOCs**, compares against a **baseline**, links related findings, and writes **evidence-backed reports** with MITRE ATT&CK context.

> **What this is not.** It is a hunting aid, not an EDR and not a remediation tool. It never kills processes, disables accounts, changes services, edits firewall rules or deletes files. Findings are *leads to validate*, not proof of compromise, and missing telemetry is never evidence that a host is clean. See [security and limitations](docs/security-and-limitations.md).

## Features

| Area | What it does |
|---|---|
| Collection (Linux, read-only) | host/OS, `/proc` processes (redacted command lines, executable hashes), systemd units/timers/drop-ins, cron, shell startup, SSH config metadata, auth logs (`auth.log`, `secure`, journald), sockets via `ss`, selected file hashes/permissions. Each collector fails independently and explains what access it needs. Nothing is ever executed and `sudo` is never invoked. |
| Rule engine | 33 YAML rules (match, threshold, sequence, baseline, IOC, correlation) validated against a schema before use. No code in rules is ever executed; regexes are bounded. |
| IOCs | Local JSON/YAML: SHA-256, process names, file paths, IPs, domains. Exact matching by default. No feeds are downloaded; nothing is uploaded. |
| Baselines | Create, validate (schema + integrity hash), compare (added/removed/modified) and *explicitly* update, with a `.bak` of the previous baseline. |
| Correlation | Declarative rules that link findings by shared identifiers (pid, path, IP) and time windows. |
| ATT&CK | Valid technique IDs, official titles and links, only where the rule's behavior justifies it. |
| Reports | `results.json`, `summary.md` (executive), `findings.md` (detailed), `findings.csv`, `attack_coverage.md`. Secrets are redacted; CSV/Markdown output is hardened against injection. |

## Quick start (synthetic demo, no root, no network)

```bash
git clone <this repository> && cd threat-hunter-tool/linux-threat-hunter
python3 -m venv .venv && source .venv/bin/activate
python -m pip install -r requirements-dev.txt && python -m pip install -e . --no-deps
python -m pytest -q
bash scripts/run-demo.sh        # validates rules, builds a baseline, hunts, writes reports to ./.demo
```

Open `.demo/reports/summary.md`. A shorter manual run:

```bash
python -m linux_threat_hunter rules validate
python -m linux_threat_hunter hunt --input examples/synthetic-evidence --iocs examples/iocs.json --output ./results
python -m linux_threat_hunter report --input ./results --output ./reports
```

Live collection (Linux only, run as the user you are authorized to use; use `--dry-run` first):

```bash
python -m linux_threat_hunter doctor
python -m linux_threat_hunter collect --profile basic --output ./evidence --dry-run
python -m linux_threat_hunter collect --profile basic --output ./evidence
python -m linux_threat_hunter hunt --input ./evidence
```

The full beginner tutorial with five guided exercises is in [docs/walkthrough.md](docs/walkthrough.md).

## Supported platforms

| Capability | Support |
|---|---|
| Live collection | Linux with `/proc`; designed for systemd-based Ubuntu LTS, Debian and Fedora; x86-64 and ARM64 |
| Evidence analysis, rules, IOC, baseline, reports, tests | Python 3.11+ on Linux, macOS and Windows (CI runs the portable suite on all three; see [troubleshooting](docs/troubleshooting.md)) |

Distributions and architectures other than the documented ones may work but are not claimed. See [docs/getting-started.md](docs/getting-started.md) for what was actually verified.

## Architecture

```
collectors ──► evidence dir ──► parsers/normalize ──► rule engine ──► findings ──► reporting
 (read-only)   (JSON + auth.log)     records          │   ▲   ▲                   (JSON/CSV/MD)
                                                      │   │   └── baseline diff
                                                      │   └────── IOC matcher
                                                      └── correlation (links findings)
```

Details: [docs/architecture.md](docs/architecture.md).

## Documentation

- [Getting started](docs/getting-started.md): setup from a fresh clone
- [Walkthrough](docs/walkthrough.md): end-to-end tutorial with five exercises
- [User guide](docs/user-guide.md): complete CLI reference and exit codes
- [Rule authoring](docs/rule-authoring.md): schema, examples, validation, false-positive guidance
- [Configuration](docs/configuration.md): every option and default
- [Troubleshooting](docs/troubleshooting.md)
- [Security and limitations](docs/security-and-limitations.md): threat model, privacy, blind spots
- [Architecture](docs/architecture.md)
- [Detection coverage](docs/detection-coverage.md): every rule, ATT&CK mapping, false positives, gaps
- [Examples](docs/examples.md): runnable synthetic scenarios

Project files: [CONTRIBUTING](CONTRIBUTING.md), [CODE_OF_CONDUCT](CODE_OF_CONDUCT.md), [SECURITY](SECURITY.md), [CHANGELOG](CHANGELOG.md), [LICENSE](LICENSE).

## Known limitations (short list)

- Snapshot telemetry: short-lived processes and connections can be missed.
- Rotated and compressed logs are not collected; auth log tail is bounded.
- Without privileges, other users' process executables, user crontabs and some logs are unreadable, and the report says so.
- Baselines can contain malicious state and go stale after legitimate updates.
- Shipped detections cover a small part of ATT&CK for Linux; see [coverage and gaps](docs/detection-coverage.md).
