# Windows Threat Hunter

A **read-only** PowerShell toolkit that hunts for persistence and suspicious activity on a Windows host, scores what it finds with a versioned rule catalog, and writes JSON, CSV and HTML reports. It works on Windows PowerShell 5.1 and PowerShell 7. It never remediates anything and never executes what it discovers.

> **Everything shipped in `sample-data/` is simulated.** The hosts, users, IP addresses and "malware" in the sample snapshots and example reports are invented lab data. Any result in this repository labelled *simulated* or *synthetic* came from those files, not from a real endpoint.

## What it checks

| Area | Data it reads |
|---|---|
| Persistence | Scheduled tasks, services, Run/RunOnce keys, startup folders and shortcuts, WMI event subscriptions |
| Accounts | Local accounts and privileged local group members |
| Execution | Processes with parent-child relationships and command-line patterns |
| Network | TCP connections and listeners tied to processes |
| Defender | Status, exclusions and Defender events |
| Event logs | Security, PowerShell script block and Sysmon events |
| Optional import | A Microsoft Defender XDR export (JSON or CSV) |

42 rules cover these areas. See the [rule catalog](docs/rule-catalog.md).

## Quick start (no Windows or admin rights needed)

```powershell
./scripts/Invoke-Demo.ps1
```

That hunts the three bundled synthetic snapshots and writes example reports. To hunt a single snapshot with the command-line script:

```powershell
./scripts/Invoke-WindowsThreatHunter.ps1 -SnapshotPath ./sample-data/snapshots/lab-intrusion.json -OutputDirectory ./reports
```

To inspect a real Windows host (read-only), run the same script without `-SnapshotPath`. Start with [Getting started](docs/getting-started.md).

## Honest results

A hunt reports **coverage** next to findings. If a data source could not be read (not elevated, Sysmon not installed, collector not requested), the report says so and the exit code is `3`, not `0`. No finding never means "clean" unless every source was collected.

| Exit code | Meaning |
|---|---|
| 0 | Completed, no findings at or above the threshold, every source collected |
| 1 | At least one active finding at or above `-FailOnSeverity` (default Medium) |
| 2 | Invalid input, configuration, rules, suppression file or path |
| 3 | No qualifying findings, but some sources were not collected or rules were skipped |
| 4 | Unexpected error |

## Documentation

| Document | What it covers |
|---|---|
| [Getting started](docs/getting-started.md) | Requirements, install, first run, live run |
| [Walkthrough](docs/walkthrough.md) | Three guided exercises on simulated data, command reference, diagrams, elevation and missing-data guidance |
| [User guide](docs/user-guide.md) | Every command, parameter, report field and workflow |
| [Configuration](docs/configuration.md) | Lists, patterns, limits, overrides, exclusions, suppressions |
| [Rule catalog](docs/rule-catalog.md) | All rules with severity, confidence, ATT&CK mapping and false-positive notes (generated) |
| [Rule authoring](docs/rule-authoring.md) | Writing, validating and testing rules |
| [Examples](docs/examples.md) | Copy-paste recipes |
| [Troubleshooting](docs/troubleshooting.md) | Common problems and what they mean |
| [Security and limitations](docs/security-and-limitations.md) | What the tool will and will not do, and where it can be wrong |
| [Threat model](docs/threat-model.md) | Assets, trust boundaries, abuse cases and mitigations |
| [Validation checklist](docs/validation-checklist.md) | What was verified, what was not, and how to verify it yourself |
| [Security policy](SECURITY.md) | Reporting a vulnerability |
| [Contributing](CONTRIBUTING.md) | Standards and how to add rules |
| [Code of conduct](CODE_OF_CONDUCT.md) | Expected behaviour |
| [Changelog](CHANGELOG.md) | Release notes |
| [License](LICENSE) | MIT |

Example reports generated from the simulated lab-intrusion snapshot are in [sample-data/reports](sample-data/reports).

## Layout

```text
src/Modules/WindowsThreatHunter   module manifest and public commands
src/Private                       collectors, engine, reporting, redaction (not exported)
src/Rules                         rule catalog (data only; rules never run code)
config                            default configuration, ATT&CK catalog, examples
tests/Unit, tests/Integration     Pester tests (portable and Windows-only)
tests/Fixtures                    synthetic scenarios and event XML
sample-data                       synthetic snapshots, XDR export, example reports
scripts                           command-line entry point, demo, tests, lint, catalog generator
docs                              documentation
```

## Requirements and limits

PowerShell 5.1 or 7. Live collection needs Windows; hunting over saved or synthetic snapshots works on any OS. Some sources need an elevated session. Detection is heuristic, so expect false positives and false negatives. Read [Security and limitations](docs/security-and-limitations.md) before relying on a result.
