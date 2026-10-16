# User guide

## Concepts

- **Collector**: reads one kind of system state, read-only. Twelve collectors are available: `ScheduledTasks`, `Services`, `RegistryRun`, `StartupFolders`, `WmiSubscriptions`, `LocalAccounts`, `Processes`, `Network`, `Defender`, `SecurityEvents`, `PowerShellEvents`, `SysmonEvents`.
- **Snapshot**: the collected items plus a **coverage** entry for every data source. It can be saved to JSON and hunted later or elsewhere.
- **Rule**: a declarative, data-only description of a suspicious pattern. Rules never contain code.
- **Finding**: a rule match with host, observation time, rule ID and version, evidence, **severity**, **confidence**, finding type, explanation, false-positive notes and a recommended next step.
- **Coverage**: for each data source, `Collected`, `Partial`, `NeedsElevation`, `Unavailable`, `Error`, `NotRequested` or `Imported`. Anything other than `Collected` or `Imported` is a gap, and rules for that source are listed under *RulesSkipped*.

Severity is the impact if the finding is real (Informational, Low, Medium, High, Critical). Confidence (Low, Medium, High) is how likely it is to be real given the evidence. They are never merged into one score.

## The command-line script

`scripts/Invoke-WindowsThreatHunter.ps1`

| Parameter | Purpose |
|---|---|
| `-SnapshotPath` | Hunt a saved or synthetic snapshot (any OS). Omit for a live Windows hunt. |
| `-ExportSnapshotPath` | Live only: also save the raw snapshot. Contains command lines and account names. |
| `-DefenderXdrPath` | Merge a Defender XDR export (`.json` or `.csv`). |
| `-ConfigPath` | Configuration override file. |
| `-RulePath` | Rule file or directory. Invalid rules stop the hunt. |
| `-SuppressionPath` | Suppression file. |
| `-Collector` | Live only: limit collection to these collectors. |
| `-RuleId`, `-Category` | Run only matching rules (`-RuleId` accepts wildcards). |
| `-MinimumSeverity` | Run only rules at or above this effective severity. |
| `-FailOnSeverity` | Lowest severity that gives exit code 1 (default Medium). |
| `-OutputDirectory`, `-Format`, `-Force` | Write reports (Json, Csv, Html). Existing files are refused without `-Force`. |
| `-ValidateOnly`, `-ListRules` | Validate configuration, rules and suppressions; or list rules. |

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Completed, no findings at or above the threshold, every data source collected |
| 1 | At least one active finding at or above `-FailOnSeverity` |
| 2 | Invalid input, configuration, rules, suppression file or path (nothing was hunted) |
| 3 | No qualifying findings, but a source was not fully collected or rules were skipped |
| 4 | Unexpected error |

Suppressed findings do not count toward exit code 1, but they stay in the reports. Rules that are disabled, or that depend on the optional XDR import, are not counted as gaps.

## Module commands

| Command | Purpose |
|---|---|
| `Invoke-WthCollection` | Read-only live collection into a snapshot object (Windows). |
| `Export-WthSnapshot` / `Import-WthSnapshot` | Save or load a snapshot. Import validates schema and size. |
| `Import-WthDefenderXdrEvent` | Parse an XDR export; reports skipped rows and unknown columns. |
| `Invoke-WthHunt` | Evaluate rules over a live collection, a snapshot file or a snapshot object. |
| `Export-WthReport` | Write JSON, CSV and HTML reports from a hunt result. |
| `Get-WthExitCode` | Map a result to the exit code. |
| `Get-WthRule`, `Test-WthRule` | List or validate rules. |
| `Get-WthConfiguration`, `Test-WthConfiguration` | Load or validate configuration. |
| `Get-WthSuppression` | Load and validate a suppression file. |
| `Test-WthEnvironment` | Describe platform, elevation, rule validity and collector readiness without collecting anything. |

Use `Get-Help <command> -Full` for details and examples.

## Reports

All three formats are written together by default, with names like `windows-threat-hunter-<host>-<timestamp>.json`.

- **JSON**: `{ReportFormatVersion, GeneratedAt, Result}`. `Result` has `Host`, `DataOrigin` (Live, Snapshot or Synthetic), `CollectedAt`, `Coverage`, `CoverageGaps`, `RulesExecuted`, `RulesSkipped`, `Findings`, `SuppressedFindings`, `Summary`, `AttackSummary`, `Warnings` and `Limitations`.
- **CSV**: one row per finding with the core fields. Cells beginning with `=`, `+`, `-` or `@` are prefixed so spreadsheets do not treat them as formulas.
- **HTML**: one self-contained page with summary, coverage, findings and limitations. Values are HTML-encoded, there is no script, and a Content-Security-Policy meta tag forbids it. Synthetic data is bannered.

Treat reports like the snapshots they come from: they may contain host names, account tags and command lines even after redaction.

## Typical workflows

1. **Triage one host.** Run as a standard user, read the coverage gaps, then decide whether to re-run elevated.
2. **Collect now, analyse later.** `-ExportSnapshotPath` on the host, copy the snapshot to an analysis machine, then `-SnapshotPath` there.
3. **Fleet noise reduction.** Keep an organization config and suppression file in version control; every suppression has an ID, rule, written reason, match criteria and optional expiry.
4. **Regression check.** Run `-ValidateOnly` and the test suite after changing rules or configuration.
