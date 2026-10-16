# Security and limitations

## What the tool guarantees

- **Read-only.** It reads system state and writes only the reports and snapshots you ask for, to a directory you name. It does not change, stop, disable, delete or repair anything. A unit test fails the build if the module source contains cmdlets that change state, start processes, evaluate strings as code, or use the network.
- **Never executes what it finds.** Discovered paths and command lines are parsed as text. Nothing is launched, loaded or evaluated.
- **No outbound telemetry.** No network calls of any kind. The HTML report contains ordinary links to attack.mitre.org that only your browser follows if you click them; the tool never fetches anything.
- **Inputs are treated as hostile.** Snapshot, rule, configuration, suppression and XDR files are size-limited and schema-validated. Regular expressions are length-limited, screened for catastrophic shapes and run with a timeout. Event XML is parsed with DTDs prohibited and no resolver. Paths with wildcards, parent segments, URLs or UNC prefixes are refused. Existing files are never overwritten without `-Force`, and protected system directories and symbolic-link output directories are refused.
- **Reports are escaped.** HTML values are encoded and the page carries a restrictive Content-Security-Policy meta tag and no script. CSV cells that start with `=`, `+`, `-` or `@` are neutralised.
- **Sensitive values are masked by default.** Secret-looking command-line values are replaced with `[REDACTED]`, and account names are replaced by short stable tags. This is heuristic and cannot catch every secret. Treat reports and snapshots as sensitive.

## What it does not do

- It does not remediate. Each finding includes a *next step* for an analyst to consider; none of it is automated. The text never recommends disabling security tools or weakening execution policy.
- It is not an EDR, antivirus or a substitute for one. It is a point-in-time triage aid.
- It cannot see what it cannot read. Without elevation, without Sysmon, with logging disabled, or with logs that have already rolled over, evidence is missing, and the report says so.
- It does not resolve every indirection. For example, the DLL behind a shared `svchost.exe` service is not resolved, and WMI and COM-handler persistence is only partly covered.
- A kernel-level or otherwise privileged attacker can falsify what Windows reports to a user-mode tool.

## Accuracy

Rules are heuristics. Each finding carries a **severity** (impact if real) and a separate **confidence** (how likely it is to be real). A finding type of *Observation* reports a plain fact (for example "real-time protection is off"); *Heuristic* is a pattern that may be benign. Every rule lists likely false positives in the [catalog](rule-catalog.md). Tune with [exclusions and suppressions](configuration.md), which require a written reason and stay visible in reports.

ATT&CK mappings are references to help triage, not a coverage claim. Several rules deliberately have no mapping because the match would be a stretch. Technique titles in `config/attack-techniques.json` should be re-verified against attack.mitre.org before each release.

## Time

Timestamps are stored as UTC ISO 8601 strings. An event's `ObservedAt` is the event time where one exists; otherwise it is the collection time, and `ObservedAtBasis` says which.

## Platform support

Live collection runs on Windows only. On other platforms every collector reports `Unavailable` and the tool still hunts snapshots. The Windows-only and elevated integration tests are skipped elsewhere and are reported as skipped, never as passed.
