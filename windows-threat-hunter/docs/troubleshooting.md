# Troubleshooting

| Symptom | Meaning and what to do |
|---|---|
| Exit code 3 and a list of coverage gaps | Nothing qualifying was found, but some sources were not collected. This is deliberate: it is not a clean result. Fix the gap (see below) or accept and record it. |
| `NeedsElevation` in coverage | The source needs administrator rights (WMI subscriptions, Security log, Defender exclusions). Re-run from an elevated PowerShell that you opened yourself. The tool never elevates itself. |
| `Error` while elevated | Policy or ACLs deny access even to administrators (for example log permissions). The message says what failed. Do not weaken security settings; ask the system owner for approved read access. |
| `Unavailable` for `Event.Sysmon` | Sysmon is not installed, or its log does not exist. The tool does not install it. |
| `Unavailable` for `Event.PowerShell` or no 4104 events | Script block logging is off, or the log rolled over. Enabling logging is a policy decision for the system owner. |
| `Unavailable` for everything on Linux/macOS | Live collection is Windows-only. Use `-SnapshotPath`. |
| Exit code 2: `Rule validation failed` | A rule file is invalid. The message lists the rule and the reason. A bad rule stops the hunt so detection is never silently reduced. Run `-ValidateOnly`. |
| Exit code 2: `Refusing to overwrite existing file` | Report or snapshot already exists. Choose another directory or add `-Force`. |
| Exit code 2: path rejected | Paths with wildcards, `..` segments, URLs, UNC prefixes or alternate data streams are refused, as are protected system directories and symbolic-link output directories. Use a normal local directory. |
| Exit code 2: `Suppression file is invalid` | A suppression needs `SUP-###` ID, an existing rule, a 15+ character reason and a match criterion. |
| `Defender XDR import: Row N skipped` | A malformed or incomplete row was skipped, not guessed. Check the export. |
| Fewer events than expected | Raise `collection.eventLookbackHours` or `maxEventsPerChannel`, and check the log's maximum size and retention. |
| A script is blocked by execution policy | Do not weaken the policy. Use an approved or signed copy as your organization requires. |
| Too many findings from a known-good tool | Add it to the relevant list in your config, or write a suppression with a reason. See [Configuration](configuration.md). |
| HTML report shows unreadable user tags | Redaction is on. Account names are masked on purpose; correlate using the tag. |
| Tests skipped | Windows-only and elevated tests skip on other systems and non-elevated sessions, and are reported as skipped, not passed. |
