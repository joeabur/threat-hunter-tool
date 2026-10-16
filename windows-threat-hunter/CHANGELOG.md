# Changelog

## 1.0.0

First release.

- Read-only collectors for scheduled tasks, services, Run/RunOnce keys, startup folders, WMI event subscriptions, local accounts and groups, processes, network connections, Defender status and events, and Security, PowerShell and Sysmon event logs.
- Optional import of a Defender XDR export (JSON or CSV).
- 42 declarative rules with stable IDs, separate severity and confidence, ATT&CK references, false-positive guidance and next steps.
- Configuration, exclusions and suppressions with required written reasons.
- JSON, CSV and HTML reports with coverage reporting and a synthetic-data banner.
- Exit codes 0 to 4, where 3 means "no findings, but the endpoint cannot be called clean".
- Pester tests with synthetic fixtures, PSScriptAnalyzer settings, and CI workflows with pinned actions.
