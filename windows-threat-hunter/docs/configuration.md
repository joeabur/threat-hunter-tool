# Configuration

The shipped defaults are in `config/default.json`. Pass an override file with `-ConfigPath` (or `Get-WthConfiguration -Path`). Objects merge key by key and arrays replace the default. Unknown keys, wrong types, negative limits and unsafe regular expressions are rejected, and a bad file stops the run with exit code 2. Check a file with:

```powershell
Import-Module ./src/Modules/WindowsThreatHunter/WindowsThreatHunter.psd1
Test-WthConfiguration -Path ./config/example-lab.json
```

## Sections

| Section | What it controls |
|---|---|
| `collection` | Which collectors run, event lookback hours, event and process caps, file metadata level (`None`, `Basic`, `Hash`, `HashAndSignature`), privileged groups to inspect |
| `limits` | Maximum input file size, regex input length, evidence value length, event data length, findings per rule, items per data source |
| `redaction` | Whether to mask secrets and account names, which fields are account names, secret patterns |
| `lists` | Named lists used by rules: user-writable path fragments, trusted prefixes, system process names, script interpreters, Office applications, expected privileged members, expected WMI consumers, and more |
| `patterns` | Named regular-expression lists: encoded PowerShell, download cradles, script host arguments, living-off-the-land abuse, service shell wrappers, suspicious script block content |
| `ruleOverrides` | Per rule: `enabled`, `severity`, `confidence`, and for aggregate rules `threshold` and `windowMinutes` |
| `reporting` | Default formats and whether suppressed findings are included |
| `suppressionFile` | Default suppression file path |

## Exclusions: tune lists, not rules

The best way to remove a known-good pattern is to add it to a list rather than disabling a rule. For example, to accept a lab administrator in privileged groups:

```json
{
  "schemaVersion": 1,
  "lists": { "expectedPrivilegedMembers": ["Administrator", "Domain Admins", "LabAdmin"] }
}
```

Because arrays replace defaults, copy the default entries you still want.

## Rule overrides

```json
{
  "schemaVersion": 1,
  "ruleOverrides": {
    "WTH-EVT-001": { "threshold": 5, "windowMinutes": 15 },
    "WTH-PROC-001": { "severity": "Low" },
    "WTH-NET-003": { "enabled": true }
  }
}
```

Overrides applied to a finding are recorded in its `ConfigOverrides` field. `WTH-NET-003` ships disabled; enable it deliberately. See `config/example-lab.json`.

## Suppressions

A suppression records an analyst decision for one rule and specific matching evidence. See `config/suppressions.example.json`.

| Field | Rule |
|---|---|
| `id` | `SUP-` followed by digits, for example `SUP-001` |
| `ruleId` | An existing rule ID |
| `reason` | A written justification of at least 15 characters |
| `match` | At least one field/value criterion (exact, case-insensitive) |
| `createdBy`, `expires` | Optional; an expired suppression no longer applies |

Suppressed findings are not deleted. They appear in the reports with the suppression ID and reason and are excluded only from active counts and exit codes. Validate with `Get-WthSuppression -Path <file>` (it returns `Suppressions` and `Errors`) or `-ValidateOnly -SuppressionPath <file>`.

## Redaction

With redaction on (the default), secret-looking values in command lines become `[REDACTED]`, and account names become stable tags like `<user:17c0d5>` so the same account is recognisable across findings without revealing it. Well-known principals such as `NT AUTHORITY\SYSTEM` stay readable. Redaction is heuristic; it is not a guarantee, and snapshots are not redacted unless you export with `-Redact`.
