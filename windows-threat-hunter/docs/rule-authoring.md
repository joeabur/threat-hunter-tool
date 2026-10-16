# Rule authoring

Rules are JSON data in `src/Rules/*.json` (`{ "schemaVersion": 1, "rules": [ ... ] }`). A rule can only match fields; it cannot run code. Validate with `./scripts/Invoke-WindowsThreatHunter.ps1 -ValidateOnly` or `Test-WthRule`.

## Required properties

`id` (`WTH-<AREA>-<NNN>`), `name`, `version` (semantic), `category`, `dataSource`, `severity`, `confidence`, `findingType` (`Observation` or `Heuristic`), `description`, `rationale`, `evidenceRequirements`, `condition`, `evidenceFields`, `titleTemplate`, `attack` (array of technique IDs, empty when no honest mapping exists), `falsePositives`, `recommendedNextStep`, `remediation`.

Optional: `aggregate`, `references` (https only), `limitations`, `enabled` (set `false` for opt-in rules), `dedupeFields`.

Categories: Persistence, Execution, Network, Accounts, DefenseEvasion, Authentication, Defender, Imported.

Data sources: ScheduledTask, Service, RegistryRun, StartupItem, WmiSubscription, LocalAccount, LocalGroupMember, Process, NetworkConnection, DefenderStatus, DefenderExclusion, DefenderEvent, Event.Security, Event.PowerShell, Event.Sysmon, DefenderXdr.

## Conditions

A condition is a tree of `all`, `any`, `not` and leaf tests `{ "field": "...", "op": "...", "value" | "values" | "list": ... }`, up to 6 levels and 60 nodes. Field names use dotted paths such as `Data.CommandLine`.

Operators: `equals`, `notEquals`, `in`, `notIn`, `contains`, `startsWith`, `endsWith`, `matches` (regular expression), `matchesList` (named pattern list), `inList`, `notInList`, `pathContainsAny`, `pathStartsWithAny`, `exists`, `notExists`, `isTrue`, `isFalse`, `gt`, `gte`, `lt`, `lte`. String comparisons are case-insensitive. Regular expressions are length-limited, screened for catastrophic shapes and timed out.

## Aggregates

`aggregate` counts matches per group inside a sliding time window: `groupBy`, `threshold`, `windowMinutes`, optional `timeField`. See `WTH-EVT-001`.

## Writing a good rule

- Pick honest **confidence**. Severity is impact if real; confidence is likelihood. A path heuristic is usually Low or Medium confidence.
- Use `Observation` only for facts the system states directly; use `Heuristic` for patterns.
- Fill `falsePositives` with real benign causes.
- Say in `evidenceRequirements` what must have been collected, so a rule on an uncollected source is skipped, not treated as clean.
- Map to ATT&CK only when it fits. Add the technique to `config/attack-techniques.json` with its official title and tactics. An empty `attack` array is better than a stretch.
- `remediation` describes what an authorized responder could consider after validation. It must never recommend disabling security controls or weakening execution policy, and the tool never performs it.

## Testing a rule

1. Add at least one scenario that fires and one that does not to `tests/Fixtures/rule-cases.json` (`expect` is the exact finding count).
2. Run `./scripts/Invoke-Tests.ps1 -Suite Unit`.
3. Regenerate the catalog: `./scripts/Export-RuleCatalog.ps1`.
