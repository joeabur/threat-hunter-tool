# Contributing

Thanks for helping. This project is a read-only detection toolkit, so the most important rule is: **a contribution must never make the tool change, stop, disable, delete, execute or transmit anything.**

## Setup

You need PowerShell 7 (Windows, Linux or macOS) or Windows PowerShell 5.1. Development dependencies are pinned in `RequiredModules.psd1`:

```powershell
Install-Module Pester -RequiredVersion 5.7.1 -Scope CurrentUser -Force -SkipPublisherCheck
Install-Module PSScriptAnalyzer -RequiredVersion 1.23.0 -Scope CurrentUser -Force
```

## Before you open a pull request

```powershell
./scripts/Invoke-Tests.ps1 -Suite All
./scripts/Invoke-Lint.ps1
./scripts/Export-RuleCatalog.ps1
```

`Export-RuleCatalog.ps1` regenerates `docs/rule-catalog.md`; commit the result when you change a rule. CI fails if the catalog is out of date.

## Code standards

- Approved verbs, comment-based help on every exported function, explicit error handling with `-ErrorAction Stop` inside `try`/`catch`.
- Code must run on Windows PowerShell 5.1 and PowerShell 7: no `??`, no `?.`, no `ConvertFrom-Json -AsHashtable`, and store timestamps as ISO 8601 strings.
- Wrap each system call in a small `Get-WthRaw*` function in `src/Private/Wrappers.ps1` so tests can mock it.
- No `Invoke-Expression`, no `Start-Process`, no network cmdlets, no cmdlets that change state.
- Treat every input as hostile: snapshot, rules, config, suppressions, XDR exports and event data.

## Adding or changing a rule

See [docs/rule-authoring.md](docs/rule-authoring.md). Every rule needs a positive and a negative scenario in `tests/Fixtures/rule-cases.json`, an honest confidence, false-positive guidance, and a next step that never advises disabling security tools or weakening execution policy.

## Test data

Use only synthetic data. Do not commit real host names, users, IP addresses (use RFC 5737 ranges such as 198.51.100.0/24 and 203.0.113.0/24), hashes of real malware, or captured incident data.

## Pull requests

Keep them focused, say what you ran, and say what you could not run (for example, Windows-only or elevated tests).
