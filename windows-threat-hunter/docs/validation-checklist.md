# Validation checklist

Use this list to verify a build. The "Status" column records what was actually done when this version was prepared; it is not a promise about your environment.

## Automated

| Check | Command | Status when prepared |
|---|---|---|
| Unit tests (portable) | `./scripts/Invoke-Tests.ps1 -Suite Unit` | Run on PowerShell 7.6.7 on Linux |
| Integration tests, portable (CLI, demo, exit codes) | `./scripts/Invoke-Tests.ps1 -Suite Integration` | Run on PowerShell 7.6.7 on Linux |
| Integration tests, Windows-only live collection | same command on Windows | **Not run** (no Windows host was available). They skip elsewhere and say so. |
| Integration tests, elevated live collection | same command in an elevated session | **Not run** |
| Windows PowerShell 5.1 | CI job `windows-powershell-5-1` | **Not run locally**; defined in CI |
| PSScriptAnalyzer | `./scripts/Invoke-Lint.ps1` | **Not run locally** (module could not be installed in the build environment); defined in CI |
| Rule catalog is current | `./scripts/Export-RuleCatalog.ps1 -Check` | Run |
| Configuration and rules valid | `./scripts/Invoke-WindowsThreatHunter.ps1 -ValidateOnly` | Run |
| Docs, links, commands and schemas consistent | Part of the unit tests (`Docs.Tests.ps1`) | Run |

## Manual, on a Windows test machine

1. Run as a standard user: `./scripts/Invoke-WindowsThreatHunter.ps1 -OutputDirectory ./reports`. Expect exit 3 or 1 with `NeedsElevation` gaps, never 0 if any source was uncollected.
2. Repeat from an elevated session. Gaps for WMI, Security log and Defender exclusions should turn into `Collected` (or an honest `Error`/`Unavailable`).
3. Compare with the system: spot-check three findings against Task Scheduler, `services.msc` and Autoruns.
4. Confirm nothing changed: the tool writes only to the output directory.
5. Open the HTML report; confirm no script runs and the data is correctly escaped.
6. Create a harmless lab persistence item (for example a scheduled task running `notepad.exe` from a temp folder), confirm the matching rule fires, then remove it yourself.
7. Check that PowerShell 5.1 and 7 give equivalent results.

## Needs independent verification

- MITRE ATT&CK technique titles and tactics in `config/attack-techniques.json` (re-verify against attack.mitre.org).
- Microsoft documentation links in rule `references`.
- Real-world false-positive rates; only synthetic data was used.
