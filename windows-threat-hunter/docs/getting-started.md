# Getting started

## Requirements

- Windows PowerShell 5.1 or PowerShell 7 or later.
- To hunt a **live host**: Windows. Some sources need an elevated session (see [Elevation](walkthrough.md#elevation-what-needs-it-and-what-happens-without-it)).
- To hunt a **saved or synthetic snapshot**: any operating system.
- To run the tests: Pester 5.7.1. For static analysis: PSScriptAnalyzer 1.23.0 (see `RequiredModules.psd1`).

You never need to change your execution policy for this tool. If scripts are blocked in your environment, ask your administrator how to run signed or approved scripts. Do not weaken the policy to run this.

## Get the code

```powershell
git clone https://github.com/joeabur/threat-hunter-tool.git
Set-Location ./threat-hunter-tool/windows-threat-hunter
```

## First run on simulated data

```powershell
./scripts/Invoke-WindowsThreatHunter.ps1 -ValidateOnly
./scripts/Invoke-Demo.ps1
```

`-ValidateOnly` checks the configuration and all rules and exits. The demo hunts three synthetic snapshots and writes example reports to `./reports/demo`. Everything it prints is simulated.

## Your first live run

Open PowerShell as a normal user first. This is read-only and collects what a standard user may read:

```powershell
./scripts/Invoke-WindowsThreatHunter.ps1 -OutputDirectory ./reports
```

Read the **coverage gaps** section before the findings. Sources that need elevation will say `NeedsElevation`. To include them, repeat the run from an elevated session that you opened deliberately. The tool never asks to elevate itself.

To keep the raw evidence for later analysis, add `-ExportSnapshotPath ./snapshots/host.json`. A snapshot contains command lines and account names. Handle it as sensitive evidence, and see `.gitignore` for the folders that are excluded from version control.

## Use it as a module

```powershell
Import-Module ./src/Modules/WindowsThreatHunter/WindowsThreatHunter.psd1
$result = Invoke-WthHunt -SnapshotPath ./sample-data/snapshots/lab-persistence.json
$result.Findings | Select-Object Severity, Confidence, RuleId, Title
Export-WthReport -Result $result -OutputDirectory ./reports
```

## Next steps

- Work through the [walkthrough](walkthrough.md).
- Tune noise with the [configuration guide](configuration.md).
- Read [security and limitations](security-and-limitations.md).
