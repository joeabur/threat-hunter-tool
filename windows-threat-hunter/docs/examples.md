# Examples

All examples run from the `windows-threat-hunter` folder. Examples that use `sample-data/` are simulated.

## Validate everything

```powershell
./scripts/Invoke-WindowsThreatHunter.ps1 -ValidateOnly
```

## List the rules

```powershell
./scripts/Invoke-WindowsThreatHunter.ps1 -ListRules
```

## Hunt a snapshot and write all reports

```powershell
./scripts/Invoke-WindowsThreatHunter.ps1 -SnapshotPath ./sample-data/snapshots/lab-intrusion.json -OutputDirectory ./reports/example
```

## Only persistence rules at Medium or above

```powershell
./scripts/Invoke-WindowsThreatHunter.ps1 -SnapshotPath ./sample-data/snapshots/lab-persistence.json -Category Persistence -MinimumSeverity Medium
```

## Fail a pipeline only on High findings

```powershell
./scripts/Invoke-WindowsThreatHunter.ps1 -SnapshotPath ./sample-data/snapshots/lab-intrusion.json -FailOnSeverity High
Write-Output "exit code: $LASTEXITCODE"
```

## Collect a snapshot on a Windows host, analyse it elsewhere

On the host (read-only):

```powershell
./scripts/Invoke-WindowsThreatHunter.ps1 -ExportSnapshotPath ./snapshots/host01.json
```

On the analysis machine:

```powershell
./scripts/Invoke-WindowsThreatHunter.ps1 -SnapshotPath ./snapshots/host01.json -OutputDirectory ./reports
```

## Narrow a live run to cheap, non-elevated sources

```powershell
./scripts/Invoke-WindowsThreatHunter.ps1 -Collector ScheduledTasks, Services, RegistryRun, StartupFolders
```

Because other sources are not collected, the result will be exit code 1 or 3, never a clean 0.

## Merge a Defender XDR export

```powershell
./scripts/Invoke-WindowsThreatHunter.ps1 -SnapshotPath ./sample-data/snapshots/lab-intrusion.json -DefenderXdrPath ./sample-data/xdr/defender-xdr-export.json
```

## Use the module in a script

```powershell
Import-Module ./src/Modules/WindowsThreatHunter/WindowsThreatHunter.psd1
$result = Invoke-WthHunt -SnapshotPath ./sample-data/snapshots/lab-persistence.json
$result.Findings | Group-Object Severity | Select-Object Name, Count
$result.CoverageGaps | Select-Object DataSource, Status
Get-WthExitCode -Result $result
```

## Tune a noisy rule

```powershell
./scripts/Invoke-WindowsThreatHunter.ps1 -SnapshotPath ./sample-data/snapshots/lab-intrusion.json -ConfigPath ./config/example-lab.json
```

## Run the demo, tests and static analysis

```powershell
./scripts/Invoke-Demo.ps1
./scripts/Invoke-Tests.ps1 -Suite Unit
./scripts/Invoke-Lint.ps1
```
