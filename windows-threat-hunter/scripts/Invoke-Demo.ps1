#Requires -Version 5.1
<#
.SYNOPSIS
    Runs the toolkit end to end over the bundled SYNTHETIC snapshots. No live collection, no admin rights.

.DESCRIPTION
    Hunts each sample snapshot, writes JSON/CSV/HTML reports for the lab intrusion scenario, and prints what a
    reader should expect. Everything here is simulated: the hosts, users and "malware" are invented lab data.

.PARAMETER OutputDirectory
    Where to write reports. Default: ./reports/demo under the current directory. Existing files are not
    overwritten unless -Force is given.

.EXAMPLE
    ./scripts/Invoke-Demo.ps1
#>
[CmdletBinding()]
param(
    [string]$OutputDirectory = (Join-Path (Join-Path (Get-Location).Path 'reports') 'demo'),
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path (Join-Path (Join-Path (Join-Path $root 'src') 'Modules') 'WindowsThreatHunter') 'WindowsThreatHunter.psd1') -Force

Write-Output '*** SIMULATED DATA: every snapshot below is synthetic lab data, not a real endpoint ***'
$snapDir = Join-Path (Join-Path $root 'sample-data') 'snapshots'
foreach ($name in 'benign-workstation', 'lab-persistence', 'lab-intrusion') {
    $r = Invoke-WthHunt -SnapshotPath (Join-Path $snapDir "$name.json")
    Write-Output ('{0,-20} findings: {1,2}  (High {2}, Medium {3}, Low {4})  rules run: {5}, skipped: {6}  exit code: {7}' -f
        $name, $r.Summary.ActiveFindings, $r.Summary.BySeverity.High, $r.Summary.BySeverity.Medium, $r.Summary.BySeverity.Low,
        $r.Summary.RulesExecuted, $r.Summary.RulesSkipped, (Get-WthExitCode -Result $r))
}

$result = Invoke-WthHunt -SnapshotPath (Join-Path $snapDir 'lab-intrusion.json') `
    -DefenderXdrPath (Join-Path (Join-Path (Join-Path $root 'sample-data') 'xdr') 'defender-xdr-export.json')
$files = Export-WthReport -Result $result -OutputDirectory $OutputDirectory -IncludeSuppressed -Force:$Force
foreach ($f in $files) { Write-Output "Report written: $f" }
Write-Output 'Demo finished. Exit codes above are for the demo data only; remember that gaps in coverage are not a clean result.'
