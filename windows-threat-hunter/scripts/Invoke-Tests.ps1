#Requires -Version 5.1
<#
.SYNOPSIS
    Runs the Pester test suite (portable unit tests everywhere; Windows-only integration tests only on Windows).

.PARAMETER Suite
    Unit, Integration or All (default). Integration tests that need Windows or elevation skip themselves elsewhere
    and say so in the output; they are never silently counted as passed.

.PARAMETER ResultPath
    Optional NUnit XML result file (for CI).

.EXAMPLE
    ./scripts/Invoke-Tests.ps1 -Suite Unit
#>
[CmdletBinding()]
param(
    [ValidateSet('Unit', 'Integration', 'All')][string]$Suite = 'All',
    [string]$ResultPath
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$pester = Get-Module -ListAvailable -Name Pester | Where-Object { $_.Version -ge [version]'5.5.0' } | Sort-Object Version -Descending | Select-Object -First 1
if (-not $pester) {
    Write-Output 'Pester 5.5 or later is not installed. Install-Module Pester -RequiredVersion 5.7.1 -Scope CurrentUser'
    exit 2
}
Import-Module $pester -Force
$paths = switch ($Suite) {
    'Unit' { @(Join-Path (Join-Path $root 'tests') 'Unit') }
    'Integration' { @(Join-Path (Join-Path $root 'tests') 'Integration') }
    default { @((Join-Path (Join-Path $root 'tests') 'Unit'), (Join-Path (Join-Path $root 'tests') 'Integration')) }
}
$cfg = New-PesterConfiguration
$cfg.Run.Path = $paths
$cfg.Run.PassThru = $true
$cfg.Output.Verbosity = 'Minimal'
if ($ResultPath) {
    $cfg.TestResult.Enabled = $true
    $cfg.TestResult.OutputPath = $ResultPath
}
$r = Invoke-Pester -Configuration $cfg
Write-Output ("Passed {0}, failed {1}, skipped {2}, not run {3}" -f $r.PassedCount, $r.FailedCount, $r.SkippedCount, $r.NotRunCount)
if ($r.FailedCount -gt 0 -or $r.FailedContainersCount -gt 0) { exit 1 }
exit 0
