#Requires -Version 5.1
<#
.SYNOPSIS
    Runs PSScriptAnalyzer over the project with the pinned settings. Read-only.

.DESCRIPTION
    Exits 0 when there are no Error or Warning findings, 1 when there are, and 2 when PSScriptAnalyzer is not
    installed (so a missing analyzer is never reported as a pass). Install it with:
    Install-Module PSScriptAnalyzer -RequiredVersion 1.23.0 -Scope CurrentUser

.EXAMPLE
    ./scripts/Invoke-Lint.ps1
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$mod = Get-Module -ListAvailable -Name PSScriptAnalyzer | Sort-Object Version -Descending | Select-Object -First 1
if (-not $mod) {
    Write-Output 'PSScriptAnalyzer is not installed: static analysis did NOT run.'
    exit 2
}
Import-Module $mod -Force
$settings = Join-Path $root 'PSScriptAnalyzerSettings.psd1'
$results = foreach ($dir in 'src', 'scripts', 'tests') {
    Invoke-ScriptAnalyzer -Path (Join-Path $root $dir) -Recurse -Settings $settings
}
$results = @($results)
foreach ($r in $results) {
    Write-Output ('{0}:{1} [{2}] {3}: {4}' -f $r.ScriptName, $r.Line, $r.Severity, $r.RuleName, $r.Message)
}
Write-Output ("PSScriptAnalyzer {0}: {1} finding(s)." -f $mod.Version, $results.Count)
if ($results.Count -gt 0) { exit 1 }
exit 0
