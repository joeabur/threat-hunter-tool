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
$mods = @(Get-Module -ListAvailable -Name PSScriptAnalyzer | Sort-Object Version -Descending)
$mod = @($mods | Where-Object { $_.Version -eq [version]'1.23.0' })[0]
if (-not $mod) { $mod = $mods[0] }
if (-not $mod) {
    Write-Output 'PSScriptAnalyzer is not installed: static analysis did NOT run.'
    exit 2
}
Import-Module $mod -Force
$settings = Join-Path $root 'PSScriptAnalyzerSettings.psd1'
$results = foreach ($dir in 'src', 'scripts') {
    Invoke-ScriptAnalyzer -Path (Join-Path $root $dir) -Recurse -Settings $settings
}
# Pester discovery variables look unused to the analyzer, so that one rule is skipped for tests only.
$results += Invoke-ScriptAnalyzer -Path (Join-Path $root 'tests') -Recurse -Settings $settings -ExcludeRule PSUseDeclaredVarsMoreThanAssignments
$results = @($results)
foreach ($r in $results) {
    $where = if ($r.ScriptPath) { $r.ScriptPath } elseif ($r.Extent -and $r.Extent.File) { $r.Extent.File } else { '(no file)' }
    Write-Output ('{0}:{1} [{2}] {3}: {4}' -f $where, $r.Line, $r.Severity, $r.RuleName, $r.Message)
    if (-not $r.RuleName) { Write-Output ($r | Format-List * | Out-String) }
}
Write-Output ("PSScriptAnalyzer {0}: {1} finding(s)." -f $mod.Version, $results.Count)
if ($results.Count -gt 0) { exit 1 }
exit 0
