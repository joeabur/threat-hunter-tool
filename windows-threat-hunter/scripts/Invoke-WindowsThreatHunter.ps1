#Requires -Version 5.1
<#
.SYNOPSIS
    Command-line entry point for the Windows Threat Hunter module with predictable exit codes.

.DESCRIPTION
    Imports the module from this repository, runs a read-only hunt (live on Windows, or over a saved or
    synthetic snapshot on any OS), prints a summary, optionally writes JSON/CSV/HTML reports, and exits with:

      0  completed; no active findings at or above -FailOnSeverity; every data source collected
      1  at least one active finding at or above -FailOnSeverity
      2  invalid input, configuration, rules, suppression file or path (nothing was hunted)
      3  no qualifying findings, but data sources were not fully collected or rules were skipped
         (the endpoint cannot be called clean)
      4  unexpected error

    The script never modifies the system being inspected. Reports are written only to -OutputDirectory.

.PARAMETER SnapshotPath
    Saved or synthetic snapshot to hunt over. Without it, a live read-only collection is run (Windows only).

.PARAMETER ExportSnapshotPath
    Live mode only: also save the raw snapshot to this .json file (treat it as sensitive evidence).

.PARAMETER DefenderXdrPath
    Optional Defender XDR export (.json or .csv) to merge into the hunt.

.PARAMETER ValidateOnly
    Validate configuration, rules and the suppression file, then exit (0 valid, 2 invalid).

.PARAMETER ListRules
    List rules and exit.

.EXAMPLE
    .\scripts\Invoke-WindowsThreatHunter.ps1 -SnapshotPath .\sample-data\snapshots\lab-persistence.json -OutputDirectory .\reports

.EXAMPLE
    .\scripts\Invoke-WindowsThreatHunter.ps1 -ValidateOnly

.EXAMPLE
    .\scripts\Invoke-WindowsThreatHunter.ps1 -Collector ScheduledTasks, Services, RegistryRun -MinimumSeverity Medium
#>
[CmdletBinding()]
param(
    [string]$SnapshotPath,
    [string]$ExportSnapshotPath,
    [string]$DefenderXdrPath,
    [string]$ConfigPath,
    [string]$RulePath,
    [string]$SuppressionPath,
    [ValidateSet('ScheduledTasks', 'Services', 'RegistryRun', 'StartupFolders', 'WmiSubscriptions', 'LocalAccounts', 'Processes', 'Network', 'Defender', 'SecurityEvents', 'PowerShellEvents', 'SysmonEvents')]
    [string[]]$Collector,
    [string[]]$RuleId,
    [string[]]$Category,
    [ValidateSet('Informational', 'Low', 'Medium', 'High', 'Critical')][string]$MinimumSeverity = 'Informational',
    [ValidateSet('Informational', 'Low', 'Medium', 'High', 'Critical')][string]$FailOnSeverity = 'Medium',
    [string]$OutputDirectory,
    [ValidateSet('Json', 'Csv', 'Html')][string[]]$Format = @('Json', 'Csv', 'Html'),
    [switch]$ValidateOnly,
    [switch]$ListRules,
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$manifest = Join-Path (Join-Path (Join-Path (Join-Path $repoRoot 'src') 'Modules') 'WindowsThreatHunter') 'WindowsThreatHunter.psd1'

function Exit-Wth {
    param([int]$Code)
    exit $Code
}

try {
    Import-Module $manifest -Force

    if ($ValidateOnly -or $ListRules) {
        $cfgArgs = @{}
        if ($ConfigPath) { $cfgArgs['Path'] = $ConfigPath }
        $config = Test-WthConfiguration @cfgArgs
        foreach ($w in $config.Warnings) { Write-Output "WARNING: $w" }
        if (-not $config.IsValid) {
            foreach ($e in $config.Errors) { Write-Output "CONFIG ERROR: $e" }
            Exit-Wth 2
        }
        $ruleArgs = @{}
        if ($RulePath) { $ruleArgs['Path'] = $RulePath }
        if ($ConfigPath) { $ruleArgs['ConfigPath'] = $ConfigPath }
        if ($ListRules) {
            Get-WthRule @ruleArgs | Format-Table RuleId, Severity, Confidence, FindingType, DataSource, Name -AutoSize | Out-String -Width 200 | Write-Output
            Exit-Wth 0
        }
        $results = @(Test-WthRule @ruleArgs)
        $bad = @($results | Where-Object { -not $_.IsValid })
        foreach ($b in $bad) { Write-Output "RULE ERROR: $($b.RuleId) ($($b.Source)): $($b.Errors -join '; ')" }
        if ($SuppressionPath) {
            $sup = Get-WthSuppression -Path $SuppressionPath
            foreach ($e in $sup.Errors) { Write-Output "SUPPRESSION ERROR: $e" }
            if ($sup.Errors.Count -gt 0) { Exit-Wth 2 }
        }
        Write-Output "Validated configuration and $($results.Count) rule(s): $($bad.Count) invalid."
        if ($bad.Count -gt 0) { Exit-Wth 2 }
        Exit-Wth 0
    }

    $hunt = @{ MinimumSeverity = $MinimumSeverity }
    if ($ConfigPath) { $hunt['ConfigPath'] = $ConfigPath }
    if ($RulePath) { $hunt['RulePath'] = $RulePath }
    if ($RuleId) { $hunt['RuleId'] = $RuleId }
    if ($Category) { $hunt['Category'] = $Category }
    if ($SuppressionPath) { $hunt['SuppressionPath'] = $SuppressionPath }
    if ($DefenderXdrPath) { $hunt['DefenderXdrPath'] = $DefenderXdrPath }

    if ($SnapshotPath) {
        $result = Invoke-WthHunt -SnapshotPath $SnapshotPath @hunt
    }
    else {
        $onWindows = ($PSVersionTable.PSEdition -eq 'Desktop') -or ([System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT)
        if (-not $onWindows) {
            Write-Output 'ERROR: live collection requires Windows. Pass -SnapshotPath to hunt over a saved or synthetic snapshot.'
            Exit-Wth 2
        }
        $collectArgs = @{}
        if ($ConfigPath) { $collectArgs['ConfigPath'] = $ConfigPath }
        if ($Collector) { $collectArgs['Collector'] = $Collector }
        $snapshot = Invoke-WthCollection @collectArgs
        if ($ExportSnapshotPath) {
            $saved = Export-WthSnapshot -Snapshot $snapshot -Path $ExportSnapshotPath -Force:$Force
            Write-Output "Snapshot saved to $saved (contains raw command lines and account names: handle as sensitive evidence)."
        }
        $result = Invoke-WthHunt -Snapshot $snapshot @hunt
    }

    if ($result.DataOrigin -eq 'Synthetic') { Write-Output '*** SIMULATED DATA: synthetic snapshot, not a real endpoint ***' }
    Write-Output ("Host: {0}   Collected: {1}   Origin: {2}" -f $result.Host, $result.CollectedAt, $result.DataOrigin)
    Write-Output ("Rules executed: {0}   skipped: {1}   Items analyzed: {2}" -f $result.Summary.RulesExecuted, $result.Summary.RulesSkipped, $result.Summary.ItemsAnalyzed)
    Write-Output ("Active findings: {0}   Suppressed: {1}   (Critical {2}, High {3}, Medium {4}, Low {5}, Informational {6})" -f
        $result.Summary.ActiveFindings, $result.Summary.SuppressedFindings, $result.Summary.BySeverity.Critical, $result.Summary.BySeverity.High,
        $result.Summary.BySeverity.Medium, $result.Summary.BySeverity.Low, $result.Summary.BySeverity.Informational)
    if (@($result.Findings).Count -gt 0) {
        $result.Findings | Select-Object Severity, Confidence, FindingType, RuleId, Title | Format-Table -AutoSize -Wrap | Out-String -Width 220 | Write-Output
    }
    if (@($result.CoverageGaps).Count -gt 0) {
        Write-Output 'Coverage gaps (these sources were NOT fully evaluated; absence of findings is not evidence of a clean endpoint):'
        $result.CoverageGaps | ForEach-Object { Write-Output ("  - {0}: {1}" -f $_.DataSource, $_.Status) }
    }
    foreach ($w in $result.Warnings) { Write-Output "WARNING: $w" }

    if ($OutputDirectory) {
        $files = Export-WthReport -Result $result -OutputDirectory $OutputDirectory -Format $Format -IncludeSuppressed -Force:$Force
        foreach ($f in $files) { Write-Output "Report written: $f" }
    }
    $code = Get-WthExitCode -Result $result -FailOnSeverity $FailOnSeverity
    Write-Output "Exit code: $code"
    Exit-Wth $code
}
catch [System.ArgumentException], [System.IO.IOException], [System.Management.Automation.ParameterBindingException] {
    Write-Output "ERROR: $($_.Exception.Message)"
    Exit-Wth 2
}
catch {
    Write-Output "UNEXPECTED ERROR: $($_.Exception.Message)"
    Write-Output $_.ScriptStackTrace
    Exit-Wth 4
}
