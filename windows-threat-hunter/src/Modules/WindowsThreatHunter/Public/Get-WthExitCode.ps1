function Get-WthExitCode {
    <#
    .SYNOPSIS
        Maps a hunt result to the toolkit's documented exit code.

    .DESCRIPTION
        0 - completed, no active findings at or above -FailOnSeverity, and every data source was collected.
        1 - at least one active finding at or above -FailOnSeverity.
        3 - no qualifying findings, but one or more data sources were not fully collected or rules were skipped,
            so the endpoint cannot be called clean. Rules that are disabled or depend on an
            optional import (Defender XDR) do not count as gaps.
        Codes 2 (invalid input, configuration or rules) and 4 (unexpected error) are produced by
        scripts/Invoke-WindowsThreatHunter.ps1 when a terminating error occurs.

    .PARAMETER Result
        Object returned by Invoke-WthHunt.

    .PARAMETER FailOnSeverity
        Lowest severity that counts as a finding for exit code 1. Default: Medium.

    .EXAMPLE
        $result = Invoke-WthHunt -SnapshotPath .\sample-data\snapshots\suspicious-persistence.json
        Get-WthExitCode -Result $result
    #>
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [Parameter(Mandatory, Position = 0)]$Result,
        [ValidateSet('Informational', 'Low', 'Medium', 'High', 'Critical')]
        [string]$FailOnSeverity = 'Medium'
    )

    $threshold = Get-WthSeverityRank -Severity $FailOnSeverity
    foreach ($f in @($Result.Findings)) {
        if ((Get-WthSeverityRank -Severity $f.Severity) -ge $threshold) { return 1 }
    }
    if (@($Result.CoverageGaps).Count -gt 0 -or @($Result.RulesSkipped | Where-Object { -not $_.Optional }).Count -gt 0) { return 3 }
    return 0
}
