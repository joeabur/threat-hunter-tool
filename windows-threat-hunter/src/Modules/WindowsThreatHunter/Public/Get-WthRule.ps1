function Get-WthRule {
    <#
    .SYNOPSIS
        Lists the detection rules in the catalog.

    .DESCRIPTION
        Loads the versioned rule files from src/Rules (or -Path), validates them and returns a summary object per
        valid rule. Use -Full to return the complete rule definitions including conditions. Rules that fail
        validation are reported with a warning and are not returned; run Test-WthRule for details.

    .PARAMETER Path
        Rule file or directory. Defaults to the shipped src/Rules directory.

    .PARAMETER Id
        One or more rule IDs (wildcards allowed), for example WTH-TASK-*.

    .PARAMETER Category
        Filter by category (Persistence, Execution, Network, Accounts, Authentication, Defender, DefenseEvasion, Imported).

    .PARAMETER DataSource
        Filter by required data source (ScheduledTask, Service, Event.Security, ...).

    .PARAMETER ConfigPath
        Optional configuration override file (rules are validated against its lists and patterns).

    .PARAMETER Full
        Return full rule definitions instead of summaries.

    .EXAMPLE
        Get-WthRule | Format-Table RuleId, Severity, Confidence, Name

    .EXAMPLE
        Get-WthRule -Id 'WTH-SVC-*' -Full
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Position = 0)][string]$Path = $script:WthRulesPath,
        [string[]]$Id,
        [string[]]$Category,
        [string[]]$DataSource,
        [string]$ConfigPath,
        [switch]$Full
    )

    $config = if ($PSBoundParameters.ContainsKey('ConfigPath')) { Get-WthConfiguration -Path $ConfigPath } else { Get-WthConfiguration }
    $set = Import-WthRuleSet -Path $Path -Config $config
    foreach ($r in $set.Results | Where-Object { -not $_.IsValid }) {
        Write-Warning "Rule '$($r.RuleId)' in $($r.Source) is invalid and was skipped: $($r.Errors -join '; ')"
    }
    foreach ($rule in $set.Rules) {
        if ($Id -and -not ($Id | Where-Object { $rule.id -like $_ })) { continue }
        if ($Category -and $rule.category -notin $Category) { continue }
        if ($DataSource -and $rule.dataSource -notin $DataSource) { continue }
        if ($Full) { $rule; continue }
        $enabled = $true
        if (Test-WthHasMember -InputObject $rule -Name 'enabled') { $enabled = [bool]$rule.enabled }
        [pscustomobject][ordered]@{
            RuleId      = $rule.id
            Name        = $rule.name
            Version     = $rule.version
            Category    = $rule.category
            DataSource  = $rule.dataSource
            Severity    = $rule.severity
            Confidence  = $rule.confidence
            FindingType = $rule.findingType
            Attack      = @($rule.attack)
            Enabled     = $enabled
            Description = $rule.description
        }
    }
}
