function Test-WthRule {
    <#
    .SYNOPSIS
        Validates detection rule files against the rule schema.

    .DESCRIPTION
        Checks every rule for required properties, ID and version formats, enumerated values, ATT&CK technique IDs
        (they must exist in the shipped catalog), title template placeholders, condition structure (operators,
        referenced lists and patterns, depth and size limits), bounded regular expressions, aggregation settings
        and duplicate IDs. Returns one result object per rule; nothing is executed.

    .PARAMETER Path
        Rule file or directory. Defaults to the shipped src/Rules directory.

    .PARAMETER ConfigPath
        Optional configuration override file whose lists and patterns the rules may reference.

    .EXAMPLE
        Test-WthRule | Where-Object { -not $_.IsValid }

    .OUTPUTS
        PSCustomObject with RuleId, Source, IsValid and Errors.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Position = 0)][string]$Path = $script:WthRulesPath,
        [string]$ConfigPath
    )

    $config = if ($PSBoundParameters.ContainsKey('ConfigPath')) { Get-WthConfiguration -Path $ConfigPath } else { Get-WthConfiguration }
    $set = Import-WthRuleSet -Path $Path -Config $config
    $set.Results
}
