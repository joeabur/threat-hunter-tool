function Get-WthSuppression {
    <#
    .SYNOPSIS
        Loads and validates a suppression file.

    .DESCRIPTION
        A suppression marks matching findings as accepted. It needs an ID, a rule ID, a written reason of at
        least 15 characters and at least one match criterion (field equals a value, or matches a bounded regular
        expression). It can expire. Suppressed findings remain visible in reports with their reason; they are
        only excluded from active counts and exit codes.

    .PARAMETER Path
        Path to the suppression JSON file (see config/suppressions.example.json).

    .EXAMPLE
        Get-WthSuppression -Path .\config\suppressions.example.json

    .OUTPUTS
        PSCustomObject with Suppressions and Errors.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, Position = 0)][string]$Path
    )

    Get-WthSuppressionData -Path $Path
}
