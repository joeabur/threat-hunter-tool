function Get-WthConfiguration {
    <#
    .SYNOPSIS
        Loads the Windows Threat Hunter configuration, merges an optional override file and validates it.

    .DESCRIPTION
        The shipped config/default.json is always loaded first. When -Path is given, that file is deep-merged
        on top: objects merge key by key, arrays and scalars replace the default. The merged result is
        validated against the configuration schema and returned as a hashtable.

        Configuration is data only (lists, regular expressions, limits, overrides). It never contains code.

    .PARAMETER Path
        Optional path to a JSON override file (for example config/example-lab.json).

    .EXAMPLE
        $config = Get-WthConfiguration
        $config.collection.eventLookbackHours

    .EXAMPLE
        $config = Get-WthConfiguration -Path .\config\example-lab.json

    .OUTPUTS
        System.Collections.Hashtable

    .NOTES
        Throws System.ArgumentException with every validation error when the configuration is invalid.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Position = 0)]
        [string]$Path
    )

    $defaults = ConvertTo-WthHashtable -InputObject (Read-WthJsonFile -Path $script:WthDefaultConfigFile -Label 'Default configuration')
    $config = $defaults
    if ($PSBoundParameters.ContainsKey('Path')) {
        $maxBytes = [long]$defaults.limits.maxInputFileBytes
        $user = ConvertTo-WthHashtable -InputObject (Read-WthJsonFile -Path $Path -Label 'Configuration file' -MaxBytes $maxBytes)
        if ($user -isnot [hashtable]) {
            throw [System.ArgumentException]::new('Configuration file must contain a JSON object.')
        }
        $config = Merge-WthHashtable -Base $defaults -Override $user
    }
    $validation = Test-WthConfigurationData -Config $config
    if (-not $validation.IsValid) {
        throw [System.ArgumentException]::new("Invalid configuration:`n - " + ($validation.Errors -join "`n - "))
    }
    foreach ($w in $validation.Warnings) { Write-Warning $w }
    Set-WthRegexLimit -MaxInputLength $config.limits.maxRegexInputLength -Confirm:$false
    return $config
}
