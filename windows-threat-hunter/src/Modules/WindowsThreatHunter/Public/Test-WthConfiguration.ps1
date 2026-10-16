function Test-WthConfiguration {
    <#
    .SYNOPSIS
        Validates a configuration file (or the defaults) without running a hunt.

    .DESCRIPTION
        Returns an object with IsValid, Errors and Warnings. Unlike Get-WthConfiguration this command does not
        throw for invalid content; it reports the problems so they can be fixed before a hunt.

    .PARAMETER Path
        Optional JSON override file to validate on top of the defaults.

    .EXAMPLE
        Test-WthConfiguration -Path .\config\example-lab.json

    .OUTPUTS
        System.Management.Automation.PSCustomObject
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Position = 0)]
        [string]$Path
    )

    try {
        $defaults = ConvertTo-WthHashtable -InputObject (Read-WthJsonFile -Path $script:WthDefaultConfigFile -Label 'Default configuration')
        $config = $defaults
        if ($PSBoundParameters.ContainsKey('Path')) {
            $user = ConvertTo-WthHashtable -InputObject (Read-WthJsonFile -Path $Path -Label 'Configuration file' -MaxBytes ([long]$defaults.limits.maxInputFileBytes))
            if ($user -isnot [hashtable]) {
                return [pscustomobject]@{ IsValid = $false; Errors = @('Configuration file must contain a JSON object.'); Warnings = @() }
            }
            $config = Merge-WthHashtable -Base $defaults -Override $user
        }
        return (Test-WthConfigurationData -Config $config)
    }
    catch {
        return [pscustomobject]@{ IsValid = $false; Errors = @($_.Exception.Message); Warnings = @() }
    }
}
