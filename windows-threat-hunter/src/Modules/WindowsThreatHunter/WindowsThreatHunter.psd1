@{
    RootModule            = 'WindowsThreatHunter.psm1'
    ModuleVersion         = '1.0.0'
    GUID                  = '6f0b8d5e-3c1a-4d7b-9e42-5a8c1f7d2b90'
    Author                = 'Windows Threat Hunter contributors'
    CompanyName           = 'Community'
    Copyright             = '(c) Windows Threat Hunter contributors. MIT License.'
    Description           = 'Read-only Windows threat hunting and persistence checker with transparent, versioned detection rules, evidence-backed findings and JSON/CSV/HTML reports.'
    PowerShellVersion     = '5.1'
    CompatiblePSEditions  = @('Desktop', 'Core')
    FunctionsToExport     = @(
        'Export-WthReport'
        'Export-WthSnapshot'
        'Get-WthConfiguration'
        'Get-WthExitCode'
        'Get-WthRule'
        'Get-WthSuppression'
        'Import-WthDefenderXdrEvent'
        'Import-WthSnapshot'
        'Invoke-WthCollection'
        'Invoke-WthHunt'
        'Test-WthConfiguration'
        'Test-WthEnvironment'
        'Test-WthRule'
    )
    CmdletsToExport       = @()
    VariablesToExport     = @()
    AliasesToExport       = @()
    PrivateData           = @{
        PSData = @{
            Tags       = @('ThreatHunting', 'Persistence', 'DFIR', 'BlueTeam', 'Windows', 'MITRE-ATTACK', 'ReadOnly')
            LicenseUri = 'https://github.com/joeabur/threat-hunter-tool/blob/main/windows-threat-hunter/LICENSE'
            ProjectUri = 'https://github.com/joeabur/threat-hunter-tool'
        }
    }
}
