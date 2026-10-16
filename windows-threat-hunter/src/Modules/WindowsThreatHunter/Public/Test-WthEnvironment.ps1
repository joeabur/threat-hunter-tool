function Test-WthEnvironment {
    <#
    .SYNOPSIS
        Verifies the PowerShell version, platform, privileges, configuration and per-collector readiness.

    .DESCRIPTION
        Read-only pre-flight check. For each collector it reports whether live collection is expected to work in
        the current session (Ready), needs an elevated session (NeedsElevation), works only partly (Partial) or
        cannot work here (Unavailable), with the reason. Nothing is collected and nothing is changed.

    .EXAMPLE
        Test-WthEnvironment | Select-Object -ExpandProperty Collectors | Format-Table

    .OUTPUTS
        PSCustomObject
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    $isWindows = Test-WthIsWindows
    $elevated = Test-WthIsElevated
    $issues = New-Object System.Collections.Generic.List[string]

    $configOk = $true
    try { [void](Get-WthConfiguration -WarningAction SilentlyContinue) }
    catch { $configOk = $false; $issues.Add("Default configuration is invalid: $($_.Exception.Message)") }

    $ruleSummary = $null
    try {
        $results = @(Test-WthRule)
        $bad = @($results | Where-Object { -not $_.IsValid })
        $ruleSummary = [pscustomobject]@{ Total = $results.Count; Invalid = $bad.Count }
        if ($bad.Count -gt 0) { $issues.Add("$($bad.Count) rule(s) failed validation. Run Test-WthRule for details.") }
    }
    catch { $issues.Add("Rules could not be loaded: $($_.Exception.Message)") }

    $needs = [ordered]@{
        ScheduledTasks   = @('Get-ScheduledTask')
        Services         = @('Get-CimInstance')
        RegistryRun      = @()
        StartupFolders   = @()
        WmiSubscriptions = @('Get-CimInstance')
        LocalAccounts    = @('Get-LocalUser', 'Get-LocalGroupMember')
        Processes        = @('Get-CimInstance')
        Network          = @('Get-NetTCPConnection', 'Get-NetUDPEndpoint')
        Defender         = @('Get-MpComputerStatus', 'Get-MpPreference', 'Get-WinEvent')
        SecurityEvents   = @('Get-WinEvent')
        PowerShellEvents = @('Get-WinEvent')
        SysmonEvents     = @('Get-WinEvent')
    }
    $logFor = @{
        PowerShellEvents = 'Microsoft-Windows-PowerShell/Operational'
        SysmonEvents     = 'Microsoft-Windows-Sysmon/Operational'
        SecurityEvents   = 'Security'
    }
    $collectors = foreach ($name in $script:WthCollectorMap.Keys) {
        $state = 'Ready'
        $notes = New-Object System.Collections.Generic.List[string]
        if (-not $isWindows) {
            $state = 'Unavailable'
            $notes.Add('Live collection requires Windows.')
        }
        else {
            $missingCmd = @($needs[$name] | Where-Object { -not (Test-WthCommandAvailable -Name $_) })
            if ($missingCmd.Count -gt 0) { $state = 'Unavailable'; $notes.Add("Missing command(s): $($missingCmd -join ', ').") }
            elseif ($script:WthElevationNeeded[$name] -eq 'Yes' -and -not $elevated) { $state = 'NeedsElevation'; $notes.Add('Requires an elevated session.') }
            elseif ($name -eq 'Defender' -and -not $elevated) { $state = 'Partial'; $notes.Add('Defender exclusions require an elevated session.') }
            if (($state -in @('Ready', 'NeedsElevation')) -and $logFor.ContainsKey($name) -and $name -ne 'SecurityEvents') {
                try { [void](Get-WthRawEventLogInfo -LogName $logFor[$name]) }
                catch {
                    if ((Get-WthExceptionClass -ErrorRecord $_) -eq 'NotAvailable') { $state = 'Unavailable'; $notes.Add("Event log '$($logFor[$name])' does not exist.") }
                    elseif ((Get-WthExceptionClass -ErrorRecord $_) -eq 'AccessDenied' -and -not $elevated) { $state = 'NeedsElevation'; $notes.Add("Reading '$($logFor[$name])' needs elevation or Event Log Readers membership.") }
                }
            }
        }
        [pscustomobject][ordered]@{
            Collector         = $name
            DataSources       = @($script:WthCollectorMap[$name])
            RequiresElevation = $script:WthElevationNeeded[$name]
            Readiness         = $state
            Notes             = ($notes -join ' ')
        }
    }
    return [pscustomobject][ordered]@{
        ToolVersion       = Get-WthToolVersion
        PowerShellVersion = $PSVersionTable.PSVersion.ToString()
        PowerShellEdition = [string]$PSVersionTable.PSEdition
        OperatingSystem   = [System.Environment]::OSVersion.VersionString
        IsWindows         = $isWindows
        IsElevated        = $elevated
        LiveCollection    = if ($isWindows) { 'Supported' } else { 'Unsupported on this OS: use saved or synthetic snapshots.' }
        ConfigurationValid = $configOk
        Rules             = $ruleSummary
        Collectors        = @($collectors)
        Issues            = $issues.ToArray()
    }
}
