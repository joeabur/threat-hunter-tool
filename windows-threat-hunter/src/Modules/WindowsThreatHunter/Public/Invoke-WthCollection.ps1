function Invoke-WthCollection {
    <#
    .SYNOPSIS
        Collects read-only telemetry from the local Windows endpoint into a snapshot object.

    .DESCRIPTION
        Runs the selected collectors (scheduled tasks, services, Run/RunOnce keys, startup folders, WMI event
        subscriptions, local accounts and privileged groups, processes, network sockets, Windows Defender, and the
        Security, PowerShell and Sysmon event logs). Collection is read-only: nothing is changed, and discovered
        binaries, scripts, tasks and services are never executed.

        A failure in one collector (missing privilege, missing log, missing feature) is recorded as coverage and
        does not stop the others. Missing data is reported as missing; it is never interpreted as clean.

        On non-Windows systems every collector reports Unavailable. Use a saved or synthetic snapshot instead.

    .PARAMETER Collector
        Collectors to run. Defaults to collection.collectors from the configuration.
        Valid: ScheduledTasks, Services, RegistryRun, StartupFolders, WmiSubscriptions, LocalAccounts, Processes,
        Network, Defender, SecurityEvents, PowerShellEvents, SysmonEvents.

    .PARAMETER ConfigPath
        Optional configuration override file.

    .PARAMETER Config
        A configuration hashtable from Get-WthConfiguration (takes precedence over -ConfigPath).

    .EXAMPLE
        $snapshot = Invoke-WthCollection
        Export-WthSnapshot -Snapshot $snapshot -Path .\evidence\snapshot.json

    .EXAMPLE
        Invoke-WthCollection -Collector ScheduledTasks, Services, RegistryRun

    .NOTES
        Snapshots contain raw command lines, account names and paths. Treat them as sensitive evidence.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [ValidateSet('ScheduledTasks', 'Services', 'RegistryRun', 'StartupFolders', 'WmiSubscriptions', 'LocalAccounts', 'Processes', 'Network', 'Defender', 'SecurityEvents', 'PowerShellEvents', 'SysmonEvents')]
        [string[]]$Collector,
        [string]$ConfigPath,
        [hashtable]$Config
    )

    if (-not $Config) {
        $Config = if ($PSBoundParameters.ContainsKey('ConfigPath')) { Get-WthConfiguration -Path $ConfigPath } else { Get-WthConfiguration }
    }
    $selected = if ($Collector) { @($Collector) } else { @($Config.collection.collectors) }
    $ordered = @($script:WthCollectorMap.Keys | Where-Object { $_ -in $selected })

    $script:WthFileExistenceCache = @{}
    $environment = Get-WthDefaultEnvironment
    $collectedAt = ConvertTo-WthIsoString -Value (Get-WthUtcNow)
    $items = @{}
    $coverage = New-Object System.Collections.Generic.List[object]
    $processLookup = @{}

    # Processes first so the network collector can attach process names without a second query.
    $run = @($ordered | Where-Object { $_ -eq 'Processes' }) + @($ordered | Where-Object { $_ -ne 'Processes' })
    foreach ($name in $run) {
        Write-Verbose "Running collector $name"
        $r = Invoke-WthCollectorByName -Name $name -Config $Config -ProcessLookup $processLookup
        foreach ($c in @($r.Coverage)) { $coverage.Add($c) }
        foreach ($ds in $r.Items.Keys) { $items[$ds] = @($r.Items[$ds]) }
        if ($name -eq 'Processes' -and $r.Items.ContainsKey('Process')) {
            foreach ($p in $r.Items['Process']) { $processLookup[[int]$p['ProcessId']] = @{ Name = $p['Name']; Path = $p['ExecutablePath'] } }
        }
    }
    foreach ($collectorName in $script:WthCollectorMap.Keys) {
        if ($collectorName -in $ordered) { continue }
        foreach ($ds in $script:WthCollectorMap[$collectorName]) {
            $coverage.Add((Build-WthCoverage -DataSource $ds -Collector $collectorName -Status NotRequested -Message 'Collector was not selected. Rules for this source were not evaluated.'))
        }
    }

    $sortedCoverage = @($coverage | Sort-Object { [array]::IndexOf($script:WthDataSources, $_.DataSource) })
    return [pscustomobject][ordered]@{
        SchemaVersion = $script:WthSnapshotSchemaVersion
        Kind          = 'WthSnapshot'
        Synthetic     = $false
        Description   = 'Live collection from the local endpoint.'
        Host          = Get-WthHostName
        CollectedAt   = $collectedAt
        Tool          = [ordered]@{ Name = $script:WthToolName; Version = (Get-WthToolVersion) }
        Platform      = [ordered]@{
            OperatingSystem   = [System.Environment]::OSVersion.VersionString
            PowerShellVersion = $PSVersionTable.PSVersion.ToString()
            PowerShellEdition = [string]$PSVersionTable.PSEdition
            Elevated          = (Test-WthIsElevated)
        }
        Environment   = $environment
        Coverage      = $sortedCoverage
        Items         = $items
    }
}
