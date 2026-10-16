#Requires -Version 5.1
# Shared constants: data sources, collectors, severity ordering and file schema versions.

$script:WthToolName = 'WindowsThreatHunter'
$script:WthSnapshotSchemaVersion = 1
$script:WthResultSchemaVersion = 1
$script:WthConfigSchemaVersion = 1
$script:WthRuleSchemaVersion = 1

$script:WthDataSources = @(
    'ScheduledTask', 'Service', 'RegistryRun', 'StartupItem', 'WmiSubscription',
    'LocalAccount', 'LocalGroupMember', 'Process', 'NetworkConnection',
    'DefenderStatus', 'DefenderExclusion', 'DefenderEvent',
    'Event.Security', 'Event.PowerShell', 'Event.Sysmon', 'DefenderXdr'
)

# Collector name -> data sources it produces
$script:WthCollectorMap = [ordered]@{
    ScheduledTasks   = @('ScheduledTask')
    Services         = @('Service')
    RegistryRun      = @('RegistryRun')
    StartupFolders   = @('StartupItem')
    WmiSubscriptions = @('WmiSubscription')
    LocalAccounts    = @('LocalAccount', 'LocalGroupMember')
    Processes        = @('Process')
    Network          = @('NetworkConnection')
    Defender         = @('DefenderStatus', 'DefenderExclusion', 'DefenderEvent')
    SecurityEvents   = @('Event.Security')
    PowerShellEvents = @('Event.PowerShell')
    SysmonEvents     = @('Event.Sysmon')
}

$script:WthCoverageStatuses = @('Collected', 'Partial', 'NeedsElevation', 'Unavailable', 'Error', 'NotRequested', 'Imported')

$script:WthSeverityOrder = @{ Informational = 0; Low = 1; Medium = 2; High = 3; Critical = 4 }
$script:WthConfidenceValues = @('Low', 'Medium', 'High')
$script:WthFindingTypes = @('Observation', 'Heuristic')
$script:WthCategories = @('Persistence', 'Execution', 'Network', 'Accounts', 'DefenseEvasion', 'Authentication', 'Defender', 'Imported')

function Get-WthSeverityRank {
    [CmdletBinding()]
    [OutputType([int])]
    param([Parameter(Mandatory, Position = 0)][string]$Severity)

    if ($script:WthSeverityOrder.ContainsKey($Severity)) { return $script:WthSeverityOrder[$Severity] }
    return -1
}

function Get-WthToolVersion {
    [CmdletBinding()]
    [OutputType([string])]
    param()

    try {
        $manifest = Join-Path $script:WthModuleRoot 'WindowsThreatHunter.psd1'
        return [string](Import-PowerShellDataFile -LiteralPath $manifest).ModuleVersion
    }
    catch {
        Write-Verbose "Could not read the module manifest version: $($_.Exception.Message)"
        return '0.0.0'
    }
}
