function Import-WthSnapshot {
    <#
    .SYNOPSIS
        Loads and validates a snapshot JSON file (live export or synthetic sample).

    .DESCRIPTION
        Validates the schema version, host, collection time, coverage entries and item containers. Unknown data
        sources are ignored with a warning in the returned object. The file size, item counts and path are
        bounded; nothing in the file is ever evaluated as code.

    .PARAMETER Path
        Snapshot .json file.

    .PARAMETER Config
        Optional configuration hashtable (used for size and item limits).

    .EXAMPLE
        $snap = Import-WthSnapshot -Path .\sample-data\snapshots\suspicious-persistence.json
        $snap.Coverage | Format-Table DataSource, Status, ItemCount

    .OUTPUTS
        PSCustomObject (same shape as Invoke-WthCollection output, plus Warnings).
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, Position = 0)][string]$Path,
        [hashtable]$Config
    )

    if (-not $Config) { $Config = Get-WthConfiguration }
    $json = Read-WthJsonFile -Path $Path -Label 'Snapshot file' -MaxBytes ([long]$Config.limits.maxInputFileBytes)
    $fail = { param($m) throw [System.ArgumentException]::new("Invalid snapshot '$Path': $m") }
    $names = @(Get-WthMemberName -InputObject $json)
    if ($names -notcontains 'schemaVersion' -or $json.schemaVersion -ne $script:WthSnapshotSchemaVersion) { & $fail "schemaVersion must be $script:WthSnapshotSchemaVersion." }
    if ($names -notcontains 'kind' -or $json.kind -ne 'WthSnapshot') { & $fail "kind must be 'WthSnapshot'." }
    foreach ($req in 'host', 'collectedAt', 'items', 'coverage') { if ($names -notcontains $req) { & $fail "missing '$req'." } }
    if ($json.host -isnot [string] -or [string]::IsNullOrWhiteSpace($json.host)) { & $fail "'host' must be a non-empty string." }
    $collectedAt = ConvertTo-WthIsoString -Value $json.collectedAt
    if (-not $collectedAt) { & $fail "'collectedAt' is not a valid date." }
    if ($json.items -is [string] -or $json.items -is [System.Collections.IEnumerable]) { & $fail "'items' must be an object keyed by data source." }
    if ($json.coverage -is [string] -or $json.coverage -isnot [System.Collections.IEnumerable]) { & $fail "'coverage' must be an array." }

    $warnings = New-Object System.Collections.Generic.List[string]
    $coverage = New-Object System.Collections.Generic.List[object]
    foreach ($c in @($json.coverage)) {
        $cn = @(Get-WthMemberName -InputObject $c)
        foreach ($req in 'DataSource', 'Status') { if ($cn -notcontains $req) { & $fail "a coverage entry is missing '$req'." } }
        if ($c.DataSource -notin $script:WthDataSources) { $warnings.Add("Ignored coverage entry for unknown data source '$($c.DataSource)'."); continue }
        if ($c.Status -notin $script:WthCoverageStatuses) { & $fail "coverage status '$($c.Status)' for $($c.DataSource) is not one of: $($script:WthCoverageStatuses -join ', ')." }
        $coverage.Add([pscustomobject][ordered]@{
                DataSource        = [string]$c.DataSource
                Collector         = if ($cn -contains 'Collector') { [string]$c.Collector } else { '' }
                Status            = [string]$c.Status
                ItemCount         = if ($cn -contains 'ItemCount') { [int]$c.ItemCount } else { 0 }
                RequiresElevation = if ($cn -contains 'RequiresElevation') { [string]$c.RequiresElevation } else { 'No' }
                Message           = if ($cn -contains 'Message') { [string]$c.Message } else { '' }
            })
    }
    $items = @{}
    $total = 0
    foreach ($ds in (Get-WthMemberName -InputObject $json.items)) {
        if ($ds -notin $script:WthDataSources) { $warnings.Add("Ignored items for unknown data source '$ds'."); continue }
        $list = $json.items.PSObject.Properties[$ds].Value
        if ($null -eq $list) { $list = @() }
        if ($list -is [string] -or $list -isnot [System.Collections.IEnumerable]) { & $fail "items.$ds must be an array." }
        $arr = @($list)
        if ($arr.Count -gt $Config.limits.maxItemsPerDataSource) { & $fail "items.$ds has $($arr.Count) entries, more than limits.maxItemsPerDataSource ($($Config.limits.maxItemsPerDataSource))." }
        foreach ($i in $arr) { if ($null -eq $i -or $i -is [string] -or $i -is [System.Collections.IEnumerable]) { & $fail "items.$ds must contain objects." } }
        $total += $arr.Count
        $items[$ds] = $arr
    }
    $environment = Get-WthDefaultEnvironment
    if ($names -contains 'environment' -and $null -ne $json.environment) {
        foreach ($k in (Get-WthMemberName -InputObject $json.environment)) {
            $v = Get-WthFieldValue -InputObject $json.environment -Path $k
            if ($v -is [string] -and $k -match '^[A-Za-z0-9()_]+$') { $environment[$k] = $v }
        }
    }
    $synthetic = ($names -contains 'synthetic') -and ($json.synthetic -eq $true)
    return [pscustomobject][ordered]@{
        SchemaVersion = $script:WthSnapshotSchemaVersion
        Kind          = 'WthSnapshot'
        Synthetic     = $synthetic
        Description   = if ($names -contains 'description') { [string]$json.description } else { '' }
        Host          = [string]$json.host
        CollectedAt   = $collectedAt
        Tool          = if ($names -contains 'tool') { $json.tool } else { $null }
        Platform      = if ($names -contains 'platform') { $json.platform } else { $null }
        Environment   = $environment
        Coverage      = $coverage.ToArray()
        Items         = $items
        TotalItems    = $total
        Warnings      = $warnings.ToArray()
    }
}
