function Import-WthDefenderXdrEvent {
    <#
    .SYNOPSIS
        Parses an exported Microsoft Defender XDR (advanced hunting / alert) file into hunt items.

    .DESCRIPTION
        Reads JSON ({ "schemaVersion": 1, "events": [ ... ] } or a bare array) or CSV exports that use the
        documented column names. This is an offline file parser: it makes no network calls and needs no Defender
        XDR credentials.

        Required columns:  Timestamp, DeviceName, ActionType
        Optional columns:  FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName,
                           InitiatingProcessCommandLine, AccountName, SHA256, AlertId, Title, Severity, Category

        A row with both Title and Severity is treated as an alert (RecordType = Alert); other rows are events.
        Rows missing a required column or with an invalid timestamp are skipped and counted. Unknown columns are
        ignored. Column names are matched case-insensitively.

    .PARAMETER Path
        Path to the .json or .csv export.

    .PARAMETER Config
        Optional configuration hashtable (size and row limits).

    .EXAMPLE
        $xdr = Import-WthDefenderXdrEvent -Path .\sample-data\xdr\defender-xdr-export.json
        $xdr.Items | Format-Table TimeCreated, RecordType, ActionType, Title

    .OUTPUTS
        PSCustomObject with Items, Skipped, Warnings and Source.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, Position = 0)][string]$Path,
        [hashtable]$Config
    )

    if (-not $Config) { $Config = Get-WthConfiguration }
    $full = Resolve-WthInputPath -Path $Path -Type File -Label 'Defender XDR export' -MaxBytes ([long]$Config.limits.maxInputFileBytes)
    $ext = [System.IO.Path]::GetExtension($full).ToLowerInvariant()
    $rows = $null
    if ($ext -eq '.json') {
        $json = Read-WthJsonFile -Path $full -Label 'Defender XDR export' -MaxBytes ([long]$Config.limits.maxInputFileBytes)
        if (Test-WthHasMember -InputObject $json -Name 'events') {
            if (Test-WthHasMember -InputObject $json -Name 'schemaVersion') {
                if ($json.schemaVersion -ne 1) { throw [System.ArgumentException]::new("Defender XDR export schemaVersion must be 1: $Path") }
            }
            $rows = @($json.events)
        }
        elseif ($json -is [System.Collections.IEnumerable] -and $json -isnot [string]) { $rows = @($json) }
        else { throw [System.ArgumentException]::new("Defender XDR export must be a JSON array or an object with an 'events' array: $Path") }
    }
    elseif ($ext -eq '.csv') {
        $rows = @(Import-Csv -LiteralPath $full -Encoding UTF8)
    }
    else {
        throw [System.ArgumentException]::new("Defender XDR export must be a .json or .csv file: $Path")
    }
    if ($rows.Count -gt $Config.limits.maxItemsPerDataSource) {
        throw [System.ArgumentException]::new("Defender XDR export has $($rows.Count) rows, more than limits.maxItemsPerDataSource ($($Config.limits.maxItemsPerDataSource)).")
    }

    $known = 'Timestamp', 'DeviceName', 'ActionType', 'FileName', 'FolderPath', 'ProcessCommandLine', 'InitiatingProcessFileName',
    'InitiatingProcessCommandLine', 'AccountName', 'SHA256', 'AlertId', 'Title', 'Severity', 'Category'
    $items = New-Object System.Collections.Generic.List[object]
    $warnings = New-Object System.Collections.Generic.List[string]
    $skipped = 0
    $unknownColumns = @{}
    $rowNumber = 0
    foreach ($row in $rows) {
        $rowNumber++
        if ($null -eq $row -or $row -is [string] -or $row -is [System.Collections.IEnumerable]) { $skipped++; continue }
        $map = @{}
        foreach ($name in (Get-WthMemberName -InputObject $row)) {
            $canon = $known | Where-Object { $_ -ieq $name } | Select-Object -First 1
            if ($canon) { $map[$canon] = Get-WthFieldValue -InputObject $row -Path $name }
            else { $unknownColumns[$name] = $true }
        }
        $missing = @(@('Timestamp', 'DeviceName', 'ActionType') | Where-Object { -not $map.ContainsKey($_) -or [string]::IsNullOrWhiteSpace([string]$map[$_]) })
        $time = if ($map.ContainsKey('Timestamp')) { ConvertTo-WthIsoString -Value $map['Timestamp'] } else { $null }
        if ($missing.Count -gt 0 -or -not $time) {
            $skipped++
            if ($warnings.Count -lt 20) { $warnings.Add("Row ${rowNumber} skipped: " + $(if ($missing.Count -gt 0) { "missing $($missing -join ', ')" } else { 'invalid Timestamp' })) }
            continue
        }
        $get = { param($k) if ($map.ContainsKey($k) -and $null -ne $map[$k]) { Limit-WthString -Text ([string]$map[$k]) -MaxLength $Config.limits.maxEventDataLength } else { $null } }
        $title = & $get 'Title'
        $severity = & $get 'Severity'
        $items.Add([ordered]@{
                RecordType                   = if ($title -and $severity) { 'Alert' } else { 'Event' }
                TimeCreated                  = $time
                DeviceName                   = & $get 'DeviceName'
                ActionType                   = & $get 'ActionType'
                FileName                     = & $get 'FileName'
                FolderPath                   = & $get 'FolderPath'
                ProcessCommandLine           = & $get 'ProcessCommandLine'
                InitiatingProcessFileName    = & $get 'InitiatingProcessFileName'
                InitiatingProcessCommandLine = & $get 'InitiatingProcessCommandLine'
                AccountName                  = & $get 'AccountName'
                SHA256                       = & $get 'SHA256'
                AlertId                      = & $get 'AlertId'
                Title                        = $title
                Severity                     = $severity
                Category                     = & $get 'Category'
            })
    }
    if ($skipped -gt 0) { $warnings.Add("$skipped row(s) were skipped because they were malformed or missing required columns.") }
    if ($unknownColumns.Count -gt 0) { $warnings.Add("Ignored unknown column(s): $((@($unknownColumns.Keys | Sort-Object)) -join ', ').") }
    return [pscustomobject][ordered]@{
        Source   = [System.IO.Path]::GetFileName($full)
        Items    = $items.ToArray()
        Skipped  = $skipped
        Warnings = $warnings.ToArray()
    }
}
