function Export-WthSnapshot {
    <#
    .SYNOPSIS
        Saves a snapshot to a JSON file for later offline hunting.

    .DESCRIPTION
        Writes UTF-8 JSON (no BOM). Refuses to overwrite an existing file without -Force and refuses protected
        system locations and symbolic links. Snapshots contain raw command lines, account names and file paths:
        store them as sensitive evidence. -Redact masks secrets and user names, but that can stop allowlists
        (for example expectedPrivilegedMembers) from matching when the snapshot is hunted later.

    .PARAMETER Snapshot
        Snapshot object from Invoke-WthCollection or Import-WthSnapshot.

    .PARAMETER Path
        Destination .json file.

    .PARAMETER Redact
        Apply the configured redaction to item values before saving.

    .PARAMETER Force
        Overwrite an existing file.

    .EXAMPLE
        Invoke-WthCollection | Export-WthSnapshot -Path .\evidence\host-snapshot.json
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]$Snapshot,
        [Parameter(Mandatory, Position = 0)][string]$Path,
        [switch]$Redact,
        [switch]$Force
    )

    process {
        Assert-WthSafePathText -Path $Path -Label 'Snapshot path'
        $full = [System.IO.Path]::GetFullPath($Path)
        if ([System.IO.Path]::GetExtension($full) -ne '.json') { throw [System.ArgumentException]::new("Snapshot path must end in .json: $Path") }
        $dir = Resolve-WthOutputDirectory -Path ([System.IO.Path]::GetDirectoryName($full)) -Label 'Snapshot directory'
        $target = Join-Path $dir ([System.IO.Path]::GetFileName($full))
        $config = Get-WthConfiguration

        $itemsOut = [ordered]@{}
        foreach ($ds in @($Snapshot.Items.Keys | Sort-Object)) {
            $list = New-Object System.Collections.Generic.List[object]
            foreach ($item in @($Snapshot.Items[$ds])) {
                if (-not $Redact) { $list.Add($item); continue }
                $copy = [ordered]@{}
                foreach ($name in (Get-WthMemberName -InputObject $item)) {
                    $copy[$name] = Protect-WthValue -Value (Get-WthFieldValue -InputObject $item -Path $name) -FieldName $name -Redaction $config.redaction -MaxLength 65536
                }
                $list.Add($copy)
            }
            $itemsOut[$ds] = $list.ToArray()
        }
        $doc = [ordered]@{
            schemaVersion = $script:WthSnapshotSchemaVersion
            kind          = 'WthSnapshot'
            synthetic     = [bool]$Snapshot.Synthetic
            description   = [string]$Snapshot.Description
            host          = [string]$Snapshot.Host
            collectedAt   = [string]$Snapshot.CollectedAt
            redacted      = [bool]$Redact
            tool          = $Snapshot.Tool
            platform      = $Snapshot.Platform
            environment   = $Snapshot.Environment
            coverage      = @($Snapshot.Coverage)
            items         = $itemsOut
        }
        Write-WthTextFile -Path $target -Content (ConvertTo-Json -InputObject $doc -Depth 12) -Force:$Force
        return $target
    }
}
