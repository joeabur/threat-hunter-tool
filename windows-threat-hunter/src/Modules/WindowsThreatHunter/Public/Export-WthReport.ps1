function Export-WthReport {
    <#
    .SYNOPSIS
        Writes JSON, CSV and/or HTML reports for a hunt result.

    .DESCRIPTION
        JSON is the complete machine-readable result. CSV lists findings, with leading = + - @ characters
        neutralized against spreadsheet formula injection. HTML is a single self-contained file in which every
        value is HTML-encoded, with no scripts and a restrictive Content-Security-Policy.

        Files are named windows-threat-hunter-<host>-<UTC time>.<ext> and are never overwritten without -Force.
        The output directory is validated (no wildcards, '..', UNC paths, links or protected system folders) and
        created if needed. Evidence in the result was redacted when findings were built; reports add no new
        sensitive data. Nothing is transmitted anywhere.

    .PARAMETER Result
        Object from Invoke-WthHunt.

    .PARAMETER OutputDirectory
        Directory for the report files.

    .PARAMETER Format
        Json, Csv and/or Html. Default: all three.

    .PARAMETER IncludeSuppressed
        Include suppressed findings in the CSV and HTML reports (JSON always contains them).

    .PARAMETER Force
        Overwrite existing report files with the same name.

    .EXAMPLE
        $result = Invoke-WthHunt -SnapshotPath .\sample-data\snapshots\suspicious-persistence.json
        Export-WthReport -Result $result -OutputDirectory .\reports

    .OUTPUTS
        System.String[] (paths of the files written)
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]$Result,
        [Parameter(Mandatory, Position = 0)][string]$OutputDirectory,
        [ValidateSet('Json', 'Csv', 'Html')][string[]]$Format = @('Json', 'Csv', 'Html'),
        [switch]$IncludeSuppressed,
        [switch]$Force
    )

    process {
        if ($Result.PSObject.Properties['Kind'] -eq $null -or $Result.Kind -ne 'WthHuntResult') {
            throw [System.ArgumentException]::new('Result must be an object returned by Invoke-WthHunt.')
        }
        $dir = Resolve-WthOutputDirectory -Path $OutputDirectory
        $now = Get-WthUtcNow
        $generated = ConvertTo-WthIsoString -Value $now
        $stamp = $now.ToString('yyyyMMdd-HHmmss', [System.Globalization.CultureInfo]::InvariantCulture)
        $base = 'windows-threat-hunter-' + (Get-WthSafeFileNamePart -Text $Result.Host) + '-' + $stamp
        $written = New-Object System.Collections.Generic.List[string]
        foreach ($fmt in ($Format | Select-Object -Unique)) {
            switch ($fmt) {
                'Json' { $file = Join-Path $dir "$base.json"; $content = Build-WthJsonReport -Result $Result -GeneratedAt $generated }
                'Csv' { $file = Join-Path $dir "$base.csv"; $content = Build-WthCsvReport -Result $Result -IncludeSuppressed:$IncludeSuppressed }
                'Html' { $file = Join-Path $dir "$base.html"; $content = Build-WthHtmlReport -Result $Result -GeneratedAt $generated -IncludeSuppressed:$IncludeSuppressed }
            }
            Write-WthTextFile -Path $file -Content $content -Force:$Force
            $written.Add($file)
        }
        return $written.ToArray()
    }
}
