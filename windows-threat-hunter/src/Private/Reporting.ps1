#Requires -Version 5.1
# Report builders: JSON, CSV (formula-injection safe) and HTML (every value HTML-encoded, no script).

$script:WthReportFormatVersion = 1

function ConvertTo-WthHtmlText {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Position = 0)][AllowNull()]$Value)

    if ($null -eq $Value) { return '' }
    $text = if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) { (@($Value) | ForEach-Object { [string]$_ }) -join ', ' } else { [string]$Value }
    return [System.Net.WebUtility]::HtmlEncode($text)
}

function ConvertTo-WthCsvSafeCell {
    <#
    .SYNOPSIS
        Neutralises spreadsheet formula injection by prefixing risky leading characters with an apostrophe.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Position = 0)][AllowNull()]$Value)

    if ($null -eq $Value) { return '' }
    $text = if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) { (@($Value) | ForEach-Object { [string]$_ }) -join '; ' } else { [string]$Value }
    $text = $text -replace '[\r\n]+', ' '
    if ($text.Length -gt 0 -and '=+-@'.Contains($text[0]) -or $text.StartsWith("`t")) { return "'" + $text }
    return $text
}

function Get-WthEvidenceText {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Position = 0)][AllowNull()]$Evidence, [string]$Separator = '; ')

    if ($null -eq $Evidence) { return '' }
    $parts = foreach ($k in $Evidence.Keys) { "$k=" + (@($Evidence[$k]) -join ',') }
    return ($parts -join $Separator)
}

function Build-WthJsonReport {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)]$Result, [Parameter(Mandatory)][string]$GeneratedAt)

    $doc = [ordered]@{
        ReportFormatVersion = $script:WthReportFormatVersion
        GeneratedAt         = $GeneratedAt
        Result              = $Result
    }
    return (ConvertTo-Json -InputObject $doc -Depth 12)
}

function Build-WthCsvReport {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)]$Result, [switch]$IncludeSuppressed)

    $rows = New-Object System.Collections.Generic.List[object]
    $all = @($Result.Findings)
    if ($IncludeSuppressed) { $all += @($Result.SuppressedFindings) }
    foreach ($f in $all) {
        $rows.Add([pscustomobject][ordered]@{
                FindingId           = ConvertTo-WthCsvSafeCell $f.FindingId
                Host                = ConvertTo-WthCsvSafeCell $f.Host
                ObservedAt          = ConvertTo-WthCsvSafeCell $f.ObservedAt
                RuleId              = ConvertTo-WthCsvSafeCell $f.RuleId
                RuleVersion         = ConvertTo-WthCsvSafeCell $f.RuleVersion
                Severity            = ConvertTo-WthCsvSafeCell $f.Severity
                Confidence          = ConvertTo-WthCsvSafeCell $f.Confidence
                FindingType         = ConvertTo-WthCsvSafeCell $f.FindingType
                Category            = ConvertTo-WthCsvSafeCell $f.Category
                Title               = ConvertTo-WthCsvSafeCell $f.Title
                Suppressed          = ConvertTo-WthCsvSafeCell $f.Suppressed
                SuppressionReason   = ConvertTo-WthCsvSafeCell $f.SuppressionReason
                Evidence            = ConvertTo-WthCsvSafeCell (Get-WthEvidenceText $f.Evidence)
                Attack              = ConvertTo-WthCsvSafeCell (@($f.Attack | ForEach-Object { $_.Id }))
                Explanation         = ConvertTo-WthCsvSafeCell $f.Explanation
                RecommendedNextStep = ConvertTo-WthCsvSafeCell $f.RecommendedNextStep
                DataOrigin          = ConvertTo-WthCsvSafeCell $Result.DataOrigin
            })
    }
    if ($rows.Count -eq 0) {
        $header = 'FindingId,Host,ObservedAt,RuleId,RuleVersion,Severity,Confidence,FindingType,Category,Title,Suppressed,SuppressionReason,Evidence,Attack,Explanation,RecommendedNextStep,DataOrigin'
        return $header + [Environment]::NewLine
    }
    return (($rows | ConvertTo-Csv -NoTypeInformation) -join [Environment]::NewLine) + [Environment]::NewLine
}

function Build-WthHtmlReport {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]$Result,
        [Parameter(Mandatory)][string]$GeneratedAt,
        [switch]$IncludeSuppressed
    )

    $h = { param($v) ConvertTo-WthHtmlText $v }
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine('<!DOCTYPE html>')
    [void]$sb.AppendLine('<html lang="en"><head><meta charset="utf-8">')
    [void]$sb.AppendLine('<meta http-equiv="Content-Security-Policy" content="default-src ''none''; style-src ''unsafe-inline''; img-src ''none''; base-uri ''none''; form-action ''none''">')
    [void]$sb.AppendLine('<meta name="viewport" content="width=device-width, initial-scale=1">')
    [void]$sb.AppendLine("<title>Windows Threat Hunter report - $(& $h $Result.Host)</title>")
    [void]$sb.AppendLine(@'
<style>
body{font-family:Segoe UI,Arial,sans-serif;margin:24px;color:#1b1f23;background:#fff;line-height:1.45}
h1{font-size:1.5em}h2{margin-top:1.8em;border-bottom:1px solid #d0d7de;padding-bottom:4px}h3{margin:0 0 6px}
table{border-collapse:collapse;width:100%;margin:8px 0}th,td{border:1px solid #d0d7de;padding:4px 8px;text-align:left;vertical-align:top;font-size:.92em}
th{background:#f6f8fa}.banner{padding:10px 14px;border-radius:6px;margin:12px 0}
.warn{background:#fff8c5;border:1px solid #d4a72c}.sim{background:#ffebe9;border:1px solid #cf222e;font-weight:600}
.finding{border:1px solid #d0d7de;border-radius:6px;padding:12px 14px;margin:12px 0}
.sev-Critical,.sev-High{border-left:6px solid #cf222e}.sev-Medium{border-left:6px solid #bf8700}.sev-Low{border-left:6px solid #0969da}.sev-Informational{border-left:6px solid #6e7781}
.suppressed{opacity:.75}pre{white-space:pre-wrap;word-break:break-word;background:#f6f8fa;padding:8px;border-radius:4px;font-size:.88em}
.tag{display:inline-block;padding:1px 8px;border-radius:10px;background:#eaeef2;font-size:.82em;margin-right:4px}
</style></head><body>
'@)
    [void]$sb.AppendLine("<h1>Windows Threat Hunter report</h1>")
    if ($Result.DataOrigin -eq 'Synthetic') {
        [void]$sb.AppendLine('<div class="banner sim">SIMULATED DATA: this report was produced from a synthetic snapshot, not from a real endpoint. Nothing below was observed on a real system.</div>')
    }
    [void]$sb.AppendLine('<div class="banner warn"><strong>Read this first.</strong> Findings are leads for an analyst, not verdicts. A finding does not prove compromise, and the absence of findings does not prove a host is clean: see the coverage table for data that could not be collected.</div>')
    [void]$sb.AppendLine('<table>')
    foreach ($row in @(
            @('Host', $Result.Host), @('Collected at (UTC)', $Result.CollectedAt), @('Report generated (UTC)', $GeneratedAt),
            @('Data origin', $Result.DataOrigin), @('Tool version', $Result.ToolVersion), @('Elevated session', $Result.Elevated),
            @('Rules executed', @($Result.RulesExecuted).Count), @('Rules skipped', @($Result.RulesSkipped).Count),
            @('Active findings', @($Result.Findings).Count), @('Suppressed findings', @($Result.SuppressedFindings).Count)
        )) {
        [void]$sb.AppendLine("<tr><th>$(& $h $row[0])</th><td>$(& $h $row[1])</td></tr>")
    }
    [void]$sb.AppendLine('</table>')

    [void]$sb.AppendLine('<h2>Findings by severity</h2><table><tr><th>Severity</th><th>Count</th></tr>')
    foreach ($sev in 'Critical', 'High', 'Medium', 'Low', 'Informational') {
        [void]$sb.AppendLine("<tr><td>$sev</td><td>$(& $h $Result.Summary.BySeverity[$sev])</td></tr>")
    }
    [void]$sb.AppendLine('</table>')

    [void]$sb.AppendLine('<h2>Data collection coverage</h2><table><tr><th>Data source</th><th>Status</th><th>Items</th><th>Needs elevation</th><th>Notes</th></tr>')
    foreach ($c in @($Result.Coverage)) {
        [void]$sb.AppendLine("<tr><td>$(& $h $c.DataSource)</td><td>$(& $h $c.Status)</td><td>$(& $h $c.ItemCount)</td><td>$(& $h $c.RequiresElevation)</td><td>$(& $h $c.Message)</td></tr>")
    }
    [void]$sb.AppendLine('</table>')

    [void]$sb.AppendLine("<h2>Findings</h2>")
    if (@($Result.Findings).Count -eq 0) {
        [void]$sb.AppendLine('<p>No active findings. This is not evidence that the endpoint is clean; check coverage and skipped rules.</p>')
    }
    $render = {
        param($f, $cssExtra)
        [void]$sb.AppendLine("<div class=""finding sev-$(& $h $f.Severity) $cssExtra"">")
        [void]$sb.AppendLine("<h3>$(& $h $f.Title)</h3>")
        [void]$sb.AppendLine("<p><span class=""tag"">Severity: $(& $h $f.Severity)</span><span class=""tag"">Confidence: $(& $h $f.Confidence)</span><span class=""tag"">$(& $h $f.FindingType)</span><span class=""tag"">$(& $h $f.RuleId) v$(& $h $f.RuleVersion)</span><span class=""tag"">$(& $h $f.FindingId)</span></p>")
        [void]$sb.AppendLine("<table><tr><th>Host</th><td>$(& $h $f.Host)</td></tr><tr><th>Observed (UTC)</th><td>$(& $h $f.ObservedAt) ($(& $h $f.ObservedAtBasis))</td></tr><tr><th>Occurrences</th><td>$(& $h $f.OccurrenceCount)</td></tr>")
        [void]$sb.AppendLine("<tr><th>Explanation</th><td>$(& $h $f.Explanation)</td></tr>")
        [void]$sb.AppendLine("<tr><th>Evidence</th><td><pre>$(& $h (Get-WthEvidenceText -Evidence $f.Evidence -Separator ([Environment]::NewLine)))</pre></td></tr>")
        $attackCells = foreach ($a in @($f.Attack)) { "<a href=""$(& $h $a.Url)"">$(& $h $a.Id)</a> $(& $h $a.Name)" }
        [void]$sb.AppendLine("<tr><th>ATT&amp;CK</th><td>$(($attackCells) -join '<br>')</td></tr>")
        $fp = foreach ($x in @($f.FalsePositives)) { "<li>$(& $h $x)</li>" }
        [void]$sb.AppendLine("<tr><th>Possible benign causes</th><td><ul>$($fp -join '')</ul></td></tr>")
        [void]$sb.AppendLine("<tr><th>Recommended next step</th><td>$(& $h $f.RecommendedNextStep)</td></tr>")
        [void]$sb.AppendLine("<tr><th>Remediation guidance (not performed by this tool)</th><td>$(& $h $f.Remediation)</td></tr>")
        if ($f.Suppressed) { [void]$sb.AppendLine("<tr><th>Suppressed</th><td>$(& $h $f.SuppressionId): $(& $h $f.SuppressionReason)</td></tr>") }
        [void]$sb.AppendLine('</table></div>')
    }
    foreach ($f in @($Result.Findings)) { & $render $f '' }
    if ($IncludeSuppressed -and @($Result.SuppressedFindings).Count -gt 0) {
        [void]$sb.AppendLine('<h2>Suppressed findings</h2><p>Suppressions are analyst decisions recorded with a written reason. They are shown so that nothing is silently hidden.</p>')
        foreach ($f in @($Result.SuppressedFindings)) { & $render $f 'suppressed' }
    }

    [void]$sb.AppendLine('<h2>ATT&amp;CK techniques referenced by active findings</h2>')
    [void]$sb.AppendLine('<p>A detection is not a technique: a rule maps to a technique when its behaviour is related to it. The list shows techniques referenced by findings in this run. It does not mean other techniques are absent, and this toolkit does not claim ATT&amp;CK coverage.</p>')
    [void]$sb.AppendLine('<table><tr><th>Technique</th><th>Name</th><th>Findings</th></tr>')
    foreach ($t in @($Result.AttackSummary)) {
        [void]$sb.AppendLine("<tr><td><a href=""$(& $h $t.Url)"">$(& $h $t.Id)</a></td><td>$(& $h $t.Name)</td><td>$(& $h $t.FindingCount)</td></tr>")
    }
    [void]$sb.AppendLine('</table>')

    [void]$sb.AppendLine('<h2>Rules skipped</h2><table><tr><th>Rule</th><th>Reason</th></tr>')
    foreach ($r in @($Result.RulesSkipped)) { [void]$sb.AppendLine("<tr><td>$(& $h $r.RuleId)</td><td>$(& $h $r.Reason)</td></tr>") }
    [void]$sb.AppendLine('</table>')

    [void]$sb.AppendLine('<h2>Warnings and errors</h2><ul>')
    foreach ($w in @($Result.Warnings)) { [void]$sb.AppendLine("<li>$(& $h $w)</li>") }
    [void]$sb.AppendLine('</ul><h2>Known limitations</h2><ul>')
    foreach ($l in @($Result.Limitations)) { [void]$sb.AppendLine("<li>$(& $h $l)</li>") }
    [void]$sb.AppendLine('</ul></body></html>')
    return $sb.ToString()
}
