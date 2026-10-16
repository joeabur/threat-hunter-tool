#Requires -Version 5.1
# Rule evaluation, finding construction, duplicate merging and suppression.

function Get-WthEffectiveRule {
    <#
    .SYNOPSIS
        Applies configuration overrides (enabled, severity, confidence, threshold, windowMinutes) to a rule.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Rule,
        [Parameter(Mandatory)][hashtable]$Config
    )

    $effective = [ordered]@{}
    foreach ($n in (Get-WthMemberName -InputObject $Rule)) { $effective[$n] = $Rule.$n }
    if (-not $effective.Contains('enabled')) { $effective['enabled'] = $true }
    $applied = New-Object System.Collections.Generic.List[string]
    $o = $Config.ruleOverrides[[string]$Rule.id]
    if ($o -is [hashtable]) {
        foreach ($k in 'enabled', 'severity', 'confidence') {
            if ($o.ContainsKey($k)) { $effective[$k] = $o[$k]; $applied.Add("$k=$($o[$k])") }
        }
        if ($effective.Contains('aggregate')) {
            $agg = [ordered]@{}
            foreach ($n in (Get-WthMemberName -InputObject $effective['aggregate'])) { $agg[$n] = $effective['aggregate'].$n }
            foreach ($k in 'threshold', 'windowMinutes') {
                if ($o.ContainsKey($k)) { $agg[$k] = $o[$k]; $applied.Add("$k=$($o[$k])") }
            }
            $effective['aggregate'] = [pscustomobject]$agg
        }
    }
    $effective['_overrides'] = $applied.ToArray()
    return [pscustomobject]$effective
}

function Get-WthEvidenceMap {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Rule,
        [Parameter(Mandatory)][AllowNull()]$Item,
        [Parameter(Mandatory)][hashtable]$Config
    )

    $evidence = [ordered]@{}
    foreach ($field in @($Rule.evidenceFields)) {
        $value = Get-WthFieldValue -InputObject $Item -Path $field
        if ($null -eq $value) { continue }
        $evidence[$field] = Protect-WthValue -Value $value -FieldName $field -Redaction $Config.redaction -MaxLength $Config.limits.maxEvidenceValueLength
    }
    return $evidence
}

function Get-WthDedupeKey {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]$Rule,
        [Parameter(Mandatory)][AllowNull()]$Item,
        [string[]]$ExtraKey
    )

    $fields = if (Test-WthHasMember -InputObject $Rule -Name 'dedupeFields') { @($Rule.dedupeFields) } else { @($Rule.evidenceFields) }
    $parts = New-Object System.Collections.Generic.List[string]
    foreach ($f in $fields) {
        $v = Get-WthFieldValue -InputObject $Item -Path $f
        $text = (@($v) | ForEach-Object { if ($_ -is [datetime] -or $_ -is [System.DateTimeOffset]) { ConvertTo-WthIsoString -Value $_ } else { [string]$_ } }) -join ','
        $parts.Add(("$f=" + $text).ToLowerInvariant())
    }
    foreach ($x in @($ExtraKey)) { $parts.Add($x.ToLowerInvariant()) }
    return ($parts -join '|')
}

function Build-WthFinding {
    <#
    .SYNOPSIS
        Builds one finding object from a rule and the item (or aggregate window) that matched it.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Rule,
        [Parameter(Mandatory)][AllowNull()]$Item,
        [Parameter(Mandatory)][hashtable]$Config,
        [Parameter(Mandatory)][hashtable]$AttackCatalog,
        [Parameter(Mandatory)][string]$HostName,
        [Parameter(Mandatory)][string]$CollectedAt,
        [hashtable]$Aggregate
    )

    $evidence = Get-WthEvidenceMap -Rule $Rule -Item $Item -Config $Config
    $extraKey = @()
    if ($Aggregate) {
        $extraKey = @($Aggregate.GroupKey)
        $evidence['Count'] = $Aggregate.Count
        $evidence['Threshold'] = $Aggregate.Threshold
        $evidence['WindowMinutes'] = $Aggregate.WindowMinutes
        $evidence['FirstSeen'] = $Aggregate.FirstSeen
        $evidence['LastSeen'] = $Aggregate.LastSeen
    }
    $key = Get-WthDedupeKey -Rule $Rule -Item $Item -ExtraKey $extraKey
    $id = 'WTH-F-' + (Get-WthSha256Hex -Text ("$($Rule.id)|$($HostName.ToLowerInvariant())|$key")).Substring(0, 12)

    $title = [regex]::Replace([string]$Rule.titleTemplate, '\{([^{}]*)\}', {
            param($m)
            $name = $m.Groups[1].Value
            if ($evidence.Contains($name)) { return (@($evidence[$name]) -join ', ') }
            return '(unknown)'
        }.GetNewClosure())
    $title = Limit-WthString -Text $title -MaxLength 300

    $observed = $CollectedAt
    $timeBasis = 'CollectionTime'
    if ($Aggregate) { $observed = $Aggregate.LastSeen; $timeBasis = 'EventTime' }
    else {
        $t = ConvertTo-WthIsoString -Value (Get-WthFieldValue -InputObject $Item -Path 'TimeCreated')
        if ($t) { $observed = $t; $timeBasis = 'EventTime' }
    }

    $attack = New-Object System.Collections.Generic.List[object]
    foreach ($tid in @($Rule.attack)) {
        $entry = $AttackCatalog[[string]$tid]
        $attack.Add([ordered]@{ Id = $entry.Id; Name = $entry.Name; Tactics = @($entry.Tactics); Url = $entry.Url })
    }

    $limitations = @()
    if (Test-WthHasMember -InputObject $Rule -Name 'limitations') { $limitations = @($Rule.limitations) }

    return [pscustomobject][ordered]@{
        FindingId           = $id
        Host                = $HostName
        ObservedAt          = $observed
        ObservedAtBasis     = $timeBasis
        CollectedAt         = $CollectedAt
        TimeZoneContext     = 'All timestamps are UTC (ISO 8601).'
        RuleId              = [string]$Rule.id
        RuleVersion         = [string]$Rule.version
        RuleName            = [string]$Rule.name
        Title               = $title
        Category            = [string]$Rule.category
        DataSource          = [string]$Rule.dataSource
        Severity            = [string]$Rule.severity
        Confidence          = [string]$Rule.confidence
        FindingType         = [string]$Rule.findingType
        Explanation         = ([string]$Rule.description + ' ' + [string]$Rule.rationale)
        EvidenceRequirements = @($Rule.evidenceRequirements)
        Evidence            = $evidence
        Attack              = $attack.ToArray()
        FalsePositives      = @($Rule.falsePositives)
        RecommendedNextStep = [string]$Rule.recommendedNextStep
        Remediation         = [string]$Rule.remediation
        Limitations         = $limitations
        ConfigOverrides     = @($Rule._overrides)
        OccurrenceCount     = 1
        Suppressed          = $false
        SuppressionId       = $null
        SuppressionReason   = $null
    }
}

function Find-WthSuppression {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$RuleId,
        [Parameter(Mandatory)][AllowNull()]$Item,
        [object[]]$Suppression,
        [Parameter(Mandatory)][datetime]$Now
    )

    foreach ($s in @($Suppression)) {
        if ($null -eq $s -or $s.RuleId -ne $RuleId) { continue }
        if ($null -ne $s.Expires -and $s.Expires -lt $Now) { continue }
        $all = $true
        foreach ($field in $s.Match.Keys) {
            $criterion = $s.Match[$field]
            $values = Get-WthValueSet -Value (Get-WthFieldValue -InputObject $Item -Path $field)
            $hit = $false
            foreach ($v in $values) {
                if ($criterion.Mode -eq 'equals') { if ([string]::Equals([string]$v, $criterion.Value, [System.StringComparison]::OrdinalIgnoreCase)) { $hit = $true; break } }
                elseif (Test-WthRegexMatch -Text ([string]$v) -Pattern $criterion.Value) { $hit = $true; break }
            }
            if (-not $hit) { $all = $false; break }
        }
        if ($all) { return $s }
    }
    return $null
}

function Invoke-WthRuleEvaluation {
    <#
    .SYNOPSIS
        Evaluates one effective rule over a set of items and returns findings plus diagnostics.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Rule,
        [AllowEmptyCollection()][object[]]$Item = @(),
        [Parameter(Mandatory)][hashtable]$Context,
        [Parameter(Mandatory)][hashtable]$Config,
        [Parameter(Mandatory)][hashtable]$AttackCatalog,
        [Parameter(Mandatory)][string]$HostName,
        [Parameter(Mandatory)][string]$CollectedAt,
        [object[]]$Suppression = @(),
        [datetime]$Now = (Get-WthUtcNow)
    )

    $findings = New-Object System.Collections.Generic.List[object]
    $warnings = New-Object System.Collections.Generic.List[string]
    $matched = New-Object System.Collections.Generic.List[object]
    foreach ($it in @($Item)) {
        if (Test-WthCondition -Condition $Rule.condition -Item $it -Context $Context) { $matched.Add($it) }
    }

    $cap = [int]$Config.limits.maxFindingsPerRule
    $truncated = $false

    if (Test-WthHasMember -InputObject $Rule -Name 'aggregate') {
        $agg = $Rule.aggregate
        $timeField = 'TimeCreated'
        if (Test-WthHasMember -InputObject $agg -Name 'timeField') { $timeField = [string]$agg.timeField }
        $window = [TimeSpan]::FromMinutes([double]$agg.windowMinutes)
        $groups = @{}
        $skipped = 0
        foreach ($it in $matched) {
            $t = ConvertFrom-WthIsoString -Value (Get-WthFieldValue -InputObject $it -Path $timeField)
            if ($null -eq $t) { $skipped++; continue }
            $keyParts = foreach ($g in @($agg.groupBy)) { (@(Get-WthFieldValue -InputObject $it -Path $g) -join ',').ToLowerInvariant() }
            $gk = ($keyParts -join '|')
            if (-not $groups.ContainsKey($gk)) { $groups[$gk] = New-Object System.Collections.Generic.List[object] }
            $groups[$gk].Add([pscustomobject]@{ Time = $t; Item = $it })
        }
        if ($skipped -gt 0) { $warnings.Add("$($Rule.id): $skipped matching item(s) had no parseable '$timeField' timestamp and were not counted.") }
        foreach ($gk in ($groups.Keys | Sort-Object)) {
            $entries = @($groups[$gk] | Sort-Object { $_.Time })
            $best = 0; $bestStart = 0; $start = 0
            for ($end = 0; $end -lt $entries.Count; $end++) {
                while (($entries[$end].Time - $entries[$start].Time) -gt $window) { $start++ }
                $size = $end - $start + 1
                if ($size -gt $best) { $best = $size; $bestStart = $start }
            }
            if ($best -lt [int]$agg.threshold) { continue }
            if ($findings.Count -ge $cap) { $truncated = $true; break }
            $first = $entries[$bestStart]
            $last = $entries[$bestStart + $best - 1]
            $aggregate = @{
                GroupKey      = $gk
                Count         = $best
                Threshold     = [int]$agg.threshold
                WindowMinutes = [int]$agg.windowMinutes
                FirstSeen     = (ConvertTo-WthIsoString -Value $first.Time)
                LastSeen      = (ConvertTo-WthIsoString -Value $last.Time)
            }
            $finding = Build-WthFinding -Rule $Rule -Item $first.Item -Config $Config -AttackCatalog $AttackCatalog -HostName $HostName -CollectedAt $CollectedAt -Aggregate $aggregate
            $sup = Find-WthSuppression -RuleId ([string]$Rule.id) -Item $first.Item -Suppression $Suppression -Now $Now
            if ($sup) { $finding.Suppressed = $true; $finding.SuppressionId = $sup.Id; $finding.SuppressionReason = $sup.Reason }
            $findings.Add($finding)
        }
    }
    else {
        foreach ($it in $matched) {
            if ($findings.Count -ge $cap) { $truncated = $true; break }
            $finding = Build-WthFinding -Rule $Rule -Item $it -Config $Config -AttackCatalog $AttackCatalog -HostName $HostName -CollectedAt $CollectedAt
            $sup = Find-WthSuppression -RuleId ([string]$Rule.id) -Item $it -Suppression $Suppression -Now $Now
            if ($sup) { $finding.Suppressed = $true; $finding.SuppressionId = $sup.Id; $finding.SuppressionReason = $sup.Reason }
            $findings.Add($finding)
        }
    }
    if ($truncated) { $warnings.Add("$($Rule.id): more than $cap findings; output truncated by limits.maxFindingsPerRule.") }
    return [pscustomobject]@{ Findings = $findings.ToArray(); Warnings = $warnings.ToArray(); ItemsEvaluated = @($Item).Count; ItemsMatched = $matched.Count }
}

function Merge-WthDuplicateFinding {
    <#
    .SYNOPSIS
        Collapses findings that share a FindingId into one finding with an OccurrenceCount.
    #>
    [CmdletBinding()]
    param([AllowEmptyCollection()][object[]]$Finding = @())

    $byId = [ordered]@{}
    foreach ($f in @($Finding)) {
        if ($byId.Contains($f.FindingId)) { $byId[$f.FindingId].OccurrenceCount++ }
        else { $byId[$f.FindingId] = $f }
    }
    return , @($byId.Values)
}

function Get-WthSuppressionData {
    <#
    .SYNOPSIS
        Loads and validates a suppression file. Suppressions need an ID, a rule, a written reason and at
        least one match criterion; they can expire. Suppressed findings stay visible in reports.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [long]$MaxBytes = 52428800
    )

    $json = Read-WthJsonFile -Path $Path -Label 'Suppression file' -MaxBytes $MaxBytes
    $errors = New-Object System.Collections.Generic.List[string]
    $list = New-Object System.Collections.Generic.List[object]
    $names = @(Get-WthMemberName -InputObject $json)
    foreach ($n in $names) { if ($n -notin 'schemaVersion', 'suppressions', 'comment') { $errors.Add("unknown top-level property '$n'") } }
    if ($json.schemaVersion -ne 1) { $errors.Add('schemaVersion must be 1') }
    if ($names -notcontains 'suppressions' -or $json.suppressions -is [string] -or $json.suppressions -isnot [System.Collections.IEnumerable]) {
        $errors.Add("'suppressions' must be an array")
        return [pscustomobject]@{ Suppressions = @(); Errors = $errors.ToArray() }
    }
    $seen = @{}
    $i = 0
    foreach ($s in @($json.suppressions)) {
        $where = "suppressions[$i]"
        $i++
        $sn = @(Get-WthMemberName -InputObject $s)
        $before = $errors.Count
        foreach ($n in $sn) { if ($n -notin 'id', 'ruleId', 'reason', 'match', 'expires', 'createdBy', 'comment') { $errors.Add("${where}: unknown property '$n'") } }
        foreach ($n in 'id', 'ruleId', 'reason', 'match') { if ($sn -notcontains $n) { $errors.Add("${where}: missing '$n'") } }
        if ($errors.Count -gt $before) { continue }
        if ($s.id -isnot [string] -or $s.id -notmatch '^SUP-[A-Za-z0-9_-]{1,40}$') { $errors.Add("${where}: 'id' must look like SUP-001") }
        elseif ($seen.ContainsKey($s.id)) { $errors.Add("${where}: duplicate suppression id '$($s.id)'") }
        else { $seen[$s.id] = $true }
        if ($s.ruleId -isnot [string] -or $s.ruleId -notmatch '^WTH-[A-Z]{2,8}-\d{3}$') { $errors.Add("${where}: 'ruleId' is not a valid rule ID") }
        if ($s.reason -isnot [string] -or $s.reason.Trim().Length -lt 15) { $errors.Add("${where}: 'reason' must be a written justification of at least 15 characters") }
        $match = @{}
        $mn = @(Get-WthMemberName -InputObject $s.match)
        if ($mn.Count -eq 0) { $errors.Add("${where}: 'match' must contain at least one field criterion (blanket suppression of a rule is not allowed)") }
        foreach ($field in $mn) {
            if ($field -notmatch '^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)*$') { $errors.Add("${where}: invalid match field '$field'"); continue }
            $crit = Get-WthFieldValue -InputObject $s.match -Path $field
            if ($crit -is [string] -or $crit -is [bool] -or $crit -is [int] -or $crit -is [long]) { $match[$field] = @{ Mode = 'equals'; Value = [string]$crit } }
            else {
                $cn = @(Get-WthMemberName -InputObject $crit)
                if ($cn.Count -eq 1 -and $cn[0] -eq 'equals') { $match[$field] = @{ Mode = 'equals'; Value = [string]$crit.equals } }
                elseif ($cn.Count -eq 1 -and $cn[0] -eq 'matches') {
                    $issue = Get-WthRegexIssue -Pattern ([string]$crit.matches)
                    if ($issue) { $errors.Add("${where}: match '$field' regex rejected - $issue") } else { $match[$field] = @{ Mode = 'matches'; Value = [string]$crit.matches } }
                }
                else { $errors.Add("${where}: match '$field' must be a string or an object with a single 'equals' or 'matches' key") }
            }
        }
        $expires = $null
        if ($sn -contains 'expires') {
            $expires = ConvertFrom-WthIsoString -Value $s.expires
            if ($null -eq $expires) { $errors.Add("${where}: 'expires' is not a valid date") }
        }
        if ($errors.Count -eq $before) {
            $list.Add([pscustomobject]@{ Id = $s.id; RuleId = $s.ruleId; Reason = $s.reason.Trim(); Match = $match; Expires = $expires })
        }
    }
    return [pscustomobject]@{ Suppressions = $list.ToArray(); Errors = $errors.ToArray() }
}
