#Requires -Version 5.1
# Rule catalog loading and validation.

$script:WthRuleKeys = @(
    'id', 'name', 'version', 'category', 'dataSource', 'severity', 'confidence', 'findingType',
    'description', 'rationale', 'evidenceRequirements', 'condition', 'aggregate', 'evidenceFields',
    'titleTemplate', 'attack', 'falsePositives', 'recommendedNextStep', 'remediation', 'references',
    'limitations', 'enabled', 'dedupeFields'
)
$script:WthRuleRequired = @(
    'id', 'name', 'version', 'category', 'dataSource', 'severity', 'confidence', 'findingType',
    'description', 'rationale', 'evidenceRequirements', 'condition', 'evidenceFields', 'titleTemplate',
    'attack', 'falsePositives', 'recommendedNextStep', 'remediation'
)
$script:WthAggregateKeys = @('groupBy', 'threshold', 'windowMinutes', 'timeField')

function Read-WthAttackCatalog {
    <#
    .SYNOPSIS
        Loads the ATT&CK technique catalog (ID, official title, tactics, URL) shipped with the toolkit.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) { $Path = $script:WthAttackCatalogPath }
    $json = Read-WthJsonFile -Path $Path -Label 'ATT&CK catalog'
    $catalog = @{}
    foreach ($t in @($json.techniques)) {
        $catalog[[string]$t.id] = [pscustomobject]@{
            Id      = [string]$t.id
            Name    = [string]$t.name
            Tactics = @($t.tactics | ForEach-Object { [string]$_ })
            Url     = [string]$t.url
        }
    }
    return $catalog
}

function Get-WthAttackUrl {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory, Position = 0)][string]$TechniqueId)

    return 'https://attack.mitre.org/techniques/' + $TechniqueId.Replace('.', '/') + '/'
}

function Test-WthRuleDefinition {
    <#
    .SYNOPSIS
        Validates one rule object against the rule schema. Returns an array of error strings.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)]$Rule,
        [Parameter(Mandatory)][hashtable]$Config,
        [Parameter(Mandatory)][hashtable]$AttackCatalog
    )

    $e = New-Object System.Collections.Generic.List[string]
    $names = @(Get-WthMemberName -InputObject $Rule)
    foreach ($n in $names) { if ($n -notin $script:WthRuleKeys) { $e.Add("unknown property '$n'") } }
    foreach ($n in $script:WthRuleRequired) { if ($n -notin $names) { $e.Add("missing required property '$n'") } }
    if ($e.Count -gt 0) { return , $e.ToArray() }

    $text = { param($v) ($v -is [string]) -and -not [string]::IsNullOrWhiteSpace($v) }
    foreach ($n in 'name', 'description', 'rationale', 'recommendedNextStep', 'remediation', 'titleTemplate') {
        if (-not (& $text $Rule.$n)) { $e.Add("'$n' must be a non-empty string") }
    }
    if ($Rule.id -isnot [string] -or $Rule.id -notmatch '^WTH-[A-Z]{2,8}-\d{3}$') { $e.Add("'id' must match WTH-<AREA>-<NNN> (for example WTH-TASK-001)") }
    if ($Rule.version -isnot [string] -or $Rule.version -notmatch '^\d+\.\d+\.\d+$') { $e.Add("'version' must be a semantic version such as 1.0.0") }
    if ($Rule.category -notin $script:WthCategories) { $e.Add("'category' must be one of: $($script:WthCategories -join ', ')") }
    if ($Rule.dataSource -notin $script:WthDataSources) { $e.Add("'dataSource' must be one of: $($script:WthDataSources -join ', ')") }
    if ($null -eq $script:WthSeverityOrder[[string]$Rule.severity]) { $e.Add("'severity' must be one of: $($script:WthSeverityOrder.Keys -join ', ')") }
    if ($Rule.confidence -notin $script:WthConfidenceValues) { $e.Add("'confidence' must be one of: $($script:WthConfidenceValues -join ', ')") }
    if ($Rule.findingType -notin $script:WthFindingTypes) { $e.Add("'findingType' must be one of: $($script:WthFindingTypes -join ', ')") }
    if ($names -contains 'enabled' -and $Rule.enabled -isnot [bool]) { $e.Add("'enabled' must be true or false") }

    foreach ($arr in 'evidenceRequirements', 'falsePositives', 'evidenceFields') {
        $v = $Rule.$arr
        if ($null -eq $v -or $v -is [string] -or $v -isnot [System.Collections.IEnumerable] -or @($v).Count -eq 0) { $e.Add("'$arr' must be a non-empty array of strings"); continue }
        foreach ($x in @($v)) { if (-not (& $text $x)) { $e.Add("'$arr' must contain only non-empty strings"); break } }
    }
    foreach ($arr in 'references', 'limitations', 'dedupeFields') {
        if ($names -notcontains $arr) { continue }
        $v = $Rule.$arr
        if ($null -eq $v -or $v -is [string] -or $v -isnot [System.Collections.IEnumerable]) { $e.Add("'$arr' must be an array of strings"); continue }
        foreach ($x in @($v)) { if (-not (& $text $x)) { $e.Add("'$arr' must contain only non-empty strings"); break } }
    }
    if ($names -contains 'references') {
        foreach ($ref in @($Rule.references)) { if ($ref -is [string] -and $ref -notmatch '^https://') { $e.Add("reference '$ref' must be an https URL") } }
    }
    foreach ($f in @($Rule.evidenceFields)) {
        if ($f -is [string] -and $f -notmatch '^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)*$') { $e.Add("evidence field '$f' is not a valid field path") }
    }
    if ($names -contains 'dedupeFields') {
        foreach ($f in @($Rule.dedupeFields)) {
            if ($f -is [string] -and $f -notmatch '^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)*$') { $e.Add("dedupe field '$f' is not a valid field path") }
        }
    }

    # ATT&CK mapping: attack may be empty only when no technique is justified; each ID must be in the catalog.
    if ($Rule.attack -is [string] -or $Rule.attack -isnot [System.Collections.IEnumerable]) { $e.Add("'attack' must be an array of technique IDs (use [] when no mapping is justified)") }
    else {
        foreach ($t in @($Rule.attack)) {
            if ($t -isnot [string] -or $t -notmatch '^T\d{4}(\.\d{3})?$') { $e.Add("attack technique '$t' is not a valid ID (expected T#### or T####.###)") }
            elseif (-not $AttackCatalog.ContainsKey($t)) { $e.Add("attack technique '$t' is not in the shipped ATT&CK catalog (config/attack-techniques.json)") }
        }
    }

    # Title template placeholders must be evidence fields (or the item's own fields listed there).
    if ($Rule.titleTemplate -is [string]) {
        $allowed = @($Rule.evidenceFields)
        foreach ($m in [regex]::Matches($Rule.titleTemplate, '\{([^{}]*)\}')) {
            if ($m.Groups[1].Value -notin $allowed -and $m.Groups[1].Value -notin 'Count', 'Threshold', 'WindowMinutes') {
                $e.Add("titleTemplate placeholder '{$($m.Groups[1].Value)}' is not listed in evidenceFields")
            }
        }
    }

    foreach ($issue in (Test-WthConditionStructure -Condition $Rule.condition -Config $Config)) { $e.Add($issue) }

    if ($names -contains 'aggregate') {
        $agg = $Rule.aggregate
        $an = @(Get-WthMemberName -InputObject $agg)
        foreach ($n in $an) { if ($n -notin $script:WthAggregateKeys) { $e.Add("aggregate: unknown property '$n'") } }
        if ($an -notcontains 'groupBy' -or $null -eq $agg.groupBy -or $agg.groupBy -is [string] -or @($agg.groupBy).Count -eq 0) { $e.Add("aggregate.groupBy must be a non-empty array of field names") }
        else { foreach ($g in @($agg.groupBy)) { if ($g -isnot [string] -or $g -notmatch '^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)*$') { $e.Add("aggregate.groupBy contains an invalid field '$g'") } } }
        if ($an -notcontains 'threshold' -or ($agg.threshold -isnot [int] -and $agg.threshold -isnot [long]) -or $agg.threshold -lt 1 -or $agg.threshold -gt 100000) { $e.Add('aggregate.threshold must be an integer between 1 and 100000') }
        if ($an -notcontains 'windowMinutes' -or ($agg.windowMinutes -isnot [int] -and $agg.windowMinutes -isnot [long]) -or $agg.windowMinutes -lt 1 -or $agg.windowMinutes -gt 10080) { $e.Add('aggregate.windowMinutes must be an integer between 1 and 10080') }
        if ($an -contains 'timeField' -and ($agg.timeField -isnot [string] -or $agg.timeField -notmatch '^[A-Za-z][A-Za-z0-9_.]*$')) { $e.Add('aggregate.timeField must be a field name') }
    }
    return , $e.ToArray()
}

function Read-WthRuleFile {
    <#
    .SYNOPSIS
        Reads one rule file ({ "schemaVersion": 1, "rules": [ ... ] }) and returns its rule objects.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [long]$MaxBytes = 52428800
    )

    $json = Read-WthJsonFile -Path $Path -Label 'Rule file' -MaxBytes $MaxBytes
    $names = @(Get-WthMemberName -InputObject $json)
    foreach ($n in $names) { if ($n -notin 'schemaVersion', 'rules', 'comment') { throw [System.ArgumentException]::new("Rule file '$Path' has unknown top-level property '$n'.") } }
    if ($json.schemaVersion -ne $script:WthRuleSchemaVersion) {
        throw [System.ArgumentException]::new("Rule file '$Path' must declare schemaVersion $script:WthRuleSchemaVersion.")
    }
    if ($names -notcontains 'rules' -or $json.rules -is [string] -or $json.rules -isnot [System.Collections.IEnumerable]) {
        throw [System.ArgumentException]::new("Rule file '$Path' must contain a 'rules' array.")
    }
    return , @($json.rules)
}

function Get-WthRuleFileList {
    [CmdletBinding()]
    [OutputType([string[]])]
    param([Parameter(Mandatory)][string]$Path)

    if ([System.IO.Directory]::Exists($Path)) {
        $dir = Resolve-WthInputPath -Path $Path -Type Directory -Label 'Rule directory'
        return , @(Get-ChildItem -LiteralPath $dir -Filter '*.json' -File | Sort-Object Name | ForEach-Object { $_.FullName })
    }
    $file = Resolve-WthInputPath -Path $Path -Type File -Label 'Rule file'
    return , @($file)
}

function Import-WthRuleSet {
    <#
    .SYNOPSIS
        Loads and validates every rule under a path. Returns rules and per-rule validation results.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][hashtable]$Config
    )

    $catalog = Read-WthAttackCatalog
    $results = New-Object System.Collections.Generic.List[object]
    $rules = New-Object System.Collections.Generic.List[object]
    $seen = @{}
    foreach ($file in (Get-WthRuleFileList -Path $Path)) {
        $leaf = [System.IO.Path]::GetFileName($file)
        try {
            $fileRules = Read-WthRuleFile -Path $file -MaxBytes $Config.limits.maxInputFileBytes
        }
        catch {
            $results.Add([pscustomobject]@{ RuleId = $null; Source = $leaf; IsValid = $false; Errors = @($_.Exception.Message) })
            continue
        }
        foreach ($rule in $fileRules) {
            $id = [string](Get-WthFieldValue -InputObject $rule -Path 'id')
            $errs = New-Object System.Collections.Generic.List[string]
            foreach ($x in (Test-WthRuleDefinition -Rule $rule -Config $Config -AttackCatalog $catalog)) { $errs.Add($x) }
            if ($id) {
                if ($seen.ContainsKey($id)) { $errs.Add("duplicate rule ID '$id' (also defined in $($seen[$id]))") }
                else { $seen[$id] = $leaf }
            }
            $results.Add([pscustomobject]@{ RuleId = $id; Source = $leaf; IsValid = ($errs.Count -eq 0); Errors = $errs.ToArray() })
            if ($errs.Count -eq 0) { $rules.Add($rule) }
        }
    }
    return [pscustomobject]@{ Rules = $rules.ToArray(); Results = $results.ToArray(); AttackCatalog = $catalog }
}
