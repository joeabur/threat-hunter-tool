#Requires -Version 5.1
# Configuration schema validation. Configuration is data: lists, regex patterns, limits and overrides.

function Test-WthConfigurationData {
    <#
    .SYNOPSIS
        Validates a configuration hashtable. Returns an object with Errors and Warnings arrays.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowNull()]$Config)

    $errors = New-Object System.Collections.Generic.List[string]
    $warnings = New-Object System.Collections.Generic.List[string]

    if ($Config -isnot [hashtable]) {
        $errors.Add('Configuration must be a JSON object.')
        return [pscustomobject]@{ IsValid = $false; Errors = $errors.ToArray(); Warnings = @() }
    }

    $topKeys = @('schemaVersion', 'collection', 'limits', 'redaction', 'lists', 'patterns', 'ruleOverrides', 'reporting', 'suppressionFile', 'comment')
    foreach ($k in $Config.Keys) { if ($k -notin $topKeys) { $errors.Add("Unknown top-level key '$k'.") } }
    if ($Config.schemaVersion -ne $script:WthConfigSchemaVersion) {
        $errors.Add("schemaVersion must be $script:WthConfigSchemaVersion.")
    }
    foreach ($section in 'collection', 'limits', 'redaction', 'lists', 'patterns', 'ruleOverrides', 'reporting') {
        if (-not $Config.ContainsKey($section) -or $Config[$section] -isnot [hashtable]) { $errors.Add("Section '$section' is required and must be an object.") }
    }
    if ($errors.Count -gt 0) { return [pscustomobject]@{ IsValid = $false; Errors = $errors.ToArray(); Warnings = $warnings.ToArray() } }

    # --- collection
    $c = $Config.collection
    $allowed = @('collectors', 'eventLookbackHours', 'maxEventsPerChannel', 'maxProcesses', 'fileMetadata', 'maxFilesToHash', 'privilegedGroups', 'includeProcessOwner', 'includeOtherUserProfiles')
    foreach ($k in $c.Keys) { if ($k -notin $allowed) { $errors.Add("collection: unknown key '$k'.") } }
    foreach ($name in @($c.collectors)) {
        if ($name -isnot [string] -or -not $script:WthCollectorMap.Contains($name)) {
            $errors.Add("collection.collectors: unknown collector '$name'. Allowed: $($script:WthCollectorMap.Keys -join ', ').")
        }
    }
    if (@($c.collectors).Count -eq 0) { $errors.Add('collection.collectors must list at least one collector.') }
    $ranges = @{ eventLookbackHours = @(1, 720); maxEventsPerChannel = @(1, 50000); maxProcesses = @(1, 100000); maxFilesToHash = @(0, 5000) }
    foreach ($key in $ranges.Keys) {
        $v = $c[$key]
        if ($null -eq $v -or $v -isnot [int] -and $v -isnot [long]) { $errors.Add("collection.$key must be an integer."); continue }
        if ($v -lt $ranges[$key][0] -or $v -gt $ranges[$key][1]) { $errors.Add("collection.$key must be between $($ranges[$key][0]) and $($ranges[$key][1]).") }
    }
    if ($c.fileMetadata -notin 'None', 'Basic', 'Hash', 'HashAndSignature') { $errors.Add("collection.fileMetadata must be None, Basic, Hash or HashAndSignature.") }
    foreach ($b in 'includeProcessOwner', 'includeOtherUserProfiles') { if ($c[$b] -isnot [bool]) { $errors.Add("collection.$b must be true or false.") } }
    foreach ($g in @($c.privilegedGroups)) { if ($g -isnot [string] -or [string]::IsNullOrWhiteSpace($g)) { $errors.Add('collection.privilegedGroups must contain non-empty strings.') } }

    # --- limits
    $l = $Config.limits
    $limitRanges = @{
        maxInputFileBytes      = @(1024, 1073741824)
        maxRegexInputLength    = @(64, 1048576)
        maxEvidenceValueLength = @(32, 65536)
        maxEventDataLength     = @(64, 1048576)
        maxFindingsPerRule     = @(1, 100000)
        maxItemsPerDataSource  = @(1, 1000000)
    }
    foreach ($k in $l.Keys) { if (-not $limitRanges.ContainsKey($k)) { $errors.Add("limits: unknown key '$k'.") } }
    foreach ($key in $limitRanges.Keys) {
        $v = $l[$key]
        if ($null -eq $v -or $v -isnot [int] -and $v -isnot [long]) { $errors.Add("limits.$key must be an integer."); continue }
        if ($v -lt $limitRanges[$key][0] -or $v -gt $limitRanges[$key][1]) { $errors.Add("limits.$key must be between $($limitRanges[$key][0]) and $($limitRanges[$key][1]).") }
    }

    # --- redaction
    $r = $Config.redaction
    foreach ($k in $r.Keys) { if ($k -notin 'enabled', 'maskUserProfilePaths', 'principalFields', 'secretPatterns') { $errors.Add("redaction: unknown key '$k'.") } }
    foreach ($b in 'enabled', 'maskUserProfilePaths') { if ($r[$b] -isnot [bool]) { $errors.Add("redaction.$b must be true or false.") } }
    if ($r.enabled -eq $false) { $warnings.Add('Redaction is disabled: reports will contain unmasked user names and command-line secrets.') }
    foreach ($p in @($r.principalFields)) { if ($p -isnot [string] -or $p -notmatch '^[A-Za-z][A-Za-z0-9_]*$') { $errors.Add("redaction.principalFields: invalid field name '$p'.") } }
    foreach ($p in @($r.secretPatterns)) {
        $issue = Get-WthRegexIssue -Pattern ([string]$p)
        if ($issue) { $errors.Add("redaction.secretPatterns: '$p' rejected - $issue") }
    }

    # --- lists and patterns
    foreach ($name in $Config.lists.Keys) {
        if ($name -notmatch '^[A-Za-z][A-Za-z0-9_]*$') { $errors.Add("lists: invalid list name '$name'."); continue }
        $entries = $Config.lists[$name]
        if ($entries -isnot [System.Collections.IEnumerable] -or $entries -is [string]) { $errors.Add("lists.${name} must be an array of strings."); continue }
        if (@($entries).Count -gt 2000) { $errors.Add("lists.${name} has more than 2000 entries.") }
        foreach ($e in @($entries)) { if ($e -isnot [string]) { $errors.Add("lists.${name} must contain only strings."); break } }
    }
    foreach ($name in $Config.patterns.Keys) {
        if ($name -notmatch '^[A-Za-z][A-Za-z0-9_]*$') { $errors.Add("patterns: invalid pattern list name '$name'."); continue }
        $entries = $Config.patterns[$name]
        if ($entries -isnot [System.Collections.IEnumerable] -or $entries -is [string]) { $errors.Add("patterns.${name} must be an array of regular expressions."); continue }
        if (@($entries).Count -gt 200) { $errors.Add("patterns.${name} has more than 200 entries.") }
        foreach ($e in @($entries)) {
            if ($e -isnot [string]) { $errors.Add("patterns.${name} must contain only strings."); break }
            $issue = Get-WthRegexIssue -Pattern $e
            if ($issue) { $errors.Add("patterns.${name}: '$e' rejected - $issue") }
        }
    }

    # --- ruleOverrides
    foreach ($id in $Config.ruleOverrides.Keys) {
        if ($id -notmatch '^WTH-[A-Z]{2,8}-\d{3}$') { $errors.Add("ruleOverrides: '$id' is not a valid rule ID."); continue }
        $o = $Config.ruleOverrides[$id]
        if ($o -isnot [hashtable]) { $errors.Add("ruleOverrides.$id must be an object."); continue }
        foreach ($k in $o.Keys) {
            switch ($k) {
                'enabled' { if ($o[$k] -isnot [bool]) { $errors.Add("ruleOverrides.$id.enabled must be true or false.") } }
                'severity' { if ($null -eq $script:WthSeverityOrder[[string]$o[$k]]) { $errors.Add("ruleOverrides.$id.severity must be one of $($script:WthSeverityOrder.Keys -join ', ').") } }
                'confidence' { if ($o[$k] -notin $script:WthConfidenceValues) { $errors.Add("ruleOverrides.$id.confidence must be Low, Medium or High.") } }
                'threshold' { if (($o[$k] -isnot [int] -and $o[$k] -isnot [long]) -or $o[$k] -lt 1 -or $o[$k] -gt 100000) { $errors.Add("ruleOverrides.$id.threshold must be an integer between 1 and 100000.") } }
                'windowMinutes' { if (($o[$k] -isnot [int] -and $o[$k] -isnot [long]) -or $o[$k] -lt 1 -or $o[$k] -gt 10080) { $errors.Add("ruleOverrides.$id.windowMinutes must be an integer between 1 and 10080.") } }
                'comment' { }
                default { $errors.Add("ruleOverrides.${id}: unknown key '$k'.") }
            }
        }
    }

    # --- reporting
    $rep = $Config.reporting
    foreach ($k in $rep.Keys) { if ($k -notin 'formats', 'includeSuppressed') { $errors.Add("reporting: unknown key '$k'.") } }
    foreach ($f in @($rep.formats)) { if ($f -notin 'Json', 'Csv', 'Html') { $errors.Add("reporting.formats: '$f' is not one of Json, Csv, Html.") } }
    if ($rep.includeSuppressed -isnot [bool]) { $errors.Add('reporting.includeSuppressed must be true or false.') }

    if ($Config.ContainsKey('suppressionFile') -and $null -ne $Config.suppressionFile -and $Config.suppressionFile -isnot [string]) {
        $errors.Add('suppressionFile must be a string path or null.')
    }

    return [pscustomobject]@{ IsValid = ($errors.Count -eq 0); Errors = $errors.ToArray(); Warnings = $warnings.ToArray() }
}

function Get-WthModuleRoot {
    [CmdletBinding()]
    [OutputType([string])]
    param()
    return $script:WthProjectRoot
}
