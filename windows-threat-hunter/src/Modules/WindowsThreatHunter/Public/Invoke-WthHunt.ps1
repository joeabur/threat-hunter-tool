function Invoke-WthHunt {
    <#
    .SYNOPSIS
        Runs the detection rules over a snapshot (live collection, saved file or object) and returns findings.

    .DESCRIPTION
        Loads and validates the configuration and rule catalog, obtains a snapshot, then evaluates every enabled
        rule whose data source was actually collected. Rules whose data source is unavailable, needs elevation or
        failed are listed under RulesSkipped, and the gap is listed under CoverageGaps: missing telemetry is never
        treated as "clean".

        The hunt is read-only. With no snapshot parameter it performs a live read-only collection (Windows only).

        Findings carry the host, observation time, rule ID and version, evidence, severity and confidence (kept as
        separate values), explanation, false-positive guidance and a recommended next step. Duplicate findings are
        merged (OccurrenceCount). Suppressed findings stay in SuppressedFindings with their written reason.

    .PARAMETER SnapshotPath
        Hunt over a saved or synthetic snapshot file (any OS).

    .PARAMETER Snapshot
        Hunt over a snapshot object from Invoke-WthCollection or Import-WthSnapshot.

    .PARAMETER Collector
        Live mode only: limit collection to these collectors.

    .PARAMETER ConfigPath
        Configuration override file. Default: config/default.json only.

    .PARAMETER Config
        Configuration hashtable from Get-WthConfiguration (takes precedence over -ConfigPath).

    .PARAMETER RulePath
        Rule file or directory. Default: the shipped src/Rules directory. Invalid rules stop the hunt.

    .PARAMETER RuleId
        Run only these rule IDs (wildcards allowed).

    .PARAMETER Category
        Run only rules in these categories.

    .PARAMETER MinimumSeverity
        Run only rules whose effective severity is at least this level.

    .PARAMETER SuppressionPath
        Suppression file. Default: suppressionFile from the configuration, if set.

    .PARAMETER DefenderXdrPath
        Optional Defender XDR export (.json or .csv) to merge as the DefenderXdr data source.

    .EXAMPLE
        $result = Invoke-WthHunt -SnapshotPath .\sample-data\snapshots\suspicious-persistence.json
        $result.Findings | Format-Table Severity, Confidence, RuleId, Title

    .EXAMPLE
        Invoke-WthHunt -SnapshotPath .\sample-data\snapshots\suspicious-persistence.json -RuleId 'WTH-TASK-*' -MinimumSeverity High

    .EXAMPLE
        Invoke-WthHunt -Collector ScheduledTasks, Services, RegistryRun     # live, read-only

    .OUTPUTS
        PSCustomObject (hunt result). Pass it to Export-WthReport or Get-WthExitCode.
    #>
    [CmdletBinding(DefaultParameterSetName = 'Live')]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, ParameterSetName = 'File')][string]$SnapshotPath,
        [Parameter(Mandatory, ParameterSetName = 'Object')]$Snapshot,
        [Parameter(ParameterSetName = 'Live')]
        [ValidateSet('ScheduledTasks', 'Services', 'RegistryRun', 'StartupFolders', 'WmiSubscriptions', 'LocalAccounts', 'Processes', 'Network', 'Defender', 'SecurityEvents', 'PowerShellEvents', 'SysmonEvents')]
        [string[]]$Collector,
        [string]$ConfigPath,
        [hashtable]$Config,
        [string]$RulePath = $script:WthRulesPath,
        [string[]]$RuleId,
        [string[]]$Category,
        [ValidateSet('Informational', 'Low', 'Medium', 'High', 'Critical')][string]$MinimumSeverity = 'Informational',
        [string]$SuppressionPath,
        [string]$DefenderXdrPath
    )

    $started = Get-WthUtcNow
    if (-not $Config) {
        $Config = if ($PSBoundParameters.ContainsKey('ConfigPath')) { Get-WthConfiguration -Path $ConfigPath } else { Get-WthConfiguration }
    }

    # --- rules: any invalid rule is a hard error so a typo can never silently disable detection
    $set = Import-WthRuleSet -Path $RulePath -Config $Config
    $invalid = @($set.Results | Where-Object { -not $_.IsValid })
    if ($invalid.Count -gt 0) {
        $lines = foreach ($r in $invalid) { " - $($r.RuleId) ($($r.Source)): $($r.Errors -join '; ')" }
        throw [System.ArgumentException]::new("Rule validation failed:`n" + ($lines -join "`n"))
    }

    # --- snapshot
    $origin = 'Live'
    $snap = $null
    switch ($PSCmdlet.ParameterSetName) {
        'File' { $snap = Import-WthSnapshot -Path $SnapshotPath -Config $Config; $origin = if ($snap.Synthetic) { 'Synthetic' } else { 'Snapshot' } }
        'Object' { $snap = $Snapshot; $origin = if ($snap.PSObject.Properties['Synthetic'] -and $snap.Synthetic) { 'Synthetic' } elseif ($snap.PSObject.Properties['Description'] -and $snap.Description -like 'Live collection*') { 'Live' } else { 'Snapshot' } }
        default { $snap = if ($Collector) { Invoke-WthCollection -Config $Config -Collector $Collector } else { Invoke-WthCollection -Config $Config } }
    }
    foreach ($req in 'Host', 'CollectedAt', 'Coverage', 'Items', 'Environment') {
        if (-not $snap.PSObject.Properties[$req]) { throw [System.ArgumentException]::new("Snapshot object is missing '$req'.") }
    }
    $warnings = New-Object System.Collections.Generic.List[string]
    if ($snap.PSObject.Properties['Warnings']) { foreach ($w in @($snap.Warnings)) { $warnings.Add([string]$w) } }

    $coverage = New-Object System.Collections.Generic.List[object]
    foreach ($c in @($snap.Coverage)) { $coverage.Add($c) }
    $items = @{}
    foreach ($k in $snap.Items.Keys) { $items[$k] = @($snap.Items[$k]) }

    if ($PSBoundParameters.ContainsKey('DefenderXdrPath')) {
        $xdr = Import-WthDefenderXdrEvent -Path $DefenderXdrPath -Config $Config
        $items['DefenderXdr'] = @($xdr.Items)
        foreach ($w in $xdr.Warnings) { $warnings.Add("Defender XDR import: $w") }
        foreach ($d in @($xdr.Items | Where-Object { $_.DeviceName -and $_.DeviceName -ine $snap.Host } | Select-Object -First 1)) {
            $warnings.Add("Defender XDR import contains events for other devices (for example '$($d.DeviceName)'); they were still evaluated.")
        }
        for ($i = $coverage.Count - 1; $i -ge 0; $i--) { if ($coverage[$i].DataSource -eq 'DefenderXdr') { $coverage.RemoveAt($i) } }
        $coverage.Add([pscustomobject][ordered]@{
                DataSource = 'DefenderXdr'; Collector = 'Import'; Status = 'Imported'; ItemCount = @($xdr.Items).Count
                RequiresElevation = 'No'; Message = "Imported from file '$($xdr.Source)'; $($xdr.Skipped) row(s) skipped. This is exported data, not a live query."
            })
    }

    # --- suppressions
    $suppressions = @()
    $suppressionFile = $SuppressionPath
    if (-not $suppressionFile -and $Config.ContainsKey('suppressionFile') -and $Config.suppressionFile) { $suppressionFile = [string]$Config.suppressionFile }
    if ($suppressionFile) {
        $loaded = Get-WthSuppressionData -Path $suppressionFile -MaxBytes ([long]$Config.limits.maxInputFileBytes)
        if ($loaded.Errors.Count -gt 0) { throw [System.ArgumentException]::new("Suppression file is invalid:`n - " + ($loaded.Errors -join "`n - ")) }
        $suppressions = @($loaded.Suppressions)
        $known = @($set.Rules | ForEach-Object { $_.id })
        foreach ($s in $suppressions) {
            if ($s.RuleId -notin $known) { $warnings.Add("Suppression $($s.Id) refers to unknown rule $($s.RuleId); it has no effect.") }
            if ($null -ne $s.Expires -and $s.Expires -lt $started) { $warnings.Add("Suppression $($s.Id) expired on $($s.Expires.ToString('yyyy-MM-dd')) and was ignored.") }
        }
    }
    foreach ($id in $Config.ruleOverrides.Keys) {
        if ($id -notin @($set.Rules | ForEach-Object { $_.id })) { $warnings.Add("Configuration override for unknown rule $id has no effect.") }
    }

    # --- evaluate
    $previousEnvironment = $script:WthEnvironment
    $script:WthEnvironment = $snap.Environment
    Reset-WthRegexState -Confirm:$false
    $executed = New-Object System.Collections.Generic.List[object]
    $skipped = New-Object System.Collections.Generic.List[object]
    $allFindings = New-Object System.Collections.Generic.List[object]
    $filtered = 0
    try {
        $context = Build-WthEvalContext -Config $Config -Environment $snap.Environment
        $minRank = Get-WthSeverityRank -Severity $MinimumSeverity
        foreach ($rawRule in $set.Rules) {
            $rule = Get-WthEffectiveRule -Rule $rawRule -Config $Config
            if ($RuleId -and -not ($RuleId | Where-Object { $rule.id -like $_ })) { $filtered++; continue }
            if ($Category -and $rule.category -notin $Category) { $filtered++; continue }
            if ((Get-WthSeverityRank -Severity $rule.severity) -lt $minRank) { $filtered++; continue }
            if (-not $rule.enabled) { $skipped.Add([pscustomobject]@{ RuleId = $rule.id; DataSource = $rule.dataSource; Optional = $true; Reason = 'Disabled (rule file or ruleOverrides).' }); continue }

            $cov = @($coverage | Where-Object { $_.DataSource -eq $rule.dataSource } | Select-Object -First 1)
            if ($cov.Count -eq 0) {
                $optional = ($rule.dataSource -eq 'DefenderXdr')
                $why = if ($optional) { 'Optional data source: no Defender XDR export was provided (-DefenderXdrPath).' } else { "No coverage information for data source '$($rule.dataSource)'; it was not collected or imported." }
                $skipped.Add([pscustomobject]@{ RuleId = $rule.id; DataSource = $rule.dataSource; Optional = $optional; Reason = $why })
                continue
            }
            if ($cov[0].Status -notin 'Collected', 'Partial', 'Imported') {
                $skipped.Add([pscustomobject]@{ RuleId = $rule.id; DataSource = $rule.dataSource; Optional = $false; Reason = "Data source '$($rule.dataSource)' is $($cov[0].Status): $($cov[0].Message)".Trim() })
                continue
            }
            $ruleItems = @()
            if ($items.ContainsKey($rule.dataSource)) { $ruleItems = @($items[$rule.dataSource]) }
            $eval = Invoke-WthRuleEvaluation -Rule $rule -Item $ruleItems -Context $context -Config $Config -AttackCatalog $set.AttackCatalog `
                -HostName $snap.Host -CollectedAt $snap.CollectedAt -Suppression $suppressions -Now $started
            foreach ($w in $eval.Warnings) { $warnings.Add($w) }
            foreach ($f in $eval.Findings) { $allFindings.Add($f) }
            $executed.Add([pscustomobject][ordered]@{
                    RuleId = $rule.id; Version = $rule.version; DataSource = $rule.dataSource
                    ItemsEvaluated = $eval.ItemsEvaluated; ItemsMatched = $eval.ItemsMatched; FindingCount = @($eval.Findings).Count
                    DataSourceStatus = $cov[0].Status
                })
        }
    }
    finally {
        $script:WthEnvironment = $previousEnvironment
    }
    $timeouts = Get-WthRegexTimeoutCount
    if ($timeouts -gt 0) { $warnings.Add("$timeouts regular-expression evaluation(s) timed out and were treated as no match.") }

    $merged = Merge-WthDuplicateFinding -Finding $allFindings.ToArray()
    $sorted = @($merged | Sort-Object @{ Expression = { Get-WthSeverityRank -Severity $_.Severity }; Descending = $true }, RuleId, ObservedAt, FindingId)
    $active = @($sorted | Where-Object { -not $_.Suppressed })
    $suppressed = @($sorted | Where-Object { $_.Suppressed })

    $bySeverity = [ordered]@{}
    foreach ($sev in 'Critical', 'High', 'Medium', 'Low', 'Informational') { $bySeverity[$sev] = @($active | Where-Object { $_.Severity -eq $sev }).Count }
    $byConfidence = [ordered]@{}
    foreach ($conf in 'High', 'Medium', 'Low') { $byConfidence[$conf] = @($active | Where-Object { $_.Confidence -eq $conf }).Count }
    $byType = [ordered]@{}
    foreach ($t in $script:WthFindingTypes) { $byType[$t] = @($active | Where-Object { $_.FindingType -eq $t }).Count }

    $attackSummary = New-Object System.Collections.Generic.List[object]
    $techniqueIds = @($active | ForEach-Object { $_.Attack } | ForEach-Object { $_.Id } | Sort-Object -Unique)
    foreach ($tid in $techniqueIds) {
        $entry = $set.AttackCatalog[$tid]
        $attackSummary.Add([pscustomobject][ordered]@{
                Id = $tid; Name = $entry.Name; Url = $entry.Url; Tactics = @($entry.Tactics)
                FindingCount = @($active | Where-Object { @($_.Attack | ForEach-Object { $_.Id }) -contains $tid }).Count
            })
    }

    $gaps = @($coverage | Where-Object { $_.Status -notin 'Collected', 'Imported' } | ForEach-Object {
            [pscustomobject][ordered]@{ DataSource = $_.DataSource; Status = $_.Status; Message = $_.Message }
        })
    $totalItems = 0
    foreach ($k in $items.Keys) { $totalItems += @($items[$k]).Count }

    $limitations = @(
        'Findings are leads for an analyst, not verdicts. No finding proves compromise, and rules use transparent heuristics that have documented benign causes.',
        'The absence of findings does not mean the endpoint is clean. Check CoverageGaps and RulesSkipped for data that was not collected.',
        'Collection is a point-in-time read. Short-lived processes, connections and events outside the configured lookback or removed by log rotation or clearing are not visible.',
        'The tool runs on the endpoint it inspects. An attacker with administrative control can tamper with the data it reads; corroborate with independent telemetry.',
        'Redaction of secrets and user names is heuristic. Treat snapshots and reports as sensitive and share them only with authorized responders.',
        'ATT&CK mappings relate a rule to a technique; they are not a claim of ATT&CK coverage, and unmapped activity is not implied to be safe.'
    )
    if ($origin -eq 'Synthetic') { $limitations = @('SIMULATED DATA: this result was produced from a synthetic snapshot and says nothing about any real endpoint.') + $limitations }

    return [pscustomobject][ordered]@{
        SchemaVersion    = $script:WthResultSchemaVersion
        Kind             = 'WthHuntResult'
        ToolVersion      = Get-WthToolVersion
        Host             = [string]$snap.Host
        DataOrigin       = $origin
        SnapshotDescription = if ($snap.PSObject.Properties['Description']) { [string]$snap.Description } else { '' }
        CollectedAt      = [string]$snap.CollectedAt
        HuntStartedAt    = (ConvertTo-WthIsoString -Value $started)
        HuntCompletedAt  = (ConvertTo-WthIsoString -Value (Get-WthUtcNow))
        Elevated         = if ($snap.PSObject.Properties['Platform'] -and $snap.Platform -and (Test-WthHasMember -InputObject $snap.Platform -Name 'Elevated')) { [bool](Get-WthFieldValue -InputObject $snap.Platform -Path 'Elevated') } else { $null }
        Summary          = [ordered]@{
            ActiveFindings     = $active.Count
            SuppressedFindings = $suppressed.Count
            BySeverity         = $bySeverity
            ByConfidence       = $byConfidence
            ByFindingType      = $byType
            ItemsAnalyzed      = $totalItems
            RulesExecuted      = $executed.Count
            RulesSkipped       = $skipped.Count
            RulesFilteredOut   = $filtered
        }
        Findings         = $active
        SuppressedFindings = $suppressed
        Coverage         = $coverage.ToArray()
        CoverageGaps     = $gaps
        RulesExecuted    = $executed.ToArray()
        RulesSkipped     = $skipped.ToArray()
        AttackSummary    = $attackSummary.ToArray()
        Warnings         = $warnings.ToArray()
        Limitations      = $limitations
    }
}
