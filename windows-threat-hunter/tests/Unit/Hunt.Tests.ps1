BeforeAll {
    . (Join-Path $PSScriptRoot '..' 'TestHelpers.ps1')
    Import-WthTestModule
    $script:Tmp = New-WthTestDirectory
    $script:Intrusion = Get-WthTestPath 'sample-data/snapshots/lab-intrusion.json'
    $script:Benign = Get-WthTestPath 'sample-data/snapshots/benign-workstation.json'
    $script:Persist = Get-WthTestPath 'sample-data/snapshots/lab-persistence.json'
}
AfterAll { Remove-WthTestDirectory -Path $script:Tmp }

Describe 'Invoke-WthHunt over synthetic snapshots' {
    It 'finds nothing on the benign workstation' {
        $r = Invoke-WthHunt -SnapshotPath $script:Benign
        @($r.Findings).Count | Should -Be 0
        $r.DataOrigin | Should -Be 'Synthetic'
    }
    It 'finds the lab intrusion with the required finding fields' {
        $r = Invoke-WthHunt -SnapshotPath $script:Intrusion
        @($r.Findings).Count | Should -BeGreaterThan 0
        foreach ($f in $r.Findings) {
            foreach ($p in 'Host', 'ObservedAt', 'RuleId', 'Evidence', 'Severity', 'Confidence', 'Explanation', 'RecommendedNextStep') {
                $f.$p | Should -Not -BeNullOrEmpty -Because "$($f.RuleId) must have $p"
            }
            $f.Severity | Should -BeIn 'Critical', 'High', 'Medium', 'Low', 'Informational'
        }
    }
    It 'reports coverage gaps and never treats missing telemetry as clean' {
        $r = Invoke-WthHunt -SnapshotPath $script:Intrusion
        @($r.CoverageGaps).Count | Should -BeGreaterThan 0
        @($r.RulesSkipped).Count | Should -BeGreaterThan 0
        $r.RulesSkipped[0].Reason | Should -Not -BeNullOrEmpty
    }
    It 'is deterministic for the same snapshot' {
        $a = Invoke-WthHunt -SnapshotPath $script:Persist
        $b = Invoke-WthHunt -SnapshotPath $script:Persist
        (@($a.Findings.RuleId) -join ',') | Should -Be (@($b.Findings.RuleId) -join ',')
    }
    It 'filters by rule ID with wildcards' {
        $r = Invoke-WthHunt -SnapshotPath $script:Persist -RuleId 'WTH-TASK-*'
        @($r.Findings | Where-Object { $_.RuleId -notlike 'WTH-TASK-*' }).Count | Should -Be 0
    }
    It 'filters by minimum severity' {
        $r = Invoke-WthHunt -SnapshotPath $script:Intrusion -MinimumSeverity High
        @($r.Findings | Where-Object { $_.Severity -notin 'High', 'Critical' }).Count | Should -Be 0
    }
    It 'does not modify the input snapshot file' {
        $before = (Get-FileHash -LiteralPath $script:Intrusion -Algorithm SHA256).Hash
        $null = Invoke-WthHunt -SnapshotPath $script:Intrusion
        (Get-FileHash -LiteralPath $script:Intrusion -Algorithm SHA256).Hash | Should -Be $before
    }
    It 'applies rule overrides from a configuration file' {
        $cfg = Join-Path $script:Tmp 'override.json'
        $first = (Invoke-WthHunt -SnapshotPath $script:Intrusion).Findings[0].RuleId
        ConvertTo-WthTestJsonFile -Path $cfg -Object @{ ruleOverrides = @{ $first = @{ enabled = $false } } }
        $r = Invoke-WthHunt -SnapshotPath $script:Intrusion -ConfigPath $cfg
        @($r.Findings | Where-Object { $_.RuleId -eq $first }).Count | Should -Be 0
    }
    It 'moves suppressed findings out of the active list and keeps the reason' {
        $first = (Invoke-WthHunt -SnapshotPath $script:Intrusion).Findings[0]
        $key = @($first.Evidence.Keys)[0]
        $sup = Join-Path $script:Tmp 'sup.json'
        ConvertTo-WthTestJsonFile -Path $sup -Object @{ schemaVersion = 1; suppressions = @(@{ id = 'SUP-T1'; ruleId = $first.RuleId; reason = 'Test suppression used only by the unit tests.'; match = @{ $key = $first.Evidence[$key] } }) }
        $r = Invoke-WthHunt -SnapshotPath $script:Intrusion -SuppressionPath $sup
        @($r.SuppressedFindings).Count | Should -BeGreaterThan 0
        $r.SuppressedFindings[0].SuppressionReason | Should -Not -BeNullOrEmpty
    }
    It 'stops on an invalid rule file instead of silently skipping it' {
        $dir = Join-Path $script:Tmp 'badrules'
        [void][System.IO.Directory]::CreateDirectory($dir)
        ConvertTo-WthTestJsonFile -Path (Join-Path $dir 'bad.json') -Object @{ schemaVersion = '1.0'; rules = @(@{ id = 'WTH-BAD-001' }) }
        { Invoke-WthHunt -SnapshotPath $script:Benign -RulePath $dir } | Should -Throw '*Rule validation failed*'
    }
    It 'rejects a missing snapshot' {
        { Invoke-WthHunt -SnapshotPath (Join-Path $script:Tmp 'nope.json') } | Should -Throw
    }
    It 'merges the XDR export when supplied' {
        $r = Invoke-WthHunt -SnapshotPath $script:Intrusion -DefenderXdrPath (Get-WthTestPath 'sample-data/xdr/defender-xdr-export.json')
        ($r.Coverage | Where-Object { $_.DataSource -eq 'DefenderXdr' }).Status | Should -Be 'Imported'
    }
}

Describe 'Get-WthExitCode' {
    It 'returns 0 for a clean hunt' {
        Get-WthExitCode -Result (Invoke-WthHunt -SnapshotPath $script:Benign) | Should -BeIn 0, 3
    }
    It 'returns 1 when findings meet the threshold' {
        Get-WthExitCode -Result (Invoke-WthHunt -SnapshotPath $script:Intrusion) | Should -Be 1
    }
}
