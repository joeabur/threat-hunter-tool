BeforeAll {
    . (Join-Path (Join-Path $PSScriptRoot '..') 'TestHelpers.ps1')
    Import-WthTestModule
    $script:Tmp = New-WthTestDirectory
    $script:Result = Invoke-WthHunt -SnapshotPath (Get-WthTestPath 'sample-data/snapshots/lab-intrusion.json')
    $script:Out = Join-Path $script:Tmp 'reports'
    $script:Files = @(Export-WthReport -Result $script:Result -OutputDirectory $script:Out)
}
AfterAll { Remove-WthTestDirectory -Path $script:Tmp }

Describe 'Report export' {
    It 'writes JSON, CSV and HTML' {
        @($script:Files).Count | Should -Be 3
        ($script:Files | ForEach-Object { [System.IO.Path]::GetExtension($_) } | Sort-Object) -join ',' | Should -Be '.csv,.html,.json'
    }
    It 'writes valid JSON with the report schema fields' {
        $json = $script:Files | Where-Object { $_ -like '*.json' }
        $o = Get-Content -LiteralPath $json -Raw | ConvertFrom-Json
        $o.ReportFormatVersion | Should -Not -BeNullOrEmpty
        foreach ($p in 'SchemaVersion', 'Host', 'DataOrigin', 'Coverage', 'Findings', 'Summary', 'Limitations') { $o.Result.PSObject.Properties.Name | Should -Contain $p }
    }
    It 'marks synthetic data in the HTML banner' {
        $html = Get-Content -LiteralPath ($script:Files | Where-Object { $_ -like '*.html' }) -Raw
        $html | Should -BeLike '*ynthetic*'
        $html | Should -BeLike '*Content-Security-Policy*'
    }
    It 'refuses to overwrite without -Force and overwrites with it' {
        # Report file names carry a timestamp, so test the overwrite guard on the shared writer directly.
        $target = $script:Files[0]
        InModuleScope WindowsThreatHunter -Parameters @{ Target = $target } {
            { Write-WthTextFile -Path $Target -Content 'x' } | Should -Throw '*Refusing to overwrite*'
            { Write-WthTextFile -Path $Target -Content 'x' -Force } | Should -Not -Throw
        }
    }
    It 'rejects wildcard output paths' {
        { Export-WthReport -Result $script:Result -OutputDirectory (Join-Path $script:Tmp '*') } | Should -Throw
    }
}

Describe 'Report escaping' {
    BeforeAll {
        InModuleScope WindowsThreatHunter {
            $script:HostileResult = [pscustomobject]@{
                SchemaVersion = '1.0'; ToolVersion = '1.0.0'; Kind = 'HuntResult'; Host = '<script>alert(1)</script>'
                DataOrigin = 'Synthetic'; CollectedAt = '2026-01-01T00:00:00.000Z'; HuntStartedAt = '2026-01-01T00:00:00.000Z'; HuntCompletedAt = '2026-01-01T00:00:01.000Z'
                Elevated = $false; SnapshotDescription = '"><img src=x onerror=alert(1)>'; Coverage = @(); CoverageGaps = @(); RulesExecuted = @(); RulesSkipped = @()
                Warnings = @(); Limitations = @(); AttackSummary = @(); SuppressedFindings = @()
                Summary = [pscustomobject]@{ ActiveFindings = 1; SuppressedFindings = 0; BySeverity = @{}; ByConfidence = @{}; ByFindingType = @{}; ItemsAnalyzed = 1; RulesExecuted = 1; RulesSkipped = 0; RulesFilteredOut = 0 }
                Findings = @([pscustomobject]@{
                    FindingId = 'F1'; RuleId = 'WTH-TEST-001'; RuleName = '<b>x</b>'; RuleVersion = '1.0.0'; Title = '=HYPERLINK("http://evil","x")'; Host = 'H'
                    ObservedAt = '2026-01-01T00:00:00.000Z'; Severity = 'High'; Confidence = 'Low'; FindingType = 'Heuristic'; Category = 'Test'; DataSource = 'Process'
                    Evidence = [ordered]@{ CommandLine = '<img src=x onerror=alert(1)>'; Formula = '+cmd|calc' }; Explanation = '<script>1</script>'
                    RecommendedNextStep = '@SUM(1)'; FalsePositives = @(); Remediation = ''; Attack = @(); Limitations = @(); EvidenceRequirements = @()
                    OccurrenceCount = 1; Suppressed = $false; SuppressionId = $null; SuppressionReason = $null; ConfigOverrides = @(); ObservedAtBasis = 'x'; TimeZoneContext = 'UTC'; CollectedAt = '2026-01-01T00:00:00.000Z'
                })
            }
        }
    }
    It 'HTML-encodes hostile content' {
        InModuleScope WindowsThreatHunter {
            $html = Build-WthHtmlReport -Result $script:HostileResult -GeneratedAt '2026-01-01T00:00:02.000Z'
            $html | Should -Not -BeLike '*<script>alert(1)*'
            $html | Should -Not -BeLike '*<img src=x*'
            $html | Should -BeLike '*&lt;script&gt;*'
        }
    }
    It 'neutralises spreadsheet formulas in CSV cells' {
        InModuleScope WindowsThreatHunter {
            $csv = Build-WthCsvReport -Result $script:HostileResult
            $csv | Should -Not -Match '(^|,)"?=HYPERLINK'
            $csv | Should -Not -Match '(^|,)"?\+cmd'
            $csv | Should -Not -Match '(^|,)"?@SUM'
        }
    }
}
