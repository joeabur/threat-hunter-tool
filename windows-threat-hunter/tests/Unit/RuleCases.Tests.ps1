# Data-driven positive and negative scenarios for every shipped rule (tests/Fixtures/rule-cases.json).
BeforeDiscovery {
    . (Join-Path (Join-Path $PSScriptRoot '..') 'TestHelpers.ps1')
    $casePath = Join-Path (Join-Path $PSScriptRoot '..') 'Fixtures' | Join-Path -ChildPath 'rule-cases.json'
    $data = Get-Content -LiteralPath $casePath -Raw | ConvertFrom-Json
    $scenarios = foreach ($p in $data.cases.PSObject.Properties) {
        $i = 0
        foreach ($c in @($p.Value)) {
            @{ RuleId = $p.Name; Index = $i; Name = [string]$c.name; Expect = [int]$c.expect }
            $i++
        }
    }
    $ruleIds = @($data.cases.PSObject.Properties.Name | ForEach-Object { @{ RuleId = $_ } })
}

BeforeAll {
    . (Join-Path (Join-Path $PSScriptRoot '..') 'TestHelpers.ps1')
    Import-WthTestModule
    $script:Cases = Get-Content -LiteralPath (Join-Path $script:FixtureRoot 'rule-cases.json') -Raw | ConvertFrom-Json
}

Describe 'Rule scenarios' {
    It '<RuleId>: <Name> (expect <Expect>)' -ForEach $scenarios {
        $case = @($script:Cases.cases.$RuleId)[$Index]
        InModuleScope WindowsThreatHunter -Parameters @{ RuleId = $RuleId; Case = $case } {
            $config = Get-WthConfiguration
            $set = Import-WthRuleSet -Path $script:WthRulesPath -Config $config
            $rule = @($set.Rules | Where-Object { $_.id -eq $RuleId })[0]
            $rule | Should -Not -BeNullOrEmpty
            # Disabled-by-default rules are exercised with their shipped logic.
            $effective = Get-WthEffectiveRule -Rule $rule -Config $config
            $ctx = Build-WthEvalContext -Config $config
            $eval = Invoke-WthRuleEvaluation -Rule $effective -Item @($Case.items) -Context $ctx -Config $config `
                -AttackCatalog $set.AttackCatalog -HostName 'LAB-HOST' -CollectedAt '2026-01-01T00:00:00.000Z' `
                -Now ([datetime]'2026-01-01T00:00:00Z')
            @($eval.Findings).Count | Should -Be ([int]$Case.expect)
        }
    }
}

Describe 'Rule case coverage' {
    It 'has scenarios for <RuleId>, with at least one positive and one negative' -ForEach $ruleIds {
        $list = @($script:Cases.cases.$RuleId)
        ($list | Where-Object { $_.expect -gt 0 }).Count | Should -BeGreaterThan 0
        ($list | Where-Object { $_.expect -eq 0 }).Count | Should -BeGreaterThan 0
    }
    It 'covers every shipped rule' {
        InModuleScope WindowsThreatHunter -Parameters @{ Ids = @($script:Cases.cases.PSObject.Properties.Name) } {
            $set = Import-WthRuleSet -Path $script:WthRulesPath -Config (Get-WthConfiguration)
            $missing = @($set.Rules.id | Where-Object { $_ -notin $Ids })
            $missing | Should -BeNullOrEmpty
        }
    }
}
