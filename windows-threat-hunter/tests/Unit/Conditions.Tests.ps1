BeforeDiscovery {
    . (Join-Path (Join-Path $PSScriptRoot '..') 'TestHelpers.ps1')
}
BeforeAll {
    . (Join-Path (Join-Path $PSScriptRoot '..') 'TestHelpers.ps1')
    Import-WthTestModule
}

Describe 'Condition operators' {
    It '<Op> on <Field>=<Item> with <Arg> is <Expected>' -ForEach @(
        @{ Op = 'equals'; Item = 'Abc'; Arg = 'abc'; Expected = $true }
        @{ Op = 'equals'; Item = 'Abc'; Arg = 'abd'; Expected = $false }
        @{ Op = 'notEquals'; Item = 'Abc'; Arg = 'abd'; Expected = $true }
        @{ Op = 'contains'; Item = 'hello world'; Arg = 'LO W'; Expected = $true }
        @{ Op = 'startsWith'; Item = 'hello'; Arg = 'HE'; Expected = $true }
        @{ Op = 'endsWith'; Item = 'hello'; Arg = 'LLO'; Expected = $true }
        @{ Op = 'matches'; Item = 'cmd /c whoami'; Arg = 'who.mi$'; Expected = $true }
        @{ Op = 'matches'; Item = 'cmd'; Arg = '^x'; Expected = $false }
        @{ Op = 'gt'; Item = 5; Arg = 3; Expected = $true }
        @{ Op = 'gte'; Item = 3; Arg = 3; Expected = $true }
        @{ Op = 'lt'; Item = 2; Arg = 3; Expected = $true }
        @{ Op = 'lte'; Item = 4; Arg = 3; Expected = $false }
        @{ Op = 'gt'; Item = 'abc'; Arg = 3; Expected = $false }
    ) {
        InModuleScope WindowsThreatHunter -Parameters @{ Op = $Op; Item = $Item; Arg = $Arg; Expected = $Expected } {
            $ctx = Build-WthEvalContext -Config (Get-WthConfiguration)
            $node = [pscustomobject]@{ field = 'F'; op = $Op; value = $Arg }
            Test-WthCondition -Condition $node -Item ([pscustomobject]@{ F = $Item }) -Context $ctx | Should -Be $Expected
        }
    }
    It 'handles in / notIn' {
        InModuleScope WindowsThreatHunter {
            $ctx = Build-WthEvalContext -Config (Get-WthConfiguration)
            $item = [pscustomobject]@{ F = 'B' }
            Test-WthCondition -Condition ([pscustomobject]@{ field = 'F'; op = 'in'; values = @('a', 'b') }) -Item $item -Context $ctx | Should -BeTrue
            Test-WthCondition -Condition ([pscustomobject]@{ field = 'F'; op = 'notIn'; values = @('a', 'b') }) -Item $item -Context $ctx | Should -BeFalse
        }
    }
    It 'handles exists, notExists, isTrue and isFalse' {
        InModuleScope WindowsThreatHunter {
            $ctx = Build-WthEvalContext -Config (Get-WthConfiguration)
            $item = [pscustomobject]@{ A = 'x'; B = ''; C = $true; D = $false }
            Test-WthCondition -Condition ([pscustomobject]@{ field = 'A'; op = 'exists' }) -Item $item -Context $ctx | Should -BeTrue
            Test-WthCondition -Condition ([pscustomobject]@{ field = 'B'; op = 'exists' }) -Item $item -Context $ctx | Should -BeFalse
            Test-WthCondition -Condition ([pscustomobject]@{ field = 'Z'; op = 'notExists' }) -Item $item -Context $ctx | Should -BeTrue
            Test-WthCondition -Condition ([pscustomobject]@{ field = 'C'; op = 'isTrue' }) -Item $item -Context $ctx | Should -BeTrue
            Test-WthCondition -Condition ([pscustomobject]@{ field = 'D'; op = 'isFalse' }) -Item $item -Context $ctx | Should -BeTrue
        }
    }
    It 'combines all / any / not' {
        InModuleScope WindowsThreatHunter {
            $ctx = Build-WthEvalContext -Config (Get-WthConfiguration)
            $item = [pscustomobject]@{ A = '1'; B = '2' }
            $a1 = [pscustomobject]@{ field = 'A'; op = 'equals'; value = '1' }
            $b9 = [pscustomobject]@{ field = 'B'; op = 'equals'; value = '9' }
            Test-WthCondition -Condition ([pscustomobject]@{ all = @($a1, $b9) }) -Item $item -Context $ctx | Should -BeFalse
            Test-WthCondition -Condition ([pscustomobject]@{ any = @($a1, $b9) }) -Item $item -Context $ctx | Should -BeTrue
            Test-WthCondition -Condition ([pscustomobject]@{ not = $b9 }) -Item $item -Context $ctx | Should -BeTrue
        }
    }
    It 'evaluates unknown operators and malformed nodes to false' {
        InModuleScope WindowsThreatHunter {
            $ctx = Build-WthEvalContext -Config (Get-WthConfiguration)
            $item = [pscustomobject]@{ A = '1' }
            Test-WthCondition -Condition ([pscustomobject]@{ field = 'A'; op = 'Invoke-Expression'; value = '1' }) -Item $item -Context $ctx | Should -BeFalse
            Test-WthCondition -Condition ([pscustomobject]@{ nonsense = 1 }) -Item $item -Context $ctx | Should -BeFalse
        }
    }
    It 'matches any element of an array-valued field' {
        InModuleScope WindowsThreatHunter {
            $ctx = Build-WthEvalContext -Config (Get-WthConfiguration)
            $item = [pscustomobject]@{ T = @('Logon', 'Boot') }
            Test-WthCondition -Condition ([pscustomobject]@{ field = 'T'; op = 'equals'; value = 'boot' }) -Item $item -Context $ctx | Should -BeTrue
        }
    }
    It 'resolves nested field paths' {
        InModuleScope WindowsThreatHunter {
            $ctx = Build-WthEvalContext -Config (Get-WthConfiguration)
            $item = [pscustomobject]@{ Data = [pscustomobject]@{ Image = 'C:\x\a.exe' } }
            Test-WthCondition -Condition ([pscustomobject]@{ field = 'Data.Image'; op = 'endsWith'; value = 'a.exe' }) -Item $item -Context $ctx | Should -BeTrue
        }
    }
    It 'uses configuration lists and path fragments' {
        InModuleScope WindowsThreatHunter {
            $cfg = Get-WthConfiguration
            $ctx = Build-WthEvalContext -Config $cfg
            $listName = @($cfg.lists.Keys)[0]
            $listName | Should -Not -BeNullOrEmpty
            $entry = @($cfg.lists[$listName])[0]
            Test-WthCondition -Condition ([pscustomobject]@{ field = 'F'; op = 'inList'; list = $listName }) -Item ([pscustomobject]@{ F = [string]$entry }) -Context $ctx | Should -BeTrue
            Test-WthCondition -Condition ([pscustomobject]@{ field = 'F'; op = 'notInList'; list = $listName }) -Item ([pscustomobject]@{ F = 'definitely-not-in-the-list-xyz' }) -Context $ctx | Should -BeTrue
        }
    }
}

Describe 'Condition structure validation' {
    It 'rejects <Name>' -ForEach @(
        @{ Name = 'an unknown operator'; Cond = @{ field = 'A'; op = 'run'; value = 'x' } }
        @{ Name = 'a missing value'; Cond = @{ field = 'A'; op = 'equals' } }
        @{ Name = 'an unknown list'; Cond = @{ field = 'A'; op = 'inList'; list = 'noSuchList' } }
        @{ Name = 'an unsafe regex'; Cond = @{ field = 'A'; op = 'matches'; value = '(a+)+$' } }
        @{ Name = 'an empty all'; Cond = @{ all = @() } }
    ) {
        InModuleScope WindowsThreatHunter -Parameters @{ Cond = $Cond } {
            $node = ConvertTo-Json $Cond -Depth 6 | ConvertFrom-Json
            $errs = @(Test-WthConditionStructure -Condition $node -Config (Get-WthConfiguration))
            $errs.Count | Should -BeGreaterThan 0
        }
    }
    It 'rejects a condition tree that is too deep' {
        InModuleScope WindowsThreatHunter {
            $node = @{ field = 'A'; op = 'exists' }
            1..10 | ForEach-Object { $node = @{ not = $node } }
            $obj = ConvertTo-Json $node -Depth 30 | ConvertFrom-Json
            @(Test-WthConditionStructure -Condition $obj -Config (Get-WthConfiguration)).Count | Should -BeGreaterThan 0
        }
    }
    It 'accepts a valid condition' {
        InModuleScope WindowsThreatHunter {
            $node = ConvertTo-Json @{ all = @(@{ field = 'A'; op = 'equals'; value = 'x' }, @{ field = 'B'; op = 'exists' }) } -Depth 6 | ConvertFrom-Json
            @(Test-WthConditionStructure -Condition $node -Config (Get-WthConfiguration) | ForEach-Object { $_ } | Where-Object { $_ }).Count | Should -Be 0
        }
    }
}
