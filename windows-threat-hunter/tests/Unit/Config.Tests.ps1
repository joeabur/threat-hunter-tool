BeforeAll {
    . (Join-Path $PSScriptRoot '..' 'TestHelpers.ps1')
    Import-WthTestModule
    $script:Tmp = New-WthTestDirectory
}
AfterAll { Remove-WthTestDirectory -Path $script:Tmp }

Describe 'Configuration' {
    It 'loads and validates the default configuration' {
        $c = Get-WthConfiguration
        $c.lists | Should -Not -BeNullOrEmpty
        $c.redaction.enabled | Should -BeTrue
        $c.collection.allowOutboundNetwork | Should -Not -BeTrue
    }
    It 'merges an override file over the defaults' {
        $p = Join-Path $script:Tmp 'o.json'
        ConvertTo-WthTestJsonFile -Path $p -Object @{ limits = @{ maxFindingsPerRule = 5 } }
        $c = Get-WthConfiguration -Path $p
        $c.limits.maxFindingsPerRule | Should -Be 5
        $c.limits.maxEvidenceValueLength | Should -Be 1024
    }
    It 'rejects <Name>' -ForEach @(
        @{ Name = 'an unknown top-level key'; Body = @{ bogus = 1 } }
        @{ Name = 'a negative limit'; Body = @{ limits = @{ maxFindingsPerRule = -1 } } }
        @{ Name = 'an unsafe regex pattern'; Body = @{ patterns = @{ custom = @('(a+)+$') } } }
        @{ Name = 'an override for an unknown severity'; Body = @{ ruleOverrides = @{ 'WTH-TASK-001' = @{ severity = 'Huge' } } } }
    ) {
        $p = Join-Path $script:Tmp ('c-' + [guid]::NewGuid().ToString('N').Substring(0, 6) + '.json')
        ConvertTo-WthTestJsonFile -Path $p -Object $Body
        { Get-WthConfiguration -Path $p } | Should -Throw
    }
    It 'rejects a missing configuration file and a path with traversal' {
        { Get-WthConfiguration -Path (Join-Path $script:Tmp 'missing.json') } | Should -Throw
        { Get-WthConfiguration -Path '..\x.json' } | Should -Throw
    }
    It 'ships an example lab configuration that validates' {
        { Get-WthConfiguration -Path (Get-WthTestPath 'config/example-lab.json') } | Should -Not -Throw
    }
    It 'ships an example suppression file that validates' {
        (Get-WthSuppression -Path (Get-WthTestPath 'config/suppressions.example.json')).Errors.Count | Should -Be 0
    }
    It 'rejects a suppression without a reason' {
        $p = Join-Path $script:Tmp 's.json'
        ConvertTo-WthTestJsonFile -Path $p -Object @{ schemaVersion = 1; suppressions = @(@{ id = 'S1'; ruleId = 'WTH-TASK-001'; reason = 'x'; match = @{ A = 'b' } }) }
        $r = Get-WthSuppression -Path $p
        @($r.Errors).Count | Should -BeGreaterThan 0
        @($r.Suppressions).Count | Should -Be 0
    }
}
