BeforeAll {
    . (Join-Path (Join-Path $PSScriptRoot '..') 'TestHelpers.ps1')
    Import-WthTestModule
    $script:Tmp = New-WthTestDirectory
}
AfterAll { Remove-WthTestDirectory -Path $script:Tmp }

Describe 'Snapshots' {
    It 'imports every shipped sample snapshot' -ForEach @(
        @{ Name = 'benign-workstation.json' }, @{ Name = 'lab-persistence.json' }, @{ Name = 'lab-intrusion.json' }
    ) {
        $s = Import-WthSnapshot -Path (Join-Path $script:SnapshotRoot $Name)
        $s.Synthetic | Should -BeTrue
        $s.Host | Should -Not -BeNullOrEmpty
    }
    It 'round-trips through Export-WthSnapshot and hunts identically' {
        $src = Import-WthSnapshot -Path (Join-Path $script:SnapshotRoot 'lab-persistence.json')
        $out = Join-Path $script:Tmp 'rt.json'
        Export-WthSnapshot -Snapshot $src -Path $out | Out-Null
        $a = Invoke-WthHunt -SnapshotPath (Join-Path $script:SnapshotRoot 'lab-persistence.json')
        $b = Invoke-WthHunt -SnapshotPath $out
        (@($a.Findings.RuleId | Sort-Object) -join ',') | Should -Be (@($b.Findings.RuleId | Sort-Object) -join ',')
    }
    It 'refuses to overwrite an existing snapshot without -Force' {
        $src = Import-WthSnapshot -Path (Join-Path $script:SnapshotRoot 'benign-workstation.json')
        $out = Join-Path $script:Tmp 'ow.json'
        Export-WthSnapshot -Snapshot $src -Path $out | Out-Null
        { Export-WthSnapshot -Snapshot $src -Path $out } | Should -Throw '*Refusing to overwrite*'
        { Export-WthSnapshot -Snapshot $src -Path $out -Force } | Should -Not -Throw
    }
    It 'rejects <Name>' -ForEach @(
        @{ Name = 'invalid JSON'; Text = '{ nope' }
        @{ Name = 'a wrong schema version'; Text = '{"schemaVersion": 99, "items": {}}' }
        @{ Name = 'an empty file'; Text = '' }
    ) {
        $p = Join-Path $script:Tmp ('bad-' + [guid]::NewGuid().ToString('N').Substring(0, 6) + '.json')
        [System.IO.File]::WriteAllText($p, $Text)
        { Import-WthSnapshot -Path $p } | Should -Throw
    }
    It 'rejects a snapshot over the size limit' {
        $p = Join-Path $script:Tmp 'big.json'
        [System.IO.File]::WriteAllText($p, '{"schemaVersion":1,"x":"' + ('a' * 1000) + '"}')
        $cfg = Get-WthConfiguration
        $cfg.limits.maxInputFileBytes = 100
        { Import-WthSnapshot -Path $p -Config $cfg } | Should -Throw
    }
}

Describe 'Test-WthEnvironment' {
    It 'describes platform, rules and every collector without collecting anything' {
        $e = Test-WthEnvironment
        $e.ToolVersion | Should -Not -BeNullOrEmpty
        $e.Rules.Invalid | Should -Be 0
        @($e.Collectors).Count | Should -BeGreaterThan 5
    }
}
