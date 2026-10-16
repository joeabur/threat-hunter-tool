BeforeDiscovery { . (Join-Path $PSScriptRoot '..' 'TestHelpers.ps1') }
BeforeAll {
    . (Join-Path $PSScriptRoot '..' 'TestHelpers.ps1')
    Import-WthTestModule
    $script:Tmp = New-WthTestDirectory
}
AfterAll { Remove-WthTestDirectory -Path $script:Tmp }

Describe 'Shipped rule catalog' {
    BeforeAll {
        $script:Rules = @(Get-WthRule -Full)
        $script:Validation = @(Test-WthRule)
    }
    It 'contains rules and all of them validate' {
        $script:Rules.Count | Should -BeGreaterThan 30
        @($script:Validation | Where-Object { -not $_.IsValid }).Count | Should -Be 0
    }
    It 'has unique, correctly formatted rule IDs' {
        $ids = @($script:Rules | ForEach-Object { $_.id })
        ($ids | Select-Object -Unique).Count | Should -Be $ids.Count
        foreach ($id in $ids) { $id | Should -Match '^WTH-[A-Z]+-\d{3}$' }
    }
    It 'gives every rule the documented metadata' {
        foreach ($r in $script:Rules) {
            foreach ($p in 'id', 'name', 'version', 'category', 'severity', 'confidence', 'dataSource', 'description', 'rationale', 'evidenceRequirements', 'falsePositives', 'remediation', 'condition') {
                $r.PSObject.Properties.Name | Should -Contain $p -Because "$($r.id) needs '$p'"
            }
        }
    }
    It 'only references ATT&CK techniques that exist in the catalog' {
        $catalog = Get-Content -LiteralPath (Get-WthTestPath 'config/attack-techniques.json') -Raw | ConvertFrom-Json
        $known = @($catalog.techniques | ForEach-Object { $_.id })
        $known.Count | Should -BeGreaterThan 0
        foreach ($r in $script:Rules) {
            foreach ($t in @($r.attack)) {
                if ($null -eq $t) { continue }
                $tid = if ($t -is [string]) { $t } else { $t.id }
                $tid | Should -BeIn $known -Because "$($r.id) maps to $tid"
            }
        }
    }
    It 'does not recommend disabling security controls or weakening execution policy' {
        foreach ($r in $script:Rules) {
            ($r.remediation + ' ' + $r.description) | Should -Not -Match '(?i)disable (windows )?defender|set-executionpolicy|bypass execution policy|turn off (real-time|antivirus)'
        }
    }
}

Describe 'Rule validation' {
    BeforeAll {
        function Write-RuleFile([string]$Name, $Rule) {
            $dir = Join-Path $script:Tmp $Name
            [void][System.IO.Directory]::CreateDirectory($dir)
            ConvertTo-WthTestJsonFile -Path (Join-Path $dir 'r.json') -Object @{ schemaVersion = 1; rules = @($Rule) }
            return $dir
        }
        $script:Template = (Get-WthRule -Full | Where-Object { $_.id -eq 'WTH-TASK-001' }) | ConvertTo-Json -Depth 20 | ConvertFrom-Json
        function Copy-Template { return ($script:Template | ConvertTo-Json -Depth 20 | ConvertFrom-Json) }
    }
    It 'accepts an unmodified rule' {
        $dir = Write-RuleFile 'ok' (Copy-Template)
        @(Test-WthRule -Path $dir | Where-Object { -not $_.IsValid }).Count | Should -Be 0
    }
    It 'rejects <Name>' -ForEach @(
        @{ Name = 'a bad ID'; Mutate = { param($r) $r.id = 'bad id' } }
        @{ Name = 'an unknown severity'; Mutate = { param($r) $r.severity = 'Catastrophic' } }
        @{ Name = 'an unknown confidence'; Mutate = { param($r) $r.confidence = 'Certain' } }
        @{ Name = 'an unknown data source'; Mutate = { param($r) $r.dataSource = 'Nope' } }
        @{ Name = 'an unknown ATT&CK technique'; Mutate = { param($r) $r.attack = @('T9999') } }
        @{ Name = 'a missing condition'; Mutate = { param($r) $r.PSObject.Properties.Remove('condition') } }
        @{ Name = 'an unsafe regex'; Mutate = { param($r) $r.condition = [pscustomobject]@{ field = 'ActionExecute'; op = 'matches'; value = '(a+)+$' } } }
    ) {
        $rule = Copy-Template
        & $Mutate $rule
        $dir = Write-RuleFile ('bad-' + [guid]::NewGuid().ToString('N').Substring(0, 6)) $rule
        @(Test-WthRule -Path $dir | Where-Object { -not $_.IsValid }).Count | Should -BeGreaterThan 0
    }
    It 'rejects duplicate rule IDs across files' {
        $dir = Join-Path $script:Tmp 'dup'
        [void][System.IO.Directory]::CreateDirectory($dir)
        foreach ($n in 'a', 'b') { ConvertTo-WthTestJsonFile -Path (Join-Path $dir "$n.json") -Object @{ schemaVersion = 1; rules = @((Copy-Template)) } }
        @(Test-WthRule -Path $dir | Where-Object { -not $_.IsValid }).Count | Should -BeGreaterThan 0
    }
    It 'reports a malformed rule file instead of throwing' {
        $dir = Join-Path $script:Tmp 'broken'
        [void][System.IO.Directory]::CreateDirectory($dir)
        '{ not json' | Set-Content -LiteralPath (Join-Path $dir 'x.json')
        @(Test-WthRule -Path $dir | Where-Object { -not $_.IsValid }).Count | Should -BeGreaterThan 0
    }
}
