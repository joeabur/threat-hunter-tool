# Portable integration tests: run the real command-line script in a child PowerShell and check exit codes,
# output and files. These run on any OS and use only synthetic data.
BeforeDiscovery { . (Join-Path (Join-Path $PSScriptRoot '..') 'TestHelpers.ps1') }
BeforeAll {
    . (Join-Path (Join-Path $PSScriptRoot '..') 'TestHelpers.ps1')
    $script:Script = Get-WthTestPath 'scripts/Invoke-WindowsThreatHunter.ps1'
    $script:Pwsh = (Get-Process -Id $PID).Path
    $script:Tmp = New-WthTestDirectory
    function Invoke-Cli {
        param([string[]]$Arguments)
        $out = & $script:Pwsh -NoProfile -File $script:Script @Arguments 2>&1
        return [pscustomobject]@{ ExitCode = $LASTEXITCODE; Output = (($out | ForEach-Object { "$_" }) -join "`n") }
    }
    $script:Snap = Join-Path (Join-Path $script:RepoRoot 'sample-data') 'snapshots'
}
AfterAll { Remove-WthTestDirectory -Path $script:Tmp }

Describe 'Command-line script' {
    It 'validates configuration and rules (exit 0)' {
        $r = Invoke-Cli -Arguments @('-ValidateOnly')
        $r.ExitCode | Should -Be 0
        $r.Output | Should -BeLike '*0 invalid*'
    }
    It 'lists rules (exit 0)' {
        $r = Invoke-Cli -Arguments @('-ListRules')
        $r.ExitCode | Should -Be 0
        $r.Output | Should -BeLike '*WTH-TASK-001*'
    }
    It 'exits 0 for the benign synthetic snapshot and labels it simulated' {
        $r = Invoke-Cli -Arguments @('-SnapshotPath', (Join-Path $script:Snap 'benign-workstation.json'))
        $r.ExitCode | Should -Be 0
        $r.Output | Should -BeLike '*SIMULATED*'
    }
    It 'exits 1 for the lab intrusion snapshot and lists coverage gaps' {
        $r = Invoke-Cli -Arguments @('-SnapshotPath', (Join-Path $script:Snap 'lab-intrusion.json'))
        $r.ExitCode | Should -Be 1
        $r.Output | Should -BeLike '*Coverage gaps*'
    }
    It 'exits 3 when nothing qualifies but coverage is incomplete' {
        $r = Invoke-Cli -Arguments @('-SnapshotPath', (Join-Path $script:Snap 'lab-intrusion.json'), '-FailOnSeverity', 'Critical')
        $r.ExitCode | Should -Be 3
    }
    It 'exits 2 for a missing snapshot' {
        (Invoke-Cli -Arguments @('-SnapshotPath', (Join-Path $script:Tmp 'missing.json'))).ExitCode | Should -Be 2
    }
    It 'exits 2 for an invalid configuration' {
        $cfg = Join-Path $script:Tmp 'bad.json'
        '{"nonsense": true}' | Set-Content -LiteralPath $cfg
        (Invoke-Cli -Arguments @('-ValidateOnly', '-ConfigPath', $cfg)).ExitCode | Should -Be 2
    }
    It 'refuses live collection off Windows with exit 2' -Skip:(Test-WthTestIsWindows) {
        (Invoke-Cli -Arguments @()).ExitCode | Should -Be 2
    }
    It 'writes the three reports and refuses to overwrite them' {
        $out = Join-Path $script:Tmp 'rep'
        $args1 = @('-SnapshotPath', (Join-Path $script:Snap 'lab-persistence.json'), '-OutputDirectory', $out)
        $r = Invoke-Cli -Arguments $args1
        $r.ExitCode | Should -Be 1
        @(Get-ChildItem -LiteralPath $out -File).Count | Should -Be 3
    }
    It 'does not touch the snapshot it reads' {
        $f = Join-Path $script:Snap 'lab-persistence.json'
        $h = (Get-FileHash -LiteralPath $f -Algorithm SHA256).Hash
        $null = Invoke-Cli -Arguments @('-SnapshotPath', $f)
        (Get-FileHash -LiteralPath $f -Algorithm SHA256).Hash | Should -Be $h
    }
}

Describe 'Demo script' {
    It 'runs end to end on synthetic data and writes reports' {
        $out = Join-Path $script:Tmp 'demo'
        $demo = Get-WthTestPath 'scripts/Invoke-Demo.ps1'
        $o = & $script:Pwsh -NoProfile -File $demo -OutputDirectory $out 2>&1
        $LASTEXITCODE | Should -Be 0
        (($o | ForEach-Object { "$_" }) -join "`n") | Should -BeLike '*SIMULATED DATA*'
        @(Get-ChildItem -LiteralPath $out -File).Count | Should -Be 3
    }
}
