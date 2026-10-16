BeforeAll {
    . (Join-Path (Join-Path $PSScriptRoot '..') 'TestHelpers.ps1')
    Import-WthTestModule
    $script:Tmp = New-WthTestDirectory
}
AfterAll { Remove-WthTestDirectory -Path $script:Tmp }

Describe 'Defender XDR import' {
    It 'imports the sample export, skips the malformed row and warns about unknown columns' {
        $r = Import-WthDefenderXdrEvent -Path (Get-WthTestPath 'sample-data/xdr/defender-xdr-export.json')
        @($r.Items).Count | Should -Be 4
        $r.Skipped | Should -Be 1
        ($r.Warnings -join ' ') | Should -BeLike '*unknown column*'
    }
    It 'imports CSV exports' {
        $csv = Join-Path $script:Tmp 'x.csv'
        "Timestamp,DeviceName,ActionType,FileName`n2026-01-01T00:00:00Z,H1,ProcessCreated,a.exe" | Set-Content -LiteralPath $csv -Encoding UTF8
        $r = Import-WthDefenderXdrEvent -Path $csv
        @($r.Items).Count | Should -Be 1
    }
    It 'rejects missing files and unsupported extensions' {
        { Import-WthDefenderXdrEvent -Path (Join-Path $script:Tmp 'nope.json') } | Should -Throw
        $txt = Join-Path $script:Tmp 'x.txt'
        'x' | Set-Content -LiteralPath $txt
        { Import-WthDefenderXdrEvent -Path $txt } | Should -Throw
    }
    It 'rejects wildcard and parent-traversal paths' {
        { Import-WthDefenderXdrEvent -Path '..\x.json' } | Should -Throw
        { Import-WthDefenderXdrEvent -Path '*.json' } | Should -Throw
    }
}
