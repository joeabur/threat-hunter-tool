BeforeAll {
    . (Join-Path $PSScriptRoot '..' 'TestHelpers.ps1')
    Import-WthTestModule
}

Describe 'Redaction' {
    Context 'Protect-WthText' {
        It 'removes <Name> but keeps the surrounding command line' -ForEach @(
            @{ Name = 'a password= value'; Text = 'tool.exe /run password=Hunter2!x --verbose'; Secret = 'Hunter2!x' }
            @{ Name = 'a -token flag value'; Text = 'cli.exe -token abcdef123456 -v'; Secret = 'abcdef123456' }
            @{ Name = 'a bearer token'; Text = 'curl -H "Authorization: Bearer abcdefghijklmnopqrstuvwxyz012345"'; Secret = 'abcdefghijklmnopqrstuvwxyz012345' }
            @{ Name = 'an AWS-style access key id'; Text = 'x --key AKIAABCDEFGHIJKLMNOP'; Secret = 'AKIAABCDEFGHIJKLMNOP' }
            @{ Name = 'a URL credential'; Text = 'git clone https://user:s3cretpw@example.test/r.git'; Secret = 's3cretpw' }
        ) {
            InModuleScope WindowsThreatHunter -Parameters @{ Text = $Text; Secret = $Secret } {
                $cfg = Get-WthConfiguration
                $out = Protect-WthText -Text $Text -Redaction $cfg.redaction
                $out | Should -Not -BeLike "*$Secret*"
                $out | Should -BeLike '*[REDACTED]*'
            }
        }
        It 'masks user profile names but keeps well-known directories' {
            InModuleScope WindowsThreatHunter {
                $cfg = Get-WthConfiguration
                (Protect-WthText -Text 'C:\Users\alice\AppData\x.exe' -Redaction $cfg.redaction) | Should -Not -BeLike '*alice*'
                (Protect-WthText -Text 'C:\Users\Public\x.exe' -Redaction $cfg.redaction) | Should -BeLike '*\Users\Public\*'
            }
        }
        It 'produces a stable tag for the same user' {
            InModuleScope WindowsThreatHunter {
                (Get-WthUserTag -Name 'alice') | Should -Be (Get-WthUserTag -Name 'alice')
                (Get-WthUserTag -Name 'alice') | Should -Not -Be (Get-WthUserTag -Name 'bob')
            }
        }
        It 'leaves text untouched when redaction is disabled' {
            InModuleScope WindowsThreatHunter {
                $cfg = Get-WthConfiguration
                $cfg.redaction.enabled = $false
                (Protect-WthText -Text 'a password=abc' -Redaction $cfg.redaction) | Should -Be 'a password=abc'
            }
        }
        It 'truncates to the maximum length' {
            InModuleScope WindowsThreatHunter {
                $cfg = Get-WthConfiguration
                (Protect-WthText -Text ('a' * 5000) -Redaction $cfg.redaction -MaxLength 100).Length | Should -BeLessOrEqual 140
            }
        }
        It 'handles null and empty input' {
            InModuleScope WindowsThreatHunter {
                $cfg = Get-WthConfiguration
                Protect-WthText -Text $null -Redaction $cfg.redaction | Should -BeNullOrEmpty
                Protect-WthText -Text '' -Redaction $cfg.redaction | Should -Be ''
            }
        }
    }
    Context 'Protect-WthPrincipal' {
        It 'masks <Name>' -ForEach @(
            @{ Name = 'a domain user'; Value = 'CORP\alice'; Not = 'alice'; Keep = 'CORP\' }
            @{ Name = 'a UPN'; Value = 'alice@corp.test'; Not = 'alice'; Keep = '@corp.test' }
            @{ Name = 'a local user'; Value = 'bob'; Not = 'bob'; Keep = '' }
        ) {
            InModuleScope WindowsThreatHunter -Parameters @{ Value = $Value; Not = $Not; Keep = $Keep } {
                $cfg = Get-WthConfiguration
                $out = Protect-WthPrincipal -Name $Value -Redaction $cfg.redaction
                $out | Should -Not -BeLike "*$Not*"
                if ($Keep) { $out | Should -BeLike "*$Keep*" }
            }
        }
        It 'keeps <Name> readable' -ForEach @(
            @{ Name = 'SYSTEM'; Value = 'NT AUTHORITY\SYSTEM' }
            @{ Name = 'a service SID'; Value = 'S-1-5-18' }
            @{ Name = 'a service account'; Value = 'NT SERVICE\TrustedInstaller' }
        ) {
            InModuleScope WindowsThreatHunter -Parameters @{ Value = $Value } {
                $cfg = Get-WthConfiguration
                (Protect-WthPrincipal -Name $Value -Redaction $cfg.redaction) | Should -Be $Value
            }
        }
    }
    Context 'Protect-WthValue' {
        It 'masks principal fields and redacts secrets in other string fields' {
            InModuleScope WindowsThreatHunter {
                $cfg = Get-WthConfiguration
                (Protect-WthValue -Value 'CORP\carol' -FieldName 'UserId' -Redaction $cfg.redaction) | Should -Not -BeLike '*carol*'
                (Protect-WthValue -Value 'x password=zzz' -FieldName 'CommandLine' -Redaction $cfg.redaction) | Should -Not -BeLike '*zzz*'
            }
        }
        It 'passes numbers and booleans through' {
            InModuleScope WindowsThreatHunter {
                $cfg = Get-WthConfiguration
                (Protect-WthValue -Value 42 -FieldName 'ProcessId' -Redaction $cfg.redaction) | Should -Be 42
                (Protect-WthValue -Value $true -FieldName 'Hidden' -Redaction $cfg.redaction) | Should -BeTrue
            }
        }
    }
}
