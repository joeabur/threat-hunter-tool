BeforeDiscovery {
    . (Join-Path (Join-Path $PSScriptRoot '..') 'TestHelpers.ps1')
}
BeforeAll {
    . (Join-Path (Join-Path $PSScriptRoot '..') 'TestHelpers.ps1')
    Import-WthTestModule
    $script:Tmp = New-WthTestDirectory
}
AfterAll { Remove-WthTestDirectory -Path $script:Tmp }

Describe 'Path validation' {
    Context 'Assert-WthSafePathText' {
        It 'rejects <Name>' -ForEach @(
            @{ Name = 'empty path'; Path = '' }
            @{ Name = 'whitespace'; Path = '   ' }
            @{ Name = 'wildcards'; Path = 'C:\data\*.json' }
            @{ Name = 'question mark'; Path = 'data?.json' }
            @{ Name = 'parent segment'; Path = '..\secrets.json' }
            @{ Name = 'embedded parent segment'; Path = 'a/b/../../c.json' }
            @{ Name = 'URL'; Path = 'https://example.com/a.json' }
            @{ Name = 'UNC path'; Path = '\\server\share\a.json' }
            @{ Name = 'UNC-style forward slashes'; Path = '//server/share/a.json' }
        ) {
            InModuleScope WindowsThreatHunter -Parameters @{ Path = $Path } {
                { Assert-WthSafePathText -Path $Path -Label 'Test path' } | Should -Throw
            }
        }
        It 'accepts an ordinary relative path' {
            InModuleScope WindowsThreatHunter {
                { Assert-WthSafePathText -Path 'reports\out' -Label 'Test path' } | Should -Not -Throw
            }
        }
        It 'rejects alternate data streams on Windows' {
            InModuleScope WindowsThreatHunter {
                Mock Test-WthIsWindows { $true }
                { Assert-WthSafePathText -Path 'C:\data\file.json:stream' -Label 'Test path' } | Should -Throw
                { Assert-WthSafePathText -Path 'C:\data\file.json' -Label 'Test path' } | Should -Not -Throw
            }
        }
    }

    Context 'Resolve-WthInputPath' {
        It 'returns the full path of an existing file' {
            $f = Join-Path $script:Tmp 'ok.json'
            Set-Content -LiteralPath $f -Value '{}'
            InModuleScope WindowsThreatHunter -Parameters @{ F = $f } {
                Resolve-WthInputPath -Path $F -Type File | Should -Be ([System.IO.Path]::GetFullPath($F))
            }
        }
        It 'throws for a missing file' {
            InModuleScope WindowsThreatHunter -Parameters @{ T = $script:Tmp } {
                { Resolve-WthInputPath -Path (Join-Path $T 'missing.json') -Type File } | Should -Throw '*does not exist*'
            }
        }
        It 'throws when a file is larger than the limit' {
            $f = Join-Path $script:Tmp 'big.json'
            [System.IO.File]::WriteAllText($f, ('x' * 2048))
            InModuleScope WindowsThreatHunter -Parameters @{ F = $f } {
                { Resolve-WthInputPath -Path $F -Type File -MaxBytes 1024 } | Should -Throw '*exceeds the limit*'
            }
        }
        It 'requires a directory when asked for one' {
            InModuleScope WindowsThreatHunter -Parameters @{ T = $script:Tmp } {
                { Resolve-WthInputPath -Path $T -Type File } | Should -Throw
                Resolve-WthInputPath -Path $T -Type Directory | Should -Be ([System.IO.Path]::GetFullPath($T))
            }
        }
        It 'rejects symbolic links' -Skip:(Test-WthTestIsWindows) {
            $target = Join-Path $script:Tmp 'real.json'
            Set-Content -LiteralPath $target -Value '{}'
            $link = Join-Path $script:Tmp 'link.json'
            New-Item -ItemType SymbolicLink -Path $link -Target $target | Out-Null
            InModuleScope WindowsThreatHunter -Parameters @{ L = $link } {
                { Resolve-WthInputPath -Path $L -Type File } | Should -Throw '*symbolic link*'
            }
        }
    }

    Context 'Resolve-WthOutputDirectory' {
        It 'creates a missing directory' {
            $d = Join-Path $script:Tmp 'new-out'
            InModuleScope WindowsThreatHunter -Parameters @{ D = $d } {
                $r = Resolve-WthOutputDirectory -Path $D
                [System.IO.Directory]::Exists($r) | Should -BeTrue
            }
        }
        It 'refuses a path that is an existing file' {
            $f = Join-Path $script:Tmp 'file.txt'
            Set-Content -LiteralPath $f -Value 'x'
            InModuleScope WindowsThreatHunter -Parameters @{ F = $f } {
                { Resolve-WthOutputDirectory -Path $F } | Should -Throw '*existing file*'
            }
        }
        It 'refuses protected system locations' {
            $protected = if (Test-WthTestIsWindows) { Join-Path $env:SystemRoot 'System32\wth-out' } else { '/etc/wth-out' }
            InModuleScope WindowsThreatHunter -Parameters @{ P = $protected } {
                { Resolve-WthOutputDirectory -Path $P } | Should -Throw '*protected*'
            }
        }
        It 'refuses a symbolic-link output directory' -Skip:(Test-WthTestIsWindows) {
            $real = Join-Path $script:Tmp 'real-out'
            [void][System.IO.Directory]::CreateDirectory($real)
            $link = Join-Path $script:Tmp 'link-out'
            New-Item -ItemType SymbolicLink -Path $link -Target $real | Out-Null
            InModuleScope WindowsThreatHunter -Parameters @{ L = $link } {
                { Resolve-WthOutputDirectory -Path $L } | Should -Throw '*symbolic link*'
            }
        }
    }

    Context 'Command line parsing' {
        It 'parses <Name>' -ForEach @(
            @{ Name = 'a quoted path'; Cmd = '"C:\Program Files\App\app.exe" -k run'; Exe = 'C:\Program Files\App\app.exe'; ArgText = '-k run'; Unq = $false }
            @{ Name = 'an unquoted path with spaces'; Cmd = 'C:\Program Files\App Dir\app.exe -run'; Exe = 'C:\Program Files\App Dir\app.exe'; ArgText = '-run'; Unq = $true }
            @{ Name = 'an unquoted path without spaces'; Cmd = 'C:\Windows\System32\spoolsv.exe'; Exe = 'C:\Windows\System32\spoolsv.exe'; ArgText = ''; Unq = $false }
            @{ Name = 'a bare command'; Cmd = 'powershell.exe -NoProfile'; Exe = 'powershell.exe'; ArgText = '-NoProfile'; Unq = $false }
            @{ Name = 'a token path'; Cmd = '%windir%\system32\SecurityHealthSystray.exe'; Exe = 'C:\Windows\system32\SecurityHealthSystray.exe'; ArgText = ''; Unq = $false }
            @{ Name = 'an NT prefixed path'; Cmd = '\??\C:\Windows\system32\drivers\x.sys'; Exe = 'C:\Windows\system32\drivers\x.sys'; ArgText = ''; Unq = $false }
        ) {
            InModuleScope WindowsThreatHunter -Parameters @{ Cmd = $Cmd; Exe = $Exe; ArgText = $ArgText; Unq = $Unq } {
                $r = Get-WthExecutableFromCommandLine -CommandLine $Cmd -Environment (Get-WthDefaultEnvironment)
                $r.ExecutablePath | Should -Be $Exe
                $r.Arguments | Should -Be $ArgText
                $r.UnquotedWithSpaces | Should -Be $Unq
            }
        }
        It 'returns nothing for empty input' {
            InModuleScope WindowsThreatHunter {
                Get-WthExecutableFromCommandLine -CommandLine '' | Should -BeNullOrEmpty
                Get-WthExecutableFromCommandLine -CommandLine $null | Should -BeNullOrEmpty
            }
        }
        It 'expands only machine-wide tokens' {
            InModuleScope WindowsThreatHunter {
                $env = @{ SystemRoot = 'D:\Win'; ProgramData = 'D:\PD' }
                Expand-WthPathToken -Path '%SystemRoot%\x;%ProgramData%\y;%APPDATA%\z' -Environment $env | Should -Be 'D:\Win\x;D:\PD\y;%APPDATA%\z'
            }
        }
        It 'extracts a leaf name' {
            InModuleScope WindowsThreatHunter {
                Get-WthLeafName -Path 'C:\a\b\WINWORD.EXE' | Should -Be 'WINWORD.EXE'
                Get-WthLeafName -Path 'cmd.exe' | Should -Be 'cmd.exe'
                Get-WthLeafName -Path $null | Should -BeNullOrEmpty
            }
        }
    }
}
