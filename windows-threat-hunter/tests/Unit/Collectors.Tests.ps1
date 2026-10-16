# Collector tests use mocks of the Get-WthRaw* shims, so they run on any OS. Live collection is covered by
# tests/Integration (Windows only).
BeforeDiscovery { . (Join-Path (Join-Path $PSScriptRoot '..') 'TestHelpers.ps1') }
BeforeAll {
    . (Join-Path (Join-Path $PSScriptRoot '..') 'TestHelpers.ps1')
    Import-WthTestModule
}

Describe 'Collector harness' {
    It 'reports Unavailable (not clean) for every source on a non-Windows host' {
        InModuleScope WindowsThreatHunter {
            Mock Test-WthIsWindows { $false }
            $r = Invoke-WthCollectorByName -Name 'Services' -Config (Get-WthConfiguration)
            $r.Coverage[0].Status | Should -Be 'Unavailable'
            @($r.Items.Keys).Count | Should -Be 0
        }
    }
    It 'classifies an access-denied failure as NeedsElevation when not elevated' {
        InModuleScope WindowsThreatHunter {
            Mock Test-WthIsWindows { $true }
            Mock Test-WthIsElevated { $false }
            Mock Get-WthRawService { throw [System.UnauthorizedAccessException]::new('denied') }
            $r = Invoke-WthCollectorByName -Name 'Services' -Config (Get-WthConfiguration)
            $r.Coverage[0].Status | Should -Be 'NeedsElevation'
        }
    }
    It 'classifies access denied as Error when already elevated' {
        InModuleScope WindowsThreatHunter {
            Mock Test-WthIsWindows { $true }
            Mock Test-WthIsElevated { $true }
            Mock Get-WthRawService { throw [System.UnauthorizedAccessException]::new('denied') }
            (Invoke-WthCollectorByName -Name 'Services' -Config (Get-WthConfiguration)).Coverage[0].Status | Should -Be 'Error'
        }
    }
    It 'classifies a missing cmdlet as Unavailable' {
        InModuleScope WindowsThreatHunter {
            Mock Test-WthIsWindows { $true }
            Mock Get-WthRawService { Get-WthNoSuchCommandXyz }
            (Invoke-WthCollectorByName -Name 'Services' -Config (Get-WthConfiguration)).Coverage[0].Status | Should -Be 'Unavailable'
        }
    }
    It 'classifies other failures as Error and says rules were not evaluated' {
        InModuleScope WindowsThreatHunter {
            Mock Test-WthIsWindows { $true }
            Mock Get-WthRawService { throw 'boom' }
            $c = (Invoke-WthCollectorByName -Name 'Services' -Config (Get-WthConfiguration)).Coverage[0]
            $c.Status | Should -Be 'Error'
            $c.Message | Should -BeLike '*not evaluated*'
        }
    }
}

Describe 'Service collector (mocked)' {
    It 'parses image paths and flags unquoted paths with spaces' {
        InModuleScope WindowsThreatHunter {
            Mock Test-WthIsWindows { $true }
            Mock Get-WthRawService {
                @(
                    [pscustomobject]@{ Name = 'Good'; DisplayName = 'Good'; PathName = '"C:\Program Files\Good\g.exe" -k x'; StartMode = 'Auto'; State = 'Running'; StartName = 'LocalSystem' }
                    [pscustomobject]@{ Name = 'Bad'; DisplayName = 'Bad'; PathName = 'C:\Program Files\Bad Dir\b.exe -run'; StartMode = 'Auto'; State = 'Running'; StartName = 'LocalSystem' }
                )
            }
            $r = Invoke-WthCollectorByName -Name 'Services' -Config (Get-WthConfiguration)
            $r.Coverage[0].Status | Should -Be 'Collected'
            $r.Coverage[0].ItemCount | Should -Be 2
            ($r.Items.Service | Where-Object { $_.Name -eq 'Bad' }).UnquotedPathWithSpaces | Should -BeTrue
            ($r.Items.Service | Where-Object { $_.Name -eq 'Good' }).UnquotedPathWithSpaces | Should -BeFalse
        }
    }
}

Describe 'Invoke-WthCollection' {
    It 'never executes discovered items: no Start-Process or Invoke-Expression anywhere in the module source' {
        $src = Get-ChildItem -LiteralPath (Join-Path $script:RepoRoot 'src') -Recurse -Filter *.ps1 | Get-Content -Raw
        $text = $src -join "`n"
        $text | Should -Not -Match '(?i)\bStart-Process\b'
        $text | Should -Not -Match '(?i)\bInvoke-Expression\b'
        $text | Should -Not -Match '(?i)\biex\s'
    }
    It 'contains no remediation or outbound network cmdlets' {
        $text = (Get-ChildItem -LiteralPath (Join-Path $script:RepoRoot 'src') -Recurse -Filter *.ps1 | Get-Content -Raw) -join "`n"
        foreach ($bad in 'Invoke-WebRequest', 'Invoke-RestMethod', 'Set-MpPreference', 'Stop-Process', 'Remove-Item', 'Disable-ScheduledTask', 'Set-ExecutionPolicy', 'Stop-Service', 'Remove-ItemProperty', 'Set-ItemProperty') {
            $text | Should -Not -Match "(?i)\b$bad\b" -Because "$bad would make the tool non-read-only"
        }
    }
    It 'returns a snapshot whose coverage lists every collector as Unavailable off Windows' -Skip:(Test-WthTestIsWindows) {
        $s = Invoke-WthCollection
        @($s.Coverage | Where-Object { $_.Status -ne 'Unavailable' }).Count | Should -Be 0
    }
}
