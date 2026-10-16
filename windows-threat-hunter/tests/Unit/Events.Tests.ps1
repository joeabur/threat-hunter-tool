BeforeAll {
    . (Join-Path (Join-Path $PSScriptRoot '..') 'TestHelpers.ps1')
    Import-WthTestModule
}

Describe 'Event XML parsing' {
    It 'parses <File>: EventId <Id>' -ForEach @(
        @{ File = 'security-4625.xml'; Id = 4625 }
        @{ File = 'security-1102.xml'; Id = 1102 }
        @{ File = 'sysmon-1.xml'; Id = 1 }
        @{ File = 'defender-1116.xml'; Id = 1116 }
    ) {
        $path = Join-Path (Join-Path $script:FixtureRoot 'events') $File
        InModuleScope WindowsThreatHunter -Parameters @{ Path = $path; Id = $Id } {
            $xml = [System.IO.File]::ReadAllText($Path)
            $e = ConvertTo-WthEventItem -EventXml $xml
            $e.EventId | Should -Be $Id
            $e.TimeCreated | Should -Match '^\d{4}-\d\d-\d\dT'
        }
    }
    It 'flattens Sysmon data and derives image leaf names' {
        $path = Join-Path (Join-Path $script:FixtureRoot 'events') 'sysmon-1.xml'
        InModuleScope WindowsThreatHunter -Parameters @{ Path = $path } {
            $e = ConvertTo-WthEventItem -EventXml ([System.IO.File]::ReadAllText($Path))
            $e.Data.ImageName | Should -Be 'cmd.exe'
            $e.Data.ParentImageName | Should -Be 'WINWORD.EXE'
        }
    }
    It 'reads UserData fields for event 1102' {
        $path = Join-Path (Join-Path $script:FixtureRoot 'events') 'security-1102.xml'
        InModuleScope WindowsThreatHunter -Parameters @{ Path = $path } {
            $e = ConvertTo-WthEventItem -EventXml ([System.IO.File]::ReadAllText($Path))
            @($e.Data.Keys).Count | Should -BeGreaterThan 0
        }
    }
    It 'rejects <File>' -ForEach @(
        @{ File = 'malformed.xml' }
        @{ File = 'no-eventid.xml' }
        @{ File = 'xxe.xml' }
    ) {
        $path = Join-Path (Join-Path $script:FixtureRoot 'events') $File
        InModuleScope WindowsThreatHunter -Parameters @{ Path = $path } {
            { ConvertTo-WthEventItem -EventXml ([System.IO.File]::ReadAllText($Path)) } | Should -Throw
        }
    }
    It 'never resolves an external entity (XXE)' {
        $path = Join-Path (Join-Path $script:FixtureRoot 'events') 'xxe.xml'
        InModuleScope WindowsThreatHunter -Parameters @{ Path = $path } {
            $leaked = $null
            try { $leaked = ConvertTo-WthEventItem -EventXml ([System.IO.File]::ReadAllText($Path)) } catch { $null = $_ }
            $leaked | Should -BeNullOrEmpty
        }
    }
    It 'truncates oversized event data' {
        InModuleScope WindowsThreatHunter {
            $xml = '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>1</EventID></System><EventData><Data Name="CommandLine">' + ('A' * 500) + '</Data></EventData></Event>'
            $e = ConvertTo-WthEventItem -EventXml $xml -MaxDataLength 50
            $e.Data.CommandLine.Length | Should -BeLessOrEqual 100
        }
    }
}
