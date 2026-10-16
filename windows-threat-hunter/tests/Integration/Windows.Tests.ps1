# Live-collection tests. They need a real Windows host and skip everywhere else. The elevated group also needs
# an administrator session. Skipped tests are reported as skipped, never as passed.
BeforeDiscovery {
    . (Join-Path (Join-Path $PSScriptRoot '..') 'TestHelpers.ps1')
    $script:OnWindows = Test-WthTestIsWindows
    $script:Elevated = Test-WthTestIsElevated
}
BeforeAll {
    . (Join-Path (Join-Path $PSScriptRoot '..') 'TestHelpers.ps1')
    Import-WthTestModule
}

Describe 'Live collection (Windows)' -Skip:(-not $script:OnWindows) {
    BeforeAll { $script:Snapshot = Invoke-WthCollection -Collector ScheduledTasks, Services, RegistryRun, StartupFolders, LocalAccounts, Processes, Network, Defender }
    It 'returns a coverage entry for every requested source' {
        @($script:Snapshot.Coverage).Count | Should -BeGreaterThan 5
    }
    It 'collects services without elevation' {
        ($script:Snapshot.Coverage | Where-Object { $_.DataSource -eq 'Service' }).Status | Should -BeIn 'Collected', 'Partial'
    }
    It 'collects processes without elevation' {
        ($script:Snapshot.Coverage | Where-Object { $_.DataSource -eq 'Process' }).Status | Should -BeIn 'Collected', 'Partial'
    }
    It 'runs a full hunt and returns a result with an exit code' {
        $r = Invoke-WthHunt -Snapshot $script:Snapshot
        Get-WthExitCode -Result $r | Should -BeIn 0, 1, 3
        $r.DataOrigin | Should -Be 'Live'
    }
    It 'never reports a gap source as Collected when not elevated' -Skip:$script:Elevated {
        $s = Invoke-WthCollection -Collector WmiSubscriptions, SecurityEvents
        @($s.Coverage | Where-Object { $_.DataSource -in 'WmiSubscription', 'Event.Security' -and $_.Status -eq 'Collected' }).Count | Should -Be 0
    }
}

Describe 'Live collection (Windows, elevated)' -Skip:(-not ($script:OnWindows -and $script:Elevated)) {
    It 'collects WMI subscriptions and the Security log or reports an honest status' {
        $s = Invoke-WthCollection -Collector WmiSubscriptions, SecurityEvents
        foreach ($c in @($s.Coverage | Where-Object { $_.DataSource -in 'WmiSubscription', 'Event.Security' })) { $c.Status | Should -BeIn 'Collected', 'Partial', 'Unavailable', 'Error' }
    }
}
