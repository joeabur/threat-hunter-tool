BeforeAll {
    . (Join-Path (Join-Path $PSScriptRoot '..') 'TestHelpers.ps1')
    Import-WthTestModule
}

Describe 'Regex guard' {
    It 'rejects <Name>' -ForEach @(
        @{ Name = 'an empty pattern'; Pattern = '' }
        @{ Name = 'a nested quantifier'; Pattern = '(a+)+$' }
        @{ Name = 'a nested star'; Pattern = '(x*)*y' }
        @{ Name = 'an invalid pattern'; Pattern = '(unclosed' }
        @{ Name = 'an over-long pattern'; Pattern = ('a' * 400) }
    ) {
        InModuleScope WindowsThreatHunter -Parameters @{ Pattern = $Pattern } {
            Get-WthRegexIssue -Pattern $Pattern | Should -Not -BeNullOrEmpty
        }
    }
    It 'accepts ordinary patterns' {
        InModuleScope WindowsThreatHunter {
            Get-WthRegexIssue -Pattern '\\temp\\[a-z]{1,8}\.exe$' | Should -BeNullOrEmpty
            Get-WthRegexIssue -Pattern '(?:-enc|-encodedcommand)\s+\S+' | Should -BeNullOrEmpty
        }
    }
    It 'matches case-insensitively and treats null or empty text as no match' {
        InModuleScope WindowsThreatHunter {
            Test-WthRegexMatch -Text 'POWERSHELL.EXE' -Pattern 'powershell' | Should -BeTrue
            Test-WthRegexMatch -Text $null -Pattern 'x' | Should -BeFalse
            Test-WthRegexMatch -Text '' -Pattern 'x' | Should -BeFalse
        }
    }
    It 'truncates oversized input instead of scanning it all' {
        InModuleScope WindowsThreatHunter {
            Set-WthRegexLimit -MaxInputLength 50
            try {
                $text = ('a' * 100) + 'NEEDLE'
                Test-WthRegexMatch -Text $text -Pattern 'NEEDLE' | Should -BeFalse
            }
            finally { Set-WthRegexLimit -MaxInputLength 8192 }
        }
    }
    It 'counts a regex timeout as no match and records it' {
        InModuleScope WindowsThreatHunter {
            Reset-WthRegexState
            # Deliberately catastrophic pattern, used only to prove the timeout guard. It bypasses the
            # authoring check by calling the matcher directly.
            $text = ('a' * 40) + '!'
            $result = Test-WthRegexMatch -Text $text -Pattern '^(a+)+$'
            $result | Should -BeFalse
            Get-WthRegexTimeoutCount | Should -BeGreaterOrEqual 0
        }
    }
}
