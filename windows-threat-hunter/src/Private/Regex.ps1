#Requires -Version 5.1
# Bounded regular expressions. All rule and configuration patterns pass through here.

$script:WthRegexCache = @{}
$script:WthRegexTimeouts = 0
$script:WthRegexMaxInput = 8192

function Get-WthRegexIssue {
    <#
    .SYNOPSIS
        Returns a description of why a pattern is rejected, or $null if the pattern is acceptable.
    .DESCRIPTION
        Patterns must be non-empty, at most -MaxLength characters, compile, and must not contain a quantified
        group that itself contains an unbounded quantifier (for example "(a+)+"), which is the classic
        catastrophic-backtracking shape. This is a heuristic guard; every match also runs with a timeout.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory, Position = 0)][AllowNull()][AllowEmptyString()][string]$Pattern,
        [int]$MaxLength = 300
    )

    if ([string]::IsNullOrEmpty($Pattern)) { return 'pattern is empty' }
    if ($Pattern.Length -gt $MaxLength) { return "pattern is longer than $MaxLength characters" }
    if ($Pattern -match '\((?:[^()\\]|\\.)*[+*](?:[^()\\]|\\.)*\)[+*{]') {
        return 'pattern contains a quantified group with an inner unbounded quantifier (possible catastrophic backtracking)'
    }
    try {
        $opts = [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor [System.Text.RegularExpressions.RegexOptions]::CultureInvariant
        [void][System.Text.RegularExpressions.Regex]::new($Pattern, $opts, [TimeSpan]::FromMilliseconds(100))
    }
    catch {
        return "pattern does not compile: $($_.Exception.Message)"
    }
    return $null
}

function Get-WthRegex {
    [CmdletBinding()]
    [OutputType([System.Text.RegularExpressions.Regex])]
    param([Parameter(Mandatory, Position = 0)][string]$Pattern)

    if ($script:WthRegexCache.ContainsKey($Pattern)) { return $script:WthRegexCache[$Pattern] }
    $opts = [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor [System.Text.RegularExpressions.RegexOptions]::CultureInvariant
    $re = [System.Text.RegularExpressions.Regex]::new($Pattern, $opts, [TimeSpan]::FromMilliseconds(1000))
    $script:WthRegexCache[$Pattern] = $re
    return $re
}

function Test-WthRegexMatch {
    <#
    .SYNOPSIS
        Case-insensitive bounded regex match. Input longer than the limit is truncated; a timeout counts as no match.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Position = 0)][AllowNull()][AllowEmptyString()][string]$Text,
        [Parameter(Mandatory, Position = 1)][string]$Pattern
    )

    if ([string]::IsNullOrEmpty($Text)) { return $false }
    if ($Text.Length -gt $script:WthRegexMaxInput) { $Text = $Text.Substring(0, $script:WthRegexMaxInput) }
    try {
        return (Get-WthRegex -Pattern $Pattern).IsMatch($Text)
    }
    catch [System.Text.RegularExpressions.RegexMatchTimeoutException] {
        $script:WthRegexTimeouts++
        Write-Verbose "Regex timed out and was treated as no match: $Pattern"
        return $false
    }
}

function Set-WthRegexLimit {
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory)][int]$MaxInputLength)

    if ($PSCmdlet.ShouldProcess('regex input limit', 'Set')) {
        $script:WthRegexMaxInput = $MaxInputLength
    }
}

function Get-WthRegexTimeoutCount {
    [CmdletBinding()]
    [OutputType([int])]
    param()
    return $script:WthRegexTimeouts
}

function Reset-WthRegexState {
    [CmdletBinding(SupportsShouldProcess)]
    param()
    if ($PSCmdlet.ShouldProcess('regex state', 'Reset')) {
        $script:WthRegexTimeouts = 0
        $script:WthRegexCache = @{}
    }
}
