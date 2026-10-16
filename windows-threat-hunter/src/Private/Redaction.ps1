#Requires -Version 5.1
# Redaction of secrets in command lines and of user names in reports.

$script:WthWellKnownPrincipals = @(
    'SYSTEM', 'LOCAL SERVICE', 'NETWORK SERVICE', 'LocalSystem', 'Administrators', 'Users', 'Everyone',
    'Authenticated Users', 'INTERACTIVE', 'SERVICE', 'ANONYMOUS LOGON'
)
$script:WthWellKnownUserDirs = @('Public', 'Default', 'Default User', 'All Users', 'Administrator')

function Get-WthUserTag {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory, Position = 0)][string]$Name)

    $hash = Get-WthSha256Hex -Text $Name.ToLowerInvariant()
    return "<user:$($hash.Substring(0, 6))>"
}

function Protect-WthText {
    <#
    .SYNOPSIS
        Removes secret-looking values and masks user profile names in free text such as command lines.
    .DESCRIPTION
        Redaction is heuristic. It reduces accidental disclosure in reports but cannot guarantee that every
        secret is recognised. Reports must still be handled as sensitive.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Position = 0)][AllowNull()][AllowEmptyString()][string]$Text,
        [Parameter(Mandatory)][hashtable]$Redaction,
        [int]$MaxLength = 1024
    )

    if ([string]::IsNullOrEmpty($Text)) { return $Text }
    $result = $Text
    if ($Redaction.enabled) {
        foreach ($pattern in @($Redaction.secretPatterns)) {
            try {
                $result = Edit-WthRegexMatch -Text $result -Pattern $pattern -Replacement {
                    param($m)
                    $g = $m.Groups['v']
                    if ($g.Success) {
                        $offset = $g.Index - $m.Index
                        return $m.Value.Remove($offset, $g.Length).Insert($offset, '[REDACTED]')
                    }
                    return '[REDACTED]'
                }
            }
            catch [System.Text.RegularExpressions.RegexMatchTimeoutException] {
                $result = '[REDACTED: redaction pattern timed out]'
                break
            }
        }
        if ($Redaction.maskUserProfilePaths) {
            $dirs = $script:WthWellKnownUserDirs
            $result = Edit-WthRegexMatch -Text $result -Pattern '(?<pre>\\Users\\)(?<name>[^\\/\s"'']+)' -Replacement {
                param($m)
                $name = $m.Groups['name'].Value
                if ($dirs -contains $name) { return $m.Value }
                return $m.Groups['pre'].Value + (Get-WthUserTag -Name $name)
            }
        }
    }
    return (Limit-WthString -Text $result -MaxLength $MaxLength)
}

function Edit-WthRegexMatch {
    <#
    .SYNOPSIS
        Replaces regex matches using a script block that receives each Match (no .NET delegate involved, so
        module-private functions stay callable from the block).
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Text,
        [Parameter(Mandatory)][string]$Pattern,
        [Parameter(Mandatory)][scriptblock]$Replacement
    )

    $re = Get-WthRegex -Pattern $Pattern
    $sb = New-Object System.Text.StringBuilder
    $last = 0
    foreach ($m in $re.Matches($Text)) {
        [void]$sb.Append($Text.Substring($last, $m.Index - $last))
        [void]$sb.Append([string](& $Replacement $m))
        $last = $m.Index + $m.Length
    }
    [void]$sb.Append($Text.Substring($last))
    return $sb.ToString()
}

function Protect-WthPrincipal {
    <#
    .SYNOPSIS
        Masks a user or account name (optionally DOMAIN\user) with a stable short tag. Well-known service
        principals are left readable.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Position = 0)][AllowNull()][AllowEmptyString()][string]$Name,
        [Parameter(Mandatory)][hashtable]$Redaction
    )

    if ([string]::IsNullOrWhiteSpace($Name)) { return $Name }
    if (-not $Redaction.enabled) { return $Name }
    $trimmed = $Name.Trim()
    if ($trimmed -match '^S-1-\d+(-\d+)+$') { return $trimmed }
    if ($trimmed -match '^(NT AUTHORITY|NT SERVICE|BUILTIN|Window Manager|Font Driver Host)\\') { return $trimmed }

    $domain = $null
    $user = $trimmed
    $idx = $trimmed.IndexOf('\')
    if ($idx -ge 0) {
        $domain = $trimmed.Substring(0, $idx)
        $user = $trimmed.Substring($idx + 1)
    }
    elseif ($trimmed -match '^(?<u>[^@]+)@(?<d>.+)$') {
        $user = $Matches['u']
        $domain = $Matches['d']
    }
    if ($script:WthWellKnownPrincipals -contains $user) { return $trimmed }
    $tag = Get-WthUserTag -Name $user
    if ($null -ne $domain) {
        if ($trimmed.IndexOf('\') -ge 0) { return "$domain\$tag" }
        return "$tag@$domain"
    }
    return $tag
}

function Protect-WthValue {
    <#
    .SYNOPSIS
        Redacts one evidence value according to the field it came from (principal fields are masked;
        strings are scrubbed; arrays are processed element-wise).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)][AllowNull()]$Value,
        [Parameter(Mandatory)][string]$FieldName,
        [Parameter(Mandatory)][hashtable]$Redaction,
        [int]$MaxLength = 1024
    )

    if ($null -eq $Value) { return $null }
    if ($Value -is [datetime] -or $Value -is [System.DateTimeOffset]) { return (ConvertTo-WthIsoString -Value $Value) }
    if ($Value -is [bool] -or $Value -is [int] -or $Value -is [long] -or $Value -is [double] -or $Value -is [decimal]) { return $Value }
    if ($Value -is [System.Collections.IDictionary]) {
        $out = [ordered]@{}
        foreach ($k in $Value.Keys) { $out[[string]$k] = Protect-WthValue -Value $Value[$k] -FieldName ([string]$k) -Redaction $Redaction -MaxLength $MaxLength }
        return $out
    }
    if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) {
        $list = New-Object System.Collections.Generic.List[object]
        foreach ($e in $Value) { $list.Add((Protect-WthValue -Value $e -FieldName $FieldName -Redaction $Redaction -MaxLength $MaxLength)) }
        return , $list.ToArray()
    }
    $text = [string]$Value
    $leaf = $FieldName.Split('.')[-1]
    if (@($Redaction.principalFields) -contains $leaf) {
        return (Protect-WthPrincipal -Name $text -Redaction $Redaction)
    }
    return (Protect-WthText -Text $text -Redaction $Redaction -MaxLength $MaxLength)
}
