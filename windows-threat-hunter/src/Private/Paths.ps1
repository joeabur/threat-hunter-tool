#Requires -Version 5.1
# Path validation and normalisation helpers.

function Assert-WthSafePathText {
    <#
    .SYNOPSIS
        Rejects path text that is empty, contains wildcards, parent-directory segments, URL schemes,
        network (UNC) prefixes or (on Windows) alternate data stream syntax.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowNull()][AllowEmptyString()][string]$Path,
        [Parameter(Mandatory)][string]$Label
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        throw [System.ArgumentException]::new("$Label must not be empty.")
    }
    if ($Path.IndexOf([char]0) -ge 0) {
        throw [System.ArgumentException]::new("$Label contains a null character.")
    }
    if ([System.Management.Automation.WildcardPattern]::ContainsWildcardCharacters($Path)) {
        throw [System.ArgumentException]::new("$Label must not contain wildcard characters: $Path")
    }
    if ($Path -match '(^|[\\/])\.\.([\\/]|$)') {
        throw [System.ArgumentException]::new("$Label must not contain '..' segments: $Path")
    }
    if ($Path -match '^[A-Za-z][A-Za-z0-9+.-]*://') {
        throw [System.ArgumentException]::new("$Label must be a local file system path, not a URL: $Path")
    }
    if ($Path -match '^(\\\\|//)') {
        throw [System.ArgumentException]::new("$Label must not be a network (UNC) path: $Path")
    }
    if (Test-WthIsWindows) {
        $rest = $Path
        if ($Path -match '^[A-Za-z]:') { $rest = $Path.Substring(2) }
        if ($rest.IndexOf(':') -ge 0) {
            throw [System.ArgumentException]::new("$Label must not contain ':' other than the drive separator: $Path")
        }
    }
}

function Test-WthReparsePoint {
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)][string]$FullPath)

    try {
        $item = Get-Item -LiteralPath $FullPath -Force -ErrorAction Stop
        return (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0)
    }
    catch {
        Write-Verbose "Reparse-point check failed for '$FullPath': $($_.Exception.Message)"
        return $false
    }
}

function Resolve-WthInputPath {
    <#
    .SYNOPSIS
        Validates and resolves an input file or directory path.
    .DESCRIPTION
        Rejects wildcards, '..' segments, URLs, UNC paths, symbolic links / reparse points, missing
        paths and files larger than -MaxBytes. Returns the absolute path.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][AllowNull()][AllowEmptyString()][string]$Path,
        [ValidateSet('File', 'Directory')][string]$Type = 'File',
        [string]$Label = 'Input path',
        [long]$MaxBytes = 52428800
    )

    Assert-WthSafePathText -Path $Path -Label $Label
    $full = [System.IO.Path]::GetFullPath($Path)

    if ($Type -eq 'File') {
        if (-not [System.IO.File]::Exists($full)) {
            throw [System.IO.FileNotFoundException]::new("$Label does not exist or is not a file: $Path")
        }
        if (Test-WthReparsePoint -FullPath $full) {
            throw [System.ArgumentException]::new("$Label is a symbolic link or reparse point, which is not accepted: $Path")
        }
        $length = ([System.IO.FileInfo]::new($full)).Length
        if ($length -gt $MaxBytes) {
            throw [System.ArgumentException]::new("$Label is $length bytes, which exceeds the limit of $MaxBytes bytes: $Path")
        }
    }
    else {
        if (-not [System.IO.Directory]::Exists($full)) {
            throw [System.IO.DirectoryNotFoundException]::new("$Label does not exist or is not a directory: $Path")
        }
        if (Test-WthReparsePoint -FullPath $full) {
            throw [System.ArgumentException]::new("$Label is a symbolic link or reparse point, which is not accepted: $Path")
        }
    }
    return $full
}

function Test-WthProtectedLocation {
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)][string]$FullPath)

    $protected = New-Object System.Collections.Generic.List[string]
    if (Test-WthIsWindows) {
        foreach ($name in 'SystemRoot', 'ProgramFiles', 'ProgramFiles(x86)') {
            $value = [System.Environment]::GetEnvironmentVariable($name)
            if (-not [string]::IsNullOrWhiteSpace($value)) { $protected.Add($value.TrimEnd('\')) }
        }
    }
    else {
        foreach ($p in '/etc', '/bin', '/sbin', '/usr', '/boot', '/sys', '/proc', '/dev', '/lib') { $protected.Add($p) }
    }
    $sep = [System.IO.Path]::DirectorySeparatorChar
    foreach ($p in $protected) {
        if ($FullPath.Equals($p, [System.StringComparison]::OrdinalIgnoreCase) -or
            $FullPath.StartsWith($p + $sep, [System.StringComparison]::OrdinalIgnoreCase)) {
            return $true
        }
    }
    return $false
}

function Resolve-WthOutputDirectory {
    <#
    .SYNOPSIS
        Validates an output directory and creates it if needed. Never writes to protected system locations.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][AllowNull()][AllowEmptyString()][string]$Path,
        [string]$Label = 'Output directory'
    )

    Assert-WthSafePathText -Path $Path -Label $Label
    $full = [System.IO.Path]::GetFullPath($Path)

    if ([System.IO.File]::Exists($full)) {
        throw [System.ArgumentException]::new("$Label points to an existing file, not a directory: $Path")
    }
    if (Test-WthProtectedLocation -FullPath $full) {
        throw [System.ArgumentException]::new("$Label is inside a protected system location and will not be used: $Path")
    }
    if ([System.IO.Directory]::Exists($full)) {
        if (Test-WthReparsePoint -FullPath $full) {
            throw [System.ArgumentException]::new("$Label is a symbolic link or reparse point, which is not accepted: $Path")
        }
        return $full
    }
    $parent = [System.IO.Path]::GetDirectoryName($full)
    if ($parent -and [System.IO.Directory]::Exists($parent) -and (Test-WthReparsePoint -FullPath $parent)) {
        throw [System.ArgumentException]::new("$Label has a parent that is a symbolic link or reparse point: $Path")
    }
    [void][System.IO.Directory]::CreateDirectory($full)
    return $full
}

function Get-WthSafeFileNamePart {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Text)

    $clean = ($Text -replace '[^A-Za-z0-9_.-]', '_').Trim('._')
    if ([string]::IsNullOrEmpty($clean)) { return 'host' }
    if ($clean.Length -gt 64) { $clean = $clean.Substring(0, 64) }
    return $clean
}

function Get-WthDefaultEnvironment {
    <#
    .SYNOPSIS
        Returns the table of path tokens used when expanding paths such as %SystemRoot%.
    .DESCRIPTION
        On Windows the real environment is used. Elsewhere, and for synthetic data, documented defaults are used
        so that results are deterministic.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()

    $table = @{
        SystemRoot        = 'C:\Windows'
        windir            = 'C:\Windows'
        SystemDrive       = 'C:'
        ProgramFiles      = 'C:\Program Files'
        'ProgramFiles(x86)' = 'C:\Program Files (x86)'
        ProgramData       = 'C:\ProgramData'
        ALLUSERSPROFILE   = 'C:\ProgramData'
    }
    if (Test-WthIsWindows) {
        foreach ($key in @($table.Keys)) {
            $value = [System.Environment]::GetEnvironmentVariable($key)
            if (-not [string]::IsNullOrWhiteSpace($value)) { $table[$key] = $value }
        }
    }
    return $table
}

function Expand-WthPathToken {
    <#
    .SYNOPSIS
        Expands a fixed set of well-known machine-wide tokens (%SystemRoot%, %ProgramFiles%, ...) from a table.
    .DESCRIPTION
        Per-user tokens such as %APPDATA% are deliberately left untouched. This function never reads the
        live environment, so results depend only on the table that is passed in.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Position = 0)][AllowNull()][AllowEmptyString()][string]$Path,
        [hashtable]$Environment
    )

    if ([string]::IsNullOrEmpty($Path)) { return $Path }
    if ($null -eq $Environment) { $Environment = $script:WthEnvironment }
    if ($null -eq $Environment) { $Environment = Get-WthDefaultEnvironment }
    $result = $Path
    foreach ($key in $Environment.Keys) {
        $token = '%' + $key + '%'
        $result = [regex]::Replace($result, [regex]::Escape($token), { param($m) $Environment[$key] }.GetNewClosure(),
            [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    }
    return $result
}

function ConvertTo-WthNormalPath {
    <#
    .SYNOPSIS
        Normalises a path string for comparison: trims, strips quotes, uses backslashes, expands machine tokens.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Position = 0)][AllowNull()][AllowEmptyString()][string]$Path,
        [hashtable]$Environment
    )

    if ([string]::IsNullOrWhiteSpace($Path)) { return $null }
    $text = $Path.Trim().Trim('"').Trim("'")
    $text = $text.Replace('/', '\')
    $text = Expand-WthPathToken -Path $text -Environment $Environment
    # Strip the \\?\ long-path prefix and the \??\ NT prefix that services sometimes use.
    $text = $text -replace '^\\\\\?\\', '' -replace '^\\\?\?\\', ''
    return $text
}

function Get-WthExecutableFromCommandLine {
    <#
    .SYNOPSIS
        Splits a command line into executable path and arguments without executing or resolving anything.
    .DESCRIPTION
        Handles quoted paths and unquoted paths containing spaces (for example service ImagePath values).
        UnquotedWithSpaces is $true when the executable path is unquoted and contains a space - the classic
        unquoted-service-path condition.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Position = 0)][AllowNull()][AllowEmptyString()][string]$CommandLine,
        [hashtable]$Environment
    )

    if ([string]::IsNullOrWhiteSpace($CommandLine)) { return $null }
    $text = $CommandLine.Trim()
    $path = $null
    $arguments = ''
    $quoted = $false

    if ($text[0] -eq '"') {
        $quoted = $true
        $end = $text.IndexOf('"', 1)
        if ($end -gt 0) {
            $path = $text.Substring(1, $end - 1)
            $arguments = $text.Substring($end + 1).Trim()
        }
        else {
            $path = $text.Substring(1)
        }
    }
    else {
        $timeout = [TimeSpan]::FromMilliseconds(500)
        $m = [regex]::Match($text, '^(?<p>.+?\.(?:exe|com|bat|cmd|scr|dll|sys|ps1|vbs|vbe|js|jse|wsf|hta|msi|cpl))(?:\s+(?<a>.*))?$',
            [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor [System.Text.RegularExpressions.RegexOptions]::Singleline, $timeout)
        if ($m.Success) {
            $path = $m.Groups['p'].Value
            if ($m.Groups['a'].Success) { $arguments = $m.Groups['a'].Value.Trim() }
        }
        else {
            $parts = $text -split '\s+', 2
            $path = $parts[0]
            if ($parts.Count -gt 1) { $arguments = $parts[1] }
        }
    }

    $normalised = ConvertTo-WthNormalPath -Path $path -Environment $Environment
    return [pscustomobject]@{
        ExecutablePath     = $normalised
        Arguments          = $arguments
        WasQuoted          = $quoted
        UnquotedWithSpaces = ((-not $quoted) -and ($null -ne $normalised) -and ($normalised.IndexOf(' ') -ge 0))
    }
}

function Get-WthLeafName {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Position = 0)][AllowNull()][AllowEmptyString()][string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) { return $null }
    $clean = $Path.Trim().Trim('"').Replace('/', '\')
    $idx = $clean.LastIndexOf('\')
    if ($idx -ge 0) { return $clean.Substring($idx + 1) }
    return $clean
}
