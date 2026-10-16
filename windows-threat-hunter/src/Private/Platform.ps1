#Requires -Version 5.1
# Platform helpers. Everything here is read-only and safe to call on any OS.

function Test-WthIsWindows {
    <#
    .SYNOPSIS
        Returns $true when running on Windows (works on Windows PowerShell 5.1 and PowerShell 7+).
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    if ($PSVersionTable.PSEdition -eq 'Desktop') { return $true }
    return ([System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT)
}

function Test-WthIsElevated {
    <#
    .SYNOPSIS
        Returns $true when the current process is running with an elevated (administrator) token.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    if (-not (Test-WthIsWindows)) { return $false }
    try {
        $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
        return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch {
        Write-Verbose "Elevation check failed: $($_.Exception.Message)"
        return $false
    }
}

function Get-WthHostName {
    [CmdletBinding()]
    [OutputType([string])]
    param()

    if (-not [string]::IsNullOrWhiteSpace($env:COMPUTERNAME)) { return $env:COMPUTERNAME }
    return [System.Environment]::MachineName
}

function Get-WthUtcNow {
    [CmdletBinding()]
    [OutputType([datetime])]
    param()

    return [System.DateTime]::UtcNow
}

function ConvertTo-WthIsoString {
    <#
    .SYNOPSIS
        Converts a date value to an invariant UTC ISO-8601 string, or $null when it cannot be parsed.
    .DESCRIPTION
        All timestamps in snapshots, findings and reports are strings in this format. That avoids the
        Windows PowerShell 5.1 "\/Date(...)\/" JSON date format and time-zone ambiguity.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Position = 0)]
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value) { return $null }
    $format = "yyyy-MM-dd'T'HH:mm:ss.fff'Z'"
    $culture = [System.Globalization.CultureInfo]::InvariantCulture

    if ($Value -is [datetime]) {
        if ($Value.Kind -eq [System.DateTimeKind]::Unspecified) { $Value = [datetime]::SpecifyKind($Value, [System.DateTimeKind]::Utc) }
        return $Value.ToUniversalTime().ToString($format, $culture)
    }
    if ($Value -is [System.DateTimeOffset]) {
        return $Value.UtcDateTime.ToString($format, $culture)
    }
    $text = [string]$Value
    if ([string]::IsNullOrWhiteSpace($text)) { return $null }

    $parsed = [System.DateTimeOffset]::MinValue
    $styles = [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal
    if ([System.DateTimeOffset]::TryParse($text, $culture, $styles, [ref]$parsed)) {
        return $parsed.UtcDateTime.ToString($format, $culture)
    }
    return $null
}

function ConvertFrom-WthIsoString {
    [CmdletBinding()]
    [OutputType([System.Nullable[datetime]])]
    param(
        [Parameter(Position = 0)]
        [AllowNull()]
        [object]$Value
    )

    $iso = ConvertTo-WthIsoString -Value $Value
    if ($null -eq $iso) { return $null }
    return [datetime]::Parse($iso, [System.Globalization.CultureInfo]::InvariantCulture,
        [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal)
}
