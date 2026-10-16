#Requires -Version 5.1
# Thin, read-only wrappers around Windows cmdlets and APIs.
#
# Collectors call these wrappers instead of the cmdlets directly so that unit tests can mock them on any
# platform. Every wrapper only reads state; none of them changes the system. Nothing here executes a
# discovered binary, script, task or service.

function Get-WthRawScheduledTask {
    [CmdletBinding()]
    param()
    Get-ScheduledTask -ErrorAction Stop
}

function Get-WthRawService {
    [CmdletBinding()]
    param()
    Get-CimInstance -ClassName Win32_Service -ErrorAction Stop
}

function Get-WthRawRegistryValue {
    <#
    .SYNOPSIS
        Reads all values of one registry key without expanding environment variables. Returns nothing when
        the key does not exist.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateSet('HKLM', 'HKCU')][string]$Hive,
        [Parameter(Mandatory)][string]$SubKey
    )

    $base = if ($Hive -eq 'HKLM') { [Microsoft.Win32.Registry]::LocalMachine } else { [Microsoft.Win32.Registry]::CurrentUser }
    $key = $base.OpenSubKey($SubKey, $false)
    if ($null -eq $key) { return }
    try {
        foreach ($name in $key.GetValueNames()) {
            [pscustomobject]@{
                Name = $name
                Data = $key.GetValue($name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
                Kind = $key.GetValueKind($name).ToString()
            }
        }
    }
    finally {
        $key.Close()
    }
}

function Get-WthRawDirectoryFile {
    <#
    .SYNOPSIS
        Lists files (not subdirectories) directly inside a directory. Returns nothing if it does not exist.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Container)) { return }
    Get-ChildItem -LiteralPath $Path -Force -File -ErrorAction Stop
}

function Get-WthRawDirectory {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Container)) { return }
    Get-ChildItem -LiteralPath $Path -Force -Directory -ErrorAction Stop
}

function Get-WthRawShortcutTarget {
    <#
    .SYNOPSIS
        Reads the target of a .lnk shortcut using the WScript.Shell COM object. The target is never launched.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    $shell = New-Object -ComObject WScript.Shell
    try {
        $lnk = $shell.CreateShortcut($Path)
        [pscustomobject]@{ TargetPath = [string]$lnk.TargetPath; Arguments = [string]$lnk.Arguments }
    }
    finally {
        [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($shell)
    }
}

function Get-WthRawWmiSubscriptionObject {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ClassName)
    Get-CimInstance -Namespace 'root\subscription' -ClassName $ClassName -ErrorAction Stop
}

function Get-WthRawLocalUser {
    [CmdletBinding()]
    param()
    Get-LocalUser -ErrorAction Stop
}

function Get-WthRawLocalGroupMember {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Group)
    Get-LocalGroupMember -Group $Group -ErrorAction Stop
}

function Get-WthRawProcess {
    [CmdletBinding()]
    param()
    Get-CimInstance -ClassName Win32_Process -ErrorAction Stop
}

function Get-WthRawProcessOwner {
    [CmdletBinding()]
    param([Parameter(Mandatory)][int]$ProcessId)
    $r = Invoke-CimMethod -Query "SELECT * FROM Win32_Process WHERE ProcessId = $ProcessId" -MethodName GetOwner -ErrorAction Stop
    if ($r -and $r.ReturnValue -eq 0) { return ($r.Domain + '\' + $r.User) }
}

function Get-WthRawTcpConnection {
    [CmdletBinding()]
    param()
    Get-NetTCPConnection -ErrorAction Stop
}

function Get-WthRawUdpEndpoint {
    [CmdletBinding()]
    param()
    Get-NetUDPEndpoint -ErrorAction Stop
}

function Get-WthRawDefenderStatus {
    [CmdletBinding()]
    param()
    Get-MpComputerStatus -ErrorAction Stop
}

function Get-WthRawDefenderPreference {
    [CmdletBinding()]
    param()
    Get-MpPreference -ErrorAction Stop
}

function Get-WthRawEvent {
    <#
    .SYNOPSIS
        Reads events from one log. Returns event XML strings (or event objects that have ToXml()).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$LogName,
        [Parameter(Mandatory)][int[]]$EventId,
        [Parameter(Mandatory)][datetime]$StartTime,
        [Parameter(Mandatory)][int]$MaxEvents
    )

    $filter = @{ LogName = $LogName; Id = $EventId; StartTime = $StartTime }
    try {
        Get-WinEvent -FilterHashtable $filter -MaxEvents $MaxEvents -ErrorAction Stop
    }
    catch {
        # "No events found" is an empty result, not a failure. Use the locale-independent error ID.
        if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { return }
        throw
    }
}

function Test-WthRawFile {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    Test-Path -LiteralPath $Path -PathType Leaf -ErrorAction Stop
}

function Get-WthRawFileHash {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
}

function Get-WthRawSignature {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    $sig = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
    [pscustomobject]@{
        Status        = $sig.Status.ToString()
        SignerSubject = if ($sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { $null }
    }
}

function Get-WthRawEventLogInfo {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$LogName)
    Get-WinEvent -ListLog $LogName -ErrorAction Stop
}

function Test-WthCommandAvailable {
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)][string]$Name)
    return [bool](Get-Command -Name $Name -ErrorAction SilentlyContinue)
}
