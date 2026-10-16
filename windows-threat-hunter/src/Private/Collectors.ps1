#Requires -Version 5.1
# Read-only collectors. Each collector returns @{ Coverage = @(...); Items = @{ <DataSource> = @(...) } }.
#
# Design rules:
#   * Collectors only read. They never modify the registry, tasks, services, accounts or Defender settings.
#   * Discovered executables, scripts, tasks and services are never launched.
#   * A failure in one collector never stops the others, and every failure is recorded as coverage.
#   * Missing data is reported as missing; it is never interpreted as "clean".

$script:WthElevationNeeded = @{
    ScheduledTasks   = 'No'
    Services         = 'No'
    RegistryRun      = 'No'
    StartupFolders   = 'No'
    WmiSubscriptions = 'Yes'
    LocalAccounts    = 'No'
    Processes        = 'No'
    Network          = 'No'
    Defender         = 'Partial'
    SecurityEvents   = 'Yes'
    PowerShellEvents = 'Maybe'
    SysmonEvents     = 'Maybe'
}
$script:WthFileExistenceCache = @{}

function Build-WthCoverage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$DataSource,
        [Parameter(Mandatory)][string]$Collector,
        [Parameter(Mandatory)][ValidateSet('Collected', 'Partial', 'NeedsElevation', 'Unavailable', 'Error', 'NotRequested', 'Imported')][string]$Status,
        [int]$ItemCount = 0,
        [string]$Message = '',
        [string]$RequiresElevation
    )

    if ([string]::IsNullOrEmpty($RequiresElevation)) {
        $RequiresElevation = if ($script:WthElevationNeeded.ContainsKey($Collector)) { $script:WthElevationNeeded[$Collector] } else { 'No' }
    }
    return [pscustomobject][ordered]@{
        DataSource        = $DataSource
        Collector         = $Collector
        Status            = $Status
        ItemCount         = $ItemCount
        RequiresElevation = $RequiresElevation
        Message           = $Message
    }
}

function Get-WthExceptionClass {
    <#
    .SYNOPSIS
        Classifies an error as AccessDenied, NotAvailable or Other without parsing localized messages.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][System.Management.Automation.ErrorRecord]$ErrorRecord)

    $ex = $ErrorRecord.Exception
    while ($null -ne $ex) {
        if ($ex -is [System.UnauthorizedAccessException] -or $ex -is [System.Security.SecurityException]) { return 'AccessDenied' }
        if ($ex -is [System.Management.Automation.CommandNotFoundException]) { return 'NotAvailable' }
        if ($ex.GetType().Name -eq 'CimException') {
            $code = "$($ex.NativeErrorCode)"
            if ($code -eq 'AccessDenied') { return 'AccessDenied' }
            if ($code -in 'InvalidNamespace', 'InvalidClass', 'NotSupported', 'NotFound', 'InvalidParameter') { return 'NotAvailable' }
        }
        if ($ex.GetType().Name -in 'EventLogNotFoundException', 'EventLogInvalidDataException') { return 'NotAvailable' }
        $ex = $ex.InnerException
    }
    if ($ErrorRecord.CategoryInfo.Category -eq [System.Management.Automation.ErrorCategory]::PermissionDenied) { return 'AccessDenied' }
    $id = [string]$ErrorRecord.FullyQualifiedErrorId
    if ($id -like 'NoMatchingLogsFound*' -or $id -like 'CommandNotFoundException*') { return 'NotAvailable' }
    return 'Other'
}

function Get-WthFailureCoverage {
    <#
    .SYNOPSIS
        Turns a caught error into an honest coverage entry for one data source.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][System.Management.Automation.ErrorRecord]$ErrorRecord,
        [Parameter(Mandatory)][string]$DataSource,
        [Parameter(Mandatory)][string]$Collector,
        [string]$UnavailableDetail = 'the required cmdlet, class or log is not present'
    )

    switch (Get-WthExceptionClass -ErrorRecord $ErrorRecord) {
        'AccessDenied' {
            if (Test-WthIsElevated) {
                return Build-WthCoverage -DataSource $DataSource -Collector $Collector -Status Error -Message 'Access was denied even though the session is elevated (policy, ACL or log permissions). Rules for this source were not evaluated.'
            }
            return Build-WthCoverage -DataSource $DataSource -Collector $Collector -Status NeedsElevation -Message 'Access denied. Re-run from an elevated PowerShell session (or an account with read access) to collect this source. Rules for this source were not evaluated.'
        }
        'NotAvailable' {
            return Build-WthCoverage -DataSource $DataSource -Collector $Collector -Status Unavailable -Message "Not available on this system: $UnavailableDetail. Rules for this source were not evaluated."
        }
        default {
            return Build-WthCoverage -DataSource $DataSource -Collector $Collector -Status Error -Message ("Collection failed: " + (Limit-WthString -Text $ErrorRecord.Exception.Message -MaxLength 300) + ' Rules for this source were not evaluated.')
        }
    }
}

function Invoke-WthCollectorSafe {
    <#
    .SYNOPSIS
        Runs one collector script block, converting any failure into coverage so other collectors can continue.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Collector,
        [Parameter(Mandatory)][scriptblock]$Script
    )

    $sources = @($script:WthCollectorMap[$Collector])
    if (-not (Test-WthIsWindows)) {
        $cov = foreach ($s in $sources) {
            Build-WthCoverage -DataSource $s -Collector $Collector -Status Unavailable -Message 'Live collection is only supported on Windows. Use -SnapshotPath to hunt over a saved or synthetic snapshot.'
        }
        return @{ Coverage = @($cov); Items = @{} }
    }
    try {
        return (& $Script)
    }
    catch {
        $err = $_
        $cov = foreach ($s in $sources) { Get-WthFailureCoverage -ErrorRecord $err -DataSource $s -Collector $Collector }
        return @{ Coverage = @($cov); Items = @{} }
    }
}

# ---------------------------------------------------------------- file helpers

function Get-WthFileExistence {
    [CmdletBinding()]
    param([Parameter(Position = 0)][AllowNull()][AllowEmptyString()][string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) { return $null }
    if ($Path.Contains('%')) { return $null }
    if ($Path -notmatch '^[A-Za-z]:\\') { return $null }
    $key = $Path.ToLowerInvariant()
    if ($script:WthFileExistenceCache.ContainsKey($key)) { return $script:WthFileExistenceCache[$key] }
    $result = $null
    try { $result = [bool](Test-WthRawFile -Path $Path) }
    catch { Write-Verbose "Could not determine whether '$Path' exists: $($_.Exception.Message)" }
    $script:WthFileExistenceCache[$key] = $result
    return $result
}

function Add-WthFileInfo {
    <#
    .SYNOPSIS
        Adds optional file hash and Authenticode signature fields to items. Reads files; never executes them.
    .DESCRIPTION
        Signature status is evidence for the analyst. No built-in rule treats "unsigned" as malicious.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [AllowEmptyCollection()][object[]]$Item = @(),
        [Parameter(Mandatory)][string]$Mode,
        [Parameter(Mandatory)][int]$MaxFiles,
        [string]$PathField = 'ExecutablePath'
    )

    if ($Mode -in 'None', 'Basic') { return '' }
    $done = @{}
    $count = 0
    $capped = $false
    foreach ($it in @($Item)) {
        $p = $it[$PathField]
        if (-not $p -or $it['ExecutableExists'] -ne $true) { continue }
        $key = $p.ToLowerInvariant()
        if (-not $done.ContainsKey($key)) {
            if ($count -ge $MaxFiles) { $capped = $true; continue }
            $count++
            $meta = @{ Sha256 = $null; SignatureStatus = $null; SignerSubject = $null }
            try { $meta.Sha256 = Get-WthRawFileHash -Path $p } catch { Write-Verbose "Hash failed for '$p': $($_.Exception.Message)" }
            if ($Mode -eq 'HashAndSignature') {
                try {
                    $sig = Get-WthRawSignature -Path $p
                    $meta.SignatureStatus = $sig.Status
                    $meta.SignerSubject = $sig.SignerSubject
                }
                catch { Write-Verbose "Signature check failed for '$p': $($_.Exception.Message)" }
            }
            $done[$key] = $meta
        }
        $m = $done[$key]
        $it['Sha256'] = $m.Sha256
        if ($Mode -eq 'HashAndSignature') { $it['SignatureStatus'] = $m.SignatureStatus; $it['SignerSubject'] = $m.SignerSubject }
    }
    if ($capped) { return "File metadata was limited to the first $MaxFiles distinct files (collection.maxFilesToHash)." }
    return ''
}

function Test-WthPublicAddress {
    <#
    .SYNOPSIS
        Returns $true for a routable (non-private, non-loopback, non-link-local, non-multicast) IP address.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Position = 0)][AllowNull()][AllowEmptyString()][string]$Address)

    if ([string]::IsNullOrWhiteSpace($Address)) { return $false }
    $clean = $Address.Split('%')[0]
    $ip = $null
    if (-not [System.Net.IPAddress]::TryParse($clean, [ref]$ip)) { return $false }
    if ($ip.IsIPv4MappedToIPv6) { $ip = $ip.MapToIPv4() }
    $b = $ip.GetAddressBytes()
    if ($ip.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
        if ($b[0] -eq 0 -or $b[0] -eq 10 -or $b[0] -eq 127 -or $b[0] -ge 224) { return $false }
        if ($b[0] -eq 172 -and $b[1] -ge 16 -and $b[1] -le 31) { return $false }
        if ($b[0] -eq 192 -and $b[1] -eq 168) { return $false }
        if ($b[0] -eq 169 -and $b[1] -eq 254) { return $false }
        if ($b[0] -eq 100 -and $b[1] -ge 64 -and $b[1] -le 127) { return $false }
        return $true
    }
    if ([System.Net.IPAddress]::IsLoopback($ip)) { return $false }
    if ($ip.IsIPv6LinkLocal -or $ip.IsIPv6SiteLocal -or $ip.IsIPv6Multicast) { return $false }
    if (($b[0] -band 0xFE) -eq 0xFC) { return $false }
    if (@($b | Where-Object { $_ -ne 0 }).Count -eq 0) { return $false }
    return $true
}

function Test-WthLoopbackAddress {
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Position = 0)][AllowNull()][AllowEmptyString()][string]$Address)

    if ([string]::IsNullOrWhiteSpace($Address)) { return $false }
    $ip = $null
    if (-not [System.Net.IPAddress]::TryParse($Address.Split('%')[0], [ref]$ip)) { return $false }
    return [System.Net.IPAddress]::IsLoopback($ip)
}

# ---------------------------------------------------------------- scheduled tasks

function Get-WthScheduledTaskCollection {
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Config)

    $items = New-Object System.Collections.Generic.List[object]
    foreach ($task in @(Get-WthRawScheduledTask)) {
        $principal = $task.Principal
        $triggerTypes = @()
        try { $triggerTypes = @($task.Triggers | ForEach-Object { if ($_.CimClass) { $_.CimClass.CimClassName } else { $_.GetType().Name } }) }
        catch { Write-Verbose "Trigger enumeration failed for task '$($task.TaskName)'." }
        $actions = @($task.Actions)
        if ($actions.Count -eq 0) { $actions = @($null) }
        $index = 0
        foreach ($action in $actions) {
            $execute = $null; $arguments = $null; $actionType = 'None'; $classId = $null
            if ($null -ne $action) {
                if ($action.PSObject.Properties['Execute']) {
                    $actionType = 'Exec'
                    $execute = [string]$action.Execute
                    $arguments = [string]$action.Arguments
                }
                elseif ($action.PSObject.Properties['ClassId']) {
                    $actionType = 'ComHandler'
                    $classId = [string]$action.ClassId
                }
                else { $actionType = $action.GetType().Name }
            }
            $commandLine = (($execute + ' ' + $arguments)).Trim()
            $exe = $null
            if ($execute) { $exe = (Get-WthExecutableFromCommandLine -CommandLine $execute).ExecutablePath }
            $full = ([string]$task.TaskPath + [string]$task.TaskName)
            $items.Add([ordered]@{
                    TaskName         = [string]$task.TaskName
                    TaskPath         = [string]$task.TaskPath
                    FullName         = $full
                    State            = [string]$task.State
                    Author           = [string]$task.Author
                    UserId           = if ($principal) { [string]$principal.UserId } else { $null }
                    RunLevel         = if ($principal) { [string]$principal.RunLevel } else { $null }
                    Hidden           = if ($task.Settings) { [bool]$task.Settings.Hidden } else { $null }
                    TriggerTypes     = $triggerTypes
                    ActionIndex      = $index
                    ActionType       = $actionType
                    ActionExecute    = $execute
                    ActionArguments  = $arguments
                    ActionCommandLine = $commandLine
                    ComClassId       = $classId
                    ExecutablePath   = $exe
                    ExecutableExists = (Get-WthFileExistence -Path $exe)
                })
            $index++
        }
    }
    $note = Add-WthFileInfo -Item $items.ToArray() -Mode $Config.collection.fileMetadata -MaxFiles $Config.collection.maxFilesToHash
    $cov = Build-WthCoverage -DataSource 'ScheduledTask' -Collector 'ScheduledTasks' -Status Collected -ItemCount $items.Count -Message ("One item per task action. Tasks whose definition the current account cannot read may be missing. " + $note).Trim()
    return @{ Coverage = @($cov); Items = @{ ScheduledTask = $items.ToArray() } }
}

# ---------------------------------------------------------------- services

function Get-WthServiceCollection {
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Config)

    $items = New-Object System.Collections.Generic.List[object]
    foreach ($svc in @(Get-WthRawService)) {
        $parsed = Get-WthExecutableFromCommandLine -CommandLine ([string]$svc.PathName)
        $exe = $null; $argText = $null; $unquoted = $false
        if ($parsed) { $exe = $parsed.ExecutablePath; $argText = $parsed.Arguments; $unquoted = $parsed.UnquotedWithSpaces }
        $items.Add([ordered]@{
                Name                   = [string]$svc.Name
                DisplayName            = [string]$svc.DisplayName
                PathName               = [string]$svc.PathName
                ExecutablePath         = $exe
                Arguments              = $argText
                StartMode              = [string]$svc.StartMode
                State                  = [string]$svc.State
                StartName              = [string]$svc.StartName
                UnquotedPathWithSpaces = $unquoted
                ExecutableExists       = (Get-WthFileExistence -Path $exe)
            })
    }
    $note = Add-WthFileInfo -Item $items.ToArray() -Mode $Config.collection.fileMetadata -MaxFiles $Config.collection.maxFilesToHash
    $cov = Build-WthCoverage -DataSource 'Service' -Collector 'Services' -Status Collected -ItemCount $items.Count -Message ("Service image path from Win32_Service. For shared-host services (svchost.exe) the actual DLL (ServiceDll) is not resolved. " + $note).Trim()
    return @{ Coverage = @($cov); Items = @{ Service = $items.ToArray() } }
}

# ---------------------------------------------------------------- Run / RunOnce

function Get-WthRegistryRunCollection {
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Config)

    $locations = @(
        @{ Hive = 'HKLM'; Sub = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Run'; Kind = 'Run' },
        @{ Hive = 'HKLM'; Sub = 'SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'; Kind = 'RunOnce' },
        @{ Hive = 'HKLM'; Sub = 'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'; Kind = 'Run' },
        @{ Hive = 'HKLM'; Sub = 'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce'; Kind = 'RunOnce' },
        @{ Hive = 'HKCU'; Sub = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Run'; Kind = 'Run' },
        @{ Hive = 'HKCU'; Sub = 'SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'; Kind = 'RunOnce' }
    )
    $items = New-Object System.Collections.Generic.List[object]
    $failed = New-Object System.Collections.Generic.List[string]
    foreach ($loc in $locations) {
        try {
            foreach ($v in @(Get-WthRawRegistryValue -Hive $loc.Hive -SubKey $loc.Sub)) {
                $data = [string]$v.Data
                $parsed = Get-WthExecutableFromCommandLine -CommandLine $data
                $exe = $null; $argText = $null
                if ($parsed) { $exe = $parsed.ExecutablePath; $argText = $parsed.Arguments }
                $items.Add([ordered]@{
                        Hive             = $loc.Hive
                        KeyPath          = $loc.Sub
                        RunType          = $loc.Kind
                        ValueName        = [string]$v.Name
                        ValueKind        = [string]$v.Kind
                        Data             = $data
                        ExecutablePath   = $exe
                        Arguments        = $argText
                        ExecutableExists = (Get-WthFileExistence -Path $exe)
                    })
            }
        }
        catch { $failed.Add("$($loc.Hive)\$($loc.Sub)") }
    }
    $note = Add-WthFileInfo -Item $items.ToArray() -Mode $Config.collection.fileMetadata -MaxFiles $Config.collection.maxFilesToHash
    $status = 'Collected'
    $msg = 'HKLM (64-bit and WOW6432Node) and the current user''s HKCU Run/RunOnce keys. Other users'' hives (HKU) are not read. ' + $note
    if ($failed.Count -gt 0) { $status = 'Partial'; $msg = "Could not read: $($failed -join '; '). " + $msg }
    $cov = Build-WthCoverage -DataSource 'RegistryRun' -Collector 'RegistryRun' -Status $status -ItemCount $items.Count -Message $msg.Trim()
    return @{ Coverage = @($cov); Items = @{ RegistryRun = $items.ToArray() } }
}

# ---------------------------------------------------------------- startup folders

function Get-WthStartupFolderCollection {
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Config)

    $pathTable = Get-WthDefaultEnvironment
    $folders = New-Object System.Collections.Generic.List[object]
    $programData = $pathTable['ProgramData']
    $folders.Add(@{ Scope = 'AllUsers'; Path = ($programData + '\Microsoft\Windows\Start Menu\Programs\Startup') })
    if ($env:APPDATA) {
        $folders.Add(@{ Scope = 'CurrentUser'; Path = ($env:APPDATA + '\Microsoft\Windows\Start Menu\Programs\Startup') })
    }
    $elevated = Test-WthIsElevated
    $otherProfiles = 0
    if ($elevated -and $Config.collection.includeOtherUserProfiles) {
        try {
            foreach ($d in @(Get-WthRawDirectory -Path ($pathTable['SystemDrive'] + '\Users'))) {
                $p = $d.FullName + '\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup'
                if ($folders | Where-Object { $_.Path -eq $p }) { continue }
                $folders.Add(@{ Scope = 'OtherUser'; Path = $p }); $otherProfiles++
            }
        }
        catch { Write-Verbose "Could not enumerate other user profiles: $($_.Exception.Message)" }
    }
    $items = New-Object System.Collections.Generic.List[object]
    foreach ($f in $folders) {
        foreach ($file in @(Get-WthRawDirectoryFile -Path $f.Path)) {
            $ext = ([string]$file.Extension).ToLowerInvariant()
            $isLnk = ($ext -eq '.lnk')
            $targetPath = $null; $targetArgs = $null
            if ($isLnk) {
                try {
                    $t = Get-WthRawShortcutTarget -Path $file.FullName
                    $targetPath = $t.TargetPath; $targetArgs = $t.Arguments
                }
                catch { Write-Verbose "Could not read shortcut '$($file.Name)': $($_.Exception.Message)" }
            }
            $exe = if ($isLnk) { ConvertTo-WthNormalPath -Path $targetPath } else { $file.FullName }
            $items.Add([ordered]@{
                    Scope             = $f.Scope
                    Path              = $file.FullName
                    FileName          = [string]$file.Name
                    Extension         = $ext
                    IsShortcut        = $isLnk
                    TargetPath        = $targetPath
                    TargetArguments   = $targetArgs
                    TargetCommandLine = (($targetPath + ' ' + $targetArgs)).Trim()
                    LastWriteTimeUtc  = (ConvertTo-WthIsoString -Value $file.LastWriteTimeUtc)
                    SizeBytes         = [long]$file.Length
                    ExecutablePath    = $exe
                    ExecutableExists  = (Get-WthFileExistence -Path $exe)
                })
        }
    }
    $note = Add-WthFileInfo -Item $items.ToArray() -Mode $Config.collection.fileMetadata -MaxFiles $Config.collection.maxFilesToHash
    $scope = if ($otherProfiles -gt 0) { "All-users, current-user and $otherProfiles other user profile startup folders." } else { 'All-users and current-user startup folders only; other profiles require an elevated session and collection.includeOtherUserProfiles.' }
    $cov = Build-WthCoverage -DataSource 'StartupItem' -Collector 'StartupFolders' -Status Collected -ItemCount $items.Count -Message ($scope + ' ' + $note).Trim()
    return @{ Coverage = @($cov); Items = @{ StartupItem = $items.ToArray() } }
}

# ---------------------------------------------------------------- WMI permanent event subscriptions

function Get-WthRefName {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Position = 0)][AllowNull()][AllowEmptyString()][string]$Reference)

    if ([string]::IsNullOrEmpty($Reference)) { return $null }
    $m = [regex]::Match($Reference, 'Name\s*=\s*"((?:[^"\\]|\\.)*)"', 'IgnoreCase', [TimeSpan]::FromMilliseconds(250))
    if ($m.Success) { return $m.Groups[1].Value.Replace('\\', '\').Replace('\"', '"') }
    return $null
}

function Get-WthWmiSubscriptionCollection {
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Config)

    $filters = @{}
    foreach ($f in @(Get-WthRawWmiSubscriptionObject -ClassName '__EventFilter')) {
        $filters[[string]$f.Name] = $f
    }
    $bindings = @(Get-WthRawWmiSubscriptionObject -ClassName '__FilterToConsumerBinding')
    $consumerToFilter = @{}
    foreach ($b in $bindings) {
        $consumerName = Get-WthRefName -Reference ([string]$b.Consumer)
        $filterName = Get-WthRefName -Reference ([string]$b.Filter)
        if ($consumerName) { $consumerToFilter[$consumerName] = $filterName }
    }
    $items = New-Object System.Collections.Generic.List[object]
    $consumers = New-Object System.Collections.Generic.List[object]
    foreach ($c in @(Get-WthRawWmiSubscriptionObject -ClassName 'CommandLineEventConsumer')) { $consumers.Add(@{ Kind = 'CommandLineEventConsumer'; Obj = $c }) }
    foreach ($c in @(Get-WthRawWmiSubscriptionObject -ClassName 'ActiveScriptEventConsumer')) { $consumers.Add(@{ Kind = 'ActiveScriptEventConsumer'; Obj = $c }) }
    foreach ($entry in $consumers) {
        $c = $entry.Obj
        $name = [string]$c.Name
        $filterName = $consumerToFilter[$name]
        $filter = if ($filterName -and $filters.ContainsKey($filterName)) { $filters[$filterName] } else { $null }
        $scriptText = if ($entry.Kind -eq 'ActiveScriptEventConsumer') { [string]$c.ScriptText } else { $null }
        $cmdTemplate = if ($entry.Kind -eq 'CommandLineEventConsumer') { [string]$c.CommandLineTemplate } else { $null }
        $exePath = if ($entry.Kind -eq 'CommandLineEventConsumer') { [string]$c.ExecutablePath } else { $null }
        $items.Add([ordered]@{
                Kind                = $entry.Kind
                Name                = $name
                CommandLineTemplate = $cmdTemplate
                ExecutablePath      = (ConvertTo-WthNormalPath -Path $exePath)
                ScriptingEngine     = if ($entry.Kind -eq 'ActiveScriptEventConsumer') { [string]$c.ScriptingEngine } else { $null }
                ScriptTextPreview   = (Limit-WthString -Text $scriptText -MaxLength 200)
                ScriptTextLength    = if ($scriptText) { $scriptText.Length } else { 0 }
                FilterName          = $filterName
                FilterQuery         = if ($filter) { [string]$filter.Query } else { $null }
                Bound               = [bool]$filterName
            })
    }
    $cov = Build-WthCoverage -DataSource 'WmiSubscription' -Collector 'WmiSubscriptions' -Status Collected -ItemCount $items.Count -Message 'Permanent subscriptions in root\subscription: CommandLineEventConsumer and ActiveScriptEventConsumer with their bound filters. Other consumer classes are not enumerated.'
    return @{ Coverage = @($cov); Items = @{ WmiSubscription = $items.ToArray() } }
}

# ---------------------------------------------------------------- local accounts and groups

function Get-WthLocalAccountCollection {
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Config)

    $coverage = New-Object System.Collections.Generic.List[object]
    $accounts = New-Object System.Collections.Generic.List[object]
    $members = New-Object System.Collections.Generic.List[object]

    try {
        foreach ($u in @(Get-WthRawLocalUser)) {
            $sid = if ($u.SID) { [string]$u.SID.Value } else { $null }
            $accounts.Add([ordered]@{
                    AccountName      = [string]$u.Name
                    Enabled          = [bool]$u.Enabled
                    SID              = $sid
                    PasswordRequired = [bool]$u.PasswordRequired
                    PasswordLastSet  = (ConvertTo-WthIsoString -Value $u.PasswordLastSet)
                    LastLogon        = (ConvertTo-WthIsoString -Value $u.LastLogon)
                })
        }
        $coverage.Add((Build-WthCoverage -DataSource 'LocalAccount' -Collector 'LocalAccounts' -Status Collected -ItemCount $accounts.Count -Message 'Local accounts only. Domain accounts are not enumerated.'))
    }
    catch { $coverage.Add((Get-WthFailureCoverage -ErrorRecord $_ -DataSource 'LocalAccount' -Collector 'LocalAccounts' -UnavailableDetail 'the Microsoft.PowerShell.LocalAccounts module is missing (for example on a domain controller)')) }

    $groupFailures = New-Object System.Collections.Generic.List[string]
    foreach ($group in @($Config.collection.privilegedGroups)) {
        try {
            foreach ($m in @(Get-WthRawLocalGroupMember -Group $group)) {
                $full = [string]$m.Name
                $short = if ($full.Contains('\')) { $full.Substring($full.LastIndexOf('\') + 1) } else { $full }
                $members.Add([ordered]@{
                        Group           = $group
                        MemberName      = $full
                        ShortName       = $short
                        ObjectClass     = [string]$m.ObjectClass
                        PrincipalSource = [string]$m.PrincipalSource
                        SID             = if ($m.SID) { [string]$m.SID.Value } else { $null }
                    })
            }
        }
        catch { $groupFailures.Add("$group ($(Get-WthExceptionClass -ErrorRecord $_))") }
    }
    if ($groupFailures.Count -gt 0) {
        $coverage.Add((Build-WthCoverage -DataSource 'LocalGroupMember' -Collector 'LocalAccounts' -Status Partial -ItemCount $members.Count -Message ("Could not read group membership for: $($groupFailures -join ', '). On Windows PowerShell 5.1 Get-LocalGroupMember fails when a group contains an unresolvable SID.")))
    }
    else {
        $coverage.Add((Build-WthCoverage -DataSource 'LocalGroupMember' -Collector 'LocalAccounts' -Status Collected -ItemCount $members.Count -Message ("Membership of: " + (@($Config.collection.privilegedGroups) -join ', ') + '. Nested domain group membership is not expanded.')))
    }
    return @{ Coverage = $coverage.ToArray(); Items = @{ LocalAccount = $accounts.ToArray(); LocalGroupMember = $members.ToArray() } }
}

# ---------------------------------------------------------------- processes

function Get-WthProcessCollection {
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Config)

    $all = @(Get-WthRawProcess)
    $byId = @{}
    foreach ($p in $all) { $byId[[int]$p.ProcessId] = $p }
    $limit = [int]$Config.collection.maxProcesses
    $truncated = $all.Count -gt $limit
    $selected = if ($truncated) { $all[0..($limit - 1)] } else { $all }
    $items = New-Object System.Collections.Generic.List[object]
    $missing = 0
    $ignoreMissing = @('Idle', 'System', 'System Idle Process', 'Registry', 'Memory Compression', 'Secure System', 'vmmem')
    foreach ($p in $selected) {
        $ppid = [int]$p.ParentProcessId
        $parent = if ($byId.ContainsKey($ppid)) { $byId[$ppid] } else { $null }
        $reliable = $false
        if ($parent -and $p.CreationDate -and $parent.CreationDate) { $reliable = ([datetime]$parent.CreationDate -le [datetime]$p.CreationDate) }
        $exe = ConvertTo-WthNormalPath -Path ([string]$p.ExecutablePath)
        if (-not $exe -and $p.Name -notin $ignoreMissing) { $missing++ }
        $owner = $null
        if ($Config.collection.includeProcessOwner) {
            try { $owner = Get-WthRawProcessOwner -ProcessId ([int]$p.ProcessId) } catch { Write-Verbose "Owner lookup failed for PID $($p.ProcessId)." }
        }
        $items.Add([ordered]@{
                ProcessId             = [int]$p.ProcessId
                ParentProcessId       = $ppid
                Name                  = [string]$p.Name
                ExecutablePath        = $exe
                CommandLine           = [string]$p.CommandLine
                CommandLineAvailable  = (-not [string]::IsNullOrEmpty([string]$p.CommandLine))
                CreationTime          = (ConvertTo-WthIsoString -Value $p.CreationDate)
                Owner                 = $owner
                ParentName            = if ($reliable) { [string]$parent.Name } else { $null }
                ParentExecutablePath  = if ($reliable) { ConvertTo-WthNormalPath -Path ([string]$parent.ExecutablePath) } else { $null }
                ParentReliable        = $reliable
            })
    }
    $msg = 'Process snapshot at collection time; short-lived processes are not captured. Parent names are only recorded when the parent started before the child (guards against PID reuse).'
    $status = 'Collected'
    if ($missing -gt 0) {
        $status = 'Partial'
        $msg += " $missing process(es) had no readable executable path or command line (protected or other users' processes when not elevated)."
    }
    if ($truncated) { $status = 'Partial'; $msg += " Limited to the first $limit of $($all.Count) processes (collection.maxProcesses)." }
    $cov = Build-WthCoverage -DataSource 'Process' -Collector 'Processes' -Status $status -ItemCount $items.Count -Message $msg
    return @{ Coverage = @($cov); Items = @{ Process = $items.ToArray() } }
}

# ---------------------------------------------------------------- network

function Get-WthNetworkCollection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$Config,
        [hashtable]$ProcessLookup
    )

    $lookupNote = ''
    if ($null -eq $ProcessLookup -or $ProcessLookup.Count -eq 0) {
        $ProcessLookup = @{}
        try {
            foreach ($p in @(Get-WthRawProcess)) {
                $ProcessLookup[[int]$p.ProcessId] = @{ Name = [string]$p.Name; Path = (ConvertTo-WthNormalPath -Path ([string]$p.ExecutablePath)) }
            }
        }
        catch { $lookupNote = ' Process names could not be resolved for sockets.' }
    }
    $items = New-Object System.Collections.Generic.List[object]
    foreach ($c in @(Get-WthRawTcpConnection)) {
        $owning = [int]$c.OwningProcess
        $proc = if ($ProcessLookup.ContainsKey($owning)) { $ProcessLookup[$owning] } else { $null }
        $state = [string]$c.State
        $listening = ($state -eq 'Listen')
        $items.Add([ordered]@{
                Protocol         = 'TCP'
                State            = $state
                LocalAddress     = [string]$c.LocalAddress
                LocalPort        = [int]$c.LocalPort
                RemoteAddress    = [string]$c.RemoteAddress
                RemotePort       = [int]$c.RemotePort
                OwningProcess    = $owning
                ProcessName      = if ($proc) { $proc.Name } else { $null }
                ProcessPath      = if ($proc) { $proc.Path } else { $null }
                IsListening      = $listening
                LocalIsLoopback  = (Test-WthLoopbackAddress -Address ([string]$c.LocalAddress))
                RemoteIsPublic   = (Test-WthPublicAddress -Address ([string]$c.RemoteAddress))
            })
    }
    $udpFailed = $false
    try {
        foreach ($u in @(Get-WthRawUdpEndpoint)) {
            $owning = [int]$u.OwningProcess
            $proc = if ($ProcessLookup.ContainsKey($owning)) { $ProcessLookup[$owning] } else { $null }
            $items.Add([ordered]@{
                    Protocol        = 'UDP'
                    State           = 'Bound'
                    LocalAddress    = [string]$u.LocalAddress
                    LocalPort       = [int]$u.LocalPort
                    RemoteAddress   = $null
                    RemotePort      = 0
                    OwningProcess   = $owning
                    ProcessName     = if ($proc) { $proc.Name } else { $null }
                    ProcessPath     = if ($proc) { $proc.Path } else { $null }
                    IsListening     = $true
                    LocalIsLoopback = (Test-WthLoopbackAddress -Address ([string]$u.LocalAddress))
                    RemoteIsPublic  = $false
                })
        }
    }
    catch { $udpFailed = $true }
    $status = 'Collected'
    $msg = 'TCP connections and UDP endpoints at collection time; short-lived connections are not captured. No traffic content or DNS data is collected.' + $lookupNote
    if ($udpFailed) { $status = 'Partial'; $msg += ' UDP endpoints could not be read.' }
    $cov = Build-WthCoverage -DataSource 'NetworkConnection' -Collector 'Network' -Status $status -ItemCount $items.Count -Message $msg
    return @{ Coverage = @($cov); Items = @{ NetworkConnection = $items.ToArray() } }
}

# ---------------------------------------------------------------- events

function ConvertTo-WthEventItem {
    <#
    .SYNOPSIS
        Parses one event (XML text or an object with ToXml()) into a flat item. DTDs and external entities are disabled.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$EventXml,
        [int]$MaxDataLength = 8192
    )

    $text = if ($EventXml -is [string]) { $EventXml } else { [string]$EventXml.ToXml() }
    $settings = New-Object System.Xml.XmlReaderSettings
    $settings.DtdProcessing = [System.Xml.DtdProcessing]::Prohibit
    $settings.XmlResolver = $null
    $settings.MaxCharactersInDocument = 4MB
    $reader = [System.Xml.XmlReader]::Create((New-Object System.IO.StringReader($text)), $settings)
    try {
        $doc = New-Object System.Xml.XmlDocument
        $doc.XmlResolver = $null
        $doc.Load($reader)
    }
    finally { $reader.Dispose() }

    $ns = New-Object System.Xml.XmlNamespaceManager($doc.NameTable)
    $ns.AddNamespace('e', 'http://schemas.microsoft.com/win/2004/08/events/event')
    $sys = $doc.SelectSingleNode('/e:Event/e:System', $ns)
    if ($null -eq $sys) { throw [System.ArgumentException]::new('Event XML has no System element.') }
    $idNode = $sys.SelectSingleNode('e:EventID', $ns)
    if ($null -eq $idNode) { throw [System.ArgumentException]::new('Event XML has no EventID.') }
    $provider = $sys.SelectSingleNode('e:Provider', $ns)
    $time = $sys.SelectSingleNode('e:TimeCreated', $ns)
    $data = [ordered]@{}
    $index = 0
    foreach ($d in $doc.SelectNodes('/e:Event/e:EventData/e:Data', $ns)) {
        $name = $d.GetAttribute('Name')
        $key = ($name -replace '[^A-Za-z0-9]', '')
        if ([string]::IsNullOrEmpty($key)) { $key = "Data$index" }
        $index++
        $data[$key] = Limit-WthString -Text $d.InnerText -MaxLength $MaxDataLength
    }
    # Some events (for example Security 1102) carry their fields in UserData/<Element>/<Field> instead of EventData.
    foreach ($d in $doc.SelectNodes("/*[local-name()='Event']/*[local-name()='UserData']/*/*")) {
        $key = ($d.LocalName -replace '[^A-Za-z0-9]', '')
        $isLeaf = ($d.ChildNodes.Count -eq 0) -or ($d.ChildNodes.Count -eq 1 -and $d.FirstChild.NodeType -eq [System.Xml.XmlNodeType]::Text)
        if ($key -and $isLeaf -and -not $data.Contains($key)) {
            $data[$key] = Limit-WthString -Text $d.InnerText -MaxLength $MaxDataLength
        }
    }
    foreach ($pair in @(@('Image', 'ImageName'), @('ParentImage', 'ParentImageName'))) {
        if ($data.Contains($pair[0])) { $data[$pair[1]] = Get-WthLeafName -Path ([string]$data[$pair[0]]) }
    }
    $channelNode = $sys.SelectSingleNode('e:Channel', $ns)
    $computerNode = $sys.SelectSingleNode('e:Computer', $ns)
    $recordNode = $sys.SelectSingleNode('e:EventRecordID', $ns)
    return [ordered]@{
        Channel     = if ($channelNode) { $channelNode.InnerText } else { $null }
        EventId     = [int]$idNode.InnerText
        TimeCreated = if ($time) { ConvertTo-WthIsoString -Value $time.GetAttribute('SystemTime') } else { $null }
        Provider    = if ($provider) { $provider.GetAttribute('Name') } else { $null }
        Computer    = if ($computerNode) { $computerNode.InnerText } else { $null }
        RecordId    = if ($recordNode) { [long]$recordNode.InnerText } else { $null }
        Data        = $data
    }
}

function Get-WthEventLogCollection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$Config,
        [Parameter(Mandatory)][string]$Collector,
        [Parameter(Mandatory)][string]$DataSource,
        [Parameter(Mandatory)][string]$LogName,
        [Parameter(Mandatory)][int[]]$EventId,
        [string]$UnavailableDetail = 'the event log does not exist'
    )

    $max = [int]$Config.collection.maxEventsPerChannel
    $start = (Get-WthUtcNow).AddHours(-1 * [int]$Config.collection.eventLookbackHours)
    $items = New-Object System.Collections.Generic.List[object]
    $bad = 0
    try {
        $raw = @(Get-WthRawEvent -LogName $LogName -EventId $EventId -StartTime $start.ToLocalTime() -MaxEvents $max)
    }
    catch {
        $cov = Get-WthFailureCoverage -ErrorRecord $_ -DataSource $DataSource -Collector $Collector -UnavailableDetail $UnavailableDetail
        return @{ Coverage = @($cov); Items = @{} }
    }
    foreach ($e in $raw) {
        try { $items.Add((ConvertTo-WthEventItem -EventXml $e -MaxDataLength $Config.limits.maxEventDataLength)) }
        catch { $bad++ }
    }
    $status = 'Collected'
    $msg = "Log '$LogName', event IDs $($EventId -join ', '), last $($Config.collection.eventLookbackHours) hour(s). Events outside this window or removed by log rotation or clearing are not visible."
    if ($raw.Count -ge $max) { $status = 'Partial'; $msg += " The maxEventsPerChannel limit ($max) was reached, so older matching events were not collected." }
    if ($bad -gt 0) { $status = 'Partial'; $msg += " $bad event(s) could not be parsed and were skipped." }
    $cov = Build-WthCoverage -DataSource $DataSource -Collector $Collector -Status $status -ItemCount $items.Count -Message $msg
    return @{ Coverage = @($cov); Items = @{ $DataSource = $items.ToArray() } }
}

# ---------------------------------------------------------------- Defender

function Get-WthDefenderCollection {
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Config)

    $coverage = New-Object System.Collections.Generic.List[object]
    $itemsByDs = @{}
    $detail = 'Windows Defender cmdlets are not installed (for example Server Core without the feature, or a third-party product has replaced Defender)'

    # --- status
    try {
        $s = Get-WthRawDefenderStatus
        $age = $null
        if ($null -ne $s.AntivirusSignatureAge) { $age = [int]$s.AntivirusSignatureAge }
        $itemsByDs['DefenderStatus'] = @([ordered]@{
                AMRunningMode             = [string]$s.AMRunningMode
                AntivirusEnabled          = [bool]$s.AntivirusEnabled
                AMServiceEnabled          = [bool]$s.AMServiceEnabled
                RealTimeProtectionEnabled = [bool]$s.RealTimeProtectionEnabled
                BehaviorMonitorEnabled    = [bool]$s.BehaviorMonitorEnabled
                IoavProtectionEnabled     = [bool]$s.IoavProtectionEnabled
                IsTamperProtected         = if ($s.PSObject.Properties['IsTamperProtected']) { [bool]$s.IsTamperProtected } else { $null }
                AntivirusSignatureAgeDays = $age
                AntivirusSignatureLastUpdated = (ConvertTo-WthIsoString -Value $s.AntivirusSignatureLastUpdated)
            })
        $coverage.Add((Build-WthCoverage -DataSource 'DefenderStatus' -Collector 'Defender' -Status Collected -ItemCount 1 -Message 'Get-MpComputerStatus. When another antivirus is active, Defender runs in passive mode and disabled real-time protection is expected.' -RequiresElevation 'No'))
    }
    catch { $coverage.Add((Get-WthFailureCoverage -ErrorRecord $_ -DataSource 'DefenderStatus' -Collector 'Defender' -UnavailableDetail $detail)) }

    # --- exclusions (administrators only; reading as a standard user returns placeholder text)
    if (Test-WthIsElevated) {
        try {
            $pref = Get-WthRawDefenderPreference
            $ex = New-Object System.Collections.Generic.List[object]
            foreach ($pair in @(@('Path', 'ExclusionPath'), @('Process', 'ExclusionProcess'), @('Extension', 'ExclusionExtension'))) {
                foreach ($v in @($pref.($pair[1]))) {
                    if (-not [string]::IsNullOrWhiteSpace([string]$v)) { $ex.Add([ordered]@{ Type = $pair[0]; Value = [string]$v }) }
                }
            }
            $itemsByDs['DefenderExclusion'] = $ex.ToArray()
            $coverage.Add((Build-WthCoverage -DataSource 'DefenderExclusion' -Collector 'Defender' -Status Collected -ItemCount $ex.Count -Message 'Path, process and extension exclusions from Get-MpPreference.' -RequiresElevation 'Yes'))
        }
        catch { $coverage.Add((Get-WthFailureCoverage -ErrorRecord $_ -DataSource 'DefenderExclusion' -Collector 'Defender' -UnavailableDetail $detail)) }
    }
    else {
        $coverage.Add((Build-WthCoverage -DataSource 'DefenderExclusion' -Collector 'Defender' -Status NeedsElevation -RequiresElevation 'Yes' -Message 'Defender exclusions are only visible to administrators. Re-run elevated to collect them; exclusion rules were not evaluated.'))
    }

    # --- detection / configuration events
    $ev = Get-WthEventLogCollection -Config $Config -Collector 'Defender' -DataSource 'DefenderEvent' -LogName 'Microsoft-Windows-Windows Defender/Operational' -EventId @(1116, 1117, 5001) -UnavailableDetail 'the Windows Defender Operational log does not exist'
    foreach ($c in $ev.Coverage) { $coverage.Add($c) }
    foreach ($k in $ev.Items.Keys) { $itemsByDs[$k] = $ev.Items[$k] }
    return @{ Coverage = $coverage.ToArray(); Items = $itemsByDs }
}

# ---------------------------------------------------------------- orchestration helper

function Invoke-WthCollectorByName {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][hashtable]$Config,
        [hashtable]$ProcessLookup
    )

    switch ($Name) {
        'ScheduledTasks' { return Invoke-WthCollectorSafe -Collector $Name -Script { Get-WthScheduledTaskCollection -Config $Config } }
        'Services' { return Invoke-WthCollectorSafe -Collector $Name -Script { Get-WthServiceCollection -Config $Config } }
        'RegistryRun' { return Invoke-WthCollectorSafe -Collector $Name -Script { Get-WthRegistryRunCollection -Config $Config } }
        'StartupFolders' { return Invoke-WthCollectorSafe -Collector $Name -Script { Get-WthStartupFolderCollection -Config $Config } }
        'WmiSubscriptions' { return Invoke-WthCollectorSafe -Collector $Name -Script { Get-WthWmiSubscriptionCollection -Config $Config } }
        'LocalAccounts' { return Invoke-WthCollectorSafe -Collector $Name -Script { Get-WthLocalAccountCollection -Config $Config } }
        'Processes' { return Invoke-WthCollectorSafe -Collector $Name -Script { Get-WthProcessCollection -Config $Config } }
        'Network' { return Invoke-WthCollectorSafe -Collector $Name -Script { Get-WthNetworkCollection -Config $Config -ProcessLookup $ProcessLookup } }
        'Defender' { return Invoke-WthCollectorSafe -Collector $Name -Script { Get-WthDefenderCollection -Config $Config } }
        'SecurityEvents' {
            return Invoke-WthCollectorSafe -Collector $Name -Script {
                Get-WthEventLogCollection -Config $Config -Collector $Name -DataSource 'Event.Security' -LogName 'Security' -EventId @(4625, 4697, 4698, 4732, 1102)
            }
        }
        'PowerShellEvents' {
            return Invoke-WthCollectorSafe -Collector $Name -Script {
                Get-WthEventLogCollection -Config $Config -Collector $Name -DataSource 'Event.PowerShell' -LogName 'Microsoft-Windows-PowerShell/Operational' -EventId @(4104) -UnavailableDetail 'the PowerShell Operational log does not exist or script block logging is not enabled'
            }
        }
        'SysmonEvents' {
            return Invoke-WthCollectorSafe -Collector $Name -Script {
                Get-WthEventLogCollection -Config $Config -Collector $Name -DataSource 'Event.Sysmon' -LogName 'Microsoft-Windows-Sysmon/Operational' -EventId @(1, 13) -UnavailableDetail 'Sysmon is not installed or its Operational log does not exist'
            }
        }
        default { throw [System.ArgumentException]::new("Unknown collector '$Name'.") }
    }
}
