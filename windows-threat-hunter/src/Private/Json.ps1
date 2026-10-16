#Requires -Version 5.1
# Bounded JSON read / UTF-8 write helpers and generic data-shape helpers.

function Read-WthJsonFile {
    <#
    .SYNOPSIS
        Reads a JSON file after path validation and a size check. Never evaluates anything in the file.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [string]$Label = 'JSON file',
        [long]$MaxBytes = 52428800
    )

    $full = Resolve-WthInputPath -Path $Path -Type File -Label $Label -MaxBytes $MaxBytes
    $text = [System.IO.File]::ReadAllText($full)
    if ([string]::IsNullOrWhiteSpace($text)) {
        throw [System.ArgumentException]::new("$Label is empty: $Path")
    }
    try {
        return (ConvertFrom-Json -InputObject $text -ErrorAction Stop)
    }
    catch {
        throw [System.ArgumentException]::new("$Label is not valid JSON ($Path): $($_.Exception.Message)")
    }
}

function Write-WthTextFile {
    <#
    .SYNOPSIS
        Writes UTF-8 text (no BOM). Refuses to overwrite an existing file unless -Force is given.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Content,
        [switch]$Force
    )

    if ([System.IO.File]::Exists($Path)) {
        if (-not $Force) {
            throw [System.IO.IOException]::new("Refusing to overwrite existing file (use -Force): $Path")
        }
        if (Test-WthReparsePoint -FullPath $Path) {
            throw [System.IO.IOException]::new("Refusing to write through a symbolic link: $Path")
        }
    }
    $encoding = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $Content, $encoding)
}

function ConvertTo-WthHashtable {
    <#
    .SYNOPSIS
        Recursively converts ConvertFrom-Json output (PSCustomObject / arrays) to hashtables and object arrays.
    #>
    [CmdletBinding()]
    param([Parameter(Position = 0)][AllowNull()]$InputObject)

    if ($null -eq $InputObject) { return $null }
    if ($InputObject -is [string] -or $InputObject -is [ValueType]) { return $InputObject }
    if ($InputObject -is [System.Collections.IDictionary]) {
        $h = @{}
        foreach ($k in $InputObject.Keys) { $h[[string]$k] = ConvertTo-WthHashtable -InputObject $InputObject[$k] }
        return $h
    }
    if ($InputObject -is [System.Collections.IEnumerable]) {
        $list = New-Object System.Collections.Generic.List[object]
        foreach ($e in $InputObject) { $list.Add((ConvertTo-WthHashtable -InputObject $e)) }
        return , $list.ToArray()
    }
    if ($InputObject -is [psobject]) {
        $h = @{}
        foreach ($p in $InputObject.PSObject.Properties) {
            if ($p.MemberType -in 'NoteProperty', 'Property', 'AliasProperty') {
                $h[$p.Name] = ConvertTo-WthHashtable -InputObject $p.Value
            }
        }
        return $h
    }
    return $InputObject
}

function Merge-WthHashtable {
    <#
    .SYNOPSIS
        Deep-merges Override into Base. Dictionaries merge recursively; arrays and scalars are replaced.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$Base,
        [Parameter(Mandatory)][hashtable]$Override
    )

    $result = @{}
    foreach ($k in $Base.Keys) { $result[$k] = $Base[$k] }
    foreach ($k in $Override.Keys) {
        if ($result.ContainsKey($k) -and $result[$k] -is [hashtable] -and $Override[$k] -is [hashtable]) {
            $result[$k] = Merge-WthHashtable -Base $result[$k] -Override $Override[$k]
        }
        else {
            $result[$k] = $Override[$k]
        }
    }
    return $result
}

function Get-WthFieldValue {
    <#
    .SYNOPSIS
        Reads a (possibly dotted) field from a hashtable or object. Returns $null when absent.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Position = 0)][AllowNull()]$InputObject,
        [Parameter(Mandatory, Position = 1)][string]$Path
    )

    $current = $InputObject
    foreach ($segment in $Path.Split('.')) {
        if ($null -eq $current) { return $null }
        if ($current -is [System.Collections.IDictionary]) {
            if ($current.Contains($segment)) { $current = $current[$segment] } else { return $null }
        }
        else {
            $prop = $current.PSObject.Properties[$segment]
            if ($null -eq $prop) { return $null }
            $current = $prop.Value
        }
    }
    return $current
}

function Test-WthHasMember {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Position = 0)][AllowNull()]$InputObject,
        [Parameter(Mandatory, Position = 1)][string]$Name
    )

    if ($null -eq $InputObject) { return $false }
    if ($InputObject -is [System.Collections.IDictionary]) { return $InputObject.Contains($Name) }
    return ($null -ne $InputObject.PSObject.Properties[$Name])
}

function Get-WthMemberName {
    [CmdletBinding()]
    [OutputType([string[]])]
    param([Parameter(Position = 0)][AllowNull()]$InputObject)

    if ($null -eq $InputObject) { return @() }
    if ($InputObject -is [System.Collections.IDictionary]) { return @($InputObject.Keys | ForEach-Object { [string]$_ }) }
    return @($InputObject.PSObject.Properties | Where-Object { $_.MemberType -in 'NoteProperty', 'Property' } | ForEach-Object { $_.Name })
}

function Get-WthSha256Hex {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory, Position = 0)][AllowEmptyString()][string]$Text)

    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
        return ([System.BitConverter]::ToString($sha.ComputeHash($bytes)).Replace('-', '').ToLowerInvariant())
    }
    finally {
        $sha.Dispose()
    }
}

function Limit-WthString {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Position = 0)][AllowNull()][AllowEmptyString()][string]$Text,
        [Parameter(Position = 1)][int]$MaxLength = 1024
    )

    if ($null -eq $Text) { return $null }
    if ($Text.Length -le $MaxLength) { return $Text }
    return ($Text.Substring(0, $MaxLength) + "...[truncated $($Text.Length - $MaxLength) chars]")
}
