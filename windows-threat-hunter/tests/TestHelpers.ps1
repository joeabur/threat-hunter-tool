# Shared helpers dot-sourced by the Pester test files. Portable: no Windows APIs are used here.

$script:RepoRoot = Split-Path -Parent $PSScriptRoot
$script:ModuleManifest = Join-Path (Join-Path (Join-Path (Join-Path $script:RepoRoot 'src') 'Modules') 'WindowsThreatHunter') 'WindowsThreatHunter.psd1'
$script:FixtureRoot = Join-Path $PSScriptRoot 'Fixtures'
$script:SnapshotRoot = Join-Path (Join-Path $script:RepoRoot 'sample-data') 'snapshots'

function Import-WthTestModule {
    Import-Module $script:ModuleManifest -Force -ErrorAction Stop
}

function Get-WthTestPath {
    param([Parameter(Mandatory)][string]$Relative)
    $parts = $Relative -split '[\\/]'
    $path = $script:RepoRoot
    foreach ($p in $parts) { $path = Join-Path $path $p }
    return $path
}

function New-WthTestDirectory {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Test helper that only creates a temporary directory.')]
    param()
    $dir = Join-Path ([System.IO.Path]::GetTempPath()) ('wth-test-' + [guid]::NewGuid().ToString('N').Substring(0, 12))
    [void][System.IO.Directory]::CreateDirectory($dir)
    return $dir
}

function Remove-WthTestDirectory {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Test helper that only removes its own temporary directory.')]
    param([string]$Path)
    if ($Path -and (Test-Path -LiteralPath $Path) -and $Path.StartsWith([System.IO.Path]::GetTempPath())) {
        Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Test-WthTestIsWindows {
    return (($PSVersionTable.PSEdition -eq 'Desktop') -or ([System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT))
}

function Test-WthTestIsElevated {
    if (-not (Test-WthTestIsWindows)) { return $false }
    $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    return (New-Object System.Security.Principal.WindowsPrincipal($id)).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

function ConvertTo-WthTestJsonFile {
    param([Parameter(Mandatory)]$Object, [Parameter(Mandatory)][string]$Path, [int]$Depth = 12)
    $text = ConvertTo-Json -InputObject $Object -Depth $Depth
    [System.IO.File]::WriteAllText($Path, $text, (New-Object System.Text.UTF8Encoding($false)))
}
