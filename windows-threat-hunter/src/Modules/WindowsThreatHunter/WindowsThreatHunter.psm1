#Requires -Version 5.1
# WindowsThreatHunter root module.
#
# The module is loaded in place from the repository: public commands live next to this file, shared private
# helpers live in <repo>/src/Private, detection rules in <repo>/src/Rules and configuration in <repo>/config.

Set-StrictMode -Version 2.0

$script:WthModuleRoot = $PSScriptRoot
$script:WthProjectRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
$script:WthSourceRoot = Join-Path $script:WthProjectRoot 'src'
$script:WthPrivatePath = Join-Path $script:WthSourceRoot 'Private'
$script:WthRulesPath = Join-Path $script:WthSourceRoot 'Rules'
$script:WthConfigRoot = Join-Path $script:WthProjectRoot 'config'
$script:WthDefaultConfigFile = Join-Path $script:WthConfigRoot 'default.json'
$script:WthAttackCatalogPath = Join-Path $script:WthConfigRoot 'attack-techniques.json'
$script:WthEnvironment = $null

# Order matters only for files that define script-scope constants used by later files.
$privateFiles = @(
    'Constants', 'Platform', 'Paths', 'Json', 'Regex', 'Redaction', 'Config', 'Conditions', 'Rules',
    'Engine', 'Wrappers', 'Collectors', 'Reporting'
)
foreach ($name in $privateFiles) {
    $file = Join-Path $script:WthPrivatePath "$name.ps1"
    if (-not (Test-Path -LiteralPath $file)) { throw "WindowsThreatHunter: missing private file $file" }
    . $file
}

$publicFiles = @(Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot 'Public') -Filter '*.ps1' -File | Sort-Object Name)
foreach ($file in $publicFiles) { . $file.FullName }

Export-ModuleMember -Function ($publicFiles | ForEach-Object { $_.BaseName })
