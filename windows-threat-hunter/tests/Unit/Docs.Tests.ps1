# Documentation, command, link, schema and CI consistency tests.
BeforeDiscovery {
    . (Join-Path (Join-Path $PSScriptRoot '..') 'TestHelpers.ps1')
    $root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $mdFiles = @(Get-ChildItem -LiteralPath $root -Recurse -Filter *.md -File | Where-Object { $_.FullName -notmatch '[\\/](test-results|TestResults)[\\/]' })
    $docFiles = @($mdFiles | ForEach-Object { @{ Path = $_.FullName; Name = $_.FullName.Substring($root.Length + 1) } })
    $workflowDir = Join-Path (Split-Path -Parent $root) '.github' | Join-Path -ChildPath 'workflows'
    $workflows = @()
    if (Test-Path -LiteralPath $workflowDir) {
        $workflows = @(Get-ChildItem -LiteralPath $workflowDir -Filter 'windows-threat-hunter-*.yml' | ForEach-Object { @{ Path = $_.FullName; Name = $_.Name } })
    }
}
BeforeAll {
    . (Join-Path (Join-Path $PSScriptRoot '..') 'TestHelpers.ps1')
    $script:Readme = Get-Content -LiteralPath (Get-WthTestPath 'README.md') -Raw
}

Describe 'Markdown links' {
    It 'resolves every relative link in <Name>' -ForEach $docFiles {
        $text = Get-Content -LiteralPath $Path -Raw
        $dir = Split-Path -Parent $Path
        $links = [regex]::Matches($text, '\]\(([^)\s]+)\)') | ForEach-Object { $_.Groups[1].Value }
        foreach ($l in $links) {
            if ($l -match '^(https?:|mailto:|#)') { continue }
            $target = ($l -split '#')[0]
            if (-not $target) { continue }
            (Test-Path -LiteralPath (Join-Path $dir $target)) | Should -BeTrue -Because "$Name links to '$l'"
        }
    }
    It 'resolves in-page anchors in <Name>' -ForEach $docFiles {
        $text = Get-Content -LiteralPath $Path -Raw
        $slugs = [regex]::Matches($text, '(?m)^#{1,6}\s+(.+?)\s*$') | ForEach-Object {
            (($_.Groups[1].Value.ToLowerInvariant() -replace '[`*]', '') -replace '[^\w\- ]', '') -replace ' ', '-'
        }
        foreach ($m in [regex]::Matches($text, '\]\(#([^)\s]+)\)')) {
            $slugs | Should -Contain $m.Groups[1].Value -Because "$Name has an anchor link #$($m.Groups[1].Value)"
        }
    }
    It 'README links to every document' {
        foreach ($d in 'docs/getting-started.md', 'docs/walkthrough.md', 'docs/user-guide.md', 'docs/configuration.md', 'docs/examples.md', 'docs/troubleshooting.md', 'docs/security-and-limitations.md', 'docs/threat-model.md', 'docs/rule-catalog.md', 'docs/rule-authoring.md', 'docs/validation-checklist.md', 'SECURITY.md', 'CONTRIBUTING.md', 'CODE_OF_CONDUCT.md', 'CHANGELOG.md', 'LICENSE') {
            $script:Readme | Should -BeLike "*]($d)*" -Because "README should link $d"
        }
    }
    It 'ships the required top-level files' {
        foreach ($f in 'README.md', 'LICENSE', 'SECURITY.md', 'CONTRIBUTING.md', 'CODE_OF_CONDUCT.md', 'RequiredModules.psd1', 'PSScriptAnalyzerSettings.psd1') {
            (Test-Path -LiteralPath (Get-WthTestPath $f)) | Should -BeTrue -Because "$f must exist"
        }
    }
}

Describe 'Documented commands' {
    It 'parses every PowerShell code block in <Name>' -ForEach $docFiles {
        $text = Get-Content -LiteralPath $Path -Raw
        foreach ($m in [regex]::Matches($text, '(?s)```powershell\r?\n(.*?)```')) {
            $errors = $null
            [void][System.Management.Automation.Language.Parser]::ParseInput($m.Groups[1].Value, [ref]$null, [ref]$errors)
            @($errors).Count | Should -Be 0 -Because "block in $Name must parse: $($m.Groups[1].Value.Substring(0, [Math]::Min(60, $m.Groups[1].Value.Length)))"
        }
    }
    It 'only references scripts that exist' {
        $all = (Get-ChildItem -LiteralPath $script:RepoRoot -Recurse -Filter *.md -File | Get-Content -Raw) -join "`n"
        foreach ($m in [regex]::Matches($all, '\./scripts/([A-Za-z\-]+\.ps1)')) {
            (Test-Path -LiteralPath (Get-WthTestPath "scripts/$($m.Groups[1].Value)")) | Should -BeTrue -Because "docs mention scripts/$($m.Groups[1].Value)"
        }
    }
    It 'only uses script parameters and module commands that exist' {
        Import-WthTestModule
        $cli = Get-Command (Get-WthTestPath 'scripts/Invoke-WindowsThreatHunter.ps1')
        $all = (Get-ChildItem -LiteralPath $script:RepoRoot -Recurse -Filter *.md -File | Get-Content -Raw) -join "`n"
        foreach ($line in ($all -split "`n" | Where-Object { $_ -match 'Invoke-WindowsThreatHunter\.ps1' -and $_ -match '\s-[A-Z]' })) {
            foreach ($p in [regex]::Matches($line, '(?<![\w-])-([A-Z][A-Za-z]+)') | ForEach-Object { $_.Groups[1].Value }) {
                $cli.Parameters.Keys | Should -Contain $p -Because "docs line uses -${p}: ${line}"
            }
        }
        $exported = (Get-Module WindowsThreatHunter).ExportedFunctions.Keys
        foreach ($m in [regex]::Matches($all, '\b((?:Invoke|Get|Test|Export|Import)-Wth[A-Za-z]+)\b(?!\*)')) {
            $exported | Should -Contain $m.Groups[1].Value -Because "docs mention $($m.Groups[1].Value)"
        }
    }
    It 'documents the same exit codes as the code' {
        $text = Get-Content -LiteralPath (Get-WthTestPath 'docs/user-guide.md') -Raw
        foreach ($c in 0..4) { $text | Should -BeLike "*| $c |*" }
    }
}

Describe 'Report schema and sample reports' {
    It 'ships example reports that match the current JSON schema' {
        Import-WthTestModule
        $sample = Get-Content -LiteralPath (Get-WthTestPath 'sample-data/reports/lab-intrusion.json') -Raw | ConvertFrom-Json
        $live = Invoke-WthHunt -SnapshotPath (Join-Path $script:SnapshotRoot 'lab-intrusion.json')
        $dir = New-WthTestDirectory
        try {
            $file = Export-WthReport -Result $live -OutputDirectory $dir -Format Json
            $now = Get-Content -LiteralPath $file -Raw | ConvertFrom-Json
            (@($sample.PSObject.Properties.Name) -join ',') | Should -Be (@($now.PSObject.Properties.Name) -join ',')
            (@($sample.Result.PSObject.Properties.Name | Sort-Object) -join ',') | Should -Be (@($now.Result.PSObject.Properties.Name | Sort-Object) -join ',')
            (@($sample.Result.Findings[0].PSObject.Properties.Name | Sort-Object) -join ',') | Should -Be (@($now.Result.Findings[0].PSObject.Properties.Name | Sort-Object) -join ',')
        }
        finally { Remove-WthTestDirectory -Path $dir }
    }
    It 'labels every shipped sample snapshot as synthetic' {
        foreach ($f in Get-ChildItem -LiteralPath $script:SnapshotRoot -Filter *.json) {
            (Get-Content -LiteralPath $f.FullName -Raw | ConvertFrom-Json).synthetic | Should -BeTrue
        }
    }
    It 'has a current generated rule catalog' {
        $rules = @(Get-WthRule -Full)
        $cat = Get-Content -LiteralPath (Get-WthTestPath 'docs/rule-catalog.md') -Raw
        foreach ($r in $rules) { $cat | Should -BeLike "*## $($r.id)*" }
        $cat | Should -BeLike "*all $($rules.Count) shipped rules*"
    }
}

Describe 'CI workflows' {
    It '<Name> pins every action to a commit SHA' -ForEach $workflows {
        $text = Get-Content -LiteralPath $Path -Raw
        foreach ($m in [regex]::Matches($text, '(?m)^\s*-?\s*uses:\s*(\S+)')) {
            $m.Groups[1].Value | Should -Match '@[0-9a-f]{40}$' -Because "unpinned action: $($m.Groups[1].Value)"
        }
    }
    It '<Name> declares least-privilege permissions and avoids pull_request_target' -ForEach $workflows {
        $text = Get-Content -LiteralPath $Path -Raw
        $text | Should -Match '(?m)^permissions:\s*\r?\n\s+contents:\s*read'
        $text | Should -Not -Match 'pull_request_target'
        $text | Should -Not -Match 'write-all'
    }
    It 'has workflows for static analysis, tests, dependency review and secret scanning' {
        $dir = Join-Path (Split-Path -Parent $script:RepoRoot) '.github' | Join-Path -ChildPath 'workflows'
        $all = (Get-ChildItem -LiteralPath $dir -Filter 'windows-threat-hunter-*.yml' | ForEach-Object { Get-Content -LiteralPath $_.FullName -Raw }) -join "`n"
        $all | Should -BeLike '*PSScriptAnalyzer*'
        $all | Should -BeLike '*Invoke-Tests.ps1*'
        $all | Should -BeLike '*dependency-review-action*'
        $all | Should -BeLike '*gitleaks*'
    }
}
