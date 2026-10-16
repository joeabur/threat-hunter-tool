#Requires -Version 5.1
# Declarative condition language. Rules contain data only; nothing in a rule is ever executed as code.

# operator -> name of the property that carries its argument ($null = no argument)
$script:WthOperators = @{
    equals            = 'value'
    notEquals         = 'value'
    in                = 'values'
    notIn             = 'values'
    contains          = 'value'
    startsWith        = 'value'
    endsWith          = 'value'
    matches           = 'value'
    matchesList       = 'list'
    inList            = 'list'
    notInList         = 'list'
    pathContainsAny   = 'list'
    pathStartsWithAny = 'list'
    exists            = $null
    notExists         = $null
    isTrue            = $null
    isFalse           = $null
    gt                = 'value'
    gte               = 'value'
    lt                = 'value'
    lte               = 'value'
}
$script:WthPatternListOps = @('matchesList')
$script:WthMaxConditionDepth = 6
$script:WthMaxConditionNodes = 60

function Build-WthEvalContext {
    <#
    .SYNOPSIS
        Builds the lookup context used by the condition evaluator from a validated configuration.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$Config,
        [hashtable]$Environment
    )

    if ($null -eq $Environment) { $Environment = Get-WthDefaultEnvironment }
    return @{
        Lists         = $Config.lists
        Patterns      = $Config.patterns
        Environment   = $Environment
        ExpandedCache = @{}
    }
}

function Get-WthExpandedList {
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)][hashtable]$Context,
        [Parameter(Mandatory)][string]$Name
    )

    if (-not $Context.ExpandedCache.ContainsKey($Name)) {
        $expanded = New-Object System.Collections.Generic.List[string]
        foreach ($entry in @($Context.Lists[$Name])) {
            $norm = ConvertTo-WthNormalPath -Path ([string]$entry) -Environment $Context.Environment
            if ($norm) { $expanded.Add($norm) }
        }
        $Context.ExpandedCache[$Name] = $expanded.ToArray()
    }
    return , $Context.ExpandedCache[$Name]
}

function Get-WthValueSet {
    # Normalises a field value to an array of non-null values (so a $null field is an empty set).
    [CmdletBinding()]
    param([Parameter(Position = 0)][AllowNull()]$Value)

    if ($null -eq $Value) { return , @() }
    if ($Value -is [string]) { return , @($Value) }
    if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [System.Collections.IDictionary]) {
        $list = New-Object System.Collections.Generic.List[object]
        foreach ($v in $Value) { if ($null -ne $v) { $list.Add($v) } }
        return , $list.ToArray()
    }
    return , @($Value)
}

function Test-WthLeafCondition {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]$Node,
        [Parameter(Mandatory)][AllowNull()]$Item,
        [Parameter(Mandatory)][hashtable]$Context
    )

    $op = [string]$Node.op
    $values = Get-WthValueSet -Value (Get-WthFieldValue -InputObject $Item -Path ([string]$Node.field))
    $cmp = [System.StringComparison]::OrdinalIgnoreCase

    switch ($op) {
        'exists' { return (@($values | Where-Object { -not ($_ -is [string] -and $_.Length -eq 0) }).Count -gt 0) }
        'notExists' { return (@($values | Where-Object { -not ($_ -is [string] -and $_.Length -eq 0) }).Count -eq 0) }
        'isTrue' { return (@($values | Where-Object { $_ -is [bool] -and $_ }).Count -gt 0) }
        'isFalse' { return (@($values | Where-Object { $_ -is [bool] -and -not $_ }).Count -gt 0) }
        { $_ -in 'equals', 'notEquals' } {
            $target = [string]$Node.value
            $hit = $false
            foreach ($v in $values) { if ([string]::Equals([string]$v, $target, $cmp)) { $hit = $true; break } }
            if ($op -eq 'equals') { return $hit } else { return (-not $hit) }
        }
        { $_ -in 'in', 'notIn' } {
            $targets = @($Node.values | ForEach-Object { [string]$_ })
            $hit = $false
            foreach ($v in $values) {
                foreach ($t in $targets) { if ([string]::Equals([string]$v, $t, $cmp)) { $hit = $true; break } }
                if ($hit) { break }
            }
            if ($op -eq 'in') { return $hit } else { return (-not $hit) }
        }
        'contains' {
            $target = [string]$Node.value
            foreach ($v in $values) { if (([string]$v).IndexOf($target, $cmp) -ge 0) { return $true } }
            return $false
        }
        'startsWith' {
            $target = [string]$Node.value
            foreach ($v in $values) { if (([string]$v).StartsWith($target, $cmp)) { return $true } }
            return $false
        }
        'endsWith' {
            $target = [string]$Node.value
            foreach ($v in $values) { if (([string]$v).EndsWith($target, $cmp)) { return $true } }
            return $false
        }
        'matches' {
            foreach ($v in $values) { if (Test-WthRegexMatch -Text ([string]$v) -Pattern ([string]$Node.value)) { return $true } }
            return $false
        }
        'matchesList' {
            $patterns = @($Context.Patterns[[string]$Node.list])
            foreach ($v in $values) {
                foreach ($p in $patterns) { if (Test-WthRegexMatch -Text ([string]$v) -Pattern ([string]$p)) { return $true } }
            }
            return $false
        }
        { $_ -in 'inList', 'notInList' } {
            $entries = @($Context.Lists[[string]$Node.list] | ForEach-Object { [string]$_ })
            $hit = $false
            foreach ($v in $values) {
                foreach ($e in $entries) { if ([string]::Equals([string]$v, $e, $cmp)) { $hit = $true; break } }
                if ($hit) { break }
            }
            if ($op -eq 'inList') { return $hit } else { return (-not $hit) }
        }
        'pathContainsAny' {
            $fragments = Get-WthExpandedList -Context $Context -Name ([string]$Node.list)
            foreach ($v in $values) {
                $path = ConvertTo-WthNormalPath -Path ([string]$v) -Environment $Context.Environment
                if (-not $path) { continue }
                foreach ($f in $fragments) { if ($path.IndexOf($f, $cmp) -ge 0) { return $true } }
            }
            return $false
        }
        'pathStartsWithAny' {
            $prefixes = Get-WthExpandedList -Context $Context -Name ([string]$Node.list)
            foreach ($v in $values) {
                $path = ConvertTo-WthNormalPath -Path ([string]$v) -Environment $Context.Environment
                if (-not $path) { continue }
                foreach ($f in $prefixes) { if ($path.StartsWith($f, $cmp)) { return $true } }
            }
            return $false
        }
        { $_ -in 'gt', 'gte', 'lt', 'lte' } {
            $target = 0.0
            if (-not [double]::TryParse([string]$Node.value, [System.Globalization.NumberStyles]::Float, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$target)) { return $false }
            foreach ($v in $values) {
                $n = 0.0
                if (-not [double]::TryParse([string]$v, [System.Globalization.NumberStyles]::Float, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$n)) { continue }
                switch ($op) {
                    'gt' { if ($n -gt $target) { return $true } }
                    'gte' { if ($n -ge $target) { return $true } }
                    'lt' { if ($n -lt $target) { return $true } }
                    'lte' { if ($n -le $target) { return $true } }
                }
            }
            return $false
        }
        default { return $false }
    }
}

function Test-WthCondition {
    <#
    .SYNOPSIS
        Evaluates a validated condition tree against one item. Unknown or malformed nodes evaluate to $false.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]$Condition,
        [Parameter(Mandatory)][AllowNull()]$Item,
        [Parameter(Mandatory)][hashtable]$Context
    )

    if (Test-WthHasMember -InputObject $Condition -Name 'all') {
        foreach ($child in @($Condition.all)) {
            if (-not (Test-WthCondition -Condition $child -Item $Item -Context $Context)) { return $false }
        }
        return $true
    }
    if (Test-WthHasMember -InputObject $Condition -Name 'any') {
        foreach ($child in @($Condition.any)) {
            if (Test-WthCondition -Condition $child -Item $Item -Context $Context) { return $true }
        }
        return $false
    }
    if (Test-WthHasMember -InputObject $Condition -Name 'not') {
        return (-not (Test-WthCondition -Condition $Condition.not -Item $Item -Context $Context))
    }
    if ((Test-WthHasMember -InputObject $Condition -Name 'field') -and (Test-WthHasMember -InputObject $Condition -Name 'op')) {
        return (Test-WthLeafCondition -Node $Condition -Item $Item -Context $Context)
    }
    return $false
}

function Test-WthConditionStructure {
    <#
    .SYNOPSIS
        Validates a condition tree and returns a list of error strings (empty when valid).
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)][AllowNull()]$Condition,
        [Parameter(Mandatory)][hashtable]$Config,
        [int]$Depth = 1,
        [hashtable]$Counter,
        [string]$Location = 'condition'
    )

    $errors = New-Object System.Collections.Generic.List[string]
    if ($null -eq $Counter) { $Counter = @{ Count = 0 } }
    $Counter.Count++

    if ($Counter.Count -gt $script:WthMaxConditionNodes) {
        $errors.Add("${Location}: condition has more than $script:WthMaxConditionNodes nodes")
        return , $errors.ToArray()
    }
    if ($Depth -gt $script:WthMaxConditionDepth) {
        $errors.Add("${Location}: condition is nested deeper than $script:WthMaxConditionDepth levels")
        return , $errors.ToArray()
    }
    if ($null -eq $Condition -or $Condition -is [string] -or $Condition -is [System.Collections.IEnumerable]) {
        $errors.Add("${Location}: must be an object")
        return , $errors.ToArray()
    }

    $names = @(Get-WthMemberName -InputObject $Condition)
    $isAll = $names -contains 'all'
    $isAny = $names -contains 'any'
    $isNot = $names -contains 'not'
    $isLeaf = ($names -contains 'field') -or ($names -contains 'op')
    $kinds = @($isAll, $isAny, $isNot, $isLeaf | Where-Object { $_ }).Count
    if ($kinds -ne 1) {
        $errors.Add("${Location}: must contain exactly one of 'all', 'any', 'not' or a 'field'/'op' pair")
        return , $errors.ToArray()
    }

    if ($isAll -or $isAny) {
        $key = if ($isAll) { 'all' } else { 'any' }
        $extra = @($names | Where-Object { $_ -notin @($key, 'comment') })
        foreach ($e in $extra) { $errors.Add("${Location}: unknown key '$e'") }
        $children = $Condition.$key
        if ($null -eq $children -or $children -is [string] -or $children -isnot [System.Collections.IEnumerable] -or @($children).Count -eq 0) {
            $errors.Add("${Location}.${key}: must be a non-empty array")
            return , $errors.ToArray()
        }
        if (@($children).Count -gt 25) { $errors.Add("${Location}.${key}: more than 25 children") }
        $i = 0
        foreach ($child in @($children)) {
            foreach ($e in (Test-WthConditionStructure -Condition $child -Config $Config -Depth ($Depth + 1) -Counter $Counter -Location "$Location.$key[$i]")) { $errors.Add($e) }
            $i++
        }
        return , $errors.ToArray()
    }
    if ($isNot) {
        $extra = @($names | Where-Object { $_ -notin @('not', 'comment') })
        foreach ($e in $extra) { $errors.Add("${Location}: unknown key '$e'") }
        foreach ($e in (Test-WthConditionStructure -Condition $Condition.not -Config $Config -Depth ($Depth + 1) -Counter $Counter -Location "$Location.not")) { $errors.Add($e) }
        return , $errors.ToArray()
    }

    # Leaf
    $allowed = @('field', 'op', 'value', 'values', 'list', 'comment')
    foreach ($n in $names) { if ($n -notin $allowed) { $errors.Add("${Location}: unknown key '$n'") } }
    $field = Get-WthFieldValue -InputObject $Condition -Path 'field'
    $op = Get-WthFieldValue -InputObject $Condition -Path 'op'
    if ([string]::IsNullOrWhiteSpace([string]$field) -or $field -isnot [string]) {
        $errors.Add("${Location}: 'field' must be a non-empty string")
    }
    elseif ($field -notmatch '^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)*$') {
        $errors.Add("${Location}: 'field' has invalid characters: $field")
    }
    if ($op -isnot [string] -or -not $script:WthOperators.ContainsKey([string]$op)) {
        $errors.Add("${Location}: unknown operator '$op'. Allowed: $((($script:WthOperators.Keys | Sort-Object) -join ', '))")
        return , $errors.ToArray()
    }
    $argName = $script:WthOperators[[string]$op]
    foreach ($candidate in 'value', 'values', 'list') {
        if ($candidate -ne $argName -and ($names -contains $candidate)) {
            $errors.Add("${Location}: operator '$op' does not accept '$candidate'")
        }
    }
    if ($null -ne $argName -and -not ($names -contains $argName)) {
        $errors.Add("${Location}: operator '$op' requires '$argName'")
        return , $errors.ToArray()
    }
    switch ($argName) {
        'value' {
            $v = $Condition.value
            if ($null -eq $v -or $v -is [System.Collections.IEnumerable] -and $v -isnot [string]) { $errors.Add("${Location}: 'value' must be a scalar") }
            elseif ($op -eq 'matches') {
                $issue = Get-WthRegexIssue -Pattern ([string]$v)
                if ($issue) { $errors.Add("${Location}: regex rejected - $issue") }
            }
            elseif ($op -in 'gt', 'gte', 'lt', 'lte') {
                $d = 0.0
                if (-not [double]::TryParse([string]$v, [System.Globalization.NumberStyles]::Float, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$d)) { $errors.Add("${Location}: 'value' must be numeric for '$op'") }
            }
        }
        'values' {
            $vs = $Condition.values
            if ($null -eq $vs -or $vs -is [string] -or $vs -isnot [System.Collections.IEnumerable] -or @($vs).Count -eq 0) { $errors.Add("${Location}: 'values' must be a non-empty array") }
            elseif (@($vs).Count -gt 200) { $errors.Add("${Location}: 'values' has more than 200 entries") }
        }
        'list' {
            $name = [string]$Condition.list
            $dict = if ($script:WthPatternListOps -contains $op) { $Config.patterns } else { $Config.lists }
            if (-not $dict.ContainsKey($name)) {
                $kind = if ($script:WthPatternListOps -contains $op) { 'patterns' } else { 'lists' }
                $errors.Add("${Location}: '$name' is not defined under configuration '$kind'")
            }
        }
    }
    return , $errors.ToArray()
}
