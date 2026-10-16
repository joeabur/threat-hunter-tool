@{
    Severity     = @('Error', 'Warning')
    IncludeRules = @(
        'PSAvoidUsingInvokeExpression'
        'PSAvoidUsingPlainTextForPassword'
        'PSAvoidUsingConvertToSecureStringWithPlainText'
        'PSAvoidUsingUsernameAndPasswordParams'
        'PSAvoidUsingComputerNameHardcoded'
        'PSAvoidUsingCmdletAliases'
        'PSAvoidUsingPositionalParameters'
        'PSAvoidGlobalVars'
        'PSAvoidUsingEmptyCatchBlock'
        'PSUseApprovedVerbs'
        'PSUseDeclaredVarsMoreThanAssignments'
        'PSUseShouldProcessForStateChangingFunctions'
        'PSUseCmdletCorrectly'
        'PSUseSingularNouns'
        'PSReservedCmdletChar'
        'PSReservedParams'
        'PSMisleadingBacktick'
        'PSPossibleIncorrectComparisonWithNull'
        'PSShouldProcess'
        'PSUseCompatibleSyntax'
    )
    Rules        = @{
        PSUseCompatibleSyntax = @{ Enable = $true; TargetVersions = @('5.1', '7.0') }
        PSAvoidUsingPositionalParameters = @{ CommandAllowList = @('Join-Path', 'Split-Path') }
    }
    # Intentional, documented exceptions are suppressed in code with [Diagnostics.CodeAnalysis.SuppressMessageAttribute]
    # and a justification, never here.
}
