param($Path = (Join-Path $PSScriptRoot '../GlowCleanWin.ps1'))
$tokens = $null; $errs = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errs)
$fns = @{}
foreach ($f in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)) {
    $ps = @(); if ($f.Body.ParamBlock) { $ps = @($f.Body.ParamBlock.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath }) }
    $fns[$f.Name] = $ps
}
"== calls to own functions with unknown named parameters / too many positionals"
foreach ($c in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true)) {
    $name = $c.GetCommandName(); if (-not $name -or -not $fns.ContainsKey($name)) { continue }
    $ps = $fns[$name]; $pos = 0
    $els = @($c.CommandElements | Select-Object -Skip 1)
    for ($i = 0; $i -lt $els.Count; $i++) {
        $e = $els[$i]
        if ($e -is [System.Management.Automation.Language.CommandParameterAst]) {
            $m = @($ps | Where-Object { $_ -like "$($e.ParameterName)*" })
            if ($m.Count -eq 0) { "  line $($e.Extent.StartLineNumber): $name -$($e.ParameterName) (unknown)" }
        }
    }
}
"== variables read but never assigned anywhere"
$assigned = @{}
foreach ($a in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] }, $true)) {
    foreach ($v in $a.Left.FindAll({ param($n) $n -is [System.Management.Automation.Language.VariableExpressionAst] }, $true)) { $assigned[$v.VariablePath.UserPath -replace '^script:', ''] = 1 }
}
foreach ($p in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.ParameterAst] }, $true)) { $assigned[$p.Name.VariablePath.UserPath] = 1 }
foreach ($fe in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.ForEachStatementAst] }, $true)) { $assigned[$fe.Variable.VariablePath.UserPath] = 1 }
# -WarningVariable etc.
$assigned['cpWarn'] = 1
$auto = 'true','false','null','_','matches','env:OS','PSVersionTable','PSCommandPath','PSScriptRoot','ErrorActionPreference','ProgressPreference','args','input','this','PSItem','Error'
$seen = @{}
foreach ($v in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.VariableExpressionAst] }, $true)) {
    $n = $v.VariablePath.UserPath -replace '^script:', ''
    if ($n -like 'env:*') { continue }
    if ($auto -contains $n) { continue }
    if (-not $assigned.ContainsKey($n) -and -not $seen.ContainsKey($n)) { $seen[$n] = 1; "  line $($v.Extent.StartLineNumber): `$$n" }
}
