param($Path = (Join-Path $PSScriptRoot '../GlowCleanWin.ps1'))
$tokens = $null; $errs = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errs)
"parse errors: $($errs.Count)"
foreach ($e in $errs) { "  line $($e.Extent.StartLineNumber): $($e.Message)" }
$bad = $ast.FindAll({ param($n) $n.GetType().Name -in @('TernaryExpressionAst','PipelineChainAst') }, $true)
"PS7-only AST nodes: $($bad.Count)"
$t7 = @($tokens | Where-Object { $_.Kind -in @('QuestionQuestion','QuestionQuestionEquals','QuestionDot','QuestionLBracket','AndAnd','OrOr') })
"PS7-only tokens: $($t7.Count)"
foreach ($t in $t7) { "  line $($t.Extent.StartLineNumber): $($t.Text)" }
$fn = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)
"functions: $($fn.Count)"
# commands called but not defined anywhere and not a known cmdlet name pattern
$defined = @($fn | ForEach-Object { $_.Name })
$calls = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true) | ForEach-Object { $_.GetCommandName() } | Where-Object { $_ } | Sort-Object -Unique
"custom-looking commands not defined: " + ((@($calls | Where-Object { $_ -notin $defined -and -not (Get-Command $_ -ErrorAction SilentlyContinue) })) -join ', ')
if ($errs.Count -or $bad.Count -or $t7.Count) { exit 1 }
