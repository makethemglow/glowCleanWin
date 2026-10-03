<#
PcCheck.ps1 - проверка и лечение ПК с Windows 10/11.

ЧТО ДЕЛАЕТ
  1. Только читает: система, защита, сертификаты (в первую очередь посторонние корневые),
     браузеры, сеть, автозапуск, учётные записи, программы, реклама и слежка Windows.
  2. Показывает итог: зелёное - хорошо, красное - плохо, жёлтое - посмотри сам, серое - справка.
  3. Один раз спрашивает, что исправить:
        YES    - всё красное
        ALL    - красное и жёлтое (кроме пунктов "только по номеру")
        1 4 7  - только эти номера (можно 3-6)
        Enter  - ничего не менять
     Перед правками создаётся точка восстановления; старые значения, удалённые сертификаты (.cer)
     и файлы складываются в папку backup рядом с отчётом, всё записывается в журнал.

КАК ЗАПУСКАТЬ
  Двойной щелчок по PcCheck.cmd (права администратора скрипт запросит сам), либо:
     powershell -NoProfile -ExecutionPolicy Bypass -File "C:\Tools\PcCheck.ps1"
  Параметры:
     -ReportOnly   только отчёт, без вопроса об исправлении
     -SkipUpdates  не искать неустановленные обновления (это самая долгая часть)
     -Demo         показать, как выглядит вывод, ничего не проверяя и не меняя

ГДЕ РЕЗУЛЬТАТ
  Рядом со скриптом: PcCheck_Reports\<компьютер>_<дата>\report.txt и backup\
  Журнал изменений:   PcCheck_Reports\<компьютер>_changes.tsv
  Свои "это нормально": PcCheck_Reports\<компьютер>_ignore.txt - по одной строке, кусок заголовка пункта.

В отчёт не попадают: командные строки целиком (в них бывают ключи), пароли, содержимое файлов.
#>
param(
    [switch]$ReportOnly,
    [switch]$SkipUpdates,
    [switch]$NoPause,
    [switch]$Demo,
    [switch]$LoadOnly,
    [switch]$Relaunched
)

$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
$script:Version = '1.0 от 2026-10-03'
$script:IsWin = ($env:OS -eq 'Windows_NT')
$script:DemoMode = [bool]$Demo
$script:SkipUpdates = [bool]$SkipUpdates

function Test-Admin {
    if (-not $script:IsWin) { return $false }
    return ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# ---------------------------------------------------------------- перезапуск: нужны права администратора и Windows PowerShell 5.1 (64 бита)
if ($script:IsWin -and -not $LoadOnly -and -not $Demo -and -not $Relaunched) {
    $needElev = -not (Test-Admin)
    $is32 = ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess)
    $needHost = ($PSVersionTable.PSEdition -eq 'Core') -or $is32
    if ($needElev -or $needHost) {
        $exe = Join-Path $env:windir 'System32\WindowsPowerShell\v1.0\powershell.exe'
        if ($is32 -and -not $needElev) { $exe = Join-Path $env:windir 'sysnative\WindowsPowerShell\v1.0\powershell.exe' }
        $argLine = '-NoProfile -ExecutionPolicy Bypass -File "' + $PSCommandPath + '" -Relaunched'
        if ($ReportOnly) { $argLine += ' -ReportOnly' }
        if ($SkipUpdates) { $argLine += ' -SkipUpdates' }
        try {
            if ($needElev) { Start-Process -FilePath $exe -ArgumentList $argLine -Verb RunAs }
            else { Start-Process -FilePath $exe -ArgumentList $argLine }
            Write-Host 'Проверка открылась в отдельном окне (с правами администратора).' -ForegroundColor Cyan
        } catch {
            Write-Host 'Не удалось запустить с правами администратора (запрос отклонён?). Ничего не сделано.' -ForegroundColor Red
        }
        return
    }
}

# ---------------------------------------------------------------- общее состояние
$script:Findings = New-Object System.Collections.ArrayList
$script:Report = New-Object System.Text.StringBuilder
$script:SigCache = @{}
$script:Section = ''
$script:RunDir = $null
$script:ReportFile = $null
$script:BackupDir = $null
$script:JournalFile = $null
$script:IgnoreList = @()
$script:UpdCache = $null
$script:RebootNeeded = $false
$script:UserHives = @()
$script:Programs = @()
$script:Ctx = $null
$script:HostsPath = ''
if ($script:IsWin) { $script:HostsPath = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts' }

$script:LevelMeta = @{
    OK   = @{ Tag = '[ OK ]'; Color = 'Green' }
    INFO = @{ Tag = '[ i  ]'; Color = 'Gray' }
    WARN = @{ Tag = '[ ?? ]'; Color = 'Yellow' }
    BAD  = @{ Tag = '[ !! ]'; Color = 'Red' }
    ERR  = @{ Tag = '[ERR ]'; Color = 'Magenta' }
}

# ---------------------------------------------------------------- вывод
function Out-Line {
    param([string]$Text = '', [string]$Color = '')
    [void]$script:Report.AppendLine($Text)
    if ($Color) { Write-Host $Text -ForegroundColor $Color } else { Write-Host $Text }
}
function Out-ReportOnly { param([string]$Text = '') [void]$script:Report.AppendLine($Text) }
function Save-Report {
    if (-not $script:ReportFile) { return }
    try { [IO.File]::WriteAllText($script:ReportFile, $script:Report.ToString(), (New-Object System.Text.UTF8Encoding($true))) } catch { }
}
function Start-Section {
    param([string]$Name)
    $script:Section = $Name
    Write-Host "  $Name..." -ForegroundColor Cyan
}

function Add-Finding {
    param(
        [Parameter(Mandatory = $true)][ValidateSet('OK', 'INFO', 'WARN', 'BAD', 'ERR')][string]$Level,
        [Parameter(Mandatory = $true)][string]$Title,
        [string[]]$Detail = @(),
        [scriptblock]$Fix = $null,
        [string]$FixText = '',
        [hashtable]$Data = @{},
        [string]$Manual = '',
        [switch]$Explicit,
        [switch]$NeedsReboot
    )
    if ($Level -eq 'WARN' -or $Level -eq 'BAD') {
        foreach ($ig in $script:IgnoreList) {
            if ($ig -and $Title.IndexOf($ig, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
                $Level = 'INFO'; $Title = "$Title  (в твоём списке «это нормально»)"; $Fix = $null; $FixText = ''; $Manual = ''
                break
            }
        }
    }
    $f = [pscustomobject]@{
        Section = $script:Section; Level = $Level; Title = $Title; Detail = @($Detail | Where-Object { $_ })
        Fix = $Fix; FixText = $FixText; Data = $Data; Manual = $Manual
        Explicit = [bool]$Explicit; NeedsReboot = [bool]$NeedsReboot; Num = 0
    }
    [void]$script:Findings.Add($f)
}

function Invoke-Check {
    param([string]$Name, [scriptblock]$Body)
    Write-Host "      $Name" -ForegroundColor DarkGray
    $ErrorActionPreference = 'Stop'
    try { & $Body }
    catch { Add-Finding -Level ERR -Title "Проверка не выполнилась: $Name" -Detail @("$($_.Exception.Message)") }
}

function Show-Finding {
    param($f, [switch]$Short)
    $m = $script:LevelMeta[$f.Level]
    $num = ''; if ($f.Num -gt 0) { $num = "#$($f.Num) " }
    Out-Line "  $($m.Tag) $num$($f.Title)" $m.Color
    if (-not $Short) {
        $max = 30; if ($f.Level -eq 'INFO' -or $f.Level -eq 'OK') { $max = 6 }
        $i = 0
        foreach ($d in $f.Detail) {
            $i++
            if ($i -le $max) { Out-Line "           $d" $m.Color } else { Out-ReportOnly "           $d" }
        }
        if ($f.Detail.Count -gt $max) { Write-Host "           ... ещё $($f.Detail.Count - $max) (полностью - в report.txt)" -ForegroundColor DarkGray }
    }
    if ($f.Fix) {
        $only = ''; if ($f.Explicit) { $only = ' (только по номеру)' }
        Out-Line "           -> исправление #$($f.Num)${only}: $($f.FixText)" 'Cyan'
    }
    if ($f.Manual) { Out-Line "           -> вручную: $($f.Manual)" 'White' }
}

# ---------------------------------------------------------------- резервные копии и журнал
function Get-BackupDir {
    if (-not (Test-Path -LiteralPath $script:BackupDir)) { New-Item -ItemType Directory -Path $script:BackupDir -Force | Out-Null }
    return $script:BackupDir
}
function Add-BackupLine {
    param([string]$File, [string]$Line)
    [IO.File]::AppendAllText((Join-Path (Get-BackupDir) $File), $Line + "`r`n", (New-Object System.Text.UTF8Encoding($false)))
}
function Add-Change {
    param([string]$Type, [string]$What)
    $line = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`t$Type`t$What"
    try { [IO.File]::AppendAllText($script:JournalFile, $line + "`r`n", (New-Object System.Text.UTF8Encoding($false))) } catch { }
    Out-ReportOnly "       журнал: $Type | $What"
}
function Backup-File {
    param([string]$Path)
    $dir = Join-Path (Get-BackupDir) 'files'
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $n = @(Get-ChildItem -LiteralPath $dir -Force).Count + 1
    $dst = Join-Path $dir ('{0:d3}_{1}' -f $n, (Split-Path $Path -Leaf))
    Copy-Item -LiteralPath $Path -Destination $dst -Force
    Add-BackupLine 'files_before.tsv' "$dst`t$Path"
    return $dst
}
function ConvertTo-NativeRegPath {
    param([string]$Path)
    $p = $Path -replace '^Microsoft\.PowerShell\.Core\\Registry::', ''
    $p = $p -replace '^Registry::', ''
    $p = $p -replace '^HKLM:\\', 'HKEY_LOCAL_MACHINE\'
    $p = $p -replace '^HKCU:\\', 'HKEY_CURRENT_USER\'
    return $p
}
function Export-RegKey {
    param([string]$Path, [string]$FileName)
    $dst = Join-Path (Get-BackupDir) $FileName
    & reg.exe export (ConvertTo-NativeRegPath $Path) $dst /y 2>&1 | Out-Null
    return $dst
}
function Get-RegValue {
    param([string]$Path, [string]$Name)
    try {
        if (-not (Test-Path -LiteralPath $Path)) { return $null }
        $k = Get-Item -LiteralPath $Path -ErrorAction Stop
        if ($k.GetValueNames() -contains $Name) { return $k.GetValue($Name, $null, 'DoNotExpandEnvironmentNames') }
    } catch { }
    return $null
}
function Backup-RegValue {
    param([string]$Path, [string]$Name)
    $cur = '(absent)'; $kind = ''
    try {
        if (Test-Path -LiteralPath $Path) {
            $k = Get-Item -LiteralPath $Path -ErrorAction Stop
            if ($k.GetValueNames() -contains $Name) {
                $v = $k.GetValue($Name, $null, 'DoNotExpandEnvironmentNames'); $kind = "$($k.GetValueKind($Name))"
                if ($v -is [byte[]]) { $cur = 'hex:' + [BitConverter]::ToString($v) } elseif ($v -is [array]) { $cur = $v -join '|' } else { $cur = "$v" }
            }
        }
    } catch { }
    Add-BackupLine 'registry_before.tsv' "$(ConvertTo-NativeRegPath $Path)`t$Name`t$kind`t$cur"
    return $cur
}
function Set-RegValueSafe {
    param([string]$Path, [string]$Name, $Value, [string]$Type = 'DWord')
    $old = Backup-RegValue $Path $Name
    if (-not (Test-Path -LiteralPath $Path)) { New-Item -Path $Path -Force | Out-Null }
    New-ItemProperty -LiteralPath $Path -Name $Name -Value $Value -PropertyType $Type -Force | Out-Null
    Add-Change 'registry set' "$(ConvertTo-NativeRegPath $Path)`t$Name`t$old -> $Value"
}
function Remove-RegValueSafe {
    param([string]$Path, [string]$Name)
    $old = Backup-RegValue $Path $Name
    if ($old -eq '(absent)') { return }
    Remove-ItemProperty -LiteralPath $Path -Name $Name -Force
    Add-Change 'registry value removed' "$(ConvertTo-NativeRegPath $Path)`t$Name`t$old"
}

# ---------------------------------------------------------------- подписи, пути, командные строки
function Get-Signer {
    param([string]$Path)
    if (-not $Path) { return 'no path' }
    if ($script:SigCache.ContainsKey($Path)) { return $script:SigCache[$Path] }
    $r = 'FILE NOT FOUND'
    if (Test-Path -LiteralPath $Path -PathType Leaf) {
        try {
            $s = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
            $r = "$($s.Status)"
            if ($s.SignerCertificate) { $r += ' | ' + $s.SignerCertificate.GetNameInfo('SimpleName', $false) }
        } catch { $r = 'signature check failed' }
    }
    $script:SigCache[$Path] = $r
    return $r
}
function Test-MsSigned { param([string]$Signer) return ($Signer -match '^Valid \| Microsoft') }
function Test-ValidSigned { param([string]$Signer) return ($Signer -match '^Valid \|') }
function Get-SignerText {
    param([string]$Signer)
    if ($Signer -eq 'FILE NOT FOUND') { return 'файла нет' }
    if ($Signer -match '^Valid \| (.+)$') { return "подпись: $($matches[1])" }
    if ($Signer -match '^NotSigned') { return 'БЕЗ ПОДПИСИ' }
    return "подпись не в порядке ($Signer)"
}
function Set-EnvText {
    param([string]$Text, [string]$Var, [string]$Value)
    if (-not $Value) { return $Text }
    return ($Text -ireplace [regex]::Escape($Var), $Value.Replace('$', '$$'))
}
function Get-ExePath {
    param([string]$Cmd, [string]$UserProfile = '')
    if (-not $Cmd) { return $null }
    $c = $Cmd.Trim()
    if ($UserProfile) {
        $c = Set-EnvText $c '%USERPROFILE%' $UserProfile
        $c = Set-EnvText $c '%LOCALAPPDATA%' (Join-Path $UserProfile 'AppData\Local')
        $c = Set-EnvText $c '%APPDATA%' (Join-Path $UserProfile 'AppData\Roaming')
        $c = Set-EnvText $c '%TEMP%' (Join-Path $UserProfile 'AppData\Local\Temp')
        $c = Set-EnvText $c '%TMP%' (Join-Path $UserProfile 'AppData\Local\Temp')
    }
    $c = [Environment]::ExpandEnvironmentVariables($c)
    $c = $c -replace '^\\\?\?\\', ''
    if ($env:SystemRoot) {
        $c = $c -replace '^\\SystemRoot\\', ($env:SystemRoot + '\')
        $c = $c -replace '^(?i)system32\\', ($env:SystemRoot + '\System32\')
    }
    $p = $null
    if ($c -match '^"([^"]+)"') { $p = $matches[1] }
    elseif ($c -match '^(.+?\.(exe|dll|sys|cmd|bat|ps1|vbs|vbe|js|jse|wsf|com|scr|hta|msi|lnk))(\s|,|$)') { $p = $matches[1] }
    else { $p = ($c -split '\s+')[0] }
    if ($p -and ($p -notmatch '[\\/]')) {
        $g = Get-Command $p -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($g) { $p = $g.Source }
    }
    return $p
}
function Test-FullPath { param([string]$Path) return ($Path -match '^[A-Za-z]:\\') }
function Test-DriveMissing {
    param([string]$Path)
    if ($Path -match '^([A-Za-z]:\\)') { return (-not (Test-Path -LiteralPath $matches[1])) }
    return $false
}
function Test-UserWritablePath {
    param([string]$Path)
    return ($Path -match '(?i)(\\Users\\[^\\]+\\AppData\\|\\Users\\Public\\|\\ProgramData\\|\\Temp\\|\\Downloads\\|\\Desktop\\|\\\$Recycle\.Bin\\|^[A-Za-z]:\\[^\\]+\.(exe|dll|bat|cmd|vbs|js|ps1)$)')
}
function Get-CommandRisk {
    param([string]$Cmd)
    $c = "$Cmd"
    if ($c -match '(?i)(\s-e(c|nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{24,}|frombase64string|downloadstring|downloadfile|\biex\b|invoke-expression|invoke-webrequest|\bmshta(\.exe)?\b|bitsadmin(\.exe)?\s+/transfer|scrobj\.dll)') { return 'BAD' }
    if ($c -match '(?i)\b(powershell|pwsh|wscript|cscript|cmd|curl|certutil)(\.exe)?\b.*https?://') { return 'BAD' }
    if ($c -match '(?i)\b(wscript|cscript|powershell|pwsh)(\.exe)?\b') { return 'WARN' }
    if ($c -match '(?i)\.(vbs|vbe|js|jse|wsf|hta|bat|cmd|ps1)(["\s]|$)') { return 'WARN' }
    return ''
}
function Hide-Secrets {
    param([string]$Text, [int]$Max = 160)
    $t = "$Text" -replace '\s+', ' '
    $t = [regex]::Replace($t, '[A-Za-z0-9+/=_\-]{28,}', '[скрыто]')
    if ($t.Length -gt $Max) { $t = $t.Substring(0, $Max) + '...' }
    return $t
}
function Test-PrivateIp {
    param([string]$Ip)
    return ("$Ip" -match '(?i)^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.|127\.|0\.0\.0\.0$|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.|fe80:|fec0:|f[cd][0-9a-f]{2}:|::1$|::$)')
}
function Get-LnkTarget {
    param([string]$Path)
    try { $sh = New-Object -ComObject WScript.Shell; return "$($sh.CreateShortcut($Path).TargetPath)" } catch { return '' }
}
function Get-DirSizeMb {
    param([string]$Path)
    $sum = 0
    foreach ($f in @(Get-ChildItem -LiteralPath $Path -Recurse -File -Force -ErrorAction SilentlyContinue)) { $sum += $f.Length }
    return [math]::Round($sum / 1MB, 1)
}

# ---------------------------------------------------------------- кто работает за компьютером
function Get-UserProfilePath {
    param([string]$Sid)
    $pp = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$Sid" 'ProfileImagePath'
    if ($pp) { return [Environment]::ExpandEnvironmentVariables("$pp") }
    return ''
}
function Get-RunContext {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $ctx = @{ CurrentSid = $id.User.Value; CurrentName = $id.Name; MainSid = $id.User.Value; MainName = $id.Name; Differs = $false; MainHive = ''; MainProfile = $env:USERPROFILE }
    try {
        $u = (Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).UserName
        if ($u) {
            $sid = (New-Object Security.Principal.NTAccount($u)).Translate([Security.Principal.SecurityIdentifier]).Value
            if ($sid -and $sid -ne $ctx.CurrentSid -and (Test-Path -LiteralPath "Registry::HKEY_USERS\$sid")) { $ctx.MainSid = $sid; $ctx.MainName = "$u"; $ctx.Differs = $true }
        }
    } catch { }
    $ctx.MainHive = "Registry::HKEY_USERS\$($ctx.MainSid)"
    $pp = Get-UserProfilePath $ctx.MainSid
    if ($pp) { $ctx.MainProfile = $pp }
    return $ctx
}
function Get-UserHives {
    $list = @()
    foreach ($k in @(Get-ChildItem -LiteralPath 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue)) {
        $sid = $k.PSChildName
        if ($sid -notmatch '^S-1-(5-21|12-1)-[\d-]+$') { continue }
        $name = $sid
        try { $name = (New-Object Security.Principal.SecurityIdentifier($sid)).Translate([Security.Principal.NTAccount]).Value } catch { }
        $list += [pscustomobject]@{ Sid = $sid; Name = $name; Hive = "Registry::HKEY_USERS\$sid"; Profile = (Get-UserProfilePath $sid) }
    }
    return $list
}
function Get-AllProfiles {
    $list = @()
    foreach ($k in @(Get-ChildItem -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' -ErrorAction SilentlyContinue)) {
        if ($k.PSChildName -notmatch '^S-1-(5-21|12-1)-[\d-]+$') { continue }
        $p = Get-UserProfilePath $k.PSChildName
        if ($p -and (Test-Path -LiteralPath $p)) { $list += [pscustomobject]@{ Sid = $k.PSChildName; Profile = $p; Name = (Split-Path $p -Leaf) } }
    }
    return $list
}
function Get-Programs {
    $roots = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall')
    foreach ($h in $script:UserHives) { $roots += "$($h.Hive)\Software\Microsoft\Windows\CurrentVersion\Uninstall" }
    $list = @(); $seen = @{}
    foreach ($r in $roots) {
        foreach ($k in @(Get-ChildItem -LiteralPath $r -ErrorAction SilentlyContinue)) {
            $p = $null
            try { $p = Get-ItemProperty -LiteralPath $k.PSPath -ErrorAction Stop } catch { continue }
            if (-not $p.DisplayName) { continue }
            $key = "$($p.DisplayName)|$($p.DisplayVersion)"
            if ($seen.ContainsKey($key)) { continue }
            $seen[$key] = 1
            $list += [pscustomobject]@{ Name = "$($p.DisplayName)"; Version = "$($p.DisplayVersion)"; Publisher = "$($p.Publisher)"; Location = "$($p.InstallLocation)"; Hidden = ($p.SystemComponent -eq 1) }
        }
    }
    return $list
}
function Test-Installed { param([string]$Rx) return (@($script:Programs | Where-Object { $_.Name -match $Rx -or $_.Publisher -match $Rx }).Count -gt 0) }
function Get-InstalledNames { param([string]$Rx) return @($script:Programs | Where-Object { -not $_.Hidden -and $_.Name -match $Rx } | ForEach-Object { "$($_.Name) $($_.Version)".Trim() } | Sort-Object -Unique) }
