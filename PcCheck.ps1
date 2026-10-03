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

# ================================================================ 1. СИСТЕМА
function Invoke-SystemChecks {
    Start-Section 'Система'

    Invoke-Check 'версия Windows' {
        $cv = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
        $os = Get-CimInstance Win32_OperatingSystem
        $build = [int]$cv.CurrentBuild
        $ver = "$($os.Caption) $($cv.DisplayVersion), сборка $build.$($cv.UBR)"
        if ($build -lt 19045) {
            Add-Finding -Level BAD -Title "Очень старая Windows без обновлений безопасности: $ver" -Manual 'обновить Windows до актуальной версии (Параметры > Центр обновления) или переустановить'
        } elseif ($build -lt 22000) {
            Add-Finding -Level WARN -Title "Windows 10: поддержка закончилась 14.10.2025 ($ver)" -Detail @('обновления безопасности приходят только по платной/временной программе ESU') -Manual 'перейти на Windows 11, если железо позволяет, или подключить ESU'
        } elseif ($build -lt 26100) {
            Add-Finding -Level WARN -Title "Старая версия Windows 11, она больше не получает обновлений: $ver" -Manual 'Параметры > Центр обновления Windows > установить обновление до 24H2/25H2'
        } else {
            Add-Finding -Level OK -Title "Версия Windows актуальная: $ver"
        }
    }

    Invoke-Check 'когда ставились обновления' {
        $hf = @(Get-HotFix -ErrorAction SilentlyContinue | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn)
        if ($hf.Count -eq 0) { Add-Finding -Level INFO -Title 'Не удалось определить дату последнего обновления Windows'; return }
        $last = $hf[-1]
        $days = [int]((Get-Date) - $last.InstalledOn).TotalDays
        $t = "последнее обновление Windows: $($last.InstalledOn.ToString('dd.MM.yyyy')) ($($last.HotFixID)), $days дн. назад"
        if ($days -gt 100) { Add-Finding -Level BAD -Title "Windows давно не обновлялась - $t" -Manual 'Параметры > Центр обновления Windows > Проверить наличие обновлений; повторять до "Вы используете последнюю версию"' }
        elseif ($days -gt 45) { Add-Finding -Level WARN -Title "Обновления запаздывают - $t" -Manual 'Параметры > Центр обновления Windows > Проверить наличие обновлений' }
        else { Add-Finding -Level OK -Title "Обновления ставятся - $t" }
    }

    Invoke-Check 'неустановленные обновления (поиск идёт до нескольких минут)' {
        if ($script:SkipUpdates) { Add-Finding -Level INFO -Title 'Поиск неустановленных обновлений пропущен (-SkipUpdates)'; return }
        if (-not $script:UpdCache) {
            $session = New-Object -ComObject Microsoft.Update.Session
            $res = $session.CreateUpdateSearcher().Search('IsInstalled=0 and IsHidden=0')
            $list = @()
            foreach ($u in $res.Updates) { $list += [pscustomobject]@{ Title = "$($u.Title)"; Type = [int]$u.Type } }
            $script:UpdCache = @{ List = $list }
        }
        $all = @($script:UpdCache.List | Where-Object { $_.Title -notmatch '(?i)Security Intelligence Update|KB2267602|механизма обнаружения|аналитики безопасности' })
        $soft = @($all | Where-Object { $_.Type -ne 2 })
        $drv = @($all | Where-Object { $_.Type -eq 2 })
        if ($soft.Count -gt 0) {
            Add-Finding -Level WARN -Title "Windows Update: не установлено обновлений: $($soft.Count)" -Detail @($soft | ForEach-Object { $_.Title }) -Manual 'Параметры > Центр обновления Windows > Установить всё'
        } else { Add-Finding -Level OK -Title 'Windows Update: все обновления системы установлены' }
        if ($drv.Count -gt 0) { Add-Finding -Level INFO -Title "Windows Update предлагает драйверы: $($drv.Count)" -Detail @($drv | ForEach-Object { $_.Title }) }
    }

    Invoke-Check 'ожидание перезагрузки' {
        $pending = (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') -or (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending')
        if ($pending) { Add-Finding -Level WARN -Title 'Windows ждёт перезагрузки, чтобы доустановить обновления' -Manual 'перезагрузить компьютер' }
    }

    Invoke-Check 'здоровье дисков' {
        foreach ($d in @(Get-PhysicalDisk | Sort-Object DeviceId)) {
            $name = "$($d.FriendlyName) ($($d.MediaType), $([math]::Round($d.Size / 1GB)) ГБ)"
            $r = $null
            try { $r = $d | Get-StorageReliabilityCounter -ErrorAction Stop } catch { }
            $det = @()
            if ($r) {
                $parts = @()
                if ($null -ne $r.Wear) { $parts += "износ $($r.Wear)%" }
                if ($r.Temperature) { $parts += "температура $($r.Temperature) C" }
                if ($r.PowerOnHours) { $parts += "наработка $($r.PowerOnHours) ч" }
                if ($r.ReadErrorsUncorrected) { $parts += "неисправленных ошибок чтения: $($r.ReadErrorsUncorrected)" }
                if ($r.WriteErrorsUncorrected) { $parts += "неисправленных ошибок записи: $($r.WriteErrorsUncorrected)" }
                if ($parts.Count) { $det += ($parts -join ', ') }
            }
            if ("$($d.HealthStatus)" -ne 'Healthy') {
                Add-Finding -Level BAD -Title "Диск сообщает о проблемах: $name - $($d.HealthStatus)" -Detail $det -Manual 'СРАЗУ сделать копию важных файлов на другой диск, потом менять диск'
            } elseif ($r -and $null -ne $r.Wear -and $r.Wear -ge 90) {
                Add-Finding -Level BAD -Title "SSD почти выработал ресурс: $name" -Detail $det -Manual 'сделать копию данных и планировать замену диска'
            } elseif ($r -and $null -ne $r.Wear -and $r.Wear -ge 70) {
                Add-Finding -Level WARN -Title "SSD заметно изношен: $name" -Detail $det -Manual 'следить за износом, держать свежую резервную копию'
            } elseif ($r -and ($r.ReadErrorsUncorrected -gt 0 -or $r.WriteErrorsUncorrected -gt 0)) {
                Add-Finding -Level WARN -Title "У диска есть неисправленные ошибки: $name" -Detail $det -Manual 'проверить диск в CrystalDiskInfo, держать резервную копию'
            } else {
                Add-Finding -Level OK -Title "Диск здоров: $name" -Detail $det
            }
        }
    }

    Invoke-Check 'свободное место' {
        $sys = "$($env:SystemDrive)".TrimEnd(':')
        foreach ($v in @(Get-Volume | Where-Object { $_.DriveLetter -and "$($_.DriveType)" -eq 'Fixed' -and $_.Size -gt 0 } | Sort-Object DriveLetter)) {
            $freeGb = [math]::Round($v.SizeRemaining / 1GB, 1); $pct = [math]::Round(100 * $v.SizeRemaining / $v.Size)
            $t = "$($v.DriveLetter): свободно $freeGb ГБ из $([math]::Round($v.Size / 1GB)) ГБ ($pct%)"
            if ("$($v.DriveLetter)" -eq $sys -and $freeGb -lt 10) { Add-Finding -Level BAD -Title "На системном диске почти нет места - $t" -Manual 'Параметры > Система > Память > Рекомендации по очистке' }
            elseif ($pct -lt 10) { Add-Finding -Level WARN -Title "Мало места - $t" -Manual 'Параметры > Система > Память' }
            else { Add-Finding -Level OK -Title "Место на диске $t" }
            if ("$($v.HealthStatus)" -ne 'Healthy') { Add-Finding -Level BAD -Title "Файловая система диска $($v.DriveLetter): не в порядке ($($v.HealthStatus))" -Manual "в PowerShell от администратора: chkdsk $($v.DriveLetter): /scan" }
        }
    }

    Invoke-Check 'шифрование диска (BitLocker)' {
        $bl = $null
        try { $bl = @(Get-BitLockerVolume -ErrorAction Stop) } catch { }
        if ($null -eq $bl) { Add-Finding -Level INFO -Title 'BitLocker: состояние недоступно (в редакции Home его нет)'; return }
        foreach ($b in $bl) {
            if ("$($b.VolumeType)" -ne 'OperatingSystem' -and "$($b.ProtectionStatus)" -ne 'On') { continue }
            Add-Finding -Level INFO -Title "BitLocker $($b.MountPoint) $($b.VolumeStatus), защита: $($b.ProtectionStatus)"
        }
    }

    Invoke-Check 'активация' {
        $det = @()
        $kms = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform' 'KeyManagementServiceName'
        if ($kms) { $det += "Windows настроена на KMS-сервер: $kms" }
        $kmsO = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\OfficeSoftwareProtectionPlatform' 'KeyManagementServiceName'
        if ($kmsO) { $det += "Office настроен на KMS-сервер: $kmsO" }
        foreach ($p in @('C:\Windows\AAct_Tools', 'C:\Windows\KMSAutoS', 'C:\ProgramData\KMSAutoS', 'C:\ProgramData\KMSAuto', 'C:\Program Files\KMSpico', 'C:\Windows\SECOH-QAD.exe', 'C:\ProgramData\Online_KMS_Activation')) {
            if (Test-Path -LiteralPath $p) { $det += "след активатора: $p" }
        }
        foreach ($t in @(Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { "$($_.TaskName)$($_.TaskPath)" -match '(?i)AAct|KMSAuto|KMSpico|KMS_VL|Activation-Renewal|Online_KMS|SvcRestartTask_KMS' })) { $det += "задача активатора: $($t.TaskPath)$($t.TaskName)" }
        $lic = @(Get-CimInstance SoftwareLicensingProduct -Filter "PartialProductKey IS NOT NULL AND ApplicationID='55c92734-d682-4d71-983e-d6ec3f16059f'" -ErrorAction SilentlyContinue | Select-Object -First 1)
        $st = ''
        if ($lic.Count) {
            $names = @{ 0 = 'не активирована'; 1 = 'активирована'; 2 = 'льготный период'; 3 = 'льготный период'; 4 = 'льготный период'; 5 = 'требуется активация'; 6 = 'льготный период' }
            $st = $names[[int]$lic[0].LicenseStatus]
            $ch = "$($lic[0].Description)" -replace '^.*,\s*', ''
            $det = @("канал лицензии: $ch") + $det
            if ($lic[0].GracePeriodRemaining -gt 0) { $det += "до следующей переактивации: $([math]::Round($lic[0].GracePeriodRemaining / 1440)) дн." }
        }
        Add-Finding -Level INFO -Title "Активация Windows: $st" -Detail $det
    }
}

# ================================================================ 2. ЗАЩИТА
$script:FixRealtime = {
    param($f)
    Set-MpPreference -DisableRealtimeMonitoring $false
    Start-Sleep -Seconds 2
    if (-not (Get-MpComputerStatus).RealTimeProtectionEnabled) { throw 'защита не включилась (мешает политика или другой антивирус) - включи в "Безопасность Windows > Защита от вирусов и угроз"' }
    Add-Change 'defender' 'realtime protection enabled'
    return 'защита в реальном времени включена'
}
$script:FixSignatures = {
    param($f)
    Update-MpSignature
    Add-Change 'defender' 'signatures updated'
    return "базы обновлены: $((Get-MpComputerStatus).AntivirusSignatureLastUpdated)"
}
$script:FixPua = {
    param($f)
    Set-MpPreference -PUAProtection Enabled
    Add-Change 'defender' 'PUA protection enabled'
    return 'блокировка нежелательных программ включена'
}
$script:FixExclusion = {
    param($f)
    $v = $f.Data.Value
    switch ($f.Data.Kind) {
        'Path' { Remove-MpPreference -ExclusionPath $v }
        'Process' { Remove-MpPreference -ExclusionProcess $v }
        'Extension' { Remove-MpPreference -ExclusionExtension $v }
        'IpAddress' { Remove-MpPreference -ExclusionIpAddress $v }
    }
    Add-Change 'defender exclusion removed' "$($f.Data.Kind)`t$v"
    return 'исключение убрано'
}
$script:FixQuickScan = {
    param($f)
    Start-MpScan -ScanType QuickScan
    Add-Change 'defender' 'quick scan run'
    return 'быстрая проверка выполнена'
}
$script:FixThreats = {
    param($f)
    Remove-MpThreat
    Add-Change 'defender' 'Remove-MpThreat (default actions applied to active threats)'
    return 'к активным угрозам применены действия Defender; после этого запусти полную проверку'
}
$script:FixRegValueRemove = {
    param($f)
    Remove-RegValueSafe $f.Data.Path $f.Data.Name
    return 'значение удалено (старое сохранено в backup\registry_before.tsv)'
}
$script:FixRegValueSet = {
    param($f)
    $type = 'DWord'; if ($f.Data.Type) { $type = $f.Data.Type }
    Set-RegValueSafe $f.Data.Path $f.Data.Name $f.Data.Value $type
    return "установлено $($f.Data.Name) = $($f.Data.Value)"
}
$script:FixFirewall = {
    param($f)
    Set-NetFirewallProfile -Name $f.Data.Names -Enabled True
    Add-Change 'firewall enabled' ($f.Data.Names -join ',')
    return 'брандмауэр включён'
}
$script:FixSmb1 = {
    param($f)
    Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -Confirm:$false
    Add-Change 'smb1 disabled' 'Set-SmbServerConfiguration -EnableSMB1Protocol false'
    return 'SMB1 выключен'
}

function Invoke-ProtectionChecks {
    Start-Section 'Защита'
    $script:ThirdAv = @()

    Invoke-Check 'какой антивирус работает' {
        $av = @()
        try { $av = @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction Stop) } catch { }
        foreach ($a in $av) {
            $on = (([int]$a.productState) -band 0x1000) -ne 0
            $fresh = (([int]$a.productState) -band 0x10) -eq 0
            $isDef = ("$($a.displayName)" -match '(?i)Defender')
            if (-not $isDef -and $on) { $script:ThirdAv += "$($a.displayName)" }
            if (-not $isDef) {
                $st = 'выключен'; if ($on) { $st = 'включён' }
                $fr = 'базы устарели'; if ($fresh) { $fr = 'базы свежие' }
                $lvl = 'INFO'; $man = ''
                if ($on -and -not $fresh) { $lvl = 'WARN'; $man = 'обновить базы антивируса или удалить его - тогда включится встроенный Defender' }
                if ("$($a.displayName)" -match '(?i)Kaspersky|Касперск|Dr\.?Web|360 Total|Avast|AVG|McAfee|Norton') {
                    Add-Finding -Level WARN -Title "Сторонний антивирус: $($a.displayName) ($st, $fr)" -Detail @('такие антивирусы ставят свой корневой сертификат и вскрывают HTTPS; встроенного Defender хватает') -Manual 'решить, нужен ли он; удалять через Параметры > Приложения'
                } else {
                    Add-Finding -Level $lvl -Title "Сторонний антивирус: $($a.displayName) ($st, $fr)" -Manual $man
                }
            }
        }
    }

    Invoke-Check 'Microsoft Defender' {
        $mp = $null
        try { $mp = Get-MpComputerStatus -ErrorAction Stop } catch { }
        if ($null -eq $mp) {
            if ($script:ThirdAv.Count) { Add-Finding -Level INFO -Title "Defender не отвечает - работает $($script:ThirdAv -join ', ')" }
            else { Add-Finding -Level BAD -Title 'Defender не отвечает, и другого антивируса не видно' -Manual 'открыть "Безопасность Windows"; если не открывается - это признак заражения или поломки' }
            return
        }
        $passive = ("$($mp.AMRunningMode)" -match '(?i)Passive') -or ($script:ThirdAv.Count -gt 0)
        if ($passive) {
            Add-Finding -Level INFO -Title "Defender в пассивном режиме, основной антивирус: $($script:ThirdAv -join ', ')"
        } else {
            if (-not $mp.AntivirusEnabled) { Add-Finding -Level BAD -Title 'Defender выключен' -Manual 'Безопасность Windows > Защита от вирусов и угроз > включить' }
            elseif (-not $mp.RealTimeProtectionEnabled) { Add-Finding -Level BAD -Title 'Защита в реальном времени выключена' -Fix $script:FixRealtime -FixText 'включить защиту в реальном времени' }
            else { Add-Finding -Level OK -Title 'Defender работает, защита в реальном времени включена' }
            if (-not $mp.IsTamperProtected) { Add-Finding -Level WARN -Title 'Защита от подделки (Tamper Protection) выключена' -Manual 'Безопасность Windows > Защита от вирусов и угроз > Управление настройками > Защита от подделки' }
            else { Add-Finding -Level OK -Title 'Защита от подделки включена' }
        }
        $age = 9999
        if ($mp.AntivirusSignatureLastUpdated) { $age = [int]((Get-Date) - $mp.AntivirusSignatureLastUpdated).TotalDays }
        if (-not $passive) {
            if ($age -gt 30) { Add-Finding -Level BAD -Title "Антивирусные базы очень старые ($age дн.)" -Fix $script:FixSignatures -FixText 'обновить базы Defender' }
            elseif ($age -gt 7) { Add-Finding -Level WARN -Title "Антивирусные базы устарели ($age дн.)" -Fix $script:FixSignatures -FixText 'обновить базы Defender' }
            else { Add-Finding -Level OK -Title "Антивирусные базы свежие (обновлены $($mp.AntivirusSignatureLastUpdated.ToString('dd.MM.yyyy')))" }
            $qa = [double]$mp.QuickScanAge
            if ($qa -gt 100000) { Add-Finding -Level WARN -Title 'Быстрая проверка Defender не запускалась ни разу' -Fix $script:FixQuickScan -FixText 'запустить быструю проверку (несколько минут)' }
            elseif ($qa -gt 14) { Add-Finding -Level WARN -Title "Быстрая проверка была $qa дн. назад" -Fix $script:FixQuickScan -FixText 'запустить быструю проверку (несколько минут)' }
            $fa = [double]$mp.FullScanAge
            if ($fa -gt 100000) { Add-Finding -Level INFO -Title 'Полная проверка Defender не запускалась ни разу' -Detail @('запуск: Start-MpScan -ScanType FullScan (идёт час-два)') }
            else { Add-Finding -Level INFO -Title "Полная проверка Defender была $fa дн. назад" }
        }
    }

    Invoke-Check 'исключения и настройки Defender' {
        $pref = $null
        try { $pref = Get-MpPreference -ErrorAction Stop } catch { }
        if ($null -eq $pref) { return }
        $n = 0
        $kinds = @(@{ K = 'Path'; V = $pref.ExclusionPath; T = 'папка/файл' }, @{ K = 'Process'; V = $pref.ExclusionProcess; T = 'процесс' }, @{ K = 'Extension'; V = $pref.ExclusionExtension; T = 'расширение' }, @{ K = 'IpAddress'; V = $pref.ExclusionIpAddress; T = 'адрес' })
        foreach ($k in $kinds) {
            foreach ($v in @($k.V | Where-Object { $_ })) {
                $n++
                $dead = $false
                if ($k.K -eq 'Path' -and (Test-FullPath "$v") -and -not (Test-DriveMissing "$v") -and -not (Test-Path -LiteralPath "$v")) { $dead = $true }
                if ($dead) {
                    Add-Finding -Level WARN -Title "Исключение Defender на несуществующий путь: $v" -Fix $script:FixExclusion -FixText 'убрать исключение' -Data @{ Kind = $k.K; Value = "$v" }
                } else {
                    Add-Finding -Level BAD -Title "Исключение Defender ($($k.T)): $v" -Detail @('антивирус туда не смотрит - так прячутся взломщики программ и вирусы') -Fix $script:FixExclusion -FixText 'убрать исключение (файлы не трогаются; Defender может потом сам удалить то, что там найдёт)' -Data @{ Kind = $k.K; Value = "$v" }
                }
            }
        }
        if ($n -eq 0) { Add-Finding -Level OK -Title 'Исключений Defender нет' }
        if ($script:ThirdAv.Count -eq 0) {
            if ([int]$pref.PUAProtection -ne 1) { Add-Finding -Level WARN -Title 'Блокировка потенциально нежелательных программ выключена' -Fix $script:FixPua -FixText 'включить PUA-защиту' }
            else { Add-Finding -Level OK -Title 'Блокировка потенциально нежелательных программ включена' }
        }
    }

    Invoke-Check 'политики, отключающие Defender' {
        $root = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'
        $pairs = @(
            @{ P = $root; N = 'DisableAntiSpyware' }, @{ P = $root; N = 'DisableAntiVirus' },
            @{ P = "$root\Real-Time Protection"; N = 'DisableRealtimeMonitoring' }, @{ P = "$root\Real-Time Protection"; N = 'DisableBehaviorMonitoring' },
            @{ P = "$root\Real-Time Protection"; N = 'DisableOnAccessProtection' }, @{ P = "$root\Real-Time Protection"; N = 'DisableScanOnRealtimeEnable' },
            @{ P = "$root\Real-Time Protection"; N = 'DisableIOAVProtection' }, @{ P = "$root\Spynet"; N = 'DisableBlockAtFirstSeen' }
        )
        $bad = 0
        foreach ($p in $pairs) {
            $v = Get-RegValue $p.P $p.N
            if ($null -ne $v -and "$v" -eq '1') {
                $bad++
                Add-Finding -Level BAD -Title "Политика отключает Defender: $($p.N)" -Detail @((ConvertTo-NativeRegPath $p.P)) -Fix $script:FixRegValueRemove -FixText 'удалить это значение из реестра' -Data @{ Path = $p.P; Name = $p.N }
            }
        }
        if ($bad -eq 0) { Add-Finding -Level OK -Title 'Политик, отключающих Defender, нет' }
    }

    Invoke-Check 'найденные угрозы' {
        $active = @()
        try { $active = @(Get-MpThreat -ErrorAction Stop | Where-Object { $_.IsActive }) } catch { }
        if ($active.Count) {
            Add-Finding -Level BAD -Title "Defender видит активные угрозы: $($active.Count)" -Detail @($active | ForEach-Object { "$($_.ThreatName)" } | Sort-Object -Unique) -Fix $script:FixThreats -FixText 'применить действия Defender к активным угрозам (карантин/удаление)' -Manual 'потом полная проверка: Start-MpScan -ScanType FullScan'
        }
        $recent = @()
        try { $recent = @(Get-MpThreatDetection -ErrorAction Stop | Where-Object { $_.InitialDetectionTime -gt (Get-Date).AddDays(-60) }) } catch { }
        if ($recent.Count) {
            $names = @{}
            try { foreach ($t in @(Get-MpThreat -ErrorAction Stop)) { $names["$($t.ThreatID)"] = "$($t.ThreatName)" } } catch { }
            $det = @($recent | Sort-Object InitialDetectionTime -Descending | Select-Object -First 15 | ForEach-Object { "$($_.InitialDetectionTime.ToString('dd.MM.yyyy HH:mm')) $($names["$($_.ThreatID)"])" })
            Add-Finding -Level WARN -Title "За последние 60 дней Defender что-то ловил: $($recent.Count) срабатываний" -Detail $det -Manual 'Безопасность Windows > Журнал защиты - посмотреть, что это было и откуда'
        } elseif ($active.Count -eq 0) {
            Add-Finding -Level OK -Title 'Активных угроз нет, за 60 дней срабатываний не было'
        }
    }

    Invoke-Check 'брандмауэр' {
        $off = @(Get-NetFirewallProfile -ErrorAction Stop | Where-Object { "$($_.Enabled)" -ne 'True' })
        $fw3 = @()
        try { $fw3 = @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName FirewallProduct -ErrorAction Stop | Where-Object { (([int]$_.productState) -band 0x1000) -ne 0 }) } catch { }
        if ($off.Count -eq 0) { Add-Finding -Level OK -Title 'Брандмауэр Windows включён во всех профилях' }
        elseif ($fw3.Count) { Add-Finding -Level INFO -Title "Брандмауэр Windows выключен, работает сторонний: $(($fw3 | ForEach-Object { $_.displayName }) -join ', ')" }
        else { Add-Finding -Level BAD -Title "Брандмауэр Windows выключен: $(($off | ForEach-Object { $_.Name }) -join ', ')" -Fix $script:FixFirewall -FixText 'включить брандмауэр' -Data @{ Names = @($off | ForEach-Object { "$($_.Name)" }) } }
    }

    Invoke-Check 'контроль учётных записей (UAC)' {
        $pol = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
        $lua = Get-RegValue $pol 'EnableLUA'
        if ($null -ne $lua -and [int]$lua -eq 0) {
            Add-Finding -Level BAD -Title 'UAC выключен: любая программа получает права администратора без вопроса' -Fix $script:FixRegValueSet -FixText 'включить UAC (нужна перезагрузка)' -Data @{ Path = $pol; Name = 'EnableLUA'; Value = 1 } -NeedsReboot
        } else {
            $cpa = Get-RegValue $pol 'ConsentPromptBehaviorAdmin'
            if ($null -ne $cpa -and [int]$cpa -eq 0) { Add-Finding -Level WARN -Title 'UAC не спрашивает подтверждения (повышение прав молча)' -Fix $script:FixRegValueSet -FixText 'вернуть стандартный запрос UAC' -Data @{ Path = $pol; Name = 'ConsentPromptBehaviorAdmin'; Value = 5 } }
            else { Add-Finding -Level OK -Title 'UAC включён' }
        }
    }

    Invoke-Check 'SmartScreen' {
        $v1 = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' 'SmartScreenEnabled'
        $v2 = Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' 'EnableSmartScreen'
        if ("$v1" -eq 'Off' -or ($null -ne $v2 -and "$v2" -eq '0')) { Add-Finding -Level WARN -Title 'SmartScreen (проверка скачанных программ) выключен' -Manual 'Безопасность Windows > Управление приложениями и браузером > Защита на основе репутации > включить' }
        else { Add-Finding -Level OK -Title 'SmartScreen не выключен' }
    }

    Invoke-Check 'устаревший протокол SMB1' {
        $smb = $null
        try { $smb = Get-SmbServerConfiguration -ErrorAction Stop } catch { }
        if ($null -eq $smb) { return }
        if ($smb.EnableSMB1Protocol) { Add-Finding -Level WARN -Title 'Включён дырявый протокол SMB1 (через него распространялся WannaCry)' -Fix $script:FixSmb1 -FixText 'выключить SMB1 (старые сетевые диски/принтеры до 2008 года могут перестать открываться)' }
        else { Add-Finding -Level OK -Title 'SMB1 выключен' }
    }
}
