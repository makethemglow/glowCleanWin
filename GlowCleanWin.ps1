<#
GlowCleanWin.ps1 - проверка и лечение ПК с Windows 10/11.

ЧТО ДЕЛАЕТ
  1. Только читает: система, защита, сертификаты (в первую очередь посторонние корневые),
     браузеры, сеть, автозапуск, учётные записи, программы, реклама и слежка Windows.
  2. Показывает итог: зелёное - хорошо, красное - плохо, жёлтое - посмотри сам, серое - справка.
  3. Один раз спрашивает, что исправить:
        YES    - всё красное (кроме пунктов "только по номеру")
        ALL    - красное и жёлтое (кроме пунктов "только по номеру")
        1 4 7  - только эти номера (можно 3-6, можно вместе: YES 12 15)
        Enter  - ничего не менять
     "Только по номеру" помечено то, где скрипт не может сам отличить вредное от твоего собственного
     (твои сценарии в автозапуске, незнакомые корневые сертификаты, сторонние приложения и т.п.).
     Перед правками создаётся точка восстановления; старые значения, удалённые сертификаты (.cer)
     и файлы складываются в папку backup рядом с отчётом, всё записывается в журнал.

КАК ЗАПУСКАТЬ
  Двойной щелчок по GlowCleanWin.cmd (права администратора скрипт запросит сам), либо:
     powershell -NoProfile -ExecutionPolicy Bypass -File "C:\Tools\GlowCleanWin.ps1"
  Параметры:
     -ReportOnly   только отчёт, без вопроса об исправлении
     -SkipUpdates  не искать неустановленные обновления (это самая долгая часть)
     -Demo         показать, как выглядит вывод, ничего не проверяя и не меняя

ГДЕ РЕЗУЛЬТАТ
  Рядом со скриптом: GlowCleanWin_Reports\<компьютер>_<дата>\report.txt и backup\
  Журнал изменений:   GlowCleanWin_Reports\<компьютер>_changes.tsv
  Свои "это нормально": GlowCleanWin_Reports\<компьютер>_ignore.txt - по одной строке, кусок заголовка пункта.

В отчёт не попадают: командные строки целиком (в них бывают ключи), пароли, содержимое файлов.

SPDX-License-Identifier: GPL-3.0-only
Copyright (C) 2026 Glowlex

This program is free software: you can redistribute it and/or modify it under the terms of the
GNU General Public License as published by the Free Software Foundation, version 3.
This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
See the GNU General Public License for more details: https://www.gnu.org/licenses/gpl-3.0.html
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

function Join-P {
    # как Join-Path, но не падает, если диска из пути сейчас нет
    param([string]$Parent, [string]$Child)
    if ($script:IsWin -or $Parent -match '\\') { return ($Parent.TrimEnd('\') + '\' + $Child.TrimStart('\')) }
    return [IO.Path]::Combine($Parent, $Child)
}
function Test-PathSafe {
    # Test-Path, который не падает на кривых путях (кавычки, запрещённые символы, отсутствующий диск)
    param([string]$Path, [string]$PathType = 'Any')
    if (-not $Path) { return $false }
    try { return [bool](Test-Path -LiteralPath $Path -PathType $PathType -ErrorAction Stop) } catch { return $false }
}
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
        $exe = Join-P $env:windir 'System32\WindowsPowerShell\v1.0\powershell.exe'
        if ($is32 -and -not $needElev) { $exe = Join-P $env:windir 'sysnative\WindowsPowerShell\v1.0\powershell.exe' }
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

if ($script:IsWin -and -not $LoadOnly -and -not $Demo) {
    $why = ''
    if (-not (Test-Admin)) { $why = 'нет прав администратора' }
    elseif ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) { $why = 'запущена 32-битная версия PowerShell' }
    if ($why) {
        Write-Host "Проверка не запущена: $why. Запусти GlowCleanWin.cmd двойным щелчком из Проводника." -ForegroundColor Red
        if (-not $NoPause) { [void](Read-Host 'Нажми Enter') }
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
$script:ProcList = $null
$script:Ctx = $null
$script:HostsPath = ''
if ($script:IsWin) { $script:HostsPath = Join-P $env:SystemRoot 'System32\drivers\etc\hosts' }

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
    if (-not (Test-PathSafe $script:BackupDir)) { New-Item -ItemType Directory -Path $script:BackupDir -Force | Out-Null }
    return $script:BackupDir
}
function Add-BackupLine {
    param([string]$File, [string]$Line)
    [IO.File]::AppendAllText((Join-P (Get-BackupDir) $File), $Line + "`r`n", (New-Object System.Text.UTF8Encoding($false)))
}
function Add-Change {
    param([string]$Type, [string]$What)
    $line = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`t$Type`t$What"
    if ($script:DemoMode) { return }
    try { [IO.File]::AppendAllText($script:JournalFile, $line + "`r`n", (New-Object System.Text.UTF8Encoding($false))) } catch { }
    # в отчёт - только что и где; сами значения (в них бывают ключи) остаются в журнале и в backup
    $echo = (@($What -split "`t") | Select-Object -First 2) -join ' | '
    if ($echo.Length -gt 200) { $echo = $echo.Substring(0, 200) + '...' }
    Out-ReportOnly "       журнал: $Type | $echo"
}
function Backup-File {
    param([string]$Path)
    $dir = Join-P (Get-BackupDir) 'files'
    if (-not (Test-PathSafe $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $n = @(Get-ChildItem -LiteralPath $dir -Force).Count + 1
    $dst = Join-P $dir ('{0:d3}_{1}' -f $n, (Split-Path $Path -Leaf))
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
    $ErrorActionPreference = 'Continue'
    $dst = Join-P (Get-BackupDir) $FileName
    try { & reg.exe export (ConvertTo-NativeRegPath $Path) $dst /y 2>$null | Out-Null } catch { }
    return $dst
}
function Get-RegValue {
    param([string]$Path, [string]$Name)
    try {
        if (-not (Test-PathSafe $Path)) { return $null }
        $k = Get-Item -LiteralPath $Path -ErrorAction Stop
        if ($k.GetValueNames() -contains $Name) { return $k.GetValue($Name, $null, 'DoNotExpandEnvironmentNames') }
    } catch { }
    return $null
}
function Backup-RegValue {
    param([string]$Path, [string]$Name)
    $cur = '(absent)'; $kind = ''
    try {
        if (Test-PathSafe $Path) {
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
function Open-RegRoot {
    # возвращает @(корневой раздел .NET, путь под ним); работает мимо провайдера PowerShell, без подстановочных знаков
    param([string]$Path)
    $native = ConvertTo-NativeRegPath $Path
    $i = $native.IndexOf('\')
    if ($i -lt 1) { throw "не разобрал путь реестра: $Path" }
    $hive = $native.Substring(0, $i); $sub = $native.Substring($i + 1)
    $root = $null
    switch ($hive) {
        'HKEY_LOCAL_MACHINE' { $root = [Microsoft.Win32.Registry]::LocalMachine }
        'HKEY_USERS' { $root = [Microsoft.Win32.Registry]::Users }
        'HKEY_CURRENT_USER' { $root = [Microsoft.Win32.Registry]::CurrentUser }
        default { throw "неожиданный куст реестра: $hive" }
    }
    return @($root, $sub)
}
function New-RegKeyRaw {
    # CreateSubKey открывает существующий раздел, ничего в нём не стирая (в отличие от New-Item -Force)
    param([string]$Path)
    $r = Open-RegRoot $Path
    $k = $r[0].CreateSubKey($r[1]); $k.Close()
}
function Remove-RegValueRaw {
    param([string]$Path, [string]$Name)
    $r = Open-RegRoot $Path
    $k = $r[0].OpenSubKey($r[1], $true)
    if ($null -eq $k) { return }
    try { $k.DeleteValue($Name, $false) } finally { $k.Close() }
}
function Set-RegValueSafe {
    param([string]$Path, [string]$Name, $Value, [string]$Type = 'DWord')
    $old = Backup-RegValue $Path $Name
    New-RegKeyRaw $Path
    New-ItemProperty -LiteralPath $Path -Name $Name -Value $Value -PropertyType $Type -Force | Out-Null
    Add-Change 'registry set' "$(ConvertTo-NativeRegPath $Path)`t$Name`t$old -> $Value"
}
function Remove-RegValueSafe {
    param([string]$Path, [string]$Name)
    $old = Backup-RegValue $Path $Name
    if ($old -eq '(absent)') { return }
    Remove-RegValueRaw $Path $Name
    Add-Change 'registry value removed' "$(ConvertTo-NativeRegPath $Path)`t$Name`t$old"
}

# ---------------------------------------------------------------- подписи, пути, командные строки
function Get-Signer {
    param([string]$Path)
    if (-not $Path) { return 'no path' }
    if ($script:SigCache.ContainsKey($Path)) { return $script:SigCache[$Path] }
    $r = 'FILE NOT FOUND'
    if (Test-PathSafe $Path -PathType Leaf) {
        if ($Path -match '(?i)\.(bat|cmd)$') { $r = 'NO FORMAT' }   # пакетный файл подписать нельзя: спрашивать о подписи незачем
        else {
            try {
                $s = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
                $r = "$($s.Status)"
                if ($r -eq 'NotSupportedFileFormat') { $r = 'NO FORMAT' }
                elseif ($s.SignerCertificate) {
                    $r += ' | ' + $s.SignerCertificate.GetNameInfo('SimpleName', $false)
                    if ($r -notmatch '^(Valid|HashMismatch) \|') {
                        # третья часть - почему подпись не подтвердилась (у изменённого файла причина уже названа)
                        $na = $s.SignerCertificate.NotAfter
                        if ($na -is [datetime] -and $na -lt (Get-Date) -and -not $s.TimeStamperCertificate) { $r += ' | expired' }
                        elseif ($s.StatusMessage) {
                            $why = ("$($s.StatusMessage)" -replace '\s+', ' ').Trim()
                            if ($why.Length -gt 110) { $why = $why.Substring(0, 110) + '...' }
                            $r += ' | ' + $why
                        }
                    }
                }
            } catch { $r = 'signature check failed' }
        }
    }
    $script:SigCache[$Path] = $r
    return $r
}
function Test-MsSigned { param([string]$Signer) return ($Signer -match '^Valid \| Microsoft') }
function Test-ValidSigned { param([string]$Signer) return ($Signer -match '^Valid \|') }
function Get-SignerText {
    param([string]$Signer)
    if ($Signer -eq 'FILE NOT FOUND') { return 'файла нет' }
    if ($Signer -eq 'NO FORMAT') { return 'у файлов этого типа подписи не бывает' }
    if ($Signer -match '^Valid \| (.+)$') { return "подпись: $($matches[1])" }
    if ($Signer -match '^NotSigned') { return 'БЕЗ ПОДПИСИ' }
    $parts = @($Signer -split ' \| ', 3)
    if ($parts.Count -ge 2) {
        if ($parts[0] -eq 'HashMismatch') { return "ФАЙЛ ИЗМЕНЁН ПОСЛЕ ПОДПИСИ (подписывал: $($parts[1]))" }
        $why = ''
        if ($parts.Count -ge 3) { $why = " - $($parts[2])"; if ($parts[2] -eq 'expired') { $why = ' - сертификат истёк, а метки времени в подписи нет' } }
        return "подпись не подтверждена: $($parts[1])$why"
    }
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
        $c = Set-EnvText $c '%LOCALAPPDATA%' (Join-P $UserProfile 'AppData\Local')
        $c = Set-EnvText $c '%APPDATA%' (Join-P $UserProfile 'AppData\Roaming')
        $c = Set-EnvText $c '%TEMP%' (Join-P $UserProfile 'AppData\Local\Temp')
        $c = Set-EnvText $c '%TMP%' (Join-P $UserProfile 'AppData\Local\Temp')
    }
    $c = [Environment]::ExpandEnvironmentVariables($c)
    $c = $c -replace '^\\\?\?\\', ''
    if ($env:SystemRoot) {
        $c = $c -replace '^\\SystemRoot\\', ($env:SystemRoot + '\')
        $c = $c -replace '^(?i)system32\\', ($env:SystemRoot + '\System32\')
    }
    $p = $null
    if ($c -match '^"([^"]+)"') {
        $p = $matches[1]
        if (-not (Test-PathSafe $p 'Leaf') -and (Test-PathSafe "$p.exe" 'Leaf')) { $p = "$p.exe" }
    } else {
        # путь без кавычек: как сама Windows, пробуем всё более длинные куски до пробела и берём первый существующий файл
        $parts = @($c -split ' '); $acc = ''
        foreach ($part in $parts) {
            $acc = ("$acc $part").TrimStart()
            if (-not $part -or $acc -notmatch '[\\/]') { continue }
            if (Test-PathSafe $acc 'Leaf') { $p = $acc; break }
            if (Test-PathSafe "$acc.exe" 'Leaf') { $p = "$acc.exe"; break }
        }
        if (-not $p) {
            if ($c -match '^(.+?\.(exe|dll|sys|cmd|bat|ps1|vbs|vbe|js|jse|wsf|com|scr|hta|msi|lnk))(\s|,|$)') { $p = $matches[1] } else { $p = $parts[0] }
        }
    }
    if ($p -and ($p -notmatch '[\\/]')) {
        $g = Get-Command $p -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($g) { $p = $g.Source }
    }
    return $p
}
function Test-FullPath { param([string]$Path) return ($Path -match '^[A-Za-z]:\\') }
function Test-DriveMissing {
    param([string]$Path)
    if ($Path -match '^([A-Za-z]:\\)') { return (-not (Test-PathSafe $matches[1])) }
    return $false
}
function Test-DeadTarget {
    # "файла нет" считаем доказанным, только когда ошибиться негде
    param([string]$Raw, [string]$Exe, [string]$Signer)
    if ($Signer -ne 'FILE NOT FOUND') { return $false }
    if (-not (Test-FullPath $Exe)) { return $false }
    if (Test-DriveMissing $Exe) { return $false }
    if ("$Raw" -match '%') { return $false }                       # переменная могла раскрыться не для того пользователя
    if ($Exe -match '(?i)\\WindowsApps\\') { return $false }       # приложения из Store администратору не видны
    $dir = ''
    try { $dir = [IO.Path]::GetDirectoryName($Exe) } catch { return $false }
    if ($dir -and (Test-PathSafe $dir)) {
        # папка есть, а заглянуть в неё нельзя - значит, про файл мы ничего не знаем
        try { $null = Get-ChildItem -LiteralPath $dir -Force -ErrorAction Stop | Select-Object -First 1 } catch { return $false }
    }
    return $true
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
    $t = [regex]::Replace($t, '(?i)(password|passwd|pass|pwd|token|secret|key)([ =:]+)(\S+)', '$1$2[скрыто]')
    $t = [regex]::Replace($t, '(://)[^/\s:@]+:[^/\s@]+@', '$1[скрыто]@')
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
            if ($sid -and $sid -ne $ctx.CurrentSid -and (Test-PathSafe "Registry::HKEY_USERS\$sid")) { $ctx.MainSid = $sid; $ctx.MainName = "$u"; $ctx.Differs = $true }
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
        if ($p -and (Test-PathSafe $p)) { $list += [pscustomobject]@{ Sid = $k.PSChildName; Profile = $p; Name = (Split-Path $p -Leaf) } }
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
            $hidden = ($p.SystemComponent -eq 1)
            if ($seen.ContainsKey($key)) {
                # одна программа бывает записана дважды - установщик и его скрытый внутренний пакет: видимая запись главнее
                if (-not $hidden) { $seen[$key].Hidden = $false }
                if (-not $seen[$key].Location -and $p.InstallLocation) { $seen[$key].Location = "$($p.InstallLocation)" }
                continue
            }
            $o = [pscustomobject]@{ Name = "$($p.DisplayName)"; Version = "$($p.DisplayVersion)"; Publisher = "$($p.Publisher)"; Location = "$($p.InstallLocation)"; Hidden = $hidden }
            $seen[$key] = $o
            $list += $o
        }
    }
    return $list
}
function Test-Installed { param([string]$Rx) return (@($script:Programs | Where-Object { $_.Name -match $Rx -or $_.Publisher -match $Rx }).Count -gt 0) }
function Get-InstalledNames { param([string]$Rx) return @($script:Programs | Where-Object { -not $_.Hidden -and $_.Name -match $Rx } | ForEach-Object { "$($_.Name) $($_.Version)".Trim() } | Sort-Object -Unique) }
function Get-OwnerProgram {
    # какой установленной программе принадлежит файл: по папке установки, иначе по имени папки в Program Files.
    # Смотрим только туда, куда без прав администратора не записать. Это подсказка для отчёта, а не проверка; '' - не нашлось
    param([string]$Path)
    $p = "$Path"
    if (-not (Test-FullPath $p) -or (Test-UserWritablePath $p)) { return '' }
    if ($p -match '(?i)^[A-Z]:\\Program Files\\WindowsApps\\([^\\_]+)_') { return "приложение из Microsoft Store $($matches[1])" }
    foreach ($a in $script:Programs) {
        $loc = "$($a.Location)".Trim('"').TrimEnd('\')
        if ($loc.Length -lt 8 -or $loc -match '(?i)^[A-Z]:\\(Program Files( \(x86\))?|Windows|ProgramData|Users)$') { continue }
        if ($p.StartsWith("$loc\", [StringComparison]::OrdinalIgnoreCase)) { return "программа $("$($a.Name) $($a.Version)".Trim())" }
    }
    if ($p -match '(?i)^[A-Z]:\\Program Files( \(x86\))?\\([^\\]+)\\') {
        $dir = $matches[2]
        if ($dir.Length -ge 3 -and $dir -ine 'Common Files') {
            foreach ($a in $script:Programs) {
                if ("$($a.Name)".StartsWith($dir, [StringComparison]::OrdinalIgnoreCase) -or "$($a.Publisher)" -ieq $dir) { return "программа $("$($a.Name) $($a.Version)".Trim())" }
            }
        }
    }
    return ''
}
function Get-ProcList {
    # запущенные программы с путём к своему файлу; список собирается один раз за проверку
    if ($null -eq $script:ProcList) {
        $list = @()
        foreach ($p in @(Get-Process -ErrorAction SilentlyContinue)) {
            $pp = ''
            try { $pp = "$($p.Path)" } catch { }
            if ($pp) { $list += [pscustomobject]@{ Name = "$($p.ProcessName)"; Id = [int]$p.Id; Path = $pp } }
        }
        $script:ProcList = $list
    }
    return $script:ProcList
}
function Get-RunningUnder {
    # имена запущенных программ, чьи файлы лежат в этой папке (или это сам файл)
    param([string]$Path)
    $d = "$Path".TrimEnd('\')
    if (-not (Test-FullPath $d) -or $d -match '[*?%]') { return @() }
    return @(Get-ProcList | Where-Object { $_.Path -ieq $d -or $_.Path.StartsWith("$d\", [StringComparison]::OrdinalIgnoreCase) } | ForEach-Object { $_.Name } | Sort-Object -Unique)
}

# ================================================================ 1. СИСТЕМА
function Invoke-SystemChecks {
    Start-Section 'Система'

    Invoke-Check 'версия Windows' {
        $cv = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
        $os = Get-CimInstance Win32_OperatingSystem
        $build = [int]$cv.CurrentBuild
        $ver = "$($os.Caption) $($cv.DisplayVersion), сборка $build.$($cv.UBR)"
        if ($build -lt 17763) {
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
        # дата установки приходит без времени: считаем целые календарные дни, сегодня - это 0
        $days = [int][math]::Floor(((Get-Date).Date - $last.InstalledOn.Date).TotalDays)
        $ago = "$days дн. назад"; if ($days -le 0) { $ago = 'сегодня' }
        $t = "последнее обновление Windows: $($last.InstalledOn.ToString('dd.MM.yyyy')) ($($last.HotFixID)), $ago"
        if ($days -gt 100) { Add-Finding -Level BAD -Title "Windows давно не обновлялась - $t" -Manual 'Параметры > Центр обновления Windows > Проверить наличие обновлений; повторять до "Вы используете последнюю версию"' }
        elseif ($days -gt 45) { Add-Finding -Level WARN -Title "Обновления запаздывают - $t" -Manual 'Параметры > Центр обновления Windows > Проверить наличие обновлений' }
        else { Add-Finding -Level OK -Title "Обновления ставятся - $t" }
    }

    Invoke-Check 'неустановленные обновления (поиск идёт до нескольких минут)' {
        if ($script:SkipUpdates) { Add-Finding -Level INFO -Title 'Поиск неустановленных обновлений пропущен (-SkipUpdates)'; return }
        if (-not $script:UpdCache) {
            try {
                $session = New-Object -ComObject Microsoft.Update.Session
                $res = $session.CreateUpdateSearcher().Search('IsInstalled=0 and IsHidden=0')
                $list = @()
                foreach ($u in $res.Updates) { $list += [pscustomobject]@{ Title = "$($u.Title)"; Type = [int]$u.Type } }
                $script:UpdCache = @{ List = $list }
            } catch {
                Add-Finding -Level INFO -Title 'Не удалось спросить Windows Update о неустановленных обновлениях (нет интернета или служба занята)' -Detail @("$($_.Exception.Message)")
                return
            }
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
                # у многих дисков Windows отдаёт здесь 0 вместо настоящего износа - ноль не показываем
                if ($r.Wear -gt 0) { $parts += "износ $($r.Wear)%" }
                elseif ("$($d.MediaType)" -eq 'SSD') { $parts += 'износ Windows не сообщает (смотреть в CrystalDiskInfo)' }
                if ($r.Temperature) { $parts += "температура $($r.Temperature) C" }
                if ($r.PowerOnHours) { $parts += "наработка $($r.PowerOnHours) ч" }
                if ($r.ReadErrorsUncorrected) { $parts += "неисправленных ошибок чтения: $($r.ReadErrorsUncorrected)" }
                if ($r.WriteErrorsUncorrected) { $parts += "неисправленных ошибок записи: $($r.WriteErrorsUncorrected)" }
                if ($parts.Count) { $det += ($parts -join ', ') }
            }
            if ("$($d.HealthStatus)" -match '(?i)Unhealthy|Warning') {
                Add-Finding -Level BAD -Title "Диск сообщает о проблемах: $name - $($d.HealthStatus)" -Detail $det -Manual 'СРАЗУ сделать копию важных файлов на другой диск, потом менять диск'
            } elseif ("$($d.HealthStatus)" -ne 'Healthy') {
                Add-Finding -Level INFO -Title "Диск не сообщает о своём здоровье: $name - $($d.HealthStatus)" -Detail $det
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
            if (Test-PathSafe $p) { $det += "след активатора: $p" }
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
$script:FixGhostAv = {
    param($f)
    foreach ($i in @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | Where-Object { "$($_.instanceGuid)" -eq $f.Data.Guid })) { Remove-CimInstance -InputObject $i }
    $left = @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | Where-Object { "$($_.instanceGuid)" -eq $f.Data.Guid })
    if ($left.Count) { throw 'запись не удалилась (защищена системой)' }
    Add-Change 'security center entry removed' "$($f.Data.Name)`t$($f.Data.Guid)"
    return 'запись удалена'
}
$script:FixSignatures = {
    param($f)
    Update-MpSignature
    Add-Change 'defender' 'signatures updated'
    return "базы обновлены: $((Get-MpComputerStatus).AntivirusSignatureLastUpdated.ToString('dd.MM.yyyy HH:mm'))"
}
$script:FixPua = {
    param($f)
    Set-MpPreference -PUAProtection Enabled
    Add-Change 'defender' 'PUA protection enabled'
    return 'блокировка нежелательных программ включена'
}
$script:FixExclusion = {
    param($f)
    $vals = @($f.Data.Values | Where-Object { $_ })
    foreach ($v in $vals) {
        Add-BackupLine 'defender_exclusions_removed.tsv' "$($f.Data.Kind)`t$v"
        switch ($f.Data.Kind) {
            'Path' { Remove-MpPreference -ExclusionPath $v }
            'Process' { Remove-MpPreference -ExclusionProcess $v }
            'Extension' { Remove-MpPreference -ExclusionExtension $v }
            'IpAddress' { Remove-MpPreference -ExclusionIpAddress $v }
        }
        Add-Change 'defender exclusion removed' "$($f.Data.Kind)`t$v"
    }
    if ($vals.Count -gt 1) { return "исключений убрано: $($vals.Count)" }
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

# папки, которые в исключения антивируса предлагают добавить сами инструменты разработки (так быстрее идёт сборка)
$script:DevExclusionRx = '(?i)(\\\.(gradle|android|m2|cargo|rustup|nuget|pub-cache|konan)|\\AppData\\Local\\Android\\Sdk|\\AppData\\Local\\Google\\AndroidStudio[^\\]*|\\AppData\\(Local|Roaming)\\JetBrains\\[^\\]+|\\node_modules)(\\|$)'
function Test-DevExclusion { param([string]$Path) return ("$Path" -match $script:DevExclusionRx) }
function Get-ExclusionGroups {
    # исключение внутри уже исключённой папки ничего не добавляет: такие пути идут одним пунктом вместе с этой папкой
    param([string[]]$Paths)
    $all = @($Paths | Where-Object { $_ } | ForEach-Object { [pscustomobject]@{ Raw = "$_"; Norm = "$_".TrimEnd('\') } })
    $groups = @()
    foreach ($p in $all) {
        $inside = $false
        foreach ($q in $all) {
            if ($q.Norm.Length -lt $p.Norm.Length -and $q.Norm -notmatch '[*?%]' -and $p.Norm.StartsWith("$($q.Norm)\", [StringComparison]::OrdinalIgnoreCase)) { $inside = $true; break }
        }
        if ($inside) { continue }
        $inner = @()
        if ($p.Norm -notmatch '[*?%]') { $inner = @($all | Where-Object { $_.Norm.Length -gt $p.Norm.Length -and $_.Norm.StartsWith("$($p.Norm)\", [StringComparison]::OrdinalIgnoreCase) } | ForEach-Object { $_.Raw }) }
        $groups += [pscustomobject]@{ Top = $p.Raw; Inner = $inner }
    }
    return $groups
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
            if (-not $isDef) {
                # запись в Центре безопасности переживает удаление программы: проверяем, что её файл ещё существует
                $avExe = Get-ExePath "$($a.pathToSignedProductExe)"
                if ($avExe -and (Test-FullPath $avExe) -and -not (Test-DriveMissing $avExe) -and -not (Test-PathSafe $avExe 'Leaf')) {
                    Add-Finding -Level WARN -Title "В Центре безопасности Windows числится антивирус, которого уже нет: $($a.displayName)" -Detail @("файл: $avExe (файла нет)", 'запись осталась от удалённой программы; из-за неё Windows может показывать, что компьютер защищает она') `
                        -Fix $script:FixGhostAv -FixText 'удалить эту запись из Центра безопасности' -Data @{ Guid = "$($a.instanceGuid)"; Name = "$($a.displayName)" } -Explicit
                    continue
                }
            }
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
        # о своём режиме Defender знает сам; список Центра безопасности бывает устаревшим
        $mode = "$($mp.AMRunningMode)"
        $passive = ($mode -match '(?i)Passive') -or ($mode -notmatch '(?i)Normal|EDR' -and $script:ThirdAv.Count -gt 0)
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
            elseif ($fa -lt 1) { Add-Finding -Level INFO -Title 'Полная проверка Defender была сегодня' }
            else { Add-Finding -Level INFO -Title "Полная проверка Defender была $fa дн. назад" }
        }
    }

    Invoke-Check 'исключения и настройки Defender' {
        $pref = $null
        try { $pref = Get-MpPreference -ErrorAction Stop } catch { }
        if ($null -eq $pref) { return }
        $n = 0
        $fixText = 'убрать исключение (файлы не трогаются; Defender может потом сам удалить то, что там найдёт; вернуть: Add-MpPreference, список в backup)'
        foreach ($g in @(Get-ExclusionGroups @($pref.ExclusionPath))) {
            $n++
            $v = "$($g.Top)"
            $data = @{ Kind = 'Path'; Values = (@($g.Top) + @($g.Inner)) }
            $more = @()
            if ($g.Inner.Count) { $more += "внутри отдельно исключены (уберутся вместе с ней): $($g.Inner -join '; ')" }
            if ($v -notmatch '[*?%]' -and (Test-FullPath $v) -and -not (Test-DriveMissing $v) -and -not (Test-PathSafe $v)) {
                Add-Finding -Level WARN -Title "Исключение Defender на несуществующий путь: $v" -Detail $more -Fix $script:FixExclusion -FixText 'убрать исключение' -Data $data
                continue
            }
            $run = @(Get-RunningUnder $v)
            if ($run.Count) { $more += "сейчас оттуда запущено: $($run -join ', ') - без исключения Defender может остановить эти программы" }
            if (Test-DevExclusion $v) {
                Add-Finding -Level WARN -Title "Исключение Defender для инструментов разработки: $v" -Detail (@('такие папки в исключения предлагают добавить сами среды разработки, чтобы сборка шла быстрее; антивирус туда не смотрит') + $more) `
                    -Fix $script:FixExclusion -FixText 'убрать исключение (сборка проектов может замедлиться; вернуть: Add-MpPreference, список в backup)' -Data $data -Explicit -Manual 'если разработкой на этом компьютере не занимаются - убрать по номеру'
            } else {
                Add-Finding -Level BAD -Title "Исключение Defender (папка/файл): $v" -Detail (@('антивирус туда не смотрит - так прячутся взломщики программ и вирусы') + $more) -Fix $script:FixExclusion -FixText $fixText -Data $data
            }
        }
        $kinds = @(@{ K = 'Process'; V = $pref.ExclusionProcess; T = 'процесс' }, @{ K = 'Extension'; V = $pref.ExclusionExtension; T = 'расширение' }, @{ K = 'IpAddress'; V = $pref.ExclusionIpAddress; T = 'адрес' })
        foreach ($k in $kinds) {
            foreach ($v in @($k.V | Where-Object { $_ })) {
                $n++
                Add-Finding -Level BAD -Title "Исключение Defender ($($k.T)): $v" -Detail @('антивирус туда не смотрит - так прячутся взломщики программ и вирусы') -Fix $script:FixExclusion -FixText $fixText -Data @{ Kind = $k.K; Values = @("$v") }
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
            Add-Finding -Level WARN -Title "За последние 60 дней Defender что-то ловил, срабатываний: $($recent.Count)" -Detail $det -Manual 'Безопасность Windows > Журнал защиты - посмотреть, что это было и откуда'
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

# ================================================================ 3. СЕРТИФИКАТЫ
$script:CertStores = @('Root', 'AuthRoot', 'CA', 'TrustedPublisher', 'TrustedPeople')
$script:StoreNames = @{ Root = 'Доверенные корневые'; AuthRoot = 'Сторонние корневые'; CA = 'Промежуточные'; TrustedPublisher = 'Доверенные издатели'; TrustedPeople = 'Доверенные лица' }
# Корневые сертификаты, которых нет в программах доверия Microsoft и Mozilla, но которые массово ставят вручную
# (по инструкции провайдера, работодателя, ведомства). В списке - SHA-256 от имени сертификата (CN) в нижнем регистре.
# Добавить свой: Get-NameHash 'Имя сертификата'
$script:OutsideProgramCa = @(
    '31311E0CA1FC4A941ECA27B835579DB8697259E8304F5102F1B2DF84C5BD2183',
    '85647D852E0AA6224CE11BF06E7F307C4E438BBC3B1F20CD2918F4EC39B60AA3',
    'E66CB6EBE8A3563B7ABCCF3E0E26B398F456EB5EA5D00A3E536B7F525BF6E51B',
    'C011DF848D897424F6E4A6461E145416AD90B91D003E677C4C35A41E78587BC9'
)
function Get-NameHash {
    param([string]$Name)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Name.Trim().ToLowerInvariant()))) -replace '-', '') } finally { $sha.Dispose() }
}
function Test-OutsideProgramCa {
    # совпадение по имени самого сертификата или по имени того, кто его выдал
    param($Cert)
    foreach ($n in @($Cert.GetNameInfo('SimpleName', $false), $Cert.GetNameInfo('SimpleName', $true))) {
        if ($n -and ($script:OutsideProgramCa -contains (Get-NameHash $n))) { return $true }
    }
    return $false
}
function Get-DerCommonNames {
    # имена (CN) всех сертификатов, чьи байты встречаются в файле; $Text - содержимое файла в кодировке Latin-1
    param([string]$Text)
    $names = @{}
    $oid = [string][char]0x06 + [char]0x03 + [char]0x55 + [char]0x04 + [char]0x03
    $i = $Text.IndexOf($oid, [StringComparison]::Ordinal)
    while ($i -ge 0 -and $i + 7 -lt $Text.Length) {
        $tag = [int]$Text[$i + 5]; $len = [int]$Text[$i + 6]
        if ($len -gt 0 -and $len -lt 128 -and $i + 7 + $len -le $Text.Length) {
            $bytes = [Text.Encoding]::GetEncoding(28591).GetBytes($Text.Substring($i + 7, $len))
            $s = ''
            if ($tag -eq 0x1E) { $s = [Text.Encoding]::BigEndianUnicode.GetString($bytes) }
            elseif ($tag -eq 0x0C -or $tag -eq 0x13 -or $tag -eq 0x14 -or $tag -eq 0x16) { $s = [Text.Encoding]::UTF8.GetString($bytes) }
            if ($s) { $names[$s] = 1 }
        }
        $i = $Text.IndexOf($oid, $i + 5, [StringComparison]::Ordinal)
    }
    return @($names.Keys)
}
$script:ESignRx = '(?i)КриптоПро|CryptoPro|ViPNet|Lissi|Signal-COM|Плагин пользователя систем электронного|IFCPlugin|Рутокен|Rutoken|JaCarta|Контур\.?(Плагин|Диагностик)|Kontur\.Plugin'
# корневые сертификаты программ, которые вскрывают HTTPS. App = как называется программа в списке установленных
$script:MitmRoots = @(
    @{ Rx = '(?i)Kaspersky|Касперск'; App = '(?i)Kaspersky|Касперск'; Name = 'Kaspersky'; Dev = $false; Always = $false },
    @{ Rx = '(?i)avast|AVG Technologies|AVG Web'; App = '(?i)avast|\bAVG\b'; Name = 'Avast/AVG'; Dev = $false; Always = $false },
    @{ Rx = '(?i)ESET SSL Filter'; App = '(?i)\bESET\b'; Name = 'ESET'; Dev = $false; Always = $false },
    @{ Rx = '(?i)Dr\.?\s?Web'; App = '(?i)Dr\.?\s?Web'; Name = 'Dr.Web'; Dev = $false; Always = $false },
    @{ Rx = '(?i)Bitdefender'; App = '(?i)Bitdefender'; Name = 'Bitdefender'; Dev = $false; Always = $false },
    @{ Rx = '(?i)AdGuard'; App = '(?i)AdGuard'; Name = 'AdGuard'; Dev = $false; Always = $false },
    @{ Rx = '(?i)DO_NOT_TRUST|FiddlerRoot'; App = '(?i)Fiddler'; Name = 'Fiddler'; Dev = $true; Always = $false },
    @{ Rx = '(?i)mitmproxy'; App = '(?i)mitmproxy'; Name = 'mitmproxy'; Dev = $true; Always = $false },
    @{ Rx = '(?i)PortSwigger'; App = '(?i)Burp Suite'; Name = 'Burp Suite'; Dev = $true; Always = $false },
    @{ Rx = '(?i)Charles Proxy'; App = '(?i)Charles'; Name = 'Charles'; Dev = $true; Always = $false },
    @{ Rx = '(?i)Superfish|eDellRoot|DSDTestProvider|Komodia|PrivDog|VisualDiscovery|WebCompanion|Lavasoft'; App = ''; Name = 'известное рекламное/шпионское ПО'; Dev = $false; Always = $true }
)
# центры сертификации, которые нормально встречаются в хранилище "Доверенные корневые"
$script:KnownRootRx = '(?i)(' + (@(
        'Microsoft', 'VeriSign', 'Thawte', 'Symantec', 'DigiCert', 'GlobalSign', 'Sectigo', 'USERTrust', 'COMODO', 'AAA Certificate Services', 'AddTrust', 'UTN-',
        'GeoTrust', 'Equifax', 'Entrust', 'Go Daddy', 'Starfield', 'Baltimore', 'ISRG', 'Amazon', 'QuoVadis', 'Certum', 'Unizeto', 'Actalis', 'SSL\.com', 'Buypass',
        'T-TeleSec', 'Telekom', 'Hotspot 2\.0', 'IdenTrust', 'DST Root', 'Digital Signature Trust', 'SecureTrust', 'Trustwave', 'XRamp', 'GTS Root', 'Google Trust',
        'AffirmTrust', 'Certigna', 'SwissSign', 'NO LIABILITY ACCEPTED', 'Class 3 Public Primary', 'Network Solutions', 'HARICA', 'Hellenic', 'D-TRUST', 'Telia',
        'SECOM', 'Security Communication', 'Chunghwa', 'TWCA', 'emSign', 'eMudhra', 'Izenpe', 'ACCV', 'FNMT', 'Camerfirma', 'NetLock', 'Microsec', 'e-Szigno',
        'OISTE', 'WISeKey', 'Atos', 'Cybertrust', 'GTE CyberTrust', 'Verizon', 'certSIGN', 'TUBITAK', 'CFCA', 'Hongkong Post', 'NAVER', 'Staat der Nederlanden',
        'SZAFIR', 'LuxTrust', 'Certinomis', 'Certplus', 'OpenTrust', 'Trustis', 'TeliaSonera', 'Sonera', 'Firmaprofesional', 'GDCA', 'GUANG DONG', 'UCA ', 'UniTrust',
        'TrustAsia', 'ANF ', 'vTrus', 'iTrusChina', 'Certainly', 'Disig', 'TunTrust', 'Agence Nationale', 'BJCA', 'BEIJING CERTIFICATE', 'SHECA', 'E-Tugra', 'Kamu SM',
        'ePKI', 'HiPKI', 'Viking Cloud', 'SecureSign', 'Chambersign', 'Chambers of Commerce', 'Swisscom', 'A-Trust', 'Halcom', 'SI-TRUST', 'Asseco', 'MULTICERT',
        'Notarius', 'PKIoverheid', 'Japan Certification', 'Cisco', 'Autoridad de Certificacion', 'TrustCor', 'COMSIGN', 'Secure Global', 'Atos TrustedRoot'
    ) -join '|') + ')'

function ConvertFrom-CertBlob {
    # запись реестра SystemCertificates: цепочка (id:4, флаг:4, длина:4, данные); id 32 = сам сертификат
    param([byte[]]$Blob)
    $i = 0
    while ($i + 12 -le $Blob.Length) {
        $id = [BitConverter]::ToUInt32($Blob, $i)
        $len = [long][BitConverter]::ToUInt32($Blob, $i + 8)
        $i += 12
        if ($i + $len -gt $Blob.Length) { break }
        $len = [int]$len
        if ($id -eq 32) {
            $der = New-Object byte[] $len
            [Array]::Copy($Blob, $i, $der, 0, $len)
            try { return (New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList (, $der)) } catch { return $null }
        }
        $i += $len
    }
    return $null
}

function Get-StoreCerts {
    $map = @{}
    $bases = @(
        @{ T = 'компьютер'; B = 'HKLM:\SOFTWARE\Microsoft\SystemCertificates' },
        @{ T = 'компьютер, групповая политика'; B = 'HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates' },
        @{ T = 'компьютер, Enterprise'; B = 'HKLM:\SOFTWARE\Microsoft\EnterpriseCertificates' }
    )
    foreach ($h in $script:UserHives) {
        $bases += @{ T = "пользователь $($h.Name)"; B = "$($h.Hive)\Software\Microsoft\SystemCertificates" }
        $bases += @{ T = "пользователь $($h.Name), политика"; B = "$($h.Hive)\Software\Policies\Microsoft\SystemCertificates" }
    }
    $script:CertScanned = 0
    foreach ($b in $bases) {
        foreach ($s in $script:CertStores) {
            $kp = "$($b.B)\$s\Certificates"
            foreach ($k in @(Get-ChildItem -LiteralPath $kp -ErrorAction SilentlyContinue)) {
                $blob = $null
                try { $blob = (Get-Item -LiteralPath $k.PSPath -ErrorAction Stop).GetValue('Blob') } catch { }
                if (-not ($blob -is [byte[]])) { continue }
                $c = ConvertFrom-CertBlob $blob
                if (-not $c) { continue }
                $script:CertScanned++
                $key = "$s|$($c.Thumbprint)"
                if (-not $map.ContainsKey($key)) { $map[$key] = [pscustomobject]@{ Store = $s; Thumb = $c.Thumbprint; Cert = $c; Where = @(); RegPaths = @(); Api = @(); UserStore = $false } }
                $map[$key].Where += $b.T
                $map[$key].RegPaths += $k.PSPath
                if ($b.T -like 'пользователь*') { $map[$key].UserStore = $true }
            }
        }
    }
    # сверка через системный API: вдруг сертификат лежит там, куда реестровый обход не заглянул
    foreach ($loc in @('LocalMachine', 'CurrentUser')) {
        foreach ($s in $script:CertStores) {
            try {
                $st = New-Object System.Security.Cryptography.X509Certificates.X509Store($s, [System.Security.Cryptography.X509Certificates.StoreLocation]$loc)
                $st.Open('ReadOnly')
                foreach ($c in $st.Certificates) {
                    $key = "$s|$($c.Thumbprint)"
                    # логическое хранилище Root включает в себя и AuthRoot - это не отдельная находка
                    if ($s -eq 'Root' -and $map.ContainsKey("AuthRoot|$($c.Thumbprint)")) { continue }
                    if ($s -eq 'AuthRoot' -and $map.ContainsKey("Root|$($c.Thumbprint)")) { continue }
                    if (-not $map.ContainsKey($key)) {
                        $map[$key] = [pscustomobject]@{ Store = $s; Thumb = $c.Thumbprint; Cert = $c; Where = @("$loc (видно только через API)"); RegPaths = @(); Api = @($loc); UserStore = ($loc -eq 'CurrentUser') }
                        $script:CertScanned++
                    }
                }
                $st.Close()
            } catch { }
        }
    }
    return @($map.Values)
}

function Get-CertLines {
    param($e)
    $c = $e.Cert
    return @(
        "кому выдан: $($c.Subject)",
        "кем выдан:  $($c.Issuer)",
        "хранилище: $($script:StoreNames[$e.Store]) ($($e.Store)); где лежит: $(($e.Where | Sort-Object -Unique) -join '; ')",
        "действует до $($c.NotAfter.ToString('dd.MM.yyyy')); отпечаток $($c.Thumbprint)"
    )
}

$script:FixRemoveCert = {
    param($f)
    $d = $f.Data
    $dir = Join-P (Get-BackupDir) 'certs'
    if (-not (Test-PathSafe $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    [IO.File]::WriteAllBytes((Join-P $dir "$($d.Store)_$($d.Thumb).cer"), $d.Der)
    $n = 0
    foreach ($kp in $d.RegPaths) {
        if (Test-PathSafe $kp) {
            Export-RegKey $kp "certs\$($d.Store)_$($d.Thumb)_$n.reg" | Out-Null
            Remove-Item -LiteralPath $kp -Recurse -Force
            Add-Change 'certificate removed' "$($d.Subject)`t$($d.Thumb)`t$(ConvertTo-NativeRegPath $kp)"
            $n++
        }
    }
    # то, что видно только через API (или осталось после реестра) - убираем через API из хранилища компьютера
    $left = @()
    foreach ($loc in @('LocalMachine', 'CurrentUser')) {
        $st = New-Object System.Security.Cryptography.X509Certificates.X509Store($d.Store, [System.Security.Cryptography.X509Certificates.StoreLocation]$loc)
        try {
            $st.Open('ReadOnly')
            $hit = @($st.Certificates | Where-Object { $_.Thumbprint -eq $d.Thumb })
            $st.Close()
            if ($hit.Count -and $loc -eq 'LocalMachine') {
                $st.Open('ReadWrite'); foreach ($c in $hit) { $st.Remove($c) }; $st.Close()
                Add-Change 'certificate removed (API)' "$($d.Subject)`t$($d.Thumb)`tLocalMachine\$($d.Store)"
                $st.Open('ReadOnly'); $hit = @($st.Certificates | Where-Object { $_.Thumbprint -eq $d.Thumb }); $st.Close()
            }
            if ($hit.Count) { $left += $loc }
        } catch { try { $st.Close() } catch { } }
    }
    if ($left.Count) { throw "сертификат всё ещё виден в $($left -join ', ') - его возвращает политика или программа; удалить вручную: certmgr.msc / certlm.msc > $($script:StoreNames[$d.Store])" }
    return "удалён (записей реестра: $n); копия: backup\certs\$($d.Store)_$($d.Thumb).cer"
}

function Invoke-CertificateChecks {
    Start-Section 'Сертификаты'
    Invoke-Check 'доверенные хранилища сертификатов Windows' {
        $all = @(Get-StoreCerts)
        $out = 0; $mitm = 0; $unk = 0; $unkList = @()
        foreach ($e in ($all | Sort-Object Store, Thumb)) {
            $c = $e.Cert
            $name = $c.GetNameInfo('SimpleName', $false)
            if (-not $name) { $name = $c.Subject }
            $data = @{ Store = $e.Store; Thumb = $e.Thumb; RegPaths = @($e.RegPaths); Subject = $c.Subject; Der = $c.RawData }
            $anchor = ($e.Store -eq 'Root' -or $e.Store -eq 'AuthRoot')
            if (Test-OutsideProgramCa $c) {
                $out++
                if ($anchor -or $e.Store -eq 'CA') {
                    $what = 'Корневой'; if ($e.Store -eq 'CA') { $what = 'Промежуточный' }
                    $why = 'с ним владелец сертификата может незаметно подменять любые HTTPS-сайты на этом компьютере'
                    if ($e.Store -eq 'CA') { $why = 'сам по себе доверия не добавляет, но работает в паре с корневым' }
                    Add-Finding -Level BAD -Title "$what сертификат вне программ доверия Microsoft и Mozilla: $name" -Detail ((Get-CertLines $e) + @($why)) `
                        -Fix $script:FixRemoveCert -FixText 'удалить сертификат (копия .cer сохраняется). Сайты, которые работают только на нём, начнут показывать предупреждение в браузере' -Data $data
                } else {
                    Add-Finding -Level WARN -Title "Сертификат вне программ доверия в «$($script:StoreNames[$e.Store])»: $name" -Detail (Get-CertLines $e) -Fix $script:FixRemoveCert -FixText 'удалить сертификат (копия .cer сохраняется)' -Data $data -Explicit
                }
                continue
            }
            if (-not $anchor) { continue }
            $hit = $null
            foreach ($m in $script:MitmRoots) { if ($c.Subject -match $m.Rx) { $hit = $m; break } }
            if ($hit) {
                $mitm++
                $inst = $false; if ($hit.App) { $inst = Test-Installed $hit.App }
                if ($hit.Always) {
                    Add-Finding -Level BAD -Title "Корневой сертификат рекламного/шпионского ПО: $name" -Detail (Get-CertLines $e) -Fix $script:FixRemoveCert -FixText 'удалить сертификат (копия .cer сохраняется)' -Data $data
                } elseif ($hit.Dev) {
                    Add-Finding -Level WARN -Title "Корневой сертификат инструмента перехвата трафика ($($hit.Name)): $name" -Detail (Get-CertLines $e) -Fix $script:FixRemoveCert -FixText 'удалить сертификат (копия .cer сохраняется)' -Data $data -Explicit
                } elseif (-not $inst) {
                    Add-Finding -Level BAD -Title "Корневой сертификат от удалённой программы ($($hit.Name)): $name" -Detail ((Get-CertLines $e) + @('программы уже нет, а её сертификат для вскрытия HTTPS остался доверенным')) -Fix $script:FixRemoveCert -FixText 'удалить сертификат (копия .cer сохраняется)' -Data $data
                } else {
                    Add-Finding -Level INFO -Title "Корневой сертификат установленной программы $($hit.Name): $name" -Detail @('программа с его помощью просматривает HTTPS-трафик; исчезнет вместе с программой')
                }
                continue
            }
            if ($e.Store -eq 'Root' -and $c.Subject -notmatch $script:KnownRootRx) {
                $unk++
                $unkList += @{ E = $e; Name = $name; Data = $data }
            }
        }
        if ($unkList.Count -gt 10) {
            Add-Finding -Level WARN -Title "Много незнакомых корневых сертификатов: $($unkList.Count)" -Detail @($unkList | ForEach-Object { "$($_.Name) | $($_.E.Cert.Subject) | $(($_.E.Where | Sort-Object -Unique) -join '; ')" }) -Manual 'показать отчёт: либо на компьютере стоит корпоративное/специальное ПО, либо скрипт не узнал обычные сертификаты'
        } else {
            foreach ($u in $unkList) {
                Add-Finding -Level WARN -Title "Незнакомый корневой сертификат: $($u.Name)" -Detail (Get-CertLines $u.E) -Fix $script:FixRemoveCert -FixText 'удалить сертификат (копия .cer сохраняется)' -Data $u.Data -Explicit -Manual 'выяснить, какая программа его поставила; если непонятно - показать отчёт'
            }
        }
        if ($out -eq 0) { Add-Finding -Level OK -Title "Сертификатов вне программ доверия Microsoft и Mozilla в доверенных хранилищах нет (компьютер и вошедшие в систему пользователи; просмотрено сертификатов: $script:CertScanned)" }
        if ($mitm -eq 0 -and $unk -eq 0) { Add-Finding -Level OK -Title 'Посторонних корневых сертификатов нет' }
    }

    Invoke-Check 'программы для электронной подписи' {
        $crypto = @(Get-InstalledNames $script:ESignRx)
        if ($crypto.Count) { Add-Finding -Level INFO -Title "Программы для электронной подписи: $($crypto.Count)" -Detail ($crypto + @('они сами ставят свои корневые сертификаты; если удалить сертификаты, а программы оставить - сертификаты могут вернуться')) }
    }
}

# ================================================================ 4. БРАУЗЕРЫ
$script:FixFirefoxRoots = {
    param($f)
    $uj = Join-P $f.Data.Profile 'user.js'
    $lines = @()
    if (Test-PathSafe $uj) {
        Backup-File $uj | Out-Null
        $lines = @(Get-Content -LiteralPath $uj -Encoding UTF8 | Where-Object { $_ -notmatch 'security\.enterprise_roots\.enabled' })
    }
    $lines += 'user_pref("security.enterprise_roots.enabled", false);'
    [IO.File]::WriteAllLines($uj, [string[]]$lines, (New-Object System.Text.UTF8Encoding($false)))
    Add-Change 'firefox pref' "$uj`tsecurity.enterprise_roots.enabled=false"
    return 'записано в user.js профиля; подействует после перезапуска Firefox'
}
$script:FixMoveFile = {
    param($f)
    if ($f.Data.NeedClosed -and @(Get-Process -Name $f.Data.NeedClosed -ErrorAction SilentlyContinue).Count) { throw "сначала закрой программу $($f.Data.NeedClosed) и запусти проверку ещё раз" }
    $n = 0
    foreach ($p in @($f.Data.Paths)) {
        if (Test-PathSafe $p) {
            $dst = Backup-File $p
            Remove-Item -LiteralPath $p -Force
            Add-Change 'file removed' "$p`tкопия: $dst"
            $n++
        }
    }
    return "убрано файлов: $n (копии в backup\files)"
}

function Invoke-BrowserChecks {
    Start-Section 'Браузеры'
    $profiles = @(Get-AllProfiles)
    $latin1 = [Text.Encoding]::GetEncoding(28591)

    Invoke-Check 'Firefox: профили' {
        $found = 0
        foreach ($up in $profiles) {
            $root = Join-P $up.Profile 'AppData\Roaming\Mozilla\Firefox\Profiles'
            foreach ($d in @(Get-ChildItem -LiteralPath $root -Directory -Force -ErrorAction SilentlyContinue)) {
                $prefs = Join-P $d.FullName 'prefs.js'
                if (-not (Test-PathSafe $prefs)) { continue }
                $found++
                $tag = "Firefox, профиль $($d.Name) ($($up.Name))"
                $state = $null
                foreach ($pf in @('prefs.js', 'user.js')) {
                    $fp = Join-P $d.FullName $pf
                    if (Test-PathSafe $fp) {
                        $m = Select-String -LiteralPath $fp -Pattern 'user_pref\("security\.enterprise_roots\.enabled",\s*(true|false)\)' -ErrorAction SilentlyContinue | Select-Object -Last 1
                        if ($m) { $state = $m.Matches[0].Groups[1].Value }
                    }
                }
                if ($state -eq 'false') {
                    Add-Finding -Level OK -Title "$tag - не доверяет сертификатам, добавленным в Windows"
                } else {
                    $why = 'настройка по умолчанию'; if ($state -eq 'true') { $why = 'включено явно' }
                    Add-Finding -Level WARN -Title "$tag - доверяет всем сертификатам, добавленным в Windows ($why)" -Detail @('Настройки > Приватность и защита > Сертификаты > "Разрешить Firefox автоматически доверять сторонним корневым сертификатам"') `
                        -Fix $script:FixFirefoxRoots -FixText 'выключить это доверие (строка в user.js профиля)' -Data @{ Profile = $d.FullName }
                }
                $db = Join-P $d.FullName 'cert9.db'
                if (Test-PathSafe $db) {
                    $txt = ''
                    try {
                        $fs = New-Object IO.FileStream($db, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
                        $buf = New-Object byte[] $fs.Length
                        [void]$fs.Read($buf, 0, $buf.Length); $fs.Close()
                        $txt = $latin1.GetString($buf)
                    } catch { }
                    $hit = @(Get-DerCommonNames $txt | Where-Object { $script:OutsideProgramCa -contains (Get-NameHash $_) })
                    if ($hit.Count) {
                        Add-Finding -Level BAD -Title "$tag - в собственной базе сертификатов Firefox есть корневой сертификат вне программ доверия" -Detail @('его импортировали прямо в Firefox (или это след уже удалённого)', $db) `
                            -Fix $script:FixMoveFile -FixText 'убрать файл cert9.db в backup (Firefox создаст чистый; пропадут только вручную добавленные сертификаты и исключения). Firefox должен быть закрыт' -Data @{ Paths = @($db); NeedClosed = 'firefox' }
                    } else {
                        Add-Finding -Level OK -Title "$tag - в собственной базе сертификатов вне программ доверия нет"
                    }
                }
                $lj = Join-P $d.FullName 'logins.json'
                if (Test-PathSafe $lj) {
                    $cnt = 0
                    try { $cnt = @((Get-Content -LiteralPath $lj -Raw -Encoding UTF8 | ConvertFrom-Json).logins | Where-Object { $_.encryptedPassword }).Count } catch { }
                    if ($cnt -gt 0) {
                        # файл может быть остатком прежнего хранилища: поэтому показываем и его дату
                        $when = (Get-Item -LiteralPath $lj -Force).LastWriteTime.ToString('dd.MM.yyyy')
                        Add-Finding -Level INFO -Title "$tag - в файле паролей logins.json записей: $cnt (файл от $when)" -Detail @('если на странице about:logins пусто, а файл старый - это остаток прежнего хранилища паролей', 'без мастер-пароля такие записи расшифрует любой, кто получит файлы профиля; надёжнее держать пароли в менеджере паролей (KeePassXC)')
                    }
                }
            }
        }
        if ($found -eq 0) { Add-Finding -Level INFO -Title 'Firefox: профилей не найдено' }
    }

    Invoke-Check 'Firefox: чужие файлы настроек в папке программы' {
        $dirs = @('C:\Program Files\Mozilla Firefox', 'C:\Program Files (x86)\Mozilla Firefox', 'C:\Program Files\Firefox Developer Edition', 'C:\Program Files\Firefox Nightly')
        foreach ($p in @($script:Programs | Where-Object { $_.Name -match '(?i)Firefox' -and $_.Location })) { $dirs += $p.Location.Trim('"').TrimEnd('\') }
        $kasper = Test-Installed '(?i)Kaspersky|Касперск'
        foreach ($base in @($dirs | Sort-Object -Unique)) {
            if (-not (Test-PathSafe (Join-P $base 'firefox.exe'))) { continue }
            $extra = @()
            $extra += @(Get-ChildItem -LiteralPath (Join-P $base 'defaults\pref') -File -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne 'channel-prefs.js' })
            $extra += @(Get-ChildItem -LiteralPath $base -File -Force -Filter '*.cfg' -ErrorAction SilentlyContinue)
            $extra += @(Get-ChildItem -LiteralPath (Join-P $base 'distribution') -File -Force -Filter 'policies.json' -ErrorAction SilentlyContinue)
            if ($extra.Count -eq 0) { Add-Finding -Level OK -Title "Firefox ($base): чужих файлов настроек нет"; continue }
            $kl = @($extra | Where-Object { $_.Name -match '^kl_' })
            $other = @($extra | Where-Object { $_.Name -notmatch '^kl_' })
            if ($kl.Count -and -not $kasper) {
                Add-Finding -Level BAD -Title "Firefox ($base): остались файлы Kaspersky, которые насильно включают доверие сертификатам Windows" -Detail @($kl | ForEach-Object { $_.FullName }) `
                    -Fix $script:FixMoveFile -FixText 'убрать эти файлы (копии в backup)' -Data @{ Paths = @($kl | ForEach-Object { $_.FullName }) }
            } elseif ($kl.Count) {
                Add-Finding -Level INFO -Title "Firefox ($base): файлы настроек от установленного Kaspersky" -Detail @($kl | ForEach-Object { $_.Name })
            }
            if ($other.Count) {
                Add-Finding -Level WARN -Title "Firefox ($base): посторонние файлы настроек (ими программы и организации управляют браузером)" -Detail @($other | ForEach-Object { "$($_.FullName) | $($_.LastWriteTime.ToString('dd.MM.yyyy'))" }) -Manual 'выяснить, кто их положил; если непонятно - показать отчёт'
            }
        }
        foreach ($pp in @('HKLM:\SOFTWARE\Policies\Mozilla\Firefox\Certificates', "$($script:Ctx.MainHive)\Software\Policies\Mozilla\Firefox\Certificates")) {
            $v = Get-RegValue $pp 'ImportEnterpriseRoots'
            if ($null -ne $v -and "$v" -eq '1') { Add-Finding -Level WARN -Title 'Политика заставляет Firefox доверять сертификатам Windows (ImportEnterpriseRoots)' -Detail @((ConvertTo-NativeRegPath $pp)) -Fix $script:FixRegValueRemove -FixText 'удалить эту политику' -Data @{ Path = $pp; Name = 'ImportEnterpriseRoots' } }
        }
    }

    Invoke-Check 'браузеры с собственным списком доверенных сертификатов' {
        $ya = @(Get-InstalledNames '(?i)Yandex\s?Browser|Яндекс\.?\s?Браузер|^Yandex$|Chromium-Gost|Chromium GOST|Atom\s?Browser|Браузер Atom')
        foreach ($up in $profiles) { if (Test-PathSafe (Join-P $up.Profile 'AppData\Local\Yandex\YandexBrowser\Application\browser.exe')) { $ya += "Яндекс Браузер (профиль $($up.Name))" } }
        $ya = @($ya | Sort-Object -Unique)
        if ($ya.Count) {
            Add-Finding -Level INFO -Title 'Установлен браузер с собственным списком доверенных сертификатов' -Detail ($ya + @('он доверяет дополнительным корневым сертификатам независимо от хранилища Windows - проверка хранилища на него не распространяется'))
        } else { Add-Finding -Level OK -Title 'Браузеров с собственным списком доверенных сертификатов нет' }
    }

    Invoke-Check 'политики, управляющие Chrome и Edge' {
        foreach ($pp in @('HKLM:\SOFTWARE\Policies\Google\Chrome', "$($script:Ctx.MainHive)\Software\Policies\Google\Chrome", "$($script:Ctx.MainHive)\Software\Policies\Microsoft\Edge")) {
            if (-not (Test-PathSafe $pp)) { continue }
            $names = @((Get-Item -LiteralPath $pp).GetValueNames() | Where-Object { $_ })
            $sub = @(Get-ChildItem -LiteralPath $pp -ErrorAction SilentlyContinue | ForEach-Object { $_.PSChildName })
            if ($names.Count + $sub.Count -gt 0) {
                Add-Finding -Level WARN -Title "Браузером управляет политика: $(ConvertTo-NativeRegPath $pp)" -Detail @("параметры: $((@($names) + @($sub)) -join ', ')", 'на домашнем компьютере так делают вредные расширения и рекламные программы (принудительная установка расширений, подмена поиска)') -Manual 'если не настраивал сам - показать отчёт'
            }
        }
    }
}

# ================================================================ 5. СЕТЬ
function Get-HostsEntries {
    param([string[]]$Lines)
    $out = @(); $n = 0
    foreach ($l in $Lines) {
        $n++
        $t = ("$l" -replace '#.*$', '').Trim()
        if (-not $t) { continue }
        $parts = @($t -split '\s+')
        if ($parts.Count -lt 2) { continue }
        $out += [pscustomobject]@{ LineNo = $n; Ip = $parts[0]; Names = @($parts[1..($parts.Count - 1)]) }
    }
    return $out
}
function Get-HostsVerdict {
    # SECURITY = глушит сайты защиты и обновлений; REDIRECT = уводит сайт на чужой адрес; LICENSE = блокировка проверки лицензий; BLOCK = прочие блокировки; LOCAL = обычные локальные записи
    param($Entry)
    $names = ($Entry.Names -join ' ')
    $sink = ("$($Entry.Ip)" -match '^(0\.0\.0\.0|127\.\d+\.\d+\.\d+|::1?|0:0:0:0:0:0:0:[01])$')
    if ($sink) {
        if ($names -match '(?i)^(localhost|[\w-]+\.localhost|ip6-localhost|ip6-loopback|[\w.-]*\.local|[\w.-]*\.test|[\w.-]*\.internal|host\.docker\.internal|kubernetes\.docker\.internal)$') { return 'LOCAL' }
        if ($names -match '(?i)(kaspersky|drweb|eset\.|avast|avg\.com|bitdefender|malwarebytes|virustotal|windowsupdate|update\.microsoft|wdcp\.microsoft|defender|norton|mcafee|sophos|trendmicro|f-secure|emsisoft|avira|comodo|virusradar|esetnod32)') { return 'SECURITY' }
        if ($names -match '(?i)(adobe|autodesk|corel|activat|licens|genuine|macromedia|sls\.microsoft|validation)') { return 'LICENSE' }
        return 'BLOCK'
    }
    if (Test-PrivateIp $Entry.Ip) { return 'LOCAL' }
    return 'REDIRECT'
}
$script:FixHostsLines = {
    param($f)
    $p = $script:HostsPath
    Backup-File $p | Out-Null
    $lines = @(Get-Content -LiteralPath $p)
    $n = 0
    foreach ($i in @($f.Data.LineNos)) {
        if ($i -ge 1 -and $i -le $lines.Count -and $lines[$i - 1] -notmatch '^\s*#') { $lines[$i - 1] = '# [GlowCleanWin] ' + $lines[$i - 1]; $n++ }
    }
    $it = Get-Item -LiteralPath $p -Force
    if ($it.IsReadOnly) { $it.IsReadOnly = $false }
    [IO.File]::WriteAllLines($p, [string[]]$lines, [Text.Encoding]::Default)
    Add-Change 'hosts lines disabled' "строки: $(@($f.Data.LineNos) -join ',')"
    return "отключено строк: $n (закомментированы, копия файла в backup\files)"
}
$script:FixProxy = {
    param($f)
    $k = $f.Data.Key
    if ($f.Data.Pac) { Remove-RegValueSafe $k 'AutoConfigURL' }
    if ($f.Data.Proxy) { Set-RegValueSafe $k 'ProxyEnable' 0 'DWord' }
    return 'прокси отключён (адрес сохранён в backup\registry_before.tsv)'
}

function Invoke-NetworkChecks {
    Start-Section 'Сеть'

    Invoke-Check 'файл hosts' {
        if (-not (Test-PathSafe $script:HostsPath)) { Add-Finding -Level INFO -Title 'Файла hosts нет (это допустимо)'; return }
        $entries = @(Get-HostsEntries @(Get-Content -LiteralPath $script:HostsPath))
        $g = @{ SECURITY = @(); REDIRECT = @(); LICENSE = @(); BLOCK = @(); LOCAL = @() }
        foreach ($e in $entries) { $g[(Get-HostsVerdict $e)] += $e }
        # большой hosts - это чей-то готовый список блокировки рекламы; в нём домены антивирусов встречаются как счётчики, а не как диверсия
        $blockList = (($g.SECURITY.Count + $g.LICENSE.Count + $g.BLOCK.Count) -gt 300)
        if ($g.SECURITY.Count -and $blockList) {
            Add-Finding -Level INFO -Title "hosts: большой список блокировок, в нём есть и домены антивирусов, строк: $($g.SECURITY.Count)" -Detail @($g.SECURITY | Select-Object -First 5 | ForEach-Object { "$($_.Ip) $($_.Names -join ' ')" })
        } elseif ($g.SECURITY.Count) {
            Add-Finding -Level BAD -Title "hosts глушит сайты антивирусов и обновлений, строк: $($g.SECURITY.Count)" -Detail @($g.SECURITY | ForEach-Object { "строка $($_.LineNo): $($_.Ip) $($_.Names -join ' ')" }) `
                -Fix $script:FixHostsLines -FixText 'закомментировать эти строки (копия hosts сохраняется)' -Data @{ LineNos = @($g.SECURITY | ForEach-Object { $_.LineNo }) }
        }
        $money = '(?i)(sber|tinkoff|tbank|vtb\.|alfabank|alfa-bank|gazprombank|raiffeisen|rshb|psbank|pochtabank|bank|gosuslugi|nalog\.|esia\.|qiwi|yoomoney|paypal|mos\.ru)'
        $redBank = @($g.REDIRECT | Where-Object { ($_.Names -join ' ') -match $money })
        $redOther = @($g.REDIRECT | Where-Object { ($_.Names -join ' ') -notmatch $money })
        if ($redBank.Count) {
            Add-Finding -Level BAD -Title "hosts уводит важные сайты на посторонние адреса, строк: $($redBank.Count)" -Detail (@($redBank | ForEach-Object { "строка $($_.LineNo): $($_.Ip) $($_.Names -join ' ')" }) + @('так воруют пароли: набираешь адрес банка, а попадаешь на подделку')) `
                -Fix $script:FixHostsLines -FixText 'закомментировать эти строки (копия hosts сохраняется)' -Data @{ LineNos = @($redBank | ForEach-Object { $_.LineNo }) }
        }
        if ($redOther.Count) {
            Add-Finding -Level WARN -Title "hosts направляет сайты на посторонние адреса, строк: $($redOther.Count)" -Detail (@($redOther | ForEach-Object { "строка $($_.LineNo): $($_.Ip) $($_.Names -join ' ')" }) + @('так делают и списки для обхода блокировок, и вредные программы; владелец этих адресов видит, куда ты ходишь')) `
                -Fix $script:FixHostsLines -FixText 'закомментировать эти строки (копия hosts сохраняется)' -Data @{ LineNos = @($redOther | ForEach-Object { $_.LineNo }) } -Explicit -Manual 'если добавлял сам для обхода блокировок - твой выбор; если нет - отключить по номеру'
        }
        if ($g.LICENSE.Count) { Add-Finding -Level INFO -Title "hosts: блокировка серверов проверки лицензий, строк: $($g.LICENSE.Count) (решение за хозяином компьютера)" -Detail @($g.LICENSE | Select-Object -First 5 | ForEach-Object { "$($_.Ip) $($_.Names -join ' ')" }) }
        if ($g.BLOCK.Count) { Add-Finding -Level INFO -Title "hosts: прочие блокировки сайтов, строк: $($g.BLOCK.Count)" -Detail @($g.BLOCK | Select-Object -First 5 | ForEach-Object { "$($_.Ip) $($_.Names -join ' ')" }) }
        if ($g.SECURITY.Count + $g.REDIRECT.Count -eq 0) { Add-Finding -Level OK -Title 'hosts: подмен адресов и блокировок антивирусов нет' }
    }

    Invoke-Check 'прокси' {
        $any = $false
        foreach ($h in $script:UserHives) {
            $k = "$($h.Hive)\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
            $en = Get-RegValue $k 'ProxyEnable'; $srv = Get-RegValue $k 'ProxyServer'; $pac = Get-RegValue $k 'AutoConfigURL'
            $on = ($null -ne $en -and [int]$en -eq 1 -and $srv)
            if ($pac) {
                $any = $true
                $pacShown = Hide-Secrets ("$pac" -replace '\?.*$', '?...')
                if ("$pac" -match '(?i)^(https?://)?(127\.0\.0\.1|localhost|\[::1\])[:/]|^file:') {
                    Add-Finding -Level WARN -Title "Включён локальный сценарий автонастройки прокси ($($h.Name))" -Detail @("адрес сценария: $pacShown", 'обычно это VPN-клиент или программа обхода блокировок на этом же компьютере') -Fix $script:FixProxy -FixText 'убрать сценарий автонастройки' -Data @{ Key = $k; Pac = $true; Proxy = $false } -Explicit
                } else {
                    Add-Finding -Level BAD -Title "Весь трафик идёт через чужой сценарий автонастройки прокси ($($h.Name))" -Detail @("адрес сценария: $pacShown", 'так вредные программы пропускают через себя банковские сайты') -Fix $script:FixProxy -FixText 'убрать сценарий автонастройки (адрес сохраняется в backup)' -Data @{ Key = $k; Pac = $true; Proxy = $false }
                }
            }
            if ($on) {
                $any = $true
                $local = ("$srv" -match '(?i)(^|=|//)(127\.0\.0\.1|localhost|\[::1\])[:;]')
                if ($local) { Add-Finding -Level WARN -Title "Включён локальный прокси ($($h.Name)): $srv" -Detail @('обычно это VPN-клиент или антивирус на этом же компьютере') -Fix $script:FixProxy -FixText 'выключить системный прокси' -Data @{ Key = $k; Pac = $false; Proxy = $true } -Explicit }
                else { Add-Finding -Level WARN -Title "Трафик браузеров идёт через прокси ($($h.Name)): $srv" -Fix $script:FixProxy -FixText 'выключить системный прокси' -Data @{ Key = $k; Pac = $false; Proxy = $true } -Manual 'если прокси не настраивал сам - выключить' }
            }
        }
        if (-not $any) { Add-Finding -Level OK -Title 'Системный прокси не используется' }
    }

    Invoke-Check 'DNS-серверы' {
        $known = @{
            '1.1.1.1' = 'Cloudflare'; '1.0.0.1' = 'Cloudflare'; '1.1.1.2' = 'Cloudflare'; '1.0.0.2' = 'Cloudflare'; '8.8.8.8' = 'Google'; '8.8.4.4' = 'Google'; '9.9.9.9' = 'Quad9'; '149.112.112.112' = 'Quad9'
            '208.67.222.222' = 'OpenDNS'; '208.67.220.220' = 'OpenDNS'; '94.140.14.14' = 'AdGuard'; '94.140.15.15' = 'AdGuard'; '76.76.2.0' = 'ControlD'; '76.76.10.0' = 'ControlD'
            '77.88.8.8' = 'Яндекс'; '77.88.8.1' = 'Яндекс'; '77.88.8.88' = 'Яндекс'; '77.88.8.2' = 'Яндекс'; '77.88.8.7' = 'Яндекс'; '77.88.8.3' = 'Яндекс'
            '2606:4700:4700::1111' = 'Cloudflare'; '2606:4700:4700::1001' = 'Cloudflare'; '2001:4860:4860::8888' = 'Google'; '2001:4860:4860::8844' = 'Google'; '2620:fe::fe' = 'Quad9'; '2620:fe::9' = 'Quad9'
        }
        $up = @{}
        try { foreach ($a in @(Get-NetAdapter -ErrorAction Stop | Where-Object { "$($_.Status)" -eq 'Up' })) { $up[[int]$a.ifIndex] = $a.Name } } catch { }
        $lines = @(); $unknown = @()
        foreach ($a in @(Get-DnsClientServerAddress -ErrorAction SilentlyContinue | Where-Object { $_.ServerAddresses })) {
            if ($up.Count -and -not $up.ContainsKey([int]$a.InterfaceIndex)) { continue }
            foreach ($ip in $a.ServerAddresses) {
                if ("$ip" -match '^fec0:') { continue }
                $who = 'роутер/локальная сеть'
                if (-not (Test-PrivateIp $ip)) { if ($known.ContainsKey("$ip")) { $who = $known["$ip"] } else { $who = 'НЕИЗВЕСТНЫЙ'; $unknown += "$ip ($($a.InterfaceAlias))" } }
                $lines += "$($a.InterfaceAlias): $ip - $who"
            }
        }
        $lines = @($lines | Sort-Object -Unique)
        if ($unknown.Count) { Add-Finding -Level WARN -Title "Незнакомые DNS-серверы: $(($unknown | Sort-Object -Unique) -join ', ')" -Detail ($lines + @('DNS-сервер решает, на какой адрес тебя отправить по имени сайта; чужой DNS может подменять сайты')) -Manual 'если это не DNS провайдера или VPN - вернуть "Получать автоматически" в свойствах сетевого подключения' }
        else { Add-Finding -Level OK -Title 'DNS-серверы обычные' -Detail $lines }
    }
}

# ================================================================ 6. АВТОЗАПУСК
$script:FixRemoveRunValue = {
    param($f)
    Remove-RegValueSafe $f.Data.Path $f.Data.Name
    return 'запись автозапуска удалена (сам файл не тронут; старое значение в backup\registry_before.tsv)'
}
$script:FixRemoveTask = {
    param($f)
    $dir = Join-P (Get-BackupDir) 'tasks'
    if (-not (Test-PathSafe $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $safe = ("$($f.Data.TaskPath)$($f.Data.TaskName)" -replace '[\\/:*?"<>|]', '_')
    (Export-ScheduledTask -TaskPath $f.Data.TaskPath -TaskName $f.Data.TaskName) | Out-File -FilePath (Join-P $dir "$safe.xml") -Encoding unicode
    if ($f.Data.DisableOnly) {
        Disable-ScheduledTask -TaskPath $f.Data.TaskPath -TaskName $f.Data.TaskName | Out-Null
        Add-Change 'task disabled' "$($f.Data.TaskPath)$($f.Data.TaskName)"
        return 'задача отключена (не удалена; копия в backup\tasks)'
    }
    Unregister-ScheduledTask -TaskPath $f.Data.TaskPath -TaskName $f.Data.TaskName -Confirm:$false
    Add-Change 'task removed' "$($f.Data.TaskPath)$($f.Data.TaskName)"
    return 'задача удалена (копия в backup\tasks, вернуть: Register-ScheduledTask -Xml)'
}

$script:FixDeleteService = {
    param($f)
    $name = "$($f.Data.Name)"
    $key = "HKLM:\SYSTEM\CurrentControlSet\Services\$name"
    if (Test-PathSafe $key) { Export-RegKey $key ("service_" + ($name -replace '[^\w.-]', '_') + '.reg') | Out-Null }
    $ErrorActionPreference = 'Continue'
    $o = & sc.exe delete $name
    if ($LASTEXITCODE -ne 0) { throw "sc delete (код $LASTEXITCODE): $((@($o) | Where-Object { $_ }) -join ' ')" }
    Add-Change 'service deleted' $name
    return 'запись службы удалена (копия ветки реестра в backup); окончательно исчезнет после перезагрузки'
}

function Invoke-AutorunChecks {
    Start-Section 'Автозапуск'

    Invoke-Check 'автозапуск из реестра (Run)' {
        $keys = @(
            @{ P = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'; U = ''; T = 'для всех' },
            @{ P = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'; U = ''; T = 'для всех, однократно' },
            @{ P = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'; U = ''; T = 'для всех, 32 бита' },
            @{ P = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce'; U = ''; T = 'для всех, 32 бита, однократно' },
            @{ P = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run'; U = ''; T = 'политика' }
        )
        foreach ($h in $script:UserHives) {
            $keys += @{ P = "$($h.Hive)\Software\Microsoft\Windows\CurrentVersion\Run"; U = $h.Profile; T = $h.Name }
            $keys += @{ P = "$($h.Hive)\Software\Microsoft\Windows\CurrentVersion\RunOnce"; U = $h.Profile; T = "$($h.Name), однократно" }
            $keys += @{ P = "$($h.Hive)\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"; U = $h.Profile; T = "$($h.Name), политика" }
        }
        $fine = @(); $flag = 0
        foreach ($k in $keys) {
            if (-not (Test-PathSafe $k.P)) { continue }
            $item = Get-Item -LiteralPath $k.P
            foreach ($n in $item.GetValueNames()) {
                if (-not $n) { continue }
                $v = "$($item.GetValue($n, '', 'DoNotExpandEnvironmentNames'))"
                if (-not $v.Trim()) { continue }
                $exe = Get-ExePath $v $k.U
                $sg = Get-Signer $exe
                $risk = Get-CommandRisk $v
                $data = @{ Path = $k.P; Name = $n }
                $det = @("файл: $exe ($(Get-SignerText $sg))", "где: $(ConvertTo-NativeRegPath $k.P)")
                if ($risk -eq 'BAD') {
                    $flag++
                    Add-Finding -Level BAD -Title "Автозапуск похож на вредоносный: $n ($($k.T))" -Detail (@("команда: $(Hide-Secrets $v)") + $det) -Fix $script:FixRemoveRunValue -FixText 'удалить запись автозапуска' -Data $data -Explicit -Manual 'если сам такого не настраивал - удалить по номеру и запустить полную проверку Defender'
                } elseif (Test-DeadTarget $v "$exe" $sg) {
                    $flag++
                    Add-Finding -Level WARN -Title "Автозапуск ведёт на несуществующий файл: $n ($($k.T))" -Detail $det -Fix $script:FixRemoveRunValue -FixText 'удалить мёртвую запись' -Data $data
                } elseif (-not (Test-ValidSigned $sg) -and $sg -ne 'FILE NOT FOUND' -and (Test-UserWritablePath "$exe")) {
                    $flag++
                    Add-Finding -Level WARN -Title "В автозапуске неподписанная программа из пользовательской папки: $n ($($k.T))" -Detail $det -Fix $script:FixRemoveRunValue -FixText 'убрать из автозапуска (файл не удаляется)' -Data $data -Explicit -Manual 'если программа незнакома - убрать по номеру'
                } elseif ($risk -eq 'WARN') {
                    $flag++
                    Add-Finding -Level WARN -Title "Автозапуск через сценарий: $n ($($k.T))" -Detail (@("команда: $(Hide-Secrets $v)") + $det) -Fix $script:FixRemoveRunValue -FixText 'убрать из автозапуска' -Data $data -Explicit -Manual 'если сам такого не настраивал - показать отчёт'
                } else {
                    $fine += "$n -> $exe ($(Get-SignerText $sg)) [$($k.T)]"
                }
            }
        }
        if ($fine.Count) { Add-Finding -Level INFO -Title "Автозапуск из реестра: записей без замечаний - $($fine.Count)" -Detail $fine }
        if ($flag -eq 0) { Add-Finding -Level OK -Title 'Автозапуск из реестра: подозрительного нет' }
    }

    Invoke-Check 'папки автозагрузки' {
        $dirs = @(@{ D = [Environment]::GetFolderPath('CommonStartup'); T = 'для всех' })
        foreach ($up in @(Get-AllProfiles)) { $dirs += @{ D = (Join-P $up.Profile 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup'); T = $up.Name } }
        $fine = @(); $flag = 0
        foreach ($d in $dirs) {
            if (-not $d.D) { continue }
            foreach ($f in @(Get-ChildItem -LiteralPath $d.D -File -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne 'desktop.ini' })) {
                $data = @{ Paths = @($f.FullName) }
                if ($f.Extension -eq '.lnk') {
                    $tg = Get-LnkTarget $f.FullName
                    $sg = Get-Signer $tg
                    if ($tg -and (Test-DeadTarget '' $tg $sg)) {
                        $flag++
                        Add-Finding -Level WARN -Title "Ярлык в автозагрузке ведёт на несуществующий файл: $($f.Name) ($($d.T))" -Detail @("цель: $tg") -Fix $script:FixMoveFile -FixText 'убрать мёртвый ярлык (копия в backup)' -Data $data -Explicit:$script:Ctx.Differs
                    } elseif ($tg -and -not (Test-ValidSigned $sg) -and $sg -ne 'FILE NOT FOUND' -and (Test-UserWritablePath $tg)) {
                        $flag++
                        Add-Finding -Level WARN -Title "В автозагрузке неподписанная программа из пользовательской папки: $($f.Name) ($($d.T))" -Detail @("цель: $tg") -Fix $script:FixMoveFile -FixText 'убрать ярлык из автозагрузки (копия в backup)' -Data $data -Explicit
                    } else { $fine += "$($f.Name) -> $tg ($(Get-SignerText $sg)) [$($d.T)]" }
                } elseif ($f.Extension -match '(?i)^\.(vbs|vbe|js|jse|wsf|hta|bat|cmd|ps1|scr|pif|com)$') {
                    $flag++
                    Add-Finding -Level BAD -Title "В автозагрузке лежит сценарий: $($f.Name) ($($d.T))" -Detail @($f.FullName, "изменён $($f.LastWriteTime.ToString('dd.MM.yyyy HH:mm'))") -Fix $script:FixMoveFile -FixText 'убрать файл из автозагрузки (копия в backup)' -Data $data -Explicit -Manual 'если сам его туда не клал - убрать по номеру'
                } else {
                    $sg = Get-Signer $f.FullName
                    if ($f.Extension -eq '.exe' -and -not (Test-ValidSigned $sg)) {
                        $flag++
                        Add-Finding -Level WARN -Title "В автозагрузке неподписанная программа: $($f.Name) ($($d.T))" -Detail @($f.FullName) -Fix $script:FixMoveFile -FixText 'убрать файл из автозагрузки (копия в backup)' -Data $data -Explicit
                    } else { $fine += "$($f.Name) [$($d.T)]" }
                }
            }
        }
        if ($fine.Count) { Add-Finding -Level INFO -Title "Папки автозагрузки: без замечаний - $($fine.Count)" -Detail $fine }
        if ($flag -eq 0) { Add-Finding -Level OK -Title 'Папки автозагрузки: подозрительного нет' }
    }

    Invoke-Check 'задачи планировщика' {
        $fine = @(); $flag = 0
        foreach ($t in @(Get-ScheduledTask -ErrorAction SilentlyContinue | Sort-Object TaskPath, TaskName)) {
            $inMs = ($t.TaskPath -like '\Microsoft\*')
            $full = "$($t.TaskPath)$($t.TaskName)"
            $data = @{ TaskPath = "$($t.TaskPath)"; TaskName = "$($t.TaskName)"; DisableOnly = $false }
            foreach ($a in @($t.Actions)) {
                if (-not ($a.PSObject.Properties.Name -contains 'Execute') -or -not $a.Execute) { continue }
                $cmd = "$($a.Execute) $($a.Arguments)"
                $exe = Get-ExePath "$($a.Execute)"
                $sg = Get-Signer $exe
                $risk = Get-CommandRisk $cmd
                if ($inMs -and $risk -ne 'BAD' -and ((Test-MsSigned $sg) -or $sg -eq 'FILE NOT FOUND' -or $sg -eq 'no path')) { continue }
                $det = @("файл: $exe ($(Get-SignerText $sg))", "состояние: $($t.State); автор: $($t.Author)")
                $dead = Test-DeadTarget $cmd "$exe" $sg
                if ("$($t.State)" -eq 'Disabled') {
                    # отключённая задача не запускается; показываем только как справку
                    if ($risk -or $dead -or -not (Test-ValidSigned $sg)) { $fine += "ОТКЛЮЧЕНА: $full -> $(Hide-Secrets $cmd 80)" }
                    continue
                }
                if ($risk -eq 'BAD') {
                    $flag++; $d2 = $data.Clone(); $d2.DisableOnly = $true
                    Add-Finding -Level BAD -Title "Задача планировщика похожа на вредоносную: $full" -Detail (@("команда: $(Hide-Secrets $cmd)") + $det) -Fix $script:FixRemoveTask -FixText 'отключить задачу' -Data $d2 -Explicit -Manual 'если сам такого не настраивал - отключить по номеру и запустить полную проверку Defender'
                } elseif ($dead) {
                    $flag++; $d2 = $data.Clone(); $d2.DisableOnly = $true
                    Add-Finding -Level WARN -Title "Задача планировщика запускает несуществующий файл: $full" -Detail $det -Fix $script:FixRemoveTask -FixText 'отключить мёртвую задачу (не удаляется; копия XML в backup)' -Data $d2
                } elseif (-not (Test-ValidSigned $sg) -and $sg -ne 'FILE NOT FOUND' -and $sg -ne 'no path' -and (Test-UserWritablePath "$exe")) {
                    $flag++; $d2 = $data.Clone(); $d2.DisableOnly = $true
                    Add-Finding -Level WARN -Title "Задача запускает неподписанную программу из пользовательской папки: $full" -Detail $det -Fix $script:FixRemoveTask -FixText 'отключить задачу' -Data $d2 -Explicit -Manual 'если программа незнакома - отключить по номеру'
                } elseif ($risk -eq 'WARN' -and -not $inMs) {
                    $flag++; $d2 = $data.Clone(); $d2.DisableOnly = $true
                    Add-Finding -Level WARN -Title "Задача запускает сценарий: $full" -Detail (@("команда: $(Hide-Secrets $cmd)") + $det) -Fix $script:FixRemoveTask -FixText 'отключить задачу' -Data $d2 -Explicit -Manual 'если сам такого не настраивал - показать отчёт'
                } elseif ($inMs) {
                    $flag++
                    Add-Finding -Level WARN -Title "В системной папке задач \Microsoft\ чужая программа: $full" -Detail $det -Manual 'показать отчёт'
                } else { $fine += "$full -> $exe ($(Get-SignerText $sg))" }
            }
        }
        if ($fine.Count) { Add-Finding -Level INFO -Title "Задачи планировщика от программ: без замечаний - $($fine.Count)" -Detail $fine }
        if ($flag -eq 0) { Add-Finding -Level OK -Title 'Планировщик: подозрительных задач нет' }
    }

    Invoke-Check 'службы' {
        $fine = @(); $flag = 0
        foreach ($s in @(Get-CimInstance Win32_Service | Sort-Object Name)) {
            $exe = Get-ExePath "$($s.PathName)"
            $sg = Get-Signer $exe
            if (Test-MsSigned $sg) { continue }
            if ($sg -eq 'no path') { continue }   # защищённые службы Windows путь не показывают - судить не о чем
            $det = @("файл: $exe ($(Get-SignerText $sg))", "запуск: $($s.StartMode); сейчас: $($s.State)")
            if (Test-DeadTarget "$($s.PathName)" "$exe" $sg) {
                if ("$($s.StartMode)" -ne 'Disabled') { $flag++; Add-Finding -Level WARN -Title "Служба без файла (остаток удалённой программы): $($s.Name)" -Detail $det -Fix $script:FixDeleteService -FixText 'удалить запись службы (файла всё равно нет)' -Data @{ Name = "$($s.Name)" } -Explicit }
            } elseif (-not (Test-ValidSigned $sg) -and $sg -ne 'FILE NOT FOUND' -and $sg -ne 'no path') {
                # многие честные программы свои службы не подписывают (или подписали давно): если файл лежит в защищённой папке
                # установленной программы - это справка. Изменённый файл и отозванная подпись сюда не попадают
                $owner = ''; if ($sg -match '^NotSigned' -or $sg -match '^(UnknownError|NotTrusted) \| .+ \| expired$') { $owner = Get-OwnerProgram "$exe" }
                if ($owner) { $fine += "$($s.Name) -> $exe ($(Get-SignerText $sg); $owner)"; continue }
                $flag++
                $lvl = 'WARN'; if (Test-UserWritablePath "$exe") { $lvl = 'BAD' }
                $what = 'с неподписанным файлом'; if ($sg -notmatch '^NotSigned') { $what = 'с файлом, подпись которого не подтверждена' }
                Add-Finding -Level $lvl -Title "Служба ${what}: $($s.Name) ($($s.DisplayName))" -Detail $det -Manual 'выяснить, что это за программа; если незнакома - показать отчёт'
            } else { $fine += "$($s.Name) -> $exe ($(Get-SignerText $sg))" }
        }
        if ($fine.Count) { Add-Finding -Level INFO -Title "Службы сторонних программ: без замечаний - $($fine.Count)" -Detail $fine }
        if ($flag -eq 0) { Add-Finding -Level OK -Title 'Службы: подозрительного нет' }
    }

    Invoke-Check 'драйверы' {
        $flag = 0; $n = 0
        foreach ($d in @(Get-CimInstance Win32_SystemDriver | Sort-Object Name)) {
            $exe = Get-ExePath "$($d.PathName)"
            $sg = Get-Signer $exe
            if (Test-MsSigned $sg) { continue }
            $n++
            if (Test-DeadTarget "$($d.PathName)" "$exe" $sg) {
                if ("$($d.StartMode)" -ne 'Disabled') { $flag++; Add-Finding -Level WARN -Title "Драйвер без файла (остаток удалённой программы): $($d.Name)" -Detail @("файл: $exe") -Fix $script:FixDeleteService -FixText 'удалить запись драйвера (файла всё равно нет)' -Data @{ Name = "$($d.Name)" } -Explicit }
            } elseif (-not (Test-ValidSigned $sg) -and $sg -ne 'FILE NOT FOUND' -and $sg -ne 'no path') {
                $flag++
                Add-Finding -Level WARN -Title "Драйвер с неподписанным файлом: $($d.Name)" -Detail @("файл: $exe ($(Get-SignerText $sg))") -Manual 'показать отчёт'
            }
        }
        if ($flag -eq 0) { Add-Finding -Level OK -Title "Драйверы: все сторонние ($n) подписаны, мёртвых нет" }
    }

    Invoke-Check 'подмена оболочки и перехват запуска программ' {
        $bad = 0
        $wl = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
        $shell = "$(Get-RegValue $wl 'Shell')".Trim()
        if ($shell -and $shell -ine 'explorer.exe') { $bad++; Add-Finding -Level BAD -Title "Вместо Проводника при входе запускается: $(Hide-Secrets $shell)" -Fix $script:FixRegValueSet -FixText 'вернуть explorer.exe' -Data @{ Path = $wl; Name = 'Shell'; Value = 'explorer.exe'; Type = 'String' } }
        $ui = "$(Get-RegValue $wl 'Userinit')".Trim().TrimEnd(',').Trim()
        $uiDef = Join-P $env:SystemRoot 'system32\userinit.exe'
        if ($ui -and $ui -ine $uiDef -and $ui -ine 'userinit.exe') { $bad++; Add-Finding -Level BAD -Title "При входе в систему запускается посторонняя программа (Userinit): $(Hide-Secrets $ui)" -Fix $script:FixRegValueSet -FixText 'вернуть стандартное значение' -Data @{ Path = $wl; Name = 'Userinit'; Value = "$uiDef,"; Type = 'String' } }
        foreach ($h in $script:UserHives) {
            $k = "$($h.Hive)\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
            $us = Get-RegValue $k 'Shell'
            if ($us) { $bad++; Add-Finding -Level BAD -Title "У пользователя $($h.Name) подменена оболочка: $(Hide-Secrets "$us")" -Fix $script:FixRegValueRemove -FixText 'удалить подмену' -Data @{ Path = $k; Name = 'Shell' } }
        }
        foreach ($k in @('HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows')) {
            $ai = "$(Get-RegValue $k 'AppInit_DLLs')".Trim()
            if ($ai) { $bad++; Add-Finding -Level BAD -Title "В каждую программу подгружается посторонняя библиотека (AppInit_DLLs): $ai" -Detail @((ConvertTo-NativeRegPath $k)) -Fix $script:FixRegValueSet -FixText 'очистить AppInit_DLLs' -Data @{ Path = $k; Name = 'AppInit_DLLs'; Value = ''; Type = 'String' } -Explicit -Manual 'показать отчёт; так делают и вирусы, и некоторые старые антивирусы' }
        }
        foreach ($root in @('HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options')) {
            foreach ($k in @(Get-ChildItem -LiteralPath $root -ErrorAction SilentlyContinue)) {
                $dbg = Get-RegValue $k.PSPath 'Debugger'
                if (-not $dbg) { continue }
                $bad++
                $data = @{ Path = $k.PSPath; Name = 'Debugger' }
                if ($k.PSChildName -match '(?i)^(sethc|utilman|osk|magnify|narrator|displayswitch|atbroker)\.exe$') {
                    Add-Finding -Level BAD -Title "Чёрный ход на экране входа: вместо $($k.PSChildName) запускается $(Hide-Secrets "$dbg")" -Fix $script:FixRegValueRemove -FixText 'удалить перехват' -Data $data
                } elseif ($k.PSChildName -match '(?i)^taskmgr\.exe$' -and "$dbg" -match '(?i)procexp|SystemInformer|ProcessHacker|TaskExplorer') {
                    $bad--
                    Add-Finding -Level INFO -Title "Диспетчер задач заменён на другую программу: $(Hide-Secrets "$dbg")" -Detail @('так делает Process Explorer / System Informer по твоей же настройке')
                } elseif ($k.PSChildName -match '(?i)(MsMpEng|MpCmdRun|SecurityHealth|avp|taskmgr|regedit|msconfig|procexp|autoruns|rstrui)') {
                    Add-Finding -Level BAD -Title "Перехвачен запуск $($k.PSChildName): вместо неё стартует $(Hide-Secrets "$dbg")" -Detail @('так вирусы не дают запустить антивирус и диспетчер задач (а Process Explorer так честно заменяет диспетчер задач)') -Fix $script:FixRegValueRemove -FixText 'удалить перехват' -Data $data -Explicit
                } else {
                    Add-Finding -Level WARN -Title "Перехвачен запуск $($k.PSChildName): вместо неё стартует $(Hide-Secrets "$dbg")" -Fix $script:FixRegValueRemove -FixText 'удалить перехват' -Data $data -Explicit
                }
            }
        }
        if ($bad -eq 0) { Add-Finding -Level OK -Title 'Оболочка и запуск программ не перехвачены' }
    }

    Invoke-Check 'скрытый автозапуск через WMI' {
        $std = '(?i)^(SCM Event Log (Filter|Consumer)|BVT(Filter|Consumer))$'
        $cons = @(Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer -ErrorAction SilentlyContinue | Where-Object { "$($_.Name)" -notmatch $std })
        $act = @($cons | Where-Object { $_.CimClass.CimClassName -match 'CommandLineEventConsumer|ActiveScriptEventConsumer' })
        if ($act.Count) {
            Add-Finding -Level WARN -Title "Есть скрытый автозапуск через WMI: $($act.Count)" -Detail @($act | ForEach-Object { "$($_.CimClass.CimClassName): $($_.Name) | $(Hide-Secrets "$($_.CommandLineTemplate)$($_.ScriptFileName)")" }) -Manual 'редкий способ; им пользуются вирусы и иногда утилиты производителя ноутбука. Показать отчёт'
        } else { Add-Finding -Level OK -Title 'Скрытого автозапуска через WMI нет' }
    }
}

# ================================================================ 7. УЧЁТНЫЕ ЗАПИСИ И УДАЛЁННЫЙ ДОСТУП
$script:RemoteToolsRx = '(?i)(AnyDesk|TeamViewer|RustDesk|Ammyy|Remote Utilities|Remote Manipulator|RMS (Host|Viewer|Удал)|LiteManager|Radmin|UltraVNC|TightVNC|RealVNC|VNC Server|TigerVNC|Supremo|AeroAdmin|ScreenConnect|ConnectWise|LogMeIn|GoToAssist|GoTo Resolve|GoToMyPC|Splashtop|\bAtera|NetSupport|Getscreen|RuDesktop|DWAgent|DWService|MeshAgent|Mesh Agent|Chrome Remote Desktop|Удаленный рабочий стол Chrome|Parsec|HopToDesk|Iperius Remote|Zoho Assist|UltraViewer|NoMachine|AweSun|\bToDesk|SimpleHelp|Action1|Tactical RMM|ZeroTier|Tailscale|Hamachi|Ассистент)'
$script:FixDisableUser = {
    param($f)
    Disable-LocalUser -SID $f.Data.Sid
    Add-Change 'local user disabled' "$($f.Data.Name)"
    return 'учётная запись отключена'
}

function Invoke-AccountChecks {
    Start-Section 'Учётные записи и удалённый доступ'

    Invoke-Check 'пользователи и администраторы' {
        $users = @(Get-LocalUser)
        $det = @()
        foreach ($u in $users) {
            if (-not $u.Enabled) { continue }
            $ll = 'никогда'; if ($u.LastLogon) { $ll = $u.LastLogon.ToString('dd.MM.yyyy') }
            $det += "$($u.Name) (последний вход: $ll)"
            if ("$($u.SID)" -match '-501$') { Add-Finding -Level WARN -Title "Включена учётная запись Гость ($($u.Name))" -Fix $script:FixDisableUser -FixText 'отключить Гостя' -Data @{ Sid = "$($u.SID)"; Name = "$($u.Name)" } }
            if ("$($u.SID)" -match '-500$') { Add-Finding -Level WARN -Title "Включена встроенная учётная запись Администратор ($($u.Name))" -Detail @('у неё нет запроса UAC; её часто включают активаторы и "помощники"') -Fix $script:FixDisableUser -FixText 'отключить встроенного Администратора' -Data @{ Sid = "$($u.SID)"; Name = "$($u.Name)" } -Explicit -Manual 'убедиться, что есть другая учётная запись с правами администратора, и отключить по номеру' }
        }
        Add-Finding -Level INFO -Title "Включённых учётных записей: $($det.Count)" -Detail $det
        $adm = @()
        try { $adm = @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop | ForEach-Object { "$($_.Name)" }) } catch { }
        if ($adm.Count) { Add-Finding -Level INFO -Title "Администраторы: $($adm -join ', ')" }
        $wl = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
        if ("$(Get-RegValue $wl 'AutoAdminLogon')" -eq '1' -and $null -ne (Get-RegValue $wl 'DefaultPassword')) {
            Add-Finding -Level WARN -Title 'Автоматический вход: пароль учётной записи лежит в реестре открытым текстом' -Manual 'netplwiz > вернуть галочку "Требовать ввод имени пользователя и пароля"'
        }
    }

    Invoke-Check 'удалённый рабочий стол и удалённые службы' {
        $ts = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
        $deny = Get-RegValue $ts 'fDenyTSConnections'
        if ($null -ne $deny -and [int]$deny -eq 0) { Add-Finding -Level WARN -Title 'Включён удалённый рабочий стол (RDP)' -Fix $script:FixRegValueSet -FixText 'выключить удалённый рабочий стол' -Data @{ Path = $ts; Name = 'fDenyTSConnections'; Value = 1 } -Manual 'если не пользуешься - выключить' }
        else { Add-Finding -Level OK -Title 'Удалённый рабочий стол выключен' }
        $ra = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance' 'fAllowToGetHelp'
        if ($null -ne $ra -and [int]$ra -eq 1) { Add-Finding -Level INFO -Title 'Удалённый помощник Windows разрешён (работает только по приглашению)' }
        foreach ($s in @(Get-Service -Name sshd, WinRM, RemoteRegistry, TlntSvr -ErrorAction SilentlyContinue | Where-Object { "$($_.Status)" -eq 'Running' })) {
            Add-Finding -Level WARN -Title "Работает служба удалённого управления: $($s.Name) ($($s.DisplayName))" -Manual 'если не настраивал сам: services.msc > остановить и поставить тип запуска "Отключена"'
        }
    }

    Invoke-Check 'программы удалённого доступа' {
        $lines = @(Get-InstalledNames $script:RemoteToolsRx)
        foreach ($s in @(Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Where-Object { "$($_.Name) $($_.DisplayName)" -match $script:RemoteToolsRx })) { $lines += "служба $($s.Name) ($($s.State))" }
        foreach ($p in @(Get-Process -ErrorAction SilentlyContinue | Where-Object { "$($_.ProcessName)" -match $script:RemoteToolsRx } | ForEach-Object { $_.ProcessName } | Sort-Object -Unique)) { $lines += "запущен процесс $p" }
        # по одному пункту на программу, чтобы знакомую можно было занести в список «это нормально»
        $byTool = @{}; $order = @()
        foreach ($l in @($lines | Sort-Object -Unique)) {
            $k = [regex]::Match($l, $script:RemoteToolsRx).Value
            if (-not $byTool.ContainsKey($k)) { $byTool[$k] = @(); $order += $k }
            $byTool[$k] += $l
        }
        foreach ($k in $order) {
            if ($k -match '(?i)Tailscale|ZeroTier|Hamachi') {
                Add-Finding -Level WARN -Title "Частная сеть с доступом к этому компьютеру: $k" -Detail ($byTool[$k] + @('связывает твои устройства напрямую; к компьютеру сможет подключиться тот, кто войдёт в твою учётную запись этой сети')) -Manual 'если ставил сам и пользуешься - оставить; иначе удалить (Параметры > Приложения)'
            } else {
                Add-Finding -Level WARN -Title "Программа удалённого доступа: $k" -Detail ($byTool[$k] + @('через неё компьютером управляют издалека; это главный инструмент телефонных мошенников')) -Manual 'если ставил сам и пользуешься - оставить; иначе удалить (Параметры > Приложения)'
            }
        }
        if ($order.Count -eq 0) { Add-Finding -Level OK -Title 'Программ удалённого доступа нет' }
    }
}

# ================================================================ 8. ПРОГРАММЫ
# известный навязанный софт (\b перед Torrent: qBittorrent сюда не относится)
$script:PupRx = '(?i)(DriverPack|Driver Booster|Driver Easy|DriverMax|IObit|Advanced SystemCare|MediaGet|\bZona\b|\buTorrent|\bBitTorrent|Амиго|Amigo|Спутник@Mail|Mail\.Ru Агент|Агент Mail\.Ru|Guard@Mail|Кнопка .Яндекс|Менеджер браузеров|Browser Manager|Яндекс\.?\s?Элементы|WebAdvisor|ByteFence|Segurazo|PC Accelerate|OneLaunch|Wave Browser|PC App Store|Web Companion|Reimage|Restoro|MyCleanPC|Slimware|WinZip Driver|Avast Secure Browser|AVG Secure Browser|Opera GX Assistant|Hola VPN|TLauncher)'
function Invoke-ProgramChecks {
    Start-Section 'Программы'

    Invoke-Check 'навязанные и нежелательные программы' {
        $pup = @(Get-InstalledNames $script:PupRx)
        if ($pup.Count) { Add-Finding -Level WARN -Title "Навязанные и нежелательные программы: $($pup.Count)" -Detail $pup -Manual 'удалить через Параметры > Приложения > Установленные приложения' }
        else { Add-Finding -Level OK -Title 'Известных навязанных программ нет' }
    }

    Invoke-Check 'общий список' {
        $vis = @($script:Programs | Where-Object { -not $_.Hidden })
        Add-Finding -Level INFO -Title "Установленных программ: $($vis.Count) (полный список - в report.txt)"
        if ($script:ProgramsDumped) { return }
        $script:ProgramsDumped = $true
        Out-ReportOnly ''
        Out-ReportOnly '--- установленные программы ---'
        foreach ($p in ($vis | Sort-Object Name)) { Out-ReportOnly "  $($p.Name) | $($p.Version) | $($p.Publisher)" }
        Out-ReportOnly ''
    }
}

# ================================================================ 9. РЕКЛАМА И СЛЕЖКА WINDOWS
# рекламные заглушки самой Microsoft: данных пользователя в них нет
$script:PromoMs = @(
    'Microsoft.BingNews', 'Microsoft.BingSearch', 'Microsoft.Copilot', 'Microsoft.MicrosoftOfficeHub', 'Microsoft.PowerAutomateDesktop',
    'Microsoft.Windows.DevHome', 'Microsoft.WindowsFeedbackHub', 'Microsoft.Edge.GameAssist', 'Microsoft.549981C3F5F10', 'Microsoft.MixedReality.Portal',
    'Microsoft.Microsoft3DViewer', 'Microsoft.3DBuilder', 'Microsoft.Print3D', 'Microsoft.Getstarted', 'Microsoft.Messaging', 'Microsoft.OneConnect', 'Microsoft.SkypeApp',
    'Microsoft.StartExperiencesApp', 'Microsoft.MicrosoftJournal', 'MicrosoftCorporationII.MicrosoftFamily'
)
# предустановленные игры и приложения сторонних фирм: ими могли пользоваться, внутри могут быть свои данные - только по номеру
$script:PromoThird = @(
    'Clipchamp.Clipchamp', 'MicrosoftTeams', '7EE7776C.LinkedInforWindows', 'king.com.*', '*.TikTok', 'Facebook.*', 'Disney.*', 'AmazonVideo.PrimeVideo',
    '*CandyCrush*', '*BubbleWitch*', '*.Netflix', '*HiddenCity*', '*MarchofEmpires*', '*.Twitter'
)
function Test-NameLike { param([string]$Name, [string[]]$Patterns) foreach ($pat in $Patterns) { if ($Name -like $pat) { return $true } }; return $false }

function Get-PrivacySettings {
    $u = $script:Ctx.MainHive
    $cdm = "$u\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
    return @(
        @{ P = $cdm; N = 'SilentInstalledAppsEnabled'; V = 0; D = 'тихая установка рекламных приложений' },
        @{ P = $cdm; N = 'PreInstalledAppsEnabled'; V = 0; D = 'предустановка рекламных приложений' },
        @{ P = $cdm; N = 'OemPreInstalledAppsEnabled'; V = 0; D = 'рекламные приложения производителя' },
        @{ P = $cdm; N = 'SoftLandingEnabled'; V = 0; D = 'советы и предложения' },
        @{ P = $cdm; N = 'SystemPaneSuggestionsEnabled'; V = 0; D = 'предложения в меню Пуск' },
        @{ P = $cdm; N = 'RotatingLockScreenOverlayEnabled'; V = 0; D = 'реклама на экране блокировки (картинка остаётся)' },
        @{ P = $cdm; N = 'SubscribedContent-310093Enabled'; V = 0; D = 'экран "Добро пожаловать" после обновлений' },
        @{ P = $cdm; N = 'SubscribedContent-338387Enabled'; V = 0; D = 'факты и советы на экране блокировки' },
        @{ P = $cdm; N = 'SubscribedContent-338388Enabled'; V = 0; D = 'предложения в Пуске' },
        @{ P = $cdm; N = 'SubscribedContent-338389Enabled'; V = 0; D = 'советы по использованию Windows' },
        @{ P = $cdm; N = 'SubscribedContent-338393Enabled'; V = 0; D = 'предложения в Параметрах' },
        @{ P = $cdm; N = 'SubscribedContent-353694Enabled'; V = 0; D = 'предложения в Параметрах' },
        @{ P = $cdm; N = 'SubscribedContent-353696Enabled'; V = 0; D = 'предложения в Параметрах' },
        @{ P = $cdm; N = 'SubscribedContent-353698Enabled'; V = 0; D = 'предложения на временной шкале' },
        @{ P = "$u\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement"; N = 'ScoobeSystemSettingEnabled'; V = 0; D = 'напоминания "завершите настройку устройства"' },
        @{ P = "$u\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo"; N = 'Enabled'; V = 0; D = 'рекламный идентификатор' },
        @{ P = "$u\Software\Microsoft\Windows\CurrentVersion\Privacy"; N = 'TailoredExperiencesWithDiagnosticDataEnabled'; V = 0; D = 'персональная реклама по диагностическим данным' },
        @{ P = "$u\Software\Microsoft\InputPersonalization"; N = 'RestrictImplicitInkCollection'; V = 1; D = 'сбор рукописного ввода' },
        @{ P = "$u\Software\Microsoft\InputPersonalization"; N = 'RestrictImplicitTextCollection'; V = 1; D = 'сбор набранного текста' },
        @{ P = "$u\Software\Microsoft\InputPersonalization\TrainedDataStore"; N = 'HarvestContacts'; V = 0; D = 'сбор контактов для подсказок ввода' },
        @{ P = "$u\Software\Microsoft\Personalization\Settings"; N = 'AcceptedPrivacyPolicy'; V = 0; D = 'согласие на персонализацию ввода' },
        @{ P = "$u\Software\Microsoft\Siuf\Rules"; N = 'NumberOfSIUFInPeriod'; V = 0; D = 'просьбы оставить отзыв' },
        @{ P = "$u\Software\Policies\Microsoft\Windows\Explorer"; N = 'DisableSearchBoxSuggestions'; V = 1; D = 'результаты из интернета в поиске Пуска' },
        @{ P = "$u\Software\Microsoft\Windows\CurrentVersion\Search"; N = 'BingSearchEnabled'; V = 0; D = 'поиск Bing в меню Пуск' },
        @{ P = "$u\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"; N = 'Start_IrisRecommendations'; V = 0; D = 'рекомендации в Пуске' },
        @{ P = "$u\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"; N = 'ShowSyncProviderNotifications'; V = 0; D = 'реклама OneDrive в Проводнике' },
        @{ P = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'; N = 'PublishUserActivities'; V = 0; D = 'журнал действий' },
        @{ P = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'; N = 'UploadUserActivities'; V = 0; D = 'отправка журнала действий в Microsoft' },
        @{ P = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization'; N = 'DODownloadMode'; V = 0; D = 'раздача обновлений другим компьютерам' },
        @{ P = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'; N = 'StartupBoostEnabled'; V = 0; D = 'Edge стартует вместе с Windows' },
        @{ P = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'; N = 'BackgroundModeEnabled'; V = 0; D = 'Edge работает в фоне после закрытия' }
    )
}
$script:FixPrivacy = {
    param($f)
    $n = 0; $fail = 0
    foreach ($s in @($f.Data.Todo)) {
        try { Set-RegValueSafe $s.P $s.N $s.V 'DWord'; $n++ } catch { $fail++; Out-ReportOnly "       не записалось: $($s.N) - $($_.Exception.Message)" }
    }
    if ($fail -and $n -eq 0) { throw "ни одна настройка не записалась ($fail)" }
    $t = "выключено настроек: $n"; if ($fail) { $t += ", не записалось: $fail (защищены системой)" }
    return "$t; подействует после перезахода в систему"
}
$script:FixPromoApps = {
    param($f)
    $n = 0; $fail = 0
    foreach ($full in @($f.Data.Packages)) {
        try {
            if ($f.Data.OtherUser) { Remove-AppxPackage -Package $full -User $f.Data.Sid -ErrorAction Stop } else { Remove-AppxPackage -Package $full -ErrorAction Stop }
            Add-Change 'appx removed' $full; $n++
        } catch { $fail++; Out-ReportOnly "       не удалилось: $full - $(($_.Exception.Message -split "`n")[0])" }
    }
    try {
        foreach ($p in @(Get-AppxProvisionedPackage -Online -ErrorAction Stop | Where-Object { Test-NameLike "$($_.DisplayName)" $f.Data.Patterns })) {
            try { Remove-AppxProvisionedPackage -Online -PackageName $p.PackageName -ErrorAction Stop | Out-Null; Add-Change 'appx deprovisioned' "$($p.PackageName)" } catch { }
        }
    } catch { }
    if ($fail -and $n -eq 0) { throw "не удалось удалить ни одного приложения ($fail)" }
    $t = "удалено приложений: $n"; if ($fail) { $t += ", не удалилось: $fail" }
    return $t
}
$script:FixDisableTasks = {
    param($f)
    $n = 0
    foreach ($t in @($f.Data.Tasks)) {
        $tp = $t.Substring(0, $t.LastIndexOf('\') + 1); $tn = $t.Substring($t.LastIndexOf('\') + 1)
        try { Disable-ScheduledTask -TaskPath $tp -TaskName $tn -ErrorAction Stop | Out-Null; Add-Change 'task disabled' $t; $n++ } catch { }
    }
    return "отключено задач: $n"
}

function Invoke-PrivacyChecks {
    Start-Section 'Реклама и слежка Windows'

    Invoke-Check 'настройки рекламы и сбора данных' {
        $all = @(Get-PrivacySettings)
        $todo = @()
        foreach ($s in $all) { $cur = Get-RegValue $s.P $s.N; if ($null -eq $cur -or "$cur" -ne "$($s.V)") { $todo += $s } }
        if ($todo.Count) {
            Add-Finding -Level WARN -Title "Реклама, подсказки и сбор данных Windows: не выключено $($todo.Count) из $($all.Count)" -Detail @($todo | ForEach-Object { $_.D }) `
                -Fix $script:FixPrivacy -FixText "выключить всё перечисленное для пользователя $($script:Ctx.MainName) (старые значения сохраняются; на работу программ не влияет; в Параметрах и в Edge местами появится надпись «управляется организацией» - это от этих настроек)" -Data @{ Todo = $todo }
        } else { Add-Finding -Level OK -Title "Реклама, подсказки и сбор данных Windows выключены ($($all.Count) настроек)" }
    }

    Invoke-Check 'задачи сбора телеметрии' {
        $want = @('\Microsoft\Windows\Customer Experience Improvement Program\Consolidator', '\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip', '\Microsoft\Windows\Feedback\Siuf\DmClient', '\Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload')
        $on = @()
        foreach ($t in $want) {
            $tp = $t.Substring(0, $t.LastIndexOf('\') + 1); $tn = $t.Substring($t.LastIndexOf('\') + 1)
            $st = Get-ScheduledTask -TaskPath $tp -TaskName $tn -ErrorAction SilentlyContinue
            if ($st -and "$($st.State)" -ne 'Disabled') { $on += $t }
        }
        if ($on.Count) { Add-Finding -Level WARN -Title "Задачи программы улучшения качества и сбора отзывов включены: $($on.Count)" -Detail $on -Fix $script:FixDisableTasks -FixText 'отключить эти задачи' -Data @{ Tasks = $on } }
        else { Add-Finding -Level OK -Title 'Задачи сбора отзывов и CEIP отключены' }
    }

    Invoke-Check 'рекламные приложения' {
        $pk = @()
        if ($script:Ctx.Differs) { $pk = @(Get-AppxPackage -User $script:Ctx.MainSid -ErrorAction Stop) } else { $pk = @(Get-AppxPackage -ErrorAction Stop) }
        $promo = @($pk | Where-Object { Test-NameLike "$($_.Name)" $script:PromoMs })
        $third = @($pk | Where-Object { Test-NameLike "$($_.Name)" $script:PromoThird })
        if ($promo.Count) {
            Add-Finding -Level WARN -Title "Рекламные встроенные приложения Microsoft: $($promo.Count)" -Detail @($promo | ForEach-Object { "$($_.Name)" } | Sort-Object -Unique) `
                -Fix $script:FixPromoApps -FixText 'удалить эти приложения (любое можно вернуть из Microsoft Store)' -Data @{ Packages = @($promo | ForEach-Object { "$($_.PackageFullName)" }); Patterns = $script:PromoMs; OtherUser = $script:Ctx.Differs; Sid = $script:Ctx.MainSid }
        } else { Add-Finding -Level OK -Title 'Рекламных встроенных приложений Microsoft нет' }
        if ($third.Count) {
            Add-Finding -Level WARN -Title "Предустановленные сторонние приложения и игры: $($third.Count)" -Detail @($third | ForEach-Object { "$($_.Name)" } | Sort-Object -Unique) `
                -Fix $script:FixPromoApps -FixText 'удалить эти приложения вместе с их данными (вернуть можно из Microsoft Store, данные - нет)' -Data @{ Packages = @($third | ForEach-Object { "$($_.PackageFullName)" }); Patterns = $script:PromoThird; OtherUser = $script:Ctx.Differs; Sid = $script:Ctx.MainSid } -Explicit -Manual 'если ими никто не пользуется - удалить по номеру'
        }
    }
}

# ================================================================ ДЕМО (ничего не проверяет и не меняет)
function Invoke-DemoChecks {
    $ok = { param($f) Start-Sleep -Milliseconds 200; return 'демо: сделано понарошку' }
    $fail = { param($f) throw 'демо: так выглядит неудача' }
    $script:Section = 'Система'
    Add-Finding -Level OK -Title 'Версия Windows актуальная: Windows 11 Pro 25H2'
    Add-Finding -Level WARN -Title 'Windows Update: не установлено обновлений: 2' -Detail @('Накопительное обновление KB0000000', 'Обновление .NET') -Manual 'Параметры > Центр обновления Windows'
    $script:Section = 'Сертификаты'
    Add-Finding -Level BAD -Title 'Корневой сертификат вне программ доверия Microsoft и Mozilla: Example Interception Root CA' -Detail @('кому выдан: CN=Example Interception Root CA, O=Example Org', 'хранилище: Доверенные корневые (Root); где лежит: компьютер') -Fix $ok -FixText 'удалить сертификат (копия .cer сохраняется)'
    Add-Finding -Level WARN -Title 'Незнакомый корневой сертификат: Example Corp Root' -Fix $ok -FixText 'удалить сертификат' -Explicit -Manual 'выяснить, какая программа его поставила'
    $script:Section = 'Защита'
    Add-Finding -Level BAD -Title 'Исключение Defender (папка/файл): C:\Example\Crack' -Fix $fail -FixText 'убрать исключение'
    Add-Finding -Level OK -Title 'Брандмауэр Windows включён во всех профилях'
    Add-Finding -Level INFO -Title 'Полная проверка Defender была 3 дн. назад'
    $script:Section = 'Реклама и слежка Windows'
    Add-Finding -Level WARN -Title 'Реклама, подсказки и сбор данных Windows: не выключено 12 из 31' -Fix $ok -FixText 'выключить всё перечисленное'
}

# ================================================================ ЗАПУСК ПРОВЕРОК, ИТОГ, ИСПРАВЛЕНИЕ
function Invoke-AllChecks {
    $script:Findings = New-Object System.Collections.ArrayList
    if ($script:DemoMode) { Invoke-DemoChecks; return }
    $script:Ctx = Get-RunContext
    $script:ProcList = $null
    $script:UserHives = @(Get-UserHives)
    $script:Programs = @(Get-Programs)
    Invoke-SystemChecks
    Invoke-ProtectionChecks
    Invoke-CertificateChecks
    Invoke-BrowserChecks
    Invoke-NetworkChecks
    Invoke-AutorunChecks
    Invoke-AccountChecks
    Invoke-ProgramChecks
    Invoke-PrivacyChecks
}

function Set-FindingNumbers {
    $n = 0
    foreach ($lvl in @('BAD', 'WARN')) {
        foreach ($f in $script:Findings) { if ($f.Level -eq $lvl -and $f.Fix) { $n++; $f.Num = $n } }
    }
}

function Show-Results {
    param([string]$Header)
    Out-Line ''
    Out-Line ('=' * 78)
    Out-Line "  $Header"
    Out-Line ('=' * 78)
    $sections = @(); foreach ($f in $script:Findings) { if ($sections -notcontains $f.Section) { $sections += $f.Section } }
    foreach ($s in $sections) {
        Out-Line ''
        Out-Line "--- $s ---" 'Cyan'
        foreach ($lvl in @('BAD', 'WARN', 'ERR', 'OK', 'INFO')) {
            foreach ($f in $script:Findings) { if ($f.Section -eq $s -and $f.Level -eq $lvl) { Show-Finding $f } }
        }
    }
}

function Show-Summary {
    param([string]$Header)
    $bad = @($script:Findings | Where-Object { $_.Level -eq 'BAD' })
    $warn = @($script:Findings | Where-Object { $_.Level -eq 'WARN' })
    $err = @($script:Findings | Where-Object { $_.Level -eq 'ERR' })
    $ok = @($script:Findings | Where-Object { $_.Level -eq 'OK' })
    Out-Line ''
    Out-Line ('=' * 78)
    Out-Line "  $Header"
    Out-Line ('=' * 78)
    Out-Line "  зелёных (хорошо): $($ok.Count)" 'Green'
    $c = 'Green'; if ($bad.Count) { $c = 'Red' }
    Out-Line "  красных (плохо):  $($bad.Count)" $c
    $c = 'Green'; if ($warn.Count) { $c = 'Yellow' }
    Out-Line "  жёлтых (посмотри сам): $($warn.Count)" $c
    if ($err.Count) { Out-Line "  проверок не выполнилось: $($err.Count)" 'Magenta' }
    if ($bad.Count) { Out-Line ''; Out-Line '  КРАСНОЕ:' 'Red'; foreach ($f in $bad) { Show-Finding $f -Short } }
    if ($warn.Count) { Out-Line ''; Out-Line '  ЖЁЛТОЕ:' 'Yellow'; foreach ($f in $warn) { Show-Finding $f -Short } }
    if ($err.Count) { Out-Line ''; Out-Line '  НЕ ПРОВЕРЕНО (ошибка самой проверки):' 'Magenta'; foreach ($f in $err) { Show-Finding $f } }
    if ($bad.Count + $warn.Count -eq 0) { Out-Line ''; Out-Line '  Всё чисто.' 'Green' }
}

function Resolve-Selection {
    # 'YES' - красное; 'ALL' - красное и жёлтое; номера и диапазоны - явно. Пункты "только по номеру" берутся только по номеру.
    param([string]$Text, $Findings)
    $pick = @{}
    $script:SelectionError = ''
    $fixable = @($Findings | Where-Object { $_.Fix -and $_.Num -gt 0 })
    foreach ($tok in @(("$Text".ToUpper() -replace '[,;]', ' ') -split '\s+' | Where-Object { $_ })) {
        if ($tok -eq 'YES' -or $tok -eq 'ДА') { foreach ($f in $fixable) { if ($f.Level -eq 'BAD' -and -not $f.Explicit) { $pick[$f.Num] = $f } } }
        elseif ($tok -eq 'ALL' -or $tok -eq 'ВСЕ' -or $tok -eq 'ВСЁ') { foreach ($f in $fixable) { if (-not $f.Explicit) { $pick[$f.Num] = $f } } }
        elseif ($tok -match '^#?(\d{1,4})$') { $n = [int]$matches[1]; foreach ($f in $fixable) { if ($f.Num -eq $n) { $pick[$f.Num] = $f } } }
        elseif ($tok -match '^#?(\d{1,4})-#?(\d{1,4})$') { $a = [int]$matches[1]; $b = [int]$matches[2]; foreach ($f in $fixable) { if ($f.Num -ge $a -and $f.Num -le $b) { $pick[$f.Num] = $f } } }
        else { $script:SelectionError = $tok }
    }
    # любое непонятное слово в ответе ("not all", "yes?") - не делаем ничего
    if ($script:SelectionError) { return @() }
    return @($pick.Keys | Sort-Object | ForEach-Object { $pick[$_] })
}

function New-RestorePoint {
    if (-not $script:IsWin -or $script:DemoMode) { return }
    $srKey = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore'
    $srOld = Get-RegValue $srKey 'SystemRestorePointCreationFrequency'
    try {
        # по умолчанию Windows разрешает одну точку в сутки; на один вызов снимаем это ограничение
        New-ItemProperty -LiteralPath $srKey -Name SystemRestorePointCreationFrequency -Value 0 -PropertyType DWord -Force | Out-Null
        Checkpoint-Computer -Description "GlowCleanWin $(Get-Date -Format 'yyyy-MM-dd HH:mm')" -RestorePointType MODIFY_SETTINGS -ErrorAction Stop -WarningVariable cpWarn -WarningAction SilentlyContinue
        if ($cpWarn) { Out-Line "  точка восстановления: $($cpWarn -join ' ')" 'Yellow' } else { Out-Line '  точка восстановления создана' 'Green' }
    } catch { Out-Line "  точка восстановления НЕ создана ($($_.Exception.Message)) - остаются копии в папке backup" 'Yellow' }
    finally {
        try {
            if ($null -eq $srOld) { Remove-ItemProperty -LiteralPath $srKey -Name SystemRestorePointCreationFrequency -ErrorAction SilentlyContinue }
            else { Set-ItemProperty -LiteralPath $srKey -Name SystemRestorePointCreationFrequency -Value $srOld }
        } catch { }
    }
}

function Invoke-Fixes {
    param($Selected)
    Out-Line ''
    Out-Line ('=' * 78)
    Out-Line "  ИСПРАВЛЕНИЕ: выбрано пунктов - $(@($Selected).Count)"
    Out-Line ('=' * 78)
    New-RestorePoint
    $okN = 0; $failN = 0
    foreach ($f in @($Selected)) {
        Out-Line ''
        Out-Line "  #$($f.Num) $($f.Title)" 'White'
        Add-Change 'FIX START' "#$($f.Num) $($f.Title)"
        $ErrorActionPreference = 'Stop'
        try {
            $res = & $f.Fix $f
            $msg = 'готово'; $last = @($res | Where-Object { $_ -is [string] }) | Select-Object -Last 1
            if ($last) { $msg = $last }
            Out-Line "       ИСПРАВЛЕНО: $msg" 'Green'
            if ($f.NeedsReboot) { $script:RebootNeeded = $true }
            $okN++
        } catch {
            Out-Line "       НЕ УДАЛОСЬ: $($_.Exception.Message)" 'Red'
            Add-Change 'FIX FAILED' "#$($f.Num) $($_.Exception.Message)"
            $failN++
        }
        $ErrorActionPreference = 'Continue'
    }
    Out-Line ''
    $c = 'Green'; if ($failN) { $c = 'Yellow' }
    Out-Line "  Исправлено: $okN, не удалось: $failN" $c
}

function Initialize-RunFolder {
    $name = "$env:COMPUTERNAME"; if (-not $name) { $name = 'PC' }
    $stamp = Get-Date -Format 'yyyy-MM-dd_HHmm'
    $candidates = @()
    if ($PSScriptRoot) { $candidates += (Join-P $PSScriptRoot 'GlowCleanWin_Reports') }
    if ($script:IsWin) { $candidates += (Join-P ([Environment]::GetFolderPath('Desktop')) 'GlowCleanWin_Reports') }
    $candidates += (Join-P ([IO.Path]::GetTempPath()) 'GlowCleanWin_Reports')
    foreach ($base in $candidates) {
        try {
            $run = Join-P $base "${name}_$stamp"
            New-Item -ItemType Directory -Path $run -Force -ErrorAction Stop | Out-Null
            $script:RunDir = $run
            $script:ReportFile = Join-P $run 'report.txt'
            $script:BackupDir = Join-P $run 'backup'
            $script:JournalFile = Join-P $base "${name}_changes.tsv"
            $ig = Join-P $base "${name}_ignore.txt"
            if (Test-PathSafe $ig) { $script:IgnoreList = @(Get-Content -LiteralPath $ig -Encoding UTF8 | ForEach-Object { "$_".Trim() } | Where-Object { $_ -and $_ -notmatch '^#' }) }
            return
        } catch { }
    }
    throw 'Не удалось создать папку для отчёта'
}

function Invoke-Main {
    Initialize-RunFolder
    $who = ''
    if ($script:IsWin) { $who = "$env:COMPUTERNAME, запущено от $([Security.Principal.WindowsIdentity]::GetCurrent().Name)" }
    Out-Line ('=' * 78)
    Out-Line "  ПРОВЕРКА КОМПЬЮТЕРА  |  GlowCleanWin $script:Version  |  $(Get-Date -Format 'dd.MM.yyyy HH:mm')"
    Out-Line "  $who"
    Out-Line ('=' * 78)
    if ($script:DemoMode) { Out-Line '  ДЕМО-РЕЖИМ: ничего не проверяется и не меняется, данные выдуманы' 'Yellow' }
    if ($script:IgnoreList.Count) { Out-Line "  подключён список «это нормально»: строк - $($script:IgnoreList.Count)" 'Gray' }
    Write-Host ''
    if (-not $script:DemoMode) { Write-Host '  Собираю данные (2-5 минут; дольше всего - поиск обновлений и проверка подписей)...' -ForegroundColor Cyan }
    Invoke-AllChecks
    if (-not $script:DemoMode -and $script:Ctx.Differs) {
        Out-Line ''
        Out-Line "  ВНИМАНИЕ: права администратора выданы другой учётной записью ($($script:Ctx.CurrentName))." 'Yellow'
        Out-Line "  Настройки пользователя проверяются и правятся для того, кто сидит за компьютером: $($script:Ctx.MainName)." 'Yellow'
    }
    Set-FindingNumbers
    Show-Results 'ПОДРОБНО ПО РАЗДЕЛАМ'
    Show-Summary 'ИТОГ'
    Save-Report

    $fixable = @($script:Findings | Where-Object { $_.Fix -and $_.Num -gt 0 })
    if ($fixable.Count -and -not $ReportOnly) {
        $red = @($fixable | Where-Object { $_.Level -eq 'BAD' -and -not $_.Explicit }).Count
        $both = @($fixable | Where-Object { -not $_.Explicit }).Count
        Out-Line ''
        Out-Line '  ЧТО ИСПРАВИТЬ? Напиши одно из:' 'White'
        Out-Line "     YES     - всё красное с автоисправлением (пунктов: $red)" 'White'
        Out-Line "     ALL     - красное и жёлтое (пунктов: $both)" 'White'
        Out-Line '     1 4 7   - только эти номера; можно диапазон 3-6; можно вместе: YES 12 15' 'White'
        Out-Line '     Enter   - ничего не менять' 'White'
        Out-Line '  Пункты с пометкой "только по номеру" выполняются только если назвать их номер.' 'Gray'
        $answer = Read-Host '  Ввод'
        Out-ReportOnly "  Ввод: $answer"
        $sel = @(Resolve-Selection $answer $script:Findings)
        if ($sel.Count) {
            Invoke-Fixes $sel
            Save-Report
            Write-Host ''
            Write-Host '  Перепроверяю...' -ForegroundColor Cyan
            Invoke-AllChecks
            Set-FindingNumbers
            Show-Summary 'ПОСЛЕ ИСПРАВЛЕНИЯ (повторная проверка)'
            if (@($script:Findings | Where-Object { $_.Fix -and $_.Num -gt 0 }).Count) { Out-Line ''; Out-Line '  Чтобы исправить оставшееся - запусти проверку ещё раз.' 'Gray' }
            if ($script:RebootNeeded) { Out-Line ''; Out-Line '  Нужна перезагрузка, чтобы изменения вступили в силу.' 'Yellow' }
        } else {
            Out-Line ''
            if ($script:SelectionError) { Out-Line "  Не понял слово «$script:SelectionError» в ответе - на всякий случай ничего не трогаю. Запусти проверку ещё раз." 'Yellow' }
            Out-Line '  Ничего не изменено.' 'Gray'
        }
    } elseif ($ReportOnly) {
        Out-Line ''
        Out-Line '  Режим "только отчёт": ничего не изменено.' 'Gray'
    }
    Out-Line ''
    Out-Line "  Отчёт:   $script:ReportFile" 'Cyan'
    if (Test-PathSafe $script:BackupDir) { Out-Line "  Копии:   $script:BackupDir" 'Cyan' }
    if (Test-PathSafe $script:JournalFile) { Out-Line "  Журнал:  $script:JournalFile" 'Cyan' }
    Save-Report
}

if ($LoadOnly) { return }
try { Invoke-Main }
catch {
    Write-Host ''
    Write-Host "ОШИБКА СКРИПТА: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "$($_.ScriptStackTrace)" -ForegroundColor DarkGray
    try { [void]$script:Report.AppendLine("ОШИБКА СКРИПТА: $($_.Exception.Message)`r`n$($_.ScriptStackTrace)"); Save-Report } catch { }
}
if (-not $NoPause) { Write-Host ''; [void](Read-Host 'Нажми Enter, чтобы закрыть окно') }
