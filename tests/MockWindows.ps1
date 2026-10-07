# Полный прогон скрипта на имитации Windows (реестр, Defender, планировщик, службы и т.д. подменены).
# Запуск: pwsh tests/MockWindows.ps1 [-Answers ALL] [-Clean]
param([string[]]$Answers = @(''), [switch]$Clean)
$ErrorActionPreference = 'Continue'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$work = Join-Path $here 'fake'; if (Test-Path $work) { Remove-Item $work -Recurse -Force }
New-Item -ItemType Directory -Path $work | Out-Null
$env:SystemRoot = 'C:\Windows'; $env:windir = 'C:\Windows'; $env:SystemDrive = 'C:'; $env:COMPUTERNAME = 'TEST-PC'
Copy-Item (Join-Path $here '../GlowCleanWin.ps1') (Join-Path $work 'GlowCleanWin.ps1')
. (Join-Path $work 'GlowCleanWin.ps1') -LoadOnly
# the test certificates get their own entries on the list
$script:OutsideProgramCa += @((Get-NameHash 'Example Interception Root CA'), (Get-NameHash 'Example Interception Sub CA'))

# ---------- fake registry
$global:Reg = New-Object System.Collections.Hashtable ([StringComparer]::OrdinalIgnoreCase)
function RK($p) { return (ConvertTo-NativeRegPath "$p").TrimEnd('\') }
function RSet($key, $name, $value, $kind = 'String') { $k = RK $key; if (-not $global:Reg.ContainsKey($k)) { $global:Reg[$k] = [ordered]@{} }; if ($null -ne $name) { $global:Reg[$k][$name] = @{ V = $value; K = $kind } } }
function Test-RegLike($p) { return ("$p" -match '^(HKLM:|HKCU:|Registry::|Microsoft\.PowerShell\.Core\\Registry::)') }
function RExists($k) { if ($global:Reg.ContainsKey($k)) { return $true }; foreach ($x in @($global:Reg.Keys)) { if ($x.StartsWith("$k\", [StringComparison]::OrdinalIgnoreCase)) { return $true } }; return $false }
class FakeKey {
    [string]$PSPath; [string]$PSChildName; [object]$Vals
    [string[]] GetValueNames() { if ($this.Vals) { return @($this.Vals.Keys) } return @() }
    [object] GetValue([string]$n) { return $this.GetValue($n, $null, $null) }
    [object] GetValue([string]$n, [object]$d) { return $this.GetValue($n, $d, $null) }
    [object] GetValue([string]$n, [object]$d, [object]$o) { if ($this.Vals -and $this.Vals.Contains($n)) { return $this.Vals[$n].V } return $d }
    [string] GetValueKind([string]$n) { return $this.Vals[$n].K }
}
function RKey($k) { $o = [FakeKey]::new(); $o.PSPath = "Microsoft.PowerShell.Core\Registry::$k"; $o.PSChildName = ($k -split '\\')[-1]; $o.Vals = $global:Reg[$k]; return $o }
$global:FakeFiles = New-Object System.Collections.Hashtable ([StringComparer]::OrdinalIgnoreCase)
function Test-WinPath($p) { return ("$p" -match '^[A-Za-z]:\\') }

function Test-Path { [CmdletBinding()] param([Parameter(Position = 0)]$Path, $LiteralPath, $PathType)
    $p = $LiteralPath; if (-not $p) { $p = $Path }
    if (Test-RegLike $p) { return (RExists (RK $p)) }
    if (Test-WinPath $p) { if ($PathType -eq 'Leaf') { return ($global:FakeFiles.ContainsKey("$p") -and $global:FakeFiles["$p"] -ne 'DIR') }; return $global:FakeFiles.ContainsKey("$p".TrimEnd('\')) -or ("$p" -eq 'C:\') }
    if (-not $p) { return $false }
    return (Microsoft.PowerShell.Management\Test-Path @PSBoundParameters)
}
function Get-Item { [CmdletBinding()] param($LiteralPath, [switch]$Force)
    if (Test-RegLike $LiteralPath) { $k = RK $LiteralPath; if (-not (RExists $k)) { throw "fake: key not found $k" }; return (RKey $k) }
    return (Microsoft.PowerShell.Management\Get-Item @PSBoundParameters)
}
function Get-ChildItem { [CmdletBinding()] param($LiteralPath, $Path, [switch]$Directory, [switch]$File, [switch]$Force, [switch]$Recurse, $Filter)
    $p = $LiteralPath; if (-not $p) { $p = $Path }
    if (Test-RegLike $p) {
        $k = RK $p; $names = @{}
        foreach ($x in @($global:Reg.Keys)) { if ($x.StartsWith("$k\", [StringComparison]::OrdinalIgnoreCase)) { $names[($x.Substring($k.Length + 1) -split '\\')[0]] = 1 } }
        foreach ($n in @($names.Keys | Sort-Object)) { RKey "$k\$n" }
        return
    }
    if (Test-WinPath $p) { return }
    if (-not (Microsoft.PowerShell.Management\Test-Path -LiteralPath $p)) { return }
    Microsoft.PowerShell.Management\Get-ChildItem @PSBoundParameters
}
function Get-ItemProperty { [CmdletBinding()] param($LiteralPath)
    $k = RK $LiteralPath; if (-not (RExists $k)) { throw "fake: no key $k" }
    $h = [ordered]@{}; if ($global:Reg[$k]) { foreach ($n in $global:Reg[$k].Keys) { $h[$n] = $global:Reg[$k][$n].V } }
    return [pscustomobject]$h
}
function New-Item { [CmdletBinding()] param($Path, $ItemType, [switch]$Force)
    if (Test-RegLike $Path) { RSet $Path $null $null; return }
    Microsoft.PowerShell.Management\New-Item @PSBoundParameters
}
function New-ItemProperty { [CmdletBinding()] param($LiteralPath, $Name, $Value, $PropertyType, [switch]$Force) RSet $LiteralPath $Name $Value $PropertyType; "junk output object" }
function Set-ItemProperty { [CmdletBinding()] param($LiteralPath, $Name, $Value) RSet $LiteralPath $Name $Value 'DWord' }
function Remove-ItemProperty { [CmdletBinding()] param($LiteralPath, $Name, [switch]$Force) $k = RK $LiteralPath; if ($global:Reg[$k]) { $global:Reg[$k].Remove($Name) } }
function Remove-Item { [CmdletBinding()] param($LiteralPath, [switch]$Recurse, [switch]$Force)
    if (Test-RegLike $LiteralPath) { $k = RK $LiteralPath; foreach ($x in @($global:Reg.Keys)) { if ($x -eq $k -or $x.StartsWith("$k\", [StringComparison]::OrdinalIgnoreCase)) { $global:Reg.Remove($x) } }; return }
    Microsoft.PowerShell.Management\Remove-Item @PSBoundParameters
}
function sc.exe { $global:LASTEXITCODE = 0; $global:ScDeleted += , "$args"; '[SC] DeleteService SUCCESS' }
$global:ScDeleted = @()
function New-RegKeyRaw { param([string]$Path) RSet $Path $null $null }
function Remove-RegValueRaw { param([string]$Path, [string]$Name) $k = RK $Path; if ($global:Reg[$k]) { $global:Reg[$k].Remove($Name) } }
function reg.exe { $global:RegExports += , "$args" }
$global:RegExports = @()
function Join-P { param([string]$Parent, [string]$Child) if ($Parent -match '^([A-Za-z]:\\|HK|Registry|Microsoft\.)') { return ($Parent.TrimEnd('\') + '\' + $Child.TrimStart('\')) }; return [IO.Path]::Combine($Parent, ($Child -replace '\\', '/')) }

# ---------- scenario
$sid = 'S-1-5-21-1-2-3-1001'; $hku = "Registry::HKEY_USERS\$sid"
$prof = Join-Path $work 'Users/Tester'
New-Item -ItemType Directory -Path $prof -Force | Out-Null
function Get-RunContext { return @{ CurrentSid = 'S-1-5-21-1-2-3-500'; CurrentName = 'TEST-PC\Admin'; MainSid = $sid; MainName = 'TEST-PC\Tester'; Differs = $true; MainHive = $hku; MainProfile = $prof } }
$build = '19045'; if ($Clean) { $build = '26200' }
RSet 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' 'CurrentBuild' $build; RSet 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' 'DisplayVersion' '22H2'; RSet 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' 'UBR' 5011
RSet "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$sid" 'ProfileImagePath' $prof
RSet "$hku\Software" $null $null
RSet 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'Userinit' 'C:\Windows\system32\userinit.exe,'
RSet 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'Shell' 'explorer.exe'
function MakeCert($subj) { $rsa = [System.Security.Cryptography.RSA]::Create(2048); $req = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new($subj, $rsa, 'SHA256', [System.Security.Cryptography.RSASignaturePadding]::Pkcs1); return $req.CreateSelfSigned([DateTimeOffset]::Now, [DateTimeOffset]::Now.AddYears(5)) }
function Blob($cert) { $ms = New-Object IO.MemoryStream; foreach ($pair in @(@(3, ([byte[]](1..20))), @(32, $cert.RawData), @(11, ([byte[]](1..6))))) { $d = [byte[]]$pair[1]; $ms.Write([BitConverter]::GetBytes([uint32]$pair[0]), 0, 4); $ms.Write([BitConverter]::GetBytes([uint32]1), 0, 4); $ms.Write([BitConverter]::GetBytes([uint32]$d.Length), 0, 4); $ms.Write($d, 0, $d.Length) }; return , $ms.ToArray() }
function PutCert($base, $store, $subj) { $c = MakeCert $subj; RSet "$base\$store\Certificates\$($c.Thumbprint)" 'Blob' (Blob $c) 'Binary' }
PutCert 'HKLM:\SOFTWARE\Microsoft\SystemCertificates' 'Root' 'CN=Microsoft Root Certificate Authority 2011, O=Microsoft Corporation, C=US'
if (-not $Clean) {
    PutCert 'HKLM:\SOFTWARE\Microsoft\SystemCertificates' 'Root' 'CN=Example Interception Root CA, O=Example Org'
    PutCert "$hku\Software\Microsoft\SystemCertificates" 'CA' 'CN=Example Interception Sub CA, O=Example Org'
    PutCert 'HKLM:\SOFTWARE\Microsoft\SystemCertificates' 'Root' 'CN=Kaspersky Anti-Virus Personal Root Certificate, O=AO Kaspersky Lab'
    PutCert "$hku\Software\Microsoft\SystemCertificates" 'Root' 'CN=NVIDIA GameStream Server'
    PutCert 'HKLM:\SOFTWARE\Microsoft\SystemCertificates' 'TrustedPublisher' 'CN=Example Interception Sub CA, O=Example Org'
    RSet 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' 'Dead' 'C:\Gone\gone.exe /x'
    RSet 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' 'Steam' '"C:\Program Files\Steam\steam.exe" -silent'
    RSet "$hku\Software\Microsoft\Windows\CurrentVersion\Run" 'Upd' 'powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMA'
    RSet "$hku\Software\Microsoft\Windows\CurrentVersion\Run" 'Evil' 'C:\Users\Tester\AppData\Roaming\evil\e.exe'
    RSet 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'Shell' 'explorer.exe, C:\x\bad.exe'
    RSet 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe' 'Debugger' 'cmd.exe'
    RSet 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\taskmgr.exe' 'Debugger' '"C:\Tools\procexp64.exe"'
    RSet 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' 'DisableAntiSpyware' 1 'DWord'
    RSet 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'EnableLUA' 0 'DWord'
    RSet "$hku\Software\Microsoft\Windows\CurrentVersion\Internet Settings" 'AutoConfigURL' 'http://evil.example/p.pac'
    RSet "$hku\Software\Microsoft\Windows\CurrentVersion\Internet Settings" 'ProxyEnable' 1 'DWord'
    RSet "$hku\Software\Microsoft\Windows\CurrentVersion\Internet Settings" 'ProxyServer' '127.0.0.1:8080'
    RSet 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections' 0 'DWord'
    foreach ($a in @('Yandex Browser', 'AnyDesk', 'DriverPack Solution', 'Autodesk Fusion', 'CryptoPro CSP')) { RSet "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$a" 'DisplayName' $a; RSet "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$a" 'DisplayVersion' '1.0' }
    RSet 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform' 'KeyManagementServiceName' 'kms.example.org'
    # one program registered twice: the hidden inner package is met first, the visible installer entry second
    RSet 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{11111111-0000-0000-0000-000000000001}' 'DisplayName' 'Example Sync'; RSet 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{11111111-0000-0000-0000-000000000001}' 'DisplayVersion' '2.1'
    RSet 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{11111111-0000-0000-0000-000000000001}' 'SystemComponent' 1 'DWord'
    RSet 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\{22222222-0000-0000-0000-000000000002}' 'DisplayName' 'Example Sync'; RSet 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\{22222222-0000-0000-0000-000000000002}' 'DisplayVersion' '2.1'
    RSet 'HKLM:\SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist' '1' 'abcdef;https://x'
}
$global:FakeFiles['C:\Program Files\Steam\steam.exe'] = 'Valid|Valve Corp.'
$global:FakeFiles['C:\Users\Tester\AppData\Roaming\evil\e.exe'] = 'NotSigned'
$global:FakeFiles['C:\Windows\System32\svchost.exe'] = 'Valid|Microsoft Windows Publisher'
$global:FakeFiles['C:\Program Files\Vendor\svc.exe'] = 'Valid|Vendor Inc'
$global:FakeFiles['C:\ProgramData\x\unsigned.exe'] = 'NotSigned'
$global:FakeFiles['C:\Program Files\Example Sync\sync-daemon.exe'] = 'NotSigned'
$global:FakeFiles['C:\Program Files\Nobody\svc.exe'] = 'UnknownError|Some Signer'
$global:FakeFiles['C:\Crack'] = 'DIR'
$global:FakeFiles['C:\Crack\bin\patch.exe'] = 'NotSigned'
$global:FakeFiles['C:\Users\Tester\.gradle'] = 'DIR'
class FakeSigCert { [string]$N; [string] GetNameInfo([object]$a, [object]$b) { return $this.N } }
function Get-AuthenticodeSignature { [CmdletBinding()] param($LiteralPath) $v = $global:FakeFiles["$LiteralPath"] -split '\|'; $c = $null; if ($v.Count -gt 1) { $c = [FakeSigCert]::new(); $c.N = $v[1] }; return [pscustomobject]@{ Status = $v[0]; SignerCertificate = $c } }

$global:S = @{ Realtime = $Clean.IsPresent; SigDate = (Get-Date).AddDays(-40); Pua = 0; ExPath = @('C:\Crack', 'C:\Crack\bin\patch.exe', 'C:\Users\Tester\.gradle', 'C:\Gone\folder'); Active = $true; FwOff = @('Public'); Smb1 = $true; GuestOn = $true; Appx = @('Microsoft.BingNews', 'king.com.CandyCrushSaga', 'Microsoft.WindowsCalculator'); Tasks = @() }
if ($Clean) { $global:S.SigDate = Get-Date; $global:S.Pua = 1; $global:S.ExPath = @(); $global:S.Active = $false; $global:S.FwOff = @(); $global:S.Smb1 = $false; $global:S.GuestOn = $false; $global:S.Appx = @('Microsoft.WindowsCalculator') }
function NewTask($p, $n, $exe, $arg, $state = 'Ready') { [pscustomobject]@{ TaskPath = $p; TaskName = $n; State = $state; Author = 'x'; Actions = @([pscustomobject]@{ Execute = $exe; Arguments = $arg }) } }
$global:S.Tasks += NewTask '\Microsoft\Windows\Customer Experience Improvement Program\' 'Consolidator' '%SystemRoot%\System32\svchost.exe' ''
$global:S.Tasks += NewTask '\' 'VendorUpdate' '"C:\Program Files\Vendor\svc.exe"' '/update'
if (-not $Clean) {
    $global:S.Tasks += NewTask '\Evil\' 'Updater' 'mshta.exe' 'vbscript:Execute("x")'
    $global:S.Tasks += NewTask '\' 'DeadTask' 'C:\Gone\dead.exe' '/run'
    $global:S.Tasks += NewTask '\' 'MyScript' 'powershell.exe' '-File C:\Scripts\backup.ps1'
}
function Get-CimInstance { [CmdletBinding()] param([Parameter(Position = 0)]$ClassName, $Namespace, $Filter)
    switch ($ClassName) {
        'Win32_OperatingSystem' { [pscustomobject]@{ Caption = 'Microsoft Windows 10 Home' } }
        'SoftwareLicensingProduct' { [pscustomobject]@{ LicenseStatus = 1; Description = 'Windows(R) Operating System, VOLUME_KMSCLIENT channel'; GracePeriodRemaining = 180000 } }
        'AntiVirusProduct' { [pscustomobject]@{ displayName = 'Windows Defender'; productState = 397568; pathToSignedProductExe = 'windowsdefender://'; instanceGuid = '{D}' }; if (-not $Clean -and -not $global:S.GhostGone) { [pscustomobject]@{ displayName = 'Old Antivirus'; productState = 266240; pathToSignedProductExe = 'C:\Gone\av\wsc_proxy.exe'; instanceGuid = '{G}' } } }
        'FirewallProduct' { }
        'Win32_Service' {
            [pscustomobject]@{ Name = 'WaaSMedicSvc'; DisplayName = 'Protected'; PathName = $null; StartMode = 'Manual'; State = 'Stopped' }
            [pscustomobject]@{ Name = 'Dnscache'; DisplayName = 'DNS'; PathName = 'C:\Windows\System32\svchost.exe -k NetworkService'; StartMode = 'Auto'; State = 'Running' }
            [pscustomobject]@{ Name = 'VendorSvc'; DisplayName = 'Vendor'; PathName = '"C:\Program Files\Vendor\svc.exe" --key=SECRETSECRETSECRETSECRETSECRETSECRET1234'; StartMode = 'Auto'; State = 'Running' }
            if (-not $Clean) {
                [pscustomobject]@{ Name = 'GoneSvc'; DisplayName = 'Gone'; PathName = 'C:\Gone\svc.exe'; StartMode = 'Auto'; State = 'Stopped' }
                [pscustomobject]@{ Name = 'BadSvc'; DisplayName = 'Bad'; PathName = 'C:\ProgramData\x\unsigned.exe'; StartMode = 'Auto'; State = 'Running' }
                [pscustomobject]@{ Name = 'AnyDesk'; DisplayName = 'AnyDesk Service'; PathName = '"C:\Program Files\Vendor\svc.exe"'; StartMode = 'Auto'; State = 'Running' }
                [pscustomobject]@{ Name = 'ExampleSync'; DisplayName = 'Example Sync daemon'; PathName = '"C:\Program Files\Example Sync\sync-daemon.exe" --service'; StartMode = 'Auto'; State = 'Running' }
                [pscustomobject]@{ Name = 'NobodySvc'; DisplayName = 'Nobody'; PathName = 'C:\Program Files\Nobody\svc.exe'; StartMode = 'Manual'; State = 'Stopped' }
            }
        }
        'Win32_SystemDriver' { [pscustomobject]@{ Name = 'drv1'; PathName = '\SystemRoot\System32\svchost.exe'; StartMode = 'Boot'; State = 'Running' }; if (-not $Clean) { [pscustomobject]@{ Name = 'Asusgio2'; PathName = '\??\C:\Gone\AsIO2.sys'; StartMode = 'Auto'; State = 'Stopped' } } }
        '__EventConsumer' { }
        default { throw "fake: unexpected class $ClassName" }
    }
}
function Remove-CimInstance { [CmdletBinding()] param($InputObject) $global:S.GhostGone = $true }
function Get-HotFix { [CmdletBinding()] param() $d = (Get-Date).AddDays(-130); if ($Clean) { $d = (Get-Date).AddDays(-5) }; [pscustomobject]@{ HotFixID = 'KB5000001'; InstalledOn = $d } }
function Get-PhysicalDisk { [pscustomobject]@{ DeviceId = 0; FriendlyName = 'SSD One'; MediaType = 'SSD'; Size = 500GB; HealthStatus = 'Healthy'; W = 0 }; if (-not $Clean) { [pscustomobject]@{ DeviceId = 1; FriendlyName = 'Old HDD'; MediaType = 'HDD'; Size = 1000GB; HealthStatus = 'Warning'; W = $null } } }
function Get-StorageReliabilityCounter { [CmdletBinding()] param([Parameter(ValueFromPipeline = $true)]$d) process { [pscustomobject]@{ Wear = $d.W; Temperature = 40; PowerOnHours = 12000; ReadErrorsUncorrected = 0; WriteErrorsUncorrected = 0 } } }
function Get-Volume { [pscustomobject]@{ DriveLetter = 'C'; DriveType = 'Fixed'; Size = 400GB; SizeRemaining = $(if ($Clean) { 200GB } else { 6GB }); HealthStatus = 'Healthy' }; [pscustomobject]@{ DriveLetter = $null; DriveType = 'Fixed'; Size = 1GB; SizeRemaining = 1GB; HealthStatus = 'Healthy' } }
function Get-BitLockerVolume { [CmdletBinding()] param() throw 'not available' }
function Get-ScheduledTask { [CmdletBinding()] param($TaskPath, $TaskName) foreach ($t in $global:S.Tasks) { if ($TaskPath -and $t.TaskPath -ne $TaskPath) { continue }; if ($TaskName -and $t.TaskName -ne $TaskName) { continue }; $t } }
function Export-ScheduledTask { [CmdletBinding()] param($TaskPath, $TaskName) '<Task/>' }
function Disable-ScheduledTask { [CmdletBinding()] param($TaskPath, $TaskName) foreach ($t in $global:S.Tasks) { if ($t.TaskPath -eq $TaskPath -and $t.TaskName -eq $TaskName) { $t.State = 'Disabled'; $t } } }
function Unregister-ScheduledTask { [CmdletBinding()] param($TaskPath, $TaskName, $Confirm) $global:S.Tasks = @($global:S.Tasks | Where-Object { -not ($_.TaskPath -eq $TaskPath -and $_.TaskName -eq $TaskName) }) }
function Get-MpComputerStatus { [CmdletBinding()] param() [pscustomobject]@{ AMRunningMode = 'Normal'; AntivirusEnabled = $true; RealTimeProtectionEnabled = $global:S.Realtime; IsTamperProtected = $Clean.IsPresent; AntivirusSignatureLastUpdated = $global:S.SigDate; QuickScanAge = [uint32]::MaxValue; FullScanAge = [uint32]3 } }
function Get-MpPreference { [CmdletBinding()] param() [pscustomobject]@{ ExclusionPath = $global:S.ExPath; ExclusionProcess = $null; ExclusionExtension = $null; ExclusionIpAddress = $null; PUAProtection = $global:S.Pua } }
function Set-MpPreference { [CmdletBinding()] param($DisableRealtimeMonitoring, $PUAProtection) if ($PSBoundParameters.ContainsKey('DisableRealtimeMonitoring')) { $global:S.Realtime = $true }; if ($PUAProtection) { $global:S.Pua = 1 } }
function Remove-MpPreference { [CmdletBinding()] param($ExclusionPath) $global:S.ExPath = @($global:S.ExPath | Where-Object { $_ -ne $ExclusionPath }) }
function Update-MpSignature { $global:S.SigDate = Get-Date }
function Start-MpScan { [CmdletBinding()] param($ScanType) }
function Remove-MpThreat { $global:S.Active = $false }
function Get-MpThreat { [CmdletBinding()] param() if ($global:S.Active) { [pscustomobject]@{ ThreatID = 1; ThreatName = 'Trojan:Win32/Fake'; IsActive = $true } } }
function Get-MpThreatDetection { [CmdletBinding()] param() if ($global:S.Active) { [pscustomobject]@{ ThreatID = 1; InitialDetectionTime = (Get-Date).AddDays(-2) } } }
function Get-NetFirewallProfile { [CmdletBinding()] param() foreach ($n in 'Domain', 'Private', 'Public') { [pscustomobject]@{ Name = $n; Enabled = ($global:S.FwOff -notcontains $n) } } }
function Set-NetFirewallProfile { [CmdletBinding()] param($Name, $Enabled) $global:S.FwOff = @() }
function Get-SmbServerConfiguration { [CmdletBinding()] param() [pscustomobject]@{ EnableSMB1Protocol = $global:S.Smb1 } }
function Set-SmbServerConfiguration { [CmdletBinding()] param($EnableSMB1Protocol, [switch]$Force, $Confirm) $global:S.Smb1 = $false }
function Get-NetAdapter { [CmdletBinding()] param() [pscustomobject]@{ Status = 'Up'; ifIndex = 5; Name = 'Ethernet' } }
function Get-DnsClientServerAddress { [CmdletBinding()] param() [pscustomobject]@{ InterfaceIndex = 5; InterfaceAlias = 'Ethernet'; ServerAddresses = @('192.168.1.1', $(if ($Clean) { '1.1.1.1' } else { '45.67.89.10' })) }; [pscustomobject]@{ InterfaceIndex = 9; InterfaceAlias = 'Down'; ServerAddresses = @('6.6.6.6') } }
function Get-LocalUser { [CmdletBinding()] param() [pscustomobject]@{ Name = 'Tester'; Enabled = $true; LastLogon = (Get-Date); SID = "$sid" }; [pscustomobject]@{ Name = 'Guest'; Enabled = $global:S.GuestOn; LastLogon = $null; SID = 'S-1-5-21-1-2-3-501' } }
function Disable-LocalUser { [CmdletBinding()] param($SID) $global:S.GuestOn = $false }
function Get-LocalGroupMember { [CmdletBinding()] param($SID) [pscustomobject]@{ Name = 'TEST-PC\Tester' } }
function Get-Process { [CmdletBinding()] param($Name, $Id)
    $all = @([pscustomobject]@{ ProcessName = 'explorer'; Id = 100; Path = 'C:\Windows\explorer.exe' })
    if (-not $Clean) { $all += [pscustomobject]@{ ProcessName = 'patch'; Id = 200; Path = 'C:\Crack\bin\patch.exe' } }
    foreach ($p in $all) { if ($Name -and $p.ProcessName -ne $Name) { continue }; if ($Id -and $p.Id -ne $Id) { continue }; $p }
}
function Get-Service { [CmdletBinding()] param($Name) if (-not $Clean) { [pscustomobject]@{ Name = 'WinRM'; DisplayName = 'Windows Remote Management'; Status = 'Running' } } }
function Get-AppxPackage { [CmdletBinding()] param($User) foreach ($a in $global:S.Appx) { [pscustomobject]@{ Name = $a; PackageFullName = "${a}_1.0_x64__abc" } } }
function Remove-AppxPackage { [CmdletBinding()] param($Package, $User) $n = $Package -replace '_1\.0_x64__abc$', ''; $global:S.Appx = @($global:S.Appx | Where-Object { $_ -ne $n }) }
function Get-AppxProvisionedPackage { [CmdletBinding()] param([switch]$Online) [pscustomobject]@{ DisplayName = 'Microsoft.BingNews'; PackageName = 'Microsoft.BingNews_1' } }
function Remove-AppxProvisionedPackage { [CmdletBinding()] param([switch]$Online, $PackageName) }

# hosts + firefox + startup on the real FS
$script:HostsPath = Join-Path $work 'hosts'
$hostsLines = @('# hosts', '127.0.0.1 localhost', '0.0.0.0 lmlicenses.wip4.adobe.com')
if (-not $Clean) { $hostsLines += @('0.0.0.0 update.kaspersky.com', '5.6.7.8 online.sberbank.ru', '204.12.192.222 chatgpt.com') }
Set-Content -LiteralPath $script:HostsPath -Value $hostsLines
$ffp = Join-Path $prof 'AppData/Roaming/Mozilla/Firefox/Profiles/abc.default-release'
New-Item -ItemType Directory -Path $ffp -Force | Out-Null
if ($Clean) { Set-Content (Join-Path $ffp 'prefs.js') 'user_pref("security.enterprise_roots.enabled", false);' ; [IO.File]::WriteAllBytes((Join-Path $ffp 'cert9.db'), [byte[]](1..200)) }
else {
    Set-Content (Join-Path $ffp 'prefs.js') 'user_pref("browser.x", 1);'
    [IO.File]::WriteAllBytes((Join-Path $ffp 'cert9.db'), ([byte[]](1..200) + [byte[]](6, 3, 0x55, 4, 3, 0x0C, 28) + [Text.Encoding]::ASCII.GetBytes('Example Interception Root CA') + [byte[]](1..50)))
    Set-Content (Join-Path $ffp 'logins.json') '{"logins":[{"id":1,"encryptedPassword":"x"},{"id":2,"encryptedPassword":"y"},{"id":3}]}'
    $st = Join-Path $prof 'AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup'
    New-Item -ItemType Directory -Path $st -Force | Out-Null
    Set-Content (Join-Path $st 'run.vbs') 'x'
}
$global:Ans = [System.Collections.Queue]::new(); foreach ($a in $Answers) { $global:Ans.Enqueue($a) }
function Read-Host { param($Prompt) $a = ''; if ($global:Ans.Count) { $a = $global:Ans.Dequeue() }; Write-Host "$Prompt`: $a  <- (ответ теста)" -ForegroundColor Magenta; return $a }
$PSScriptRoot_fake = $work
Invoke-Main
"--- harness: reg exports: $($global:RegExports.Count)"
