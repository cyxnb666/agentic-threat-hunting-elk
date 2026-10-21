# Threat hunt report — 20261017-075717-converged-exp-B4-playbook

**Hypothesis:** An adversary who compromised Windows hosts in this network stole credentials from them (MITRE ATT&CK tactic: Credential Access).

**Verdict: Confirmed** — 16 in-scope incident(s) of verified malicious findings (confidence >= medium): I01 T1003 (F02), I02 T1003.001 (F01, F11, F36, F39), I03 T1003.001 (F19), I04 T1056.001 (F66), I05 T1056.004 (F67), I06 T1187 (F23), I08 T1212 (F26), I09 T1552 (F32), I10 T1552.001 (F33), I11 T1552.001 (F41), I12 T1552.001 (F63), I13 T1552.001 (F64), I14 T1552.001 (F65), I15 T1552.001 (F68), I16 T1552.004 (F62), I18 T1649 (F60)

Verdict method: rules over verified evidence (Confirmed if >=1 in-scope incident of verified malicious findings (confidence >= medium); Inconclusive if only suspicious incidents or coverage gaps; Refuted if full coverage and no malicious/suspicious finding)

| Run | Value |
|---|---|
| Profile | converged (thinking=False, temperature=0.0) |
| Model | deepseek-flash |
| Started / finished (UTC) | 2026-10-16T23:57:17+00:00 / 2026-10-17T00:04:28+00:00 (430.3 s) |
| LLM calls / tokens | 119 / {'prompt': 3535440, 'completion': 84318} |
| MCP tool calls | 1175 (server tools: list_data_sources, get_fields, search, count, aggregate, timeline, esql, get_event, get_registry) |
| ATT&CK tactics | credential-access — An adversary with existing access to Windows hosts on this network is stealing credentials from those hosts. |

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
| I01 | T1003 | yes | malicious/high | F02 | PowerShell credential-collection toolkit (Get-PrivateKeys, Get-Keystrokes, Invoke-ScreenCapture, Invoke-Exfil) on scranton |
| I02 | T1003.001 | yes | malicious/high | F01, F11, F36, F39 | LSASS memory accessed with full-access masks by PowerShell and WinRM host under pbeesly |
| I03 | T1003.001 | yes | malicious/high | F19 | Credential material accessed via LSASS handle and private-key export (not offline cracking) |
| I04 | T1056.001 | yes | malicious/high | F66 | Get-Keystrokes keylogger function executed on scranton |
| I05 | T1056.004 | yes | malicious/medium | F67 | Invoke-ScreenCapture screenshot capture function executed on scranton |
| I06 | T1187 | yes | malicious/high | F23 | WebDAV Mini-Redirector forced authentication from scranton to 192.168.0.4 |
| I07 | T1187 | yes | suspicious/medium | F24 | SMB/445 connections to 192.168.0.4 from scranton and nashua workstations |
| I08 | T1212 | yes | malicious/high | F26 | Steganographic PowerShell payload opens LSASS with PROCESS_ALL_ACCESS on scranton |
| I09 | T1552 | yes | malicious/high | F32 | accesschk.exe run by pbeesly creates a file named 'passwordsDB' on scranton |
| I10 | T1552.001 | yes | malicious/high | F33 | Plaintext credentials in files/command lines: passwordsDB artifact and PsExec -p password |
| I11 | T1552.001 | yes | malicious/high | F41 | Invoke-Exfil PowerShell script with hardcoded credentials on SCRANTON |
| I12 | T1552.001 | yes | malicious/high | F63 | pspasswd.exe downloaded and accesschk.exe used to create 'passwordsDB' file on scranton |
| I13 | T1552.001 | yes | malicious/high | F64 | Invoke-Exfil with hardcoded credentials and archive password on scranton |
| I14 | T1552.001 | yes | malicious/high | F65 | Password-protected Rar archive of user profile created on nashua with hardcoded password |
| I15 | T1552.001 | yes | malicious/medium | F68 | Explicit-credential logons (4648) with pbeesly from scranton to nashua via PSEXESVC |
| I16 | T1552.004 | yes | malicious/high | F62 | Get-PrivateKeys exports LocalMachine certificates with private keys using hardcoded password 'saribas' on scranton |
| I17 | T1555.004 | yes | suspicious/medium | F37 | LSASS handle requests by user processes (Credential Manager/DPAPI harvest mechanism) |
| I18 | T1649 | yes | malicious/high | F60 | PowerShell script exported all LocalMachine certificates with private keys to .pfx files on scranton |
| I19 | out-of-scope:T1021 | no | suspicious/medium | F10 | PsExec lateral movement to NASHUA with python C2 (not network sniffing) |
| I20 | out-of-scope:T1021 | no | malicious/high | F40 | PsExec with plaintext credentials used to move to NASHUA and install PSEXESVC |
| I21 | out-of-scope:T1059.001 | no | malicious/high | F12 | Obfuscated PowerShell with reflective code loading and base64 shellcode on scranton |

## Findings

### F02 · malicious / high · T1003 · pbeesly PowerShell credential-collection toolkit on scranton (Get-PrivateKeys, Get-Keystrokes, Invoke-ScreenCapture, Invoke-Exfil)

Evidence status: **verified**

On scranton.dmevals.local, user pbeesly ran a PowerShell credential/collection toolkit from C:\Program Files\SysinternalsSuite\psversion.ps1 between 03:04 and 03:08 on 2020-05-02. Script blocks include Get-PrivateKeys (exports certificate private keys to .pfx using a hardcoded password), Get-Keystrokes, Invoke-ScreenCapture, and Invoke-Exfil, which compresses the Downloads directory into OfficeSupplies.7z and copies it to a WebDAV share at \\192.168.0.4\webdav. This is credential access and staging activity by the same user whose PowerShell process opened LSASS with full access.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | powershell.script_block_text | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b21vS3 | q-68af76f232 | ok |
| 2 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | powershell.script_block_text | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b10BXt | q-67d4d90830 | ok |
| 3 | 2020-05-02 03:06:59.000Z | scranton.dmevals.local | windows.powershell | powershell.script_block_text | Get-Keystrokes;Start-Sleep -Seconds 15;View-Job -JobName "Keystrokes" | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b21_Tx | q-68af76f232 | ok |

### F01 · malicious / high · T1003.001 · LSASS memory accessed with full-access masks by PowerShell and PowerShell Remoting host under user pbeesly

Evidence status: **verified**

On 2020-05-02, user pbeesly obtained handles to lsass.exe with full-access masks from PowerShell processes on two hosts. On scranton.dmevals.local, powershell.exe (PID 2976) opened lsass.exe (PID 736) with GrantedAccess 0x1F3FFF and 0x1FFFFF at 03:05:16; the same access was recorded in Windows Security 4656 with AccessMask 0x1f3fff/0x1fffff. On nashua.dmevals.local, wsmprovhost.exe (PID 7720, PowerShell Remoting) opened lsass.exe (PID 728) with GrantedAccess 0x1F3FFF at 03:09:29, also seen in Security 4656 with AccessMask 0x1f3fff. The call traces run through PowerShell/System.Management.Automation native images, consistent with in-memory LSASS credential dumping. This occurred in the middle of a pbeesly PowerShell toolkit session (Get-PrivateKeys, Get-Keystrokes, Invoke-ScreenCapture, Invoke-Exfil) on scranton.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R-k131 | q-fe1b9af7e2 | ok |
| 2 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R-k13y | q-fe1b9af7e2 | ok |
| 3 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1RrM7IJ | q-05413bc808 | ok |
| 4 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | win.AccessMask | 0x1fffff | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YldM_p | q-36a06901cc | ok |
| 5 | 2020-05-02 03:09:29.000Z | nashua.dmevals.local | windows.security | win.AccessMask | 0x1f3fff | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YjaXaO | q-36a06901cc | ok |

### F12 · malicious / high · T1056 · Obfuscated PowerShell with reflective code loading and base64 shellcode on scranton

Evidence status: **verified**

On scranton.dmevals.local, user pbeesly executed a PowerShell script block (EventID 4104, ScriptBlockId bc19aae2-d1f9-49b2-b718-192531ae928f) that defines functions using Microsoft.Win32.UnsafeNativeMethods GetProcAddress/GetModuleHandle and DefineDynamicAssembly/DefineDynamicModule to build an in-memory delegate, then decodes a base64 byte array ([System.Convert]::FromBase64String) — a reflective shellcode loader. A child process was spawned as powershell.exe -nop -w hidden -e <base64> whose parent command line was powershell.exe -c "Get-ItemPropertyValue 'HKLM:\\SOFTWARE\Javasoft' 'value Supplement' \| Invoke-Expression", i.e. hidden encoded execution. This tooling is consistent with in-memory credential capture on the host.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:21:29.000Z | scranton.dmevals.local | windows.powershell | powershell.script_block_text | function jzI {  	Param ($yKR, $cq)		  	$vvA = ([AppDomain]::CurrentDomain.GetAssemblies() \| Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[… | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1bzyNfQ | q-df6fd0d289 | ok |
| 2 | 2020-05-02 03:21:29.000Z | scranton.dmevals.local | windows.powershell | user.name | pbeesly | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1bzyNfQ | q-5d12951e87 | ok |
| 3 | 2020-05-02 03:21:28.949Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\windows\System32\WindowsPowerShell\v1.0\powershell.exe" -nop -w hidden -e aQBmACgAWwBJAG4AdABQAHQAcgBdADoAOgBTAGkAegBlACAALQBlAHEAIAA0ACkAewAkAGIAPQAkAGUAbg… | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1MtUml9 | q-87789bffbe | ok |
| 4 | 2020-05-02 03:21:28.949Z | scranton.dmevals.local | windows.sysmon | process.parent.command_line | powershell.exe -c "Get-ItemPropertyValue 'HKLM:\\SOFTWARE\Javasoft' 'value Supplement' \| Invoke-Expression" | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1MtUml9 | q-87789bffbe | ok |

### F66 · malicious / high · T1056.001 · Get-Keystrokes keylogger function executed on scranton

Evidence status: **verified**

On scranton.dmevals.local, user pbeesly executed Get-Keystrokes at 03:06:59 (PowerSploit/Empire keylogger that logs keys pressed, time and active window). This is input-capture credential theft.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:06:59.000Z | scranton.dmevals.local | windows.powershell | powershell.script_block_text | Get-Keystrokes;Start-Sleep -Seconds 15;View-Job -JobName "Keystrokes" | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b21_Tx | q-d4a1a130a1 | ok |
| 2 | 2020-05-02 03:06:59.000Z | scranton.dmevals.local | windows.powershell | powershell.script_block_text | function Get-Keystrokes { &lt;# .SYNOPSIS       Logs keys pressed, time and the active window (when changed).     Some modifications for Empire by @harmj0y.    … | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b22PQN | q-d4a1a130a1 | ok |

### F11 · malicious / high · T1056.004 · PowerShell opens LSASS with PROCESS_ALL_ACCESS (0x1FFFFF) using reflective/injected code

Evidence status: **verified**

On scranton.dmevals.local, PowerShell.exe (PID 2976) opened lsass.exe (PID 736) with GrantedAccess 0x1FFFFF (PROCESS_ALL_ACCESS) at 2020-05-02T03:05:16.654Z. The CallTrace shows only ntdll.dll/KERNELBASE.dll followed by UNKNOWN(000001996D28200D), indicating the calling code is not backed by a known module (reflectively loaded/injected code) — the classic signature of credential API hooking / in-memory credential theft. A second open with 0x1f3fff occurred at 03:05:16.623Z. This is the same host/user (pbeesly) that ran an obfuscated PowerShell script using GetProcAddress/GetModuleHandle and a base64 shellcode blob.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R-k131 | q-c523e0a03b | ok |
| 2 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.CallTrace | C:\windows\SYSTEM32\ntdll.dll+9c584\|C:\windows\System32\KERNELBASE.dll+2732e\|UNKNOWN(000001996D28200D) | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R-k131 | q-c523e0a03b | ok |
| 3 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.TargetImage | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R-k131 | q-c523e0a03b | ok |
| 4 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R-k13y | q-c523e0a03b | ok |

### F67 · malicious / medium · T1056.004 · Invoke-ScreenCapture screenshot capture function executed on scranton

Evidence status: **verified**

On scranton.dmevals.local, user pbeesly executed Invoke-ScreenCapture at 03:05:53, a background job that repeatedly captures the screen to random-named .bmp files in $env:USERPROFILE\Downloads. Screen capture can harvest credentials displayed on screen.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:53.000Z | scranton.dmevals.local | windows.powershell | powershell.script_block_text | Invoke-ScreenCapture;Start-Sleep -Seconds 3;View-Job -JobName "Screenshot" | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b22PTB | q-d4a1a130a1 | ok |

### F19 · malicious / high · T1110.002 · Credential material accessed via LSASS handle and private-key export (not offline cracking)

Evidence status: **verified**

On scranton.dmevals.local, PowerShell.exe (PID 2976) opened a handle to C:\windows\system32\lsass.exe with GrantedAccess 0x1FFFFF (full access) at 2020-05-02T03:05:16.654Z, and a second access with 0x1f3fff at 03:05:16.623Z — consistent with in-memory credential dumping rather than offline password cracking. In the same window user pbeesly ran a Get-PrivateKeys script that enumerates cert:\LocalMachine and exports every certificate to a .pfx file protected by the hardcoded password "saribas", and an Invoke-Exfil script that compresses the Downloads folder and copies it to a WebDAV share (\\192.168.0.4\webdav) using hardcoded credentials. No cracking tooling, wordlists or potfiles were observed (no *hash*/*crack* command lines, no .pot files).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R-k131 | q-13783086f0 | ok |
| 2 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.TargetImage | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R-k131 | q-13783086f0 | ok |
| 3 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R-k131 | q-13783086f0 | ok |
| 4 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | powershell.script_block_text | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b21vS3 | q-40a49a4e11 | ok |
| 5 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | powershell.script_block_text | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b10BXt | q-d769627643 | ok |

### F23 · malicious / high · T1187 · WebDAV Mini-Redirector forced authentication from scranton (10.0.1.4) to 192.168.0.4

Evidence status: **verified**

On 2020-04-30 between 00:32:18 and 00:32:21 UTC, host 10.0.1.4 (scranton.dmevals.local) issued 36 HTTP requests to 192.168.0.4:80 using the Microsoft-WebDAV-MiniRedir/10.0.18362 user agent, including OPTIONS and PROPFIND methods against /webdav and /webdav/OfficeSupplies.7z. The server answered 401 Unauthorized, which is the classic forced-authentication pattern: the WebDAV redirector causes the Windows host to automatically send NTLM/Kerberos credentials to an attacker-controlled listener. All 36 WebDAV-method requests came from a single source, 10.0.1.4, to a single destination, 192.168.0.4, and 61 of 62 HTTP requests in the window used the WebDAV MiniRedir agent. This is consistent with an adversary coercing authentication from a compromised workstation to capture credential material.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-04-30 00:32:21.422Z | simplerockbuild.simplerock.lan | zeek | user_agent.original | Microsoft-WebDAV-MiniRedir/10.0.18362 | .ds-logs-zeek-default-2026.10.16-000001 / AaFFktQ25mySA1aO8Ieh | q-0452973b93 | ok |
| 2 | 2020-04-30 00:32:21.422Z | simplerockbuild.simplerock.lan | zeek | http.request.method | OPTIONS | .ds-logs-zeek-default-2026.10.16-000001 / AaFFktQ25mySA1aO8Ieh | q-0452973b93 | ok |
| 3 | 2020-04-30 00:32:21.422Z | simplerockbuild.simplerock.lan | zeek | http.response.status_code | 401 | .ds-logs-zeek-default-2026.10.16-000001 / AaFFktQ25mySA1aO8Ieh | q-0452973b93 | ok |
| 4 | 2020-04-30 00:32:21.895Z | simplerockbuild.simplerock.lan | zeek | url.original | /webdav/OfficeSupplies.7z | .ds-logs-zeek-default-2026.10.16-000001 / AaFFktQ25mySA1aO8Iej | q-43180d76be | ok |
| 5 | 2020-04-30 00:32:21.895Z | simplerockbuild.simplerock.lan | zeek | http.request.method | PROPFIND | .ds-logs-zeek-default-2026.10.16-000001 / AaFFktQ25mySA1aO8Iej | q-43180d76be | ok |
| 6 | 2020-04-30 00:32:21.422Z | simplerockbuild.simplerock.lan | zeek | source.ip | 10.0.1.4 | .ds-logs-zeek-default-2026.10.16-000001 / AaFFktQ25mySA1aO8Ieh | q-0452973b93 | ok |
| 7 | 2020-04-30 00:32:21.422Z | simplerockbuild.simplerock.lan | zeek | destination.ip | 192.168.0.4 | .ds-logs-zeek-default-2026.10.16-000001 / AaFFktQ25mySA1aO8Ieh | q-0452973b93 | ok |

### F26 · malicious / high · T1212 · Steganographic PowerShell payload opens LSASS with PROCESS_ALL_ACCESS on scranton.dmevals.local

Evidence status: **verified**

On scranton.dmevals.local, a hidden PowerShell process (PID 2976, user DMEVALS\pbeesly, High integrity, launched from control.exe with -noni -noexit -ep bypass -window hidden) decoded a script hidden inside C:\Users\pbeesly\Downloads\monkey.png via System.Drawing pixel extraction and executed it with IEX. ~6.5 minutes later the same process (SourceProcessGUID {47ab858c-e1e4-5eac-b803-000000000400}, PID 2976) opened lsass.exe (PID 736) with GrantedAccess 0x1F3FFF and then 0x1FFFFF (PROCESS_ALL_ACCESS) — the classic handle rights used to read credential material from LSASS memory. This is attacker-driven credential access on a compromised host, not normal system behaviour: legitimate lsass access in this dataset comes from svchost.exe with 0x1000, and the only other full-access opens are OS boot-time wininit/csrss accesses at 03:19:09. The same host also shows a remote-execution chain (Invoke-Command to NASHUA, Invoke-SeaDukeStage) and exfiltration staging (Invoke-Exfil, 7-Zip password-protected archive) under user pbeesly.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:58:44.325Z | scranton.dmevals.local | windows.sysmon | process.command_line | "PowerShell.exe" -noni -noexit -ep bypass -window hidden -c "sal a New-Object;Add-Type -AssemblyName 'System.Drawing'; $g=a System.Drawing.Bitmap('C:\Users\pbee… | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1WdFNhN | q-98432b1e51 | ok |
| 2 | 2020-05-02 02:58:44.325Z | scranton.dmevals.local | windows.sysmon | user.name | pbeesly | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1WdFNhN | q-98432b1e51 | ok |
| 3 | 2020-05-02 02:58:44.325Z | scranton.dmevals.local | windows.sysmon | process.parent.executable | C:\Windows\System32\control.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1WdFNhN | q-98432b1e51 | ok |
| 4 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R-k131 | q-b66b0f7b7e | ok |
| 5 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.TargetImage | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R-k131 | q-b66b0f7b7e | ok |
| 6 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R-k131 | q-b66b0f7b7e | ok |
| 7 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R-k13y | q-325ce97433 | ok |
| 8 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1RrM7IJ | q-325ce97433 | ok |
| 9 | 2020-05-02 03:09:23.000Z | scranton.dmevals.local | windows.powershell | powershell.script_block_text | Invoke-Command -ComputerName NASHUA -ScriptBlock { Get-Process -IncludeUserName \| Select-Object UserName,SessionId \| Where-Object { $_.UserName -like "*\$env:… | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1bsxQxS | q-33baab6209 | ok |
| 10 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | powershell.script_block_text | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b10BXt | q-33baab6209 | ok |

### F32 · malicious / high · T1552 · accesschk.exe run by pbeesly creates a file named 'passwordsDB' on scranton

Evidence status: **verified**

On 2020-05-02 at 03:04:34 UTC on scranton.dmevals.local, user DMEVALS\pbeesly launched C:\Program Files\SysinternalsSuite\accessChk.exe from a parent powershell.exe (Sysmon event 1, IntegrityLevel High). One second later the same process (PID 9204) created the file C:\Program Files\SysinternalsSuite\passwordsDB (Sysmon event 11). A file literally named for a password database, produced by a Sysinternals access-enumeration tool run interactively by a user, is consistent with an adversary collecting unsecured credentials. The same user session also ran sdelete64.exe to securely wipe files (C:\programdata\victim\???cod.3aka3.scr, C:\Users\pbeesly\AppData\Roaming\Draft.Zip, C:\Users\pbeesly\Downloads\SysinternalsSuite.zip) and used PsExec64.exe with a plaintext password, indicating deliberate anti-forensics and credential handling.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:35.069Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Program Files\SysinternalsSuite\passwordsDB | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R_lkD8 | q-ca7b558c8c | ok |
| 2 | 2020-05-02 03:04:35.069Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\Program Files\SysinternalsSuite\accesschk.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R_lkD8 | q-ca7b558c8c | ok |
| 3 | 2020-05-02 03:04:34.951Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\accesschk.exe" | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R_lkD_ | q-5916f9d780 | ok |
| 4 | 2020-05-02 03:04:34.951Z | scranton.dmevals.local | windows.sysmon | process.parent.executable | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R_lkD_ | q-5916f9d780 | ok |
| 5 | 2020-05-02 03:02:04.324Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\sdelete64.exe" /accepteula C:\programdata\victim\???cod.3aka3.scr | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1SEqWk4 | q-3af4fdd605 | ok |

### F33 · malicious / high · T1552.001 · Plaintext credentials in files/command lines: passwordsDB artifact and PsExec -p password

Evidence status: **verified**

On scranton.dmevals.local, user DMEVALS\pbeesly handled credentials in cleartext. At 03:04:34 UTC accesschk.exe created C:\Program Files\SysinternalsSuite\passwordsDB (a file named as a password store). From 03:11:18 to 03:14:42 UTC the same user repeatedly ran C:\Program Files\SysinternalsSuite\PsExec64.exe with the password supplied in plaintext on the command line: -accepteula \\NASHUA -u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe. The identical command line appears in PowerShell script-block logging (4104) on scranton, confirming the credential was embedded in a script. This is credential material stored/used in files and command lines rather than a secure store.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:18.784Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\PsExec64.exe" -accepteula \\NASHUA -u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1RqK7jn | q-c180581289 | ok |
| 2 | 2020-05-02 03:11:18.000Z | scranton.dmevals.local | windows.powershell | powershell.script_block_text | .\PsExec64.exe -accepteula \\NASHUA -u "dmevals\pbeesly" -p "Fl0nk3rt0n!T0by" -i 2 "C:\Windows\Temp\python.exe" | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1brw_To | q-1c4a57f360 | ok |
| 3 | 2020-05-02 03:04:35.069Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Program Files\SysinternalsSuite\passwordsDB | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R_lkD8 | q-ca7b558c8c | ok |
| 4 | 2020-05-02 03:11:40.000Z | nashua.dmevals.local | windows.security | process.executable | C:\Windows\PSEXESVC.exe | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YogQzA | q-08ba84f7eb | ok |

### F63 · malicious / high · T1552.001 · pspasswd.exe downloaded and accesschk.exe used to create 'passwordsDB' file on scranton

Evidence status: **verified**

On scranton.dmevals.local, powershell.exe (pid 3876, user pbeesly) created Sysinternals pspasswd64.exe/pspasswd.exe under C:\Users\pbeesly\Downloads\SysinternalsSuite at 03:00:28-03:00:32. At 03:04:34 accesschk.exe was executed by powershell.exe and at 03:04:35 it created a file named 'passwordsDB' in C:\Program Files\SysinternalsSuite. pspasswd is a password-change tool and accesschk is a permissions tool; the 'passwordsDB' artifact indicates credential material being staged to disk.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:00:28.986Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Users\pbeesly\Downloads\SysinternalsSuite\pspasswd64.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1SIw95- | q-338c08e677 | ok |
| 2 | 2020-05-02 03:04:35.069Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Program Files\SysinternalsSuite\passwordsDB | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R_lkD8 | q-78e5a6190e | ok |
| 3 | 2020-05-02 03:04:34.951Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\accesschk.exe" | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R_lkD_ | q-e6b745e35a | ok |

### F64 · malicious / high · T1552.001 · Invoke-Exfil PowerShell function with hardcoded credentials ('cozy'/'MyCozyPassw0rd!') and archive password 'lolol' on scranton

Evidence status: **verified**

On scranton.dmevals.local, user pbeesly ran Invoke-Exfil (psversion.ps1) at 03:08:02. It compresses $env:USERPROFILE\Downloads into OfficeSupplies.7z with password 'lolol', then builds a PSCredential from hardcoded username 'cozy' and password 'MyCozyPassw0rd!' and maps \\192.168.0.4\webdav to copy the archive out. Plaintext credentials are embedded in the script.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | powershell.script_block_text | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b10BXt | q-ad7bba0d06 | ok |
| 2 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | powershell.script_block_text | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b10BXt | q-ad7bba0d06 | ok |

### F65 · malicious / high · T1552.001 · Password-protected Rar archive of user profile created on nashua with hardcoded password

Evidence status: **verified**

On nashua.dmevals.local, user pbeesly ran Rar.exe (staged in C:\Windows\Temp) at 03:16:19 to create working.zip with the hardcoded password 'fGzq5yKw', archiving $env:APPDATA\working.zip. A preceding PowerShell script (03:15:59) collected files matching *psw*, *pass*, *login*, *admin*, *vpn*, *.pst, *.ost etc. from the user profile. The archive and Rar.exe were then wiped with sdelete64.exe.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:16:19.395Z | nashua.dmevals.local | windows.sysmon | process.command_line | "C:\Windows\Temp\Rar.exe" a -hpfGzq5yKw C:\Users\pbeesly\Desktop\working.zip C:\Users\pbeesly\AppData\Roaming\working.zip | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1RhBpvd | q-338f8e19cb | ok |
| 2 | 2020-05-02 03:15:59.000Z | nashua.dmevals.local | windows.powershell | powershell.script_block_text | $env:APPDATA;$files=ChildItem -Path $env:USERPROFILE\ -Include *.doc,*.xps,*.xls,*.ppt,*.pps,*.wps,*.wpd,*.ods,*.odt,*.lwp,*.jtd,*.pdf,*.zip,*.rar,*.docx,*.url,… | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1bsxhdc | q-c17e49a95e | ok |

### F68 · malicious / medium · T1552.001 · Explicit-credential logons (4648) with pbeesly from scranton to nashua via PSEXESVC

Evidence status: **verified**

Security 4648 explicit-credential logon events show pbeesly authenticating on nashua.dmevals.local via C:\Windows\PSEXESVC.exe at 03:11:40, 03:12:46, 03:13:49 and 03:15:03, and on scranton.dmevals.local from 10.0.1.6 at 03:11:18, 03:12:25, 03:13:28 and 03:14:42. This is credential use for lateral movement consistent with the PsExec activity.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:40.000Z | nashua.dmevals.local | windows.security | win.ProcessName | C:\Windows\PSEXESVC.exe | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YogQzA | q-5d7565f440 | ok |
| 2 | 2020-05-02 03:11:18.000Z | scranton.dmevals.local | windows.security | win.IpAddress | 10.0.1.6 | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YcSP2J | q-5d7565f440 | ok |

### F62 · malicious / high · T1552.004 · Get-PrivateKeys PowerShell function exports all LocalMachine certificates with private keys to .pfx files using hardcoded password 'saribas' on scranton

Evidence status: **verified**

On scranton.dmevals.local, user pbeesly ran a PowerShell script (readme.ps1) defining Get-PrivateKeys, which enumerates cert:\LocalMachine recursively and calls Export-PfxCertificate for every cert with a thumbprint, writing random-named .pfx files to $env:USERPROFILE\Downloads protected by the hardcoded password 'saribas'. The function was invoked at 03:04:56 and a .pfx file (coyn5igj.3io.pfx) was created in C:\Users\pbeesly\Downloads at 03:04:57 by powershell.exe. This is private-key theft from the certificate store.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | powershell.script_block_text | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b21vS3 | q-1b35a1ed24 | ok |
| 2 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\readme.ps1 | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b21vS3 | q-1b35a1ed24 | ok |
| 3 | 2020-05-02 03:04:57.460Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R_lUAH | q-72db757240 | ok |

### F36 · malicious / high · T1555 · Interactive PowerShell and WinRM host open LSASS with full-access masks (credential dumping pattern)

Evidence status: **verified**

On scranton.dmevals.local at 2020-05-02T03:05:16Z, a PowerShell process (C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe, PID 0xba0) running as user pbeesly requested a handle to \Device\HarddiskVolume2\Windows\System32\lsass.exe with AccessMask 0x1fffff, which includes 'Read from process memory' and 'Duplicate handle into or out of process' — the access pattern used to read credential material out of LSASS. The same user pbeesly, via wsmprovhost.exe (WinRM remote shell, PID 0x1e28) on nashua.dmevals.local at 2020-05-02T03:09:29Z, requested a handle to lsass.exe with AccessMask 0x1f3fff, again including read-process-memory. These are the only two non-system processes in the dataset that opened LSASS with these high-privilege masks (the 0x1fffff/0x1f3fff buckets otherwise consist of csrss.exe/svchost.exe opening ordinary processes). The activity is part of a broader pbeesly intrusion on scranton/nashua that also includes encoded/hidden PowerShell, sdelete64 anti-forensic wiping, and exfiltration tooling.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | win.AccessMask | 0x1fffff | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YldM_p | q-e5fbb12914 | ok |
| 2 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | win.ProcessName | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YldM_p | q-e5fbb12914 | ok |
| 3 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | win.ObjectName | \Device\HarddiskVolume2\Windows\System32\lsass.exe | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YldM_p | q-e5fbb12914 | ok |
| 4 | 2020-05-02 03:09:29.000Z | nashua.dmevals.local | windows.security | win.AccessMask | 0x1f3fff | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YjaXaO | q-e5fbb12914 | ok |
| 5 | 2020-05-02 03:09:29.000Z | nashua.dmevals.local | windows.security | win.ProcessName | C:\Windows\System32\wsmprovhost.exe | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YjaXaO | q-e5fbb12914 | ok |
| 6 | 2020-05-02 03:09:29.000Z | nashua.dmevals.local | windows.security | win.SubjectUserName | pbeesly | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YjaXaO | q-e5fbb12914 | ok |

### F39 · malicious / high · T1556 · PowerShell Remoting host on NASHUA opened LSASS with full-access mask 0x1f3fff

Evidence status: **verified**

On nashua.dmevals.local at 2020-05-02T03:09:29.430Z, wsmprovhost.exe (PID 7720, the PowerShell Remoting host, running as SYSTEM) opened lsass.exe (PID 728) with GrantedAccess 0x1f3fff — a full-access mask consistent with reading/patching the authentication process rather than the benign 0x1000 query mask seen for svchost. The call trace shows the access originating from PowerShell management assemblies (Microsoft.PowerShell.Commands.Management.ni.dll), i.e. a PowerShell session. This wsmprovhost process was created at 03:09:23.885Z by svchost.exe under user pbeesly, immediately after pbeesly used PsExec64.exe from scranton.dmevals.local to reach \\NASHUA with explicit credentials. This is attacker-driven access to the LSASS authentication process.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1RrM7IJ | q-dcd537ccde | ok |
| 2 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1RrM7IJ | q-dcd537ccde | ok |
| 3 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.TargetImage | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1RrM7IJ | q-dcd537ccde | ok |
| 4 | 2020-05-02 03:09:23.885Z | nashua.dmevals.local | windows.sysmon | process.command_line | C:\windows\system32\wsmprovhost.exe -Embedding | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1RsNKXB | q-3d601348a1 | ok |
| 5 | 2020-05-02 03:09:23.885Z | nashua.dmevals.local | windows.sysmon | user.name | pbeesly | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1RsNKXB | q-3d601348a1 | ok |

### F40 · malicious / high · T1556 · PsExec with plaintext credentials used to move to NASHUA and install PSEXESVC

Evidence status: **verified**

From scranton.dmevals.local, user pbeesly repeatedly launched C:\Program Files\SysinternalsSuite\PsExec64.exe with the command line '"C:\Program Files\SysinternalsSuite\PsExec64.exe" -accepteula \\NASHUA -u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe' (03:11:18, 03:12:25, 03:13:28, 03:14:42). Each run caused the PSEXESVC service to be installed on nashua.dmevals.local (ImagePath %SystemRoot%\PSEXESVC.exe, demand start) and PSEXESVC.exe to execute as SYSTEM, which then produced 4648 explicit-credential logons for pbeesly. This is the credential-reuse/lateral-movement context in which the LSASS access occurred.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:14:42.601Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\PsExec64.exe" -accepteula \\NASHUA -u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1RkEAFq | q-3d601348a1 | ok |
| 2 | 2020-05-02 03:15:03.000Z | nashua.dmevals.local | windows.other | win.ServiceName | PSEXESVC | .ds-logs-windows.other-default-2026.10.16-000001 / AaFFkdQ25mySA1aOnx2W | q-a110df99a2 | ok |
| 3 | 2020-05-02 03:15:03.000Z | nashua.dmevals.local | windows.other | win.ImagePath | %SystemRoot%\PSEXESVC.exe | .ds-logs-windows.other-default-2026.10.16-000001 / AaFFkdQ25mySA1aOnx2W | q-a110df99a2 | ok |
| 4 | 2020-05-02 03:11:40.000Z | nashua.dmevals.local | windows.security | process.executable | C:\Windows\PSEXESVC.exe | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YogQzA | q-cc6121c94d | ok |

### F41 · malicious / high · T1556 · Invoke-Exfil PowerShell script with hardcoded credentials on SCRANTON

Evidence status: **verified**

On scranton.dmevals.local at 2020-05-02T03:08:02Z, user pbeesly executed a PowerShell script block defining 'function Invoke-Exfil' (ScriptBlock ID b2b03a9c-43f0-4285-837d-f22d4600b2ae, Path C:\Program Files\SysinternalsSuite\psversion.ps1). The script compresses the user's Downloads folder into an encrypted 7z archive and copies it to a WebDAV share using hardcoded credentials ($UserName = "cozy", $Password = "MyCozyPassw0rd!"). This demonstrates the operator's use of stolen/hardcoded credentials and staged exfiltration on the same host from which the PsExec credential-reuse to NASHUA originated.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | powershell.script_block_text | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b10BXt | q-19a7207079 | ok |
| 2 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | user.name | pbeesly | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b10BXt | q-19a7207079 | ok |
| 3 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\psversion.ps1 | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b10BXt | q-eec4f1543a | ok |

### F60 · malicious / high · T1649 · PowerShell script exported all LocalMachine certificates with private keys to .pfx files on scranton.dmevals.local

Evidence status: **verified**

On 2020-05-02 at 03:04:56 UTC on host scranton.dmevals.local, user pbeesly executed a PowerShell script block named 'Get-PrivateKeys' (ScriptBlock ID 9d153741-75c3-4062-afe3-aeca0aee611b, Path C:\Program Files\SysinternalsSuite\readme.ps1). The script recursively enumerates cert:\LocalMachine, and for every certificate with a Thumbprint exports it with Export-PfxCertificate to a randomly named .pfx file under $env:USERPROFILE\Downloads, protected by the hardcoded password 'saribas'. This is direct theft of authentication certificates and their private keys (T1649). The export is corroborated by Sysmon: powershell.exe read HKLM\SOFTWARE\Microsoft\SystemCertificates\MY\Certificates\48B5E43D09D080DF8863152FD22ED7C43443D499\Blob and ...\Remote Desktop\Certificates\615B93C2D2B647D1670500B3338EAAEC83BA5646\Blob at 03:04:57, and wrote C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx at 03:04:57.460. The activity is preceded (02:58:44) by a hidden, execution-policy-bypassed PowerShell launched by control.exe that decodes a payload from C:\Users\pbeesly\Downloads\monkey.png and IEXes it, indicating an initial stager on the same host/user. The certificate registry writes on other hosts (svchost.exe/lsass.exe/taskhostw.exe touching AuthRoot, Windows Live ID Token Issuer, ACRS stores) are normal OS certificate-store maintenance and are not attributed to the attacker.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | powershell.script_block_text | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b21vS3 | q-bf52516863 | ok |
| 2 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | powershell.script_block_text | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b21vS3 | q-bf52516863 | ok |
| 3 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\readme.ps1 | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b21vS3 | q-bf52516863 | ok |
| 4 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | user.name | pbeesly | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b21vS3 | q-bf52516863 | ok |
| 5 | 2020-05-02 03:04:57.460Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R_lUAH | q-ad1f505113 | ok |
| 6 | 2020-05-02 03:04:57.428Z | scranton.dmevals.local | windows.sysmon | registry.path | HKLM\SOFTWARE\Microsoft\SystemCertificates\MY\Certificates\48B5E43D09D080DF8863152FD22ED7C43443D499\Blob | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R_lED5 | q-142357c0af | ok |
| 7 | 2020-05-02 02:58:44.325Z | scranton.dmevals.local | windows.sysmon | process.command_line | "PowerShell.exe" -noni -noexit -ep bypass -window hidden -c "sal a New-Object;Add-Type -AssemblyName 'System.Drawing'; $g=a System.Drawing.Bitmap('C:\Users\pbee… | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1WdFNhN | q-60d111b604 | ok |

### F10 · suspicious / medium · T1040 · Attacker activity in window is PsExec lateral movement and python C2, not network sniffing

Evidence status: **verified**

The genuine malicious activity in this window is unrelated to T1040: on scranton.dmevals.local, PsExec64.exe (parent powershell.exe, user pbeesly) repeatedly runs against \\NASHUA with plaintext credentials (-u dmevals\pbeesly -p Fl0nk3rt0n!T0by) to launch C:\Windows\Temp\python.exe. On nashua.dmevals.local that python.exe (parent C:\Windows\PSEXESVC.exe, user pbeesly) then opens hundreds of TCP connections to 192.168.0.4:8443. This is lateral movement/execution and C2, not credential sniffing, so it does not satisfy T1040; it is noted here only to distinguish it from the benign capture activity.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:18.784Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\PsExec64.exe" -accepteula \\NASHUA -u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1RqK7jn | q-5f8cd3abf7 | ok |
| 2 | 2020-05-02 03:11:40.213Z | nashua.dmevals.local | windows.sysmon | process.command_line | "C:\Windows\Temp\python.exe"  | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1RpKsKx | q-97a7446451 | ok |
| 3 | 2020-05-02 03:15:05.142Z | nashua.dmevals.local | windows.sysmon | destination.ip | 192.168.0.4 | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1RjDSP- | q-92c22131f6 | ok |

### F24 · suspicious / medium · T1187 · SMB/445 connections to 192.168.0.4 from scranton and nashua workstations

Evidence status: **verified**

Zeek conn records show outbound SMB traffic to 192.168.0.4: 10 connections on port 445 (all from 10.0.1.4) and 5 on port 139, alongside 392 total connections from 10.0.1.6 (376) and 10.0.1.4 (16) to 192.168.0.4. Sysmon event code 3 confirms a connection from nashua.dmevals.local to 10.0.0.4:445. The same 192.168.0.4 host is the WebDAV coercion target, so the SMB traffic to it is consistent with the same forced-authentication/credential-capture activity rather than ordinary file sharing.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-04-30 00:32:21.422Z | simplerockbuild.simplerock.lan | zeek | destination.ip | 192.168.0.4 | .ds-logs-zeek-default-2026.10.16-000001 / AaFFktQ25mySA1aO8Ieh | q-0452973b93 | ok |
| 2 | 2020-05-02 03:21:57.321Z | nashua.dmevals.local | windows.sysmon | destination.port | 445 | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1MsQYML | q-48c9a5fad4 | ok |
| 3 | 2020-05-02 03:21:57.321Z | nashua.dmevals.local | windows.sysmon | host.name | nashua.dmevals.local | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1MsQYML | q-48c9a5fad4 | ok |

### F37 · suspicious / medium · T1555.004 · LSASS handle requests by user processes (Credential Manager/DPAPI harvest mechanism) — no vault object access observed

Evidence status: **verified**

The LSASS handle requests with 0x1fffff (scranton, powershell.exe, pbeesly) and 0x1f3fff (nashua, wsmprovhost.exe, pbeesly) are the mechanism by which Windows Credential Manager / DPAPI secrets held in LSASS memory would be harvested, so they are relevant to T1555.004. However, no direct access to Credential Manager vault objects, DPAPI Protect/Credential/Vault object names, or cmdkey/vaultcmd execution was observed: the only credential-related object-access events on lsass.exe were from C:\WindowsAzure\Packages\CollectGuestLogs.exe (Azure guest log collection, benign) and Windows Defender MsMpEng.exe, and the only 'Credential' string in windows.other was the benign 'Credential Guard configuration: 0x0, 0' event on scranton. The credential-store-specific artifact is therefore not directly observed; the LSASS access is attributed to T1555 broadly.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:22:38.000Z | nashua.dmevals.local | windows.security | win.ProcessName | C:\WindowsAzure\Packages\CollectGuestLogs.exe | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YEBswS | q-e5fbb12914 | ok |
| 2 | 2020-05-02 03:20:15.000Z | scranton.dmevals.local | windows.security | win.ProcessName | C:\Program Files\Windows Defender\MsMpEng.exe | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YGClc_ | q-e5fbb12914 | ok |
| 3 | 2020-05-02 03:19:09.000Z | scranton.dmevals.local | windows.other | message | Credential Guard configuration: 0x0, 0 | .ds-logs-windows.other-default-2026.10.16-000001 / AaFFkdQ25mySA1aOnx1Y | q-3fb3fd1aac | ok |

### F03 · benign / high · T1003.002 · SAM registry value writes are by lsass.exe itself (normal OS behavior)

Evidence status: **verified**

Sysmon event 13 writes to HKLM\SAM\SAM\Domains\Account\F on scranton.dmevals.local at 03:19:10 were performed by C:\windows\system32\lsass.exe (PID 748, SYSTEM), not by any attacker tool. No reg save, no SAM hive file copy, and no non-lsass process touching SAM was observed. This is routine LSASS maintenance of the SAM database, not credential dumping.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:10.368Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1NY3HhA | q-0cd5c6ed25 | ok |
| 2 | 2020-05-02 03:19:10.368Z | scranton.dmevals.local | windows.sysmon | registry.path | HKLM\SAM\SAM\Domains\Account\F | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1NY3HhA | q-0cd5c6ed25 | ok |

### F05 · benign / high · T1003.003 · No NTDS / domain-database dumping observed

Evidence status: **verified**

No ntds.dit file access, no vssadmin/diskshadow/ntdsutil execution, and no NTDS-related file creation were found in sysmon, security, powershell or other datasets. The activity is confined to LSASS memory access and host-level credential collection, not domain controller database theft.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:21:28.476Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Windows\Prefetch\SECURITYHEALTHSYSTRAY.EXE-41AD6DE1.pf | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1MtUmZF | q-9318992e9f | ok |

### F06 · benign / high · T1003.004 · No LSA Secrets dumping observed

Evidence status: **verified**

No access to SECURITY\Policy\Secrets registry keys, no lsadump/reg save of the SECURITY hive, and no LSA-secret-related script blocks were found. The only SECURITY-hive writes were lsass.exe updating its own Cache\NL$1 values.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:15:03.894Z | nashua.dmevals.local | windows.sysmon | registry.path | HKLM\SECURITY\Cache\NL$1 | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1RjDyQJ | q-0c11bb288b | ok |

### F04 · benign / high · T1003.005 · SECURITY\Cache\NL$1 writes are by lsass.exe (normal cached-credential maintenance)

Evidence status: **verified**

Sysmon event 13 writes to HKLM\SECURITY\Cache\NL$1 on nashua.dmevals.local (03:11-03:15) and scranton.dmevals.local (03:20) were all performed by C:\windows\system32\lsass.exe. These are the OS updating its own cached domain credential entries, not an attacker extracting them. No tool read or exported the cache.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:40.144Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1RpKsLE | q-0c11bb288b | ok |
| 2 | 2020-05-02 03:20:46.691Z | scranton.dmevals.local | windows.sysmon | registry.path | HKLM\SECURITY\Cache\NL$1 | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1NAd3XG | q-0c11bb288b | ok |

### F07 · benign / high · T1003.006 · No DCSync observed

Evidence status: **verified**

No drsuapi/DCSync command lines, no lsadump script blocks, and no directory-replication abuse were found in sysmon or powershell datasets. No evidence of DCSync in this window.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:09.809Z | scranton.dmevals.local | windows.sysmon | process.command_line | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1NY3HhL | q-17e83cdfad | ok |

### F08 · benign / high · T1040 · Azure Network Watcher packet capture on scranton.dmevals.local is legitimate platform monitoring, not adversary sniffing

Evidence status: **verified**

The only packet-capture activity in the dataset is the Azure Network Watcher agent on scranton.dmevals.local. NetworkWatcherAgent.exe (parent C:\Windows\System32\services.exe, user SYSTEM) starts a capture via netsh.exe 'trace start capture=yes traceFile=...etl' and manages ETW trace sessions with logman.exe (GAEvents/RTEvents, output to C:\WindowsAzure\Logs\*.etl). All parent processes are Azure guest-agent components (WaAppAgent.exe, WindowsAzureGuestAgent.exe, services.exe) and the binaries live under C:\Packages\Plugins\Microsoft.Azure.NetworkWatcher... and C:\WindowsAzure\Packages. This is the standard Azure VM network-capture/diagnostics agent, not an adversary sniffing tool. No tcpdump/windump/wireshark/rawcap, no Npcap/WinPcap driver load, no pcap files, and no promiscuous-mode commands were observed on any host.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:17.154Z | scranton.dmevals.local | windows.sysmon | process.command_line | C:\windows\system32\netsh.exe trace start capture=yes traceFile="C:\windows\TEMP\E7116ECA-DFE6-43C7-8FA8-8D3AC5AA8726\B91E06C5-1C7C-4830-9A76-74FA211560A7.etl" | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1NW1Kgv | q-84eefb22c8 | ok |
| 2 | 2020-05-02 03:19:13.877Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\Packages\Plugins\Microsoft.Azure.NetworkWatcher.NetworkWatcherAgentWindows\1.4.1421.1\NetworkWatcherAgent\NetworkWatcherAgent.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1WpSJN6 | q-84eefb22c8 | ok |
| 3 | 2020-05-02 03:19:29.878Z | scranton.dmevals.local | windows.sysmon | process.command_line | "logman.exe" create trace GAEvents -max 50 -f bincirc -o C:\WindowsAzure\Logs\WaAppAgent.etl -p "{3000b92b-ca8b-4269-90ea-c4185ee09e92}" | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1NUxiiK | q-84eefb22c8 | ok |
| 4 | 2020-05-02 03:19:17.000Z | scranton.dmevals.local | windows.security | process.parent.executable | C:\Packages\Plugins\Microsoft.Azure.NetworkWatcher.NetworkWatcherAgentWindows\1.4.1421.1\NetworkWatcherAgent\NetworkWatcherAgent.exe | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YYOcv1 | q-3cae958a01 | ok |

### F09 · benign / high · T1040 · No sniffing tooling, capture drivers or pcap artifacts found on any host

Evidence status: **verified**

Searches for network-sniffing tooling across the Windows datasets returned no adversary capture activity: no process creation of tcpdump/windump/wireshark/rawcap, no image load of npcap/pcap/winpcap drivers, no pcap/sniff/promiscuous strings in PowerShell script blocks, and no pcap files written. The only .etl files created are OS/Azure diagnostic logs (ProvTool, waasmedic, SleepStudy, WDI, DiagnosticLogCSP) written by System/svchost/ProvTool. The zeek ICMP connection check also returned zero hits. The technique is therefore not observed as attacker behaviour in this window.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:02:47.444Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\ProgramData\Microsoft\DiagnosticLogCSP\Collectors\DiagnosticLogCSP_Collector_DeviceProvisioning.etl | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1SDpYge | q-f3406a6f9f | ok |
| 2 | 2020-05-02 03:10:11.658Z | nashua.dmevals.local | windows.sysmon | win.TargetFilename | C:\Windows\System32\SleepStudy\user-not-present-trace-2020-05-01-23-10-11.etl | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1RrMbJC | q-f3406a6f9f | ok |

### F13 · benign / high · T1056 · Benign LSASS handle requests by system processes (svchost, Defender, Azure agents)

Evidence status: **verified**

The bulk of LSASS process-access events are legitimate: svchost.exe (0x1000, 216+30+28+12 events across scranton/newyork/nashua/utica), Microsoft Azure IaaSAntimalware AntimalwareConfig.exe and WindowsAzureTelemetryService.exe (0x1400), and MsMpEng.exe — all with normal module-backed call traces (ntdll/KERNELBASE/perfts/CorperfmonExt). Security 4656 handle requests to lsass.exe/SAM by SCRANTON$ (SYSTEM) and by lsass.exe itself are routine OS activity. These are not credential capture.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:56:14.000Z | utica.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\svchost.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1WhJHLy | q-2b8666ceb7 | ok |
| 2 | 2020-05-02 03:20:41.869Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\Packages\Plugins\Microsoft.Azure.Security.IaaSAntimalware\1.5.5.9\AntimalwareConfig.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1NAenUm | q-f30dad9955 | ok |
| 3 | 2020-05-02 03:19:21.000Z | scranton.dmevals.local | windows.security | win.ObjectType | SAM_SERVER | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YWMnGq | q-e9860a3d85 | ok |

### F14 · benign / medium · T1056.001 · No keylogger-specific API usage observed

Evidence status: **verified**

No process-creation command lines or PowerShell script blocks referencing keylogging APIs (GetAsyncKeyState, SetWindowsHookEx, keylog) were found; the corresponding checks returned zero hits. The LSASS/winlogon/explorer process-access events observed are dominated by svchost.exe with 0x1000 and by the malicious PowerShell LSASS open already reported under T1056.004, not by a keyboard-capture hook.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:01:04.106Z | scranton.dmevals.local | windows.sysmon | win.TargetImage | C:\windows\system32\winlogon.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1SIv93X | q-2b8666ceb7 | ok |

### F15 · benign / medium · T1056.002 · No GUI input capture / credential prompt abuse observed

Evidence status: **verified**

No process-creation events with command lines referencing Credential or prompt-based GUI capture were found (check returned zero hits). No evidence of fake credential prompt or GUI input capture on the monitored hosts.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:06:59.218Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -Version 5.1 -s -NoLogo -NoProfile | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R4eBiX | q-87789bffbe | ok |

### F16 · benign / medium · T1056.003 · No web portal capture observed

Evidence status: **verified**

No file writes to web roots (wwwroot/inetpub/login/portal), no IIS/w3wp process activity, and no HTTP POST or login/portal URLs were found in the datasets (checks returned zero hits). No evidence of web portal credential capture.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:06:59.218Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R4eBiX | q-87789bffbe | ok |

### F17 · benign / high · T1110 · No brute-force authentication activity; credential access was via LSASS dumping and key theft

Evidence status: **verified**

Across windows.security (41002 events, 2020-05-02T02:55:25Z..03:28:09Z) there are zero 4625 failed-logon events (count=0), and windows.other contains no account-lockout or failed-authentication messages. The only authentication-related hits are benign: a Remote Desktop session logon succeeded for DMEVALS\pbeesly (event 21) and a Customer Experience Improvement Program logon notification (event 7001) on scranton. No repeated authentication attempts, no password guessing, spraying or stuffing is present. The credential access that did occur on these hosts was LSASS memory access and private-key export, not brute force.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:20:48.000Z | scranton.dmevals.local | windows.other | message | Remote Desktop Services: Session logon succeeded:    User: DMEVALS\pbeesly  Session ID: 2  Source Network Address: 172.18.39.2 | .ds-logs-windows.other-default-2026.10.16-000001 / AaFFkdQ25mySA1aOnx0y | q-c66889ee05 | ok |
| 2 | 2020-05-02 03:20:46.000Z | scranton.dmevals.local | windows.other | message | User Logon Notification for Customer Experience Improvement Program | .ds-logs-windows.other-default-2026.10.16-000001 / AaFFkdQ25mySA1aOnx04 | q-c2e8442d97 | ok |

### F18 · benign / high · T1110.001 · No password-guessing attempts observed

Evidence status: **verified**

No 4625 failed logons exist in windows.security (count=0) and no failed-authentication messages in windows.other. The PowerShell hits matching *Password*/*Credential* are not guessing loops: they are a Get-PrivateKeys function that exports certificates using a hardcoded password, and an Invoke-Exfil function that uses a hardcoded credential to map a WebDAV share. No iteration over candidate passwords against an authentication service was seen.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | powershell.script_block_text | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b21vS3 | q-40a49a4e11 | ok |
| 2 | 2020-05-02 03:18:54.000Z | scranton.dmevals.local | windows.other | message | Crash dump initialization failed! | .ds-logs-windows.other-default-2026.10.16-000001 / AaFFkdQ25mySA1aOnx1g | q-395208af39 | ok |

### F20 · benign / high · T1110.003 · No password-spraying pattern; explicit-credential logons are PSEXESVC lateral movement

Evidence status: **verified**

There are no 4625 failures (count=0) and no account-lockout messages, so no spray pattern exists. The 4648 explicit-credential logons on nashua.dmevals.local (23:11:40, 23:12:46, 23:13:49, 23:15:03) all use the single account pbeesly via C:\Windows\PSEXESVC.exe targeting localhost, matching PsExec service installation (event 7045 PSEXESVC) — lateral movement with already-obtained credentials, not a spray of one password across many accounts.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:40.000Z | nashua.dmevals.local | windows.security | process.executable | C:\Windows\PSEXESVC.exe | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YogQzA | q-a78f5f004c | ok |
| 2 | 2020-05-02 03:11:40.000Z | nashua.dmevals.local | windows.security | win.TargetUserName | pbeesly | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YogQzA | q-a78f5f004c | ok |
| 3 | 2020-05-02 03:11:39.000Z | nashua.dmevals.local | windows.other | message | A service was installed in the system.    Service Name:  PSEXESVC  Service File Name:  %SystemRoot%\PSEXESVC.exe  Service Type:  user mode service  Service Star… | .ds-logs-windows.other-default-2026.10.16-000001 / AaFFkdQ25mySA1aOnx2T | q-c2e8442d97 | ok |

### F21 · benign / high · T1110.004 · No credential-stuffing activity observed

Evidence status: **verified**

No 4625 failed logons exist in windows.security (count=0) and no failed-authentication messages in windows.other, so there is no evidence of many username/password pairs being tried against a service. The only credential reuse seen is the single account pbeesly used for PSEXESVC lateral movement and the hardcoded credentials inside the attacker's PowerShell scripts, which is credential theft/reuse rather than stuffing.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:12:46.000Z | nashua.dmevals.local | windows.security | win.TargetUserName | pbeesly | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YcSCoM | q-a78f5f004c | ok |
| 2 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | powershell.script_block_text | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b10BXt | q-d769627643 | ok |

### F22 · benign / medium · T1111 · No MFA/smart-card/OTP interception artifacts; credential theft toolkit observed instead

Evidence status: **verified**

Hunting for T1111 (Multi-Factor Authentication Interception) across windows.security, windows.sysmon, windows.powershell and windows.other produced no evidence of MFA interception. All 297 successful logons (4624) are ordinary types (3 network=218, 5 service=61, 2 interactive=15, 10 RDP=2, 0=1) using Negotiate/Kerberos; the 218 Kerberos logons are machine-account (computer$) network logons on newyork.dmevals.local. The 15 explicit-credential logons (4648) are pbeesly via PSEXESVC.exe/svchost.exe and built-in DWM/UMFD/winlogon accounts. LSASS access (Sysmon 10, 326 events) is dominated by svchost.exe with GrantedAccess 0x1000 (PROCESS_QUERY_LIMITED_INFORMATION) — normal. Registry 'Credential' hits are CredentialGuard/CredentialEnrollmentManager service setup by lsass.exe/services.exe — benign OS activity. No smart-card, OTP, token-interception, or credential-provider tampering was observed. However, the same window contains genuine credential-access activity on scranton.dmevals.local by user pbeesly (a PowerShell toolkit psversion.ps1/readme.ps1 exporting machine certificate private keys, capturing keystrokes/clipboard/screenshots, and PowerShell.exe opening LSASS with full access 0x1FFFFF) — this is credential theft (T1552.004/T1056.001/T1003), not MFA interception, so it is reported here as context rather than as a T1111 hit.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R-k131 | q-add0c8009d | ok |
| 2 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R-k131 | q-add0c8009d | ok |
| 3 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | powershell.script_block_text | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b21vS3 | q-5656560e3a | ok |
| 4 | 2020-05-02 03:06:59.000Z | scranton.dmevals.local | windows.powershell | powershell.script_block_text | Get-Keystrokes;Start-Sleep -Seconds 15;View-Job -JobName "Keystrokes" | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b21_Tx | q-9acda950d9 | ok |
| 5 | 2020-05-02 02:56:14.000Z | utica.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1000 | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1WhJHLy | q-851218a46a | ok |
| 6 | 2020-05-02 03:20:46.000Z | scranton.dmevals.local | windows.security | win.TargetServerName | localhost | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YQHQbW | q-db841aebf3 | ok |

### F25 · benign / medium · T1187 · Inbound SMB share access to SYSVOL on newyork from SCRANTON$ and NEWYORK$ machine accounts

Evidence status: **verified**

Security events 5140/5145 on newyork.dmevals.local show network share access to \\*\SYSVOL from machine accounts NEWYORK$ (fe80::e40c:95b6:b0a7:6429) and SCRANTON$ (10.0.1.4). These are domain-controller SYSVOL/Group Policy reads by computer accounts, a routine AD replication/GPO pattern, not credential coercion. No attacker-controlled listener or credential capture is evidenced here.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:56:47.000Z | newyork.dmevals.local | windows.security | user.name | NEWYORK$ | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YsmIPl | q-15335b5bc8 | ok |
| 2 | 2020-05-02 03:01:43.000Z | newyork.dmevals.local | windows.security | user.name | SCRANTON$ | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YcRSol | q-15335b5bc8 | ok |
| 3 | 2020-05-02 03:01:43.000Z | newyork.dmevals.local | windows.security | source.ip | 10.0.1.4 | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YcRSol | q-15335b5bc8 | ok |

### F27 · benign / medium · T1212 · Kerberos service-ticket requests (4768/4769) are routine domain authentication, not exploitation

Evidence status: **verified**

The 42 Kerberos events (28x 4769, 14x 4768) on newyork.dmevals.local are ordinary service-ticket requests by the domain account pbeesly@DMEVALS.LOCAL and machine accounts (SCRANTON$) from client addresses 10.0.1.4/10.0.1.6, requesting tickets for NEWYORK$, NASHUA$ and krbtgt. No anomalous encryption downgrade, no RC4-only pattern, no ticket-forging indicators were observed; these are normal domain logon/ticket-granting activity and do not by themselves evidence exploitation for credential access.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:04.000Z | newyork.dmevals.local | windows.security | event.code | 4769 | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YhYtYv | q-dab7464ed4 | ok |
| 2 | 2020-05-02 03:04:04.000Z | newyork.dmevals.local | windows.security | user.name | pbeesly@DMEVALS.LOCAL | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YhYtYv | q-dab7464ed4 | ok |
| 3 | 2020-05-02 03:19:13.000Z | newyork.dmevals.local | windows.security | user.name | SCRANTON$@DMEVALS.LOCAL | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YOGdm5 | q-dab7464ed4 | ok |

### F28 · benign / medium · T1212 · Zeek notices/weird records show no exploit traffic tied to credential access

Evidence status: **verified**

The 14 Zeek notice/weird records (2020-04-30, non-overlapping with the Windows windows) are generic protocol anomalies: ip_hdr_len_zero, truncated_IP, unknown_dce_rpc_auth_type, and two SSL::Invalid_Server_Cert notices for self-signed certificates. None indicate exploitation for credential access, and the Zeek window does not overlap the Windows credential-access activity.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-04-30 00:15:18.392Z | simplerockbuild.simplerock.lan | zeek | message | {"@stream":"notice","@system":"simplerockbuild.simplerock.lan","@proc":"zeek","ts":1588205718.392851,"uid":"CN30222JydecBjLXGh","id_orig_h":"10.0.1.4","id_orig_… | .ds-logs-zeek-default-2026.10.16-000001 / AaFFktQ25mySA1aO74el | q-82ea4581f4 | ok |
| 2 | 2020-04-30 00:14:21.969Z | simplerockbuild.simplerock.lan | zeek | message | {"@stream":"weird","@system":"simplerockbuild.simplerock.lan","@proc":"zeek","ts":1588205661.969959,"uid":"C3HnI71C1OMdjvWltf","id_orig_h":"10.0.1.4","id_orig_p… | .ds-logs-zeek-default-2026.10.16-000001 / AaFFktQ25mySA1aO8IdY | q-82ea4581f4 | ok |

### F29 · benign / high · T1539 · WebDAV client cookie operations (DavSetCookie / INetCookies) on scranton — benign

Evidence status: **verified**

The only 'cookie'-matching process activity is the Windows WebDAV client: rundll32.exe loading davclnt.dll,DavSetCookie to set a WebDAV cookie for the mount http://192.168.0.4/webdav, run as user pbeesly on scranton.dmevals.local (5 events, 2020-05-02 03:08:50–03:10:23). The matching Sysmon file-creation is svchost.exe creating the LocalService INetCookies store under a Windows package AC directory. These are standard WebDAV/IE cookie-store operations, not theft of browser session cookies.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:08:50.000Z | scranton.dmevals.local | windows.security | process.command_line | rundll32.exe C:\windows\system32\davclnt.dll,DavSetCookie 192.168.0.4 http://192.168.0.4/webdav | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YeU-Dp | q-8305b35bb0 | ok |
| 2 | 2020-05-02 03:21:05.681Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Windows\ServiceProfiles\LocalService\AppData\Local\Packages\warp_jit_db4a1097-b484-4973-bbf2-a04208ecd4d4\AC\INetCookies | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1MsOhX7 | q-8f9632d07c | ok |

### F30 · benign / high · T1539 · Edge browser file activity on scranton/nashua — benign browser operation

Evidence status: **verified**

Sysmon file-creation and process-access events touching MicrosoftEdge.exe/MicrosoftEdgeCP.exe are generated by the browser itself (Temp, Recovery, DataStore files) and by Explorer.exe (GrantedAccess 0x2000) and svchost.exe (0x3000) on nashua.dmevals.local. No non-browser process read or copied a browser cookie database (no Cookies/Login Data/Web Data file access was found).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:21:05.914Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Users\pbeesly\AppData\Local\Packages\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\AC\MicrosoftEdge\User\Default\Recovery\Active\RecoveryStore.{5E6C474D-D0E6-4BC1-A0… | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1MsPCud | q-8af8ca73da | ok |
| 2 | 2020-05-02 03:24:23.993Z | nashua.dmevals.local | windows.sysmon | win.GrantedAccess | 0x2000 | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1Muar8B | q-5dec91cf7d | ok |

### F31 · benign / high · T1539 · No web session cookie theft observed; environment shows unrelated attacker activity

Evidence status: **verified**

Across windows.security, windows.sysmon, windows.powershell and windows.other there is no evidence of browser session cookie theft: no cookie-stealer tooling, no access to browser cookie stores, and no cookie-referencing PowerShell script blocks (C158/C159 zero hits). The environment does contain other attacker activity (PsExec64.exe with plaintext credentials to \\NASHUA, python.exe, sdelete64.exe wiping C:\programdata\victim\???cod.3aka3.scr), but none of it constitutes T1539.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:14:42.601Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\PsExec64.exe" -accepteula \\NASHUA -u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1RkEAFq | q-84f37fa1ed | ok |
| 2 | 2020-05-02 03:02:04.324Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\sdelete64.exe" /accepteula C:\programdata\victim\???cod.3aka3.scr | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1SEqWk4 | q-84f37fa1ed | ok |

### F35 · benign / high · T1552.002 · Registry Password/Credential value writes are OS service activity

Evidence status: **verified**

The 17 Sysmon event-13 registry writes matching Password/Credential keys on nashua/scranton are all performed by legitimate system processes: svchost.exe writing HKU\.DEFAULT\Software\Microsoft\IdentityCRL\ProviderPasswordLength/CharacterGroups, lsass.exe writing DeviceGuard\Scenarios\CredentialGuard\Enabled, services.exe writing CredentialEnrollmentManagerUserSvc service keys, and winlogon.exe writing Winlogon\PasswordExpiryNotification. None represent an adversary storing or harvesting credentials in the registry.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:28.255Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\svchost.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R8i4gn | q-fd263345ab | ok |
| 2 | 2020-05-02 03:19:09.865Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1NY3HhV | q-fd263345ab | ok |
| 3 | 2020-05-02 03:21:20.841Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\winlogon.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1MtSxRG | q-fd263345ab | ok |

### F34 · benign / high · T1552.006 · SYSVOL GPO file access is normal machine-account Group Policy processing

Evidence status: **verified**

SMB/SYSVOL access to GPO files (gpt.ini, GptTmpl.inf, SecEdit, Machine\Microsoft\Windows NT) was observed in both zeek (2020-04-30, observers simplerockbuild.simplerock.lan and bobs.bigwheel.local reading \\NEWYORK.dmevals.local\sysvol) and windows.security 5145 events on newyork.dmevals.local. All 5145 subjects are machine accounts (NEWYORK$, SCRANTON$, NASHUA$) performing routine Group Policy refresh, and the zeek smb_files records are SMB::FILE_OPEN of standard policy paths. No Groups.xml with cpassword was read by a user account, and no attacker process accessed SYSVOL. This is expected domain behaviour, not GPP credential harvesting.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:01:43.000Z | newyork.dmevals.local | windows.security | user.name | SCRANTON$ | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YcRSol | q-d4f213e0ee | ok |
| 2 | 2020-05-02 02:56:47.000Z | newyork.dmevals.local | windows.security | user.name | NEWYORK$ | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1Yph4sr | q-d4f213e0ee | ok |
| 3 | 2020-04-30 00:12:01.659Z | simplerockbuild.simplerock.lan | zeek | event.action | smb_files | .ds-logs-zeek-default-2026.10.16-000001 / AaFFktQ25mySA1aO8IeO | q-7a24e7204b | ok |

### F38 · benign / high · T1555.003 · No browser credential-store access observed

Evidence status: **verified**

No evidence of web-browser credential theft was found. Searches for browser credential artifacts (Login Data, logins.json, cookies) in Sysmon file-create events, for browser processes (chrome.exe/firefox.exe) as LSASS access targets, and for browser-credential strings in PowerShell script blocks and Windows security object-access events returned no hits. The only cookie-related file event was an INetCookies file under a LocalService package profile on scranton, which is normal OS/app behaviour.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:21:05.681Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Windows\ServiceProfiles\LocalService\AppData\Local\Packages\warp_jit_db4a1097-b484-4973-bbf2-a04208ecd4d4\AC\INetCookies | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1MsOhX7 | q-b66a9ac021 | ok |

### F42 · benign / high · T1556 · Routine LSASS handle access by svchost and security agents (benign baseline)

Evidence status: **verified**

The bulk of the 326 LSASS-access events are benign: 289 from C:\windows\system32\svchost.exe and 28 from Microsoft Azure security/telemetry agents (AntimalwareConfig.exe, WindowsAzureTelemetryService.exe), overwhelmingly with GrantedAccess 0x1000 (PROCESS_QUERY_LIMITED_INFORMATION) or 0x1400. These are normal Windows service and AV/telemetry reads of LSASS, not authentication-process modification. The two powershell.exe LSASS accesses on scranton (0x1000, call trace through System.ni.dll) are likewise low-privilege query access.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:56:14.000Z | utica.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1000 | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1WhJHLy | q-e2bce0d50a | ok |
| 2 | 2020-05-02 02:56:14.000Z | utica.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\svchost.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1WhJHLy | q-e2bce0d50a | ok |
| 3 | 2020-05-02 03:20:41.869Z | scranton.dmevals.local | windows.sysmon | win.SourceImage | C:\Packages\Plugins\Microsoft.Azure.Security.IaaSAntimalware\1.5.5.9\AntimalwareConfig.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1NAenUm | q-dcd537ccde | ok |

### F43 · benign / high · T1556 · Benign cryptdll/samlib/samcli image loads into normal Windows processes

Evidence status: **verified**

The 77 image-load hits for lsass/cryptdll/sam/msv1_0 are ordinary Microsoft-signed DLL loads (cryptdll.dll 'Cryptography Manager', samlib.dll 'SAM Library DLL', samcli.dll 'Security Accounts Manager Client DLL') into legitimate processes such as SearchProtocolHost.exe, SearchFilterHost.exe, WmiPrvSE.exe, svchost.exe, dsregcmd.exe and powershell.exe. No unsigned or non-Microsoft module was loaded into LSASS, so this does not indicate authentication-process modification.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:57:01.962Z | scranton.dmevals.local | windows.sysmon | win.ImageLoaded | C:\Windows\System32\cryptdll.dll | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1WgHZ_S | q-0249c50b17 | ok |
| 2 | 2020-05-02 03:01:42.236Z | scranton.dmevals.local | windows.sysmon | win.ImageLoaded | C:\Windows\System32\samlib.dll | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1SFrjaS | q-0249c50b17 | ok |
| 3 | 2020-05-02 03:04:04.220Z | scranton.dmevals.local | windows.sysmon | win.ImageLoaded | C:\Windows\System32\samcli.dll | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1SAnG1Y | q-0249c50b17 | ok |

### F44 · benign / high · T1556 · Benign LSA registry writes by lsass.exe and password-expiry notifications

Evidence status: **verified**

Registry writes touching LSA/password keys are normal OS behaviour: lsass.exe writing HKLM\System\CurrentControlSet\Control\Lsa\ProductType, LsaCfgFlagsDefault and LsaPid on scranton, svchost.exe writing IdentityCRL ProviderPasswordLength/CharacterGroups, and winlogon.exe writing the per-user PasswordExpiryNotification NotShownReason. No Notification Packages (password filter DLL) or NetworkProvider value was modified, so no T1556.002/T1556.008 persistence was established.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:10.368Z | scranton.dmevals.local | windows.sysmon | registry.path | HKLM\System\CurrentControlSet\Control\Lsa\ProductType | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1NY3HhB | q-3e9ce006f0 | ok |
| 2 | 2020-05-02 03:05:28.255Z | nashua.dmevals.local | windows.sysmon | registry.path | HKU\.DEFAULT\Software\Microsoft\IdentityCRL\ProviderPasswordLength | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R8i4gn | q-3e9ce006f0 | ok |
| 3 | 2020-05-02 03:21:20.841Z | scranton.dmevals.local | windows.sysmon | registry.path | HKU\S-1-5-21-1830255721-3727074217-2423397540-1107\Software\Microsoft\Windows\Winlogon\PasswordExpiryNotification\NotShownReason | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1MtSxRG | q-3e9ce006f0 | ok |

### F45 · benign / medium · T1557 · No adversary-in-the-middle activity; observed credential theft is PsExec-based lateral movement, not AiTM

Evidence status: **verified**

Across windows.security, windows.sysmon, windows.other, windows.powershell and zeek there is no evidence of an adversary positioned in the middle of network traffic. The only credential-related activity is plaintext-credential lateral movement: on scranton.dmevals.local user pbeesly ran PsExec64.exe against \\NASHUA with explicit credentials (-u dmevals\pbeesly -p Fl0nk3rt0n!T0by) to launch C:\Windows\Temp\python.exe, which installed the PSEXESVC service on nashua.dmevals.local. That is T1021.002/T1078/T1003 territory, not T1557. Object-access stacking (4663/4670/4656) shows only routine processes (powershell, svchost, WmiPrvSE, services, lsass) touching Key/Token/File objects, and Sysmon network connections (event 3) show normal domain traffic (LDAP 389, Kerberos 88, SMB 445, DNS 53) with no unexpected relay host.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:14:42.601Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\PsExec64.exe" -accepteula \\NASHUA -u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1RkEAFq | q-a8d08ed2cc | ok |
| 2 | 2020-05-02 03:15:03.000Z | nashua.dmevals.local | windows.other | win.ServiceName | PSEXESVC | .ds-logs-windows.other-default-2026.10.16-000001 / AaFFkdQ25mySA1aOnx2W | q-f99115af28 | ok |
| 3 | 2020-05-02 03:12:46.000Z | nashua.dmevals.local | windows.security | win.ServiceFileName | %SystemRoot%\PSEXESVC.exe | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YcRyrP | q-71f000a757 | ok |

### F46 · benign / medium · T1557.001 · No name-resolution poisoning or SMB relay; DNS/WPAD lookups are routine and unanswered

Evidence status: **verified**

Name-resolution activity is normal. Zeek DNS shows wpad.dmevals.local queried by 10.0.1.4 and 10.0.1.6 returning NXDOMAIN (routine WPAD auto-discovery with no rogue WPAD responder answering), plus ordinary single-label NetBIOS-style lookups for SCRANTON/NASHUA and LDAP SRV records. Sysmon event 22 query names are all legitimate (host names, microsoft.com/azureedge telemetry, ocsp.digicert.com). No LLMNR/NBT-NS poisoning tooling appears in PowerShell script blocks, and no SMB relay destination stands out: SMB (445) connections are between domain hosts (e.g. 10.0.1.4/10.0.1.5/10.0.1.6 to 10.0.0.4) with normal machine-account logons (NASHUA$, NEWYORK$, SCRANTON$, WEC$).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-04-30 00:37:59.169Z | simplerockbuild.simplerock.lan | zeek | zeek.query | wpad.dmevals.local | .ds-logs-zeek-default-2026.10.16-000001 / AaFFktQ25mySA1aO74f6 | q-5aadaead92 | ok |
| 2 | 2020-04-30 00:37:59.169Z | simplerockbuild.simplerock.lan | zeek | zeek.rcode_name | NXDOMAIN | .ds-logs-zeek-default-2026.10.16-000001 / AaFFktQ25mySA1aO74f6 | q-5aadaead92 | ok |
| 3 | 2020-05-02 03:25:31.000Z | newyork.dmevals.local | windows.security | win.TargetUserName | NASHUA$ | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkNQ25mySA1X-_nFZ | q-d6cc861c6e | ok |

### F47 · benign / medium · T1557.002 · No ARP cache poisoning; duplicate MACs are separate connections / lab placeholder

Evidence status: **verified**

Zeek conn records show host 10.0.1.4 reaching 10.0.1.6 with two different source MACs (00:0d:3a:4d:42:f2 and fc:bd:67:e1:a9:c1) and a responder MAC of 12:34:56:78:9a:bc. These are distinct connections at distinct timestamps, not one MAC claiming multiple IPs simultaneously, and 12:34:56:78:9a:bc is a synthetic/placeholder address rather than a real gratuitous-ARP spoof. No ARP-poisoning tooling (arp/netsh interface) appears in PowerShell script blocks, and no network-configuration object tampering is visible in the 4663/4670/4656 object-access events.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-04-30 00:45:00.056Z | simplerockbuild.simplerock.lan | zeek | zeek.resp_l2_addr | 12:34:56:78:9a:bc | .ds-logs-zeek-default-2026.10.16-000001 / AaFFktQ25mySA1aO8Ica | q-2f75859513 | ok |
| 2 | 2020-04-30 00:45:00.042Z | bobs.bigwheel.local | zeek | zeek.orig_l2_addr | fc:bd:67:e1:a9:c1 | .ds-logs-zeek-default-2026.10.16-000001 / AaFFktQ25mySA1bi_UDc | q-6c4d844581 | ok |

### F49 · benign / medium · T1558 · No Kerberos ticket theft or forging observed; LSASS accesses are legitimate system processes

Evidence status: **verified**

Across windows.security, windows.sysmon and zeek there is no evidence of Kerberos ticket theft or forging. The 4769 service-ticket requests on newyork.dmevals.local are normal KDC-issued tickets (AES256, TicketOptions 0x40810000/0x60810010 = forwardable/renewable TGT renewal), and the 4768 AS-REQs all carry PreAuthType=2 (pre-authentication required). LSASS handle accesses with elevated masks (0x1fffff, 0x1f3fff, 0x101001) come from legitimate Windows components (wininit.exe, csrss.exe, svchost.exe) and from PowerShell/wsmprovhost whose surrounding activity is exfiltration, not ticket manipulation. No ticket-forging or roasting tooling was found.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:04.000Z | newyork.dmevals.local | windows.security | win.ServiceName | krbtgt | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YhYtYx | q-7abd8e569a | ok |
| 2 | 2020-05-02 03:04:04.000Z | newyork.dmevals.local | windows.security | win.TicketOptions | 0x60810010 | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YhYtYx | q-7abd8e569a | ok |
| 3 | 2020-05-02 03:20:45.000Z | newyork.dmevals.local | windows.security | win.PreAuthType | 2 | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YQHgaq | q-f59ebf2eaf | ok |
| 4 | 2020-05-02 03:19:09.803Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\wininit.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1NY3HhM | q-23b7b2ea0b | ok |
| 5 | 2020-05-02 03:19:09.803Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\csrss.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1NY3HhN | q-23b7b2ea0b | ok |

### F50 · benign / medium · T1558.001 · No golden-ticket indicators: no RC4 downgrade and no anomalous krbtgt service tickets

Evidence status: **verified**

All 28 Kerberos service-ticket requests (event 4769) on newyork.dmevals.local use TicketEncryptionType 0x12 (AES256), with no RC4 (0x17/0x18) downgrade that would suggest a forged golden ticket. The three krbtgt service-ticket requests (by pbeesly@DMEVALS.LOCAL and SCRANTON$@DMEVALS.LOCAL) carry TicketOptions 0x60810010, consistent with legitimate TGT renewal rather than forged-ticket use. No golden-ticket forging tooling was found in PowerShell script blocks.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:04.000Z | newyork.dmevals.local | windows.security | win.TicketEncryptionType | 0x12 | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YhYtYx | q-7abd8e569a | ok |
| 2 | 2020-05-02 03:19:13.000Z | newyork.dmevals.local | windows.security | win.ServiceName | krbtgt | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YaPjsB | q-7843c1e61b | ok |
| 3 | 2020-05-02 03:19:13.000Z | newyork.dmevals.local | windows.security | win.TicketOptions | 0x60810010 | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YaPjsB | q-7843c1e61b | ok |

### F51 · benign / medium · T1558.002 · No silver-ticket indicators: all service tickets are KDC-issued with normal options

Evidence status: **verified**

The 4769 service-ticket requests on newyork.dmevals.local target machine accounts (NEWYORK$, NASHUA$, SCRANTON$, WEC$) and krbtgt, all with TicketEncryptionType 0x12 and standard TicketOptions (0x40800000/0x40810000/0x60810010). There is no evidence of service tickets being used without corresponding KDC validation, and no silver-ticket tooling in PowerShell script blocks.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:20:45.000Z | newyork.dmevals.local | windows.security | win.ServiceName | SCRANTON$ | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YQHgat | q-7abd8e569a | ok |
| 2 | 2020-05-02 03:20:45.000Z | newyork.dmevals.local | windows.security | win.TicketOptions | 0x40810000 | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YQHgat | q-7abd8e569a | ok |

### F52 · benign / medium · T1558.003 · No Kerberoasting: no RC4 TGS requests for SPNs and no roasting tooling

Evidence status: **verified**

No Kerberos service-ticket requests used RC4 encryption (all 4769 events are 0x12/AES256), which is the hallmark of Kerberoasting. The PowerShell script blocks contain no Kerberoast/Invoke-Kerberoast/Rubeus content. The only notable PowerShell activity on scranton.dmevals.local by user pbeesly is an exfiltration script (Invoke-Exfil compressing Downloads and copying to a WebDAV share), which is unrelated to Kerberoasting.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:04.000Z | newyork.dmevals.local | windows.security | win.TicketEncryptionType | 0x12 | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YhYtYv | q-7abd8e569a | ok |
| 2 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | powershell.script_block_text | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b10BXt | q-1cf311d5a9 | ok |

### F53 · benign / medium · T1558.004 · No AS-REP roasting: all AS-REQs require pre-authentication

Evidence status: **verified**

All 14 Kerberos AS-REQ events (event 4768) on newyork.dmevals.local for accounts pbeesly and SCRANTON$ carry PreAuthType=2, meaning pre-authentication was required. Accounts without pre-auth (the precondition for AS-REP roasting) were not observed, and no AS-REP roasting tooling (GetNPUsers, Rubeus, DontRequirePreAuth) appears in PowerShell script blocks.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:20:45.000Z | newyork.dmevals.local | windows.security | win.PreAuthType | 2 | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YQHgaq | q-f59ebf2eaf | ok |
| 2 | 2020-05-02 03:19:13.000Z | newyork.dmevals.local | windows.security | win.PreAuthType | 2 | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YOGdm9 | q-f59ebf2eaf | ok |

### F54 · benign / high · T1606 · No forged web credential activity; hits are benign WebDAV cookie handling and unrelated tooling

Evidence status: **verified**

Across windows.security, windows.sysmon, windows.powershell, windows.other and zeek there is no evidence of web-credential forging. Logon process names for 4624/4648 are all standard (Kerberos 217, Advapi 76, User32 2, NtLmSsp 1). The only 'cookie' process activity is rundll32 davclnt.dll,DavSetCookie on scranton.dmevals.local, which is the normal WebDAV client setting its auth cookie when the exfil script maps \\192.168.0.4\webdav. The single PowerShell 4104 hit matching 'token' is a Sysinternals readme.ps1 helper (Get-AttributesMask) enumerating SE_GROUP_* token attributes, not credential forging. The windows.other 5857/5858/7045 hits are routine WMI RSOP DeleteInstance noise from SYSTEM.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:10:23.154Z | scranton.dmevals.local | windows.sysmon | process.command_line | rundll32.exe C:\windows\system32\davclnt.dll,DavSetCookie 192.168.0.4 http://192.168.0.4/webdav | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1RrMLE_ | q-09580842fe | ok |
| 2 | 2020-05-02 03:04:04.000Z | scranton.dmevals.local | windows.powershell | powershell.script_block_text | function Get-AttributesMask($AttributesMask) {     &lt;#         SE_GROUP_MANDATORY          0x00000001  The group is mandatory.         SE_GROUP_ENABLED_BY_DEF… | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b22vQJ | q-8870d4c10c | ok |
| 3 | 2020-05-02 02:56:47.000Z | newyork.dmevals.local | windows.other | message | Id = {C11E1664-7828-4AD0-B23A-0FCEF0EA26C0}; ClientMachine = NEWYORK; User = NT AUTHORITY\SYSTEM; ClientProcessId = 1588; Component = Unknown; Operation = Start… | .ds-logs-windows.other-default-2026.10.16-000001 / AaFFkdQ25mySA1aOnx1E | q-40429e3339 | ok |

### F55 · benign / high · T1606.001 · No forged web cookies; only benign WebDAV DavSetCookie and an INetCookies file write

Evidence status: **verified**

The only cookie-related artifacts are (1) rundll32 davclnt.dll,DavSetCookie calls on scranton.dmevals.local at 03:08:50 and 03:10:22-23, which are the standard WebDAV client cookie set when the exfil script maps \\192.168.0.4\webdav, and (2) a single svchost.exe file-create of C:\Windows\ServiceProfiles\LocalService\...\AC\INetCookies, a normal Windows service-profile cookie store. No browser cookie theft, tampering, or forged session cookie was observed. The PowerShell 4104 'cookie/session' hit is the same benign Sysinternals readme.ps1 token-attribute helper.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:10:23.154Z | scranton.dmevals.local | windows.sysmon | process.command_line | rundll32.exe C:\windows\system32\davclnt.dll,DavSetCookie 192.168.0.4 http://192.168.0.4/webdav | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1RrMLE_ | q-09580842fe | ok |
| 2 | 2020-05-02 03:21:05.681Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Windows\ServiceProfiles\LocalService\AppData\Local\Packages\warp_jit_db4a1097-b484-4973-bbf2-a04208ecd4d4\AC\INetCookies | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1MsOhX7 | q-2bda489568 | ok |
| 3 | 2020-05-02 03:04:04.000Z | scranton.dmevals.local | windows.powershell | powershell.script_block_text | function Get-AttributesMask($AttributesMask) {     &lt;#         SE_GROUP_MANDATORY          0x00000001  The group is mandatory.         SE_GROUP_ENABLED_BY_DEF… | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b22vQJ | q-3ee9e4d900 | ok |

### F56 · benign / high · T1606.002 · No SAML token forging; no SAML/ADFS/assertion artifacts anywhere

Evidence status: **verified**

No SAML token forging was observed. The PowerShell 4104 search for SAML/NotOnOrAfter/Assertion returned zero hits; the sysmon process search for saml/token/cert command lines returned zero hits; the zeek HTTP search for saml/adfs/token URLs returned zero hits. Kerberos traffic in the zeek window is normal AS/TGS exchange for pbeesly (krbtgt/DMEVALS.LOCAL, cifs/NASHUA, HTTP/NASHUA, ldap/NEWYORK) with standard KDC_ERR_PREAUTH_REQUIRED, and logon process names are all standard. No federated-identity or token-signing material was touched.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:26:48.000Z | newyork.dmevals.local | windows.security | win.LogonProcessName | Kerberos | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkNQ25mySA1X-_nFC | q-d1ab154e76 | ok |
| 2 | 2020-04-30 00:32:18.095Z | simplerockbuild.simplerock.lan | zeek | event.action | http | .ds-logs-zeek-default-2026.10.16-000001 / AaFFktQ25mySA1aO8Idl | q-ba10c77178 | ok |

### F57 · benign / high · T1621 · WMI RSOP/Group Policy activity in windows.other is benign, not MFA request generation

Evidence status: **verified**

The only hit for the T1621 hypothesis was 85 WMI-Activity events (event.code 5857/5858) in windows.other on newyork.dmevals.local. Full-event inspection shows these are standard WMI provider starts (dsccore, CIMWin32, deploymentprovider, dnsclientcim, StorageWMI) and RSOP_ExtensionStatus DeleteInstance operations under Root\Rsop\Computer, executed by NT AUTHORITY\SYSTEM (S-1-5-18) via wmiprvse.exe. This is routine Group Policy/RSOP processing, not multi-factor authentication request generation. No MFA/2FA/authenticator/push-notification activity was found in any dataset.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:56:47.000Z | newyork.dmevals.local | windows.other | message | Id = {C11E1664-7828-4AD0-B23A-0FCEF0EA26C0}; ClientMachine = NEWYORK; User = NT AUTHORITY\SYSTEM; ClientProcessId = 1588; Component = Unknown; Operation = Start… | .ds-logs-windows.other-default-2026.10.16-000001 / AaFFkdQ25mySA1aOnx1E | q-dfb8d9a3ad | ok |
| 2 | 2020-05-02 03:01:28.000Z | newyork.dmevals.local | windows.other | message | dsccore provider started with result code 0x0. HostProcess = wmiprvse.exe; ProcessID = 5344; ProviderPath = %systemroot%\system32\DscCore.dll | .ds-logs-windows.other-default-2026.10.16-000001 / AaFFkdQ25mySA1aOnx21 | q-955e813e8d | ok |
| 3 | 2020-05-02 03:01:30.000Z | newyork.dmevals.local | windows.other | message | CIMWin32 provider started with result code 0x0. HostProcess = wmiprvse.exe; ProcessID = 4292; ProviderPath = %systemroot%\system32\wbem\cimwin32.dll | .ds-logs-windows.other-default-2026.10.16-000001 / AaFFkdQ25mySA1aOnx07 | q-955e813e8d | ok |

### F58 · benign / high · T1621 · No failed-logon or MFA-fatigue pattern in windows.security

Evidence status: **verified**

windows.security contains zero event.code 4625 (failed logon) events, so there is no repeated authentication-failure pattern that would accompany an MFA fatigue / request-generation campaign. The only authentication-related events are explicit-credential logons (4648) and NTLM validation (4776) for user pbeesly across scranton/nashua/newyork, which are normal interactive/remote logon activity.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:20:40.000Z | newyork.dmevals.local | windows.security | win.TargetUserName | pbeesly | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YQHwYC | q-890f6fd16d | ok |
| 2 | 2020-05-02 03:20:46.000Z | scranton.dmevals.local | windows.security | win.TargetUserName | pbeesly | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YQHQbW | q-890f6fd16d | ok |

### F59 · benign / high · T1621 · Sysmon 'push' matches are Windows services, not MFA push notifications

Evidence status: **verified**

A sysmon process-creation search for mfa/authenticator/2fa/push returned only three benign Windows service processes on scranton.dmevals.local: svchost.exe hosting PushToInstall, sc.exe starting 'pushtoinstall registration', and svchost.exe hosting dmwappushservice. These are built-in Windows services and unrelated to multi-factor authentication request generation.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:22:11.866Z | scranton.dmevals.local | windows.sysmon | process.command_line | C:\windows\System32\svchost.exe -k netsvcs -p -s PushToInstall | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1MtWeH6 | q-f4c8e14732 | ok |
| 2 | 2020-05-02 03:22:11.790Z | scranton.dmevals.local | windows.sysmon | process.command_line | C:\windows\system32\sc.exe start pushtoinstall registration | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1MtWNHL | q-f4c8e14732 | ok |

### F61 · benign / medium · T1649 · Kerberos TGT requests and certificate-store registry writes on other hosts show no certificate-forging activity

Evidence status: **verified**

The remaining T1649 check hits are consistent with normal Windows behaviour. Kerberos AS-REQ (event 4768) activity in windows.security is limited to the account pbeesly (9 requests) and the machine account SCRANTON$ (5 requests), all with Status 0x0 from internal addresses 10.0.1.4/10.0.1.6 on newyork.dmevals.local — ordinary domain logon traffic, not certificate-based authentication abuse. The certificate/crypto registry writes in windows.sysmon are dominated by OS components (svchost.exe, lsass.exe, taskhostw.exe, smss.exe) touching AuthRoot, Windows Live ID Token Issuer, ACRS PhysicalStores and SymbolicLinkValue keys, i.e. routine certificate-store maintenance. The Zeek x509 subjects (rempel.group.net, conn.sons.info) are external TLS server certificates from a non-overlapping window and show no forged authentication certificates. None of these constitute attacker certificate theft or forging.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:20:45.000Z | newyork.dmevals.local | windows.security | win.TargetUserName | pbeesly | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YQHgaq | q-4da882e94f | ok |
| 2 | 2020-05-02 03:19:13.000Z | newyork.dmevals.local | windows.security | win.TargetUserName | SCRANTON$ | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YOGdm9 | q-4da882e94f | ok |
| 3 | 2020-05-02 03:16:19.447Z | nashua.dmevals.local | windows.sysmon | registry.path | HKLM\SOFTWARE\Microsoft\SystemCertificates\AuthRoot\Certificates\AFE5D244A8D1194230FF479FE2F897BBCD7A8CB4\Blob | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1RhBptB | q-142357c0af | ok |
| 4 | 2020-05-02 03:20:49.745Z | scranton.dmevals.local | windows.sysmon | registry.path | HKU\S-1-5-21-1830255721-3727074217-2423397540-1107\Software\Microsoft\SystemCertificates\ACRS\PhysicalStores\.LocalMachine\OpenStoreProvider | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1NDgB6i | q-142357c0af | ok |

### F48 · not_observed / medium · T1557.003 · No DHCP spoofing; no DHCP-related telemetry present

Evidence status: **verified**

No DHCP spoofing indicators exist in the data. The windows.other System channel contains no DHCP-related event codes (1341/1342/1020/1063 absent from the code distribution), no PowerShell script block references DHCP, and the zeek capture contains no dhcp log type (only conn/files/ssl/x509/dce_rpc/http/dns/kerberos/dpd/smb_files/smb_mapping/weird/notice/pe). Sysmon network connections show no DHCP ports 67/68. The technique is therefore not observable in this dataset rather than positively benign.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-04-30 00:37:59.169Z | simplerockbuild.simplerock.lan | zeek | event.action | dns | .ds-logs-zeek-default-2026.10.16-000001 / AaFFktQ25mySA1aO74f6 | q-5aadaead92 | ok |

## Technique conclusions

One line per technique in scope: status from the triage of its family; `not_observed` = checked, nothing found; `not_observable` = no dataset records it.

| Technique | Status | Reason |
|---|---|---|
| T1003 OS Credential Dumping | malicious | pbeesly ran a PowerShell credential-collection toolkit (Get-PrivateKeys, Get-Keystrokes, Invoke-ScreenCapture, Invoke-Exfil) on scranton, and PowerShell processes opened LSASS with full access. |
| T1003.001 LSASS Memory | malicious | powershell.exe (scranton) and wsmprovhost.exe (nashua) opened lsass.exe with GrantedAccess 0x1F3FFF/0x1FFFFF under user pbeesly, confirmed by Security 4656 AccessMask 0x1f3fff/0x1fffff. |
| T1003.002 Security Account Manager | benign | SAM registry writes were performed by lsass.exe itself; no reg save or SAM hive copy by any attacker tool. |
| T1003.003 NTDS | not_observed | No ntds.dit access, vssadmin/diskshadow/ntdsutil execution, or NTDS file creation in any dataset. |
| T1003.004 LSA Secrets | not_observed | No SECURITY\Policy\Secrets access, lsadump, or SECURITY hive save observed. |
| T1003.005 Cached Domain Credentials | benign | SECURITY\Cache\NL$1 writes were by lsass.exe updating its own cached credentials; no extraction by a tool. |
| T1003.006 DCSync | not_observed | No drsuapi/DCSync command lines or lsadump script blocks found. |
| T1040 Network Sniffing | benign | The only packet-capture activity is the legitimate Azure Network Watcher agent on scranton.dmevals.local (NetworkWatcherAgent.exe -> netsh trace start capture=yes / logman ETW sessions, all parented by Azure guest-agent … |
| T1056 Input Capture | malicious | Obfuscated PowerShell (reflective GetProcAddress/GetModuleHandle loader + base64 shellcode) executed by pbeesly on scranton.dmevals.local, consistent with in-memory credential capture tooling. |
| T1056.001 Keylogging | malicious | Get-Keystrokes keylogger function executed by pbeesly on scranton. |
| T1056.002 GUI Input Capture | not_observed | No GUI input capture or credential-prompt abuse; the 4688 Credential/prompt check returned zero hits. |
| T1056.003 Web Portal Capture | not_observed | No web-root file writes, IIS/w3wp activity, or login/portal HTTP requests; related checks returned zero hits. |
| T1056.004 Credential API Hooking | malicious | Invoke-ScreenCapture screenshot-capture job executed by pbeesly on scranton. |
| T1110 Brute Force | not_observed | Zero 4625 failed-logon events in windows.security (count=0) and no lockout/failure messages in windows.other; no repeated authentication attempts of any kind. |
| T1110.001 Password Guessing | not_observed | No failed logons and no password-iteration loops; PowerShell *Password* hits are hardcoded-password key export and exfil scripts, not guessing. |
| T1110.002 Password Cracking | malicious | PowerShell.exe opened lsass.exe with GrantedAccess 0x1fffff/0x1f3fff on scranton (credential dumping) and pbeesly exported all machine certificates to .pfx with hardcoded password 'saribas'; no offline cracking tooling s… |
| T1110.003 Password Spraying | not_observed | No 4625 failures or lockouts; the 4648 explicit-credential logons are single-account PSEXESVC lateral movement, not a one-password-many-accounts spray. |
| T1110.004 Credential Stuffing | not_observed | No failed logons and no many-credential-pair attempts; only single-account pbeesly reuse via PSEXESVC and hardcoded script credentials. |
| T1111 Multi-Factor Authentication Interception | not_observed | No MFA/smart-card/OTP/token-interception artifacts in any dataset. Logons are ordinary Negotiate/Kerberos types; LSASS access is benign svchost.exe 0x1000; 'Credential' registry hits are CredentialGuard/CredentialEnrollm… |
| T1187 Forced Authentication | malicious | Zeek HTTP logs show 36 WebDAV Mini-Redirector (Microsoft-WebDAV-MiniRedir/10.0.18362) OPTIONS/PROPFIND requests from 10.0.1.4 to 192.168.0.4:80 returning 401 Unauthorized, the canonical forced-authentication pattern for … |
| T1212 Exploitation for Credential Access | malicious | On scranton.dmevals.local a hidden, steganography-decoding PowerShell process (PID 2976, user DMEVALS\pbeesly, launched from control.exe with -ep bypass -window hidden) opened lsass.exe with GrantedAccess 0x1F3FFF and 0x… |
| T1539 Steal Web Session Cookie | benign | All cookie-related hits are benign Windows WebDAV client operations (rundll32 davclnt.dll,DavSetCookie and the LocalService INetCookies store) and normal Edge browser file activity. No browser session cookie database was… |
| T1552 Unsecured Credentials | malicious | Multiple unsecured-credential artifacts: passwordsDB, hardcoded passwords in scripts, password-protected archives. |
| T1552.001 Credentials In Files | malicious | pspasswd downloaded, accesschk created 'passwordsDB', Invoke-Exfil and Rar used hardcoded credentials/passwords; explicit-credential 4648 logons via PSEXESVC. |
| T1552.002 Credentials in Registry | benign | All Password/Credential registry writes were by svchost/lsass/services/winlogon system processes; no adversary registry credential storage. |
| T1552.003 Shell History | not_observed | No consolehost_history or shell-history access found in sysmon or security datasets. |
| T1552.004 Private Keys | malicious | Get-PrivateKeys exported all LocalMachine certs with private keys to .pfx files using hardcoded password 'saribas' on scranton; .pfx file created by powershell.exe. |
| T1552.006 Group Policy Preferences | benign | SYSVOL/GptTmpl.inf/Groups.xml access was routine Group Policy processing by machine accounts (NEWYORK$, SCRANTON$, NASHUA$); no attacker read of GPP cpassword. |
| T1555 Credentials from Password Stores | malicious | User pbeesly's powershell.exe (scranton, 03:05:16) and wsmprovhost.exe (nashua, 03:09:29) opened lsass.exe with 0x1fffff/0x1f3fff masks including read-process-memory — credential-dumping access pattern, part of a broader… |
| T1555.003 Credentials from Web Browsers | not_observed | No browser credential files (Login Data/logins.json/cookies), browser processes as LSASS targets, or browser-credential strings in any dataset. |
| T1555.004 Windows Credential Manager | suspicious | LSASS full-access handle requests are the Credential Manager/DPAPI harvest mechanism, but no vault/DPAPI/Credential Manager object access or cmdkey/vaultcmd execution was observed; only benign CollectGuestLogs/MsMpEng ls… |
| T1555.005 Password Managers | not_observed | No KeePass/1Password/Bitwarden/LastPass executables, .kdbx files, or password-manager strings in any dataset. |
| T1556 Modify Authentication Process | malicious | wsmprovhost.exe (PowerShell Remoting, user pbeesly) opened lsass.exe with GrantedAccess 0x1f3fff on nashua.dmevals.local, reached via PsExec with plaintext credentials from scranton; an Invoke-Exfil script with hardcoded… |
| T1556.001 Domain Controller Authentication | not_observed | No domain-controller authentication modification observed. The 4624 LogonType 3 events are machine-account (NEWYORK$) network logons and the 4648 explicit-credential logons are PsExec/winlogon activity; no DC authenticat… |
| T1556.002 Password Filter DLL | not_observed | No password filter DLL activity: no Notification Packages registry value was written and no lsass image-load of a non-Microsoft filter DLL was seen (only signed cryptdll/samlib/samcli loads). |
| T1556.005 Reversible Encryption | not_observed | No reversible-encryption activity: no 4739/5136/4738 events, no Set-ADUser/dsmod/AllowReversiblePasswordEncryption command lines, and no matching PowerShell script blocks. |
| T1556.006 Multi-Factor Authentication | not_observed | No MFA modification observed: no 4739/5136/4738 directory-service change events and no Set-ADUser/Set-ADAuthenticationPolicy command lines in sysmon or PowerShell. |
| T1556.007 Hybrid Identity | not_observed | No hybrid-identity modification observed: no 5136 directory-service change events and no Connect-MsolService/Connect-AzureAD/New-AzureAD* script blocks in PowerShell. |
| T1556.008 Network Provider DLL | not_observed | No network provider DLL activity: no 4657 registry change to a NetworkProvider/Credential key and no New-Item/NetworkProvider PowerShell script blocks. |
| T1557 Adversary-in-the-Middle | benign | No AiTM positioning observed; the credential-related activity is plaintext-credential PsExec lateral movement (scranton->NASHUA), which is not T1557. |
| T1557.001 Name Resolution Poisoning and SMB Relay | benign | DNS/WPAD lookups are routine and unanswered (NXDOMAIN); no LLMNR/NBT-NS poisoning tooling and no anomalous SMB relay destination. |
| T1557.002 ARP Cache Poisoning | benign | Duplicate source MACs belong to separate connections and the responder MAC 12:34:56:78:9a:bc is a placeholder; no ARP-poisoning tooling or network-config tampering. |
| T1557.003 DHCP Spoofing | not_observed | No DHCP event codes, no DHCP PowerShell references, no zeek dhcp log type and no DHCP ports 67/68 in Sysmon connections. |
| T1558 Steal or Forge Kerberos Tickets | not_observed | No Kerberos ticket theft or forging. 4769 tickets are normal KDC-issued AES256 tickets; 4768 AS-REQs all require pre-auth; elevated LSASS accesses are from legitimate system processes (wininit, csrss, svchost) and PowerS… |
| T1558.001 Golden Ticket | not_observed | No RC4 downgrade (all 4769 tickets are 0x12/AES256) and no anomalous krbtgt service tickets; krbtgt requests use normal TGT-renewal options 0x60810010. No golden-ticket tooling in PowerShell. |
| T1558.002 Silver Ticket | not_observed | All service tickets are KDC-issued with standard options; no evidence of tickets used without KDC validation and no silver-ticket tooling. |
| T1558.003 Kerberoasting | not_observed | No RC4 TGS requests for SPNs and no Kerberoast/Invoke-Kerberoast/Rubeus content in PowerShell script blocks. |
| T1558.004 AS-REP Roasting | not_observed | All 4768 AS-REQs carry PreAuthType=2 (pre-auth required); no accounts without pre-auth and no AS-REP roasting tooling observed. |
| T1606 Forge Web Credentials | not_observed | No forged web credential artifacts. Logon process names are all standard; the only cookie-related process activity is benign WebDAV DavSetCookie from the exfil script's New-PSDrive, and the 'token' PowerShell hit is a Sy… |
| T1606.001 Web Cookies | not_observed | No browser cookie theft/tampering or forged session cookies. Only a benign WebDAV DavSetCookie (rundll32 davclnt.dll) and a normal svchost INetCookies file write were seen. |
| T1606.002 SAML Tokens | not_observed | Zero hits for SAML/ADFS/Assertion/NotOnOrAfter in PowerShell, sysmon command lines, or zeek HTTP URLs. Kerberos traffic is normal AS/TGS for pbeesly. |
| T1621 Multi-Factor Authentication Request Generatio… | not_observed | No multi-factor authentication request generation activity was found. The only T1621 check with hits (windows.other 5857/5858) is benign WMI RSOP/Group Policy provider activity by SYSTEM. windows.security has zero 4625 f… |
| T1649 Steal or Forge Authentication Certificates | malicious | Certificate private-key export to .pfx via Get-PrivateKeys on scranton (new artifact beyond the anchor). |

## Coverage

Cells: number of hits of the planned checks, `n/a` (reason in report.json), or GAP.

| Technique | windows.other | windows.powershell | windows.security | windows.sysmon | zeek |
|---|---|---|---|---|---|
| T1003 OS Credential Dumping | 0 hits | 0 hits | 11437 hits | 39730 hits | n/a |
| T1003.001 LSASS Memory | 0 hits | 0 hits | 947 hits | 981 hits | n/a |
| T1003.002 Security Account Manager | 0 hits | 11 hits | 16 hits | 10 hits | n/a |
| T1003.003 NTDS | 0 hits | 0 hits | 0 hits | 0 hits | n/a |
| T1003.004 LSA Secrets | 0 hits | 0 hits | 0 hits | 327 hits | n/a |
| T1003.005 Cached Domain Credentials | 0 hits | 0 hits | 0 hits | 330 hits | n/a |
| T1003.006 DCSync | 90 hits | 0 hits | 21 hits | 0 hits | 9 hits |
| T1040 Network Sniffing | 5 hits | 0 hits | 460 hits | 0 hits | 0 hits |
| T1056 Input Capture | 90 hits | 0 hits | 21834 hits | 39609 hits | 0 hits |
| T1056.001 Keylogging | 5 hits | 0 hits | 10990 hits | 39779 hits | 0 hits |
| T1056.002 GUI Input Capture | 5 hits | 418 hits | 460 hits | 450 hits | 0 hits |
| T1056.003 Web Portal Capture | 5 hits | 4 hits | 5337 hits | 1649 hits | 0 hits |
| T1056.004 Credential API Hooking | 0 hits | 0 hits | 13 hits | 59963 hits | n/a |
| T1110 Brute Force | 2 hits | 4 hits | 0 hits | 30 hits | n/a |
| T1110.001 Password Guessing | 2 hits | 4 hits | 0 hits | 0 hits | n/a |
| T1110.002 Password Cracking | 1 hits | 12 hits | 10977 hits | 346 hits | n/a |
| T1110.003 Password Spraying | 7 hits | 4 hits | 15 hits | 1 hits | n/a |
| T1110.004 Credential Stuffing | 4 hits | 4 hits | 0 hits | 0 hits | n/a |
| T1111 Multi-Factor Authentication Interception | 2 hits | 3 hits | 312 hits | 39294 hits | n/a |
| T1187 Forced Authentication | 0 hits | 0 hits | 11140 hits | 1715 hits | 86 hits |
| T1212 Exploitation for Credential Access | 0 hits | 16 hits | 70 hits | 78566 hits | 14 hits |
| T1539 Steal Web Session Cookie | 0 hits | 0 hits | 465 hits | 40933 hits | 2 hits |
| T1552 Unsecured Credentials | 0 hits | 2 hits | 460 hits | 19208 hits | 12 hits |
| T1552.001 Credentials In Files | 0 hits | 1 hits | 312 hits | 2148 hits | 12 hits |
| T1552.002 Credentials in Registry | 12 hits | 1 hits | 1000 hits | 17606 hits | n/a |
| T1552.003 Shell History | 5 hits | 1 hits | 0 hits | 15 hits | n/a |
| T1552.004 Private Keys | 0 hits | 2 hits | 0 hits | 1 hits | n/a |
| T1552.006 Group Policy Preferences | 0 hits | 32 hits | 56 hits | 22 hits | n/a |
| T1555 Credentials from Password Stores | 2 hits | 5 hits | 19 hits | 1326 hits | n/a |
| T1555.003 Credentials from Web Browsers | 0 hits | 0 hits | 0 hits | 0 hits | n/a |
| T1555.004 Windows Credential Manager | 2 hits | 3 hits | 0 hits | 652 hits | n/a |
| T1555.005 Password Managers | 0 hits | 0 hits | 0 hits | 0 hits | n/a |
| T1556 Modify Authentication Process | 0 hits | 0 hits | 0 hits | 729 hits | n/a |
| T1556.001 Domain Controller Authentication | 0 hits | 0 hits | 545 hits | 359 hits | n/a |
| T1556.002 Password Filter DLL | 10 hits | 0 hits | 0 hits | 33 hits | n/a |
| T1556.005 Reversible Encryption | 0 hits | 1 hits | 0 hits | 0 hits | n/a |
| T1556.006 Multi-Factor Authentication | 0 hits | 1 hits | 0 hits | 0 hits | n/a |
| T1556.007 Hybrid Identity | 0 hits | 0 hits | 594 hits | 20259 hits | n/a |
| T1556.008 Network Provider DLL | 4 hits | 0 hits | 36 hits | 59543 hits | n/a |
| T1557 Adversary-in-the-Middle | 2 hits | 0 hits | 21954 hits | 1310 hits | 1226 hits |
| T1557.001 Name Resolution Poisoning and SMB Relay | 2 hits | 0 hits | 23 hits | 1310 hits | 53 hits |
| T1557.002 ARP Cache Poisoning | 2 hits | 0 hits | 10977 hits | 1310 hits | 1226 hits |
| T1557.003 DHCP Spoofing | 216 hits | 0 hits | 0 hits | 1229 hits | 2140 hits |
| T1558 Steal or Forge Kerberos Tickets | 9 hits | 0 hits | 745 hits | 39609 hits | 35 hits |
| T1558.001 Golden Ticket | 216 hits | 0 hits | 268 hits | 39283 hits | 35 hits |
| T1558.002 Silver Ticket | 9 hits | 0 hits | 268 hits | 326 hits | 35 hits |
| T1558.003 Kerberoasting | 216 hits | 0 hits | 368 hits | 39283 hits | 35 hits |
| T1558.004 AS-REP Roasting | 216 hits | 0 hits | 42 hits | 447 hits | 35 hits |
| T1606 Forge Web Credentials | 90 hits | 1 hits | 312 hits | 326 hits | 475 hits |
| T1606.001 Web Cookies | 9 hits | 1 hits | 312 hits | 1 hits | 62 hits |
| T1606.002 SAML Tokens | 90 hits | 0 hits | 312 hits | 0 hits | 0 hits |
| T1621 Multi-Factor Authentication Request Generatio… | 85 hits | 0 hits | 0 hits | 0 hits | 0 hits |
| T1649 Steal or Forge Authentication Certificates | 90 hits | 1 hits | 50 hits | 1133 hits | 378 hits |

Cells: 265, gaps: 0.

## Queries

Every MCP tool call of this run (1175), in order (source: mcp_audit.jsonl written by the MCP server).

| Query | Phase | Tool | Arguments | Hits / rows | Cited by |
|---|---|---|---|---|---|
| q-56410359ee | scope | list_data_sources | {} | None |  |
| q-418596491f | scope | get_registry | {} | None |  |
| q-add8f89b72 | scope | get_fields | {"dataset": "windows.other", "prefix": ""} | None |  |
| q-e72f0c4a83 | scope | get_fields | {"dataset": "windows.powershell", "prefix": ""} | None |  |
| q-82fd6799a7 | scope | get_fields | {"dataset": "windows.security", "prefix": ""} | None |  |
| q-7cbde4bc39 | scope | get_fields | {"dataset": "windows.sysmon", "prefix": ""} | None |  |
| q-c501899eaa | scope | get_fields | {"dataset": "zeek", "prefix": ""} | None |  |
| q-c7acf7ed6c | check C001 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 447 |  |
| q-e3b5e32557 | check C002 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-ad85118c85 | check C003 | aggregate | {"dataset": "windows.security", "field": "win.ObjectType", "query": "event.code:(4656 OR 4663 OR 4670)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 10977 |  |
| q-ab6bc72940 | check C004 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 460 |  |
| q-0a960b7aa7 | check C005 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*lsass* OR powershell.script_block_text:*mimikatz* OR powershell.script_block_text:*sekurlsa* OR powershell.script_block_text:*DumpCreds*)", "time_from": null, "time_… | 0 |  |
| q-1f8c8991d8 | check C006 | search | {"dataset": "windows.other", "query": "message:(*lsass* OR *mimikatz* OR *sekurlsa* OR *procdump*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "p… | 0 |  |
| q-a8b7052025 | check C007 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-8cd3266b0c | check C008 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 326 |  |
| q-f2d69f824a | check C009 | aggregate | {"dataset": "windows.sysmon", "field": "win.SourceImage", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-b399e4a468 | check C010 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*lsass* OR file.path:*.dmp)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "pro… | 2 |  |
| q-17e83cdfad | check C011 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*lsass* OR process.command_line:*comsvcs* OR process.command_line:*MiniDump*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dat… | 1 | F07 |
| q-f527f395d8 | check C012 | search | {"dataset": "windows.sysmon", "query": "event.code:(13 OR 14) AND registry.path:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.comm… | 0 |  |
| q-bbd9fc2476 | check C013 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4673", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 934 |  |
| q-0d9e3075b3 | check C014 | search | {"dataset": "windows.security", "query": "event.code:4656 AND win.ObjectName:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command… | 13 |  |
| q-274848222f | check C015 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*lsass* OR powershell.script_block_text:*MiniDump* OR powershell.script_block_text:*Invoke-Mimikatz*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "… | 0 |  |
| q-b85462c795 | check C016 | search | {"dataset": "windows.other", "query": "message:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 0 |  |
| q-9318992e9f | check C017 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*SAM* OR file.path:*SECURITY* OR file.path:*SYSTEM*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "… | 3 | F05 |
| q-6cac1cba4f | check C018 | search | {"dataset": "windows.sysmon", "query": "event.code:(13 OR 14) AND (registry.path:*SAM* OR registry.path:*SECURITY*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "proces… | 7 |  |
| q-20acf66572 | check C019 | search | {"dataset": "windows.sysmon", "query": "event.code:2 AND (process.command_line:*SAM* OR process.command_line:*reg*save*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "p… | 0 |  |
| q-0b0eb718a3 | check C020 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*reg save* OR process.command_line:*save*hklm* OR process.command_line:*SAM*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dat… | 0 |  |
| q-483942b362 | check C021 | aggregate | {"dataset": "windows.security", "field": "process.command_line", "query": "event.code:4688 AND (process.command_line:*reg* OR process.command_line:*save*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 6 |  |
| q-5922000514 | check C022 | search | {"dataset": "windows.security", "query": "event.code:(4656 OR 4663) AND (win.ObjectName:*SAM* OR win.ObjectName:*SECURITY*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name",… | 10 |  |
| q-090e7c74cc | check C023 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*SAM* OR powershell.script_block_text:*reg save* OR powershell.script_block_text:*hive*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "… | 11 |  |
| q-2528b0e316 | check C024 | search | {"dataset": "windows.other", "query": "message:(*SAM* OR *SECURITY hive* OR *reg save*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.comm… | 0 |  |
| q-ec526361ce | check C025 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*ntds* OR file.path:*NTDS*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "pro… | 0 |  |
| q-000461bce9 | check C026 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*ntds* OR process.command_line:*vssadmin* OR process.command_line:*ntdsutil* OR process.command_line:*diskshadow*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "ho… | 0 |  |
| q-eab6ecf9eb | check C027 | search | {"dataset": "windows.sysmon", "query": "event.code:2 AND file.path:*ntds*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "so… | 0 |  |
| q-9276e88327 | check C028 | aggregate | {"dataset": "windows.security", "field": "process.command_line", "query": "event.code:4688 AND (process.command_line:*ntds* OR process.command_line:*vssadmin* OR process.command_line:*diskshadow*)", "time_from": null, "time_to": null, "size": 50, "sub_field": … | 0 |  |
| q-1ea66cd943 | check C029 | search | {"dataset": "windows.other", "query": "message:(*shadow* OR *VSS* OR *ntds*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 0 |  |
| q-76bbec9c2e | check C030 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*ntds* OR powershell.script_block_text:*diskshadow* OR powershell.script_block_text:*vssadmin*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.n… | 0 |  |
| q-119cb4ad1c | check C031 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 326 |  |
| q-65dc5d8acd | check C032 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*secrets* OR process.command_line:*lsadump* OR process.command_line:*reg save*HKLM\\\\SECURITY*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observe… | 0 |  |
| q-4fda88ae15 | check C033 | search | {"dataset": "windows.sysmon", "query": "event.code:7 AND win.ImageLoaded:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_lin… | 1 |  |
| q-fb6871ec36 | check C034 | search | {"dataset": "windows.security", "query": "event.code:(4656 OR 4663 OR 4670) AND win.ObjectName:*SECURITY*Policy*Secrets*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "p… | 0 |  |
| q-3f8f91c65b | check C035 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:(4656 OR 4663 OR 4670) AND win.ObjectName:*Secrets*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-2fc83c1070 | check C036 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*Secrets* OR powershell.script_block_text:*lsadump* OR powershell.script_block_text:*LSA*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name",… | 0 |  |
| q-63af5b5f93 | check C037 | search | {"dataset": "windows.other", "query": "message:(*Secrets* OR *LSA* OR *lsadump*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_lin… | 0 |  |
| q-87c454a7c6 | check C038 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 326 |  |
| q-f969c03830 | check C039 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*cache* OR process.command_line:*DCC2* OR process.command_line:*mscache* OR process.command_line:*cachedump*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.na… | 4 |  |
| q-b1ec3f40f2 | check C040 | search | {"dataset": "windows.security", "query": "event.code:(4656 OR 4663 OR 4670) AND (win.ObjectName:*Cache* OR win.ObjectName:*SECURITY*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "u… | 0 |  |
| q-b59e6b70d5 | check C041 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:(4656 OR 4663 OR 4670) AND win.ObjectName:*Cache*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-0c7c7dc607 | check C042 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*cache* OR powershell.script_block_text:*DCC2* OR powershell.script_block_text:*mscache*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", … | 0 |  |
| q-891b46fbd6 | check C043 | search | {"dataset": "windows.other", "query": "message:(*cached*credential* OR *mscache* OR *DCC2*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.… | 0 |  |
| q-ce29efe25f | check C044 | count | {"dataset": "windows.security", "query": "event.code:4662", "time_from": null, "time_to": null} | 7 |  |
| q-7222af2a21 | check C045 | aggregate | {"dataset": "windows.security", "field": "win.AccessMask", "query": "event.code:4662", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 7 |  |
| q-b49846932e | check C046 | aggregate | {"dataset": "windows.security", "field": "win.SubjectUserName", "query": "event.code:4662", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 7 |  |
| q-56978d2dd5 | check C047 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*drsuapi* OR process.command_line:*lsadump* OR process.command_line:*dcsync*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dat… | 0 |  |
| q-6281724b1b | check C048 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*DCSync* OR powershell.script_block_text:*lsadump* OR powershell.script_block_text:*drsuapi*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.nam… | 0 |  |
| q-0421335c98 | check C049 | search | {"dataset": "windows.other", "query": "event.code:7045 OR event.code:5858 OR event.code:5857", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process… | 90 |  |
| q-532b8845b6 | check C050 | search | {"dataset": "zeek", "query": "event.action:dce_rpc AND (zeek.operation:*DRSUAPI* OR zeek.endpoint:*drsuapi* OR zeek.named_pipe:*drsuapi*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code"… | 9 |  |
| q-9592145cc7 | check C051 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 460 |  |
| q-cdf59a8171 | check C052 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*pcap* OR process.command_line:*sniff* OR process.command_line:*promisc*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.da… | 0 |  |
| q-42851c85ac | check C053 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-30290b6f40 | check C054 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.executable:*tcpdump* OR process.executable:*windump* OR process.executable:*wireshark* OR process.executable:*rawcap* OR process.executable:*npcap*)", "time_from": null, "time_to": null, "fields… | 0 |  |
| q-98a2a1bf39 | check C055 | search | {"dataset": "windows.sysmon", "query": "event.code:6 AND (win.Image:*npcap* OR win.Image:*pcap* OR win.Image:*winpcap*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "pr… | 0 |  |
| q-5251f61121 | check C056 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*pcap* OR powershell.script_block_text:*sniff* OR powershell.script_block_text:*promiscuous*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.nam… | 0 |  |
| q-7a7c322018 | check C057 | search | {"dataset": "zeek", "query": "event.action:conn AND network.transport:icmp", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "s… | 0 |  |
| q-306b29e5f1 | check C058 | aggregate | {"dataset": "windows.security", "field": "win.ObjectType", "query": "event.code:4656 OR event.code:4663 OR event.code:4670", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 10977 |  |
| q-2cb397a48b | check C059 | aggregate | {"dataset": "windows.security", "field": "win.AccessMask", "query": "event.code:4656 OR event.code:4663", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 10834 |  |
| q-e9860a3d85 | check C060 | search | {"dataset": "windows.security", "query": "event.code:4656 AND (win.ObjectName:*lsass* OR win.ObjectName:*credential* OR win.ObjectName:*SAM*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.c… | 23 | F13 |
| q-9c39d9a8a4 | check C061 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-a1d7d07473 | check C062 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-a49653cc61 | check C063 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND (win.GrantedAccess:0x1010 OR win.GrantedAccess:0x1410 OR win.GrantedAccess:0x1438 OR win.GrantedAccess:0x143a)", "time_from": null, "time_to": null, "fields": ["@timestamp", … | 0 |  |
| q-704740b7e6 | check C064 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*Get-Credential* OR powershell.script_block_text:*CredentialManager* OR powershell.script_block_text:*keylog*)", "time_from": null, "time_to": null, "fields": ["@time… | 0 |  |
| q-07f8b423da | check C065 | search | {"dataset": "windows.other", "query": "event.code:7045 OR event.code:5858 OR event.code:5857", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process… | 90 |  |
| q-bae30305aa | check C066 | search | {"dataset": "zeek", "query": "event.action:http AND http.request.method:POST", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 0 |  |
| q-e8c18c965c | check C067 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-2b8666ceb7 | check C068 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND (win.TargetImage:*lsass* OR win.TargetImage:*winlogon* OR win.TargetImage:*explorer*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event… | 470 | F13, F14 |
| q-0ed32081a7 | check C069 | search | {"dataset": "windows.sysmon", "query": "event.code:13 AND (registry.path:*Keyboard* OR registry.path:*keylog* OR registry.path:*Scancode*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code… | 26 |  |
| q-1f7a3d68a6 | check C070 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*keylog* OR process.command_line:*GetAsyncKeyState* OR process.command_line:*SetWindowsHookEx*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer… | 0 |  |
| q-4c18d4dd92 | check C071 | aggregate | {"dataset": "windows.security", "field": "win.ObjectType", "query": "event.code:4656 OR event.code:4663 OR event.code:4670", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 10977 |  |
| q-188b70f8e9 | check C072 | search | {"dataset": "windows.security", "query": "event.code:4656 AND (win.ObjectName:*lsass* OR win.ObjectName:*winlogon*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "proces… | 13 |  |
| q-7f02fafe34 | check C073 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-813fc51fd9 | check C074 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*keylog* OR powershell.script_block_text:*GetAsyncKeyState* OR powershell.script_block_text:*SetWindowsHookEx*)", "time_from": null, "time_to": null, "fields": ["@tim… | 0 |  |
| q-2b6f5a2d58 | check C075 | search | {"dataset": "zeek", "query": "event.action:http AND http.request.method:POST", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 0 |  |
| q-c3bf4264c9 | check C076 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*Credential* OR powershell.script_block_text:*Prompt* OR powershell.script_block_text:*Read-Host*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "hos… | 4 |  |
| q-e60b97d610 | check C077 | aggregate | {"dataset": "windows.powershell", "field": "win.ScriptBlockId", "query": "event.code:4104", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 414 |  |
| q-52637abf77 | check C078 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*Credential* OR process.command_line:*prompt* OR process.command_line:*consent*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.… | 3 |  |
| q-76fb951284 | check C079 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 447 |  |
| q-ab3aea69df | check C080 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*Credential* OR process.command_line:*prompt*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user… | 0 |  |
| q-6f7d9272b5 | check C081 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 460 |  |
| q-ebe94d71a1 | check C082 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-bec16ea370 | check C083 | search | {"dataset": "zeek", "query": "event.action:http AND http.request.method:POST", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 0 |  |
| q-60ac6c1810 | check C084 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*login* OR file.path:*portal* OR file.path:*wwwroot* OR file.path:*inetpub*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "eve… | 0 |  |
| q-4eb89c2cb1 | check C085 | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 1649 |  |
| q-39cad11558 | check C086 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*iis* OR process.command_line:*w3wp* OR process.command_line:*wwwroot*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset",… | 0 |  |
| q-658b70db81 | check C087 | search | {"dataset": "windows.security", "query": "event.code:4663 AND (win.ObjectName:*wwwroot* OR win.ObjectName:*inetpub* OR win.ObjectName:*login*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.… | 0 |  |
| q-27a7c6f62a | check C088 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 5337 |  |
| q-f1b8c73c8e | check C089 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*wwwroot* OR powershell.script_block_text:*login* OR powershell.script_block_text:*credential*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.n… | 4 |  |
| q-dcc1b2635d | check C090 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-2499d47fb8 | check C091 | search | {"dataset": "zeek", "query": "event.action:http AND (url.original:*login* OR url.original:*portal*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "… | 0 |  |
| q-b21f1d56ba | check C092 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-08f0d3dffe | check C093 | aggregate | {"dataset": "windows.sysmon", "field": "win.SourceImage", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-10aa198a3d | check C094 | aggregate | {"dataset": "windows.sysmon", "field": "win.ImageLoaded", "query": "event.code:7", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 20259 |  |
| q-4810f95742 | check C095 | search | {"dataset": "windows.sysmon", "query": "event.code:8", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinatio… | 95 |  |
| q-98343bf0a3 | check C096 | aggregate | {"dataset": "windows.security", "field": "win.CallerProcessName", "query": "event.code:4656 AND win.ObjectType:*Process*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 13 |  |
| q-bd73c9e008 | check C097 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:*hook* OR powershell.script_block_text:*SetWindowsHookEx* OR powershell.script_block_text:*MiniDump*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.… | 0 |  |
| q-0739da44f6 | check C098 | search | {"dataset": "windows.other", "query": "message:*hook* OR message:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "sou… | 0 |  |
| q-cfd87d5209 | check C099 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-402221c1d0 | check C100 | aggregate | {"dataset": "windows.security", "field": "source.ip", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-9038aed94d | check C101 | timeline | {"dataset": "windows.security", "query": "event.code:4625", "interval": "1m", "time_from": null, "time_to": null} | 0 |  |
| q-c66889ee05 | check C102 | search | {"dataset": "windows.other", "query": "message:*logon* OR message:*password*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 2 | F17 |
| q-9db4af2608 | check C103 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:*Credential* OR powershell.script_block_text:*Password*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.n… | 4 |  |
| q-40c8439540 | check C104 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*net* OR process.command_line:*login*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 30 |  |
| q-663fa45637 | check C105 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-f3c4bd1bf0 | check C106 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 0 |  |
| q-bd107426f5 | check C107 | timeline | {"dataset": "windows.security", "query": "event.code:4625", "interval": "1m", "time_from": null, "time_to": null} | 0 |  |
| q-395208af39 | check C108 | search | {"dataset": "windows.other", "query": "message:*4625* OR message:*failed*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "so… | 2 | F18 |
| q-d87280fd47 | check C109 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:*Password* OR powershell.script_block_text:*Credential*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.n… | 4 |  |
| q-00999082e6 | check C110 | aggregate | {"dataset": "windows.sysmon", "field": "process.command_line", "query": "event.code:1 AND process.command_line:*password*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-cb29134bfe | check C111 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 OR event.code:4656 OR event.code:4670", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 10977 |  |
| q-836af9248f | check C112 | aggregate | {"dataset": "windows.security", "field": "win.ProcessName", "query": "event.code:4663 AND (win.ObjectName:*SAM* OR win.ObjectName:*SECURITY*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-cf3925c8fb | check C113 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*hash* OR process.command_line:*crack*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-caf53f7175 | check C114 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND (win.TargetFilename:*.txt OR win.TargetFilename:*.pot)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 20 |  |
| q-2f0edf1f0e | check C115 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10 AND (win.TargetImage:*lsass* OR win.TargetImage:*SAM*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-e2a7a4bb6e | check C116 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:*hash* OR powershell.script_block_text:*ConvertTo-SecureString*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code",… | 12 |  |
| q-aa752373e6 | check C117 | search | {"dataset": "windows.other", "query": "message:*SAM* OR message:*hash*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "sourc… | 1 |  |
| q-e24181899d | check C118 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-8d1259e03c | check C119 | aggregate | {"dataset": "windows.security", "field": "source.ip", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-572a12a34a | check C120 | search | {"dataset": "windows.security", "query": "event.code:4648", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 15 |  |
| q-051f63044d | check C121 | timeline | {"dataset": "windows.security", "query": "event.code:4625", "interval": "1m", "time_from": null, "time_to": null} | 0 |  |
| q-c2e8442d97 | check C122 | search | {"dataset": "windows.other", "query": "message:*logon* OR message:*account*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "… | 7 | F17, F20 |
| q-819b31f3c7 | check C123 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:*Password* OR powershell.script_block_text:*Credential*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.n… | 4 |  |
| q-d2fd13038c | check C124 | aggregate | {"dataset": "windows.sysmon", "field": "process.command_line", "query": "event.code:1 AND process.command_line:*user*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1 |  |
| q-a5eeac7751 | check C125 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-bfe396d44d | check C126 | aggregate | {"dataset": "windows.security", "field": "source.ip", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-2a24feab5a | check C127 | timeline | {"dataset": "windows.security", "query": "event.code:4625", "interval": "1m", "time_from": null, "time_to": null} | 0 |  |
| q-5f21a09aa4 | check C128 | search | {"dataset": "windows.other", "query": "message:*logon* OR message:*credential*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line"… | 4 |  |
| q-294ad48d65 | check C129 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:*Credential* OR powershell.script_block_text:*Password*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.n… | 4 |  |
| q-dbc72a2d89 | check C130 | aggregate | {"dataset": "windows.sysmon", "field": "process.command_line", "query": "event.code:1 AND process.command_line:*password*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-48659d607a | check C131 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 297 |  |
| q-0579cf99c5 | check C132 | search | {"dataset": "windows.security", "query": "event.code:4648", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 15 |  |
| q-ac076005b8 | check C133 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-c4276bc9ee | check C134 | search | {"dataset": "windows.sysmon", "query": "event.code:13 AND registry.path:*Credential*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command… | 11 |  |
| q-c3dafbc6ea | check C135 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND powershell.script_block_text:*Credential*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executab… | 3 |  |
| q-d97cc36922 | check C136 | search | {"dataset": "windows.other", "query": "message:*Credential*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "des… | 2 |  |
| q-d59beeb480 | check C137 | aggregate | {"dataset": "windows.security", "field": "win.ObjectType", "query": "event.code:4656 OR event.code:4663 OR event.code:4670", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 10977 |  |
| q-15335b5bc8 | check C138 | search | {"dataset": "windows.security", "query": "event.code:5140 OR event.code:5145", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 163 | F25 |
| q-a6e8287b82 | check C139 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1649 |  |
| q-8582841eda | check C140 | search | {"dataset": "windows.sysmon", "query": "event.code:3 AND (destination.port:445 OR destination.port:139)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable… | 66 |  |
| q-74c4de2add | check C141 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*445* OR powershell.script_block_text:*WebDAV* OR powershell.script_block_text:*NTLM*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "ob… | 0 |  |
| q-0f352c7e22 | check C142 | search | {"dataset": "windows.other", "query": "message:*445* OR message:*WebDAV*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "sou… | 0 |  |
| q-8139d98e92 | check C143 | aggregate | {"dataset": "zeek", "field": "destination.port", "query": "event.action:conn AND (destination.port:445 OR destination.port:139)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 50 |  |
| q-25f110f7ca | check C144 | search | {"dataset": "zeek", "query": "event.action:http AND (http.request.method:PROPFIND OR http.request.method:MOVE OR http.request.method:OPTIONS)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.c… | 36 |  |
| q-63c7114687 | check C145 | aggregate | {"dataset": "windows.security", "field": "event.code", "query": "event.code:4768 OR event.code:4769 OR event.code:4770", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 42 |  |
| q-dab7464ed4 | check C146 | search | {"dataset": "windows.security", "query": "event.code:4769", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 28 | F27 |
| q-1fbfcf0c30 | check C147 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-ef9c84f7e2 | check C148 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.GrantedAccess:*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line",… | 39283 |  |
| q-33baab6209 | check C149 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*Invoke-* OR powershell.script_block_text:*Exploit*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "ev… | 16 | F26 |
| q-b98dab9654 | check C150 | search | {"dataset": "windows.other", "query": "message:*exploit*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destin… | 0 |  |
| q-82ea4581f4 | check C151 | search | {"dataset": "zeek", "query": "event.action:notice OR event.action:weird", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "sour… | 14 | F28 |
| q-a9fce50d68 | check C152 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 460 |  |
| q-db2281b121 | check C153 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*cookie* OR process.command_line:*Cookie*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.nam… | 5 |  |
| q-955d4d3558 | check C154 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1649 |  |
| q-6487baed09 | check C155 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (win.TargetFilename:*Cookies* OR win.TargetFilename:*cookie*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "pr… | 1 |  |
| q-1c35a251f7 | check C156 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-56e514ed73 | check C157 | search | {"dataset": "windows.sysmon", "query": "event.code:2 AND (win.TargetFilename:*Cookies* OR win.TargetFilename:*cookie*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "pro… | 0 |  |
| q-e669c64d8f | check C158 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*cookie* OR powershell.script_block_text:*Cookie*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "even… | 0 |  |
| q-eedd5c3e51 | check C159 | search | {"dataset": "windows.other", "query": "message:*cookie*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destina… | 0 |  |
| q-61fb2a2e24 | check C160 | search | {"dataset": "zeek", "query": "event.action:http AND http.request.method:GET", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "… | 2 |  |
| q-959f48f21c | check C161 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 460 |  |
| q-dfd1e6485d | check C162 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*password* OR process.command_line:*credential* OR process.command_line:*unattend*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name",… | 0 |  |
| q-09a447b9bf | check C163 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1649 |  |
| q-876a404663 | check C164 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (win.TargetFilename:*unattend* OR win.TargetFilename:*password* OR win.TargetFilename:*credential*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.da… | 1 |  |
| q-12530a80f9 | check C165 | aggregate | {"dataset": "windows.sysmon", "field": "registry.path", "query": "event.code:13 OR event.code:14", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 17541 |  |
| q-fd263345ab | check C166 | search | {"dataset": "windows.sysmon", "query": "event.code:13 AND (registry.path:*Password* OR registry.path:*Credential*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process… | 17 | F35 |
| q-03fe4638dc | check C167 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*password* OR powershell.script_block_text:*credential*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset",… | 2 |  |
| q-32991ec912 | check C168 | search | {"dataset": "windows.other", "query": "message:*password*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 0 |  |
| q-7a24e7204b | check C169 | search | {"dataset": "zeek", "query": "event.action:smb_files", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinatio… | 12 | F34 |
| q-aad534bf9a | check C170 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 297 |  |
| q-08ba84f7eb | check C171 | search | {"dataset": "windows.security", "query": "event.code:4648", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 15 | F33 |
| q-a282bc5e31 | check C172 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 447 |  |
| q-aafb8105c1 | check C173 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*password* OR process.command_line:*credential* OR process.command_line:*config*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event… | 8 |  |
| q-b9e9ea4e7c | check C174 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1649 |  |
| q-e2002af1a5 | check C175 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (win.TargetFilename:*.config OR win.TargetFilename:*.xml OR win.TargetFilename:*.txt)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event… | 44 |  |
| q-1af26f196a | check C176 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*Get-Content* OR powershell.script_block_text:*Select-String*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dat… | 1 |  |
| q-b982c3665b | check C177 | search | {"dataset": "windows.other", "query": "message:*password*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 0 |  |
| q-ee0726a607 | check C178 | search | {"dataset": "zeek", "query": "event.action:smb_files", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinatio… | 12 |  |
| q-056d7f6afd | check C179 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"13\" AND (TO_LOWER(registry.path) LIKE \"*\\\\sam\\\\*\" OR TO_LOWER(registry.path) LIKE \"*\\\\security\\\\*\" OR TO_LOWER(registry.path) LIKE \"*password*\" OR TO_LOWER… | ERROR |  |
| q-899bfa95d6 | check C179 (repaired) | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"13\" AND (TO_LOWER(registry.path) LIKE \"*\\\\\\\\sam\\\\\\\\*\" OR TO_LOWER(registry.path) LIKE \"*\\\\\\\\security\\\\\\\\*\" OR TO_LOWER(registry.path) LIKE \"*passwor… | 60 |  |
| q-2dfd6da257 | check C180 | aggregate | {"dataset": "windows.sysmon", "field": "registry.path", "query": "event.code:13", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 17541 |  |
| q-8a6333db93 | check C181 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*reg query*\" OR TO_LOWER(process.command_line) LIKE \"*reg save*\" OR TO_LOWER(process.command_line) LIKE \"*\\\\sam*\" OR… | ERROR |  |
| q-12b83322f3 | check C181 (repaired) | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*reg query*\" OR TO_LOWER(process.command_line) LIKE \"*reg save*\" OR TO_LOWER(process.command_line) LIKE \"*sam*\" OR TO_… | 5 |  |
| q-96dd52f6a7 | check C182 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4663\",\"4656\",\"4670\",\"4658\") AND (TO_LOWER(win.ObjectName) LIKE \"*\\\\sam*\" OR TO_LOWER(win.ObjectName) LIKE \"*\\\\security*\" OR TO_LOWER(win.ObjectName) LIK… | ERROR |  |
| q-903fa7c7d4 | check C182 (repaired) | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4663\",\"4656\",\"4670\",\"4658\") AND (TO_LOWER(win.ObjectName) LIKE \"*sam*\" OR TO_LOWER(win.ObjectName) LIKE \"*security*\" OR TO_LOWER(win.ObjectName) LIKE \"*lsa… | 500 |  |
| q-dd062bfdb5 | check C183 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code IN (\"4103\",\"4104\") AND (TO_LOWER(COALESCE(powershell.script_block_text, win.ScriptBlockText, \"\")) LIKE \"*reg query*\" OR TO_LOWER(COALESCE(powershell.script_block_t… | 1 |  |
| q-f415c680d0 | check C184 | esql | {"query": "FROM logs-windows.other-default METADATA _id, _index \| WHERE TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*\\\\sam*\" OR TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*\\\\security*\" OR TO_LOWER(COALESCE(message, win.Message, \"\"… | ERROR |  |
| q-6f56582840 | check C184 (repaired) | esql | {"query": "FROM logs-windows.other-default METADATA _id, _index \| WHERE TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*sam*\" OR TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*security*\" OR TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE … | 12 |  |
| q-51ea38cfab | check C185 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code IN (\"4103\",\"4104\") AND (TO_LOWER(COALESCE(powershell.script_block_text, win.ScriptBlockText, \"\")) LIKE \"*history*\" OR TO_LOWER(COALESCE(powershell.script_block_tex… | 1 |  |
| q-a5126177af | check C186 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*consolehost_history*\" OR TO_LOWER(process.command_line) LIKE \"*psreadline*\" OR TO_LOWER(process.command_line) LIKE \"*h… | 0 |  |
| q-df63d424b5 | check C187 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*consolehost_history*\" OR TO_LOWER(file.path) LIKE \"*psreadline*\" OR TO_LOWER(file.path) LIKE \"*\\\\history*\" OR TO_LOWER(file.p… | ERROR |  |
| q-5744dcfa81 | check C187 (repaired) | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*consolehost_history*\" OR TO_LOWER(file.path) LIKE \"*psreadline*\" OR TO_LOWER(file.path) LIKE \"*history*\" OR TO_LOWER(file.path)… | 15 |  |
| q-93a0b2e1e7 | check C188 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4663\",\"4656\",\"4658\") AND (TO_LOWER(win.ObjectName) LIKE \"*consolehost_history*\" OR TO_LOWER(win.ObjectName) LIKE \"*psreadline*\" OR TO_LOWER(win.ObjectName) LI… | 0 |  |
| q-4a1baad920 | check C189 | esql | {"query": "FROM logs-windows.other-default METADATA _id, _index \| WHERE TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*history*\" OR TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*psreadline*\" \| KEEP @timestamp, host.name, event.code, messag… | 5 |  |
| q-2793a3f0cb | check C190 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*.key\" OR TO_LOWER(file.path) LIKE \"*.pgp\" OR TO_LOWER(file.path) LIKE \"*.gpg\" OR TO_LOWER(file.path) LIKE \"*.ppk\" OR TO_LOWER… | 1 |  |
| q-3ebe523a61 | check C191 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*.pem*\" OR TO_LOWER(process.command_line) LIKE \"*.pfx*\" OR TO_LOWER(process.command_line) LIKE \"*.p12*\" OR TO_LOWER(pr… | 0 |  |
| q-5ca23c244a | check C192 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"5145\" AND (TO_LOWER(win.RelativeTargetName) LIKE \"*.key\" OR TO_LOWER(win.RelativeTargetName) LIKE \"*.pem\" OR TO_LOWER(win.RelativeTargetName) LIKE \"*.pfx\" OR TO_… | 0 |  |
| q-cf87770402 | check C193 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4663\",\"4656\",\"4658\") AND (TO_LOWER(win.ObjectName) LIKE \"*.key\" OR TO_LOWER(win.ObjectName) LIKE \"*.pem\" OR TO_LOWER(win.ObjectName) LIKE \"*.pfx\" OR TO_LOWE… | 0 |  |
| q-e0b3d5b8ea | check C194 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code IN (\"4103\",\"4104\") AND (TO_LOWER(COALESCE(powershell.script_block_text, win.ScriptBlockText, \"\")) LIKE \"*.pem*\" OR TO_LOWER(COALESCE(powershell.script_block_text, … | 2 |  |
| q-d65fd293c8 | check C195 | esql | {"query": "FROM logs-windows.other-default METADATA _id, _index \| WHERE TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*.pem*\" OR TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*.pfx*\" OR TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*… | 0 |  |
| q-9a860e4041 | check C196 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code IN (\"4103\",\"4104\") AND (TO_LOWER(COALESCE(powershell.script_block_text, win.ScriptBlockText, \"\")) LIKE \"*groups.xml*\" OR TO_LOWER(COALESCE(powershell.script_block_… | 32 |  |
| q-bcbac6468b | check C197 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*sysvol*\" OR TO_LOWER(process.command_line) LIKE \"*groups.xml*\" OR TO_LOWER(process.command_line) LIKE \"*cpassword*\" O… | 0 |  |
| q-e3539b7938 | check C198 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*groups.xml*\" OR TO_LOWER(file.path) LIKE \"*sysvol*\" OR TO_LOWER(file.path) LIKE \"*gpprefdecrypt*\" OR TO_LOWER(file.path) LIKE \… | 22 |  |
| q-e6924f8f37 | check C199 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"5145\" AND (TO_LOWER(win.RelativeTargetName) LIKE \"*groups.xml*\" OR TO_LOWER(win.ShareName) LIKE \"*sysvol*\" OR TO_LOWER(win.ShareName) LIKE \"*netlogon*\") \| KEEP … | 56 |  |
| q-876fc76a90 | check C200 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4663\",\"4656\",\"4658\") AND (TO_LOWER(win.ObjectName) LIKE \"*groups.xml*\" OR TO_LOWER(win.ObjectName) LIKE \"*sysvol*\" OR TO_LOWER(win.ObjectName) LIKE \"*gpp*\")… | 0 |  |
| q-2a1775e766 | check C201 | esql | {"query": "FROM logs-windows.other-default METADATA _id, _index \| WHERE TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*sysvol*\" OR TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*groups.xml*\" OR TO_LOWER(COALESCE(message, win.Message, \"\")) … | 0 |  |
| q-b639881db9 | check C202 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND (TO_LOWER(win.TargetImage) LIKE \"*lsass.exe\" OR TO_LOWER(win.SourceImage) LIKE \"*lsass.exe\") \| KEEP @timestamp, host.name, user.name, win.SourceImage, win.T… | 500 |  |
| q-1ddedda11f | check C203 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass.exe", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-c3c03c6d8b | check C204 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*sekurlsa*\" OR TO_LOWER(process.command_line) LIKE \"*lsadump*\" OR TO_LOWER(process.command_line) LIKE \"*mimikatz*\" OR … | 0 |  |
| q-a3e95771c4 | check C205 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4663\",\"4656\",\"4670\",\"4658\") AND (TO_LOWER(win.ObjectName) LIKE \"*\\\\protect\\\\*\" OR TO_LOWER(win.ObjectName) LIKE \"*credential*\" OR TO_LOWER(win.ObjectNam… | ERROR |  |
| q-e5fbb12914 | check C205 (repaired) | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4663\",\"4656\",\"4670\",\"4658\") AND (TO_LOWER(win.ObjectName) LIKE \"*protect*\" OR TO_LOWER(win.ObjectName) LIKE \"*credential*\" OR TO_LOWER(win.ObjectName) LIKE … | 19 | F36, F37 |
| q-3cf04020cb | check C206 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4688\" AND (TO_LOWER(process.command_line) LIKE \"*sekurlsa*\" OR TO_LOWER(process.command_line) LIKE \"*lsadump*\" OR TO_LOWER(process.command_line) LIKE \"*mimikatz*\… | 0 |  |
| q-e00558e154 | check C207 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code IN (\"4103\",\"4104\") AND (TO_LOWER(COALESCE(powershell.script_block_text, win.ScriptBlockText, \"\")) LIKE \"*sekurlsa*\" OR TO_LOWER(COALESCE(powershell.script_block_te… | 5 |  |
| q-3fb3fd1aac | check C208 | esql | {"query": "FROM logs-windows.other-default METADATA _id, _index \| WHERE TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*lsass*\" OR TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*credential*\" OR TO_LOWER(COALESCE(message, win.Message, \"\")) L… | 2 | F37 |
| q-7c575ef64a | check C209 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*login data*\" OR TO_LOWER(process.command_line) LIKE \"*\\\\google\\\\chrome\\\\user data*\" OR TO_LOWER(process.command_l… | ERROR |  |
| q-9773782fe5 | check C209 (repaired) | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*login data*\" OR TO_LOWER(process.command_line) LIKE \"*google*chrome*user data*\" OR TO_LOWER(process.command_line) LIKE … | 0 |  |
| q-2fdf70c728 | check C210 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*login data*\" OR TO_LOWER(file.path) LIKE \"*logins.json*\" OR TO_LOWER(file.path) LIKE \"*key3.db*\" OR TO_LOWER(file.path) LIKE \"… | ERROR |  |
| q-d476907b0a | check C210 (repaired) | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*login data*\" OR TO_LOWER(file.path) LIKE \"*logins.json*\" OR TO_LOWER(file.path) LIKE \"*key3.db*\" OR TO_LOWER(file.path) LIKE \"… | 0 |  |
| q-80f95ca317 | check C211 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND (TO_LOWER(win.TargetImage) LIKE \"*chrome.exe\" OR TO_LOWER(win.TargetImage) LIKE \"*firefox.exe\" OR TO_LOWER(win.TargetImage) LIKE \"*msedge.exe\" OR TO_LOWER(… | 0 |  |
| q-96cbe75bad | check C212 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4663\",\"4656\",\"4658\") AND (TO_LOWER(win.ObjectName) LIKE \"*login data*\" OR TO_LOWER(win.ObjectName) LIKE \"*logins.json*\" OR TO_LOWER(win.ObjectName) LIKE \"*ke… | ERROR |  |
| q-3081de38b7 | check C212 (repaired) | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4663\",\"4656\",\"4658\") AND (TO_LOWER(win.ObjectName) LIKE \"*login data*\" OR TO_LOWER(win.ObjectName) LIKE \"*logins.json*\" OR TO_LOWER(win.ObjectName) LIKE \"*ke… | 0 |  |
| q-9875dc32fb | check C213 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code IN (\"4103\",\"4104\") AND (TO_LOWER(COALESCE(powershell.script_block_text, win.ScriptBlockText, \"\")) LIKE \"*login data*\" OR TO_LOWER(COALESCE(powershell.script_block_… | 0 |  |
| q-685e51b821 | check C214 | esql | {"query": "FROM logs-windows.other-default METADATA _id, _index \| WHERE TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*login data*\" OR TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*logins.json*\" OR TO_LOWER(COALESCE(message, win.Message, \"… | 0 |  |
| q-ee47ca9a66 | check C215 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 326 |  |
| q-a8918aa53b | check C216 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-9057bb1073 | check C217 | search | {"dataset": "windows.sysmon", "query": "event.code:15 AND file.path:*Credentials*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 0 |  |
| q-87de2ccda3 | check C218 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*vault* OR process.command_line:*Credential* OR process.command_line:*cmdkey*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "eve… | 0 |  |
| q-941e8031d4 | check C219 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*Credential* OR powershell.script_block_text:*vault* OR powershell.script_block_text:*cmdkey*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.na… | 3 |  |
| q-00bc03f67e | check C220 | search | {"dataset": "windows.other", "query": "message:*Credential* OR message:*vault*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line"… | 2 |  |
| q-4e3eafb95a | check C221 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.executable:*keepass* OR process.executable:*1password* OR process.executable:*bitwarden* OR process.executable:*lastpass* OR process.executable:*dashlane*)", "time_from": null, "time_to": null, … | 0 |  |
| q-e7f7864257 | check C222 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*keepass* OR file.path:*1password* OR file.path:*bitwarden* OR file.path:*lastpass*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.datase… | 0 |  |
| q-16790b4b6e | check C223 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND (win.TargetImage:*keepass* OR win.TargetImage:*1password* OR win.TargetImage:*bitwarden*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "e… | 0 |  |
| q-5223dbb234 | check C224 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*keepass* OR process.command_line:*1password* OR process.command_line:*bitwarden* OR process.command_line:*kdbx*)", "time_from": null, "time_to": null, "fields": ["@timestamp",… | 0 |  |
| q-685785031e | check C225 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*keepass* OR powershell.script_block_text:*kdbx* OR powershell.script_block_text:*1password* OR powershell.script_block_text:*bitwarden*)", "time_from": null, "time_t… | 0 |  |
| q-4b12a11078 | check C226 | search | {"dataset": "windows.other", "query": "message:*keepass* OR message:*1password* OR message:*bitwarden* OR message:*kdbx*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "p… | 0 |  |
| q-e2bce0d50a | check C227 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 326 | F42 |
| q-f6ae95a375 | check C228 | aggregate | {"dataset": "windows.sysmon", "field": "win.SourceImage", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-0249c50b17 | check C229 | search | {"dataset": "windows.sysmon", "query": "event.code:7 AND (win.ImageLoaded:*lsass* OR win.ImageLoaded:*cryptdll* OR win.ImageLoaded:*sam* OR win.ImageLoaded:*msv1_0*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "… | 77 | F43 |
| q-df17a819fc | check C230 | search | {"dataset": "windows.security", "query": "event.code:4657 AND (win.ObjectName:*lsass* OR win.ObjectName:*cryptdll* OR win.ObjectName:*msv1_0* OR win.ObjectName:*sam*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", … | 0 |  |
| q-82dbb8df52 | check C231 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*lsass* OR process.command_line:*cryptdll* OR process.command_line:*msv1_0*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event… | 0 |  |
| q-f83a8a3809 | check C232 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*lsass* OR powershell.script_block_text:*cryptdll* OR powershell.script_block_text:*msv1_0* OR powershell.script_block_text:*SecurityPackages*)", "time_from": null, "… | 0 |  |
| q-bd2278e887 | check C233 | search | {"dataset": "windows.other", "query": "message:*lsass* OR message:*cryptdll* OR message:*msv1_0*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "pro… | 0 |  |
| q-e213e331cb | check C234 | search | {"dataset": "windows.security", "query": "event.code:4624 AND win.LogonType:3", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line",… | 218 |  |
| q-2d07182dba | check C235 | search | {"dataset": "windows.security", "query": "event.code:4648", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 15 |  |
| q-c48f7e4b1b | check C236 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4624 OR event.code:4648", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 312 |  |
| q-fc9b2b81b1 | check C237 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 326 |  |
| q-49390c31f3 | check C238 | search | {"dataset": "windows.sysmon", "query": "event.code:7 AND (win.ImageLoaded:*lsass* OR win.ImageLoaded:*cryptdll*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.e… | 33 |  |
| q-7725dde61c | check C239 | search | {"dataset": "windows.other", "query": "message:*lsass* OR message:*cryptdll*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 0 |  |
| q-2fbe3dc49d | check C240 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*lsass* OR powershell.script_block_text:*cryptdll* OR powershell.script_block_text:*Skeleton* OR powershell.script_block_text:*DCShadow*)", "time_from": null, "time_t… | 0 |  |
| q-8b8cf5e029 | check C241 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*System32* AND (file.path:*.dll))", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable"… | 0 |  |
| q-721b247ad2 | check C242 | search | {"dataset": "windows.sysmon", "query": "event.code:7 AND (win.ImageLoaded:*lsass* OR win.ImageLoaded:*cryptdll*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.e… | 33 |  |
| q-ae215fb0e0 | check C243 | search | {"dataset": "windows.security", "query": "event.code:4657 AND (win.ObjectName:*Notification\\ Packages* OR win.ObjectName:*Password* OR win.ObjectName:*lsass*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.… | 0 |  |
| q-ca32903f28 | check C244 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*Notification* OR process.command_line:*PasswordFilter*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.co… | 0 |  |
| q-f511118f3f | check C245 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*Notification* OR powershell.script_block_text:*PasswordFilter* OR powershell.script_block_text:*lsass*)", "time_from": null, "time_to": null, "fields": ["@timestamp"… | 0 |  |
| q-bcc5a4831d | check C246 | search | {"dataset": "windows.other", "query": "message:*Notification* OR message:*PasswordFilter* OR message:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.execu… | 10 |  |
| q-f3d5f8805f | check C247 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*AllowReversiblePasswordEncryption* OR powershell.script_block_text:*ReversibleEncryption* OR powershell.script_block_text:*Set-ADUser*)", "time_from": null, "time_to… | 1 |  |
| q-cc7dd65e71 | check C248 | search | {"dataset": "windows.powershell", "query": "event.code:4103 AND (message:*AllowReversiblePasswordEncryption* OR message:*ReversibleEncryption*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event… | 0 |  |
| q-001014bc77 | check C249 | search | {"dataset": "windows.security", "query": "event.code:4739", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 0 |  |
| q-b28f17d016 | check C250 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*Reversible* OR process.command_line:*Set-ADUser* OR process.command_line:*dsmod*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", … | 0 |  |
| q-5c025b05bd | check C251 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*Reversible* OR process.command_line:*Set-ADUser* OR process.command_line:*dsmod*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "even… | 0 |  |
| q-5762a106a7 | check C252 | search | {"dataset": "windows.other", "query": "message:*Reversible* OR message:*AllowReversiblePasswordEncryption*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executa… | 0 |  |
| q-9fa0ba099a | check C253 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(powershell.script_block_text) LIKE \"*set-aduser*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*set-adauthenticationpolicy*\" OR TO_LOWER(powershell.script_block_text)… | 1 |  |
| q-ab2fd04435 | check C254 | count | {"dataset": "windows.security", "query": "event.code:4739", "time_from": null, "time_to": null} | 0 |  |
| q-2519ddce59 | check C255 | aggregate | {"dataset": "windows.security", "field": "win.ObjectType", "query": "event.code:5136 OR event.code:4739", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-869dc610c8 | check C256 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*set-aduser*\" OR TO_LOWER(process.command_line) LIKE \"*set-adauthenticationpolicy*\" OR TO_LOWER(process.command_line) LI… | 0 |  |
| q-09e5776d1a | check C257 | search | {"dataset": "windows.other", "query": "event.code:4739 OR event.code:5136 OR event.code:4738", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process… | 0 |  |
| q-03f9966786 | check C258 | aggregate | {"dataset": "windows.security", "field": "win.LogonProcessName", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 297 |  |
| q-2b4038f8cd | check C259 | aggregate | {"dataset": "windows.security", "field": "win.AuthenticationPackageName", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 297 |  |
| q-e11fe40742 | check C260 | count | {"dataset": "windows.security", "query": "event.code:5136", "time_from": null, "time_to": null} | 0 |  |
| q-7fa9af4396 | check C261 | aggregate | {"dataset": "windows.sysmon", "field": "win.ImageLoaded", "query": "event.code:7", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 20259 |  |
| q-e274984862 | check C262 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(powershell.script_block_text) LIKE \"*connect-msolservice*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*connect-azuread*\" OR TO_LOWER(powershell.script_block_text) L… | 0 |  |
| q-fd88b4343f | check C263 | search | {"dataset": "windows.other", "query": "event.code:5136 OR event.code:4739 OR event.code:4738", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process… | 0 |  |
| q-57603dec63 | check C264 | count | {"dataset": "windows.security", "query": "event.code:4657", "time_from": null, "time_to": null} | 36 |  |
| q-5f2af60644 | check C265 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4657\" AND (TO_LOWER(win.ObjectName) LIKE \"*networkprovider*\" OR TO_LOWER(win.ObjectName) LIKE \"*credential*\" OR TO_LOWER(win.ObjectName) LIKE \"*winlogon*\") \| KE… | 0 |  |
| q-78780b8c45 | check C266 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*networkprovider*\" OR TO_LOWER(file.path) LIKE \"*system32*credential*\" OR TO_LOWER(file.path) LIKE \"*winlogon*\") \| KEEP @timest… | 1 |  |
| q-6fc0f7bb71 | check C267 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 39283 |  |
| q-ced72b2f8d | check C268 | aggregate | {"dataset": "windows.sysmon", "field": "win.ImageLoaded", "query": "event.code:7", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 20259 |  |
| q-e24d83bc24 | check C269 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(powershell.script_block_text) LIKE \"*networkprovider*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*new-itemproperty*\" OR TO_LOWER(powershell.script_block_text) LIKE… | 0 |  |
| q-8180fbe2c7 | check C270 | search | {"dataset": "windows.other", "query": "event.code:4657 OR event.code:11 OR event.code:7", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.comm… | 4 |  |
| q-4d180aa40c | check C271 | aggregate | {"dataset": "windows.security", "field": "win.ObjectType", "query": "event.code:4663 OR event.code:4670 OR event.code:4656", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 10977 |  |
| q-b88cda0d58 | check C272 | aggregate | {"dataset": "windows.security", "field": "win.ProcessName", "query": "event.code:4663 OR event.code:4670 OR event.code:4656", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 10977 |  |
| q-5888dd4a86 | check C273 | aggregate | {"dataset": "windows.sysmon", "field": "win.DestinationHostname", "query": "event.code:3", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 1229 |  |
| q-d698e49a25 | check C274 | aggregate | {"dataset": "windows.sysmon", "field": "win.QueryName", "query": "event.code:22", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 81 |  |
| q-e2b244deee | check C275 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(powershell.script_block_text) LIKE \"*responder*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*mitm*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*arpspoof*\" OR… | 0 |  |
| q-15384c59fb | check C276 | search | {"dataset": "windows.other", "query": "event.code:4663 OR event.code:4670 OR event.code:4656 OR event.code:3 OR event.code:22", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name… | 2 |  |
| q-84efc85a1e | check C277 | aggregate | {"dataset": "zeek", "field": "zeek.conn_state", "query": "event.action:conn", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 613 |  |
| q-545dda5a47 | check C278 | aggregate | {"dataset": "zeek", "field": "zeek.service", "query": "event.action:conn", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 613 |  |
| q-dc5bffec20 | check C279 | count | {"dataset": "windows.security", "query": "event.code:4697", "time_from": null, "time_to": null} | 23 |  |
| q-3ca1e957e1 | check C280 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4657\" AND TO_LOWER(win.ObjectName) LIKE \"*dnsclient*\" \| KEEP @timestamp, host.name, user.name, win.ObjectName, win.NewValue, _id, _index"} | 0 |  |
| q-4a1d3235c5 | check C281 | aggregate | {"dataset": "windows.sysmon", "field": "win.DestinationHostname", "query": "event.code:3", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 1229 |  |
| q-c15aed7c3c | check C282 | aggregate | {"dataset": "windows.sysmon", "field": "win.QueryName", "query": "event.code:22", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 81 |  |
| q-c19e7e7c64 | check C283 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(powershell.script_block_text) LIKE \"*llmnr*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*nbt-ns*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*responder*\" OR … | 0 |  |
| q-f7afccad65 | check C284 | search | {"dataset": "windows.other", "query": "event.code:4697 OR event.code:4657 OR event.code:3 OR event.code:22", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executa… | 2 |  |
| q-5e75233cdb | check C285 | aggregate | {"dataset": "zeek", "field": "zeek.id_resp_h", "query": "event.action:conn AND zeek.service:smb", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-28d9b44933 | check C286 | aggregate | {"dataset": "zeek", "field": "zeek.query", "query": "event.action:dns", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 53 |  |
| q-b3be7a4e69 | check C287 | aggregate | {"dataset": "windows.sysmon", "field": "win.DestinationHostname", "query": "event.code:3", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 1229 |  |
| q-0f9a817f41 | check C288 | aggregate | {"dataset": "windows.sysmon", "field": "win.QueryName", "query": "event.code:22", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 81 |  |
| q-1d78e4a257 | check C289 | aggregate | {"dataset": "windows.security", "field": "win.ProcessName", "query": "event.code:4663 OR event.code:4670 OR event.code:4656", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 10977 |  |
| q-2c5e006952 | check C290 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(powershell.script_block_text) LIKE \"*arp*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*netsh interface*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*get-netne… | 0 |  |
| q-ca9a022498 | check C291 | search | {"dataset": "windows.other", "query": "event.code:3 OR event.code:22 OR event.code:4663 OR event.code:4670", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executa… | 2 |  |
| q-6b82fda83e | check C292 | aggregate | {"dataset": "zeek", "field": "zeek.orig_l2_addr", "query": "event.action:conn", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 613 |  |
| q-cdfbda1631 | check C293 | aggregate | {"dataset": "zeek", "field": "zeek.resp_l2_addr", "query": "event.action:conn", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 613 |  |
| q-0fcce4cee3 | check C294 | search | {"dataset": "windows.other", "query": "event.code:(1341 OR 1342 OR 1020 OR 1063)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_lin… | 0 |  |
| q-7ababff4b4 | check C295 | aggregate | {"dataset": "windows.other", "field": "event.code", "query": "*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 216 |  |
| q-d261063a76 | check C296 | search | {"dataset": "windows.security", "query": "event.code:5156 AND win.Direction:Inbound", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_… | 0 |  |
| q-877cef8ab9 | check C297 | aggregate | {"dataset": "windows.sysmon", "field": "destination.port", "query": "event.code:3", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1229 |  |
| q-aa17b06860 | check C298 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:(*Dhcp* OR *dhcp*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.… | 0 |  |
| q-7240185558 | check C299 | aggregate | {"dataset": "zeek", "field": "event.action", "query": "*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 2140 |  |
| q-12ac85ad3d | check C300 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4672", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 212 |  |
| q-fe42112497 | check C301 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 297 |  |
| q-aff6d19647 | check C302 | search | {"dataset": "windows.security", "query": "event.code:4634", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 236 |  |
| q-8804d209d6 | check C303 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-237a36d9a1 | check C304 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-18ea6e56fa | check C305 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:(*kerberos* OR *Kerberos* OR *ticket* OR *Ticket*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name",… | 0 |  |
| q-ecb72ace9f | check C306 | search | {"dataset": "windows.other", "query": "event.code:(7045 OR 7040)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip",… | 9 |  |
| q-b5683e3c0b | check C307 | aggregate | {"dataset": "zeek", "field": "zeek.request_type", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 35 |  |
| q-741517c7cd | check C308 | search | {"dataset": "windows.security", "query": "event.code:4769", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 28 |  |
| q-9f598c07d5 | check C309 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4672", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 212 |  |
| q-0ab0812af6 | check C310 | aggregate | {"dataset": "windows.security", "field": "win.TicketEncryptionType", "query": "event.code:4769", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 28 |  |
| q-95cb8f4e53 | check C311 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-8d2cc33bb3 | check C312 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:(*golden* OR *Golden* OR *krbtgt* OR *KRBTGT*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "pr… | 0 |  |
| q-92813edb8e | check C313 | aggregate | {"dataset": "windows.other", "field": "event.code", "query": "*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 216 |  |
| q-acfd63681c | check C314 | aggregate | {"dataset": "zeek", "field": "zeek.request_type", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 35 |  |
| q-2e7f7e5272 | check C315 | search | {"dataset": "windows.security", "query": "event.code:4769", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 28 |  |
| q-7b4fb1a1c1 | check C316 | aggregate | {"dataset": "windows.security", "field": "win.ServiceName", "query": "event.code:4769", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 28 |  |
| q-71e58ec4b1 | check C317 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4672", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 212 |  |
| q-b2683f0a49 | check C318 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-166cb3e720 | check C319 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:(*silver* OR *Silver* OR *service ticket* OR *SPN*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name"… | 0 |  |
| q-927ed72d48 | check C320 | search | {"dataset": "windows.other", "query": "event.code:(7045 OR 7040)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip",… | 9 |  |
| q-cc9677a72a | check C321 | aggregate | {"dataset": "zeek", "field": "zeek.request_type", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 35 |  |
| q-94788d77b7 | check C322 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4769", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 28 |  |
| q-e9d7e54f20 | check C323 | aggregate | {"dataset": "windows.security", "field": "win.TicketEncryptionType", "query": "event.code:4769", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 28 |  |
| q-5d6ff2f041 | check C324 | search | {"dataset": "windows.security", "query": "event.code:4648", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 15 |  |
| q-8a0ff2b11d | check C325 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 297 |  |
| q-bec95a6efe | check C326 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-a4ac4351b6 | check C327 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:(*Kerberoast* OR *kerberoast* OR *Invoke-Kerberoast* OR *Rubeus*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code… | 0 |  |
| q-60db3804c8 | check C328 | aggregate | {"dataset": "windows.other", "field": "event.code", "query": "*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 216 |  |
| q-f06ae7cf29 | check C329 | aggregate | {"dataset": "zeek", "field": "zeek.request_type", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 35 |  |
| q-2faaa10ba4 | check C330 | search | {"dataset": "windows.security", "query": "event.code:4768", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 14 |  |
| q-056d3b1c96 | check C331 | aggregate | {"dataset": "windows.security", "field": "win.PreAuthType", "query": "event.code:4768", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 14 |  |
| q-0cf5cedd29 | check C332 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4768", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 14 |  |
| q-12ae58c824 | check C333 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 447 |  |
| q-b6b21938eb | check C334 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:(*AS-REP* OR *asrep* OR *GetNPUsers* OR *DontRequirePreAuth*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "… | 0 |  |
| q-4085999e8f | check C335 | aggregate | {"dataset": "windows.other", "field": "event.code", "query": "*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 216 |  |
| q-f67e365886 | check C336 | aggregate | {"dataset": "zeek", "field": "zeek.request_type", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 35 |  |
| q-7bf23adb28 | check C337 | aggregate | {"dataset": "windows.security", "field": "win.LogonProcessName", "query": "event.code:4624 OR event.code:4648", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 312 |  |
| q-d277760d05 | check C338 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-c084c56296 | check C339 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*cookie* OR powershell.script_block_text:*token* OR powershell.script_block_text:*SAML*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "… | 1 |  |
| q-40429e3339 | check C340 | search | {"dataset": "windows.other", "query": "event.code:7045 OR event.code:5857 OR event.code:5858", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process… | 90 | F54 |
| q-7c3ff12e9d | check C341 | aggregate | {"dataset": "zeek", "field": "event.action", "query": "event.action:http OR event.action:ssl OR event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 475 |  |
| q-241700ebc1 | check C342 | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11 AND (file.path:*cookie* OR file.path:*Cookies*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1 |  |
| q-d815e53442 | check C343 | aggregate | {"dataset": "windows.security", "field": "win.LogonProcessName", "query": "event.code:4624 OR event.code:4648", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 312 |  |
| q-3ee9e4d900 | check C344 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*cookie* OR powershell.script_block_text:*Set-Cookie* OR powershell.script_block_text:*session*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.… | 1 | F55 |
| q-230ad71b07 | check C345 | search | {"dataset": "windows.other", "query": "event.code:11 OR event.code:16", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source… | 9 |  |
| q-ba10c77178 | check C346 | search | {"dataset": "zeek", "query": "event.action:http AND http.request.method:*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "so… | 62 | F56 |
| q-e68a655bc4 | check C347 | aggregate | {"dataset": "windows.security", "field": "win.LogonProcessName", "query": "event.code:4624 OR event.code:4648", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 312 |  |
| q-35289affda | check C348 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*SAML* OR powershell.script_block_text:*NotOnOrAfter* OR powershell.script_block_text:*Assertion*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "hos… | 0 |  |
| q-f06f37eb23 | check C349 | search | {"dataset": "windows.other", "query": "event.code:7045 OR event.code:5857 OR event.code:5858", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process… | 90 |  |
| q-58769693cb | check C350 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*saml* OR process.command_line:*token* OR process.command_line:*cert*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-8316bef28b | check C351 | search | {"dataset": "zeek", "query": "event.action:http AND (url.original:*saml* OR url.original:*adfs* OR url.original:*token*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "p… | 0 |  |
| q-d1a366ea55 | check C352 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-1ba62bec4c | check C353 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-e0fccf07d0 | check C354 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*MFA* OR powershell.script_block_text:*2FA* OR powershell.script_block_text:*Authenticator*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name… | 0 |  |
| q-9a62b7bed0 | check C355 | search | {"dataset": "windows.other", "query": "event.code:4625 OR event.code:5857 OR event.code:5858", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process… | 85 |  |
| q-d0f3c03a5d | check C356 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*login* OR process.command_line:*auth* OR process.command_line:*mfa*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-b6d9950bce | check C357 | search | {"dataset": "zeek", "query": "event.action:http AND (url.original:*login* OR url.original:*auth* OR url.original:*mfa*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "pr… | 0 |  |
| q-b3bdf05df6 | check C358 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4657", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 36 |  |
| q-bfe2eaa518 | check C359 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4768", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 14 |  |
| q-6f5100f8c9 | check C360 | aggregate | {"dataset": "windows.sysmon", "field": "registry.path", "query": "event.code:13 AND (registry.path:*Certificate* OR registry.path:*Crypto* OR registry.path:*Keys*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1133 |  |
| q-4e2d3b4cc0 | check C361 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*Certificate* OR powershell.script_block_text:*Export-PfxCertificate* OR powershell.script_block_text:*New-SelfSignedCertificate*)", "time_from": null, "time_to": nul… | 1 |  |
| q-7551882c57 | check C362 | search | {"dataset": "windows.other", "query": "event.code:7045 OR event.code:5857 OR event.code:5858", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process… | 90 |  |
| q-20f32b0c39 | check C363 | aggregate | {"dataset": "zeek", "field": "zeek.certificate_subject", "query": "event.action:x509", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 378 |  |
| q-fe1b9af7e2 | triage T1003 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND (win.GrantedAccess:0x1fffff OR win.GrantedAccess:0x101001 OR win.GrantedAccess:0x1f3fff OR win.GrantedAccess:0x1000000 OR win.GrantedAccess:0x3000 OR win.GrantedAccess:0x1400… | 33 | F01 |
| q-0cd5c6ed25 | triage T1003 step 1 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NY3HhA"} | None | F03 |
| q-78c1e7b496 | triage T1003 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-3ab7e835c6 | triage T1003 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k13y"} | None |  |
| q-68af76f232 | triage T1003 step 2 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND @timestamp >= \"2020-05-02T03:04:00.000Z\" AND @timestamp <= \"2020-05-02T03:07:00.000Z\" \| KEEP @timestamp, host.name, user.name, powershell.script_block… | 30 | F02 |
| q-67d4d90830 | triage T1003 step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(powershell.script_block_text) LIKE \"*lsass*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*minidump*\" OR TO_LOWER(powershell.script_block_… | 13 | F02 |
| q-bfa372b438 | triage T1003 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"13\" AND registry.path LIKE \"*SAM*\" \| KEEP @timestamp, host.name, process.executable, registry.path, registry.data.strings, _id, _index \| LIMIT 30"} | 2 |  |
| q-304f226f0d | triage T1003 step 4 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-05413bc808 | triage T1003 step 4 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrM7IJ"} | None | F01 |
| q-0c11bb288b | triage T1003 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"13\" AND registry.path LIKE \"*SECURITY*\" \| KEEP @timestamp, host.name, process.executable, registry.path, registry.data.strings, _id, _index \| LIMIT 20"} | 5 | F04, F06 |
| q-36a06901cc | triage T1003 step 5 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4656\" AND win.ObjectName LIKE \"*lsass*\" \| KEEP @timestamp, host.name, user.name, process.executable, win.ObjectName, win.AccessMask, _id, _index \| LIMIT 20"} | 13 | F01 |
| q-5f1b60b6af | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-40bf6d9486 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k13y"} | None |  |
| q-37c8028142 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrM7IJ"} | None |  |
| q-3abacf8931 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YldM_p"} | None |  |
| q-f07bad69d7 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YjaXaO"} | None |  |
| q-2b1377e44a | triage T1003 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None |  |
| q-d9799ee838 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-f2284cf39e | triage T1003 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21_Tx"} | None |  |
| q-b52892aee9 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NY3HhA"} | None |  |
| q-cc90d20f84 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NY3HhA"} | None |  |
| q-a874f93f26 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RpKsLE"} | None |  |
| q-670cd39223 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NAd3XG"} | None |  |
| q-0de3662878 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MtUmZF"} | None |  |
| q-6c931c7d8b | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RjDyQJ"} | None |  |
| q-912f66ef89 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NY3HhL"} | None |  |
| q-3cae958a01 | triage T1040 step 1 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.executable:*NetworkWatcher* OR process.executable:*logman* OR process.executable:*netsh* OR process.executable:*pktmon*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host… | 13 | F08 |
| q-84eefb22c8 | triage T1040 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*pktmon* OR process.command_line:*netsh* OR process.command_line:*logman* OR process.command_line:*NetworkWatcher* OR process.command_line:*capture*)", "time_from": null, "time_to":… | 14 | F08 |
| q-5f8cd3abf7 | triage T1040 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.executable:*psexec* OR process.executable:*PsExec* OR process.command_line:*PSEXESVC* OR process.command_line:*\\\\\\\\*\\\\\\\\admin$*)", "time_from": null, "time_to": null, "fields": ["@timest… | 8 | F10 |
| q-f3406a6f9f | triage T1040 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (win.TargetFilename:*pcap* OR win.TargetFilename:*.etl OR win.TargetFilename:*capture* OR win.TargetFilename:*dump*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.nam… | 46 | F09 |
| q-97a7446451 | triage T1040 step 3 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.executable:*python* OR process.command_line:*python*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "process.executable", "process.command_line", "proc… | 9 | F10 |
| q-19030cf41c | triage T1040 step 3 | search | {"dataset": "windows.sysmon", "query": "event.code:8 AND (win.TargetImage:*python* OR win.SourceImage:*python* OR win.TargetImage:*psexec* OR win.TargetImage:*PSEXESVC*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "… | 0 |  |
| q-92c22131f6 | triage T1040 step 4 | search | {"dataset": "windows.sysmon", "query": "event.code:3 AND (process.executable:*python* OR process.executable:*PSEXESVC*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "process.executable", "destination.ip", "destinatio… | 348 | F10 |
| q-28150d206b | triage T1040 step 4 | search | {"dataset": "zeek", "query": "event.action:conn AND network.transport:icmp", "time_from": null, "time_to": null, "fields": ["@timestamp", "event.action", "network.transport", "source.ip", "destination.ip", "destination.port", "zeek.conn_state", "observer.name"… | 0 |  |
| q-212e0f2401 | triage T1040 step 5 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "win.ServiceName", "win.ImagePath", "message"], "size": 50, "sort": "asc"} | 5 |  |
| q-9bc151b194 | triage T1040 step 5 | search | {"dataset": "windows.sysmon", "query": "event.code:6 AND (win.Image:*npcap* OR win.Image:*pcap* OR win.Image:*winpcap* OR win.Image:*NetworkWatcher*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "process.executable",… | 0 |  |
| q-1691aa68a8 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NW1Kgv"} | None |  |
| q-5e4159ca47 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1WpSJN6"} | None |  |
| q-addf7716c0 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NUxiiK"} | None |  |
| q-bdf563f792 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YYOcv1"} | None |  |
| q-d1cb23451d | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1SDpYge"} | None |  |
| q-e1af553475 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrMbJC"} | None |  |
| q-4cb48154d1 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RqK7jn"} | None |  |
| q-8d443a8cc7 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RpKsKx"} | None |  |
| q-66918c2245 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RjDSP-"} | None |  |
| q-3184a3422f | triage T1056 step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND win.TargetImage LIKE \"*lsass*\" \| STATS cnt = COUNT(*) BY process.executable, win.GrantedAccess, host.name \| SORT cnt DESC \| LIMIT 50"} | 18 |  |
| q-f30dad9955 | triage T1056 step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND win.TargetImage LIKE \"*lsass*\" AND win.GrantedAccess IN (\"0x1fffff\",\"0x101001\",\"0x1f3fff\",\"0x1000000\",\"0x3000\",\"0x1400\") \| KEEP @timestamp, host.n… | 33 | F13 |
| q-c523e0a03b | triage T1056 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND win.TargetImage LIKE \"*lsass*\" AND process.executable LIKE \"*PowerShell*\" \| KEEP @timestamp, host.name, process.executable, process.command_line, win.Grante… | 4 | F11 |
| q-df6fd0d289 | triage T1056 step 2 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" \| KEEP @timestamp, host.name, user.name, powershell.script_block_text, _id, _index \| LIMIT 30"} | 30 | F12 |
| q-5d12951e87 | triage T1056 step 3 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1bzyNfQ"} | None | F12 |
| q-c544fb002c | triage T1056 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-87789bffbe | triage T1056 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (process.command_line LIKE \"*PowerShell*\" OR process.command_line LIKE \"*lsass*\" OR process.command_line LIKE \"*FromBase64*\") \| KEEP @timestamp, host.name,… | 5 | F12, F15, F16 |
| q-65efd5281e | triage T1056 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND process.executable LIKE \"*wsmprovhost*\" \| KEEP @timestamp, host.name, process.executable, win.TargetImage, win.GrantedAccess, win.CallTrace, _id, _index \| LI… | 10 |  |
| q-aa3cff810f | triage T1056 step 5 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MtUml9"} | None |  |
| q-c393ac5eaa | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-0d7ec66dcd | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-7c5c93d957 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-389c0f7161 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k13y"} | None |  |
| q-c5b946a021 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1bzyNfQ"} | None |  |
| q-8774194568 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1bzyNfQ"} | None |  |
| q-c17ec9bc85 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MtUml9"} | None |  |
| q-ed4e510094 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MtUml9"} | None |  |
| q-44be6e54d9 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1WhJHLy"} | None |  |
| q-7220e0b700 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NAenUm"} | None |  |
| q-6430ff7b59 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YWMnGq"} | None |  |
| q-ccefc563cd | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1SIv93X"} | None |  |
| q-e2627c6ba5 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R4eBiX"} | None |  |
| q-2c5917a6d3 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R4eBiX"} | None |  |
| q-40a49a4e11 | triage T1110 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None | F18, F19 |
| q-d769627643 | triage T1110 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None | F19, F21 |
| q-80a33db14c | triage T1110 step 1 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-5ca936ad7f | triage T1110 step 1 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-13783086f0 | triage T1110 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND (win.GrantedAccess:0x1fffff OR win.GrantedAccess:0x101001 OR win.GrantedAccess:0x1f3fff OR win.GrantedAccess:0x1000000 OR win.GrantedAccess:0x3000 OR win.GrantedAccess:0x1400… | 33 | F19 |
| q-328b95d70a | triage T1110 step 2 | search | {"dataset": "windows.security", "query": "event.code:4624 AND win.LogonType:3", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "win.TargetUserName", "source.ip", "win.LogonType", "win.AuthenticationPackageName"], "size": 30, "sort": … | 218 |  |
| q-26a9280e40 | triage T1110 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-8489339c35 | triage T1110 step 3 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1YogQzA"} | ERROR |  |
| q-a78f5f004c | triage T1110 step 4 | search | {"dataset": "windows.security", "query": "event.code:4648 AND process.executable:*PSEXESVC*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "win.TargetUserName", "process.executable", "win.TargetServerName", "user.name"], "size": 10… | 4 | F20, F21 |
| q-e0de41e5ea | triage T1110 step 4 | count | {"dataset": "windows.security", "query": "event.code:4625", "time_from": null, "time_to": null} | 0 |  |
| q-a6ab503488 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx0y"} | None |  |
| q-ff9385bc8b | triage T1110 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx04"} | None |  |
| q-60ab3abd54 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None |  |
| q-75c747ebae | triage T1110 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx1g"} | None |  |
| q-c27a16f5c2 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-dfc6ccac05 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-0a62fc913e | triage T1110 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-3faeea8ecc | triage T1110 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None |  |
| q-95d595c5b8 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-9b9f99a56b | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YogQzA"} | None |  |
| q-edb3fce775 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YogQzA"} | None |  |
| q-a22e0db132 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx2T"} | None |  |
| q-49d7d56cfd | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YcSCoM"} | None |  |
| q-d59218d491 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-06c191b304 | triage T1111 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-db841aebf3 | triage T1111 step 1 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YQHQbW"} | None | F22 |
| q-9b848abdc7 | triage T1111 step 1 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-851218a46a | triage T1111 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "process.executable", "win.TargetImage", "win.GrantedAccess", "win.CallTrace"], "size": 50, "sort": "a… | 326 | F22 |
| q-5755c8570d | triage T1111 step 2 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 326 |  |
| q-08c14aeec7 | triage T1111 step 2 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 326 |  |
| q-f6cb38e2e8 | triage T1111 step 2 | search | {"dataset": "windows.security", "query": "event.code:4624 AND win.LogonType:10", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "win.LogonType", "win.IpAddress", "win.Workstation", "win.AuthenticationPackageName"], "size… | 2 |  |
| q-5319ce8320 | triage T1111 step 2 | search | {"dataset": "windows.security", "query": "event.code:4624 AND win.LogonType:2", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "win.LogonType", "win.IpAddress", "win.Workstation", "win.AuthenticationPackageName"], "size"… | 15 |  |
| q-add0c8009d | triage T1111 step 3 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND (win.GrantedAccess:0x1fffff OR win.GrantedAccess:0x101001 OR win.GrantedAccess:0x1f3fff OR win.GrantedAccess:0x1000000 OR win.GrantedAccess:0x3000)", "time_from": null, "time… | 9 | F22 |
| q-239a3485dd | triage T1111 step 3 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND process.executable:*PowerShell*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "process.executable", "win.GrantedAccess", "win.CallTrace"], "size… | 4 |  |
| q-c1f612ae56 | triage T1111 step 3 | search | {"dataset": "windows.security", "query": "event.code:4624 AND win.LogonType:5", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "win.LogonType", "win.IpAddress", "win.AuthenticationPackageName"], "size": 10, "sort": "asc"… | 61 |  |
| q-4cec81ee93 | triage T1111 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*smartcard*\" OR TO_LOWER(process.command_line) LIKE \"*otp*\" OR TO_LOWER(process.command_line) LIKE \"*mfa*\" OR TO_LOWER… | 4 |  |
| q-3df443d207 | triage T1111 step 4 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-1e2dc276b6 | triage T1111 step 4 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrM7IJ"} | None |  |
| q-f2a41f544c | triage T1111 step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND @timestamp >= \"2020-05-02T03:04:00.000Z\" AND @timestamp <= \"2020-05-02T03:07:00.000Z\" \| KEEP @timestamp, host.name, user.name, powershell.script_block… | 35 |  |
| q-5656560e3a | triage T1111 step 5 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None | F22 |
| q-8be782708b | triage T1111 step 5 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21_Rv"} | None |  |
| q-9acda950d9 | triage T1111 step 5 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND powershell.script_block_text LIKE \"*Get-Keystrokes*\" \| KEEP @timestamp, host.name, user.name, powershell.script_block_text, _id, _index"} | 1 | F22 |
| q-742dec4a37 | triage T1111 step 6 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4624\" AND (win.AuthenticationPackageName LIKE \"*Kerberos*\" OR win.AuthenticationPackageName LIKE \"*smart*\" OR win.AuthenticationPackageName LIKE \"*PKU2U*\" OR win… | 218 |  |
| q-1494f2e88f | triage T1111 step 6 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*export-pfxcertificate*\" OR TO_LOWER(process.command_line) LIKE \"*certutil*\" OR TO_LOWER(process.command_line) LIKE \"*m… | 0 |  |
| q-33057021c1 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-00d6fff390 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-e17225e397 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None |  |
| q-bc5e244296 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21_Tx"} | None |  |
| q-96290061e4 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1WhJHLy"} | None |  |
| q-f40ac6d2b8 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YQHQbW"} | None |  |
| q-0452973b93 | triage T1187 step 1 | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8Ieh"} | None | F23, F24 |
| q-43180d76be | triage T1187 step 1 | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8Iej"} | None | F23 |
| q-30a67ad861 | triage T1187 step 1 | aggregate | {"dataset": "zeek", "field": "source.ip", "query": "event.action:http AND (http.request.method:PROPFIND OR http.request.method:MOVE OR http.request.method:OPTIONS)", "time_from": null, "time_to": null, "size": 20, "sub_field": "destination.ip"} | 36 |  |
| q-570c87a396 | triage T1187 step 1 | aggregate | {"dataset": "zeek", "field": "user_agent.original", "query": "event.action:http", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 62 |  |
| q-cfff307546 | triage T1187 step 2 | aggregate | {"dataset": "zeek", "field": "destination.ip", "query": "event.action:conn AND (destination.port:445 OR destination.port:139)", "time_from": null, "time_to": null, "size": 20, "sub_field": "source.ip"} | 50 |  |
| q-5f5e32be73 | triage T1187 step 2 | aggregate | {"dataset": "zeek", "field": "destination.ip", "query": "event.action:conn", "time_from": null, "time_to": null, "size": 30, "sub_field": "source.ip"} | 613 |  |
| q-ea680f209f | triage T1187 step 2 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == 4624 AND win.LogonType == \"3\" \| KEEP @timestamp, host.name, win.TargetUserName, win.IpAddress, win.LogonProcessName, win.AuthenticationPackageName, _id, _index \| LIMI… | ERROR |  |
| q-7f4fd7509e | triage T1187 step 3 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4624\" AND win.LogonType == \"3\" \| KEEP @timestamp, host.name, win.TargetUserName, win.IpAddress, win.LogonProcessName, win.AuthenticationPackageName, _id, _index \| … | 50 |  |
| q-e9b75062b4 | triage T1187 step 3 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4624\" AND win.LogonType == \"3\" \| STATS c = COUNT(*) BY win.TargetUserName, win.IpAddress, host.name \| SORT c DESC \| LIMIT 30"} | 16 |  |
| q-48c9a5fad4 | triage T1187 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"3\" AND (destination.ip == \"192.168.0.4\" OR destination.port == 445 OR destination.port == 139) \| KEEP @timestamp, host.name, process.executable, user.name, destinatio… | 40 | F24 |
| q-0e0bce0a77 | triage T1187 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*webdav*\" OR TO_LOWER(process.command_line) LIKE \"*192.168.0.4*\" OR TO_LOWER(process.command_line) LIKE \"*\\\\\\\\*\") … | 30 |  |
| q-19b862e8cd | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8Ieh"} | None |  |
| q-a9c1fc7cf3 | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8Ieh"} | None |  |
| q-b54a28389f | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8Ieh"} | None |  |
| q-63d9e65bff | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8Iej"} | None |  |
| q-d5cb06513d | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8Iej"} | None |  |
| q-d99aff767b | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8Ieh"} | None |  |
| q-8794989a49 | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8Ieh"} | None |  |
| q-9aa38e579b | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8Ieh"} | None |  |
| q-ba05669633 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MsQYML"} | None |  |
| q-16d751e280 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MsQYML"} | None |  |
| q-95bb4664af | triage T1187 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YsmIPl"} | None |  |
| q-ee051b29ed | triage T1187 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YcRSol"} | None |  |
| q-f217ad65cb | triage T1187 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YcRSol"} | None |  |
| q-ce7115a426 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "n/a"} | ERROR |  |
| q-ea337e3214 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "n/a"} | ERROR |  |
| q-4fd8c7bee4 | triage T1212 step 1 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 326 |  |
| q-b8bafa2cbb | triage T1212 step 1 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 326 |  |
| q-325ce97433 | triage T1212 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND (win.GrantedAccess:0x1fffff OR win.GrantedAccess:0x1f3fff OR win.GrantedAccess:0x101001 OR win.GrantedAccess:0x1000000)", "time_from": null, "time_to": null, "fields": ["@tim… | 8 | F26 |
| q-87367a5890 | triage T1212 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND process.executable:*PowerShell*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "proc… | 4 |  |
| q-b66b0f7b7e | triage T1212 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None | F26 |
| q-31384dd0f1 | triage T1212 step 3 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*lsass* OR powershell.script_block_text:*MiniDump* OR powershell.script_block_text:*Credential* OR powershell.script_block_text:*Dump*)", "time_from": null, "time_to"… | 3 |  |
| q-d7ef803386 | triage T1212 step 4 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*lsass* OR process.command_line:*MiniDump* OR process.command_line:*sekurlsa* OR process.command_line:*procdump* OR process.command_line:*comsvcs* OR process.command_line:*DumpCred*… | 1 |  |
| q-76914fddd8 | triage T1212 step 4 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND process.pid:2976", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "so… | 1 |  |
| q-98432b1e51 | triage T1212 step 5 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1WdFNhN"} | None | F26 |
| q-14b2ebfa5a | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1WdFNhN"} | None |  |
| q-7053b280da | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1WdFNhN"} | None |  |
| q-ca62b0aba2 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1WdFNhN"} | None |  |
| q-debb71806e | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-e003c21e63 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-4e21c983a7 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-82f1f5c625 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k13y"} | None |  |
| q-2f1ca5e7f6 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrM7IJ"} | None |  |
| q-946c18e86c | triage T1212 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1bsxQxS"} | None |  |
| q-7b89cb7450 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-d64e210c1a | triage T1212 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YhYtYv"} | None |  |
| q-a3c448e062 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YhYtYv"} | None |  |
| q-50ceb700b2 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YOGdm5"} | None |  |
| q-d9093a12a8 | triage T1212 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO74el"} | None |  |
| q-aef621ac62 | triage T1212 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8IdY"} | None |  |
| q-8f9632d07c | triage T1539 step 1 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MsOhX7"} | None | F29 |
| q-8305b35bb0 | triage T1539 step 1 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YeU-Dp"} | None | F29 |
| q-32daaef834 | triage T1539 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(win.TargetFilename) LIKE \"*cookies*\" OR TO_LOWER(win.TargetFilename) LIKE \"*login data*\" OR TO_LOWER(win.TargetFilename) LIKE \"*web data*\" OR TO_… | 1 |  |
| q-5dec91cf7d | triage T1539 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND (TO_LOWER(win.TargetImage) LIKE \"*chrome*\" OR TO_LOWER(win.TargetImage) LIKE \"*firefox*\" OR TO_LOWER(win.TargetImage) LIKE \"*iexplore*\" OR TO_LOWER(win.Tar… | 374 | F30 |
| q-bd3260df3e | triage T1539 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*cookie*\" OR TO_LOWER(process.command_line) LIKE \"*login data*\" OR TO_LOWER(process.command_line) LIKE \"*web data*\" OR… | 5 |  |
| q-8af8ca73da | triage T1539 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(win.TargetFilename) LIKE \"*appdata*local*google*\" OR TO_LOWER(win.TargetFilename) LIKE \"*appdata*roaming*mozilla*\" OR TO_LOWER(win.TargetFilename) … | 5 | F30 |
| q-84f37fa1ed | triage T1539 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.executable) LIKE \"*python*\" OR TO_LOWER(process.executable) LIKE \"*psexec*\" OR TO_LOWER(process.executable) LIKE \"*sdelete*\") \| KEEP @tim… | 15 | F31 |
| q-e36a0ff877 | triage T1539 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND (TO_LOWER(win.TargetImage) LIKE \"*lsass*\" OR TO_LOWER(win.TargetImage) LIKE \"*chrome*\" OR TO_LOWER(win.TargetImage) LIKE \"*firefox*\") \| KEEP @timestamp, h… | 326 |  |
| q-a78da5a8c4 | triage T1539 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND TO_LOWER(win.TargetFilename) LIKE \"*webdav*\" \| KEEP @timestamp, host.name, process.executable, win.TargetFilename, _id, _index"} | 0 |  |
| q-acd501b0b0 | triage T1539 step 5 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4688\" AND TO_LOWER(process.command_line) LIKE \"*davclnt*\" \| KEEP @timestamp, host.name, user.name, process.command_line, _id, _index"} | 5 |  |
| q-76005b720d | triage T1539 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YeU-Dp"} | None |  |
| q-b1f5e19a11 | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MsOhX7"} | None |  |
| q-416c39f0e7 | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MsPCud"} | None |  |
| q-1001969d3c | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1Muar8B"} | None |  |
| q-f0456b2f8c | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RkEAFq"} | None |  |
| q-553bd69f5b | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1SEqWk4"} | None |  |
| q-ca7b558c8c | triage T1552 step 1 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R_lkD8"} | None | F32, F33 |
| q-8e75b6245e | triage T1552 step 1 | search | {"dataset": "windows.sysmon", "query": "process.executable:*accesschk* OR process.command_line:*accesschk*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executa… | 2 |  |
| q-40e00eace9 | triage T1552 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*sysvol* OR process.command_line:*Groups.xml* OR process.command_line:*gpt.ini* OR process.command_line:*GptTmpl*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "ho… | 0 |  |
| q-d1b8fc8df0 | triage T1552 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (win.TargetFilename:*passwordsDB* OR win.TargetFilename:*passwords* OR win.TargetFilename:*Groups.xml*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "even… | 1 |  |
| q-5916f9d780 | triage T1552 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R_lkD_"} | None | F32 |
| q-3af4fdd605 | triage T1552 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND process.executable:*SysinternalsSuite*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "proc… | 8 | F32 |
| q-d4f213e0ee | triage T1552 step 2 | search | {"dataset": "windows.security", "query": "event.code:5145 AND (win.RelativeTargetName:*GptTmpl* OR win.RelativeTargetName:*Groups.xml* OR win.RelativeTargetName:*gpt.ini* OR win.RelativeTargetName:*SecEdit*)", "time_from": null, "time_to": null, "fields": ["@t… | 23 | F34 |
| q-fea0280a67 | triage T1552 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND win.TargetFilename:*SysinternalsSuite*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "pro… | 311 |  |
| q-1c4a57f360 | triage T1552 step 3 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*passwordsDB* OR powershell.script_block_text:*accesschk* OR powershell.script_block_text:*Fl0nk3rt0n* OR powershell.script_block_text:*sysvol*)", "time_from": null, … | 5 | F33 |
| q-628ad4871f | triage T1552 step 3 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (win.TargetFilename:*Draft.Zip* OR win.TargetFilename:*victim* OR win.TargetFilename:*cod.3aka3*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.data… | 1 |  |
| q-c180581289 | triage T1552 step 3 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND process.command_line:*Fl0nk3rt0n*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.c… | 4 | F33 |
| q-a9ebb5e46f | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R_lkD8"} | None |  |
| q-25f62bd36a | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R_lkD8"} | None |  |
| q-dcf0cbe39b | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R_lkD_"} | None |  |
| q-47e0297573 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R_lkD_"} | None |  |
| q-8b31f1c513 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1SEqWk4"} | None |  |
| q-fe1f465185 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RqK7jn"} | None |  |
| q-3bbe0b0c51 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1brw_To"} | None |  |
| q-842ce3a7bf | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R_lkD8"} | None |  |
| q-c58b09b1e1 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YogQzA"} | None |  |
| q-db92f319c5 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YcRSol"} | None |  |
| q-e4739c674a | triage T1552 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1Yph4sr"} | None |  |
| q-265478a94a | triage T1552 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8IeO"} | None |  |
| q-c66788d266 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R8i4gn"} | None |  |
| q-b1e5d973d9 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NY3HhV"} | None |  |
| q-722fe3afdc | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MtSxRG"} | None |  |
| q-0338fdeb7d | triage T1555 step 1 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YldM_p"} | None |  |
| q-72faa867fa | triage T1555 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-c3e2622fbb | triage T1555 step 1 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1Nc7emR"} | None |  |
| q-7a6e976246 | triage T1555 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*lsass*\" OR TO_LOWER(process.command_line) LIKE \"*sdelete*\" OR TO_LOWER(process.command_line) LIKE \"*dump*\" OR TO_LOWE… | 7 |  |
| q-d617578bea | triage T1555 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*sdelete*\" OR TO_LOWER(file.path) LIKE \"*lsass*\" OR TO_LOWER(file.path) LIKE \"*.dmp\" OR TO_LOWER(file.path) LIKE \"*credential*\… | 13 |  |
| q-73120b65a8 | triage T1555 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND TO_LOWER(process.executable) LIKE \"*powershell*\" \| KEEP @timestamp, host.name, user.name, process.executable, process.command_line, _id, _index"} | 12 |  |
| q-61b5d303a4 | triage T1555 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND win.GrantedAccess IN (\"0x1fffff\",\"0x1f3fff\",\"0x101001\",\"0x1000000\") \| KEEP @timestamp, host.name, user.name, win.SourceImage, win.TargetImage, win.Grant… | 500 |  |
| q-14f0d06045 | triage T1555 step 4 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YjaXaO"} | None |  |
| q-b66a9ac021 | triage T1555 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*login data*\" OR TO_LOWER(file.path) LIKE \"*logins.json*\" OR TO_LOWER(file.path) LIKE \"*cookies*\" OR TO_LOWER(file.path) LIKE \"… | 1 | F38 |
| q-dcf5b7ebc3 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YldM_p"} | None |  |
| q-a7deee38c6 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YldM_p"} | None |  |
| q-4518803404 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YldM_p"} | None |  |
| q-7c842e2bcf | triage T1555 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YjaXaO"} | None |  |
| q-8806fcb13b | triage T1555 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YjaXaO"} | None |  |
| q-48b0a6f084 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YjaXaO"} | None |  |
| q-1585e4a789 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YEBswS"} | None |  |
| q-3a6fda5bfd | triage T1555 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YGClc_"} | None |  |
| q-05808f740e | triage T1555 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx1Y"} | None |  |
| q-15e7aebbf0 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MsOhX7"} | None |  |
| q-6f4db6aa95 | triage T1556 step 1 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 326 |  |
| q-55078b5cde | triage T1556 step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND win.TargetImage LIKE \"*lsass*\" AND process.executable LIKE \"*powershell*\" \| KEEP @timestamp, host.name, process.executable, process.command_line, win.Source… | 2 |  |
| q-dcd537ccde | triage T1556 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND win.TargetImage LIKE \"*lsass*\" AND win.GrantedAccess IN (\"0x1fffff\",\"0x1f3fff\",\"0x101001\",\"0x1000000\",\"0x3000\",\"0x1400\") \| KEEP @timestamp, host.n… | 33 | F39, F42 |
| q-cc6121c94d | triage T1556 step 2 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4648\" \| KEEP @timestamp, host.name, user.name, process.executable, win.TargetServerName, win.TargetUserName, win.IpAddress, _id, _index"} | 15 | F40 |
| q-a77a2bac95 | triage T1556 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrM7IJ"} | None |  |
| q-19a7207079 | triage T1556 step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(powershell.script_block_text) LIKE \"*lsass*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*credential*\" OR TO_LOWER(powershell.script_bloc… | 5 | F41 |
| q-eec4f1543a | triage T1556 step 4 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None | F41 |
| q-3e9ce006f0 | triage T1556 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"13\" AND (TO_LOWER(registry.path) LIKE \"*notification packages*\" OR TO_LOWER(registry.path) LIKE \"*networkprovider*\" OR TO_LOWER(registry.path) LIKE \"*lsa*\" OR TO_L… | 9 | F44 |
| q-3d601348a1 | triage T1556 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.executable) LIKE \"*wsmprovhost*\" OR TO_LOWER(process.executable) LIKE \"*psexesvc*\" OR TO_LOWER(process.command_line) LIKE \"*psexec*\" OR TO… | 9 | F39, F40 |
| q-a110df99a2 | triage T1556 step 5 | esql | {"query": "FROM logs-windows.other-default METADATA _id, _index \| WHERE event.code == \"7045\" OR event.code == \"7040\" \| KEEP @timestamp, host.name, win.ServiceName, win.ImagePath, win.ServiceType, win.StartType, _id, _index"} | 9 | F40 |
| q-f9f5496a1e | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrM7IJ"} | None |  |
| q-8ba227ef1f | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrM7IJ"} | None |  |
| q-85aa35c932 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrM7IJ"} | None |  |
| q-c4162cdf5c | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RsNKXB"} | None |  |
| q-c250616703 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RsNKXB"} | None |  |
| q-a3a2d3f5c7 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RkEAFq"} | None |  |
| q-948e58fc5b | triage T1556 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx2W"} | None |  |
| q-abf475e254 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx2W"} | None |  |
| q-ac288853e5 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YogQzA"} | None |  |
| q-a89949cbf1 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-f2db90a321 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-6360a19ce3 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-8fb2bd443e | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1WhJHLy"} | None |  |
| q-3cb4d7b621 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1WhJHLy"} | None |  |
| q-da0243e25b | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NAenUm"} | None |  |
| q-19601a3ddc | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1WgHZ_S"} | None |  |
| q-7ed54c0fa7 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1SFrjaS"} | None |  |
| q-49e69c5e81 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1SAnG1Y"} | None |  |
| q-30182ad0d4 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NY3HhB"} | None |  |
| q-d324769766 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R8i4gn"} | None |  |
| q-a84b857380 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MtSxRG"} | None |  |
| q-7b13209ab3 | triage T1557 step 1 | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx0z"} | None |  |
| q-48889ca741 | triage T1557 step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"3\" AND destination.port IN (445, 139, 138, 137) \| KEEP @timestamp, host.name, process.executable, destination.ip, destination.port, win.SourceIp, _id, _index \| LIMIT 5… | 50 |  |
| q-71f000a757 | triage T1557 step 2 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4697\" \| KEEP @timestamp, host.name, user.name, win.ServiceName, win.ServiceFileName, win.ServiceType, _id, _index \| LIMIT 30"} | 23 | F45 |
| q-a8d08ed2cc | triage T1557 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.executable) LIKE \"*psexec*\" OR TO_LOWER(process.command_line) LIKE \"*psexec*\" OR TO_LOWER(process.executable) LIKE \"*sdelete*\" OR TO_LOWER… | 10 | F45 |
| q-2f75859513 | triage T1557 step 3 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"conn\" AND zeek.resp_l2_addr == \"12:34:56:78:9a:bc\" \| KEEP @timestamp, source.ip, destination.ip, destination.port, zeek.service, zeek.orig_l2_addr, zeek.resp_l2_addr, _id, _i… | 30 | F47 |
| q-6c4d844581 | triage T1557 step 3 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"conn\" AND zeek.orig_l2_addr == \"fc:bd:67:e1:a9:c1\" \| KEEP @timestamp, source.ip, destination.ip, destination.port, zeek.service, zeek.orig_l2_addr, zeek.resp_l2_addr, _id, _i… | 30 | F47 |
| q-156319bbee | triage T1557 step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(powershell.script_block_text) LIKE \"*invoke-mimikatz*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*sekurlsa*\" OR TO_LOWER(powershell.scr… | 10 |  |
| q-f99115af28 | triage T1557 step 4 | esql | {"query": "FROM logs-windows.other-default METADATA _id, _index \| WHERE event.code == \"7045\" \| KEEP @timestamp, host.name, user.name, win.ServiceName, win.ImagePath, win.ServiceType, _id, _index \| LIMIT 20"} | 5 | F45 |
| q-d6cc861c6e | triage T1557 step 5 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4624\" AND win.LogonType IN (\"3\",\"8\") AND win.TargetUserName LIKE \"*$\" \| KEEP @timestamp, host.name, win.TargetUserName, win.LogonType, win.IpAddress, win.Workst… | 20 | F46 |
| q-5aadaead92 | triage T1557 step 5 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"dns\" AND (zeek.query LIKE \"*wpad*\" OR zeek.query LIKE \"*NASHUA*\" OR zeek.query LIKE \"*SCRANTON*\") \| KEEP @timestamp, source.ip, zeek.query, zeek.answers, zeek.rcode_name,… | 14 | F46, F48 |
| q-894843ba6e | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RkEAFq"} | None |  |
| q-3c6343e07f | triage T1557 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx2W"} | None |  |
| q-52f4501f1c | triage T1557 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YcRyrP"} | None |  |
| q-037a070ace | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO74f6"} | None |  |
| q-3762698338 | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO74f6"} | None |  |
| q-c07cec63e8 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1X-_nFZ"} | None |  |
| q-2dd6d644cd | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8Ica"} | None |  |
| q-9423ce0e2b | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1bi_UDc"} | None |  |
| q-335e8479f3 | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO74f6"} | None |  |
| q-23b7b2ea0b | triage T1558 step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND TO_LOWER(win.TargetImage) LIKE \"*lsass*\" AND win.GrantedAccess IN (\"0x1fffff\", \"0x101001\", \"0x1f3fff\", \"0x1000000\", \"0x3000\") \| KEEP @timestamp, hos… | 9 | F49 |
| q-7abd8e569a | triage T1558 step 1 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4769\" \| KEEP @timestamp, host.name, user.name, win.ServiceName, win.TicketEncryptionType, win.TicketOptions, source.ip, _id, _index"} | 28 | F49, F50, F51, F52 |
| q-d4d1c4e038 | triage T1558 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-9260ba3108 | triage T1558 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrM7IJ"} | None |  |
| q-b1e54025f4 | triage T1558 step 2 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4768\" OR event.code == \"4771\" OR event.code == \"4769\" \| STATS c = COUNT(*) BY event.code, win.TargetUserName, win.ServiceName \| SORT c DESC"} | 10 |  |
| q-1cf311d5a9 | triage T1558 step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(powershell.script_block_text) LIKE \"*lsass*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*minidump*\" OR TO_LOWER(powershell.script_block_… | 5 | F52 |
| q-f59ebf2eaf | triage T1558 step 3 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4768\" \| KEEP @timestamp, host.name, user.name, win.TargetUserName, win.PreAuthType, win.TicketEncryptionType, win.IpAddress, _id, _index"} | 14 | F49, F53 |
| q-426c20eed9 | triage T1558 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*lsass*\" OR TO_LOWER(process.command_line) LIKE \"*dump*\" OR TO_LOWER(process.command_line) LIKE \"*mimikatz*\" OR TO_LOW… | 1 |  |
| q-80b88731f4 | triage T1558 step 4 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4672\" \| STATS c = COUNT(*) BY win.TargetUserName, host.name \| SORT c DESC"} | 3 |  |
| q-8df9079998 | triage T1558 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND host.name == \"scranton.dmevals.local\" AND TO_LOWER(process.executable) LIKE \"*powershell*\" \| KEEP @timestamp, host.name, user.name, process.executable, proce… | 11 |  |
| q-49a9e8baeb | triage T1558 step 5 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-ff0197431b | triage T1558 step 6 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4624\" AND win.LogonType IN (\"10\",\"9\") \| KEEP @timestamp, host.name, user.name, win.TargetUserName, win.LogonType, win.IpAddress, _id, _index"} | 2 |  |
| q-7843c1e61b | triage T1558 step 6 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4769\" AND win.ServiceName == \"krbtgt\" \| KEEP @timestamp, host.name, user.name, win.ServiceName, win.TicketOptions, win.TicketEncryptionType, _id, _index"} | 3 | F50 |
| q-0f04a628f6 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YhYtYx"} | None |  |
| q-6409cec634 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YhYtYx"} | None |  |
| q-96c9e176db | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YQHgaq"} | None |  |
| q-1a79f814d9 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NY3HhM"} | None |  |
| q-628850db24 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NY3HhN"} | None |  |
| q-d3b9cac0f2 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YhYtYx"} | None |  |
| q-8f2e9f9dbd | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YaPjsB"} | None |  |
| q-5c8e2668e1 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YaPjsB"} | None |  |
| q-57a800f8e3 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YQHgat"} | None |  |
| q-889ffaedd4 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YQHgat"} | None |  |
| q-4945c14ab5 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YhYtYv"} | None |  |
| q-d1a487af58 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-934db63de5 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YQHgaq"} | None |  |
| q-a65834428f | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YOGdm9"} | None |  |
| q-8870d4c10c | triage T1606 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b22vQJ"} | None | F54 |
| q-a093654dd5 | triage T1606 step 1 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx1E"} | ERROR |  |
| q-182aba887f | triage T1606 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND (win.GrantedAccess:0x1fffff OR win.GrantedAccess:0x101001 OR win.GrantedAccess:0x1f3fff OR win.GrantedAccess:0x1000000 OR win.GrantedAccess:0x3000)", "time_from": null, "time… | 9 |  |
| q-2bda489568 | triage T1606 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*cookie* OR file.path:*Cookies*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "process.executable", "process.command_line", "file.path", "user.name"], "size": 1… | 1 | F55 |
| q-5252b3ba84 | triage T1606 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-28c7c1c0ed | triage T1606 step 3 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*lsass* OR powershell.script_block_text:*MiniDump* OR powershell.script_block_text:*Dump* OR powershell.script_block_text:*Credential*)", "time_from": null, "time_to"… | 3 |  |
| q-6d38d76894 | triage T1606 step 4 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-c3e2585e51 | triage T1606 step 4 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND process.pid:2976", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "process.executable", "process.command_line", "process.parent.executable", "process.parent.command_line", "use… | 1 |  |
| q-90ad5d86c9 | triage T1606 step 5 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4624\" OR event.code == \"4648\" \| STATS c = COUNT(*) BY win.LogonProcessName, win.LogonType, win.TargetUserName \| SORT c DESC \| LIMIT 30"} | 25 |  |
| q-2d4cab624f | triage T1606 step 5 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"kerberos\" \| KEEP @timestamp, source.ip, destination.ip, zeek.client, zeek.service, zeek.success, zeek.request_type, zeek.error_msg \| LIMIT 40"} | 35 |  |
| q-904aa9e14f | triage T1606 step 6 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*cookie*\" OR TO_LOWER(process.command_line) LIKE \"*saml*\" OR TO_LOWER(process.command_line) LIKE \"*adfs*\" OR TO_LOWER(… | 5 |  |
| q-92ca1afc88 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1WdFNhN"} | None |  |
| q-61ec1b6a4f | triage T1606 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b22vQJ"} | None |  |
| q-ebf0d6e688 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx1E"} | None |  |
| q-5b37558825 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1WdFNhN"} | None |  |
| q-ccee319f37 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MsOhX7"} | None |  |
| q-658eb54cb2 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b22vQJ"} | None |  |
| q-cdef2263d0 | triage T1606 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8Idl"} | None |  |
| q-082e5b7514 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx1E"} | ERROR |  |
| q-09580842fe | triage T1606 step 8 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND TO_LOWER(process.command_line) LIKE \"*davsetcookie*\" \| KEEP @timestamp, host.name, _id, _index, process.command_line \| LIMIT 5"} | 5 | F54, F55 |
| q-d1ab154e76 | triage T1606 step 8 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4624\" AND win.LogonProcessName == \"Kerberos\" \| KEEP @timestamp, host.name, _id, _index, win.LogonProcessName, win.TargetUserName \| LIMIT 3"} | 3 | F56 |
| q-91c0fc51f9 | triage T1621 step 1 | aggregate | {"dataset": "windows.other", "field": "event.code", "query": "*", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 216 |  |
| q-5a98e0e18e | triage T1621 step 1 | aggregate | {"dataset": "windows.other", "field": "win.Operation", "query": "event.code:5858 OR event.code:5857 OR event.code:5860", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 88 |  |
| q-955e813e8d | triage T1621 step 2 | search | {"dataset": "windows.other", "query": "event.code:5857", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "message", "win.Operation", "user.name"], "size": 5, "sort": "asc"} | 36 | F57 |
| q-890f6fd16d | triage T1621 step 2 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4625\" OR event.code == \"4776\" OR event.code == \"4648\" \| KEEP @timestamp, host.name, event.code, win.TargetUserName, win.LogonType, win.IpAddress, _id, _index \| L… | 16 | F58 |
| q-fef846dac0 | triage T1621 step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(powershell.script_block_text) LIKE \"*mfa*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*authenticator*\" OR TO_LOWER(powershell.script_blo… | 0 |  |
| q-2daf02d43b | triage T1621 step 3 | count | {"dataset": "windows.security", "query": "event.code:4625", "time_from": null, "time_to": null} | 0 |  |
| q-f4c8e14732 | triage T1621 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*mfa*\" OR TO_LOWER(process.command_line) LIKE \"*authenticator*\" OR TO_LOWER(process.command_line) LIKE \"*2fa*\" OR TO_L… | 3 | F59 |
| q-dfb8d9a3ad | triage T1621 step 4 | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx1E"} | None | F57 |
| q-ff4002eb5a | triage T1621 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx1E"} | None |  |
| q-62b22773fc | triage T1621 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx21"} | None |  |
| q-4d420dc403 | triage T1621 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx07"} | None |  |
| q-b837528c09 | triage T1621 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YQHwYC"} | None |  |
| q-da1a92484d | triage T1621 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YQHQbW"} | None |  |
| q-4d4c173726 | triage T1621 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MtWeH6"} | None |  |
| q-505fa12541 | triage T1621 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MtWNHL"} | None |  |
| q-bf52516863 | triage T1649 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None | F60 |
| q-18dee1290f | triage T1649 step 1 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == 4104 AND (powershell.script_block_text LIKE \"*Cert*\" OR powershell.script_block_text LIKE \"*PrivateKey*\" OR powershell.script_block_text LIKE \"*Export*\") \| KEEP … | ERROR |  |
| q-1c26b9d3b7 | triage T1649 step 2 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (powershell.script_block_text LIKE \"*Cert*\" OR powershell.script_block_text LIKE \"*PrivateKey*\" OR powershell.script_block_text LIKE \"*Export*\" OR po… | 20 |  |
| q-ad1f505113 | triage T1649 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (file.path LIKE \"*.pfx*\" OR file.path LIKE \"*Downloads*\") \| KEEP @timestamp, host.name, user.name, process.executable, file.path, _id, _index \| LIMIT 30"} | 30 | F60 |
| q-4a386c435c | triage T1649 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (process.command_line LIKE \"*readme.ps1*\" OR process.command_line LIKE \"*Get-PrivateKeys*\" OR process.command_line LIKE \"*Export-Pfx*\") \| KEEP @timestamp, … | 0 |  |
| q-142357c0af | triage T1649 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"13\" AND registry.path LIKE \"*SystemCertificates*\" \| KEEP @timestamp, host.name, user.name, process.executable, registry.path, registry.data.strings, _id, _index \| LI… | 19 | F60, F61 |
| q-eeab24f1dd | triage T1649 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND process.executable LIKE \"*powershell*\" AND (process.command_line LIKE \"*readme*\" OR process.command_line LIKE \"*Sysinternals*\" OR process.command_line LIKE … | 1 |  |
| q-4da882e94f | triage T1649 step 4 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4768\" \| KEEP @timestamp, host.name, user.name, win.TargetUserName, win.IpAddress, win.Status, _id, _index \| LIMIT 20"} | 14 | F61 |
| q-60d111b604 | triage T1649 step 5 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1WdFNhN"} | None | F60 |
| q-d7da1492be | triage T1649 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None |  |
| q-60883480b6 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None |  |
| q-d4d18881ce | triage T1649 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None |  |
| q-da831043c1 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None |  |
| q-fce4ab37c1 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R_lUAH"} | None |  |
| q-9bb417732e | triage T1649 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R_lED5"} | None |  |
| q-0948edf85d | triage T1649 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1WdFNhN"} | None |  |
| q-38bc80632c | triage T1649 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YQHgaq"} | None |  |
| q-dd2580b8ad | triage T1649 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YOGdm9"} | None |  |
| q-caa8db2f6f | triage T1649 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RhBptB"} | None |  |
| q-669f40d532 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NDgB6i"} | None |  |
| q-d511c25b0f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-3380bd72b4 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k13y"} | None |  |
| q-6c11fb0c6f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrM7IJ"} | None |  |
| q-8cf766da67 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YldM_p"} | None |  |
| q-0e86157f06 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YjaXaO"} | None |  |
| q-337f37867a | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None |  |
| q-b3d19adc11 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-fe7b235667 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21_Tx"} | None |  |
| q-97510a6c4c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NY3HhA"} | None |  |
| q-840504f3ea | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NY3HhA"} | None |  |
| q-adf08afbca | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RpKsLE"} | None |  |
| q-c19d2a0fef | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NAd3XG"} | None |  |
| q-a0ab9ecfcf | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MtUmZF"} | None |  |
| q-c01a6fa82d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RjDyQJ"} | None |  |
| q-ea9f3b6feb | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NY3HhL"} | None |  |
| q-d3a30167ac | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NW1Kgv"} | None |  |
| q-519804e46a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1WpSJN6"} | None |  |
| q-0ab487177a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NUxiiK"} | None |  |
| q-09f3dc340c | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YYOcv1"} | None |  |
| q-78d5b214dd | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1SDpYge"} | None |  |
| q-1fa32dbc2a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrMbJC"} | None |  |
| q-06ae3ad222 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RqK7jn"} | None |  |
| q-9a54969f23 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RpKsKx"} | None |  |
| q-8a00420bc6 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RjDSP-"} | None |  |
| q-8044ea7a9d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-e7869ad220 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-10f2dcbbb2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-ab623a8987 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k13y"} | None |  |
| q-7879c3cbdd | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1bzyNfQ"} | None |  |
| q-ded4c738b5 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1bzyNfQ"} | None |  |
| q-7ba8ab7d4b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MtUml9"} | None |  |
| q-353f983fc4 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MtUml9"} | None |  |
| q-8e65467ae1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1WhJHLy"} | None |  |
| q-20fd684fbe | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NAenUm"} | None |  |
| q-47a85bade3 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YWMnGq"} | None |  |
| q-31b56d5498 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1SIv93X"} | None |  |
| q-93298aa21f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R4eBiX"} | None |  |
| q-c7580b0d29 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R4eBiX"} | None |  |
| q-3c80751176 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx0y"} | None |  |
| q-684e196e43 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx04"} | None |  |
| q-dc6c5fe20d | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None |  |
| q-f18c246552 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx1g"} | None |  |
| q-b16e4df357 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-2389613a84 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-a40ea73190 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-30296e0db0 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None |  |
| q-7191f9aa1e | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-9b21cc7fec | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YogQzA"} | None |  |
| q-5bb4fa6019 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YogQzA"} | None |  |
| q-812f7239ef | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx2T"} | None |  |
| q-4f9b245975 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YcSCoM"} | None |  |
| q-b2e89a0300 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-c020512760 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-3939b9a896 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-3ed660c907 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None |  |
| q-0eb94a12cf | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21_Tx"} | None |  |
| q-3e96059ee5 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1WhJHLy"} | None |  |
| q-6e706f4437 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YQHQbW"} | None |  |
| q-f7c836cf22 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8Ieh"} | None |  |
| q-150c79ad8e | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8Ieh"} | None |  |
| q-b7a182735e | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8Ieh"} | None |  |
| q-47b475c0b5 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8Iej"} | None |  |
| q-fe49d929ea | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8Iej"} | None |  |
| q-85043a58b2 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8Ieh"} | None |  |
| q-1cdd91815e | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8Ieh"} | None |  |
| q-bd9090694f | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8Ieh"} | None |  |
| q-d69ce9d623 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MsQYML"} | None |  |
| q-c8d9e7d565 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MsQYML"} | None |  |
| q-e76e434157 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YsmIPl"} | None |  |
| q-949f9fb151 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YcRSol"} | None |  |
| q-0f9b35d123 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YcRSol"} | None |  |
| q-4792a5073b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1WdFNhN"} | None |  |
| q-bee11e2643 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1WdFNhN"} | None |  |
| q-c147d8f201 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1WdFNhN"} | None |  |
| q-a939e493ae | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-06c53c3e89 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-7f259c0887 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-e67c62b8e1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k13y"} | None |  |
| q-b74be89072 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrM7IJ"} | None |  |
| q-ed19cbe5f8 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1bsxQxS"} | None |  |
| q-80cea46402 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-9721f636bb | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YhYtYv"} | None |  |
| q-89980914bf | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YhYtYv"} | None |  |
| q-51ee1d4da0 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YOGdm5"} | None |  |
| q-a13e2c8a7d | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO74el"} | None |  |
| q-1681c2e048 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8IdY"} | None |  |
| q-c07fd3f453 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YeU-Dp"} | None |  |
| q-e24c436446 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MsOhX7"} | None |  |
| q-a3c8872011 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MsPCud"} | None |  |
| q-1430df138c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1Muar8B"} | None |  |
| q-ece3601b32 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RkEAFq"} | None |  |
| q-6b9d60a0af | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1SEqWk4"} | None |  |
| q-35641c63f3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R_lkD8"} | None |  |
| q-0d334b5f9b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R_lkD8"} | None |  |
| q-604c143a2b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R_lkD_"} | None |  |
| q-14468d9832 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R_lkD_"} | None |  |
| q-a0fc679209 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1SEqWk4"} | None |  |
| q-66998674fe | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RqK7jn"} | None |  |
| q-7516fd4763 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1brw_To"} | None |  |
| q-d468da0903 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R_lkD8"} | None |  |
| q-32b176af45 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YogQzA"} | None |  |
| q-2fef3dba73 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YcRSol"} | None |  |
| q-1f66eeb75c | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1Yph4sr"} | None |  |
| q-dc56e4d2ad | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8IeO"} | None |  |
| q-bdf66f7ca1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R8i4gn"} | None |  |
| q-c4ec1883c7 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NY3HhV"} | None |  |
| q-a5fb7047cc | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MtSxRG"} | None |  |
| q-84dfb90f83 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YldM_p"} | None |  |
| q-38a70b3409 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YldM_p"} | None |  |
| q-d8852849e5 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YldM_p"} | None |  |
| q-24e2d71d61 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YjaXaO"} | None |  |
| q-15205662f8 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YjaXaO"} | None |  |
| q-dc285de3ed | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YjaXaO"} | None |  |
| q-bbf86a35f4 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YEBswS"} | None |  |
| q-67814d54ee | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YGClc_"} | None |  |
| q-18ec8f31aa | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx1Y"} | None |  |
| q-76601ec7d9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MsOhX7"} | None |  |
| q-0cb2735786 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrM7IJ"} | None |  |
| q-7d7d693dcf | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrM7IJ"} | None |  |
| q-90dfce889a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrM7IJ"} | None |  |
| q-f88c205e03 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RsNKXB"} | None |  |
| q-3ef093ce9d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RsNKXB"} | None |  |
| q-c8c1e51254 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RkEAFq"} | None |  |
| q-641b67a576 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx2W"} | None |  |
| q-6402413f99 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx2W"} | None |  |
| q-34a3a55c6c | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YogQzA"} | None |  |
| q-bef3e912f5 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-75026761d0 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-ffd4034c00 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-f4f3ff8231 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1WhJHLy"} | None |  |
| q-d961d750c3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1WhJHLy"} | None |  |
| q-a8a52f0266 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NAenUm"} | None |  |
| q-8ef87d2a1b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1WgHZ_S"} | None |  |
| q-a356546eca | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1SFrjaS"} | None |  |
| q-2443b89387 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1SAnG1Y"} | None |  |
| q-50d9ac180b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NY3HhB"} | None |  |
| q-eb705686f6 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R8i4gn"} | None |  |
| q-6041091009 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MtSxRG"} | None |  |
| q-d00b996bdb | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RkEAFq"} | None |  |
| q-fd989d77b9 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx2W"} | None |  |
| q-b90b52bf94 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YcRyrP"} | None |  |
| q-fa70219f43 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO74f6"} | None |  |
| q-d4559e5437 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO74f6"} | None |  |
| q-12888146d7 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1X-_nFZ"} | None |  |
| q-fe74ca1bd9 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8Ica"} | None |  |
| q-9e9aa5307c | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1bi_UDc"} | None |  |
| q-1e14ae0af8 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO74f6"} | None |  |
| q-c67ba6c307 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YhYtYx"} | None |  |
| q-adadd3e96d | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YhYtYx"} | None |  |
| q-9f65a5c876 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YQHgaq"} | None |  |
| q-5201798daf | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NY3HhM"} | None |  |
| q-21df6a8f32 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NY3HhN"} | None |  |
| q-4c9b0f60e1 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YhYtYx"} | None |  |
| q-c834159174 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YaPjsB"} | None |  |
| q-5d62710889 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YaPjsB"} | None |  |
| q-4159bd1cec | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YQHgat"} | None |  |
| q-860dcb075e | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YQHgat"} | None |  |
| q-be2c628042 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YhYtYv"} | None |  |
| q-e881a4dc96 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-291a046feb | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YQHgaq"} | None |  |
| q-94ce4866c3 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YOGdm9"} | None |  |
| q-b7b1bf7662 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrMLE_"} | None |  |
| q-8bf0d99260 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b22vQJ"} | None |  |
| q-36765752f5 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx1E"} | None |  |
| q-5638e0abf1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrMLE_"} | None |  |
| q-ffa43cfc03 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MsOhX7"} | None |  |
| q-9975e9d017 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b22vQJ"} | None |  |
| q-5a784da882 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1X-_nFC"} | None |  |
| q-c473241608 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8Idl"} | None |  |
| q-b859460b1e | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx1E"} | None |  |
| q-bd0453d443 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx21"} | None |  |
| q-6a17c85a09 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx07"} | None |  |
| q-a3f8263086 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YQHwYC"} | None |  |
| q-a8e03500ba | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YQHQbW"} | None |  |
| q-088b1c38c8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MtWeH6"} | None |  |
| q-396f12e468 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MtWNHL"} | None |  |
| q-97f2eb5e20 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None |  |
| q-1517a27af5 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None |  |
| q-a89792893a | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None |  |
| q-2fb425ce13 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None |  |
| q-aa9db325b5 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R_lUAH"} | None |  |
| q-dc3be04dd4 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R_lED5"} | None |  |
| q-70f1f9fa23 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1WdFNhN"} | None |  |
| q-f95160cc4f | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YQHgaq"} | None |  |
| q-52661e95f6 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YOGdm9"} | None |  |
| q-9406a34d5c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RhBptB"} | None |  |
| q-95e193d453 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NDgB6i"} | None |  |
| q-281ca2e7d3 | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND host.name:\"nashua.dmevals.local\"", "time_from": "2020-05-02T02:54:23.885000+00:00", "time_to": "2020-05-02T03:37:38+00:00", "size": 100, "sub_field": "process.parent.exec… | 61 |  |
| q-3354971561 | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11 AND host.name:\"nashua.dmevals.local\"", "time_from": "2020-05-02T02:54:23.885000+00:00", "time_to": "2020-05-02T03:37:38+00:00", "size": 100, "sub_field": "process.executable"} | 249 |  |
| q-5021ac676e | pivot seed | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND host.name:\"nashua.dmevals.local\"", "time_from": "2020-05-02T02:54:23.885000+00:00", "time_to": "2020-05-02T03:37:38+00:00", "size": 100, "sub_field": "process.parent… | 63 |  |
| q-ec49153c56 | pivot seed | aggregate | {"dataset": "windows.powershell", "field": "event.code", "query": "host.name:\"nashua.dmevals.local\"", "time_from": "2020-05-02T02:54:23.885000+00:00", "time_to": "2020-05-02T03:37:38+00:00", "size": 100, "sub_field": null} | 192 |  |
| q-e755a20b51 | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND host.name:\"scranton.dmevals.local\"", "time_from": "2020-05-02T02:43:44.325000+00:00", "time_to": "2020-05-02T03:36:29+00:00", "size": 100, "sub_field": "process.parent.ex… | 359 |  |
| q-2bb44ae2d6 | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11 AND host.name:\"scranton.dmevals.local\"", "time_from": "2020-05-02T02:43:44.325000+00:00", "time_to": "2020-05-02T03:36:29+00:00", "size": 100, "sub_field": "process.executable"} | 1276 |  |
| q-a4322bc4dc | pivot seed | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND host.name:\"scranton.dmevals.local\"", "time_from": "2020-05-02T02:43:44.325000+00:00", "time_to": "2020-05-02T03:36:29+00:00", "size": 100, "sub_field": "process.pare… | 370 |  |
| q-489657f924 | pivot seed | aggregate | {"dataset": "windows.powershell", "field": "event.code", "query": "host.name:\"scranton.dmevals.local\"", "time_from": "2020-05-02T02:43:44.325000+00:00", "time_to": "2020-05-02T03:36:29+00:00", "size": 100, "sub_field": null} | 8602 |  |
| q-48de6da987 | pivot step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" \| WHERE TO_LOWER(process.executable) LIKE \"*\\\\temp\\\\*\" OR TO_LOWER(process.executable) LIKE \"*\\\\programdata\\\\*\" OR TO_LOWER(process.executable) LIKE \"*\… | ERROR |  |
| q-b523d4884c | pivot step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" \| WHERE TO_LOWER(file.path) LIKE \"*passw*\" OR TO_LOWER(file.path) LIKE \"*.pfx\" OR TO_LOWER(file.path) LIKE \"*.key\" OR TO_LOWER(file.path) LIKE \"*cred*\" OR T… | ERROR |  |
| q-e81f217cc1 | pivot step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" \| WHERE TO_LOWER(process.executable) LIKE \"*\\\\\\\\temp\\\\\\\\*\" OR TO_LOWER(process.executable) LIKE \"*\\\\\\\\programdata\\\\\\\\*\" OR TO_LOWER(process.execu… | 10 |  |
| q-342cd71581 | pivot step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" \| WHERE TO_LOWER(file.path) LIKE \"*passw*\" OR TO_LOWER(file.path) LIKE \"*.pfx\" OR TO_LOWER(file.path) LIKE \"*.key\" OR TO_LOWER(file.path) LIKE \"*cred*\" OR T… | 7 |  |
| q-9783c6dc84 | pivot step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" \| WHERE TO_LOWER(message) LIKE \"*pspasswd*\" OR TO_LOWER(message) LIKE \"*passwordsdb*\" OR TO_LOWER(message) LIKE \"*pfx*\" OR TO_LOWER(message) LIKE \"*pri… | 166 |  |
| q-338f8e19cb | pivot step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" \| WHERE TO_LOWER(process.command_line) LIKE \"*pspasswd*\" OR TO_LOWER(process.command_line) LIKE \"*passwordsdb*\" OR TO_LOWER(process.command_line) LIKE \"*pfx*\" … | 2 | F65 |
| q-338c08e677 | pivot step 4 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1SIw95-"} | None | F63 |
| q-78e5a6190e | pivot step 4 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R_lkD8"} | None | F63 |
| q-72db757240 | pivot step 4 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R_lUAH"} | None | F62 |
| q-5077261150 | pivot step 4 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NY3Hhd"} | None |  |
| q-c17e49a95e | pivot step 5 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" \| WHERE TO_LOWER(message) LIKE \"*pspasswd*\" OR TO_LOWER(message) LIKE \"*passwordsdb*\" OR TO_LOWER(message) LIKE \"*export-pfxcertificate*\" OR TO_LOWER(me… | 6 | F65 |
| q-0744caf54f | pivot step 5 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4688\" \| WHERE TO_LOWER(process.command_line) LIKE \"*pspasswd*\" OR TO_LOWER(process.command_line) LIKE \"*passwordsdb*\" OR TO_LOWER(process.command_line) LIKE \"*pf… | 8 |  |
| q-1b35a1ed24 | pivot step 6 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None | F62 |
| q-d4a1a130a1 | pivot step 6 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" \| WHERE TO_LOWER(message) LIKE \"*get-keystrokes*\" OR TO_LOWER(message) LIKE \"*get-privatekeys*\" OR TO_LOWER(message) LIKE \"*invoke-screencapture*\" OR TO… | 9 | F66, F67 |
| q-ad7bba0d06 | pivot step 7 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None | F64 |
| q-e6b745e35a | pivot step 7 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" \| WHERE TO_LOWER(process.command_line) LIKE \"*pspasswd*\" OR TO_LOWER(process.executable) LIKE \"*pspasswd*\" OR TO_LOWER(process.command_line) LIKE \"*accesschk*\"… | 1 | F63 |
| q-440ecceae8 | pivot step 7 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4624\" OR event.code == \"4648\" \| WHERE TO_LOWER(winlog.event_data.TargetUserName) LIKE \"*pbeesly*\" OR TO_LOWER(winlog.event_data.SubjectUserName) LIKE \"*pbeesly*\… | ERROR |  |
| q-a5c04a9ba9 | pivot step 8 | get_fields | {"dataset": "windows.security", "prefix": "winlog.event_data"} | None |  |
| q-c772316fd3 | pivot step 8 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4648\" OR event.code == \"4624\" \| KEEP @timestamp, host.name, user.name, winlog.event_data.TargetUserName, winlog.event_data.LogonType, winlog.event_data.IpAddress, w… | ERROR |  |
| q-92c21fb4b0 | pivot step 9 | get_fields | {"dataset": "windows.security", "prefix": ""} | None |  |
| q-5d7565f440 | pivot step 10 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4648\" \| KEEP @timestamp, host.name, user.name, win.TargetUserName, win.ProcessName, win.IpAddress, _id, _index \| SORT @timestamp ASC \| LIMIT 30"} | 15 | F68 |
| q-7341ce6c6b | pivot step 10 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" \| WHERE host.name LIKE \"*newyork*\" OR host.name LIKE \"*utica*\" \| WHERE TO_LOWER(file.path) LIKE \"*passw*\" OR TO_LOWER(file.path) LIKE \"*.pfx\" OR TO_LOWER(f… | 0 |  |
| q-e0b5ed68e1 | pivot verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None |  |
| q-0cb4347077 | pivot verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None |  |
| q-aa98c5006c | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R_lUAH"} | None |  |
| q-ed9a84208a | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1SIw95-"} | None |  |
| q-e3e6356091 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R_lkD8"} | None |  |
| q-0ca029e5c4 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R_lkD_"} | None |  |
| q-8be2992b19 | pivot verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-f9d7c1a234 | pivot verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-f41b793eba | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RhBpvd"} | None |  |
| q-9aea770ed2 | pivot verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1bsxhdc"} | None |  |
| q-cf5c2f30d8 | pivot verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21_Tx"} | None |  |
| q-3e9ad4c37f | pivot verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b22PQN"} | None |  |
| q-b2c1080a13 | pivot verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b22PTB"} | None |  |
| q-3699e648c9 | pivot verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YogQzA"} | None |  |
| q-d6e771a392 | pivot verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YcSP2J"} | None |  |
| q-4970165089 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-ec90aa13a9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k13y"} | None |  |
| q-2701d03fa0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrM7IJ"} | None |  |
| q-2d6ae37953 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YldM_p"} | None |  |
| q-6af1746f1c | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YjaXaO"} | None |  |
| q-7fd91916ea | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None |  |
| q-1f171c131e | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-efa718aa4c | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21_Tx"} | None |  |
| q-952687b552 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NY3HhA"} | None |  |
| q-7df1118b0a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NY3HhA"} | None |  |
| q-fb634c5ed7 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RpKsLE"} | None |  |
| q-8e0b7dcb49 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NAd3XG"} | None |  |
| q-b9e23b40e1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MtUmZF"} | None |  |
| q-1ba35b25c7 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RjDyQJ"} | None |  |
| q-db5e3655e9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NY3HhL"} | None |  |
| q-897b5e020b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NW1Kgv"} | None |  |
| q-75aa83ef6e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1WpSJN6"} | None |  |
| q-11642b6d35 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NUxiiK"} | None |  |
| q-028c125563 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YYOcv1"} | None |  |
| q-03865a9215 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1SDpYge"} | None |  |
| q-354d3738d5 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrMbJC"} | None |  |
| q-684f01ec4f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RqK7jn"} | None |  |
| q-08f2c1e595 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RpKsKx"} | None |  |
| q-96a87bbfdd | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RjDSP-"} | None |  |
| q-7667f00ea3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-9a77615db8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-a9080b1bcc | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-d5ec6c7025 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k13y"} | None |  |
| q-122b919960 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1bzyNfQ"} | None |  |
| q-e256171e33 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1bzyNfQ"} | None |  |
| q-145ca5c8a7 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MtUml9"} | None |  |
| q-362772cfc7 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MtUml9"} | None |  |
| q-e7685d8e0d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1WhJHLy"} | None |  |
| q-4360521280 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NAenUm"} | None |  |
| q-2f42ad0faf | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YWMnGq"} | None |  |
| q-7c13699cee | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1SIv93X"} | None |  |
| q-6d29d5fb5e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R4eBiX"} | None |  |
| q-41e59d9abc | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R4eBiX"} | None |  |
| q-d639993611 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx0y"} | None |  |
| q-fcff29591e | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx04"} | None |  |
| q-a70887fa2f | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None |  |
| q-b086666676 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx1g"} | None |  |
| q-815749c26a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-2dfdde78da | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-b7b25cff52 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-8ee06d0e5b | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None |  |
| q-e03a75c61f | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-719918aef2 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YogQzA"} | None |  |
| q-4366d39586 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YogQzA"} | None |  |
| q-340259385e | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx2T"} | None |  |
| q-3c415b65a6 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YcSCoM"} | None |  |
| q-c462495b9a | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-40ed3e5fc8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-28fffce719 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-072094501a | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None |  |
| q-e59846a203 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21_Tx"} | None |  |
| q-b39c9a60a7 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1WhJHLy"} | None |  |
| q-50ea04b9dc | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YQHQbW"} | None |  |
| q-39a30557a8 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8Ieh"} | None |  |
| q-18ac17978b | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8Ieh"} | None |  |
| q-eaf260d8f5 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8Ieh"} | None |  |
| q-57c7f9ff50 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8Iej"} | None |  |
| q-717bb0b39e | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8Iej"} | None |  |
| q-95a566b43c | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8Ieh"} | None |  |
| q-886227bb52 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8Ieh"} | None |  |
| q-63cbfd07ec | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8Ieh"} | None |  |
| q-5e20026513 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MsQYML"} | None |  |
| q-cadbf820ab | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MsQYML"} | None |  |
| q-38de9e19d5 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YsmIPl"} | None |  |
| q-b07fa73219 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YcRSol"} | None |  |
| q-e5adb649ba | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YcRSol"} | None |  |
| q-f12dbcf7c6 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1WdFNhN"} | None |  |
| q-12b042b4c0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1WdFNhN"} | None |  |
| q-ee99a157e4 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1WdFNhN"} | None |  |
| q-53b2c83edf | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-4e26305b60 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-9f3120ee83 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-ecf1bf6b0e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k13y"} | None |  |
| q-34a6506d62 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrM7IJ"} | None |  |
| q-aa2118d517 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1bsxQxS"} | None |  |
| q-fa452aaf42 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-eed68b53ff | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YhYtYv"} | None |  |
| q-30a880f2d1 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YhYtYv"} | None |  |
| q-0efe963616 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YOGdm5"} | None |  |
| q-9b62410978 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO74el"} | None |  |
| q-5283b8da89 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8IdY"} | None |  |
| q-26c695333d | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YeU-Dp"} | None |  |
| q-6dd10c979d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MsOhX7"} | None |  |
| q-719978abc1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MsPCud"} | None |  |
| q-0f96c16190 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1Muar8B"} | None |  |
| q-423f8afedd | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RkEAFq"} | None |  |
| q-5a16f57824 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1SEqWk4"} | None |  |
| q-3262879f6c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R_lkD8"} | None |  |
| q-79d071c406 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R_lkD8"} | None |  |
| q-cc6e6ded1d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R_lkD_"} | None |  |
| q-14de4fbb8b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R_lkD_"} | None |  |
| q-7ffcf435b3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1SEqWk4"} | None |  |
| q-b4de5c5910 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RqK7jn"} | None |  |
| q-b72d0a91ff | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1brw_To"} | None |  |
| q-1d83adb2ad | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R_lkD8"} | None |  |
| q-db1c958720 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YogQzA"} | None |  |
| q-8508b48c62 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YcRSol"} | None |  |
| q-f8f8e248c4 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1Yph4sr"} | None |  |
| q-b0068e4555 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8IeO"} | None |  |
| q-d20f3e01d0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R8i4gn"} | None |  |
| q-36c3c5d1a8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NY3HhV"} | None |  |
| q-022ef3a7a0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MtSxRG"} | None |  |
| q-5829825edd | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YldM_p"} | None |  |
| q-9830e461d7 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YldM_p"} | None |  |
| q-cb5ef6fd73 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YldM_p"} | None |  |
| q-314d0184b8 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YjaXaO"} | None |  |
| q-0ec174d3e4 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YjaXaO"} | None |  |
| q-67721dc603 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YjaXaO"} | None |  |
| q-df57dcb050 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YEBswS"} | None |  |
| q-25f2f97cb6 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YGClc_"} | None |  |
| q-0d1c560248 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx1Y"} | None |  |
| q-24ee454004 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MsOhX7"} | None |  |
| q-c31a45179a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrM7IJ"} | None |  |
| q-5b5117a348 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrM7IJ"} | None |  |
| q-3debd2d9ef | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrM7IJ"} | None |  |
| q-705147f71d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RsNKXB"} | None |  |
| q-2968745870 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RsNKXB"} | None |  |
| q-52b23217e6 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RkEAFq"} | None |  |
| q-caf1297f34 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx2W"} | None |  |
| q-b1892947b4 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx2W"} | None |  |
| q-e407a05b40 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YogQzA"} | None |  |
| q-bb469ccaa0 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-3517d1a0dc | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-a3b6652107 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-60dc30af12 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1WhJHLy"} | None |  |
| q-9b81df0885 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1WhJHLy"} | None |  |
| q-fcaaf9fa2b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NAenUm"} | None |  |
| q-cf90443635 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1WgHZ_S"} | None |  |
| q-19aa4e29ab | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1SFrjaS"} | None |  |
| q-6fc3aacac8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1SAnG1Y"} | None |  |
| q-dcafb652d7 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NY3HhB"} | None |  |
| q-e8b811e9bf | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R8i4gn"} | None |  |
| q-9101937448 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MtSxRG"} | None |  |
| q-728f90cb32 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RkEAFq"} | None |  |
| q-bb4b0846bc | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx2W"} | None |  |
| q-6cf58e5b79 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YcRyrP"} | None |  |
| q-325202d59a | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO74f6"} | None |  |
| q-773e2b33bd | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO74f6"} | None |  |
| q-f6dc27c22c | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1X-_nFZ"} | None |  |
| q-8e3ab2a08e | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8Ica"} | None |  |
| q-e5f9609d5c | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1bi_UDc"} | None |  |
| q-e0f966ccf5 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO74f6"} | None |  |
| q-c8895f6fcf | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YhYtYx"} | None |  |
| q-8fdcb0e107 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YhYtYx"} | None |  |
| q-52218e4e3a | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YQHgaq"} | None |  |
| q-c842e0cbd6 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NY3HhM"} | None |  |
| q-7a6c64f917 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NY3HhN"} | None |  |
| q-109b280440 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YhYtYx"} | None |  |
| q-94dcc23eab | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YaPjsB"} | None |  |
| q-35ef8c1ad2 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YaPjsB"} | None |  |
| q-86f6c3f164 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YQHgat"} | None |  |
| q-19cb6d05ce | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YQHgat"} | None |  |
| q-cbeafd46b8 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YhYtYv"} | None |  |
| q-1a190d9b4f | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-89592cfb36 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YQHgaq"} | None |  |
| q-2ce0932c67 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YOGdm9"} | None |  |
| q-7fe1bee953 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrMLE_"} | None |  |
| q-ba2148c682 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b22vQJ"} | None |  |
| q-6ebf843df9 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx1E"} | None |  |
| q-86204fc6bb | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrMLE_"} | None |  |
| q-6226bf89dc | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MsOhX7"} | None |  |
| q-5fda17acb1 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b22vQJ"} | None |  |
| q-0af38612d4 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1X-_nFC"} | None |  |
| q-ff9e65c155 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8Idl"} | None |  |
| q-5e5034375c | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx1E"} | None |  |
| q-f86c964ebe | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx21"} | None |  |
| q-790c1892c4 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx07"} | None |  |
| q-fbba8dc56c | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YQHwYC"} | None |  |
| q-35241eaccf | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YQHQbW"} | None |  |
| q-465bcd4ebe | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MtWeH6"} | None |  |
| q-ad21376999 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MtWNHL"} | None |  |
| q-c0003f22a6 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None |  |
| q-bbe9e7479d | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None |  |
| q-e6a1cb4ecc | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None |  |
| q-29fc032cba | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None |  |
| q-4c5eec20e5 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R_lUAH"} | None |  |
| q-75139dcf82 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R_lED5"} | None |  |
| q-686e8ee1b4 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1WdFNhN"} | None |  |
| q-4b864eb348 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YQHgaq"} | None |  |
| q-8465291778 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YOGdm9"} | None |  |
| q-a7489ff743 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RhBptB"} | None |  |
| q-7970f2163e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NDgB6i"} | None |  |
| q-25082547be | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None |  |
| q-69afde4cd2 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None |  |
| q-e971fa9996 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R_lUAH"} | None |  |
| q-fbef257091 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1SIw95-"} | None |  |
| q-b9dffe40c5 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R_lkD8"} | None |  |
| q-436f289a3c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R_lkD_"} | None |  |
| q-9d9fe06ecd | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-9634b2779f | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-7dca1c7d7b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RhBpvd"} | None |  |
| q-41c1c4f41e | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1bsxhdc"} | None |  |
| q-17c45d502e | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21_Tx"} | None |  |
| q-82c7b57bd6 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b22PQN"} | None |  |
| q-903b0487db | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b22PTB"} | None |  |
| q-cfb64e91ef | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YogQzA"} | None |  |
| q-c4487653b7 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YcSP2J"} | None |  |

## Verification

Evidence items cited: 202; confirmed against the stored events: 202; rejected: 0. Each item was re-fetched with get_event; it is confirmed only if the event exists, the cited field holds the cited value, and the cited query_id is a query of this run that returned that event.
Evidence sent back to the agents for correction during the run: 7 item(s) in 4 submission(s) (one correction round each; what still failed was rejected).

## Limitations

- Findings describe what the stored logs show; activity these sources did not log cannot be seen.
- Datasets with non-overlapping time windows (see Data examined) were analysed separately.
- Long field values are shortened in this report; full events are retrievable by _index/_id.
