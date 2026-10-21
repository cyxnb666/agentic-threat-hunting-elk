# Threat hunt report — 20261017-081623-converged-final-playbook

**Hypothesis:** An adversary who compromised Windows hosts in this network stole credentials from them (MITRE ATT&CK tactic: Credential Access).

**Verdict: Confirmed** — 10 in-scope incident(s) of verified malicious findings (confidence >= medium): I01 T1003 (F02), I02 T1003.001 (F01, F09, F31, F32, F34, F45), I03 T1003.002 (F60, F61), I04 T1056.004 (F08, F21, F52), I05 T1187 (F19), I06 T1552.001 (F28), I07 T1552.001 (F58), I08 T1552.001 (F62), I09 T1552.001 (F63), I10 T1552.004 (F27, F55, F59)

Verdict method: rules over verified evidence (Confirmed if >=1 in-scope incident of verified malicious findings (confidence >= medium); Inconclusive if only suspicious incidents or coverage gaps; Refuted if full coverage and no malicious/suspicious finding)

| Run | Value |
|---|---|
| Profile | converged (thinking=False, temperature=0.0) |
| Model | deepseek-flash |
| Started / finished (UTC) | 2026-10-17T00:16:23+00:00 / 2026-10-17T00:24:29+00:00 (486.0 s) |
| LLM calls / tokens | 132 / {'prompt': 3410426, 'completion': 86480} |
| MCP tool calls | 1181 (server tools: list_data_sources, get_fields, search, count, aggregate, timeline, esql, get_event, get_registry) |
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
| I01 | T1003 | yes | malicious/high | F02 | pbeesly multi-stage PowerShell credential/secret collection toolkit on scranton |
| I02 | T1003.001 | yes | malicious/high | F01, F09, F31, F32, F34, F45 | LSASS memory access with full-access masks by attacker PowerShell/wsmprovhost on scranton and nashua |
| I03 | T1003.002 | yes | malicious/medium | F60, F61 | lsass.exe creates PASSWD.LOG and opens SAM hive with KEY_ALL_ACCESS on scranton |
| I04 | T1056.004 | yes | malicious/high | F08, F21, F52 | Reflective in-memory API resolution and shellcode loader via PowerShell on scranton |
| I05 | T1187 | yes | malicious/high | F19 | WebDAV/SMB forced-authentication coercion from scranton to 192.168.0.4 |
| I06 | T1552.001 | yes | malicious/medium | F28 | accesschk.exe run by pbeesly creating a 'passwordsDB' file on scranton |
| I07 | T1552.001 | yes | malicious/high | F58 | Sysinternals pspasswd.exe/pspasswd64.exe downloaded to Downloads on scranton |
| I08 | T1552.001 | yes | malicious/high | F62 | Rar.exe on nashua creates password-protected working.zip then sdelete64 wipes it |
| I09 | T1552.001 | yes | malicious/high | F63 | Invoke-Exfil compresses Downloads with password 'lolol' and exfiltrates to WebDAV with hardcoded creds |
| I10 | T1552.004 | yes | malicious/high | F27, F55, F59 | Get-PrivateKeys exports LocalMachine certificates to password-protected .pfx files on scranton |
| I11 | T1558.001 | yes | suspicious/low | F47 | Kerberos service-ticket requests for the krbtgt service with RC4 encryption |
| I12 | T1558.003 | yes | suspicious/medium | F46 | RC4-downgraded Kerberos service-ticket requests for machine accounts (Kerberoasting pattern) |
| I13 | out-of-scope:T1021 | no | suspicious/medium | F07, F26 | PsExec-delivered python.exe lateral movement and C2 on nashua |

## Findings

### F02 · malicious / high · T1003 · Credential-access activity embedded in pbeesly attack toolkit on scranton

Evidence status: **verified**

The pbeesly account on scranton.dmevals.local ran a multi-stage PowerShell toolkit between 02:56Z and 03:21Z on 2020-05-02, including functions Invoke-Discovery, Invoke-Persistence, Get-PrivateKeys (exporting certificate private keys to .pfx), Invoke-Exfil (7-Zip password-protected archive of the Downloads folder), Invoke-SeaDukeStage, Keystroke-Check and Invoke-ScreenCapture. This is the surrounding context for the LSASS access on the same host and shows deliberate credential/secret collection rather than normal administration.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZSl2ML | q-7a613058cb | ok |
| 2 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZCgBha | q-7a613058cb | ok |
| 3 | 2020-05-02 03:10:22.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | Invoke-SeaDukeStage -ComputerName NASHUA | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZJhF-L | q-7a613058cb | ok |
| 4 | 2020-05-02 03:01:03.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | get-process | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZSmWOt | q-7a613058cb | ok |

### F01 · malicious / high · T1003.001 · PowerShell process opened LSASS with PROCESS_ALL_ACCESS (0x1FFFFF) on scranton

Evidence status: **verified**

On 2020-05-02T03:05:16Z on scranton.dmevals.local, a PowerShell.exe process (PID 2976, user context SYSTEM) opened lsass.exe (PID 736) with GrantedAccess 0x1FFFFF (PROCESS_ALL_ACCESS) and 0x1F3FFF, the access masks used to read LSASS memory for credential dumping. This occurred in the middle of a pbeesly-driven attack chain (Invoke-Discovery, Invoke-Persistence, Get-PrivateKeys, Invoke-Exfil, Invoke-SeaDukeStage) on the same host, and the same PowerShell session had earlier run 'get-process'. A second LSASS open with 0x1F3FFF came from wsmprovhost.exe (PID 7720) on nashua.dmevals.local at 03:09:29Z, consistent with PowerShell remoting (Invoke-Command -ComputerName NASHUA) issued from scranton.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTka0Gm | q-a9231dd6ea | ok |
| 2 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTka0Gm | q-a9231dd6ea | ok |
| 3 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.TargetImage | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTka0Gm | q-a9231dd6ea | ok |
| 4 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHNH1uOFchItUHCTY0 | q-6160612708 | ok |
| 5 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHNH1uOFchItUHCTY0 | q-6160612708 | ok |
| 6 | 2020-05-02 03:09:23.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | Invoke-Command -ComputerName NASHUA -ScriptBlock { Get-Process -IncludeUserName \| Select-Object UserName,SessionId \| Where-Object { $_.UserName -like "*\$env:… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZKhD3z | q-7a613058cb | ok |

### F60 · malicious / medium · T1003.002 · lsass.exe creates C:\Windows\debug\PASSWD.LOG on scranton (SAM credential log artifact)

Evidence status: **verified**

On scranton.dmevals.local, lsass.exe (PID 748) created C:\Windows\debug\PASSWD.LOG at 03:19:09.994. A PASSWD.LOG written by lsass in the debug directory is a classic SAM/credential-dump artifact, appearing minutes after the attacker's LSASS handle acquisition and SAM hive access.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:09.994Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Windows\debug\PASSWD.LOG | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItO9rO3J | q-31d469c46b | ok |

### F09 · malicious / high · T1056 · PowerShell and wsmprovhost request full-access handles to lsass.exe on scranton/nashua

Evidence status: **verified**

On scranton.dmevals.local, powershell.exe running as pbeesly requested a handle to \Device\HarddiskVolume2\Windows\System32\lsass.exe with Access Mask 0x1F3FFF (includes 'Read from process memory', 'Write to process memory', 'Duplicate handle into or out of process'), and Sysmon recorded the same PowerShell process opening lsass with GrantedAccess 0x1f3fff and 0x1fffff. On nashua.dmevals.local, wsmprovhost.exe (pbeesly) also opened lsass with GrantedAccess 0x1f3fff. These are credential-capture accesses to LSASS memory, not normal system behaviour (the baseline LSASS opens are svchost.exe with 0x1000).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | win.AccessMask | 0x1f3fff | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItaDOKA_ | q-8fe5725db9 | ok |
| 2 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | win.ObjectName | \Device\HarddiskVolume2\Windows\System32\lsass.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItaDOKA_ | q-8fe5725db9 | ok |
| 3 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | process.executable | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItaDOKA_ | q-8fe5725db9 | ok |
| 4 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTka0Gj | q-70846dec16 | ok |
| 5 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTka0Gm | q-70846dec16 | ok |
| 6 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHNH1uOFchItUHCTY0 | q-70846dec16 | ok |
| 7 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHNH1uOFchItUHCTY0 | q-70846dec16 | ok |

### F08 · malicious / high · T1056.004 · Reflective in-memory API resolution (GetProcAddress/GetModuleHandle) via PowerShell on scranton

Evidence status: **verified**

On scranton.dmevals.local, user pbeesly executed a PowerShell script block (Event 4104, ScriptBlockId bc19aae2-d1f9-49b2-b718-192531ae928f) that reflectively resolves native APIs: it fetches Microsoft.Win32.UnsafeNativeMethods from System.dll, calls GetModuleHandle/GetProcAddress, defines a dynamic assembly named 'ReflectedDelegate' with a delegate type, and then decodes a base64 shellcode blob ([System.Convert]::FromBase64String("/EiD5PDozAAAA...")) for in-memory execution. This is the classic pattern for hooking/intercepting native credential APIs without touching disk. It is preceded by a hidden base64-encoded PowerShell launch (powershell.exe -nop -w hidden -e ...) and a steganographic loader reading C:\Users\pbeesly\Downloads\monkey.png into IEX.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:21:29.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function jzI {  	Param ($yKR, $cq)		  	$vvA = ([AppDomain]::CurrentDomain.GetAssemblies() \| Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZRkUVV | q-dc332aa75f | ok |
| 2 | 2020-05-02 03:21:29.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function jzI {  	Param ($yKR, $cq)		  	$vvA = ([AppDomain]::CurrentDomain.GetAssemblies() \| Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZRkUVV | q-dc332aa75f | ok |
| 3 | 2020-05-02 03:21:29.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function jzI {  	Param ($yKR, $cq)		  	$vvA = ([AppDomain]::CurrentDomain.GetAssemblies() \| Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZRkUVV | q-dc332aa75f | ok |
| 4 | 2020-05-02 03:21:29.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function jzI {  	Param ($yKR, $cq)		  	$vvA = ([AppDomain]::CurrentDomain.GetAssemblies() \| Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZRkUVV | q-dc332aa75f | ok |
| 5 | 2020-05-02 03:21:28.949Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\windows\System32\WindowsPowerShell\v1.0\powershell.exe" -nop -w hidden -e aQBmACgAWwBJAG4AdABQAHQAcgBdADoAOgBTAGkAegBlACAALQBlAHEAIAA0ACkAewAkAGIAPQAkAGUAbg… | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItOcHa1B | q-373901e8ed | ok |
| 6 | 2020-05-02 02:58:44.325Z | scranton.dmevals.local | windows.sysmon | process.command_line | "PowerShell.exe" -noni -noexit -ep bypass -window hidden -c "sal a New-Object;Add-Type -AssemblyName 'System.Drawing'; $g=a System.Drawing.Bitmap('C:\Users\pbee… | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHNH1uOFchItQB61zZ | q-373901e8ed | ok |

### F19 · malicious / high · T1187 · WebDAV/SMB forced-authentication coercion from scranton (10.0.1.4) to 192.168.0.4

Evidence status: **verified**

On 2020-04-30 between 00:32:14 and 00:35:25 UTC, host 10.0.1.4 (scranton.dmevals.local) connected to 192.168.0.4 over SMB (tcp/445 and tcp/139) and then issued 36 HTTP requests to port 80 using the Windows WebDAV redirector user agents 'Microsoft-WebDAV-MiniRedir/10.0.18362' and 'DavClnt'. The requests were OPTIONS and PROPFIND to /webdav, /webdav/, /webdav/OfficeSupplies.7z and /webdav/python.exe. The PROPFIND requests carried an AUTHORIZATION header (client_header_names includes AUTHORIZATION) and the server answered 401 Unauthorized before returning 207 Multi-Status, i.e. the host's credentials were coerced and accepted by the remote WebDAV listener. This is the classic T1187 forced-authentication chain (SMB/WebDAV UNC trigger -> NTLM credential capture) against an attacker-controlled listener at 192.168.0.4. All 36 WebDAV requests originate from 10.0.1.4 and target 192.168.0.4 only.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-04-30 00:32:21.535Z | simplerockbuild.simplerock.lan | zeek | user_agent.original | Microsoft-WebDAV-MiniRedir/10.0.18362 | .ds-logs-zeek-default-2026.10.17-000001 / AaFHNX1uOFchItbgrYjN | q-1270e751a4 | ok |
| 2 | 2020-04-30 00:32:21.535Z | simplerockbuild.simplerock.lan | zeek | zeek.client_header_names | ["CONNECTION", "USER-AGENT", "DEPTH", "TRANSLATE", "CONTENT-LENGTH", "HOST", "AUTHORIZATION"] | .ds-logs-zeek-default-2026.10.17-000001 / AaFHNX1uOFchItbgrYjN | q-1270e751a4 | ok |
| 3 | 2020-04-30 00:32:21.895Z | simplerockbuild.simplerock.lan | zeek | url.original | /webdav/OfficeSupplies.7z | .ds-logs-zeek-default-2026.10.17-000001 / AaFHNX1uOFchItbgrYgN | q-7ad3c0a9bb | ok |
| 4 | 2020-04-30 00:32:21.895Z | simplerockbuild.simplerock.lan | zeek | http.response.status_code | 401 | .ds-logs-zeek-default-2026.10.17-000001 / AaFHNX1uOFchItbgrYgN | q-7ad3c0a9bb | ok |
| 5 | 2020-04-30 00:32:21.950Z | simplerockbuild.simplerock.lan | zeek | http.response.status_code | 207 | .ds-logs-zeek-default-2026.10.17-000001 / AaFHNX1uOFchItbgrYi8 | q-94b4d4fd48 | ok |
| 6 | 2020-04-30 00:32:17.069Z | simplerockbuild.simplerock.lan | zeek | destination.port | 445 | .ds-logs-zeek-default-2026.10.17-000001 / AaFHNX1uOFchItbgrogt | q-e10e237bf0 | ok |
| 7 | 2020-04-30 00:32:18.094Z | simplerockbuild.simplerock.lan | zeek | destination.port | 80 | .ds-logs-zeek-default-2026.10.17-000001 / AaFHNX1uOFchItbgrYiQ | q-e10e237bf0 | ok |

### F21 · malicious / high · T1212 · Obfuscated PowerShell reflective shellcode loader on scranton.dmevals.local (user pbeesly)

Evidence status: **verified**

On 2020-05-02T03:21:29Z on scranton.dmevals.local, a PowerShell script block (ScriptBlockId bc19aae2-d1f9-49b2-b718-192531ae928f, PID 8784, user pbeesly, SID S-1-5-21-1830255721-3727074217-2423397540-1107) was executed that resolves Win32 APIs via Microsoft.Win32.UnsafeNativeMethods GetProcAddress/GetModuleHandle, builds an in-memory delegate through DefineDynamicAssembly('ReflectedDelegate')/DefineDynamicModule('InMemoryModule'), and decodes a base64 blob beginning with a PE header ('/EiD5PDozAAAAEFRQVBSUVZ...'). This is a reflective shellcode/PE loader (obfuscated function names jzI/yT, variables yKR/cq/uJ) — the standard vehicle for in-memory credential-access tooling. It is corroborated by LSASS process-access events on the same host minutes earlier: PowerShell.exe (PID 2976) opened lsass.exe with GrantedAccess 0x1F3FFF and 0x1FFFFF (full access) at 03:05:16Z, and on nashua.dmevals.local wsmprovhost.exe (PID 7720, WinRM, user pbeesly) opened lsass.exe with 0x1F3FFF at 03:09:29Z with a call trace through Microsoft.PowerShell.Commands.Management. Full-access handles to LSASS from PowerShell/WinRM are consistent with credential dumping driven by the loaded payload.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:21:29.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function jzI {  	Param ($yKR, $cq)		  	$vvA = ([AppDomain]::CurrentDomain.GetAssemblies() \| Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZRkUVV | q-126f60d032 | ok |
| 2 | 2020-05-02 03:21:29.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function jzI {  	Param ($yKR, $cq)		  	$vvA = ([AppDomain]::CurrentDomain.GetAssemblies() \| Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZRkUVV | q-31fb7e025a | ok |
| 3 | 2020-05-02 03:21:29.000Z | scranton.dmevals.local | windows.powershell | user.name | pbeesly | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZRkUVV | q-31fb7e025a | ok |
| 4 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTka0Gm | q-2605eb1300 | ok |
| 5 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTka0Gm | q-2605eb1300 | ok |
| 6 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHNH1uOFchItUHCTY0 | q-2605eb1300 | ok |
| 7 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHNH1uOFchItUHCTY0 | q-2605eb1300 | ok |

### F28 · malicious / medium · T1552.001 · accesschk.exe run by pbeesly creating a 'passwordsDB' file

Evidence status: **verified**

On scranton.dmevals.local, user pbeesly launched C:\Program Files\SysinternalsSuite\accesschk.exe (parent process powershell.exe, integrity High), and one second later that process created the file C:\Program Files\SysinternalsSuite\passwordsDB. The tooling was staged by the same PowerShell session that downloaded/extracted SysinternalsSuite and ran the Get-PrivateKeys certificate-theft function, so this is consistent with an adversary searching for credentials stored in files (T1552.001). The command line carried no arguments, so the exact target of the search is not visible in the telemetry.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:34.951Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\accesschk.exe" | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTkbkGg | q-789d257815 | ok |
| 2 | 2020-05-02 03:04:34.951Z | scranton.dmevals.local | windows.sysmon | process.parent.executable | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTkbkGg | q-789d257815 | ok |
| 3 | 2020-05-02 03:04:35.069Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Program Files\SysinternalsSuite\passwordsDB | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTkbkGF | q-daf20c2843 | ok |
| 4 | 2020-05-02 03:04:34.951Z | scranton.dmevals.local | windows.sysmon | user.name | pbeesly | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTkbkGg | q-789d257815 | ok |

### F58 · malicious / high · T1552.001 · Sysinternals pspasswd.exe/pspasswd64.exe downloaded to Downloads on scranton (password-manipulation tool)

Evidence status: **verified**

On scranton.dmevals.local, PowerShell (user pbeesly) wrote pspasswd.exe and pspasswd64.exe into C:\Users\pbeesly\Downloads\SysinternalsSuite\ at 03:00:28-03:00:32, alongside the accesschk.exe already anchored. pspasswd is a Sysinternals credential/password-manipulation tool, consistent with the attacker toolkit staging credentials. No execution of pspasswd was observed in the window.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:00:32.048Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Users\pbeesly\Downloads\SysinternalsSuite\pspasswd.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTummpO | q-fabb4c9591 | ok |
| 2 | 2020-05-02 03:00:28.986Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Users\pbeesly\Downloads\SysinternalsSuite\pspasswd64.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTummrw | q-fabb4c9591 | ok |

### F62 · malicious / high · T1552.001 · Rar.exe on nashua creates password-protected working.zip then sdelete64 wipes it

Evidence status: **verified**

On nashua.dmevals.local, PowerShell (pbeesly) launched C:\Windows\Temp\Rar.exe at 03:16:19 to create a password-protected archive C:\Users\pbeesly\Desktop\working.zip (password fGzq5yKw) from C:\Users\pbeesly\AppData\Roaming\working.zip, then ran sdelete64.exe at 03:16:52-03:17:41 to securely delete Rar.exe and both copies of working.zip. Password-protected staging plus anti-forensic wiping indicates credential/data collection and cleanup.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:16:19.395Z | nashua.dmevals.local | windows.sysmon | process.command_line | "C:\Windows\Temp\Rar.exe" a -hpfGzq5yKw C:\Users\pbeesly\Desktop\working.zip C:\Users\pbeesly\AppData\Roaming\working.zip | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTPA5kN | q-61bb43ca3b | ok |
| 2 | 2020-05-02 03:16:52.456Z | nashua.dmevals.local | windows.sysmon | process.command_line | .\sdelete64.exe  /accepteula "C:\Windows\Temp\Rar.exe" | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItPO_TIA | q-2a7a3a1be4 | ok |

### F63 · malicious / high · T1552.001 · Invoke-Exfil compresses Downloads with password 'lolol' and exfiltrates to WebDAV with hardcoded creds

Evidence status: **verified**

On scranton.dmevals.local, PowerShell (pbeesly) ran Invoke-Exfil (script psversion.ps1) at 03:08:02, compressing the entire Downloads directory into a password-protected OfficeSupplies.7z (password 'lolol') and copying it to \\192.168.0.4\webdav using hardcoded credentials cozy/MyCozyPassw0rd!. The archive OfficeSupplies.7z was written at 03:08:35. This is credential/data collection and exfiltration using embedded credentials.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZCgBha | q-5c0cb3579d | ok |
| 2 | 2020-05-02 03:08:35.270Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Users\pbeesly\AppData\Roaming\OfficeSupplies.7z | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTWI7pZ | q-fabb4c9591 | ok |

### F27 · malicious / high · T1552.004 · PowerShell Get-PrivateKeys exports all LocalMachine certificates to .pfx files

Evidence status: **verified**

On scranton.dmevals.local, user pbeesly ran a PowerShell script (readme.ps1 in C:\Program Files\SysinternalsSuite) defining a Get-PrivateKeys function that enumerates cert:\LocalMachine recursively and exports every certificate with a thumbprint to a randomly-named .pfx file under the user's Downloads folder, protected by the hardcoded password 'saribas'. This is direct private-key/certificate theft (T1552.004). It is part of a larger intrusion chain on the same host/user: a .scr payload executed from C:\ProgramData\victim, PowerShell download/extraction of SysinternalsSuite, accesschk.exe credential hunting, and an Invoke-Exfil function that 7-Zip-compresses the Downloads folder with password 'lolol'.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZSl2ML | q-9d1fe851d5 | ok |
| 2 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\readme.ps1 | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZSl2ML | q-9d1fe851d5 | ok |
| 3 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | user.name | pbeesly | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZSl2ML | q-9d1fe851d5 | ok |
| 4 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | host.name | scranton.dmevals.local | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZSl2ML | q-9d1fe851d5 | ok |

### F59 · malicious / high · T1552.004 · Get-PrivateKeys exports LocalMachine certs to .pfx with hardcoded password 'saribas' (readme.ps1)

Evidence status: **verified**

On scranton.dmevals.local, PowerShell (pbeesly) ran the Get-PrivateKeys function from C:\Program Files\SysinternalsSuite\readme.ps1 at 03:04:56, exporting every LocalMachine certificate to random-named .pfx files in Downloads protected by the hardcoded password 'saribas'. The resulting file coyn5igj.3io.pfx was written at 03:04:57. This is private-key/certificate theft beyond the anchored export description.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZSl2ML | q-34c65b54aa | ok |
| 2 | 2020-05-02 03:04:57.460Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTkbEF9 | q-a6210fcd28 | ok |

### F31 · malicious / high · T1555 · PowerShell and PowerShell Remoting processes opened LSASS with full-access masks on scranton and nashua

Evidence status: **verified**

On 2020-05-02, user pbeesly's PowerShell activity on scranton.dmevals.local and nashua.dmevals.local opened handles to lsass.exe with PROCESS_ALL_ACCESS-class masks (0x1fffff, 0x1f3fff), the access pattern used to read credential material from LSASS memory. On scranton, PowerShell.exe (pid 2976) accessed lsass.exe (pid 736) with GrantedAccess 0x1FFFFF and 0x1F3FFF at 03:05:16, with a CallTrace ending in UNKNOWN(000001996D28200D) - an unbacked/unknown module, not a normal Windows DLL path. That same pid 2976 was launched at 02:58:44 by control.exe with a hidden, execution-policy-bypass PowerShell command that decodes a steganographic payload from C:\Users\pbeesly\Downloads\monkey.png and IEX-executes it. On nashua, wsmprovhost.exe (PowerShell Remoting, pid 7720) accessed lsass.exe (pid 728) with 0x1F3FFF at 03:09:29, its CallTrace running through PowerShell Management native images and multiple UNKNOWN modules. Windows Security object-access auditing (4656) independently records the same pbeesly/PowerShell and pbeesly/wsmprovhost LSASS accesses with AccessMask 0x1fffff and 0x1f3fff. The only other high-mask LSASS access is MsMpEng.exe (Windows Defender), which is the benign baseline. This is credential access against LSASS by attacker-controlled PowerShell, not normal system behaviour.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTka0Gm | q-2f8445d78a | ok |
| 2 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.CallTrace | C:\windows\SYSTEM32\ntdll.dll+9c584\|C:\windows\System32\KERNELBASE.dll+2732e\|UNKNOWN(000001996D28200D) | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTka0Gm | q-5b72d9f3d6 | ok |
| 3 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTka0Gm | q-5b72d9f3d6 | ok |
| 4 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHNH1uOFchItUHCTY0 | q-8c3e41f8c1 | ok |
| 5 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHNH1uOFchItUHCTY0 | q-8c3e41f8c1 | ok |
| 6 | 2020-05-02 02:58:44.325Z | scranton.dmevals.local | windows.sysmon | process.command_line | "PowerShell.exe" -noni -noexit -ep bypass -window hidden -c "sal a New-Object;Add-Type -AssemblyName 'System.Drawing'; $g=a System.Drawing.Bitmap('C:\Users\pbee… | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHNH1uOFchItQB61zZ | q-4d7271fedb | ok |
| 7 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | win.AccessMask | 0x1fffff | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItaDOKB- | q-8660874423 | ok |
| 8 | 2020-05-02 03:09:29.000Z | nashua.dmevals.local | windows.security | win.ProcessName | C:\Windows\System32\wsmprovhost.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItZ8FLV1 | q-8660874423 | ok |

### F32 · malicious / medium · T1555.004 · LSASS handle acquisition with full-access masks by attacker PowerShell (Credential Manager/DPAPI vault harvesting path)

Evidence status: **verified**

The same LSASS accesses that support T1555 are the mechanism by which Windows Credential Manager secrets (DPAPI-protected vaults) are harvested: reading LSASS memory yields logon credentials and DPAPI material. On scranton.dmevals.local, pbeesly's powershell.exe requested a handle to \Device\HarddiskVolume2\Windows\System32\lsass.exe with AccessMask 0x1fffff (Security 4656, AUDIT_SUCCESS), and on nashua.dmevals.local pbeesly's wsmprovhost.exe accessed lsass.exe with 0x1f3fff. No direct Credential Manager / vault / cmdkey command line or vault file access was observed (checks C217-C220 returned no hits), so the Credential Manager-specific artifact is inferred from the LSASS full-access reads rather than directly logged. The benign baseline for high-mask LSASS access is MsMpEng.exe (Windows Defender) and the CollectGuestLogs.exe Azure agent (0x1410/0x10).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | win.ObjectName | \Device\HarddiskVolume2\Windows\System32\lsass.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItaDOKB- | q-8660874423 | ok |
| 2 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | win.ProcessName | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItaDOKB- | q-8660874423 | ok |
| 3 | 2020-05-02 03:09:29.000Z | nashua.dmevals.local | windows.security | win.AccessMask | 0x1f3fff | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItZ8FLV1 | q-8660874423 | ok |
| 4 | 2020-05-02 03:20:15.000Z | scranton.dmevals.local | windows.security | win.ProcessName | C:\Program Files\Windows Defender\MsMpEng.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItVq1T69 | q-8660874423 | ok |

### F34 · malicious / high · T1556 · LSASS accessed with PROCESS_ALL_ACCESS by steganographic PowerShell loader (credential theft, not auth-process modification)

Evidence status: **verified**

On scranton.dmevals.local, user pbeesly, a hidden PowerShell process (PID 2976, entity_id {47ab858c-e1e4-5eac-b803-000000000400}) was spawned by control.exe running a steganographic loader that decodes C:\Users\pbeesly\Downloads\monkey.png and IEX-executes the payload. That same process then opened lsass.exe with GrantedAccess 0x1FFFFF (PROCESS_ALL_ACCESS), the access mask used for LSASS credential dumping. This is credential theft from LSASS memory rather than modification of the authentication process itself; no authentication-process tampering (password filter, network provider, reversible encryption, MFA/hybrid identity) was observed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTka0Gm | q-fd6d5e496c | ok |
| 2 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTka0Gm | q-fd6d5e496c | ok |
| 3 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.TargetImage | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTka0Gm | q-fd6d5e496c | ok |
| 4 | 2020-05-02 02:58:44.325Z | scranton.dmevals.local | windows.sysmon | process.command_line | "PowerShell.exe" -noni -noexit -ep bypass -window hidden -c "sal a New-Object;Add-Type -AssemblyName 'System.Drawing'; $g=a System.Drawing.Bitmap('C:\Users\pbee… | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHNH1uOFchItQB61zZ | q-fe7ad2d060 | ok |
| 5 | 2020-05-02 02:58:44.325Z | scranton.dmevals.local | windows.sysmon | win.ParentImage | C:\Windows\System32\control.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHNH1uOFchItQB61zZ | q-fe7ad2d060 | ok |

### F45 · malicious / high · T1558 · LSASS memory access with PROCESS_ALL_ACCESS by steganography-loaded PowerShell on scranton

Evidence status: **verified**

On scranton.dmevals.local, PowerShell.exe (PID 2976) opened lsass.exe with GrantedAccess 0x1FFFFF (PROCESS_ALL_ACCESS) at 2020-05-02T03:05:16.654Z, the access mask used to read credential material from LSASS. The same PID 2976 was launched at 02:58:44 by user pbeesly with a hidden-window, execution-policy-bypass command that decodes a bitmap (C:\Users\pbeesly\Downloads\monkey.png) into a byte array and pipes it to IEX — a steganographic payload loader. This is credential theft activity on the host.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTka0Gm | q-7f63510c6a | ok |
| 2 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTka0Gm | q-7f63510c6a | ok |
| 3 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.TargetImage | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTka0Gm | q-7f63510c6a | ok |
| 4 | 2020-05-02 02:58:44.325Z | scranton.dmevals.local | windows.sysmon | process.command_line | "PowerShell.exe" -noni -noexit -ep bypass -window hidden -c "sal a New-Object;Add-Type -AssemblyName 'System.Drawing'; $g=a System.Drawing.Bitmap('C:\Users\pbee… | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHNH1uOFchItQB61zZ | q-55aee02bbe | ok |
| 5 | 2020-05-02 02:58:44.325Z | scranton.dmevals.local | windows.sysmon | user.name | pbeesly | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHNH1uOFchItQB61zZ | q-55aee02bbe | ok |

### F55 · malicious / high · T1649 · PowerShell Get-PrivateKeys exports all LocalMachine certificates to password-protected .pfx files on scranton.dmevals.local

Evidence status: **verified**

On 2020-05-01T23:04:56 (host scranton.dmevals.local, user pbeesly, powershell.exe PID 3876) a PowerShell script block defining function Get-PrivateKeys was executed. The function enumerates every certificate under cert:\LocalMachine recursively and, for each certificate with a Thumbprint, calls Export-PfxCertificate to write it to "$env:USERPROFILE\Downloads\$RandomFileName.pfx" protected by the hardcoded password "saribas". The script was loaded from Path C:\Program Files\SysinternalsSuite\readme.ps1 (ScriptBlock ID 9d153741-75c3-4062-afe3-aeca0aee611b). Seconds later at 03:04:57.460Z Sysmon recorded the creation of the exported bundle C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx by powershell.exe, and registry writes to HKLM\SOFTWARE\Microsoft\SystemCertificates\MY\Certificates\48B5E43D09D080DF8863152FD22ED7C43443D499\Blob by powershell.exe on the same host. At 23:08:51 the same user ran function Invoke-BeachCleanup which deletes "$env:USERPROFILE\Downloads\*.pfx" (plus .bmp/.png and %APPDATA%\OfficeSupplies.7z), consistent with anti-forensic cleanup of the stolen certificate material. This is theft of authentication certificates/private keys (T1649).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZSl2ML | q-dea2bebdd8 | ok |
| 2 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\readme.ps1 | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZSl2ML | q-dea2bebdd8 | ok |
| 3 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | user.name | pbeesly | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZSl2ML | q-dea2bebdd8 | ok |
| 4 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | host.name | scranton.dmevals.local | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZSl2ML | q-dea2bebdd8 | ok |
| 5 | 2020-05-02 03:04:57.460Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTkbEF9 | q-a4ee49fc40 | ok |
| 6 | 2020-05-02 03:04:57.460Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\WindowsPowerShell\v1.0\powershell.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTkbEF9 | q-a4ee49fc40 | ok |
| 7 | 2020-05-02 03:08:51.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-BeachCleanup {     Write-Host "[*] Cleaning up"     Remove-Item -Path "$env:USERPROFILE\Downloads\*.pfx" -Force     Remove-Item -Path "$env:USER… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZLhp5O | q-c0182b0819 | ok |
| 8 | 2020-05-02 03:04:57.428Z | scranton.dmevals.local | windows.sysmon | registry.path | HKLM\SOFTWARE\Microsoft\SystemCertificates\MY\Certificates\48B5E43D09D080DF8863152FD22ED7C43443D499\Blob | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTkbEGc | q-d6f3cf33ad | ok |

### F61 · suspicious / medium · T1003.002 · SAM registry hive opened with KEY_ALL_ACCESS (0xf003f) by lsass.exe on scranton

Evidence status: **verified**

On scranton.dmevals.local, lsass.exe opened the SAM registry object with AccessMask 0xf003f (KEY_ALL_ACCESS) at 03:19:21-03:20:46, immediately after the PASSWD.LOG creation. Full-access SAM hive access is consistent with local account credential extraction (SAM dump).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:21.000Z | scranton.dmevals.local | windows.security | win.ObjectName | SAM | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItVr3Lv_ | q-4e85a3cca8 | ok |
| 2 | 2020-05-02 03:19:21.000Z | scranton.dmevals.local | windows.security | win.AccessMask | 0xf003f | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItVr3Lv_ | q-4e85a3cca8 | ok |

### F07 · suspicious / medium · T1040 · PsExec-delivered python.exe payload on nashua is lateral movement, not sniffing

Evidence status: **verified**

On scranton.dmevals.local, user pbeesly ran PsExec64.exe with explicit credentials (dmevals\pbeesly) against \\NASHUA to launch C:\Windows\Temp\python.exe, which then ran on nashua.dmevals.local under PSEXESVC.exe and made repeated outbound TCP connections to 192.168.0.4:8443. This is credential-based lateral movement / C2, not network sniffing; no capture driver or sniffing tool was involved. Reported here only because it appeared in the T1040 hunt scope.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:18.784Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\PsExec64.exe" -accepteula \\NASHUA -u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTVGglR | q-2c528a6209 | ok |
| 2 | 2020-05-02 03:11:40.213Z | nashua.dmevals.local | windows.sysmon | process.command_line | "C:\Windows\Temp\python.exe"  | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTVGQmt | q-2c528a6209 | ok |
| 3 | 2020-05-02 03:15:05.142Z | nashua.dmevals.local | windows.sysmon | win.DestinationPort | 8443 | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItPK66ha | q-80a1984ab2 | ok |

### F22 · suspicious / medium · T1212 · LSASS full-access handles from PowerShell and WinRM host processes

Evidence status: **NOT verified (2/3 evidence items)** — excluded from the verdict

Across the Windows hosts, 326 Sysmon process-access (event.code 10) events targeted lsass.exe. The overwhelming majority (289) came from svchost.exe with benign GrantedAccess 0x1000, but a small set used high-privilege masks: PowerShell.exe (PID 2976) on scranton.dmevals.local opened lsass.exe with 0x1F3FFF and 0x1FFFFF at 03:05:16Z, and wsmprovhost.exe (PID 7720, WinRM, user pbeesly) on nashua.dmevals.local opened lsass.exe with 0x1F3FFF at 03:09:29Z. Full-access (0x1FFFFF) and 0x1F3FFF handles to LSASS from scripting/WinRM processes are the classic signature of credential dumping. Note: the 0x1FFFFF accesses by wininit.exe/csrss.exe at 03:19:09Z coincide with a fresh lsass.exe process creation (PID 748) and are consistent with a system reboot, so those are treated as benign.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | message | Process accessed:  RuleName: -  UtcTime: 2020-05-02 03:05:16.654  SourceProcessGUID: {47ab858c-e1e4-5eac-b803-000000000400}  SourceProcessId: 2976  SourceThread… | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTka0Gm | q-7628f4845a | ok |
| 2 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | message | Process accessed:  RuleName: -  UtcTime: 2020-05-02 03:09:29.430  SourceProcessGUID: {5aa8ec29-e463-5eac-6303-000000000400}  SourceProcessId: 7720  SourceThread… | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHNH1uOFchItUHCTY0 | q-1cf5a0f97a | FAILED: claimed value differs from the stored value |
| 3 | 2020-05-02 03:19:09.809Z | scranton.dmevals.local | windows.sysmon | process.command_line | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItO9re0C | q-541c9cb2d8 | ok |

### F26 · suspicious / medium · T1539 · PsExec-launched python.exe on nashua and WebDAV python.exe retrieval (lateral movement, not cookie theft)

Evidence status: **verified**

On nashua.dmevals.local, C:\Windows\Temp\python.exe was launched repeatedly (2020-05-02 03:11:40-03:15:04) with parent C:\Windows\PSEXESVC.exe under user pbeesly, and Zeek shows HTTP GET /webdav/python.exe from 10.0.1.4 to 192.168.0.4 with user-agent Microsoft-WebDAV-MiniRedir/10.0.18362. This is PsExec/WebDAV-delivered tooling consistent with lateral movement, but the command lines contain no cookie references and no browser cookie store was accessed, so it is not evidence of T1539 web session cookie theft.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:15:03.954Z | nashua.dmevals.local | windows.sysmon | process.parent.executable | C:\Windows\PSEXESVC.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItPK66i5 | q-db816fabb9 | ok |
| 2 | 2020-05-02 03:15:03.954Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItPK66i5 | q-db816fabb9 | ok |
| 3 | 2020-04-30 00:35:25.656Z | simplerockbuild.simplerock.lan | zeek | url.original | /webdav/python.exe | .ds-logs-zeek-default-2026.10.17-000001 / AaFHNX1uOFchItbgrog- | q-d97291f20d | ok |

### F47 · suspicious / low · T1558.001 · Kerberos service-ticket requests for the krbtgt service with RC4 encryption

Evidence status: **verified**

Three 4769 events on newyork.dmevals.local requested a service ticket for the krbtgt service (Service ID S-1-5-21-1830255721-3727074217-2423397540-502) with TicketOptions 0x60810010 and Ticket Encryption Type 0x12 (RC4), by pbeesly@DMEVALS.LOCAL and SCRANTON$@DMEVALS.LOCAL from 10.0.1.4. Requests for the krbtgt service are unusual and can accompany golden-ticket forging/reconnaissance, but no forged-ticket artifact (e.g. anomalous 4672 logon or TGT issuance) was directly observed, so this is assessed as suspicious rather than confirmed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:04.000Z | newyork.dmevals.local | windows.security | win.ServiceName | krbtgt | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItaDOKC- | q-5c6f82aa56 | ok |
| 2 | 2020-05-02 03:04:04.000Z | newyork.dmevals.local | windows.security | win.TicketOptions | 0x60810010 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItaDOKC- | q-5c6f82aa56 | ok |
| 3 | 2020-05-02 03:04:04.000Z | newyork.dmevals.local | windows.security | win.TicketEncryptionType | 0x12 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItaDOKC- | q-5c6f82aa56 | ok |
| 4 | 2020-05-02 03:19:13.000Z | newyork.dmevals.local | windows.security | user.name | SCRANTON$@DMEVALS.LOCAL | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItV3-aXQ | q-5c6f82aa56 | ok |

### F46 · suspicious / medium · T1558.003 · RC4-downgraded Kerberos service-ticket requests for machine accounts (Kerberoasting pattern)

Evidence status: **verified**

On newyork.dmevals.local, 28 Kerberos service-ticket (4769) requests were logged, all with Ticket Encryption Type 0x12 (RC4-HMAC). Requests targeted machine/service accounts NASHUA$ (10), NEWYORK$ (11), SCRANTON$ (3) and WEC$ (1) with TicketOptions 0x40810000, issued to pbeesly@DMEVALS.LOCAL from 10.0.1.4/10.0.1.6. RC4 encryption on TGS requests is the hallmark of Kerberoasting, where an attacker requests service tickets to crack the service account password offline. This coincides with the LSASS access and steganographic PowerShell loader on scranton.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:09:23.000Z | newyork.dmevals.local | windows.security | win.ServiceName | NASHUA$ | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItZ8FbW6 | q-aa424d15d8 | ok |
| 2 | 2020-05-02 03:09:23.000Z | newyork.dmevals.local | windows.security | win.TicketEncryptionType | 0x12 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItZ8FbW6 | q-aa424d15d8 | ok |
| 3 | 2020-05-02 03:09:23.000Z | newyork.dmevals.local | windows.security | win.TicketOptions | 0x40810000 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItZ8FbW6 | q-aa424d15d8 | ok |
| 4 | 2020-05-02 03:09:23.000Z | newyork.dmevals.local | windows.security | user.name | pbeesly@DMEVALS.LOCAL | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItZ8FbW6 | q-aa424d15d8 | ok |
| 5 | 2020-05-02 03:09:23.000Z | newyork.dmevals.local | windows.security | source.ip | ::ffff:10.0.1.4 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItZ8FbW6 | q-aa424d15d8 | ok |

### F52 · suspicious / medium · T1606.002 · No SAML token forging; only an unrelated in-memory PowerShell loader on scranton

Evidence status: **verified**

No SAML/ADFS/token forging was observed: PowerShell 4104 script blocks contained no SAML/NotOnOrAfter/Assertion content (C348 zero hits), no process command line referenced saml/token/cert (C350 zero hits), and Zeek HTTP had no saml/adfs/token URLs (C351 zero hits). The one notable PowerShell event is a 4104 script block on scranton.dmevals.local at 2020-05-02T03:21:29Z under user pbeesly (SID S-1-5-21-1830255721-3727074217-2423397540-1107, PID 8784) that defines GetProcAddress/GetModuleHandle delegate helpers and decodes a base64 blob into a byte array — an in-memory loader pattern, but it contains no web-credential/SAML forging content and is not evidence of T1606.002. The 5857/5858 WMI events on newyork are routine RSOP_ExtensionStatus DeleteInstance operations by SYSTEM.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:21:29.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function jzI {  	Param ($yKR, $cq)		  	$vvA = ([AppDomain]::CurrentDomain.GetAssemblies() \| Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZRkUVV | q-29e4212442 | ok |
| 2 | 2020-05-02 03:21:29.000Z | scranton.dmevals.local | windows.powershell | user.name | pbeesly | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZRkUVV | q-29e4212442 | ok |
| 3 | 2020-05-02 03:21:29.000Z | scranton.dmevals.local | windows.powershell | host.name | scranton.dmevals.local | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZRkUVV | q-29e4212442 | ok |

### F03 · benign / high · T1003.002 · SAM registry writes are by lsass.exe itself (benign)

Evidence status: **verified**

The only SAM-hive registry writes observed (event.code 13) are TargetObject HKLM\SAM\SAM\Domains\Account\F written by C:\windows\system32\lsass.exe (PID 748) on scranton.dmevals.local at 03:19:10Z, and a LogonUI SessionData write. These are normal operating-system writes by the LSASS process that owns the SAM database, not an external tool copying or dumping the SAM hive. No reg save / hive-copy activity was found.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:10.368Z | scranton.dmevals.local | windows.sysmon | win.TargetObject | HKLM\SAM\SAM\Domains\Account\F | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItO9rO3D | q-dfbd56f0fb | ok |
| 2 | 2020-05-02 03:19:10.368Z | scranton.dmevals.local | windows.sysmon | win.Image | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItO9rO3D | q-dfbd56f0fb | ok |

### F04 · benign / high · T1003.005 · HKLM\SECURITY\Cache (NL$) writes by lsass.exe (benign)

Evidence status: **verified**

Registry value sets on HKLM\SECURITY\Cache\NL$1 on nashua.dmevals.local were performed by C:\windows\system32\lsass.exe (PID 728) at 03:11-03:15Z. These are normal cached-domain-credential updates written by LSASS itself, not an attacker reading or dumping the cache.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:40.144Z | nashua.dmevals.local | windows.sysmon | win.TargetObject | HKLM\SECURITY\Cache\NL$1 | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTVGQnT | q-d36cf40b8b | ok |
| 2 | 2020-05-02 03:11:40.144Z | nashua.dmevals.local | windows.sysmon | win.Image | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTVGQnT | q-d36cf40b8b | ok |

### F05 · benign / high · T1040 · Azure Network Watcher netsh packet capture on scranton (benign, legitimate Azure agent)

Evidence status: **verified**

On scranton.dmevals.local, the Azure Network Watcher agent (NetworkWatcherAgent.exe, launched by services.exe / cmd.exe from the WindowsAzure GuestAgent) started a packet capture via 'netsh trace start capture=yes' writing to C:\windows\TEMP\...etl, then stopped it. This is the built-in Azure Network Watcher packet-capture feature, not adversary sniffing. No pcap/npcap/winpcap driver was loaded and no third-party capture tool was executed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:17.154Z | scranton.dmevals.local | windows.sysmon | process.command_line | C:\windows\system32\netsh.exe trace start capture=yes traceFile="C:\windows\TEMP\E7116ECA-DFE6-43C7-8FA8-8D3AC5AA8726\B91E06C5-1C7C-4830-9A76-74FA211560A7.etl" | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItPM8kte | q-6cfb643b20 | ok |
| 2 | 2020-05-02 03:19:13.877Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\Packages\Plugins\Microsoft.Azure.NetworkWatcher.NetworkWatcherAgentWindows\1.4.1421.1\NetworkWatcherAgent\NetworkWatcherAgent.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItO9qRCx | q-6cfb643b20 | ok |
| 3 | 2020-05-02 03:19:17.000Z | scranton.dmevals.local | windows.security | process.parent.executable | C:\Packages\Plugins\Microsoft.Azure.NetworkWatcher.NetworkWatcherAgentWindows\1.4.1421.1\NetworkWatcherAgent\NetworkWatcherAgent.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItVt4o2y | q-45025c9d24 | ok |

### F06 · benign / high · T1040 · No packet-capture tooling or capture drivers found on any host

Evidence status: **verified**

Hunting for sniffing tools across the Windows datasets returned no evidence of network sniffing: no tcpdump/windump/wireshark/rawcap executables, no pcap/npcap/winpcap/ndiscap/netmon driver loads (sysmon event 6), and no pcap/sniff/promiscuous strings in PowerShell script blocks. The only capture-related activity is the legitimate Azure Network Watcher netsh trace.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:17.154Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\Windows\System32\netsh.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItPM8kte | q-6cfb643b20 | ok |

### F10 · benign / medium · T1056.001 · No keylogger-specific indicators observed

Evidence status: **verified**

No process command lines or PowerShell script blocks containing keylogger APIs (GetAsyncKeyState, SetWindowsHookEx, 'keylog') were found; the checks for those returned zero hits. The LSASS/winlogon process accesses observed are credential-memory reads (T1056/T1056.004), not keyboard input capture. The high-volume Sysmon process-access events to lsass/winlogon/explorer are dominated by legitimate svchost.exe (0x1000) and system processes.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:01:03.622Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1000 | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTtmJQ5 | q-fa59f1d49a | ok |

### F11 · benign / medium · T1056.002 · No GUI input capture indicators observed

Evidence status: **verified**

No PowerShell script blocks or process command lines referencing credential prompts (Get-Credential, Read-Host, CredentialManager) were found; the corresponding checks returned zero hits. No GUI input-capture activity is evidenced in the retrieved data.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:16:36.000Z | newyork.dmevals.local | windows.powershell | win.ScriptBlockText | Set-Alias -Name rcim -Value Remove-cimInstance -Option ReadOnly, AllScope -ErrorAction SilentlyContinue | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZRkUeo | q-12a16f098c | ok |

### F12 · benign / medium · T1056.003 · No web portal capture indicators observed

Evidence status: **verified**

No file writes to web roots (wwwroot/inetpub/login), no IIS/w3wp process activity, and no HTTP POST or login/portal URLs were found; the corresponding checks returned zero hits. The zeek dataset does not overlap in time with the Windows datasets, so no web-portal capture is evidenced.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:16:36.000Z | newyork.dmevals.local | windows.powershell | win.ScriptBlockText | Set-Alias -Name gcls -Value Get-CimClass -Option ReadOnly, AllScope -ErrorAction SilentlyContinue | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZRkUep | q-12a16f098c | ok |

### F13 · benign / high · T1110 · No brute-force authentication activity observed on Windows hosts

Evidence status: **verified**

Across windows.security (41002 events, 2020-05-02T02:55:25Z..03:28:09Z), windows.other, windows.powershell and windows.sysmon there are zero failed-logon events (4625) and no authentication-failure or account-lockout messages. The only authentication-related hits are successful explicit-credential logons (4648) from PsExec (C:\Windows\PSEXESVC.exe) and normal system logons, plus a single successful NTLM validation (4776, Status 0x0) for pbeesly on newyork.dmevals.local. No brute-force pattern is present.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:20:40.000Z | newyork.dmevals.local | windows.security | win.Status | 0x0 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItVn1FNc | q-fa3ec49aaf | ok |
| 2 | 2020-05-02 03:11:40.000Z | nashua.dmevals.local | windows.security | process.executable | C:\Windows\PSEXESVC.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItZ7Ev8p | q-ac01685190 | ok |

### F14 · benign / high · T1110.001 · No password-guessing activity (no failed logons, no password tooling)

Evidence status: **verified**

No 4625 failed-logon events exist in windows.security, and no process command lines referencing passwords were found in windows.sysmon (event.code:1 with *password* returned zero). The only 'password'/'failed'-adjacent hits in windows.other were unrelated system messages (a crash-dump init failure and a DNS PTR registration failure). Nothing indicates repeated password guessing.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:18:54.000Z | scranton.dmevals.local | windows.other | message | Crash dump initialization failed! | .ds-logs-windows.other-default-2026.10.17-000001 / AaFHNH1uOFchItbrX8RY | q-d764e36cb1 | ok |
| 2 | 2020-05-02 03:19:20.000Z | scranton.dmevals.local | windows.other | message | The system failed to register pointer (PTR) resource records (RRs) for network adapter  with settings:               Adapter Name : {3F54D943-1568-43BC-9FDA-67D… | .ds-logs-windows.other-default-2026.10.17-000001 / AaFHNH1uOFchItbrX8Rb | q-d764e36cb1 | ok |

### F15 · benign / high · T1110.002 · No password-cracking artifacts; LSASS/SAM access is benign system behavior

Evidence status: **verified**

No reads of the SAM/SECURITY registry hive were found (event.code:4663 with win.ObjectName == 'SAM' returned zero rows; the 'SAM' bucket in the aggregate was a substring match on unrelated object names). No hash/crack command lines (C113 zero), no PowerShell credential/hash scripts (C103/C109/C116/C123/C129 zero). LSASS handle opens (326 total) are dominated by svchost.exe with GrantedAccess 0x1000 (PROCESS_QUERY_LIMITED_INFORMATION), i.e. routine system access, not credential dumping for offline cracking. The only 'passwordsDB' file creation is by Sysinternals accesschk.exe, a benign tooling artifact.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:24:18.178Z | nashua.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1000 | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItOYDnci | q-326308520f | ok |
| 2 | 2020-05-02 03:04:35.069Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Program Files\SysinternalsSuite\passwordsDB | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTkbkGF | q-0555bd48af | ok |

### F16 · benign / high · T1110.003 · No password-spraying activity; 4648 logons are PsExec and normal system logons

Evidence status: **verified**

No 4625 failed logons exist, so no spray pattern is present. The 15 explicit-credential logons (4648) are 4 from C:\Windows\PSEXESVC.exe on nashua.dmevals.local (PsExec lateral movement by pbeesly) and normal system logons from winlogon.exe/wininit.exe/taskhostw.exe/svchost.exe on scranton.dmevals.local. No process command lines referencing user lists were found (C124 only userinit.exe).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:40.000Z | nashua.dmevals.local | windows.security | win.TargetUserName | pbeesly | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItZ7Ev8p | q-ac01685190 | ok |
| 2 | 2020-05-02 03:19:10.000Z | scranton.dmevals.local | windows.security | win.ProcessName | C:\Windows\System32\winlogon.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItV19Rnb | q-630a64acfb | ok |

### F17 · benign / high · T1110.004 · No credential-stuffing activity observed

Evidence status: **verified**

No failed logons (4625) and no credential-related logon messages indicating stuffing. The windows.other 'credential' hits are a Credential Guard configuration line and unrelated system messages. No password/credential command lines in sysmon (C130 zero) and no PowerShell credential scripts (C129 zero). The only successful credential use is the legitimate pbeesly RDP session (Source Network Address 172.18.39.2) and PsExec logons.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:09.000Z | scranton.dmevals.local | windows.other | message | Credential Guard configuration: 0x0, 0 | .ds-logs-windows.other-default-2026.10.17-000001 / AaFHNH1uOFchItbrX8R_ | q-ea554e6cf7 | ok |
| 2 | 2020-05-02 03:20:48.000Z | scranton.dmevals.local | windows.other | message | Remote Desktop Services: Session logon succeeded:    User: DMEVALS\pbeesly  Session ID: 2  Source Network Address: 172.18.39.2 | .ds-logs-windows.other-default-2026.10.17-000001 / AaFHNH1uOFchItbrX8RS | q-682b4f059d | ok |

### F18 · benign / medium · T1111 · No MFA interception artifacts; observed credential activity is explicit-credential logon (PsExec lateral movement)

Evidence status: **verified**

Hunting for T1111 (MFA Interception) across windows.security, windows.sysmon, windows.other and windows.powershell found no evidence of MFA/smart-card/token interception. The 4648 explicit-credential logons on nashua.dmevals.local and scranton.dmevals.local show the account pbeesly's credentials being used by C:\Windows\PSEXESVC.exe (PsExec service) and svchost.exe targeting 'localhost' — this is credential USE for lateral movement, not interception of an MFA factor. Logon types are ordinary (2 interactive, 3 network, 5 service, 10 RDP). The only 'Credential'-named registry writes are benign Windows components: lsass.exe setting DeviceGuard\Scenarios\CredentialGuard\Enabled to 0x0 (Credential Guard not enabled) and services.exe registering the built-in CredentialEnrollmentManagerUserSvc service. Registry 'Token' hits are all Windows ContentManagementSDK\DeviceTokens\MSA writes by backgroundTaskHost.exe (normal OS behavior). No smartcard/MFA/token command lines or credential-provider tampering were observed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:40.000Z | nashua.dmevals.local | windows.security | process.executable | C:\Windows\PSEXESVC.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItZ7Ev8p | q-0ae28fc9a5 | ok |
| 2 | 2020-05-02 03:11:40.000Z | nashua.dmevals.local | windows.security | win.TargetServerName | localhost | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItZ7Ev8p | q-0ae28fc9a5 | ok |
| 3 | 2020-05-02 03:20:46.000Z | scranton.dmevals.local | windows.security | process.executable | C:\Windows\System32\svchost.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItVn01NG | q-9a408c2d69 | ok |
| 4 | 2020-05-02 03:19:09.865Z | scranton.dmevals.local | windows.sysmon | registry.path | HKLM\System\CurrentControlSet\Control\DeviceGuard\Scenarios\CredentialGuard\Enabled | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItO9rO3Z | q-ed825ef790 | ok |
| 5 | 2020-05-02 03:19:09.865Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItO9rO3Z | q-ed825ef790 | ok |
| 6 | 2020-05-02 03:19:09.000Z | scranton.dmevals.local | windows.other | message | Credential Guard configuration: 0x0, 0 | .ds-logs-windows.other-default-2026.10.17-000001 / AaFHNH1uOFchItbrX8R_ | q-77b6441167 | ok |
| 7 | 2020-05-02 02:59:16.458Z | scranton.dmevals.local | windows.sysmon | registry.path | \REGISTRY\A\{4d47dc8a-e1ef-3a84-d6d7-68121fc34e62}\LocalState\ContentManagementSDK\DeviceTokens\MSA\Value | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItT_4wsv | q-c54d5e722c | ok |
| 8 | 2020-05-02 02:59:16.458Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\backgroundTaskHost.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItT_4wsv | q-c54d5e722c | ok |

### F20 · benign / high · T1187 · Benign machine-account SMB share access (SYSVOL/IPC$/ADMIN$) on newyork

Evidence status: **verified**

The 163 windows.security 5140/5145 share-access events on 2020-05-02 are normal domain traffic: machine accounts NEWYORK$, SCRANTON$, NASHUA$, UTICA$ and WEC$ accessing \\*\SYSVOL, \\*\IPC$ and \\*\ADMIN$ from internal addresses (10.0.1.4, 10.0.1.5, 10.0.1.6, 10.0.1.10, fe80::e40c:95b6:b0a7:6429). Corresponding 4624 LogonType 3 events are all machine-account ($) network logons between domain hosts. No user credentials are coerced and no external/attacker-controlled destination appears, so these share events are not forced authentication.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:56:47.000Z | newyork.dmevals.local | windows.security | win.ShareName | \\*\SYSVOL | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItaKWxp4 | q-c4fa459d20 | ok |
| 2 | 2020-05-02 03:01:43.000Z | newyork.dmevals.local | windows.security | user.name | SCRANTON$ | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItaFQQtn | q-c4fa459d20 | ok |
| 3 | 2020-05-02 03:24:13.000Z | newyork.dmevals.local | windows.security | win.TargetUserName | SCRANTON$ | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItVcwORA | q-4dda1d0e0b | ok |

### F23 · benign / medium · T1212 · Kerberos service-ticket requests and DCE-RPC auth anomalies — no exploitation observed

Evidence status: **verified**

The Kerberos hits (28x 4769, 14x 4768) are routine service-ticket requests by pbeesly@DMEVALS.LOCAL and machine accounts (SCRANTON$, NEWYORK$, NASHUA$) from internal addresses 10.0.1.4/10.0.1.6 — normal domain authentication, no anomalous encryption downgrade or ticket-forging indicators. The Zeek weird/notice records (ip_hdr_len_zero, truncated_IP, unknown_dce_rpc_auth_type, self-signed cert) are protocol-level anomalies on the 2020-04-30 window that does not overlap the Windows telemetry, and none show exploit payloads or credential theft. No evidence of exploitation-for-credential-access in these sources.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:09:04.000Z | newyork.dmevals.local | windows.security | message | A Kerberos service ticket was requested.    Account Information:  	Account Name:		pbeesly@DMEVALS.LOCAL  	Account Domain:		DMEVALS.LOCAL  	Logon GUID:		{6fdaf3e… | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItZ8FraW | q-cc1e582a0c | ok |
| 2 | 2020-04-30 00:14:21.969Z | simplerockbuild.simplerock.lan | zeek | message | {"@stream":"weird","@system":"simplerockbuild.simplerock.lan","@proc":"zeek","ts":1588205661.969959,"uid":"C3HnI71C1OMdjvWltf","id_orig_h":"10.0.1.4","id_orig_p… | .ds-logs-zeek-default-2026.10.17-000001 / AaFHNX1uOFchItbgrYiq | q-b6a20aca86 | ok |

### F24 · benign / high · T1539 · WebDAV DavSetCookie via rundll32/davclnt.dll on scranton (benign Windows WebDAV redirector)

Evidence status: **verified**

On scranton.dmevals.local, user pbeesly spawned rundll32.exe loading davclnt.dll with the DavSetCookie export five times (2020-05-02 03:08:50 and 03:10:22-03:10:23), parent process svchost.exe. The command line 'rundll32.exe C:\windows\system32\davclnt.dll,DavSetCookie 192.168.0.4 http://192.168.0.4/webdav' is the Windows WebDAV redirector storing a WebDAV authentication cookie for the http://192.168.0.4/webdav share. This is a WebDAV client cookie, not a browser/web-application session cookie, and is normal Windows behaviour when a WebDAV path is accessed. No browser cookie store was read or exfiltrated.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:08:50.000Z | scranton.dmevals.local | windows.security | process.command_line | rundll32.exe C:\windows\system32\davclnt.dll,DavSetCookie 192.168.0.4 http://192.168.0.4/webdav | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItZ8Frba | q-dc1d2b4135 | ok |
| 2 | 2020-05-02 03:08:50.000Z | scranton.dmevals.local | windows.security | process.parent.executable | C:\Windows\System32\svchost.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItZ8Frba | q-dc1d2b4135 | ok |
| 3 | 2020-05-02 03:10:23.154Z | scranton.dmevals.local | windows.sysmon | process.command_line | rundll32.exe C:\windows\system32\davclnt.dll,DavSetCookie 192.168.0.4 http://192.168.0.4/webdav | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTVHe6C | q-1a5520809c | ok |

### F25 · benign / high · T1539 · INetCookies file created by LocalService svchost on scranton (benign service cookie store)

Evidence status: **verified**

Sysmon file-create event on scranton.dmevals.local at 2020-05-02T03:21:05.681Z shows C:\windows\System32\svchost.exe (PID 7200, SYSTEM) creating C:\Windows\ServiceProfiles\LocalService\AppData\Local\Packages\warp_jit_db4a1097-b484-4973-bbf2-a04208ecd4d4\AC\INetCookies. This is a Windows service writing its own per-package INetCookies store under the LocalService profile, not access to or theft of a browser session cookie database. No browser cookie file (Chrome/Edge/Firefox Cookies) was touched.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:21:05.681Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Windows\ServiceProfiles\LocalService\AppData\Local\Packages\warp_jit_db4a1097-b484-4973-bbf2-a04208ecd4d4\AC\INetCookies | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItOVAUl3 | q-d984ae27b1 | ok |
| 2 | 2020-05-02 03:21:05.681Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\System32\svchost.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItOVAUl3 | q-d984ae27b1 | ok |

### F30 · benign / high · T1552.002 · Registry Password/Credential value sets are Windows service and identity components

Evidence status: **verified**

Sysmon registry SetValue events matching Password/Credential keys on nashua.dmevals.local and scranton.dmevals.local are all written by legitimate Windows components: svchost.exe setting HKU\.DEFAULT\Software\Microsoft\IdentityCRL\ProviderPasswordLength/CharacterGroups, lsass.exe setting the DeviceGuard CredentialGuard\Enabled value, services.exe registering the CredentialEnrollmentManagerUserSvc service, and winlogon.exe setting the Winlogon PasswordExpiryNotification value. These are normal OS/identity operations, not adversary credential storage in the registry.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:28.255Z | nashua.dmevals.local | windows.sysmon | win.TargetObject | HKU\.DEFAULT\Software\Microsoft\IdentityCRL\ProviderPasswordLength | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItThYt63 | q-673272504b | ok |
| 2 | 2020-05-02 03:19:09.865Z | scranton.dmevals.local | windows.sysmon | win.TargetObject | HKLM\System\CurrentControlSet\Control\DeviceGuard\Scenarios\CredentialGuard\Enabled | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItO9rO3Z | q-673272504b | ok |
| 3 | 2020-05-02 03:21:20.841Z | scranton.dmevals.local | windows.sysmon | win.TargetObject | HKU\S-1-5-21-1830255721-3727074217-2423397540-1107\Software\Microsoft\Windows\Winlogon\PasswordExpiryNotification\NotShownTime | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItKT-1UH | q-673272504b | ok |

### F29 · benign / high · T1552.006 · Group Policy SecEdit/GptTmpl.inf file access by svchost.exe (normal Group Policy processing)

Evidence status: **verified**

Sysmon file-create events show C:\Windows\System32\GroupPolicy\DataStore\0\sysvol\dmevals.local\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf being written on scranton.dmevals.local. The writing process is C:\windows\system32\svchost.exe (the Group Policy client), which is the expected behaviour of a domain-joined machine applying its GPO. No Groups.xml/cpassword access or GPP credential extraction was observed, so this is routine Group Policy activity rather than adversary GPP abuse.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:01:43.091Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Windows\System32\GroupPolicy\DataStore\0\sysvol\dmevals.local\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.in… | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTqhAkt | q-341c0b0e3e | ok |
| 2 | 2020-05-02 03:01:43.091Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\svchost.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTqhAkt | q-341c0b0e3e | ok |
| 3 | 2020-05-02 03:01:43.091Z | scranton.dmevals.local | windows.sysmon | host.name | scranton.dmevals.local | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTqhAkt | q-341c0b0e3e | ok |

### F33 · benign / high · T1555.003 · No browser credential-store access observed

Evidence status: **verified**

Checks for browser credential theft (C209-C214) returned no hits: no process command lines referencing Login Data / logins.json / browser credential files, no file-creation events for browser credential stores, no process-access events targeting chrome.exe/firefox.exe, and no matching object-access or PowerShell script content. The only browser-related LSASS event is lsass.exe opening MicrosoftEdge.exe (0x1000/0x1478), which is normal Edge/Windows behaviour, not credential theft. No evidence of web-browser credential harvesting in this dataset.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:21:05.057Z | scranton.dmevals.local | windows.sysmon | win.TargetImage | C:\Windows\SystemApps\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\MicrosoftEdge.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItOVAkmV | q-99bea5d958 | ok |

### F35 · benign / medium · T1556.001 · Network logons and explicit-credential logons are normal domain/PSEXESVC activity, no DC authentication backdoor

Evidence status: **verified**

Type-3 network logons (4624) on newyork.dmevals.local are machine-account (NEWYORK$) authentications from ::1, link-local and 10.0.0.4 addresses, consistent with normal domain computer-account traffic. The 4648 explicit-credential events show pbeesly's own credentials being used by C:\Windows\PSEXESVC.exe on nashua.dmevals.local (Target Server 'localhost') and from scranton.dmevals.local to target server NASHUA — consistent with PsExec-style lateral movement using the user's own credentials, not a DC authentication-process backdoor.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:55:54.000Z | newyork.dmevals.local | windows.security | user.name | NEWYORK$ | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItaKXhpQ | q-bc461a94ba | ok |
| 2 | 2020-05-02 03:11:40.000Z | nashua.dmevals.local | windows.security | process.executable | C:\Windows\PSEXESVC.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItZ7Ev8p | q-cfb18a77f5 | ok |
| 3 | 2020-05-02 03:11:18.000Z | scranton.dmevals.local | windows.security | win.TargetServerName | NASHUA | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItZ7Ev9J | q-cfb18a77f5 | ok |

### F36 · benign / medium · T1556.002 · No password filter DLL registration or LSA notification package modification observed

Evidence status: **verified**

Searches for password-filter/notification-package artifacts returned no hits: no 4657 registry changes to Notification Packages/Password/lsass keys, no 4688 process creation with Notification/PasswordFilter command lines, and no 4104 script blocks referencing Notification/PasswordFilter/lsass. Registry writes matching 'Notification' were only benign Windows notification-store keys (HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Notifications\Data\...) written by Explorer/RuntimeBroker/backgroundTaskHost. No password filter DLL was registered.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:58:09.240Z | scranton.dmevals.local | windows.sysmon | registry.path | HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Notifications\Data\418A073AA3BC3475 | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHNH1uOFchItQC7zHD | q-47496adea8 | ok |
| 2 | 2020-05-02 02:58:09.240Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\Explorer.EXE | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHNH1uOFchItQC7zHD | q-47496adea8 | ok |

### F37 · benign / medium · T1556.005 · No reversible-encryption / AllowReversiblePasswordEncryption activity observed

Evidence status: **verified**

No hits for reversible-encryption indicators: no 4739 (domain policy change) events, no 4688/1 process creations with Reversible/Set-ADUser/dsmod command lines, and no 4104/4103 script blocks referencing AllowReversiblePasswordEncryption or ReversibleEncryption. No evidence that account password storage was switched to reversible encryption.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:18.000Z | scranton.dmevals.local | windows.security | event.code | 4648 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItZ7Ev9J | q-40a7cb651f | ok |

### F38 · benign / medium · T1556.006 · No MFA modification activity observed

Evidence status: **verified**

No 4739 domain-policy-change events and no 5136 directory-service-change events were found, and no process/script activity referencing Set-ADUser/Set-ADAccountControl or MFA-related changes. No evidence of multi-factor authentication being disabled or modified.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:18.000Z | scranton.dmevals.local | windows.security | event.code | 4648 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItZ7Ev9J | q-40a7cb651f | ok |

### F39 · benign / medium · T1556.007 · No hybrid-identity / cloud-connect activity observed

Evidence status: **verified**

No 5136 directory-service-change events and no PowerShell script blocks referencing Connect-MsolService/Connect-AzureAD or similar hybrid-identity cmdlets were found. No evidence of hybrid identity authentication modification.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZCgBha | q-1b7617d472 | ok |

### F40 · benign / medium · T1556.008 · No network provider DLL registration observed

Evidence status: **verified**

No 4657 registry changes to NetworkProvider/Credential keys and no PowerShell script blocks referencing NetworkProvider/New-ItemProperty were found. No evidence of a malicious network provider DLL being registered to capture credentials.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:58:09.240Z | scranton.dmevals.local | windows.sysmon | registry.path | HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Notifications\Data\418A073AA3BC3475 | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHNH1uOFchItQC7zHD | q-47496adea8 | ok |

### F41 · benign / high · T1557 · Network capture/ARP enumeration on scranton is Azure Guest Agent telemetry, not AiTM

Evidence status: **verified**

On scranton.dmevals.local (2020-05-02 ~03:19Z) SYSTEM ran 'netsh trace start capture=yes' writing an ETL to C:\windows\TEMP\<GUID>\...etl, 'netsh trace stop', 'ipconfig.exe /all' and 'arp.exe /a'. All of these are spawned by Azure guest-agent components (C:\WindowsAzure\Packages\WaAppAgent.exe, WindowsAzureGuestAgent.exe, WindowsAzureTelemetryService.exe, CollectGuestLogs.exe), i.e. routine Azure VM diagnostic/telemetry collection, not adversary-in-the-middle positioning. No Responder/MITM tooling was found in PowerShell script blocks.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:17.154Z | scranton.dmevals.local | windows.sysmon | process.command_line | C:\windows\system32\netsh.exe trace start capture=yes traceFile="C:\windows\TEMP\E7116ECA-DFE6-43C7-8FA8-8D3AC5AA8726\B91E06C5-1C7C-4830-9A76-74FA211560A7.etl" | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItPM8kte | q-73717aa89c | ok |
| 2 | 2020-05-02 03:20:04.471Z | scranton.dmevals.local | windows.sysmon | process.parent.executable | C:\WindowsAzure\Packages\WaAppAgent.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItOrW_1k | q-b91a06eb31 | ok |
| 3 | 2020-05-02 03:19:25.370Z | scranton.dmevals.local | windows.sysmon | process.parent.executable | C:\WindowsAzure\Packages\GuestAgent\WindowsAzureGuestAgent.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItPE0PcG | q-b91a06eb31 | ok |

### F42 · benign / high · T1557.001 · No name-resolution poisoning or SMB relay; SMB traffic is normal DC-bound domain traffic

Evidence status: **verified**

Sysmon DNS queries (event 22) are ordinary AD/Windows lookups (NEWYORK/NASHUA/SCRANTON, _ldap._tcp SRV records, wpad, Microsoft telemetry) with no LLMNR/NBT-NS poisoning pattern. Zeek SMB connections (port 445) all terminate in RSTO against the domain controller 10.0.0.4 and are tagged krb,smb,gssapi — normal authenticated domain traffic, not relayed authentication to an unauthorized host. The 23 Security 4697 service-install events are Windows default per-user services (svchost -k UnistackSvcGroup etc.) plus PSEXESVC from PsExec lateral movement, none of which is name-resolution poisoning or SMB relay.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-04-30 00:36:38.970Z | simplerockbuild.simplerock.lan | zeek | zeek.service | krb,smb,gssapi | .ds-logs-zeek-default-2026.10.17-000001 / AaFHNX1uOFchItbgroge | q-0596d90661 | ok |
| 2 | 2020-04-30 00:36:38.970Z | simplerockbuild.simplerock.lan | zeek | destination.ip | 10.0.0.4 | .ds-logs-zeek-default-2026.10.17-000001 / AaFHNX1uOFchItbgroge | q-0596d90661 | ok |
| 3 | 2020-05-02 03:15:03.000Z | nashua.dmevals.local | windows.security | win.ServiceName | PSEXESVC | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItZ7DT5G | q-86ca22fea6 | ok |

### F43 · benign / high · T1557.002 · Synthetic placeholder MAC in Zeek capture is a lab artifact, not ARP cache poisoning

Evidence status: **verified**

In the Zeek capture the responder L2 address 12:34:56:78:9a:bc appears on 559 of 613 connections — a well-known synthetic/placeholder MAC used in test datasets, not a real host claiming multiple IPs. The only ARP-related process activity is 'arp.exe /a' on scranton.dmevals.local, spawned by Azure guest-agent/telemetry components (WaAppAgent.exe, WindowsAzureGuestAgent.exe, WindowsAzureTelemetryService.exe), i.e. routine diagnostic enumeration. No gratuitous-ARP or duplicate MAC-to-IP mapping indicative of ARP cache poisoning was observed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-04-30 00:45:00.056Z | simplerockbuild.simplerock.lan | zeek | zeek.resp_l2_addr | 12:34:56:78:9a:bc | .ds-logs-zeek-default-2026.10.17-000001 / AaFHNX1uOFchItbgrohb | q-5440ebf61e | ok |
| 2 | 2020-05-02 03:19:40.288Z | scranton.dmevals.local | windows.sysmon | process.command_line | "arp.exe" /a | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItOtYA8Z | q-b91a06eb31 | ok |
| 3 | 2020-05-02 03:19:40.288Z | scranton.dmevals.local | windows.sysmon | process.parent.executable | C:\WindowsAzure\Packages\Telemetry\WindowsAzureTelemetryService.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItOtYA8Z | q-b91a06eb31 | ok |

### F44 · benign / high · T1557.003 · No DHCP activity present in any dataset — DHCP spoofing not observable

Evidence status: **verified**

No DHCP-related telemetry exists in the collected data: windows.other contains no DHCP event codes (1341/1342/1020/1063), the Zeek capture has no dhcp log type (only conn/dns/http/ssl/kerberos/dce_rpc/smb_*), and Sysmon network-connect events show no traffic to DHCP ports 67/68. The only DHCP-adjacent process is the legitimate 'svchost.exe -k LocalServiceNetworkRestricted -p -s Dhcp' service on scranton. With no DHCP client/server events captured, DHCP spoofing cannot be confirmed or refuted from this data.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:11.533Z | scranton.dmevals.local | windows.sysmon | process.command_line | C:\windows\system32\svchost.exe -k LocalServiceNetworkRestricted -p -s Dhcp | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItPF0sG6 | q-73717aa89c | ok |

### F48 · benign / low · T1558.002 · No silver-ticket (forged service ticket) evidence observed

Evidence status: **verified**

The 4769 service-ticket requests observed (NASHUA$, NEWYORK$, SCRANTON$, WEC$) all returned Failure Code 0x0 (success) and were issued by the KDC to legitimate principals; no service ticket was used without a corresponding KDC-issued request, and no anomalous service-account logon followed. No silver-ticket forging artifact was identified in the available telemetry.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:04.000Z | newyork.dmevals.local | windows.security | win.Status | 0x0 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItaDOKC- | q-5c6f82aa56 | ok |

### F49 · benign / low · T1558.004 · No AS-REP roasting evidence observed

Evidence status: **verified**

No AS-REP roasting indicators were found: PowerShell script-block searches for AS-REP/GetNPUsers/DontRequirePreAuth returned zero hits, and no 4768 pre-authentication-disabled ticket requests were observed in the security log. The Kerberos activity present is TGS-request based, not AS-REP based.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:04.000Z | newyork.dmevals.local | windows.security | win.TicketOptions | 0x60810010 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItaDOKC- | q-5c6f82aa56 | ok |

### F50 · benign / medium · T1606 · No forged web credential activity; LSASS access hits are benign system/PowerShell tooling

Evidence status: **verified**

Across the 2020-05-02 02:55–03:28Z window on scranton/newyork/nashua/utica.dmevals.local there is no evidence of web-credential forging. The only LSASS process-access events with high access masks came from legitimate Windows binaries: PowerShell.exe (PID 2976) opening lsass.exe with GrantedAccess 0x1FFFFF on scranton at 03:05:16Z, and wsmprovhost.exe (PID 7720) opening lsass.exe with 0x1F3FFF on nashua at 03:09:29Z (call trace through .NET/PowerShell Management native images). The remaining high-mask accesses (0x3000, 0x101001, 0x1000000) were svchost.exe/wininit.exe/csrss.exe on scranton. Logon process names for 4624/4648 were Kerberos (217), Advapi (76), User32 (2), NtLmSsp (1) — no anomalous authentication package. The 5857/5858 WMI events on newyork are routine RSOP_ExtensionStatus DeleteInstance operations by NT AUTHORITY\SYSTEM (ClientProcessId 1588) with ResultCode 0x80041002. No cookie/SAML/token forging tooling was observed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTka0Gm | q-51b4aec113 | ok |
| 2 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTka0Gm | q-331d8d1f6f | ok |
| 3 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHNH1uOFchItUHCTY0 | q-1d86e9cc7c | ok |
| 4 | 2020-05-02 02:56:47.000Z | newyork.dmevals.local | windows.other | message | Id = {C11E1664-7828-4AD0-B23A-0FCEF0EA26C0}; ClientMachine = NEWYORK; User = NT AUTHORITY\SYSTEM; ClientProcessId = 1588; Component = Unknown; Operation = Start… | .ds-logs-windows.other-default-2026.10.17-000001 / AaFHNH1uOFchItbrX8Rl | q-14b06cb672 | ok |

### F51 · benign / medium · T1606.001 · Single INetCookies file event is a ServiceProfiles LocalService artifact, not cookie theft/forgery

Evidence status: **verified**

The only file-creation event matching cookie paths in the whole window is on scranton.dmevals.local at 2020-05-02T03:21:05.681Z, created by C:\windows\System32\svchost.exe under the path C:\Windows\ServiceProfiles\LocalService\AppData\Local\Packages\warp_jit_db4a1097-b484-4973-bbf2-a04208ecd4d4\AC\INetCookies — a per-package LocalService container, not a user browser cookie store, and no user context. No PowerShell script block referenced cookie/Set-Cookie/session content (C344 zero hits), and the Zeek HTTP traffic in the non-overlapping 2020-04-30 window is WebDAV OPTIONS/PROPFIND from 10.0.1.4 to 192.168.0.4 with user agents DavClnt and Microsoft-WebDAV-MiniRedir/10.0.18362, with no cookie-bearing web authentication. No forged web cookie activity observed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:21:05.681Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Windows\ServiceProfiles\LocalService\AppData\Local\Packages\warp_jit_db4a1097-b484-4973-bbf2-a04208ecd4d4\AC\INetCookies | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItOVAUl3 | q-d8124967af | ok |
| 2 | 2020-05-02 03:21:05.681Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\System32\svchost.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItOVAUl3 | q-d8124967af | ok |
| 3 | 2020-04-30 00:32:18.095Z | simplerockbuild.simplerock.lan | zeek | user_agent.original | DavClnt | .ds-logs-zeek-default-2026.10.17-000001 / AaFHNX1uOFchItbgrYjF | q-d6a6ad4ac9 | ok |

### F53 · benign / high · T1621 · WMI provider/RSOP activity in windows.other is benign Group Policy processing, not MFA request generation

Evidence status: **verified**

The only T1621 check with hits (C355) matched WMI event codes 5857/5858/5860 in windows.other. Reading the events shows standard WMI provider starts (wmiprvse.exe hosting wmiprov.dll, sppwmi.dll, bcdprov.dll, tscfgwmi.dll) and RSOP_ExtensionStatus DeleteInstance operations under Root\Rsop\Computer, all executed by NT AUTHORITY\SYSTEM / NETWORK SERVICE. These are routine Group Policy / WMI provider lifecycle events on newyork, scranton, nashua and utica, with no authentication-request or MFA-prompt semantics. No MFA fatigue / push-spam activity is present.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:56:47.000Z | newyork.dmevals.local | windows.other | message | Id = {C11E1664-7828-4AD0-B23A-0FCEF0EA26C0}; ClientMachine = NEWYORK; User = NT AUTHORITY\SYSTEM; ClientProcessId = 1588; Component = Unknown; Operation = Start… | .ds-logs-windows.other-default-2026.10.17-000001 / AaFHNH1uOFchItbrX8Rl | q-b727fc4189 | ok |
| 2 | 2020-05-02 02:56:47.000Z | newyork.dmevals.local | windows.other | user.name | SYSTEM | .ds-logs-windows.other-default-2026.10.17-000001 / AaFHNH1uOFchItbrX8Rl | q-b727fc4189 | ok |
| 3 | 2020-05-02 02:56:47.000Z | newyork.dmevals.local | windows.other | event.code | 5858 | .ds-logs-windows.other-default-2026.10.17-000001 / AaFHNH1uOFchItbrX8Rl | q-b727fc4189 | ok |

### F54 · benign / high · T1621 · No MFA/authenticator/push activity in PowerShell, security, sysmon or zeek logs

Evidence status: **verified**

Searches for MFA-related content returned nothing: no PowerShell script blocks containing mfa/authenticator/2fa/push (0 rows), no failed-logon events 4625/4771 in windows.security (0 rows), and no MFA/login/auth URLs in zeek HTTP (only WebDAV file-transfer requests such as /webdav/OfficeSupplies.7z). The only authentication-adjacent activity is explicit-credential logons (event 4648) by user 'pbeesly' via PsExec (C:\Windows\PSEXESVC.exe) on nashua and scranton — this is credential use / lateral movement, not multi-factor authentication request generation. No evidence of T1621 in this environment.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:15:03.000Z | nashua.dmevals.local | windows.security | win.ProcessName | C:\Windows\PSEXESVC.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItZ7DD7u | q-5cf213092e | ok |
| 2 | 2020-05-02 03:15:03.000Z | nashua.dmevals.local | windows.security | win.TargetUserName | pbeesly | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItZ7DD7u | q-5cf213092e | ok |
| 3 | 2020-05-02 03:15:03.000Z | nashua.dmevals.local | windows.security | host.name | nashua.dmevals.local | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItZ7DD7u | q-5cf213092e | ok |

### F56 · benign / high · T1649 · Routine certificate-store registry writes by legitimate Windows system processes

Evidence status: **verified**

The bulk of certificate/crypto registry activity in windows.sysmon (1133 events matching Certificate/Crypto/Keys) and the windows.security 4657 hit on \REGISTRY\MACHINE\SOFTWARE\Microsoft\SystemCertificates\ROOT\Certificates\BE36A4562FB2EE05DBB3D32323ADF445084ED656 are attributable to normal OS components: lsass.exe updating AuthRoot certificate blobs, svchost.exe updating Windows Live ID Token Issuer and AuthRoot certificates, taskhostw.exe writing per-user ACRS PhysicalStores values, smss.exe writing the WOW6432Node SymbolicLinkValue, and the CertPropSvc instance of svchost.exe. These are standard certificate propagation/root-update operations, not adversary certificate theft.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:59:37.453Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItT2v6oH | q-d6f3cf33ad | ok |
| 2 | 2020-05-02 03:05:28.255Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\svchost.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItThYt7K | q-d6f3cf33ad | ok |
| 3 | 2020-05-02 03:20:49.745Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\taskhostw.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItO2iUEp | q-d6f3cf33ad | ok |
| 4 | 2020-05-02 03:19:09.192Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\System32\smss.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItPF08Hi | q-d6f3cf33ad | ok |
| 5 | 2020-05-02 03:16:19.000Z | nashua.dmevals.local | windows.security | win.ProcessName | C:\Windows\Sysmon.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItZ6CoZN | q-8b3f2ded6e | ok |
| 6 | 2020-05-02 03:19:11.990Z | scranton.dmevals.local | windows.sysmon | process.command_line | C:\windows\system32\svchost.exe -k netsvcs -s CertPropSvc | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItO9q-10 | q-11bfc1a332 | ok |

### F57 · benign / medium · T1649 · Kerberos TGT requests for pbeesly and SCRANTON$ are normal authentication

Evidence status: **verified**

The 14 Kerberos AS-REQ (event 4768) events in windows.security are TGT requests for pbeesly (9) and the machine account SCRANTON$ (5), all with Status 0x0 (success), TicketEncryptionType 0x12 (AES256) and TicketOptions 0x40810010, originating from 10.0.1.4/10.0.1.6. These are ordinary domain logon/TGT acquisitions and show no certificate-based (PKINIT) anomaly; they are not evidence of certificate theft or forging.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:18.000Z | newyork.dmevals.local | windows.security | win.TargetUserName | pbeesly | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItZ7Ef_w | q-cacd5e8a65 | ok |
| 2 | 2020-05-02 03:11:18.000Z | newyork.dmevals.local | windows.security | win.Status | 0x0 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItZ7Ef_w | q-cacd5e8a65 | ok |
| 3 | 2020-05-02 03:19:13.000Z | newyork.dmevals.local | windows.security | win.TargetUserName | SCRANTON$ | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItV3-aXJ | q-cacd5e8a65 | ok |
| 4 | 2020-05-02 03:11:18.000Z | newyork.dmevals.local | windows.security | win.TicketEncryptionType | 0x12 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItZ7Ef_w | q-cacd5e8a65 | ok |

## Technique conclusions

One line per technique in scope: status from the triage of its family; `not_observed` = checked, nothing found; `not_observable` = no dataset records it.

| Technique | Status | Reason |
|---|---|---|
| T1003 OS Credential Dumping | malicious | pbeesly on scranton ran a credential/secret-collection toolkit (Get-PrivateKeys, Invoke-Exfil, Invoke-SeaDukeStage) around the LSASS access. |
| T1003.001 LSASS Memory | malicious | PowerShell (pbeesly) opened lsass.exe with 0x1fffff (PROCESS_ALL_ACCESS) on scranton at 03:05:16, corroborating the anchored LSASS access. |
| T1003.002 Security Account Manager | malicious | lsass.exe created C:\Windows\debug\PASSWD.LOG and opened the SAM hive with KEY_ALL_ACCESS (0xf003f) on scranton at 03:19, consistent with SAM credential dumping. |
| T1003.003 NTDS | not_observed | No NTDS.dit access, vssadmin/diskshadow/ntdsutil activity found in any dataset. |
| T1003.004 LSA Secrets | not_observed | No LSA Secrets / SECURITY Policy Secrets access or lsadump activity found. |
| T1003.005 Cached Domain Credentials | benign | HKLM\SECURITY\Cache\NL$1 writes were normal LSASS cached-credential updates, not dumping. |
| T1003.006 DCSync | not_observed | No DCSync / drsuapi / lsadump replication activity found in any dataset. |
| T1040 Network Sniffing | not_observed | No network sniffing activity found. The only packet-capture behavior is the legitimate Azure Network Watcher agent running 'netsh trace start capture=yes' on scranton.dmevals.local (parent NetworkWatcherAgent.exe from th… |
| T1056 Input Capture | malicious | PowerShell (pbeesly) and wsmprovhost.exe requested full-access handles (0x1f3fff/0x1fffff) to lsass.exe on scranton and nashua, indicating credential capture from LSASS memory. |
| T1056.001 Keylogging | not_observed | No keylogger APIs (GetAsyncKeyState/SetWindowsHookEx) or keylog strings in command lines or script blocks; those checks returned zero hits. |
| T1056.002 GUI Input Capture | not_observed | No credential-prompt/GUI input-capture indicators (Get-Credential, Read-Host, CredentialManager) found; checks returned zero hits. |
| T1056.003 Web Portal Capture | not_observed | No web-root file writes, IIS/w3wp activity, or login/portal HTTP requests; checks returned zero hits and zeek does not overlap in time. |
| T1056.004 Credential API Hooking | malicious | PowerShell script block on scranton reflectively resolves GetProcAddress/GetModuleHandle via UnsafeNativeMethods, builds a 'ReflectedDelegate' dynamic assembly and executes base64 shellcode in memory - native API hooking… |
| T1110 Brute Force | not_observed | Zero 4625 failed logons and no authentication-failure/lockout messages across all Windows datasets; only successful 4648/4776 logons. |
| T1110.001 Password Guessing | not_observed | No failed logons and no password-referencing process command lines; only unrelated system messages matched 'password'/'failed'. |
| T1110.002 Password Cracking | not_observed | No SAM/SECURITY hive reads, no hash/crack command lines; LSASS access is benign svchost 0x1000 queries and the only passwordsDB file is a Sysinternals accesschk artifact. |
| T1110.003 Password Spraying | not_observed | No failed logons to form a spray pattern; 4648 events are PsExec and normal system logons, no user-list tooling. |
| T1110.004 Credential Stuffing | not_observed | No failed logons or credential-stuffing indicators; only a Credential Guard config line and a legitimate RDP session logon. |
| T1111 Multi-Factor Authentication Interception | not_observed | No MFA/smart-card/token interception artifacts were found. 4648 explicit-credential logons reflect credential use by PSEXESVC.exe/svchost.exe (lateral movement), not interception. Credential-named registry writes are ben… |
| T1187 Forced Authentication | malicious | Host 10.0.1.4 (scranton) coerced its credentials to an attacker-controlled WebDAV/SMB listener at 192.168.0.4: SMB connections to tcp/445 and tcp/139 followed by 36 WebDAV OPTIONS/PROPFIND requests using Microsoft-WebDAV… |
| T1212 Exploitation for Credential Access | malicious | Obfuscated PowerShell reflective shellcode loader (UnsafeNativeMethods GetProcAddress/GetModuleHandle + DefineDynamicAssembly ReflectedDelegate + base64 PE blob) executed as user pbeesly on scranton.dmevals.local, corrob… |
| T1539 Steal Web Session Cookie | benign | All cookie-related hits are benign Windows behaviour: DavSetCookie via rundll32/davclnt.dll is the WebDAV redirector storing a WebDAV auth cookie (not a browser session cookie), and the INetCookies file creation is a Loc… |
| T1552 Unsecured Credentials | malicious | Multiple unsecured-credential artifacts: hardcoded passwords in scripts ('saribas', 'lolol', 'MyCozyPassw0rd!'), pspasswd staging, and password-protected archive staging. |
| T1552.001 Credentials In Files | malicious | pspasswd.exe/pspasswd64.exe staged in Downloads; Rar.exe created password-protected working.zip then sdelete64 wiped it; Invoke-Exfil compressed Downloads with password 'lolol' and exfiltrated using hardcoded creds. |
| T1552.002 Credentials in Registry | benign | All Password/Credential registry SetValue events are written by legitimate Windows components (svchost IdentityCRL, lsass CredentialGuard, services CredentialEnrollmentManagerUserSvc, winlogon PasswordExpiryNotification)… |
| T1552.003 Shell History | not_observed | No consolehost_history or shell-history access was found in sysmon/security telemetry. |
| T1552.004 Private Keys | malicious | Get-PrivateKeys exported all LocalMachine certificates to .pfx files protected by hardcoded password 'saribas' (coyn5igj.3io.pfx written to Downloads). |
| T1552.006 Group Policy Preferences | benign | GptTmpl.inf/SecEdit file writes are performed by svchost.exe (Group Policy client) as normal GPO processing; no Groups.xml/cpassword access observed. |
| T1555 Credentials from Password Stores | suspicious | LSASS full-access handle acquisition by attacker PowerShell/wsmprovhost is consistent with credential-store harvesting, but no explicit vault read was captured. |
| T1555.003 Credentials from Web Browsers | suspicious | Certificate/private-key export to .pfx via PowerShell is consistent with browser/credential-store harvesting, though no explicit browser credential store access was observed. |
| T1555.004 Windows Credential Manager | suspicious | Full-access LSASS handles by attacker processes on scranton/nashua are consistent with Credential Manager/DPAPI vault harvesting, but no vault file access was directly observed. |
| T1555.005 Password Managers | not_observed | No KeePass/1Password/Bitwarden/LastPass/.kdbx references in process, file, PowerShell or other-channel data. |
| T1556 Modify Authentication Process | suspicious | LSASS was opened with GrantedAccess 0x1FFFFF (PROCESS_ALL_ACCESS) by a hidden steganographic PowerShell loader (monkey.png -> IEX) on scranton.dmevals.local as pbeesly, indicating credential theft from LSASS memory. This… |
| T1556.001 Domain Controller Authentication | not_observed | Type-3 logons are machine-account (NEWYORK$) authentications and 4648 events are pbeesly's own credentials used by PSEXESVC for lateral movement; no DC authentication-process backdoor. |
| T1556.002 Password Filter DLL | not_observed | No password filter DLL registration, no Notification Packages registry change, no related process/script activity. |
| T1556.005 Reversible Encryption | not_observed | No 4739 policy changes and no Reversible/Set-ADUser/dsmod activity. |
| T1556.006 Multi-Factor Authentication | not_observed | No 4739/5136 events and no MFA-related process or script activity. |
| T1556.007 Hybrid Identity | not_observed | No 5136 events and no Connect-MsolService/Connect-AzureAD hybrid-identity activity. |
| T1556.008 Network Provider DLL | not_observed | No NetworkProvider/Credential registry changes and no related script activity. |
| T1557 Adversary-in-the-Middle | benign | Network capture/ARP enumeration on scranton is Azure Guest Agent telemetry (netsh trace, ipconfig /all, arp /a spawned by WaAppAgent/GuestAgent/TelemetryService); no AiTM tooling found. |
| T1557.001 Name Resolution Poisoning and SMB Relay | benign | DNS queries are normal AD/Windows lookups; SMB connections all RSTO to the DC 10.0.0.4 with krb,smb,gssapi; 4697 installs are default Windows services and PSEXESVC. No LLMNR/NBT-NS poisoning or SMB relay. |
| T1557.002 ARP Cache Poisoning | benign | Responder MAC 12:34:56:78:9a:bc is a synthetic placeholder in the lab capture; arp.exe /a is Azure agent telemetry. No gratuitous-ARP or duplicate MAC-to-IP mapping. |
| T1557.003 DHCP Spoofing | not_observable | No DHCP events in any dataset (no 1341/1342/1020/1063, no Zeek dhcp log, no port 67/68 traffic); DHCP spoofing cannot be assessed from this data. |
| T1558 Steal or Forge Kerberos Tickets | malicious | PowerShell.exe (PID 2976) on scranton opened lsass.exe with GrantedAccess 0x1fffff (PROCESS_ALL_ACCESS); the same process was launched by pbeesly with a hidden-window steganographic loader decoding monkey.png and piping … |
| T1558.001 Golden Ticket | suspicious | Three 4769 requests for the krbtgt service with RC4 (0x12) and TicketOptions 0x60810010 by pbeesly and SCRANTON$; unusual but no forged-ticket artifact directly confirmed. |
| T1558.002 Silver Ticket | not_observed | All observed 4769 service-ticket requests were KDC-issued with Failure Code 0x0; no forged service ticket used without a corresponding KDC request. |
| T1558.003 Kerberoasting | suspicious | 28 TGS (4769) requests all with RC4 encryption 0x12 targeting machine/service accounts NASHUA$, NEWYORK$, SCRANTON$, WEC$ — RC4 downgrade consistent with Kerberoasting. |
| T1558.004 AS-REP Roasting | not_observed | No AS-REP roasting indicators: PowerShell searches for AS-REP/GetNPUsers/DontRequirePreAuth returned zero hits and no pre-auth-disabled 4768 requests were seen. |
| T1606 Forge Web Credentials | not_observed | No forged web credential activity: LSASS access events with high masks came from legitimate PowerShell.exe (0x1FFFFF) and wsmprovhost.exe (0x1F3FFF) on scranton/nashua, other high-mask accesses were svchost/wininit/csrss… |
| T1606.001 Web Cookies | not_observed | Only cookie-path file event is a ServiceProfiles\LocalService INetCookies container created by svchost.exe on scranton; no PowerShell cookie/Set-Cookie/session script content and no cookie-bearing web auth in Zeek HTTP (… |
| T1606.002 SAML Tokens | not_observed | No SAML/ADFS/token artifacts in PowerShell 4104 script blocks, process command lines, or Zeek HTTP URLs; the only notable PowerShell event is an unrelated in-memory loader script block on scranton with no SAML/token forg… |
| T1621 Multi-Factor Authentication Request Generatio… | not_observed | No multi-factor authentication request generation activity found. The only T1621 check hit (C355, WMI 5857/5858/5860 in windows.other) is benign Group Policy/RSOP WMI provider activity by SYSTEM/NETWORK SERVICE. Searches… |
| T1649 Steal or Forge Authentication Certificates | malicious | Certificate/private-key export to .pfx files via Get-PrivateKeys on scranton is consistent with stolen certificate abuse. |

## Coverage

Cells: number of hits of the planned checks, `n/a` (reason in report.json), or GAP.

| Technique | windows.other | windows.powershell | windows.security | windows.sysmon | zeek |
|---|---|---|---|---|---|
| T1003 OS Credential Dumping | 0 hits | 0 hits | 11437 hits | 39730 hits | n/a |
| T1003.001 LSASS Memory | 0 hits | 0 hits | 947 hits | 981 hits | n/a |
| T1003.002 Security Account Manager | 0 hits | 2 hits | 16 hits | 10 hits | n/a |
| T1003.003 NTDS | 0 hits | 0 hits | 0 hits | 0 hits | n/a |
| T1003.004 LSA Secrets | 0 hits | 0 hits | 0 hits | 327 hits | n/a |
| T1003.005 Cached Domain Credentials | 0 hits | 0 hits | 0 hits | 330 hits | n/a |
| T1003.006 DCSync | 90 hits | 0 hits | 21 hits | 0 hits | 9 hits |
| T1040 Network Sniffing | 5 hits | 0 hits | 460 hits | 0 hits | 0 hits |
| T1056 Input Capture | 90 hits | 0 hits | 21834 hits | 39609 hits | 0 hits |
| T1056.001 Keylogging | 5 hits | 0 hits | 10990 hits | 39779 hits | 0 hits |
| T1056.002 GUI Input Capture | 5 hits | 414 hits | 460 hits | 450 hits | 0 hits |
| T1056.003 Web Portal Capture | 5 hits | 0 hits | 5337 hits | 1649 hits | 0 hits |
| T1056.004 Credential API Hooking | 0 hits | 0 hits | 13 hits | 59963 hits | n/a |
| T1110 Brute Force | 2 hits | 0 hits | 0 hits | 30 hits | n/a |
| T1110.001 Password Guessing | 2 hits | 0 hits | 0 hits | 0 hits | n/a |
| T1110.002 Password Cracking | 1 hits | 0 hits | 10977 hits | 346 hits | n/a |
| T1110.003 Password Spraying | 7 hits | 0 hits | 15 hits | 1 hits | n/a |
| T1110.004 Credential Stuffing | 4 hits | 0 hits | 0 hits | 0 hits | n/a |
| T1111 Multi-Factor Authentication Interception | 2 hits | 0 hits | 312 hits | 39294 hits | n/a |
| T1187 Forced Authentication | 0 hits | 0 hits | 11140 hits | 1715 hits | 86 hits |
| T1212 Exploitation for Credential Access | 0 hits | 0 hits | 70 hits | 78566 hits | 14 hits |
| T1539 Steal Web Session Cookie | 0 hits | 0 hits | 465 hits | 40933 hits | 2 hits |
| T1552 Unsecured Credentials | 0 hits | 0 hits | 460 hits | 19208 hits | 12 hits |
| T1552.001 Credentials In Files | 0 hits | 0 hits | 312 hits | 2148 hits | 12 hits |
| T1552.002 Credentials in Registry | 3 hits | 1 hits | 1000 hits | 17606 hits | n/a |
| T1552.003 Shell History | 5 hits | 1 hits | 0 hits | 15 hits | n/a |
| T1552.004 Private Keys | 0 hits | 2 hits | 0 hits | 1 hits | n/a |
| T1552.006 Group Policy Preferences | 0 hits | 32 hits | 56 hits | 22 hits | n/a |
| T1555 Credentials from Password Stores | 2 hits | 5 hits | 19 hits | 1326 hits | n/a |
| T1555.003 Credentials from Web Browsers | 0 hits | 0 hits | 0 hits | 0 hits | n/a |
| T1555.004 Windows Credential Manager | 2 hits | 0 hits | 0 hits | 652 hits | n/a |
| T1555.005 Password Managers | 0 hits | 0 hits | 0 hits | 0 hits | n/a |
| T1556 Modify Authentication Process | 0 hits | 0 hits | 0 hits | 729 hits | n/a |
| T1556.001 Domain Controller Authentication | 0 hits | 0 hits | 545 hits | 359 hits | n/a |
| T1556.002 Password Filter DLL | 10 hits | 0 hits | 0 hits | 33 hits | n/a |
| T1556.005 Reversible Encryption | 0 hits | 0 hits | 0 hits | 0 hits | n/a |
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
| T1606 Forge Web Credentials | 90 hits | 0 hits | 312 hits | 326 hits | 475 hits |
| T1606.001 Web Cookies | 9 hits | 0 hits | 312 hits | 1 hits | 62 hits |
| T1606.002 SAML Tokens | 90 hits | 0 hits | 312 hits | 0 hits | 0 hits |
| T1621 Multi-Factor Authentication Request Generatio… | 85 hits | 0 hits | 0 hits | 0 hits | 0 hits |
| T1649 Steal or Forge Authentication Certificates | 90 hits | 0 hits | 50 hits | 1133 hits | 378 hits |

Cells: 265, gaps: 0.

## Queries

Every MCP tool call of this run (1181), in order (source: mcp_audit.jsonl written by the MCP server).

| Query | Phase | Tool | Arguments | Hits / rows | Cited by |
|---|---|---|---|---|---|
| q-b64454abcb | scope | list_data_sources | {} | None |  |
| q-f62fdba282 | scope | get_registry | {} | None |  |
| q-fb91e6ee3d | scope | get_fields | {"dataset": "windows.other", "prefix": ""} | None |  |
| q-f22f9ad263 | scope | get_fields | {"dataset": "windows.powershell", "prefix": ""} | None |  |
| q-72e3426329 | scope | get_fields | {"dataset": "windows.security", "prefix": ""} | None |  |
| q-8d10e35a1a | scope | get_fields | {"dataset": "windows.sysmon", "prefix": ""} | None |  |
| q-c390d5d815 | scope | get_fields | {"dataset": "zeek", "prefix": ""} | None |  |
| q-007fd1c9fd | check C001 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 447 |  |
| q-647b043c9c | check C002 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-6ebd3d3caa | check C003 | aggregate | {"dataset": "windows.security", "field": "win.ObjectType", "query": "event.code:(4656 OR 4663 OR 4670)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 10977 |  |
| q-5487ed95fb | check C004 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 460 |  |
| q-5d21ca0b00 | check C005 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*lsass* OR powershell.script_block_text:*mimikatz* OR powershell.script_block_text:*sekurlsa* OR powershell.script_block_text:*DumpCreds*)", "time_from": null, "time_… | 0 |  |
| q-bcd3bce8f3 | check C006 | search | {"dataset": "windows.other", "query": "message:(*lsass* OR *mimikatz* OR *sekurlsa* OR *procdump*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "p… | 0 |  |
| q-4b2e43f17e | check C007 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-1da2a942e1 | check C008 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 326 |  |
| q-790b4f201f | check C009 | aggregate | {"dataset": "windows.sysmon", "field": "win.SourceImage", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-051dc46a7d | check C010 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*lsass* OR file.path:*.dmp)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "pro… | 2 |  |
| q-6fd9d7f805 | check C011 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*lsass* OR process.command_line:*comsvcs* OR process.command_line:*MiniDump*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dat… | 1 |  |
| q-02bb0e8e11 | check C012 | search | {"dataset": "windows.sysmon", "query": "event.code:(13 OR 14) AND registry.path:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.comm… | 0 |  |
| q-4f5d022c81 | check C013 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4673", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 934 |  |
| q-bc0451a0a1 | check C014 | search | {"dataset": "windows.security", "query": "event.code:4656 AND win.ObjectName:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command… | 13 |  |
| q-1abf820ba3 | check C015 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*lsass* OR powershell.script_block_text:*MiniDump* OR powershell.script_block_text:*Invoke-Mimikatz*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "… | 0 |  |
| q-74675c0e02 | check C016 | search | {"dataset": "windows.other", "query": "message:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 0 |  |
| q-6e8b87ef0b | check C017 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*SAM* OR file.path:*SECURITY* OR file.path:*SYSTEM*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "… | 3 |  |
| q-d36cf40b8b | check C018 | search | {"dataset": "windows.sysmon", "query": "event.code:(13 OR 14) AND (registry.path:*SAM* OR registry.path:*SECURITY*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "proces… | 7 | F04 |
| q-c11bed9526 | check C019 | search | {"dataset": "windows.sysmon", "query": "event.code:2 AND (process.command_line:*SAM* OR process.command_line:*reg*save*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "p… | 0 |  |
| q-4389c1f6d7 | check C020 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*reg save* OR process.command_line:*save*hklm* OR process.command_line:*SAM*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dat… | 0 |  |
| q-09dd795a46 | check C021 | aggregate | {"dataset": "windows.security", "field": "process.command_line", "query": "event.code:4688 AND (process.command_line:*reg* OR process.command_line:*save*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 6 |  |
| q-6a3c7f881c | check C022 | search | {"dataset": "windows.security", "query": "event.code:(4656 OR 4663) AND (win.ObjectName:*SAM* OR win.ObjectName:*SECURITY*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name",… | 10 |  |
| q-919e71136c | check C023 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*SAM* OR powershell.script_block_text:*reg save* OR powershell.script_block_text:*hive*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "… | 2 |  |
| q-3c0c32f527 | check C024 | search | {"dataset": "windows.other", "query": "message:(*SAM* OR *SECURITY hive* OR *reg save*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.comm… | 0 |  |
| q-ed60c06560 | check C025 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*ntds* OR file.path:*NTDS*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "pro… | 0 |  |
| q-3523501ef4 | check C026 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*ntds* OR process.command_line:*vssadmin* OR process.command_line:*ntdsutil* OR process.command_line:*diskshadow*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "ho… | 0 |  |
| q-4e9acdbb5d | check C027 | search | {"dataset": "windows.sysmon", "query": "event.code:2 AND file.path:*ntds*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "so… | 0 |  |
| q-175afca3ad | check C028 | aggregate | {"dataset": "windows.security", "field": "process.command_line", "query": "event.code:4688 AND (process.command_line:*ntds* OR process.command_line:*vssadmin* OR process.command_line:*diskshadow*)", "time_from": null, "time_to": null, "size": 50, "sub_field": … | 0 |  |
| q-c19a126403 | check C029 | search | {"dataset": "windows.other", "query": "message:(*shadow* OR *VSS* OR *ntds*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 0 |  |
| q-dd0300e894 | check C030 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*ntds* OR powershell.script_block_text:*diskshadow* OR powershell.script_block_text:*vssadmin*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.n… | 0 |  |
| q-de6ad6ce29 | check C031 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 326 |  |
| q-1af6d8a57e | check C032 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*secrets* OR process.command_line:*lsadump* OR process.command_line:*reg save*HKLM\\\\SECURITY*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observe… | 0 |  |
| q-7e83ae6d3c | check C033 | search | {"dataset": "windows.sysmon", "query": "event.code:7 AND win.ImageLoaded:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_lin… | 1 |  |
| q-1c6764e5be | check C034 | search | {"dataset": "windows.security", "query": "event.code:(4656 OR 4663 OR 4670) AND win.ObjectName:*SECURITY*Policy*Secrets*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "p… | 0 |  |
| q-03e9f11c7a | check C035 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:(4656 OR 4663 OR 4670) AND win.ObjectName:*Secrets*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-ec431d370a | check C036 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*Secrets* OR powershell.script_block_text:*lsadump* OR powershell.script_block_text:*LSA*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name",… | 0 |  |
| q-1b2b64a380 | check C037 | search | {"dataset": "windows.other", "query": "message:(*Secrets* OR *LSA* OR *lsadump*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_lin… | 0 |  |
| q-9db899dcf7 | check C038 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 326 |  |
| q-8d41017bb6 | check C039 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*cache* OR process.command_line:*DCC2* OR process.command_line:*mscache* OR process.command_line:*cachedump*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.na… | 4 |  |
| q-42949c1dd9 | check C040 | search | {"dataset": "windows.security", "query": "event.code:(4656 OR 4663 OR 4670) AND (win.ObjectName:*Cache* OR win.ObjectName:*SECURITY*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "u… | 0 |  |
| q-bb7ff6b407 | check C041 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:(4656 OR 4663 OR 4670) AND win.ObjectName:*Cache*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-cad58e92bf | check C042 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*cache* OR powershell.script_block_text:*DCC2* OR powershell.script_block_text:*mscache*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", … | 0 |  |
| q-d9eb22697a | check C043 | search | {"dataset": "windows.other", "query": "message:(*cached*credential* OR *mscache* OR *DCC2*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.… | 0 |  |
| q-3888942b49 | check C044 | count | {"dataset": "windows.security", "query": "event.code:4662", "time_from": null, "time_to": null} | 7 |  |
| q-825dd328f7 | check C045 | aggregate | {"dataset": "windows.security", "field": "win.AccessMask", "query": "event.code:4662", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 7 |  |
| q-47cf179b0b | check C046 | aggregate | {"dataset": "windows.security", "field": "win.SubjectUserName", "query": "event.code:4662", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 7 |  |
| q-e6a0985de2 | check C047 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*drsuapi* OR process.command_line:*lsadump* OR process.command_line:*dcsync*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dat… | 0 |  |
| q-2f6ab684d5 | check C048 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*DCSync* OR powershell.script_block_text:*lsadump* OR powershell.script_block_text:*drsuapi*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.nam… | 0 |  |
| q-d1c9dd7d88 | check C049 | search | {"dataset": "windows.other", "query": "event.code:7045 OR event.code:5858 OR event.code:5857", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process… | 90 |  |
| q-bfc7dbd566 | check C050 | search | {"dataset": "zeek", "query": "event.action:dce_rpc AND (zeek.operation:*DRSUAPI* OR zeek.endpoint:*drsuapi* OR zeek.named_pipe:*drsuapi*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code"… | 9 |  |
| q-7825b19095 | check C051 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 460 |  |
| q-b12a396d02 | check C052 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*pcap* OR process.command_line:*sniff* OR process.command_line:*promisc*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.da… | 0 |  |
| q-a0c0ccdc3c | check C053 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-79f13b16df | check C054 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.executable:*tcpdump* OR process.executable:*windump* OR process.executable:*wireshark* OR process.executable:*rawcap* OR process.executable:*npcap*)", "time_from": null, "time_to": null, "fields… | 0 |  |
| q-e3b338b366 | check C055 | search | {"dataset": "windows.sysmon", "query": "event.code:6 AND (win.Image:*npcap* OR win.Image:*pcap* OR win.Image:*winpcap*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "pr… | 0 |  |
| q-747f23ac3b | check C056 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*pcap* OR powershell.script_block_text:*sniff* OR powershell.script_block_text:*promiscuous*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.nam… | 0 |  |
| q-33c46ab0a1 | check C057 | search | {"dataset": "zeek", "query": "event.action:conn AND network.transport:icmp", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "s… | 0 |  |
| q-dd9f4e77d4 | check C058 | aggregate | {"dataset": "windows.security", "field": "win.ObjectType", "query": "event.code:4656 OR event.code:4663 OR event.code:4670", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 10977 |  |
| q-0b662e1620 | check C059 | aggregate | {"dataset": "windows.security", "field": "win.AccessMask", "query": "event.code:4656 OR event.code:4663", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 10834 |  |
| q-b72a1d4cc6 | check C060 | search | {"dataset": "windows.security", "query": "event.code:4656 AND (win.ObjectName:*lsass* OR win.ObjectName:*credential* OR win.ObjectName:*SAM*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.c… | 23 |  |
| q-89748cf6c6 | check C061 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-19142172f7 | check C062 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-ac153328e6 | check C063 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND (win.GrantedAccess:0x1010 OR win.GrantedAccess:0x1410 OR win.GrantedAccess:0x1438 OR win.GrantedAccess:0x143a)", "time_from": null, "time_to": null, "fields": ["@timestamp", … | 0 |  |
| q-9d81aa034b | check C064 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*Get-Credential* OR powershell.script_block_text:*CredentialManager* OR powershell.script_block_text:*keylog*)", "time_from": null, "time_to": null, "fields": ["@time… | 0 |  |
| q-b45a7611c0 | check C065 | search | {"dataset": "windows.other", "query": "event.code:7045 OR event.code:5858 OR event.code:5857", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process… | 90 |  |
| q-0088765b7a | check C066 | search | {"dataset": "zeek", "query": "event.action:http AND http.request.method:POST", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 0 |  |
| q-a2257f75a9 | check C067 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-6450b3ee0b | check C068 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND (win.TargetImage:*lsass* OR win.TargetImage:*winlogon* OR win.TargetImage:*explorer*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event… | 470 |  |
| q-b1f4b4f8d6 | check C069 | search | {"dataset": "windows.sysmon", "query": "event.code:13 AND (registry.path:*Keyboard* OR registry.path:*keylog* OR registry.path:*Scancode*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code… | 26 |  |
| q-aea2acbc81 | check C070 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*keylog* OR process.command_line:*GetAsyncKeyState* OR process.command_line:*SetWindowsHookEx*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer… | 0 |  |
| q-aab2ec1369 | check C071 | aggregate | {"dataset": "windows.security", "field": "win.ObjectType", "query": "event.code:4656 OR event.code:4663 OR event.code:4670", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 10977 |  |
| q-caa4afba92 | check C072 | search | {"dataset": "windows.security", "query": "event.code:4656 AND (win.ObjectName:*lsass* OR win.ObjectName:*winlogon*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "proces… | 13 |  |
| q-118e78c7d6 | check C073 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-3a6dbedf64 | check C074 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*keylog* OR powershell.script_block_text:*GetAsyncKeyState* OR powershell.script_block_text:*SetWindowsHookEx*)", "time_from": null, "time_to": null, "fields": ["@tim… | 0 |  |
| q-395d248182 | check C075 | search | {"dataset": "zeek", "query": "event.action:http AND http.request.method:POST", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 0 |  |
| q-4a237726ae | check C076 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*Credential* OR powershell.script_block_text:*Prompt* OR powershell.script_block_text:*Read-Host*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "hos… | 0 |  |
| q-fc2592d052 | check C077 | aggregate | {"dataset": "windows.powershell", "field": "win.ScriptBlockId", "query": "event.code:4104", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 414 |  |
| q-f1f154fb3f | check C078 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*Credential* OR process.command_line:*prompt* OR process.command_line:*consent*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.… | 3 |  |
| q-a0dd004b0b | check C079 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 447 |  |
| q-f1d9db9caf | check C080 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*Credential* OR process.command_line:*prompt*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user… | 0 |  |
| q-14ea9db502 | check C081 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 460 |  |
| q-c5a32d9e27 | check C082 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-180517124a | check C083 | search | {"dataset": "zeek", "query": "event.action:http AND http.request.method:POST", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 0 |  |
| q-5c362dfb4a | check C084 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*login* OR file.path:*portal* OR file.path:*wwwroot* OR file.path:*inetpub*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "eve… | 0 |  |
| q-ee8cafe0a8 | check C085 | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 1649 |  |
| q-b18b956ac9 | check C086 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*iis* OR process.command_line:*w3wp* OR process.command_line:*wwwroot*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset",… | 0 |  |
| q-6d2cd85c43 | check C087 | search | {"dataset": "windows.security", "query": "event.code:4663 AND (win.ObjectName:*wwwroot* OR win.ObjectName:*inetpub* OR win.ObjectName:*login*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.… | 0 |  |
| q-a616b7e4c5 | check C088 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 5337 |  |
| q-5f30a65ff1 | check C089 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*wwwroot* OR powershell.script_block_text:*login* OR powershell.script_block_text:*credential*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.n… | 0 |  |
| q-b02816f661 | check C090 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-2126045cfa | check C091 | search | {"dataset": "zeek", "query": "event.action:http AND (url.original:*login* OR url.original:*portal*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "… | 0 |  |
| q-03c7d25ae7 | check C092 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-7f5d80b7c6 | check C093 | aggregate | {"dataset": "windows.sysmon", "field": "win.SourceImage", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-ff29236cf1 | check C094 | aggregate | {"dataset": "windows.sysmon", "field": "win.ImageLoaded", "query": "event.code:7", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 20259 |  |
| q-bf88ffbb88 | check C095 | search | {"dataset": "windows.sysmon", "query": "event.code:8", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinatio… | 95 |  |
| q-2a6d3073d0 | check C096 | aggregate | {"dataset": "windows.security", "field": "win.CallerProcessName", "query": "event.code:4656 AND win.ObjectType:*Process*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 13 |  |
| q-1eb5f81cba | check C097 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:*hook* OR powershell.script_block_text:*SetWindowsHookEx* OR powershell.script_block_text:*MiniDump*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.… | 0 |  |
| q-2d6d2d1dea | check C098 | search | {"dataset": "windows.other", "query": "message:*hook* OR message:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "sou… | 0 |  |
| q-3557d3995b | check C099 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-76278af634 | check C100 | aggregate | {"dataset": "windows.security", "field": "source.ip", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-b6baaf980a | check C101 | timeline | {"dataset": "windows.security", "query": "event.code:4625", "interval": "1m", "time_from": null, "time_to": null} | 0 |  |
| q-7067a59d1a | check C102 | search | {"dataset": "windows.other", "query": "message:*logon* OR message:*password*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 2 |  |
| q-710bbfe433 | check C103 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:*Credential* OR powershell.script_block_text:*Password*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.n… | 0 |  |
| q-378aea48ab | check C104 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*net* OR process.command_line:*login*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 30 |  |
| q-e1730306ed | check C105 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-aef02679d0 | check C106 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 0 |  |
| q-3ce1aa216c | check C107 | timeline | {"dataset": "windows.security", "query": "event.code:4625", "interval": "1m", "time_from": null, "time_to": null} | 0 |  |
| q-d764e36cb1 | check C108 | search | {"dataset": "windows.other", "query": "message:*4625* OR message:*failed*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "so… | 2 | F14 |
| q-5385f5327b | check C109 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:*Password* OR powershell.script_block_text:*Credential*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.n… | 0 |  |
| q-c4c64fa45e | check C110 | aggregate | {"dataset": "windows.sysmon", "field": "process.command_line", "query": "event.code:1 AND process.command_line:*password*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-954b7f951b | check C111 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 OR event.code:4656 OR event.code:4670", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 10977 |  |
| q-b3af3a568f | check C112 | aggregate | {"dataset": "windows.security", "field": "win.ProcessName", "query": "event.code:4663 AND (win.ObjectName:*SAM* OR win.ObjectName:*SECURITY*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-e3f5f84d8c | check C113 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*hash* OR process.command_line:*crack*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-f039c6da00 | check C114 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND (win.TargetFilename:*.txt OR win.TargetFilename:*.pot)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 20 |  |
| q-cd13dffac3 | check C115 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10 AND (win.TargetImage:*lsass* OR win.TargetImage:*SAM*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-fcffe66dce | check C116 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:*hash* OR powershell.script_block_text:*ConvertTo-SecureString*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code",… | 0 |  |
| q-ef3b8a3ba9 | check C117 | search | {"dataset": "windows.other", "query": "message:*SAM* OR message:*hash*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "sourc… | 1 |  |
| q-8cebd9512f | check C118 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-3049ae6fc8 | check C119 | aggregate | {"dataset": "windows.security", "field": "source.ip", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-4ef4dad47f | check C120 | search | {"dataset": "windows.security", "query": "event.code:4648", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 15 |  |
| q-0c2f493940 | check C121 | timeline | {"dataset": "windows.security", "query": "event.code:4625", "interval": "1m", "time_from": null, "time_to": null} | 0 |  |
| q-f04499aebb | check C122 | search | {"dataset": "windows.other", "query": "message:*logon* OR message:*account*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "… | 7 |  |
| q-0129ac513b | check C123 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:*Password* OR powershell.script_block_text:*Credential*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.n… | 0 |  |
| q-6f14fd7b4a | check C124 | aggregate | {"dataset": "windows.sysmon", "field": "process.command_line", "query": "event.code:1 AND process.command_line:*user*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1 |  |
| q-ceea2f2484 | check C125 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-0241884471 | check C126 | aggregate | {"dataset": "windows.security", "field": "source.ip", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-b722797a84 | check C127 | timeline | {"dataset": "windows.security", "query": "event.code:4625", "interval": "1m", "time_from": null, "time_to": null} | 0 |  |
| q-ea554e6cf7 | check C128 | search | {"dataset": "windows.other", "query": "message:*logon* OR message:*credential*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line"… | 4 | F17 |
| q-9d70f404d5 | check C129 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:*Credential* OR powershell.script_block_text:*Password*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.n… | 0 |  |
| q-c97161e9d2 | check C130 | aggregate | {"dataset": "windows.sysmon", "field": "process.command_line", "query": "event.code:1 AND process.command_line:*password*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-f404e514b9 | check C131 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 297 |  |
| q-f2df20f3a8 | check C132 | search | {"dataset": "windows.security", "query": "event.code:4648", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 15 |  |
| q-1f7be53670 | check C133 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-ed29b9f990 | check C134 | search | {"dataset": "windows.sysmon", "query": "event.code:13 AND registry.path:*Credential*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command… | 11 |  |
| q-f8e8edfb00 | check C135 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND powershell.script_block_text:*Credential*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executab… | 0 |  |
| q-df61e5c3d7 | check C136 | search | {"dataset": "windows.other", "query": "message:*Credential*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "des… | 2 |  |
| q-bd7f27ba96 | check C137 | aggregate | {"dataset": "windows.security", "field": "win.ObjectType", "query": "event.code:4656 OR event.code:4663 OR event.code:4670", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 10977 |  |
| q-c4fa459d20 | check C138 | search | {"dataset": "windows.security", "query": "event.code:5140 OR event.code:5145", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 163 | F20 |
| q-022d1a5f4a | check C139 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1649 |  |
| q-59f3e9811d | check C140 | search | {"dataset": "windows.sysmon", "query": "event.code:3 AND (destination.port:445 OR destination.port:139)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable… | 66 |  |
| q-f69e4589ad | check C141 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*445* OR powershell.script_block_text:*WebDAV* OR powershell.script_block_text:*NTLM*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "ob… | 0 |  |
| q-ef3957fe26 | check C142 | search | {"dataset": "windows.other", "query": "message:*445* OR message:*WebDAV*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "sou… | 0 |  |
| q-39721ee76c | check C143 | aggregate | {"dataset": "zeek", "field": "destination.port", "query": "event.action:conn AND (destination.port:445 OR destination.port:139)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 50 |  |
| q-761aeeb6a7 | check C144 | search | {"dataset": "zeek", "query": "event.action:http AND (http.request.method:PROPFIND OR http.request.method:MOVE OR http.request.method:OPTIONS)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.c… | 36 |  |
| q-29b3de2110 | check C145 | aggregate | {"dataset": "windows.security", "field": "event.code", "query": "event.code:4768 OR event.code:4769 OR event.code:4770", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 42 |  |
| q-cc1e582a0c | check C146 | search | {"dataset": "windows.security", "query": "event.code:4769", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 28 | F23 |
| q-bee097bcef | check C147 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-7de0d8a826 | check C148 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.GrantedAccess:*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line",… | 39283 |  |
| q-417020ea1c | check C149 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*Invoke-* OR powershell.script_block_text:*Exploit*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "ev… | 0 |  |
| q-753c3d3c5a | check C150 | search | {"dataset": "windows.other", "query": "message:*exploit*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destin… | 0 |  |
| q-b6a20aca86 | check C151 | search | {"dataset": "zeek", "query": "event.action:notice OR event.action:weird", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "sour… | 14 | F23 |
| q-8bce11ee94 | check C152 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 460 |  |
| q-8282ee01a7 | check C153 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*cookie* OR process.command_line:*Cookie*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.nam… | 5 |  |
| q-6607d36376 | check C154 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1649 |  |
| q-2595c9d0c8 | check C155 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (win.TargetFilename:*Cookies* OR win.TargetFilename:*cookie*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "pr… | 1 |  |
| q-81907b5d74 | check C156 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-163434fc88 | check C157 | search | {"dataset": "windows.sysmon", "query": "event.code:2 AND (win.TargetFilename:*Cookies* OR win.TargetFilename:*cookie*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "pro… | 0 |  |
| q-878f3e2e7e | check C158 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*cookie* OR powershell.script_block_text:*Cookie*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "even… | 0 |  |
| q-8bdf4e4f37 | check C159 | search | {"dataset": "windows.other", "query": "message:*cookie*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destina… | 0 |  |
| q-578d16be19 | check C160 | search | {"dataset": "zeek", "query": "event.action:http AND http.request.method:GET", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "… | 2 |  |
| q-fafff89dd7 | check C161 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 460 |  |
| q-79c0396853 | check C162 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*password* OR process.command_line:*credential* OR process.command_line:*unattend*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name",… | 0 |  |
| q-0e462c46be | check C163 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1649 |  |
| q-9455ad2ca7 | check C164 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (win.TargetFilename:*unattend* OR win.TargetFilename:*password* OR win.TargetFilename:*credential*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.da… | 1 |  |
| q-7b675cec98 | check C165 | aggregate | {"dataset": "windows.sysmon", "field": "registry.path", "query": "event.code:13 OR event.code:14", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 17541 |  |
| q-673272504b | check C166 | search | {"dataset": "windows.sysmon", "query": "event.code:13 AND (registry.path:*Password* OR registry.path:*Credential*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process… | 17 | F30 |
| q-9e73321bca | check C167 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*password* OR powershell.script_block_text:*credential*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset",… | 0 |  |
| q-d3c2a7b7da | check C168 | search | {"dataset": "windows.other", "query": "message:*password*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 0 |  |
| q-cb0e7557ff | check C169 | search | {"dataset": "zeek", "query": "event.action:smb_files", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinatio… | 12 |  |
| q-937a833634 | check C170 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 297 |  |
| q-91c2a2c29e | check C171 | search | {"dataset": "windows.security", "query": "event.code:4648", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 15 |  |
| q-781a8baa8c | check C172 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 447 |  |
| q-f270eca782 | check C173 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*password* OR process.command_line:*credential* OR process.command_line:*config*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event… | 8 |  |
| q-a5571faae2 | check C174 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1649 |  |
| q-fe4614eea2 | check C175 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (win.TargetFilename:*.config OR win.TargetFilename:*.xml OR win.TargetFilename:*.txt)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event… | 44 |  |
| q-6b22f3a3c1 | check C176 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*Get-Content* OR powershell.script_block_text:*Select-String*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dat… | 0 |  |
| q-7120fa733e | check C177 | search | {"dataset": "windows.other", "query": "message:*password*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 0 |  |
| q-4fde699c85 | check C178 | search | {"dataset": "zeek", "query": "event.action:smb_files", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinatio… | 12 |  |
| q-d6066b309d | check C179 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"13\" AND (TO_LOWER(registry.path) LIKE \"*\\\\sam\\\\*\" OR TO_LOWER(registry.path) LIKE \"*\\\\security\\\\*\" OR TO_LOWER(registry.path) LIKE \"*password*\" OR TO_LOWER… | ERROR |  |
| q-4c796e3de9 | check C179 (repaired) | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"13\" AND (TO_LOWER(registry.path) LIKE \"*\\\\\\\\sam\\\\\\\\*\" OR TO_LOWER(registry.path) LIKE \"*\\\\\\\\security\\\\\\\\*\" OR TO_LOWER(registry.path) LIKE \"*passwor… | 60 |  |
| q-f361050016 | check C180 | aggregate | {"dataset": "windows.sysmon", "field": "registry.path", "query": "event.code:13", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 17541 |  |
| q-ecd565a133 | check C181 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*reg query*\" OR TO_LOWER(process.command_line) LIKE \"*reg save*\" OR TO_LOWER(process.command_line) LIKE \"*\\\\sam*\" OR… | ERROR |  |
| q-da927d04a3 | check C181 (repaired) | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*reg query*\" OR TO_LOWER(process.command_line) LIKE \"*reg save*\" OR TO_LOWER(process.command_line) LIKE \"*sam*\" OR TO_… | 5 |  |
| q-f152584d08 | check C182 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4663\",\"4656\",\"4670\",\"4658\") AND (TO_LOWER(win.ObjectName) LIKE \"*\\\\sam*\" OR TO_LOWER(win.ObjectName) LIKE \"*\\\\security*\" OR TO_LOWER(win.ObjectName) LIK… | ERROR |  |
| q-729034e318 | check C182 (repaired) | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4663\",\"4656\",\"4670\",\"4658\") AND (TO_LOWER(win.ObjectName) LIKE \"*\\\\\\\\sam*\" OR TO_LOWER(win.ObjectName) LIKE \"*\\\\\\\\security*\" OR TO_LOWER(win.ObjectN… | 500 |  |
| q-5fc66edd95 | check C183 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code IN (\"4103\",\"4104\") AND (TO_LOWER(COALESCE(powershell.script_block_text, win.ScriptBlockText, \"\")) LIKE \"*reg query*\" OR TO_LOWER(COALESCE(powershell.script_block_t… | ERROR |  |
| q-dd30a95b9c | check C183 (repaired) | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code IN (\"4103\",\"4104\") AND (TO_LOWER(COALESCE(win.ScriptBlockText, \"\")) LIKE \"*reg query*\" OR TO_LOWER(COALESCE(win.ScriptBlockText, \"\")) LIKE \"*reg save*\" OR TO_L… | 1 |  |
| q-11b61ca2c1 | check C184 | esql | {"query": "FROM logs-windows.other-default METADATA _id, _index \| WHERE TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*\\\\sam*\" OR TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*\\\\security*\" OR TO_LOWER(COALESCE(message, win.Message, \"\"… | ERROR |  |
| q-98f160a01a | check C184 (repaired) | esql | {"query": "FROM logs-windows.other-default METADATA _id, _index \| WHERE TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*\\\\\\\\sam*\" OR TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*\\\\\\\\security*\" OR TO_LOWER(COALESCE(message, win.Messa… | 3 |  |
| q-6b9d8bcf39 | check C185 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code IN (\"4103\",\"4104\") AND (TO_LOWER(COALESCE(powershell.script_block_text, win.ScriptBlockText, \"\")) LIKE \"*history*\" OR TO_LOWER(COALESCE(powershell.script_block_tex… | ERROR |  |
| q-e8ad82237b | check C185 (repaired) | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code IN (\"4103\",\"4104\") AND (TO_LOWER(COALESCE(win.ScriptBlockText, \"\")) LIKE \"*history*\" OR TO_LOWER(COALESCE(win.ScriptBlockText, \"\")) LIKE \"*consolehost_history*\… | 1 |  |
| q-ee8bd5f793 | check C186 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*consolehost_history*\" OR TO_LOWER(process.command_line) LIKE \"*psreadline*\" OR TO_LOWER(process.command_line) LIKE \"*h… | 0 |  |
| q-cc5d1ddbe0 | check C187 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*consolehost_history*\" OR TO_LOWER(file.path) LIKE \"*psreadline*\" OR TO_LOWER(file.path) LIKE \"*\\\\history*\" OR TO_LOWER(file.p… | ERROR |  |
| q-b884e9c6eb | check C187 (repaired) | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*consolehost_history*\" OR TO_LOWER(file.path) LIKE \"*psreadline*\" OR TO_LOWER(file.path) LIKE \"*history*\") \| KEEP @timestamp, h… | 15 |  |
| q-e279134113 | check C188 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4663\",\"4656\",\"4658\") AND (TO_LOWER(win.ObjectName) LIKE \"*consolehost_history*\" OR TO_LOWER(win.ObjectName) LIKE \"*psreadline*\" OR TO_LOWER(win.ObjectName) LI… | 0 |  |
| q-972d779ee6 | check C189 | esql | {"query": "FROM logs-windows.other-default METADATA _id, _index \| WHERE TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*history*\" OR TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*psreadline*\" \| KEEP @timestamp, host.name, event.code, messag… | 5 |  |
| q-6ab1e01493 | check C190 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*.key\" OR TO_LOWER(file.path) LIKE \"*.pgp\" OR TO_LOWER(file.path) LIKE \"*.gpg\" OR TO_LOWER(file.path) LIKE \"*.ppk\" OR TO_LOWER… | 1 |  |
| q-56e32131b5 | check C191 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*.pem*\" OR TO_LOWER(process.command_line) LIKE \"*.pfx*\" OR TO_LOWER(process.command_line) LIKE \"*.p12*\" OR TO_LOWER(pr… | 0 |  |
| q-ea87d009fe | check C192 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"5145\" AND (TO_LOWER(win.RelativeTargetName) LIKE \"*.key\" OR TO_LOWER(win.RelativeTargetName) LIKE \"*.pem\" OR TO_LOWER(win.RelativeTargetName) LIKE \"*.pfx\" OR TO_… | 0 |  |
| q-da516815d8 | check C193 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4663\",\"4656\",\"4658\") AND (TO_LOWER(win.ObjectName) LIKE \"*.key\" OR TO_LOWER(win.ObjectName) LIKE \"*.pem\" OR TO_LOWER(win.ObjectName) LIKE \"*.pfx\" OR TO_LOWE… | 0 |  |
| q-ce5bd2c590 | check C194 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code IN (\"4103\",\"4104\") AND (TO_LOWER(COALESCE(powershell.script_block_text, win.ScriptBlockText, \"\")) LIKE \"*.pem*\" OR TO_LOWER(COALESCE(powershell.script_block_text, … | ERROR |  |
| q-af69e436ca | check C194 (repaired) | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code IN (\"4103\",\"4104\") AND (TO_LOWER(COALESCE(win.ScriptBlockText, \"\")) LIKE \"*.pem*\" OR TO_LOWER(COALESCE(win.ScriptBlockText, \"\")) LIKE \"*.pfx*\" OR TO_LOWER(COAL… | 2 |  |
| q-a9bc117391 | check C195 | esql | {"query": "FROM logs-windows.other-default METADATA _id, _index \| WHERE TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*.pem*\" OR TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*.pfx*\" OR TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*… | 0 |  |
| q-9da0220b83 | check C196 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code IN (\"4103\",\"4104\") AND (TO_LOWER(COALESCE(powershell.script_block_text, win.ScriptBlockText, \"\")) LIKE \"*groups.xml*\" OR TO_LOWER(COALESCE(powershell.script_block_… | ERROR |  |
| q-d8fe2976b9 | check C196 (repaired) | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code IN (\"4103\",\"4104\") AND (TO_LOWER(COALESCE(win.ScriptBlockText, \"\")) LIKE \"*groups.xml*\" OR TO_LOWER(COALESCE(win.ScriptBlockText, \"\")) LIKE \"*sysvol*\" OR TO_LO… | 32 |  |
| q-97942e9c31 | check C197 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*sysvol*\" OR TO_LOWER(process.command_line) LIKE \"*groups.xml*\" OR TO_LOWER(process.command_line) LIKE \"*cpassword*\" O… | 0 |  |
| q-bf837a9e3e | check C198 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*groups.xml*\" OR TO_LOWER(file.path) LIKE \"*sysvol*\" OR TO_LOWER(file.path) LIKE \"*gpprefdecrypt*\" OR TO_LOWER(file.path) LIKE \… | 22 |  |
| q-00c0247065 | check C199 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"5145\" AND (TO_LOWER(win.RelativeTargetName) LIKE \"*groups.xml*\" OR TO_LOWER(win.ShareName) LIKE \"*sysvol*\" OR TO_LOWER(win.ShareName) LIKE \"*netlogon*\") \| KEEP … | 56 |  |
| q-9a101a7bc7 | check C200 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4663\",\"4656\",\"4658\") AND (TO_LOWER(win.ObjectName) LIKE \"*groups.xml*\" OR TO_LOWER(win.ObjectName) LIKE \"*sysvol*\" OR TO_LOWER(win.ObjectName) LIKE \"*gpp*\")… | 0 |  |
| q-e97ba40df9 | check C201 | esql | {"query": "FROM logs-windows.other-default METADATA _id, _index \| WHERE TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*sysvol*\" OR TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*groups.xml*\" OR TO_LOWER(COALESCE(message, win.Message, \"\")) … | 0 |  |
| q-99bea5d958 | check C202 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND (TO_LOWER(win.TargetImage) LIKE \"*lsass.exe\" OR TO_LOWER(win.SourceImage) LIKE \"*lsass.exe\") \| KEEP @timestamp, host.name, user.name, win.SourceImage, win.T… | 500 | F33 |
| q-5fe48fc7bf | check C203 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass.exe", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-4c551b9807 | check C204 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*sekurlsa*\" OR TO_LOWER(process.command_line) LIKE \"*lsadump*\" OR TO_LOWER(process.command_line) LIKE \"*mimikatz*\" OR … | 0 |  |
| q-faf45e477d | check C205 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4663\",\"4656\",\"4670\",\"4658\") AND (TO_LOWER(win.ObjectName) LIKE \"*\\\\protect\\\\*\" OR TO_LOWER(win.ObjectName) LIKE \"*credential*\" OR TO_LOWER(win.ObjectNam… | ERROR |  |
| q-dbf3aacc4b | check C205 (repaired) | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4663\",\"4656\",\"4670\",\"4658\") AND (TO_LOWER(win.ObjectName) LIKE \"*protect*\" OR TO_LOWER(win.ObjectName) LIKE \"*credential*\" OR TO_LOWER(win.ObjectName) LIKE … | 19 |  |
| q-e85c530b2d | check C206 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4688\" AND (TO_LOWER(process.command_line) LIKE \"*sekurlsa*\" OR TO_LOWER(process.command_line) LIKE \"*lsadump*\" OR TO_LOWER(process.command_line) LIKE \"*mimikatz*\… | 0 |  |
| q-7964869cd3 | check C207 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code IN (\"4103\",\"4104\") AND (TO_LOWER(COALESCE(powershell.script_block_text, win.ScriptBlockText, \"\")) LIKE \"*sekurlsa*\" OR TO_LOWER(COALESCE(powershell.script_block_te… | ERROR |  |
| q-96b4b522f2 | check C207 (repaired) | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code IN (\"4103\",\"4104\") AND (TO_LOWER(COALESCE(win.ScriptBlockText, \"\")) LIKE \"*sekurlsa*\" OR TO_LOWER(COALESCE(win.ScriptBlockText, \"\")) LIKE \"*lsadump*\" OR TO_LOW… | 5 |  |
| q-3808437d75 | check C208 | esql | {"query": "FROM logs-windows.other-default METADATA _id, _index \| WHERE TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*lsass*\" OR TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*credential*\" OR TO_LOWER(COALESCE(message, win.Message, \"\")) L… | 2 |  |
| q-ef69c60c23 | check C209 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*login data*\" OR TO_LOWER(process.command_line) LIKE \"*\\\\google\\\\chrome\\\\user data*\" OR TO_LOWER(process.command_l… | ERROR |  |
| q-f1d486f31c | check C209 (repaired) | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*login data*\" OR TO_LOWER(process.command_line) LIKE \"*google*chrome*user data*\" OR TO_LOWER(process.command_line) LIKE … | 0 |  |
| q-5559d70cad | check C210 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*login data*\" OR TO_LOWER(file.path) LIKE \"*logins.json*\" OR TO_LOWER(file.path) LIKE \"*key3.db*\" OR TO_LOWER(file.path) LIKE \"… | ERROR |  |
| q-fc90901fb6 | check C210 (repaired) | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*login data*\" OR TO_LOWER(file.path) LIKE \"*logins.json*\" OR TO_LOWER(file.path) LIKE \"*key3.db*\" OR TO_LOWER(file.path) LIKE \"… | 0 |  |
| q-17148e9425 | check C211 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND (TO_LOWER(win.TargetImage) LIKE \"*chrome.exe\" OR TO_LOWER(win.TargetImage) LIKE \"*firefox.exe\" OR TO_LOWER(win.TargetImage) LIKE \"*msedge.exe\" OR TO_LOWER(… | 0 |  |
| q-134d38c634 | check C212 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4663\",\"4656\",\"4658\") AND (TO_LOWER(win.ObjectName) LIKE \"*login data*\" OR TO_LOWER(win.ObjectName) LIKE \"*logins.json*\" OR TO_LOWER(win.ObjectName) LIKE \"*ke… | ERROR |  |
| q-4d7f14a570 | check C212 (repaired) | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4663\",\"4656\",\"4658\") AND (TO_LOWER(win.ObjectName) LIKE \"*login data*\" OR TO_LOWER(win.ObjectName) LIKE \"*logins.json*\" OR TO_LOWER(win.ObjectName) LIKE \"*ke… | 0 |  |
| q-2ac5c1cac4 | check C213 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code IN (\"4103\",\"4104\") AND (TO_LOWER(COALESCE(powershell.script_block_text, win.ScriptBlockText, \"\")) LIKE \"*login data*\" OR TO_LOWER(COALESCE(powershell.script_block_… | ERROR |  |
| q-accafd0563 | check C213 (repaired) | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code IN (\"4103\",\"4104\") AND (TO_LOWER(COALESCE(win.ScriptBlockText, \"\")) LIKE \"*login data*\" OR TO_LOWER(COALESCE(win.ScriptBlockText, \"\")) LIKE \"*logins.json*\" OR … | 0 |  |
| q-b86ac04146 | check C214 | esql | {"query": "FROM logs-windows.other-default METADATA _id, _index \| WHERE TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*login data*\" OR TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*logins.json*\" OR TO_LOWER(COALESCE(message, win.Message, \"… | 0 |  |
| q-b8c008c101 | check C215 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 326 |  |
| q-acc5caf474 | check C216 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-b50a92b676 | check C217 | search | {"dataset": "windows.sysmon", "query": "event.code:15 AND file.path:*Credentials*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 0 |  |
| q-d001e8df52 | check C218 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*vault* OR process.command_line:*Credential* OR process.command_line:*cmdkey*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "eve… | 0 |  |
| q-c8217ca5c5 | check C219 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*Credential* OR powershell.script_block_text:*vault* OR powershell.script_block_text:*cmdkey*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.na… | 0 |  |
| q-54adfe0bd3 | check C220 | search | {"dataset": "windows.other", "query": "message:*Credential* OR message:*vault*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line"… | 2 |  |
| q-b213b6202e | check C221 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.executable:*keepass* OR process.executable:*1password* OR process.executable:*bitwarden* OR process.executable:*lastpass* OR process.executable:*dashlane*)", "time_from": null, "time_to": null, … | 0 |  |
| q-325bea272f | check C222 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*keepass* OR file.path:*1password* OR file.path:*bitwarden* OR file.path:*lastpass*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.datase… | 0 |  |
| q-f148b9923a | check C223 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND (win.TargetImage:*keepass* OR win.TargetImage:*1password* OR win.TargetImage:*bitwarden*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "e… | 0 |  |
| q-68475d63bd | check C224 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*keepass* OR process.command_line:*1password* OR process.command_line:*bitwarden* OR process.command_line:*kdbx*)", "time_from": null, "time_to": null, "fields": ["@timestamp",… | 0 |  |
| q-ffb70a91d8 | check C225 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*keepass* OR powershell.script_block_text:*kdbx* OR powershell.script_block_text:*1password* OR powershell.script_block_text:*bitwarden*)", "time_from": null, "time_t… | 0 |  |
| q-5a9bd33f5b | check C226 | search | {"dataset": "windows.other", "query": "message:*keepass* OR message:*1password* OR message:*bitwarden* OR message:*kdbx*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "p… | 0 |  |
| q-8ada076aed | check C227 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 326 |  |
| q-dd441dbf1f | check C228 | aggregate | {"dataset": "windows.sysmon", "field": "win.SourceImage", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-b5e453cac4 | check C229 | search | {"dataset": "windows.sysmon", "query": "event.code:7 AND (win.ImageLoaded:*lsass* OR win.ImageLoaded:*cryptdll* OR win.ImageLoaded:*sam* OR win.ImageLoaded:*msv1_0*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "… | 77 |  |
| q-87cb3c5ef8 | check C230 | search | {"dataset": "windows.security", "query": "event.code:4657 AND (win.ObjectName:*lsass* OR win.ObjectName:*cryptdll* OR win.ObjectName:*msv1_0* OR win.ObjectName:*sam*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", … | 0 |  |
| q-08a09f2146 | check C231 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*lsass* OR process.command_line:*cryptdll* OR process.command_line:*msv1_0*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event… | 0 |  |
| q-be93e142db | check C232 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*lsass* OR powershell.script_block_text:*cryptdll* OR powershell.script_block_text:*msv1_0* OR powershell.script_block_text:*SecurityPackages*)", "time_from": null, "… | 0 |  |
| q-c1deae4d48 | check C233 | search | {"dataset": "windows.other", "query": "message:*lsass* OR message:*cryptdll* OR message:*msv1_0*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "pro… | 0 |  |
| q-bc461a94ba | check C234 | search | {"dataset": "windows.security", "query": "event.code:4624 AND win.LogonType:3", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line",… | 218 | F35 |
| q-40a7cb651f | check C235 | search | {"dataset": "windows.security", "query": "event.code:4648", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 15 | F37, F38 |
| q-719973a049 | check C236 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4624 OR event.code:4648", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 312 |  |
| q-92e00b1ea9 | check C237 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 326 |  |
| q-b3e7ca9012 | check C238 | search | {"dataset": "windows.sysmon", "query": "event.code:7 AND (win.ImageLoaded:*lsass* OR win.ImageLoaded:*cryptdll*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.e… | 33 |  |
| q-778a23152a | check C239 | search | {"dataset": "windows.other", "query": "message:*lsass* OR message:*cryptdll*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 0 |  |
| q-69a68ea240 | check C240 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*lsass* OR powershell.script_block_text:*cryptdll* OR powershell.script_block_text:*Skeleton* OR powershell.script_block_text:*DCShadow*)", "time_from": null, "time_t… | 0 |  |
| q-67c8da83b1 | check C241 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*System32* AND (file.path:*.dll))", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable"… | 0 |  |
| q-02567511a4 | check C242 | search | {"dataset": "windows.sysmon", "query": "event.code:7 AND (win.ImageLoaded:*lsass* OR win.ImageLoaded:*cryptdll*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.e… | 33 |  |
| q-a5c4c54d88 | check C243 | search | {"dataset": "windows.security", "query": "event.code:4657 AND (win.ObjectName:*Notification\\ Packages* OR win.ObjectName:*Password* OR win.ObjectName:*lsass*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.… | 0 |  |
| q-7546ea6785 | check C244 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*Notification* OR process.command_line:*PasswordFilter*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.co… | 0 |  |
| q-27a6e358e0 | check C245 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*Notification* OR powershell.script_block_text:*PasswordFilter* OR powershell.script_block_text:*lsass*)", "time_from": null, "time_to": null, "fields": ["@timestamp"… | 0 |  |
| q-5765ab84b4 | check C246 | search | {"dataset": "windows.other", "query": "message:*Notification* OR message:*PasswordFilter* OR message:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.execu… | 10 |  |
| q-57d4a06a00 | check C247 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*AllowReversiblePasswordEncryption* OR powershell.script_block_text:*ReversibleEncryption* OR powershell.script_block_text:*Set-ADUser*)", "time_from": null, "time_to… | 0 |  |
| q-47ce8aae4e | check C248 | search | {"dataset": "windows.powershell", "query": "event.code:4103 AND (message:*AllowReversiblePasswordEncryption* OR message:*ReversibleEncryption*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event… | 0 |  |
| q-819db1ffde | check C249 | search | {"dataset": "windows.security", "query": "event.code:4739", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 0 |  |
| q-4311a75aac | check C250 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*Reversible* OR process.command_line:*Set-ADUser* OR process.command_line:*dsmod*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", … | 0 |  |
| q-456faac1a0 | check C251 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*Reversible* OR process.command_line:*Set-ADUser* OR process.command_line:*dsmod*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "even… | 0 |  |
| q-84f959124d | check C252 | search | {"dataset": "windows.other", "query": "message:*Reversible* OR message:*AllowReversiblePasswordEncryption*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executa… | 0 |  |
| q-0074e77e06 | check C253 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(powershell.script_block_text) LIKE \"*set-aduser*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*set-adauthenticationpolicy*\" OR TO_LOWER(powershell.script_block_text)… | ERROR |  |
| q-4130462b1f | check C253 (repaired) | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*set-aduser*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*set-adauthenticationpolicy*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*strongauthenticati… | 1 |  |
| q-e0fbe3e20e | check C254 | count | {"dataset": "windows.security", "query": "event.code:4739", "time_from": null, "time_to": null} | 0 |  |
| q-cf474e0482 | check C255 | aggregate | {"dataset": "windows.security", "field": "win.ObjectType", "query": "event.code:5136 OR event.code:4739", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-1be186b1cb | check C256 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*set-aduser*\" OR TO_LOWER(process.command_line) LIKE \"*set-adauthenticationpolicy*\" OR TO_LOWER(process.command_line) LI… | 0 |  |
| q-d521b78aa9 | check C257 | search | {"dataset": "windows.other", "query": "event.code:4739 OR event.code:5136 OR event.code:4738", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process… | 0 |  |
| q-9510c19a07 | check C258 | aggregate | {"dataset": "windows.security", "field": "win.LogonProcessName", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 297 |  |
| q-1efb68e666 | check C259 | aggregate | {"dataset": "windows.security", "field": "win.AuthenticationPackageName", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 297 |  |
| q-0282068951 | check C260 | count | {"dataset": "windows.security", "query": "event.code:5136", "time_from": null, "time_to": null} | 0 |  |
| q-2e3b711dc6 | check C261 | aggregate | {"dataset": "windows.sysmon", "field": "win.ImageLoaded", "query": "event.code:7", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 20259 |  |
| q-45584763c0 | check C262 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(powershell.script_block_text) LIKE \"*connect-msolservice*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*connect-azuread*\" OR TO_LOWER(powershell.script_block_text) L… | ERROR |  |
| q-b574146221 | check C262 (repaired) | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*connect-msolservice*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*connect-azuread*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*new-azuread*\" OR TO… | 0 |  |
| q-5ca28cefa0 | check C263 | search | {"dataset": "windows.other", "query": "event.code:5136 OR event.code:4739 OR event.code:4738", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process… | 0 |  |
| q-f9ee5bdb01 | check C264 | count | {"dataset": "windows.security", "query": "event.code:4657", "time_from": null, "time_to": null} | 36 |  |
| q-c624b4a775 | check C265 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4657\" AND (TO_LOWER(win.ObjectName) LIKE \"*networkprovider*\" OR TO_LOWER(win.ObjectName) LIKE \"*credential*\" OR TO_LOWER(win.ObjectName) LIKE \"*winlogon*\") \| KE… | 0 |  |
| q-36fe97a54c | check C266 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*networkprovider*\" OR TO_LOWER(file.path) LIKE \"*system32*credential*\" OR TO_LOWER(file.path) LIKE \"*winlogon*\") \| KEEP @timest… | 1 |  |
| q-5884808e9a | check C267 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 39283 |  |
| q-98ff4e3c5f | check C268 | aggregate | {"dataset": "windows.sysmon", "field": "win.ImageLoaded", "query": "event.code:7", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 20259 |  |
| q-8672f70cfb | check C269 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(powershell.script_block_text) LIKE \"*networkprovider*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*new-itemproperty*\" OR TO_LOWER(powershell.script_block_text) LIKE… | ERROR |  |
| q-8dc37df3a9 | check C269 (repaired) | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*networkprovider*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*new-itemproperty*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*reg add*\" \| KEEP @tim… | 0 |  |
| q-3345e03673 | check C270 | search | {"dataset": "windows.other", "query": "event.code:4657 OR event.code:11 OR event.code:7", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.comm… | 4 |  |
| q-9426fd0654 | check C271 | aggregate | {"dataset": "windows.security", "field": "win.ObjectType", "query": "event.code:4663 OR event.code:4670 OR event.code:4656", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 10977 |  |
| q-f9fc25b5ef | check C272 | aggregate | {"dataset": "windows.security", "field": "win.ProcessName", "query": "event.code:4663 OR event.code:4670 OR event.code:4656", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 10977 |  |
| q-f52a4a1b8f | check C273 | aggregate | {"dataset": "windows.sysmon", "field": "win.DestinationHostname", "query": "event.code:3", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 1229 |  |
| q-54cafa724d | check C274 | aggregate | {"dataset": "windows.sysmon", "field": "win.QueryName", "query": "event.code:22", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 81 |  |
| q-ea2b02a868 | check C275 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(powershell.script_block_text) LIKE \"*responder*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*mitm*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*arpspoof*\" OR… | ERROR |  |
| q-2b9d206c87 | check C275 (repaired) | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*responder*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*mitm*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*arpspoof*\" OR TO_LOWER(win.ScriptBlockTe… | 0 |  |
| q-f44c3e9d4a | check C276 | search | {"dataset": "windows.other", "query": "event.code:4663 OR event.code:4670 OR event.code:4656 OR event.code:3 OR event.code:22", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name… | 2 |  |
| q-e02d24be2a | check C277 | aggregate | {"dataset": "zeek", "field": "zeek.conn_state", "query": "event.action:conn", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 613 |  |
| q-33f06666ca | check C278 | aggregate | {"dataset": "zeek", "field": "zeek.service", "query": "event.action:conn", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 613 |  |
| q-6bdeee196a | check C279 | count | {"dataset": "windows.security", "query": "event.code:4697", "time_from": null, "time_to": null} | 23 |  |
| q-b447ab53fe | check C280 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4657\" AND TO_LOWER(win.ObjectName) LIKE \"*dnsclient*\" \| KEEP @timestamp, host.name, user.name, win.ObjectName, win.NewValue, _id, _index"} | 0 |  |
| q-7d9a386955 | check C281 | aggregate | {"dataset": "windows.sysmon", "field": "win.DestinationHostname", "query": "event.code:3", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 1229 |  |
| q-c51d3b6ace | check C282 | aggregate | {"dataset": "windows.sysmon", "field": "win.QueryName", "query": "event.code:22", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 81 |  |
| q-4dffc1a19d | check C283 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(powershell.script_block_text) LIKE \"*llmnr*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*nbt-ns*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*responder*\" OR … | ERROR |  |
| q-6169fb7fff | check C283 (repaired) | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*llmnr*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*nbt-ns*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*responder*\" OR TO_LOWER(win.ScriptBlockTex… | 0 |  |
| q-40fcad4e82 | check C284 | search | {"dataset": "windows.other", "query": "event.code:4697 OR event.code:4657 OR event.code:3 OR event.code:22", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executa… | 2 |  |
| q-02ea5f9cdf | check C285 | aggregate | {"dataset": "zeek", "field": "zeek.id_resp_h", "query": "event.action:conn AND zeek.service:smb", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-ae7a7445be | check C286 | aggregate | {"dataset": "zeek", "field": "zeek.query", "query": "event.action:dns", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 53 |  |
| q-ad5bdf88b8 | check C287 | aggregate | {"dataset": "windows.sysmon", "field": "win.DestinationHostname", "query": "event.code:3", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 1229 |  |
| q-1a3d2b8e66 | check C288 | aggregate | {"dataset": "windows.sysmon", "field": "win.QueryName", "query": "event.code:22", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 81 |  |
| q-9653c7abd4 | check C289 | aggregate | {"dataset": "windows.security", "field": "win.ProcessName", "query": "event.code:4663 OR event.code:4670 OR event.code:4656", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 10977 |  |
| q-c1cb31eb01 | check C290 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(powershell.script_block_text) LIKE \"*arp*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*netsh interface*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*get-netne… | ERROR |  |
| q-cf0420927d | check C290 (repaired) | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*arp*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*netsh interface*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*get-netneighbor*\" OR TO_LOWER(win.S… | 0 |  |
| q-d2691025f8 | check C291 | search | {"dataset": "windows.other", "query": "event.code:3 OR event.code:22 OR event.code:4663 OR event.code:4670", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executa… | 2 |  |
| q-1b0083c5f4 | check C292 | aggregate | {"dataset": "zeek", "field": "zeek.orig_l2_addr", "query": "event.action:conn", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 613 |  |
| q-f8b5f63359 | check C293 | aggregate | {"dataset": "zeek", "field": "zeek.resp_l2_addr", "query": "event.action:conn", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 613 |  |
| q-d5b8aff444 | check C294 | search | {"dataset": "windows.other", "query": "event.code:(1341 OR 1342 OR 1020 OR 1063)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_lin… | 0 |  |
| q-16a2ef149d | check C295 | aggregate | {"dataset": "windows.other", "field": "event.code", "query": "*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 216 |  |
| q-c9b7875f1b | check C296 | search | {"dataset": "windows.security", "query": "event.code:5156 AND win.Direction:Inbound", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_… | 0 |  |
| q-e289fe5f6b | check C297 | aggregate | {"dataset": "windows.sysmon", "field": "destination.port", "query": "event.code:3", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1229 |  |
| q-27ec005789 | check C298 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:(*Dhcp* OR *dhcp*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.… | 0 |  |
| q-893126ab80 | check C299 | aggregate | {"dataset": "zeek", "field": "event.action", "query": "*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 2140 |  |
| q-d40cab1860 | check C300 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4672", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 212 |  |
| q-8dcface14b | check C301 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 297 |  |
| q-4519830db1 | check C302 | search | {"dataset": "windows.security", "query": "event.code:4634", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 236 |  |
| q-33966b8276 | check C303 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-0883d20282 | check C304 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-5679a6a9fd | check C305 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:(*kerberos* OR *Kerberos* OR *ticket* OR *Ticket*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name",… | 0 |  |
| q-b5cffaccd4 | check C306 | search | {"dataset": "windows.other", "query": "event.code:(7045 OR 7040)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip",… | 9 |  |
| q-be958ab582 | check C307 | aggregate | {"dataset": "zeek", "field": "zeek.request_type", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 35 |  |
| q-4114aef6af | check C308 | search | {"dataset": "windows.security", "query": "event.code:4769", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 28 |  |
| q-b69115f7a8 | check C309 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4672", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 212 |  |
| q-3ef5f8e95e | check C310 | aggregate | {"dataset": "windows.security", "field": "win.TicketEncryptionType", "query": "event.code:4769", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 28 |  |
| q-2d9241953b | check C311 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-87a2b2d886 | check C312 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:(*golden* OR *Golden* OR *krbtgt* OR *KRBTGT*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "pr… | 0 |  |
| q-d04308fefe | check C313 | aggregate | {"dataset": "windows.other", "field": "event.code", "query": "*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 216 |  |
| q-b4d602262b | check C314 | aggregate | {"dataset": "zeek", "field": "zeek.request_type", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 35 |  |
| q-1d262350c4 | check C315 | search | {"dataset": "windows.security", "query": "event.code:4769", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 28 |  |
| q-6a80c6e53e | check C316 | aggregate | {"dataset": "windows.security", "field": "win.ServiceName", "query": "event.code:4769", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 28 |  |
| q-e471ed82c9 | check C317 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4672", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 212 |  |
| q-b95771ef0a | check C318 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-b68d5d32d7 | check C319 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:(*silver* OR *Silver* OR *service ticket* OR *SPN*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name"… | 0 |  |
| q-92a10671e2 | check C320 | search | {"dataset": "windows.other", "query": "event.code:(7045 OR 7040)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip",… | 9 |  |
| q-9638837557 | check C321 | aggregate | {"dataset": "zeek", "field": "zeek.request_type", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 35 |  |
| q-5fd21fd495 | check C322 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4769", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 28 |  |
| q-41cf8b5b21 | check C323 | aggregate | {"dataset": "windows.security", "field": "win.TicketEncryptionType", "query": "event.code:4769", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 28 |  |
| q-7083ce3d46 | check C324 | search | {"dataset": "windows.security", "query": "event.code:4648", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 15 |  |
| q-6506289af0 | check C325 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 297 |  |
| q-74000ee5e0 | check C326 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-acd37a296c | check C327 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:(*Kerberoast* OR *kerberoast* OR *Invoke-Kerberoast* OR *Rubeus*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code… | 0 |  |
| q-1c1baa2309 | check C328 | aggregate | {"dataset": "windows.other", "field": "event.code", "query": "*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 216 |  |
| q-254d94b88d | check C329 | aggregate | {"dataset": "zeek", "field": "zeek.request_type", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 35 |  |
| q-63e8a8048c | check C330 | search | {"dataset": "windows.security", "query": "event.code:4768", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 14 |  |
| q-e07e0a65b7 | check C331 | aggregate | {"dataset": "windows.security", "field": "win.PreAuthType", "query": "event.code:4768", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 14 |  |
| q-aeabadcae1 | check C332 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4768", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 14 |  |
| q-b6cc763f58 | check C333 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 447 |  |
| q-06aabe9a98 | check C334 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:(*AS-REP* OR *asrep* OR *GetNPUsers* OR *DontRequirePreAuth*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "… | 0 |  |
| q-573d4c3afd | check C335 | aggregate | {"dataset": "windows.other", "field": "event.code", "query": "*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 216 |  |
| q-60dd1c4e39 | check C336 | aggregate | {"dataset": "zeek", "field": "zeek.request_type", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 35 |  |
| q-ab717ede46 | check C337 | aggregate | {"dataset": "windows.security", "field": "win.LogonProcessName", "query": "event.code:4624 OR event.code:4648", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 312 |  |
| q-72c683b381 | check C338 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-60955a86c4 | check C339 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*cookie* OR powershell.script_block_text:*token* OR powershell.script_block_text:*SAML*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "… | 0 |  |
| q-bc6e62e726 | check C340 | search | {"dataset": "windows.other", "query": "event.code:7045 OR event.code:5857 OR event.code:5858", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process… | 90 |  |
| q-05347f0c35 | check C341 | aggregate | {"dataset": "zeek", "field": "event.action", "query": "event.action:http OR event.action:ssl OR event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 475 |  |
| q-9e48547fce | check C342 | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11 AND (file.path:*cookie* OR file.path:*Cookies*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1 |  |
| q-ebe26be2b2 | check C343 | aggregate | {"dataset": "windows.security", "field": "win.LogonProcessName", "query": "event.code:4624 OR event.code:4648", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 312 |  |
| q-f8492f7cb5 | check C344 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*cookie* OR powershell.script_block_text:*Set-Cookie* OR powershell.script_block_text:*session*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.… | 0 |  |
| q-3e060d82fd | check C345 | search | {"dataset": "windows.other", "query": "event.code:11 OR event.code:16", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source… | 9 |  |
| q-d6a6ad4ac9 | check C346 | search | {"dataset": "zeek", "query": "event.action:http AND http.request.method:*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "so… | 62 | F51 |
| q-0aa95155df | check C347 | aggregate | {"dataset": "windows.security", "field": "win.LogonProcessName", "query": "event.code:4624 OR event.code:4648", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 312 |  |
| q-7b0d8c026a | check C348 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*SAML* OR powershell.script_block_text:*NotOnOrAfter* OR powershell.script_block_text:*Assertion*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "hos… | 0 |  |
| q-278d787f12 | check C349 | search | {"dataset": "windows.other", "query": "event.code:7045 OR event.code:5857 OR event.code:5858", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process… | 90 |  |
| q-b549eb1bbf | check C350 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*saml* OR process.command_line:*token* OR process.command_line:*cert*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-17449123f2 | check C351 | search | {"dataset": "zeek", "query": "event.action:http AND (url.original:*saml* OR url.original:*adfs* OR url.original:*token*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "p… | 0 |  |
| q-a1a5a8c034 | check C352 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-d6aac0d8bc | check C353 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-bd431fb1c6 | check C354 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*MFA* OR powershell.script_block_text:*2FA* OR powershell.script_block_text:*Authenticator*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name… | 0 |  |
| q-b727fc4189 | check C355 | search | {"dataset": "windows.other", "query": "event.code:4625 OR event.code:5857 OR event.code:5858", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process… | 85 | F53 |
| q-70de95794b | check C356 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*login* OR process.command_line:*auth* OR process.command_line:*mfa*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-8fbb39d277 | check C357 | search | {"dataset": "zeek", "query": "event.action:http AND (url.original:*login* OR url.original:*auth* OR url.original:*mfa*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "pr… | 0 |  |
| q-6a05260752 | check C358 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4657", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 36 |  |
| q-f1969d7666 | check C359 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4768", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 14 |  |
| q-85ec986220 | check C360 | aggregate | {"dataset": "windows.sysmon", "field": "registry.path", "query": "event.code:13 AND (registry.path:*Certificate* OR registry.path:*Crypto* OR registry.path:*Keys*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1133 |  |
| q-b1686c2861 | check C361 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*Certificate* OR powershell.script_block_text:*Export-PfxCertificate* OR powershell.script_block_text:*New-SelfSignedCertificate*)", "time_from": null, "time_to": nul… | 0 |  |
| q-ded2f23a6e | check C362 | search | {"dataset": "windows.other", "query": "event.code:7045 OR event.code:5857 OR event.code:5858", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process… | 90 |  |
| q-c5a026d930 | check C363 | aggregate | {"dataset": "zeek", "field": "zeek.certificate_subject", "query": "event.action:x509", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 378 |  |
| q-ed3c34cf97 | triage T1003 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND (win.GrantedAccess:0x1fffff OR win.GrantedAccess:0x1f3fff OR win.GrantedAccess:0x101001 OR win.GrantedAccess:0x1000000 OR win.GrantedAccess:0x3000 OR win.GrantedAccess:0x1400… | 33 |  |
| q-dfbd56f0fb | triage T1003 step 1 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO9rO3D"} | None | F03 |
| q-a9231dd6ea | triage T1003 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None | F01 |
| q-6160612708 | triage T1003 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None | F01 |
| q-043b026fd8 | triage T1003 step 2 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*lsass*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*mimikatz*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*sekurlsa*… | 0 |  |
| q-7a613058cb | triage T1003 step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*credential*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*password*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*dump… | 26 | F01, F02 |
| q-ec91829c58 | triage T1003 step 3 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4688\" AND (TO_LOWER(process.command_line) LIKE \"*lsass*\" OR TO_LOWER(process.command_line) LIKE \"*dump*\" OR TO_LOWER(process.command_line) LIKE \"*credential*\" OR… | 1 |  |
| q-8835da1979 | triage T1003 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND process.executable LIKE \"*powershell*\" \| KEEP @timestamp, host.name, user.name, process.executable, process.command_line, process.parent.executable, _id, _inde… | 12 |  |
| q-360e95bd1f | triage T1003 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"13\" AND registry.path LIKE \"*SAM*\" \| KEEP @timestamp, host.name, process.executable, registry.path, registry.data.strings, _id, _index"} | 2 |  |
| q-a28a3eb270 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-3b64de1334 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-7e3b73fb24 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-abcbdbe8ba | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None |  |
| q-b93fd36a9d | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None |  |
| q-c7e8be9ae7 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZKhD3z"} | None |  |
| q-a68dddc2cb | triage T1003 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-9a06eec301 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZCgBha"} | None |  |
| q-848402264e | triage T1003 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZJhF-L"} | None |  |
| q-94ac653ade | triage T1003 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSmWOt"} | None |  |
| q-033d0b0d3a | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO9rO3D"} | None |  |
| q-36f6435886 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO9rO3D"} | None |  |
| q-c0d967e442 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTVGQnT"} | None |  |
| q-538846a6db | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTVGQnT"} | None |  |
| q-b25536b19c | triage T1040 step 1 | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8TL"} | None |  |
| q-45025c9d24 | triage T1040 step 1 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.executable:*NetworkWatcher* OR process.executable:*pcap* OR process.executable:*dump* OR process.executable:*netsh* OR process.executable:*logman*)", "time_from": null, "time_to": null, "fi… | 13 | F05 |
| q-6cfb643b20 | triage T1040 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*pcap* OR process.command_line:*sniff* OR process.command_line:*promisc* OR process.command_line:*netsh* OR process.command_line:*logman* OR process.command_line:*NetworkWatcher*)",… | 14 | F05, F06 |
| q-2c528a6209 | triage T1040 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.executable:*python* OR process.executable:*PsExec* OR process.executable:*sdelete* OR process.executable:*PSEXESVC*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "… | 19 | F07 |
| q-03004d0833 | triage T1040 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:6 AND (win.Image:*npcap* OR win.Image:*pcap* OR win.Image:*winpcap* OR win.Image:*NetworkWatcher* OR win.Image:*ndiscap* OR win.Image:*netmon*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "h… | 0 |  |
| q-8037fea8a1 | triage T1040 step 2 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*pcap* OR win.ScriptBlockText:*sniff* OR win.ScriptBlockText:*promisc* OR win.ScriptBlockText:*netsh* OR win.ScriptBlockText:*capture*)", "time_from": null, "time_to": null, "… | 0 |  |
| q-7f74eaf915 | triage T1040 step 3 | search | {"dataset": "windows.sysmon", "query": "host.name:nashua.dmevals.local AND (process.executable:*python* OR win.Image:*python* OR win.TargetFilename:*python*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "process.exec… | 515 |  |
| q-05d41ba32d | triage T1040 step 3 | search | {"dataset": "windows.sysmon", "query": "event.code:22 AND (win.QueryName:* OR win.DestinationIp:*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "process.executable", "process.command_line", "win.QueryName", "win.Dest… | 81 |  |
| q-cf9ced48ea | triage T1040 step 3 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"conn\" \| STATS cnt = COUNT(*) BY network.transport, destination.port \| SORT cnt DESC \| LIMIT 30"} | 17 |  |
| q-80a1984ab2 | triage T1040 step 4 | search | {"dataset": "windows.sysmon", "query": "event.code:3 AND process.executable:*python*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "process.executable", "win.DestinationIp", "win.DestinationPort", "win.Protocol", "win… | 348 | F07 |
| q-7dfe59d1b2 | triage T1040 step 4 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"conn\" AND (network.transport == \"icmp\" OR destination.port == 1234 OR source.port == 1234) \| KEEP @timestamp, source.ip, destination.ip, destination.port, network.transport, … | 1 |  |
| q-fbeba8de36 | triage T1040 step 4 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"notice\" OR event.action == \"weird\" \| KEEP @timestamp, event.action, zeek.note, zeek.msg, source.ip, destination.ip, _id, _index \| LIMIT 30"} | 14 |  |
| q-a180390093 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItPM8kte"} | None |  |
| q-66d9765ddb | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO9qRCx"} | None |  |
| q-20ddb72318 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVt4o2y"} | None |  |
| q-80841f730a | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItPM8kte"} | None |  |
| q-7d4c922121 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTVGglR"} | None |  |
| q-135b4c28a6 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTVGQmt"} | None |  |
| q-d9e4be9170 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItPK66ha"} | None |  |
| q-8fe5725db9 | triage T1056 step 1 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKA_"} | None | F09 |
| q-fa59f1d49a | triage T1056 step 1 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTtmJQ5"} | None | F10 |
| q-4b40ade0e7 | triage T1056 step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND win.TargetImage LIKE \"*lsass*\" \| STATS c = COUNT(*) BY process.executable, win.GrantedAccess \| SORT c DESC"} | 15 |  |
| q-12a16f098c | triage T1056 step 1 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" \| KEEP @timestamp, host.name, user.name, win.ScriptBlockText, _id, _index \| LIMIT 20"} | 20 | F11, F12 |
| q-dc332aa75f | triage T1056 step 2 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRkUVV"} | None | F08 |
| q-70846dec16 | triage T1056 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND win.TargetImage LIKE \"*lsass*\" AND win.GrantedAccess IN (\"0x1f3fff\",\"0x1fffff\",\"0x101001\",\"0x1f0fff\",\"0x143a\",\"0x1410\") \| KEEP @timestamp, host.na… | 7 | F09 |
| q-8a7bc951a4 | triage T1056 step 2 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND win.ScriptBlockText LIKE \"*UnsafeNativeMethods*\" \| KEEP @timestamp, host.name, user.name, win.ScriptBlockText, _id, _index"} | 2 |  |
| q-373901e8ed | triage T1056 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND process.executable LIKE \"*powershell*\" \| KEEP @timestamp, host.name, user.name, process.command_line, process.parent.executable, _id, _index \| LIMIT 30"} | 12 | F08 |
| q-bbd3ea99d5 | triage T1056 step 3 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4656\" AND win.ObjectType == \"SAM_SERVER\" \| KEEP @timestamp, host.name, user.name, process.executable, win.ObjectName, win.AccessMask, _id, _index"} | 10 |  |
| q-a715238914 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRkUVV"} | None |  |
| q-b167d5893e | triage T1056 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRkUVV"} | None |  |
| q-54bebcac92 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRkUVV"} | None |  |
| q-20371d5356 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRkUVV"} | None |  |
| q-20ceb5d267 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOcHa1B"} | None |  |
| q-3c45b0bdac | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQB61zZ"} | None |  |
| q-8de56bc5aa | triage T1056 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKA_"} | None |  |
| q-4d0ff74ff1 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKA_"} | None |  |
| q-f90b01a4b3 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKA_"} | None |  |
| q-4cbdf22b2a | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gj"} | None |  |
| q-5f894e189a | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-6a042fcc0b | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None |  |
| q-4e28d375db | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None |  |
| q-28134ebb2a | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTtmJQ5"} | None |  |
| q-98cba73bd3 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRkUeo"} | None |  |
| q-09209009db | triage T1056 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRkUep"} | None |  |
| q-ac01685190 | triage T1110 step 1 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ev8p"} | None | F13, F16 |
| q-630a64acfb | triage T1110 step 1 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItV19Rnb"} | None | F16 |
| q-682b4f059d | triage T1110 step 1 | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8RS"} | None | F17 |
| q-c3b4612045 | triage T1110 step 1 | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8TL"} | None |  |
| q-f398128ace | triage T1110 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND TO_LOWER(win.TargetImage) LIKE \"*lsass*\" \| STATS cnt = COUNT(*) BY process.executable, win.GrantedAccess, host.name \| SORT cnt DESC \| LIMIT 30"} | 18 |  |
| q-a576cf4b26 | triage T1110 step 2 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4663\" AND win.ObjectName LIKE \"*SAM*\" \| KEEP @timestamp, host.name, win.ObjectName, win.ProcessName, win.AccessMask, win.SubjectUserName, _id, _index \| LIMIT 20"} | 0 |  |
| q-aebeb975a8 | triage T1110 step 2 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4624\" \| STATS cnt = COUNT(*) BY win.LogonType, win.TargetUserName, host.name \| SORT cnt DESC \| LIMIT 30"} | 23 |  |
| q-53deedd36a | triage T1110 step 3 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4663\" AND win.ObjectName == \"SAM\" \| KEEP @timestamp, host.name, win.ObjectName, win.ProcessName, win.AccessMask, win.SubjectUserName, _id, _index \| LIMIT 20"} | 0 |  |
| q-b30e7e5293 | triage T1110 step 3 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4648\" \| STATS cnt = COUNT(*) BY win.ProcessName, win.TargetUserName, host.name \| SORT cnt DESC \| LIMIT 30"} | 9 |  |
| q-01003cc531 | triage T1110 step 4 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4625\" OR event.code == \"4771\" OR event.code == \"4776\" \| STATS cnt = COUNT(*) BY event.code, win.TargetUserName, source.ip \| SORT cnt DESC \| LIMIT 30"} | 1 |  |
| q-63b31b208a | triage T1110 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*password*\" OR TO_LOWER(process.command_line) LIKE \"*credential*\" OR TO_LOWER(process.command_line) LIKE \"*brute*\" OR … | 0 |  |
| q-fa3ec49aaf | triage T1110 step 5 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4776\" \| KEEP @timestamp, host.name, win.TargetUserName, win.Status, win.Workstation, _id, _index \| LIMIT 5"} | 1 | F13 |
| q-a42f1b8ad5 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVn1FNc"} | None |  |
| q-9a51b4938f | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ev8p"} | None |  |
| q-951370a4ec | triage T1110 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8RY"} | None |  |
| q-254b4f971a | triage T1110 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8Rb"} | None |  |
| q-17bc875a1a | triage T1110 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "q-f398128ace"} | ERROR |  |
| q-6faf73c2f7 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "q-f039c6da00"} | ERROR |  |
| q-3e9f0d37c3 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ev8p"} | None |  |
| q-f5191a44c9 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItV19Rnb"} | None |  |
| q-b4167bd94c | triage T1110 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8R_"} | None |  |
| q-97cd8c824c | triage T1110 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8RS"} | None |  |
| q-326308520f | triage T1110 step 7 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND TO_LOWER(win.TargetImage) LIKE \"*lsass*\" AND process.executable LIKE \"*svchost*\" \| KEEP @timestamp, host.name, process.executable, win.GrantedAccess, _id, _… | 3 | F15 |
| q-bb41c1f2d5 | triage T1110 step 7 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND win.TargetFilename LIKE \"*SysinternalsSuite*\" \| KEEP @timestamp, host.name, win.TargetFilename, _id, _index \| LIMIT 3"} | 3 |  |
| q-0555bd48af | triage T1110 step 8 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTkbkGF"} | None | F15 |
| q-0ae28fc9a5 | triage T1111 step 1 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ev8p"} | None | F18 |
| q-9a408c2d69 | triage T1111 step 1 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVn01NG"} | None | F18 |
| q-ed825ef790 | triage T1111 step 1 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO9rO3Z"} | None | F18 |
| q-77b6441167 | triage T1111 step 1 | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8R_"} | None | F18 |
| q-c66f30be79 | triage T1111 step 2 | search | {"dataset": "windows.security", "query": "event.code:4624 AND win.LogonType:2", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "win.LogonType", "win.AuthenticationPackageName", "win.LogonProcessName", "source.ip", "win.I… | 15 |  |
| q-eb03887a17 | triage T1111 step 2 | search | {"dataset": "windows.security", "query": "event.code:4624 AND win.LogonType:10", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "win.LogonType", "win.AuthenticationPackageName", "win.LogonProcessName", "source.ip", "win.… | 2 |  |
| q-aa5651f3d0 | triage T1111 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*smartcard* OR process.command_line:*SmartCard* OR process.command_line:*MFA* OR process.command_line:*token*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.n… | 0 |  |
| q-3dcfde8632 | triage T1111 step 3 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.executable:*PSEXESVC* OR process.command_line:*psexec* OR process.command_line:*PSEXESVC*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "process.executable", "proc… | 4 |  |
| q-c54d5e722c | triage T1111 step 3 | search | {"dataset": "windows.sysmon", "query": "event.code:13 AND (registry.path:*Smartcard* OR registry.path:*SmartCard* OR registry.path:*MFA* OR registry.path:*Token* OR registry.path:*DeviceGuard*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "ho… | 31 | F18 |
| q-a816957f79 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ev8p"} | None |  |
| q-c45246c771 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ev8p"} | None |  |
| q-d783ac495d | triage T1111 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVn01NG"} | None |  |
| q-fa733bae6f | triage T1111 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO9rO3Z"} | None |  |
| q-680534642d | triage T1111 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO9rO3Z"} | None |  |
| q-0bf385fccc | triage T1111 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8R_"} | None |  |
| q-9964c0fffb | triage T1111 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItT_4wsv"} | None |  |
| q-4873342aa2 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItT_4wsv"} | None |  |
| q-1270e751a4 | triage T1187 step 1 | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrYjN"} | None | F19 |
| q-7ad3c0a9bb | triage T1187 step 1 | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrYgN"} | None | F19 |
| q-fc16bb6d5c | triage T1187 step 1 | aggregate | {"dataset": "zeek", "field": "source.ip", "query": "event.action:http AND (http.request.method:PROPFIND OR http.request.method:MOVE OR http.request.method:OPTIONS)", "time_from": null, "time_to": null, "size": 20, "sub_field": "destination.ip"} | 36 |  |
| q-8e1ca0c613 | triage T1187 step 1 | aggregate | {"dataset": "zeek", "field": "user_agent.original", "query": "event.action:http", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 62 |  |
| q-a5fc2eb428 | triage T1187 step 2 | aggregate | {"dataset": "zeek", "field": "source.ip", "query": "event.action:conn AND (destination.port:445 OR destination.port:139)", "time_from": null, "time_to": null, "size": 20, "sub_field": "destination.ip"} | 50 |  |
| q-ef7a98604c | triage T1187 step 2 | aggregate | {"dataset": "windows.security", "field": "win.ShareName", "query": "event.code:5140 OR event.code:5145", "time_from": null, "time_to": null, "size": 20, "sub_field": "source.ip"} | 163 |  |
| q-7557d50e70 | triage T1187 step 2 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4624 AND win.LogonType:3", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 218 |  |
| q-94b4d4fd48 | triage T1187 step 2 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"http\" AND http.request.method == \"PROPFIND\" \| KEEP @timestamp, source.ip, destination.ip, url.original, http.response.status_code, _id, _index \| LIMIT 40"} | 26 | F19 |
| q-e10e237bf0 | triage T1187 step 3 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"conn\" AND destination.ip == \"192.168.0.4\" \| KEEP @timestamp, source.ip, destination.ip, destination.port, network.transport, _id, _index \| LIMIT 30"} | 30 | F19 |
| q-0cd1e667c3 | triage T1187 step 3 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == 4624 AND win.LogonType == 3 \| KEEP @timestamp, host.name, win.TargetUserName, win.IpAddress, win.Workstation, _id, _index \| LIMIT 40"} | ERROR |  |
| q-4dda1d0e0b | triage T1187 step 4 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4624\" AND win.LogonType == \"3\" \| KEEP @timestamp, host.name, win.TargetUserName, win.IpAddress, win.Workstation, _id, _index \| LIMIT 40"} | 40 | F20 |
| q-cb899d56ff | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrYjN"} | None |  |
| q-13a85b957b | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrYjN"} | None |  |
| q-974f32864b | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrYgN"} | None |  |
| q-59534e1861 | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrYgN"} | None |  |
| q-559716cc2a | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrYi8"} | None |  |
| q-b552ab35b3 | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrogt"} | None |  |
| q-26f0af23cd | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrYiQ"} | None |  |
| q-2fc3668ed3 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaKWxp4"} | None |  |
| q-86d392638e | triage T1187 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaFQQtn"} | None |  |
| q-0b35b800cb | triage T1187 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVcwORA"} | None |  |
| q-726bf9f147 | triage T1212 step 1 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 326 |  |
| q-d9af1a6b1b | triage T1212 step 1 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 326 |  |
| q-2605eb1300 | triage T1212 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND (win.GrantedAccess:0x1fffff OR win.GrantedAccess:0x101001 OR win.GrantedAccess:0x1f3fff OR win.GrantedAccess:0x1000000 OR win.GrantedAccess:0x3000)", "time_from": null, "time… | 9 | F21 |
| q-2468eb0538 | triage T1212 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND (process.executable:*PowerShell* OR process.executable:*wsmprovhost*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.data… | 5 |  |
| q-7628f4845a | triage T1212 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None | F22 |
| q-1cf5a0f97a | triage T1212 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None | F22 |
| q-1929572d20 | triage T1212 step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == 4104 \| KEEP @timestamp, host.name, user.name, win.ScriptBlockText, _id, _index \| LIMIT 30"} | ERROR |  |
| q-541c9cb2d8 | triage T1212 step 4 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*lsass* OR process.command_line:*MiniDump* OR process.command_line:*sekurlsa* OR process.command_line:*procdump* OR process.command_line:*comsvcs*)", "time_from": null, "time_to": n… | 1 | F22 |
| q-126f60d032 | triage T1212 step 5 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" \| KEEP @timestamp, host.name, user.name, win.ScriptBlockText, _id, _index \| LIMIT 25"} | 25 | F21 |
| q-f9459d65da | triage T1212 step 5 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND process.executable:*wsmprovhost*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.co… | 1 |  |
| q-31fb7e025a | triage T1212 step 6 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRkUVV"} | None | F21 |
| q-9eae031d2c | triage T1212 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRkUVV"} | None |  |
| q-dd7319e452 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRkUVV"} | None |  |
| q-9dcfdb16a8 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRkUVV"} | None |  |
| q-84da3364ed | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-ea14d12610 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-2dd4e779e0 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None |  |
| q-81cc443072 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None |  |
| q-99486927f7 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-67f5494477 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None |  |
| q-ef0ef44315 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO9re0C"} | None |  |
| q-4d15c559c1 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ8FraW"} | None |  |
| q-8abad45151 | triage T1212 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrYiq"} | None |  |
| q-d984ae27b1 | triage T1539 step 1 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOVAUl3"} | None | F25 |
| q-dc1d2b4135 | triage T1539 step 1 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ8Frba"} | None | F24 |
| q-d97291f20d | triage T1539 step 1 | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrog-"} | None | F26 |
| q-ca5460051c | triage T1539 step 2 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == 4688 AND process.command_line LIKE \"*davclnt*\" \| KEEP @timestamp, host.name, user.name, process.executable, process.command_line, _id, _index"} | ERROR |  |
| q-78e4ead50b | triage T1539 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 1 AND (TO_LOWER(process.command_line) LIKE \"*cookie*\" OR TO_LOWER(process.command_line) LIKE \"*webdav*\" OR TO_LOWER(process.command_line) LIKE \"*davclnt*\") \| KEEP @t… | ERROR |  |
| q-f119dd1644 | triage T1539 step 3 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4688\" AND process.command_line LIKE \"*davclnt*\" \| KEEP @timestamp, host.name, user.name, process.executable, process.command_line, _id, _index"} | 5 |  |
| q-1a5520809c | triage T1539 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*cookie*\" OR TO_LOWER(process.command_line) LIKE \"*webdav*\" OR TO_LOWER(process.command_line) LIKE \"*davclnt*\") \| KEE… | 5 | F24 |
| q-db816fabb9 | triage T1539 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND TO_LOWER(process.executable) LIKE \"*python*\" \| KEEP @timestamp, host.name, user.name, process.executable, process.command_line, process.parent.executable, _id,… | 5 | F26 |
| q-accf4611e9 | triage T1539 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND TO_LOWER(win.TargetFilename) LIKE \"*inetcookies*\" \| KEEP @timestamp, host.name, process.executable, win.TargetFilename, _id, _index"} | 1 |  |
| q-42b9f0f735 | triage T1539 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ8Frba"} | None |  |
| q-a5b65e7f5d | triage T1539 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ8Frba"} | None |  |
| q-d88427901a | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTVHe6C"} | None |  |
| q-9dbef4a6a3 | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOVAUl3"} | None |  |
| q-7d4c878e4a | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOVAUl3"} | None |  |
| q-303cc19b6e | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItPK66i5"} | None |  |
| q-cd51739882 | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItPK66i5"} | None |  |
| q-716ab7563f | triage T1539 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrog-"} | None |  |
| q-daf20c2843 | triage T1552 step 1 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTkbkGF"} | None | F28 |
| q-e1fb326b6f | triage T1552 step 1 | search | {"dataset": "windows.sysmon", "query": "process.executable:*accesschk* OR process.command_line:*accesschk*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executa… | 2 |  |
| q-acf7a848fb | triage T1552 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND win.TargetFilename:*passwordsDB*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.c… | 1 |  |
| q-db3ae06d91 | triage T1552 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*passwordsDB* OR process.command_line:*accesschk*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.… | 1 |  |
| q-789d257815 | triage T1552 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTkbkGg"} | None | F28 |
| q-7d49bad326 | triage T1552 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (win.TargetFilename:*SysinternalsSuite* OR win.TargetFilename:*passwords*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "us… | 311 |  |
| q-595370eab2 | triage T1552 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND user.name:pbeesly", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "s… | 141 |  |
| q-341c0b0e3e | triage T1552 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND win.TargetFilename:*GptTmpl*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.comma… | 3 | F29 |
| q-660e83e56a | triage T1552 step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*password*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*credential*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*accessch… | 12 |  |
| q-96b4bbad7b | triage T1552 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND TO_LOWER(process.command_line) LIKE \"*passwordsdb*\" \| KEEP @timestamp, host.name, user.name, process.executable, process.command_line, _id, _index \| LIMIT 20"… | 0 |  |
| q-817f3b3563 | triage T1552 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(win.TargetFilename) LIKE \"*passwordsdb*\" OR TO_LOWER(win.TargetFilename) LIKE \"*sysinternals*\") \| KEEP @timestamp, host.name, win.TargetFilename, … | 30 |  |
| q-9d1fe851d5 | triage T1552 step 4 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None | F27 |
| q-e25275fd76 | triage T1552 step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*get-privatekeys*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*.pfx*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*cert:\\… | ERROR |  |
| q-66ba5382f4 | triage T1552 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*groups.xml*\" OR TO_LOWER(process.command_line) LIKE \"*cpassword*\" OR TO_LOWER(process.command_line) LIKE \"*gpp*\" OR T… | 0 |  |
| q-9c9f90a6c8 | triage T1552 step 5 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*invoke-exfil*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*7zip*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*officeSupp… | 4 |  |
| q-094637c4b2 | triage T1552 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*cpassword*\" OR TO_LOWER(process.command_line) LIKE \"*groups.xml*\" OR TO_LOWER(process.command_line) LIKE \"*gpp*\") \| … | 0 |  |
| q-3f3541c9cf | triage T1552 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND TO_LOWER(process.command_line) LIKE \"*accesschk*\" \| KEEP @timestamp, host.name, user.name, process.executable, process.command_line, _id, _index \| LIMIT 20"} | 1 |  |
| q-c176a505ff | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-51d84ff82b | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-6adb51a562 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-ec41e65cbc | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-51b026aa89 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTkbkGg"} | None |  |
| q-deaa08cc99 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTkbkGg"} | None |  |
| q-610ce1e201 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTkbkGF"} | None |  |
| q-0fc2a19c22 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTkbkGg"} | None |  |
| q-6bc718951e | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTqhAkt"} | None |  |
| q-d0204798cb | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTqhAkt"} | None |  |
| q-6c73295346 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItUHBzVa"} | ERROR |  |
| q-b7576ecca8 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItThYt63"} | None |  |
| q-a801a9c65d | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO9rO3Z"} | None |  |
| q-51b0122383 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItKT-1UH"} | None |  |
| q-d0045a98b1 | triage T1552 step 7 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItUHBzVa"} | ERROR |  |
| q-a7cf3bf353 | triage T1555 step 1 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKB-"} | None |  |
| q-ed74f66311 | triage T1555 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZCgBha"} | None |  |
| q-2f8445d78a | triage T1555 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND TO_LOWER(win.TargetImage) LIKE \"*lsass.exe\" AND win.GrantedAccess IN (\"0x1fffff\",\"0x1f3fff\",\"0x101001\",\"0x1000000\",\"0x3000\") \| KEEP @timestamp, host… | 9 | F31 |
| q-1e28461a9c | triage T1555 step 2 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND TO_LOWER(COALESCE(win.ScriptBlockText,\"\")) LIKE \"*lsass*\" \| KEEP @timestamp, host.name, user.name, win.ScriptBlockText, _id, _index"} | 0 |  |
| q-5b72d9f3d6 | triage T1555 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None | F31 |
| q-594d3f6450 | triage T1555 step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(COALESCE(win.ScriptBlockText,\"\")) LIKE \"*invoke-mimi*\" OR TO_LOWER(COALESCE(win.ScriptBlockText,\"\")) LIKE \"*dump*\" OR TO_LOWER(COALESCE(w… | 0 |  |
| q-4d7271fedb | triage T1555 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND process.pid == 2976 \| KEEP @timestamp, host.name, user.name, process.executable, process.command_line, process.parent.executable, _id, _index"} | 1 | F31 |
| q-24cbf2da02 | triage T1555 step 4 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4688\" AND (TO_LOWER(process.command_line) LIKE \"*lsass*\" OR TO_LOWER(process.command_line) LIKE \"*dump*\" OR TO_LOWER(process.command_line) LIKE \"*credential*\" OR… | 0 |  |
| q-18372e0cea | triage T1555 step 5 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQB61zZ"} | None |  |
| q-8c3e41f8c1 | triage T1555 step 5 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None | F31 |
| q-8660874423 | triage T1555 step 6 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4663\",\"4656\") AND TO_LOWER(win.ObjectName) LIKE \"*lsass*\" AND win.AccessMask IN (\"0x1fffff\",\"0x1f3fff\",\"0x101001\") \| KEEP @timestamp, host.name, user.name,… | 4 | F31, F32 |
| q-87335c2b16 | triage T1555 step 6 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*credential*\" OR TO_LOWER(file.path) LIKE \"*vault*\" OR TO_LOWER(file.path) LIKE \"*.rdg\" OR TO_LOWER(file.path) LIKE \"*dpapi*\" … | 0 |  |
| q-a78040ffba | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-b762651af8 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-562129db72 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-8ea769137d | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None |  |
| q-ddce849baf | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None |  |
| q-b286b8267a | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQB61zZ"} | None |  |
| q-1cca736941 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKB-"} | None |  |
| q-e95ea44a7d | triage T1555 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ8FLV1"} | None |  |
| q-c305548ff0 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKB-"} | None |  |
| q-9361008706 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKB-"} | None |  |
| q-2c5f76ee8b | triage T1555 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ8FLV1"} | None |  |
| q-48c80c5158 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVq1T69"} | None |  |
| q-1de3714847 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOVAkmV"} | None |  |
| q-266c7fe3cd | triage T1556 step 1 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 326 |  |
| q-c59a3b1325 | triage T1556 step 1 | aggregate | {"dataset": "windows.sysmon", "field": "win.SourceImage", "query": "event.code:10 AND win.TargetImage:*lsass* AND NOT win.SourceImage:*svchost*", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 37 |  |
| q-fd6d5e496c | triage T1556 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND (win.GrantedAccess:0x1fffff OR win.GrantedAccess:0x101001 OR win.GrantedAccess:0x1f3fff OR win.GrantedAccess:0x1000000 OR win.GrantedAccess:0x3000 OR win.GrantedAccess:0x1400… | 33 | F34 |
| q-cfb18a77f5 | triage T1556 step 2 | search | {"dataset": "windows.security", "query": "event.code:4648 AND user.name:pbeesly", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "process.executable", "win.TargetServerName", "win.TargetUserName", "win.IpAddress", "win.S… | 9 | F35 |
| q-e9617327d8 | triage T1556 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-1b7617d472 | triage T1556 step 3 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*MiniDump* OR win.ScriptBlockText:*Dump* OR win.ScriptBlockText:*Credential* OR win.ScriptBlockText:*sekurlsa* OR win.ScriptBlockText:*Invoke-Mi… | 3 | F39 |
| q-fe7ad2d060 | triage T1556 step 4 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND process.pid:2976", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "process.pid", "process.command_line", "process.executable", "user.name", "win.ParentImage"], "s… | 1 | F34 |
| q-c5efd11a52 | triage T1556 step 4 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Invoke-Mimikatz* OR win.ScriptBlockText:*sekurlsa* OR win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*DumpCred* OR win.ScriptBlockText:*Get-Credential* OR win.ScriptBlock… | 0 |  |
| q-41a9ccdcfa | triage T1556 step 5 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQB61zZ"} | None |  |
| q-be4b5713f0 | triage T1556 step 5 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND user.name:pbeesly", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "user.name", "win.ScriptBlockText", "message"], "size": 30, "sort": "asc"} | 157 |  |
| q-bbc1d787f7 | triage T1556 step 6 | search | {"dataset": "windows.security", "query": "event.code:4648 AND process.executable:*PSEXESVC*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "user.name", "process.executable", "win.TargetUserName", "win.TargetServerName… | 4 |  |
| q-47496adea8 | triage T1556 step 6 | search | {"dataset": "windows.sysmon", "query": "(event.code:11 AND (win.TargetFilename:*cryptdll* OR win.TargetFilename:*msv1_0* OR win.TargetFilename:*Skeleton* OR win.TargetFilename:*pfilter*)) OR (event.code:13 AND (registry.path:*Notification* OR registry.path:*Pa… | 449 | F36, F40 |
| q-f815ee3c3c | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-54d157f819 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-f3b50a251e | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-b3df79e511 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQB61zZ"} | None |  |
| q-f5d66f5fe5 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQB61zZ"} | None |  |
| q-521a0b2fb0 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaKXhpQ"} | None |  |
| q-9a93dac57f | triage T1556 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ev8p"} | None |  |
| q-525b935177 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ev9J"} | None |  |
| q-ac3618e11d | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQC7zHD"} | None |  |
| q-eecd048f8c | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQC7zHD"} | None |  |
| q-9e36d2617c | triage T1556 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ev9J"} | None |  |
| q-d54d9177d1 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ev9J"} | None |  |
| q-9b806db29c | triage T1556 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZCgBha"} | None |  |
| q-65b39e5a38 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQC7zHD"} | None |  |
| q-32a9bf5a4d | triage T1557 step 1 | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8RT"} | None |  |
| q-5440ebf61e | triage T1557 step 1 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"conn\" AND zeek.resp_l2_addr == \"12:34:56:78:9a:bc\" \| KEEP @timestamp, source.ip, destination.ip, destination.port, zeek.service, zeek.orig_l2_addr, zeek.resp_l2_addr, zeek.co… | 20 | F43 |
| q-0596d90661 | triage T1557 step 2 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"conn\" AND zeek.service LIKE \"*smb*\" \| KEEP @timestamp, source.ip, destination.ip, destination.port, zeek.service, zeek.conn_state, zeek.orig_l2_addr, zeek.resp_l2_addr, _id, … | 16 | F42 |
| q-047362de6f | triage T1557 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"3\" AND (destination.port == 67 OR destination.port == 68 OR destination.port == 137 OR destination.port == 138 OR destination.port == 5355) \| KEEP @timestamp, host.name… | 24 |  |
| q-86ca22fea6 | triage T1557 step 3 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4697\" \| KEEP @timestamp, host.name, user.name, win.ServiceName, win.ServiceFileName, win.ServiceType, _id, _index \| LIMIT 25"} | 23 | F42 |
| q-73717aa89c | triage T1557 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*netsh*\" OR TO_LOWER(process.command_line) LIKE \"*arp *\" OR TO_LOWER(process.command_line) LIKE \"*dhcp*\" OR TO_LOWER(p… | 6 | F41, F44 |
| q-af79c82954 | triage T1557 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE host.name == \"scranton.dmevals.local\" AND @timestamp >= \"2020-05-02T03:18:00.000Z\" AND @timestamp <= \"2020-05-02T03:21:00.000Z\" AND event.code == \"1\" \| KEEP @timestamp, user.nam… | 40 |  |
| q-0d3d016605 | triage T1557 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.executable) LIKE \"*psexec*\" OR TO_LOWER(process.executable) LIKE \"*javamtsup*\" OR TO_LOWER(process.command_line) LIKE \"*javamtsup*\") \| KE… | 5 |  |
| q-51088befbc | triage T1557 step 5 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOlQHAt"} | None |  |
| q-b91a06eb31 | triage T1557 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.executable) LIKE \"*arp.exe*\" OR TO_LOWER(process.command_line) LIKE \"*arp -a*\" OR TO_LOWER(process.command_line) LIKE \"*arp.exe*\") \| KEEP… | 3 | F41, F43 |
| q-0d8658f3da | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItPM8kte"} | None |  |
| q-f61ef6306b | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOrW_1k"} | None |  |
| q-0f652fb878 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItPE0PcG"} | None |  |
| q-a554a4bacc | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgroge"} | None |  |
| q-317e0800c9 | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgroge"} | None |  |
| q-60315223e5 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7DT5G"} | None |  |
| q-a1056d2599 | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrohb"} | None |  |
| q-c3e239ee3f | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOtYA8Z"} | None |  |
| q-d7b7dafb62 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOtYA8Z"} | None |  |
| q-b9a2c1a3bc | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItPF0sG6"} | None |  |
| q-a47cb03d5d | triage T1558 step 1 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == 4769 \| KEEP @timestamp, host.name, user.name, source.ip, win.ServiceName, win.TicketEncryptionType, win.TicketOptions, win.TargetUserName, _id, _index \| SORT @timestamp… | ERROR |  |
| q-15dbcaef5b | triage T1558 step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 10 AND win.TargetImage LIKE \"*lsass*\" AND win.GrantedAccess IN (\"0x1fffff\", \"0x101001\", \"0x1f3fff\", \"0x1000000\", \"0x3000\") \| KEEP @timestamp, host.name, proces… | ERROR |  |
| q-aa424d15d8 | triage T1558 step 2 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4769\" \| KEEP @timestamp, host.name, user.name, source.ip, win.ServiceName, win.TicketEncryptionType, win.TicketOptions, win.TargetUserName, _id, _index \| SORT @times… | 28 | F46 |
| q-7f63510c6a | triage T1558 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND win.TargetImage LIKE \"*lsass*\" AND win.GrantedAccess IN (\"0x1fffff\", \"0x101001\", \"0x1f3fff\", \"0x1000000\", \"0x3000\") \| KEEP @timestamp, host.name, pr… | 9 | F45 |
| q-6b8a13613d | triage T1558 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-8053ddef85 | triage T1558 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (process.command_line LIKE \"*lsass*\" OR process.command_line LIKE \"*kerber*\" OR process.command_line LIKE \"*ticket*\" OR process.command_line LIKE \"*Invoke-… | 2 |  |
| q-5603335e30 | triage T1558 step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (win.ScriptBlockText LIKE \"*lsass*\" OR win.ScriptBlockText LIKE \"*kerber*\" OR win.ScriptBlockText LIKE \"*ticket*\" OR win.ScriptBlockText LIKE \"*Invo… | 1 |  |
| q-b9e2640116 | triage T1558 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND host.name == \"scranton.dmevals.local\" AND @timestamp >= \"2020-05-02T03:04:00.000Z\" AND @timestamp <= \"2020-05-02T03:07:00.000Z\" \| KEEP @timestamp, process.… | 19 |  |
| q-41a90ad955 | triage T1558 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND process.pid == \"2976\" \| KEEP @timestamp, host.name, process.executable, process.command_line, process.parent.executable, user.name, _id, _index \| SORT @timest… | ERROR |  |
| q-5c6f82aa56 | triage T1558 step 5 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4769\" AND win.ServiceName == \"krbtgt\" \| KEEP @timestamp, host.name, user.name, source.ip, win.ServiceName, win.TicketEncryptionType, win.TicketOptions, win.Status, … | 3 | F47, F48, F49 |
| q-55aee02bbe | triage T1558 step 6 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND process.pid == 2976 \| KEEP @timestamp, host.name, process.executable, process.command_line, process.parent.executable, user.name, _id, _index \| SORT @timestamp … | 1 | F45 |
| q-9cb69793de | triage T1558 step 6 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKC-"} | None |  |
| q-d595001052 | triage T1558 step 7 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4769\" \| STATS cnt = COUNT(*) BY win.ServiceName, win.TicketEncryptionType, win.TicketOptions \| SORT cnt DESC \| LIMIT 30"} | 6 |  |
| q-cdd6e46696 | triage T1558 step 7 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4672\" \| KEEP @timestamp, host.name, user.name, win.TargetUserName, win.PrivilegeList, _id, _index \| SORT @timestamp ASC \| LIMIT 15"} | 15 |  |
| q-d6796b6e51 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-0e392095d6 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-c40195a720 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-8dcc243dff | triage T1558 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQB61zZ"} | None |  |
| q-3660bf24ee | triage T1558 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQB61zZ"} | None |  |
| q-7cdfdd8aff | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ8FbW6"} | None |  |
| q-63b4a590e1 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ8FbW6"} | None |  |
| q-949c13e7d5 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ8FbW6"} | None |  |
| q-775f8211c7 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ8FbW6"} | None |  |
| q-b2924bf62a | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ8FbW6"} | None |  |
| q-cfe84eaca9 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKC-"} | None |  |
| q-8a9238578f | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKC-"} | None |  |
| q-5073a273f2 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKC-"} | None |  |
| q-a5aa4b9e74 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItV3-aXQ"} | None |  |
| q-117d5d258a | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKC-"} | None |  |
| q-317bb85629 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKC-"} | None |  |
| q-14b06cb672 | triage T1606 step 1 | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8Rl"} | None | F50 |
| q-a8b15f6dbf | triage T1606 step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 10 AND win.TargetImage LIKE \"*lsass*\" AND win.GrantedAccess IN (\"0x1fffff\", \"0x101001\", \"0x1f3fff\", \"0x1000000\", \"0x3000\") \| KEEP @timestamp, host.name, proces… | ERROR |  |
| q-51b4aec113 | triage T1606 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND win.TargetImage LIKE \"*lsass*\" AND win.GrantedAccess IN (\"0x1fffff\", \"0x101001\", \"0x1f3fff\", \"0x1000000\", \"0x3000\") \| KEEP @timestamp, host.name, pr… | 9 | F50 |
| q-d8124967af | triage T1606 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (file.path LIKE \"*cookie*\" OR file.path LIKE \"*Cookies*\") \| KEEP @timestamp, host.name, process.executable, file.path, user.name, _id, _index"} | 1 | F51 |
| q-331d8d1f6f | triage T1606 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None | F50 |
| q-1d86e9cc7c | triage T1606 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None | F50 |
| q-e49c7d7f01 | triage T1606 step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" \| KEEP @timestamp, host.name, user.name, win.ScriptBlockText, _id, _index \| LIMIT 20"} | 20 |  |
| q-61f3a09329 | triage T1606 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (process.command_line LIKE \"*lsass*\" OR process.command_line LIKE \"*dump*\" OR process.command_line LIKE \"*credential*\" OR process.command_line LIKE \"*sekur… | 1 |  |
| q-29e4212442 | triage T1606 step 5 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRkUVV"} | None | F52 |
| q-588302b140 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-d320ef9366 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-d4a32a4868 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None |  |
| q-fa625d4b7a | triage T1606 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8Rl"} | None |  |
| q-36c2eed17c | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOVAUl3"} | None |  |
| q-a09e18e93b | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOVAUl3"} | None |  |
| q-f599ead21c | triage T1606 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrYjF"} | None |  |
| q-66d348aa8e | triage T1606 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRkUVV"} | None |  |
| q-222c9fff6e | triage T1606 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRkUVV"} | None |  |
| q-6c481727a4 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRkUVV"} | None |  |
| q-761b412ad2 | triage T1621 step 1 | aggregate | {"dataset": "windows.other", "field": "event.code", "query": "*", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 216 |  |
| q-feadb8a78c | triage T1621 step 1 | aggregate | {"dataset": "windows.other", "field": "host.name", "query": "event.code:5857 OR event.code:5858 OR event.code:5860", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 88 |  |
| q-39415b8a82 | triage T1621 step 2 | esql | {"query": "FROM logs-windows.other-default METADATA _id, _index \| WHERE event.code == \"5857\" OR event.code == \"5858\" OR event.code == \"5860\" \| KEEP @timestamp, host.name, event.code, user.name, message \| LIMIT 5"} | 5 |  |
| q-c274928d66 | triage T1621 step 2 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4625\" OR event.code == \"4771\" OR event.code == \"4776\" OR event.code == \"4648\" \| KEEP @timestamp, host.name, event.code, win.TargetUserName, win.LogonType, win.I… | 16 |  |
| q-11b5552b40 | triage T1621 step 3 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4648\" \| KEEP @timestamp, host.name, win.TargetUserName, win.SubjectUserName, win.ProcessName, win.IpAddress, win.TargetServerName \| LIMIT 30"} | 15 |  |
| q-23bf2f85a6 | triage T1621 step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*mfa*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*authenticator*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*2fa*\" OR TO_LOWER(win.ScriptBlockText… | 0 |  |
| q-0329c970c3 | triage T1621 step 4 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4625\" OR event.code == \"4771\" \| KEEP @timestamp, host.name, event.code, win.TargetUserName, win.Status, win.IpAddress \| LIMIT 20"} | 0 |  |
| q-b3d237fd68 | triage T1621 step 4 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"http\" \| KEEP @timestamp, url.original, http.request.method, host.name \| LIMIT 20"} | 20 |  |
| q-11359a0c8e | triage T1621 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8Rl"} | None |  |
| q-a9cfbc9a8c | triage T1621 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8Rl"} | None |  |
| q-0d9299b8f0 | triage T1621 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8Rl"} | None |  |
| q-7ad69efba5 | triage T1621 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "unknown"} | ERROR |  |
| q-c0ee53ce65 | triage T1621 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "unknown"} | ERROR |  |
| q-17f7980788 | triage T1621 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "unknown"} | ERROR |  |
| q-5cf213092e | triage T1621 step 6 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4648\" AND win.ProcessName == \"C:\\\\Windows\\\\PSEXESVC.exe\" \| KEEP @timestamp, host.name, _id, _index, win.TargetUserName, win.ProcessName \| LIMIT 5"} | 4 | F54 |
| q-c43cf23cd8 | triage T1649 step 1 | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8Rl"} | None |  |
| q-8b3f2ded6e | triage T1649 step 1 | search | {"dataset": "windows.security", "query": "event.code:4657 AND win.ObjectName:*SystemCertificates*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "win.ObjectName", "win.OperationType", "win.SubjectUserName", "win.ProcessName", "win.… | 1 | F56 |
| q-d6f3cf33ad | triage T1649 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:13 AND registry.path:*SystemCertificates*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "registry.path", "process.executable", "user.name", "win.Details"], "size": 30, "sort": "as… | 19 | F55, F56 |
| q-0c3f28f870 | triage T1649 step 2 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Cert* OR win.ScriptBlockText:*Pfx* OR win.ScriptBlockText:*X509*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "process.command_li… | 1 |  |
| q-cacd5e8a65 | triage T1649 step 2 | search | {"dataset": "windows.security", "query": "event.code:4768", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "win.TargetUserName", "win.IpAddress", "win.Status", "win.TicketOptions", "win.TicketEncryptionType"], "size": 20, "sort": "as… | 14 | F57 |
| q-11bfc1a332 | triage T1649 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*Cert* OR process.command_line:*Pfx* OR process.command_line:*X509* OR process.command_line:*Export*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "pr… | 1 | F56 |
| q-dea2bebdd8 | triage T1649 step 3 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None | F55 |
| q-a4ee49fc40 | triage T1649 step 3 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND file.path:*.pfx", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "file.path", "process.executable", "user.name", "event.code"], "size": 20, "sort": "asc"} | 1 | F55 |
| q-c0182b0819 | triage T1649 step 3 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*PrivateKeys* OR win.ScriptBlockText:*pfx* OR win.ScriptBlockText:*saribas*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "process.… | 3 | F55 |
| q-2a0ecc28d2 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-79a47459fd | triage T1649 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-4cdbba0036 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-abe950ebd0 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-34c049615e | triage T1649 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTkbEF9"} | None |  |
| q-08c61fa7b9 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTkbEF9"} | None |  |
| q-8d2e440eb0 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZLhp5O"} | None |  |
| q-99d19accce | triage T1649 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTkbEGc"} | None |  |
| q-2af6109f12 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItT2v6oH"} | None |  |
| q-89f2b93e00 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItThYt7K"} | None |  |
| q-4b70540d33 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO2iUEp"} | None |  |
| q-f6888360ac | triage T1649 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItPF08Hi"} | None |  |
| q-9bc86e40eb | triage T1649 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ6CoZN"} | None |  |
| q-ef64df2560 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO9q-10"} | None |  |
| q-6ef97a7405 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ef_w"} | None |  |
| q-0f2c0a6be8 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ef_w"} | None |  |
| q-9ac0e5975b | triage T1649 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItV3-aXJ"} | None |  |
| q-c706227892 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ef_w"} | None |  |
| q-9d44dd55fc | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-a8f43dc1eb | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-9ef2a33524 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-d48cbad7e0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None |  |
| q-06ccbabb07 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None |  |
| q-08f950a98a | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZKhD3z"} | None |  |
| q-2dea2d3fd6 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-6560398cb4 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZCgBha"} | None |  |
| q-7c829f34fe | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZJhF-L"} | None |  |
| q-2a9ecf184d | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSmWOt"} | None |  |
| q-7de4efbbc0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO9rO3D"} | None |  |
| q-978370f210 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO9rO3D"} | None |  |
| q-5a2e5deb65 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTVGQnT"} | None |  |
| q-5bf9be1df6 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTVGQnT"} | None |  |
| q-16a3f95e74 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItPM8kte"} | None |  |
| q-f0aa4ee380 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO9qRCx"} | None |  |
| q-a46ded8e9f | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVt4o2y"} | None |  |
| q-666aa513a2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItPM8kte"} | None |  |
| q-10745bb7b4 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTVGglR"} | None |  |
| q-ded0ee94ce | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTVGQmt"} | None |  |
| q-b1bada00f7 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItPK66ha"} | None |  |
| q-57b73b1051 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRkUVV"} | None |  |
| q-b75a903f00 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRkUVV"} | None |  |
| q-f6fb12eccc | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRkUVV"} | None |  |
| q-9bffa1909a | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRkUVV"} | None |  |
| q-ef3d53f24f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOcHa1B"} | None |  |
| q-be5364c3fd | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQB61zZ"} | None |  |
| q-cdfb99884e | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKA_"} | None |  |
| q-e00f61eda0 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKA_"} | None |  |
| q-d6e204b4ce | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKA_"} | None |  |
| q-8b6e5aa3ca | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gj"} | None |  |
| q-357235901d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-fd6db480d5 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None |  |
| q-edb1477e7e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None |  |
| q-58a23b3720 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTtmJQ5"} | None |  |
| q-593012fddc | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRkUeo"} | None |  |
| q-f3ec6549f8 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRkUep"} | None |  |
| q-81f7d6c5a1 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVn1FNc"} | None |  |
| q-2f3ef02678 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ev8p"} | None |  |
| q-8ce462452d | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8RY"} | None |  |
| q-29a0f534fa | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8Rb"} | None |  |
| q-bc61d707a0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOYDnci"} | None |  |
| q-57c0852f99 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTkbkGF"} | None |  |
| q-4ef67d1008 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ev8p"} | None |  |
| q-156c9556ec | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItV19Rnb"} | None |  |
| q-a5afc6cfb6 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8R_"} | None |  |
| q-2371819ed9 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8RS"} | None |  |
| q-154a880831 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ev8p"} | None |  |
| q-5df5c7b687 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ev8p"} | None |  |
| q-e91c600226 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVn01NG"} | None |  |
| q-7e37937312 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO9rO3Z"} | None |  |
| q-6b015a2d9f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO9rO3Z"} | None |  |
| q-e9066b7eb9 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8R_"} | None |  |
| q-b57315ed77 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItT_4wsv"} | None |  |
| q-af42a6f994 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItT_4wsv"} | None |  |
| q-b1ccaa35d4 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrYjN"} | None |  |
| q-6906fdf4b5 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrYjN"} | None |  |
| q-f8e760b0d4 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrYgN"} | None |  |
| q-fd646524b7 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrYgN"} | None |  |
| q-cae74c5e62 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrYi8"} | None |  |
| q-a94529ff24 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrogt"} | None |  |
| q-0cbe088eed | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrYiQ"} | None |  |
| q-815206ae27 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaKWxp4"} | None |  |
| q-76d30d4963 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaFQQtn"} | None |  |
| q-eb80cf8cdc | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVcwORA"} | None |  |
| q-49e53c3c83 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRkUVV"} | None |  |
| q-72058fb7c1 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRkUVV"} | None |  |
| q-01ee4d03ff | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRkUVV"} | None |  |
| q-c2722a4d38 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-d2b8cb3333 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-1d7a8ea5d1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None |  |
| q-fc33981a25 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None |  |
| q-f383dd3266 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-57f7123b3a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None |  |
| q-0a1f4d0931 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO9re0C"} | None |  |
| q-3ebb699f51 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ8FraW"} | None |  |
| q-dcd9723168 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrYiq"} | None |  |
| q-e5a114f7f3 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ8Frba"} | None |  |
| q-574bcf2748 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ8Frba"} | None |  |
| q-1fc5dc05b4 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTVHe6C"} | None |  |
| q-b2a525ac92 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOVAUl3"} | None |  |
| q-b87bbf0fab | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOVAUl3"} | None |  |
| q-a398ecc51a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItPK66i5"} | None |  |
| q-f4f3f21877 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItPK66i5"} | None |  |
| q-bb091d47b3 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrog-"} | None |  |
| q-9a7f8a6a95 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-fda4e9a2ef | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-cdf6e76988 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-e841687002 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-e73e665b5c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTkbkGg"} | None |  |
| q-e707ef9ea1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTkbkGg"} | None |  |
| q-1f7c931bad | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTkbkGF"} | None |  |
| q-6b2b68f82c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTkbkGg"} | None |  |
| q-c1a7e0a5bd | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTqhAkt"} | None |  |
| q-1616d5a224 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTqhAkt"} | None |  |
| q-e2fdb8702b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTqhAkt"} | None |  |
| q-ab9e8c9bbd | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItThYt63"} | None |  |
| q-17e9c4d587 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO9rO3Z"} | None |  |
| q-a04d1118c6 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItKT-1UH"} | None |  |
| q-10fedb1f08 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-5599608abf | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-5ad061de9a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-22b56006d8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None |  |
| q-6a905c8058 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None |  |
| q-7edfabedc9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQB61zZ"} | None |  |
| q-e67da7febe | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKB-"} | None |  |
| q-bdaf9ca70a | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ8FLV1"} | None |  |
| q-b459897cd7 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKB-"} | None |  |
| q-61a73e7a4b | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKB-"} | None |  |
| q-1e9410a39d | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ8FLV1"} | None |  |
| q-ea09cf447a | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVq1T69"} | None |  |
| q-5e88df7fc3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOVAkmV"} | None |  |
| q-dacf697665 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-6d72e3c87d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-e2a9971d88 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-ddc0f09fe1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQB61zZ"} | None |  |
| q-b852bc6da8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQB61zZ"} | None |  |
| q-e2b8d26d16 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaKXhpQ"} | None |  |
| q-f4eab066e6 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ev8p"} | None |  |
| q-68a030e9e2 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ev9J"} | None |  |
| q-6e073c4a6a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQC7zHD"} | None |  |
| q-bf7abca110 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQC7zHD"} | None |  |
| q-6ff5be7630 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ev9J"} | None |  |
| q-6d140a39af | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ev9J"} | None |  |
| q-a17c3a6967 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZCgBha"} | None |  |
| q-83cbfaf88d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQC7zHD"} | None |  |
| q-1f5b01b029 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItPM8kte"} | None |  |
| q-8edc1caff9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOrW_1k"} | None |  |
| q-87c68bfd18 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItPE0PcG"} | None |  |
| q-dceacd99ce | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgroge"} | None |  |
| q-fd70fa26e1 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgroge"} | None |  |
| q-e74b03613e | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7DT5G"} | None |  |
| q-ef2624c304 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrohb"} | None |  |
| q-2a14068f41 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOtYA8Z"} | None |  |
| q-73b94800e5 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOtYA8Z"} | None |  |
| q-572d5f31b0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItPF0sG6"} | None |  |
| q-8e2489ca44 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-ccc10ea58d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-36be0b50b0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-e810dc0c55 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQB61zZ"} | None |  |
| q-e4b138995f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQB61zZ"} | None |  |
| q-98ef57c41a | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ8FbW6"} | None |  |
| q-e74f10a356 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ8FbW6"} | None |  |
| q-4550e8ba72 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ8FbW6"} | None |  |
| q-06ce7b5dc7 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ8FbW6"} | None |  |
| q-1532117716 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ8FbW6"} | None |  |
| q-dbf43fd8b4 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKC-"} | None |  |
| q-87aa0bce5c | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKC-"} | None |  |
| q-806ee5e8b5 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKC-"} | None |  |
| q-473d2d4db4 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItV3-aXQ"} | None |  |
| q-d28d361af4 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKC-"} | None |  |
| q-0da30c1def | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKC-"} | None |  |
| q-f0cace022d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-2361189096 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-ccb1b0a7a3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None |  |
| q-2e18574594 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8Rl"} | None |  |
| q-4671c14ee3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOVAUl3"} | None |  |
| q-fcf9d5d409 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOVAUl3"} | None |  |
| q-ba4603e70b | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrYjF"} | None |  |
| q-3d1190681b | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRkUVV"} | None |  |
| q-48f97bb276 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRkUVV"} | None |  |
| q-365c1ce3c3 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRkUVV"} | None |  |
| q-6e0c906235 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8Rl"} | None |  |
| q-db45995cd7 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8Rl"} | None |  |
| q-3e36a3886a | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8Rl"} | None |  |
| q-8f3fba94ed | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7DD7u"} | None |  |
| q-3a4fa43792 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7DD7u"} | None |  |
| q-7cda3c645b | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7DD7u"} | None |  |
| q-8535f063e5 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-10d21f5087 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-e7a9102085 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-3c0b4533a5 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-20c3fe8cf5 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTkbEF9"} | None |  |
| q-18b5dc9b07 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTkbEF9"} | None |  |
| q-80d0b2474f | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZLhp5O"} | None |  |
| q-e53894ef8e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTkbEGc"} | None |  |
| q-176e626902 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItT2v6oH"} | None |  |
| q-5dc6dfe465 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItThYt7K"} | None |  |
| q-6ed4efee26 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO2iUEp"} | None |  |
| q-8f788a7ec2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItPF08Hi"} | None |  |
| q-81a0753fca | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ6CoZN"} | None |  |
| q-5831db8303 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO9q-10"} | None |  |
| q-f7a93ed6d5 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ef_w"} | None |  |
| q-e4fa7e2564 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ef_w"} | None |  |
| q-729aa8063c | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItV3-aXJ"} | None |  |
| q-7dc4d76641 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ef_w"} | None |  |
| q-a65ed32ebb | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND host.name:\"nashua.dmevals.local\"", "time_from": "2020-05-02T02:54:29+00:00", "time_to": "2020-05-02T03:30:05.142000+00:00", "size": 100, "sub_field": "process.parent.exec… | 61 |  |
| q-8628a63f59 | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11 AND host.name:\"nashua.dmevals.local\"", "time_from": "2020-05-02T02:54:29+00:00", "time_to": "2020-05-02T03:30:05.142000+00:00", "size": 100, "sub_field": "process.executable"} | 249 |  |
| q-7144429d8c | pivot seed | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND host.name:\"nashua.dmevals.local\"", "time_from": "2020-05-02T02:54:29+00:00", "time_to": "2020-05-02T03:30:05.142000+00:00", "size": 100, "sub_field": "process.parent… | 63 |  |
| q-02798e00f2 | pivot seed | aggregate | {"dataset": "windows.powershell", "field": "event.code", "query": "host.name:\"nashua.dmevals.local\"", "time_from": "2020-05-02T02:54:29+00:00", "time_to": "2020-05-02T03:30:05.142000+00:00", "size": 100, "sub_field": null} | 192 |  |
| q-56ceb88def | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND host.name:\"newyork.dmevals.local\"", "time_from": "2020-05-02T02:49:04+00:00", "time_to": "2020-05-02T03:34:13+00:00", "size": 100, "sub_field": "process.parent.executable… | 18 |  |
| q-319d94ac37 | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11 AND host.name:\"newyork.dmevals.local\"", "time_from": "2020-05-02T02:49:04+00:00", "time_to": "2020-05-02T03:34:13+00:00", "size": 100, "sub_field": "process.executable"} | 81 |  |
| q-da3cf0261b | pivot seed | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND host.name:\"newyork.dmevals.local\"", "time_from": "2020-05-02T02:49:04+00:00", "time_to": "2020-05-02T03:34:13+00:00", "size": 100, "sub_field": "process.parent.execu… | 18 |  |
| q-c263b2ed38 | pivot seed | aggregate | {"dataset": "windows.powershell", "field": "event.code", "query": "host.name:\"newyork.dmevals.local\"", "time_from": "2020-05-02T02:49:04+00:00", "time_to": "2020-05-02T03:34:13+00:00", "size": 100, "sub_field": null} | 2185 |  |
| q-8808728c3e | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND host.name:\"scranton.dmevals.local\"", "time_from": "2020-05-02T02:43:44.325000+00:00", "time_to": "2020-05-02T03:36:29+00:00", "size": 100, "sub_field": "process.parent.ex… | 359 |  |
| q-cfbc79752e | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11 AND host.name:\"scranton.dmevals.local\"", "time_from": "2020-05-02T02:43:44.325000+00:00", "time_to": "2020-05-02T03:36:29+00:00", "size": 100, "sub_field": "process.executable"} | 1276 |  |
| q-8de7b5cbf1 | pivot seed | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND host.name:\"scranton.dmevals.local\"", "time_from": "2020-05-02T02:43:44.325000+00:00", "time_to": "2020-05-02T03:36:29+00:00", "size": 100, "sub_field": "process.pare… | 370 |  |
| q-5c469428fb | pivot seed | aggregate | {"dataset": "windows.powershell", "field": "event.code", "query": "host.name:\"scranton.dmevals.local\"", "time_from": "2020-05-02T02:43:44.325000+00:00", "time_to": "2020-05-02T03:36:29+00:00", "size": 100, "sub_field": null} | 8602 |  |
| q-2a7a3a1be4 | pivot step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" \| WHERE TO_LOWER(process.executable) LIKE \"*rar*\" OR TO_LOWER(process.executable) LIKE \"*sdelete*\" OR TO_LOWER(process.executable) LIKE \"*psexec*\" OR TO_LOWER(… | 20 | F62 |
| q-e1f72e44ee | pivot step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" \| WHERE TO_LOWER(file.path) LIKE \"*passw*\" OR TO_LOWER(file.path) LIKE \"*.pfx\" OR TO_LOWER(file.path) LIKE \"*.kdbx\" OR TO_LOWER(file.path) LIKE \"*cred*\" OR … | 11 |  |
| q-31d469c46b | pivot step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO9rO3J"} | None | F60 |
| q-84eebb8d2c | pivot step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTkbkGF"} | None |  |
| q-a6210fcd28 | pivot step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTkbEF9"} | None | F59 |
| q-61bb43ca3b | pivot step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTPA5kN"} | None | F62 |
| q-edc530b666 | pivot step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" \| WHERE TO_LOWER(message) LIKE \"*pspasswd*\" OR TO_LOWER(message) LIKE \"*passwd*\" OR TO_LOWER(message) LIKE \"*credential*\" OR TO_LOWER(message) LIKE \"*p… | 15 |  |
| q-3558afc94c | pivot step 3 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4688\" \| WHERE TO_LOWER(process.command_line) LIKE \"*pspasswd*\" OR TO_LOWER(process.command_line) LIKE \"*passwd*\" OR TO_LOWER(process.command_line) LIKE \"*rar*\" … | 2 |  |
| q-34c65b54aa | pivot step 4 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None | F59 |
| q-5c0cb3579d | pivot step 4 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZCgBha"} | None | F63 |
| q-4f55470710 | pivot step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" \| WHERE TO_LOWER(process.command_line) LIKE \"*pspasswd*\" OR TO_LOWER(process.command_line) LIKE \"*passwd*\" OR TO_LOWER(process.command_line) LIKE \"*net user*\" … | 0 |  |
| q-1fb3f5cdc8 | pivot step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" \| WHERE TO_LOWER(process.executable) LIKE \"*pspasswd*\" OR TO_LOWER(process.command_line) LIKE \"*pspasswd*\" OR TO_LOWER(process.command_line) LIKE \"*readme.ps1*\… | 0 |  |
| q-13e66f4c4f | pivot step 5 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4663\" OR event.code == \"4656\" \| WHERE TO_LOWER(winlog.event_data.ObjectName) LIKE \"*sam*\" OR TO_LOWER(winlog.event_data.ObjectName) LIKE \"*security*\" OR TO_LOWE… | ERROR |  |
| q-7c036eb1f7 | pivot step 6 | get_fields | {"dataset": "windows.security", "prefix": "winlog.event_data"} | None |  |
| q-9759f1f20b | pivot step 6 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4663\" \| WHERE TO_LOWER(winlog.event_data.ObjectName) LIKE \"*sam\" OR TO_LOWER(winlog.event_data.ObjectName) LIKE \"*lsass*\" OR TO_LOWER(winlog.event_data.ObjectName… | ERROR |  |
| q-68796ec87f | pivot step 7 | get_fields | {"dataset": "windows.security", "prefix": ""} | None |  |
| q-4e85a3cca8 | pivot step 8 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4663\" OR event.code == \"4656\" \| WHERE TO_LOWER(win.ObjectName) LIKE \"*sam\" OR TO_LOWER(win.ObjectName) LIKE \"*lsass*\" OR TO_LOWER(win.ObjectName) LIKE \"*vault*… | 33 | F61 |
| q-7a4d6e9ac5 | pivot step 8 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4688\" \| WHERE TO_LOWER(process.command_line) LIKE \"*pspasswd*\" OR TO_LOWER(process.command_line) LIKE \"*accesschk*\" OR TO_LOWER(process.command_line) LIKE \"*read… | 1 |  |
| q-fabb4c9591 | pivot step 9 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" \| WHERE TO_LOWER(file.path) LIKE \"*pspasswd*\" OR TO_LOWER(file.path) LIKE \"*readme.ps1*\" OR TO_LOWER(file.path) LIKE \"*psversion.ps1*\" OR TO_LOWER(file.path) … | 9 | F58, F63 |
| q-070e221d3f | pivot step 9 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" \| WHERE TO_LOWER(process.command_line) LIKE \"*pspasswd*\" OR TO_LOWER(process.command_line) LIKE \"*net user*\" OR TO_LOWER(process.command_line) LIKE \"*net localg… | 0 |  |
| q-83482b1568 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTummpO"} | None |  |
| q-37889795dc | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTummrw"} | None |  |
| q-e9f93a0ec8 | pivot verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-263f43c7f5 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTkbEF9"} | None |  |
| q-d75ed6ce2e | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO9rO3J"} | None |  |
| q-805a171593 | pivot verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVr3Lv_"} | None |  |
| q-34ecdb8c82 | pivot verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVr3Lv_"} | None |  |
| q-cbce120d26 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTPA5kN"} | None |  |
| q-d7ee3f562c | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItPO_TIA"} | None |  |
| q-9458e3a895 | pivot verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZCgBha"} | None |  |
| q-6aa13e03f2 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTWI7pZ"} | None |  |
| q-864be38bea | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-f77535b796 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-946ef29f84 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-4a7744fdfe | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None |  |
| q-7e1b56f515 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None |  |
| q-fe3138a105 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZKhD3z"} | None |  |
| q-a8eac30786 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-12df30a819 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZCgBha"} | None |  |
| q-712000c97f | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZJhF-L"} | None |  |
| q-7c1b78520a | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSmWOt"} | None |  |
| q-ebc6003324 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO9rO3D"} | None |  |
| q-66f1740737 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO9rO3D"} | None |  |
| q-21d8353de4 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTVGQnT"} | None |  |
| q-272d4ce4c2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTVGQnT"} | None |  |
| q-6b82e484b9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItPM8kte"} | None |  |
| q-353cbf2167 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO9qRCx"} | None |  |
| q-cf62d33740 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVt4o2y"} | None |  |
| q-ea070c5214 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItPM8kte"} | None |  |
| q-8ccbb15fc2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTVGglR"} | None |  |
| q-3c78475de4 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTVGQmt"} | None |  |
| q-396410c7bb | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItPK66ha"} | None |  |
| q-af1efa4522 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRkUVV"} | None |  |
| q-2c20eb6471 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRkUVV"} | None |  |
| q-745a10df8c | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRkUVV"} | None |  |
| q-37fcf4eb76 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRkUVV"} | None |  |
| q-dd6468d527 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOcHa1B"} | None |  |
| q-b71ff13c1a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQB61zZ"} | None |  |
| q-0f8d9a2b38 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKA_"} | None |  |
| q-e0eeba9d1a | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKA_"} | None |  |
| q-3bbf83b027 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKA_"} | None |  |
| q-8e20181c40 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gj"} | None |  |
| q-8d29192526 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-a5f69f52b5 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None |  |
| q-65a2468bc6 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None |  |
| q-79fa9aa5bd | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTtmJQ5"} | None |  |
| q-157f41892b | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRkUeo"} | None |  |
| q-4a9a22709e | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRkUep"} | None |  |
| q-87e0347398 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVn1FNc"} | None |  |
| q-5164c30aba | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ev8p"} | None |  |
| q-6413a5e323 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8RY"} | None |  |
| q-be4db66b2e | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8Rb"} | None |  |
| q-b84bfb5c99 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOYDnci"} | None |  |
| q-2b99a7ab1f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTkbkGF"} | None |  |
| q-e4110f2e72 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ev8p"} | None |  |
| q-65bd167398 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItV19Rnb"} | None |  |
| q-f94304678a | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8R_"} | None |  |
| q-fa25a5e6ce | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8RS"} | None |  |
| q-4edd9b6bc7 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ev8p"} | None |  |
| q-beab075af8 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ev8p"} | None |  |
| q-e1bf134800 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVn01NG"} | None |  |
| q-dc32c4a274 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO9rO3Z"} | None |  |
| q-daa786c18b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO9rO3Z"} | None |  |
| q-40d08d99b1 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8R_"} | None |  |
| q-68995e8b2c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItT_4wsv"} | None |  |
| q-c712571147 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItT_4wsv"} | None |  |
| q-194ba1bad4 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrYjN"} | None |  |
| q-6a02e284a3 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrYjN"} | None |  |
| q-03380099fb | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrYgN"} | None |  |
| q-25f9b95fc3 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrYgN"} | None |  |
| q-8df9d59ee2 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrYi8"} | None |  |
| q-c182fabe89 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrogt"} | None |  |
| q-bf32e2ab32 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrYiQ"} | None |  |
| q-df8d36f046 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaKWxp4"} | None |  |
| q-95e5642299 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaFQQtn"} | None |  |
| q-785801e013 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVcwORA"} | None |  |
| q-20aa33d799 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRkUVV"} | None |  |
| q-113b0162f4 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRkUVV"} | None |  |
| q-cf13d0aa30 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRkUVV"} | None |  |
| q-8a6ae261b2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-6f76662440 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-d1c5bc3371 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None |  |
| q-4b18395fef | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None |  |
| q-c91476445a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-fae3a8992f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None |  |
| q-0d4d0b6a8b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO9re0C"} | None |  |
| q-25903bb82c | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ8FraW"} | None |  |
| q-99e3d416b8 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrYiq"} | None |  |
| q-d48dbae70c | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ8Frba"} | None |  |
| q-fee9d0dcac | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ8Frba"} | None |  |
| q-22bc4c3730 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTVHe6C"} | None |  |
| q-fa57673e92 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOVAUl3"} | None |  |
| q-00cf807dc4 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOVAUl3"} | None |  |
| q-d035afec49 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItPK66i5"} | None |  |
| q-3b7aec9d6c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItPK66i5"} | None |  |
| q-8ac7b4e43e | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrog-"} | None |  |
| q-310e26a4b4 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-33cafa2d26 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-6842e4c09f | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-306429dfab | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-55a9055605 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTkbkGg"} | None |  |
| q-0cff8ab846 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTkbkGg"} | None |  |
| q-105b0b2606 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTkbkGF"} | None |  |
| q-009bdd5ea5 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTkbkGg"} | None |  |
| q-96173f4693 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTqhAkt"} | None |  |
| q-7ad2d466ec | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTqhAkt"} | None |  |
| q-e0e16e5630 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTqhAkt"} | None |  |
| q-e4cdee69a1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItThYt63"} | None |  |
| q-b6508d209c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO9rO3Z"} | None |  |
| q-079fc98adb | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItKT-1UH"} | None |  |
| q-1f44e9bd6c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-ce04ffddac | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-31463f3c2e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-c9b632419a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None |  |
| q-dc1667ee95 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None |  |
| q-93042b7fe5 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQB61zZ"} | None |  |
| q-bad4852e19 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKB-"} | None |  |
| q-507d6ff0d8 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ8FLV1"} | None |  |
| q-2ec26e3eda | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKB-"} | None |  |
| q-3ca8d97725 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKB-"} | None |  |
| q-05ea7be419 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ8FLV1"} | None |  |
| q-1872003d3f | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVq1T69"} | None |  |
| q-c44c28c042 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOVAkmV"} | None |  |
| q-b3eccde10c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-31e94259f6 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-0324c46c2e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-8dd15492f8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQB61zZ"} | None |  |
| q-e119e81205 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQB61zZ"} | None |  |
| q-e56d849881 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaKXhpQ"} | None |  |
| q-05e00a33a2 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ev8p"} | None |  |
| q-361a3646df | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ev9J"} | None |  |
| q-381a58f411 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQC7zHD"} | None |  |
| q-974cc874f9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQC7zHD"} | None |  |
| q-2e4e2ae6a2 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ev9J"} | None |  |
| q-2a8bfe8de4 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ev9J"} | None |  |
| q-20aa26a045 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZCgBha"} | None |  |
| q-18f41b21a4 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQC7zHD"} | None |  |
| q-7d6a7f56ef | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItPM8kte"} | None |  |
| q-1e70e54108 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOrW_1k"} | None |  |
| q-752fc894cf | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItPE0PcG"} | None |  |
| q-aba9007a34 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgroge"} | None |  |
| q-744e4dc900 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgroge"} | None |  |
| q-eeb497cfd4 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7DT5G"} | None |  |
| q-203049ac23 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrohb"} | None |  |
| q-d12046813b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOtYA8Z"} | None |  |
| q-50fda338d1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOtYA8Z"} | None |  |
| q-c4eb624b50 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItPF0sG6"} | None |  |
| q-7d083917b4 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-3ce812ed2b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-c97c360df6 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-5a7d4e6d9f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQB61zZ"} | None |  |
| q-ae3b194c26 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQB61zZ"} | None |  |
| q-d084612be8 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ8FbW6"} | None |  |
| q-f4491e5917 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ8FbW6"} | None |  |
| q-7457d035ec | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ8FbW6"} | None |  |
| q-57926511aa | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ8FbW6"} | None |  |
| q-6390a536ad | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ8FbW6"} | None |  |
| q-2301dda8ea | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKC-"} | None |  |
| q-9c2e9ef3d5 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKC-"} | None |  |
| q-9265d7ef51 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKC-"} | None |  |
| q-5ff1f9f03d | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItV3-aXQ"} | None |  |
| q-65b88512ad | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKC-"} | None |  |
| q-82c6674078 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKC-"} | None |  |
| q-1542cd1883 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-1446a2f0c6 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-f218d5a55c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None |  |
| q-aeede8efff | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8Rl"} | None |  |
| q-3903418032 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOVAUl3"} | None |  |
| q-bb25014073 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOVAUl3"} | None |  |
| q-6a65d2d1ad | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrYjF"} | None |  |
| q-e0e4bad41f | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRkUVV"} | None |  |
| q-341541462c | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRkUVV"} | None |  |
| q-ba29033091 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRkUVV"} | None |  |
| q-afaea9e38d | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8Rl"} | None |  |
| q-a130c32edb | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8Rl"} | None |  |
| q-5c7a159f05 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8Rl"} | None |  |
| q-c887f97359 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7DD7u"} | None |  |
| q-1c7168a271 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7DD7u"} | None |  |
| q-b08d595ca0 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7DD7u"} | None |  |
| q-3e731fc449 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-7405e33cc5 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-7835e4d59e | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-eaeeac1e13 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-a8c7760ec2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTkbEF9"} | None |  |
| q-27fa9959f6 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTkbEF9"} | None |  |
| q-16b32129e7 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZLhp5O"} | None |  |
| q-82a9a617ea | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTkbEGc"} | None |  |
| q-5ee2b53eed | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItT2v6oH"} | None |  |
| q-35a826c176 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItThYt7K"} | None |  |
| q-ddcfff18d5 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO2iUEp"} | None |  |
| q-58505b1b56 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItPF08Hi"} | None |  |
| q-5bf3e26d37 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ6CoZN"} | None |  |
| q-f00d9660bc | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO9q-10"} | None |  |
| q-c8f17903a7 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ef_w"} | None |  |
| q-9c12d2dfef | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ef_w"} | None |  |
| q-73e0e7df23 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItV3-aXJ"} | None |  |
| q-f71db7c8bf | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ef_w"} | None |  |
| q-f48f2531a2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTummpO"} | None |  |
| q-e139eecf87 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTummrw"} | None |  |
| q-8b1c168e16 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-61cfaf5b3f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTkbEF9"} | None |  |
| q-e4ac99008c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO9rO3J"} | None |  |
| q-242c52c4f2 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVr3Lv_"} | None |  |
| q-b09ec45b85 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVr3Lv_"} | None |  |
| q-fc6bb51c6d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTPA5kN"} | None |  |
| q-7cb8fa8da9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItPO_TIA"} | None |  |
| q-08a8baacbd | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZCgBha"} | None |  |
| q-ff60d2c781 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTWI7pZ"} | None |  |

## Verification

Evidence items cited: 197; confirmed against the stored events: 196; rejected: 1. Each item was re-fetched with get_event; it is confirmed only if the event exists, the cited field holds the cited value, and the cited query_id is a query of this run that returned that event.
Evidence sent back to the agents for correction during the run: 11 item(s) in 6 submission(s) (one correction round each; what still failed was rejected).

## Limitations

- Findings describe what the stored logs show; activity these sources did not log cannot be seen.
- Datasets with non-overlapping time windows (see Data examined) were analysed separately.
- Long field values are shortened in this report; full events are retrievable by _index/_id.
