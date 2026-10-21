# Threat hunt report — 20261017-082843-converged-final2-full

**Hypothesis:** An adversary who compromised Windows hosts in this network stole credentials from them (MITRE ATT&CK tactic: Credential Access).

**Verdict: Confirmed** — 7 in-scope incident(s) of verified malicious findings (confidence >= medium): I01 T1003 (F66), I02 T1003.001 (F01, F02, F13, F19, F24, F26, F51), I03 T1056 (F12), I04 T1056.001 (F14, F65), I06 T1552.001 (F31, F64), I07 T1552.004 (F30, F61), I08 T1555 (F39)

Verdict method: rules over verified evidence (Confirmed if >=1 in-scope incident of verified malicious findings (confidence >= medium); Inconclusive if only suspicious incidents or coverage gaps; Refuted if full coverage and no malicious/suspicious finding)

| Run | Value |
|---|---|
| Profile | converged (thinking=False, temperature=0.0) |
| Model | deepseek-flash |
| Started / finished (UTC) | 2026-10-17T00:28:43+00:00 / 2026-10-17T00:39:36+00:00 (652.7 s) |
| LLM calls / tokens | 127 / {'prompt': 3773654, 'completion': 118711} |
| MCP tool calls | 1168 (server tools: list_data_sources, get_fields, search, count, aggregate, timeline, esql, get_event, get_registry) |
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
| I01 | T1003 | yes | malicious/high | F66 | Credential-access tooling staged and executed from C:\Windows\Temp on nashua |
| I02 | T1003.001 | yes | malicious/high | F01, F02, F13, F19, F24, F26, F51 | LSASS memory access with full-access masks by PowerShell and wsmprovhost (scranton and nashua) |
| I03 | T1056 | yes | malicious/high | F12 | Malicious screensaver cod.3aka3.scr drives PowerShell credential-access chain on scranton |
| I04 | T1056.001 | yes | malicious/high | F14, F65 | PowerShell steganographic loader and shellcode injector on scranton |
| I05 | T1111 | yes | suspicious/medium | F23 | PowerShell Invoke-Exfil credential-handling exfiltration script on scranton |
| I06 | T1552.001 | yes | malicious/high | F31, F64 | Sysinternals accesschk.exe run and passwordsDB file on scranton |
| I07 | T1552.004 | yes | malicious/high | F30, F61 | PowerShell Get-PrivateKeys exports all LocalMachine private keys to .pfx files on scranton |
| I08 | T1555 | yes | malicious/high | F39 | Malicious intrusion chain on scranton with credential use and exfiltration |
| I09 | out-of-scope:T1021 | no | suspicious/high | F11, F20, F60 | PsExec lateral movement with cleartext credentials (scranton to nashua) |

## Findings

### F02 · malicious / high · T1003 · Credential dumping activity by user pbeesly across scranton and nashua

Evidence status: **verified**

The credential-access tactic is evidenced by user pbeesly's interactive PowerShell session on scranton.dmevals.local opening LSASS with full-access masks (0x1FFFFF, 0x1F3FFF) at 03:05:16, and by the resulting remote session on nashua.dmevals.local where wsmprovhost.exe opened LSASS with 0x1F3FFF at 03:09:29. The session also ran credential/collection functions (Get-PrivateKeys, Get-Keystrokes, Invoke-ScreenCapture). The bulk of LSASS handle activity (svchost.exe 0x1000, AntimalwareConfig.exe/WindowsAzureTelemetryService.exe 0x1400, wininit/csrss 0x1fffff at process start) is normal system behaviour; the pbeesly PowerShell/wsmprovhost accesses are the anomalous ones.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTka0Gm | q-cdfdaeb9a2 | ok |
| 2 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHNH1uOFchItUHCTY0 | q-cdfdaeb9a2 | ok |
| 3 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | win.ObjectName | \Device\HarddiskVolume2\Windows\System32\lsass.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItaDOKB- | q-cf0a641e43 | ok |
| 4 | 2020-05-02 03:09:23.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | Invoke-Command -ComputerName NASHUA -ScriptBlock { Get-Process -IncludeUserName \| Select-Object UserName,SessionId \| Where-Object { $_.UserName -like "*\$env:… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZKhD3z | q-98014e96b3 | ok |

### F66 · malicious / high · T1003 · Credential-access tooling staged and executed from C:\Windows\Temp on nashua.dmevals.local

Evidence status: **verified**

On nashua.dmevals.local, attacker tooling (python.exe, Rar.exe, sdelete64.exe) was dropped into and executed from C:\Windows\Temp by user pbeesly, driven by PsExec (PSEXESVC.exe) and PowerShell. The python.exe binary performed credential-file discovery and the Rar/sdelete pair staged and then wiped the collected credential archive, consistent with credential access and collection on the host.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:10:23.626Z | nashua.dmevals.local | windows.sysmon | file.path | C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTVHAmR | q-73197609f4 | ok |
| 2 | 2020-05-02 03:11:40.213Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTVGQmt | q-9fdf768fc4 | ok |
| 3 | 2020-05-02 03:16:52.456Z | nashua.dmevals.local | windows.sysmon | process.command_line | .\sdelete64.exe  /accepteula "C:\Windows\Temp\Rar.exe" | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItPO_TIA | q-9fdf768fc4 | ok |

### F01 · malicious / high · T1003.001 · LSASS memory accessed with full-read access masks by PowerShell and wsmprovhost

Evidence status: **verified**

On scranton.dmevals.local, PowerShell.exe (PID 2976, user pbeesly) opened a handle to lsass.exe (PID 736) with GrantedAccess 0x1FFFFF (PROCESS_ALL_ACCESS) and 0x1F3FFF at 2020-05-02T03:05:16, i.e. full read/write of LSASS memory. The Security 4656 audit event for the same handle (AccessMask 0x1FFFFF) explicitly lists 'Read from process memory'. The same PowerShell session (user pbeesly) was executing credential/collection toolkit functions (Get-PrivateKeys, Get-Keystrokes, Invoke-ScreenCapture, Invoke-Persistence). Minutes later, on nashua.dmevals.local, wsmprovhost.exe (PID 7720, user pbeesly, spawned by Invoke-Command -ComputerName NASHUA) opened lsass.exe (PID 728) with GrantedAccess 0x1F3FFF at 2020-05-02T03:09:29. These are the classic access masks used to read LSASS memory for credential theft.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTka0Gm | q-cdfdaeb9a2 | ok |
| 2 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTka0Gj | q-cdfdaeb9a2 | ok |
| 3 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTka0Gm | q-cdfdaeb9a2 | ok |
| 4 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | win.AccessMask | 0x1fffff | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItaDOKB- | q-cee6cee290 | ok |
| 5 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | win.SubjectUserName | pbeesly | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItaDOKB- | q-cf0a641e43 | ok |
| 6 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHNH1uOFchItUHCTY0 | q-cdfdaeb9a2 | ok |
| 7 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHNH1uOFchItUHCTY0 | q-cdfdaeb9a2 | ok |
| 8 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZSl2ML | q-9ead50151a | ok |

### F12 · malicious / high · T1056 · Malicious screensaver cod.3aka3.scr drives PowerShell credential-access chain on scranton.dmevals.local

Evidence status: **verified**

On 2020-05-02 at 02:55:56 UTC on scranton.dmevals.local, user pbeesly executed C:\ProgramData\victim\â€®cod.3aka3.scr (a .scr screensaver binary in a 'victim' staging directory) via explorer.exe. The process immediately spawned cmd.exe and then powershell.exe, and was the only non-system process observed accessing the LSA registry key \REGISTRY\MACHINE\SYSTEM\ControlSet001\Control\Lsa (event 4663, AccessMask 0x1). The PowerShell child then ran a steganographic payload extractor reading C:\Users\pbeesly\Downloads\monkey.png and a shellcode injector using VirtualAlloc/CreateThread, and later opened lsass.exe with GrantedAccess 0x1fffff (PROCESS_ALL_ACCESS). This is a coherent credential-access intrusion chain on the host.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:55:56.157Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\ProgramData\victim\â€®cod.3aka3.scr | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHNH1uOFchItQE_psP | q-47a2f163d0 | ok |
| 2 | 2020-05-02 02:55:56.157Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\ProgramData\victim\â€®cod.3aka3.scr" /S | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHNH1uOFchItQE_psP | q-47a2f163d0 | ok |
| 3 | 2020-05-02 02:55:56.000Z | scranton.dmevals.local | windows.security | win.ObjectName | \REGISTRY\MACHINE\SYSTEM\ControlSet001\Control\Lsa | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItaKXhpR | q-c6a5f414c7 | ok |
| 4 | 2020-05-02 02:55:56.000Z | scranton.dmevals.local | windows.security | process.executable | C:\ProgramData\victim\â€®cod.3aka3.scr | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItaKXhpR | q-c6a5f414c7 | ok |
| 5 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTka0Gm | q-25a263ba88 | ok |

### F14 · malicious / high · T1056.001 · PowerShell steganographic loader and shellcode injector executed by pbeesly on scranton.dmevals.local

Evidence status: **verified**

On 2020-05-02 between 02:58:44 and 02:58:45 UTC on scranton.dmevals.local, PowerShell (user pbeesly) executed a hidden-window command that read C:\Users\pbeesly\Downloads\monkey.png, decoded pixel data into a byte array and IEX'd the result (steganographic payload delivery), and a second script block that P/Invokes kernel32 VirtualAlloc and CreateThread to run an embedded shellcode byte array. The same host also staged Sysinternals (PsExec64, sdelete64) and created HKCU Folder\shell\open\command registry keys. No explicit keylogging API strings (GetAsyncKeyState/SetWindowsHookEx) were observed, but the loader/injector and LSASS access constitute the input-capture/credential-theft tooling on this host.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:58:45.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | sal a New-Object;Add-Type -AssemblyName 'System.Drawing'; $g=a System.Drawing.Bitmap('C:\Users\pbeesly\Downloads\monkey.png');$o=a Byte[] 4480;for($i=0; $i -le … | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZWqNDf | q-744cc64a9a | ok |
| 2 | 2020-05-02 02:58:45.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | $cFIrwwpZzGzU = @"  [DllImport("kernel32.dll")]  public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZWqNA3 | q-56a58c9c1c | ok |
| 3 | 2020-05-02 02:57:00.933Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Users\pbeesly\Downloads\monkey.png | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHNH1uOFchItQD9QiN | q-3869954636 | ok |
| 4 | 2020-05-02 02:58:44.325Z | scranton.dmevals.local | windows.sysmon | process.command_line | "PowerShell.exe" -noni -noexit -ep bypass -window hidden -c "sal a New-Object;Add-Type -AssemblyName 'System.Drawing'; $g=a System.Drawing.Bitmap('C:\Users\pbee… | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHNH1uOFchItQB61zZ | q-47a2f163d0 | ok |

### F65 · malicious / high · T1056.001 · PyInstaller python.exe launched via PsExec performs credential discovery and anti-forensic wiping on nashua

Evidence status: **verified**

On nashua.dmevals.local, C:\Windows\Temp\python.exe (a PyInstaller-packed binary, SHA256=43782EC4337D8F3DDB7EA0C451B3BC4F212F84C8D5571BD0A842001C859A02AE) was spawned by C:\Windows\PSEXESVC.exe as user pbeesly, then re-spawned itself and drove the credential-harvesting PowerShell. It also wrote Rar.exe and sdelete64.exe into C:\Windows\Temp. The python.exe enumerated processes with usernames (Get-Process -IncludeUserName) and then wiped the Rar.exe and working.zip artifacts with sdelete64.exe to destroy evidence.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:40.213Z | nashua.dmevals.local | windows.sysmon | process.parent.executable | C:\Windows\PSEXESVC.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTVGQmt | q-9fdf768fc4 | ok |
| 2 | 2020-05-02 03:15:04.235Z | nashua.dmevals.local | windows.sysmon | win.Hashes | SHA1=585EB59D12A111E9291518C5CF5D3FD296C2B581,MD5=57292CE8714E2D221D9D97C9D061D332,SHA256=43782EC4337D8F3DDB7EA0C451B3BC4F212F84C8D5571BD0A842001C859A02AE,IMPHA… | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTPBJnI | q-fe5d9a7eff | ok |
| 3 | 2020-05-02 03:15:31.530Z | nashua.dmevals.local | windows.sysmon | file.path | C:\Windows\Temp\Rar.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItPK6qjB | q-73197609f4 | ok |
| 4 | 2020-05-02 03:15:38.985Z | nashua.dmevals.local | windows.sysmon | file.path | C:\Windows\Temp\sdelete64.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTPBJkP | q-73197609f4 | ok |
| 5 | 2020-05-02 03:17:18.030Z | nashua.dmevals.local | windows.sysmon | process.command_line | .\sdelete64.exe  /accepteula "C:\Users\pbeesly\AppData\Roaming\working.zip"  | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItPJ5Bh7 | q-9fdf768fc4 | ok |
| 6 | 2020-05-02 03:09:28.000Z | nashua.dmevals.local | windows.powershell | win.ScriptBlockText |  Get-Process -IncludeUserName \| Select-Object UserName,SessionId \| Where-Object { $_.UserName -like "*\$env:USERNAME" } \| Sort-Object SessionId -Unique  | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZLhqPR | q-83e5840d01 | ok |

### F13 · malicious / high · T1056.004 · PowerShell opens LSASS with PROCESS_ALL_ACCESS (0x1fffff) on scranton.dmevals.local

Evidence status: **verified**

At 2020-05-02 03:05:16 UTC on scranton.dmevals.local, C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe (PID 2976) opened C:\windows\system32\lsass.exe (PID 736) with GrantedAccess 0x1fffff (PROCESS_ALL_ACCESS) and a CallTrace ending in UNKNOWN(000001996D28200D), indicating an unbacked/injected code path rather than a normal signed module. This is the same PowerShell process that earlier executed the steganographic loader and shellcode injector, and is consistent with credential API hooking / in-memory credential theft from LSASS. The other LSASS accesses in the dataset are svchost.exe with 0x1000 (query-limited, benign) and wininit/csrss with 0x1fffff at boot.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTka0Gm | q-25a263ba88 | ok |
| 2 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTka0Gm | q-25a263ba88 | ok |
| 3 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.CallTrace | C:\windows\SYSTEM32\ntdll.dll+9c584\|C:\windows\System32\KERNELBASE.dll+2732e\|UNKNOWN(000001996D28200D) | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTka0Gm | q-25a263ba88 | ok |
| 4 | 2020-05-02 03:01:03.622Z | scranton.dmevals.local | windows.sysmon | win.TargetImage | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTtmJQ5 | q-12d9c8d328 | ok |

### F26 · malicious / high · T1212 · PowerShell process opened LSASS with PROCESS_ALL_ACCESS on scranton.dmevals.local

Evidence status: **verified**

On 2020-05-02 03:05:16 UTC, PowerShell.exe (PID 2976, user pbeesly) on scranton.dmevals.local opened lsass.exe (PID 736) with GrantedAccess 0x1f3fff and then 0x1fffff (PROCESS_ALL_ACCESS) — the access mask required to read LSASS memory for credential extraction. This occurred in the middle of a hands-on-keyboard intrusion by user pbeesly on the same host (Invoke-Discovery, Invoke-Persistence, Get-PrivateKeys dumping cert private keys, Invoke-Exfil, and Sysinternals accesschk.exe usage), consistent with exploitation/abuse of LSASS for credential access.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTka0Gm | q-0e0a32eacb | ok |
| 2 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTka0Gm | q-0e0a32eacb | ok |
| 3 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.TargetImage | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTka0Gm | q-0e0a32eacb | ok |
| 4 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTka0Gj | q-0e0a32eacb | ok |
| 5 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZSl2ML | q-0f412c5714 | ok |
| 6 | 2020-05-02 03:04:34.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | &amp; "C:\Program Files\SysinternalsSuite\accesschk.exe" | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZSl2MI | q-0f412c5714 | ok |

### F64 · malicious / high · T1552.001 · Credential-file harvesting and password-protected exfil archive on nashua.dmevals.local

Evidence status: **verified**

On nashua.dmevals.local, user pbeesly (via PsExec-launched C:\Windows\Temp\python.exe, a PyInstaller binary) ran a PowerShell script that recursively searched the user profile for credential-bearing files (*pass*, *login*, *admin*, *vpn, *.pst, *.ost, etc.), compressed them into working.zip, then created a password-protected Rar archive (Rar.exe a -hpfGzq5yKw) and wiped the artifacts with sdelete64.exe. This is credential/secret harvesting from files on disk (T1552.001) plus staged exfiltration.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:15:59.000Z | nashua.dmevals.local | windows.powershell | win.ScriptBlockText | $env:APPDATA;$files=ChildItem -Path $env:USERPROFILE\ -Include *.doc,*.xps,*.xls,*.ppt,*.pps,*.wps,*.wpd,*.ods,*.odt,*.lwp,*.jtd,*.pdf,*.zip,*.rar,*.docx,*.url,… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZLhp5i | q-de85d7018d | ok |
| 2 | 2020-05-02 03:16:19.000Z | nashua.dmevals.local | windows.powershell | win.ScriptBlockText | .\Rar.exe a -hpfGzq5yKw "$env:USERPROFILE\Desktop\working.zip" "$env:APPDATA\working.zip" | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZLh9Pm | q-de85d7018d | ok |
| 3 | 2020-05-02 03:16:19.395Z | nashua.dmevals.local | windows.sysmon | process.command_line | "C:\Windows\Temp\Rar.exe" a -hpfGzq5yKw C:\Users\pbeesly\Desktop\working.zip C:\Users\pbeesly\AppData\Roaming\working.zip | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTPA5kN | q-9fdf768fc4 | ok |
| 4 | 2020-05-02 03:16:00.353Z | nashua.dmevals.local | windows.sysmon | file.path | C:\Users\pbeesly\AppData\Roaming\working.zip | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItPCxFs- | q-3227ad8595 | ok |

### F30 · malicious / high · T1552.004 · PowerShell script exports all LocalMachine private keys to .pfx files on scranton

Evidence status: **verified**

On 2020-05-02 at 03:04:56 UTC, user pbeesly on scranton.dmevals.local executed a PowerShell script block named Get-PrivateKeys (script block ID 9d153741-75c3-4062-afe3-aeca0aee611b, path C:\Program Files\SysinternalsSuite\readme.ps1). The script enumerates cert:\LocalMachine recursively and, for every certificate with a Thumbprint, calls Export-PfxCertificate to write a randomly-named .pfx into $env:USERPROFILE\Downloads, protecting it with the hardcoded plaintext password "saribas". One second later (03:04:57.460) Sysmon recorded powershell.exe creating C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx, confirming the export executed. This is systematic collection of private keys from the machine certificate store.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZSl2ML | q-45602f80c8 | ok |
| 2 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\readme.ps1 | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZSl2ML | q-ad7ecf9bb2 | ok |
| 3 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | user.name | pbeesly | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZSl2ML | q-ad7ecf9bb2 | ok |
| 4 | 2020-05-02 03:04:57.460Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTkbEF9 | q-d07ecdb228 | ok |
| 5 | 2020-05-02 03:04:57.460Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\WindowsPowerShell\v1.0\powershell.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTkbEF9 | q-d07ecdb228 | ok |

### F39 · malicious / high · T1555 · Malicious intrusion chain on scranton (pbeesly) with credential use and exfiltration, but no password-store theft

Evidence status: **verified**

On scranton.dmevals.local user pbeesly executed C:\ProgramData\victim\cod.3aka3.scr (spawned by explorer.exe), which launched cmd.exe then powershell.exe. PowerShell ran a hidden one-liner decoding a payload from C:\Users\pbeesly\Downloads\monkey.png via System.Drawing GetPixel and IEX, and sdclt.exe was launched (UAC-bypass pattern) followed by control.exe. A 4104 script block defines Invoke-Exfil, which compresses the Downloads folder with 7Zip4Powershell using password 'lolol' into %APPDATA%\OfficeSupplies.7z and copies it to a WebDAV share \\192.168.0.4\webdav using hardcoded credentials (user 'cozy', password 'MyCozyPassw0rd!'). The .scr was later wiped with sdelete64.exe. This is credential USE and exfiltration, not credential-store theft; no browser, Credential Manager or password-manager store was accessed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:55:56.157Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\ProgramData\victim\â€®cod.3aka3.scr" /S | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHNH1uOFchItQE_psP | q-8350735139 | ok |
| 2 | 2020-05-02 02:58:45.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | sal a New-Object;Add-Type -AssemblyName 'System.Drawing'; $g=a System.Drawing.Bitmap('C:\Users\pbeesly\Downloads\monkey.png');$o=a Byte[] 4480;for($i=0; $i -le … | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZWqNDf | q-630adc1242 | ok |
| 3 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZCgBha | q-142d13836c | ok |
| 4 | 2020-05-02 03:02:04.000Z | scranton.dmevals.local | windows.security | process.command_line | "C:\Program Files\SysinternalsSuite\sdelete64.exe" /accepteula C:\programdata\victim\???cod.3aka3.scr | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItaFQQsu | q-fda0ee873b | ok |
| 5 | 2020-05-02 03:08:35.270Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Users\pbeesly\AppData\Roaming\OfficeSupplies.7z | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTWI7pZ | q-d2cd83ca01 | ok |

### F51 · malicious / high · T1558 · LSASS memory accessed with full-access masks by PowerShell on scranton.dmevals.local

Evidence status: **verified**

On 2020-05-02 at 03:05:16-03:05:16.654Z on scranton.dmevals.local, PowerShell.exe (PID 2976) opened lsass.exe (PID 736) with GrantedAccess 0x1F3FFF and 0x1FFFFF — full-process access masks used for credential/ticket extraction. This occurred in the middle of a hands-on-keyboard PowerShell session by user pbeesly that also ran Get-PrivateKeys, Get-Clipboard, Get-Keystrokes, Invoke-ScreenCapture, Invoke-Exfil and Invoke-Persistence, indicating credential theft from the host. Other LSASS accesses (svchost.exe, AntimalwareConfig.exe, WindowsAzureTelemetryService.exe) used benign 0x1000/0x1400 masks.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTka0Gm | q-614adc9cb3 | ok |
| 2 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTka0Gm | q-614adc9cb3 | ok |
| 3 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTka0Gj | q-6364213c8e | ok |
| 4 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZSl2ML | q-8337b97a90 | ok |
| 5 | 2020-05-02 03:06:59.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | Get-Keystrokes;Start-Sleep -Seconds 15;View-Job -JobName "Keystrokes" | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZRk1C1 | q-8337b97a90 | ok |

### F61 · malicious / high · T1649 · PowerShell 'Get-PrivateKeys' exports all machine certificates with private keys to .pfx files on scranton

Evidence status: **verified**

On scranton.dmevals.local, user pbeesly, a hidden/obfuscated PowerShell (PID 2976, launched with -noni -noexit -ep bypass -window hidden) decoded a steganographic payload from C:\Users\pbeesly\Downloads\monkey.png and executed it via IEX. It spawned powershell.exe PID 3876 which invoked the function Get-PrivateKeys. That function enumerates cert:\LocalMachine recursively and, for every certificate with a Thumbprint, calls Export-PfxCertificate to write a randomly-named .pfx into $env:USERPROFILE\Downloads, protected by the hardcoded password 'saribas'. Sysmon event 11 confirms the resulting file C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx created by PID 3876 at 2020-05-02T03:04:57.460Z. This is theft of authentication certificates/private keys (T1649).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZSl2ML | q-f67232940d | ok |
| 2 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZSl2ML | q-f67232940d | ok |
| 3 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | process.command_line | Get-PrivateKeys | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZRlVDe | q-dcc62bace5 | ok |
| 4 | 2020-05-02 03:04:57.460Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTkbEF9 | q-7a200a8a6d | ok |
| 5 | 2020-05-02 03:00:13.551Z | scranton.dmevals.local | windows.sysmon | win.ParentCommandLine | "PowerShell.exe" -noni -noexit -ep bypass -window hidden -c "sal a New-Object;Add-Type -AssemblyName 'System.Drawing'; $g=a System.Drawing.Bitmap('C:\Users\pbee… | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTvoSAW | q-8211bb3f26 | ok |

### F11 · suspicious / high · T1040 · Separate attacker activity: PsExec lateral movement with plaintext credentials (not network sniffing)

Evidence status: **verified**

Unrelated to T1040 but present in the same window: on scranton.dmevals.local, user pbeesly ran C:\Program Files\SysinternalsSuite\PsExec64.exe repeatedly against \\NASHUA with credentials supplied in cleartext on the command line (-u dmevals\pbeesly -p Fl0nk3rt0n!T0by), launching C:\Windows\Temp\python.exe on nashua.dmevals.local (PSEXESVC service installed 4x, python.exe spawned 4x as pbeesly). sdelete64.exe was also used on scranton to wipe C:\programdata\victim\???cod.3aka3.scr and other files. This is lateral movement / defense evasion, not network sniffing, and is reported here only for context.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:18.000Z | scranton.dmevals.local | windows.security | process.command_line | "C:\Program Files\SysinternalsSuite\PsExec64.exe" -accepteula \\NASHUA -u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItZ7Ev9A | q-c8fbd2167c | ok |
| 2 | 2020-05-02 03:11:40.000Z | nashua.dmevals.local | windows.security | process.executable | C:\Windows\Temp\python.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItZ7Ef_B | q-c8fbd2167c | ok |
| 3 | 2020-05-02 03:02:04.000Z | scranton.dmevals.local | windows.security | process.command_line | "C:\Program Files\SysinternalsSuite\sdelete64.exe" /accepteula C:\programdata\victim\???cod.3aka3.scr | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItaFQQsu | q-c8fbd2167c | ok |
| 4 | 2020-05-02 03:11:39.000Z | nashua.dmevals.local | windows.other | message | A service was installed in the system.    Service Name:  PSEXESVC  Service File Name:  %SystemRoot%\PSEXESVC.exe  Service Type:  user mode service  Service Star… | .ds-logs-windows.other-default-2026.10.17-000001 / AaFHNH1uOFchItbrYMQT | q-8612f8c5a1 | ok |

### F19 · suspicious / medium · T1110.002 · LSASS memory read by PowerShell on scranton (credential dumping, not cracking)

Evidence status: **verified**

On scranton.dmevals.local, PowerShell.exe (PID 2976, running as SYSTEM) opened lsass.exe (PID 736) with GrantedAccess 0x1F3FFF at 2020-05-02T03:05:16Z, a full-access mask consistent with credential dumping from LSASS memory. Two earlier accesses at 03:01:03Z used 0x1000. This is credential theft from memory rather than offline password cracking: no SAM/SECURITY/SYSTEM hive file access by a non-lsass process, no reg save/ntds/hashcat/john script text and no .dit/.hive file writes were found. The 4663/4656 hits on \REGISTRY\MACHINE\SYSTEM\...\Lsa and 4656 handle requests to SAM/SECURITY come only from C:\Windows\System32\lsass.exe, which is normal.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTka0Gj | q-fb4a362a7a | ok |
| 2 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTka0Gj | q-fb4a362a7a | ok |
| 3 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.TargetImage | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTka0Gj | q-fb4a362a7a | ok |
| 4 | 2020-05-02 03:11:40.000Z | nashua.dmevals.local | windows.security | process.executable | C:\Windows\PSEXESVC.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItZ7Ev8p | q-de7862b697 | ok |

### F20 · suspicious / medium · T1110.003 · Repeated explicit-credential logons with one account (pbeesly) via PsExec — not spraying

Evidence status: **verified**

Between 2020-05-02T03:11:18Z and 03:15:03Z, scranton.dmevals.local issued four 4648 explicit-credential logons for pbeesly targeting server NASHUA from 10.0.1.6, each matched by a 4648 on nashua.dmevals.local from C:\Windows\PSEXESVC.exe, and four PSEXESVC.exe service launches on nashua (03:11:39, 03:12:46, 03:13:49, 03:15:03). All attempts use the same single account pbeesly with the same password and succeed (4624 type 3 Kerberos logons for pbeesly on nashua at 03:11:18, 03:12:25, 03:13:28, 03:14:42), so this is repeated lateral use of one stolen credential, not password spraying across many accounts. The remaining 4648 events are machine/DWM/UMFD accounts from winlogon/wininit/taskhostw, which is normal.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:18.000Z | scranton.dmevals.local | windows.security | win.TargetUserName | pbeesly | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItZ7Ev9J | q-de7862b697 | ok |
| 2 | 2020-05-02 03:11:40.000Z | nashua.dmevals.local | windows.security | process.executable | C:\Windows\PSEXESVC.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItZ7Ev8p | q-de7862b697 | ok |
| 3 | 2020-05-02 03:11:39.934Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\Windows\PSEXESVC.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHNH1uOFchItUGBlWZ | q-b6ccdbf000 | ok |
| 4 | 2020-05-02 03:10:23.000Z | nashua.dmevals.local | windows.security | win.LogonProcessName | Kerberos | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItZ7FP8C | q-6e5412cefb | ok |

### F23 · suspicious / medium · T1111 · Suspicious credential-handling PowerShell exfil script (pbeesly on scranton) - not MFA interception

Evidence status: **verified**

A PowerShell script block named Invoke-Exfil was executed by user pbeesly on scranton.dmevals.local (ScriptBlock ID b2b03a9c-43f0-4285-837d-f22d4600b2ae, path C:\Program Files\SysinternalsSuite\psversion.ps1). It installs 7Zip4Powershell, compresses the user's Downloads folder into a password-protected archive, builds a PSCredential from a hardcoded username 'cozy' and password 'MyCozyPassw0rd!', maps a WebDAV drive to \\192.168.0.4\webdav and copies the archive there. This is credential use and data exfiltration, not interception of MFA material; it is reported here as suspicious context but does not satisfy T1111.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZCgBha | q-d8df1fa281 | ok |
| 2 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZCgBha | q-d8df1fa281 | ok |
| 3 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | process.command_line | Invoke-Exfil | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZCgq7J | q-351d4194f5 | ok |

### F24 · suspicious / medium · T1111 · Broad LSASS access by wsmprovhost.exe on nashua - credential dumping, not MFA interception

Evidence status: **verified**

On nashua.dmevals.local, wsmprovhost.exe (PID 7720, PowerShell remoting host) opened lsass.exe (PID 728) with GrantedAccess 0x1f3fff, a broad mask including PROCESS_VM_READ, with a call trace through PowerShell management assemblies. This is consistent with credential dumping via PowerShell remoting (T1003), not MFA interception. It is reported as suspicious context; it does not demonstrate T1111.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHNH1uOFchItUHCTY0 | q-9b536a1c93 | ok |
| 2 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHNH1uOFchItUHCTY0 | q-9b536a1c93 | ok |
| 3 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.TargetImage | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHNH1uOFchItUHCTY0 | q-9b536a1c93 | ok |

### F31 · suspicious / medium · T1552.001 · Sysinternals accesschk.exe run and passwordsDB file on scranton; nuget.config creation is benign

Evidence status: **verified**

On scranton.dmevals.local, user pbeesly ran accesschk.exe from C:\Program Files\SysinternalsSuite via PowerShell (script block 08718796-b72d-4e05-a41f-d7c0557c4a7b, 03:04:34), and at 03:04:35 accesschk.exe created the file C:\Program Files\SysinternalsSuite\passwordsDB. The name and the surrounding credential-collection activity (private-key export minutes later) suggest file-system reconnaissance for credential material, but no command line showing a search for credential files was captured, so this is suspicious rather than confirmed. Separately, powershell.exe created C:\Users\pbeesly\AppData\Roaming\NuGet\nuget.config at 03:08:31, which is a normal NuGet/PowerShell artifact and benign.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:34.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | &amp; "C:\Program Files\SysinternalsSuite\accesschk.exe" | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZSl2MI | q-1da61d68f2 | ok |
| 2 | 2020-05-02 03:04:35.069Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Program Files\SysinternalsSuite\passwordsDB | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTkbkGF | q-8f038fff11 | ok |
| 3 | 2020-05-02 03:04:35.069Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\Program Files\SysinternalsSuite\accesschk.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTkbkGF | q-8f038fff11 | ok |
| 4 | 2020-05-02 03:08:31.192Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Users\pbeesly\AppData\Roaming\NuGet\nuget.config | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHNH1uOFchItUHCjbV | q-47d62e30ec | ok |

### F60 · suspicious / medium · T1621 · Cleartext credential use via PsExec on scranton.dmevals.local (credential access, not MFA generation)

Evidence status: **verified**

While hunting T1621 I observed a PowerShell script block (event 4104) on scranton.dmevals.local executed by user pbeesly that invokes PsExec64.exe against \\NASHUA with the account password passed in cleartext on the command line (-u "dmevals\pbeesly" -p "Fl0nk3rt0n!T0by") to launch C:\Windows\Temp\python.exe. This is credential-access-relevant (cleartext credential exposure / lateral movement tooling) but is NOT Multi-Factor Authentication Request Generation, so it does not support the T1621 hypothesis. It is reported here as suspicious context only.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:18.000Z | scranton.dmevals.local | windows.powershell | process.command_line | .\PsExec64.exe -accepteula \\NASHUA -u "dmevals\pbeesly" -p "Fl0nk3rt0n!T0by" -i 2 "C:\Windows\Temp\python.exe" | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZLhZrg | q-39d8971118 | ok |
| 2 | 2020-05-02 03:11:18.000Z | scranton.dmevals.local | windows.powershell | host.name | scranton.dmevals.local | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZLhZrg | q-39d8971118 | ok |
| 3 | 2020-05-02 03:11:18.000Z | scranton.dmevals.local | windows.powershell | user.name | pbeesly | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZLhZrg | q-39d8971118 | ok |

### F03 · benign / medium · T1003.002 · No SAM/SECURITY hive dumping observed

Evidence status: **verified**

No evidence of SAM/SECURITY registry hive theft. The only file-creation hits matching SAM/SECURITY were Prefetch files (SECURITYHEALTHSYSTRAY.EXE-*.pf etc.) created by svchost.exe, and the only registry writes to SAM/SECURITY were lsass.exe writing HKLM\SAM\SAM\Domains\Account\F and HKLM\SECURITY\Cache\NL$1 (normal lsass behaviour), plus LogonUI writing LoggedOnSAMUser. No reg save, no hive copies, no 4663/4656 handle requests to SAM objects by non-lsass processes.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:21:28.476Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Windows\Prefetch\SECURITYHEALTHSYSTRAY.EXE-41AD6DE1.pf | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItKT-FUX | q-addb40acba | ok |
| 2 | 2020-05-02 03:19:10.368Z | scranton.dmevals.local | windows.sysmon | win.TargetObject | HKLM\SAM\SAM\Domains\Account\F | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItO9rO3D | q-e7418bf96e | ok |
| 3 | 2020-05-02 03:11:40.144Z | nashua.dmevals.local | windows.sysmon | win.TargetObject | HKLM\SECURITY\Cache\NL$1 | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTVGQnT | q-e7418bf96e | ok |

### F04 · benign / medium · T1003.003 · No NTDS.dit access observed

Evidence status: **verified**

No hits for ntds.dit file creation/access, no diskshadow/vssadmin/esentutl command lines, and no NTDS-related service installs across sysmon, security, powershell and other datasets. No domain-controller credential theft activity was observed in this window.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:18:34.907Z | scranton.dmevals.local | windows.sysmon | process.command_line | C:\windows\system32\dxgiadaptercache.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItO-r7Fc | q-b6f1d187b6 | ok |

### F05 · benign / medium · T1003.004 · No LSA secrets dumping observed

Evidence status: **verified**

No lsadump/secrets command lines, no SECURITY\Policy\Secrets registry access, and no credential-dumping service installs. The samlib.dll/cryptdll.dll image loads and the Lsa registry reads (AccessMask 0x1) are normal Windows component behaviour. The LSASS memory access by pbeesly's PowerShell is captured under T1003.001.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:01:36.915Z | newyork.dmevals.local | windows.sysmon | win.ImageLoaded | C:\Windows\System32\cryptdll.dll | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTqhQkl | q-7d30c4928b | ok |
| 2 | 2020-05-02 03:25:33.000Z | nashua.dmevals.local | windows.security | win.ObjectName | \REGISTRY\MACHINE\SYSTEM\ControlSet001\Control\Lsa | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItVcvuSc | q-e6e9dbf6bc | ok |

### F06 · benign / medium · T1003.005 · No cached domain credential dumping observed

Evidence status: **verified**

No cache/dcc2/mscache command lines or SECURITY\Cache handle requests by non-lsass processes. The HKLM\SECURITY\Cache\NL$1 writes are performed by lsass.exe itself (normal cached-credential maintenance), not by a dumping tool.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:40.144Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTVGQnT | q-e7418bf96e | ok |

### F07 · benign / medium · T1003.006 · No DCSync observed

Evidence status: **verified**

No 4662 events with the DS-Replication GUIDs, no 4929 (replication source removed) events, and no DCSync/lsadump/drsuapi PowerShell script blocks. No directory-replication credential theft was observed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:18:34.907Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\Windows\System32\dxgiadaptercache.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItO-r7Fc | q-b6f1d187b6 | ok |

### F08 · benign / high · T1040 · netsh trace capture on scranton is Azure Network Watcher agent activity (benign)

Evidence status: **verified**

On 2020-05-01 23:19:17 and 23:19:24 (host scranton.dmevals.local), netsh.exe was launched with 'trace start capture=yes traceFile=...etl' and 'trace stop'. Both processes were created by C:\Packages\Plugins\Microsoft.Azure.NetworkWatcher.NetworkWatcherAgentWindows\1.4.1421.1\NetworkWatcherAgent\NetworkWatcherAgent.exe under the machine account SCRANTON$ (S-1-5-18, logon 0x3E7). This is the Microsoft Azure Network Watcher packet-capture feature, a legitimate cloud monitoring agent, not adversary sniffing. The surrounding logman.exe ETL trace management (GAEvents/RTEvents/WindowsAzure-GuestAgent-Diagnostic) is likewise Azure Guest Agent telemetry.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:17.000Z | scranton.dmevals.local | windows.security | process.command_line | C:\windows\system32\netsh.exe trace start capture=yes traceFile="C:\windows\TEMP\E7116ECA-DFE6-43C7-8FA8-8D3AC5AA8726\B91E06C5-1C7C-4830-9A76-74FA211560A7.etl" | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItVt4o2y | q-9a0831b648 | ok |
| 2 | 2020-05-02 03:19:17.000Z | scranton.dmevals.local | windows.security | process.parent.executable | C:\Packages\Plugins\Microsoft.Azure.NetworkWatcher.NetworkWatcherAgentWindows\1.4.1421.1\NetworkWatcherAgent\NetworkWatcherAgent.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItVt4o2y | q-25c1a6464f | ok |
| 3 | 2020-05-02 03:19:24.000Z | scranton.dmevals.local | windows.security | process.command_line | C:\windows\system32\netsh.exe trace stop | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItVr2bv9 | q-9a0831b648 | ok |
| 4 | 2020-05-02 03:19:24.000Z | scranton.dmevals.local | windows.security | win.SubjectUserName | SCRANTON$ | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItVr2bv9 | q-8b2b0a7ea4 | ok |
| 5 | 2020-05-02 03:19:13.000Z | scranton.dmevals.local | windows.security | process.command_line | "C:\Packages\Plugins\Microsoft.Azure.NetworkWatcher.NetworkWatcherAgentWindows\1.4.1421.1\NetworkWatcherAgent\NetworkWatcherAgent.exe" /service | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItVz8aWs | q-4c1bc36bf0 | ok |
| 6 | 2020-05-02 03:19:29.000Z | scranton.dmevals.local | windows.security | process.command_line | "logman.exe" create trace GAEvents -max 50 -f bincirc -o C:\WindowsAzure\Logs\WaAppAgent.etl -p "{3000b92b-ca8b-4269-90ea-c4185ee09e92}" | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItVr2bu5 | q-4c1bc36bf0 | ok |

### F09 · benign / high · T1040 · No packet-capture/sniffing tooling or drivers observed on any host

Evidence status: **verified**

Across the whole windows.sysmon window (2020-05-02T02:55:23Z..03:28:17Z, 143884 events) there were zero process-creation events for pktmon/tcpdump/tshark/windump/RawCap/netsh trace, and zero driver-load (event 6) events for pcap/npcap/pktmon images (ES\|QL queries q-cd9dc54e7a and q-6cb5fc33dc returned 0 rows). windows.powershell had no script-block (4104) content referencing pktmon, netsh trace, New-NetEventSession or pcap. The only capture-related process creations in windows.security were the Azure Network Watcher netsh trace pair and Azure Guest Agent logman.exe ETL trace management. No evidence of adversary network sniffing on the monitored Windows hosts.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:17.000Z | scranton.dmevals.local | windows.security | process.executable | C:\Windows\System32\netsh.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItVt4o2y | q-9a0831b648 | ok |
| 2 | 2020-05-02 03:19:24.000Z | scranton.dmevals.local | windows.security | process.executable | C:\Windows\System32\netsh.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItVr2bv9 | q-9a0831b648 | ok |
| 3 | 2020-05-02 03:18:38.000Z | scranton.dmevals.local | windows.security | process.executable | C:\Windows\System32\logman.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItV19xlz | q-4c1bc36bf0 | ok |

### F10 · benign / medium · T1040 · Zeek segment shows only normal SMB/Kerberos/NetBIOS traffic, no sniffing pattern

Evidence status: **verified**

In the zeek window (2020-04-30T00:06:38Z..00:45:00Z, observers bobs.bigwheel.local and simplerockbuild.simplerock.lan) connection states were dominated by RSTO (420), SF (84), S0 (52), RSTR (45), REJ (10), S1 (2). The RSTO/S0/REJ entries are ordinary SMB (445), Kerberos/gssapi and NetBIOS name-service (udp/138 broadcast to 10.0.1.255) traffic between 10.0.1.x hosts and 10.0.0.4, plus rejected SMB attempts to 192.168.0.4. No promiscuous-mode, ARP-spoofing or capture-related anomaly is visible. Note this window does not overlap the Windows datasets, so it cannot be correlated by time.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-04-30 00:06:38.903Z | simplerockbuild.simplerock.lan | zeek | message | {"@stream":"conn","@system":"simplerockbuild.simplerock.lan","@proc":"zeek","ts":1588205198.90335,"uid":"CbD9Ha1JtdoSnfM4Mf","id_orig_h":"10.0.1.4","id_orig_p":… | .ds-logs-zeek-default-2026.10.17-000001 / AaFHNX1uOFchItbgrog0 | q-2471e3c599 | ok |
| 2 | 2020-04-30 00:08:43.385Z | bobs.bigwheel.local | zeek | message | {"@stream":"conn","@system":"bobs.bigwheel.local","@proc":"zeek","ts":1588205323.385543,"uid":"CvxbPE3MuO7boUdSc8","id_orig_h":"10.0.1.6","id_orig_p":138,"id_re… | .ds-logs-zeek-default-2026.10.17-000001 / AaFHNn1uOFchItY0uF-5 | q-2471e3c599 | ok |
| 3 | 2020-04-30 00:32:14.891Z | simplerockbuild.simplerock.lan | zeek | message | {"@stream":"conn","@system":"simplerockbuild.simplerock.lan","@proc":"zeek","ts":1588206734.891382,"uid":"CdtjnW2vt1HxMCIR1k","id_orig_h":"10.0.1.4","id_orig_p"… | .ds-logs-zeek-default-2026.10.17-000001 / AaFHNX1uOFchItbgrYih | q-2471e3c599 | ok |

### F15 · benign / medium · T1056.002 · No GUI input capture observed

Evidence status: **verified**

No evidence of GUI input capture (e.g., fake credential prompts, consent.exe abuse for credential harvesting) was found. consent.exe was observed once on scranton.dmevals.local spawned by svchost.exe at 02:58:42, which is normal UAC elevation behaviour, not GUI input capture. The zeek dataset (2020-04-30) does not overlap the Windows telemetry window and showed no HTTP POST activity.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:58:42.868Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\Windows\System32\consent.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHNH1uOFchItQB7V3u | q-47a2f163d0 | ok |

### F16 · benign / medium · T1056.003 · No web portal capture observed

Evidence status: **verified**

No IIS/w3wp/web.config/wwwroot activity or web-portal credential capture was observed. The zero-hit checks for wwwroot/inetpub/web.config file creation, iis/w3wp/appcmd process creation, and HTTP POST in zeek returned nothing. The zeek window (2020-04-30) does not overlap the Windows host telemetry (2020-05-02).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:55:56.157Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\ProgramData\victim\â€®cod.3aka3.scr | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHNH1uOFchItQE_psP | q-47a2f163d0 | ok |

### F17 · benign / high · T1110 · No brute-force authentication failures; only successful credential validation on newyork

Evidence status: **verified**

The only credential-validation event in the window is a single 4776 on newyork.dmevals.local at 2020-05-02T03:20:40Z for account pbeesly from workstation 10.0.1.4 with Error Code 0x0 (AUDIT_SUCCESS). No 4625 (failed logon), 4771 (Kerberos pre-auth failure) or 4776 failure events exist anywhere in windows.security, windows.other or windows.powershell, so there is no evidence of repeated authentication attempts, guessing, spraying or stuffing against any host.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:20:40.000Z | newyork.dmevals.local | windows.security | win.Status | 0x0 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItVn1FNc | q-6c515900f3 | ok |
| 2 | 2020-05-02 03:20:40.000Z | newyork.dmevals.local | windows.security | win.EventType | AUDIT_SUCCESS | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItVn1FNc | q-6c515900f3 | ok |
| 3 | 2020-05-02 03:20:40.000Z | newyork.dmevals.local | windows.security | win.Workstation | 10.0.1.4 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItVn1FNc | q-6c515900f3 | ok |

### F18 · benign / high · T1110.001 · No password-guessing pattern; the only password-bearing command line is a single PsExec launch with a valid credential

Evidence status: **verified**

The single sysmon process-creation hit for a password argument is PsExec64.exe run by pbeesly on scranton.dmevals.local at 2020-05-02T03:11:18Z against \\NASHUA with -u dmevals\pbeesly -p Fl0nk3rt0n!T0by, i.e. one explicit, successful credential use rather than a guessing loop. No 4625 failures, no net use/runas guessing commands and no LogonUser/New-Object Net scripts were found, so password guessing is not observed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:18.784Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\PsExec64.exe" -accepteula \\NASHUA -u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTVGglR | q-7d06caaeaf | ok |
| 2 | 2020-05-02 03:11:18.784Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\Program Files\SysinternalsSuite\PsExec64.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTVGglR | q-7d06caaeaf | ok |

### F21 · benign / high · T1110.004 · No credential-stuffing pair lists; only a single reused credential

Evidence status: **verified**

The only script blocks matching username/password/credential keywords are Microsoft module resource strings (MSFT_ScriptResourceStrings.psd1) on newyork.dmevals.local, plus the Get-PrivateKeys and Invoke-Exfil functions on scranton that reference a hard-coded password for certificate export and archive encryption. No username/password pair list, no login/auth command line and no 4625 failures were observed, so credential stuffing is not present.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:01:30.000Z | newyork.dmevals.local | windows.powershell | win.ScriptBlockText | # Localized	09/15/2018 04:54 AM (GMT)	303:6.40.10614 	MSFT_ScriptResourceStrings.psd1  # Localized MSFT_ScriptResourceStrings.psd1    ConvertFrom-StringData @' … | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZSmWPy | q-da26c43519 | ok |
| 2 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZSl2ML | q-a0370dd50b | ok |

### F22 · benign / medium · T1111 · No MFA interception artifacts; credential-related hits are benign Windows components or non-MFA credential theft/exfil

Evidence status: **verified**

Hunting for T1111 (Multi-Factor Authentication Interception) across windows.security, windows.sysmon, windows.powershell, windows.other and zeek produced no evidence of MFA token/smartcard/OTP interception. The Credential/Vault/Smartcard registry hits are Windows' own CredentialEnrollmentManagerUserSvc service registration and a CredentialGuard configuration value of 0x0 (disabled) written by lsass/services.exe on scranton.dmevals.local. PowerShell script blocks matching 'Credential' are module help text and an exfiltration function. LSASS process-access events are overwhelmingly from svchost.exe (289 of 326) i.e. normal Windows behavior. The genuinely suspicious activity observed (a hardcoded-credential exfil script by user pbeesly on scranton, and wsmprovhost.exe reading lsass with GrantedAccess 0x1f3fff on nashua) is credential theft/exfiltration, which maps to other techniques (e.g. T1003/T1041), not MFA interception. No MFA interception was observed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:09.865Z | scranton.dmevals.local | windows.sysmon | message | Registry value set:  RuleName: -  EventType: SetValue  UtcTime: 2020-05-02 03:19:09.865  ProcessGuid: {47ab858c-e6ad-5eac-0c00-000000000500}  ProcessId: 748  Im… | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItO9rO3Z | q-2cca923411 | ok |
| 2 | 2020-05-02 03:20:48.264Z | scranton.dmevals.local | windows.sysmon | message | Registry value set:  RuleName: -  EventType: SetValue  UtcTime: 2020-05-02 03:20:48.264  ProcessGuid: {47ab858c-e6ad-5eac-0b00-000000000500}  ProcessId: 736  Im… | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItOxeHN4 | q-2cca923411 | ok |
| 3 | 2020-05-02 03:19:09.000Z | scranton.dmevals.local | windows.other | message | Credential Guard configuration: 0x0, 0 | .ds-logs-windows.other-default-2026.10.17-000001 / AaFHNH1uOFchItbrX8R_ | q-869ec941d6 | ok |
| 4 | 2020-05-02 03:01:03.622Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1000 | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTtmJQ5 | q-8034840eed | ok |
| 5 | 2020-05-02 03:01:30.000Z | newyork.dmevals.local | windows.powershell | process.command_line | alidateSet('Seconds','Minutes','Hours','Days')]         [System.String]         $TimeSpanType     )     switch ($TimeSpanType)     {         'Seconds' { return … | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZSmmNB | q-fe1a469c7e | ok |

### F25 · benign / high · T1187 · No forced-authentication (T1187) activity observed; SMB/UNC traffic is normal domain and credential-based lateral movement

Evidence status: **verified**

Hunting for T1187 Forced Authentication across windows.security, windows.sysmon, windows.other and zeek produced no evidence of coercion of NTLM/Net-NTLMv2 authentication. The 121 event.code 5145 share-access events are all machine-account (NEWYORK$, SCRANTON$) reads of the \\*\SYSVOL share for GPO files (gpt.ini, Policies\{31B2F340-...}) — normal domain replication, not attacker-controlled shares. All 66 outbound SMB connections (destination.port 445) originate from the System process to the DC 10.0.0.4 / link-local fe80::e40c:95b6:b0a7:6429, i.e. normal domain traffic. The only .lnk files created are benign: two Explorer 'Recent' shortcuts on scranton (Backup and Restore (Windows 7).lnk, System and Security.lnk) and a StartUp shortcut hostui.lnk dropped by PowerShell as part of a separate fileless-payload chain (hostui.exe -> powershell Get-ItemPropertyValue HKLM:\SOFTWARE\Javasoft \| Invoke-Expression), which is execution/persistence, not forced authentication. The only UNC path usage is PsExec64.exe \\NASHUA with explicit credentials (-u dmevals\pbeesly -p ...), i.e. credential-based lateral movement, not auth coercion. No .scf/.url/.searchConnector-ms/.library-ms lures and no WebDAV (@SSL/DavWWWRoot) references were found. The single windows.other NTLM event (6038) is an informational per-boot notice that NTLM is in use, not a coercion attempt.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:56:47.000Z | newyork.dmevals.local | windows.security | win.ShareName | \\*\SYSVOL | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItaKWxp5 | q-9a97c4b753 | ok |
| 2 | 2020-05-02 02:56:47.000Z | newyork.dmevals.local | windows.security | win.RelativeTargetName | dmevals.local\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\gpt.ini | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItaKWxp5 | q-9a97c4b753 | ok |
| 3 | 2020-05-02 03:01:43.000Z | newyork.dmevals.local | windows.security | user.name | SCRANTON$ | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItaFQQtn | q-9a97c4b753 | ok |
| 4 | 2020-05-02 03:01:43.033Z | scranton.dmevals.local | windows.sysmon | process.executable | System | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTqgghU | q-92502ee814 | ok |
| 5 | 2020-05-02 03:01:43.033Z | scranton.dmevals.local | windows.sysmon | destination.port | 445 | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTqgghU | q-92502ee814 | ok |
| 6 | 2020-05-02 02:58:44.405Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Users\pbeesly\AppData\Roaming\Microsoft\Windows\Recent\Backup and Restore (Windows 7).lnk | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHNH1uOFchItQA64yf | q-48ace60116 | ok |
| 7 | 2020-05-02 03:04:23.681Z | scranton.dmevals.local | windows.sysmon | file.path | C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\hostui.lnk | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTmcl_4 | q-1e206fb990 | ok |
| 8 | 2020-05-02 03:14:42.601Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\PsExec64.exe" -accepteula \\NASHUA -u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItPDyDoS | q-2d6132c68d | ok |
| 9 | 2020-05-02 03:20:41.000Z | scranton.dmevals.local | windows.other | event.code | 6038 | .ds-logs-windows.other-default-2026.10.17-000001 / AaFHNH1uOFchItbrX8RH | q-0df1f1a8c5 | ok |

### F27 · benign / medium · T1212 · wsmprovhost.exe broad process access on nashua.dmevals.local (benign enumeration)

Evidence status: **verified**

On nashua.dmevals.local, wsmprovhost.exe (PowerShell remoting host) opened many unrelated processes (ApplicationFrameHost.exe, browser_broker.exe, conhost.exe, ctfmon.exe, DllHost.exe, dwm.exe) with GrantedAccess 0x1f3fff, with call traces through .NET native images (System.ni.dll). This broad, multi-target pattern is consistent with a PowerShell remoting session enumerating processes rather than targeted LSASS credential access; only one lsass access (0x1f3fff) was seen from wsmprovhost, not the PROCESS_ALL_ACCESS mask.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:09:29.384Z | nashua.dmevals.local | windows.sysmon | win.TargetImage | C:\windows\system32\ApplicationFrameHost.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHNH1uOFchItUHCTYl | q-4aad6379e6 | ok |
| 2 | 2020-05-02 03:09:29.415Z | nashua.dmevals.local | windows.sysmon | win.TargetImage | C:\windows\system32\dwm.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHNH1uOFchItUHCTYt | q-4aad6379e6 | ok |
| 3 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHNH1uOFchItUHCTY0 | q-0e0a32eacb | ok |

### F28 · benign / medium · T1212 · Kerberos TGT/service-ticket requests on newyork.dmevals.local (normal authentication)

Evidence status: **verified**

Event codes 4768/4769 on newyork.dmevals.local show user pbeesly requesting TGTs and service tickets for krbtgt, NEWYORK$, and NASHUA$ from client addresses 10.0.1.4/10.0.1.6. These are routine Kerberos authentication events with no evidence of forged tickets, RC4 downgrade, or exploitation; they do not indicate exploitation for credential access.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:18.000Z | newyork.dmevals.local | windows.security | event.code | 4768 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItZ7Ef_w | q-889f5548f2 | ok |
| 2 | 2020-05-02 03:09:04.000Z | newyork.dmevals.local | windows.security | event.code | 4769 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItZ8FraW | q-889f5548f2 | ok |

### F29 · benign / low · T1212 · Zeek DCE/RPC DRS and endpoint-mapper traffic (separate window, no exploitation)

Evidence status: **verified**

Zeek dce_rpc records (2020-04-30, non-overlapping window) show 10.0.1.4 calling 10.0.0.4 on epmapper and drsuapi (DRSBind/DRSCrackNames/DRSUnbind) and lsarpc. These are standard Windows RPC/AD replication operations with no exploit payload or overflow indicators; no exploitation for credential access is observable in this window.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-04-30 00:12:00.968Z | simplerockbuild.simplerock.lan | zeek | message | {"@stream":"dce_rpc","@system":"simplerockbuild.simplerock.lan","@proc":"zeek","ts":1588205520.968267,"uid":"Cn4LXE1sRGUWLD2kAc","id_orig_h":"10.0.1.4","id_orig… | .ds-logs-zeek-default-2026.10.17-000001 / AaFHNX1uOFchItbgrogQ | q-d49f5f1b69 | ok |
| 2 | 2020-04-30 00:12:00.962Z | simplerockbuild.simplerock.lan | zeek | message | {"@stream":"dce_rpc","@system":"simplerockbuild.simplerock.lan","@proc":"zeek","ts":1588205520.96246,"uid":"CDQRH83UIpbjplJKBc","id_orig_h":"10.0.1.4","id_orig_… | .ds-logs-zeek-default-2026.10.17-000001 / AaFHNX1uOFchItbgrYhe | q-d49f5f1b69 | ok |

### F32 · benign / medium · T1552.002 · No registry credential access observed

Evidence status: **verified**

The registry value-set events touching Password/Credential keys (17 hits) were all routine OS activity: svchost.exe writing IdentityCRL ProviderPasswordLength/CharacterGroups, lsass.exe setting DeviceGuard CredentialGuard Enabled, services.exe registering CredentialEnrollmentManagerUserSvc, and winlogon.exe writing PasswordExpiryNotification. No reg query/save/export of HKLM\SAM or HKLM\SECURITY was observed. No evidence of credentials-in-registry collection.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:09.865Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItO9rO3Z | q-b4b1294224 | ok |
| 2 | 2020-05-02 03:05:28.255Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\svchost.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItThYt63 | q-b4b1294224 | ok |

### F33 · benign / medium · T1552.003 · No shell history access observed

Evidence status: **verified**

No events referenced ConsoleHost_history, .bash_history, .zsh_history, or Get-History in process command lines, file creations, or PowerShell script blocks. No shell-history credential collection was observed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZSl2ML | q-45602f80c8 | ok |

### F34 · benign / medium · T1552.006 · No Group Policy Preferences credential access observed

Evidence status: **verified**

No cpassword, Groups.xml, gpprefdecrypt, or AES-key references appeared in PowerShell script blocks, process command lines, or other-channel messages. The only SYSVOL/GPP-related activity was routine SMB reads of \\NEWYORK.dmevals.local\sysvol gpt.ini and GptTmpl.inf by domain machines in the separate (non-overlapping) zeek window, which is normal Group Policy processing, not credential extraction.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-04-30 00:12:01.659Z | simplerockbuild.simplerock.lan | zeek | message | {"@stream":"smb_files","@system":"simplerockbuild.simplerock.lan","@proc":"zeek","ts":1588205521.659592,"uid":"C6niUh1gdPBNBhfNDe","id_orig_h":"10.0.1.4","id_or… | .ds-logs-zeek-default-2026.10.17-000001 / AaFHNX1uOFchItbgrog6 | q-a8ebcbaaad | ok |

### F35 · benign / high · T1555 · LSASS handle access on all four hosts is benign system/AV/telemetry activity, not credential dumping

Evidence status: **verified**

Sysmon Event 10 shows 326 accesses to C:\windows\system32\lsass.exe. Stacking by source process and GrantedAccess shows the bulk (216 on scranton, 30 newyork, 28 nashua, 12 utica) are svchost.exe with GrantedAccess 0x1000 (PROCESS_QUERY_LIMITED_INFORMATION), plus Azure IaaSAntimalware AntimalwareConfig.exe and WindowsAzureTelemetryService.exe with 0x1400, and wininit/csrss/services with high access at boot. Call traces resolve to legitimate modules (ntdll, KERNELBASE, lsm.dll, sysmain.dll, CorperfmonExt.dll, perfts.dll). No mimikatz/sekurlsa/lsadump command lines were found (C197 zero hits).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:59.323Z | scranton.dmevals.local | windows.sysmon | win.CallTrace | C:\windows\SYSTEM32\ntdll.dll+9c584\|C:\windows\System32\KERNELBASE.dll+2732e\|c:\windows\system32\sysmain.dll+1e689\|c:\windows\system32\sysmain.dll+1e509\|c:\… | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItO4kjEa | q-1492f15493 | ok |
| 2 | 2020-05-02 03:19:09.803Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\csrss.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItO9re0E | q-1492f15493 | ok |
| 3 | 2020-05-02 03:20:41.543Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\Packages\Plugins\Microsoft.Azure.Security.IaaSAntimalware\1.5.5.9\AntimalwareConfig.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItOqWMLr | q-1492f15493 | ok |

### F37 · benign / high · T1555.004 · Credential Manager / Vault hits are benign Windows service and MuiCache registry entries

Evidence status: **verified**

The only 'Credential'/'Vault' hits are benign: services.exe creating the CredentialEnrollmentManagerUserSvc service keys and MuiCache entries for CredentialEnrollmentManager.exe on scranton/nashua, and lsass.exe writing DeviceGuard\Scenarios\CredentialGuard\Enabled=0. The windows.other hits are a Credential Guard configuration event and an unrelated DNS PTR registration failure. PowerShell 4104 hits for 'credential' are the stock MSFT_ScriptResourceStrings.psd1 resource file. No cmdkey/vault credential-store dumping was observed (C209/C210 zero hits).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:20:48.264Z | scranton.dmevals.local | windows.sysmon | registry.path | HKLM\System\CurrentControlSet\Services\CredentialEnrollmentManagerUserSvc_13619b\ImagePath | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItOxeHN4 | q-bd1e6e4e31 | ok |
| 2 | 2020-05-02 03:19:09.865Z | scranton.dmevals.local | windows.sysmon | registry.path | HKLM\System\CurrentControlSet\Control\DeviceGuard\Scenarios\CredentialGuard\Enabled | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItO9rO3Z | q-bd1e6e4e31 | ok |
| 3 | 2020-05-02 03:19:09.000Z | scranton.dmevals.local | windows.other | message | Credential Guard configuration: 0x0, 0 | .ds-logs-windows.other-default-2026.10.17-000001 / AaFHNH1uOFchItbrX8R_ | q-d6b56cfe83 | ok |

### F40 · benign / medium · T1556 · LSASS process access on Windows hosts — no authentication-process modification observed

Evidence status: **verified**

326 Sysmon Event 10 accesses to lsass.exe were observed across utica/newyork/scranton/nashua. Stacking by source image shows 289 from C:\windows\system32\svchost.exe and the remainder from known system/AV components (AntimalwareConfig.exe, WindowsAzureTelemetryService.exe, wininit.exe, csrss.exe, services.exe, wsmprovhost.exe). GrantedAccess is overwhelmingly 0x1000 (PROCESS_QUERY_LIMITED_INFORMATION). Only 9 events used high-privilege masks; the notable one is PowerShell.exe (PID 2976) on scranton.dmevals.local at 2020-05-02T03:05:16.654Z opening lsass with GrantedAccess 0x1FFFFF (full access) under NT AUTHORITY\SYSTEM. No credential-dumping tooling, no lsass image-load of a non-Microsoft DLL, and no registry modification of the authentication process were found, so this is consistent with credential access (T1003) rather than T1556 authentication-process tampering. No T1556 modification of the authentication process was observed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTka0Gm | q-fef986f028 | ok |
| 2 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTka0Gm | q-fef986f028 | ok |
| 3 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.TargetImage | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTka0Gm | q-fef986f028 | ok |
| 4 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHNH1uOFchItUHCTY0 | q-07120a044b | ok |
| 5 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHNH1uOFchItUHCTY0 | q-07120a044b | ok |

### F41 · benign / medium · T1556.001 · Network logons (4624 type 3) and explicit-credential logons (4648) are routine machine-account and PsExec activity

Evidence status: **verified**

218 Event 4624 type-3 logons were observed, dominated by machine accounts (NEWYORK$) authenticating from ::1, fe80:: and 10.0.0.4 — normal computer-account network authentication. 15 Event 4648 explicit-credential logons were observed: repeated pbeesly logons on scranton.dmevals.local from 10.0.1.6 and on nashua.dmevals.local via C:\Windows\PSEXESVC.exe, plus routine DWM-1/UMFD-1/UMFD-2/SCRANTON$ winlogon/taskhostw logons. The PSEXESVC pattern is PsExec lateral movement, not DC authentication backdooring. No modification of domain-controller authentication was observed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:40.000Z | nashua.dmevals.local | windows.security | process.executable | C:\Windows\PSEXESVC.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItZ7Ev8p | q-6ffaa00602 | ok |
| 2 | 2020-05-02 03:11:40.000Z | nashua.dmevals.local | windows.security | win.TargetUserName | pbeesly | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItZ7Ev8p | q-6ffaa00602 | ok |
| 3 | 2020-05-02 02:55:54.000Z | newyork.dmevals.local | windows.security | user.name | NEWYORK$ | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItaKXhpQ | q-74e9d88e59 | ok |

### F42 · benign / high · T1556.002 · No password filter DLL registration or Notification Packages modification observed

Evidence status: **verified**

Checks for password-filter activity returned no hits: no Sysmon Event 11 file creation of a DLL under System32 (C229), no Event 4657 registry change to Notification Packages / Password / lsass keys (C231), and no PowerShell 4104 script block referencing Notification Packages, password filter or lsass (C232). No password filter DLL was registered.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:16:19.000Z | nashua.dmevals.local | windows.security | win.ObjectName | \REGISTRY\MACHINE\SOFTWARE\Microsoft\SystemCertificates\ROOT\Certificates\BE36A4562FB2EE05DBB3D32323ADF445084ED656 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItZ6CoZN | q-dc5b538fdb | ok |

### F43 · benign / high · T1556.005 · No reversible-encryption / PasswordEncryption setting changes observed

Evidence status: **verified**

Checks for reversible encryption returned no hits: no Event 4739 (C234), no PowerShell 4103 payload referencing Reversible/PasswordEncryption (C236), no Sysmon Event 1 command line with Reversible/PasswordEncryption/Set-ADUser (C237), and no windows.other message referencing Reversible/PasswordEncryption (C238). No account was configured to store passwords with reversible encryption.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:16.000Z | scranton.dmevals.local | windows.security | win.ObjectName | \REGISTRY\MACHINE\SYSTEM\ControlSet001\Control\WMI\Autologger\EventLog-Application\{3000b92b-ca8b-4269-90ea-c4185ee09e92} | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItVt5I2Y | q-dc5b538fdb | ok |

### F44 · benign / high · T1556.006 · No MFA / authentication-policy modification observed

Evidence status: **verified**

Checks for MFA tampering returned no hits: no Event 4739 (C241), no Sysmon Event 1 command line with Set-ADUser/Set-ADAuthenticationPolicy (C243), and no windows.other message referencing authentication policy / MFA / strong authentication (C244). No multi-factor authentication configuration was modified.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:16.000Z | scranton.dmevals.local | windows.security | win.ObjectValueName | Enabled | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItVv6C9m | q-dc5b538fdb | ok |

### F45 · benign / high · T1556.007 · No hybrid-identity / federation modification observed

Evidence status: **verified**

Checks for hybrid identity tampering returned no hits: no Event 5136 AD object modification (C245/C246), no PowerShell script block referencing Connect-MsolService/Connect-AzureAD (C249), and no windows.other message referencing ADFS/federation/Azure AD (C250). No hybrid identity or federation trust was modified.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:16:19.000Z | nashua.dmevals.local | windows.security | win.OperationType | %%1905 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItZ6CoZN | q-dc5b538fdb | ok |

### F46 · benign / high · T1556.008 · No network provider / credential provider DLL registration observed

Evidence status: **verified**

Checks for network provider DLL tampering returned no hits: no Event 4657 registry change to NetworkProvider/Credential keys (C252), no Sysmon Event 11 file creation under NetworkProvider/System32 (C254), no PowerShell script block referencing NetworkProvider/credential providers (C257), and no windows.other message referencing network provider/credential provider (C258). No network provider DLL was registered.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:16.000Z | scranton.dmevals.local | windows.security | win.ObjectName | \REGISTRY\MACHINE\SYSTEM\ControlSet001\Control\WMI\Autologger\EventLog-Application\{3000b92b-ca8b-4269-90ea-c4185ee09e92} | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItVw6X-9 | q-dc5b538fdb | ok |

### F47 · benign / medium · T1557 · No adversary-in-the-middle activity observed; SMB/Kerberos traffic is normal domain traffic

Evidence status: **verified**

Across windows.sysmon, windows.security and zeek there is no evidence of AiTM positioning. All SMB (445) connections originate from the System process on domain members toward the DC 10.0.0.4 or local IPv6 (fe80::e40c:95b6:b0a7:6429), and all 4624 logons are Kerberos machine-account (LogonType 3) authentications between domain members and the DC. No relay, no anomalous authentication source, no interception tooling.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:01:43.033Z | scranton.dmevals.local | windows.sysmon | process.executable | System | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTqgghU | q-09a8dd31f0 | ok |
| 2 | 2020-05-02 03:01:43.033Z | scranton.dmevals.local | windows.sysmon | destination.port | 445 | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTqgghU | q-09a8dd31f0 | ok |
| 3 | 2020-05-02 03:26:48.000Z | newyork.dmevals.local | windows.security | win.AuthenticationPackageName | Kerberos | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItVcvuSE | q-7b568af01d | ok |
| 4 | 2020-05-02 03:26:48.000Z | newyork.dmevals.local | windows.security | win.LogonType | 3 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItVcvuSE | q-7b568af01d | ok |

### F48 · benign / medium · T1557.001 · Name resolution and SMB traffic show no poisoning or relay; DNS failures are routine

Evidence status: **verified**

Sysmon EventCode 22 DNS queries are routine: wpad.dmevals.local returns NXDOMAIN, LDAP SRV lookups (_ldap._tcp...) return normal results, and Microsoft telemetry resolves normally. The only non-zero QueryStatus values are routine lookup failures (9003/9501/9852/123) for wpad and SRV records. No LLMNR/NBT-NS poisoning tooling (Inveigh/Responder) was found in PowerShell script blocks or windows.other messages. The suspicious base64 hidden PowerShell on scranton.dmevals.local (user pbeesly) is a reflective loader (GetProcAddress/UnsafeNativeMethods), not name-resolution poisoning.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:31.333Z | scranton.dmevals.local | windows.sysmon | win.QueryName | wpad | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItOmQp3C | q-fb36cc0245 | ok |
| 2 | 2020-05-02 03:19:31.333Z | scranton.dmevals.local | windows.sysmon | win.QueryStatus | 9003 | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItOmQp3C | q-fb36cc0245 | ok |
| 3 | 2020-05-02 03:20:04.561Z | scranton.dmevals.local | windows.sysmon | win.QueryResults | type:  33 ;10.0.0.4; | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItO2ikE2 | q-fc6427c04f | ok |
| 4 | 2020-05-02 03:21:29.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function jzI {  	Param ($yKR, $cq)		  	$vvA = ([AppDomain]::CurrentDomain.GetAssemblies() \| Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZRkUVV | q-41d63715cd | ok |

### F49 · benign / medium · T1557.002 · No ARP cache poisoning activity observed

Evidence status: **verified**

No ARP-related tooling, ARP manipulation commands, or anomalous layer-2 events were observed in any dataset. Network connections are all standard unicast/broadcast traffic from the System process; no evidence of ARP cache poisoning or gratuitous ARP activity.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:22:30.169Z | utica.dmevals.local | windows.sysmon | process.executable | System | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItObGa1g | q-6da5ca386a | ok |
| 2 | 2020-05-02 03:22:30.169Z | utica.dmevals.local | windows.sysmon | destination.port | 137 | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItObGa1g | q-6da5ca386a | ok |

### F50 · benign / medium · T1557.003 · No DHCP spoofing activity; no DHCP traffic present

Evidence status: **verified**

No DHCP (UDP 67/68) traffic exists in any dataset. The only UDP name-service traffic is normal NetBIOS name service (137/138) from the System process to broadcast (10.0.1.255/10.0.0.255) and local addresses, which is standard Windows behavior. No rogue DHCP server or DHCP spoofing indicators were observed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:20.177Z | scranton.dmevals.local | windows.sysmon | destination.port | 138 | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItPL74K2 | q-6da5ca386a | ok |
| 2 | 2020-05-02 03:19:20.177Z | scranton.dmevals.local | windows.sysmon | destination.ip | 10.0.1.255 | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItPL74K2 | q-6da5ca386a | ok |
| 3 | 2020-05-02 03:19:20.177Z | scranton.dmevals.local | windows.sysmon | process.executable | System | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItPL74K2 | q-6da5ca386a | ok |

### F54 · benign / medium · T1558.001 · No Golden Ticket indicators observed

Evidence status: **verified**

No evidence of forged TGTs: no RC4 (0x17) ticket encryption, no krbtgt/mimikatz/sekurlsa/golden commands in PowerShell or Sysmon process creation, and no anomalous non-existent accounts in 4769 service requests. The 4672 special-privilege logons are all for the machine account NEWYORK$ and for pbeesly on nashua/scranton, consistent with normal service and administrative logons. Although LSASS was accessed with full-access masks (see T1558 finding), no forged-ticket artifacts were observed in this window.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:55:54.000Z | newyork.dmevals.local | windows.security | user.name | NEWYORK$ | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItaKXhpM | q-24e5838a46 | ok |
| 2 | 2020-05-02 03:20:46.000Z | scranton.dmevals.local | windows.security | user.name | pbeesly | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItVn01Ns | q-2f040c1325 | ok |

### F55 · benign / medium · T1558.002 · No Silver Ticket indicators observed

Evidence status: **verified**

No evidence of forged service tickets: all 4769 service ticket requests use AES256 (0x12) with no RC4 downgrade, and no silver/mimikatz/ticket commands were observed in PowerShell or Sysmon process creation. Service ticket requests target legitimate machine accounts (NASHUA$, NEWYORK$, SCRANTON$, WEC$) and krbtgt.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:14.000Z | newyork.dmevals.local | windows.security | win.ServiceName | WEC$ | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItV3-aUM | q-91662072e0 | ok |
| 2 | 2020-05-02 03:19:14.000Z | newyork.dmevals.local | windows.security | win.ServiceName | SCRANTON$ | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItV3-aUJ | q-91662072e0 | ok |

### F52 · benign / high · T1558.003 · No Kerberoasting: all service ticket requests use AES256, not RC4

Evidence status: **verified**

All 28 Kerberos service ticket requests (event 4769) on newyork.dmevals.local use TicketEncryptionType 0x12 (AES256-CTS-HMAC-SHA1-96); none use 0x17 (RC4), the encryption downgrade that characterizes Kerberoasting. The requested services are machine accounts (NASHUA$, NEWYORK$, SCRANTON$, WEC$) and krbtgt, consistent with normal SMB/DC authentication by pbeesly and the SCRANTON$ computer account. No RC4 ticket requests, no SPN enumeration, and no kerberoast/Rubeus/Invoke-Kerberoast commands were observed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:18.000Z | newyork.dmevals.local | windows.security | win.TicketEncryptionType | 0x12 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItZ7Ef_y | q-91662072e0 | ok |
| 2 | 2020-05-02 03:11:18.000Z | newyork.dmevals.local | windows.security | win.ServiceName | NASHUA$ | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItZ7Ef_y | q-91662072e0 | ok |
| 3 | 2020-05-02 03:19:13.000Z | newyork.dmevals.local | windows.security | win.ServiceName | NEWYORK$ | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItV3-aVk | q-91662072e0 | ok |

### F53 · benign / high · T1558.004 · No AS-REP Roasting: all AS-REQ events require pre-authentication

Evidence status: **verified**

All 14 Kerberos authentication service requests (event 4768) on newyork.dmevals.local have PreAuthType 2 (pre-authentication required). No account requested a TGT with PreAuthType 0, which is the prerequisite for AS-REP Roasting. No asreproast/Rubeus/kerberos commands were observed in PowerShell or Sysmon process creation.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:20:45.000Z | newyork.dmevals.local | windows.security | win.PreAuthType | 2 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItVn1FMZ | q-91662072e0 | ok |
| 2 | 2020-05-02 03:19:13.000Z | newyork.dmevals.local | windows.security | win.PreAuthType | 2 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItV3-aXJ | q-91662072e0 | ok |

### F56 · benign / medium · T1606 · No forged web-credential artifacts; observed activity is credential-access/execution chain (PSEXESVC, javamtsup.exe, hostui.exe)

Evidence status: **verified**

Across windows.security, windows.sysmon, windows.powershell and windows.other (2020-05-01T22:55Z..2020-05-02T03:28Z) the only notable activity is a lateral-movement/execution chain by user pbeesly: PSEXESVC service installs on nashua.dmevals.local with explicit-credential logons (4648) for pbeesly, a javamtsup.exe service install on scranton.dmevals.local, and hostui.exe launched via encoded PowerShell. None of the retrieved events contain any artifact of forging web credentials (no SAML/ADFS/token-signing, no cookie forging, no anomalous authentication packages). Logon process names (Kerberos 217, Advapi 76, User32 2, NtLmSsp 1) and authentication packages (Kerberos 217, Negotiate 78, NTLM 1) are all standard Windows values. T1606 is therefore not supported by the evidence.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:15.000Z | scranton.dmevals.local | windows.other | message | A service was installed in the system.    Service Name:  Java(TM) Virtual Machine Support Service  Service File Name:  C:\Windows\System32\javamtsup.exe  Servic… | .ds-logs-windows.other-default-2026.10.17-000001 / AaFHNH1uOFchItbrX8TL | q-cf001e04b8 | ok |
| 2 | 2020-05-02 03:11:40.000Z | nashua.dmevals.local | windows.security | win.ProcessName | C:\Windows\PSEXESVC.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItZ7Ev8p | q-f6e07f6e2d | ok |
| 3 | 2020-05-02 03:21:27.276Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Windows\System32\hostui.exe"  | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItKT-VVW | q-310b9121ff | ok |

### F57 · benign / medium · T1606.001 · Cookie file creation is a benign Windows service artifact; no cookie forging/replay observed

Evidence status: **verified**

The only cookie-related hit is a Sysmon file-create (event 11) of C:\Windows\ServiceProfiles\LocalService\AppData\Local\Packages\warp_jit_...\AC\INetCookies by C:\windows\System32\svchost.exe (SYSTEM) on scranton.dmevals.local at 2020-05-02T03:21:05Z. This is a normal Windows service-profile INetCookies store write, not theft or forging of web cookies. The single PowerShell 4104 hit matching 'cookie/session' is a benign Sysinternals readme.ps1 script block (Get-AttributesMask) unrelated to cookies. No evidence of cookie forging or session hijack.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:21:05.681Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Windows\ServiceProfiles\LocalService\AppData\Local\Packages\warp_jit_db4a1097-b484-4973-bbf2-a04208ecd4d4\AC\INetCookies | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItOVAUl3 | q-7b714ddaa6 | ok |
| 2 | 2020-05-02 03:21:05.681Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\System32\svchost.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItOVAUl3 | q-7b714ddaa6 | ok |
| 3 | 2020-05-02 03:04:04.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\readme.ps1 | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZRllBR | q-dac60f9a13 | ok |

### F58 · benign / medium · T1606.002 · No SAML/ADFS token-forging artifacts; authentication packages are standard

Evidence status: **verified**

No SAML/ADFS/token-signing activity was found. The PowerShell search for SAML/ADFS/NotOnOrAfter returned zero hits, and the Sysmon file-create search for adfs/token paths returned zero hits. Successful logons (4624) use only standard authentication packages (Kerberos 217, Negotiate 78, NTLM 1) and logon process names (Kerberos, Advapi, User32, NtLmSsp). The 7045/7040 service events are PSEXESVC, javamtsup.exe and standard Windows service start-type changes, none related to token-signing infrastructure. T1606.002 is not supported.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:55:54.000Z | newyork.dmevals.local | windows.security | event.code | 4624 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItaKXhpQ | q-01a08336ca | ok |
| 2 | 2020-05-02 03:19:22.000Z | scranton.dmevals.local | windows.other | message | The start type of the Microsoft NDIS Capture service was changed from demand start to system start. | .ds-logs-windows.other-default-2026.10.17-000001 / AaFHNH1uOFchItbrX8Rc | q-1c6a745c0b | ok |

### F59 · benign / high · T1621 · No MFA request generation activity observed; only routine Windows telemetry and domain authentication

Evidence status: **verified**

Across windows.sysmon, windows.security, windows.powershell, windows.other and zeek there is no evidence of MFA/2FA/authenticator/OTP request generation. The C343 hits are ordinary Windows telemetry processes (backgroundTaskHost.exe, BackgroundTransferHost.exe, powershell.exe) making outbound 443/80 connections to Microsoft/cloud IPs (52.167.250.154, 23.56.173.48, 72.21.91.29, 23.36.34.97) from scranton.dmevals.local (10.0.1.4) and nashua.dmevals.local (10.0.1.6) under user pbeesly. The C354/C355 Kerberos hits are normal domain authentication (pbeesly/DMEVALS.LOCAL AS/TGS requests to 10.0.0.4, one KDC_ERR_PREAUTH_REQUIRED which is standard pre-auth). No 4625 failed-logon events exist (C339/C340/C341 zero hits) and no PowerShell script block references MFA/2FA/Authenticator (C342 zero hits).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:59:16.747Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\Windows\System32\backgroundTaskHost.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItT-3yn1 | q-4e7073c183 | ok |
| 2 | 2020-05-02 02:59:22.535Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\Windows\System32\BackgroundTransferHost.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItT70Tl_ | q-4e7073c183 | ok |
| 3 | 2020-05-02 02:59:16.747Z | scranton.dmevals.local | windows.sysmon | destination.ip | 52.167.250.154 | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItT-3yn1 | q-4e7073c183 | ok |
| 4 | 2020-04-30 00:24:19.110Z | simplerockbuild.simplerock.lan | zeek | zeek.error_msg | KDC_ERR_PREAUTH_REQUIRED | .ds-logs-zeek-default-2026.10.17-000001 / AaFHNX1uOFchItbgrYi0 | q-e16dc66657 | ok |
| 5 | 2020-04-30 00:24:19.119Z | simplerockbuild.simplerock.lan | zeek | zeek.success | True | .ds-logs-zeek-default-2026.10.17-000001 / AaFHNX1uOFchItbgrIjh | q-e16dc66657 | ok |

### F62 · benign / high · T1649 · Registry 4657 certificate-store and autologger modifications are benign system activity

Evidence status: **verified**

The 36 event.code 4657 hits in windows.security are routine. On nashua.dmevals.local the modified key is \REGISTRY\MACHINE\SOFTWARE\Microsoft\SystemCertificates\ROOT\Certificates\BE36A4562FB2EE05DBB3D32323ADF445084ED656 (value 'Blob') performed by C:\Windows\Sysmon.exe under SYSTEM (NASHUA$), i.e. Sysmon's own root-certificate store maintenance. The remaining 4657 hits on scranton.dmevals.local are wevtutil.exe modifying WMI Autologger\EventLog-Application configuration values (Enabled/MatchAnyKeyword) under SYSTEM. Neither reflects adversary tampering with certificate stores or AD CS.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:16:19.000Z | nashua.dmevals.local | windows.security | win.ObjectName | \REGISTRY\MACHINE\SOFTWARE\Microsoft\SystemCertificates\ROOT\Certificates\BE36A4562FB2EE05DBB3D32323ADF445084ED656 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItZ6CoZN | q-2826fa89d9 | ok |
| 2 | 2020-05-02 03:16:19.000Z | nashua.dmevals.local | windows.security | process.executable | C:\Windows\Sysmon.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItZ6CoZN | q-2826fa89d9 | ok |
| 3 | 2020-05-02 03:19:16.000Z | scranton.dmevals.local | windows.security | process.executable | C:\Windows\System32\wevtutil.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItVt5I2Y | q-2826fa89d9 | ok |

### F63 · benign / medium · T1649 · Kerberos TGT requests use password pre-auth only, no certificate-based (PKINIT) authentication observed

Evidence status: **verified**

All 14 event.code 4768 TGT requests in windows.security (host newyork.dmevals.local, accounts pbeesly and SCRANTON$) carry win.PreAuthType = 2, i.e. standard password-based pre-authentication. No PKINIT/certificate-based pre-auth (which would indicate use of a stolen or forged authentication certificate) was observed, so there is no evidence of forged-certificate authentication in this window.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:18.000Z | newyork.dmevals.local | windows.security | win.PreAuthType | 2 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItZ7Ef_w | q-17b3f4ce52 | ok |
| 2 | 2020-05-02 03:11:18.000Z | newyork.dmevals.local | windows.security | event.code | 4768 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItZ7Ef_w | q-17b3f4ce52 | ok |

### F36 · not_observed / high · T1555.003 · No browser credential-store access observed

Evidence status: **verified**

Checks C202-C207 for browser credential artifacts (Login Data, Cookies, Web Data, Local State, logins.json, key3/key4.db) returned zero hits across sysmon file-create, sysmon process-create, security object-access, powershell script blocks and windows.other. A targeted ES\|QL search for process access to chrome/firefox/iexplore/msedge and command lines referencing browser credential files also returned zero rows. No evidence of web-browser credential theft on any host.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:21:05.681Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Windows\ServiceProfiles\LocalService\AppData\Local\Packages\warp_jit_db4a1097-b484-4973-bbf2-a04208ecd4d4\AC\INetCookies | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItOVAUl3 | q-0ef5946f95 | ok |

### F38 · not_observed / high · T1555.005 · No password-manager access observed

Evidence status: **verified**

Checks C213-C217 for KeePass/1Password/LastPass/Bitwarden process access, .kdbx/.opvault/.agilekeychain file writes, and password-related script blocks/other-channel messages returned zero hits. A targeted ES\|QL search for process access to keepass/1password/lastpass/bitwarden and command lines referencing them returned zero rows. No password-manager credential theft on any host.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:21:05.681Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Windows\ServiceProfiles\LocalService\AppData\Local\Packages\warp_jit_db4a1097-b484-4973-bbf2-a04208ecd4d4\AC\INetCookies | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItOVAUl3 | q-0ef5946f95 | ok |

## Pivot candidates

Processes the pivot reviewer had to assess (started by a script host or from outside the Windows directory, rare in the 15-minute windows around verified activity).

| Host | Executable | Starts | Parents | Assessment | Reason |
|---|---|---|---|---|---|
| nashua.dmevals.local | C:\Program Files\WindowsApps\Microsoft.SkypeApp_14.35.152.0_x64__kzf8qxf38zg5c\S… | 1 | C:\Program Files\WindowsApps\Microsoft.SkypeApp_14.35.152.0_x64__kzf8qxf38zg5c\S… | benign | Legitimate Microsoft Store Skype app; self-parented restart, no credential-access behavior. |
| nashua.dmevals.local | C:\Windows\Temp\python.exe | 5 | C:\Windows\PSEXESVC.exe, C:\Windows\Temp\python.exe | malicious | PyInstaller binary spawned by PSEXESVC.exe as pbeesly; drove credential-file harvesting PowerShell and dropped Rar.exe/sdelete64.exe. |
| nashua.dmevals.local | C:\Windows\Temp\Rar.exe | 1 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | malicious | Attacker-dropped archiver run by PowerShell to create password-protected working.zip of harvested credential files. |
| nashua.dmevals.local | C:\Windows\Temp\sdelete64.exe | 3 | C:\Windows\System32\cmd.exe | malicious | Attacker-dropped wiper used to securely delete Rar.exe and working.zip artifacts (anti-forensics). |
| nashua.dmevals.local | C:\WindowsAzure\Packages\CollectGuestLogs.exe | 1 | C:\WindowsAzure\Packages\WaAppAgent.exe | benign | Azure guest agent diagnostic collector, standard parent WaAppAgent.exe. |
| scranton.dmevals.local | C:\Packages\Plugins\Microsoft.Azure.NetworkWatcher.NetworkWatcherAgentWindows\1.… | 4 | C:\Windows\System32\cmd.exe, C:\Windows\System32\services.exe | benign | Azure Network Watcher agent, standard Azure plugin path and parent. |
| scranton.dmevals.local | C:\Packages\Plugins\Microsoft.Azure.Security.IaaSAntimalware\1.5.5.9\Antimalware… | 1 | C:\WindowsAzure\Packages\GuestAgent\WindowsAzureGuestAgent.exe | benign | Azure IaaS Antimalware configuration component, standard plugin path. |
| scranton.dmevals.local | C:\Packages\Plugins\Microsoft.Compute.CustomScriptExtension\1.10.5\bin\CustomScr… | 1 | C:\Windows\System32\cmd.exe | benign | Azure Custom Script Extension handler, standard Azure VM extension. |
| scranton.dmevals.local | C:\Packages\Plugins\Microsoft.Compute.JsonADDomainExtension\1.3.2\bin\JsonADDoma… | 1 | C:\Windows\System32\cmd.exe | benign | Azure AD domain-join extension, standard Azure VM extension. |
| scranton.dmevals.local | C:\Program Files (x86)\Google\Update\1.3.35.452\GoogleCrashHandler.exe | 2 | C:\Program Files (x86)\Google\Update\GoogleUpdate.exe | benign | Google Update crash handler, legitimate updater component. |
| scranton.dmevals.local | C:\Program Files (x86)\Google\Update\1.3.35.452\GoogleCrashHandler64.exe | 2 | C:\Program Files (x86)\Google\Update\GoogleUpdate.exe | benign | Google Update crash handler (64-bit), legitimate updater component. |
| scranton.dmevals.local | C:\Program Files (x86)\Google\Update\GoogleUpdate.exe | 3 | C:\Program Files (x86)\Google\Update\GoogleUpdate.exe, C:\Windows\System32\servi… | benign | Google Update service, legitimate updater. |
| scranton.dmevals.local | C:\Program Files\SysinternalsSuite\accessChk.exe | 1 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | suspicious | Sysinternals accesschk run by PowerShell as pbeesly to enumerate permissions - reconnaissance consistent with the intrusion chain (already an anchor). |
| scranton.dmevals.local | C:\Program Files\SysinternalsSuite\PsExec64.exe | 4 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | malicious | PsExec used by PowerShell as pbeesly for lateral movement with explicit credentials (anchor T1040/T1621). |
| scranton.dmevals.local | C:\Program Files\SysinternalsSuite\sdelete64.exe | 3 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | malicious | Sysinternals sdelete run by PowerShell as pbeesly to wipe artifacts (anti-forensics). |
| scranton.dmevals.local | C:\Program Files\Windows Defender\MsMpEng.exe | 1 | C:\Windows\System32\services.exe | benign | Windows Defender antimalware service, standard parent services.exe. |
| scranton.dmevals.local | C:\Program Files\Windows Defender\NisSrv.exe | 2 | C:\Windows\System32\services.exe | benign | Windows Defender network inspection service, standard parent services.exe. |
| scranton.dmevals.local | C:\ProgramData\victim\â€®cod.3aka3.scr | 1 | C:\Windows\explorer.exe | malicious | Malicious screensaver launched by explorer.exe that drives the PowerShell credential-access chain (anchor T1056). |
| scranton.dmevals.local | C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe | 2 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | suspicious | C# compiler invoked by PowerShell with temp .cmdline response files - in-memory compilation of attacker code (e.g. credential tooling). |
| scranton.dmevals.local | C:\Windows\System32\hostui.exe | 1 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | suspicious | hostui.exe spawned by PowerShell as pbeesly - unusual parent for this binary, consistent with attacker execution chain. |
| scranton.dmevals.local | C:\Windows\System32\sdclt.exe | 3 | C:\Windows\System32\cmd.exe | suspicious | sdclt.exe (known UAC-bypass/COM-hijack binary) launched by cmd.exe as pbeesly, spawning control.exe - suspicious execution chain. |
| scranton.dmevals.local | C:\WindowsAzure\Packages\GuestAgent\BfeToolWin8.exe | 1 | C:\WindowsAzure\Packages\GuestAgent\WindowsAzureGuestAgent.exe | benign | Azure guest agent firewall tool, standard parent WindowsAzureGuestAgent.exe. |
| scranton.dmevals.local | C:\WindowsAzure\Packages\GuestAgent\FindVolume\FindVolume.exe | 1 | C:\WindowsAzure\Packages\GuestAgent\WindowsAzureGuestAgent.exe | benign | Azure guest agent volume discovery utility, standard parent. |
| scranton.dmevals.local | C:\WindowsAzure\Packages\GuestAgent\WindowsAzureGuestAgent.exe | 1 | C:\Windows\System32\services.exe | benign | Azure guest agent service, standard parent services.exe. |
| scranton.dmevals.local | C:\WindowsAzure\Packages\Telemetry\WindowsAzureTelemetryService.exe | 1 | C:\Windows\System32\services.exe | benign | Azure telemetry service, standard parent services.exe. |
| scranton.dmevals.local | C:\WindowsAzure\Packages\WaAppAgent.exe | 1 | C:\Windows\System32\services.exe | benign | Azure Windows Azure Agent, standard parent services.exe. |
| scranton.dmevals.local | C:\WindowsAzure\SecAgent\WaSecAgentProv.exe | 2 | C:\WindowsAzure\Packages\WaAppAgent.exe | benign | Azure security agent provider, standard parent WaAppAgent.exe. |
| scranton.dmevals.local | C:\WindowsAzure\WindowsAzureNetAgent_1.0.0.143\WindowsAzureNetAgent\Plugins\VFPl… | 1 | C:\WindowsAzure\WindowsAzureNetAgent_1.0.0.143\WindowsAzureNetAgent\WindowsAzure… | benign | Azure network agent VF plugin, standard Azure component. |
| scranton.dmevals.local | C:\WindowsAzure\WindowsAzureNetAgent_1.0.0.143\WindowsAzureNetAgent\WindowsAzure… | 1 | C:\Windows\System32\services.exe | benign | Azure network agent service, standard parent services.exe. |

## Technique conclusions

One line per technique in scope: status from the triage of its family; `not_observed` = checked, nothing found; `not_observable` = no dataset records it.

| Technique | Status | Reason |
|---|---|---|
| T1003 OS Credential Dumping | malicious | Credential-access tooling staged/executed from C:\Windows\Temp on nashua by pbeesly. |
| T1003.001 LSASS Memory | malicious | PowerShell.exe (pbeesly) on scranton opened lsass.exe with 0x1FFFFF and 0x1F3FFF at 03:05:16 (Security 4656 confirms 'Read from process memory'); wsmprovhost.exe (pbeesly) on nashua opened lsass with 0x1F3FFF at 03:09:29… |
| T1003.002 Security Account Manager | not_observed | No SAM/SECURITY hive copies or reg save; only Prefetch files and normal lsass registry writes were seen. |
| T1003.003 NTDS | not_observed | No ntds.dit access, no diskshadow/vssadmin/esentutl activity. |
| T1003.004 LSA Secrets | not_observed | No lsadump/secrets commands or SECURITY\Policy\Secrets access; only benign DLL loads and Lsa registry reads. |
| T1003.005 Cached Domain Credentials | not_observed | No cache/dcc2/mscache dumping; HKLM\SECURITY\Cache\NL$1 writes are by lsass.exe itself. |
| T1003.006 DCSync | not_observed | No 4662 DS-Replication GUID events, no 4929, no DCSync/drsuapi script blocks. |
| T1040 Network Sniffing | benign | The only capture-related activity was netsh.exe 'trace start capture=yes'/'trace stop' on scranton.dmevals.local, spawned by the Microsoft Azure Network Watcher agent (NetworkWatcherAgent.exe) under the machine account S… |
| T1056 Input Capture | malicious | Malicious screensaver cod.3aka3.scr in C:\ProgramData\victim\ launched by explorer.exe spawned cmd/powershell and was the only non-system process accessing the LSA registry key on scranton.dmevals.local. |
| T1056.001 Keylogging | malicious | PyInstaller python.exe (PsExec-spawned) drove credential discovery and anti-forensic wiping on nashua. |
| T1056.002 GUI Input Capture | not_observed | No fake credential prompts or GUI input capture; the single consent.exe event is normal UAC elevation. |
| T1056.003 Web Portal Capture | not_observed | No IIS/w3wp/web.config/wwwroot or web-portal capture activity; zero-hit checks and non-overlapping zeek window. |
| T1056.004 Credential API Hooking | malicious | PowerShell.exe opened lsass.exe with GrantedAccess 0x1fffff (PROCESS_ALL_ACCESS) and an UNKNOWN call-trace frame, consistent with credential API hooking / in-memory credential theft. |
| T1110 Brute Force | not_observed | No 4625/4771 failures and only one 4776 credential validation, which succeeded (Error Code 0x0) on newyork for pbeesly; no repeated authentication attempts against any host. |
| T1110.001 Password Guessing | not_observed | No failed logons, no net use/runas guessing commands, no LogonUser/New-Object Net scripts; the only password-bearing command line is a single successful PsExec launch with a valid credential. |
| T1110.002 Password Cracking | suspicious | PowerShell.exe on scranton opened lsass.exe with GrantedAccess 0x1f3fff (credential dumping from memory), but no SAM/SECURITY/SYSTEM hive reads by non-lsass processes, no reg save/ntds/hashcat/john scripts and no .dit/.h… |
| T1110.003 Password Spraying | suspicious | Four 4648 explicit-credential logons and four PSEXESVC launches against NASHUA within four minutes, but all use the same account pbeesly and all succeed — repeated use of one credential rather than spraying across many a… |
| T1110.004 Credential Stuffing | not_observed | No username/password pair lists or login/auth tooling; only Microsoft module resource strings and a hard-coded password in Get-PrivateKeys/Invoke-Exfil, with no failed authentication events. |
| T1111 Multi-Factor Authentication Interception | not_observed | No events show interception of MFA material (smartcard, token, OTP, credential provider). Credential/Vault/Smartcard registry hits are Windows' own CredentialEnrollmentManagerUserSvc service registration and a Credential… |
| T1187 Forced Authentication | not_observed | No forced-authentication artifacts found. All 5145 share accesses are machine-account SYSVOL/GPO reads; all 445 connections are System-process domain traffic to the DC; the only .lnk files are benign Explorer Recent item… |
| T1212 Exploitation for Credential Access | malicious | PowerShell.exe (PID 2976, user pbeesly) on scranton.dmevals.local opened lsass.exe with GrantedAccess 0x1f3fff and 0x1fffff (PROCESS_ALL_ACCESS) at 2020-05-02 03:05:16 UTC, the access mask needed to read LSASS memory for… |
| T1539 Steal Web Session Cookie | not_observed | no status submitted |
| T1552 Unsecured Credentials | malicious | Unsecured credential files harvested from the user profile on nashua. |
| T1552.001 Credentials In Files | malicious | PowerShell on nashua recursively searched the user profile for credential-named files (*pass*, *login*, *admin*, *vpn, *.pst, *.ost) and archived them. |
| T1552.002 Credentials in Registry | not_observed | Registry Password/Credential value sets were all routine OS activity; no SAM/SECURITY registry collection. |
| T1552.003 Shell History | not_observed | No ConsoleHost_history/.bash_history/Get-History references in any dataset. |
| T1552.004 Private Keys | malicious | PowerShell Get-PrivateKeys exported LocalMachine certificates to a .pfx in Downloads, confirmed by the created .pfx file. |
| T1552.006 Group Policy Preferences | not_observed | No cpassword/Groups.xml/gpprefdecrypt references; SYSVOL reads were routine GPO processing. |
| T1555 Credentials from Password Stores | benign | LSASS handle accesses are all from legitimate system processes (svchost 0x1000, Azure antimalware/telemetry 0x1400, wininit/csrss/services at boot) with call traces in ntdll/KERNELBASE/lsm/sysmain/CorperfmonExt; no dumpi… |
| T1555.003 Credentials from Web Browsers | not_observed | No browser credential-store artifacts (Login Data, Cookies, Web Data, Local State, logins.json, key3/key4.db) in file-create, process-create, object-access, script-block or other-channel events; no process access to chro… |
| T1555.004 Windows Credential Manager | benign | All Credential/Vault hits are benign Windows components: CredentialEnrollmentManagerUserSvc service keys and MuiCache entries created by services.exe, CredentialGuard registry value written by lsass, a Credential Guard c… |
| T1555.005 Password Managers | not_observed | No KeePass/1Password/LastPass/Bitwarden process access, no .kdbx/.opvault/.agilekeychain file writes, and no password-manager references in script blocks or other-channel messages. |
| T1556 Modify Authentication Process | not_observed | 326 LSASS accesses were dominated by SYSTEM-context system binaries (svchost 289, wininit, csrss, wsmprovhost, AV/telemetry) with GrantedAccess 0x1000; the single high-privilege PowerShell.exe 0x1FFFFF read on scranton i… |
| T1556.001 Domain Controller Authentication | not_observed | 4624 type-3 logons are machine-account (NEWYORK$) network authentications and 4648 explicit-credential logons are pbeesly via PSEXESVC (PsExec lateral movement) plus routine winlogon/taskhostw logons; no DC authenticatio… |
| T1556.002 Password Filter DLL | not_observed | No password filter DLL file creation, no Notification Packages registry change, no PowerShell referencing password filters. |
| T1556.005 Reversible Encryption | not_observed | No 4739, no Reversible/PasswordEncryption command lines or script blocks, no Set-ADUser activity. |
| T1556.006 Multi-Factor Authentication | not_observed | No 4739, no Set-ADUser/authentication-policy command lines, no MFA/authentication-policy messages. |
| T1556.007 Hybrid Identity | not_observed | No 5136 AD object changes, no Connect-MsolService/Connect-AzureAD script blocks, no ADFS/federation/Azure AD messages. |
| T1556.008 Network Provider DLL | not_observed | No NetworkProvider/Credential registry changes, no network provider DLL file creation, no related script blocks or messages. |
| T1557 Adversary-in-the-Middle | not_observed | No AiTM positioning: SMB/445 traffic is all System-process to the DC, and all 4624 logons are Kerberos machine-account (LogonType 3) authentications between domain members and the DC. |
| T1557.001 Name Resolution Poisoning and SMB Relay | not_observed | DNS queries are routine (wpad NXDOMAIN, LDAP SRV, Microsoft telemetry); no LLMNR/NBT-NS poisoning tooling (Inveigh/Responder) found. The suspicious scranton PowerShell is a reflective loader, not name-resolution poisonin… |
| T1557.002 ARP Cache Poisoning | not_observed | No ARP manipulation tooling or anomalous layer-2 events in any dataset. |
| T1557.003 DHCP Spoofing | not_observed | No DHCP (UDP 67/68) traffic at all; only normal NetBIOS name service (137/138) from the System process to broadcast/local addresses. |
| T1558 Steal or Forge Kerberos Tickets | malicious | PowerShell.exe on scranton.dmevals.local opened lsass.exe with GrantedAccess 0x1FFFFF and 0x1F3FFF during a pbeesly hands-on-keyboard session that also ran Get-PrivateKeys/Get-Clipboard/Get-Keystrokes — credential/ticket… |
| T1558.001 Golden Ticket | not_observed | No forged-TGT artifacts: no RC4 (0x17) tickets, no krbtgt/mimikatz/sekurlsa commands, no anomalous accounts in 4769 requests. |
| T1558.002 Silver Ticket | not_observed | No forged service-ticket artifacts: all 4769 requests use AES256 (0x12), no RC4 downgrade, no silver/mimikatz/ticket commands. |
| T1558.003 Kerberoasting | not_observed | All 28 service ticket requests (4769) use TicketEncryptionType 0x12 (AES256); none use 0x17 (RC4), and no kerberoast/Rubeus/SPN-enumeration activity was seen. |
| T1558.004 AS-REP Roasting | not_observed | All 14 AS-REQ events (4768) have PreAuthType 2 (pre-auth required); no PreAuthType 0 requests and no asreproast/Rubeus commands. |
| T1606 Forge Web Credentials | not_observed | No forged web-credential artifacts in any retrieved event. Observed activity (PSEXESVC explicit-credential logons for pbeesly, javamtsup.exe service install, hostui.exe via encoded PowerShell) is credential-access/execut… |
| T1606.001 Web Cookies | not_observed | Only cookie-related event is a benign svchost.exe (SYSTEM) write of the LocalService INetCookies store on scranton.dmevals.local; the single PowerShell 'cookie/session' hit is a benign Sysinternals readme.ps1 script bloc… |
| T1606.002 SAML Tokens | not_observed | Zero hits for SAML/ADFS/NotOnOrAfter in PowerShell and for adfs/token file paths in Sysmon. Authentication packages on 4624 logons are only Kerberos/Negotiate/NTLM; no token-signing infrastructure or forged SAML token ac… |
| T1621 Multi-Factor Authentication Request Generatio… | not_observed | No MFA/2FA/authenticator/OTP request-generation activity in any dataset. C343 sysmon hits are routine Windows telemetry processes (backgroundTaskHost.exe, BackgroundTransferHost.exe, powershell.exe) connecting to Microso… |
| T1649 Steal or Forge Authentication Certificates | malicious | On scranton.dmevals.local, obfuscated hidden PowerShell (PID 2976, payload decoded from monkey.png via IEX) spawned PID 3876 which ran Get-PrivateKeys, exporting every cert:\LocalMachine certificate with a private key to… |

## Coverage

Cells: number of hits of the planned checks, `n/a` (reason in report.json), or GAP.

| Technique | windows.other | windows.powershell | windows.security | windows.sysmon | zeek |
|---|---|---|---|---|---|
| T1003 OS Credential Dumping | 0 hits | 0 hits | 5341 hits | 1070 hits | 62 hits |
| T1003.001 LSASS Memory | 0 hits | 0 hits | 13 hits | 655 hits | n/a |
| T1003.002 Security Account Manager | 0 hits | 0 hits | 0 hits | 10 hits | n/a |
| T1003.003 NTDS | 0 hits | 0 hits | 0 hits | 0 hits | n/a |
| T1003.004 LSA Secrets | 0 hits | 0 hits | 0 hits | 384 hits | n/a |
| T1003.005 Cached Domain Credentials | 0 hits | 0 hits | 0 hits | 330 hits | n/a |
| T1003.006 DCSync | 5 hits | 0 hits | 7 hits | 326 hits | 132 hits |
| T1040 Network Sniffing | 5 hits | 0 hits | 462 hits | 0 hits | 613 hits |
| T1056 Input Capture | 5 hits | 3 hits | 16230 hits | 39609 hits | 0 hits |
| T1056.001 Keylogging | 5 hits | 0 hits | 10893 hits | 17893 hits | 0 hits |
| T1056.002 GUI Input Capture | 5 hits | 5085 hits | 215 hits | 450 hits | 0 hits |
| T1056.003 Web Portal Capture | 5 hits | 4 hits | 0 hits | 1649 hits | 0 hits |
| T1056.004 Credential API Hooking | 3 hits | 3 hits | 19 hits | 60194 hits | n/a |
| T1110 Brute Force | 0 hits | 4 hits | 1 hits | 1 hits | n/a |
| T1110.001 Password Guessing | 0 hits | 0 hits | 0 hits | 0 hits | n/a |
| T1110.002 Password Cracking | 0 hits | 0 hits | 4637 hits | 326 hits | n/a |
| T1110.003 Password Spraying | 0 hits | 4 hits | 15 hits | 0 hits | n/a |
| T1110.004 Credential Stuffing | 0 hits | 2 hits | 0 hits | 0 hits | n/a |
| T1111 Multi-Factor Authentication Interception | 2 hits | 3 hits | 312 hits | 39294 hits | 35 hits |
| T1187 Forced Authentication | 1 hits | 0 hits | 11098 hits | 69 hits | 23 hits |
| T1212 Exploitation for Credential Access | 0 hits | 22 hits | 42 hits | 78566 hits | 123 hits |
| T1539 Steal Web Session Cookie | 0 hits | 13 hits | 460 hits | 39445 hits | 2 hits |
| T1552 Unsecured Credentials | 2 hits | 3 hits | 460 hits | 19 hits | 12 hits |
| T1552.001 Credentials In Files | 0 hits | 1 hits | 312 hits | 518 hits | 0 hits |
| T1552.002 Credentials in Registry | 11 hits | 0 hits | 1473 hits | 7 hits | n/a |
| T1552.003 Shell History | 5 hits | 0 hits | 0 hits | 0 hits | n/a |
| T1552.004 Private Keys | 0 hits | 2 hits | 0 hits | 1 hits | n/a |
| T1552.006 Group Policy Preferences | 0 hits | 0 hits | 38 hits | 18 hits | n/a |
| T1555 Credentials from Password Stores | 0 hits | 0 hits | 6 hits | 796 hits | n/a |
| T1555.003 Credentials from Web Browsers | 0 hits | 0 hits | 0 hits | 0 hits | n/a |
| T1555.004 Windows Credential Manager | 2 hits | 2 hits | 0 hits | 326 hits | n/a |
| T1555.005 Password Managers | 0 hits | 0 hits | 0 hits | 0 hits | n/a |
| T1556 Modify Authentication Process | 0 hits | 5 hits | 0 hits | 401 hits | n/a |
| T1556.001 Domain Controller Authentication | 0 hits | 3 hits | 233 hits | 359 hits | n/a |
| T1556.002 Password Filter DLL | 4 hits | 0 hits | 0 hits | 1 hits | n/a |
| T1556.005 Reversible Encryption | 0 hits | 1 hits | 0 hits | 0 hits | n/a |
| T1556.006 Multi-Factor Authentication | 0 hits | 2 hits | 10977 hits | 0 hits | n/a |
| T1556.007 Hybrid Identity | 0 hits | 0 hits | 297 hits | 7 hits | n/a |
| T1556.008 Network Provider DLL | 0 hits | 0 hits | 36 hits | 919 hits | n/a |
| T1557 Adversary-in-the-Middle | 0 hits | 0 hits | 11120 hits | 1693 hits | 2228 hits |
| T1557.001 Name Resolution Poisoning and SMB Relay | 0 hits | 0 hits | 46 hits | 0 hits | 812 hits |
| T1557.002 ARP Cache Poisoning | 4 hits | 0 hits | 11977 hits | 1430 hits | 613 hits |
| T1557.003 DHCP Spoofing | 0 hits | 0 hits | 0 hits | 308 hits | 0 hits |
| T1558 Steal or Forge Kerberos Tickets | 0 hits | 0 hits | 787 hits | 652 hits | 35 hits |
| T1558.001 Golden Ticket | 9 hits | 0 hits | 476 hits | 326 hits | 35 hits |
| T1558.002 Silver Ticket | 9 hits | 0 hits | 476 hits | 326 hits | 35 hits |
| T1558.003 Kerberoasting | 9 hits | 0 hits | 552 hits | 326 hits | 35 hits |
| T1558.004 AS-REP Roasting | 9 hits | 0 hits | 14 hits | 326 hits | 35 hits |
| T1606 Forge Web Credentials | 5 hits | 1 hits | 312 hits | 39283 hits | n/a |
| T1606.001 Web Cookies | 4 hits | 1 hits | 297 hits | 1 hits | 124 hits |
| T1606.002 SAML Tokens | 9 hits | 0 hits | 594 hits | 0 hits | n/a |
| T1621 Multi-Factor Authentication Request Generatio… | 0 hits | 0 hits | 0 hits | 54 hits | 70 hits |
| T1649 Steal or Forge Authentication Certificates | 0 hits | 1 hits | 64 hits | 1 hits | n/a |

Cells: 265, gaps: 0.

## Queries

Every MCP tool call of this run (1168), in order (source: mcp_audit.jsonl written by the MCP server).

| Query | Phase | Tool | Arguments | Hits / rows | Cited by |
|---|---|---|---|---|---|
| q-7f3feb91cb | scope | list_data_sources | {} | None |  |
| q-9fb068685b | scope | get_registry | {} | None |  |
| q-f4e5703f35 | scope | get_fields | {"dataset": "windows.other", "prefix": ""} | None |  |
| q-2cbf18249f | scope | get_fields | {"dataset": "windows.powershell", "prefix": ""} | None |  |
| q-a6957b4f53 | scope | get_fields | {"dataset": "windows.security", "prefix": ""} | None |  |
| q-e577e3c10a | scope | get_fields | {"dataset": "windows.sysmon", "prefix": ""} | None |  |
| q-a9cfbf1d05 | scope | get_fields | {"dataset": "zeek", "prefix": ""} | None |  |
| q-e6dbc554c1 | check C001 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND process.executable:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 744 |  |
| q-fede7a49fe | check C002 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-83223609af | check C003 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND win.ObjectType:Key", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 5331 |  |
| q-46003c7604 | check C004 | aggregate | {"dataset": "windows.security", "field": "win.ProcessName", "query": "event.code:4656 AND win.ObjectName:*SAM*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 10 |  |
| q-2beca9bf0d | check C005 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*mimikatz* OR win.ScriptBlockText:*sekurlsa* OR win.ScriptBlockText:*DumpCreds*)", "time_from": null, "time_to": null, "fields": ["@timestamp", … | 0 |  |
| q-ee6805970d | check C006 | search | {"dataset": "windows.other", "query": "event.code:7045 AND (win.ImagePath:*lsass* OR win.ImagePath:*dump* OR win.ServiceName:*dump*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "us… | 0 |  |
| q-437c0ee3e8 | check C007 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-bc37024f98 | check C008 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-0a5ad80fa6 | check C009 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*lsass* OR process.command_line:*sekurlsa* OR process.command_line:*MiniDump* OR process.command_line:*procdump*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "hos… | 1 |  |
| q-907a4f4d4c | check C010 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (win.TargetFilename:*.dmp OR win.TargetFilename:*lsass*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process… | 2 |  |
| q-1dd8a4fbcd | check C011 | search | {"dataset": "windows.sysmon", "query": "event.code:13 AND registry.path:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line… | 0 |  |
| q-649d0ef6cb | check C012 | aggregate | {"dataset": "windows.security", "field": "win.ProcessName", "query": "event.code:4673 AND win.ObjectName:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-9a26bb760a | check C013 | aggregate | {"dataset": "windows.security", "field": "win.ProcessName", "query": "event.code:4656 AND win.ObjectName:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 13 |  |
| q-ff12f3a7f7 | check C014 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*MiniDump* OR win.ScriptBlockText:*sekurlsa*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "even… | 0 |  |
| q-c1f2b567a2 | check C015 | search | {"dataset": "windows.other", "query": "event.code:7045 AND win.ImagePath:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_lin… | 0 |  |
| q-addb40acba | check C016 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (win.TargetFilename:*SAM* OR win.TargetFilename:*SYSTEM* OR win.TargetFilename:*SECURITY*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "… | 3 | F03 |
| q-e7418bf96e | check C017 | search | {"dataset": "windows.sysmon", "query": "event.code:13 AND (registry.path:*SAM* OR registry.path:*SECURITY*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.execut… | 7 | F03, F06 |
| q-5f8e26b66f | check C018 | search | {"dataset": "windows.sysmon", "query": "event.code:2 AND (win.TargetFilename:*SAM* OR win.TargetFilename:*SECURITY*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "proce… | 0 |  |
| q-1fee5970a7 | check C019 | aggregate | {"dataset": "windows.security", "field": "win.ProcessName", "query": "event.code:4663 AND (win.ObjectName:*SAM* OR win.ObjectName:*SECURITY*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-003a91b9ba | check C020 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*reg save* OR process.command_line:*save*hklm*SAM* OR process.command_line:*save*hklm*SECURITY*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "ob… | 0 |  |
| q-2a4104c6f8 | check C021 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*reg save* OR win.ScriptBlockText:*SAM* OR win.ScriptBlockText:*SECURITY*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.… | 0 |  |
| q-e630f5cd3f | check C022 | search | {"dataset": "windows.other", "query": "event.code:7045 AND (win.ImagePath:*reg* OR win.ImagePath:*SAM*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable… | 0 |  |
| q-b969219a0c | check C023 | search | {"dataset": "windows.other", "query": "event.code:7045 AND (win.ImagePath:*ntds* OR win.ImagePath:*vss* OR win.ImagePath:*diskshadow*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "… | 0 |  |
| q-c805d5b522 | check C024 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (win.TargetFilename:*ntds.dit* OR win.TargetFilename:*.dit)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "proc… | 0 |  |
| q-064a83a6eb | check C025 | search | {"dataset": "windows.sysmon", "query": "event.code:2 AND win.TargetFilename:*ntds.dit*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.comma… | 0 |  |
| q-40c48e177b | check C026 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*ntds* OR process.command_line:*diskshadow* OR process.command_line:*vssadmin* OR process.command_line:*esentutl*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "ho… | 0 |  |
| q-a45471369e | check C027 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*ntds* OR process.command_line:*diskshadow* OR process.command_line:*vssadmin*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "ev… | 0 |  |
| q-60ead11bbd | check C028 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*ntds* OR win.ScriptBlockText:*diskshadow* OR win.ScriptBlockText:*vssadmin*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "eve… | 0 |  |
| q-971acc4e0a | check C029 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 326 |  |
| q-7d30c4928b | check C030 | search | {"dataset": "windows.sysmon", "query": "event.code:7 AND (win.ImageLoaded:*samlib* OR win.ImageLoaded:*vaultcli* OR win.ImageLoaded:*cryptdll*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event… | 54 | F05 |
| q-b6f1d187b6 | check C031 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*secrets* OR process.command_line:*lsadump* OR process.command_line:*cache*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.data… | 4 | F04, F07 |
| q-01b8e3116c | check C032 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND win.ObjectName:*SECURITY*Policy*Secrets*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-8f2a8f7dcc | check C033 | aggregate | {"dataset": "windows.security", "field": "win.ProcessName", "query": "event.code:4656 AND win.ObjectName:*SECURITY*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-ec27e56b7a | check C034 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*lsadump* OR win.ScriptBlockText:*SECURITY*Policy*Secrets* OR win.ScriptBlockText:*secrets*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "obser… | 0 |  |
| q-ef2f0a4a01 | check C035 | search | {"dataset": "windows.other", "query": "event.code:7045 AND (win.ImagePath:*lsadump* OR win.ImagePath:*secrets*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.ex… | 0 |  |
| q-31cdfe8b27 | check C036 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 326 |  |
| q-8bda3e7e4b | check C037 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*cache* OR process.command_line:*dcc2* OR process.command_line:*mscache*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset… | 4 |  |
| q-e28cfd403f | check C038 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND win.ObjectName:*SECURITY*Cache*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-3baa79f9a1 | check C039 | aggregate | {"dataset": "windows.security", "field": "win.ProcessName", "query": "event.code:4656 AND win.ObjectName:*Cache*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-0f3b0082cf | check C040 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*cache* OR win.ScriptBlockText:*dcc2* OR win.ScriptBlockText:*mscache*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dat… | 0 |  |
| q-ed97efbf5e | check C041 | search | {"dataset": "windows.other", "query": "event.code:7045 AND (win.ImagePath:*cache* OR win.ImagePath:*dcc*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executab… | 0 |  |
| q-16d25d5d59 | check C042 | search | {"dataset": "windows.security", "query": "event.code:4662 AND win.Properties:\"*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2*\"", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "pr… | 0 |  |
| q-fd4c9369a7 | check C043 | aggregate | {"dataset": "windows.security", "field": "win.SubjectUserName", "query": "event.code:4662", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 7 |  |
| q-670dd5ff10 | check C044 | search | {"dataset": "windows.security", "query": "event.code:4929", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 0 |  |
| q-695c7e601d | check C045 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 326 |  |
| q-533972ed92 | check C046 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND win.ScriptBlockText:(*DCSync* OR *lsadump* OR *drsuapi* OR *Get-Change* OR *replicat*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset",… | 0 |  |
| q-0694c4584b | check C047 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-7854c26a12 | check C048 | search | {"dataset": "zeek", "query": "event.action:dce_rpc AND zeek.operation:*DRS*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "… | 9 |  |
| q-ce3e896cb6 | check C049 | aggregate | {"dataset": "zeek", "field": "zeek.operation", "query": "event.action:dce_rpc", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 123 |  |
| q-9a0831b648 | check C050 | search | {"dataset": "windows.security", "query": "event.code:4688 AND process.command_line:(*pktmon* OR *netsh* OR *windump* OR *tcpdump* OR *Wireshark* OR *tshark* OR *RawCap*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name… | 2 | F08, F09 |
| q-3eff2d55db | check C051 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 460 |  |
| q-8612f8c5a1 | check C052 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 | F11 |
| q-e2c666ab38 | check C053 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND process.command_line:(*pktmon* OR *netsh trace* OR *windump* OR *tcpdump* OR *tshark* OR *RawCap*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.data… | 0 |  |
| q-15c07f881f | check C054 | search | {"dataset": "windows.sysmon", "query": "event.code:6 AND win.Image:*pktmon* OR event.code:6 AND win.Image:*npcap*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.… | 0 |  |
| q-475d1a346d | check C055 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND win.ScriptBlockText:(*pktmon* OR *netsh trace* OR *New-NetEventSession* OR *pcap*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "ev… | 0 |  |
| q-3a00e012d3 | check C056 | aggregate | {"dataset": "zeek", "field": "zeek.conn_state", "query": "event.action:conn", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 613 |  |
| q-d5e917c1b1 | check C057 | search | {"dataset": "windows.security", "query": "event.code:4663 AND win.ObjectType:*Key*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_l… | 5331 |  |
| q-6979717159 | check C058 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 5337 |  |
| q-fc46c3e062 | check C059 | search | {"dataset": "windows.security", "query": "event.code:4656 AND win.ObjectType:*Key*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_l… | 5419 |  |
| q-0cdc815e20 | check C060 | search | {"dataset": "windows.security", "query": "event.code:4670", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 143 |  |
| q-d678221e25 | check C061 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 326 |  |
| q-f3003fd972 | check C062 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-39dcba7a5e | check C063 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND win.ScriptBlockText:(*SetWindowsHookEx* OR *GetAsyncKeyState* OR *keylog* OR *Credential*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.datas… | 3 |  |
| q-1175f0cd36 | check C064 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-f4e3390f07 | check C065 | search | {"dataset": "zeek", "query": "event.action:http AND http.request.method:POST", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 0 |  |
| q-446649983b | check C066 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 326 |  |
| q-320edad399 | check C067 | search | {"dataset": "windows.sysmon", "query": "event.code:13 AND registry.path:(*Keyboard* OR *keylog* OR *Scancode*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.exe… | 26 |  |
| q-75106df5a6 | check C068 | aggregate | {"dataset": "windows.sysmon", "field": "registry.path", "query": "event.code:13", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 17541 |  |
| q-3bd60f05b8 | check C069 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND process.command_line:(*keylog* OR *GetAsyncKeyState* OR *SetWindowsHookEx* OR *scancode*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "ev… | 0 |  |
| q-edce721a81 | check C070 | search | {"dataset": "windows.security", "query": "event.code:4663 AND win.ObjectType:*Key*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_l… | 5331 |  |
| q-0f00bfcaae | check C071 | search | {"dataset": "windows.security", "query": "event.code:4656 AND win.ObjectType:*Key*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_l… | 5419 |  |
| q-934f5b11a1 | check C072 | search | {"dataset": "windows.security", "query": "event.code:4670", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 143 |  |
| q-20ace4c7e6 | check C073 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND win.ScriptBlockText:(*GetAsyncKeyState* OR *SetWindowsHookEx* OR *keylog* OR *scancode*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset… | 0 |  |
| q-b741f99bbf | check C074 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-be3e5239a9 | check C075 | search | {"dataset": "zeek", "query": "event.action:http AND http.request.method:POST", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 0 |  |
| q-6a8f5a15f5 | check C076 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND win.ScriptBlockText:(*Credential* OR *Prompt* OR *Get-Credential* OR *SecureString* OR *UAC*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.da… | 5 |  |
| q-4dd01d6065 | check C077 | search | {"dataset": "windows.powershell", "query": "event.code:4103", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "des… | 5080 |  |
| q-3c2d5b95ef | check C078 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND process.command_line:(*Get-Credential* OR *Credential* OR *prompt* OR *consent*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code"… | 3 |  |
| q-ab00d11ab9 | check C079 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 447 |  |
| q-7235d8935c | check C080 | search | {"dataset": "windows.security", "query": "event.code:4688 AND process.command_line:(*Credential* OR *prompt* OR *consent*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", … | 3 |  |
| q-d4059ca8d8 | check C081 | search | {"dataset": "windows.security", "query": "event.code:4672", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 212 |  |
| q-e8cfd1ef3c | check C082 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-5b058d4be7 | check C083 | search | {"dataset": "zeek", "query": "event.action:http AND http.request.method:POST", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 0 |  |
| q-c01619ad63 | check C084 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND file.path:(*wwwroot* OR *inetpub* OR *login* OR *portal*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "proces… | 0 |  |
| q-5c373cc594 | check C085 | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 1649 |  |
| q-3067875466 | check C086 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND process.command_line:(*iis* OR *w3wp* OR *appcmd* OR *web.config*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name",… | 0 |  |
| q-2aeb5156e6 | check C087 | search | {"dataset": "windows.security", "query": "event.code:4663 AND win.ObjectName:(*wwwroot* OR *inetpub* OR *web.config*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "proc… | 0 |  |
| q-1e5ed669ff | check C088 | search | {"dataset": "windows.security", "query": "event.code:4688 AND process.command_line:(*iis* OR *w3wp* OR *appcmd*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.e… | 0 |  |
| q-e0d38c5e24 | check C089 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND win.ScriptBlockText:(*wwwroot* OR *inetpub* OR *web.config* OR *login* OR *credential*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset"… | 4 |  |
| q-5674f2a78a | check C090 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-d90b063ecb | check C091 | search | {"dataset": "zeek", "query": "event.action:http AND http.request.method:POST", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 0 |  |
| q-ffaeb4495a | check C092 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-fdabf4207d | check C093 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-bd942602ab | check C094 | aggregate | {"dataset": "windows.sysmon", "field": "win.SourceImage", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-7c65c9ff7f | check C095 | aggregate | {"dataset": "windows.sysmon", "field": "win.ImageLoaded", "query": "event.code:7", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 20259 |  |
| q-0885a23b89 | check C096 | search | {"dataset": "windows.sysmon", "query": "event.code:8 AND win.StartFunction:*Credential*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.comm… | 0 |  |
| q-2dac4c7dfb | check C097 | aggregate | {"dataset": "windows.security", "field": "win.CallerProcessName", "query": "event.code:4656 AND win.ObjectType:*Process*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 13 |  |
| q-405cd7535c | check C098 | aggregate | {"dataset": "windows.security", "field": "win.ProcessName", "query": "event.code:4663 AND win.ObjectType:*Process*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 6 |  |
| q-873aeacd62 | check C099 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND win.ScriptBlockText:(*lsass* OR *MiniDump* OR *Credential*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name",… | 3 |  |
| q-c12913f2b5 | check C100 | search | {"dataset": "windows.other", "query": "event.code:10 OR event.code:7 OR event.code:8", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command… | 3 |  |
| q-fa00a505b6 | check C101 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-e91483b37c | check C102 | aggregate | {"dataset": "windows.security", "field": "source.ip", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-94e0ae9dd1 | check C103 | timeline | {"dataset": "windows.security", "query": "event.code:4625", "interval": "1m", "time_from": null, "time_to": null} | 0 |  |
| q-845571b821 | check C104 | search | {"dataset": "windows.security", "query": "event.code:4776", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 1 |  |
| q-b8faea8886 | check C105 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-3bf5f22ca3 | check C106 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND win.ScriptBlockText:(*Password* OR *Credential* OR *Login*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name",… | 4 |  |
| q-25e973d06e | check C107 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*password* OR process.command_line:*pass*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1 |  |
| q-a7175a7aed | check C108 | search | {"dataset": "windows.other", "query": "event.code:4625 OR event.code:4776", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "so… | 0 |  |
| q-3f819c08ee | check C109 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-da93d72e2a | check C110 | aggregate | {"dataset": "windows.security", "field": "win.Workstation", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-1baf20409b | check C111 | timeline | {"dataset": "windows.security", "query": "event.code:4625 AND win.LogonType:3", "interval": "1m", "time_from": null, "time_to": null} | 0 |  |
| q-c6c496cdba | check C112 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND win.ScriptBlockText:(*4625* OR *LogonUser* OR *New-Object*Net*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.na… | 0 |  |
| q-145880d01d | check C113 | aggregate | {"dataset": "windows.sysmon", "field": "process.command_line", "query": "event.code:1 AND (process.command_line:*net use* OR process.command_line:*net.exe*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-464829a358 | check C114 | search | {"dataset": "windows.other", "query": "event.code:4625", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 0 |  |
| q-a036e6053d | check C115 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND (win.ObjectName:*SAM* OR win.ObjectName:*SECURITY* OR win.ObjectName:*SYSTEM*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 4484 |  |
| q-1cf853fc8a | check C116 | aggregate | {"dataset": "windows.security", "field": "win.ProcessName", "query": "event.code:4656 AND (win.ObjectName:*SAM* OR win.ObjectName:*SECURITY*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 10 |  |
| q-abf1365c02 | check C117 | aggregate | {"dataset": "windows.security", "field": "win.ProcessName", "query": "event.code:4670", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 143 |  |
| q-dd03ad8ab3 | check C118 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*sam* OR process.command_line:*ntds* OR process.command_line:*hash*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-3ce8d6bf06 | check C119 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND (win.TargetFilename:*.dit OR win.TargetFilename:*.hive OR win.TargetFilename:*sam*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-2c071106f4 | check C120 | aggregate | {"dataset": "windows.sysmon", "field": "win.SourceImage", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-dfbb2cb130 | check C121 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND win.ScriptBlockText:(*reg save* OR *ntds* OR *hashcat* OR *john*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.… | 0 |  |
| q-87e4b7e685 | check C122 | search | {"dataset": "windows.other", "query": "event.code:4663 OR event.code:4656 OR event.code:4670", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process… | 0 |  |
| q-7dd88f86a5 | check C123 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-34e9673871 | check C124 | aggregate | {"dataset": "windows.security", "field": "source.ip", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-ac5f38fbbd | check C125 | search | {"dataset": "windows.security", "query": "event.code:4771", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 0 |  |
| q-d1df22d0d1 | check C126 | search | {"dataset": "windows.security", "query": "event.code:4648", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 15 |  |
| q-e105cb821e | check C127 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND win.ScriptBlockText:(*Credential* OR *Password*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.e… | 4 |  |
| q-eaca13d218 | check C128 | aggregate | {"dataset": "windows.sysmon", "field": "process.command_line", "query": "event.code:1 AND (process.command_line:*net use* OR process.command_line:*runas*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-2808566d57 | check C129 | search | {"dataset": "windows.other", "query": "event.code:4771 OR event.code:4648", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "so… | 0 |  |
| q-893ae2618b | check C130 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-a7795a837d | check C131 | aggregate | {"dataset": "windows.security", "field": "source.ip", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-8507ac6e1a | check C132 | timeline | {"dataset": "windows.security", "query": "event.code:4625", "interval": "5m", "time_from": null, "time_to": null} | 0 |  |
| q-da26c43519 | check C133 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND win.ScriptBlockText:(*username* OR *password* OR *credential*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.nam… | 2 | F21 |
| q-1d7952b1e9 | check C134 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*login* OR process.command_line:*auth*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-024e07b89e | check C135 | search | {"dataset": "windows.other", "query": "event.code:4625", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 0 |  |
| q-97be437d10 | check C136 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 297 |  |
| q-1521655e53 | check C137 | search | {"dataset": "windows.security", "query": "event.code:4648", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 15 |  |
| q-2047faec79 | check C138 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-2cca923411 | check C139 | search | {"dataset": "windows.sysmon", "query": "event.code:13 AND (registry.path:*Credential* OR registry.path:*Vault* OR registry.path:*Smartcard*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.co… | 11 | F22 |
| q-fe1a469c7e | check C140 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Credential* OR win.ScriptBlockText:*Vault* OR win.ScriptBlockText:*Smartcard*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "e… | 3 | F22 |
| q-869ec941d6 | check C141 | search | {"dataset": "windows.other", "query": "message:*Smartcard* OR message:*Credential*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_l… | 2 | F22 |
| q-b7d97bca51 | check C142 | search | {"dataset": "zeek", "query": "event.action:kerberos", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destination… | 35 |  |
| q-bb93458184 | check C143 | aggregate | {"dataset": "windows.security", "field": "win.ObjectType", "query": "event.code:(4656 OR 4663 OR 4670)", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 10977 |  |
| q-9bc218e3ab | check C144 | search | {"dataset": "windows.security", "query": "event.code:5145 AND win.RelativeTargetName:*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.comma… | 121 |  |
| q-874b52cdd2 | check C145 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*\\\\*.lnk OR file.path:*\\\\*.url OR file.path:*\\\\*.scf)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.n… | 3 |  |
| q-28b618bc06 | check C146 | aggregate | {"dataset": "windows.sysmon", "field": "destination.port", "query": "event.code:3 AND (destination.port:139 OR destination.port:445)", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 66 |  |
| q-70d116b22c | check C147 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*445* OR win.ScriptBlockText:*139* OR win.ScriptBlockText:*NTLM*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset",… | 0 |  |
| q-0df1f1a8c5 | check C148 | search | {"dataset": "windows.other", "query": "message:*NTLM* OR message:*SMB*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "sourc… | 1 | F25 |
| q-5a681d9937 | check C149 | search | {"dataset": "zeek", "query": "event.action:smb_files OR event.action:smb_mapping", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_lin… | 23 |  |
| q-889f5548f2 | check C150 | search | {"dataset": "windows.security", "query": "event.code:(4768 OR 4769 OR 4770)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "… | 42 | F28 |
| q-42fd855a62 | check C151 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-6aa5407b2e | check C152 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.GrantedAccess:*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line",… | 39283 |  |
| q-0246238ccf | check C153 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Invoke-* OR win.ScriptBlockText:*Reflective* OR win.ScriptBlockText:*Assembly*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "… | 22 |  |
| q-9b4839a968 | check C154 | search | {"dataset": "windows.other", "query": "message:*exploit* OR message:*overflow*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line"… | 0 |  |
| q-d49f5f1b69 | check C155 | search | {"dataset": "zeek", "query": "event.action:dce_rpc", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destination.… | 123 | F29 |
| q-05ac45159e | check C156 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 460 |  |
| q-1ce0010915 | check C157 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-32fc336071 | check C158 | search | {"dataset": "windows.sysmon", "query": "event.code:2 AND file.path:*Cookie*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "… | 0 |  |
| q-d762134d7e | check C159 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*Cookies* OR file.path:*Login Data* OR file.path:*Web Data*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.… | 162 |  |
| q-22c1595827 | check C160 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Cookies* OR win.ScriptBlockText:*Login Data* OR win.ScriptBlockText:*sqlite*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "ev… | 13 |  |
| q-b5aa9b849e | check C161 | search | {"dataset": "windows.other", "query": "message:*Cookie*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destina… | 0 |  |
| q-2fdacc7e57 | check C162 | search | {"dataset": "zeek", "query": "event.action:http AND http.request.method:GET", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "… | 2 |  |
| q-d799db2167 | check C163 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 460 |  |
| q-a7f904bb5d | check C164 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*unattend* OR file.path:*web.config* OR file.path:*passwords* OR file.path:*.config)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.datase… | 2 |  |
| q-b4b1294224 | check C165 | search | {"dataset": "windows.sysmon", "query": "event.code:13 AND (registry.path:*Password* OR registry.path:*Credential*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process… | 17 | F32 |
| q-c4c1efd9a2 | check C166 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*password* OR win.ScriptBlockText:*credential* OR win.ScriptBlockText:*Get-ChildItem*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.na… | 3 |  |
| q-a9997dac37 | check C167 | search | {"dataset": "windows.other", "query": "message:*password* OR message:*credential*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 2 |  |
| q-a8ebcbaaad | check C168 | search | {"dataset": "zeek", "query": "event.action:smb_files", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinatio… | 12 | F34 |
| q-af1590f803 | check C169 | search | {"dataset": "windows.security", "query": "event.code:(4624 OR 4648)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.i… | 312 |  |
| q-87ba488be7 | check C170 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 447 |  |
| q-abfad123e2 | check C171 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*.txt OR file.path:*.xml OR file.path:*.ini OR file.path:*.ps1)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "us… | 71 |  |
| q-64a5672ac3 | check C172 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Select-String* OR win.ScriptBlockText:*findstr* OR win.ScriptBlockText:*Get-Content*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.na… | 1 |  |
| q-2987d818ac | check C173 | search | {"dataset": "windows.other", "query": "message:*.config OR message:*.txt", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "sou… | 0 |  |
| q-0b5fb0c5bf | check C174 | search | {"dataset": "zeek", "query": "event.action:smb_files AND file.path:*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.… | 0 |  |
| q-064c1f1a21 | check C175 | aggregate | {"dataset": "windows.sysmon", "field": "registry.path", "query": "event.code:13 AND (registry.path:*SAM* OR registry.path:*SECURITY* OR registry.path:*LSA* OR registry.path:*Control\\\\Set\\\\Control\\\\Lsa*)", "time_from": null, "time_to": null, "size": 50, "… | 7 |  |
| q-864f6c6565 | check C176 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*reg*query* OR process.command_line:*reg*save* OR process.command_line:*reg*export*)", "time_from": null, "time_to": null, "size": 50, "sub_field": nu… | 0 |  |
| q-460c63b828 | check C177 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND (win.ObjectName:*SAM* OR win.ObjectName:*SECURITY* OR win.ObjectName:*Lsa*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1473 |  |
| q-2436058894 | check C178 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*reg*query* OR win.ScriptBlockText:*HKLM\\\\SAM* OR win.ScriptBlockText:*HKLM\\\\SECURITY*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observ… | 0 |  |
| q-e93cd1693f | check C179 | search | {"dataset": "windows.other", "query": "message:*reg*query* OR message:*SAM* OR message:*SECURITY*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "pr… | 11 |  |
| q-e817a54153 | check C180 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Get-History* OR win.ScriptBlockText:*ConsoleHost_history* OR win.ScriptBlockText:*history*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "obser… | 0 |  |
| q-e19464dc65 | check C181 | aggregate | {"dataset": "windows.sysmon", "field": "process.command_line", "query": "event.code:1 AND (process.command_line:*ConsoleHost_history* OR process.command_line:*Get-History* OR process.command_line:*.bash_history*)", "time_from": null, "time_to": null, "size": 5… | 0 |  |
| q-4da3c06cf9 | check C182 | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11 AND (file.path:*ConsoleHost_history* OR file.path:*.bash_history* OR file.path:*.zsh_history*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-9321a92921 | check C183 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND (win.ObjectName:*ConsoleHost_history* OR win.ObjectName:*.bash_history*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-6e54d64f3d | check C184 | search | {"dataset": "windows.other", "query": "message:*history*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destin… | 5 |  |
| q-78499cd1c0 | check C185 | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11 AND (file.path:*.pem OR file.path:*.pfx OR file.path:*.p12 OR file.path:*.key OR file.path:*.ppk OR file.path:*.pgp OR file.path:*.cer OR file.path:*.p7b)", "time_from": null, "time_to… | 1 |  |
| q-25f4312ee7 | check C186 | aggregate | {"dataset": "windows.sysmon", "field": "process.command_line", "query": "event.code:1 AND (process.command_line:*.pem OR process.command_line:*.pfx OR process.command_line:*.p12 OR process.command_line:*.ppk OR process.command_line:*.key)", "time_from": null, … | 0 |  |
| q-dbf4af261a | check C187 | aggregate | {"dataset": "windows.security", "field": "win.RelativeTargetName", "query": "event.code:5145 AND (win.RelativeTargetName:*.pem OR win.RelativeTargetName:*.pfx OR win.RelativeTargetName:*.p12 OR win.RelativeTargetName:*.key OR win.RelativeTargetName:*.ppk)", "t… | 0 |  |
| q-13ac881f5d | check C188 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*.pfx* OR win.ScriptBlockText:*.pem* OR win.ScriptBlockText:*.p12* OR win.ScriptBlockText:*Export-PfxCertificate*)", "time_from": null, "time_to": null, "fields": ["@timestamp… | 2 |  |
| q-20384303d5 | check C189 | search | {"dataset": "windows.other", "query": "message:*.pfx* OR message:*.pem* OR message:*.p12*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.co… | 0 |  |
| q-5a96d60fbf | check C190 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*cpassword* OR win.ScriptBlockText:*Groups.xml* OR win.ScriptBlockText:*gpprefdecrypt* OR win.ScriptBlockText:*AES*)", "time_from": null, "time_to": null, "fields": ["@timesta… | 0 |  |
| q-60d271a180 | check C191 | aggregate | {"dataset": "windows.sysmon", "field": "process.command_line", "query": "event.code:1 AND (process.command_line:*Groups.xml* OR process.command_line:*cpassword* OR process.command_line:*gpprefdecrypt* OR process.command_line:*SYSVOL*)", "time_from": null, "tim… | 0 |  |
| q-93e58ef0c0 | check C192 | aggregate | {"dataset": "windows.security", "field": "win.RelativeTargetName", "query": "event.code:5145 AND (win.RelativeTargetName:*Groups.xml* OR win.RelativeTargetName:*SYSVOL* OR win.RelativeTargetName:*Policies*)", "time_from": null, "time_to": null, "size": 50, "su… | 38 |  |
| q-31f14c292d | check C193 | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11 AND (file.path:*Groups.xml* OR file.path:*SYSVOL* OR file.path:*Policies*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 18 |  |
| q-58cf6923c4 | check C194 | search | {"dataset": "windows.other", "query": "message:*Groups.xml* OR message:*cpassword* OR message:*SYSVOL*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable"… | 0 |  |
| q-98310a429c | check C195 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10 AND (win.TargetImage:*lsass* OR win.TargetImage:*winlogon* OR win.TargetImage:*Credential* OR win.TargetImage:*vault*)", "time_from": null, "time_to": null, "size": 50, "sub_fiel… | 470 |  |
| q-26a0d11631 | check C196 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-8f5b561280 | check C197 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*sekurlsa* OR process.command_line:*lsadump* OR process.command_line:*mimikatz* OR process.command_line:*procdump*lsass* OR process.command_line:*coms… | 0 |  |
| q-7066d69fd1 | check C198 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND (win.ObjectName:*lsass* OR win.ObjectName:*vault* OR win.ObjectName:*Credential*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 6 |  |
| q-543f070cb9 | check C199 | aggregate | {"dataset": "windows.security", "field": "win.TargetProcessName", "query": "event.code:4656 AND (win.TargetProcessName:*lsass* OR win.TargetProcessName:*vault*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-74ac51faaf | check C200 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*MiniDump* OR win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*sekurlsa* OR win.ScriptBlockText:*Invoke-Mimikatz*)", "time_from": null, "time_to": null, "fields": ["@timest… | 0 |  |
| q-bc104db7f9 | check C201 | search | {"dataset": "windows.other", "query": "message:*lsass* OR message:*MiniDump* OR message:*mimikatz*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "p… | 0 |  |
| q-5ab9fa4a11 | check C202 | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11 AND (file.path:*Login Data* OR file.path:*Cookies* OR file.path:*Web Data* OR file.path:*Local State* OR file.path:*logins.json*)", "time_from": null, "time_to": null, "size": 50, "sub… | 0 |  |
| q-0097904ae1 | check C203 | aggregate | {"dataset": "windows.sysmon", "field": "process.command_line", "query": "event.code:1 AND (process.command_line:*Login Data* OR process.command_line:*logins.json* OR process.command_line:*Local State* OR process.command_line:*sqlite*)", "time_from": null, "tim… | 0 |  |
| q-11288add26 | check C204 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10 AND (win.TargetImage:*chrome* OR win.TargetImage:*firefox* OR win.TargetImage:*iexplore* OR win.TargetImage:*msedge*)", "time_from": null, "time_to": null, "size": 50, "sub_field… | 0 |  |
| q-0c1c54d818 | check C205 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND (win.ObjectName:*Login Data* OR win.ObjectName:*logins.json* OR win.ObjectName:*Cookies*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-89e0be6664 | check C206 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Login Data* OR win.ScriptBlockText:*logins.json* OR win.ScriptBlockText:*Local State*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.n… | 0 |  |
| q-0c97d2f62b | check C207 | search | {"dataset": "windows.other", "query": "message:*Login Data* OR message:*logins.json*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command… | 0 |  |
| q-62e01a4978 | check C208 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND (win.TargetImage:*lsass* OR win.TargetImage:*vault* OR win.TargetImage:*credential*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.… | 326 |  |
| q-4bc7d06ec0 | check C209 | search | {"dataset": "windows.sysmon", "query": "event.code:15 AND (win.TargetFilename:*Vault* OR win.TargetFilename:*Credentials* OR win.TargetFilename:*Credential*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.da… | 0 |  |
| q-5aa852a14e | check C210 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*vault* OR process.command_line:*credential* OR process.command_line:*cmdkey*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "eve… | 0 |  |
| q-ca4bbd7af3 | check C211 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*vault* OR win.ScriptBlockText:*credential* OR win.ScriptBlockText:*cmdkey*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "even… | 2 |  |
| q-d6b56cfe83 | check C212 | search | {"dataset": "windows.other", "query": "message:*Vault* OR message:*Credential*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line"… | 2 | F37 |
| q-2e87c13980 | check C213 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*keepass* OR process.command_line:*1password* OR process.command_line:*lastpass* OR process.command_line:*bitwarden* OR process.command_line:*password*)", "time_from": null, "t… | 0 |  |
| q-3ca51d9292 | check C214 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND (win.TargetImage:*keepass* OR win.TargetImage:*1password* OR win.TargetImage:*lastpass* OR win.TargetImage:*bitwarden*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "obser… | 0 |  |
| q-9403363920 | check C215 | search | {"dataset": "windows.sysmon", "query": "event.code:15 AND (win.TargetFilename:*.kdbx OR win.TargetFilename:*.opvault OR win.TargetFilename:*.agilekeychain)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.data… | 0 |  |
| q-0896a7cca3 | check C216 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*keepass* OR win.ScriptBlockText:*password* OR win.ScriptBlockText:*vault*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event… | 0 |  |
| q-2bb35d8983 | check C217 | search | {"dataset": "windows.other", "query": "message:*password* OR message:*KeePass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line"… | 0 |  |
| q-c39297b6d6 | check C218 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 326 |  |
| q-e979ff6358 | check C219 | search | {"dataset": "windows.sysmon", "query": "event.code:7 AND (win.ImageLoaded:*lsass* OR win.ImageLoaded:*cryptdll* OR win.ImageLoaded:*sam* OR win.ImageLoaded:*wdigest*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", … | 75 |  |
| q-4086c8f33e | check C220 | search | {"dataset": "windows.security", "query": "event.code:4657 AND (win.ObjectName:*lsass* OR win.ObjectName:*sam* OR win.ObjectName:*security*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.cod… | 0 |  |
| q-87c8a0e2ea | check C221 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*sam* OR win.ScriptBlockText:*wdigest* OR win.ScriptBlockText:*authentication*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "… | 5 |  |
| q-f34e88f07b | check C222 | search | {"dataset": "windows.other", "query": "message:*lsass* OR message:*cryptdll*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 0 |  |
| q-74e9d88e59 | check C223 | search | {"dataset": "windows.security", "query": "event.code:4624 AND win.LogonType:3 AND win.AuthenticationPackageName:*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.… | 218 | F41 |
| q-b9e7ecfca3 | check C224 | search | {"dataset": "windows.security", "query": "event.code:4648 AND win.TargetUserName:*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_l… | 15 |  |
| q-95779f99e7 | check C225 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 326 |  |
| q-2e63f68c34 | check C226 | search | {"dataset": "windows.sysmon", "query": "event.code:7 AND (win.ImageLoaded:*lsass* OR win.ImageLoaded:*cryptdll*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.e… | 33 |  |
| q-2704bfbe9a | check C227 | search | {"dataset": "windows.other", "query": "message:*lsass* OR message:*cryptdll*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 0 |  |
| q-c60dc42833 | check C228 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*cryptdll* OR win.ScriptBlockText:*dcsync* OR win.ScriptBlockText:*domain*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host… | 3 |  |
| q-436d32e8b6 | check C229 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (win.TargetFilename:*System32* AND (win.TargetFilename:*.dll))", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "p… | 0 |  |
| q-b934c07b3c | check C230 | search | {"dataset": "windows.sysmon", "query": "event.code:7 AND (win.ImageLoaded:*lsass* OR win.ImageLoaded:*password* OR win.ImageLoaded:*filter*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.co… | 1 |  |
| q-32ff21d1ed | check C231 | search | {"dataset": "windows.security", "query": "event.code:4657 AND (win.ObjectName:*Notification Packages* OR win.ObjectName:*Password* OR win.ObjectName:*lsass*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.da… | 0 |  |
| q-4a196df8bf | check C232 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Notification Packages* OR win.ScriptBlockText:*password filter* OR win.ScriptBlockText:*lsass*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "o… | 0 |  |
| q-1eb32ebfe9 | check C233 | search | {"dataset": "windows.other", "query": "message:*password* OR message:*Notification Packages*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process… | 4 |  |
| q-ce41ccabd1 | check C234 | search | {"dataset": "windows.security", "query": "event.code:4739 AND win.NewValue:*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 0 |  |
| q-fd19409975 | check C235 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*AllowReversiblePasswordEncryption* OR win.ScriptBlockText:*ReversibleEncryption* OR win.ScriptBlockText:*Set-ADUser* OR win.ScriptBlockText:*Set-ADDefaultDomainPasswordPolicy… | 1 |  |
| q-284d342cdf | check C236 | search | {"dataset": "windows.powershell", "query": "event.code:4103 AND (win.Payload:*Reversible* OR win.Payload:*PasswordEncryption*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.nam… | 0 |  |
| q-e4e7ae9b6f | check C237 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*Reversible* OR process.command_line:*PasswordEncryption* OR process.command_line:*Set-ADUser*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer… | 0 |  |
| q-6d2a803892 | check C238 | search | {"dataset": "windows.other", "query": "message:*Reversible* OR message:*PasswordEncryption*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.… | 0 |  |
| q-f415e0b44b | check C239 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(process.command_line) LIKE \"*set-aduser*\" OR TO_LOWER(process.command_line) LIKE \"*set-adaccount*\" OR TO_LOWER(process.command_line) LIKE \"*set-adauthenticationpolicy*\… | 1 |  |
| q-f04224ac3d | check C240 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*set-aduser*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*set-adauthenticationpolicy*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*strongauthenticati… | 1 |  |
| q-df6b41de57 | check C241 | count | {"dataset": "windows.security", "query": "event.code:4739", "time_from": null, "time_to": null} | 0 |  |
| q-55d7d78478 | check C242 | aggregate | {"dataset": "windows.security", "field": "win.ObjectType", "query": "event.code:4663 OR event.code:4656 OR event.code:4670", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 10977 |  |
| q-7585721470 | check C243 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*set-aduser*\" OR TO_LOWER(process.command_line) LIKE \"*set-adauthenticationpolicy*\" OR TO_LOWER(process.command_line) LI… | 0 |  |
| q-5151c5ad93 | check C244 | esql | {"query": "FROM logs-windows.other-default METADATA _id, _index \| WHERE TO_LOWER(message) LIKE \"*authentication policy*\" OR TO_LOWER(message) LIKE \"*mfa*\" OR TO_LOWER(message) LIKE \"*strong authentication*\" OR TO_LOWER(message) LIKE \"*adfs*\" \| KEEP @… | 0 |  |
| q-2f18581f94 | check C245 | count | {"dataset": "windows.security", "query": "event.code:5136", "time_from": null, "time_to": null} | 0 |  |
| q-ffdfa228af | check C246 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"5136\" \| KEEP @timestamp, host.name, user.name, win.ObjectType, win.ObjectValueName, win.OperationType, win.SubjectUserName, _id, _index"} | 0 |  |
| q-bf74f37cdd | check C247 | aggregate | {"dataset": "windows.security", "field": "win.LogonProcessName", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 297 |  |
| q-46e5feb10c | check C248 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"7\" AND (TO_LOWER(win.ImageLoaded) LIKE \"*adfs*\" OR TO_LOWER(win.ImageLoaded) LIKE \"*azure*\" OR TO_LOWER(win.ImageLoaded) LIKE \"*aad*\" OR TO_LOWER(win.ImageLoaded) … | 7 |  |
| q-f8821d0e21 | check C249 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*connect-msolservice*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*connect-azuread*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*set-msol*\" OR TO_LO… | 0 |  |
| q-b33ae14961 | check C250 | esql | {"query": "FROM logs-windows.other-default METADATA _id, _index \| WHERE TO_LOWER(message) LIKE \"*adfs*\" OR TO_LOWER(message) LIKE \"*federation*\" OR TO_LOWER(message) LIKE \"*azure ad*\" OR TO_LOWER(message) LIKE \"*hybrid*\" \| KEEP @timestamp, host.name,… | 0 |  |
| q-5851e366f4 | check C251 | count | {"dataset": "windows.security", "query": "event.code:4657", "time_from": null, "time_to": null} | 36 |  |
| q-d07b20a73a | check C252 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4657\" AND (TO_LOWER(win.ObjectName) LIKE \"*networkprovider*\" OR TO_LOWER(win.ObjectName) LIKE \"*credential*\" OR TO_LOWER(win.ObjectName) LIKE \"*winlogon*\" OR TO_… | 0 |  |
| q-859faa5ca1 | check C253 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"13\" AND (TO_LOWER(registry.path) LIKE \"*networkprovider*\" OR TO_LOWER(registry.path) LIKE \"*credential providers*\" OR TO_LOWER(registry.path) LIKE \"*winlogon*\" OR … | 12 |  |
| q-6a35af8fd0 | check C254 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*networkprovider*\" OR TO_LOWER(file.path) LIKE \"*system32*\" AND TO_LOWER(file.path) LIKE \"*.dll\") \| KEEP @timestamp, host.name,… | 0 |  |
| q-1fdef7de21 | check C255 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND (TO_LOWER(win.TargetImage) LIKE \"*lsass*\" OR TO_LOWER(win.TargetImage) LIKE \"*winlogon*\" OR TO_LOWER(win.TargetImage) LIKE \"*services*\") \| KEEP @timestamp… | 500 |  |
| q-fda76a7f0f | check C256 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"7\" AND (TO_LOWER(win.ImageLoaded) LIKE \"*networkprovider*\" OR TO_LOWER(win.ImageLoaded) LIKE \"*np*.dll\" OR TO_LOWER(win.ImageLoaded) LIKE \"*credential*\") \| KEEP @… | 257 |  |
| q-327159ddbd | check C257 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*networkprovider*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*credential providers*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*new-itemproperty*\"… | 0 |  |
| q-efe1f934e4 | check C258 | esql | {"query": "FROM logs-windows.other-default METADATA _id, _index \| WHERE TO_LOWER(message) LIKE \"*network provider*\" OR TO_LOWER(message) LIKE \"*credential provider*\" OR TO_LOWER(message) LIKE \"*winlogon*\" \| KEEP @timestamp, host.name, event.code, messa… | 0 |  |
| q-b982faf412 | check C259 | aggregate | {"dataset": "windows.security", "field": "win.ObjectType", "query": "event.code:4663 OR event.code:4670 OR event.code:4656", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 10977 |  |
| q-2c26c0168e | check C260 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4670\" \| KEEP @timestamp, host.name, user.name, win.ObjectType, win.ObjectName, win.OldSd, win.NewSd, _id, _index"} | 143 |  |
| q-fc6427c04f | check C261 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"22\" \| KEEP @timestamp, host.name, process.executable, win.QueryName, win.QueryResults, win.QueryStatus, _id, _index"} | 81 | F48 |
| q-1a417e25e9 | check C262 | aggregate | {"dataset": "windows.sysmon", "field": "destination.ip", "query": "event.code:3", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1229 |  |
| q-b498a3151f | check C263 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"3\" AND (destination.port == 445 OR destination.port == 139 OR destination.port == 389 OR destination.port == 88) \| KEEP @timestamp, host.name, process.executable, desti… | 383 |  |
| q-ce1d766876 | check C264 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*inveigh*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*responder*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*llmnr*\" OR TO_LOWER(win.ScriptBlockTe… | 0 |  |
| q-d67f01e2b6 | check C265 | esql | {"query": "FROM logs-windows.other-default METADATA _id, _index \| WHERE TO_LOWER(message) LIKE \"*llmnr*\" OR TO_LOWER(message) LIKE \"*nbt-ns*\" OR TO_LOWER(message) LIKE \"*name resolution*\" OR TO_LOWER(message) LIKE \"*dns client*\" \| KEEP @timestamp, ho… | 0 |  |
| q-c8b244033c | check C266 | aggregate | {"dataset": "zeek", "field": "event.action", "query": "*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 2140 |  |
| q-0c1c393425 | check C267 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"dns\" AND (dns.question.name LIKE \"*\" ) \| KEEP @timestamp, source.ip, destination.ip, dns.question.name, dns.response_code, _id, _index"} | 53 |  |
| q-d8b989d41a | check C268 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"kerberos\" \| KEEP @timestamp, source.ip, destination.ip, zeek.client, zeek.service, zeek.success, zeek.error_msg, _id, _index"} | 35 |  |
| q-bbdb9b00bc | check C269 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"dns\" AND (dns.question.name LIKE \"*\" ) \| KEEP @timestamp, source.ip, destination.ip, dns.question.name, dns.response_code, _id, _index"} | 53 |  |
| q-54fd49f9d1 | check C270 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"smb_mapping\" OR event.action == \"smb_files\" OR event.action == \"dce_rpc\" \| KEEP @timestamp, source.ip, destination.ip, zeek.path, zeek.share_type, zeek.filename, _id, _inde… | 146 |  |
| q-0c8021fd89 | check C271 | aggregate | {"dataset": "zeek", "field": "destination.port", "query": "event.action:conn", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 613 |  |
| q-6e76282c19 | check C272 | count | {"dataset": "windows.security", "query": "event.code:4697", "time_from": null, "time_to": null} | 23 |  |
| q-2b407e7a18 | check C273 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4697\" \| KEEP @timestamp, host.name, user.name, win.ServiceName, win.ServiceFileName, win.ServiceType, _id, _index"} | 23 |  |
| q-656dd9a12f | check C274 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"13\" AND (TO_LOWER(registry.path) LIKE \"*dnsclient*\" OR TO_LOWER(registry.path) LIKE \"*enablemulticast*\") \| KEEP @timestamp, host.name, process.executable, registry.… | 0 |  |
| q-3b65e57066 | check C275 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*enablemulticast*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*llmnr*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*nbt-ns*\" OR TO_LOWER(win.ScriptBl… | 0 |  |
| q-ec4e8c13d2 | check C276 | esql | {"query": "FROM logs-windows.other-default METADATA _id, _index \| WHERE TO_LOWER(message) LIKE \"*llmnr*\" OR TO_LOWER(message) LIKE \"*nbt-ns*\" OR TO_LOWER(message) LIKE \"*multicast*\" OR TO_LOWER(message) LIKE \"*dns client*\" \| KEEP @timestamp, host.nam… | 0 |  |
| q-3a03c0a62b | check C277 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"22\" \| KEEP @timestamp, host.name, process.executable, win.QueryName, win.QueryResults, _id, _index"} | 81 |  |
| q-3ee2709f72 | check C278 | aggregate | {"dataset": "windows.sysmon", "field": "destination.ip", "query": "event.code:3", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1229 |  |
| q-a6a39f3439 | check C279 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"3\" AND (destination.port == 445 OR destination.port == 139 OR destination.port == 80 OR destination.port == 443) \| KEEP @timestamp, host.name, process.executable, desti… | 120 |  |
| q-708db92552 | check C280 | aggregate | {"dataset": "windows.security", "field": "win.ObjectType", "query": "event.code:4663 OR event.code:4656 OR event.code:4670", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 10977 |  |
| q-5d74377cf8 | check C281 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"5156\" OR event.code == \"5158\" \| KEEP @timestamp, host.name, process.executable, source.ip, destination.ip, destination.port, _id, _index"} | 500 |  |
| q-6c49a416b7 | check C282 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*arp*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*get-netneighbor*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*new-netneighbor*\" OR TO_LOWER(win.S… | 0 |  |
| q-f5b2e52d79 | check C283 | esql | {"query": "FROM logs-windows.other-default METADATA _id, _index \| WHERE TO_LOWER(message) LIKE \"*arp*\" OR TO_LOWER(message) LIKE \"*neighbor*\" OR TO_LOWER(message) LIKE \"*gateway*\" \| KEEP @timestamp, host.name, event.code, message, _id, _index"} | 4 |  |
| q-243cb71bc5 | check C284 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"conn\" \| KEEP @timestamp, source.ip, destination.ip, destination.port, zeek.conn_state, zeek.history, _id, _index"} | 500 |  |
| q-9d36f3397d | check C285 | search | {"dataset": "windows.other", "query": "event.code:(1341 OR 1342 OR 1020 OR 1063)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_lin… | 0 |  |
| q-d8747688b3 | check C286 | search | {"dataset": "windows.security", "query": "event.code:(5156 OR 5158) AND network.transport:udp", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "proces… | 0 |  |
| q-1a14270565 | check C287 | aggregate | {"dataset": "windows.sysmon", "field": "destination.port", "query": "event.code:3 AND network.transport:udp", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 308 |  |
| q-299ce4ffdd | check C288 | search | {"dataset": "windows.powershell", "query": "process.command_line:(*dhcp* OR *ipconfig* OR *netsh*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "p… | 0 |  |
| q-635e60b9ca | check C289 | search | {"dataset": "zeek", "query": "event.action:conn AND network.transport:udp AND destination.port:(67 OR 68)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executab… | 0 |  |
| q-0f1d252398 | check C290 | aggregate | {"dataset": "windows.security", "field": "event.code", "query": "event.code:(4672 OR 4634 OR 4769 OR 4768 OR 4624)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 787 |  |
| q-cdc6661967 | check C291 | search | {"dataset": "windows.security", "query": "event.code:4769 AND win.TicketEncryptionType:(0x17 OR 0x18)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable",… | 0 |  |
| q-f2d751ccae | check C292 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 326 |  |
| q-aab84384ca | check C293 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-b92e1cfe8e | check C294 | search | {"dataset": "windows.powershell", "query": "process.command_line:(*kerberos* OR *ticket* OR *klist* OR *kirbi*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.ex… | 0 |  |
| q-0105f4301a | check C295 | search | {"dataset": "windows.other", "query": "event.code:(7045 OR 7040 OR 7036) AND message:(*kerberos* OR *kdc*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executa… | 0 |  |
| q-9f9f10fb84 | check C296 | search | {"dataset": "zeek", "query": "event.action:kerberos", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destination… | 35 |  |
| q-f3da518b23 | check C297 | search | {"dataset": "windows.security", "query": "event.code:4769 AND win.TicketEncryptionType:0x17", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.… | 0 |  |
| q-438d10c9a7 | check C298 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4769", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 28 |  |
| q-24e5838a46 | check C299 | search | {"dataset": "windows.security", "query": "event.code:(4672 OR 4634)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.i… | 448 | F54 |
| q-3f5a3564bc | check C300 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 326 |  |
| q-ac9a58575f | check C301 | search | {"dataset": "windows.powershell", "query": "process.command_line:(*krbtgt* OR *golden* OR *mimikatz* OR *sekurlsa*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "proces… | 0 |  |
| q-637c06aeac | check C302 | search | {"dataset": "windows.other", "query": "event.code:(7045 OR 7040)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip",… | 9 |  |
| q-0986de32b9 | check C303 | search | {"dataset": "zeek", "query": "event.action:kerberos", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destination… | 35 |  |
| q-c64afa5111 | check C304 | search | {"dataset": "windows.security", "query": "event.code:4769 AND win.TicketEncryptionType:0x17", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.… | 0 |  |
| q-d0d734c5a4 | check C305 | aggregate | {"dataset": "windows.security", "field": "win.ServiceName", "query": "event.code:4769", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 28 |  |
| q-ffed1c68fc | check C306 | search | {"dataset": "windows.security", "query": "event.code:(4672 OR 4634)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.i… | 448 |  |
| q-681cb4d326 | check C307 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 326 |  |
| q-5382303f52 | check C308 | search | {"dataset": "windows.powershell", "query": "process.command_line:(*silver* OR *mimikatz* OR *kerberos::golden* OR *ticket*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name",… | ERROR |  |
| q-818b5284f1 | check C308 (repaired) | search | {"dataset": "windows.powershell", "query": "process.command_line:(*silver* OR *mimikatz* OR *ticket*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable",… | 0 |  |
| q-2b8c9ee879 | check C309 | search | {"dataset": "windows.other", "query": "event.code:(7045 OR 7040)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip",… | 9 |  |
| q-d8899ad216 | check C310 | search | {"dataset": "zeek", "query": "event.action:kerberos", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destination… | 35 |  |
| q-80ac57438c | check C311 | search | {"dataset": "windows.security", "query": "event.code:4769 AND win.TicketEncryptionType:0x17", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.… | 0 |  |
| q-42c97f3cba | check C312 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4769", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 28 |  |
| q-3b5563e1b4 | check C313 | search | {"dataset": "windows.security", "query": "event.code:(4624 OR 4648 OR 4672)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "… | 524 |  |
| q-cb778852fd | check C314 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 326 |  |
| q-b1c264936e | check C315 | search | {"dataset": "windows.powershell", "query": "process.command_line:(*kerberoast* OR *invoke-kerberoast* OR *rubeus* OR *setspn*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.nam… | 0 |  |
| q-fab1b8e14e | check C316 | search | {"dataset": "windows.other", "query": "event.code:(7045 OR 7040)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip",… | 9 |  |
| q-dce2f559b6 | check C317 | search | {"dataset": "zeek", "query": "event.action:kerberos", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destination… | 35 |  |
| q-3c8116a4cb | check C318 | search | {"dataset": "windows.security", "query": "event.code:4768 AND win.PreAuthType:0", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line… | 0 |  |
| q-12a1e62f45 | check C319 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4768", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 14 |  |
| q-bb28a373ea | check C320 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND process.command_line:(*asreproast* OR *rubeus* OR *kerberos*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "pro… | 0 |  |
| q-1b4388cec3 | check C321 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 326 |  |
| q-33ba960bba | check C322 | search | {"dataset": "windows.powershell", "query": "process.command_line:(*asreproast* OR *as-rep* OR *rubeus* OR *kerberos*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "proc… | 0 |  |
| q-895895b7b2 | check C323 | search | {"dataset": "windows.other", "query": "event.code:(7045 OR 7040)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip",… | 9 |  |
| q-6502d44748 | check C324 | search | {"dataset": "zeek", "query": "event.action:kerberos", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destination… | 35 |  |
| q-8d56cbcbf5 | check C325 | aggregate | {"dataset": "windows.security", "field": "win.LogonProcessName", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 297 |  |
| q-fc1094985c | check C326 | search | {"dataset": "windows.security", "query": "event.code:4648", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 15 |  |
| q-39ae18bde0 | check C327 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-370a2e07db | check C328 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*token* OR win.ScriptBlockText:*cookie* OR win.ScriptBlockText:*SAML*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.data… | 1 |  |
| q-03190162fb | check C329 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-67aead2ad7 | check C330 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*cookie* OR file.path:*Cookies*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable",… | 1 |  |
| q-a81d1e0dd1 | check C331 | aggregate | {"dataset": "windows.security", "field": "win.LogonProcessName", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 297 |  |
| q-2ace299831 | check C332 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*cookie* OR win.ScriptBlockText:*Set-Cookie* OR win.ScriptBlockText:*session*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "ev… | 1 |  |
| q-c0d09c8744 | check C333 | search | {"dataset": "windows.other", "query": "event.code:11", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinatio… | 4 |  |
| q-01a08336ca | check C334 | search | {"dataset": "windows.security", "query": "event.code:4624 AND win.AuthenticationPackageName:*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "proces… | 297 | F58 |
| q-86cea73421 | check C335 | aggregate | {"dataset": "windows.security", "field": "win.AuthenticationPackageName", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 297 |  |
| q-1c6a745c0b | check C336 | search | {"dataset": "windows.other", "query": "event.code:7045 OR event.code:7040", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "so… | 9 | F58 |
| q-81a4a41d97 | check C337 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*SAML* OR win.ScriptBlockText:*ADFS* OR win.ScriptBlockText:*NotOnOrAfter*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event… | 0 |  |
| q-8564a1eeb8 | check C338 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*adfs* OR file.path:*token*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "pr… | 0 |  |
| q-db7d5d73c0 | check C339 | count | {"dataset": "windows.security", "query": "event.code:4625", "time_from": null, "time_to": null} | 0 |  |
| q-b4f3aab869 | check C340 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-30dfbe2dec | check C341 | search | {"dataset": "windows.other", "query": "event.code:4625", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 0 |  |
| q-99b3de47f9 | check C342 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*MFA* OR win.ScriptBlockText:*2FA* OR win.ScriptBlockText:*Authenticator*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.… | 0 |  |
| q-130781a071 | check C343 | search | {"dataset": "windows.sysmon", "query": "event.code:3 AND (destination.port:443 OR destination.port:80)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable"… | 54 |  |
| q-2826fa89d9 | check C344 | search | {"dataset": "windows.security", "query": "event.code:4657", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 36 | F62 |
| q-17b3f4ce52 | check C345 | search | {"dataset": "windows.security", "query": "event.code:4768", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 14 | F63 |
| q-185daf5b41 | check C346 | aggregate | {"dataset": "windows.security", "field": "win.PreAuthType", "query": "event.code:4768", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 14 |  |
| q-7a200a8a6d | check C347 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*.pfx OR file.path:*.p12 OR file.path:*.cer OR file.path:*.crt)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "us… | 1 | F61 |
| q-f67232940d | check C348 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Export-PfxCertificate* OR win.ScriptBlockText:*certutil* OR win.ScriptBlockText:*New-SelfSignedCertificate*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "h… | 1 | F61 |
| q-44197ecd7b | check C349 | search | {"dataset": "windows.other", "query": "event.code:4657", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 0 |  |
| q-213f55468e | check C350 | aggregate | {"dataset": "zeek", "field": "zeek.service", "query": "event.action:conn AND (destination.port:445 OR destination.port:139)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 50 |  |
| q-b5693e81b2 | check C351 | aggregate | {"dataset": "zeek", "field": "zeek.filename", "query": "event.action:smb_files", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 12 |  |
| q-9cfc84f3a5 | check C352 | aggregate | {"dataset": "zeek", "field": "http.request.method", "query": "event.action:http", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 62 |  |
| q-a4fd64d232 | check C353 | aggregate | {"dataset": "zeek", "field": "user_agent.original", "query": "event.action:http", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 62 |  |
| q-b26964307e | check C354 | aggregate | {"dataset": "zeek", "field": "zeek.success", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 35 |  |
| q-d1afb6484b | check C355 | aggregate | {"dataset": "zeek", "field": "zeek.error_msg", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 35 |  |
| q-ee42bec6a4 | triage T1003 step 1 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTtmJQ5"} | None |  |
| q-fad5648b0c | triage T1003 step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 10 AND win.TargetImage LIKE \"*lsass*\" AND win.GrantedAccess IN (\"0x1fffff\",\"0x101001\",\"0x1f3fff\",\"0x1000000\",\"0x3000\",\"0x1400\") \| KEEP @timestamp, host.name,… | ERROR |  |
| q-cdfdaeb9a2 | triage T1003 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND win.TargetImage LIKE \"*lsass*\" AND win.GrantedAccess IN (\"0x1fffff\",\"0x101001\",\"0x1f3fff\",\"0x1000000\",\"0x3000\") \| KEEP @timestamp, host.name, proces… | 9 | F01, F02 |
| q-bdd68c373a | triage T1003 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND win.TargetImage LIKE \"*lsass*\" AND win.GrantedAccess == \"0x1400\" \| KEEP @timestamp, host.name, process.executable, win.GrantedAccess, win.SourceImage, _id, … | 24 |  |
| q-d288a42f20 | triage T1003 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-2a102d369a | triage T1003 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gj"} | None |  |
| q-98014e96b3 | triage T1003 step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (win.ScriptBlockText LIKE \"*lsass*\" OR win.ScriptBlockText LIKE \"*MiniDump*\" OR win.ScriptBlockText LIKE \"*DumpCred*\" OR win.ScriptBlockText LIKE \"*… | 3 | F02 |
| q-9ead50151a | triage T1003 step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND @timestamp >= \"2020-05-02T03:04:00.000Z\" AND @timestamp <= \"2020-05-02T03:07:00.000Z\" \| KEEP @timestamp, host.name, user.name, win.ScriptBlockText, _i… | 30 | F01 |
| q-86dc60e3c8 | triage T1003 step 4 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None |  |
| q-f5b262e513 | triage T1003 step 5 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4663\" AND (win.ObjectName LIKE \"*SAM*\" OR win.ObjectName LIKE \"*SECURITY*\" OR win.ObjectName LIKE \"*Cache*\") \| KEEP @timestamp, host.name, user.name, win.Proces… | 0 |  |
| q-cee6cee290 | triage T1003 step 5 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4656\" AND win.ObjectName LIKE \"*lsass*\" \| KEEP @timestamp, host.name, user.name, win.ProcessName, win.ObjectName, win.AccessMask, _id, _index \| LIMIT 20"} | 13 | F01 |
| q-cf0a641e43 | triage T1003 step 6 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKB-"} | None | F01, F02 |
| q-e6e9dbf6bc | triage T1003 step 6 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4663\" AND win.ObjectName LIKE \"*Lsa*\" \| KEEP @timestamp, host.name, user.name, win.ProcessName, win.ObjectName, win.AccessMask, _id, _index \| LIMIT 20"} | 20 | F05 |
| q-36ca737a84 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-56b7bf948f | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gj"} | None |  |
| q-d7e9926ed6 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-7648e27cbb | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKB-"} | None |  |
| q-5767a60e80 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKB-"} | None |  |
| q-75c172bdb0 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None |  |
| q-c0bc58aac9 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None |  |
| q-0761156884 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-07a30b50c0 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-987be81c6b | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None |  |
| q-0f47133ce4 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKB-"} | None |  |
| q-bdad508ee4 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZKhD3z"} | None |  |
| q-6928c15246 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItKT-FUX"} | None |  |
| q-2a04086835 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO9rO3D"} | None |  |
| q-d2f5fa6fed | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTVGQnT"} | None |  |
| q-1644e90293 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO-r7Fc"} | None |  |
| q-6859cf82d2 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTqhQkl"} | None |  |
| q-1aca27b6c6 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVcvuSc"} | None |  |
| q-dff5774967 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTVGQnT"} | None |  |
| q-b752396e23 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO-r7Fc"} | None |  |
| q-25c1a6464f | triage T1040 step 1 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVt4o2y"} | None | F08 |
| q-8b2b0a7ea4 | triage T1040 step 1 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVr2bv9"} | None | F08 |
| q-4c1bc36bf0 | triage T1040 step 1 | search | {"dataset": "windows.security", "query": "event.code:4688 AND process.command_line:(*trace* OR *capture* OR *logman* OR *NetworkWatcher*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code"… | 14 | F08, F09 |
| q-ff9463b58d | triage T1040 step 1 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND process.command_line:(*trace* OR *capture* OR *logman* OR *NetworkWatcher* OR *etl*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 14 |  |
| q-c8fbd2167c | triage T1040 step 2 | search | {"dataset": "windows.security", "query": "event.code:4688 AND process.executable:(*python.exe OR *PsExec64.exe OR *sdelete64.exe OR *PSEXESVC.exe)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "ev… | 19 | F11 |
| q-69ee0b3ade | triage T1040 step 2 | aggregate | {"dataset": "zeek", "field": "zeek.service", "query": "*", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 2140 |  |
| q-2471e3c599 | triage T1040 step 2 | search | {"dataset": "zeek", "query": "event.action:conn AND zeek.conn_state:(S0 OR REJ OR RSTO)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.comm… | 482 | F10 |
| q-6cb5fc33dc | triage T1040 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"6\" AND (TO_LOWER(win.Image) LIKE \"*pktmon*\" OR TO_LOWER(win.Image) LIKE \"*npcap*\" OR TO_LOWER(win.Image) LIKE \"*pcap*\" OR TO_LOWER(win.Image) LIKE \"*winpcap*\") \… | 0 |  |
| q-cd9dc54e7a | triage T1040 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*pktmon*\" OR TO_LOWER(process.command_line) LIKE \"*netsh trace*\" OR TO_LOWER(process.command_line) LIKE \"*tcpdump*\" OR… | 0 |  |
| q-59127969b7 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVt4o2y"} | None |  |
| q-eb5f68a3ed | triage T1040 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVt4o2y"} | None |  |
| q-4cdeede424 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVr2bv9"} | None |  |
| q-d098ef4a5f | triage T1040 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVr2bv9"} | None |  |
| q-f3a0dbab8f | triage T1040 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVz8aWs"} | None |  |
| q-21e798d5cb | triage T1040 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVr2bu5"} | None |  |
| q-c443e16711 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "q-cd9dc54e7a"} | ERROR |  |
| q-5ac6aae9de | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "q-6cb5fc33dc"} | ERROR |  |
| q-da64c481b3 | triage T1040 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrog0"} | None |  |
| q-afb28f0ce5 | triage T1040 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNn1uOFchItY0uF-5"} | None |  |
| q-1560104b31 | triage T1040 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrYih"} | None |  |
| q-16f25480a7 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ev9A"} | None |  |
| q-a4b52f1662 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ef_B"} | None |  |
| q-835051c85a | triage T1040 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaFQQsu"} | None |  |
| q-d77635bd95 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrYMQT"} | None |  |
| q-9c725b5d3b | triage T1056 step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND TO_LOWER(win.TargetImage) LIKE \"*lsass*\" \| STATS cnt = COUNT(*) BY process.executable, win.GrantedAccess, host.name \| SORT cnt DESC \| LIMIT 50"} | 18 |  |
| q-b1e34768df | triage T1056 step 1 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4663\" AND win.ObjectName LIKE \"*Lsa*\" \| STATS cnt = COUNT(*) BY process.executable, user.name, host.name \| SORT cnt DESC \| LIMIT 50"} | 50 |  |
| q-47a2f163d0 | triage T1056 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" \| KEEP @timestamp, host.name, user.name, process.executable, process.command_line, process.parent.executable, _id, _index \| SORT @timestamp ASC \| LIMIT 100"} | 100 | F12, F14, F15, F16 |
| q-c6a5f414c7 | triage T1056 step 2 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4663\" AND process.executable LIKE \"*victim*\" \| KEEP @timestamp, host.name, user.name, process.executable, win.ObjectName, win.AccessMask, win.AccessList, _id, _inde… | 1 | F12 |
| q-744cc64a9a | triage T1056 step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" \| KEEP @timestamp, host.name, user.name, win.ScriptBlockText, _id, _index \| SORT @timestamp ASC \| LIMIT 30"} | 30 | F14 |
| q-12d9c8d328 | triage T1056 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND TO_LOWER(win.TargetImage) LIKE \"*lsass*\" AND (process.executable LIKE \"*powershell*\" OR process.executable LIKE \"*victim*\" OR process.executable LIKE \"*ru… | 2 | F13 |
| q-56a58c9c1c | triage T1056 step 4 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZWqNA3"} | None | F14 |
| q-a6e0442811 | triage T1056 step 4 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTtmJQ5"} | None |  |
| q-22126128e7 | triage T1056 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND TO_LOWER(win.TargetImage) LIKE \"*lsass*\" AND win.GrantedAccess IN (\"0x1010\",\"0x1410\",\"0x1438\",\"0x143a\",\"0x1f0fff\",\"0x1fffff\",\"0x1418\") \| KEEP @t… | 3 |  |
| q-3869954636 | triage T1056 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*monkey*\" OR TO_LOWER(file.path) LIKE \"*victim*\" OR TO_LOWER(file.path) LIKE \"*.scr\") \| KEEP @timestamp, host.name, user.name, … | 1 | F14 |
| q-25a263ba88 | triage T1056 step 6 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None | F12, F13 |
| q-c26bf88d31 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQE_psP"} | None |  |
| q-828f8be126 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQE_psP"} | None |  |
| q-08795d5a38 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaKXhpR"} | None |  |
| q-f24dc4a843 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaKXhpR"} | None |  |
| q-a51fca429f | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItTka0Gm"} | ERROR |  |
| q-99a775b198 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-31e012eeaa | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-67fa8e9148 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-0448a677c0 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTtmJQ5"} | None |  |
| q-c735fdc10b | triage T1056 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZWqNDf"} | None |  |
| q-bcd07afc36 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZWqNA3"} | None |  |
| q-9cd8214f19 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQD9QiN"} | None |  |
| q-3dce39382e | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQB61zZ"} | None |  |
| q-f93ede070d | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQB7V3u"} | None |  |
| q-ec193059fb | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQE_psP"} | None |  |
| q-613e2bb603 | triage T1110 step 1 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == 4648 \| KEEP @timestamp, host.name, user.name, process.executable, source.ip, win.TargetUserName, win.TargetServerName, _id, _index \| SORT @timestamp"} | ERROR |  |
| q-2292280587 | triage T1110 step 1 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == 4624 AND win.LogonType == 3 \| KEEP @timestamp, host.name, user.name, win.TargetUserName, source.ip, win.LogonProcessName, _id, _index \| SORT @timestamp"} | ERROR |  |
| q-de7862b697 | triage T1110 step 2 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4648\" \| KEEP @timestamp, host.name, user.name, process.executable, source.ip, win.TargetUserName, win.TargetServerName, _id, _index \| SORT @timestamp"} | 15 | F19, F20 |
| q-0adc5236df | triage T1110 step 2 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4624\" AND win.LogonType == \"3\" \| KEEP @timestamp, host.name, user.name, win.TargetUserName, source.ip, win.LogonProcessName, _id, _index \| SORT @timestamp"} | 218 |  |
| q-ea9d100b10 | triage T1110 step 3 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4624\" AND win.LogonType == \"3\" AND win.TargetUserName != *\"$\" \| KEEP @timestamp, host.name, user.name, win.TargetUserName, source.ip, win.LogonProcessName, _id, _… | ERROR |  |
| q-82c46c5961 | triage T1110 step 3 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4776\" OR event.code == \"4771\" OR event.code == \"4625\" \| KEEP @timestamp, host.name, user.name, win.TargetUserName, win.Status, win.ErrorCode, source.ip, _id, _ind… | ERROR |  |
| q-6e5412cefb | triage T1110 step 4 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4624\" AND win.LogonType == \"3\" AND win.TargetUserName NOT LIKE \"*$\" \| KEEP @timestamp, host.name, user.name, win.TargetUserName, source.ip, win.LogonProcessName, … | 20 | F20 |
| q-51fffcbe1b | triage T1110 step 4 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4776\" OR event.code == \"4771\" OR event.code == \"4625\" \| KEEP @timestamp, host.name, user.name, win.TargetUserName, win.Status, source.ip, _id, _index \| SORT @tim… | 1 |  |
| q-6c515900f3 | triage T1110 step 5 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVn1FNc"} | None | F17 |
| q-b6ccdbf000 | triage T1110 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (process.command_line LIKE \"*psexec*\" OR process.command_line LIKE \"*PSEXESVC*\" OR process.executable LIKE \"*PSEXESVC*\") \| KEEP @timestamp, host.name, user… | 4 | F20 |
| q-7d06caaeaf | triage T1110 step 6 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (process.command_line LIKE \"*pbeesly*\" OR process.command_line LIKE \"*net use*\" OR process.command_line LIKE \"*net.exe*\" OR process.command_line LIKE \"*run… | 15 | F18 |
| q-b9c7821c57 | triage T1110 step 6 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND win.TargetImage LIKE \"*lsass*\" AND win.SourceImage LIKE \"*PowerShell*\" \| KEEP @timestamp, host.name, user.name, win.SourceImage, win.TargetImage, win.Grante… | 4 |  |
| q-fb4a362a7a | triage T1110 step 7 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gj"} | None | F19 |
| q-a0370dd50b | triage T1110 step 7 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (win.ScriptBlockText LIKE \"*Invoke-Mimikatz*\" OR win.ScriptBlockText LIKE \"*lsass*\" OR win.ScriptBlockText LIKE \"*DumpCreds*\" OR win.ScriptBlockText … | 6 | F21 |
| q-994c3ed7f2 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVn1FNc"} | None |  |
| q-d402881804 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVn1FNc"} | None |  |
| q-001d7558e1 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVn1FNc"} | None |  |
| q-9fdc58ffe1 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTVGglR"} | None |  |
| q-f42d3cd0fb | triage T1110 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTVGglR"} | None |  |
| q-ad23d3d153 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gj"} | None |  |
| q-425f6cce7b | triage T1110 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gj"} | None |  |
| q-739297e658 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gj"} | None |  |
| q-0b2b84c84e | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ev8p"} | None |  |
| q-cbe6df6cdd | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ev9J"} | None |  |
| q-9d7354fc59 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ev8p"} | None |  |
| q-f0bf1f8b9a | triage T1110 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUGBlWZ"} | None |  |
| q-8633bc1c72 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7FP8C"} | None |  |
| q-fabcde12ec | triage T1110 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSmWPy"} | None |  |
| q-75d260cf1d | triage T1110 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-d8df1fa281 | triage T1111 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZCgBha"} | None | F23 |
| q-1525a0650a | triage T1111 step 1 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ev8p"} | None |  |
| q-e0dbf514cb | triage T1111 step 1 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND win.TargetImage:C\\:\\\\windows\\\\system32\\\\lsass.exe", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 326 |  |
| q-351d4194f5 | triage T1111 step 2 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND win.ScriptBlockText:*Invoke-Exfil*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "p… | 2 | F23 |
| q-8034840eed | triage T1111 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:C\\:\\\\windows\\\\system32\\\\lsass.exe AND (process.executable:*powershell* OR process.executable:*wsmprovhost*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.na… | 3 | F22 |
| q-96e50fca58 | triage T1111 step 2 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4648", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 15 |  |
| q-9b536a1c93 | triage T1111 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None | F24 |
| q-06ac9a10f9 | triage T1111 step 3 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4624 AND win.TargetUserName:pbeesly", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 30 |  |
| q-2e3279c605 | triage T1111 step 3 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:C\\:\\\\windows\\\\system32\\\\lsass.exe", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 326 |  |
| q-cc874f1740 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO9rO3Z"} | None |  |
| q-0e54aceedc | triage T1111 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOxeHN4"} | None |  |
| q-35ee92e8df | triage T1111 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8R_"} | None |  |
| q-0bc8b78aeb | triage T1111 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTtmJQ5"} | None |  |
| q-04a4451b9b | triage T1111 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSmmNB"} | None |  |
| q-8eb4db9ebd | triage T1111 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZCgBha"} | None |  |
| q-3c287a2fb7 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZCgBha"} | None |  |
| q-4e88a24dce | triage T1111 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZCgq7J"} | None |  |
| q-4993af6e39 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None |  |
| q-030cfc0862 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None |  |
| q-8ffdfcc01a | triage T1111 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None |  |
| q-1e206fb990 | triage T1187 step 1 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTmcl_4"} | None | F25 |
| q-255e893ea1 | triage T1187 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND file.path:*hostui*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 3 |  |
| q-7de543b77b | triage T1187 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND process.command_line:*hostui*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.comma… | 3 |  |
| q-b1d5b936ce | triage T1187 step 1 | search | {"dataset": "windows.powershell", "query": "win.ScriptBlockText:*hostui* OR win.ScriptBlockText:*StartUp* OR win.ScriptBlockText:*.lnk*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", … | 3 |  |
| q-34284b05c2 | triage T1187 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItKT-VVW"} | None |  |
| q-92502ee814 | triage T1187 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:3 AND (destination.port:445 OR destination.port:139)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "process.executable", "destination.ip", "destination.port", "user.name"], "size"… | 66 | F25 |
| q-07d1447f31 | triage T1187 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND process.executable:*hostui*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command… | 1 |  |
| q-d33119d321 | triage T1187 step 3 | search | {"dataset": "windows.sysmon", "query": "process.entity_id:{47ab858c-e737-5eac-fa00-000000000500} OR process.parent.entity_id:{47ab858c-e737-5eac-fa00-000000000500}", "time_from": null, "time_to": null, "fields": ["@timestamp", "event.code", "process.executable… | ERROR |  |
| q-9a97c4b753 | triage T1187 step 3 | search | {"dataset": "windows.security", "query": "event.code:5145 AND win.RelativeTargetName:*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "source.ip", "win.ShareName", "win.RelativeTargetName", "win.ObjectType"], "size": 5… | 121 | F25 |
| q-efff629740 | triage T1187 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE process.parent.entity_id == \"{47ab858c-e737-5eac-fa00-000000000500}\" OR process.entity_id == \"{47ab858c-e737-5eac-fa00-000000000500}\" \| KEEP @timestamp, event.code, process.executab… | 23 |  |
| q-47a815b27f | triage T1187 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 3 AND process.executable LIKE \"*hostui*\" \| KEEP @timestamp, host.name, process.executable, destination.ip, destination.port, _id, _index \| LIMIT 20"} | ERROR |  |
| q-cc0e3d563a | triage T1187 step 5 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOgLXSd"} | None |  |
| q-a8381adcc7 | triage T1187 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"3\" AND process.executable LIKE \"*hostui*\" \| KEEP @timestamp, host.name, process.executable, destination.ip, destination.port, _id, _index \| LIMIT 20"} | 0 |  |
| q-826029c550 | triage T1187 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"3\" AND process.executable LIKE \"*powershell*\" \| KEEP @timestamp, host.name, process.executable, destination.ip, destination.port, _id, _index \| LIMIT 30"} | 24 |  |
| q-2d6132c68d | triage T1187 step 6 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE (event.code == \"11\" AND (file.path LIKE \"*.scf\" OR file.path LIKE \"*.searchConnector-ms\" OR file.path LIKE \"*.library-ms\" OR file.path LIKE \"*.url\")) OR (event.code == \"1\" AN… | 7 | F25 |
| q-b8898737e2 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaKWxp5"} | None |  |
| q-9c07d5eaf3 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaKWxp5"} | None |  |
| q-a0c9b7679a | triage T1187 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaFQQtn"} | None |  |
| q-ab3e24d26b | triage T1187 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTqgghU"} | None |  |
| q-4bb45b6d77 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTqgghU"} | None |  |
| q-573653b5b7 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItQA64yf"} | ERROR |  |
| q-a397cc94b5 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTmcl_4"} | None |  |
| q-35e40099a3 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItPDyDoS"} | None |  |
| q-119f5f6767 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8RH"} | None |  |
| q-48ace60116 | triage T1187 step 8 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQA64yf"} | None | F25 |
| q-b44c83d022 | triage T1212 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZWqNDf"} | None |  |
| q-64640fe575 | triage T1212 step 1 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 326 |  |
| q-0e0a32eacb | triage T1212 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND (win.GrantedAccess:0x1fffff OR win.GrantedAccess:0x1f3fff OR win.GrantedAccess:0x101001 OR win.GrantedAccess:0x1000000 OR win.GrantedAccess:0x3000)", "time_from": null, "time… | 9 | F26, F27 |
| q-261352909d | triage T1212 step 2 | aggregate | {"dataset": "windows.sysmon", "field": "win.SourceImage", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 326 |  |
| q-f6cac77ebf | triage T1212 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-1871f72e99 | triage T1212 step 3 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*MiniDump* OR win.ScriptBlockText:*Dump* OR win.ScriptBlockText:*Credential* OR win.ScriptBlockText:*sekurlsa* OR win.ScriptBlockText:*mimikatz*… | 3 |  |
| q-0f412c5714 | triage T1212 step 4 | search | {"dataset": "windows.powershell", "query": "host.name:scranton.dmevals.local AND event.code:4104 AND @timestamp:[2020-05-02T03:04:00.000Z TO 2020-05-02T03:07:00.000Z]", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "pro… | 35 | F26 |
| q-4aad6379e6 | triage T1212 step 4 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.SourceImage:*wsmprovhost*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "process.executable", "process.command_line", "win.SourceImage", "win.TargetImage", "win.Granted… | 120 | F27 |
| q-cbb876ff8e | triage T1212 step 5 | search | {"dataset": "windows.powershell", "query": "host.name:scranton.dmevals.local AND event.code:4104 AND @timestamp:[2020-05-02T03:05:00.000Z TO 2020-05-02T03:06:30.000Z]", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "pro… | 13 |  |
| q-43ac266c6d | triage T1212 step 5 | search | {"dataset": "windows.security", "query": "host.name:scranton.dmevals.local AND event.code:10", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "win.TargetImage", "win.SourceImage", "win.GrantedAccess", "win.ProcessName",… | 0 |  |
| q-99237dc957 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-1351c7cf5f | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-ba985a8786 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-4643c3049a | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gj"} | None |  |
| q-cc979ce19b | triage T1212 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-f2a7a4d013 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2MI"} | None |  |
| q-a712b9b2ee | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTYl"} | None |  |
| q-236f254836 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTYt"} | None |  |
| q-ec6e4dc819 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None |  |
| q-066445e404 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ef_w"} | None |  |
| q-2ec4815804 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ8FraW"} | None |  |
| q-42ce38b53f | triage T1212 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrogQ"} | None |  |
| q-aec148e13a | triage T1212 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrYhe"} | None |  |
| q-a17667a00e | triage T1539 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZCgBha"} | None |  |
| q-a68e3e35d2 | triage T1539 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRlFAc"} | None |  |
| q-5964e48229 | triage T1539 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*cookies*\" OR TO_LOWER(file.path) LIKE \"*login data*\" OR TO_LOWER(file.path) LIKE \"*web data*\") \| KEEP @timestamp, host.name, p… | 1 |  |
| q-e3ec76bbf0 | triage T1539 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND (TO_LOWER(win.TargetImage) LIKE \"*chrome*\" OR TO_LOWER(win.TargetImage) LIKE \"*edge*\" OR TO_LOWER(win.TargetImage) LIKE \"*firefox*\" OR TO_LOWER(win.TargetI… | 50 |  |
| q-0341a57ee8 | triage T1539 step 3 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE TO_LOWER(win.ObjectName) LIKE \"*cookies*\" OR TO_LOWER(win.ObjectName) LIKE \"*login data*\" OR TO_LOWER(win.ObjectName) LIKE \"*web data*\" OR TO_LOWER(win.ProcessName) LIKE \"*chrom… | 0 |  |
| q-d62e677e6a | triage T1539 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*cookies*\" OR TO_LOWER(file.path) LIKE \"*login data*\" OR TO_LOWER(file.path) LIKE \"*web data*\") \| STATS c = COUNT(*) BY process… | 1 |  |
| q-2723359a62 | triage T1539 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (file.path LIKE \"*Cookies*\" OR file.path LIKE \"*Login Data*\" OR file.path LIKE \"*Web Data*\") \| STATS c = COUNT(*) BY file.path \| SORT c DESC \| LIMIT 30"… | 1 |  |
| q-c32a17c06a | triage T1539 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*appdata*\" AND (TO_LOWER(file.path) LIKE \"*microsoft*edge*\" OR TO_LOWER(file.path) LIKE \"*google*chrome*\" OR TO_LOWER(file.path)… | 4 |  |
| q-3584b20c2b | triage T1539 step 5 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*cookie*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*session*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*login data*\" OR TO_LOWER(win.ScriptBlock… | 20 |  |
| q-004c88cbeb | triage T1539 step 5 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"http\" \| KEEP @timestamp, source.ip, destination.ip, url.original, http.request.method, user_agent.original, _id, _index \| LIMIT 30"} | 30 |  |
| q-f5a52e0461 | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOVAUl3"} | None |  |
| q-b30e011dd5 | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOVAUl3"} | None |  |
| q-b181d8a66d | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOYDXeb"} | None |  |
| q-729b169ac2 | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOYDXeb"} | None |  |
| q-59c4b61037 | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOVAUmm"} | None |  |
| q-9d2aec941a | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOZEq4k"} | None |  |
| q-1ded7a9107 | triage T1539 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZCgBha"} | None |  |
| q-4c76406ee3 | triage T1539 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRlFAc"} | None |  |
| q-9c2af4b2f6 | triage T1539 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrYi9"} | None |  |
| q-ad7ecf9bb2 | triage T1552 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None | F30 |
| q-8f038fff11 | triage T1552 step 1 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTkbkGF"} | None | F31 |
| q-a1c1cd5278 | triage T1552 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*.pfx OR file.path:*Downloads*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", … | 314 |  |
| q-c71d2c3aa5 | triage T1552 step 2 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Export-PfxCertificate* OR win.ScriptBlockText:*Get-PrivateKeys* OR win.ScriptBlockText:*cert:\\\\LocalMachine*)", "time_from": null, "time_to": null, "fields": ["@timestamp",… | ERROR |  |
| q-32d2ba4a11 | triage T1552 step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == 4104 AND (win.ScriptBlockText LIKE \"*Export-PfxCertificate*\" OR win.ScriptBlockText LIKE \"*Get-PrivateKeys*\" OR win.ScriptBlockText LIKE \"*LocalMachine*\") \| KEEP… | ERROR |  |
| q-c6d0b958f8 | triage T1552 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 11 AND file.path LIKE \"*.pfx\" \| KEEP @timestamp, host.name, process.executable, file.path, _id, _index"} | ERROR |  |
| q-45602f80c8 | triage T1552 step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (win.ScriptBlockText LIKE \"*Export-PfxCertificate*\" OR win.ScriptBlockText LIKE \"*Get-PrivateKeys*\") \| KEEP @timestamp, host.name, user.name, win.Scri… | 2 | F30, F33 |
| q-d07ecdb228 | triage T1552 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND file.path LIKE \"*.pfx\" \| KEEP @timestamp, host.name, process.executable, file.path, _id, _index"} | 1 | F30 |
| q-f9b62231aa | triage T1552 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (process.command_line LIKE \"*password*\" OR process.command_line LIKE \"*credential*\" OR process.command_line LIKE \"*passwordsDB*\" OR process.command_line LIK… | 0 |  |
| q-1da61d68f2 | triage T1552 step 5 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (win.ScriptBlockText LIKE \"*password*\" OR win.ScriptBlockText LIKE \"*credential*\" OR win.ScriptBlockText LIKE \"*passwordsDB*\" OR win.ScriptBlockText … | 3 | F31 |
| q-3eb505415c | triage T1552 step 6 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2MI"} | None |  |
| q-47d62e30ec | triage T1552 step 6 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCjbV"} | None | F31 |
| q-c5e80b27f0 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-379f73a4b3 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-65d4eca483 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-a8a20dfc71 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTkbEF9"} | None |  |
| q-68fc30fee2 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTkbEF9"} | None |  |
| q-4ba4977f33 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2MI"} | None |  |
| q-4c8377a954 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTkbkGF"} | None |  |
| q-409b8dd97b | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTkbkGF"} | None |  |
| q-53ad47fd5a | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCjbV"} | None |  |
| q-102f5bdda7 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO9rO3Z"} | None |  |
| q-75e47e3fdc | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItThYt63"} | None |  |
| q-395d668d06 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-43b6337401 | triage T1552 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrog6"} | None |  |
| q-d7719dd4d5 | triage T1555 step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 10 AND win.TargetImage LIKE \"*lsass*\" \| STATS cnt = COUNT(*) BY process.executable, win.GrantedAccess, host.name \| SORT cnt DESC \| LIMIT 50"} | ERROR |  |
| q-73f5d2e5aa | triage T1555 step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 10 AND win.TargetImage LIKE \"*lsass*\" AND win.GrantedAccess IN (\"0x1fffff\", \"0x101001\", \"0x1f3fff\", \"0x1000000\", \"0x3000\", \"0x1400\") \| KEEP @timestamp, host.… | ERROR |  |
| q-c336f38665 | triage T1555 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND win.TargetImage LIKE \"*lsass*\" \| STATS cnt = COUNT(*) BY process.executable, win.GrantedAccess, host.name \| SORT cnt DESC \| LIMIT 50"} | 18 |  |
| q-1492f15493 | triage T1555 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND win.TargetImage LIKE \"*lsass*\" AND win.GrantedAccess IN (\"0x1fffff\", \"0x101001\", \"0x1f3fff\", \"0x1000000\", \"0x3000\", \"0x1400\") \| KEEP @timestamp, h… | 33 | F35 |
| q-c00944eed3 | triage T1555 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gj"} | None |  |
| q-07443b649c | triage T1555 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None |  |
| q-8350735139 | triage T1555 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" \| KEEP @timestamp, host.name, user.name, process.executable, process.command_line, process.parent.executable, _id, _index \| SORT @timestamp ASC \| LIMIT 60"} | 60 | F39 |
| q-630adc1242 | triage T1555 step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (win.ScriptBlockText LIKE \"*monkey*\" OR win.ScriptBlockText LIKE \"*IEX*\" OR win.ScriptBlockText LIKE \"*FromBase64*\" OR win.ScriptBlockText LIKE \"*Do… | 7 | F39 |
| q-0ef5946f95 | triage T1555 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (file.path LIKE \"*Login Data*\" OR file.path LIKE \"*Cookies*\" OR file.path LIKE \"*Web Data*\" OR file.path LIKE \"*Local State*\" OR file.path LIKE \"*logins… | 1 | F36, F38 |
| q-142d13836c | triage T1555 step 5 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZCgBha"} | None | F39 |
| q-5b33734a74 | triage T1555 step 5 | esql | {"query": "FROM logs-windows.security METADATA _id, _index \| WHERE event.code == \"4688\" AND (process.command_line LIKE \"*cmdkey*\" OR process.command_line LIKE \"*vault*\" OR process.command_line LIKE \"*credential*\" OR process.command_line LIKE \"*Login … | ERROR |  |
| q-fda0ee873b | triage T1555 step 6 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4688\" AND (process.command_line LIKE \"*cmdkey*\" OR process.command_line LIKE \"*vault*\" OR process.command_line LIKE \"*credential*\" OR process.command_line LIKE \… | 6 | F39 |
| q-bd1e6e4e31 | triage T1555 step 6 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"13\" AND (registry.path LIKE \"*Vault*\" OR registry.path LIKE \"*Credential*\" OR registry.path LIKE \"*Credentials*\") \| KEEP @timestamp, host.name, user.name, process… | 11 | F37 |
| q-2b22883490 | triage T1555 step 7 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE (event.code == \"10\" AND (win.TargetImage LIKE \"*chrome*\" OR win.TargetImage LIKE \"*firefox*\" OR win.TargetImage LIKE \"*iexplore*\" OR win.TargetImage LIKE \"*msedge*\" OR win.Targ… | 0 |  |
| q-5cd193526e | triage T1555 step 7 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"13\" AND (registry.path LIKE \"*sdclt*\" OR registry.path LIKE \"*CurrentVersion\\\\App Paths*\" OR registry.path LIKE \"*WindowsBackup*\" OR registry.path LIKE \"*Folder… | ERROR |  |
| q-dec4d7a6ae | triage T1555 step 8 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"13\" AND registry.path LIKE \"*sdclt*\" \| KEEP @timestamp, host.name, process.executable, registry.path, registry.data.strings, _id, _index \| LIMIT 30"} | 0 |  |
| q-d2cd83ca01 | triage T1555 step 8 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (file.path LIKE \"*monkey.png*\" OR file.path LIKE \"*OfficeSupplies*\" OR file.path LIKE \"*3aka3*\" OR file.path LIKE \"*victim*\") \| KEEP @timestamp, host.na… | 2 | F39 |
| q-148ab447a8 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO4kjEa"} | None |  |
| q-8d9f58b9fc | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO9re0E"} | None |  |
| q-dd91678d1a | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOqWMLr"} | None |  |
| q-b571e6aa6f | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOVAUl3"} | None |  |
| q-1da20c85d2 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOxeHN4"} | None |  |
| q-a3b6db3d00 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO9rO3Z"} | None |  |
| q-1abb269282 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8R_"} | None |  |
| q-85a2146be5 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOVAUl3"} | None |  |
| q-5ef398a9d9 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQE_psP"} | None |  |
| q-bef40d50c4 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZWqNDf"} | None |  |
| q-5006d5f719 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZCgBha"} | None |  |
| q-4b5b83f064 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaFQQsu"} | None |  |
| q-7fd9e09ed7 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTWI7pZ"} | None |  |
| q-00332e75e6 | triage T1556 step 1 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 326 |  |
| q-ed2ad44189 | triage T1556 step 1 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 326 |  |
| q-b73bcef696 | triage T1556 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND (win.GrantedAccess:0x1fffff OR win.GrantedAccess:0x101001 OR win.GrantedAccess:0x1f3fff OR win.GrantedAccess:0x1000000 OR win.GrantedAccess:0x3000)", "time_from": null, "time… | 9 |  |
| q-2d8115dbfd | triage T1556 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND process.executable:*wsmprovhost*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "process.executable", "win.GrantedAccess", "win.SourceImage", "us… | 1 |  |
| q-fef986f028 | triage T1556 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None | F40 |
| q-07120a044b | triage T1556 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None | F40 |
| q-c25dd214f4 | triage T1556 step 4 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*MiniDump* OR win.ScriptBlockText:*DumpCred* OR win.ScriptBlockText:*Invoke-Mimikatz* OR win.ScriptBlockText:*sekurlsa*)", "time_from": null, "t… | 0 |  |
| q-6ffaa00602 | triage T1556 step 4 | search | {"dataset": "windows.security", "query": "event.code:4648", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "process.executable", "win.TargetUserName", "win.TargetDomainName", "source.ip", "message"], "size": 15, "sort": … | 15 | F41 |
| q-d96b152f78 | triage T1556 step 5 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND host.name:scranton.dmevals.local", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "win.ScriptBlockText"], "size": 15, "sort": "@timestamp"} | 146 |  |
| q-f3d0caef78 | triage T1556 step 5 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*lsass* OR process.command_line:*dump* OR process.command_line:*sekurlsa* OR process.command_line:*procdump*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.na… | 1 |  |
| q-e11e359d70 | triage T1556 step 6 | search | {"dataset": "windows.other", "query": "event.code:7045 OR event.code:7040", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "win.ServiceName", "win.ImagePath", "win.ServiceType", "message"], "size": 15, "sort": "asc"} | 9 |  |
| q-dc5b538fdb | triage T1556 step 6 | search | {"dataset": "windows.security", "query": "event.code:4739 OR event.code:5136 OR event.code:4657", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "win.ObjectName", "win.ObjectValueName", "win.NewValue", "win.OperationType… | 36 | F42, F43, F44, F45, F46 |
| q-2e5f647763 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-617b79f278 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-afa779e22c | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-e4f48e4fb0 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None |  |
| q-ae5924b9cb | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None |  |
| q-363e18650a | triage T1556 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ev8p"} | None |  |
| q-21ee70ebb1 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ev8p"} | None |  |
| q-b63c95ec1d | triage T1556 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaKXhpQ"} | None |  |
| q-9ee0ff6a5f | triage T1556 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ6CoZN"} | None |  |
| q-f53b7bee25 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVt5I2Y"} | None |  |
| q-d978100d3e | triage T1556 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVv6C9m"} | None |  |
| q-fa4beb3e67 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ6CoZN"} | None |  |
| q-08951fca8d | triage T1556 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVw6X-9"} | None |  |
| q-09a8dd31f0 | triage T1557 step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"3\" AND (destination.port == 445 OR destination.port == 139) \| KEEP @timestamp, host.name, process.executable, destination.ip, destination.port, _id, _index \| SORT @tim… | 66 | F47 |
| q-fb36cc0245 | triage T1557 step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"22\" AND (win.QueryStatus != \"0\") \| KEEP @timestamp, host.name, process.executable, win.QueryName, win.QueryResults, win.QueryStatus, _id, _index"} | 7 | F48 |
| q-9ecd40c6dd | triage T1557 step 2 | esql | {"query": "FROM logs-windows.other-default METADATA _id, _index \| WHERE event.code == \"5858\" OR event.code == \"5857\" OR event.code == \"5860\" \| KEEP @timestamp, host.name, event.code, message, win.param1, win.param2, win.param3, _id, _index \| LIMIT 20"… | 20 |  |
| q-b1569faa75 | triage T1557 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" \| KEEP @timestamp, host.name, process.executable, process.command_line, process.parent.executable, user.name, _id, _index \| LIMIT 50"} | 50 |  |
| q-b22b021232 | triage T1557 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOcHa1B"} | None |  |
| q-41d63715cd | triage T1557 step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" \| KEEP @timestamp, host.name, user.name, win.ScriptBlockText, _id, _index \| LIMIT 30"} | 30 | F48 |
| q-6da5ca386a | triage T1557 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"3\" AND (destination.port == 67 OR destination.port == 68 OR destination.port == 137 OR destination.port == 138 OR destination.port == 5355) \| KEEP @timestamp, host.name… | 24 | F49, F50 |
| q-3efaa8bf6a | triage T1557 step 4 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"5156\" AND network.transport == \"udp\" \| KEEP @timestamp, host.name, process.executable, source.ip, destination.ip, destination.port, _id, _index \| LIMIT 30"} | ERROR |  |
| q-3d33787a44 | triage T1557 step 5 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"5156\" \| KEEP @timestamp, host.name, process.executable, source.ip, destination.ip, destination.port, win.Protocol, _id, _index \| LIMIT 40"} | 40 |  |
| q-7b568af01d | triage T1557 step 5 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4624\" \| KEEP @timestamp, host.name, win.LogonType, win.TargetUserName, win.IpAddress, win.AuthenticationPackageName, win.LogonProcessName, _id, _index \| LIMIT 40"} | 40 | F47 |
| q-0e5380a852 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTqgghU"} | None |  |
| q-ceaf23ec83 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTqgghU"} | None |  |
| q-75f5dc20e3 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVcvuSE"} | None |  |
| q-428f44bc93 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVcvuSE"} | None |  |
| q-a436d4cd90 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOmQp3C"} | None |  |
| q-1bc43780e6 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOmQp3C"} | None |  |
| q-583b6df7c9 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO2ikE2"} | None |  |
| q-1e1249d0a8 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRkUVV"} | None |  |
| q-cf5bc6267b | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItObGa1g"} | None |  |
| q-b52bf1a2ff | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItObGa1g"} | None |  |
| q-ae8e54f975 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItPL74K2"} | None |  |
| q-19b43f4ee3 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItPL74K2"} | None |  |
| q-0298da204c | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItPL74K2"} | None |  |
| q-69b9ea73ec | triage T1558 step 1 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-928d96e7a2 | triage T1558 step 1 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass* AND NOT win.GrantedAccess:(0x1000 OR 0x1400)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 9 |  |
| q-6364213c8e | triage T1558 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND win.GrantedAccess:(0x1fffff OR 0x101001 OR 0x1f3fff OR 0x1000000 OR 0x3000)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "even… | 9 | F51 |
| q-c809bfdf32 | triage T1558 step 2 | search | {"dataset": "windows.security", "query": "event.code:4769", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 28 |  |
| q-614adc9cb3 | triage T1558 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None | F51 |
| q-711a195725 | triage T1558 step 3 | search | {"dataset": "windows.powershell", "query": "host.name:scranton.dmevals.local AND event.code:(4104 OR 4103)", "time_from": null, "time_to": null, "fields": ["@timestamp", "event.code", "win.ScriptBlockText", "process.command_line", "user.name"], "size": 30, "so… | 4192 |  |
| q-8337b97a90 | triage T1558 step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND @timestamp >= \"2020-05-02T03:04:00.000Z\" AND @timestamp <= \"2020-05-02T03:07:00.000Z\" \| KEEP @timestamp, host.name, user.name, win.ScriptBlockText, _i… | 35 | F51 |
| q-cbbdf8e0f5 | triage T1558 step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*lsass*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*mimikatz*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*invoke-*\" OR TO_LOWER(win.ScriptBlockTex… | 20 |  |
| q-91662072e0 | triage T1558 step 5 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4769\" OR event.code == \"4768\" \| KEEP @timestamp, host.name, user.name, win.TargetUserName, win.TicketEncryptionType, win.TicketOptions, win.PreAuthType, win.Service… | 42 | F52, F53, F55 |
| q-2f040c1325 | triage T1558 step 5 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4672\" AND user.name LIKE \"*pbeesly*\" \| KEEP @timestamp, host.name, user.name, win.PrivilegeList, _id, _index \| LIMIT 20"} | 19 | F54 |
| q-2ea6fdcfb4 | triage T1558 step 6 | aggregate | {"dataset": "windows.security", "field": "win.PreAuthType", "query": "event.code:4768", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 14 |  |
| q-5e33ddf67c | triage T1558 step 6 | aggregate | {"dataset": "windows.security", "field": "win.TicketEncryptionType", "query": "event.code:4769", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 28 |  |
| q-c2bb1547ea | triage T1558 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-cb3be66baf | triage T1558 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-419bb9945b | triage T1558 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gj"} | None |  |
| q-c1e08b9e9f | triage T1558 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-87a4dc41d1 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRk1C1"} | None |  |
| q-62e9a19fa6 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ef_y"} | None |  |
| q-7b8e386b4f | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ef_y"} | None |  |
| q-e24730af2b | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItV3-aVk"} | None |  |
| q-a41f181bc5 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVn1FMZ"} | None |  |
| q-09f9a03c28 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItV3-aXJ"} | None |  |
| q-f2d4f028e3 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaKXhpM"} | None |  |
| q-6b8b2bd15b | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVn01Ns"} | None |  |
| q-0bd43dbae0 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItV3-aUM"} | None |  |
| q-196b23d572 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItV3-aUJ"} | None |  |
| q-cf001e04b8 | triage T1606 step 1 | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8TL"} | None | F56 |
| q-dac60f9a13 | triage T1606 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRllBR"} | None | F57 |
| q-7b714ddaa6 | triage T1606 step 1 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOVAUl3"} | None | F57 |
| q-f6e07f6e2d | triage T1606 step 1 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ev8p"} | None | F56 |
| q-5a13b48d76 | triage T1606 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE user.name == \"pbeesly\" AND event.code == \"1\" \| KEEP @timestamp, host.name, process.executable, process.command_line, process.parent.executable, _id, _index \| LIMIT 50"} | 50 |  |
| q-baf3da9be7 | triage T1606 step 2 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" \| KEEP @timestamp, host.name, user.name, win.Path, _id, _index \| LIMIT 50"} | 50 |  |
| q-310b9121ff | triage T1606 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE process.executable LIKE \"*javamtsup*\" OR process.executable LIKE \"*hostui*\" OR process.command_line LIKE \"*javamtsup*\" \| KEEP @timestamp, host.name, user.name, process.executable,… | 30 | F56 |
| q-f740ff3dc5 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8TL"} | None |  |
| q-5d5713fdae | triage T1606 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ev8p"} | None |  |
| q-e585b4c867 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItKT-VVW"} | None |  |
| q-e8374539e9 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOVAUl3"} | None |  |
| q-29bc0fc178 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOVAUl3"} | None |  |
| q-7d24779ce5 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRllBR"} | None |  |
| q-da8bd1453b | triage T1606 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaKXhpQ"} | None |  |
| q-a617dc15ec | triage T1606 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8Rc"} | None |  |
| q-2ac8312a67 | triage T1621 step 1 | search | {"dataset": "windows.powershell", "query": "win.ScriptBlockText:(*MFA* OR *2FA* OR *Authenticator* OR *Multi-Factor* OR *multifactor* OR *OneTime* OR *OTP* OR *verification* OR *challenge*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.n… | 0 |  |
| q-4e7073c183 | triage T1621 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:3 AND (destination.port:443 OR destination.port:80)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "process.executable", "destination.ip", "destination.port", "source.… | 54 | F59 |
| q-2fbf5ab3f7 | triage T1621 step 2 | aggregate | {"dataset": "windows.powershell", "field": "process.command_line", "query": "event.code:4104", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 414 |  |
| q-e16dc66657 | triage T1621 step 2 | search | {"dataset": "zeek", "query": "event.action:kerberos", "time_from": null, "time_to": null, "fields": ["@timestamp", "source.ip", "destination.ip", "zeek.client", "zeek.service", "zeek.success", "zeek.error_msg", "zeek.request_type"], "size": 35, "sort": "asc"} | 35 | F59 |
| q-d2391cc33d | triage T1621 step 3 | search | {"dataset": "windows.powershell", "query": "process.command_line:*PsExec*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "so… | 4 |  |
| q-679c71bea7 | triage T1621 step 3 | aggregate | {"dataset": "windows.other", "field": "event.code", "query": "*", "time_from": null, "time_to": null, "size": 40, "sub_field": null} | 216 |  |
| q-406b05c24d | triage T1621 step 4 | search | {"dataset": "windows.other", "query": "message:(*MFA* OR *multi-factor* OR *multifactor* OR *authenticator* OR *one-time* OR *OTP* OR *verification code* OR *push notification*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "obser… | 9 |  |
| q-2be2040908 | triage T1621 step 4 | search | {"dataset": "windows.security", "query": "event.code:4624 AND win.LogonType:3", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "win.TargetUserName", "win.IpAddress", "win.LogonType", "win.AuthenticationPackageName"], "size": 20, "sor… | 218 |  |
| q-39d8971118 | triage T1621 step 5 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZLhZrg"} | None | F60 |
| q-74fbba690e | triage T1621 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItT-3yn1"} | None |  |
| q-fe0f870642 | triage T1621 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItT70Tl_"} | None |  |
| q-097bfe4360 | triage T1621 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItT-3yn1"} | None |  |
| q-f77c86d175 | triage T1621 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrYi0"} | None |  |
| q-f46070e072 | triage T1621 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrIjh"} | None |  |
| q-04c12e7d1e | triage T1621 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZLhZrg"} | None |  |
| q-442a45dea2 | triage T1621 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZLhZrg"} | None |  |
| q-6ab47a7afe | triage T1621 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZLhZrg"} | None |  |
| q-839499f9d5 | triage T1649 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-1640e491c3 | triage T1649 step 1 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTkbEF9"} | None |  |
| q-e9894dc0ee | triage T1649 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND TO_LOWER(file.path) LIKE \"*.pfx\" \| KEEP @timestamp, host.name, user.name, process.executable, file.path, _id, _index"} | 1 |  |
| q-b607a4e37c | triage T1649 step 2 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*export-pfxcertificate*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*get-privatekeys*\" OR TO_LOWER(win.ScriptBlockText… | ERROR |  |
| q-dcc62bace5 | triage T1649 step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*export-pfxcertificate*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*get-privatekeys*\") \| KEEP @timestamp, host.name,… | 2 | F61 |
| q-1f39e86fb6 | triage T1649 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND process.pid == \"3876\" \| KEEP @timestamp, host.name, user.name, process.executable, process.command_line, process.parent.executable, process.parent.command_line… | ERROR |  |
| q-241bd29e3d | triage T1649 step 4 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRlVDe"} | None |  |
| q-8211bb3f26 | triage T1649 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND process.pid == 3876 \| KEEP @timestamp, host.name, user.name, process.executable, process.command_line, process.parent.executable, process.parent.command_line, _i… | 2 | F61 |
| q-622d2ae3de | triage T1649 step 5 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTvoSAW"} | None |  |
| q-48ba4855d5 | triage T1649 step 5 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ6CoZN"} | None |  |
| q-aad6cc0aef | triage T1649 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-e6f9ff40c0 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-4e4d6da1b1 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRlVDe"} | None |  |
| q-7295e7c28e | triage T1649 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTkbEF9"} | None |  |
| q-0953c1045e | triage T1649 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTvoSAW"} | None |  |
| q-867935d086 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ6CoZN"} | None |  |
| q-d31b99db31 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ6CoZN"} | None |  |
| q-41e2d996b2 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVt5I2Y"} | None |  |
| q-ce4f590e48 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ef_w"} | None |  |
| q-c7ec061dc9 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ef_w"} | None |  |
| q-eb595fb3b7 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-54c2c8aaa7 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gj"} | None |  |
| q-cc14db3a7c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-64f5356e91 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKB-"} | None |  |
| q-15c38d4950 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKB-"} | None |  |
| q-5594c1a9ad | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None |  |
| q-7426c7d753 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None |  |
| q-0e5e660f5c | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-302661e9a8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-8637cce7e7 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None |  |
| q-a3e0d45a77 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKB-"} | None |  |
| q-32e315d21f | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZKhD3z"} | None |  |
| q-f6b9ec8bdd | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItKT-FUX"} | None |  |
| q-91bd603aed | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO9rO3D"} | None |  |
| q-76964b2cf2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTVGQnT"} | None |  |
| q-76267203b1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO-r7Fc"} | None |  |
| q-29e373f081 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTqhQkl"} | None |  |
| q-4cfbe27d44 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVcvuSc"} | None |  |
| q-4c18a6d72a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTVGQnT"} | None |  |
| q-847eea0661 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO-r7Fc"} | None |  |
| q-88a4e1d26a | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVt4o2y"} | None |  |
| q-96c44cf7a1 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVt4o2y"} | None |  |
| q-d95917692e | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVr2bv9"} | None |  |
| q-191ac21e0f | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVr2bv9"} | None |  |
| q-149986e9c8 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVz8aWs"} | None |  |
| q-a8afdf3030 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVr2bu5"} | None |  |
| q-2b1e2535ef | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVt4o2y"} | None |  |
| q-e840825b8f | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVr2bv9"} | None |  |
| q-0b486b0820 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItV19xlz"} | None |  |
| q-7c0f68860f | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrog0"} | None |  |
| q-b462abfd66 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNn1uOFchItY0uF-5"} | None |  |
| q-2a712009f3 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrYih"} | None |  |
| q-37744e6694 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ev9A"} | None |  |
| q-78abd12021 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ef_B"} | None |  |
| q-7b34794e8f | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaFQQsu"} | None |  |
| q-fbaeba003d | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrYMQT"} | None |  |
| q-d886a20be2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQE_psP"} | None |  |
| q-014cf18723 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQE_psP"} | None |  |
| q-24c5217bbb | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaKXhpR"} | None |  |
| q-65073834ba | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaKXhpR"} | None |  |
| q-f30b243ae6 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-3292d3bab0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-b0ce37ac70 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-81eab0fb82 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-d51eb2700d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTtmJQ5"} | None |  |
| q-e883feeab8 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZWqNDf"} | None |  |
| q-5e1c06802d | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZWqNA3"} | None |  |
| q-3117df744b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQD9QiN"} | None |  |
| q-d4c39b758b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQB61zZ"} | None |  |
| q-2ecfc23f6d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQB7V3u"} | None |  |
| q-a877be540a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQE_psP"} | None |  |
| q-2e72a64326 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVn1FNc"} | None |  |
| q-ffa50fa572 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVn1FNc"} | None |  |
| q-410dcb5e19 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVn1FNc"} | None |  |
| q-c9cd6a6858 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTVGglR"} | None |  |
| q-b32643f672 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTVGglR"} | None |  |
| q-c26f66b247 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gj"} | None |  |
| q-e46bc953c0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gj"} | None |  |
| q-aa63f04c2c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gj"} | None |  |
| q-18d9760c35 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ev8p"} | None |  |
| q-be3407c4fc | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ev9J"} | None |  |
| q-4a9150325b | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ev8p"} | None |  |
| q-eb0cc42357 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUGBlWZ"} | None |  |
| q-c8040662e4 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7FP8C"} | None |  |
| q-1395719f04 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSmWPy"} | None |  |
| q-ac155346c7 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-58a1a6290b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO9rO3Z"} | None |  |
| q-93d60b791c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOxeHN4"} | None |  |
| q-756dfe3360 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8R_"} | None |  |
| q-10dc87b922 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTtmJQ5"} | None |  |
| q-4d9e640292 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSmmNB"} | None |  |
| q-30175b0d64 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZCgBha"} | None |  |
| q-88085d7a58 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZCgBha"} | None |  |
| q-9cd2c39b0d | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZCgq7J"} | None |  |
| q-875984a86b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None |  |
| q-3a38791407 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None |  |
| q-22daa9185d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None |  |
| q-dc3d2c90db | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaKWxp5"} | None |  |
| q-8f69d759eb | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaKWxp5"} | None |  |
| q-c3204709c0 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaFQQtn"} | None |  |
| q-c3b2e003b0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTqgghU"} | None |  |
| q-48eb3458c1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTqgghU"} | None |  |
| q-a28241d8f4 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQA64yf"} | None |  |
| q-3342a903ab | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTmcl_4"} | None |  |
| q-1009261814 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItPDyDoS"} | None |  |
| q-fb637dd6a7 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8RH"} | None |  |
| q-f4e1eda564 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-ae17adebfd | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-b54273f92c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-2d410de842 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gj"} | None |  |
| q-46fb219c7d | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-1ba9632060 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2MI"} | None |  |
| q-033a76c755 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTYl"} | None |  |
| q-6fab103b7e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTYt"} | None |  |
| q-5f47c11884 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None |  |
| q-37e879b0ae | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ef_w"} | None |  |
| q-156c1e91dd | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ8FraW"} | None |  |
| q-c40a971549 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrogQ"} | None |  |
| q-be437d9d3a | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrYhe"} | None |  |
| q-67891cfeeb | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-4c51288b4f | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-78f1fc6f62 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-f43df57d3c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTkbEF9"} | None |  |
| q-929beeb51e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTkbEF9"} | None |  |
| q-92e716e697 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2MI"} | None |  |
| q-955e580f49 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTkbkGF"} | None |  |
| q-c054c7f3a9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTkbkGF"} | None |  |
| q-5238e3c1e9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCjbV"} | None |  |
| q-05c2dbc56b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO9rO3Z"} | None |  |
| q-ec68b52818 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItThYt63"} | None |  |
| q-cfa4cf89d8 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-dcfc6cd4a5 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrog6"} | None |  |
| q-72a16444a3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO4kjEa"} | None |  |
| q-2233c3849e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO9re0E"} | None |  |
| q-c6ece7b8c2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOqWMLr"} | None |  |
| q-53faf1724a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOVAUl3"} | None |  |
| q-5748c3b22d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOxeHN4"} | None |  |
| q-2b1ec4e8a6 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO9rO3Z"} | None |  |
| q-39c219bf0d | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8R_"} | None |  |
| q-d84b19934d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOVAUl3"} | None |  |
| q-27510729e0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQE_psP"} | None |  |
| q-e5f724c37b | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZWqNDf"} | None |  |
| q-e164834bc2 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZCgBha"} | None |  |
| q-9a19279cf4 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaFQQsu"} | None |  |
| q-264156cab9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTWI7pZ"} | None |  |
| q-56a51787cc | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-b4fb8aabb8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-d2aa72e66a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-eacd8471e8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None |  |
| q-1e2227bb56 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None |  |
| q-af7b73fb9b | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ev8p"} | None |  |
| q-584832b493 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ev8p"} | None |  |
| q-0293e84640 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaKXhpQ"} | None |  |
| q-f75530ec25 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ6CoZN"} | None |  |
| q-f0ca2471f8 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVt5I2Y"} | None |  |
| q-b88ab75d0c | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVv6C9m"} | None |  |
| q-999eeedcd6 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ6CoZN"} | None |  |
| q-ca9c9dc229 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVw6X-9"} | None |  |
| q-a8cd8c48d0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTqgghU"} | None |  |
| q-b5766e8c8b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTqgghU"} | None |  |
| q-b0232967a6 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVcvuSE"} | None |  |
| q-682ff5cb5c | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVcvuSE"} | None |  |
| q-aab103c798 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOmQp3C"} | None |  |
| q-691b9b693e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOmQp3C"} | None |  |
| q-10c5b78399 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO2ikE2"} | None |  |
| q-b37fe65368 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRkUVV"} | None |  |
| q-7e1f756bb7 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItObGa1g"} | None |  |
| q-ecb9c074f2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItObGa1g"} | None |  |
| q-bd7a3282aa | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItPL74K2"} | None |  |
| q-e1a11774db | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItPL74K2"} | None |  |
| q-aa694a659b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItPL74K2"} | None |  |
| q-21c3b361b7 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-a68723b394 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-dfd24c00c2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gj"} | None |  |
| q-c0aca6ad2f | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-983d7ef4b0 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRk1C1"} | None |  |
| q-383087c2df | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ef_y"} | None |  |
| q-c802069707 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ef_y"} | None |  |
| q-0ca1fa3444 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItV3-aVk"} | None |  |
| q-75b6bd6c25 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVn1FMZ"} | None |  |
| q-e37b57e3cf | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItV3-aXJ"} | None |  |
| q-3aee221d80 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaKXhpM"} | None |  |
| q-f9d12638c3 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVn01Ns"} | None |  |
| q-9bc1a5cf0e | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItV3-aUM"} | None |  |
| q-5534cdce17 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItV3-aUJ"} | None |  |
| q-c217cc2bff | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8TL"} | None |  |
| q-c9a13d7813 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ev8p"} | None |  |
| q-42424d403a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItKT-VVW"} | None |  |
| q-92fa318cf1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOVAUl3"} | None |  |
| q-1ee830a0ff | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOVAUl3"} | None |  |
| q-8ee4ffcd5d | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRllBR"} | None |  |
| q-e1961fc536 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaKXhpQ"} | None |  |
| q-aa207a2140 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8Rc"} | None |  |
| q-3e132f12e4 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItT-3yn1"} | None |  |
| q-daf9db0290 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItT70Tl_"} | None |  |
| q-84266cf995 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItT-3yn1"} | None |  |
| q-a62ea7f673 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrYi0"} | None |  |
| q-f9d0f3d6f8 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrIjh"} | None |  |
| q-bd25c6acec | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZLhZrg"} | None |  |
| q-0a18e03a2a | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZLhZrg"} | None |  |
| q-70d1977a5d | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZLhZrg"} | None |  |
| q-218941abc8 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-0b8678920b | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-beffb3f9f6 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRlVDe"} | None |  |
| q-5dcab17945 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTkbEF9"} | None |  |
| q-98f660e3b2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTvoSAW"} | None |  |
| q-8713eb3a57 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ6CoZN"} | None |  |
| q-145c860d74 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ6CoZN"} | None |  |
| q-90b91956e5 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVt5I2Y"} | None |  |
| q-60a4087924 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ef_w"} | None |  |
| q-ca502c27b0 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ef_w"} | None |  |
| q-9d977a9325 | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND host.name:\"nashua.dmevals.local\"", "time_from": "2020-05-02T02:54:29.430000+00:00", "time_to": "2020-05-02T03:26:40+00:00", "size": 100, "sub_field": "process.parent.exec… | 61 |  |
| q-a45e7e1c4b | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11 AND host.name:\"nashua.dmevals.local\"", "time_from": "2020-05-02T02:54:29.430000+00:00", "time_to": "2020-05-02T03:26:40+00:00", "size": 100, "sub_field": "process.executable"} | 248 |  |
| q-a917a46ad5 | pivot seed | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND host.name:\"nashua.dmevals.local\"", "time_from": "2020-05-02T02:54:29.430000+00:00", "time_to": "2020-05-02T03:26:40+00:00", "size": 100, "sub_field": "process.parent… | 63 |  |
| q-e72ad33e23 | pivot seed | aggregate | {"dataset": "windows.powershell", "field": "event.code", "query": "host.name:\"nashua.dmevals.local\"", "time_from": "2020-05-02T02:54:29.430000+00:00", "time_to": "2020-05-02T03:26:40+00:00", "size": 100, "sub_field": null} | 192 |  |
| q-f5cc5e40ca | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND host.name:\"scranton.dmevals.local\"", "time_from": "2020-05-02T02:40:56+00:00", "time_to": "2020-05-02T03:26:18+00:00", "size": 100, "sub_field": "process.parent.executabl… | 359 |  |
| q-00f6282b03 | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11 AND host.name:\"scranton.dmevals.local\"", "time_from": "2020-05-02T02:40:56+00:00", "time_to": "2020-05-02T03:26:18+00:00", "size": 100, "sub_field": "process.executable"} | 1274 |  |
| q-38511a2bf4 | pivot seed | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND host.name:\"scranton.dmevals.local\"", "time_from": "2020-05-02T02:40:56+00:00", "time_to": "2020-05-02T03:26:18+00:00", "size": 100, "sub_field": "process.parent.exec… | 370 |  |
| q-90ee01e845 | pivot seed | aggregate | {"dataset": "windows.powershell", "field": "event.code", "query": "host.name:\"scranton.dmevals.local\"", "time_from": "2020-05-02T02:40:56+00:00", "time_to": "2020-05-02T03:26:18+00:00", "size": 100, "sub_field": null} | 8602 |  |
| q-9fdf768fc4 | pivot step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND host.name:\"nashua.dmevals.local\" AND (process.executable:\"C:\\\\Windows\\\\Temp\\\\python.exe\" OR process.executable:\"C:\\\\Windows\\\\Temp\\\\Rar.exe\" OR process.executable:\"C:\\\\Windows\\\\Temp… | 9 | F64, F65, F66 |
| q-73197609f4 | pivot step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND host.name:\"nashua.dmevals.local\" AND (file.path:*python* OR file.path:*Rar* OR file.path:*sdelete* OR file.path:*PSEXESVC*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "file.path", … | 13 | F65, F66 |
| q-654aff37be | pivot step 2 | search | {"dataset": "windows.powershell", "query": "host.name:\"nashua.dmevals.local\" AND event.code:4104", "time_from": null, "time_to": null, "fields": ["@timestamp", "event.code", "powershell.file.script_block_text", "user.name"], "size": 15, "sort": "asc"} | 11 |  |
| q-3227ad8595 | pivot step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND host.name:\"nashua.dmevals.local\" AND (file.path:*working* OR file.path:*zip* OR file.path:*cred* OR file.path:*pass* OR file.path:*\\.pfx* OR file.path:*\\.txt*)", "time_from": null, "time_to": null, … | 3 | F64 |
| q-83e5840d01 | pivot step 3 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZLhqPR"} | None | F65 |
| q-e3e86779bd | pivot step 3 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZKhUGR"} | None |  |
| q-fe5d9a7eff | pivot step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTPBJnI"} | None | F65 |
| q-de85d7018d | pivot step 4 | search | {"dataset": "windows.powershell", "query": "host.name:\"nashua.dmevals.local\" AND event.code:4104 AND (win.ScriptBlockText:*cred* OR win.ScriptBlockText:*password* OR win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*Rar* OR win.ScriptBlockText:*zip* OR win… | 3 | F64 |
| q-ccde8c71ff | pivot step 4 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND host.name:\"scranton.dmevals.local\" AND (process.executable:\"C:\\\\Windows\\\\System32\\\\hostui.exe\" OR process.executable:\"C:\\\\Windows\\\\System32\\\\sdclt.exe\" OR process.executable:\"C:\\\\Win… | 6 |  |
| q-ae03f1d4f1 | pivot verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZLhp5i"} | None |  |
| q-fe7ccf30d8 | pivot verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZLh9Pm"} | None |  |
| q-9059c8f424 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTPA5kN"} | None |  |
| q-d8e59bc840 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItPCxFs-"} | None |  |
| q-32ca3c83c6 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTVGQmt"} | None |  |
| q-ff3b278e16 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTPBJnI"} | None |  |
| q-c6eb5b9c10 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItPK6qjB"} | None |  |
| q-4fa197e385 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTPBJkP"} | None |  |
| q-80a6b74fee | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItPJ5Bh7"} | None |  |
| q-178ce2e70b | pivot verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZLhqPR"} | None |  |
| q-d9e1eeb532 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTVHAmR"} | None |  |
| q-ddc753d582 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTVGQmt"} | None |  |
| q-97816df157 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItPO_TIA"} | None |  |
| q-aea63306e4 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-1fc12acf2e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gj"} | None |  |
| q-a3fd7437ea | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-b6de46d8c7 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKB-"} | None |  |
| q-a159cbd9ca | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKB-"} | None |  |
| q-99215dc656 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None |  |
| q-001b2ccab1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None |  |
| q-3a6d73940f | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-d24f5c0eac | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-067927fb30 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None |  |
| q-86752a8fa1 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKB-"} | None |  |
| q-dd849bb91e | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZKhD3z"} | None |  |
| q-cddf0122eb | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItKT-FUX"} | None |  |
| q-db8a8cde5d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO9rO3D"} | None |  |
| q-ca7b0d86a1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTVGQnT"} | None |  |
| q-b582f9f9f2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO-r7Fc"} | None |  |
| q-88c3e96c81 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTqhQkl"} | None |  |
| q-5f684f3c45 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVcvuSc"} | None |  |
| q-3398ee263f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTVGQnT"} | None |  |
| q-d32f019ecf | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO-r7Fc"} | None |  |
| q-3d838a0ed5 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVt4o2y"} | None |  |
| q-8baee9f936 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVt4o2y"} | None |  |
| q-97e15d3c5b | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVr2bv9"} | None |  |
| q-d1f2688905 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVr2bv9"} | None |  |
| q-c06ad4c61c | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVz8aWs"} | None |  |
| q-6ddb51483e | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVr2bu5"} | None |  |
| q-2410c3e4f5 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVt4o2y"} | None |  |
| q-f78d7f5e85 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVr2bv9"} | None |  |
| q-24bfcd4b92 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItV19xlz"} | None |  |
| q-fb7a12a611 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrog0"} | None |  |
| q-8f0727a1e6 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNn1uOFchItY0uF-5"} | None |  |
| q-ab66a8c898 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrYih"} | None |  |
| q-c64c677330 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ev9A"} | None |  |
| q-fdac21eb92 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ef_B"} | None |  |
| q-33f3c16102 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaFQQsu"} | None |  |
| q-375f2c6499 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrYMQT"} | None |  |
| q-5a9aeb3a81 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQE_psP"} | None |  |
| q-68fed94ae6 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQE_psP"} | None |  |
| q-851f0bc5c8 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaKXhpR"} | None |  |
| q-75880b8503 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaKXhpR"} | None |  |
| q-705cf4f760 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-1a82bb579d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-1748d58b06 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-9c6b22d62e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-6d4f674252 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTtmJQ5"} | None |  |
| q-95ce6bb0d4 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZWqNDf"} | None |  |
| q-91c9ed647c | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZWqNA3"} | None |  |
| q-ae7cdb9a2d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQD9QiN"} | None |  |
| q-35288375a1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQB61zZ"} | None |  |
| q-91f9804c34 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQB7V3u"} | None |  |
| q-59d2397a4d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQE_psP"} | None |  |
| q-aa0946763f | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVn1FNc"} | None |  |
| q-5ba25a6671 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVn1FNc"} | None |  |
| q-481f83699e | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVn1FNc"} | None |  |
| q-cc086b27cc | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTVGglR"} | None |  |
| q-eafb6c49b6 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTVGglR"} | None |  |
| q-158a78c1e2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gj"} | None |  |
| q-8f9cffc233 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gj"} | None |  |
| q-21dae03cc2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gj"} | None |  |
| q-7b31b81a9c | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ev8p"} | None |  |
| q-48e7ea99cb | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ev9J"} | None |  |
| q-714b503263 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ev8p"} | None |  |
| q-cdae288477 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUGBlWZ"} | None |  |
| q-7bb1b3611a | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7FP8C"} | None |  |
| q-0b8f8ba50d | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSmWPy"} | None |  |
| q-7779fbe838 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-47ad3bde95 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO9rO3Z"} | None |  |
| q-e8bb33a403 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOxeHN4"} | None |  |
| q-9e3ca5693d | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8R_"} | None |  |
| q-892ac977ab | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTtmJQ5"} | None |  |
| q-1da50a569a | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSmmNB"} | None |  |
| q-d0cdb92ff3 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZCgBha"} | None |  |
| q-0e293f411a | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZCgBha"} | None |  |
| q-34a6092815 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZCgq7J"} | None |  |
| q-e98355f0ff | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None |  |
| q-2894d635f8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None |  |
| q-5cfc82e76a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None |  |
| q-58da4a9a7d | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaKWxp5"} | None |  |
| q-55a0b87073 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaKWxp5"} | None |  |
| q-052fb1718f | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaFQQtn"} | None |  |
| q-f8ad23db98 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTqgghU"} | None |  |
| q-6754178e70 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTqgghU"} | None |  |
| q-c062727d11 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQA64yf"} | None |  |
| q-37bd3e89dc | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTmcl_4"} | None |  |
| q-ab3884f848 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItPDyDoS"} | None |  |
| q-c98392f7d9 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8RH"} | None |  |
| q-503d08992c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-06b1ffd623 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-899f03d3f0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-7f1c95fa33 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gj"} | None |  |
| q-fe056dfdf7 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-4ce6b28c19 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2MI"} | None |  |
| q-72ddabae44 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTYl"} | None |  |
| q-8cae241e6c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTYt"} | None |  |
| q-80c5a5c75f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None |  |
| q-38faf0017f | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ef_w"} | None |  |
| q-3ffee1b32f | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ8FraW"} | None |  |
| q-5e45410daa | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrogQ"} | None |  |
| q-476548021d | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrYhe"} | None |  |
| q-af8cb73a68 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-7b421210c0 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-581f626f1f | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-5968b42733 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTkbEF9"} | None |  |
| q-218ad50b56 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTkbEF9"} | None |  |
| q-a200d10e6a | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2MI"} | None |  |
| q-8f30d9d828 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTkbkGF"} | None |  |
| q-d9b3daaebf | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTkbkGF"} | None |  |
| q-526e8ec100 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCjbV"} | None |  |
| q-a0aaa5bf32 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO9rO3Z"} | None |  |
| q-70cda56cc7 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItThYt63"} | None |  |
| q-e96b5d170a | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-e1a2a31ff8 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrog6"} | None |  |
| q-8534795a46 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO4kjEa"} | None |  |
| q-a27c5a838b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO9re0E"} | None |  |
| q-0747504a3e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOqWMLr"} | None |  |
| q-ef84b5b3b4 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOVAUl3"} | None |  |
| q-f043171823 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOxeHN4"} | None |  |
| q-c1538928ee | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO9rO3Z"} | None |  |
| q-57cac64351 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8R_"} | None |  |
| q-297835bdcf | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOVAUl3"} | None |  |
| q-6602905eb4 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQE_psP"} | None |  |
| q-c0b92f7a93 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZWqNDf"} | None |  |
| q-e2859f1034 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZCgBha"} | None |  |
| q-486e846cd7 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaFQQsu"} | None |  |
| q-0aa04b23c1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTWI7pZ"} | None |  |
| q-bcb5fd8db9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-6fb3f1d1e5 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-6e26c94007 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-8ff597268e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None |  |
| q-2a6167af51 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None |  |
| q-62734266be | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ev8p"} | None |  |
| q-8add4b5078 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ev8p"} | None |  |
| q-7afe77a3c6 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaKXhpQ"} | None |  |
| q-be7632ce13 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ6CoZN"} | None |  |
| q-c3454f1dd7 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVt5I2Y"} | None |  |
| q-169a3062b1 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVv6C9m"} | None |  |
| q-55d38955b5 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ6CoZN"} | None |  |
| q-5c680c8788 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVw6X-9"} | None |  |
| q-e16f8b6a56 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTqgghU"} | None |  |
| q-903582ae38 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTqgghU"} | None |  |
| q-34c282b507 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVcvuSE"} | None |  |
| q-f1d5b9af2c | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVcvuSE"} | None |  |
| q-1950f498bb | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOmQp3C"} | None |  |
| q-d42a9baf8c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOmQp3C"} | None |  |
| q-ba6a2eeb9d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO2ikE2"} | None |  |
| q-14898fbc2b | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRkUVV"} | None |  |
| q-54f6c134bb | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItObGa1g"} | None |  |
| q-5b76f207c2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItObGa1g"} | None |  |
| q-8e717bbd38 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItPL74K2"} | None |  |
| q-08bb5c1618 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItPL74K2"} | None |  |
| q-de6ae5cd1b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItPL74K2"} | None |  |
| q-39836b034b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-cadaa3b5ef | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-188420c56c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gj"} | None |  |
| q-d08ea7ee59 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-e7eddae6dd | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRk1C1"} | None |  |
| q-f6806919fc | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ef_y"} | None |  |
| q-3db265ab0d | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ef_y"} | None |  |
| q-53b866efc7 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItV3-aVk"} | None |  |
| q-98624c7d90 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVn1FMZ"} | None |  |
| q-95c28163e7 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItV3-aXJ"} | None |  |
| q-0b356ee1fb | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaKXhpM"} | None |  |
| q-cf76fdb08d | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVn01Ns"} | None |  |
| q-beac7a938e | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItV3-aUM"} | None |  |
| q-d357d94792 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItV3-aUJ"} | None |  |
| q-788bcdb3ff | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8TL"} | None |  |
| q-ae548d7c47 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ev8p"} | None |  |
| q-a2b12da731 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItKT-VVW"} | None |  |
| q-98984fb0e9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOVAUl3"} | None |  |
| q-3e01b61278 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOVAUl3"} | None |  |
| q-57db5a0d56 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRllBR"} | None |  |
| q-85e82043b7 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaKXhpQ"} | None |  |
| q-5c98cf39db | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8Rc"} | None |  |
| q-0279f62318 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItT-3yn1"} | None |  |
| q-2a92b8c6b6 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItT70Tl_"} | None |  |
| q-b86753e398 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItT-3yn1"} | None |  |
| q-0d08bec3cd | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrYi0"} | None |  |
| q-96edf594eb | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrIjh"} | None |  |
| q-ef5959a682 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZLhZrg"} | None |  |
| q-f15363f158 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZLhZrg"} | None |  |
| q-bdaf6eede3 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZLhZrg"} | None |  |
| q-a02e557576 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-6ab33d3cc4 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-3da81507a7 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRlVDe"} | None |  |
| q-6d5dbbe6ad | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTkbEF9"} | None |  |
| q-dae0ab8a10 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTvoSAW"} | None |  |
| q-e41963f72c | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ6CoZN"} | None |  |
| q-78f9fc5a81 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ6CoZN"} | None |  |
| q-091cddadd2 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVt5I2Y"} | None |  |
| q-4ed1fb46e8 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ef_w"} | None |  |
| q-174421ddc5 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ef_w"} | None |  |
| q-5f2e741deb | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZLhp5i"} | None |  |
| q-6e8fe27d4c | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZLh9Pm"} | None |  |
| q-13892c91ed | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTPA5kN"} | None |  |
| q-7b550918b5 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItPCxFs-"} | None |  |
| q-7516bf8220 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTVGQmt"} | None |  |
| q-b3b73dc2a1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTPBJnI"} | None |  |
| q-70cac6a47f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItPK6qjB"} | None |  |
| q-b662dbb406 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTPBJkP"} | None |  |
| q-1113b186f2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItPJ5Bh7"} | None |  |
| q-511ef928fb | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZLhqPR"} | None |  |
| q-e6a50125e7 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTVHAmR"} | None |  |
| q-778be1ffc0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTVGQmt"} | None |  |
| q-fda376503f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItPO_TIA"} | None |  |

## Verification

Evidence items cited: 204; confirmed against the stored events: 204; rejected: 0. Each item was re-fetched with get_event; it is confirmed only if the event exists, the cited field holds the cited value, and the cited query_id is a query of this run that returned that event.
Evidence sent back to the agents for correction during the run: 9 item(s) in 7 submission(s) (one correction round each; what still failed was rejected).

## Limitations

- Findings describe what the stored logs show; activity these sources did not log cannot be seen.
- Datasets with non-overlapping time windows (see Data examined) were analysed separately.
- Long field values are shortened in this report; full events are retrievable by _index/_id.
