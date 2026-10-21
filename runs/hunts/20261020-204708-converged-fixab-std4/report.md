# Threat hunt report — 20261020-204708-converged-fixab-std4

**Hypothesis:** An adversary who compromised Windows hosts in this network stole credentials from them (MITRE ATT&CK tactic: Credential Access).

**Verdict: Confirmed** — 9 in-scope incident(s) of verified malicious findings (confidence >= medium): I01 T1003.001 (F01, F08, F09, F23, F32, F36, F52), I02 T1003.001 (F58), I04 T1110.002 (F16), I05 T1110.003 (F17), I06 T1187 (F20), I09 T1552.001 (F59), I10 T1552.001 (F63), I12 T1552.004 (F27, F55, F60), I17 T1649 (F19)

Verdict method: rules over verified evidence (Confirmed if >=1 in-scope incident of verified malicious findings (confidence >= medium); Inconclusive if only suspicious incidents or coverage gaps; Refuted if full coverage and no malicious/suspicious finding)

| Run | Value |
|---|---|
| Profile | converged (thinking=False, temperature=0.0) |
| Model | deepseek-flash |
| Started / finished (UTC) | 2026-10-20T12:47:09+00:00 / 2026-10-20T12:57:19+00:00 (610.0 s) |
| LLM calls / tokens | 156 / {'prompt': 4810507, 'completion': 129292} |
| MCP tool calls | 1290 (server tools: list_data_sources, get_fields, search, count, aggregate, timeline, esql, get_event, get_registry) |
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
| I01 | T1003.001 | yes | malicious/high | F01, F08, F09, F23, F32, F36, F52 | LSASS memory access with full-access mask by PowerShell on scranton (and wsmprovhost on nashua) |
| I02 | T1003.001 | yes | malicious/high | F58 | NASHUA: python.exe via PsExec opened LSASS, read LSA secrets, staged credential archive |
| I03 | T1003.005 | yes | suspicious/medium | F05 | Cached domain credential registry writes by lsass (benign logon caching) |
| I04 | T1110.002 | yes | malicious/high | F16 | Credential material harvested from LSASS/SAM; no offline cracking observed |
| I05 | T1110.003 | yes | malicious/medium | F17 | No password spraying; reused pbeesly credentials for lateral movement |
| I06 | T1187 | yes | malicious/high | F20 | WebDAV/UNC forced authentication to attacker server 192.168.0.4 from scranton |
| I07 | T1187 | yes | suspicious/medium | F21 | NASHUA python.exe beaconing to 192.168.0.4:8443 with self-signed TLS |
| I08 | T1552.001 | yes | suspicious/medium | F28 | Credential-harvesting tooling staged as .ps1 in SysinternalsSuite; no plaintext credential files read |
| I09 | T1552.001 | yes | malicious/high | F59 | NASHUA: harvested password/login-named files into working.zip |
| I10 | T1552.001 | yes | malicious/high | F63 | SCRANTON: unsigned .scr dropper launched by explorer.exe writing monkey.png payload |
| I11 | T1552.001 | yes | suspicious/medium | F64 | SCRANTON: accesschk.exe permission reconnaissance from staged SysinternalsSuite |
| I12 | T1552.004 | yes | malicious/high | F27, F55, F60 | Certificate/private-key export via Get-PrivateKeys to .pfx files on scranton |
| I13 | T1552.006 | yes | suspicious/medium | F62 | SCRANTON: registry value read and Invoke-Expression'd, hostui.exe elevated |
| I14 | T1555.003 | yes | suspicious/medium | F61 | SCRANTON: sdclt.exe UAC-bypass launcher followed by hidden steganographic PowerShell |
| I15 | T1555.004 | yes | suspicious/low | F33 | Windows Vault / Credential Manager artifacts touched on scranton |
| I16 | T1558 | yes | suspicious/medium | F47 | Compromised host chain scranton→nashua with LSASS access; no Kerberos ticket theft observed |
| I17 | T1649 | yes | malicious/high | F19 | Certificate harvesting followed by archive and exfiltration (scranton) |
| I18 | T1649 | yes | suspicious/low | F56 | ROOT certificate store blob modification on nashua by Sysmon.exe |

## Findings

### F01 · malicious / high · T1003.001 · Full-access LSASS handle opened by PowerShell on scranton and by wsmprovhost on nashua during an active intrusion

Evidence status: **verified**

On 2020-05-02 at 03:05:16, PowerShell.exe (PID 2976) on scranton.dmevals.local opened lsass.exe (PID 736) with GrantedAccess 0x1f3fff and then 0x1fffff (PROCESS_ALL_ACCESS) — the classic LSASS memory-read mask used by credential dumpers. The call trace is ntdll/KERNELBASE followed by UNKNOWN(000001996D28200D), i.e. code not backed by a loaded module, consistent with injected/reflective code. This occurred inside a hands-on-keyboard intrusion by user pbeesly on scranton (same session ran Invoke-Discovery, Invoke-Persistence, Invoke-ScreenCapture, Keystroke-Check, Invoke-Exfil and a VirtualAlloc/CreateThread Add-Type loader). Four minutes later, at 03:09:29, wsmprovhost.exe (PID 7720, SYSTEM) on nashua.dmevals.local opened lsass.exe (PID 728) with 0x1f3fff, immediately after pbeesly ran 'Invoke-Command -ComputerName NASHUA { Get-Process -IncludeUserName ... }' and 'Invoke-SeaDukeStage -ComputerName NASHUA' from scranton. The remaining LSASS accesses in the dataset are benign: svchost.exe with 0x1000 (query-limited), Azure AntimalwareConfig.exe/WindowsAzureTelemetryService.exe with 0x1400, and csrss/wininit with 0x1fffff at boot.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hQQBhJ | q-6692ee2ec3 | ok |
| 2 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hQQBhJ | q-6692ee2ec3 | ok |
| 3 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.CallTrace | C:\windows\SYSTEM32\ntdll.dll+9c584\|C:\windows\System32\KERNELBASE.dll+2732e\|UNKNOWN(000001996D28200D) | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hQQBhJ | q-5cb4deeb4d | ok |
| 4 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7c939yF | q-6692ee2ec3 | ok |
| 5 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7c939yF | q-6692ee2ec3 | ok |
| 6 | 2020-05-02 03:09:23.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | Invoke-Command -ComputerName NASHUA -ScriptBlock { Get-Process -IncludeUserName \| Select-Object UserName,SessionId \| Where-Object { $_.UserName -like "*\$env:… | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qrRbzS | q-360d28af56 | ok |
| 7 | 2020-05-02 03:10:22.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | Invoke-SeaDukeStage -ComputerName NASHUA | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qqQ-d4 | q-360d28af56 | ok |

### F58 · malicious / high · T1003.001 · NASHUA: python.exe delivered via PsExec opened LSASS with 0x1f3fff, then read LSA secrets and staged/exfiltrated a credential archive

Evidence status: **verified**

On nashua.dmevals.local, pbeesly used PsExec64.exe from scranton (10.0.1.4) with the cleartext password '-p Fl0nk3rt0n!T0by' to launch C:\Windows\Temp\python.exe four times (03:11:39-03:15:03). At 03:09:29 a wsmprovhost.exe WinRM session had already opened lsass.exe with AccessMask 0x1f3fff (full access incl. read/write process memory). The python.exe sessions then repeatedly opened the LSA registry key (\REGISTRY\MACHINE\SYSTEM\ControlSet001\Control\Lsa, AccessMask 0x1, Query key value) at 03:11:40, 03:12:46, 03:13:49 and 03:15:03, spawned powershell.exe, and beaconed to 192.168.0.4:8443. The PowerShell session enumerated files matching *pass*, *login*, *admin*, *vpn*, *.pst, *.ost, compressed them to $env:APPDATA\working.zip, archived with Rar.exe -hpfGzq5yKw, then wiped Rar.exe and both zips with sdelete64.exe. This is new LSASS/credential-store access on nashua beyond the anchors (which only covered the wsmprovhost handle).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:09:29.000Z | nashua.dmevals.local | windows.security | win.AccessMask | 0x1f3fff | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7njy6Co | q-488c4bd245 | ok |
| 2 | 2020-05-02 03:11:40.000Z | nashua.dmevals.local | windows.security | win.ObjectName | \REGISTRY\MACHINE\SYSTEM\ControlSet001\Control\Lsa | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7niyNuG | q-6526ffcdbc | ok |
| 3 | 2020-05-02 03:11:18.784Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\PsExec64.exe" -accepteula \\NASHUA -u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7cxoQzx | q-e4bdd67e38 | ok |
| 4 | 2020-05-02 03:16:19.395Z | nashua.dmevals.local | windows.sysmon | process.command_line | "C:\Windows\Temp\Rar.exe" a -hpfGzq5yKw C:\Users\pbeesly\Desktop\working.zip C:\Users\pbeesly\AppData\Roaming\working.zip | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7c4xY6Y | q-21852756c9 | ok |
| 5 | 2020-05-02 03:15:59.000Z | nashua.dmevals.local | windows.powershell | win.ScriptBlockText | $env:APPDATA;$files=ChildItem -Path $env:USERPROFILE\ -Include *.doc,*.xps,*.xls,*.ppt,*.pps,*.wps,*.wpd,*.ods,*.odt,*.lwp,*.jtd,*.pdf,*.zip,*.rar,*.docx,*.url,… | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qrRC92 | q-d0eb93d8c5 | ok |
| 6 | 2020-05-02 03:15:05.142Z | nashua.dmevals.local | windows.sysmon | destination.ip | 192.168.0.4 | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7c5ylrT | q-d29d997918 | ok |

### F08 · malicious / high · T1056.004 · PowerShell opened LSASS with full-access mask and created a remote thread in lsass.exe on scranton

Evidence status: **verified**

On scranton.dmevals.local at 2020-05-02T03:05:16, PowerShell.exe (PID 2976, user pbeesly) opened a handle to C:\windows\system32\lsass.exe with GrantedAccess 0x1FFFFF (PROCESS_ALL_ACCESS) and 0x1f3fff, with a CallTrace ending in an UNKNOWN module (C:\windows\SYSTEM32\ntdll.dll+9c584\|C:\windows\System32\KERNELBASE.dll+2732e\|UNKNOWN(000001996D28200D)) — the classic signature of a credential-dumping tool calling OpenProcess on LSASS. In the same second Sysmon event 8 recorded a CreateRemoteThread from that same PowerShell process (PID 2976) into lsass.exe (PID 736), NewThreadId 912, StartAddress 0x00000117610E0000 with StartModule '-' (unbacked memory). Windows Security 4656 corroborates the handle request by C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe on \Device\HarddiskVolume2\Windows\System32\lsass.exe with AccessMask 0x1fffff / 0x1f3fff. This is attacker activity consistent with API hooking / in-memory credential theft against LSASS, not normal system behaviour. (The second CreateRemoteThread into lsass at 03:18:34 came from csrss.exe with StartModule KERNELBASE.dll / StartFunction CtrlRoutine, which is a benign Windows mechanism.)

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hQQBhJ | q-1dbf4fa7ff | ok |
| 2 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.CallTrace | C:\windows\SYSTEM32\ntdll.dll+9c584\|C:\windows\System32\KERNELBASE.dll+2732e\|UNKNOWN(000001996D28200D) | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hQQBhJ | q-1dbf4fa7ff | ok |
| 3 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.SourceImage | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hQQBhH | q-7af04f8269 | ok |
| 4 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.StartAddress | 0x00000117610E0000 | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hQQBhH | q-7af04f8269 | ok |
| 5 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.StartModule | - | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hQQBhH | q-7af04f8269 | ok |
| 6 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | win.AccessMask | 0x1fffff | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7nq7mb8 | q-594892f658 | ok |
| 7 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | win.ProcessName | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7nq7mb8 | q-594892f658 | ok |

### F16 · malicious / high · T1110.002 · Credential material harvested from lsass memory and SAM on SCRANTON by pbeesly's PowerShell, and from lsass on NASHUA via WinRM — offline cracking not observed

Evidence status: **verified**

On scranton.dmevals.local at 03:05:16Z the process C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe running as pbeesly (logon 0x372e81) requested a handle to \Device\HarddiskVolume2\Windows\System32\lsass.exe with AccessMask 0x1fffff (including 'Read from process memory'), and at 03:09:29Z wsmprovhost.exe as pbeesly opened lsass with 0x1f3fff on nashua.dmevals.local. On scranton, lsass.exe itself then requested SAM_SERVER handles with AccessMask 0xf003f at 03:19:21Z and 03:20:46Z. This is credential dumping from LSASS/SAM (the T1110.002 check family), but no hashcat/john/cracking tooling, no ntds.dit or hive file writes, and no 4663 reads of SAM/SECURITY were observed — the cracking step itself is not present in the data.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | win.AccessMask | 0x1fffff | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7nq7mb8 | q-51a6e89a9e | ok |
| 2 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | win.ObjectName | \Device\HarddiskVolume2\Windows\System32\lsass.exe | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7nq7mb8 | q-51a6e89a9e | ok |
| 3 | 2020-05-02 03:09:29.000Z | nashua.dmevals.local | windows.security | win.ProcessName | C:\Windows\System32\wsmprovhost.exe | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7njy6Co | q-61e94599d2 | ok |
| 4 | 2020-05-02 03:19:21.000Z | scranton.dmevals.local | windows.security | win.ObjectName | SAM | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7ryFh2_ | q-acf95ae9e2 | ok |
| 5 | 2020-05-02 03:19:21.000Z | scranton.dmevals.local | windows.security | win.AccessMask | 0xf003f | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7ryFh2_ | q-acf95ae9e2 | ok |
| 6 | 2020-05-02 03:19:09.809Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\Windows\System32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7cxqOgJ | q-d2f6b4db8d | ok |

### F17 · malicious / medium · T1110.003 · No password spraying: no failed logons, and the repeated pbeesly network logons are lateral movement with already-stolen credentials

Evidence status: **verified**

There are zero 4625 events, so no spray pattern exists. The 218 successful type-3 logons are dominated by machine accounts (NEWYORK$ 123, SCRANTON$ 37, NASHUA$ 25, WEC$ 8, UTICA$ 5) plus 20 for pbeesly. The pbeesly logons are a single account reused across hosts — Kerberos type-3 from 10.0.1.4 to newyork and nashua, and explicit-credential 4648 events on nashua.dmevals.local from C:\Windows\PSEXESVC.exe using pbeesly's credentials (03:11:40Z onward), following the Invoke-SeaDukeStage -ComputerName NASHUA script on scranton at 03:10:22Z. This is lateral movement with harvested credentials, not spraying.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:40.000Z | nashua.dmevals.local | windows.security | process.executable | C:\Windows\PSEXESVC.exe | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7niyNur | q-bb65d9e37b | ok |
| 2 | 2020-05-02 03:11:40.000Z | nashua.dmevals.local | windows.security | win.TargetUserName | pbeesly | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7niyNur | q-bb65d9e37b | ok |
| 3 | 2020-05-02 03:10:22.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | Invoke-SeaDukeStage -ComputerName NASHUA | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qqQ-d4 | q-dfa64d9d2b | ok |
| 4 | 2020-05-02 03:10:23.000Z | nashua.dmevals.local | windows.security | win.LogonType | 3 | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7niytuv | q-63f97fc222 | ok |

### F19 · malicious / high · T1111 · Certificate/private-key harvesting (Get-PrivateKeys → Export-PfxCertificate) on scranton.dmevals.local, followed by archive and exfiltration

Evidence status: **verified**

On 2020-05-02 between 03:04:56Z and 03:08:51Z, user pbeesly on scranton.dmevals.local executed a PowerShell function 'Get-PrivateKeys' (script block 9d153741-75c3-4062-afe3-aeca0aee611b, loaded from C:\Program Files\SysinternalsSuite\readme.ps1) that enumerates cert:\LocalMachine recursively and exports every certificate with a thumbprint via Export-PfxCertificate to randomly named .pfx files in the user's Downloads folder, protected by the hardcoded password 'saribas'. Sysmon file-create confirms the resulting artifact C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx at 03:04:57Z. At 03:05:16Z the same PowerShell process (PID 2976) opened lsass.exe with GrantedAccess 0x1f3fff and 0x1fffff (full access, call trace ending in UNKNOWN module) — consistent with in-memory access to authentication material. The stolen key material was then staged: an 'Invoke-Exfil' script block (b2b03a9c-43f0-4285-837d-f22d4600b2ae) compressed the Downloads folder into $env:APPDATA\OfficeSupplies.7z (file created 03:08:35Z) and copied it to a WebDAV share \\192.168.0.4\webdav using a PSCredential built from a plaintext password. Finally 'Invoke-BeachCleanup' deletes *.pfx, *.bmp, *.png and OfficeSupplies.7z to remove traces. This is theft of certificate-based credentials/private keys — the material used for smart-card/certificate MFA — and is malicious. Supporting context: pbeesly also installed PSEXESVC on nashua.dmevals.local (7045 at 03:11:39Z, 03:12:46Z, 03:13:49Z, 03:15:03Z) with 4648 explicit-credential logons, and ran Invoke-Command against NASHUA at 03:09:23Z. The 4648 events for DWM-1/UMFD-0/UMFD-1/UMFD-2/SCRANTON$ from winlogon.exe/wininit.exe/taskhostw.exe are normal Windows logon behaviour, and the CredentialGuard/CredentialEnrollmentManager registry writes by lsass.exe/services.exe are benign OS activity.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qvSysm | q-084a247697 | ok |
| 2 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\readme.ps1 | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qvSysm | q-81a6837e8c | ok |
| 3 | 2020-05-02 03:04:57.460Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hQQRgs | q-43d4f7fc4e | ok |
| 4 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hQQBhJ | q-21f3e3a4cd | ok |
| 5 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.CallTrace | C:\windows\SYSTEM32\ntdll.dll+9c584\|C:\windows\System32\KERNELBASE.dll+2732e\|UNKNOWN(000001996D28200D) | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hQQBhJ | q-a03fc337e3 | ok |
| 6 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qjPglL | q-0b4aab38c9 | ok |
| 7 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qjPglL | q-0b4aab38c9 | ok |
| 8 | 2020-05-02 03:08:35.270Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Users\pbeesly\AppData\Roaming\OfficeSupplies.7z | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7c_44mH | q-43d4f7fc4e | ok |
| 9 | 2020-05-02 03:08:51.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-BeachCleanup {     Write-Host "[*] Cleaning up"     Remove-Item -Path "$env:USERPROFILE\Downloads\*.pfx" -Force     Remove-Item -Path "$env:USER… | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qrRC9i | q-084a247697 | ok |
| 10 | 2020-05-02 03:11:39.000Z | nashua.dmevals.local | windows.other | message | A service was installed in the system.    Service Name:  PSEXESVC  Service File Name:  %SystemRoot%\PSEXESVC.exe  Service Type:  user mode service  Service Star… | .ds-logs-windows.other-default-2026.10.20-000001 / AaFZR_JfH5wFd7pNHuCk | q-ade520b30f | ok |

### F20 · malicious / high · T1187 · WebDAV/UNC forced-authentication path used by pbeesly on SCRANTON to reach attacker WebDAV server 192.168.0.4

Evidence status: **verified**

On scranton.dmevals.local, user pbeesly ran a PowerShell script block (4104, ScriptBlock ID b2b03a9c-43f0-4285-837d-f22d4600b2ae, path C:\Program Files\SysinternalsSuite\psversion.ps1) defining Invoke-Exfil, which maps a network drive to the UNC/WebDAV path \\192.168.0.4\webdav using New-PSDrive with explicit credentials (cozy / MyCozyPassw0rd!) and copies the password-protected archive OfficeSupplies.7z there. At 2020-05-02T03:08:47Z the same powershell.exe (PID 3852, DMEVALS\pbeesly) on 10.0.1.4 initiated a TCP connection to 192.168.0.4:80, and svchost.exe (LOCAL SERVICE, the WebClient/DavClnt service) followed with further connections to 192.168.0.4:80 at 03:08:50 and 03:10:23. In the zeek window (2020-04-30, non-overlapping) the same host 10.0.1.4 first had SMB 445/139 attempts to 192.168.0.4 rejected (conn_state REJ) and then fell back to HTTP WebDAV: OPTIONS/PROPFIND requests with User-Agent 'Microsoft-WebDAV-MiniRedir/10.0.18362' and 'DavClnt' to /webdav, /webdav/OfficeSupplies.7z and /webdav/python.exe, all answered 401 Unauthorized — the classic WebDAV-based forced-authentication/credential-capture pattern. This is attacker tooling (Invoke-Exfil / Invoke-BeachCleanup) on a compromised host, not normal system behaviour.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qjPglL | q-550b359ef5 | ok |
| 2 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\psversion.ps1 | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qjPglL | q-550b359ef5 | ok |
| 3 | 2020-05-02 03:08:47.769Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7c-48Ye | q-76187ef5f0 | ok |
| 4 | 2020-05-02 03:08:47.769Z | scranton.dmevals.local | windows.sysmon | destination.ip | 192.168.0.4 | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7c-48Ye | q-76187ef5f0 | ok |
| 5 | 2020-05-02 03:08:50.904Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\Windows\System32\svchost.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7c-4sYX | q-821bc80951 | ok |
| 6 | 2020-04-30 00:32:18.095Z | simplerockbuild.simplerock.lan | zeek | user_agent.original | DavClnt | .ds-logs-zeek-default-2026.10.20-000001 / AaFZSPJfH5wFd7o_Z1YZ | q-dec4f4e06e | ok |
| 7 | 2020-04-30 00:35:25.615Z | simplerockbuild.simplerock.lan | zeek | url.original | /webdav/python.exe | .ds-logs-zeek-default-2026.10.20-000001 / AaFZSPJfH5wFd7o_Zlb7 | q-7c8ec3ff97 | ok |
| 8 | 2020-04-30 00:35:25.615Z | simplerockbuild.simplerock.lan | zeek | http.response.status_code | 401 | .ds-logs-zeek-default-2026.10.20-000001 / AaFZSPJfH5wFd7o_Zlb7 | q-7c8ec3ff97 | ok |
| 9 | 2020-04-30 00:32:14.891Z | simplerockbuild.simplerock.lan | zeek | zeek.conn_state | REJ | .ds-logs-zeek-default-2026.10.20-000001 / AaFZSPJfH5wFd7o_Z1a3 | q-08be945036 | ok |

### F23 · malicious / high · T1212 · PowerShell process on SCRANTON opened LSASS with PROCESS_ALL_ACCESS (0x1fffff) after in-memory shellcode injection

Evidence status: **verified**

On scranton.dmevals.local, user pbeesly's PowerShell.exe (PID 2976, spawned 2020-05-02T02:58:44Z by control.exe /name Microsoft.BackupAndRestoreCenter with '-noni -noexit -ep bypass -window hidden') first executed a script block that Add-Type'd kernel32 VirtualAlloc/CreateThread and carried a large 0xfc,0x48,0x83,0xe4... byte array (classic shellcode loader). At 2020-05-02T03:05:16.623Z and 03:05:16.654Z that same PID 2976 opened C:\windows\system32\lsass.exe with GrantedAccess 0x1f3fff and 0x1fffff (PROCESS_ALL_ACCESS), with a call trace ending in UNKNOWN(000001996D28200D) — the handle request came from unbacked/injected memory rather than a signed module. This is the strongest T1212 signal in the data: a non-privileged user process obtaining full access to LSASS memory. In the same session the actor also dumped private keys (Get-PrivateKeys writing C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx at 03:04:57Z), ran Invoke-Discovery/Invoke-Persistence/Invoke-ScreenCapture/Invoke-Exfil, and used Invoke-Command against NASHUA. No LSASS dump file was written to disk (only WerFault WER*.tmp.dmp from SkypeApp crashes), so the credential theft appears to have been performed in memory.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hQQBhJ | q-f4c6668d86 | ok |
| 2 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.CallTrace | C:\windows\SYSTEM32\ntdll.dll+9c584\|C:\windows\System32\KERNELBASE.dll+2732e\|UNKNOWN(000001996D28200D) | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hQQBhJ | q-d185526e72 | ok |
| 3 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.TargetImage | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hQQBhJ | q-d185526e72 | ok |
| 4 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hQQBhG | q-f4c6668d86 | ok |
| 5 | 2020-05-02 02:58:45.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | $cFIrwwpZzGzU = @"  [DllImport("kernel32.dll")]  public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);… | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7q0Yv7J | q-f0a60297d4 | ok |
| 6 | 2020-05-02 02:58:44.325Z | scranton.dmevals.local | windows.sysmon | process.command_line | "PowerShell.exe" -noni -noexit -ep bypass -window hidden -c "sal a New-Object;Add-Type -AssemblyName 'System.Drawing'; $g=a System.Drawing.Bitmap('C:\Users\pbee… | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7htwOyZ | q-e0fba41263 | ok |
| 7 | 2020-05-02 03:04:57.460Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hQQRgs | q-58bb9c5704 | ok |

### F59 · malicious / high · T1552.001 · NASHUA: PowerShell on the PsExec-launched python.exe session harvested password/login-named files and password-protected them into working.zip

Evidence status: **verified**

At 03:15:59 on nashua.dmevals.local, in the PowerShell session spawned by C:\Windows\Temp\python.exe (itself started by PSEXESVC.exe under pbeesly), a script block recursively enumerated the user profile for credential-bearing file patterns (*pass*, *psw*, *login*, *admin*, *sifr*, *sifer*, *vpn, *.pst, *.ost) and compressed them with Compress-Archive into $env:APPDATA\working.zip. Rar.exe then re-archived it with password fGzq5yKw to the Desktop, and sdelete64.exe deleted Rar.exe and both archives. This is new credential-file collection on nashua, distinct from the scranton .ps1 staging anchor.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:15:59.000Z | nashua.dmevals.local | windows.powershell | win.ScriptBlockText | $env:APPDATA;$files=ChildItem -Path $env:USERPROFILE\ -Include *.doc,*.xps,*.xls,*.ppt,*.pps,*.wps,*.wpd,*.ods,*.odt,*.lwp,*.jtd,*.pdf,*.zip,*.rar,*.docx,*.url,… | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qrRC92 | q-d0eb93d8c5 | ok |
| 2 | 2020-05-02 03:16:19.395Z | nashua.dmevals.local | windows.sysmon | process.command_line | "C:\Windows\Temp\Rar.exe" a -hpfGzq5yKw C:\Users\pbeesly\Desktop\working.zip C:\Users\pbeesly\AppData\Roaming\working.zip | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7c4xY6Y | q-21852756c9 | ok |
| 3 | 2020-05-02 03:17:18.030Z | nashua.dmevals.local | windows.sysmon | process.command_line | .\sdelete64.exe  /accepteula "C:\Users\pbeesly\AppData\Roaming\working.zip"  | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7crhzvV | q-21852756c9 | ok |
| 4 | 2020-05-02 03:15:48.652Z | nashua.dmevals.local | windows.sysmon | process.parent.executable | C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7culihF | q-21852756c9 | ok |

### F63 · malicious / high · T1552.001 · SCRANTON: unsigned .scr dropped in C:\ProgramData\victim launched by explorer.exe and wrote the steganographic monkey.png payload

Evidence status: **verified**

At 02:55:56 on scranton.dmevals.local, pbeesly launched C:\ProgramData\victim\â€®cod.3aka3.scr (unsigned, no version/company metadata) from explorer.exe with the /S switch. At 02:57:00 the same .scr wrote C:\Users\pbeesly\Downloads\monkey.png, which hidden PowerShell then decoded into shellcode and executed. The .scr is the initial dropper for the credential-access tooling on scranton.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:55:56.157Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\ProgramData\victim\â€®cod.3aka3.scr" /S | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hy0krT | q-0c3998a4a6 | ok |
| 2 | 2020-05-02 02:55:56.157Z | scranton.dmevals.local | windows.sysmon | process.parent.executable | C:\Windows\explorer.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hy0krT | q-0c3998a4a6 | ok |
| 3 | 2020-05-02 02:57:00.933Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Users\pbeesly\Downloads\monkey.png | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hwyqdH | q-7031fbaddb | ok |

### F27 · malicious / high · T1552.004 · PowerShell Get-PrivateKeys exports all LocalMachine certificates to password-protected .pfx files

Evidence status: **verified**

On scranton.dmevals.local, user pbeesly (SID S-1-5-21-1830255721-3727074217-2423397540-1107) ran a PowerShell session (PID 3876) that defined and then invoked a function 'Get-PrivateKeys'. The function enumerates every certificate under cert:\LocalMachine recursively and calls Export-PfxCertificate for each one that has a thumbprint, writing the private key material to "$env:USERPROFILE\Downloads\<random>.pfx" protected by the hardcoded password "saribas". The function definition was logged at 2020-05-02T03:04:56Z (script block 9d153741-75c3-4062-afe3-aeca0aee611b, Path C:\Program Files\SysinternalsSuite\readme.ps1), the invocation 'Get-PrivateKeys' at the same second (script block 206799ba-a627-40b9-892e-398c92354238), and one second later Sysmon recorded the resulting file C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx created by powershell.exe. This is deliberate private-key theft from the local certificate store, staged into the user's Downloads folder which the same session subsequently compressed and exfiltrated (Invoke-Exfil, Compress-7Zip of $env:USERPROFILE\Downloads to %APPDATA%\OfficeSupplies.7z, copied to \\192.168.0.4\webdav).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qvSysm | q-9693ecab6d | ok |
| 2 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qvSysm | q-9693ecab6d | ok |
| 3 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\readme.ps1 | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qvSysm | q-9693ecab6d | ok |
| 4 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | Get-PrivateKeys | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qvTSsN | q-2bfafa8670 | ok |
| 5 | 2020-05-02 03:04:57.460Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hQQRgs | q-a74ae07c1d | ok |
| 6 | 2020-05-02 03:04:57.460Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\WindowsPowerShell\v1.0\powershell.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hQQRgs | q-a74ae07c1d | ok |
| 7 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qjPglL | q-4b3f3c75ff | ok |
| 8 | 2020-05-02 03:08:35.270Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Users\pbeesly\AppData\Roaming\OfficeSupplies.7z | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7c_44mH | q-d35d0c2dc3 | ok |

### F60 · malicious / high · T1552.004 · SCRANTON: Get-PrivateKeys exported every LocalMachine certificate with private key to password-protected .pfx files in Downloads

Evidence status: **verified**

At 03:04:56 on scranton.dmevals.local, pbeesly's PowerShell (script path C:\Program Files\SysinternalsSuite\readme.ps1) defined and invoked Get-PrivateKeys, which enumerates cert:\LocalMachine recursively and calls Export-PfxCertificate for every certificate with a thumbprint into $env:USERPROFILE\Downloads\<random>.pfx protected by the hardcoded password 'saribas'. The exported .pfx files were then swept into the exfil archive by Invoke-Exfil (Compress-7Zip of the whole Downloads directory to $env:APPDATA\OfficeSupplies.7z) and deleted by Invoke-BeachCleanup (Remove-Item Downloads\*.pfx).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qvSysm | q-db55b980fc | ok |
| 2 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\readme.ps1 | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qvSysm | q-db55b980fc | ok |
| 3 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qjPglL | q-2b0add9768 | ok |
| 4 | 2020-05-02 03:08:51.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-BeachCleanup {     Write-Host "[*] Cleaning up"     Remove-Item -Path "$env:USERPROFILE\Downloads\*.pfx" -Force     Remove-Item -Path "$env:USER… | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qrRC9i | q-4ee98e4e1c | ok |

### F32 · malicious / high · T1555 · Hidden steganographic PowerShell (PID 2976) on scranton opened LSASS with full access 0x1FFFFF

Evidence status: **verified**

On scranton.dmevals.local, user pbeesly's session was already compromised: a malicious C:\ProgramData\victim\cod.3aka3.scr launched cmd.exe, then sdclt.exe/control.exe, which spawned PowerShell PID 2976 at 2020-05-02T02:58:44Z with '-noni -noexit -ep bypass -window hidden' decoding a payload from C:\Users\pbeesly\Downloads\monkey.png and IEX-ing it (High integrity). At 03:05:16Z that same PowerShell PID 2976 (SourceProcessGUID {47ab858c-e1e4-5eac-b803-000000000400}) opened lsass.exe with GrantedAccess 0x1f3fff and 0x1fffff, with an UNKNOWN call trace — the classic credential-dumping access mask, corroborated by Security 4656 on \Device\HarddiskVolume2\Windows\System32\lsass.exe with AccessMask 0x1fffff/0x1f3fff by pbeesly's powershell.exe. No legitimate script block explains this access. Other LSASS access in the window is benign (svchost/lsm.dll, csrss/wininit at boot, MsMpEng, CollectGuestLogs 0x1410, lsass self-access to SAM).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:58:44.325Z | scranton.dmevals.local | windows.sysmon | process.command_line | "PowerShell.exe" -noni -noexit -ep bypass -window hidden -c "sal a New-Object;Add-Type -AssemblyName 'System.Drawing'; $g=a System.Drawing.Bitmap('C:\Users\pbee… | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7htwOyZ | q-1c7e9f2bb1 | ok |
| 2 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hQQBhJ | q-4d19df0e8b | ok |
| 3 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.CallTrace | C:\windows\SYSTEM32\ntdll.dll+9c584\|C:\windows\System32\KERNELBASE.dll+2732e\|UNKNOWN(000001996D28200D) | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hQQBhJ | q-4d19df0e8b | ok |
| 4 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hQQBhG | q-69e5a74c86 | ok |
| 5 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | win.AccessMask | 0x1fffff | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7nq7mb8 | q-c8a8c41a8e | ok |
| 6 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | user.name | pbeesly | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7nq7mb8 | q-c8a8c41a8e | ok |
| 7 | 2020-05-02 02:55:56.157Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\ProgramData\victim\â€®cod.3aka3.scr | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hy0krT | q-fc53c64549 | ok |

### F36 · malicious / high · T1556 · Hidden steganographic PowerShell (monkey.png) opened LSASS with full access 0x1FFFFF on SCRANTON

Evidence status: **verified**

On scranton.dmevals.local at 2020-05-02T02:58:44 a hidden, execution-policy-bypass PowerShell (PID 2976, user DMEVALS\pbeesly, High integrity, parent control.exe /name Microsoft.BackupAndRestoreCenter) decoded a payload out of C:\Users\pbeesly\Downloads\monkey.png via System.Drawing GetPixel and IEX'd it. At 03:05:16.654 that same process (SourceProcessGUID {47ab858c-e1e4-5eac-b803-000000000400}, PID 2976) opened lsass.exe (PID 736) with GrantedAccess 0x1FFFFF (PROCESS_ALL_ACCESS) — the only full-access LSASS handle in the dataset from a non-system binary. The surrounding activity is a hands-on-keyboard intrusion by pbeesly: keystroke/screenshot jobs, Invoke-SeaDukeStage against NASHUA, PsExec64 with the cleartext password 'Fl0nk3rt0n!T0by' to NASHUA, and Invoke-Exfil. This is credential access against the authentication process, not a benign admin action.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hQQBhJ | q-37a4359874 | ok |
| 2 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hQQBhJ | q-37a4359874 | ok |
| 3 | 2020-05-02 02:58:44.325Z | scranton.dmevals.local | windows.sysmon | process.command_line | "PowerShell.exe" -noni -noexit -ep bypass -window hidden -c "sal a New-Object;Add-Type -AssemblyName 'System.Drawing'; $g=a System.Drawing.Bitmap('C:\Users\pbee… | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7htwOyZ | q-64f2e9a4aa | ok |
| 4 | 2020-05-02 02:58:44.325Z | scranton.dmevals.local | windows.sysmon | process.parent.executable | C:\Windows\System32\control.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7htwOyZ | q-64f2e9a4aa | ok |
| 5 | 2020-05-02 03:11:18.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | .\PsExec64.exe -accepteula \\NASHUA -u "dmevals\pbeesly" -p "Fl0nk3rt0n!T0by" -i 2 "C:\Windows\Temp\python.exe" | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qrRFHq | q-8670030bf3 | ok |
| 6 | 2020-05-02 03:10:22.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | Invoke-SeaDukeStage -ComputerName NASHUA | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qqQ-d4 | q-8670030bf3 | ok |

### F55 · malicious / high · T1649 · PowerShell Get-PrivateKeys exported every LocalMachine certificate (with private key) to .pfx files on scranton

Evidence status: **verified**

On scranton.dmevals.local, in the context of user pbeesly (SID ...-1107), a PowerShell script block named Get-PrivateKeys was executed at 2020-05-01T23:04:56-04:00 (script block 9d153741-75c3-4062-afe3-aeca0aee611b, path C:\Program Files\SysinternalsSuite\readme.ps1). It enumerates cert:\LocalMachine recursively and calls Export-PfxCertificate for every certificate with a thumbprint, writing password-protected .pfx files (password 'saribas') into $env:USERPROFILE\Downloads with random names. One second later Sysmon recorded the resulting file C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx created by powershell.exe (PID 3876). A later script block (Invoke-BeachCleanup, psversion.ps1, 23:08:51) deletes $env:USERPROFILE\Downloads\*.pfx, *.bmp, *.png and %APPDATA%\OfficeSupplies.7z, i.e. anti-forensic cleanup of the stolen certificate bundles. This is certificate/private-key theft for authentication (T1649) on a host that also shows other attacker tooling (hidden -ep bypass PowerShell decoding a bitmap, SysinternalsSuite.zip staging, PSEXESVC service installs on nashua).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qvSysm | q-520d3e132a | ok |
| 2 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\readme.ps1 | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qvSysm | q-520d3e132a | ok |
| 3 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | user.name | pbeesly | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qvSysm | q-520d3e132a | ok |
| 4 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | Get-PrivateKeys | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qvTSsN | q-a1518c1673 | ok |
| 5 | 2020-05-02 03:04:57.460Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hQQRgs | q-3cf3e7a07a | ok |
| 6 | 2020-05-02 03:04:57.460Z | scranton.dmevals.local | windows.sysmon | win.Image | C:\windows\system32\WindowsPowerShell\v1.0\powershell.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hQQRgs | q-3cf3e7a07a | ok |
| 7 | 2020-05-02 03:08:51.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-BeachCleanup {     Write-Host "[*] Cleaning up"     Remove-Item -Path "$env:USERPROFILE\Downloads\*.pfx" -Force     Remove-Item -Path "$env:USER… | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qrRC9i | q-a1518c1673 | ok |

### F05 · suspicious / medium · T1003.005 · HKLM\SECURITY\Cache\NL$1 writes are lsass.exe caching the intruder's own logons, not cachedump

Evidence status: **verified**

lsass.exe wrote HKLM\SECURITY\Cache\NL$1 (the cached-domain-credential store) five times: four times on nashua.dmevals.local between 03:11:40 and 03:15:03 and once on scranton.dmevals.local at 03:20:46. The nashua writes line up exactly with the PsExec64.exe launches from scranton (03:11:18, 03:12:25, 03:13:28, 03:14:42) that started C:\Windows\Temp\python.exe on nashua as dmevals\pbeesly, i.e. lsass populating the cache for those interactive logons. No cachedump tooling, no 4663/4656 access to the Cache key by a non-lsass process, and no matching script-block text was found, so this is a side effect of the intrusion rather than a cache-extraction technique.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:40.144Z | nashua.dmevals.local | windows.sysmon | registry.path | HKLM\SECURITY\Cache\NL$1 | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7c82OiA | q-ccedcd087b | ok |
| 2 | 2020-05-02 03:11:40.144Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7c82OiA | q-ccedcd087b | ok |
| 3 | 2020-05-02 03:12:46.768Z | nashua.dmevals.local | windows.sysmon | host.name | nashua.dmevals.local | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7cwoB6Q | q-ccedcd087b | ok |
| 4 | 2020-05-02 03:11:18.784Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\PsExec64.exe" -accepteula \\NASHUA -u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7cxoQzx | q-15bb43663b | ok |

### F09 · suspicious / medium · T1056.004 · wsmprovhost.exe (WinRM remote session) opened LSASS with 0x1f3fff on nashua

Evidence status: **verified**

On nashua.dmevals.local at 2020-05-02T03:09:29, wsmprovhost.exe (the WinRM host process, spawned at 03:09:23 as 'C:\windows\system32\wsmprovhost.exe -Embedding' under svchost.exe) requested a handle to \Device\HarddiskVolume2\Windows\System32\lsass.exe with AccessMask 0x1f3fff, and Sysmon event 10 shows the same wsmprovhost.exe accessing lsass with GrantedAccess 0x1f3fff. A remote PowerShell session reading LSASS memory is consistent with credential dumping over WinRM; the same user (pbeesly) also ran C:\Windows\Temp\python.exe on this host. No legitimate reason for wsmprovhost to request LSASS memory access was observed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:09:29.000Z | nashua.dmevals.local | windows.security | win.AccessMask | 0x1f3fff | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7njy6Co | q-594892f658 | ok |
| 2 | 2020-05-02 03:09:29.000Z | nashua.dmevals.local | windows.security | win.ProcessName | C:\Windows\System32\wsmprovhost.exe | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7njy6Co | q-594892f658 | ok |
| 3 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7c939yF | q-9153c740b0 | ok |
| 4 | 2020-05-02 03:09:23.885Z | nashua.dmevals.local | windows.sysmon | process.command_line | C:\windows\system32\wsmprovhost.exe -Embedding | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7c-4cYK | q-28cd6ddcb0 | ok |

### F21 · suspicious / medium · T1187 · NASHUA python.exe beaconing to 192.168.0.4:8443 with self-signed TLS cert (credential-capture listener)

Evidence status: **verified**

On nashua.dmevals.local, C:\Windows\Temp\python.exe (dropped at 03:10:23Z and launched repeatedly via PsExec64 from scranton as DMEVALS\pbeesly) made dozens of TCP connections from 10.0.1.6 to 192.168.0.4:8443 starting 2020-05-02T03:15:05Z. In the earlier zeek window the same host 10.0.1.6 (observer bobs.bigwheel.local) produced repeated RSTO ssl connections to 192.168.0.4:8443 accompanied by SSL::Invalid_Server_Cert notices ('self signed certificate'). This is the same external 192.168.0.4 endpoint used for the WebDAV coercion, and a self-signed TLS listener is consistent with an authentication-capture/relay endpoint; the python.exe is attacker tooling rather than normal system behaviour.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:15:05.142Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7c5ylrT | q-821bc80951 | ok |
| 2 | 2020-05-02 03:15:05.142Z | nashua.dmevals.local | windows.sysmon | destination.port | 8443 | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7c5ylrT | q-821bc80951 | ok |
| 3 | 2020-05-02 03:10:23.626Z | nashua.dmevals.local | windows.sysmon | win.TargetFilename | C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7c82-ha | q-b74ff903d5 | ok |
| 4 | 2020-04-30 00:40:44.740Z | bobs.bigwheel.local | zeek | zeek.note | SSL::Invalid_Server_Cert | .ds-logs-zeek-default-2026.10.20-000001 / AaFZSPJfH5wFd7qUct2z | q-08be945036 | ok |
| 5 | 2020-04-30 00:40:44.730Z | bobs.bigwheel.local | zeek | zeek.conn_state | RSTO | .ds-logs-zeek-default-2026.10.20-000001 / AaFZSPJfH5wFd7qVdaEh | q-08be945036 | ok |

### F28 · suspicious / medium · T1552.001 · Credential-harvesting tooling staged as .ps1 files in SysinternalsSuite; no plaintext credential files read

Evidence status: **verified**

The attacker's PowerShell functions were executed from files masquerading as Sysinternals content: C:\Program Files\SysinternalsSuite\readme.ps1 (Get-PrivateKeys) and C:\Program Files\SysinternalsSuite\psversion.ps1 (Invoke-Exfil), alongside a SysinternalsSuite archive unpacked into C:\Users\pbeesly\Downloads at 03:00:32-03:00:33Z. The session also ran Invoke-Discovery (WMI AV/firewall enumeration, net user group enumeration) at 03:04:03Z. However, no evidence was found of the adversary reading credential-bearing files: no process command line referenced unattend files, web.config, findstr/reg query/reg save/cmdkey/vaultcmd, and the only 4104 blocks matching password/credential keywords other than the attacker's own were benign PowerShell module resource strings on newyork.dmevals.local. The .txt/.xml file creations in the C152 stack are Cortana/Edge/WER/Windows Update artefacts and Sysinternals readme files. The technique is therefore assessed as suspicious staging rather than confirmed credentials-in-files theft.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\psversion.ps1 | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qjPglL | q-4b3f3c75ff | ok |
| 2 | 2020-05-02 03:04:03.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Discovery {     $DiscoveryInfo =@()     $CurrentDir = Get-Location      $DiscoveryInfo += [PSCustomObject]@{                 CurrentDirectory = … | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qvSytV | q-f753b2fe94 | ok |
| 3 | 2020-05-02 03:00:33.564Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Users\pbeesly\Downloads\SysinternalsSuite\Procmon.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7habqSt | q-d35d0c2dc3 | ok |
| 4 | 2020-05-02 03:01:30.000Z | newyork.dmevals.local | windows.powershell | win.ScriptBlockText | # Localized	09/15/2018 04:54 AM (GMT)	303:6.40.10614 	MSFT_ScriptResourceStrings.psd1  # Localized MSFT_ScriptResourceStrings.psd1    ConvertFrom-StringData @' … | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qwUVtv | q-8aa002535b | ok |

### F64 · suspicious / medium · T1552.001 · SCRANTON: accessChk.exe run from the attacker-staged SysinternalsSuite directory by pbeesly's PowerShell

Evidence status: **verified**

At 03:04:34 on scranton.dmevals.local, pbeesly's PowerShell ran accesschk.exe from the attacker-staged C:\Program Files\SysinternalsSuite directory (the same directory that held the credential-harvesting .ps1 scripts), one minute after sdelete64.exe wiped the dropped .scr, Draft.Zip and SysinternalsSuite.zip. This is permission reconnaissance supporting the credential-access chain rather than credential theft itself.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:34.951Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\accesschk.exe" | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hRQwNZ | q-e4bdd67e38 | ok |
| 2 | 2020-05-02 03:04:34.951Z | scranton.dmevals.local | windows.sysmon | process.parent.executable | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hRQwNZ | q-e4bdd67e38 | ok |
| 3 | 2020-05-02 03:02:04.324Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\sdelete64.exe" /accepteula C:\programdata\victim\???cod.3aka3.scr | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hWVSlm | q-e4bdd67e38 | ok |

### F62 · suspicious / medium · T1552.006 · SCRANTON: hidden PowerShell read HKLM\SOFTWARE\Javasoft 'value Supplement' and Invoke-Expression'd it, then launched hostui.exe elevated

Evidence status: **verified**

At 03:21:27-03:21:29 on scranton.dmevals.local, pbeesly's PowerShell ran 'Start-Process C:\Windows\System32\hostui.exe -verb runas' and a second PowerShell executed 'Get-ItemPropertyValue ''HKLM:\SOFTWARE\Javasoft'' ''value Supplement'' \| Invoke-Expression', which spawned a base64-encoded hidden PowerShell (-nop -w hidden -e ...). Reading a registry value and executing it is a configuration/secret-store abuse pattern; no plaintext credential value was observed in the logs.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:21:27.890Z | scranton.dmevals.local | windows.sysmon | process.parent.command_line | powershell.exe -c "Get-ItemPropertyValue 'HKLM:\\SOFTWARE\Javasoft' 'value Supplement' \| Invoke-Expression" | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7YJ9Kbo | q-e4bdd67e38 | ok |
| 2 | 2020-05-02 03:21:27.276Z | scranton.dmevals.local | windows.sysmon | process.parent.command_line | powershell.exe  -c "Start-Process C:\Windows\System32\hostui.exe -verb runas" | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7YE3lVE | q-e4bdd67e38 | ok |
| 3 | 2020-05-02 03:21:28.949Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\windows\System32\WindowsPowerShell\v1.0\powershell.exe" -nop -w hidden -e aQBmACgAWwBJAG4AdABQAHQAcgBdADoAOgBTAGkAegBlACAALQBlAHEAIAA0ACkAewAkAGIAPQAkAGUAbg… | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7YD3Who | q-e4bdd67e38 | ok |

### F61 · suspicious / medium · T1555.003 · SCRANTON: sdclt.exe (UAC bypass launcher) spawned by cmd.exe under pbeesly, immediately followed by hidden steganographic PowerShell and csc.exe compile

Evidence status: **verified**

At 02:58:42-02:58:43 on scranton.dmevals.local, three sdclt.exe processes were started by cmd.exe under pbeesly; sdclt is the classic UAC-bypass binary and its execution immediately preceded the hidden PowerShell that decoded monkey.png and compiled qkbkqqbs.dll via csc.exe (02:58:45). No browser credential-store file (Login Data / cookies) was observed being read, so this is assessed as suspicious elevation/loader activity rather than confirmed browser-credential theft.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:58:42.401Z | scranton.dmevals.local | windows.sysmon | process.command_line | C:\windows\system32\sdclt.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7huwtP3 | q-e4bdd67e38 | ok |
| 2 | 2020-05-02 02:58:45.297Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe" /noconfig /fullpaths @"C:\Users\pbeesly\AppData\Local\Temp\qkbkqqbs\qkbkqqbs.cmdline" | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7htvuyY | q-e4bdd67e38 | ok |
| 3 | 2020-05-02 02:58:44.338Z | scranton.dmevals.local | windows.sysmon | process.parent.command_line | "PowerShell.exe" -noni -noexit -ep bypass -window hidden -c "sal a New-Object;Add-Type -AssemblyName 'System.Drawing'; $g=a System.Drawing.Bitmap('C:\Users\pbee… | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7htwOyJ | q-e4bdd67e38 | ok |

### F33 · suspicious / low · T1555.004 · Windows Vault / Credential Manager artifacts touched on scranton during the intrusion

Evidence status: **verified**

On scranton.dmevals.local, vaultcli.dll was loaded by svchost.exe, SearchUI.exe, SearchIndexer.exe and smartscreen.exe between 03:20:52Z and 03:21:20Z, vaultsvc.dll was loaded by lsass.exe at 03:21:24Z, and lsass.exe deleted C:\Users\pbeesly\AppData\Local\Microsoft\Vault\UserProfileRoaming\Latest.dat at 03:22:35Z. These are the Windows Credential Manager/Vault stores, and the timing follows the malicious PowerShell LSASS access at 03:05:16Z. However, no vaultcmd/cmdkey command line, no 4688/4663 access to Vault or Credentials objects, and no PowerShell script block referencing vault/Credential/cmdkey was observed (C199, C200, C202, C201 all empty or unrelated), so this may be normal Vault service activity; it cannot be confirmed as credential theft from the available events.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:22:35.895Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Users\pbeesly\AppData\Local\Microsoft\Vault\UserProfileRoaming\Latest.dat | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRfJfH5wFd7b6t2mM | q-a0a73ed81f | ok |
| 2 | 2020-05-02 03:22:35.895Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRfJfH5wFd7b6t2mM | q-a0a73ed81f | ok |
| 3 | 2020-05-02 03:21:24.910Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Windows\System32\vaultsvc.dll | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7YK9pro | q-a0a73ed81f | ok |
| 4 | 2020-05-02 03:20:52.345Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Windows\System32\vaultcli.dll | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRfJfH5wFd7b_yhXF | q-a0a73ed81f | ok |

### F47 · suspicious / medium · T1558 · Compromised host chain (scranton → nashua) with LSASS handle access, but no Kerberos ticket theft/forgery observed

Evidence status: **verified**

On 2020-05-02 the pbeesly account on scranton.dmevals.local ran a SeaDuke-style PowerShell toolkit (Invoke-Discovery, Invoke-Persistence, Invoke-ScreenCapture, Invoke-Exfil, Invoke-BeachCleanup) launched from C:\ProgramData\victim\cod.3aka3.scr via cmd.exe, then used Invoke-Command against NASHUA and Invoke-SeaDukeStage -ComputerName NASHUA. On nashua.dmevals.local PSEXESVC.exe was created and spawned C:\Windows\Temp\python.exe as pbeesly. LSASS process-access events exist (326 total) but the rare high-access ones are attributable to system components (svchost/lsm.dll, wininit, csrss, WindowsAzureTelemetryService) and to PowerShell/wsmprovhost with a managed-code call trace, not to a credential-dumping tool. No Kerberos ticket manipulation (no krbtgt/SPN abuse, no forged-ticket indicators) was observed, so the T1558 family itself is not confirmed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:56:04.510Z | scranton.dmevals.local | windows.sysmon | process.parent.executable | C:\ProgramData\victim\â€®cod.3aka3.scr | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hy0Urg | q-cadd8b91f9 | ok |
| 2 | 2020-05-02 03:10:22.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | Invoke-SeaDukeStage -ComputerName NASHUA | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qqQ-d4 | q-1d911df3cf | ok |
| 3 | 2020-05-02 03:11:40.213Z | nashua.dmevals.local | windows.sysmon | process.command_line | "C:\Windows\Temp\python.exe"  | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7c82OhP | q-7510a3eb00 | ok |
| 4 | 2020-05-02 03:11:39.934Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\Windows\PSEXESVC.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7c82Oiy | q-b33780e3c9 | ok |
| 5 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hQQBhG | q-b078007414 | ok |

### F52 · suspicious / medium · T1606 · No forged web credential material observed; credential-access precursor (LSASS memory access) present on scranton and nashua

Evidence status: **verified**

Across windows.security, windows.sysmon, windows.powershell and windows.other (2020-05-02 02:55-03:28Z) there is no artifact of web-credential forging: no SAML/ADFS/token-signing or cookie/AES script blocks (C313, C324 zero hits), no browser cookie/Login Data file writes by anything other than svchost/MicrosoftEdge (C315/C316), and 4624 logon process/package stacks are ordinary (Kerberos 217, Advapi 76, User32 2, NtLmSsp 1). What is present is credential-access precursor activity: on scranton.dmevals.local PowerShell.exe (PID 2976) opened lsass.exe with GrantedAccess 0x1f3fff and 0x1fffff at 03:05:16Z, and on nashua.dmevals.local wsmprovhost.exe (PID 7720, PowerShell remoting host) opened lsass.exe with 0x1f3fff at 03:09:29Z. The scranton host also ran a malicious screen-saver C:\ProgramData\victim\...cod.3aka3.scr from explorer.exe as pbeesly at 02:55:56Z, later deleted with sdelete64.exe, and at 03:21:29Z pbeesly executed obfuscated PowerShell (GetProcAddress/ReflectedDelegate dynamic delegate + base64 PE blob, and a gzip+base64 scriptblock) - consistent with in-memory tooling that could harvest credentials. No forged cookie or SAML token was observed being created or used, so T1606 itself is not evidenced.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hQQBhJ | q-a01f6b26c4 | ok |
| 2 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.TargetImage | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hQQBhJ | q-a01f6b26c4 | ok |
| 3 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7c939yF | q-a01f6b26c4 | ok |
| 4 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7c939yF | q-a01f6b26c4 | ok |
| 5 | 2020-05-02 02:55:56.157Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\ProgramData\victim\â€®cod.3aka3.scr" /S | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hy0krT | q-a0504f0ae8 | ok |
| 6 | 2020-05-02 03:02:04.000Z | scranton.dmevals.local | windows.security | process.command_line | "C:\Program Files\SysinternalsSuite\sdelete64.exe" /accepteula C:\programdata\victim\???cod.3aka3.scr | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7ns9wrd | q-352043db38 | ok |
| 7 | 2020-05-02 03:21:29.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function jzI {  	Param ($yKR, $cq)		  	$vvA = ([AppDomain]::CurrentDomain.GetAssemblies() \| Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[… | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qzW1OH | q-4033b7c8d8 | ok |
| 8 | 2020-05-02 03:21:29.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | &amp;([scriptblock]::create((New-Object System.IO.StreamReader(New-Object System.IO.Compression.GzipStream((New-Object System.IO.MemoryStream(,[System.Convert]:… | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qzXFp5 | q-4033b7c8d8 | ok |

### F56 · suspicious / low · T1649 · Single ROOT certificate store blob modification on nashua by Sysmon.exe (no corroborating forgery activity)

Evidence status: **verified**

On nashua.dmevals.local at 2020-05-01T23:16:19-04:00 a Security 4657 event shows the REG_BINARY 'Blob' value of \REGISTRY\MACHINE\SOFTWARE\Microsoft\SystemCertificates\ROOT\Certificates\BE36A4562FB2EE05DBB3D32323ADF445084ED656 modified by process C:\Windows\Sysmon.exe under NASHUA$ (S-1-5-18, logon 0x3E7). It is the only SystemCertificates-related 4657 in the whole dataset (count 1), so it is not a routine pattern, but the writing process is Sysmon.exe and no certificate creation/export, forged-certificate use, or anomalous Kerberos ticket encryption was observed on nashua (all 14 4768 events use 0x12). Treated as suspicious-but-unconfirmed rather than confirmed forgery.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:16:19.000Z | nashua.dmevals.local | windows.security | win.ObjectName | \REGISTRY\MACHINE\SOFTWARE\Microsoft\SystemCertificates\ROOT\Certificates\BE36A4562FB2EE05DBB3D32323ADF445084ED656 | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7rzHZUI | q-00dcaec134 | ok |
| 2 | 2020-05-02 03:16:19.000Z | nashua.dmevals.local | windows.security | win.ProcessName | C:\Windows\Sysmon.exe | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7rzHZUI | q-00dcaec134 | ok |
| 3 | 2020-05-02 03:16:19.000Z | nashua.dmevals.local | windows.security | win.SubjectUserName | NASHUA$ | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7rzHZUI | q-00dcaec134 | ok |

### F02 · benign / medium · T1003.002 · SAM hive written by lsass.exe on scranton (normal SAM account-update behaviour, not a dump)

Evidence status: **verified**

The only SAM-hive registry write in the window is HKLM\SAM\SAM\Domains\Account\F written by C:\windows\system32\lsass.exe on scranton.dmevals.local at 03:19:10, alongside LogonUI.exe writing LoggedOnSAMUser for DMEVALS\pbeesly at 03:20:46. These are lsass-internal account/logon bookkeeping writes, not an export. No reg save / hive export command line, no SAM/SECURITY/SYSTEM hive file creation (only Prefetch .pf files matched), and no 4663/4656 access to SAM or SECURITY hive objects were observed. Note: the intrusion on scranton did not need SAM dumping because the operator already had the plaintext password for dmevals\pbeesly, which was passed to PsExec64.exe on the command line.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:10.368Z | scranton.dmevals.local | windows.sysmon | registry.path | HKLM\SAM\SAM\Domains\Account\F | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7cpgKxF | q-ccedcd087b | ok |
| 2 | 2020-05-02 03:19:10.368Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7cpgKxF | q-ccedcd087b | ok |
| 3 | 2020-05-02 03:20:46.738Z | scranton.dmevals.local | windows.sysmon | registry.path | HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\SessionData\2\LoggedOnSAMUser | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7cNAtxy | q-ccedcd087b | ok |

### F03 · benign / medium · T1003.003 · No NTDS.dit access, VSS copy or ntdsutil activity observed

Evidence status: **verified**

All NTDS-related checks returned zero hits: no process command line referencing ntds/ntdsutil/vssadmin/diskshadow, no .dit file creation, no file-creation event for ntds paths, no 4663 access to an ntds object, and no matching Windows.other or PowerShell script-block text. The domain controller utica.dmevals.local shows no evidence of directory-database theft in this window.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:20:36.000Z | utica.dmevals.local | windows.security | host.name | utica.dmevals.local | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7nOhdc5 | q-b07f473a09 | ok |

### F04 · benign / medium · T1003.004 · Only benign LOCAL SERVICE query of Policy\Secrets\$MACHINE.ACC on the DC; no LSA secret dumping

Evidence status: **verified**

The only SecretObject accesses in the dataset are two 4662 events on utica.dmevals.local (03:03:32 and 03:20:36) where NT AUTHORITY\LOCAL SERVICE queried Policy\Secrets\$MACHINE.ACC with AccessMask 0x2 (read) — routine machine-account secret access by a local service, not an attacker enumerating LSA secrets. No 4663/4656 access to SECURITY\Policy\Secrets, no registry modification of that path, and no lsadump/Secrets script-block or event-log text was found.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:20:36.000Z | utica.dmevals.local | windows.security | win.ObjectName | Policy\Secrets\$MACHINE.ACC | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7nOhdc5 | q-b07f473a09 | ok |
| 2 | 2020-05-02 03:20:36.000Z | utica.dmevals.local | windows.security | win.SubjectUserName | LOCAL SERVICE | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7nOhdc5 | q-b07f473a09 | ok |
| 3 | 2020-05-02 03:03:32.000Z | utica.dmevals.local | windows.security | win.AccessMask | 0x2 | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7nq8GZx | q-b07f473a09 | ok |

### F06 · benign / medium · T1003.006 · No DCSync: no directory-replication access on the DC and no drsuapi/lsadump tooling

Evidence status: **verified**

No 4929 (directory service replication source removed) events exist, no process command line or script block references drsuapi/lsadump/dcsync, and the only 4662 events on utica.dmevals.local are the two benign LOCAL SERVICE SecretObject queries — no DS-Replication-Get-Changes access on the domain object. The credential theft in this intrusion was LSASS memory access on member servers, not DCSync against the DC.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:20:36.000Z | utica.dmevals.local | windows.security | win.ObjectType | SecretObject | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7nOhdc5 | q-b07f473a09 | ok |

### F07 · benign / high · T1040 · netsh packet capture on scranton.dmevals.local is the Azure Network Watcher guest extension, not adversary sniffing

Evidence status: **verified**

The only packet-capture activity in the Windows telemetry is on scranton.dmevals.local at 2020-05-02T03:19:17Z: netsh.exe was launched as NT AUTHORITY\SYSTEM (LogonId 0x3e7, IntegrityLevel System) with 'trace start capture=yes traceFile="C:\windows\TEMP\E7116ECA-DFE6-43C7-8FA8-8D3AC5AA8726\B91E06C5-1C7C-4830-9A76-74FA211560A7.etl"' and stopped ~7s later with 'netsh trace stop'. Both invocations have ParentImage C:\Packages\Plugins\Microsoft.Azure.NetworkWatcher.NetworkWatcherAgentWindows\1.4.1421.1\NetworkWatcherAgent\NetworkWatcherAgent.exe /service, and the agent itself was started by services.exe and installed via cmd.exe running the extension's enable.cmd under WindowsAzureGuestAgent.exe. The agent binary reports Company 'Microsoft CoreXT' and Description 'Networking-NetAnalytics release_14_nwa (af53be328) Microsoft CoreXT'. The netsh process loaded only the Microsoft-signed hnetmon.dll (Signature 'Microsoft Windows', SignatureStatus Valid). The same NetworkWatcherAgent appears on nashua, scranton and utica (73 sysmon events, mostly registry), i.e. it is a fleet-wide Azure platform extension. The parallel logman.exe ETW trace create/start/stop commands (GAEvents, RTEvents, WindowsAzure-GuestAgent-Diagnostic writing to C:\WindowsAzure\Logs\*.etl) are likewise all children of C:\WindowsAzure\Packages\WaAppAgent.exe. No pktmon, dumpcap, windump, RawCap, Wireshark or Npcap/wpcap/npf driver load was observed (C058 and C059 returned zero hits; the only packet-related image load was hnetmon.dll). Separately, the genuine intrusion in this window (pbeesly using PsExec64.exe with the plaintext password to run an unsigned C:\Windows\Temp\python.exe on nashua) shows no capture tooling, so T1040 is not part of the attacker's tradecraft here.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:17.154Z | scranton.dmevals.local | windows.sysmon | process.command_line | C:\windows\system32\netsh.exe trace start capture=yes traceFile="C:\windows\TEMP\E7116ECA-DFE6-43C7-8FA8-8D3AC5AA8726\B91E06C5-1C7C-4830-9A76-74FA211560A7.etl" | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7cla5Dm | q-58e7607975 | ok |
| 2 | 2020-05-02 03:19:17.154Z | scranton.dmevals.local | windows.sysmon | win.ParentImage | C:\Packages\Plugins\Microsoft.Azure.NetworkWatcher.NetworkWatcherAgentWindows\1.4.1421.1\NetworkWatcherAgent\NetworkWatcherAgent.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7cla5Dm | q-58e7607975 | ok |
| 3 | 2020-05-02 03:19:24.000Z | scranton.dmevals.local | windows.security | process.command_line | C:\windows\system32\netsh.exe trace stop | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7nSl9D4 | q-e9216bff73 | ok |
| 4 | 2020-05-02 03:20:41.000Z | scranton.dmevals.local | windows.security | process.command_line | C:\windows\system32\cmd.exe /c ""C:\Packages\Plugins\Microsoft.Azure.NetworkWatcher.NetworkWatcherAgentWindows\1.4.1421.1\NetworkWatcherAgent\enable.cmd"" | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7nOhte9 | q-d65a0ae3c2 | ok |
| 5 | 2020-05-02 03:19:17.353Z | scranton.dmevals.local | windows.sysmon | win.ImageLoaded | C:\Windows\System32\hnetmon.dll | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7cUGpQW | q-3f0601edee | ok |
| 6 | 2020-05-02 03:19:17.353Z | scranton.dmevals.local | windows.sysmon | win.Signature | Microsoft Windows | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7cUGpQW | q-3f0601edee | ok |
| 7 | 2020-05-02 03:19:13.877Z | scranton.dmevals.local | windows.sysmon | win.Description | Networking-NetAnalytics release_14_nwa (af53be328) Microsoft CoreXT | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hy1Evq | q-2b235b96ea | ok |
| 8 | 2020-05-02 03:19:29.878Z | scranton.dmevals.local | windows.sysmon | process.command_line | "logman.exe" create trace GAEvents -max 50 -f bincirc -o C:\WindowsAzure\Logs\WaAppAgent.etl -p "{3000b92b-ca8b-4269-90ea-c4185ee09e92}" | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7cdRgzF | q-66a1c57682 | ok |
| 9 | 2020-05-02 03:11:18.784Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\PsExec64.exe" -accepteula \\NASHUA -u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7cxoQzx | q-66a1c57682 | ok |
| 10 | 2020-05-02 03:11:40.213Z | nashua.dmevals.local | windows.sysmon | process.command_line | "C:\Windows\Temp\python.exe"  | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7c82OhP | q-dc53890b2a | ok |

### F11 · benign / medium · T1056.001 · No keylogger artefacts: keyboard registry writes and hook/image loads are OS baseline

Evidence status: **verified**

The 26 registry writes matching Keyboard/keylog/SetWindowsHookEx are all keyboard-layout and device-enumeration keys (HKU\.DEFAULT\Keyboard Layout\Preload, CTF KeyboardLayout, HARDWARE\DEVICEMAP\KeyboardClass, TERMINPUT_BUS device parameters) — normal Windows input-stack activity. No Sysmon 1 command line, Sysmon 7 image load, or PowerShell 4104 script block referencing keylog/GetAsyncKeyState/SetWindowsHookEx was found (checks C069, C070, C073 returned zero hits). No keylogger service was installed: the only 7045 service installs are javamtsup.exe and PSEXESVC.exe. Note that the malicious PowerShell on scranton (Invoke-Exfil, hidden -e encoded command, IEX from a bitmap) is credential/exfil activity, not input capture.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:15.000Z | scranton.dmevals.local | windows.other | process.executable | C:\Windows\System32\javamtsup.exe | .ds-logs-windows.other-default-2026.10.20-000001 / AaFZR_JfH5wFd7pNHuDg | q-f9ccf38ced | ok |
| 2 | 2020-05-02 03:11:39.000Z | nashua.dmevals.local | windows.other | process.executable | %SystemRoot%\PSEXESVC.exe | .ds-logs-windows.other-default-2026.10.20-000001 / AaFZR_JfH5wFd7pNHuCk | q-f9ccf38ced | ok |

### F12 · benign / medium · T1056.002 · Only genuine Windows consent.exe prompts; no fake credential GUI

Evidence status: **verified**

The three process-creation hits for Credential/consent/Runas are all C:\Windows\System32\consent.exe (the legitimate UAC consent UI) in both Sysmon 1 and Security 4688. The PowerShell 4104 hits for Credential/Get-Credential/Windows.Forms/InputBox are module-help text and the Invoke-Exfil function that builds a PSCredential from a hardcoded password — not a GUI prompt harvesting user input. A UAC elevation was requested on scranton at 03:21:19 ('Start-Process C:\Windows\System32\hostui.exe -verb runas'), which is elevation, not GUI input capture.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:21:19.323Z | scranton.dmevals.local | windows.sysmon | process.command_line | powershell.exe  -c "Start-Process C:\Windows\System32\hostui.exe -verb runas" | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRfJfH5wFd7b8wDMC | q-a170136fdf | ok |
| 2 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qjPglL | q-ebdb7f354c | ok |

### F13 · benign / medium · T1056.003 · No web portal capture: no web-root writes or login-page tampering

Evidence status: **verified**

No file creation in wwwroot/inetpub or login/portal pages was observed (Sysmon 11 hits are SysinternalsSuite downloads such as Autologon.exe/logonsessions.exe and netlogon.ftl), no 4663 object access on web roots, and no process creation referencing wwwroot/inetpub/iis (checks C080, C081 zero hits). Zeek HTTP traffic (non-overlapping window, 2020-04-30) shows only /webdav, /webdav/OfficeSupplies.7z and /webdav/python.exe — WebDAV file transfer used for exfiltration, not a credential-capturing portal. The WebDAV activity is malicious exfil but does not constitute web portal capture.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qjPglL | q-ebdb7f354c | ok |
| 2 | 2020-05-02 03:10:23.154Z | scranton.dmevals.local | windows.sysmon | process.command_line | rundll32.exe C:\windows\system32\davclnt.dll,DavSetCookie 192.168.0.4 http://192.168.0.4/webdav | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7c93Nx4 | q-47f2093d6f | ok |

### F10 · benign / high · T1056.004 · Benign LSASS handle requests by Defender, Azure guest-log collector, lsass itself and csrss

Evidence status: **verified**

The remaining LSASS access events are attributable to known system components: MsMpEng.exe (Windows Defender) with 0x1fffff at 03:20:15 on scranton, CollectGuestLogs.exe (WindowsAzure guest agent) with 0x1410 on scranton/nashua/utica/newyork, lsass.exe opening its own object with 0x1478, svchost.exe with 0x101001/0x3000, wininit.exe with 0x1fffff/0x1000000 during the 03:19:09 lsass restart, and csrss.exe's CreateRemoteThread into lsass with StartModule KERNELBASE.dll / StartFunction CtrlRoutine. These are standard security/telemetry/OS behaviour, not hooking.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:20:15.000Z | scranton.dmevals.local | windows.security | win.ProcessName | C:\Program Files\Windows Defender\MsMpEng.exe | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7nSlNDC | q-594892f658 | ok |
| 2 | 2020-05-02 03:20:42.000Z | scranton.dmevals.local | windows.security | win.ProcessName | C:\WindowsAzure\Packages\CollectGuestLogs.exe | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7nKhItU | q-594892f658 | ok |
| 3 | 2020-05-02 03:18:34.813Z | scranton.dmevals.local | windows.sysmon | win.StartFunction | CtrlRoutine | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7cyrL8F | q-697f9456f5 | ok |
| 4 | 2020-05-02 03:19:09.803Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1000000 | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7cpgKyV | q-9153c740b0 | ok |

### F14 · benign / high · T1110 · No brute-force / password-guessing activity observed; credential theft on SCRANTON was via lsass memory access and certificate export, not password attacks

Evidence status: **verified**

Across windows.security (02:55:25–03:28:09Z), windows.other, windows.sysmon and windows.powershell there are zero 4625 failed-logon events, no failed-logon messages in windows.other, and no net.exe/net1/hydra-style login tooling in sysmon process creation. The only 'password'-related hits are the attacker's own PowerShell credential handling (Get-PrivateKeys exporting PFX files with a hardcoded password 'saribas', and Invoke-Exfil building a PSCredential for 'cozy'), which is credential access/exfiltration, not brute force. The T1110 family itself is not observed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qvSysm | q-2a219e974b | ok |
| 2 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qjPglL | q-6faee2b80d | ok |

### F15 · benign / high · T1110.001 · No password guessing: no failed logons, no login tooling; only a hidden PowerShell stager command line matched the 'pass' keyword

Evidence status: **verified**

The single sysmon process-creation hit for the pass/login keyword search is a hidden PowerShell one-liner on scranton.dmevals.local (parent control.exe, 02:58:44Z) that decodes a bitmap into a script — it matched only because of '-ep bypass', not because it attempts logons. No 4625 events exist in windows.security at all, so there is no evidence of password guessing against any account.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:58:44.325Z | scranton.dmevals.local | windows.sysmon | process.command_line | "PowerShell.exe" -noni -noexit -ep bypass -window hidden -c "sal a New-Object;Add-Type -AssemblyName 'System.Drawing'; $g=a System.Drawing.Bitmap('C:\Users\pbee… | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7htwOyZ | q-c7d35e430d | ok |

### F18 · benign / high · T1110.004 · No credential stuffing: the only credential lists in scripts are the attacker's own hardcoded exfil credentials

Evidence status: **verified**

The two 4104 hits for 'credential'/'password' are Microsoft's own MSFT_ScriptResourceStrings.psd1 localization text on newyork.dmevals.local (SYSTEM), not credential lists. The attacker scripts on scranton use single hardcoded credentials ('saribas' for PFX export, 'cozy'/'MyCozyPassw0rd!' for the WebDAV exfil drive at \\192.168.0.4\webdav) rather than stuffing lists of stolen username/password pairs against logon services. No 4625 events and no stuffing tooling were observed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:01:30.000Z | newyork.dmevals.local | windows.powershell | win.ScriptBlockText | # Localized	09/15/2018 04:54 AM (GMT)	303:6.40.10614 	MSFT_ScriptResourceStrings.psd1  # Localized MSFT_ScriptResourceStrings.psd1    ConvertFrom-StringData @' … | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qwUVtv | q-9aadba0043 | ok |
| 2 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qjPglL | q-6faee2b80d | ok |

### F22 · benign / high · T1187 · Routine SYSVOL/ADMIN$/IPC$ share access and SMB connections are benign administrative traffic

Evidence status: **verified**

The 5140/5145 share-access hits in windows.security are ordinary domain traffic: NEWYORK$ reading SYSVOL gpt.ini/GptTmpl.inf over its own IPv6 link-local address, SCRANTON$/NASHUA$/UTICA$/WEC$ connecting to \\*\IPC$ and \\*\SYSVOL for Group Policy and SAMR, and pbeesly accessing \\*\ADMIN$\Temp\python.exe on nashua (the PsExec staging of the tooling, not a coercion). The 66 sysmon port 445/139 connections are System PID 4 kernel connections between 10.0.1.x hosts and 10.0.0.4 (the DC), i.e. normal domain SMB. The windows.other event.code 6 hits are standard file-system filter driver load messages (WdFilter, SysmonDrv, FileInfo, Wof, CldFlt, luafv) on scranton at boot. None of these represent forced authentication to an attacker-controlled resource.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:01:43.000Z | newyork.dmevals.local | windows.security | win.ShareName | \\*\SYSVOL | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7ns-Aqw | q-2c664618f2 | ok |
| 2 | 2020-05-02 03:04:04.000Z | newyork.dmevals.local | windows.security | win.ShareName | \\*\IPC$ | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7nq72Zu | q-2c664618f2 | ok |
| 3 | 2020-05-02 03:10:23.000Z | nashua.dmevals.local | windows.security | win.ShareName | \\*\ADMIN$ | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7niytut | q-2c664618f2 | ok |
| 4 | 2020-05-02 03:01:43.033Z | scranton.dmevals.local | windows.sysmon | process.executable | System | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hWVykL | q-2daa2f85ba | ok |
| 5 | 2020-05-02 03:18:53.000Z | scranton.dmevals.local | windows.other | message | File System Filter 'SysmonDrv' (0.0, ‎2020‎-‎04‎-‎27T11:29:43.000000000Z) has successfully loaded and registered with Filter Manager. | .ds-logs-windows.other-default-2026.10.20-000001 / AaFZR_JfH5wFd7pNHuDM | q-d7041607ab | ok |

### F24 · benign / high · T1212 · wsmprovhost.exe LSASS handle on NASHUA is PowerShell remoting Get-Process -IncludeUserName, not exploitation

Evidence status: **verified**

On nashua.dmevals.local at 2020-05-02T03:09:29.430Z, wsmprovhost.exe (PID 7720) opened lsass.exe with GrantedAccess 0x1f3fff. The call trace is entirely backed by signed .NET/PowerShell modules (System.ni.dll and Microsoft.PowerShell.Commands.Management.ni.dll), and the corresponding 4104 script block on NASHUA at 23:09:28 is 'Get-Process -IncludeUserName \| Select-Object UserName,SessionId ...' issued via Invoke-Command -ComputerName NASHUA from scranton. That cmdlet legitimately queries process owners, which requires opening LSASS. It is a side effect of the actor's lateral session enumeration, not an exploit against a credential service.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.CallTrace | C:\windows\SYSTEM32\ntdll.dll+9c584\|C:\windows\System32\KERNELBASE.dll+2732e\|C:\windows\assembly\NativeImages_v4.0.30319_64\System\9803982d7bc887e2745bff18a43… | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7c939yF | q-6d83d54d86 | ok |
| 2 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7c939yF | q-6d83d54d86 | ok |
| 3 | 2020-05-02 03:09:28.000Z | nashua.dmevals.local | windows.powershell | win.ScriptBlockText |  Get-Process -IncludeUserName \| Select-Object UserName,SessionId \| Where-Object { $_.UserName -like "*\$env:USERNAME" } \| Sort-Object SessionId -Unique  | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qrRapX | q-734722cc87 | ok |

### F25 · benign / high · T1212 · Remaining LSASS handle access (svchost/lsm.dll, wininit, csrss, Azure telemetry) is normal Windows behaviour

Evidence status: **verified**

Of 326 Sysmon event 10 hits on lsass.exe, 293 requested only 0x1000 and 24 requested 0x1400. The elevated-access remainder on scranton.dmevals.local is accounted for by OS components: svchost.exe with a call trace through c:\windows\system32\lsm.dll (0x101001, 03:18:34Z), wininit.exe (0x1000000 and 0x1fffff, 03:19:09Z) and csrss.exe (0x1fffff, 03:19:09Z) during a session-manager restart, and WindowsAzureTelemetryService.exe via CorperfmonExt.dll (0x1400, 03:19:42-03:19:50Z). None of these show unbacked call-trace frames. The windows.other 'code 1/10/11' hits are Hyper-V miniport pause/restart and time-change messages, and the zeek notices/weirds (ip_hdr_len_zero, truncated_IP, unknown_dce_rpc_auth_type, self-signed certs) are on a non-overlapping 2020-04-30 capture with no exploit signature. No service-install (7045) events were present in windows.security.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:18:34.438Z | scranton.dmevals.local | windows.sysmon | win.CallTrace | C:\windows\SYSTEM32\ntdll.dll+9def4\|c:\windows\system32\lsm.dll+1aa6e\|c:\windows\system32\lsm.dll+1a9c3\|c:\windows\system32\lsm.dll+65e1\|c:\windows\system32… | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7cyrL9g | q-f4c6668d86 | ok |
| 2 | 2020-05-02 03:19:42.009Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\WindowsAzure\Packages\Telemetry\WindowsAzureTelemetryService.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7cUGJOD | q-f4c6668d86 | ok |
| 3 | 2020-05-02 03:19:09.803Z | scranton.dmevals.local | windows.sysmon | win.CallTrace | C:\windows\SYSTEM32\ntdll.dll+9c584\|C:\windows\system32\basesrv.DLL+2fba\|C:\windows\SYSTEM32\CSRSRV.dll+5af4\|C:\windows\SYSTEM32\ntdll.dll+6cedf | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7cpgKyU | q-f4c6668d86 | ok |
| 4 | 2020-05-02 03:02:46.000Z | scranton.dmevals.local | windows.other | message | Miniport NIC 'Microsoft Hyper-V Network Adapter' restarted | .ds-logs-windows.other-default-2026.10.20-000001 / AaFZR_JfH5wFd7pNHuBw | q-d9b0a0e967 | ok |
| 5 | 2020-04-30 00:14:21.969Z | simplerockbuild.simplerock.lan | zeek | message | {"@stream":"weird","@system":"simplerockbuild.simplerock.lan","@proc":"zeek","ts":1588205661.969959,"uid":"C3HnI71C1OMdjvWltf","id_orig_h":"10.0.1.4","id_orig_p… | .ds-logs-zeek-default-2026.10.20-000001 / AaFZSPJfH5wFd7o_Z1bK | q-634de48a61 | ok |

### F26 · benign / medium · T1539 · No web session cookie theft observed; scranton host instead ran a file-harvest/archive/exfil chain under pbeesly

Evidence status: **verified**

Hunting for T1539 on the 2020-05-02 window found no evidence of browser cookie-store theft. The only file-create events matching cookie/credential-store names were Edge's own runtime files on scranton.dmevals.local (MicrosoftEdge.exe creating _TempTestAccess.txt, RecoveryStore dat and ~DF*.TMP under C:\Users\pbeesly\AppData\Local\Packages\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\AC\MicrosoftEdge\User\Default), plus a svchost.exe write to the LocalService INetCookies package path — normal browser/OS behaviour. No 4663 object-access audit events referenced Cookies, Login Data, Web Data or the Edge profile, and no process command line referenced cookies, sqlite or a browser credential database. The 4104 script blocks that matched the cookie/sqlite keyword check were Microsoft module manifests (xStorage, xADCommon, DNSClientCache) loaded by SYSTEM on newyork.dmevals.local, i.e. benign module loading. Separately, the same window does contain clearly malicious activity on scranton.dmevals.local by user pbeesly: a recursive collection of documents/password-named files into %APPDATA%\Draft.Zip, a screen-capture/keystroke-check toolkit, and an Invoke-Exfil function that 7-Zips the Downloads folder and copies it to a WebDAV share at \\192.168.0.4\webdav using hardcoded credentials. That is credential/document collection and exfiltration, but it targets files and screen/keyboard input, not browser session cookies, so it does not satisfy T1539.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:21:05.198Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Users\pbeesly\AppData\Local\Packages\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\AC\MicrosoftEdge\User\Default\DataStore\_TempTestAccess.txt | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7YE4VZs | q-d9371a2452 | ok |
| 2 | 2020-05-02 03:21:05.681Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Windows\ServiceProfiles\LocalService\AppData\Local\Packages\warp_jit_db4a1097-b484-4973-bbf2-a04208ecd4d4\AC\INetCookies | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7cPCBow | q-177065e74c | ok |
| 3 | 2020-05-02 02:56:17.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | $env:APPDATA;$files=ChildItem -Path $env:USERPROFILE\ -Include *.doc,*.xps,*.xls,*.ppt,*.pps,*.wps,*.wpd,*.ods,*.odt,*.lwp,*.jtd,*.pdf,*.zip,*.rar,*.docx,*.url,… | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7q0ZP57 | q-b07ae28dc9 | ok |
| 4 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qjPglL | q-cf45294542 | ok |
| 5 | 2020-05-02 03:05:45.000Z | scranton.dmevals.local | windows.powershell | message | Creating Scriptblock text (1 of 1):  <# PsTools Version in this package: 2.44 #> function Invoke-ScreenCapture # https://www.pdq.com/blog/capturing-screenshots-… | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qvSyvc | q-c9c4104b15 | ok |
| 6 | 2020-05-02 02:56:18.032Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Users\pbeesly\AppData\Roaming\Draft.Zip | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hwzKeY | q-b68e97ec75 | ok |

### F29 · benign / high · T1552.002 · No credential access via registry observed

Evidence status: **verified**

Registry writes touching password/credential paths on the Windows hosts are all operating-system activity: HKLM\System\CurrentControlSet\Control\DeviceGuard\Scenarios\CredentialGuard\Enabled, the CredentialEnrollmentManagerUserSvc_13619b service keys, IdentityCRL ProviderPasswordLength/CharacterGroups defaults, MuiCache entries for CredentialEnrollmentManager.exe and vaultsvc.dll, and Winlogon PasswordExpiryNotification values written by winlogon.exe. No reg query/reg save/cmdkey/vaultcmd command lines were found in Sysmon process creation, and no 4663 object access to Password/Credential/Secret registry keys was recorded. No adversary registry credential harvesting is evident.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:21:20.841Z | scranton.dmevals.local | windows.sysmon | registry.path | HKU\S-1-5-21-1830255721-3727074217-2423397540-1107\Software\Microsoft\Windows\Winlogon\PasswordExpiryNotification\NotShownReason | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7YK95pg | q-8146ff28ab | ok |
| 2 | 2020-05-02 03:19:49.485Z | scranton.dmevals.local | windows.sysmon | registry.path | HKU\.DEFAULT\Software\Classes\Local Settings\MuiCache\4\52C64B7E\@%SystemRoot%\system32\vaultsvc.dll,-1003 | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7cTFiiN | q-8146ff28ab | ok |

### F30 · benign / high · T1552.003 · No shell history access observed

Evidence status: **verified**

No PowerShell script block, process command line, file creation or 4663 object access referencing ConsoleHost_history, Get-History or any history file was found on any host. The only process whose command line referenced a .txt file was logman.exe, which is the Azure guest agent (parent C:\WindowsAzure\Packages\WaAppAgent.exe) creating ETW trace sessions with -pf C:\WindowsAzure\Packages\GuestAgent\ProviderGuids.txt. No shell-history credential theft is evident.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:41.076Z | scranton.dmevals.local | windows.sysmon | process.command_line | "logman.exe" create trace RTEvents -max 50 -f bincirc -o C:\WindowsAzure\Logs\RuntimeEvents.etl -pf C:\WindowsAzure\Packages\GuestAgent\ProviderGuids.txt | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7cfUP4A | q-2ab888093b | ok |
| 2 | 2020-05-02 03:19:41.076Z | scranton.dmevals.local | windows.sysmon | process.parent.executable | C:\WindowsAzure\Packages\WaAppAgent.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7cfUP4A | q-2ab888093b | ok |

### F31 · benign / high · T1552.006 · SYSVOL/GPP reads are routine domain GPO refresh, no cpassword harvesting

Evidence status: **verified**

All SYSVOL access in windows.security (5145) is machine-account Group Policy refresh against \\*\SYSVOL on newyork.dmevals.local: NEWYORK$ from fe80::e40c:95b6:b0a7:6429, SCRANTON$ from 10.0.1.4 and NASHUA$ from 10.0.1.6, reading only gpt.ini, the Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf and directory listings for policy {31B2F340-016D-11D2-945F-00C04FB984F9} and {6AC1786C-016F-11D2-945F-00C04fB984F9}. The matching zeek smb_files records (2020-04-30, non-overlapping window) show the same gpt.ini/GptTmpl.inf pattern from 10.0.1.4 and 10.0.1.6. No Groups.xml, Preferences directory or cpassword reference appears in any script block, command line or file event, so no Group Policy Preferences credential extraction is evident.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:16.000Z | newyork.dmevals.local | windows.security | win.RelativeTargetName | dmevals.local\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7ncs5oy | q-14e220219f | ok |
| 2 | 2020-05-02 03:19:16.000Z | newyork.dmevals.local | windows.security | user.name | SCRANTON$ | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7ncs5oy | q-14e220219f | ok |
| 3 | 2020-04-30 00:20:49.313Z | bobs.bigwheel.local | zeek | message | {"@stream":"smb_files","@system":"bobs.bigwheel.local","@proc":"zeek","ts":1588206049.313572,"uid":"CF37FuG0Jho600cAa","id_orig_h":"10.0.1.6","id_orig_p":56957,… | .ds-logs-zeek-default-2026.10.20-000001 / AaFZSPJfH5wFd7qUcN0h | q-08b0582072 | ok |

### F34 · benign / medium · T1555.003 · No browser credential-store access observed

Evidence status: **verified**

Checks C191, C193, C194, C195 and C196 for browser credential files (Login Data, logins.json, key4.db, Cookies, Web Data) returned no hits. The only browser-related file activity was ordinary MicrosoftEdge.exe writes to its own AppData package folders on scranton.dmevals.local at 03:18:33Z and 03:21:05Z (temp files, RecoveryStore, _TempTestAccess.txt), which is normal Edge operation, not credential theft. No process opened a handle to chrome.exe/firefox.exe/msedge.exe for credential extraction.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:21:05.198Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Users\pbeesly\AppData\Local\Packages\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\AC\MicrosoftEdge\User\Default\DataStore\_TempTestAccess.txt | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7YE4VZs | q-b061d163b8 | ok |
| 2 | 2020-05-02 03:18:33.063Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\Windows\SystemApps\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\MicrosoftEdge.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7crhjub | q-b061d163b8 | ok |

### F35 · benign / medium · T1555.005 · No password-manager access observed

Evidence status: **verified**

Checks C203, C204, C205, C206 and C207 for KeePass/1Password/Bitwarden execution, .kdbx file creation and password-manager process handles returned no hits. The only archive activity seen was on nashua.dmevals.local, where C:\Windows\Temp\Rar.exe created a password-protected working.zip at 03:16:19Z under pbeesly — that is data staging/collection, not password-manager credential theft.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:16:19.395Z | nashua.dmevals.local | windows.sysmon | process.command_line | "C:\Windows\Temp\Rar.exe" a -hpfGzq5yKw C:\Users\pbeesly\Desktop\working.zip C:\Users\pbeesly\AppData\Roaming\working.zip | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7c4xY6Y | q-73e14056fb | ok |

### F37 · benign / medium · T1556.001 · No domain-controller authentication tampering; LSASS access on DCs is AV/telemetry/system

Evidence status: **verified**

The 326 LSASS process-access events are dominated by svchost.exe (289), the Azure IaaSAntimalware AntimalwareConfig.exe (15) and WindowsAzureTelemetryService.exe (13) with read-only masks 0x1000/0x1400; the 0x1FFFFF/0x1F3FFF handles from wininit.exe/csrss.exe at 03:19:09 on scranton are the normal boot-time LSASS handoff (lsass.exe itself was created at 03:19:09.809). No 7045 service install pointing at lsass/cryptdll, no 4657 change to Lsa/SecurityProviders/WDigest, and no 4739 domain-policy change were observed. The only non-standard LSASS accessor is the malicious PowerShell covered under T1556, which is not DC authentication patching.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:09.809Z | scranton.dmevals.local | windows.sysmon | process.command_line | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7cxqOgJ | q-552998e8e8 | ok |
| 2 | 2020-05-02 03:12:46.000Z | nashua.dmevals.local | windows.other | win.ServiceName | PSEXESVC | .ds-logs-windows.other-default-2026.10.20-000001 / AaFZR_JfH5wFd7pNHuDx | q-7271bed453 | ok |
| 3 | 2020-05-02 03:04:15.000Z | scranton.dmevals.local | windows.other | win.ImagePath | C:\Windows\System32\javamtsup.exe | .ds-logs-windows.other-default-2026.10.20-000001 / AaFZR_JfH5wFd7pNHuDg | q-7271bed453 | ok |

### F38 · benign / high · T1556.002 · No password filter DLL installed or registered

Evidence status: **verified**

No Sysmon EventID 11 file creation of a DLL into System32/SysWOW64, no registry write to 'Notification Packages' or PasswordFilter keys, and no 4657 change to Notification/Lsa objects were returned. The 18,866 System32/SysWOW64 image loads are all standard Microsoft DLLs (ntdll, KernelBase, kernel32, rpcrt4, sechost, ...). No password-filter persistence is present.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:09.865Z | scranton.dmevals.local | windows.sysmon | registry.path | HKLM\System\CurrentControlSet\Control\Lsa\LsaCfgFlagsDefault | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7cpgKyZ | q-aa2529c79d | ok |
| 2 | 2020-05-02 03:19:10.368Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7cpgKxG | q-aa2529c79d | ok |

### F39 · benign / high · T1556.005 · No reversible-encryption / Set-ADAccountControl activity

Evidence status: **verified**

No PowerShell 4104/4103 script block or Sysmon process command line referenced ReversibleEncryption, AllowReversiblePasswordEncryption, Set-ADAccountControl or dsmod, and no 4739 domain-policy change events exist in windows.security. The only AD-related PowerShell on newyork.dmevals.local is the stock ActiveDirectory module resource strings loaded by SYSTEM.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:16:32.000Z | newyork.dmevals.local | windows.powershell | win.ScriptBlockText | dentity parameter, but the New-ADUser cmdlet uses the         Name parameter.     .EXAMPLE         $getADUserParams = Get-CommonADParameters @PSBoundParameters … | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qyVUi_ | q-7dd781956c | ok |

### F40 · benign / medium · T1556.006 · No MFA configuration change observed

Evidence status: **verified**

No 4739 (domain policy changed) events exist in windows.security, so no MFA/authentication-policy weakening is recorded. Logon types are ordinary (3: 218, 5: 61, 2: 15, 10: 2, 0: 1) and logon process names are Kerberos/Advapi/User32/NtLmSsp. Note the attacker did reuse a cleartext password via PsExec (4648 for pbeesly to NASHUA), but that is credential reuse, not MFA tampering.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:12:25.000Z | scranton.dmevals.local | windows.security | win.TargetServerName | NASHUA | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7nixwZC | q-0f4118591a | ok |
| 2 | 2020-05-02 03:12:25.000Z | scranton.dmevals.local | windows.security | win.TargetUserName | pbeesly | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7nixwZC | q-0f4118591a | ok |

### F41 · benign / high · T1556.007 · No hybrid-identity / directory-service modification

Evidence status: **verified**

No 5136 directory-service change events exist in windows.security, and the 20,259 Sysmon image loads contain only standard Microsoft DLLs — nothing loaded into AAD Connect, Azure AD or cloud-identity processes. The WindowsAzureTelemetryService.exe LSASS reads (0x1400) are the Azure guest-agent telemetry, not identity tampering.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:42.009Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\WindowsAzure\Packages\Telemetry\WindowsAzureTelemetryService.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7cUGJOD | q-37a4359874 | ok |

### F42 · benign / high · T1556.008 · No network provider DLL registered; npmproxy/facecredentialprovider loads are normal

Evidence status: **verified**

No Sysmon registry write to a NetworkProvider key and no 4657 change to a NetworkProvider object were returned; the 4657 ObjectName values are WMI Autologger GUIDs and certificate/WSMAN keys. The 'np/provider' image-load hits are ordinary Windows components (npmproxy.dll, InputHost.dll, TextInputFramework.dll, facecredentialprovider.dll). The malicious PowerShell LSASS access is covered under T1556, not a network-provider implant.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:21:09.000Z | scranton.dmevals.local | windows.security | win.ProcessName | C:\Windows\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy\SearchUI.exe | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7nKgYvV | q-4c2cfc1769 | ok |

### F43 · benign / medium · T1557 · No adversary-in-the-middle activity observed; network and logon evidence consistent with normal domain operations

Evidence status: **verified**

Across the Windows and Zeek windows there is no evidence of traffic interception. Sysmon EventCode=3 destinations are dominated by the domain controllers (192.168.0.4, 10.0.0.4) and local/loopback addresses, with the remainder being Microsoft/Office telemetry endpoints. The only NTLM network logon (4624, LogonType 3, NtLmSsp, NTLM V2) is pbeesly on scranton.dmevals.local at 2020-05-01T23:20:41-04:00 from 172.18.39.2 with Workstation Name 10.0.1.4; 172.18.39.2 is the address newyork.dmevals.local's dns.exe forwards queries to (source.ip 10.0.0.4, source.port 53), i.e. the DC's own DNS forwarder path, not a relay. The real attacker activity in this window is lateral movement (PsExec service installs by pbeesly on nashua.dmevals.local followed by C:\Windows\Temp\python.exe), which is outside the T1557 family.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:20:41.000Z | scranton.dmevals.local | windows.security | win.LogonProcessName | NtLmSsp  | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7nQi3T7 | q-d2d39602a0 | ok |
| 2 | 2020-05-02 03:20:41.000Z | scranton.dmevals.local | windows.security | win.IpAddress | 172.18.39.2 | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7nQi3T7 | q-d2d39602a0 | ok |
| 3 | 2020-05-02 02:55:25.828Z | newyork.dmevals.local | windows.sysmon | destination.ip | 172.18.39.2 | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hy1EsU | q-45ee074f44 | ok |
| 4 | 2020-05-02 02:55:25.828Z | newyork.dmevals.local | windows.sysmon | process.executable | C:\Windows\System32\dns.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hy1EsU | q-45ee074f44 | ok |

### F44 · benign / medium · T1557.001 · NBT-NS name queries and SMB sessions are routine domain traffic, not poisoning or relay

Evidence status: **verified**

The only LLMNR/NBT-NS-port traffic is six NBT name queries (qtype NB, port 137) to the broadcast address 10.0.1.255: three from 10.0.1.6 (NASHUA) at 2020-04-30T00:34:51-53Z and three from 10.0.1.4 (SCRANTON) at 00:35:01-03Z, with no responses captured and no LLMNR (5355) traffic at all. SMB file/mapping records come only from 10.0.1.4 and 10.0.1.6 to 10.0.0.4 (NEWYORK.dmevals.local) and are ordinary IPC$ and sysvol GPO reads (gpt.ini, Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf). No relay tooling, no LLMNR/NBT-NS poisoning script blocks (PowerShell search returned zero hits), and the 4697 service installs are PsExec (PSEXESVC) and normal svchost-based services, not relay tooling.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-04-30 00:34:51.731Z | bobs.bigwheel.local | zeek | destination.port | 137 | .ds-logs-zeek-default-2026.10.20-000001 / AaFZSPJfH5wFd7qUcN2T | q-4981f9a5cb | ok |
| 2 | 2020-04-30 00:34:51.731Z | bobs.bigwheel.local | zeek | dns.question.name | NASHUA | .ds-logs-zeek-default-2026.10.20-000001 / AaFZSPJfH5wFd7qUcN2T | q-4981f9a5cb | ok |
| 3 | 2020-04-30 00:12:01.673Z | simplerockbuild.simplerock.lan | zeek | zeek.name | dmevals.local\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf | .ds-logs-zeek-default-2026.10.20-000001 / AaFZSPJfH5wFd7o_Zlbj | q-c9c4af85c7 | ok |
| 4 | 2020-05-02 03:11:39.000Z | nashua.dmevals.local | windows.security | win.ServiceName | PSEXESVC | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7niyNuI | q-9074583e00 | ok |

### F45 · benign / medium · T1557.002 · ARP/route enumeration is Azure guest-agent telemetry; no ARP cache poisoning indicators

Evidence status: **verified**

The only arp.exe and route.exe executions are on scranton.dmevals.local at 2020-05-02T03:19:24-03:20:04Z, run as SYSTEM by WindowsAzureGuestAgent.exe, WindowsAzureTelemetryService.exe and WaAppAgent.exe with the read-only arguments "arp.exe" /a and "route.exe" print — Azure VM health/telemetry collection, not ARP manipulation. No arpspoof/ARP-poison script blocks were found in PowerShell (zero hits). In the Zeek window the responder MAC 12:34:56:78:9a:bc is used consistently for the domain controller 10.0.0.4 across DNS, SMB, Kerberos, LDAP, NTP and dce_rpc flows from both 10.0.1.4 and 10.0.1.6, i.e. a single stable gateway/DC MAC rather than a duplicated or spoofed L2 address.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:25.370Z | scranton.dmevals.local | windows.sysmon | process.command_line | "arp.exe" /a | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7cYMP7j | q-90fd754cc0 | ok |
| 2 | 2020-05-02 03:19:25.370Z | scranton.dmevals.local | windows.sysmon | process.parent.executable | C:\WindowsAzure\Packages\GuestAgent\WindowsAzureGuestAgent.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7cYMP7j | q-90fd754cc0 | ok |
| 3 | 2020-05-02 03:19:24.769Z | scranton.dmevals.local | windows.sysmon | process.command_line | "route.exe" print | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7cYMf4P | q-90fd754cc0 | ok |
| 4 | 2020-04-30 00:06:38.903Z | simplerockbuild.simplerock.lan | zeek | zeek.resp_l2_addr | 12:34:56:78:9a:bc | .ds-logs-zeek-default-2026.10.20-000001 / AaFZSPJfH5wFd7o_aFZ1 | q-3c6ded3f09 | ok |

### F46 · benign / medium · T1557.003 · No DHCP spoofing: no DHCP events in any dataset, and network-config commands are Azure agent activity

Evidence status: **verified**

DHCP client/server events (1341, 1342, 1020, 1063) are absent from windows.other, and the Zeek dataset contains no dhcp log type at all, so rogue DHCP offers/ACKs are not present in the collected data. The only DHCP/network-configuration command lines are on scranton.dmevals.local at 2020-05-02T03:19:17-03:19:57Z: netsh.exe trace start/stop spawned by NetworkWatcherAgent.exe and "ipconfig.exe" /all spawned by WindowsAzureGuestAgent.exe, WindowsAzureTelemetryService.exe and WaAppAgent.exe — Azure platform diagnostics, not DHCP manipulation. No dhcp/rogue script blocks in PowerShell (zero hits).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:17.154Z | scranton.dmevals.local | windows.sysmon | process.command_line | C:\windows\system32\netsh.exe trace start capture=yes traceFile="C:\windows\TEMP\E7116ECA-DFE6-43C7-8FA8-8D3AC5AA8726\B91E06C5-1C7C-4830-9A76-74FA211560A7.etl" | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7cla5Dm | q-dc15d9a137 | ok |
| 2 | 2020-05-02 03:19:24.192Z | scranton.dmevals.local | windows.sysmon | process.command_line | "ipconfig.exe" /all | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7cjZtk- | q-dc15d9a137 | ok |
| 3 | 2020-05-02 03:19:24.192Z | scranton.dmevals.local | windows.sysmon | process.parent.executable | C:\WindowsAzure\Packages\GuestAgent\WindowsAzureGuestAgent.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7cjZtk- | q-dc15d9a137 | ok |

### F48 · benign / medium · T1558.001 · No golden-ticket indicators: krbtgt TGS requests are normal pbeesly logons with pre-auth

Evidence status: **verified**

windows.security contains 4768 (14) and 4769 (28) events, all on newyork.dmevals.local for pbeesly from 10.0.1.4/10.0.1.6 with Status 0x0 and TicketEncryptionType 0x12 (AES256). The krbtgt service-ticket requests carry TicketOptions 0x40810010/0x60810010 and the 4768 events all show PreAuthType 2, i.e. normal pre-authenticated TGT issuance. No 4769 for krbtgt with anomalous options, no RC4 downgrade, and no LSASS access by a dumping tool that would yield KRBTGT material. The high-access LSASS events (0x1fffff/0x1f3fff) come from csrss.exe, wininit.exe, PowerShell.exe and wsmprovhost.exe with managed-code call traces, not from a credential-theft utility.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:18.000Z | newyork.dmevals.local | windows.security | win.PreAuthType | 2 | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7niyNvO | q-8285d8d1f3 | ok |
| 2 | 2020-05-02 03:04:04.000Z | newyork.dmevals.local | windows.security | win.TicketEncryptionType | 0x12 | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7nq72Yx | q-2f34c2eb88 | ok |
| 3 | 2020-05-02 03:19:09.803Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\csrss.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7cpgKyU | q-7dd6e5284b | ok |

### F49 · benign / medium · T1558.002 · No silver-ticket indicators: service tickets are only for host accounts (NEWYORK$, NASHUA$) by pbeesly

Evidence status: **verified**

All 28 4769 events are on newyork.dmevals.local, requested by pbeesly (and SCRANTON$) for machine service accounts NEWYORK$ and NASHUA$ with AES256 (0x12) and Status 0x0; no service-account SPN tickets for user accounts, no RC4 (0x17) tickets, and no 4672 events attributable to a service account being elevated (the 4672 events are NEWYORK$ machine-account privilege assignments). The 4624 logon-type distribution (3:218, 5:61, 2:15, 10:2, 0:1) shows no unusual service-ticket-driven logon burst. The pbeesly network logons to nashua (LogonType 3, Kerberos) and the PSEXESVC LogonType 2 logons are lateral movement by the compromised account, not forged service tickets.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:09:23.000Z | newyork.dmevals.local | windows.security | win.ServiceName | NASHUA$ | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7njzKBN | q-8285d8d1f3 | ok |
| 2 | 2020-05-02 03:11:40.000Z | nashua.dmevals.local | windows.security | win.ProcessName | C:\Windows\PSEXESVC.exe | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7niyNuT | q-48b5c909b6 | ok |
| 3 | 2020-05-02 02:55:54.000Z | newyork.dmevals.local | windows.security | win.SubjectUserName | NEWYORK$ | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7rxFDL4 | q-bfd6f60f1b | ok |

### F50 · benign / medium · T1558.003 · No Kerberoasting: no burst of TGS requests for user SPNs and no roasting tooling

Evidence status: **verified**

Only 11 TGS requests appear in zeek (2020-04-30 window, non-overlapping with the Windows data) and 28 4769 events in windows.security, all for machine accounts NEWYORK$/NASHUA$ with AES256 encryption and success status — no single account requesting many distinct service SPNs, no RC4-encrypted service tickets typical of Kerberoasting. PowerShell script-block searches for kerberoast/SPN/Invoke-Kerberoast/GetUserSPNs returned zero hits; the observed PowerShell content is SeaDuke-style discovery/persistence/screen-capture/exfil code, not ticket extraction.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:04.000Z | newyork.dmevals.local | windows.security | win.ServiceName | NEWYORK$ | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7nq72bs | q-2f34c2eb88 | ok |
| 2 | 2020-05-02 03:04:03.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | Invoke-Discovery | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qvSysW | q-a772da6cd0 | ok |

### F51 · benign / medium · T1558.004 · No AS-REP roasting: all 14 TGT requests used pre-authentication

Evidence status: **verified**

All 14 4768 events on newyork.dmevals.local have win.PreAuthType 2 (pre-authentication enabled) with Status 0x0, so no account requested a TGT without pre-auth. No AS-REP roasting tooling was found: the sysmon process-creation search for asrep/GetNPUsers/kerberos command lines and the PowerShell script-block search for asrep/AS-REP/GetNPUsers/preauth both returned zero hits.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:40.000Z | newyork.dmevals.local | windows.security | win.PreAuthType | 2 | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7niyNsI | q-8285d8d1f3 | ok |
| 2 | 2020-05-02 03:11:40.000Z | newyork.dmevals.local | windows.security | win.ServiceName | krbtgt | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7niyNsI | q-8285d8d1f3 | ok |

### F53 · benign / medium · T1606.001 · No browser cookie theft or forged-cookie use observed

Evidence status: **verified**

The cookie-related checks produced only benign results. File-creation events matching *Cookies*/*Login Data*/*Web Data* (162 events) are dominated by svchost.exe writing C:\Windows\ServiceState\EventLog\Data\lastalive0.dat / lastalive1.dat (133+28) and GroupPolicy DataStore files, plus a single MicrosoftEdge.exe write of C:\Users\pbeesly\AppData\Local\Packages\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\AC\MicrosoftEdge\User\Default\DataStore\_TempTestAccess.txt - normal Edge profile behaviour, not cookie exfiltration. The only PowerShell script block matching cookie/session keywords was a Get-AttributesMask helper function (token/privilege enumeration code), not cookie manipulation. No forged cookie was observed being injected or replayed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:55:56.151Z | scranton.dmevals.local | windows.sysmon | win.TargetImage | C:\ProgramData\victim\â€®cod.3aka3.scr | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hy0krN | q-37271f5232 | ok |
| 2 | 2020-05-02 03:04:04.000Z | scranton.dmevals.local | windows.powershell | process.command_line | function Get-AttributesMask($AttributesMask) {     &lt;#         SE_GROUP_MANDATORY          0x00000001  The group is mandatory.         SE_GROUP_ENABLED_BY_DEF… | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qvTCvl | q-67dc9b253d | ok |

### F54 · benign / medium · T1606.002 · No SAML token forging activity (no ADFS/token-signing artifacts)

Evidence status: **verified**

Searches for SAML/ADFS/token-signing script blocks returned zero hits, and the 4648 explicit-credential events (15 total) are ordinary: pbeesly explicit logons from 10.0.1.6 on scranton and via PSEXESVC on nashua, plus DWM/UMFD/winlogon/taskhostw system account logons. No SAML token was observed being forged or replayed in this window.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:40.000Z | nashua.dmevals.local | windows.security | process.executable | C:\Windows\PSEXESVC.exe | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7niyNur | q-0864fb258e | ok |
| 2 | 2020-05-02 03:19:35.000Z | scranton.dmevals.local | windows.security | process.executable | C:\Windows\System32\taskhostw.exe | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7ryFR3O | q-0864fb258e | ok |

### F57 · benign / high · T1649 · Remaining 4657 registry writes are WMI Autologger/WSMAN configuration, not certificate tampering

Evidence status: **verified**

Of the 36 Security 4657 events, 34 target \REGISTRY\MACHINE\SYSTEM\ControlSet001\Control\WMI\Autologger\EventLog-Application\{GUID} values (Enabled/MatchAnyKeyword) written by C:\Windows\System32\wevtutil.exe under SCRANTON$ on scranton.dmevals.local at 23:19:16, and one targets \REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\SafeClientList. These are event-log autologger and WSMAN configuration changes, not certificate store or CA configuration, so they do not support certificate theft/forgery. Kerberos TGT requests (14 x 4768) all used encryption type 0x12 with no anomalous pattern.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:16.000Z | scranton.dmevals.local | windows.security | win.ObjectName | \REGISTRY\MACHINE\SYSTEM\ControlSet001\Control\WMI\Autologger\EventLog-Application\{498a78f0-d57b-488d-9666-b0e7f5473cd9} | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7ryGB0J | q-825d8b0003 | ok |
| 2 | 2020-05-02 03:19:16.000Z | scranton.dmevals.local | windows.security | process.executable | C:\Windows\System32\wevtutil.exe | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7ryGB0J | q-825d8b0003 | ok |

## Pivot candidates

Processes the pivot reviewer had to assess (started by a script host or from outside the Windows directory, rare in the 15-minute windows around verified activity).

| Host | Executable | Starts | Parents | Assessment | Reason |
|---|---|---|---|---|---|
| nashua.dmevals.local | C:\Program Files\WindowsApps\Microsoft.SkypeApp_14.35.152.0_x64__kzf8qxf38zg5c\S… | 1 | C:\Program Files\WindowsApps\Microsoft.SkypeApp_14.35.152.0_x64__kzf8qxf38zg5c\S… | benign | Signed Store app self-restarting; its WerFault crash reports are unrelated to credential access. |
| nashua.dmevals.local | C:\Windows\Temp\python.exe | 5 | C:\Windows\PSEXESVC.exe, C:\Windows\Temp\python.exe | malicious | Delivered by PsExec64.exe from scranton with cleartext password Fl0nk3rt0n!T0by; ran 4 times under pbeesly, opened the LSA registry key, spawned powershell.exe … |
| nashua.dmevals.local | C:\Windows\Temp\Rar.exe | 1 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | malicious | Started by the python.exe-spawned PowerShell to password-protect the harvested archive: 'Rar.exe a -hpfGzq5yKw ... working.zip'; deleted afterwards with sdelete… |
| nashua.dmevals.local | C:\Windows\Temp\sdelete64.exe | 3 | C:\Windows\System32\cmd.exe | malicious | Anti-forensics: wiped Rar.exe and both working.zip copies (Roaming and Desktop) after exfiltration staging. |
| nashua.dmevals.local | C:\WindowsAzure\Packages\CollectGuestLogs.exe | 1 | C:\WindowsAzure\Packages\WaAppAgent.exe | benign | Azure guest agent diagnostic collection, parented by WaAppAgent.exe; routine platform telemetry. |
| newyork.dmevals.local | C:\Windows\System32\conhost.exe | 3 | C:\WindowsAzure\Packages\CollectGuestLogs.exe, C:\Windows\System32\cmd.exe, C:\W… | benign | Console host for cmd.exe/dsregcmd.exe/CollectGuestLogs.exe on newyork; no credential access. |
| scranton.dmevals.local | C:\Packages\Plugins\Microsoft.Azure.NetworkWatcher.NetworkWatcherAgentWindows\1.… | 4 | C:\Windows\System32\cmd.exe, C:\Windows\System32\services.exe | benign | Azure Network Watcher extension binary under the platform plugin path, started by services.exe/cmd.exe. |
| scranton.dmevals.local | C:\Packages\Plugins\Microsoft.Azure.Security.IaaSAntimalware\1.5.5.9\Antimalware… | 1 | C:\WindowsAzure\Packages\GuestAgent\WindowsAzureGuestAgent.exe | benign | Azure IaaS antimalware configuration helper launched by WindowsAzureGuestAgent.exe. |
| scranton.dmevals.local | C:\Packages\Plugins\Microsoft.Compute.CustomScriptExtension\1.10.5\bin\CustomScr… | 1 | C:\Windows\System32\cmd.exe | benign | Azure VM extension handler; standard platform component. |
| scranton.dmevals.local | C:\Packages\Plugins\Microsoft.Compute.JsonADDomainExtension\1.3.2\bin\JsonADDoma… | 1 | C:\Windows\System32\cmd.exe | benign | Azure domain-join extension handler; standard platform component. |
| scranton.dmevals.local | C:\Program Files (x86)\Google\Update\1.3.35.452\GoogleCrashHandler.exe | 2 | C:\Program Files (x86)\Google\Update\GoogleUpdate.exe | benign | Google Update crash handler, parented by GoogleUpdate.exe. |
| scranton.dmevals.local | C:\Program Files (x86)\Google\Update\1.3.35.452\GoogleCrashHandler64.exe | 2 | C:\Program Files (x86)\Google\Update\GoogleUpdate.exe | benign | Google Update crash handler, parented by GoogleUpdate.exe. |
| scranton.dmevals.local | C:\Program Files (x86)\Google\Update\GoogleUpdate.exe | 3 | C:\Program Files (x86)\Google\Update\GoogleUpdate.exe, C:\Windows\System32\servi… | benign | Legitimate updater started by services.exe/svchost.exe. |
| scranton.dmevals.local | C:\Program Files\SysinternalsSuite\accessChk.exe | 1 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | suspicious | Sysinternals access-enumeration tool run by pbeesly's PowerShell from the attacker-staged SysinternalsSuite directory during the intrusion (permission reconnais… |
| scranton.dmevals.local | C:\Program Files\SysinternalsSuite\PsExec64.exe | 4 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | malicious | Used four times with '-u dmevals\pbeesly -p Fl0nk3rt0n!T0by' to push C:\Windows\Temp\python.exe to \\NASHUA, i.e. lateral movement with harvested credentials. |
| scranton.dmevals.local | C:\Program Files\SysinternalsSuite\sdelete64.exe | 3 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | malicious | Anti-forensics on scranton: wiped the dropped .scr, Draft.Zip and SysinternalsSuite.zip after use. |
| scranton.dmevals.local | C:\Program Files\Windows Defender\MsMpEng.exe | 1 | C:\Windows\System32\services.exe | benign | Defender service binary started by services.exe. |
| scranton.dmevals.local | C:\Program Files\Windows Defender\NisSrv.exe | 2 | C:\Windows\System32\services.exe | benign | Defender network inspection service started by services.exe. |
| scranton.dmevals.local | C:\ProgramData\victim\â€®cod.3aka3.scr | 1 | C:\Windows\explorer.exe | malicious | Unsigned .scr dropped in C:\ProgramData\victim and launched by explorer.exe with /S under pbeesly; it wrote C:\Users\pbeesly\Downloads\monkey.png, the steganogr… |
| scranton.dmevals.local | C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe | 2 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | malicious | Invoked by hidden PowerShell to compile attacker C# into qkbkqqbs.dll and 0piklvia.dll in the user Temp directory (in-memory loader). |
| scranton.dmevals.local | C:\Windows\System32\hostui.exe | 1 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | suspicious | Started by PowerShell with '-verb runas' (elevation prompt abuse) immediately before the HKLM Javasoft Invoke-Expression chain. |
| scranton.dmevals.local | C:\Windows\System32\sdclt.exe | 3 | C:\Windows\System32\cmd.exe | suspicious | Three sdclt.exe launches by cmd.exe under pbeesly at 02:58:42-43, immediately preceding the hidden monkey.png PowerShell and csc.exe compile; consistent with a … |
| scranton.dmevals.local | C:\WindowsAzure\Packages\GuestAgent\BfeToolWin8.exe | 1 | C:\WindowsAzure\Packages\GuestAgent\WindowsAzureGuestAgent.exe | benign | Azure guest agent firewall helper. |
| scranton.dmevals.local | C:\WindowsAzure\Packages\GuestAgent\FindVolume\FindVolume.exe | 1 | C:\WindowsAzure\Packages\GuestAgent\WindowsAzureGuestAgent.exe | benign | Azure guest agent volume discovery helper. |
| scranton.dmevals.local | C:\WindowsAzure\Packages\GuestAgent\WindowsAzureGuestAgent.exe | 1 | C:\Windows\System32\services.exe | benign | Azure guest agent service. |
| scranton.dmevals.local | C:\WindowsAzure\Packages\Telemetry\WindowsAzureTelemetryService.exe | 1 | C:\Windows\System32\services.exe | benign | Azure telemetry service. |
| scranton.dmevals.local | C:\WindowsAzure\Packages\WaAppAgent.exe | 1 | C:\Windows\System32\services.exe | benign | Azure agent host service. |
| scranton.dmevals.local | C:\WindowsAzure\SecAgent\WaSecAgentProv.exe | 2 | C:\WindowsAzure\Packages\WaAppAgent.exe | benign | Azure security agent provider. |
| scranton.dmevals.local | C:\WindowsAzure\WindowsAzureNetAgent_1.0.0.143\WindowsAzureNetAgent\Plugins\VFPl… | 1 | C:\WindowsAzure\WindowsAzureNetAgent_1.0.0.143\WindowsAzureNetAgent\WindowsAzure… | benign | Azure network agent plugin. |
| scranton.dmevals.local | C:\WindowsAzure\WindowsAzureNetAgent_1.0.0.143\WindowsAzureNetAgent\WindowsAzure… | 1 | C:\Windows\System32\services.exe | benign | Azure network agent service. |

## Technique conclusions

One line per technique in scope: status from the triage of its family; `not_observed` = checked, nothing found; `not_observable` = no dataset records it.

| Technique | Status | Reason |
|---|---|---|
| T1003 OS Credential Dumping | malicious | Hands-on-keyboard intrusion by pbeesly on scranton (Invoke-Discovery/Persistence/ScreenCapture/Exfil, Add-Type VirtualAlloc loader, PsExec64 with plaintext password to NASHUA) included full-access LSASS handle opens on s… |
| T1003.001 LSASS Memory | malicious | NASHUA: wsmprovhost.exe opened lsass with 0x1f3fff and the PsExec-delivered C:\Windows\Temp\python.exe sessions repeatedly queried the LSA registry key, then harvested and archived credential-named files. |
| T1003.002 Security Account Manager | benign | Only lsass.exe internal writes to HKLM\SAM\SAM\Domains\Account\F and LogonUI LoggedOnSAMUser; no reg save/hive export, no SAM file creation, no 4663/4656 SAM access. |
| T1003.003 NTDS | not_observed | All NTDS checks (command lines, .dit file creation, 4663 ntds objects, other/powershell text) returned zero hits. |
| T1003.004 LSA Secrets | benign | Only two 4662 SecretObject reads of Policy\Secrets\$MACHINE.ACC by NT AUTHORITY\LOCAL SERVICE on utica; no Policy\Secrets registry modification or lsadump tooling. |
| T1003.005 Cached Domain Credentials | suspicious | lsass.exe wrote HKLM\SECURITY\Cache\NL$1 four times on nashua and once on scranton, coinciding with the PsExec logons as pbeesly — cache population caused by the intrusion, no cachedump tooling or non-lsass access to the… |
| T1003.006 DCSync | not_observed | No 4929 events, no drsuapi/lsadump/dcsync references, and no DS-Replication access on the utica domain object. |
| T1040 Network Sniffing | benign | The only packet-capture behaviour observed is the Azure Network Watcher guest extension on scranton.dmevals.local: netsh.exe 'trace start capture=yes' / 'trace stop' spawned by NetworkWatcherAgent.exe (Microsoft CoreXT, … |
| T1056 Input Capture | malicious | Parent technique: LSASS credential access by PowerShell on scranton (0x1FFFFF handle + CreateRemoteThread into lsass) and by wsmprovhost on nashua (0x1f3fff) constitute input/credential capture activity. |
| T1056.001 Keylogging | not_observed | No keylogger indicators: keyboard registry writes are OS layout/device keys; zero hits for keylog/GetAsyncKeyState/SetWindowsHookEx in command lines, image loads or script blocks; no keylogger service installed. |
| T1056.002 GUI Input Capture | not_observed | Only legitimate consent.exe UAC prompts and PowerShell credential-object construction; no fake credential GUI or input-box harvesting. |
| T1056.003 Web Portal Capture | not_observed | No writes to wwwroot/inetpub or login pages, no 4663 access on web roots; Zeek HTTP shows only WebDAV file transfer (exfil), not portal capture. |
| T1056.004 Credential API Hooking | malicious | PowerShell.exe on scranton opened lsass with 0x1FFFFF/0x1f3fff (UNKNOWN call trace) and created a remote thread in lsass with an unbacked start address; wsmprovhost.exe on nashua also opened lsass with 0x1f3fff. |
| T1110 Brute Force | not_observed | No 4625 failed logons anywhere in windows.security, no failed-logon messages in windows.other, and no login/brute-force tooling in sysmon process creation. The password-related hits are the attacker's own hardcoded crede… |
| T1110.001 Password Guessing | not_observed | Zero 4625 events and no guessing tooling; the only keyword hit was a hidden PowerShell bitmap-decoding stager whose command line merely contains '-ep bypass'. |
| T1110.002 Password Cracking | malicious | Credential material was harvested rather than cracked: pbeesly's powershell.exe opened lsass with 0x1fffff on scranton (03:05:16Z), wsmprovhost.exe opened lsass with 0x1f3fff on nashua (03:09:29Z), and lsass requested SA… |
| T1110.003 Password Spraying | not_observed | No failed logons to form a spray pattern. The repeated pbeesly network logons (Kerberos type-3 from 10.0.1.4 and PSEXESVC 4648 explicit-credential logons on nashua) are reuse of one already-compromised account for latera… |
| T1110.004 Credential Stuffing | not_observed | The only 'credential'/'password' script hits are Microsoft localization strings and the attacker's single hardcoded exfil credentials ('cozy'/'MyCozyPassw0rd!'); no stolen credential lists were replayed against logon ser… |
| T1111 Multi-Factor Authentication Interception | malicious | pbeesly on scranton.dmevals.local ran a Get-PrivateKeys PowerShell function that enumerated cert:\LocalMachine and exported every certificate with its private key to password-protected .pfx files (confirmed artifact C:\U… |
| T1187 Forced Authentication | malicious | SCRANTON (10.0.1.4) as pbeesly ran Invoke-Exfil PowerShell that maps \\192.168.0.4\webdav via New-PSDrive and copies OfficeSupplies.7z there; sysmon shows powershell.exe and svchost.exe (WebClient) connecting to 192.168.… |
| T1212 Exploitation for Credential Access | malicious | On scranton.dmevals.local, pbeesly's hidden, execution-policy-bypassed PowerShell.exe (PID 2976) that had loaded VirtualAlloc/CreateThread shellcode opened lsass.exe with GrantedAccess 0x1fffff/0x1f3fff and an UNKNOWN() … |
| T1539 Steal Web Session Cookie | not_observed | No browser cookie store was read, copied or exfiltrated. Cookie/credential-store filename matches were Edge's own runtime files created by MicrosoftEdge.exe on scranton and a svchost.exe write to the LocalService INetCoo… |
| T1552 Unsecured Credentials | malicious | Unsecured credential material was harvested on scranton.dmevals.local: PowerShell Get-PrivateKeys exported every LocalMachine certificate's private key to .pfx files in the user's Downloads folder, which the same session… |
| T1552.001 Credentials In Files | malicious | NASHUA: PowerShell under python.exe enumerated *pass*/*psw*/*login*/*admin*/*vpn/*.pst/*.ost files in the user profile and compressed them into working.zip, then Rar.exe password-protected it and sdelete64.exe wiped the … |
| T1552.002 Credentials in Registry | benign | All registry writes to password/credential paths are OS activity (CredentialGuard, CredentialEnrollmentManagerUserSvc, IdentityCRL, Winlogon PasswordExpiryNotification); no reg query/save, cmdkey or vaultcmd execution an… |
| T1552.003 Shell History | benign | No reference to ConsoleHost_history, Get-History or any history file in script blocks, process command lines, file creations or object accesses; the only .txt-referencing process is the Azure guest agent's logman.exe. |
| T1552.004 Private Keys | malicious | SCRANTON: Get-PrivateKeys exported every LocalMachine certificate with private key to Downloads\<random>.pfx with password 'saribas'; the .pfx files were then 7-Zip'd into OfficeSupplies.7z and deleted. |
| T1552.006 Group Policy Preferences | suspicious | SCRANTON: PowerShell read HKLM\SOFTWARE\Javasoft 'value Supplement' and Invoke-Expression'd it, spawning a base64 hidden PowerShell after an elevated hostui.exe launch. |
| T1555 Credentials from Password Stores | malicious | Hidden steganographic PowerShell PID 2976 on scranton (spawned via sdclt/control from a malicious .scr) opened lsass.exe with 0x1f3fff and 0x1fffff and an UNKNOWN call trace at 03:05:16Z, corroborated by Security 4656 Ac… |
| T1555.003 Credentials from Web Browsers | suspicious | SCRANTON: sdclt.exe UAC-bypass launches by cmd.exe immediately preceded hidden steganographic PowerShell and csc.exe compiles; no browser credential-store file read was observed. |
| T1555.004 Windows Credential Manager | suspicious | Vault/Credential Manager artifacts (vaultcli.dll, vaultsvc.dll, deletion of Microsoft\Vault\UserProfileRoaming\Latest.dat by lsass.exe) on scranton shortly after the LSASS dump access, but no vaultcmd/cmdkey execution or… |
| T1555.005 Password Managers | not_observed | No KeePass/1Password/Bitwarden execution, .kdbx files or password-manager process access; Rar.exe on nashua is staging, not password-manager theft. |
| T1556 Modify Authentication Process | malicious | Hidden steganographic PowerShell (monkey.png decode, PID 2976, DMEVALS\pbeesly) opened lsass.exe with GrantedAccess 0x1FFFFF on scranton.dmevals.local at 03:05:16, inside a broader SeaDuke/PsExec intrusion. |
| T1556.001 Domain Controller Authentication | not_observed | No DC authentication patching: no lsass/cryptdll service install, no Lsa/SecurityProviders/WDigest registry change, no 4739; LSASS access on DCs is AV/telemetry/system with read-only masks. |
| T1556.002 Password Filter DLL | not_observed | No DLL written to System32/SysWOW64 and no Notification Packages / PasswordFilter registry modification. |
| T1556.005 Reversible Encryption | not_observed | No ReversibleEncryption/Set-ADAccountControl/dsmod usage in PowerShell or process command lines and no 4739 events. |
| T1556.006 Multi-Factor Authentication | not_observed | No 4739 policy change and no MFA-related configuration events; logon types/processes are ordinary. |
| T1556.007 Hybrid Identity | not_observed | No 5136 directory-service changes and no anomalous DLLs loaded into cloud-identity processes. |
| T1556.008 Network Provider DLL | not_observed | No NetworkProvider registry write (Sysmon 13 or 4657); np/provider image loads are standard Windows components. |
| T1557 Adversary-in-the-Middle | not_observed | No interception evidence: Sysmon connections go to DCs/telemetry endpoints; the single NTLM network logon (pbeesly on scranton from 172.18.39.2) matches the DC's own DNS forwarder address used by newyork dns.exe. |
| T1557.001 Name Resolution Poisoning and SMB Relay | not_observed | Only six NBT name queries to 10.0.1.255 with no responses and no LLMNR/5355 traffic; SMB records are routine IPC$/sysvol GPO reads from 10.0.1.4 and 10.0.1.6 to 10.0.0.4; no poisoning/relay tooling or script blocks. |
| T1557.002 ARP Cache Poisoning | not_observed | arp.exe /a and route.exe print are read-only Azure guest-agent/telemetry calls on scranton; no arpspoof/poison script blocks; Zeek shows one stable responder MAC (12:34:56:78:9a:bc) for the DC, not duplicated/spoofed L2 … |
| T1557.003 DHCP Spoofing | not_observable | No DHCP events exist in windows.other (no 1341/1342/1020/1063) and Zeek has no dhcp log type, so rogue DHCP cannot be assessed; the only network-config commands (netsh trace, ipconfig /all) are Azure agent diagnostics. |
| T1558 Steal or Forge Kerberos Tickets | suspicious | A real intrusion chain is present (cod.3aka3.scr → cmd/powershell on scranton, SeaDuke PowerShell toolkit, Invoke-SeaDukeStage to NASHUA, PSEXESVC spawning C:\Windows\Temp\python.exe on nashua) and LSASS handle-access ev… |
| T1558.001 Golden Ticket | benign | krbtgt 4769 requests are normal pbeesly logons (AES256, Status 0x0) and all 4768 events show PreAuthType 2; no forged-ticket or KRBTGT-dumping indicators. |
| T1558.002 Silver Ticket | benign | Service tickets are only for machine accounts NEWYORK$/NASHUA$ with AES256 and success status; no anomalous service-account elevation or forged service-ticket logons. |
| T1558.003 Kerberoasting | benign | No burst of TGS requests for user SPNs, no RC4 service tickets, and zero PowerShell hits for kerberoast/SPN/GetUserSPNs tooling. |
| T1558.004 AS-REP Roasting | benign | All 14 TGT requests used pre-authentication (PreAuthType 2) and no asrep/GetNPUsers tooling was found in sysmon or PowerShell logs. |
| T1606 Forge Web Credentials | not_observed | No forged web credential material (cookie or SAML) was created or used in the window; however credential-access precursor LSASS memory access by PowerShell (0x1fffff/0x1f3fff) on scranton and wsmprovhost on nashua, plus … |
| T1606.001 Web Cookies | not_observed | Cookie/Login Data file writes were only svchost lastalive/GroupPolicy files and one MicrosoftEdge profile temp file; the only cookie/session PowerShell hit was a Get-AttributesMask helper. No forged cookie use. |
| T1606.002 SAML Tokens | not_observed | Zero hits for SAML/ADFS/token-signing script blocks; 4648 explicit-credential events are routine pbeesly/PSEXESVC and system-account logons. |
| T1621 Multi-Factor Authentication Request Generatio… | not_observed | 5 planned checks, all with zero hits |
| T1649 Steal or Forge Authentication Certificates | malicious | PowerShell Get-PrivateKeys on scranton.dmevals.local (user pbeesly) enumerated cert:\LocalMachine and exported every certificate with private key to password-protected .pfx files in Downloads (coyn5igj.3io.pfx observed c… |

## Coverage

Cells: number of hits of the planned checks, `n/a` (reason in report.json), or GAP.

| Technique | windows.other | windows.powershell | windows.security | windows.sysmon | zeek |
|---|---|---|---|---|---|
| T1003 OS Credential Dumping | 0 hits | 0 hits | 11768 hits | 39730 hits | GAP: n/a refused (time window … |
| T1003.001 LSASS Memory | 0 hits | 0 hits | 934 hits | 39612 hits | n/a |
| T1003.002 Security Account Manager | 11 hits | 0 hits | 6 hits | 11 hits | n/a |
| T1003.003 NTDS | 0 hits | 0 hits | 0 hits | 0 hits | n/a |
| T1003.004 LSA Secrets | 0 hits | 0 hits | 934 hits | 373 hits | n/a |
| T1003.005 Cached Domain Credentials | 0 hits | 0 hits | 934 hits | 6956 hits | n/a |
| T1003.006 DCSync | 5 hits | 0 hits | 21 hits | 0 hits | n/a |
| T1040 Network Sniffing | 5 hits | 0 hits | 25 hits | 1 hits | 613 hits |
| T1056 Input Capture | 5 hits | 3 hits | 11013 hits | 652 hits | n/a |
| T1056.001 Keylogging | 5 hits | 0 hits | 10977 hits | 26 hits | n/a |
| T1056.002 GUI Input Capture | 5 hits | 5085 hits | 3 hits | 3 hits | n/a |
| T1056.003 Web Portal Capture | 5 hits | 2 hits | 0 hits | 8 hits | 62 hits |
| T1056.004 Credential API Hooking | 0 hits | 0 hits | 13 hits | 59870 hits | n/a |
| T1110 Brute Force | 0 hits | 4 hits | 0 hits | 0 hits | n/a |
| T1110.001 Password Guessing | 0 hits | 0 hits | 0 hits | 1 hits | n/a |
| T1110.002 Password Cracking | 0 hits | 0 hits | 10977 hits | 326 hits | n/a |
| T1110.003 Password Spraying | 2 hits | 0 hits | 233 hits | 0 hits | n/a |
| T1110.004 Credential Stuffing | 0 hits | 2 hits | 0 hits | 0 hits | n/a |
| T1111 Multi-Factor Authentication Interception | 5 hits | 3 hits | 312 hits | 39294 hits | n/a |
| T1187 Forced Authentication | 11 hits | 88 hits | 163 hits | 1715 hits | 649 hits |
| T1212 Exploitation for Credential Access | 10 hits | 22 hits | 460 hits | 652 hits | 14 hits |
| T1539 Steal Web Session Cookie | 7 hits | 13 hits | 460 hits | 162 hits | 2 hits |
| T1552 Unsecured Credentials | 7 hits | 2 hits | 460 hits | 61 hits | 12 hits |
| T1552.001 Credentials In Files | 7 hits | 2 hits | 5634 hits | 1650 hits | 12 hits |
| T1552.002 Credentials in Registry | 2 hits | 5 hits | 0 hits | 20 hits | n/a |
| T1552.003 Shell History | n/a | 0 hits | 0 hits | 0 hits | n/a |
| T1552.004 Private Keys | 0 hits | 2 hits | 0 hits | 1 hits | n/a |
| T1552.006 Group Policy Preferences | 0 hits | 0 hits | 0 hits | 0 hits | n/a |
| T1555 Credentials from Password Stores | 0 hits | 3 hits | 29 hits | 653 hits | n/a |
| T1555.003 Credentials from Web Browsers | 0 hits | 0 hits | 0 hits | 162 hits | n/a |
| T1555.004 Windows Credential Manager | n/a | 3 hits | 0 hits | 1396 hits | n/a |
| T1555.005 Password Managers | n/a | 0 hits | 0 hits | 0 hits | n/a |
| T1556 Modify Authentication Process | n/a | n/a | 297 hits | 484 hits | n/a |
| T1556.001 Domain Controller Authentication | 0 hits | n/a | 312 hits | 359 hits | n/a |
| T1556.002 Password Filter DLL | n/a | n/a | 0 hits | 18866 hits | n/a |
| T1556.005 Reversible Encryption | n/a | 0 hits | 0 hits | 0 hits | n/a |
| T1556.006 Multi-Factor Authentication | 0 hits | 0 hits | 0 hits | 0 hits | n/a |
| T1556.007 Hybrid Identity | 0 hits | 0 hits | 297 hits | 20259 hits | n/a |
| T1556.008 Network Provider DLL | 0 hits | 0 hits | 36 hits | 471 hits | n/a |
| T1557 Adversary-in-the-Middle | 0 hits | 0 hits | 16314 hits | 1310 hits | 1226 hits |
| T1557.001 Name Resolution Poisoning and SMB Relay | 0 hits | 0 hits | 46 hits | 8 hits | 82 hits |
| T1557.002 ARP Cache Poisoning | 0 hits | 0 hits | 3203 hits | 1310 hits | 1226 hits |
| T1557.003 DHCP Spoofing | 216 hits | 0 hits | 297 hits | 5 hits | 2140 hits |
| T1558 Steal or Forge Kerberos Tickets | 216 hits | 0 hits | 509 hits | 652 hits | 35 hits |
| T1558.001 Golden Ticket | 216 hits | 0 hits | 41214 hits | 326 hits | 35 hits |
| T1558.002 Silver Ticket | 216 hits | 0 hits | 509 hits | 326 hits | 35 hits |
| T1558.003 Kerberoasting | 216 hits | 0 hits | 41511 hits | 326 hits | 35 hits |
| T1558.004 AS-REP Roasting | 216 hits | 0 hits | 41016 hits | 0 hits | 35 hits |
| T1606 Forge Web Credentials | 5 hits | 0 hits | 609 hits | 78566 hits | n/a |
| T1606.001 Web Cookies | 4 hits | 1 hits | 312 hits | 324 hits | n/a |
| T1606.002 SAML Tokens | 5 hits | 0 hits | 312 hits | 1 hits | n/a |
| T1621 Multi-Factor Authentication Request Generatio… | 0 hits | 0 hits | 0 hits | n/a | n/a |
| T1649 Steal or Forge Authentication Certificates | 5 hits | 1 hits | 100 hits | 1 hits | n/a |

Cells: 265, gaps: 1.

## Queries

Every MCP tool call of this run (1290), in order (source: mcp_audit.jsonl written by the MCP server).

| Query | Phase | Tool | Arguments | Hits / rows | Cited by |
|---|---|---|---|---|---|
| q-5dffccbd43 | scope | list_data_sources | {} | None |  |
| q-8b64ddd8b8 | scope | get_registry | {} | None |  |
| q-c123bbee6f | scope | get_fields | {"dataset": "windows.other", "prefix": ""} | None |  |
| q-d68d95d92d | scope | get_fields | {"dataset": "windows.powershell", "prefix": ""} | None |  |
| q-643c95ec9a | scope | get_fields | {"dataset": "windows.security", "prefix": ""} | None |  |
| q-010381c90a | scope | get_fields | {"dataset": "windows.sysmon", "prefix": ""} | None |  |
| q-493d0cdc28 | scope | get_fields | {"dataset": "zeek", "prefix": ""} | None |  |
| q-ab3415a79b | check C001 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 447 |  |
| q-8eebb614f6 | check C002 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 39283 |  |
| q-0a161c65c3 | check C003 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 5337 |  |
| q-e5664473b7 | check C004 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4656", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 5497 |  |
| q-00295a0780 | check C005 | aggregate | {"dataset": "windows.security", "field": "win.ProcessName", "query": "event.code:4673", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 934 |  |
| q-8dfd042764 | check C006 | search | {"dataset": "windows.powershell", "query": "win.ScriptBlockText:*mimikatz* OR win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*procdump* OR win.ScriptBlockText:*comsvcs* OR win.ScriptBlockText:*MiniDump*", "time_from": null, "time_to": null, "fields": ["@ti… | 0 |  |
| q-11b10f384f | check C007 | search | {"dataset": "windows.other", "query": "message:*lsass* OR message:*mimikatz* OR message:*procdump* OR message:*MiniDump*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "p… | 0 |  |
| q-efd77af060 | check C008 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 39283 |  |
| q-41b264c134 | check C009 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 326 |  |
| q-7eb1276487 | check C010 | aggregate | {"dataset": "windows.sysmon", "field": "process.command_line", "query": "event.code:1 AND (process.command_line:*lsass* OR process.command_line:*MiniDump* OR process.command_line:*comsvcs* OR process.command_line:*procdump*)", "time_from": null, "time_to": nul… | 1 |  |
| q-fb3d96df29 | check C011 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND (win.TargetFilename:*.dmp OR win.TargetFilename:*lsass*)", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 2 |  |
| q-9e54144a27 | check C012 | aggregate | {"dataset": "windows.sysmon", "field": "registry.path", "query": "event.code:13 AND registry.path:*lsass*", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-4f31682a8b | check C013 | aggregate | {"dataset": "windows.security", "field": "win.ProcessName", "query": "event.code:4673", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 934 |  |
| q-6c8665e133 | check C014 | search | {"dataset": "windows.powershell", "query": "win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*MiniDump* OR win.ScriptBlockText:*comsvcs*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code… | 0 |  |
| q-c7b5056611 | check C015 | search | {"dataset": "windows.other", "query": "message:*lsass* OR message:*MiniDump*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 0 |  |
| q-48b1a74ada | check C016 | aggregate | {"dataset": "windows.sysmon", "field": "process.command_line", "query": "event.code:1 AND (process.command_line:*reg*save* OR process.command_line:*SAM* OR process.command_line:*SECURITY* OR process.command_line:*SYSTEM*)", "time_from": null, "time_to": null, … | 1 |  |
| q-8c5227ba20 | check C017 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND (win.TargetFilename:*SAM* OR win.TargetFilename:*SECURITY* OR win.TargetFilename:*SYSTEM* OR win.TargetFilename:*.hiv OR win.TargetFilename:*.save)", "time_from": null, "t… | 3 |  |
| q-23815b1629 | check C018 | aggregate | {"dataset": "windows.sysmon", "field": "registry.path", "query": "event.code:13 AND (registry.path:*SAM* OR registry.path:*SECURITY*)", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 7 |  |
| q-3de19c0a52 | check C019 | search | {"dataset": "windows.sysmon", "query": "event.code:2 AND (file.path:*SAM* OR file.path:*SECURITY*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "p… | 0 |  |
| q-29d19fdaa2 | check C020 | aggregate | {"dataset": "windows.security", "field": "process.command_line", "query": "event.code:4688 AND (process.command_line:*reg* OR process.command_line:*SAM* OR process.command_line:*SECURITY*)", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 6 |  |
| q-213378df42 | check C021 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND (win.ObjectName:*SAM* OR win.ObjectName:*SECURITY*)", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-6ed7b0ad18 | check C022 | search | {"dataset": "windows.powershell", "query": "win.ScriptBlockText:*reg*save* OR win.ScriptBlockText:*SAM* OR win.ScriptBlockText:*SECURITY*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code"… | 0 |  |
| q-86fd6ac09d | check C023 | search | {"dataset": "windows.other", "query": "message:*SAM* OR message:*SECURITY*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "s… | 11 |  |
| q-8f841ae9c5 | check C024 | aggregate | {"dataset": "windows.sysmon", "field": "process.command_line", "query": "event.code:1 AND (process.command_line:*ntds* OR process.command_line:*vssadmin* OR process.command_line:*ntdsutil* OR process.command_line:*diskshadow*)", "time_from": null, "time_to": n… | 0 |  |
| q-29f65d6f59 | check C025 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND (win.TargetFilename:*ntds* OR win.TargetFilename:*.dit)", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-f65f2a1879 | check C026 | search | {"dataset": "windows.sysmon", "query": "event.code:2 AND file.path:*ntds*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "so… | 0 |  |
| q-d5199e9083 | check C027 | aggregate | {"dataset": "windows.security", "field": "process.command_line", "query": "event.code:4688 AND (process.command_line:*ntds* OR process.command_line:*vssadmin* OR process.command_line:*ntdsutil* OR process.command_line:*diskshadow*)", "time_from": null, "time_t… | 0 |  |
| q-5f71ca15a1 | check C028 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND win.ObjectName:*ntds*", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-547128c3c9 | check C029 | search | {"dataset": "windows.other", "query": "message:*ntds* OR message:*vssadmin* OR message:*diskshadow*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "… | 0 |  |
| q-bd4740ffaa | check C030 | search | {"dataset": "windows.powershell", "query": "win.ScriptBlockText:*ntds* OR win.ScriptBlockText:*vssadmin* OR win.ScriptBlockText:*diskshadow*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.co… | 0 |  |
| q-6a0d1749c9 | check C031 | aggregate | {"dataset": "windows.sysmon", "field": "registry.path", "query": "event.code:13 AND registry.path:*SECURITY*Policy*Secrets*", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-8caf0cf3f8 | check C032 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 326 |  |
| q-be5f6d73b1 | check C033 | aggregate | {"dataset": "windows.sysmon", "field": "win.ImageLoaded", "query": "event.code:7 AND (win.ImageLoaded:*lsass* OR win.ImageLoaded:*sam* OR win.ImageLoaded:*vault*)", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 47 |  |
| q-5b9976121b | check C034 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND (win.ObjectName:*SECURITY* OR win.ObjectName:*Policy*Secrets*)", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-709d595a92 | check C035 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4656 AND (win.ObjectName:*SECURITY* OR win.ObjectName:*Secrets*)", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-ebf3151250 | check C036 | aggregate | {"dataset": "windows.security", "field": "win.ProcessName", "query": "event.code:4673", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 934 |  |
| q-98b79d8297 | check C037 | search | {"dataset": "windows.powershell", "query": "win.ScriptBlockText:*Secrets* OR win.ScriptBlockText:*lsadump* OR win.ScriptBlockText:*LSA*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", … | 0 |  |
| q-2eef5c243e | check C038 | search | {"dataset": "windows.other", "query": "message:*Secrets* OR message:*lsadump*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line",… | 0 |  |
| q-6e3e5e4c90 | check C039 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 326 |  |
| q-d392934ef5 | check C040 | aggregate | {"dataset": "windows.sysmon", "field": "registry.path", "query": "event.code:13 AND (registry.path:*Cache* OR registry.path:*SECURITY*Cache*)", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 6625 |  |
| q-9c61af40f2 | check C041 | aggregate | {"dataset": "windows.sysmon", "field": "process.command_line", "query": "event.code:1 AND (process.command_line:*cache* OR process.command_line:*cachedump* OR process.command_line:*lsass*)", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 5 |  |
| q-75b7abe1f8 | check C042 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND (win.ObjectName:*Cache* OR win.ObjectName:*SECURITY*)", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-a56ea60628 | check C043 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4656 AND (win.ObjectName:*Cache* OR win.ObjectName:*SECURITY*)", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-7c5cc10b5b | check C044 | aggregate | {"dataset": "windows.security", "field": "win.ProcessName", "query": "event.code:4673", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 934 |  |
| q-be95ac8c22 | check C045 | search | {"dataset": "windows.powershell", "query": "win.ScriptBlockText:*cachedump* OR win.ScriptBlockText:*cache* OR win.ScriptBlockText:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code"… | 0 |  |
| q-4972aafa8d | check C046 | search | {"dataset": "windows.other", "query": "message:*cachedump* OR message:*Cache*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line",… | 0 |  |
| q-50d6b11ca0 | check C047 | count | {"dataset": "windows.security", "query": "event.code:4662", "time_from": null, "time_to": null} | 7 |  |
| q-ba6f0e3d7a | check C048 | aggregate | {"dataset": "windows.security", "field": "win.Properties", "query": "event.code:4662", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 7 |  |
| q-b191d43d20 | check C049 | aggregate | {"dataset": "windows.security", "field": "win.SubjectUserName", "query": "event.code:4662", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 7 |  |
| q-37eca51e79 | check C050 | search | {"dataset": "windows.security", "query": "event.code:4929", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 0 |  |
| q-a8a23b1600 | check C051 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*drsuapi* OR process.command_line:*lsadump* OR process.command_line:*dcsync*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-4924cc8a15 | check C052 | aggregate | {"dataset": "windows.powershell", "field": "host.name", "query": "event.code:4104 AND (win.ScriptBlockText:*dcsync* OR win.ScriptBlockText:*DCSync* OR win.ScriptBlockText:*lsadump* OR win.ScriptBlockText:*Get-Change*)", "time_from": null, "time_to": null, "siz… | 0 |  |
| q-5c9f1b0997 | check C053 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-a19f19bb1e | check C054 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND (process.command_line:*pktmon* OR process.command_line:*netsh* OR process.command_line:*windump* OR process.command_line:*tcpdump* OR process.command_line:*RawCap* OR … | 2 |  |
| q-417db9feca | check C055 | aggregate | {"dataset": "windows.security", "field": "win.ServiceName", "query": "event.code:4697 OR event.code:7045", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 23 |  |
| q-b7c9c9f408 | check C056 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-d6bb94e42c | check C057 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*pktmon* OR process.command_line:*dumpcap* OR process.command_line:*windump* OR process.command_line:*RawCap* OR process.command_line:*netsh*cap*)", "… | 1 |  |
| q-8803c82a72 | check C058 | aggregate | {"dataset": "windows.sysmon", "field": "win.ImageLoaded", "query": "event.code:7 AND (win.ImageLoaded:*wpcap* OR win.ImageLoaded:*Packet* OR win.ImageLoaded:*npf*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-17669b75e6 | check C059 | aggregate | {"dataset": "windows.powershell", "field": "host.name", "query": "event.code:4104 AND (win.ScriptBlockText:*pktmon* OR win.ScriptBlockText:*netsh* OR win.ScriptBlockText:*dumpcap* OR win.ScriptBlockText:*RawCap*)", "time_from": null, "time_to": null, "size": 5… | 0 |  |
| q-c04a3a3eda | check C060 | aggregate | {"dataset": "zeek", "field": "zeek.service", "query": "event.action:conn", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 613 |  |
| q-c845b0830d | check C061 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4656 OR event.code:4663 OR event.code:4670", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 10977 |  |
| q-11d140d419 | check C062 | aggregate | {"dataset": "windows.security", "field": "win.ProcessName", "query": "event.code:4656 AND (win.ObjectName:*lsass* OR win.ObjectName:*SAM* OR win.ObjectName:*SECURITY* OR win.ObjectName:*Credential*)", "time_from": null, "time_to": null, "size": 50, "sub_field"… | 23 |  |
| q-d69b2a698c | check C063 | aggregate | {"dataset": "windows.security", "field": "win.AccessMask", "query": "event.code:4656 AND win.ObjectName:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 13 |  |
| q-7a99245daa | check C064 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass.exe", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-4f81246d12 | check C065 | aggregate | {"dataset": "windows.sysmon", "field": "win.SourceImage", "query": "event.code:10 AND win.TargetImage:*lsass.exe", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-6efc85ac9f | check C066 | aggregate | {"dataset": "windows.powershell", "field": "host.name", "query": "event.code:4104 AND (win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*MiniDump* OR win.ScriptBlockText:*Credential* OR win.ScriptBlockText:*keylog*)", "time_from": null, "time_to": null, "siz… | 3 |  |
| q-f9ccf38ced | check C067 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 | F11 |
| q-4998cb9b6b | check C068 | aggregate | {"dataset": "windows.sysmon", "field": "registry.path", "query": "event.code:13 AND (registry.path:*Keyboard* OR registry.path:*keylog* OR registry.path:*SetWindowsHookEx*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 26 |  |
| q-3aaf71f06d | check C069 | aggregate | {"dataset": "windows.sysmon", "field": "win.ImageLoaded", "query": "event.code:7 AND (win.ImageLoaded:*keylog* OR win.ImageLoaded:*hook*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-9b0447a818 | check C070 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*keylog* OR process.command_line:*GetAsyncKeyState* OR process.command_line:*SetWindowsHookEx*)", "time_from": null, "time_to": null, "size": 50, "sub… | 0 |  |
| q-1b2255ef3d | check C071 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4656 OR event.code:4663 OR event.code:4670", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 10977 |  |
| q-e97bd1af8b | check C072 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-659a4971d2 | check C073 | aggregate | {"dataset": "windows.powershell", "field": "host.name", "query": "event.code:4104 AND (win.ScriptBlockText:*keylog* OR win.ScriptBlockText:*GetAsyncKeyState* OR win.ScriptBlockText:*SetWindowsHookEx*)", "time_from": null, "time_to": null, "size": 50, "sub_fiel… | 0 |  |
| q-a947ac86bc | check C074 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*Credential* OR process.command_line:*prompt* OR process.command_line:*consent* OR process.command_line:*Runas*)", "time_from": null, "time_to": null,… | 3 |  |
| q-43051ad09e | check C075 | aggregate | {"dataset": "windows.powershell", "field": "host.name", "query": "event.code:4104 AND (win.ScriptBlockText:*Credential* OR win.ScriptBlockText:*Get-Credential* OR win.ScriptBlockText:*Windows.Forms* OR win.ScriptBlockText:*InputBox*)", "time_from": null, "time… | 5 |  |
| q-ce583e94f3 | check C076 | aggregate | {"dataset": "windows.powershell", "field": "host.name", "query": "event.code:4103", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 5080 |  |
| q-959bbc4303 | check C077 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND (process.command_line:*Credential* OR process.command_line:*consent* OR process.command_line:*Runas*)", "time_from": null, "time_to": null, "size": 50, "sub_field": nu… | 3 |  |
| q-6160d9ff1d | check C078 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-080a4e1ccc | check C079 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND (win.TargetFilename:*login* OR win.TargetFilename:*logon* OR win.TargetFilename:*portal* OR win.TargetFilename:*wwwroot*)", "time_from": null, "time_to": null, "size": 50,… | 8 |  |
| q-fa0c50599b | check C080 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*wwwroot* OR process.command_line:*inetpub* OR process.command_line:*iis*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-c3e36d4a52 | check C081 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND (win.ObjectName:*wwwroot* OR win.ObjectName:*inetpub* OR win.ObjectName:*login*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-bd596ecdae | check C082 | aggregate | {"dataset": "windows.powershell", "field": "host.name", "query": "event.code:4104 AND (win.ScriptBlockText:*wwwroot* OR win.ScriptBlockText:*inetpub* OR win.ScriptBlockText:*login*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 2 |  |
| q-0fe84e4f78 | check C083 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-0ba960f2e5 | check C084 | aggregate | {"dataset": "zeek", "field": "url.original", "query": "event.action:http", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 62 |  |
| q-9061915f96 | check C085 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-b769bfd806 | check C086 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND (win.TargetImage:*lsass* OR win.TargetImage:*LSASS*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-a33ac8f25b | check C087 | aggregate | {"dataset": "windows.sysmon", "field": "win.ImageLoaded", "query": "event.code:7", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 20259 |  |
| q-b97197420a | check C088 | search | {"dataset": "windows.sysmon", "query": "event.code:8 AND (win.SourceImage:*lsass* OR win.TargetImage:*lsass*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.exec… | 2 |  |
| q-64ab4e782b | check C089 | aggregate | {"dataset": "windows.security", "field": "win.CallerProcessName", "query": "event.code:4656 AND (win.ObjectName:*lsass* OR win.ObjectName:*LSASS*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 13 |  |
| q-d0d75446b8 | check C090 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*MiniDump* OR win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*comsvcs*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event… | 0 |  |
| q-464b7d3170 | check C091 | search | {"dataset": "windows.other", "query": "message:*lsass* OR win.ImagePath:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line… | 0 |  |
| q-eda9fa064e | check C092 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-ff5f93a673 | check C093 | aggregate | {"dataset": "windows.security", "field": "source.ip", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-32b58b2951 | check C094 | timeline | {"dataset": "windows.security", "query": "event.code:4625", "interval": "1m", "time_from": null, "time_to": null} | 0 |  |
| q-e39c00cbe1 | check C095 | aggregate | {"dataset": "windows.security", "field": "win.Status", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-534762980e | check C096 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*net1* OR process.command_line:*net.exe* OR process.command_line:*hydra* OR process.command_line:*ncrack*)", "time_from": null, "time_to": null, "size… | 0 |  |
| q-f5f0e55a94 | check C097 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*BruteForce* OR win.ScriptBlockText:*Password* OR win.ScriptBlockText:*Credential*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name"… | 4 |  |
| q-19fa8ac327 | check C098 | search | {"dataset": "windows.other", "query": "message:*logon* AND message:*fail*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "so… | 0 |  |
| q-9a079a4192 | check C099 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-33987ad55b | check C100 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 0 |  |
| q-5c545dc717 | check C101 | search | {"dataset": "windows.security", "query": "event.code:4625 AND win.TargetUserName:*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_l… | 0 |  |
| q-5103a89101 | check C102 | aggregate | {"dataset": "windows.sysmon", "field": "process.command_line", "query": "event.code:1 AND (process.command_line:*pass* OR process.command_line:*login*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1 |  |
| q-679f00cd0b | check C103 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*4625* OR win.ScriptBlockText:*Failed*Logon*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user… | 0 |  |
| q-70bf578759 | check C104 | search | {"dataset": "windows.other", "query": "message:*password*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 0 |  |
| q-7d01669965 | check C105 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*hashcat* OR process.command_line:*john* OR process.command_line:*crack*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-55fd4d2c27 | check C106 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND (win.TargetFilename:*ntds.dit* OR win.TargetFilename:*.hive* OR win.TargetFilename:*SAM*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-ba508d3df6 | check C107 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND (win.TargetImage:*lsass* OR win.TargetImage:*SAM*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-7f4003ec2d | check C108 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 OR event.code:4656 OR event.code:4670", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 10977 |  |
| q-43275a921e | check C109 | aggregate | {"dataset": "windows.security", "field": "win.ProcessName", "query": "event.code:4663 AND (win.ObjectName:*SAM* OR win.ObjectName:*SECURITY* OR win.ObjectName:*ntds*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-a97c470461 | check C110 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*hashcat* OR win.ScriptBlockText:*Invoke-Mimikatz* OR win.ScriptBlockText:*DumpCreds*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.na… | 0 |  |
| q-0afdbf7c2f | check C111 | search | {"dataset": "windows.other", "query": "file.path:*ntds* OR file.path:*SAM*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "s… | 0 |  |
| q-59d942c091 | check C112 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 200, "sub_field": null} | 0 |  |
| q-9d30ee0394 | check C113 | aggregate | {"dataset": "windows.security", "field": "source.ip", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-58159ea1d3 | check C114 | search | {"dataset": "windows.security", "query": "event.code:4648", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 15 |  |
| q-73427de37d | check C115 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4624 AND win.LogonType:3", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 218 |  |
| q-df37cefe32 | check C116 | aggregate | {"dataset": "windows.sysmon", "field": "process.command_line", "query": "event.code:1 AND (process.command_line:*spray* OR process.command_line:*DomainPasswordSpray*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-a400fc0408 | check C117 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Spray* OR win.ScriptBlockText:*4625*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name",… | 0 |  |
| q-ec67d8ea8f | check C118 | search | {"dataset": "windows.other", "query": "message:*logon*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 2 |  |
| q-4d04d24d8d | check C119 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 200, "sub_field": null} | 0 |  |
| q-b90d56a3ae | check C120 | aggregate | {"dataset": "windows.security", "field": "source.ip", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-40f15e76cb | check C121 | search | {"dataset": "windows.security", "query": "event.code:4625 AND win.LogonType:3", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line",… | 0 |  |
| q-63eebb21ba | check C122 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*stuff* OR process.command_line:*combo* OR process.command_line:*credential*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-9aadba0043 | check C123 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*credential* OR win.ScriptBlockText:*password*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "us… | 2 | F18 |
| q-58d7794c59 | check C124 | search | {"dataset": "windows.other", "query": "message:*account* AND message:*fail*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "… | 0 |  |
| q-c9f695a721 | check C125 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 297 |  |
| q-38983abf36 | check C126 | search | {"dataset": "windows.security", "query": "event.code:4648", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 15 |  |
| q-45a515b440 | check C127 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 39283 |  |
| q-2690649683 | check C128 | search | {"dataset": "windows.sysmon", "query": "event.code:13 AND registry.path:*Credential*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command… | 11 |  |
| q-56db1dfb7e | check C129 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND win.ScriptBlockText:*Credential*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "pro… | 3 |  |
| q-ade520b30f | check C130 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 | F19 |
| q-e3562f69b7 | check C131 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:5145", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 121 |  |
| q-f49ed87e83 | check C132 | aggregate | {"dataset": "windows.security", "field": "win.ShareName", "query": "event.code:5140", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 42 |  |
| q-356390f8c7 | check C133 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1649 |  |
| q-2daa2f85ba | check C134 | search | {"dataset": "windows.sysmon", "query": "event.code:3 AND (destination.port:445 OR destination.port:139)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable… | 66 | F22 |
| q-1c8e50e06d | check C135 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*\\\\* OR win.ScriptBlockText:*http*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", … | 88 |  |
| q-d7041607ab | check C136 | search | {"dataset": "windows.other", "query": "event.code:6", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destination… | 11 | F22 |
| q-30124fe6d8 | check C137 | aggregate | {"dataset": "zeek", "field": "destination.port", "query": "event.action:conn", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 613 |  |
| q-08259b7740 | check C138 | search | {"dataset": "zeek", "query": "event.action:http AND (http.request.method:PROPFIND OR http.request.method:OPTIONS OR http.request.method:MOVE)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.c… | 36 |  |
| q-430e0b657a | check C139 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 326 |  |
| q-f12b1b0b2c | check C140 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 326 |  |
| q-dc465961ad | check C141 | aggregate | {"dataset": "windows.security", "field": "win.ServiceFileName", "query": "event.code:7045", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 0 |  |
| q-ca03aa397f | check C142 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 460 |  |
| q-717cb5f7eb | check C143 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Invoke-* OR win.ScriptBlockText:*Reflection* OR win.ScriptBlockText:*Assembly*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "… | 22 |  |
| q-d9b0a0e967 | check C144 | search | {"dataset": "windows.other", "query": "event.code:1 OR event.code:10 OR event.code:11", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.comman… | 10 | F25 |
| q-634de48a61 | check C145 | search | {"dataset": "zeek", "query": "event.action:notice OR event.action:weird", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "sour… | 14 | F25 |
| q-17eda5e106 | check C146 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND (win.TargetFilename:*Cookies* OR win.TargetFilename:*Login Data* OR win.TargetFilename:*Web Data*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 162 |  |
| q-33f7185dd8 | check C147 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND (win.TargetImage:*chrome* OR win.TargetImage:*firefox* OR win.TargetImage:*msedge* OR win.TargetImage:*iexplore*)", "time_from": null, "time_to": null, "size": 30, "sub_fi… | 0 |  |
| q-c76fd6ffde | check C148 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 460 |  |
| q-6622023960 | check C149 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Cookies* OR win.ScriptBlockText:*Login Data* OR win.ScriptBlockText:*sqlite*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "ev… | 13 |  |
| q-c9d44656cf | check C150 | search | {"dataset": "windows.other", "query": "event.code:11 OR event.code:1", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.… | 7 |  |
| q-d2d2d06686 | check C151 | search | {"dataset": "zeek", "query": "event.action:http AND http.request.method:GET", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "… | 2 |  |
| q-9b7e93f3c1 | check C152 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND (win.TargetFilename:*unattend* OR win.TargetFilename:*.config OR win.TargetFilename:*.txt OR win.TargetFilename:*.xml)", "time_from": null, "time_to": null, "size": 50, "s… | 44 |  |
| q-44dd788973 | check C153 | aggregate | {"dataset": "windows.sysmon", "field": "registry.path", "query": "event.code:13 AND (registry.path:*Password* OR registry.path:*Credential*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 17 |  |
| q-4bd8da19bb | check C154 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 460 |  |
| q-8aa002535b | check C155 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*password* OR win.ScriptBlockText:*credential* OR win.ScriptBlockText:*Get-Content*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name… | 2 | F28 |
| q-99e1278719 | check C156 | search | {"dataset": "windows.other", "query": "event.code:1 OR event.code:11", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.… | 7 |  |
| q-1f85b1f5a7 | check C157 | search | {"dataset": "zeek", "query": "event.action:smb_files", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinatio… | 12 |  |
| q-4ec6a398b2 | check C158 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*password* OR process.command_line:*credential* OR process.command_line:*.config OR process.command_line:*.txt)", "time_from": null, "time_to": null, … | 1 |  |
| q-4c00e89af8 | check C159 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1649 |  |
| q-1cc06d167c | check C160 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 5337 |  |
| q-5432a8536d | check C161 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 297 |  |
| q-fc18ac34ba | check C162 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Select-String* OR win.ScriptBlockText:*Get-ChildItem* OR win.ScriptBlockText:*findstr*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.… | 2 |  |
| q-f57f113aea | check C163 | search | {"dataset": "windows.other", "query": "event.code:1 OR event.code:11", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.… | 7 |  |
| q-08b0582072 | check C164 | search | {"dataset": "zeek", "query": "event.action:smb_files", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinatio… | 12 | F31 |
| q-e7f4426c44 | check C165 | aggregate | {"dataset": "windows.sysmon", "field": "registry.path", "query": "event.code:13 AND (registry.path:*Password* OR registry.path:*Credential* OR registry.path:*Login* OR registry.path:*Secret*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 20 |  |
| q-249d780f7d | check C166 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*reg\\ query* OR process.command_line:*reg\\ save* OR process.command_line:*Password* OR process.command_line:*Credential*)", "time_from": null, "time_to": null, "fields": ["@timest… | 0 |  |
| q-4b79323cdf | check C167 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Password* OR win.ScriptBlockText:*Credential* OR win.ScriptBlockText:*reg\\ query* OR win.ScriptBlockText:*Get-ItemProperty*)", "time_from": null, "time_to": null, "fields": … | 5 |  |
| q-982aaeff09 | check C168 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND (win.ObjectName:*Password* OR win.ObjectName:*Credential* OR win.ObjectName:*Secret*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-d9fec7bb78 | check C169 | search | {"dataset": "windows.other", "query": "message:*Password* OR message:*Credential* OR message:*reg\\ query*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executa… | 2 |  |
| q-674b140418 | check C170 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*history* OR win.ScriptBlockText:*ConsoleHost_history* OR win.ScriptBlockText:*Get-History*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "obser… | 0 |  |
| q-0a300adeae | check C171 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*history* OR process.command_line:*Get-History* OR process.command_line:*ConsoleHost_history*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.… | 0 |  |
| q-ae133d7d2d | check C172 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*ConsoleHost_history* OR file.path:*history*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process… | 0 |  |
| q-4353d9313b | check C173 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND win.ObjectName:*history*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-bb4dbfd1cd | check C174 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*.pfx* OR process.command_line:*.pem* OR process.command_line:*.key* OR process.command_line:*.p12* OR process.command_line:*.ppk*)", "time_from": null, "time_to": null, "fields": [… | 0 |  |
| q-3b0e06e879 | check C175 | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11 AND (file.path:*.pfx OR file.path:*.pem OR file.path:*.key OR file.path:*.p12 OR file.path:*.ppk OR file.path:*.cer OR file.path:*.p7b)", "time_from": null, "time_to": null, "size": 50… | 1 |  |
| q-43fb5ef7f4 | check C176 | aggregate | {"dataset": "windows.security", "field": "win.RelativeTargetName", "query": "event.code:5145 AND (win.RelativeTargetName:*.pfx OR win.RelativeTargetName:*.pem OR win.RelativeTargetName:*.key OR win.RelativeTargetName:*.p12 OR win.RelativeTargetName:*.ppk)", "t… | 0 |  |
| q-d4a9c52c0d | check C177 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*.pfx* OR win.ScriptBlockText:*.pem* OR win.ScriptBlockText:*.ppk* OR win.ScriptBlockText:*Export-PfxCertificate* OR win.ScriptBlockText:*certutil*)", "time_from": null, "time… | 2 |  |
| q-f1350f2447 | check C178 | search | {"dataset": "windows.other", "query": "message:*.pfx* OR message:*.pem* OR message:*.ppk* OR message:*.p12*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.execut… | 0 |  |
| q-578f267437 | check C179 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*cpassword* OR win.ScriptBlockText:*Groups.xml* OR win.ScriptBlockText:*gpp* OR win.ScriptBlockText:*AES* OR win.ScriptBlockText:*SYSVOL*)", "time_from": null, "time_to": null… | 0 |  |
| q-073c699982 | check C180 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*Groups.xml* OR process.command_line:*cpassword* OR process.command_line:*SYSVOL* OR process.command_line:*gpp*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host… | 0 |  |
| q-31995331b7 | check C181 | aggregate | {"dataset": "windows.security", "field": "win.RelativeTargetName", "query": "event.code:5145 AND (win.RelativeTargetName:*Groups.xml OR win.RelativeTargetName:*SYSVOL* OR win.RelativeTargetName:*.xml)", "time_from": null, "time_to": null, "size": 50, "sub_fiel… | 0 |  |
| q-0eb0b57a38 | check C182 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*Groups.xml OR file.path:*SYSVOL*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable… | 0 |  |
| q-210674bb87 | check C183 | search | {"dataset": "windows.other", "query": "message:*Groups.xml* OR message:*cpassword* OR message:*SYSVOL*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable"… | 0 |  |
| q-f1b8caeaf2 | check C184 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND (win.TargetImage:*lsass.exe OR win.TargetImage:*lsass*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-bf5d5f7b8c | check C185 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND (win.TargetImage:*lsass.exe OR win.TargetImage:*lsass*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-a3052d6f72 | check C186 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*MiniDump* OR process.command_line:*comsvcs* OR process.command_line:*procdump* OR process.command_line:*sekurlsa* OR process.command_line:*lsass*)", "time_from": null, "time_to": n… | 1 |  |
| q-9da5a3e1d2 | check C187 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND (win.ObjectName:*lsass* OR win.ObjectName:*SAM* OR win.ObjectName:*SECURITY* OR win.ObjectName:*NTDS* OR win.ObjectName:*DPAPI* OR win.ObjectName:*Credential*)", "time_fro… | 6 |  |
| q-052a66b2c7 | check C188 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4656 AND (win.ObjectName:*lsass* OR win.ObjectName:*SAM* OR win.ObjectName:*SECURITY* OR win.ObjectName:*NTDS*)", "time_from": null, "time_to": null, "size": 50, "sub_field": n… | 23 |  |
| q-3dac90dd2b | check C189 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*MiniDump* OR win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*sekurlsa* OR win.ScriptBlockText:*Invoke-Mimikatz* OR win.ScriptBlockText:*Credential*)", "time_from": null, … | 3 |  |
| q-e0cceb35da | check C190 | search | {"dataset": "windows.other", "query": "message:*lsass* OR message:*MiniDump* OR message:*mimikatz* OR message:*procdump*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "p… | 0 |  |
| q-abd81cfc12 | check C191 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND (win.TargetImage:*chrome.exe OR win.TargetImage:*firefox.exe OR win.TargetImage:*msedge.exe OR win.TargetImage:*iexplore.exe)", "time_from": null, "time_to": null, "size":… | 0 |  |
| q-982ff9c0fc | check C192 | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11 AND (file.path:*Login\\ Data* OR file.path:*logins.json* OR file.path:*key4.db* OR file.path:*Cookies* OR file.path:*Web Data*)", "time_from": null, "time_to": null, "size": 50, "sub_f… | 162 |  |
| q-2d43b96886 | check C193 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*Login\\ Data* OR process.command_line:*logins.json* OR process.command_line:*key4.db* OR process.command_line:*Cookies*)", "time_from": null, "time_to": null, "fields": ["@timestam… | 0 |  |
| q-a9d4072633 | check C194 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND (win.ObjectName:*Login\\ Data* OR win.ObjectName:*logins.json* OR win.ObjectName:*key4.db* OR win.ObjectName:*Cookies*)", "time_from": null, "time_to": null, "size": 50, "… | 0 |  |
| q-edc6bae369 | check C195 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Login\\ Data* OR win.ScriptBlockText:*logins.json* OR win.ScriptBlockText:*key4.db* OR win.ScriptBlockText:*Cookies*)", "time_from": null, "time_to": null, "fields": ["@times… | 0 |  |
| q-8abe721e92 | check C196 | search | {"dataset": "windows.other", "query": "message:*Login\\ Data* OR message:*logins.json* OR message:*key4.db*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.execut… | 0 |  |
| q-866b8f476c | check C197 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND (process.executable:*lsass* OR win.TargetImage:*lsass*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1070 |  |
| q-f1a673a4ab | check C198 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-d44f1395a6 | check C199 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*vaultcmd* OR process.command_line:*Credential* OR process.command_line:*cmdkey*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event… | 0 |  |
| q-98ab1c52a7 | check C200 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*vaultcmd* OR process.command_line:*cmdkey* OR process.command_line:*Credential*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "… | 0 |  |
| q-950e549d10 | check C201 | search | {"dataset": "windows.sysmon", "query": "event.code:15 AND (win.TargetFilename:*Credentials* OR win.TargetFilename:*Vault*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", … | 0 |  |
| q-29188d1636 | check C202 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*vault* OR win.ScriptBlockText:*Credential* OR win.ScriptBlockText:*cmdkey*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "even… | 3 |  |
| q-384c8bcb9f | check C203 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*keepass* OR process.command_line:*1password* OR process.command_line:*bitwarden* OR process.command_line:*lastpass*)", "time_from": null, "time_to": … | 0 |  |
| q-ef28b286d3 | check C204 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (win.TargetFilename:*.kdbx OR win.TargetFilename:*1password* OR win.TargetFilename:*keepass*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset"… | 0 |  |
| q-f06bba0856 | check C205 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND (win.TargetImage:*keepass* OR win.TargetImage:*1password* OR win.TargetImage:*bitwarden*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-77e4865dd6 | check C206 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*keepass* OR process.command_line:*1password* OR process.command_line:*bitwarden*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", … | 0 |  |
| q-fe6d1a3dcf | check C207 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*kdbx* OR win.ScriptBlockText:*keepass* OR win.ScriptBlockText:*1password*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event… | 0 |  |
| q-fd18849c3d | check C208 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-a32787d5cf | check C209 | aggregate | {"dataset": "windows.sysmon", "field": "win.ImageLoaded", "query": "event.code:7 AND (win.ImageLoaded:*lsass* OR win.ImageLoaded:*cryptdll* OR win.ImageLoaded:*sam* OR win.ImageLoaded:*wdigest* OR win.ImageLoaded:*kerberos*)", "time_from": null, "time_to": nul… | 92 |  |
| q-919f9774da | check C210 | search | {"dataset": "windows.sysmon", "query": "event.code:13 AND (registry.path:*SecurityProviders* OR registry.path:*Lsa* OR registry.path:*WDigest* OR registry.path:*Authentication*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "obser… | 66 |  |
| q-b076a43676 | check C211 | search | {"dataset": "windows.security", "query": "event.code:4657 AND (win.ObjectName:*Lsa* OR win.ObjectName:*SecurityProviders* OR win.ObjectName:*WDigest*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset",… | 0 |  |
| q-329cc36d46 | check C212 | aggregate | {"dataset": "windows.security", "field": "win.LogonProcessName", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 297 |  |
| q-f5a31d30b7 | check C213 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 297 |  |
| q-dd9525fd68 | check C214 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4648", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 15 |  |
| q-7a8b887fce | check C215 | aggregate | {"dataset": "windows.sysmon", "field": "win.ImageLoaded", "query": "event.code:7 AND (win.ImageLoaded:*lsass* OR win.ImageLoaded:*cryptdll*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 33 |  |
| q-b3694e18fb | check C216 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-0b619388e6 | check C217 | search | {"dataset": "windows.other", "query": "event.code:7045 AND (win.ImagePath:*lsass* OR win.ImagePath:*cryptdll* OR win.ServiceName:*lsass*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code"… | 0 |  |
| q-cc63edbd38 | check C218 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (win.TargetFilename:*System32* OR win.TargetFilename:*SysWOW64*) AND win.TargetFilename:*.dll", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset"… | 0 |  |
| q-5838ef590d | check C219 | search | {"dataset": "windows.sysmon", "query": "event.code:13 AND (registry.path:*Notification Packages* OR registry.path:*PasswordFilter* OR registry.path:*Lsa*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.datas… | 0 |  |
| q-f43d014eb8 | check C220 | search | {"dataset": "windows.security", "query": "event.code:4657 AND (win.ObjectName:*Notification* OR win.ObjectName:*Lsa*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "proc… | 0 |  |
| q-7cc4fc7e98 | check C221 | aggregate | {"dataset": "windows.sysmon", "field": "win.ImageLoaded", "query": "event.code:7 AND win.ImageLoaded:*.dll AND (win.ImageLoaded:*System32* OR win.ImageLoaded:*SysWOW64*)", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 18866 |  |
| q-97c6469004 | check C222 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*ReversibleEncryption* OR win.ScriptBlockText:*AllowReversiblePasswordEncryption* OR win.ScriptBlockText:*Set-ADAccountControl*)", "time_from": null, "time_to": null, "fields"… | 0 |  |
| q-11c9a86d1e | check C223 | search | {"dataset": "windows.powershell", "query": "event.code:4103 AND (win.Payload:*Reversible* OR win.Payload:*Set-ADAccountControl*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.n… | 0 |  |
| q-1923b0d68a | check C224 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*Reversible* OR process.command_line:*Set-ADAccountControl* OR process.command_line:*dsmod*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.na… | 0 |  |
| q-52e8c529b7 | check C225 | search | {"dataset": "windows.security", "query": "event.code:4739", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 0 |  |
| q-c420bd6ee2 | check C226 | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*set-aduser*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*set-adauthenticationpolicy*\" OR TO_LOWER(process.command_line) LIKE \"*set-aduser*\" OR TO_LOWER(proc… | ERROR |  |
| q-be69a52fb3 | check C226 (repaired) | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*set-aduser*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*set-adauthenticationpolicy*\" OR TO_LOWER(process.command_line) LIKE \"*set-aduser*\" OR TO_LOWER(proc… | ERROR |  |
| q-b71acde4b0 | check C227 | aggregate | {"dataset": "windows.security", "field": "event.code", "query": "event.code:4739", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 0 |  |
| q-509ea83dcc | check C228 | search | {"dataset": "windows.security", "query": "event.code:4739", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 0 |  |
| q-2e9e5484d5 | check C229 | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*set-aduser*\" OR TO_LOWER(process.command_line) LIKE \"*set-adauthenticationpolicy*\" OR TO_LOWER(process.command_line) LIKE \"*dsacls*… | ERROR |  |
| q-f791f682a8 | check C229 (repaired) | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*set-aduser*\" OR TO_LOWER(process.command_line) LIKE \"*set-adauthenticationpolicy*\" OR TO_LOWER(process.command_line) LIKE \"*dsacls*… | ERROR |  |
| q-98f0603509 | check C230 | esql | {"query": "FROM windows.other METADATA _id, _index \| WHERE TO_LOWER(message) LIKE \"*authentication*\" OR TO_LOWER(message) LIKE \"*mfa*\" OR TO_LOWER(message) LIKE \"*policy*\" \| KEEP @timestamp, host.name, event.code, message, _id, _index"} | ERROR |  |
| q-080f8d8ff6 | check C230 (repaired) | esql | {"query": "FROM windows.other METADATA _id, _index \| WHERE TO_LOWER(message) LIKE \"*authentication*\" OR TO_LOWER(message) LIKE \"*mfa*\" OR TO_LOWER(message) LIKE \"*policy*\" \| KEEP @timestamp, host.name, event.code, message, _id, _index"} | ERROR |  |
| q-9daf141aa1 | check C231 | aggregate | {"dataset": "windows.sysmon", "field": "win.ImageLoaded", "query": "event.code:7", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 20259 |  |
| q-a0bef1c6a2 | check C232 | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == \"7\" AND (TO_LOWER(win.ImageLoaded) LIKE \"*azure*\" OR TO_LOWER(win.ImageLoaded) LIKE \"*aad*\" OR TO_LOWER(win.ImageLoaded) LIKE \"*cloud*\" OR TO_LOWER(win.ImageLoaded) LIKE \"*lsas… | ERROR |  |
| q-83c2dfb35c | check C232 (repaired) | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == \"7\" AND (TO_LOWER(win.ImageLoaded) LIKE \"*azure*\" OR TO_LOWER(win.ImageLoaded) LIKE \"*aad*\" OR TO_LOWER(win.ImageLoaded) LIKE \"*cloud*\" OR TO_LOWER(win.ImageLoaded) LIKE \"*lsas… | ERROR |  |
| q-3bdc46cfa9 | check C233 | aggregate | {"dataset": "windows.security", "field": "event.code", "query": "event.code:5136", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 0 |  |
| q-e99211ef78 | check C234 | search | {"dataset": "windows.security", "query": "event.code:5136", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 0 |  |
| q-b75445aa87 | check C235 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 297 |  |
| q-c0a8c29977 | check C236 | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*azuread*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*aadinternals*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*connect-msolservice*\" OR TO_LOWER(win.ScriptBlo… | ERROR |  |
| q-c65bc8ba18 | check C236 (repaired) | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*azuread*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*aadinternals*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*connect-msolservice*\" OR TO_LOWER(win.ScriptBlo… | ERROR |  |
| q-bbdf7ede97 | check C237 | esql | {"query": "FROM windows.other METADATA _id, _index \| WHERE TO_LOWER(message) LIKE \"*azure*\" OR TO_LOWER(message) LIKE \"*aad*\" OR TO_LOWER(message) LIKE \"*hybrid*\" \| KEEP @timestamp, host.name, event.code, message, _id, _index"} | ERROR |  |
| q-265304b790 | check C237 (repaired) | esql | {"query": "FROM windows.other METADATA _id, _index \| WHERE TO_LOWER(message) LIKE \"*azure*\" OR TO_LOWER(message) LIKE \"*aad*\" OR TO_LOWER(message) LIKE \"*hybrid*\" \| KEEP @timestamp, host.name, event.code, message, _id, _index"} | ERROR |  |
| q-d373176bab | check C238 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetObject", "query": "event.code:13 AND registry.path:*NetworkProvider*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-76122befa0 | check C239 | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*system32*\" AND TO_LOWER(file.path) LIKE \"*.dll\") \| KEEP @timestamp, host.name, file.path, process.executable, _id, _index"} | ERROR |  |
| q-4bc3891258 | check C239 (repaired) | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*system32*\" AND TO_LOWER(file.path) LIKE \"*.dll\") \| KEEP @timestamp, host.name, file.path, process.executable, _id, _index"} | ERROR |  |
| q-b1f278be1b | check C240 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-82a447d5c0 | check C241 | aggregate | {"dataset": "windows.sysmon", "field": "win.ImageLoaded", "query": "event.code:7 AND (win.ImageLoaded:*np* OR win.ImageLoaded:*provider*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 145 |  |
| q-da0cb4856f | check C242 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4657", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 36 |  |
| q-15f14653e2 | check C243 | search | {"dataset": "windows.security", "query": "event.code:4657 AND win.ObjectName:*NetworkProvider*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "proce… | 0 |  |
| q-da4e82dde6 | check C244 | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*networkprovider*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*hkml*networkprovider*\" OR TO_LOWER(process.command_line) LIKE \"*networkprovider*\" \| KEEP @tim… | ERROR |  |
| q-0eae889f15 | check C244 (repaired) | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*networkprovider*\" OR TO_LOWER(process.command_line) LIKE \"*networkprovider*\" \| KEEP @timestamp, host.name, user.name, win.ScriptBlockText, p… | 0 |  |
| q-e72f787edf | check C245 | esql | {"query": "FROM windows.other METADATA _id, _index \| WHERE TO_LOWER(message) LIKE \"*network provider*\" OR TO_LOWER(message) LIKE \"*networkprovider*\" \| KEEP @timestamp, host.name, event.code, message, _id, _index"} | ERROR |  |
| q-65122615bc | check C245 (repaired) | esql | {"query": "FROM windows.other METADATA _id, _index \| WHERE TO_LOWER(message) LIKE \"*network provider*\" OR TO_LOWER(message) LIKE \"*networkprovider*\" \| KEEP @timestamp, host.name, event.code, message, _id, _index"} | ERROR |  |
| q-370b40b526 | check C246 | aggregate | {"dataset": "windows.sysmon", "field": "destination.ip", "query": "event.code:3", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1229 |  |
| q-60a514b2ed | check C247 | aggregate | {"dataset": "windows.sysmon", "field": "dns.question.name", "query": "event.code:22", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 81 |  |
| q-312f7371f2 | check C248 | aggregate | {"dataset": "windows.security", "field": "event.code", "query": "event.code:4663 OR event.code:4670 OR event.code:4656", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 10977 |  |
| q-2ba148d2ae | check C249 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 5337 |  |
| q-59d1d034e2 | check C250 | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*responder*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*inveigh*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*mitm*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*ar… | ERROR |  |
| q-5747f4cfd5 | check C250 (repaired) | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*responder*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*inveigh*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*mitm*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*ar… | ERROR |  |
| q-b53c113a15 | check C251 | esql | {"query": "FROM windows.other METADATA _id, _index \| WHERE TO_LOWER(message) LIKE \"*mitm*\" OR TO_LOWER(message) LIKE \"*relay*\" OR TO_LOWER(message) LIKE \"*spoof*\" \| KEEP @timestamp, host.name, event.code, message, _id, _index"} | ERROR |  |
| q-b8880dc1ad | check C251 (repaired) | esql | {"query": "FROM windows.other METADATA _id, _index \| WHERE TO_LOWER(message) LIKE \"*mitm*\" OR TO_LOWER(message) LIKE \"*relay*\" OR TO_LOWER(message) LIKE \"*spoof*\" \| KEEP @timestamp, host.name, event.code, message, _id, _index"} | ERROR |  |
| q-0cc95fcf08 | check C252 | aggregate | {"dataset": "zeek", "field": "zeek.service", "query": "event.action:conn", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 613 |  |
| q-2ccaf90207 | check C253 | aggregate | {"dataset": "zeek", "field": "destination.port", "query": "event.action:conn", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 613 |  |
| q-6df0b072d1 | check C254 | aggregate | {"dataset": "zeek", "field": "destination.port", "query": "event.action:dns", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 53 |  |
| q-beb7ce5bf5 | check C255 | search | {"dataset": "zeek", "query": "event.action:dns AND (destination.port:5355 OR destination.port:137)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "p… | 6 |  |
| q-eb229fe3fc | check C256 | aggregate | {"dataset": "zeek", "field": "source.ip", "query": "event.action:smb_files OR event.action:smb_mapping", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 23 |  |
| q-855595129c | check C257 | aggregate | {"dataset": "windows.security", "field": "event.code", "query": "event.code:4697", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 23 |  |
| q-c33826af9c | check C258 | search | {"dataset": "windows.security", "query": "event.code:4697", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 23 |  |
| q-16fc77ebf0 | check C259 | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == \"13\" AND TO_LOWER(registry.path) LIKE \"*dnsclient*\" AND TO_LOWER(registry.path) LIKE \"*enablemulticast*\" \| KEEP @timestamp, host.name, registry.path, registry.data.strings, _id, … | ERROR |  |
| q-42df376681 | check C259 (repaired) | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == \"13\" AND TO_LOWER(registry.path) LIKE \"*dnsclient*\" AND TO_LOWER(registry.path) LIKE \"*enablemulticast*\" \| KEEP @timestamp, host.name, registry.path, registry.data.strings, _id, … | ERROR |  |
| q-d1540ca678 | check C260 | aggregate | {"dataset": "windows.sysmon", "field": "destination.ip", "query": "event.code:3 AND (destination.port:5355 OR destination.port:137)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 8 |  |
| q-6c03c1b541 | check C261 | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*llmnr*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*nbt-ns*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*responder*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*in… | ERROR |  |
| q-2e6baa7d18 | check C261 (repaired) | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*llmnr*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*nbt-ns*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*responder*\" OR TO_LOWER(win.ScriptBlockTex… | 0 |  |
| q-5c36e52291 | check C262 | esql | {"query": "FROM windows.other METADATA _id, _index \| WHERE TO_LOWER(message) LIKE \"*llmnr*\" OR TO_LOWER(message) LIKE \"*nbt-ns*\" OR TO_LOWER(message) LIKE \"*multicast*\" \| KEEP @timestamp, host.name, event.code, message, _id, _index"} | ERROR |  |
| q-7787cbfc4d | check C262 (repaired) | esql | {"query": "FROM windows.other METADATA _id, _index \| WHERE TO_LOWER(message) LIKE \"*llmnr*\" OR TO_LOWER(message) LIKE \"*nbt-ns*\" OR TO_LOWER(message) LIKE \"*multicast*\" \| KEEP @timestamp, host.name, event.code, message, _id, _index"} | ERROR |  |
| q-4166a336c7 | check C263 | aggregate | {"dataset": "windows.sysmon", "field": "destination.ip", "query": "event.code:3", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1229 |  |
| q-b3d06dc733 | check C264 | aggregate | {"dataset": "windows.sysmon", "field": "dns.question.name", "query": "event.code:22", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 81 |  |
| q-4ef42abb77 | check C265 | aggregate | {"dataset": "windows.security", "field": "event.code", "query": "event.code:5156 OR event.code:5157", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 3203 |  |
| q-badb0a2a9f | check C266 | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*arpspoof*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*arp*poison*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*ettercap*\" OR TO_LOWER(win.ScriptBlockText) LIKE… | ERROR |  |
| q-beec545095 | check C266 (repaired) | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*arpspoof*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*arp*poison*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*ettercap*\" OR TO_LOWER(win.ScriptBl… | 0 |  |
| q-1f22420785 | check C267 | esql | {"query": "FROM windows.other METADATA _id, _index \| WHERE TO_LOWER(message) LIKE \"*arp*\" \| KEEP @timestamp, host.name, event.code, message, _id, _index"} | ERROR |  |
| q-fcd0fa4cf5 | check C267 (repaired) | esql | {"query": "FROM windows.other METADATA _id, _index \| WHERE TO_LOWER(message) LIKE \"*arp*\" \| KEEP @timestamp, host.name, event.code, message, _id, _index"} | ERROR |  |
| q-b66148c8b9 | check C268 | aggregate | {"dataset": "zeek", "field": "zeek.orig_l2_addr", "query": "event.action:conn", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 613 |  |
| q-a140d65288 | check C269 | aggregate | {"dataset": "zeek", "field": "zeek.resp_l2_addr", "query": "event.action:conn", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 613 |  |
| q-e36d7c981e | check C270 | aggregate | {"dataset": "windows.other", "field": "event.code", "query": "*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 216 |  |
| q-d6edbe075e | check C271 | search | {"dataset": "windows.other", "query": "event.code:(1341 OR 1342 OR 1020 OR 1063)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_lin… | 0 |  |
| q-0b68d65798 | check C272 | aggregate | {"dataset": "windows.security", "field": "win.LogonProcessName", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 297 |  |
| q-7a9165faed | check C273 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*dhcp* OR process.command_line:*ipconfig* OR process.command_line:*netsh*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 5 |  |
| q-9c302888b9 | check C274 | search | {"dataset": "windows.powershell", "query": "win.ScriptBlockText:(*dhcp* OR *DhcpServer* OR *rogue*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "… | 0 |  |
| q-c876ce2e8f | check C275 | aggregate | {"dataset": "zeek", "field": "event.action", "query": "*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 2140 |  |
| q-41bf993394 | check C276 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-dda4ff125a | check C277 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-d5d7911c50 | check C278 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4672", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 212 |  |
| q-37c2592012 | check C279 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 297 |  |
| q-c84bbb5a4d | check C280 | aggregate | {"dataset": "windows.other", "field": "event.code", "query": "*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 216 |  |
| q-8c296d807b | check C281 | search | {"dataset": "windows.powershell", "query": "win.ScriptBlockText:(*kerberos* OR *kirbi* OR *ticket* OR *mimikatz* OR *Rubeus*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name… | 0 |  |
| q-cab011da58 | check C282 | aggregate | {"dataset": "zeek", "field": "zeek.request_type", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 35 |  |
| q-a653ecd8ae | check C283 | aggregate | {"dataset": "windows.security", "field": "event.code", "query": "*", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 41002 |  |
| q-914d5989cc | check C284 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4672", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 212 |  |
| q-049a6dd37f | check C285 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-8dfd0c96d3 | check C286 | aggregate | {"dataset": "windows.other", "field": "event.code", "query": "*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 216 |  |
| q-c8b9d40b30 | check C287 | search | {"dataset": "windows.powershell", "query": "win.ScriptBlockText:(*krbtgt* OR *golden* OR *mimikatz* OR *sekurlsa*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process… | 0 |  |
| q-46cab987ac | check C288 | aggregate | {"dataset": "zeek", "field": "zeek.request_type", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 35 |  |
| q-4715c4d2dd | check C289 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4672", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 212 |  |
| q-e08e1ecb31 | check C290 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 297 |  |
| q-a590ce0116 | check C291 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-93bc324cf1 | check C292 | aggregate | {"dataset": "windows.other", "field": "event.code", "query": "*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 216 |  |
| q-c27f74c02a | check C293 | search | {"dataset": "windows.powershell", "query": "win.ScriptBlockText:(*silver* OR *kerberoast* OR *tgs* OR *mimikatz*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.… | 0 |  |
| q-b46eb586fb | check C294 | aggregate | {"dataset": "zeek", "field": "zeek.request_type", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 35 |  |
| q-cf304f3ba0 | check C295 | aggregate | {"dataset": "windows.security", "field": "event.code", "query": "*", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 41002 |  |
| q-a18fecf5ea | check C296 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 297 |  |
| q-eaa50d6e8b | check C297 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4672", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 212 |  |
| q-20de847f83 | check C298 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-b6ee442455 | check C299 | aggregate | {"dataset": "windows.other", "field": "event.code", "query": "*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 216 |  |
| q-f7f55fd803 | check C300 | search | {"dataset": "windows.powershell", "query": "win.ScriptBlockText:(*kerberoast* OR *SPN* OR *Invoke-Kerberoast* OR *GetUserSPNs*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.na… | 0 |  |
| q-a56ec803c0 | check C301 | aggregate | {"dataset": "zeek", "field": "zeek.request_type", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 35 |  |
| q-0c4e7f128b | check C302 | aggregate | {"dataset": "windows.security", "field": "event.code", "query": "*", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 41002 |  |
| q-9dff762af2 | check C303 | aggregate | {"dataset": "windows.security", "field": "win.PreAuthType", "query": "event.code:4768", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 14 |  |
| q-87f16340bf | check C304 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*asrep* OR process.command_line:*GetNPUsers* OR process.command_line:*kerberos*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-0b294511b9 | check C305 | aggregate | {"dataset": "windows.other", "field": "event.code", "query": "*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 216 |  |
| q-0381fb47b3 | check C306 | search | {"dataset": "windows.powershell", "query": "win.ScriptBlockText:(*asrep* OR *AS-REP* OR *GetNPUsers* OR *preauth*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process… | 0 |  |
| q-9e6c3a0df4 | check C307 | aggregate | {"dataset": "zeek", "field": "zeek.request_type", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 35 |  |
| q-3b330c0788 | check C308 | aggregate | {"dataset": "windows.security", "field": "win.LogonProcessName", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 297 |  |
| q-fb07410bf3 | check C309 | aggregate | {"dataset": "windows.security", "field": "win.AuthenticationPackageName", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 297 |  |
| q-b38bd05093 | check C310 | search | {"dataset": "windows.security", "query": "event.code:4648", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 15 |  |
| q-d12bb87d18 | check C311 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-6868f6f1b9 | check C312 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-9259871261 | check C313 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Aes* OR win.ScriptBlockText:*Cookie* OR win.ScriptBlockText:*Token* OR win.ScriptBlockText:*SAML*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name",… | 0 |  |
| q-ef74aef7cf | check C314 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-1ab80100d2 | check C315 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND (win.TargetFilename:*Cookies* OR win.TargetFilename:*Login Data* OR win.TargetFilename:*Web Data*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 162 |  |
| q-2b4e55d52e | check C316 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:11 AND (win.TargetFilename:*Cookies* OR win.TargetFilename:*Login Data*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 162 |  |
| q-80731a9e99 | check C317 | search | {"dataset": "windows.security", "query": "event.code:4648", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 15 |  |
| q-4623a939cc | check C318 | aggregate | {"dataset": "windows.security", "field": "win.LogonProcessName", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 297 |  |
| q-67dc9b253d | check C319 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Cookies* OR win.ScriptBlockText:*Set-Cookie* OR win.ScriptBlockText:*session*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "e… | 1 | F53 |
| q-7fcdaa4ffe | check C320 | search | {"dataset": "windows.other", "query": "event.code:11", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinatio… | 4 |  |
| q-0864fb258e | check C321 | search | {"dataset": "windows.security", "query": "event.code:4648", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 15 | F54 |
| q-24d887d043 | check C322 | aggregate | {"dataset": "windows.security", "field": "win.AuthenticationPackageName", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 297 |  |
| q-e0dab0b2be | check C323 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-f676fe80fe | check C324 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*SAML* OR win.ScriptBlockText:*ADFS* OR win.ScriptBlockText:*token-signing*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "even… | 0 |  |
| q-35f5b59e5b | check C325 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND (win.TargetFilename:*ADFS* OR win.TargetFilename:*.pfx* OR win.TargetFilename:*.p12*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1 |  |
| q-a5ad0ecbe7 | check C326 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-d399a87635 | check C327 | timeline | {"dataset": "windows.security", "query": "event.code:4625", "interval": "1m", "time_from": null, "time_to": null} | 0 |  |
| q-22a9de6cc0 | check C328 | aggregate | {"dataset": "windows.security", "field": "source.ip", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-525d7decf6 | check C329 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*MFA* OR win.ScriptBlockText:*Authenticator* OR win.ScriptBlockText:*Push*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event… | 0 |  |
| q-6463c7532b | check C330 | search | {"dataset": "windows.other", "query": "event.code:4625", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 0 |  |
| q-825d8b0003 | check C331 | search | {"dataset": "windows.security", "query": "event.code:4657", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 36 | F57 |
| q-ae45044cd5 | check C332 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4657", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 36 |  |
| q-1d2dbe82db | check C333 | search | {"dataset": "windows.security", "query": "event.code:4768", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 14 |  |
| q-771f117cb9 | check C334 | aggregate | {"dataset": "windows.security", "field": "win.TicketEncryptionType", "query": "event.code:4768", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 14 |  |
| q-44919b3148 | check C335 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND (win.TargetFilename:*.pfx* OR win.TargetFilename:*.p12* OR win.TargetFilename:*.cer* OR win.TargetFilename:*.pvk*)", "time_from": null, "time_to": null, "size": 50, "sub_f… | 1 |  |
| q-4808c0e3cd | check C336 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Cert* OR win.ScriptBlockText:*Export-PfxCertificate* OR win.ScriptBlockText:*New-SelfSignedCertificate*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.… | 1 |  |
| q-d7f86c3d76 | check C337 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-795423fb6d | triage T1003 step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 10 AND win.TargetImage LIKE \"*lsass*\" \| STATS cnt = COUNT(*) BY process.executable, win.GrantedAccess, host.name \| SORT cnt DESC"} | ERROR |  |
| q-2f50c7f008 | triage T1003 step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 13 AND (registry.path LIKE \"*SAM*\" OR registry.path LIKE \"*SECURITY*\") \| KEEP @timestamp, host.name, process.executable, registry.path, registry.data.strings, user.nam… | ERROR |  |
| q-a16d4c920b | triage T1003 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND win.TargetImage LIKE \"*lsass*\" \| STATS cnt = COUNT(*) BY process.executable, win.GrantedAccess, host.name \| SORT cnt DESC"} | 18 |  |
| q-ccedcd087b | triage T1003 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"13\" AND (registry.path LIKE \"*SAM*\" OR registry.path LIKE \"*SECURITY*\") \| KEEP @timestamp, host.name, process.executable, registry.path, registry.data.strings, user… | 7 | F02, F05 |
| q-6692ee2ec3 | triage T1003 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND win.TargetImage LIKE \"*lsass*\" AND (win.GrantedAccess == \"0x1f3fff\" OR win.GrantedAccess == \"0x1fffff\" OR win.GrantedAccess == \"0x101001\") \| KEEP @times… | 7 | F01 |
| q-15bb43663b | triage T1003 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (process.executable LIKE \"*python*\" OR process.executable LIKE \"*PsExec*\" OR process.executable LIKE \"*sdelete*\" OR process.executable LIKE \"*rundll32*\" O… | 30 | F05 |
| q-d7c23bdd9b | triage T1003 step 4 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None |  |
| q-5cb4deeb4d | triage T1003 step 4 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None | F01 |
| q-e8adb8095c | triage T1003 step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (win.ScriptBlockText LIKE \"*lsass*\" OR win.ScriptBlockText LIKE \"*MiniDump*\" OR win.ScriptBlockText LIKE \"*procdump*\" OR win.ScriptBlockText LIKE \"*… | 2 |  |
| q-360d28af56 | triage T1003 step 5 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (win.ScriptBlockText LIKE \"*Invoke-*\" OR win.ScriptBlockText LIKE \"*Get-Process*\" OR win.ScriptBlockText LIKE \"*OpenProcess*\" OR win.ScriptBlockText … | 25 | F01 |
| q-8afdebb3ef | triage T1003 step 5 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4688\" AND (process.command_line LIKE \"*python*\" OR process.command_line LIKE \"*PsExec*\" OR process.command_line LIKE \"*sdelete*\" OR process.command_line LIKE \"*… | 17 |  |
| q-04d08bd3fd | triage T1003 step 6 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qqQ-d4"} | None |  |
| q-a59709ecb1 | triage T1003 step 6 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4662\", \"4624\", \"4672\") AND host.name LIKE \"utica*\" \| STATS cnt = COUNT(*) BY event.code, win.ObjectType, win.Properties, win.TargetUserName, win.LogonType \| S… | 1 |  |
| q-b07f473a09 | triage T1003 step 7 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4662\" AND host.name LIKE \"utica*\" \| KEEP @timestamp, host.name, user.name, win.SubjectUserName, win.SubjectDomainName, win.ObjectType, win.ObjectName, win.Propertie… | 2 | F03, F04, F06 |
| q-a3f42e7d4c | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-b7a95063fe | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-74c1359b8b | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-a1728d972a | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None |  |
| q-b92087ed6d | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None |  |
| q-b2c7dea38b | triage T1003 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qrRbzS"} | None |  |
| q-b6aeafbed0 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qqQ-d4"} | None |  |
| q-c6ef8a0c2a | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cpgKxF"} | None |  |
| q-df9040294f | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cpgKxF"} | None |  |
| q-e0d728ea22 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cNAtxy"} | None |  |
| q-5d6441c983 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nOhdc5"} | None |  |
| q-cd7384ff8d | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nOhdc5"} | None |  |
| q-086a62550b | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nOhdc5"} | None |  |
| q-670c501c99 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq8GZx"} | None |  |
| q-d389f225d9 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c82OiA"} | None |  |
| q-9ffb488884 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c82OiA"} | None |  |
| q-04a23fb988 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cwoB6Q"} | None |  |
| q-d368c74590 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cxoQzx"} | None |  |
| q-90d506fd13 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nOhdc5"} | None |  |
| q-e9216bff73 | triage T1040 step 1 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*pktmon* OR process.command_line:*netsh* OR process.command_line:*windump* OR process.command_line:*tcpdump* OR process.command_line:*RawCap* OR process.command_line:*Wireshark… | 2 | F07 |
| q-5b30f01ff8 | triage T1040 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*pktmon* OR process.command_line:*dumpcap* OR process.command_line:*windump* OR process.command_line:*RawCap* OR process.command_line:*netsh*cap*)", "time_from": null, "time_to": nu… | 1 |  |
| q-88ee48b9ed | triage T1040 step 2 | search | {"dataset": "windows.sysmon", "query": "process.executable:*NetworkWatcherAgent* OR process.command_line:*NetworkWatcher*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "process.executable", "process.command_line", "wi… | 73 |  |
| q-2fb34d86ce | triage T1040 step 2 | aggregate | {"dataset": "windows.sysmon", "field": "win.ImageLoaded", "query": "event.code:7 AND (win.ImageLoaded:*pcap* OR win.ImageLoaded:*npf* OR win.ImageLoaded:*Packet* OR win.ImageLoaded:*ndis* OR win.ImageLoaded:*netmon*)", "time_from": null, "time_to": null, "size… | 2 |  |
| q-3f0601edee | triage T1040 step 3 | search | {"dataset": "windows.sysmon", "query": "event.code:7 AND win.ImageLoaded:*hnetmon*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "process.executable", "win.ImageLoaded", "win.Signed", "win.Signature", "win.SignatureSt… | 2 | F07 |
| q-2b235b96ea | triage T1040 step 3 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND process.executable:*NetworkWatcherAgent*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "process.executable", "process.command_line", "win.Signed", "win.Signatur… | 4 | F07 |
| q-c3e94dc047 | triage T1040 step 4 | search | {"dataset": "windows.sysmon", "query": "process.executable:*javamtsup* OR file.path:*javamtsup* OR win.TargetFilename:*javamtsup*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "process.executable", "process.command_li… | 14 |  |
| q-35bbdc4c17 | triage T1040 step 4 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1", "time_from": null, "time_to": null, "size": 60, "sub_field": null} | 447 |  |
| q-66a1c57682 | triage T1040 step 5 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.executable:*logman.exe OR process.executable:*python.exe OR process.executable:*PsExec64.exe)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "process.ex… | 16 | F07 |
| q-d65a0ae3c2 | triage T1040 step 5 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*logman* OR process.command_line:*pktmon* OR process.command_line:*NetworkWatcher* OR process.command_line:*trace*)", "time_from": null, "time_to": null, "fields": ["@timestamp… | 14 | F07 |
| q-58e7607975 | triage T1040 step 6 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cla5Dm"} | None | F07 |
| q-dc53890b2a | triage T1040 step 6 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND process.executable:*python.exe", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "process.executable", "process.command_line", "win.ParentCommandLine", "win.Hashes"… | 5 | F07 |
| q-6b50da3dc0 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cla5Dm"} | None |  |
| q-fa89de8987 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cla5Dm"} | None |  |
| q-b4afc43196 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nSl9D4"} | None |  |
| q-c97297a01c | triage T1040 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nOhte9"} | None |  |
| q-846c5a185d | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cUGpQW"} | None |  |
| q-2c52adb2c3 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cUGpQW"} | None |  |
| q-86dce53995 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hy1Evq"} | None |  |
| q-88071492a0 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cdRgzF"} | None |  |
| q-a99cc6d959 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cxoQzx"} | None |  |
| q-8b8c151529 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c82OhP"} | None |  |
| q-7af04f8269 | triage T1056 step 1 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhH"} | None | F08 |
| q-697f9456f5 | triage T1056 step 1 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cyrL8F"} | None | F10 |
| q-d95ffb3692 | triage T1056 step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 10 AND win.TargetImage LIKE \"*lsass*\" AND (win.GrantedAccess == \"0x1fffff\" OR win.GrantedAccess == \"0x101001\" OR win.GrantedAccess == \"0x1f3fff\" OR win.GrantedAcces… | ERROR |  |
| q-0f5e1a8012 | triage T1056 step 1 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == 4104 AND (win.ScriptBlockText LIKE \"*lsass*\" OR win.ScriptBlockText LIKE \"*MiniDump*\" OR win.ScriptBlockText LIKE \"*Credential*\" OR win.ScriptBlockText LIKE \"*ke… | ERROR |  |
| q-9153c740b0 | triage T1056 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND win.TargetImage LIKE \"*lsass*\" AND (win.GrantedAccess == \"0x1fffff\" OR win.GrantedAccess == \"0x101001\" OR win.GrantedAccess == \"0x1f3fff\" OR win.GrantedA… | 9 | F09, F10 |
| q-b99158cc4f | triage T1056 step 2 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (win.ScriptBlockText LIKE \"*lsass*\" OR win.ScriptBlockText LIKE \"*MiniDump*\" OR win.ScriptBlockText LIKE \"*Credential*\" OR win.ScriptBlockText LIKE \… | 3 |  |
| q-1dbf4fa7ff | triage T1056 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None | F08 |
| q-ebdb7f354c | triage T1056 step 3 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None | F12, F13 |
| q-47f2093d6f | triage T1056 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (process.command_line LIKE \"*lsass*\" OR process.command_line LIKE \"*MiniDump*\" OR process.command_line LIKE \"*comsvcs*\" OR process.command_line LIKE \"*proc… | 8 | F13 |
| q-594892f658 | triage T1056 step 3 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4656\" AND win.ObjectName LIKE \"*lsass*\" \| KEEP @timestamp, host.name, user.name, win.ProcessName, win.ObjectName, win.AccessMask, win.AccessList, _id, _index"} | 13 | F08, F09, F10 |
| q-a170136fdf | triage T1056 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND host.name == \"scranton.dmevals.local\" AND process.executable LIKE \"*powershell*\" \| KEEP @timestamp, host.name, user.name, process.executable, process.command… | 11 | F12 |
| q-28cd6ddcb0 | triage T1056 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND host.name == \"nashua.dmevals.local\" AND (process.executable LIKE \"*wsmprovhost*\" OR process.parent.executable LIKE \"*wsmprovhost*\" OR process.executable LIK… | 2 | F09 |
| q-7146dc6d8b | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-8e2b8c2fa6 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-193123d5be | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhH"} | None |  |
| q-d2569004a2 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhH"} | None |  |
| q-65f7ace6ca | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhH"} | None |  |
| q-209a87ff07 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq7mb8"} | None |  |
| q-422bfc5dc0 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq7mb8"} | None |  |
| q-204ef534c3 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7njy6Co"} | None |  |
| q-20eb89818b | triage T1056 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7njy6Co"} | None |  |
| q-3310355ecf | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None |  |
| q-5b05bc21ae | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c-4cYK"} | None |  |
| q-68a0221065 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nSlNDC"} | None |  |
| q-a3fcd17698 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nKhItU"} | None |  |
| q-9e7ef84646 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cyrL8F"} | None |  |
| q-32974f57e3 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cpgKyV"} | None |  |
| q-0c4e82183b | triage T1056 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuDg"} | None |  |
| q-7f61ab4a73 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuCk"} | None |  |
| q-3dc63f02aa | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRfJfH5wFd7b8wDMC"} | None |  |
| q-2f89a22faa | triage T1056 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None |  |
| q-a8745b8ed0 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None |  |
| q-b948114723 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c93Nx4"} | None |  |
| q-e7ec537e38 | triage T1110 step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 10 AND (TO_LOWER(win.TargetImage) LIKE \"*lsass*\" OR TO_LOWER(win.TargetImage) LIKE \"*sam*\") \| STATS c = COUNT(*) BY win.GrantedAccess, process.executable, host.name, u… | ERROR |  |
| q-430d034f49 | triage T1110 step 1 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (4656, 4663, 4670) AND (win.ObjectName LIKE \"*SAM*\" OR win.ObjectName LIKE \"*lsass*\" OR win.ObjectName LIKE \"*SECURITY*\") \| KEEP @timestamp, host.name, event.code,… | ERROR |  |
| q-74b3b23432 | triage T1110 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND (TO_LOWER(win.TargetImage) LIKE \"*lsass*\" OR TO_LOWER(win.TargetImage) LIKE \"*sam*\") \| STATS c = COUNT(*) BY win.GrantedAccess, process.executable, host.nam… | 18 |  |
| q-61e94599d2 | triage T1110 step 2 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4656\", \"4663\", \"4670\") AND (win.ObjectName LIKE \"*SAM*\" OR win.ObjectName LIKE \"*lsass*\" OR win.ObjectName LIKE \"*SECURITY*\") \| KEEP @timestamp, host.name,… | 29 | F16 |
| q-2a219e974b | triage T1110 step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*lsass*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*mimikatz*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*minidump*\" O… | 18 | F14 |
| q-d2f6b4db8d | triage T1110 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*lsass*\" OR TO_LOWER(process.command_line) LIKE \"*mimikatz*\" OR TO_LOWER(process.command_line) LIKE \"*dump*\" OR TO_LOW… | 1 | F16 |
| q-e71a8fe026 | triage T1110 step 4 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None |  |
| q-dfa64d9d2b | triage T1110 step 4 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qqQ-d4"} | None | F17 |
| q-c7d35e430d | triage T1110 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND host.name == \"scranton.dmevals.local\" \| KEEP @timestamp, user.name, process.executable, process.command_line, process.parent.executable, _id, _index \| SORT @t… | 359 | F15 |
| q-63f97fc222 | triage T1110 step 5 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4624\" AND win.TargetUserName == \"pbeesly\" \| KEEP @timestamp, host.name, win.LogonType, win.TargetUserName, win.IpAddress, win.Workstation, win.LogonProcessName, win… | 30 | F17 |
| q-bb65d9e37b | triage T1110 step 6 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNur"} | None | F17 |
| q-acf95ae9e2 | triage T1110 step 6 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7ryFh2_"} | None | F16 |
| q-2d016c414e | triage T1110 step 7 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4672\" AND win.SubjectUserName == \"pbeesly\" \| KEEP @timestamp, host.name, win.SubjectUserName, win.PrivilegeList, _id, _index \| SORT @timestamp ASC"} | 19 |  |
| q-6faee2b80d | triage T1110 step 7 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None | F14, F18 |
| q-51a6e89a9e | triage T1110 step 8 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq7mb8"} | None | F16 |
| q-1dd5a7a77a | triage T1110 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None |  |
| q-425d940e03 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None |  |
| q-39d5cd7dd2 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7htwOyZ"} | None |  |
| q-38f9768e2b | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq7mb8"} | None |  |
| q-3df7e4ee1a | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq7mb8"} | None |  |
| q-284df2bdff | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7njy6Co"} | None |  |
| q-8a481ac19c | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7ryFh2_"} | None |  |
| q-1dccea78dd | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7ryFh2_"} | None |  |
| q-0891f95879 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cxqOgJ"} | None |  |
| q-57a2f7ede3 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNur"} | None |  |
| q-d77740a4a7 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNur"} | None |  |
| q-9c642e5573 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qqQ-d4"} | None |  |
| q-cb90a5a2b8 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niytuv"} | None |  |
| q-c1fadd5437 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qwUVtv"} | None |  |
| q-921a4bd171 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None |  |
| q-0b4aab38c9 | triage T1111 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None | F19 |
| q-d1dcf615ac | triage T1111 step 1 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nKg4v1"} | None |  |
| q-9a7db5c10a | triage T1111 step 1 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10 AND (win.GrantedAccess:0x1010 OR win.GrantedAccess:0x1410 OR win.GrantedAccess:0x1fffff OR win.GrantedAccess:0x101000 OR win.GrantedAccess:0x101001 OR win.GrantedAccess:0x1f3fff)… | 1852 |  |
| q-5e8bdefa4f | triage T1111 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "process.executable", "win.TargetImage", "win.GrantedAccess", "win.CallTrace", "user.name"], "size": 3… | 326 |  |
| q-e726cf8254 | triage T1111 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 1 AND (TO_LOWER(process.command_line) LIKE \"*mfa*\" OR TO_LOWER(process.command_line) LIKE \"*token*\" OR TO_LOWER(process.command_line) LIKE \"*credential*\" OR TO_LOWER(… | ERROR |  |
| q-21f3e3a4cd | triage T1111 step 3 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND NOT win.GrantedAccess:0x1000", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "process.executable", "win.TargetImage", "win.GrantedAccess", "win.Ca… | 33 | F19 |
| q-37aa3261cb | triage T1111 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*mfa*\" OR TO_LOWER(process.command_line) LIKE \"*token*\" OR TO_LOWER(process.command_line) LIKE \"*credential*\" OR TO_LO… | 3 |  |
| q-a03fc337e3 | triage T1111 step 4 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None | F19 |
| q-92ca52ebd1 | triage T1111 step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND host.name == \"scranton.dmevals.local\" AND @timestamp >= \"2020-05-02T03:00:00.000Z\" AND @timestamp <= \"2020-05-02T03:10:00.000Z\" \| KEEP @timestamp, h… | 20 |  |
| q-084a247697 | triage T1111 step 5 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*.pfx*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*certutil*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*certificate*\"… | 4 | F19 |
| q-43d4f7fc4e | triage T1111 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*.pfx*\" OR TO_LOWER(file.path) LIKE \"*.p12*\" OR TO_LOWER(file.path) LIKE \"*office*\" OR TO_LOWER(file.path) LIKE \"*.7z*\") \| KE… | 4 | F19 |
| q-81a6837e8c | triage T1111 step 6 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None | F19 |
| q-d5be74dd68 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None |  |
| q-cff2fa8f67 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None |  |
| q-13c6cf78b8 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQRgs"} | None |  |
| q-ebe8ea1bd7 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-d5a2ff8501 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-55d9181561 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None |  |
| q-7584132a6d | triage T1111 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None |  |
| q-4a01a192de | triage T1111 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c_44mH"} | None |  |
| q-2c91f5ee46 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qrRC9i"} | None |  |
| q-6c82e6ae24 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuCk"} | None |  |
| q-dec4f4e06e | triage T1187 step 1 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"http\" AND (http.request.method == \"PROPFIND\" OR http.request.method == \"OPTIONS\" OR http.request.method == \"MOVE\") \| KEEP @timestamp, observer.name, source.ip, destinatio… | 36 | F20 |
| q-ed870a47a7 | triage T1187 step 1 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == 5140 OR event.code == 5145 \| KEEP @timestamp, host.name, event.code, win.ShareName, win.ObjectName, win.SubjectUserName, win.IpAddress, win.RelativeTargetName, _id, _ind… | ERROR |  |
| q-7c8ec3ff97 | triage T1187 step 2 | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_Zlb7"} | None | F20 |
| q-2c664618f2 | triage T1187 step 2 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"5140\" OR event.code == \"5145\" \| KEEP @timestamp, host.name, event.code, win.ShareName, win.ObjectName, win.SubjectUserName, win.IpAddress, win.RelativeTargetName, _… | 60 | F22 |
| q-08be945036 | triage T1187 step 3 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE (event.action == \"conn\" AND (destination.ip == \"192.168.0.4\" OR source.ip == \"192.168.0.4\")) OR event.action == \"notice\" OR (event.action == \"smb_files\") \| KEEP @timestamp, event.action… | 60 | F20, F21 |
| q-b74ff903d5 | triage T1187 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE process.executable LIKE \"*python*\" OR process.command_line LIKE \"*python*\" OR win.TargetFilename LIKE \"*python.exe*\" \| KEEP @timestamp, host.name, event.code, user.name, process.e… | 40 | F21 |
| q-54e0c118a4 | triage T1187 step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (win.ScriptBlockText LIKE \"*webdav*\" OR win.ScriptBlockText LIKE \"*192.168*\" OR win.ScriptBlockText LIKE \"*DavClnt*\" OR win.ScriptBlockText LIKE \"*\… | 17 |  |
| q-3632641104 | triage T1187 step 4 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"dns\" AND (dns.question.name LIKE \"*192.168*\" OR zeek.answers LIKE \"*192.168.0.4*\") \| KEEP @timestamp, observer.name, source.ip, dns.question.name, zeek.answers, _id, _index… | 0 |  |
| q-550b359ef5 | triage T1187 step 5 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None | F20 |
| q-968fff74b7 | triage T1187 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE destination.ip LIKE \"192.168.0.*\" OR source.ip LIKE \"192.168.0.*\" \| KEEP @timestamp, host.name, event.code, user.name, process.executable, source.ip, destination.ip, destination.por… | ERROR |  |
| q-821bc80951 | triage T1187 step 6 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE TO_STRING(destination.ip) LIKE \"192.168.0.*\" OR TO_STRING(source.ip) LIKE \"192.168.0.*\" \| KEEP @timestamp, host.name, event.code, user.name, process.executable, source.ip, destinati… | 30 | F20, F21 |
| q-c826cb2703 | triage T1187 step 6 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4624\" AND (win.AuthenticationPackageName == \"NTLM\" OR win.TargetUserName == \"cozy\") \| KEEP @timestamp, host.name, event.code, win.TargetUserName, win.Authenticati… | 1 |  |
| q-76187ef5f0 | triage T1187 step 7 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c-48Ye"} | None | F20 |
| q-c29e3937d2 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None |  |
| q-c7d120e17d | triage T1187 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None |  |
| q-c07f865fdd | triage T1187 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c-48Ye"} | None |  |
| q-9628096121 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c-48Ye"} | None |  |
| q-7fc21114b8 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c-4sYX"} | None |  |
| q-5911fb8aab | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_Z1YZ"} | None |  |
| q-14c03b8b52 | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_Zlb7"} | None |  |
| q-b6bba83c81 | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_Zlb7"} | None |  |
| q-11d8c30c7e | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_Z1a3"} | None |  |
| q-5461cc6e26 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c5ylrT"} | None |  |
| q-885e5e25f5 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c5ylrT"} | None |  |
| q-bf638c1778 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c82-ha"} | None |  |
| q-54b64821ea | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7qUct2z"} | None |  |
| q-321c9f2584 | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7qVdaEh"} | None |  |
| q-2501479814 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7ns-Aqw"} | None |  |
| q-e30d6079b2 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq72Zu"} | None |  |
| q-c8932d639c | triage T1187 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niytut"} | None |  |
| q-0adda3e575 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hWVykL"} | None |  |
| q-7c4930a41e | triage T1187 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuDM"} | None |  |
| q-f4c6668d86 | triage T1212 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND (win.GrantedAccess:0x1fffff OR win.GrantedAccess:0x101001 OR win.GrantedAccess:0x1f3fff OR win.GrantedAccess:0x1000000 OR win.GrantedAccess:0x3000 OR win.GrantedAccess:0x1400… | 33 | F23, F25 |
| q-c7a15f0f16 | triage T1212 step 1 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND win.TargetImage:*lsass* AND (win.GrantedAccess:0x1fffff OR win.GrantedAccess:0x101001 OR win.GrantedAccess:0x1f3fff OR win.GrantedAccess:0x1000000 OR win.GrantedAccess:0x3… | 9 |  |
| q-d185526e72 | triage T1212 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None | F23 |
| q-734722cc87 | triage T1212 step 2 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*MiniDump* OR win.ScriptBlockText:*Dump* OR win.ScriptBlockText:*Credential* OR win.ScriptBlockText:*Get-Process* OR win.ScriptBlockText:*OpenPr… | 8 | F24 |
| q-e743c69733 | triage T1212 step 3 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*lsass* OR process.command_line:*MiniDump* OR process.command_line:*dump* OR process.command_line:*sekurlsa* OR process.command_line:*procdump* OR process.command_line:*comsvcs* OR … | 1 |  |
| q-8c526691bf | triage T1212 step 3 | search | {"dataset": "windows.security", "query": "event.code:4624 AND win.LogonType:9", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "user.name", "win.TargetUserName", "win.LogonType", "win.IpAddress", "win.ProcessName", "win… | 0 |  |
| q-e0fba41263 | triage T1212 step 4 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND host.name:scranton.dmevals.local AND (process.executable:*powershell* OR process.executable:*wsmprovhost* OR process.executable:*psexec* OR process.executable:*python*)", "time_from": null, "time_to": nu… | 11 | F23 |
| q-6d83d54d86 | triage T1212 step 4 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None | F24 |
| q-a090739d4a | triage T1212 step 5 | search | {"dataset": "windows.powershell", "query": "host.name:scranton.dmevals.local AND @timestamp:[2020-05-02T03:04:00.000Z TO 2020-05-02T03:07:30.000Z]", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "event.code", "process.p… | 1815 |  |
| q-58bb9c5704 | triage T1212 step 5 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (win.TargetFilename:*.dmp OR win.TargetFilename:*.pfx OR win.TargetFilename:*lsass* OR win.TargetFilename:*.7z)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", … | 6 | F23 |
| q-f0a60297d4 | triage T1212 step 6 | search | {"dataset": "windows.powershell", "query": "host.name:scranton.dmevals.local AND process.pid:2976 AND event.code:4104", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "event.code", "process.pid", "process.command_line", … | 3 | F23 |
| q-d0925890cd | triage T1212 step 6 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND process.executable:*WerFault*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "process.executable", "process.command_line", "process.parent.executable", "user.na… | 4 |  |
| q-7b80f21da3 | triage T1212 step 7 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7q0Yv7J"} | None |  |
| q-f071daea86 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-45db263020 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-855fcda86b | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-2dd81c93bd | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhG"} | None |  |
| q-32c8e423f5 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7q0Yv7J"} | None |  |
| q-7c891edf8a | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7htwOyZ"} | None |  |
| q-bfac5c08f7 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQRgs"} | None |  |
| q-c828f8f411 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None |  |
| q-9b21572bdb | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None |  |
| q-073fd057c5 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qrRapX"} | None |  |
| q-88c05ad6df | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cyrL9g"} | None |  |
| q-0a525bc57f | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cUGJOD"} | None |  |
| q-1a83bc7b7f | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cpgKyU"} | None |  |
| q-d5f60b2ab5 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuBw"} | None |  |
| q-8df5a6e852 | triage T1212 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_Z1bK"} | None |  |
| q-cf45294542 | triage T1539 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None | F26 |
| q-c9c4104b15 | triage T1539 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSyvc"} | None | F26 |
| q-177065e74c | triage T1539 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(win.TargetFilename) LIKE \"*cookies*\" OR TO_LOWER(win.TargetFilename) LIKE \"*login data*\" OR TO_LOWER(win.TargetFilename) LIKE \"*web data*\" OR TO_… | 1 | F26 |
| q-25adbd1c5e | triage T1539 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*cookies*\" OR TO_LOWER(process.command_line) LIKE \"*login data*\" OR TO_LOWER(process.command_line) LIKE \"*local state*\… | 3 |  |
| q-d9371a2452 | triage T1539 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND TO_LOWER(win.TargetFilename) LIKE \"*microsoftedge*\" \| KEEP @timestamp, host.name, user.name, process.executable, win.TargetFilename, _id, _index \| SORT @time… | 4 | F26 |
| q-3994886c90 | triage T1539 step 3 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4663\" AND (TO_LOWER(win.ObjectName) LIKE \"*cookies*\" OR TO_LOWER(win.ObjectName) LIKE \"*login data*\" OR TO_LOWER(win.ObjectName) LIKE \"*microsoftedge*\" OR TO_LOW… | 0 |  |
| q-c078efc92b | triage T1539 step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*cookie*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*credential*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*password*\… | 11 |  |
| q-bcf1f4d57e | triage T1539 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(win.TargetFilename) LIKE \"*.7z\" OR TO_LOWER(win.TargetFilename) LIKE \"*officesupplies*\" OR TO_LOWER(win.TargetFilename) LIKE \"*.zip\" OR TO_LOWER(… | ERROR |  |
| q-b07ae28dc9 | triage T1539 step 5 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7q0ZP57"} | None | F26 |
| q-b68e97ec75 | triage T1539 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(win.TargetFilename) LIKE \"*.7z\" OR TO_LOWER(win.TargetFilename) LIKE \"*officesupplies*\" OR TO_LOWER(win.TargetFilename) LIKE \"*.zip\" OR TO_LOWER(… | 320 | F26 |
| q-7400ac2317 | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7YE4VZs"} | None |  |
| q-37a7b2398f | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cPCBow"} | None |  |
| q-8a60fe4e61 | triage T1539 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7q0ZP57"} | None |  |
| q-0571a0a4e7 | triage T1539 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None |  |
| q-7e71d32481 | triage T1539 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSyvc"} | None |  |
| q-fd5c4ddb6a | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hwzKeY"} | None |  |
| q-9693ecab6d | triage T1552 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None | F27 |
| q-f753b2fe94 | triage T1552 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSytV"} | None | F28 |
| q-ca996278b6 | triage T1552 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND TO_LOWER(win.TargetFilename) LIKE \"*.pfx\" \| KEEP @timestamp, host.name, user.name, process.executable, win.TargetFilename, _id, _index"} | 1 |  |
| q-34eeb964e8 | triage T1552 step 2 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*export-pfxcertificate*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*cpassword*\" OR TO_LOWER(win.ScriptBlockText) LIKE… | 3 |  |
| q-4b3f3c75ff | triage T1552 step 3 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None | F27, F28 |
| q-2bfafa8670 | triage T1552 step 3 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvTSsN"} | None | F27 |
| q-14e220219f | triage T1552 step 4 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"5145\" AND (TO_LOWER(win.RelativeTargetName) LIKE \"*groups.xml*\" OR TO_LOWER(win.ShareName) LIKE \"*sysvol*\" OR TO_LOWER(win.RelativeTargetName) LIKE \"*gpttmpl*\" O… | 56 | F31 |
| q-bcc11603b1 | triage T1552 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*unattend*\" OR TO_LOWER(process.command_line) LIKE \"*sysvol*\" OR TO_LOWER(process.command_line) LIKE \"*groups.xml*\" OR… | 0 |  |
| q-2ab888093b | triage T1552 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND process.executable LIKE \"*logman.exe\" \| KEEP @timestamp, host.name, user.name, process.executable, process.command_line, process.parent.executable, _id, _index… | 7 | F30 |
| q-8146ff28ab | triage T1552 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"13\" AND (TO_LOWER(registry.path) LIKE \"*winlogon*\" OR TO_LOWER(registry.path) LIKE \"*autologon*\" OR TO_LOWER(registry.path) LIKE \"*defaultpassword*\" OR TO_LOWER(re… | 13 | F29 |
| q-a74ae07c1d | triage T1552 step 6 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQRgs"} | None | F27 |
| q-1c6b7d585d | triage T1552 step 6 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(win.TargetFilename) LIKE \"*.7z\" OR TO_LOWER(win.TargetFilename) LIKE \"*officesupplies*\" OR TO_LOWER(win.TargetFilename) LIKE \"*\\\\downloads\\\\*\… | ERROR |  |
| q-d35d0c2dc3 | triage T1552 step 7 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(win.TargetFilename) LIKE \"*.7z\" OR TO_LOWER(win.TargetFilename) LIKE \"*officesupplies*\" OR TO_LOWER(win.TargetFilename) LIKE \"*downloads*\") \| KE… | 317 | F27, F28 |
| q-51b6668f62 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None |  |
| q-3c2fbec3d4 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None |  |
| q-651ee8eae1 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None |  |
| q-b573359893 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvTSsN"} | None |  |
| q-659343a5ef | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQRgs"} | None |  |
| q-2758575271 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQRgs"} | None |  |
| q-23ba9e5d02 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None |  |
| q-96e4526b8d | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c_44mH"} | None |  |
| q-1ba7297975 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None |  |
| q-63297cad8a | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSytV"} | None |  |
| q-9ee20fc84d | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7habqSt"} | None |  |
| q-8e963d4938 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qwUVtv"} | None |  |
| q-d5e0c37b34 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7YK95pg"} | None |  |
| q-4d361cff6d | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cTFiiN"} | None |  |
| q-0146ced97c | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cfUP4A"} | None |  |
| q-8452541045 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cfUP4A"} | None |  |
| q-c8a3b47705 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7ncs5oy"} | None |  |
| q-e3969d72b8 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7ncs5oy"} | None |  |
| q-6e086326a4 | triage T1552 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7qUcN0h"} | None |  |
| q-69e5a74c86 | triage T1555 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND (win.GrantedAccess:0x1fffff OR win.GrantedAccess:0x101001 OR win.GrantedAccess:0x1f3fff OR win.GrantedAccess:0x1000000 OR win.GrantedAccess:0x3000)", "time_from": null, "time… | 9 | F32 |
| q-3a2386ac22 | triage T1555 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None |  |
| q-1184f991f9 | triage T1555 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND (process.executable:*PowerShell.exe OR process.executable:*powershell.exe OR process.executable:*wsmprovhost.exe)", "time_from": null, "time_to": null, "fields": ["@timestamp… | 5 |  |
| q-78f93addcb | triage T1555 step 2 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == 4104 AND (TO_LOWER(win.ScriptBlockText) LIKE \"*minidump*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*sekurlsa*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*lsass*\" OR TO… | ERROR |  |
| q-4d19df0e8b | triage T1555 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None | F32 |
| q-599ccd4e35 | triage T1555 step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*minidump*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*sekurlsa*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*lsass*\" O… | 5 |  |
| q-fc53c64549 | triage T1555 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND host.name == \"scranton.dmevals.local\" \| KEEP @timestamp, host.name, user.name, process.executable, process.command_line, process.parent.executable, win.Process… | 359 | F32 |
| q-c8a8c41a8e | triage T1555 step 4 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4656\" AND (TO_LOWER(win.ObjectName) LIKE \"*lsass*\" OR TO_LOWER(win.ObjectName) LIKE \"*sam*\" OR TO_LOWER(win.ObjectName) LIKE \"*security*\" OR TO_LOWER(win.ObjectN… | 32 | F32 |
| q-1c7e9f2bb1 | triage T1555 step 5 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7htwOyZ"} | None | F32 |
| q-73e14056fb | triage T1555 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND host.name == \"nashua.dmevals.local\" \| KEEP @timestamp, host.name, user.name, process.executable, process.command_line, process.parent.executable, win.ProcessId… | 61 | F35 |
| q-0544c08b83 | triage T1555 step 6 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None |  |
| q-b061d163b8 | triage T1555 step 6 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE (event.code == \"11\" OR event.code == \"15\" OR event.code == \"23\") AND (TO_LOWER(file.path) LIKE \"*login data*\" OR TO_LOWER(file.path) LIKE \"*logins.json*\" OR TO_LOWER(file.path)… | 9 | F34 |
| q-521499666e | triage T1555 step 7 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE (TO_LOWER(file.path) LIKE \"*\\\\vault\\\\*\" OR TO_LOWER(file.path) LIKE \"*\\\\credentials\\\\*\" OR TO_LOWER(file.path) LIKE \"*protect\\\\*\") \| KEEP @timestamp, host.name, user.nam… | ERROR |  |
| q-8c8de46092 | triage T1555 step 7 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4663\" AND (TO_LOWER(win.ObjectName) LIKE \"*vault*\" OR TO_LOWER(win.ObjectName) LIKE \"*credential*\" OR TO_LOWER(win.ObjectName) LIKE \"*protect*\" OR TO_LOWER(win.O… | 0 |  |
| q-a0a73ed81f | triage T1555 step 8 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE TO_LOWER(file.path) LIKE \"*vault*\" OR TO_LOWER(file.path) LIKE \"*credentials*\" OR TO_LOWER(file.path) LIKE \"*protect*\" \| KEEP @timestamp, host.name, user.name, event.code, file.pa… | 29 | F33 |
| q-9b7f121a01 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7htwOyZ"} | None |  |
| q-a9132b5032 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-7a8632cc7f | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-6908f5c4c2 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhG"} | None |  |
| q-6050741e3c | triage T1555 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq7mb8"} | None |  |
| q-332d8eb15a | triage T1555 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq7mb8"} | None |  |
| q-9570ab4bdf | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hy0krT"} | None |  |
| q-42ccd74358 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRfJfH5wFd7b6t2mM"} | None |  |
| q-ce45857543 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRfJfH5wFd7b6t2mM"} | None |  |
| q-d6dea37edf | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7YK9pro"} | None |  |
| q-7467de982f | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRfJfH5wFd7b_yhXF"} | None |  |
| q-071a40a77f | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7YE4VZs"} | None |  |
| q-d19ce05eb7 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7crhjub"} | None |  |
| q-6539ebf81c | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c4xY6Y"} | None |  |
| q-2c5c25190b | triage T1556 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND (process.executable:*PowerShell* OR process.executable:*wsmprovhost* OR process.executable:*wininit* OR process.executable:*csrss* OR process.executable:*services*)", "time_f… | 9 |  |
| q-37a4359874 | triage T1556 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND (win.GrantedAccess:0x1fffff OR win.GrantedAccess:0x101001 OR win.GrantedAccess:0x1f3fff OR win.GrantedAccess:0x1000000 OR win.GrantedAccess:0x3000 OR win.GrantedAccess:0x1400… | 33 | F36, F41 |
| q-6eb3e32472 | triage T1556 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-95a569b33e | triage T1556 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None |  |
| q-8670030bf3 | triage T1556 step 2 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND @timestamp >= \"2020-05-02T03:00:00.000Z\" AND @timestamp <= \"2020-05-02T03:12:00.000Z\" \| KEEP @timestamp, host.name, user.name, win.ScriptBlockId, win.… | 50 | F36 |
| q-7dd781956c | triage T1556 step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*mimikatz*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*invoke-mimi*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*lsass*\… | 6 | F39 |
| q-552998e8e8 | triage T1556 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*lsass*\" OR TO_LOWER(process.command_line) LIKE \"*procdump*\" OR TO_LOWER(process.command_line) LIKE \"*mimikatz*\" OR TO… | 1 | F37 |
| q-4cd76563b7 | triage T1556 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (process.pid == 2976 OR process.parent.pid == 2976 OR TO_LOWER(process.command_line) LIKE \"*invoke-seaduke*\" OR TO_LOWER(process.command_line) LIKE \"*psexec*\"… | 14 |  |
| q-4c2cfc1769 | triage T1556 step 4 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4673\",\"4674\",\"4703\",\"4670\",\"4945\",\"5447\",\"5441\",\"5446\") AND (TO_LOWER(win.ObjectName) LIKE \"*lsa*\" OR TO_LOWER(win.ObjectName) LIKE \"*securityprovide… | 40 | F42 |
| q-64f2e9a4aa | triage T1556 step 5 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7htwOyZ"} | None | F36 |
| q-aa2529c79d | triage T1556 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"13\" AND (TO_LOWER(registry.path) LIKE \"*notification packages*\" OR TO_LOWER(registry.path) LIKE \"*lsa*\" OR TO_LOWER(registry.path) LIKE \"*networkprovider*\" OR TO_L… | 40 | F38 |
| q-0f4118591a | triage T1556 step 6 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4648\" \| KEEP @timestamp, host.name, user.name, win.TargetUserName, win.TargetServerName, win.ProcessName, win.SubjectUserName, _id, _index \| LIMIT 20"} | 15 | F40 |
| q-7271bed453 | triage T1556 step 6 | esql | {"query": "FROM logs-windows.other-default METADATA _id, _index \| WHERE event.code == \"7045\" \| KEEP @timestamp, host.name, win.ServiceName, win.ImagePath, win.ServiceType, win.StartType, _id, _index \| LIMIT 20"} | 5 | F37 |
| q-d57cb3f95c | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-c5285ac6d6 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-55171f712a | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7htwOyZ"} | None |  |
| q-59d78acf84 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7htwOyZ"} | None |  |
| q-22348fc40b | triage T1556 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qrRFHq"} | None |  |
| q-8768e642ed | triage T1556 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qqQ-d4"} | None |  |
| q-1be29a2d52 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cxqOgJ"} | None |  |
| q-c3c6acacbd | triage T1556 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuDx"} | None |  |
| q-f30258dd03 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuDg"} | None |  |
| q-47c91c01b2 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cpgKyZ"} | None |  |
| q-8f547ee06c | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cpgKxG"} | None |  |
| q-2600b383d3 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qyVUi_"} | None |  |
| q-387664eec9 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nixwZC"} | None |  |
| q-a97f992498 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nixwZC"} | None |  |
| q-7c7275ca2d | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cUGJOD"} | None |  |
| q-3efca3cdf7 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nKgYvV"} | None |  |
| q-4981f9a5cb | triage T1557 step 1 | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7qUcN2T"} | None | F44 |
| q-c9c4af85c7 | triage T1557 step 1 | search | {"dataset": "zeek", "query": "event.action:smb_files OR event.action:smb_mapping", "time_from": null, "time_to": null, "fields": ["@timestamp", "source.ip", "destination.ip", "zeek.path", "zeek.name", "zeek.filename", "zeek.action", "zeek.share_type", "zeek.se… | 23 | F44 |
| q-3c6ded3f09 | triage T1557 step 2 | search | {"dataset": "zeek", "query": "event.action:conn AND zeek.resp_l2_addr:\"12:34:56:78:9a:bc\"", "time_from": null, "time_to": null, "fields": ["@timestamp", "source.ip", "destination.ip", "destination.port", "zeek.orig_l2_addr", "zeek.resp_l2_addr", "zeek.servic… | 559 | F45 |
| q-dc15d9a137 | triage T1557 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*dhcp* OR process.command_line:*ipconfig* OR process.command_line:*netsh*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "process.executab… | 5 | F46 |
| q-ca780a18f7 | triage T1557 step 3 | search | {"dataset": "windows.security", "query": "event.code:4624 AND (win.LogonProcessName:\"NtLmSsp \" OR win.LogonType:3)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "event.code", "win.LogonProcessName", "win.LogonType",… | 218 |  |
| q-082bc8124b | triage T1557 step 3 | search | {"dataset": "windows.sysmon", "query": "event.code:3 AND (destination.ip:\"10.0.1.5\" OR destination.ip:\"10.0.1.6\" OR destination.ip:\"10.0.1.4\")", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "process.executable", … | 158 |  |
| q-4f84735745 | triage T1557 step 4 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.executable:*PSEXESVC* OR process.executable:*psexec* OR process.command_line:*psexec*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "process.executabl… | 4 |  |
| q-9074583e00 | triage T1557 step 4 | search | {"dataset": "windows.security", "query": "event.code:4697 AND win.ServiceName:PSEXESVC", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "event.code", "win.ServiceName", "win.ServiceFileName", "win.SubjectUserName", "win.… | 4 | F44 |
| q-d2d39602a0 | triage T1557 step 5 | search | {"dataset": "windows.security", "query": "event.code:4624 AND win.LogonProcessName:\"NtLmSsp \"", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "event.code", "win.LogonProcessName", "win.LogonType", "win.AuthenticationP… | 1 | F43 |
| q-01ce087eb0 | triage T1557 step 5 | aggregate | {"dataset": "windows.security", "field": "win.IpAddress", "query": "event.code:4624 AND win.LogonType:3", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 218 |  |
| q-9c588a06c7 | triage T1557 step 6 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nQi3T7"} | None |  |
| q-45ee074f44 | triage T1557 step 6 | search | {"dataset": "windows.sysmon", "query": "event.code:3 AND destination.ip:\"172.18.39.2\"", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "process.executable", "process.command_line", "destination.ip", "destination.port",… | 30 | F43 |
| q-cfcb3c08f4 | triage T1557 step 7 | search | {"dataset": "windows.sysmon", "query": "event.code:3 AND (destination.port:5355 OR destination.port:137 OR destination.port:138)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "process.executable", "process.command_lin… | 24 |  |
| q-399a083fe2 | triage T1557 step 7 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1", "time_from": null, "time_to": null, "size": 60, "sub_field": null} | 447 |  |
| q-90fd754cc0 | triage T1557 step 8 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.executable:*ARP.EXE OR process.executable:*ROUTE.EXE OR process.executable:*python.exe)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "process.executab… | 11 | F45 |
| q-32b319576a | triage T1557 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nQi3T7"} | None |  |
| q-6bb7e4c3bc | triage T1557 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nQi3T7"} | None |  |
| q-7b69d1eba7 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hy1EsU"} | None |  |
| q-2b7e813af2 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hy1EsU"} | None |  |
| q-9206d4f406 | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7qUcN2T"} | None |  |
| q-1a48f6e4d8 | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7qUcN2T"} | None |  |
| q-57ee0742f1 | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_Zlbj"} | None |  |
| q-f2c718e8d8 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNuI"} | None |  |
| q-a26b373f87 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cYMP7j"} | None |  |
| q-5dbc061b8c | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cYMP7j"} | None |  |
| q-e03f6618c4 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cYMf4P"} | None |  |
| q-b8223095f6 | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_aFZ1"} | None |  |
| q-bd6c067dc3 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cla5Dm"} | None |  |
| q-63f840e4ed | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cjZtk-"} | None |  |
| q-1d1d6dc76e | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cjZtk-"} | None |  |
| q-7dd6e5284b | triage T1558 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND (win.GrantedAccess:0x1fffff OR win.GrantedAccess:0x101001 OR win.GrantedAccess:0x1f3fff OR win.GrantedAccess:0x1000000 OR win.GrantedAccess:0x3000 OR win.GrantedAccess:0x1400… | 33 | F48 |
| q-8285d8d1f3 | triage T1558 step 1 | search | {"dataset": "windows.security", "query": "event.code:4769 OR event.code:4768", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "win.TargetUserName", "win.ServiceName", "win.TicketEncryptionType", "win.TicketOptions", "win.PreAuthType"… | 42 | F48, F49, F51 |
| q-b078007414 | triage T1558 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhG"} | None | F47 |
| q-1a8a303207 | triage T1558 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None |  |
| q-cadd8b91f9 | triage T1558 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.executable:*powershell* OR process.executable:*wsmprovhost* OR process.executable:*cmd.exe)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "process.executable", "pro… | 30 | F47 |
| q-0db7571c0f | triage T1558 step 3 | search | {"dataset": "windows.powershell", "query": "event.code:4104", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "win.ScriptBlockText", "event.code", "win.Path"], "size": 30, "sort": "asc"} | 414 |  |
| q-7510a3eb00 | triage T1558 step 3 | search | {"dataset": "windows.sysmon", "query": "process.executable:*python* OR process.parent.executable:*python* OR win.TargetFilename:*python*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "process.executable", "process.command_line", "… | 521 | F47 |
| q-32ce0573b1 | triage T1558 step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == 4104 AND (TO_LOWER(win.ScriptBlockText) LIKE \"*lsass*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*ticket*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*krb*\" OR TO_LOWER(… | ERROR |  |
| q-48b5c909b6 | triage T1558 step 4 | search | {"dataset": "windows.security", "query": "event.code:4624 AND host.name:nashua.dmevals.local", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "win.TargetUserName", "win.LogonType", "win.IpAddress", "win.Workstation", "w… | 25 | F49 |
| q-a772da6cd0 | triage T1558 step 5 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*lsass*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*ticket*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*krb*\" OR TO_LO… | 21 | F50 |
| q-2f34c2eb88 | triage T1558 step 5 | search | {"dataset": "windows.security", "query": "event.code:4769", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "win.TargetUserName", "win.ServiceName", "win.TicketEncryptionType", "win.TicketOptions", "win.IpAddress", "win.Status", "win.… | 28 | F48, F50 |
| q-1d911df3cf | triage T1558 step 6 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qqQ-d4"} | None | F47 |
| q-b33780e3c9 | triage T1558 step 6 | search | {"dataset": "windows.sysmon", "query": "host.name:nashua.dmevals.local AND (process.executable:*python* OR process.parent.executable:*python* OR process.executable:*PSEXESVC* OR process.parent.executable:*PSEXESVC* OR win.TargetImage:*lsass*)", "time_from": nu… | 737 | F47 |
| q-bfd6f60f1b | triage T1558 step 7 | search | {"dataset": "windows.security", "query": "event.code:4672 OR event.code:4648", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "win.TargetUserName", "win.SubjectUserName", "win.LogonType", "win.IpAddress", "win.ProcessNa… | 227 | F49 |
| q-97cbd4d7f3 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hy0Urg"} | None |  |
| q-2a99e5da89 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qqQ-d4"} | None |  |
| q-b64e6bc13a | triage T1558 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c82OhP"} | None |  |
| q-88f496377c | triage T1558 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c82Oiy"} | None |  |
| q-ef43a884ee | triage T1558 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhG"} | None |  |
| q-4bf62918f6 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNvO"} | None |  |
| q-90c611a0c0 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq72Yx"} | None |  |
| q-1d07fb710c | triage T1558 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cpgKyU"} | None |  |
| q-4c4d664ae4 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7njzKBN"} | None |  |
| q-ef206b5a12 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNuT"} | None |  |
| q-c5eeaf9618 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7rxFDL4"} | None |  |
| q-ecf68ab169 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq72bs"} | None |  |
| q-a69295d1b9 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysW"} | None |  |
| q-56dd630fa2 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNsI"} | None |  |
| q-01fc3759fc | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNsI"} | None |  |
| q-acb35e5a09 | triage T1606 step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 10 AND win.TargetImage LIKE \"*lsass.exe\" \| STATS c = COUNT(*) BY process.executable, host.name, win.GrantedAccess \| SORT c DESC"} | ERROR |  |
| q-31ee982830 | triage T1606 step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 10 AND win.GrantedAccess IN (\"0x1010\",\"0x1410\",\"0x1fffff\",\"0x101001\",\"0x101541\",\"0x101441\",\"0x121440\",\"0x101068\") \| KEEP @timestamp, host.name, process.exe… | ERROR |  |
| q-6057c533c8 | triage T1606 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND win.TargetImage LIKE \"*lsass.exe\" \| STATS c = COUNT(*) BY process.executable, host.name, win.GrantedAccess \| SORT c DESC"} | 18 |  |
| q-37271f5232 | triage T1606 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND win.GrantedAccess IN (\"0x1010\",\"0x1410\",\"0x1fffff\",\"0x101001\",\"0x101541\",\"0x101441\",\"0x121440\",\"0x101068\",\"0x101040\",\"0x101400\") \| KEEP @tim… | 500 | F53 |
| q-a01f6b26c4 | triage T1606 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND win.TargetImage LIKE \"*lsass.exe\" AND win.GrantedAccess != \"0x1000\" AND win.GrantedAccess != \"0x1400\" \| KEEP @timestamp, host.name, process.executable, pr… | 9 | F52 |
| q-a0504f0ae8 | triage T1606 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE process.executable LIKE \"*cod.3aka3.scr\" OR process.parent.executable LIKE \"*cod.3aka3.scr\" OR win.TargetFilename LIKE \"*cod.3aka3*\" \| KEEP @timestamp, event.code, host.name, proc… | 100 | F52 |
| q-d0b9d7beea | triage T1606 step 4 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-7dbed27484 | triage T1606 step 4 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None |  |
| q-4033b7c8d8 | triage T1606 step 5 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (win.ScriptBlockText LIKE \"*lsass*\" OR win.ScriptBlockText LIKE \"*MiniDump*\" OR win.ScriptBlockText LIKE \"*AES*\" OR win.ScriptBlockText LIKE \"*FromB… | 6 | F52 |
| q-352043db38 | triage T1606 step 5 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4688\" AND (process.command_line LIKE \"*lsass*\" OR process.command_line LIKE \"*procdump*\" OR process.command_line LIKE \"*comsvcs*\" OR process.command_line LIKE \"… | 2 | F52 |
| q-e71446795b | triage T1606 step 6 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qzW1OH"} | None |  |
| q-615ceccdc9 | triage T1606 step 6 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qzXFp5"} | None |  |
| q-0e02b29f1f | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-e7ab6d67cd | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-9eb520a8fa | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None |  |
| q-db865239fb | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None |  |
| q-b7db3c93cb | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hy0krT"} | None |  |
| q-17394a1ed3 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7ns9wrd"} | None |  |
| q-faf5f0afa9 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qzW1OH"} | None |  |
| q-fd39015815 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qzXFp5"} | None |  |
| q-f3c55589a4 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hy0krN"} | None |  |
| q-2a557674ab | triage T1606 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvTCvl"} | None |  |
| q-e8edf02804 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNur"} | None |  |
| q-0e4c74accd | triage T1606 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7ryFR3O"} | None |  |
| q-520d3e132a | triage T1649 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None | F55 |
| q-00dcaec134 | triage T1649 step 1 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7rzHZUI"} | None | F56 |
| q-f90b238a98 | triage T1649 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND win.TargetFilename:*pfx*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "process.executable", "process.command_line", "win.TargetFilename", "win.Image"], "size"… | 1 |  |
| q-664e8bad8f | triage T1649 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 1 AND (TO_LOWER(process.command_line) LIKE \"*cert*\" OR TO_LOWER(process.command_line) LIKE \"*pfx*\" OR TO_LOWER(process.command_line) LIKE \"*export*\" OR TO_LOWER(proce… | ERROR |  |
| q-c06b35fa7f | triage T1649 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*cert*\" OR TO_LOWER(process.command_line) LIKE \"*pfx*\" OR TO_LOWER(process.command_line) LIKE \"*export*\" OR TO_LOWER(p… | 13 |  |
| q-3cf3e7a07a | triage T1649 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQRgs"} | None | F55 |
| q-a1518c1673 | triage T1649 step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*cert*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*pfx*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*privatekey*\" OR TO… | 5 | F55 |
| q-e810a9828c | triage T1649 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(win.TargetFilename) LIKE \"*\\\\\\\\downloads\\\\\\\\*\" OR TO_LOWER(win.TargetFilename) LIKE \"*\\\\\\\\temp\\\\\\\\*\") \| KEEP @timestamp, host.name… | 494 |  |
| q-3d72102973 | triage T1649 step 5 | count | {"dataset": "windows.security", "query": "event.code:4657 AND win.ObjectName:*SystemCertificates*", "time_from": null, "time_to": null} | 1 |  |
| q-f9cf435350 | triage T1649 step 5 | count | {"dataset": "windows.sysmon", "query": "event.code:11 AND win.TargetFilename:*pfx*", "time_from": null, "time_to": null} | 1 |  |
| q-a0ef438a74 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None |  |
| q-76093f3ac9 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None |  |
| q-46b33bf3d0 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None |  |
| q-a209f7df50 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvTSsN"} | None |  |
| q-64f35193a3 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQRgs"} | None |  |
| q-dd98dbce19 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQRgs"} | None |  |
| q-11eb110e6b | triage T1649 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qrRC9i"} | None |  |
| q-b712e6c8d6 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7rzHZUI"} | None |  |
| q-ad1155100c | triage T1649 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7rzHZUI"} | None |  |
| q-31f36d635f | triage T1649 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7rzHZUI"} | None |  |
| q-82adfec12c | triage T1649 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7ryGB0J"} | None |  |
| q-b2fe80cd0c | triage T1649 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7ryGB0J"} | None |  |
| q-a863ce6fa4 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-b5774b502f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-f127cb763e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-84e78c66b4 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None |  |
| q-09a4698356 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None |  |
| q-31643805a8 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qrRbzS"} | None |  |
| q-476ff1d186 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qqQ-d4"} | None |  |
| q-b27d132048 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cpgKxF"} | None |  |
| q-4131685917 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cpgKxF"} | None |  |
| q-f2bb5db23a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cNAtxy"} | None |  |
| q-175ab51830 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nOhdc5"} | None |  |
| q-1858545e04 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nOhdc5"} | None |  |
| q-a8797f8f3e | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nOhdc5"} | None |  |
| q-0e365e1f36 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq8GZx"} | None |  |
| q-50e653e136 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c82OiA"} | None |  |
| q-8135fd5eaf | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c82OiA"} | None |  |
| q-1a58f28a2a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cwoB6Q"} | None |  |
| q-9312dcdcaf | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cxoQzx"} | None |  |
| q-8e7f4b11ae | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nOhdc5"} | None |  |
| q-69b3aacced | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cla5Dm"} | None |  |
| q-fed2a69194 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cla5Dm"} | None |  |
| q-d57c35c0f7 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nSl9D4"} | None |  |
| q-a092d27d43 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nOhte9"} | None |  |
| q-5af320c502 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cUGpQW"} | None |  |
| q-33328fb4b3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cUGpQW"} | None |  |
| q-e3ec337b06 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hy1Evq"} | None |  |
| q-c8388b3901 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cdRgzF"} | None |  |
| q-dc9917139c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cxoQzx"} | None |  |
| q-2253315d7f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c82OhP"} | None |  |
| q-484fcd9ff8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-e851cc1051 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-ab4d090984 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhH"} | None |  |
| q-f427d8a8a3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhH"} | None |  |
| q-7f4b1e33d1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhH"} | None |  |
| q-1bf79fa021 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq7mb8"} | None |  |
| q-c4a7655d06 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq7mb8"} | None |  |
| q-e594aa40db | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7njy6Co"} | None |  |
| q-d9f57601c7 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7njy6Co"} | None |  |
| q-6fca043de2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None |  |
| q-b6952a312b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c-4cYK"} | None |  |
| q-0569add07c | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nSlNDC"} | None |  |
| q-2e93b6d1bf | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nKhItU"} | None |  |
| q-575c6d257b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cyrL8F"} | None |  |
| q-176d2e8e22 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cpgKyV"} | None |  |
| q-3f2f9f5e0f | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuDg"} | None |  |
| q-60e7602eb4 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuCk"} | None |  |
| q-c0bbcae6b9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRfJfH5wFd7b8wDMC"} | None |  |
| q-fa7cf00416 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None |  |
| q-46db710fa4 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None |  |
| q-8a23290ead | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c93Nx4"} | None |  |
| q-52f8714fed | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None |  |
| q-135112cb6f | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None |  |
| q-6256c9d0d4 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7htwOyZ"} | None |  |
| q-4fd2b2857a | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq7mb8"} | None |  |
| q-1860765f93 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq7mb8"} | None |  |
| q-ee345fdccf | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7njy6Co"} | None |  |
| q-181305cd1a | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7ryFh2_"} | None |  |
| q-f96676734d | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7ryFh2_"} | None |  |
| q-b4175b503c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cxqOgJ"} | None |  |
| q-17bf1be136 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNur"} | None |  |
| q-be66a6206c | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNur"} | None |  |
| q-e6b4a82f29 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qqQ-d4"} | None |  |
| q-e5d19ded16 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niytuv"} | None |  |
| q-296d47880b | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qwUVtv"} | None |  |
| q-be1155261b | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None |  |
| q-8ec7b71401 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None |  |
| q-5c236592b9 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None |  |
| q-50c8707e27 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQRgs"} | None |  |
| q-b4becc7db3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-6050a8731f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-7434b62d5b | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None |  |
| q-17c0400921 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None |  |
| q-79ef192268 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c_44mH"} | None |  |
| q-855cc80e4b | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qrRC9i"} | None |  |
| q-af22203568 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuCk"} | None |  |
| q-a304ce61fe | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None |  |
| q-a2daeb1f4a | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None |  |
| q-9dec742a3f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c-48Ye"} | None |  |
| q-01646788bb | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c-48Ye"} | None |  |
| q-6c353b1dc0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c-4sYX"} | None |  |
| q-58b4a5f270 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_Z1YZ"} | None |  |
| q-afe08b5ee4 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_Zlb7"} | None |  |
| q-f0f82489cb | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_Zlb7"} | None |  |
| q-8e20616601 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_Z1a3"} | None |  |
| q-b63b55cc2c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c5ylrT"} | None |  |
| q-430af47858 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c5ylrT"} | None |  |
| q-fd6a1a17dc | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c82-ha"} | None |  |
| q-d00478c2b6 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7qUct2z"} | None |  |
| q-06ba633b71 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7qVdaEh"} | None |  |
| q-ba6884476b | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7ns-Aqw"} | None |  |
| q-3f30fa61e0 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq72Zu"} | None |  |
| q-89248cc182 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niytut"} | None |  |
| q-9dc858546b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hWVykL"} | None |  |
| q-ba68a8aff9 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuDM"} | None |  |
| q-00a13c73db | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-1785867172 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-aece3f230b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-fada1775de | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhG"} | None |  |
| q-9dab8f04f8 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7q0Yv7J"} | None |  |
| q-a4db0a0ec8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7htwOyZ"} | None |  |
| q-00ffa33a84 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQRgs"} | None |  |
| q-eac3925ffa | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None |  |
| q-95ebf22e0b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None |  |
| q-f4a2d15b35 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qrRapX"} | None |  |
| q-3f1a8a75d2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cyrL9g"} | None |  |
| q-d55ac5bdb4 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cUGJOD"} | None |  |
| q-f4d6188b3d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cpgKyU"} | None |  |
| q-443d43cac5 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuBw"} | None |  |
| q-715a8a8050 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_Z1bK"} | None |  |
| q-5de3bebee9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7YE4VZs"} | None |  |
| q-1e119b88f2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cPCBow"} | None |  |
| q-fdc4ca3a6f | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7q0ZP57"} | None |  |
| q-3a92476976 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None |  |
| q-e29ad36be3 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSyvc"} | None |  |
| q-01c499b039 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hwzKeY"} | None |  |
| q-ecd28cb878 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None |  |
| q-efe90f99c4 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None |  |
| q-9e4bec714c | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None |  |
| q-dd56d0ebf6 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvTSsN"} | None |  |
| q-670b6eae64 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQRgs"} | None |  |
| q-c2c9d81dea | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQRgs"} | None |  |
| q-983b7fe733 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None |  |
| q-229e77e6fc | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c_44mH"} | None |  |
| q-39dde66fdb | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None |  |
| q-718cedd002 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSytV"} | None |  |
| q-a3f347c653 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7habqSt"} | None |  |
| q-ba31ed25e5 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qwUVtv"} | None |  |
| q-7edfffbd66 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7YK95pg"} | None |  |
| q-ae46f14a98 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cTFiiN"} | None |  |
| q-022abbe5d5 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cfUP4A"} | None |  |
| q-51cd61f604 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cfUP4A"} | None |  |
| q-96d2ef1d79 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7ncs5oy"} | None |  |
| q-3ea316f48a | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7ncs5oy"} | None |  |
| q-2e0af0849f | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7qUcN0h"} | None |  |
| q-b28a92f89e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7htwOyZ"} | None |  |
| q-779f50815f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-84aa9ed92d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-5aa7dfc647 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhG"} | None |  |
| q-49679b27c0 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq7mb8"} | None |  |
| q-741298d678 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq7mb8"} | None |  |
| q-7b1d07bdb2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hy0krT"} | None |  |
| q-45434999bc | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRfJfH5wFd7b6t2mM"} | None |  |
| q-5076e84851 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRfJfH5wFd7b6t2mM"} | None |  |
| q-20c600685e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7YK9pro"} | None |  |
| q-0bb6420d51 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRfJfH5wFd7b_yhXF"} | None |  |
| q-930cfa7926 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7YE4VZs"} | None |  |
| q-1f42468455 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7crhjub"} | None |  |
| q-f6eb0ce16d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c4xY6Y"} | None |  |
| q-2670c099c7 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-5a1d1d7567 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-47395df11c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7htwOyZ"} | None |  |
| q-37e385a593 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7htwOyZ"} | None |  |
| q-55b95c1331 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qrRFHq"} | None |  |
| q-e33ce71e98 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qqQ-d4"} | None |  |
| q-f72c4d1a49 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cxqOgJ"} | None |  |
| q-014e85bb4a | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuDx"} | None |  |
| q-144553d86e | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuDg"} | None |  |
| q-3009aa7ad8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cpgKyZ"} | None |  |
| q-97a1fa4c5e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cpgKxG"} | None |  |
| q-861a9ad86f | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qyVUi_"} | None |  |
| q-f9660080be | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nixwZC"} | None |  |
| q-8bf985ad8a | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nixwZC"} | None |  |
| q-673d3905d0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cUGJOD"} | None |  |
| q-12945a71d4 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nKgYvV"} | None |  |
| q-3cad9320fb | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nQi3T7"} | None |  |
| q-6a357ea226 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nQi3T7"} | None |  |
| q-73b7abfa81 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hy1EsU"} | None |  |
| q-0a90b850e2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hy1EsU"} | None |  |
| q-5734c6290b | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7qUcN2T"} | None |  |
| q-d92aa25e39 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7qUcN2T"} | None |  |
| q-13a8ba342e | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_Zlbj"} | None |  |
| q-f21391181c | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNuI"} | None |  |
| q-fa4e9ba313 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cYMP7j"} | None |  |
| q-a324351051 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cYMP7j"} | None |  |
| q-7842094449 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cYMf4P"} | None |  |
| q-da665de07f | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_aFZ1"} | None |  |
| q-5d339b9266 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cla5Dm"} | None |  |
| q-42ae85d5de | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cjZtk-"} | None |  |
| q-437c7f12c3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cjZtk-"} | None |  |
| q-e5eedd4c84 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hy0Urg"} | None |  |
| q-b96cff16cc | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qqQ-d4"} | None |  |
| q-4488257ad8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c82OhP"} | None |  |
| q-e8eb08994e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c82Oiy"} | None |  |
| q-e9d75b8f49 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhG"} | None |  |
| q-ac5b9bfff0 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNvO"} | None |  |
| q-8b0c61370e | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq72Yx"} | None |  |
| q-8efa361397 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cpgKyU"} | None |  |
| q-f886b0a1ea | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7njzKBN"} | None |  |
| q-9a12dbf6eb | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNuT"} | None |  |
| q-f24a62cb51 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7rxFDL4"} | None |  |
| q-65d59f22bc | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq72bs"} | None |  |
| q-8e9dcf5045 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysW"} | None |  |
| q-d6ee73a820 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNsI"} | None |  |
| q-6191cb2092 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNsI"} | None |  |
| q-d5ad836f51 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-24fa74e573 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-48f63c886c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None |  |
| q-8b535565da | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None |  |
| q-6ca792d309 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hy0krT"} | None |  |
| q-b54cde29e2 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7ns9wrd"} | None |  |
| q-33d323c583 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qzW1OH"} | None |  |
| q-98209e808a | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qzXFp5"} | None |  |
| q-66aecf34c0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hy0krN"} | None |  |
| q-6f390c9feb | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvTCvl"} | None |  |
| q-54ee3daa7c | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNur"} | None |  |
| q-d339c8e8e2 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7ryFR3O"} | None |  |
| q-e8ccb78eb1 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None |  |
| q-fdb05c6ab8 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None |  |
| q-48396d3cb8 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None |  |
| q-90151b2604 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvTSsN"} | None |  |
| q-0cede33816 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQRgs"} | None |  |
| q-eb47e0585d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQRgs"} | None |  |
| q-d61b2844a4 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qrRC9i"} | None |  |
| q-c8153d0de3 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7rzHZUI"} | None |  |
| q-0fe9a2959a | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7rzHZUI"} | None |  |
| q-d82bd06817 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7rzHZUI"} | None |  |
| q-0ebb554d81 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7ryGB0J"} | None |  |
| q-ac7bf9a2a5 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7ryGB0J"} | None |  |
| q-866454197e | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND host.name:\"nashua.dmevals.local\"", "time_from": "2020-05-02T02:54:23.885000+00:00", "time_to": "2020-05-02T03:31:19+00:00", "size": 100, "sub_field": "process.parent.exec… | 61 |  |
| q-27acf935c5 | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11 AND host.name:\"nashua.dmevals.local\"", "time_from": "2020-05-02T02:54:23.885000+00:00", "time_to": "2020-05-02T03:31:19+00:00", "size": 100, "sub_field": "process.executable"} | 249 |  |
| q-e26850714f | pivot seed | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND host.name:\"nashua.dmevals.local\"", "time_from": "2020-05-02T02:54:23.885000+00:00", "time_to": "2020-05-02T03:31:19+00:00", "size": 100, "sub_field": "process.parent… | 63 |  |
| q-acc59da1ac | pivot seed | aggregate | {"dataset": "windows.powershell", "field": "event.code", "query": "host.name:\"nashua.dmevals.local\"", "time_from": "2020-05-02T02:54:23.885000+00:00", "time_to": "2020-05-02T03:31:19+00:00", "size": 100, "sub_field": null} | 192 |  |
| q-8ffc4e697e | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND host.name:\"newyork.dmevals.local\"", "time_from": "2020-05-02T02:46:30+00:00", "time_to": "2020-05-02T03:16:30+00:00", "size": 100, "sub_field": "process.parent.executable… | 16 |  |
| q-f3e4a4ba54 | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11 AND host.name:\"newyork.dmevals.local\"", "time_from": "2020-05-02T02:46:30+00:00", "time_to": "2020-05-02T03:16:30+00:00", "size": 100, "sub_field": "process.executable"} | 58 |  |
| q-4beb765824 | pivot seed | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND host.name:\"newyork.dmevals.local\"", "time_from": "2020-05-02T02:46:30+00:00", "time_to": "2020-05-02T03:16:30+00:00", "size": 100, "sub_field": "process.parent.execu… | 16 |  |
| q-4c3bccd748 | pivot seed | aggregate | {"dataset": "windows.powershell", "field": "event.code", "query": "host.name:\"newyork.dmevals.local\"", "time_from": "2020-05-02T02:46:30+00:00", "time_to": "2020-05-02T03:16:30+00:00", "size": 100, "sub_field": null} | 1210 |  |
| q-e962068f67 | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND host.name:\"scranton.dmevals.local\"", "time_from": "2020-05-02T02:40:56.157000+00:00", "time_to": "2020-05-02T03:37:35.895000+00:00", "size": 100, "sub_field": "process.pa… | 359 |  |
| q-ddc4707b78 | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11 AND host.name:\"scranton.dmevals.local\"", "time_from": "2020-05-02T02:40:56.157000+00:00", "time_to": "2020-05-02T03:37:35.895000+00:00", "size": 100, "sub_field": "process.executable… | 1276 |  |
| q-4de7b7c3e6 | pivot seed | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND host.name:\"scranton.dmevals.local\"", "time_from": "2020-05-02T02:40:56.157000+00:00", "time_to": "2020-05-02T03:37:35.895000+00:00", "size": 100, "sub_field": "proce… | 370 |  |
| q-651e85830a | pivot seed | aggregate | {"dataset": "windows.powershell", "field": "event.code", "query": "host.name:\"scranton.dmevals.local\"", "time_from": "2020-05-02T02:40:56.157000+00:00", "time_to": "2020-05-02T03:37:35.895000+00:00", "size": 100, "sub_field": null} | 8602 |  |
| q-21852756c9 | pivot step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND host.name == \"nashua.dmevals.local\" AND (process.executable LIKE \"*\\\\\\\\Temp\\\\\\\\*\" OR process.parent.executable LIKE \"*\\\\\\\\Temp\\\\\\\\*\" OR proc… | 19 | F58, F59 |
| q-e4bdd67e38 | pivot step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND host.name == \"scranton.dmevals.local\" AND (process.parent.executable LIKE \"*powershell.exe\" OR process.executable LIKE \"*SysinternalsSuite*\" OR process.exec… | 27 | F58, F61, F62, F64 |
| q-7981431cc0 | pivot step 2 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE host.name == \"nashua.dmevals.local\" AND event.code == \"4104\" \| KEEP @timestamp, user.name, powershell.script_block_text, _id, _index \| SORT @timestamp ASC"} | ERROR |  |
| q-7031fbaddb | pivot step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*\\\\\\\\temp\\\\\\\\*\" OR TO_LOWER(file.path) LIKE \"*working.zip*\" OR TO_LOWER(file.path) LIKE \"*draft.zip*\" OR TO_LOWER(file.p… | 500 | F63 |
| q-6e3594d591 | pivot step 3 | get_fields | {"dataset": "windows.powershell", "prefix": ""} | None |  |
| q-8a41ff8537 | pivot step 3 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE host.name == \"nashua.dmevals.local\" AND event.code IN (\"4624\",\"4672\",\"5140\",\"5145\",\"4648\",\"4673\") \| KEEP @timestamp, event.code, user.name, win.event_data.TargetUserName… | ERROR |  |
| q-d0eb93d8c5 | pivot step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE host.name == \"nashua.dmevals.local\" AND event.code == \"4104\" \| KEEP @timestamp, user.name, win.ScriptBlockText, _id, _index \| SORT @timestamp ASC"} | 11 | F58, F59 |
| q-1cf968a51d | pivot step 4 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE host.name == \"nashua.dmevals.local\" AND event.code IN (\"4624\",\"4672\",\"5140\",\"5145\",\"4648\") \| KEEP @timestamp, event.code, user.name, win.Message, _id, _index \| SORT @time… | 107 |  |
| q-638fa1ae31 | pivot step 5 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4663\",\"4656\") AND (TO_LOWER(win.Message) LIKE \"*\\\\\\\\config\\\\\\\\sam*\" OR TO_LOWER(win.Message) LIKE \"*\\\\\\\\config\\\\\\\\security*\" OR TO_LOWER(win.Mes… | 154 |  |
| q-4ee98e4e1c | pivot step 5 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE host.name == \"scranton.dmevals.local\" AND event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*lsass*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*sam*\" OR TO_LOWER(win… | 8 | F60 |
| q-6526ffcdbc | pivot step 6 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNuG"} | None | F58 |
| q-488c4bd245 | pivot step 6 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7njy6Co"} | None | F58 |
| q-4361c96dda | pivot step 6 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq72Yf"} | None |  |
| q-822fd1594c | pivot step 7 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"3\" AND host.name == \"nashua.dmevals.local\" \| KEEP @timestamp, user.name, process.executable, source.ip, source.port, destination.ip, destination.port, network.directi… | ERROR |  |
| q-8d6d909ff9 | pivot step 7 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq7mb8"} | None |  |
| q-5545fa60e8 | pivot step 8 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"3\" AND host.name == \"nashua.dmevals.local\" \| KEEP @timestamp, user.name, process.executable, source.ip, source.port, destination.ip, destination.port, _id, _index \| … | 428 |  |
| q-aebbb7cafd | pivot step 8 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq72YQ"} | None |  |
| q-d29d997918 | pivot step 9 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"3\" AND host.name == \"nashua.dmevals.local\" AND (process.executable LIKE \"*python.exe\" OR process.executable LIKE \"*powershell.exe\" OR process.executable LIKE \"*Ra… | 348 | F58 |
| q-f0fd58e50e | pivot step 9 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq72Yf"} | None |  |
| q-8e9aa5ba4f | pivot step 10 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq72Yf"} | None |  |
| q-2b0add9768 | pivot step 10 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None | F60 |
| q-c08588a807 | pivot step 11 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq72Yf"} | None |  |
| q-db55b980fc | pivot step 11 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None | F60 |
| q-3997ca0f9c | pivot verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7njy6Co"} | None |  |
| q-4233328696 | pivot verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNuG"} | None |  |
| q-86c3298ba2 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cxoQzx"} | None |  |
| q-4812897ae2 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c4xY6Y"} | None |  |
| q-79a93158b4 | pivot verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qrRC92"} | None |  |
| q-1e0b632e02 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c5ylrT"} | None |  |
| q-853565946c | pivot verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qrRC92"} | None |  |
| q-94255ca89a | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c4xY6Y"} | None |  |
| q-25e66bc2a1 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7crhzvV"} | None |  |
| q-fdbdd61341 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7culihF"} | None |  |
| q-0e7549d297 | pivot verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None |  |
| q-7d7e5c5bc5 | pivot verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None |  |
| q-f92894c3f5 | pivot verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None |  |
| q-812ac79092 | pivot verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qrRC9i"} | None |  |
| q-6683140c0b | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7huwtP3"} | None |  |
| q-ad9a2ad436 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7htvuyY"} | None |  |
| q-4820352695 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7JHlRK"} | ERROR |  |
| q-4597750147 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7YJ9Kbo"} | None |  |
| q-58719d5f73 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7YE3lVE"} | None |  |
| q-0efafcb272 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7YD3Who"} | None |  |
| q-9850f9d9f0 | pivot step 13 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7JHlRK"} | ERROR |  |
| q-0c3998a4a6 | pivot step 13 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hy0krT"} | None | F63 |
| q-97890f1656 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-9b95e432c3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-84d2f63cb8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-9de9df03c2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None |  |
| q-ae719510a8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None |  |
| q-b8b053b50d | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qrRbzS"} | None |  |
| q-354069d37b | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qqQ-d4"} | None |  |
| q-80e754516f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cpgKxF"} | None |  |
| q-b03c58a082 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cpgKxF"} | None |  |
| q-9084c99737 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cNAtxy"} | None |  |
| q-8c5198f336 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nOhdc5"} | None |  |
| q-763cfe8db0 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nOhdc5"} | None |  |
| q-0f2ba64922 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nOhdc5"} | None |  |
| q-603588fe96 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq8GZx"} | None |  |
| q-081b16b5d1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c82OiA"} | None |  |
| q-9541c4cf32 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c82OiA"} | None |  |
| q-d3316aed3f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cwoB6Q"} | None |  |
| q-14f570ff88 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cxoQzx"} | None |  |
| q-51c53a2efb | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nOhdc5"} | None |  |
| q-9fb0de01a6 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cla5Dm"} | None |  |
| q-0a707c049c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cla5Dm"} | None |  |
| q-b2dca236c0 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nSl9D4"} | None |  |
| q-83e8451c9d | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nOhte9"} | None |  |
| q-69e4032e14 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cUGpQW"} | None |  |
| q-e2a226ccdd | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cUGpQW"} | None |  |
| q-427fdfca2c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hy1Evq"} | None |  |
| q-4c4c936c82 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cdRgzF"} | None |  |
| q-d2b7fccc4e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cxoQzx"} | None |  |
| q-8ca49816d8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c82OhP"} | None |  |
| q-729b274f83 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-50863e3434 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-03555efd15 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhH"} | None |  |
| q-e8c8dbe6cc | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhH"} | None |  |
| q-f15f3e423d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhH"} | None |  |
| q-4db8360cea | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq7mb8"} | None |  |
| q-8ba6ac1432 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq7mb8"} | None |  |
| q-e8069d77e2 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7njy6Co"} | None |  |
| q-a91f72cf57 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7njy6Co"} | None |  |
| q-866258a07b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None |  |
| q-480f39e99e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c-4cYK"} | None |  |
| q-1ed59d6730 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nSlNDC"} | None |  |
| q-f5b85d8302 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nKhItU"} | None |  |
| q-7204ccf93c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cyrL8F"} | None |  |
| q-9e0ace1c96 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cpgKyV"} | None |  |
| q-8b470a8f28 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuDg"} | None |  |
| q-c70cc6ab18 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuCk"} | None |  |
| q-182b70da57 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRfJfH5wFd7b8wDMC"} | None |  |
| q-5a91ec4336 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None |  |
| q-291abb2924 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None |  |
| q-4091d25290 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c93Nx4"} | None |  |
| q-da4dba2bc3 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None |  |
| q-269fab0eb0 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None |  |
| q-c028ef21e0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7htwOyZ"} | None |  |
| q-ce88df14a5 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq7mb8"} | None |  |
| q-21b6d2f944 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq7mb8"} | None |  |
| q-a783d11ec1 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7njy6Co"} | None |  |
| q-b72e228251 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7ryFh2_"} | None |  |
| q-efe261b1ed | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7ryFh2_"} | None |  |
| q-f9630dcc73 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cxqOgJ"} | None |  |
| q-992ba587b7 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNur"} | None |  |
| q-9e8621da63 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNur"} | None |  |
| q-b2570216b3 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qqQ-d4"} | None |  |
| q-04d7021282 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niytuv"} | None |  |
| q-e664683b4a | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qwUVtv"} | None |  |
| q-9b79373465 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None |  |
| q-f329cef010 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None |  |
| q-0aaa01ccdf | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None |  |
| q-ced12496bb | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQRgs"} | None |  |
| q-4f82c7669c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-983c0ee177 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-56bfd74536 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None |  |
| q-5330952063 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None |  |
| q-816b090512 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c_44mH"} | None |  |
| q-5a1cfef7cc | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qrRC9i"} | None |  |
| q-b250705395 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuCk"} | None |  |
| q-3edede25ef | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None |  |
| q-46a9dd5f3e | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None |  |
| q-8981c0dc35 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c-48Ye"} | None |  |
| q-a0e5540e02 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c-48Ye"} | None |  |
| q-b77a2000be | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c-4sYX"} | None |  |
| q-04cd8b70d4 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_Z1YZ"} | None |  |
| q-658179f7f2 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_Zlb7"} | None |  |
| q-2649966e00 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_Zlb7"} | None |  |
| q-e7e4128d85 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_Z1a3"} | None |  |
| q-438bff968f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c5ylrT"} | None |  |
| q-5cc1170d0d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c5ylrT"} | None |  |
| q-7e7132d7e4 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c82-ha"} | None |  |
| q-6fec03a9b6 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7qUct2z"} | None |  |
| q-9d016e453b | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7qVdaEh"} | None |  |
| q-454c423cc6 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7ns-Aqw"} | None |  |
| q-acb69ed5f5 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq72Zu"} | None |  |
| q-979940cfd6 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niytut"} | None |  |
| q-08b6ebd834 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hWVykL"} | None |  |
| q-684aa039eb | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuDM"} | None |  |
| q-ce92063d9c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-f322af9129 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-4d79add1cc | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-60f3859c7e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhG"} | None |  |
| q-574254903b | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7q0Yv7J"} | None |  |
| q-f4390edf78 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7htwOyZ"} | None |  |
| q-f0182b7643 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQRgs"} | None |  |
| q-0e72d4ab86 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None |  |
| q-460f604298 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None |  |
| q-cf254e0704 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qrRapX"} | None |  |
| q-b26b4577c5 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cyrL9g"} | None |  |
| q-0966717e98 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cUGJOD"} | None |  |
| q-931b86d678 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cpgKyU"} | None |  |
| q-01d31bc556 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuBw"} | None |  |
| q-af420ace3f | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_Z1bK"} | None |  |
| q-c0fd82a152 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7YE4VZs"} | None |  |
| q-5f75a05d4c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cPCBow"} | None |  |
| q-b3e6d3ae38 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7q0ZP57"} | None |  |
| q-f43c9455fe | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None |  |
| q-6ce87fb1bf | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSyvc"} | None |  |
| q-79c4b3bb29 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hwzKeY"} | None |  |
| q-d80f779768 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None |  |
| q-42e5a0c89f | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None |  |
| q-82da6cc8b1 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None |  |
| q-21cef542e1 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvTSsN"} | None |  |
| q-6a142a76bb | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQRgs"} | None |  |
| q-65850b6905 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQRgs"} | None |  |
| q-9ab6da8bfd | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None |  |
| q-12b2a55c3a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c_44mH"} | None |  |
| q-0a92a9df0e | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None |  |
| q-6d8e0e1815 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSytV"} | None |  |
| q-8f97531970 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7habqSt"} | None |  |
| q-8c245c8d60 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qwUVtv"} | None |  |
| q-339e96fa04 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7YK95pg"} | None |  |
| q-cd4d93a4b4 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cTFiiN"} | None |  |
| q-eec91c013e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cfUP4A"} | None |  |
| q-0b636011a4 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cfUP4A"} | None |  |
| q-686d78f75e | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7ncs5oy"} | None |  |
| q-8bb45f8387 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7ncs5oy"} | None |  |
| q-a961a9a2fe | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7qUcN0h"} | None |  |
| q-9342a2d9e5 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7htwOyZ"} | None |  |
| q-e5e48c16a3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-72702a4fdf | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-0a9e171d1e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhG"} | None |  |
| q-0817339757 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq7mb8"} | None |  |
| q-a53449df69 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq7mb8"} | None |  |
| q-b5b9df45bc | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hy0krT"} | None |  |
| q-429fa1aeb3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRfJfH5wFd7b6t2mM"} | None |  |
| q-e7de834c9d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRfJfH5wFd7b6t2mM"} | None |  |
| q-38730ed2e6 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7YK9pro"} | None |  |
| q-b67bccd300 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRfJfH5wFd7b_yhXF"} | None |  |
| q-d206622eef | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7YE4VZs"} | None |  |
| q-18626a32d4 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7crhjub"} | None |  |
| q-f2f5ae7f77 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c4xY6Y"} | None |  |
| q-8db6cda403 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-f53c513f39 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-63da206e96 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7htwOyZ"} | None |  |
| q-0f65f1ef3f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7htwOyZ"} | None |  |
| q-03117c631e | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qrRFHq"} | None |  |
| q-db8bb19300 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qqQ-d4"} | None |  |
| q-877736c44f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cxqOgJ"} | None |  |
| q-af6c264c9c | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuDx"} | None |  |
| q-bae5fc6067 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuDg"} | None |  |
| q-e7fd36a8c0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cpgKyZ"} | None |  |
| q-c22da711fd | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cpgKxG"} | None |  |
| q-89b8709066 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qyVUi_"} | None |  |
| q-c3bc3bcc3e | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nixwZC"} | None |  |
| q-a16fe8b868 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nixwZC"} | None |  |
| q-e84ec15470 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cUGJOD"} | None |  |
| q-4409c23c5f | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nKgYvV"} | None |  |
| q-56f4ffb2dd | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nQi3T7"} | None |  |
| q-2339886c7e | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nQi3T7"} | None |  |
| q-9a4218d753 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hy1EsU"} | None |  |
| q-adfab8fc86 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hy1EsU"} | None |  |
| q-253e73551d | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7qUcN2T"} | None |  |
| q-60c5b293cf | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7qUcN2T"} | None |  |
| q-71c4d4b0e4 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_Zlbj"} | None |  |
| q-2f3109196b | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNuI"} | None |  |
| q-01192fafcb | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cYMP7j"} | None |  |
| q-249d2b30b3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cYMP7j"} | None |  |
| q-3ba1659335 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cYMf4P"} | None |  |
| q-dabed1bd3e | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_aFZ1"} | None |  |
| q-d5275db22e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cla5Dm"} | None |  |
| q-d60e16dc78 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cjZtk-"} | None |  |
| q-6a017e29bc | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cjZtk-"} | None |  |
| q-73f67caa7f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hy0Urg"} | None |  |
| q-6ca9ef8a1e | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qqQ-d4"} | None |  |
| q-8600c509aa | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c82OhP"} | None |  |
| q-160f4dd302 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c82Oiy"} | None |  |
| q-951993c9e1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhG"} | None |  |
| q-9fabca70c8 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNvO"} | None |  |
| q-d9aeeaea42 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq72Yx"} | None |  |
| q-648d4669e6 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cpgKyU"} | None |  |
| q-c668439c41 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7njzKBN"} | None |  |
| q-b1010298b5 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNuT"} | None |  |
| q-93f642b8d3 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7rxFDL4"} | None |  |
| q-99a6e20f76 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq72bs"} | None |  |
| q-adb529b0cf | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysW"} | None |  |
| q-cb1d9e7484 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNsI"} | None |  |
| q-12af26da7c | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNsI"} | None |  |
| q-1a04d6920a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-5ff62c1ded | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-848bac0025 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None |  |
| q-0744fa92e3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None |  |
| q-54109664df | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hy0krT"} | None |  |
| q-f7181edc8e | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7ns9wrd"} | None |  |
| q-b3fc0bd46d | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qzW1OH"} | None |  |
| q-c26d7c16a6 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qzXFp5"} | None |  |
| q-09370c99ee | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hy0krN"} | None |  |
| q-692a728ba8 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvTCvl"} | None |  |
| q-b3dbe76eee | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNur"} | None |  |
| q-a50b1c4a81 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7ryFR3O"} | None |  |
| q-6309293c5d | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None |  |
| q-b40d8e3c15 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None |  |
| q-f9ccedc865 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None |  |
| q-92dcfa7c0b | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvTSsN"} | None |  |
| q-8fb885415e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQRgs"} | None |  |
| q-63447a9241 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQRgs"} | None |  |
| q-94e32f9425 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qrRC9i"} | None |  |
| q-317f6bbccc | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7rzHZUI"} | None |  |
| q-a1b3b2915f | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7rzHZUI"} | None |  |
| q-33daee7929 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7rzHZUI"} | None |  |
| q-f37aa1cd96 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7ryGB0J"} | None |  |
| q-58b1920f4a | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7ryGB0J"} | None |  |
| q-8e5c88599b | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7njy6Co"} | None |  |
| q-5bbc77b31f | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNuG"} | None |  |
| q-e2f79a17e1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cxoQzx"} | None |  |
| q-497b2146bb | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c4xY6Y"} | None |  |
| q-2df748ae17 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qrRC92"} | None |  |
| q-5c18786f4a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c5ylrT"} | None |  |
| q-bc8a5be54c | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qrRC92"} | None |  |
| q-23c537b90c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c4xY6Y"} | None |  |
| q-34a0dc6dda | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7crhzvV"} | None |  |
| q-f767739e21 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7culihF"} | None |  |
| q-0debc11437 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None |  |
| q-5ec7c96ee4 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None |  |
| q-e71aee2b53 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None |  |
| q-9debed3821 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qrRC9i"} | None |  |
| q-fe938c088e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7huwtP3"} | None |  |
| q-124cea9889 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7htvuyY"} | None |  |
| q-5ab4da3365 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7htwOyJ"} | None |  |
| q-950dbb50c5 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7YJ9Kbo"} | None |  |
| q-86443654f0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7YE3lVE"} | None |  |
| q-5c2d400c46 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7YD3Who"} | None |  |
| q-f0ee6bc4fb | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hy0krT"} | None |  |
| q-8fd39f11ae | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hy0krT"} | None |  |
| q-bb9da55e98 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hwyqdH"} | None |  |
| q-5b7ec37a69 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hRQwNZ"} | None |  |
| q-e03e349305 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hRQwNZ"} | None |  |
| q-f8dc39fe68 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hWVSlm"} | None |  |

## Verification

Evidence items cited: 244; confirmed against the stored events: 244; rejected: 0. Each item was re-fetched with get_event; it is confirmed only if the event exists, the cited field holds the cited value, and the cited query_id is a query of this run that returned that event.
Evidence sent back to the agents for correction during the run: 3 item(s) in 3 submission(s) (one correction round each; what still failed was rejected).

## Limitations

- Findings describe what the stored logs show; activity these sources did not log cannot be seen.
- Datasets with non-overlapping time windows (see Data examined) were analysed separately.
- Long field values are shortened in this report; full events are retrievable by _index/_id.
