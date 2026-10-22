# Threat hunt report — 20261022-140341-converged-recheck-playbook-b

**Hypothesis:** An adversary who compromised Windows hosts in this network stole credentials from them (MITRE ATT&CK tactic: Credential Access).

**Verdict: Confirmed** — 11 in-scope incident(s) of verified malicious findings (confidence >= medium): I01 T1003.001 (F01, F16, F31, F55), I02 T1056.001 (F59), I03 T1187 (F20), I04 T1212 (F09, F22), I05 T1212 (F23), I06 T1552 (F27, F61), I07 T1552.001 (F28, F56), I08 T1552.001 (F58), I10 T1555.003 (F57), I11 T1558 (F44), I13 T1649 (F49, F53, F60)

Verdict method: rules over verified evidence (Confirmed if >=1 in-scope incident of verified malicious findings (confidence >= medium); Inconclusive if only suspicious incidents or coverage gaps; Refuted if full coverage and no malicious/suspicious finding)

| Run | Value |
|---|---|
| Profile | converged (thinking=False, temperature=0.0) |
| Model | deepseek-flash |
| Started / finished (UTC) | 2026-10-22T06:03:42+00:00 / 2026-10-22T06:12:32+00:00 (530.8 s) |
| LLM calls / tokens | 150 / {'prompt': 4326094, 'completion': 97495} |
| MCP tool calls | 1292 (server tools: list_data_sources, get_fields, search, count, aggregate, timeline, esql, get_event, get_registry) |
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
| I01 | T1003.001 | yes | malicious/high | F01, F16, F31, F55 | LSASS memory access with full-access masks by attacker PowerShell on scranton and WMI/WinRM host on nashua |
| I02 | T1056.001 | yes | malicious/high | F59 | PowerShell keystroke logger and clipboard capture on scranton |
| I03 | T1187 | yes | malicious/high | F20 | WebDAV forced authentication from scranton followed by SMB/ADMIN$ credential use against nashua and newyork |
| I04 | T1212 | yes | malicious/high | F09, F22 | Steganographic hidden PowerShell stager (control.exe parent) that opened LSASS on scranton |
| I05 | T1212 | yes | malicious/medium | F23 | WMI remote-exec host opened LSASS on nashua |
| I06 | T1552 | yes | malicious/high | F27, F61 | accesschk.exe credential reconnaissance creating passwordsDB and querying LSA registry key on scranton |
| I07 | T1552.001 | yes | malicious/high | F28, F56 | Plaintext password on PsExec64 command line used against NASHUA |
| I08 | T1552.001 | yes | malicious/high | F58 | Credential-named file collection and password-protected archive on nashua |
| I09 | T1555.003 | yes | suspicious/medium | F25 | PowerShell opened Microsoft Edge browser processes with full access on scranton |
| I10 | T1555.003 | yes | malicious/medium | F57 | Browser processes opened with full access on nashua |
| I11 | T1558 | yes | malicious/high | F44 | Kerberos ticket requests for krbtgt alongside LSASS access on scranton |
| I12 | T1606.002 | yes | suspicious/medium | F51 | No SAML token forgery observed; certificate export is closest precursor |
| I13 | T1649 | yes | malicious/high | F49, F53, F60 | Certificate/private-key export via Get-PrivateKeys on scranton |
| I14 | out-of-scope:T1027 | no | malicious/medium | F63 | In-memory DLL compilation via csc.exe on scranton |
| I15 | out-of-scope:T1204 | no | malicious/high | F62 | Masqueraded .scr stager in ProgramData\victim on scranton |
| I16 | out-of-scope:T1548 | no | suspicious/medium | F64 | hostui.exe launched with -verb runas for elevation on scranton |
| I17 | out-of-scope:T1548 | no | suspicious/low | F65 | sdclt.exe spawned by cmd on scranton |

## Findings

### F01 · malicious / high · T1003.001 · LSASS memory opened with full-access masks by attacker PowerShell session (pbeesly) on scranton and nashua

Evidence status: **verified**

On 2020-05-02 at 03:05:16 (UTC) the user pbeesly on scranton.dmevals.local requested handles to \Device\HarddiskVolume2\Windows\System32\lsass.exe from powershell.exe with AccessMask 0x1f3fff and 0x1fffff (DELETE, WRITE_DAC, WRITE_OWNER, VM operation, read/write process memory, duplicate handle, create thread). Sysmon corroborates the same opens from PowerShell.exe with GrantedAccess 0x1f3fff and 0x1fffff at 03:05:16.623/03:05:16.654. At 03:09:29 the same user, via a remote PowerShell session (wsmprovhost.exe, logon 0x85AAD2) on nashua.dmevals.local, again opened lsass.exe with 0x1f3fff. This occurred inside a hands-on-keyboard intrusion: the same pbeesly session had just run a PowerShell toolkit (readme.ps1 / psversion.ps1 from C:\Program Files\SysinternalsSuite) containing Keystroke-Check, Get-Keystrokes, Invoke-ScreenCapture, Get-Clipboard, Get-PrivateKeys and Invoke-Exfil, and had executed accesschk.exe. No lsass.dmp file was written to disk in the observed window, but the access masks are those of a memory-read/credential-dump attempt against LSASS. Other LSASS opens in the dataset (svchost.exe 0x1000/0x1400, CollectGuestLogs.exe, MsMpEng.exe, AntimalwareConfig.exe, wininit/csrss at process start) are normal system behaviour.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | win.AccessMask | 0x1f3fff | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBy0A4ua | q-2a6ecde853 | ok |
| 2 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | win.ObjectName | \Device\HarddiskVolume2\Windows\System32\lsass.exe | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBy0A4ua | q-fe0f79fff7 | ok |
| 3 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | win.AccessMask | 0x1fffff | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBy0A4uc | q-2a6ecde853 | ok |
| 4 | 2020-05-02 03:09:29.000Z | nashua.dmevals.local | windows.security | win.ProcessName | C:\Windows\System32\wsmprovhost.exe | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBux8Gu0 | q-014f0def43 | ok |
| 5 | 2020-05-02 03:09:29.000Z | nashua.dmevals.local | windows.security | win.AccessMask | 0x1f3fff | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBux8Gu0 | q-2a6ecde853 | ok |
| 6 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoMQUXF | q-5d29bae4fd | ok |
| 7 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoMQUXI | q-5d29bae4fd | ok |
| 8 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBn663fz | q-5d29bae4fd | ok |
| 9 | 2020-05-02 03:06:47.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\psversion.ps1 | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByRZ7r- | q-bb1eb242de | ok |
| 10 | 2020-05-02 03:06:59.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | Get-Keystrokes;Start-Sleep -Seconds 15;View-Job -JobName "Keystrokes" | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByRaLr9 | q-343a985f75 | ok |

### F55 · malicious / high · T1003.001 · PsExec-pushed python.exe opened LSASS with 0x1f3fff and beaconed to 192.168.0.4:8443

Evidence status: **verified**

On nashua, C:\Windows\Temp\python.exe (PyInstaller, parent PSEXESVC.exe, pbeesly) opened lsass 0x1f3fff at 03:09:29 then beaconed to 192.168.0.4:8443 from 03:15:05.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.TargetImage | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBn663fz | q-88b5a0a7f1 | ok |
| 2 | 2020-05-02 03:15:05.142Z | nashua.dmevals.local | windows.sysmon | destination.ip | 192.168.0.4 | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBnyzTy7 | q-58c74cb32c | ok |
| 3 | 2020-05-02 03:11:40.213Z | nashua.dmevals.local | windows.sysmon | process.parent.executable | C:\Windows\PSEXESVC.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoz4j7h | q-271d43c365 | ok |

### F59 · malicious / high · T1056.001 · PowerShell keystroke logger and clipboard capture on scranton

Evidence status: **verified**

pbeesly on scranton ran Get-Keystrokes (job 'Keystrokes') and Get-Clipboard at 03:06:42-03:07:49.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:06:59.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | Get-Keystrokes;Start-Sleep -Seconds 15;View-Job -JobName "Keystrokes" | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByRaLr9 | q-d70255cf90 | ok |
| 2 | 2020-05-02 03:06:42.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | Get-Clipboard | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByRaLr6 | q-d70255cf90 | ok |

### F09 · malicious / high · T1056.004 · Steganography-launched hidden PowerShell opened LSASS with full access on scranton (credential API hooking / memory access)

Evidence status: **verified**

On scranton.dmevals.local a malicious screen saver C:\ProgramData\victim\â€®cod.3aka3.scr (PID 8524) wrote C:\Users\pbeesly\Downloads\monkey.png at 02:57:00Z. At 02:58:44Z a hidden, execution-policy-bypassing PowerShell (PID 2976, user DMEVALS\pbeesly, High integrity, parent control.exe /name Microsoft.BackupAndRestoreCenter) was spawned that read the bitmap pixel data and IEX'd the decoded bytes (steganographic payload delivery). That same process entity {47ab858c-e1e4-5eac-b803-000000000400} then requested handles to lsass.exe (PID 736) at 03:05:16Z with GrantedAccess 0x1F3FFF and 0x1FFFFF — full-process access including PROCESS_VM_READ, the access pattern used to read credential material from LSASS memory. The call trace ends in UNKNOWN modules, not a signed security product. This is the only PowerShell-sourced full-access LSASS open in the whole dataset (all other LSASS opens are svchost 0x1000, Azure antimalware/telemetry 0x1400, or OS processes).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:57:00.933Z | scranton.dmevals.local | windows.sysmon | win.Image | C:\ProgramData\victim\â€®cod.3aka3.scr | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBouy-nD | q-2df377002a | ok |
| 2 | 2020-05-02 02:57:00.933Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Users\pbeesly\Downloads\monkey.png | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBouy-nD | q-2df377002a | ok |
| 3 | 2020-05-02 02:58:44.325Z | scranton.dmevals.local | windows.sysmon | process.command_line | "PowerShell.exe" -noni -noexit -ep bypass -window hidden -c "sal a New-Object;Add-Type -AssemblyName 'System.Drawing'; $g=a System.Drawing.Bitmap('C:\Users\pbee… | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBorwtwa | q-548f4c63a7 | ok |
| 4 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoMQUXF | q-0dafc00bcf | ok |
| 5 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoMQUXF | q-0dafc00bcf | ok |
| 6 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoMQUXI | q-0dafc00bcf | ok |
| 7 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.CallTrace | C:\windows\SYSTEM32\ntdll.dll+9c584\|C:\windows\System32\KERNELBASE.dll+2732e\|UNKNOWN(000001996D252982) | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoMQUXF | q-ed217f100c | ok |

### F20 · malicious / high · T1187 · WebDAV forced authentication from scranton (10.0.1.4) to attacker-style WebDAV server 192.168.0.4, followed by SMB/ADMIN$ credential use against nashua and newyork

Evidence status: **verified**

On 2020-04-30 between 00:32:14 and 00:32:21 UTC, host 10.0.1.4 (scranton.dmevals.local, per the zeek-scranton log source) first probed 192.168.0.4 on TCP 445 and 139 (all connections REJ, i.e. SMB blocked), then immediately pivoted to HTTP/80 WebDAV against the same host. The client used the Windows WebDAV redirector user agents 'DavClnt' and 'Microsoft-WebDAV-MiniRedir/10.0.18362' and issued OPTIONS, PROPFIND, PROPPATCH, PUT, LOCK and UNLOCK against /webdav and /webdav/OfficeSupplies.7z. The server repeatedly answered 401 Unauthorized and the client re-sent the requests, which is the classic forced-authentication/NTLM-coercion pattern: the victim is made to authenticate to an attacker-controlled WebDAV endpoint so its Net-NTLM hash can be captured. The same host then wrote a file to the remote WebDAV share (PUT /webdav/OfficeSupplies.7z returned 201 Created, then 204 No Content, with a 2.1 MB upload on the port-80 connection), consistent with staging data to the attacker's server. In the Windows telemetry window (2020-05-02 02:55-03:28 UTC, non-overlapping with zeek) the same source address 10.0.1.4 is seen authenticating as user 'pbeesly' and as machine account 'SCRANTON$' to SYSVOL, IPC$ and ADMIN$ shares on newyork.dmevals.local and nashua.dmevals.local (9 ADMIN$ accesses to \\*\ADMIN$ -> \??\C:\windows on nashua between 23:10 and 23:18 local time), i.e. the coerced/obtained credentials were used for lateral SMB access. The SMB connections observed in Sysmon to 10.0.0.4 and 10.0.1.6 are System-process (port 445/139) domain traffic and are not themselves coercive, but the WebDAV sequence is a clear forced-authentication attempt.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-04-30 00:32:18.095Z | simplerockbuild.simplerock.lan | zeek | user_agent.original | DavClnt | .ds-logs-zeek-default-2026.10.22-000001 / AaFiKZc9VXKkeBwkgR9D | q-5187e20aca | ok |
| 2 | 2020-04-30 00:32:18.095Z | simplerockbuild.simplerock.lan | zeek | http.request.method | OPTIONS | .ds-logs-zeek-default-2026.10.22-000001 / AaFiKZc9VXKkeBwkgR9D | q-5187e20aca | ok |
| 3 | 2020-04-30 00:32:21.422Z | simplerockbuild.simplerock.lan | zeek | user_agent.original | Microsoft-WebDAV-MiniRedir/10.0.18362 | .ds-logs-zeek-default-2026.10.22-000001 / AaFiKZc9VXKkeBwkgR9H | q-5187e20aca | ok |
| 4 | 2020-04-30 00:32:21.422Z | simplerockbuild.simplerock.lan | zeek | http.response.status_code | 401 | .ds-logs-zeek-default-2026.10.22-000001 / AaFiKZc9VXKkeBwkgR9H | q-5187e20aca | ok |
| 5 | 2020-04-30 00:32:21.895Z | simplerockbuild.simplerock.lan | zeek | url.original | /webdav/OfficeSupplies.7z | .ds-logs-zeek-default-2026.10.22-000001 / AaFiKZc9VXKkeBwkgh9V | q-0d955bf9c8 | ok |
| 6 | 2020-04-30 00:32:21.895Z | simplerockbuild.simplerock.lan | zeek | destination.ip | 192.168.0.4 | .ds-logs-zeek-default-2026.10.22-000001 / AaFiKZc9VXKkeBwkgh9V | q-0d955bf9c8 | ok |
| 7 | 2020-04-30 00:32:21.918Z | simplerockbuild.simplerock.lan | zeek | http.response.status_code | 201 | .ds-logs-zeek-default-2026.10.22-000001 / AaFiKZc9VXKkeBwkgh8V | q-5187e20aca | ok |
| 8 | 2020-04-30 00:32:21.918Z | simplerockbuild.simplerock.lan | zeek | http.request.method | PUT | .ds-logs-zeek-default-2026.10.22-000001 / AaFiKZc9VXKkeBwkgh8V | q-5187e20aca | ok |
| 9 | 2020-04-30 00:32:14.891Z | simplerockbuild.simplerock.lan | zeek | destination.port | 445 | .ds-logs-zeek-default-2026.10.22-000001 / AaFiKZc9VXKkeBwkgR_2 | q-3766a99c59 | ok |
| 10 | 2020-04-30 00:32:14.891Z | simplerockbuild.simplerock.lan | zeek | zeek.conn_state | REJ | .ds-logs-zeek-default-2026.10.22-000001 / AaFiKZc9VXKkeBwkgR_2 | q-3766a99c59 | ok |
| 11 | 2020-04-30 00:32:21.532Z | simplerockbuild.simplerock.lan | zeek | zeek.orig_bytes | 2181167 | .ds-logs-zeek-default-2026.10.22-000001 / AaFiKZc9VXKkeBwkgh-i | q-3766a99c59 | ok |
| 12 | 2020-05-02 03:10:23.000Z | nashua.dmevals.local | windows.security | win.ShareName | \\*\ADMIN$ | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBuv5CHS | q-2ce408ae43 | ok |
| 13 | 2020-05-02 03:10:23.000Z | nashua.dmevals.local | windows.security | user.name | pbeesly | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBuv5CHS | q-2ce408ae43 | ok |
| 14 | 2020-05-02 03:10:23.000Z | nashua.dmevals.local | windows.security | source.ip | 10.0.1.4 | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBuv5CHS | q-2ce408ae43 | ok |
| 15 | 2020-05-02 03:01:43.000Z | newyork.dmevals.local | windows.security | user.name | SCRANTON$ | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBy8KXgw | q-610c35c330 | ok |

### F22 · malicious / high · T1212 · Hidden PowerShell stager (control.exe parent) opened lsass with full-access 0x1FFFFF/0x1F3FFF on scranton

Evidence status: **verified**

On scranton.dmevals.local, PID 2976 (C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe, user DMEVALS\pbeesly, IntegrityLevel High) was spawned at 2020-05-02T02:58:44Z by C:\Windows\System32\control.exe with the command line "PowerShell.exe" -noni -noexit -ep bypass -window hidden -c "sal a New-Object;Add-Type -AssemblyName 'System.Drawing'; $g=a System.Drawing.Bitmap('C:\Users\pbeesly\Downloads\monkey.png');...IEX([System.Text.Encoding]::ASCII.GetString($o[0..3932]))" — a steganographic, hidden-window, execution-policy-bypass loader. At 03:05:16Z that same process (SourceProcessGUID {47ab858c-e1e4-5eac-b803-000000000400}) opened lsass.exe (PID 736) twice with GrantedAccess 0x1F3FFF and 0x1FFFFF, i.e. PROCESS_ALL_ACCESS-equivalent rights that permit reading credential material. The call trace ends in UNKNOWN(000001996D28200D), not a Windows LSA module, indicating code injected/allocated in the PowerShell process rather than a legitimate LSA API path. This is the only PowerShell-to-lsass full-access pair in the dataset and is consistent with in-memory credential theft from lsass.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:58:44.325Z | scranton.dmevals.local | windows.sysmon | process.command_line | "PowerShell.exe" -noni -noexit -ep bypass -window hidden -c "sal a New-Object;Add-Type -AssemblyName 'System.Drawing'; $g=a System.Drawing.Bitmap('C:\Users\pbee… | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBorwtwa | q-fd61b4b0b7 | ok |
| 2 | 2020-05-02 02:58:44.325Z | scranton.dmevals.local | windows.sysmon | process.parent.executable | C:\Windows\System32\control.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBorwtwa | q-fd61b4b0b7 | ok |
| 3 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoMQUXI | q-8d314fe1ed | ok |
| 4 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.TargetImage | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoMQUXI | q-8d314fe1ed | ok |
| 5 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.CallTrace | C:\windows\SYSTEM32\ntdll.dll+9c584\|C:\windows\System32\KERNELBASE.dll+2732e\|UNKNOWN(000001996D28200D) | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoMQUXI | q-8d314fe1ed | ok |
| 6 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoMQUXF | q-4b892f3097 | ok |

### F23 · malicious / medium · T1212 · WMI remote-exec host (wsmprovhost.exe, user pbeesly) opened lsass with 0x1F3FFF on nashua

Evidence status: **verified**

On nashua.dmevals.local, PID 7720 (C:\windows\system32\wsmprovhost.exe -Embedding, parent svchost.exe -k DcomLaunch -p, running as DMEVALS\pbeesly) was created at 2020-05-02T03:09:23Z and six seconds later, at 03:09:29Z, opened lsass.exe (PID 728) with GrantedAccess 0x1F3FFF. The call trace runs through System.ni.dll and Microsoft.PowerShell.Commands.Management.ni.dll, showing the access was made from PowerShell code executed inside a WMI/WinRM remote-execution host — i.e. the same operator (pbeesly) who ran the hidden stager on scranton reached nashua remotely and requested near-full access to lsass. This is the only wsmprovhost-to-lsass access in the dataset.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBn663fz | q-b883aef126 | ok |
| 2 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBn663fz | q-b883aef126 | ok |
| 3 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.TargetImage | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBn663fz | q-b883aef126 | ok |
| 4 | 2020-05-02 03:09:23.885Z | nashua.dmevals.local | windows.sysmon | process.command_line | C:\windows\system32\wsmprovhost.exe -Embedding | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBo05D7L | q-c2b5afd30f | ok |
| 5 | 2020-05-02 03:09:23.885Z | nashua.dmevals.local | windows.sysmon | user.name | pbeesly | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBo05D7L | q-c2b5afd30f | ok |

### F27 · malicious / high · T1552 · accesschk.exe run by pbeesly on SCRANTON creates 'passwordsDB' and queries the LSA registry key

Evidence status: **verified**

On scranton.dmevals.local at 2020-05-02T03:04:34Z user pbeesly launched C:\Program Files\SysinternalsSuite\accessChk.exe from a PowerShell parent (4688 + Sysmon 1). One second later (03:04:35Z) that process created the file C:\Program Files\SysinternalsSuite\passwordsDB (Sysmon 11), and at 03:04:54Z it opened \REGISTRY\MACHINE\SYSTEM\ControlSet001\Control\Lsa with AccessMask 0x1 / 'Query key value' (4656 and 4663, SubjectUserName pbeesly). This is credential reconnaissance/collection on the host: a Sysinternals access-enumeration tool being used to probe the LSA secrets key and to write a file named for passwords. It is part of a broader intrusion chain on the same host (sdelete64 wiping C:\programdata\victim\???cod.3aka3.scr, Draft.Zip and SysinternalsSuite.zip, then PsExec64 to NASHUA with a plaintext password).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:35.069Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Program Files\SysinternalsSuite\passwordsDB | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoNRGHl | q-7f2ec55667 | ok |
| 2 | 2020-05-02 03:04:34.951Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\accesschk.exe" | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoNRGHW | q-34a1144b0c | ok |
| 3 | 2020-05-02 03:04:54.000Z | scranton.dmevals.local | windows.security | win.ObjectName | \REGISTRY\MACHINE\SYSTEM\ControlSet001\Control\Lsa | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBy4FbJN | q-46d894a4c4 | ok |
| 4 | 2020-05-02 03:04:54.000Z | scranton.dmevals.local | windows.security | win.AccessMask | 0x1 | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBy4FbJN | q-46d894a4c4 | ok |
| 5 | 2020-05-02 03:04:54.000Z | scranton.dmevals.local | windows.security | win.SubjectUserName | pbeesly | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBy4FbJN | q-46d894a4c4 | ok |
| 6 | 2020-05-02 03:04:54.000Z | scranton.dmevals.local | windows.security | win.ObjectName | \REGISTRY\MACHINE\SYSTEM\ControlSet001\Control\Lsa | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBy1A5nE | q-3ffe7e83d6 | ok |

### F61 · malicious / high · T1552 · accesschk.exe credential reconnaissance on scranton

Evidence status: **verified**

On scranton accesschk.exe was run by pbeesly's PowerShell at 03:04:34 and wrote passwordsDB, part of the credential-hunting toolkit.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:34.951Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\accesschk.exe" | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoNRGHW | q-a406ca9b70 | ok |
| 2 | 2020-05-02 03:04:35.069Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Program Files\SysinternalsSuite\passwordsDB | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoNRGHl | q-811152a628 | ok |

### F62 · malicious / high · T1552 · Masqueraded .scr stager in ProgramData\victim on scranton

Evidence status: **verified**

A masqueraded .scr in C:\ProgramData\victim was launched from explorer at 02:55:56 and spawned cmd/powershell, starting the hands-on-keyboard session.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:55:56.157Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\ProgramData\victim\â€®cod.3aka3.scr" /S | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBow1KRR | q-a406ca9b70 | ok |
| 2 | 2020-05-02 02:55:56.157Z | scranton.dmevals.local | windows.sysmon | process.parent.executable | C:\Windows\explorer.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBow1KRR | q-a406ca9b70 | ok |

### F63 · malicious / medium · T1552 · In-memory DLL compilation via csc.exe on scranton

Evidence status: **verified**

PowerShell on scranton invoked csc.exe twice to compile DLLs (qkbkqqbs.dll, 0piklvia.dll) in the user Temp directory.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:58:45.297Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe" /noconfig /fullpaths @"C:\Users\pbeesly\AppData\Local\Temp\qkbkqqbs\qkbkqqbs.cmdline" | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBorwNwU | q-a406ca9b70 | ok |

### F28 · malicious / high · T1552.001 · Plaintext password used on PsExec64 command line to reach NASHUA, then Rar.exe archives data with a hardcoded password

Evidence status: **verified**

On scranton.dmevals.local, pbeesly's PowerShell ran PsExec64.exe four times (03:11:18, 03:12:25, 03:13:28, 03:14:42Z) with the credential supplied in cleartext on the command line: -u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe. The same string appears in PowerShell 4104 script blocks. Each attempt produced a 4648 explicit-credential logon on nashua.dmevals.local with Process Name C:\Windows\PSEXESVC.exe and TargetUserName pbeesly, and C:\Windows\Temp\python.exe then executed on NASHUA under PSEXESVC.exe. On NASHUA at 03:16:19Z Rar.exe was run as 'a -hpfGzq5yKw C:\Users\pbeesly\Desktop\working.zip C:\Users\pbeesly\AppData\Roaming\working.zip', i.e. staging collected data into a password-protected archive, after which sdelete64.exe was used to wipe Rar.exe and the zips. Credentials embedded in command lines/scripts were used to move laterally and to protect exfiltrated data.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:18.784Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\PsExec64.exe" -accepteula \\NASHUA -u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoz4z4i | q-34a1144b0c | ok |
| 2 | 2020-05-02 03:11:18.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | .\PsExec64.exe -accepteula \\NASHUA -u "dmevals\pbeesly" -p "Fl0nk3rt0n!T0by" -i 2 "C:\Windows\Temp\python.exe" | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByCVdVX | q-c168fa5d14 | ok |
| 3 | 2020-05-02 03:11:40.000Z | nashua.dmevals.local | windows.security | win.ProcessName | C:\Windows\PSEXESVC.exe | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBuu5GRH | q-ecf904adc0 | ok |
| 4 | 2020-05-02 03:11:40.000Z | nashua.dmevals.local | windows.security | win.TargetUserName | pbeesly | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBuu5GRH | q-ecf904adc0 | ok |
| 5 | 2020-05-02 03:11:40.213Z | nashua.dmevals.local | windows.sysmon | process.command_line | "C:\Windows\Temp\python.exe"  | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoz4j7h | q-0c5e542dfd | ok |
| 6 | 2020-05-02 03:16:19.395Z | nashua.dmevals.local | windows.sysmon | process.command_line | "C:\Windows\Temp\Rar.exe" a -hpfGzq5yKw C:\Users\pbeesly\Desktop\working.zip C:\Users\pbeesly\AppData\Roaming\working.zip | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBow1qSj | q-0c5e542dfd | ok |

### F56 · malicious / high · T1552.001 · Plaintext password on PsExec64 command line reused against NASHUA

Evidence status: **verified**

pbeesly on scranton ran PsExec64 four times with -u dmevals\pbeesly -p Fl0nk3rt0n!T0by to launch python.exe on NASHUA.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:18.784Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\PsExec64.exe" -accepteula \\NASHUA -u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoz4z4i | q-a406ca9b70 | ok |

### F58 · malicious / high · T1552.001 · Credential-named file collection and password-protected archive on nashua

Evidence status: **verified**

On nashua PowerShell collected *pass*,*login*,*admin*,*vpn* files into working.zip, Rar.exe re-archived it with password fGzq5yKw, then sdelete64 wiped artifacts.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:15:59.000Z | nashua.dmevals.local | windows.powershell | win.ScriptBlockText | $env:APPDATA;$files=ChildItem -Path $env:USERPROFILE\ -Include *.doc,*.xps,*.xls,*.ppt,*.pps,*.wps,*.wpd,*.ods,*.odt,*.lwp,*.jtd,*.pdf,*.zip,*.rar,*.docx,*.url,… | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByDVjze | q-87498e0161 | ok |
| 2 | 2020-05-02 03:16:19.395Z | nashua.dmevals.local | windows.sysmon | process.command_line | "C:\Windows\Temp\Rar.exe" a -hpfGzq5yKw C:\Users\pbeesly\Desktop\working.zip C:\Users\pbeesly\AppData\Roaming\working.zip | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBow1qSj | q-50076c0b7c | ok |

### F60 · malicious / high · T1552.004 · Private-key export and exfil staging on scranton

Evidence status: **verified**

Get-PrivateKeys exported LocalMachine certs to .pfx and Invoke-Exfil compressed Downloads into OfficeSupplies.7z with password 'lolol'.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:57.460Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoMQkXH | q-811152a628 | ok |
| 2 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByPYrDh | q-d70255cf90 | ok |

### F57 · malicious / medium · T1555.003 · Browser processes opened with full access on nashua

Evidence status: **verified**

On nashua wsmprovhost (pbeesly) opened MicrosoftEdge.exe, MicrosoftEdgeCP.exe and MicrosoftEdgeSH.exe with 0x1f3fff at 03:09:29.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:09:29.446Z | nashua.dmevals.local | windows.sysmon | win.TargetImage | C:\Windows\SystemApps\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\MicrosoftEdge.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBox2Il2 | q-88b5a0a7f1 | ok |
| 2 | 2020-05-02 03:09:29.446Z | nashua.dmevals.local | windows.sysmon | win.TargetImage | C:\Windows\System32\MicrosoftEdgeCP.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBox2Il3 | q-88b5a0a7f1 | ok |

### F44 · malicious / high · T1558 · Credential theft on scranton: PowerShell full-access LSASS handle plus Kerberos ticket requests for krbtgt

Evidence status: **verified**

On scranton.dmevals.local a PowerShell process (PID 2976, launched 02:58:44Z as pbeesly from control.exe with '-noni -noexit -ep bypass -window hidden' and an IEX-decoded payload) opened lsass.exe with GrantedAccess 0x1f3fff and 0x1fffff at 03:05:16Z — full-access handles consistent with credential/ticket extraction. The same session ran discovery, persistence, private-key export, keystroke capture and exfil functions. On newyork.dmevals.local (DC) 4769 events show pbeesly@DMEVALS.LOCAL requesting a krbtgt service ticket at 03:04:04Z and SCRANTON$@DMEVALS.LOCAL requesting krbtgt tickets at 03:19:13Z and 03:19:15Z, all AES256 (0x12) and successful. The zeek capture (non-overlapping window) shows only normal AES256 AS/TGS for pbeesly, so no forged/downgraded tickets are visible there.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoMQUXI | q-d7e461e862 | ok |
| 2 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoMQUXF | q-9ea4ffe483 | ok |
| 3 | 2020-05-02 02:58:44.325Z | scranton.dmevals.local | windows.sysmon | process.command_line | "PowerShell.exe" -noni -noexit -ep bypass -window hidden -c "sal a New-Object;Add-Type -AssemblyName 'System.Drawing'; $g=a System.Drawing.Bitmap('C:\Users\pbee… | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBorwtwa | q-677756f18b | ok |
| 4 | 2020-05-02 03:04:04.000Z | newyork.dmevals.local | windows.security | win.ServiceName | krbtgt | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBy4FbJD | q-e1cc491a98 | ok |
| 5 | 2020-05-02 03:19:13.000Z | newyork.dmevals.local | windows.security | win.TargetUserName | SCRANTON$@DMEVALS.LOCAL | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBuw7KBe | q-b971461e4f | ok |
| 6 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByRaLqc | q-5c45c47419 | ok |

### F49 · malicious / high · T1606 · Credential theft and certificate/private-key export by PowerShell on SCRANTON (pbeesly) — no forged web credential observed

Evidence status: **verified**

On scranton.dmevals.local, user pbeesly ran an interactive PowerShell session (PID 2976, launched 02:58:44 from control.exe /name Microsoft.BackupAndRestoreCenter with -noni -noexit -ep bypass -window hidden and an IEX-decoded bitmap payload) that performed credential access: at 03:04:56 it defined and ran Get-PrivateKeys, which enumerates cert:\LocalMachine and exports each certificate with a thumbprint to a random .pfx file in the user's Downloads folder (coyn5igj.3io.pfx created 03:04:57); at 03:05:16 the same PowerShell.exe opened lsass.exe with GrantedAccess 0x1FFFFF (full access, call trace ending in an UNKNOWN module) and again with 0x1f3fff; it then ran screen capture (gwq4xdwv.s5g.bmp, 03:06:00), Get-Clipboard, Get-Keystrokes, and staged an archive at C:\Users\pbeesly\AppData\Roaming\OfficeSupplies.7z (03:08:35) with a cleanup function that deletes *.pfx/*.bmp/*.png and OfficeSupplies.7z. It then moved laterally to NASHUA with Invoke-Command and PsExec64 using the cleartext password for dmevals\pbeesly, producing 4648 explicit-credential logons on scranton (10.0.1.6) and PSEXESVC.exe logons on nashua. The stolen material (exported private keys/certificates, LSASS memory, keystrokes, clipboard) is the raw material for forging web credentials, but no forged cookie or SAML assertion was observed being used: no cookie/SAML/token strings in PowerShell 4104 script blocks, no SAML/ADFS/token URLs in Zeek HTTP, and the only cookie-path file event is a benign svchost INetCookies write. The technique family is therefore assessed as malicious credential access on the host, with the forging step itself not observed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoMQUXI | q-83f578e1dd | ok |
| 2 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoMQUXI | q-83f578e1dd | ok |
| 3 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoMQUXF | q-83f578e1dd | ok |
| 4 | 2020-05-02 02:58:44.325Z | scranton.dmevals.local | windows.sysmon | process.command_line | "PowerShell.exe" -noni -noexit -ep bypass -window hidden -c "sal a New-Object;Add-Type -AssemblyName 'System.Drawing'; $g=a System.Drawing.Bitmap('C:\Users\pbee… | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBorwtwa | q-659f812f34 | ok |
| 5 | 2020-05-02 03:04:57.460Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoMQkXH | q-e5b7ae3f11 | ok |
| 6 | 2020-05-02 03:08:35.270Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Users\pbeesly\AppData\Roaming\OfficeSupplies.7z | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBo05T5k | q-e5b7ae3f11 | ok |
| 7 | 2020-05-02 03:11:40.000Z | nashua.dmevals.local | windows.security | process.executable | C:\Windows\PSEXESVC.exe | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBuu5GRH | q-62449c65a1 | ok |

### F53 · malicious / high · T1649 · PowerShell Get-PrivateKeys exports all LocalMachine certificates to password-protected .pfx files on scranton.dmevals.local

Evidence status: **verified**

On scranton.dmevals.local, user pbeesly (SID S-1-5-21-1830255721-3727074217-2423397540-1107) executed a staged PowerShell chain: at 2020-05-01T23:03:49-04:00 'Move-Item .\readme.txt readme.ps1' renamed a file to a .ps1, at 23:03:57 '. .\readme.ps1' dot-sourced it, and at 23:04:56 the function 'Get-PrivateKeys' was defined and invoked. The script block (ScriptBlock ID 9d153741-75c3-4062-afe3-aeca0aee611b, Path C:\Program Files\SysinternalsSuite\readme.ps1) enumerates cert:\LocalMachine recursively and calls Export-PfxCertificate for every certificate with a thumbprint, writing to $env:USERPROFILE\Downloads\<random>.pfx protected by the hardcoded plaintext password 'saribas'. At 2020-05-02T03:04:57.460Z Sysmon recorded the resulting file C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx created by powershell.exe (PID 3876), and at 03:04:57.272-03:04:57.428Z the same powershell.exe (PID 3876) wrote certificate store blobs under HKLM\SOFTWARE\Microsoft\SystemCertificates\Remote Desktop\Certificates\615B93C2D2B647D1670500B3338EAAEC83BA5646\Blob and HKLM\SOFTWARE\Microsoft\SystemCertificates\MY\Certificates\48B5E43D09D080DF8863152FD22ED7C43443D499\Blob. This is theft of authentication certificates (including private keys) for later use/forgery. The other certificate-store registry writes in the window (lsass.exe, svchost.exe, smss.exe, taskhostw.exe, and the single 4657 on nashua.dmevals.local by NASHUA$ via C:\Windows\Sysmon.exe) are routine OS certificate-store maintenance and are not attacker activity.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByRaLqc | q-fb63d989b6 | ok |
| 2 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\readme.ps1 | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByRaLqc | q-fb63d989b6 | ok |
| 3 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | user.name | pbeesly | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByRaLqc | q-fb63d989b6 | ok |
| 4 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | process.command_line | Get-PrivateKeys | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByRaLrb | q-2f3eff0691 | ok |
| 5 | 2020-05-02 03:03:49.000Z | scranton.dmevals.local | windows.powershell | process.command_line | Move-Item .\readme.txt readme.ps1 | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByRarqv | q-2f3eff0691 | ok |
| 6 | 2020-05-02 03:03:57.000Z | scranton.dmevals.local | windows.powershell | process.command_line | . .\readme.ps1 | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByRaboh | q-2f3eff0691 | ok |
| 7 | 2020-05-02 03:04:57.460Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoMQkXH | q-ba4ef36d7b | ok |
| 8 | 2020-05-02 03:04:57.428Z | scranton.dmevals.local | windows.sysmon | registry.path | HKLM\SOFTWARE\Microsoft\SystemCertificates\MY\Certificates\48B5E43D09D080DF8863152FD22ED7C43443D499\Blob | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoMQkXN | q-43672a8d16 | ok |
| 9 | 2020-05-02 03:04:57.272Z | scranton.dmevals.local | windows.sysmon | registry.path | HKLM\SOFTWARE\Microsoft\SystemCertificates\Remote Desktop\Certificates\615B93C2D2B647D1670500B3338EAAEC83BA5646\Blob | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoNQ2BV | q-43672a8d16 | ok |

### F16 · suspicious / medium · T1110.002 · LSASS accessed with full access by PowerShell on scranton, but no cracking artifacts

Evidence status: **verified**

On scranton.dmevals.local at 2020-05-02T03:05:16.654Z the process C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe (PID 2976) opened C:\windows\system32\lsass.exe (PID 736) with GrantedAccess 0x1fffff, and a second handle with 0x1f3fff at 03:05:16.623Z; wsmprovhost.exe on nashua.dmevals.local also opened lsass with 0x1f3fff at 03:09:29.430Z. These are the only non-system, non-Azure-agent LSASS accesses with read/full masks (the 289 svchost.exe accesses are 0x1000 only). This is consistent with in-memory credential theft feeding offline cracking, but no cracking tooling, wordlists, potfiles or hash-conversion script blocks were found, so T1110.002 (password cracking) itself is not evidenced.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoMQUXI | q-91cf7dfa6d | ok |
| 2 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoMQUXF | q-46d48f5e72 | ok |
| 3 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBn663fz | q-46d48f5e72 | ok |
| 4 | 2020-05-02 03:01:03.622Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1000 | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoXbqWA | q-46d48f5e72 | ok |

### F25 · suspicious / medium · T1539 · PowerShell opened MicrosoftEdge.exe with full access (0x1FFFFF) on scranton.dmevals.local during a hands-on-keyboard intrusion

Evidence status: **verified**

On scranton.dmevals.local, in the same session where user pbeesly ran a hidden, encoded PowerShell stager (monkey.png bitmap-decoded IEX launched from control.exe at 02:58:44), a PowerShell.exe process (PID 2976) opened the Microsoft Edge browser process (PID 7748, C:\Windows\SystemApps\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\MicrosoftEdge.exe) with GrantedAccess 0x1FFFFF at 2020-05-02T03:05:17Z, and immediately afterwards opened MicrosoftEdgeSH.exe and MicrosoftEdgeCP.exe with the same full access. Full-process access to a browser is the prerequisite for reading session cookies out of browser memory. No cookie file access, cookie-named command line, or cookie-related script block was observed, so the theft itself is not proven; the surrounding activity (hidden encoded PowerShell, credential-file harvesting script, PsExec, sdelete) makes this access suspicious rather than benign.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:17.076Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoMQUWX | q-34be878ebe | ok |
| 2 | 2020-05-02 03:05:17.076Z | scranton.dmevals.local | windows.sysmon | win.TargetImage | C:\Windows\SystemApps\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\MicrosoftEdge.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoMQUWX | q-34be878ebe | ok |
| 3 | 2020-05-02 03:05:17.076Z | scranton.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoMQUWX | q-34be878ebe | ok |
| 4 | 2020-05-02 03:05:17.094Z | scranton.dmevals.local | windows.sysmon | win.TargetImage | C:\windows\system32\MicrosoftEdgeSH.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoMQUWe | q-34be878ebe | ok |
| 5 | 2020-05-02 03:05:17.094Z | scranton.dmevals.local | windows.sysmon | win.TargetImage | C:\Windows\System32\MicrosoftEdgeCP.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoMQUWf | q-34be878ebe | ok |
| 6 | 2020-05-02 02:58:44.325Z | scranton.dmevals.local | windows.sysmon | process.command_line | "PowerShell.exe" -noni -noexit -ep bypass -window hidden -c "sal a New-Object;Add-Type -AssemblyName 'System.Drawing'; $g=a System.Drawing.Bitmap('C:\Users\pbee… | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBorwtwa | q-a3de8c738c | ok |

### F64 · suspicious / medium · T1552 · hostui.exe launched with -verb runas for elevation

Evidence status: **verified**

At 03:21:27 pbeesly's PowerShell launched hostui.exe with -verb runas to force a UAC elevation prompt.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:21:27.276Z | scranton.dmevals.local | windows.sysmon | process.parent.command_line | powershell.exe  -c "Start-Process C:\Windows\System32\hostui.exe -verb runas" | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBi30hQJ | q-a406ca9b70 | ok |

### F65 · suspicious / low · T1552 · sdclt.exe spawned by cmd on scranton

Evidence status: **verified**

sdclt.exe, a known UAC-bypass binary, was spawned three times by cmd at 02:58:42 during the intrusion.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:58:42.401Z | scranton.dmevals.local | windows.sysmon | process.command_line | C:\windows\system32\sdclt.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBosxOR1 | q-a406ca9b70 | ok |

### F31 · suspicious / medium · T1555 · PowerShell and WinRM host processes opened LSASS with near-full access rights on scranton and nashua (pbeesly)

Evidence status: **verified**

On 2020-05-02, user pbeesly's PowerShell.exe (PID 2976) on scranton.dmevals.local opened lsass.exe (PID 736) with GrantedAccess 0x1f3fff at 03:05:16.623Z and 0x1fffff at 03:05:16.654Z, with a call trace ending in an UNKNOWN module (ntdll!NtOpenProcess -> KERNELBASE -> UNKNOWN), i.e. not a normal Windows component. Four minutes later, at 03:09:29.430Z, wsmprovhost.exe (PID 7720) on nashua.dmevals.local opened lsass.exe (PID 728) with 0x1f3fff, its call trace running through System.ni.dll and Microsoft.PowerShell.Commands.Management.ni.dll — a PowerShell/.NET code path, not a Windows service. These are the only two non-system processes in the whole dataset with such broad LSASS masks (all other LSASS handles are svchost 0x1000, Azure antimalware/telemetry 0x1400, plus wininit/csrss at boot). The same user ran a remote Invoke-Command to NASHUA at 03:09:23Z, immediately preceding the nashua LSASS access, and had network logons (type 3) to newyork and nashua. However, no credential-dumping tooling, dump file, or password-store artifact was observed: no sekurlsa/lsadump/mimikatz/procdump/comsvcs/minidump/vault/cmdkey/DPAPI/browser-store strings in any process command line, script block, file path or object-access event. The activity is consistent with in-memory credential access via PowerShell, but the technique family (password stores) is not directly evidenced.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoMQUXI | q-8187f335d2 | ok |
| 2 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoMQUXI | q-8187f335d2 | ok |
| 3 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.CallTrace | C:\windows\SYSTEM32\ntdll.dll+9c584\|C:\windows\System32\KERNELBASE.dll+2732e\|UNKNOWN(000001996D28200D) | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoMQUXI | q-d2e9732a7f | ok |
| 4 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBn663fz | q-8187f335d2 | ok |
| 5 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBn663fz | q-7892708f7d | ok |
| 6 | 2020-05-02 03:09:23.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | Invoke-Command -ComputerName NASHUA -ScriptBlock { Get-Process -IncludeUserName \| Select-Object UserName,SessionId \| Where-Object { $_.UserName -like "*\$env:… | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByEVwPJ | q-ae4b1b1d87 | ok |
| 7 | 2020-05-02 03:09:23.000Z | nashua.dmevals.local | windows.security | process.command_line | C:\windows\system32\wsmprovhost.exe -Embedding | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBuv5SEZ | q-669157b78f | ok |

### F51 · suspicious / medium · T1606.002 · No SAML token forgery observed; certificate/private-key export is the closest precursor

Evidence status: **verified**

No SAML assertion, NotOnOrAfter or Assertion strings appear in PowerShell 4104 script blocks, no process command line references saml/token/cert, and no Zeek HTTP request targets saml/adfs/token URLs. However, on scranton.dmevals.local the attacker-run PowerShell executed Get-PrivateKeys at 03:04:56, exporting every LocalMachine certificate with a thumbprint to random .pfx files (coyn5igj.3io.pfx at 03:04:57) using the hardcoded password 'saribas' — private keys and certificates are exactly the material used to sign forged SAML tokens, so this is a plausible precursor, but the forging/use of a token itself was not observed in these datasets.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:57.460Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoMQkXH | q-e5b7ae3f11 | ok |
| 2 | 2020-05-02 03:04:57.460Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\WindowsPowerShell\v1.0\powershell.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoMQkXH | q-e5b7ae3f11 | ok |
| 3 | 2020-05-02 03:06:00.421Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Users\pbeesly\Downloads\gwq4xdwv.s5g.bmp | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoHL6FX | q-e5b7ae3f11 | ok |

### F02 · benign / medium · T1003.002 · SAM database and SAM_DOMAIN/SAM_SERVER handles opened by lsass.exe on scranton (system-account context, no attacker tooling)

Evidence status: **verified**

On scranton.dmevals.local at 2020-05-01T23:19:10-23:19:22 (local, = 03:19 UTC) lsass.exe running as SCRANTON$ (S-1-5-18, logon 0x3E7) requested handles to SAM_SERVER 'SAM' (0xf003f), SAM_DOMAIN 'SCRANTON' (0xf07df) and SAM_ALIAS 'DOMAINS\Builtin\Aliases\00000221' (0xf), and wrote HKLM\SAM\SAM\Domains\Account\F. This is the local LSA/SAM service itself, not an external dumping tool: no reg save of HKLM\SAM/SECURITY, no esentutl/ntdsutil, and no SAM/SECURITY hive file copies were found (the only file-create hits matching SAM/SECURITY were Prefetch .pf files). The SAM access coincides with an lsass.exe restart on the host (lsass.exe process create at 03:19:09.809, LsaPid write 0x2ec, CredentialGuard Enabled=0), i.e. normal LSA initialization. No evidence of an adversary extracting local account hashes.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:21.000Z | scranton.dmevals.local | windows.security | win.ObjectName | SAM | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBudp5HI | q-2a6ecde853 | ok |
| 2 | 2020-05-02 03:19:21.000Z | scranton.dmevals.local | windows.security | win.AccessMask | 0xf07df | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBuWmZPb | q-2a6ecde853 | ok |
| 3 | 2020-05-02 03:19:11.000Z | scranton.dmevals.local | windows.security | win.ObjectType | SAM_ALIAS | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBuv695R | q-2a6ecde853 | ok |
| 4 | 2020-05-02 03:19:10.368Z | scranton.dmevals.local | windows.sysmon | registry.path | HKLM\SAM\SAM\Domains\Account\F | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBnqqYem | q-0247f87418 | ok |
| 5 | 2020-05-02 03:19:09.834Z | scranton.dmevals.local | windows.sysmon | registry.path | HKLM\System\CurrentControlSet\Control\Lsa\LsaPid | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBnaXZbu | q-0247f87418 | ok |

### F04 · benign / medium · T1003.003 · No NTDS.dit / volume-shadow / ntdsutil activity observed

Evidence status: **verified**

Searches for NTDS file creation, ntdsutil/vssadmin/diskshadow command lines in Sysmon and Security 4688, and for shadow/VSS/ntds strings in windows.other and PowerShell script blocks returned no hits. The only domain-controller-like host in scope (newyork) shows only routine service activity (UsoClient, dsregcmd, W32Time). No evidence of NTDS extraction.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:06:14.652Z | newyork.dmevals.local | windows.sysmon | process.command_line | C:\windows\System32\dsregcmd.exe $(Arg0) $(Arg1) $(Arg2) | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoGKqgM | q-4d190c2982 | ok |

### F05 · benign / medium · T1003.004 · No LSA Secrets / SECURITY hive dumping observed

Evidence status: **verified**

No process creations with secrets/lsadump/reg save HKLM\SECURITY, no 4656/4663/4670 events on SECURITY Policy Secrets objects, and no PowerShell or windows.other messages referencing LSA secrets were found. The only SECURITY-related registry activity was lsass.exe writing HKLM\SECURITY\Cache\NL$1 on nashua (see T1003.005).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:09.865Z | scranton.dmevals.local | windows.sysmon | registry.path | HKLM\System\CurrentControlSet\Control\DeviceGuard\Scenarios\CredentialGuard\Enabled | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBnfdUsq | q-0247f87418 | ok |

### F03 · benign / medium · T1003.005 · HKLM\SECURITY\Cache\NL$1 writes by lsass.exe on nashua — normal cached-credential maintenance, not dumping

Evidence status: **verified**

On nashua.dmevals.local, lsass.exe (PID 728) set the value HKLM\SECURITY\Cache\NL$1 to 'Binary Data' at 03:11:40, 03:12:46, 03:13:49 and 03:15:03 on 2020-05-02. These are writes by the LSA process itself to the cached-domain-credential cache, consistent with normal logon/cache updates (the same host was being accessed by pbeesly around this time), not an external read of the cache. No security-audit handle events on SECURITY\Cache objects and no PowerShell referencing mscache/DCC2 were found, so there is no evidence of cached credential extraction.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:40.144Z | nashua.dmevals.local | windows.sysmon | registry.path | HKLM\SECURITY\Cache\NL$1 | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBox14nu | q-4223fee7d3 | ok |
| 2 | 2020-05-02 03:12:46.768Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBn44l3s | q-4223fee7d3 | ok |

### F06 · benign / medium · T1003.006 · No DCSync / DRSUAPI replication abuse observed

Evidence status: **verified**

No process command lines containing drsuapi/lsadump/dcsync and no PowerShell script blocks referencing DCSync/lsadump/drsuapi were found. The attacker's PowerShell activity on scranton/nashua focused on keystroke logging, screen capture, clipboard, private-key export and exfiltration, plus PsExec to NASHUA with plaintext credentials, but no directory replication request was observed in the available telemetry.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:18.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | .\PsExec64.exe -accepteula \\NASHUA -u "dmevals\pbeesly" -p "Fl0nk3rt0n!T0by" -i 2 "C:\Windows\Temp\python.exe" | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByCVdVX | q-c264e2de9c | ok |

### F07 · benign / high · T1040 · Azure Network Watcher agent performs netsh packet capture on SCRANTON (platform telemetry, not adversary sniffing)

Evidence status: **verified**

On scranton.dmevals.local at 2020-05-02T03:19:17Z, netsh.exe was launched as NT AUTHORITY\SYSTEM (LogonId 0x3e7, session 0) with 'trace start capture=yes traceFile="C:\windows\TEMP\E7116ECA-DFE6-43C7-8FA8-8D3AC5AA8726\B91E06C5-1C7C-4830-9A76-74FA211560A7.etl"' and stopped at 03:19:24Z with 'netsh trace stop'. The parent is the Microsoft Azure NetworkWatcherAgent service (C:\Packages\Plugins\Microsoft.Azure.NetworkWatcher.NetworkWatcherAgentWindows\1.4.1421.1\NetworkWatcherAgent\NetworkWatcherAgent.exe /service), which was itself installed/started as a service on the same host minutes earlier (4688 'Install /service /autoStart', 'Test /service /autoStart', '/service'). This is the Azure platform's own packet-capture capability, not attacker-driven sniffing: no pcap/npcap/winpcap driver load, no tcpdump/windump/wireshark/rawcap execution, and no sniff/promiscuous command lines were found anywhere in the Windows telemetry.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:17.154Z | scranton.dmevals.local | windows.sysmon | process.command_line | C:\windows\system32\netsh.exe trace start capture=yes traceFile="C:\windows\TEMP\E7116ECA-DFE6-43C7-8FA8-8D3AC5AA8726\B91E06C5-1C7C-4830-9A76-74FA211560A7.etl" | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBnvvDAD | q-1c5b8b6b31 | ok |
| 2 | 2020-05-02 03:19:17.154Z | scranton.dmevals.local | windows.sysmon | process.parent.executable | C:\Packages\Plugins\Microsoft.Azure.NetworkWatcher.NetworkWatcherAgentWindows\1.4.1421.1\NetworkWatcherAgent\NetworkWatcherAgent.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBnvvDAD | q-a78d796593 | ok |
| 3 | 2020-05-02 03:19:24.835Z | scranton.dmevals.local | windows.sysmon | process.command_line | C:\windows\system32\netsh.exe trace stop | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBnkjXIW | q-1c5b8b6b31 | ok |
| 4 | 2020-05-02 03:20:41.000Z | scranton.dmevals.local | windows.security | process.command_line | "C:\Packages\Plugins\Microsoft.Azure.NetworkWatcher.NetworkWatcherAgentWindows\1.4.1421.1\NetworkWatcherAgent\NetworkWatcherAgent.exe"  Install /service /autoSt… | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBufr2mN | q-386c7ae461 | ok |

### F08 · benign / medium · T1040 · No adversary network-sniffing tooling observed; the real intrusion on NASHUA used a PyInstaller python.exe beacon, not a sniffer

Evidence status: **verified**

Hunting for T1040-specific artifacts across windows.sysmon, windows.security and windows.powershell returned nothing: no tcpdump/windump/wireshark/rawcap process creation, no pcap/npcap/winpcap image loads (sysmon event 6 aggregation on win.Image returned 0 buckets), no sniff/promisc/pcap command lines, and no capture-driver service installs (the only 7045 services were a Java support service and PSEXESVC). The genuine compromise in this window is separate from sniffing: on scranton.dmevals.local user pbeesly ran a hidden, encoded PowerShell stager (monkey.png bitmap decode + IEX), then 'Invoke-SeaDukeStage -ComputerName NASHUA' and repeated PsExec64 with plaintext credentials (\\NASHUA -u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe), which spawned PSEXESVC and C:\Windows\Temp\python.exe on nashua.dmevals.local (SHA256 43782EC4337D8F3DDB7EA0C451B3BC4F212F84C8D5571BD0A842001C859A02AE) that unpacked a PyInstaller bundle to _MEI29522 and opened many TCP connections to 192.168.0.4:8443. That is C2/lateral movement, not passive network sniffing, so T1040 is not supported by the evidence.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:10:22.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | Invoke-SeaDukeStage -ComputerName NASHUA | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByDV_QB | q-17fcfe7984 | ok |
| 2 | 2020-05-02 03:11:18.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | .\PsExec64.exe -accepteula \\NASHUA -u "dmevals\pbeesly" -p "Fl0nk3rt0n!T0by" -i 2 "C:\Windows\Temp\python.exe" | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByCVdVX | q-2d6f9adf03 | ok |
| 3 | 2020-05-02 03:11:40.213Z | nashua.dmevals.local | windows.sysmon | process.parent.executable | C:\Windows\PSEXESVC.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoz4j7h | q-13bc2bb9bc | ok |
| 4 | 2020-05-02 03:15:05.142Z | nashua.dmevals.local | windows.sysmon | destination.port | 8443 | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBnyzTy7 | q-2909de4eec | ok |
| 5 | 2020-05-02 03:15:04.135Z | nashua.dmevals.local | windows.sysmon | win.TargetFilename | C:\Users\pbeesly\AppData\Local\Temp\_MEI29522 | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBow16Q8 | q-65393b3954 | ok |

### F10 · benign / medium · T1056 · LSASS handle requests and SAM object access on scranton/nashua are OS-internal or benign PowerShell cmdlet activity

Evidence status: **verified**

The 4656 handle-request hits to lsass.exe/SAM are dominated by legitimate system activity: lsass.exe itself opening SAM_SERVER (AccessMask 0xf003f, subject SCRANTON$ logon 0x3E7), Windows Defender MsMpEng.exe, Azure CollectGuestLogs.exe, and svchost.exe. The one non-OS LSASS open outside scranton's malicious PowerShell was wsmprovhost.exe on nashua.dmevals.local at 03:09:29Z with 0x1F3FFF, but its call trace runs through System.ni.dll and Microsoft.PowerShell.Commands.Management.ni.dll and coincides with the benign script block 'Get-Process -IncludeUserName \| Select-Object UserName,SessionId' at 03:09:28-29Z, i.e. a PowerShell cmdlet enumerating process owners rather than credential theft. The remaining LSASS opens (svchost 0x1000 x286, AntimalwareConfig.exe/WindowsAzureTelemetryService.exe 0x1400) are standard.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:21.000Z | scranton.dmevals.local | windows.security | win.ObjectType | SAM_SERVER | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBudp5HI | q-18382da5de | ok |
| 2 | 2020-05-02 03:19:21.000Z | scranton.dmevals.local | windows.security | win.AccessMask | 0xf003f | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBudp5HI | q-18382da5de | ok |
| 3 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBn663fz | q-9e886773ee | ok |
| 4 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBn663fz | q-9e886773ee | ok |
| 5 | 2020-05-02 03:09:28.000Z | nashua.dmevals.local | windows.powershell | win.ScriptBlockText |  Get-Process -IncludeUserName \| Select-Object UserName,SessionId \| Where-Object { $_.UserName -like "*\$env:USERNAME" } \| Sort-Object SessionId -Unique  | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByCVtlI | q-d790701ca9 | ok |

### F11 · benign / medium · T1056.001 · No keylogger artifacts (GetAsyncKeyState/SetWindowsHookEx/keylog files) observed

Evidence status: **verified**

No process creation with keylogging command lines (GetAsyncKeyState, SetWindowsHookEx, keylog) and no file writes matching keylog/hook/capture paths were found in windows.sysmon; the only matching file write was monkey.png, which is the steganographic payload carrier for the PowerShell loader, not a keystroke log. No keylogger behaviour is evidenced in the available telemetry.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:57:00.933Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Users\pbeesly\Downloads\monkey.png | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBouy-nD | q-2df377002a | ok |

### F12 · benign / medium · T1056.002 · No GUI credential-prompt capture observed

Evidence status: **verified**

No 4688 process creations with Credential/prompt command lines and no PowerShell script blocks using Get-Credential/Read-Host/prompt were found. The only credential object in the data is a hardcoded PSCredential ('cozy' / 'MyCozyPassw0rd!') inside the Invoke-Exfil function on scranton, used to map a WebDAV share for exfiltration — not a GUI input-capture prompt.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByPYrDh | q-8118f843e6 | ok |

### F13 · benign / medium · T1056.003 · No web portal capture (IIS/wwwroot/login page tampering) observed

Evidence status: **verified**

No file writes to wwwroot/inetpub/login/portal paths, no iis/w3wp process command lines, no 4663 object access to wwwroot/inetpub/login, and no PowerShell script blocks referencing wwwroot/login. The zeek dataset (2020-04-30) does not overlap the Windows window and contained no HTTP POSTs, so web portal capture is not evidenced.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:57:00.933Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Users\pbeesly\Downloads\monkey.png | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBouy-nD | q-2df377002a | ok |

### F14 · benign / high · T1110 · No brute-force authentication activity; credential theft on scranton/nashua used other means

Evidence status: **verified**

Across windows.security (2020-05-02T02:55:25Z..03:28:09Z) there are no 4625 failed-logon events, no 4771/4776 failure codes and no 4740 lockouts: the only 4776 credential-validation event is a success (Error Code 0x0) for pbeesly from workstation 10.0.1.4 on newyork.dmevals.local at 23:20:40. Successful network logons (4624 type 3) come from a small set of internal addresses (::1, 10.0.1.4, 10.0.1.6, 10.0.0.4, 10.0.1.5, 10.0.1.10, 172.18.39.2) with no repeated-failure pattern, and the windows.other channel contains no lockout or failed-auth messages (only a crash-dump init failure and a DNS PTR registration failure). The credential access that did occur on these hosts (LSASS handle opens, keystroke capture, private-key export) is not brute force, so T1110 itself is not observed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:20:40.000Z | newyork.dmevals.local | windows.security | message | The computer attempted to validate the credentials for an account.    Authentication Package:	MICROSOFT_AUTHENTICATION_PACKAGE_V1_0  Logon Account:	pbeesly  Sou… | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBuTlU_q | q-59491a9664 | ok |
| 2 | 2020-05-02 03:18:54.000Z | scranton.dmevals.local | windows.other | message | Crash dump initialization failed! | .ds-logs-windows.other-default-2026.10.22-000001 / AaFiKJc9VXKkeBwdMB0P | q-e057b4cf9e | ok |

### F15 · benign / high · T1110.001 · No password-guessing failures; only successful credential validation observed

Evidence status: **verified**

Password guessing would produce bursts of 4625 events with varied target accounts, but windows.security contains zero 4625 events in the window and the single 4776 on newyork.dmevals.local at 23:20:40 is a successful validation of pbeesly (Error Code 0x0) from 10.0.1.4. No process command lines referencing passwords were found in sysmon process creation, and no PowerShell script blocks referencing Password/Credential were found. The interactive PowerShell work on scranton by pbeesly (Sysinternals suite, Invoke-Discovery, Invoke-Persistence, Get-PrivateKeys, Get-Keystrokes) is hands-on-keyboard activity, not password guessing.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:20:40.000Z | newyork.dmevals.local | windows.security | win.TargetUserName | pbeesly | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBuTlU_q | q-59491a9664 | ok |
| 2 | 2020-05-02 03:06:59.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | Get-Keystrokes;Start-Sleep -Seconds 15;View-Job -JobName "Keystrokes" | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByRaLr9 | q-cdfbf4a968 | ok |

### F17 · benign / high · T1110.003 · No password spraying: no failed logons, no account lockouts, no user-list tooling

Evidence status: **verified**

Spraying would show many 4625s across accounts from one source; windows.security has none, and windows.other has no lockout messages. The 4648 explicit-credential logons are pbeesly re-authenticating from 10.0.1.6 to scranton and PSEXESVC.exe on nashua.dmevals.local (23:11:18-23:15:03) plus normal DWM/UMFD/winlogon/taskhostw system logons on scranton at 23:19-23:20, i.e. lateral movement with already-known credentials rather than guessing. The only command line referencing 'user' is C:\windows\system32\userinit.exe, and the nashua PowerShell only enumerated its own sessions (Get-Process -IncludeUserName filtered on $env:USERNAME).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:40.000Z | nashua.dmevals.local | windows.security | process.executable | C:\Windows\PSEXESVC.exe | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBuu5GRH | q-5201e9bdec | ok |
| 2 | 2020-05-02 03:11:39.000Z | nashua.dmevals.local | windows.other | message | A service was installed in the system.    Service Name:  PSEXESVC  Service File Name:  %SystemRoot%\PSEXESVC.exe  Service Type:  user mode service  Service Star… | .ds-logs-windows.other-default-2026.10.22-000001 / AaFiKJc9VXKkeBwdMB0i | q-58634eef9f | ok |
| 3 | 2020-05-02 03:09:28.000Z | nashua.dmevals.local | windows.powershell | win.ScriptBlockText |  Get-Process -IncludeUserName \| Select-Object UserName,SessionId \| Where-Object { $_.UserName -like "*\$env:USERNAME" } \| Sort-Object SessionId -Unique  | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByCVtlI | q-fb3ded11cd | ok |

### F18 · benign / high · T1110.004 · No credential stuffing; stolen secrets were harvested locally (keystrokes, private keys, files)

Evidence status: **verified**

No 4625 failures or lockouts exist to indicate replay of credential lists against the hosts. Instead, on scranton.dmevals.local pbeesly ran Get-PrivateKeys (exporting cert:\LocalMachine private keys to .pfx using ConvertTo-SecureString -String "saribas"), Get-Keystrokes and Invoke-ScreenCapture, and on nashua.dmevals.local pbeesly archived files matching *pass*, *login*, *vpn, *sifr* into working.zip and then ran Rar.exe with a password. These are credential-collection actions, not credential stuffing, so T1110.004 is not observed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByRaLqc | q-3ad32b7687 | ok |
| 2 | 2020-05-02 03:15:59.000Z | nashua.dmevals.local | windows.powershell | win.ScriptBlockText | $env:APPDATA;$files=ChildItem -Path $env:USERPROFILE\ -Include *.doc,*.xps,*.xls,*.ppt,*.pps,*.wps,*.wpd,*.ods,*.odt,*.lwp,*.jtd,*.pdf,*.zip,*.rar,*.docx,*.url,… | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByDVjze | q-fb3ded11cd | ok |
| 3 | 2020-05-02 03:16:19.000Z | nashua.dmevals.local | windows.powershell | win.ScriptBlockText | .\Rar.exe a -hpfGzq5yKw "$env:USERPROFILE\Desktop\working.zip" "$env:APPDATA\working.zip" | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByCVMj0 | q-fb3ded11cd | ok |

### F19 · benign / medium · T1111 · No MFA interception artifacts; credential access observed is LSASS memory access (T1003.001), not MFA token theft

Evidence status: **verified**

The T1111 hypothesis is not supported by the retrieved data. The 4648 explicit-credential logons (15 total) are dominated by the compromised account pbeesly (9 events) used by PSEXESVC.exe on nashua.dmevals.local and by svchost.exe on scranton.dmevals.local, plus routine DWM-/UMFD-/machine-account logons from winlogon.exe/wininit.exe/taskhostw.exe. The 'Credential' registry hits (11 Sysmon 13 events) are all Windows servicing noise: lsass.exe setting DeviceGuard\Scenarios\CredentialGuard\Enabled to 0x00000000 and services.exe creating the CredentialEnrollmentManagerUserSvc_13619b service plus MuiCache entries. windows.other shows only 'Credential Guard configuration: 0x0, 0' (event 14) and an unrelated DNS PTR registration failure. No smart-card, token, OTP, or MFA-provider interception activity was found. The genuine credential-access activity in this window is LSASS memory access: on nashua.dmevals.local wsmprovhost.exe (PID 7720, WinRM remote shell) opened lsass.exe (PID 728) with GrantedAccess 0x1f3fff and a PowerShell/System.ni.dll call trace at 2020-05-02T03:09:29Z, and on scranton.dmevals.local powershell.exe (PID 3876) accessed lsass.exe with GrantedAccess 0x1000 at 03:01:03Z. This is credential dumping (T1003.001), not MFA interception, so T1111 is assessed benign/not observed while the underlying credential theft is real.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBn663fz | q-f9bad7c42c | ok |
| 2 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBn663fz | q-f9bad7c42c | ok |
| 3 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.TargetImage | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBn663fz | q-f9bad7c42c | ok |
| 4 | 2020-05-02 03:01:03.622Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1000 | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoXbqWA | q-f9bad7c42c | ok |
| 5 | 2020-05-02 03:11:40.000Z | nashua.dmevals.local | windows.security | process.executable | C:\Windows\PSEXESVC.exe | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBuu5GRH | q-297f0bbc06 | ok |
| 6 | 2020-05-02 03:11:40.000Z | nashua.dmevals.local | windows.security | win.TargetUserName | pbeesly | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBuu5GRH | q-297f0bbc06 | ok |
| 7 | 2020-05-02 03:19:09.865Z | scranton.dmevals.local | windows.sysmon | win.TargetObject | HKLM\System\CurrentControlSet\Control\DeviceGuard\Scenarios\CredentialGuard\Enabled | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBnfdUsq | q-6acc84e640 | ok |
| 8 | 2020-05-02 03:20:48.264Z | scranton.dmevals.local | windows.sysmon | win.Details | C:\windows\system32\CredentialEnrollmentManager.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBnQM1oU | q-6acc84e640 | ok |
| 9 | 2020-05-02 03:19:09.000Z | scranton.dmevals.local | windows.other | message | Credential Guard configuration: 0x0, 0 | .ds-logs-windows.other-default-2026.10.22-000001 / AaFiKJc9VXKkeBwdMB1A | q-39d7464c05 | ok |
| 10 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByPYrDh | q-b7ebf73c1c | ok |

### F21 · benign / medium · T1187 · Routine domain SMB/SYSVOL/IPC$ share access and System-process SMB connections are benign background activity

Evidence status: **verified**

The bulk of the T1187 check hits are normal domain operations, not forced authentication. Of 163 share-access events (5140/5145), the shares are only \\*\SYSVOL (69), \\*\IPC$ (65) and \\*\ADMIN$ (29) - standard Group Policy replication and remote-management shares. Many are machine-account authentications (NEWYORK$, SCRANTON$) over IPv6 link-local fe80::e40c:95b6:b0a7:6429 or from 10.0.1.4, matching DFSR/GPO traffic. The 66 Sysmon event.code 3 hits on ports 445/139 all come from process.executable 'System' (PID 4) to 10.0.0.4, 10.0.1.6 and the local link-local address, i.e. kernel SMB client/server traffic, not a user-mode coercer. The 1649 Sysmon file-creation events are dominated by prefetch, EventLog lastalive*.dat, DFSR replica XML, GroupPolicy DataStore and Cortana cache files - no .lnk/.scf/.url/.library-ms coercion files were observed. Zeek SMB connections (45 to 445, 5 to 139) are internal host-to-host traffic. The PowerShell (4104) and windows.other checks for 445/WebDAV/NTLM returned zero hits. Only the 10.0.1.4 -> 192.168.0.4 WebDAV sequence is anomalous; the remaining share and SMB activity is consistent with normal AD administration.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:56:47.000Z | newyork.dmevals.local | windows.security | win.ShareName | \\*\SYSVOL | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBy7JbTW | q-3a1eca9fb6 | ok |
| 2 | 2020-05-02 02:56:47.000Z | newyork.dmevals.local | windows.security | user.name | NEWYORK$ | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBy7JbTW | q-3a1eca9fb6 | ok |
| 3 | 2020-05-02 03:01:43.033Z | scranton.dmevals.local | windows.sysmon | process.executable | System | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoSWKN8 | q-b7c2867b60 | ok |
| 4 | 2020-05-02 03:01:43.033Z | scranton.dmevals.local | windows.sysmon | destination.ip | 10.0.0.4 | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoSWKN8 | q-b7c2867b60 | ok |

### F24 · benign / high · T1212 · Remaining lsass process-access events are legitimate Windows LSA/AV/telemetry behaviour

Evidence status: **verified**

Of 326 Sysmon event-10 accesses to lsass.exe, 289 come from svchost.exe and the rest from AntimalwareConfig.exe (15), WindowsAzureTelemetryService.exe (13), wininit.exe (2), csrss.exe (1) and services.exe (1) — normal LSA, AV and Azure guest-agent activity. The rare masks are also benign: the svchost 0x101001 access on scranton at 03:18:34Z has a call trace entirely through c:\windows\system32\lsm.dll (the LSA policy provider), and the wininit/csrss 0x1FFFFF/0x1000000 accesses at 03:19:09Z are the standard boot-time lsass initialisation by its parent processes. The two PowerShell 0x1000 accesses (read-only, VM_READ) are not credential-dumping rights. No exploit artefacts were found in windows.other (no 'exploit' messages) or in PowerShell script blocks (no Invoke-*/Exploit matches), and the Zeek notices/weirds are from a non-overlapping 2020-04-30 window with no credential-access content.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:18:34.438Z | scranton.dmevals.local | windows.sysmon | win.CallTrace | C:\windows\SYSTEM32\ntdll.dll+9def4\|c:\windows\system32\lsm.dll+1aa6e\|c:\windows\system32\lsm.dll+1a9c3\|c:\windows\system32\lsm.dll+65e1\|c:\windows\system32… | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBnrrZmZ | q-1bd76db01c | ok |
| 2 | 2020-05-02 03:18:34.438Z | scranton.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\svchost.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBnrrZmZ | q-1bd76db01c | ok |
| 3 | 2020-05-02 03:19:09.803Z | scranton.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\csrss.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBnqqYet | q-4b892f3097 | ok |

### F26 · benign / high · T1539 · Benign browser cookie-store and cookie-URL artifacts (INetCookies file creation, davclnt DavSetCookie, Edge memory access by Explorer/svchost)

Evidence status: **verified**

The remaining T1539 hits are normal Windows behaviour: (1) svchost.exe (SYSTEM) created C:\Windows\ServiceProfiles\LocalService\...\warp_jit_...\AC\INetCookies on scranton.dmevals.local at 03:21:05Z, a WARP/AppContainer cookie store file, not a browser profile cookie DB; (2) five 4688 events on scranton.dmevals.local show rundll32.exe C:\windows\system32\davclnt.dll,DavSetCookie 192.168.0.4 http://192.168.0.4/webdav under pbeesly — the WebDAV client setting a cookie for a WebDAV share, not theft; (3) the bulk of Edge process-access events (Sysmon 10) come from Explorer.EXE (0x2000) and svchost.exe/sysmain (0x3000) on scranton and nashua, i.e. shell and prefetch/superfetch activity. No cookie database file access, no cookie-related script block (4104) and no cookie-related windows.other message was found.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:21:05.681Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Windows\ServiceProfiles\LocalService\AppData\Local\Packages\warp_jit_db4a1097-b484-4973-bbf2-a04208ecd4d4\AC\INetCookies | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBi-6ySm | q-4b7476811f | ok |
| 2 | 2020-05-02 03:08:50.000Z | scranton.dmevals.local | windows.security | process.command_line | rundll32.exe C:\windows\system32\davclnt.dll,DavSetCookie 192.168.0.4 http://192.168.0.4/webdav | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBur1GH0 | q-a90e0a1778 | ok |
| 3 | 2020-05-02 02:55:59.199Z | scranton.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\Explorer.EXE | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBow06T9 | q-90b7b676ad | ok |
| 4 | 2020-05-02 02:57:28.777Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x3000 | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBotx_LQ | q-90b7b676ad | ok |

### F29 · benign / medium · T1552.002 · Registry Password/Credential value sets are Windows service and identity-provider noise

Evidence status: **verified**

The 17 Sysmon 13 hits on registry paths containing Password/Credential are all written by legitimate system processes: svchost.exe setting HKU\.DEFAULT\Software\Microsoft\IdentityCRL\ProviderPasswordLength / ProviderPasswordCharacterGroups on nashua and scranton, lsass.exe setting DeviceGuard\Scenarios\CredentialGuard\Enabled to 0 on scranton, services.exe creating the CredentialEnrollmentManagerUserSvc_13619b service values, and winlogon.exe writing PasswordExpiryNotification\NotShownTime. None of these are credential harvesting; the only genuine registry credential access observed is accesschk.exe reading the LSA key, reported under T1552.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:28.255Z | nashua.dmevals.local | windows.sysmon | win.TargetObject | HKU\.DEFAULT\Software\Microsoft\IdentityCRL\ProviderPasswordLength | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoKOGL_ | q-4d5d637cba | ok |
| 2 | 2020-05-02 03:19:09.865Z | scranton.dmevals.local | windows.sysmon | win.TargetObject | HKLM\System\CurrentControlSet\Control\DeviceGuard\Scenarios\CredentialGuard\Enabled | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBnfdUsq | q-4d5d637cba | ok |
| 3 | 2020-05-02 03:20:48.264Z | scranton.dmevals.local | windows.sysmon | win.TargetObject | HKLM\System\CurrentControlSet\Services\CredentialEnrollmentManagerUserSvc_13619b\Type | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBnQM1oP | q-4d5d637cba | ok |

### F30 · benign / medium · T1552.006 · SYSVOL GptTmpl.inf / gpt.ini reads are routine Group Policy processing, not GPP credential harvesting

Evidence status: **verified**

Zeek smb_files shows two hosts (simplerockbuild.simplerock.lan 10.0.1.4 at 2020-04-30T00:12:01Z and bobs.bigwheel.local 10.0.1.6 at 00:20:49Z) opening \\NEWYORK.dmevals.local\sysvol paths gpt.ini, Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf and the policy folder tree. These are the standard files a domain member reads during Group Policy refresh; no Groups.xml, Services.xml or ScheduledTasks.xml with cpassword was accessed, and the zeek window (2020-04-30) does not overlap the Windows host telemetry (2020-05-02). No GPP-embedded credential access is evidenced.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-04-30 00:12:01.659Z | simplerockbuild.simplerock.lan | zeek | zeek.name | dmevals.local\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\gpt.ini | .ds-logs-zeek-default-2026.10.22-000001 / AaFiKZc9VXKkeBwkgR8g | q-a61aa30d0c | ok |
| 2 | 2020-04-30 00:12:01.673Z | simplerockbuild.simplerock.lan | zeek | zeek.name | dmevals.local\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf | .ds-logs-zeek-default-2026.10.22-000001 / AaFiKZc9VXKkeBwkgh8M | q-a61aa30d0c | ok |
| 3 | 2020-04-30 00:20:49.313Z | bobs.bigwheel.local | zeek | zeek.path | \\NEWYORK.dmevals.local\sysvol | .ds-logs-zeek-default-2026.10.22-000001 / AaFiKZc9VXKkeByNiUGh | q-a61aa30d0c | ok |

### F32 · benign / medium · T1555.004 · LSASS handle activity is dominated by Windows/Azure components; no Credential Manager (vault/cmdkey/DPAPI) access

Evidence status: **verified**

Stacking all 326 Sysmon EID 10 events targeting lsass.exe shows the bulk is routine: svchost.exe 0x1000 (286 events), Microsoft Azure IaaSAntimalware AntimalwareConfig.exe 0x1400 (13), WindowsAzureTelemetryService.exe 0x1400 (11), svchost 0x101001 (2, lsm.dll call trace), svchost 0x3000 (1, sysmain.dll), and boot-time wininit/csrss 0x1fffff/0x1000000. Security object-access auditing on lsass.exe likewise shows only CollectGuestLogs.exe (0x1410/0x10), MsMpEng.exe (0x1fffff/0x10) and lsass itself (0x1478). No vaultcmd, cmdkey, DPAPI, Credential Manager registry/file access, or 4688/4104 command lines referencing vault or credentials were found; the only 'Credential' message is a routine Credential Guard configuration event (0x0) on scranton. The two anomalous PowerShell/wsmprovhost LSASS handles are reported under T1555.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:56:14.000Z | utica.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\svchost.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBov0sHE | q-08c020b92c | ok |
| 2 | 2020-05-02 03:19:42.009Z | scranton.dmevals.local | windows.sysmon | win.SourceImage | C:\WindowsAzure\Packages\Telemetry\WindowsAzureTelemetryService.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBnUQthh | q-8187f335d2 | ok |
| 3 | 2020-05-02 03:20:15.000Z | scranton.dmevals.local | windows.security | win.ProcessName | C:\Program Files\Windows Defender\MsMpEng.exe | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBudppHD | q-09a1bcb59d | ok |
| 4 | 2020-05-02 03:19:09.000Z | scranton.dmevals.local | windows.other | message | Credential Guard configuration: 0x0, 0 | .ds-logs-windows.other-default-2026.10.22-000001 / AaFiKJc9VXKkeBwdMB1A | q-a471516865 | ok |

### F33 · benign / high · T1556 · LSASS handle access on all four hosts is dominated by svchost.exe with benign access masks; no authentication-process modification observed

Evidence status: **verified**

326 Sysmon event.code 10 accesses to lsass.exe were recorded between 2020-05-02T02:56 and 03:28. Stacking by source image gives svchost.exe 289 (scranton 219, newyork 30, nashua 28, utica 12), AntimalwareConfig.exe 15, WindowsAzureTelemetryService.exe 13, PowerShell.exe/powershell.exe 4, wininit.exe 2, csrss.exe 1, services.exe 1, wsmprovhost.exe 1. Stacking by GrantedAccess shows 293 of 326 are 0x1000 (PROCESS_QUERY_LIMITED_INFORMATION). The rare high masks are all explained by their call traces: svchost.exe 0x101001 at 03:18:34 on scranton comes through lsm.dll (Local Session Manager), wininit.exe/csrss.exe 0x1fffff at 03:19:09 on scranton come through wininit.exe/basesrv.DLL/CSRSRV.dll (session teardown/restart), and svchost.exe 0x3000 at 03:19:59 comes through sysmain.dll. The only PowerShell full-access handle (0x1fffff, 0x1f3fff at 03:05:16 on scranton, PID 2976) has an UNKNOWN call trace, but the surrounding PowerShell 4104/4103 records for that window show only screen-capture code (Invoke-ScreenCapture, Add-Type System.Windows.Forms/System.Drawing, Start-Job 'Screenshot'), not credential access. No 4657 registry write to LSA/SAM/cryptdll/msv1_0, no 4688 command line referencing lsass/cryptdll/msv1_0, and no PowerShell script block referencing lsass/cryptdll/msv1_0 was found.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoMQUXI | q-ef9db801fc | ok |
| 2 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.CallTrace | C:\windows\SYSTEM32\ntdll.dll+9c584\|C:\windows\System32\KERNELBASE.dll+2732e\|UNKNOWN(000001996D28200D) | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoMQUXI | q-ef9db801fc | ok |
| 3 | 2020-05-02 03:18:34.438Z | scranton.dmevals.local | windows.sysmon | win.CallTrace | C:\windows\SYSTEM32\ntdll.dll+9def4\|c:\windows\system32\lsm.dll+1aa6e\|c:\windows\system32\lsm.dll+1a9c3\|c:\windows\system32\lsm.dll+65e1\|c:\windows\system32… | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBnrrZmZ | q-2a5c19c191 | ok |
| 4 | 2020-05-02 03:19:09.803Z | scranton.dmevals.local | windows.sysmon | win.CallTrace | C:\windows\SYSTEM32\ntdll.dll+9c584\|C:\windows\system32\basesrv.DLL+2fba\|C:\windows\SYSTEM32\CSRSRV.dll+5af4\|C:\windows\SYSTEM32\ntdll.dll+6cedf | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBnqqYet | q-2a5c19c191 | ok |
| 5 | 2020-05-02 03:05:53.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | Invoke-ScreenCapture;Start-Sleep -Seconds 3;View-Job -JobName "Screenshot" | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByRarrZ | q-38b6e6965a | ok |

### F34 · benign / high · T1556.001 · Network logons are machine-account and PsExec traffic; no DC authentication backdoor

Evidence status: **verified**

218 type-3 logons (4624) are dominated by the NEWYORK$ machine account from ::1, fe80::e40c:95b6:b0a7:6429 and 10.0.0.4 on newyork.dmevals.local, i.e. normal machine-account network authentication. The 15 explicit-credential logons (4648) show user pbeesly authenticating to target server NASHUA from scranton.dmevals.local (source 10.0.1.6) and, on nashua.dmevals.local, C:\Windows\PSEXESVC.exe using pbeesly's own credentials against localhost — consistent with PsExec lateral movement, not with injected/false credentials. No 4657 write to LSA/SAM/cryptdll/msv1_0 and no lsass/cryptdll reference in windows.other or PowerShell script blocks was found.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:56:47.000Z | newyork.dmevals.local | windows.security | user.name | NEWYORK$ | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBy3Dxwo | q-9435033a53 | ok |
| 2 | 2020-05-02 03:11:40.000Z | nashua.dmevals.local | windows.security | process.executable | C:\Windows\PSEXESVC.exe | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBuu5GRH | q-17135ecd7d | ok |
| 3 | 2020-05-02 03:14:42.000Z | scranton.dmevals.local | windows.security | win.TargetServerName | NASHUA | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBumxOdt | q-642acd5a6c | ok |

### F35 · benign / high · T1556.002 · No password filter DLL registration or System32 DLL drop

Evidence status: **verified**

No 4657 registry write to Notification Packages/Password/lsass, no 4688 command line containing Notification or PasswordFilter, no PowerShell script block containing Notification/PasswordFilter/lsass, and no Sysmon event.code 11 file creation of a .dll under System32 were returned. The only service installs in windows.other are PSEXESVC (%SystemRoot%\PSEXESVC.exe, demand start, four times on nashua.dmevals.local by pbeesly) and 'Java(TM) Virtual Machine Support Service' (C:\Windows\System32\javamtsup.exe, auto start, on scranton.dmevals.local) — neither is a password filter package.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:15:03.000Z | nashua.dmevals.local | windows.other | win.ServiceName | PSEXESVC | .ds-logs-windows.other-default-2026.10.22-000001 / AaFiKJc9VXKkeBwdMB02 | q-95d8e7cdbd | ok |
| 2 | 2020-05-02 03:04:15.000Z | scranton.dmevals.local | windows.other | win.ImagePath | C:\Windows\System32\javamtsup.exe | .ds-logs-windows.other-default-2026.10.22-000001 / AaFiKJc9VXKkeBwdLx2Z | q-95d8e7cdbd | ok |

### F36 · benign / high · T1556.005 · No reversible-encryption or AD account-flag modification

Evidence status: **verified**

No 4739 (domain policy change), no 4688/Sysmon event.code 1 command line containing Reversible/Set-ADUser/dsmod, no PowerShell 4104/4103 referencing AllowReversiblePasswordEncryption, and no windows.other message referencing Reversible were returned. The only AD-related PowerShell content on newyork.dmevals.local is the built-in ActiveDirectory module resource/help text (MSFT_ScriptResourceStrings.psd1, Get-CommonADParameters help), not a user-flag change.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:16:32.000Z | newyork.dmevals.local | windows.powershell | win.ScriptBlockText | # Localized	09/15/2018 04:54 AM (GMT)	303:6.40.10614 	MSFT_ScriptResourceStrings.psd1  # Localized MSFT_ScriptResourceStrings.psd1    ConvertFrom-StringData @' … | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByEVwPx | q-69b49a752f | ok |

### F37 · benign / high · T1556.006 · No MFA/authentication-policy registry or directory changes

Evidence status: **verified**

No 4739, no 5136 and no 4738 events were returned in windows.security or windows.other, and no Set-ADUser/Set-ADDomain command line was found in Sysmon process creation. The registry writes under HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication on scranton.dmevals.local are LogonUI session bookkeeping (LoggedOnUser DMEVALS\pbeesly, SelectedUserSID, FaceLogon CredProvUncompletedInstances, LogonSoundPlayed) written by C:\windows\system32\LogonUI.exe, plus the standard CredentialEnrollmentManagerUserSvc_13619b service keys written by services.exe — normal interactive-logon behaviour, not MFA tampering.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:20:46.738Z | scranton.dmevals.local | windows.sysmon | registry.path | HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\SessionData\2\LoggedOnSAMUser | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBjD_woi | q-eaba8c19f2 | ok |
| 2 | 2020-05-02 03:20:48.264Z | scranton.dmevals.local | windows.sysmon | registry.data.strings | C:\windows\system32\CredentialEnrollmentManager.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBnQM1oU | q-eaba8c19f2 | ok |

### F38 · benign / high · T1556.007 · No hybrid-identity / federation or directory-service modification

Evidence status: **verified**

No 5136 directory-service change events were returned in windows.security or windows.other, and no PowerShell script block containing Connect-MsolService/Connect-AzureAD was found. The only hybrid-identity-adjacent activity is dsregcmd.exe on newyork.dmevals.local loading cryptdll.dll at 03:06:14, which is the standard device-registration client loading the crypto manager DLL.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:06:14.783Z | newyork.dmevals.local | windows.sysmon | process.executable | C:\Windows\System32\dsregcmd.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoGKaib | q-ec707aa897 | ok |

### F39 · benign / high · T1556.008 · No Network Provider DLL registration

Evidence status: **verified**

No 4657 write to NetworkProvider/Credential-related registry keys and no PowerShell script block containing NetworkProvider/New-ItemProperty were returned. The registry writes touching credential-related paths on scranton.dmevals.local are MuiCache entries for CredentialEnrollmentManager.exe written by services.exe and the Winlogon PasswordExpiryNotification values written by winlogon.exe — standard OS behaviour, not a network provider DLL registration.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:21:20.841Z | scranton.dmevals.local | windows.sysmon | registry.path | HKU\S-1-5-21-1830255721-3727074217-2423397540-1107\Software\Microsoft\Windows\Winlogon\PasswordExpiryNotification\NotShownReason | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBi85CSi | q-eaba8c19f2 | ok |
| 2 | 2020-05-02 03:21:58.147Z | nashua.dmevals.local | windows.sysmon | registry.path | HKU\.DEFAULT\Software\Classes\Local Settings\MuiCache\1\52C64B7E\@%SystemRoot%\system32\CredentialEnrollmentManager.exe,-101 | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBi96CXA | q-eaba8c19f2 | ok |

### F40 · benign / medium · T1557 · No adversary-in-the-middle activity; observed credential theft is PsExec lateral movement with plaintext credentials

Evidence status: **verified**

Hunting for AiTM positioning (rogue SMB/relay hosts, name-resolution anomalies, network tampering) produced no attacker-in-the-middle evidence in any dataset. The real malicious activity in the Windows window is different: user pbeesly on scranton.dmevals.local ran PsExec64.exe from PowerShell four times (03:11:18, 03:12:25, 03:13:28, 03:14:42) against \\NASHUA with the password supplied in cleartext on the command line, staging C:\Windows\Temp\python.exe on nashua.dmevals.local via ADMIN$ (5145 at 03:10:23) and installing PSEXESVC (4697/7045) four times. That is lateral movement / credential misuse, not AiTM. The only 'network' hits were benign: netsh.exe trace start/stop spawned by the Azure NetworkWatcherAgent, and svchost.exe -k LocalServiceNetworkRestricted -p -s Dhcp (the DHCP client service).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:14:42.601Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\PsExec64.exe" -accepteula \\NASHUA -u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoz3z5O | q-a7ba6322d7 | ok |
| 2 | 2020-05-02 03:19:17.154Z | scranton.dmevals.local | windows.sysmon | process.command_line | C:\windows\system32\netsh.exe trace start capture=yes traceFile="C:\windows\TEMP\E7116ECA-DFE6-43C7-8FA8-8D3AC5AA8726\B91E06C5-1C7C-4830-9A76-74FA211560A7.etl" | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBnvvDAD | q-ed151cc6d8 | ok |
| 3 | 2020-05-02 03:19:11.533Z | scranton.dmevals.local | windows.sysmon | process.command_line | C:\windows\system32\svchost.exe -k LocalServiceNetworkRestricted -p -s Dhcp | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBnmk3GC | q-ed151cc6d8 | ok |

### F41 · benign / medium · T1557.001 · No LLMNR/NBT-NS poisoning or SMB relay; SMB traffic is normal domain authentication

Evidence status: **verified**

Name-resolution and SMB activity in the Zeek capture (2020-04-30, non-overlapping with the Windows window) shows only ordinary domain behaviour: wpad.dmevals.local lookups returning NXDOMAIN every ~10 minutes from 10.0.1.4 and 10.0.1.6, NetBIOS broadcast lookups for SCRANTON/NASHUA to 10.0.1.255, and LDAP/Kerberos SRV queries against the DC 10.0.0.4. SMB sessions are Kerberos/GSSAPI-authenticated to the DC (10.0.0.4) and to 10.0.1.6, with no unauthenticated relay-style SMB to an unexpected host. No PowerShell script block referenced responder, mitm, llmnr or nbt-ns (zero hits), and no 4657 registry change to DNSClient was recorded. The 4697 service installs in the Windows window are PSEXESVC (lateral movement) and Windows per-user services, not relay tooling.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-04-30 00:37:59.169Z | simplerockbuild.simplerock.lan | zeek | zeek.query | wpad.dmevals.local | .ds-logs-zeek-default-2026.10.22-000001 / AaFiKZc9VXKkeBwkgR-T | q-a249fca169 | ok |
| 2 | 2020-04-30 00:35:03.399Z | simplerockbuild.simplerock.lan | zeek | zeek.query | SCRANTON | .ds-logs-zeek-default-2026.10.22-000001 / AaFiKZc9VXKkeBwkgR-Z | q-a249fca169 | ok |
| 3 | 2020-04-30 00:36:38.970Z | simplerockbuild.simplerock.lan | zeek | zeek.service | krb,smb,gssapi | .ds-logs-zeek-default-2026.10.22-000001 / AaFiKZc9VXKkeBwkgR_V | q-3c9537d2a8 | ok |
| 4 | 2020-05-02 03:15:03.000Z | nashua.dmevals.local | windows.security | win.ServiceName | PSEXESVC | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBumxOeO | q-22874b9eba | ok |

### F42 · benign / medium · T1557.002 · No ARP cache poisoning; MAC/IP pairings are consistent per host

Evidence status: **verified**

Stacking L2 addresses on Zeek conn records shows three source MACs (00:0d:3a:13:e3:69, 00:0d:3a:4d:42:f2, fc:bd:67:e1:a9:c1) and responder MACs 12:34:56:78:9a:bc plus broadcast ff:ff:ff:ff:ff:ff. The 12:34:56:78:9a:bc value is a synthetic/placeholder MAC used by the capture environment, not a rogue device claiming multiple IPs. The 00:35:26 flows from 10.0.1.4 to 10.0.1.6 on 445 are recorded by the second sensor (bobs.bigwheel.local) with that sensor's own view of the same hosts, and no single MAC is seen claiming multiple distinct IPs in a way that indicates gratuitous ARP poisoning. No PowerShell script block referenced arp or netsh interface (zero hits), and no netsh interface/ARP manipulation command was executed on any host.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-04-30 00:35:26.038Z | bobs.bigwheel.local | zeek | zeek.resp_l2_addr | 00:0d:3a:13:e3:69 | .ds-logs-zeek-default-2026.10.22-000001 / AaFiKZc9VXKkeByOkBkA | q-d1a20cbb44 | ok |
| 2 | 2020-04-30 00:40:22.431Z | simplerockbuild.simplerock.lan | zeek | zeek.resp_l2_addr | 12:34:56:78:9a:bc | .ds-logs-zeek-default-2026.10.22-000001 / AaFiKZc9VXKkeBwkgR_N | q-a703824df9 | ok |
| 3 | 2020-04-30 00:40:22.431Z | simplerockbuild.simplerock.lan | zeek | zeek.orig_l2_addr | 00:0d:3a:4d:42:f2 | .ds-logs-zeek-default-2026.10.22-000001 / AaFiKZc9VXKkeBwkgR_N | q-a703824df9 | ok |

### F43 · benign / medium · T1557.003 · No DHCP spoofing; DHCP traffic is the local client service only

Evidence status: **verified**

No DHCP spoofing indicators exist in the collected data. The windows.other System channel contains no DHCP server/client event codes (1341/1342/1020/1063 returned zero hits), the Zeek capture contains no dhcp log type at all (only conn, files, ssl, x509, dce_rpc, http, dns, kerberos, dpd, smb_files, weird, smb_mapping, notice, pe), and no PowerShell script block mentioned Dhcp. Sysmon network connections show no traffic to UDP 67/68; the only DHCP-related process is the legitimate svchost.exe -k LocalServiceNetworkRestricted -p -s Dhcp client service on scranton.dmevals.local at 03:19:11.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:11.533Z | scranton.dmevals.local | windows.sysmon | process.command_line | C:\windows\system32\svchost.exe -k LocalServiceNetworkRestricted -p -s Dhcp | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBnmk3GC | q-ed151cc6d8 | ok |
| 2 | 2020-05-02 03:19:17.154Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\Windows\System32\netsh.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBnvvDAD | q-ed151cc6d8 | ok |

### F45 · benign / medium · T1558.001 · No golden-ticket evidence: krbtgt TGS requests are AES256 and no forged-ticket indicators

Evidence status: **verified**

All 28 4769 events on newyork.dmevals.local have TicketEncryptionType 0x12 (AES256) and Status 0x0; the krbtgt service-ticket requests by pbeesly (03:04:04Z) and SCRANTON$ (03:19:13Z, 03:19:15Z) are ordinary TGS requests with no RC4 downgrade, no anomalous principals and no 4672 special-privilege logons attributable to a forged principal (the 4672 aggregation returned no buckets). No golden-ticket forging is observable; the LSASS access is reported under T1558 as credential theft.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:04.000Z | newyork.dmevals.local | windows.security | win.TicketEncryptionType | 0x12 | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBy4FbJD | q-e1cc491a98 | ok |
| 2 | 2020-05-02 03:19:13.000Z | newyork.dmevals.local | windows.security | win.TicketOptions | 0x60810010 | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBuw7KBe | q-b971461e4f | ok |
| 3 | 2020-05-02 03:19:13.000Z | newyork.dmevals.local | windows.security | win.Status | 0x0 | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBuw7KBe | q-b971461e4f | ok |

### F46 · benign / medium · T1558.002 · No silver-ticket indicators in TGS requests

Evidence status: **verified**

The 4769 service-ticket requests on newyork.dmevals.local are for machine accounts (NEWYORK$, NASHUA$, SCRANTON$, WEC$) and krbtgt, all AES256 (0x12) with Status 0x0 and normal ticket options; no service-account SPN ticket burst or RC4 service ticket typical of silver-ticket use was observed. No PowerShell script block referenced silver tickets or SPNs.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:09:23.000Z | newyork.dmevals.local | windows.security | win.ServiceName | NASHUA$ | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBuv5SEr | q-b971461e4f | ok |
| 2 | 2020-05-02 03:09:23.000Z | newyork.dmevals.local | windows.security | win.TicketEncryptionType | 0x12 | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBuv5SEr | q-b971461e4f | ok |

### F47 · benign / medium · T1558.003 · No Kerberoasting observed

Evidence status: **verified**

No PowerShell script block contained Kerberoast/Invoke-Kerberoast/Rubeus strings, and the 4769 stack shows only AES256 tickets for machine accounts and krbtgt — no RC4 (0x17) service-ticket requests for user SPNs that would indicate Kerberoasting. The credential theft on scranton targeted LSASS memory rather than service-ticket roasting.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:04.000Z | newyork.dmevals.local | windows.security | win.ServiceName | NEWYORK$ | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBy8J3fS | q-b971461e4f | ok |
| 2 | 2020-05-02 03:04:04.000Z | newyork.dmevals.local | windows.security | win.TicketEncryptionType | 0x12 | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBy8J3fS | q-b971461e4f | ok |

### F48 · benign / medium · T1558.004 · No AS-REP roasting observed

Evidence status: **verified**

Zeek kerberos records (2020-04-30 window) show only pbeesly AS exchanges to krbtgt/DMEVALS.LOCAL that first return KDC_ERR_PREAUTH_REQUIRED and then succeed with aes256-cts-hmac-sha1-96 — i.e. pre-authentication is enforced, so no AS-REP roasting. No PowerShell script block referenced AS-REP/GetNPUsers/DontRequirePreAuth.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-04-30 00:24:19.110Z | simplerockbuild.simplerock.lan | zeek | zeek.error_msg | KDC_ERR_PREAUTH_REQUIRED | .ds-logs-zeek-default-2026.10.22-000001 / AaFiKZc9VXKkeBwkgh9J | q-ec2d02d4e2 | ok |
| 2 | 2020-04-30 00:24:19.119Z | simplerockbuild.simplerock.lan | zeek | zeek.cipher | aes256-cts-hmac-sha1-96 | .ds-logs-zeek-default-2026.10.22-000001 / AaFiKZc9VXKkeBwkgh9K | q-ec2d02d4e2 | ok |

### F50 · benign / medium · T1606.001 · No forged web cookies observed; only cookie-path file event is a benign svchost INetCookies write

Evidence status: **verified**

The single file-creation event matching a cookie store is svchost.exe writing C:\Windows\ServiceProfiles\LocalService\AppData\Local\Packages\warp_jit_db4a1097-b484-4973-bbf2-a04208ecd4d4\AC\INetCookies on scranton.dmevals.local at 03:21:05 — a normal LocalService package cache write, not browser cookie theft or injection. No PowerShell 4104 script block in the window contained cookie/Set-Cookie/session strings, and the Zeek HTTP records (2020-04-30, non-overlapping window) show only 10.0.1.4 -> 192.168.0.4 requests with no cookie or session-token evidence retrievable. The credential theft on scranton (LSASS access, keystrokes, clipboard) could enable session hijacking, but no forged cookie was observed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:21:05.681Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Windows\ServiceProfiles\LocalService\AppData\Local\Packages\warp_jit_db4a1097-b484-4973-bbf2-a04208ecd4d4\AC\INetCookies | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBi-6ySm | q-b39a75abd1 | ok |
| 2 | 2020-05-02 03:21:05.681Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\System32\svchost.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBi-6ySm | q-b39a75abd1 | ok |

### F52 · benign / high · T1621 · No MFA/2FA request-generation activity observed; windows.other hits are routine WMI provider and RSoP events

Evidence status: **verified**

The only T1621 check with hits (C355, 85 events in windows.other) consists entirely of WMI provider start events (5857, 36 events: dsccore, CIMWin32, deploymentprovider, dnsclientcim, StorageWMI, MSVDS__PROVIDER, Win32_WIN32_TERMINALSERVICE_Prov, WMIProv, BcdProv, SppProvider, all 'result code 0x0' under wmiprvse.exe) and WMI RSoP DeleteInstance events (5858, 49 events, 48 on newyork.dmevals.local with ResultCode 0x80041002 for RSOP_ExtensionStatus GUIDs). The single 5858 on scranton.dmevals.local is a WMI ExecNotificationQuery for Win32_ProcessStartTrace WHERE ProcessName = 'wsmprovhost.exe' (ResultCode 0x80041032). None of these are authentication or MFA-push events; they are normal WMI/RSoP housekeeping. No 4625 failures exist in windows.security (C352/C353 zero hits), no MFA/2FA/authenticator strings in PowerShell 4104 script blocks (C354 zero; the one 'verify' match is a PowerShellGet resource-string block on scranton under user pbeesly), no login/auth/mfa command lines in Sysmon process creation (C356 zero), and no login/auth/mfa HTTP URLs in zeek (C357 zero). The only authentication activity of note is a single NTLM network logon (4624 type 3, NtLmSsp, NTLM V2, workstation 10.0.1.4, source 172.18.39.2) for pbeesly on scranton.dmevals.local at 2020-05-02T03:20:41Z followed by a type 10 RemoteInteractive logon for the same account at 03:20:46Z — a successful logon sequence, not repeated MFA prompts or push bombing. No evidence of MFA request generation in this dataset.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:01:28.000Z | newyork.dmevals.local | windows.other | message | dsccore provider started with result code 0x0. HostProcess = wmiprvse.exe; ProcessID = 5344; ProviderPath = %systemroot%\system32\DscCore.dll | .ds-logs-windows.other-default-2026.10.22-000001 / AaFiKJc9VXKkeBwdLx2X | q-5a30008c0e | ok |
| 2 | 2020-05-02 02:56:47.000Z | newyork.dmevals.local | windows.other | message | Id = {C11E1664-7828-4AD0-B23A-0FCEF0EA26C0}; ClientMachine = NEWYORK; User = NT AUTHORITY\SYSTEM; ClientProcessId = 1588; Component = Unknown; Operation = Start… | .ds-logs-windows.other-default-2026.10.22-000001 / AaFiKJc9VXKkeBwdMB0b | q-52aa0440f3 | ok |
| 3 | 2020-05-02 03:22:41.000Z | scranton.dmevals.local | windows.other | message | Id = {BCCD0404-4290-0001-D00C-D0673020D601}; ClientMachine = SCRANTON; User = NT AUTHORITY\SYSTEM; ClientProcessId = 852; Component = Unknown; Operation = Start… | .ds-logs-windows.other-default-2026.10.22-000001 / AaFiKJc9VXKkeBwdMB1I | q-3d291d92f4 | ok |
| 4 | 2020-05-02 03:08:04.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | tFileInfo with -Force or New-ScriptFileInfo cmdlet to add the PSScriptInfo to the script file.  MissingRequiredPSScriptInfoProperties=Script '{0}' is missing re… | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByOXiqV | q-86498d0c23 | ok |
| 5 | 2020-05-02 03:20:41.000Z | scranton.dmevals.local | windows.security | win.LogonProcessName | NtLmSsp  | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBufr2mI | q-e4a2fb0e9b | ok |
| 6 | 2020-05-02 03:20:46.000Z | scranton.dmevals.local | windows.security | win.LogonType | 10 | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBudppFY | q-7fe33e482e | ok |

### F54 · benign / medium · T1649 · Routine certificate-store registry writes and Kerberos TGT requests (benign context)

Evidence status: **verified**

The remaining T1649 check hits are normal system behaviour. The 4657 registry-modification event on nashua.dmevals.local (2020-05-01T23:16:19-04:00) was performed by machine account NASHUA$ (S-1-5-18, logon 0x3E7) via C:\Windows\Sysmon.exe on the ROOT\Certificates\BE36A4562FB2EE05DBB3D32323ADF445084ED656 Blob, i.e. a certificate-store blob update, not attacker tampering. The other SystemCertificates registry writes in sysmon came from lsass.exe, svchost.exe, smss.exe and taskhostw.exe (AuthRoot, Windows Live ID Token Issuer, ACRS physical-store values) — standard Windows certificate propagation. The 14 Kerberos 4768 TGT requests on newyork.dmevals.local were for pbeesly (9) and the SCRANTON$ machine account (5) from internal addresses 10.0.1.4/10.0.1.6, with no PKINIT/certificate-based anomalies visible. The Zeek x509 subjects (rempel.group.net 376, conn.sons.info 2) are from a non-overlapping 2020-04-30 window and show no forged-certificate indicators. Note: the malicious certificate export itself is reported in the separate malicious finding.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:16:19.000Z | nashua.dmevals.local | windows.security | win.ObjectName | \REGISTRY\MACHINE\SOFTWARE\Microsoft\SystemCertificates\ROOT\Certificates\BE36A4562FB2EE05DBB3D32323ADF445084ED656 | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBuu4mRU | q-6d68c3286f | ok |
| 2 | 2020-05-02 03:16:19.000Z | nashua.dmevals.local | windows.security | win.ProcessName | C:\Windows\Sysmon.exe | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBuu4mRU | q-6d68c3286f | ok |
| 3 | 2020-05-02 02:59:37.453Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBogld9W | q-43672a8d16 | ok |
| 4 | 2020-05-02 03:11:18.000Z | newyork.dmevals.local | windows.security | win.TargetUserName | pbeesly | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBuy-fsg | q-26e17f8678 | ok |
| 5 | 2020-05-02 03:19:13.000Z | newyork.dmevals.local | windows.security | win.TargetUserName | SCRANTON$ | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBus3Fam | q-26e17f8678 | ok |

## Pivot candidates

Processes the pivot reviewer had to assess (started by a script host or from outside the Windows directory, rare in the 15-minute windows around verified activity).

| Host | Executable | Starts | Parents | Assessment | Reason |
|---|---|---|---|---|---|
| nashua.dmevals.local | C:\Program Files\WindowsApps\Microsoft.SkypeApp_14.35.152.0_x64__kzf8qxf38zg5c\S… | 1 | C:\Program Files\WindowsApps\Microsoft.SkypeApp_14.35.152.0_x64__kzf8qxf38zg5c\S… | benign | Signed Store app, only produced a WerFault crash report. |
| nashua.dmevals.local | C:\Windows\Temp\python.exe | 5 | C:\Windows\PSEXESVC.exe, C:\Windows\Temp\python.exe | malicious | PsExec-pushed PyInstaller payload that opened LSASS and beaconed to 192.168.0.4:8443. |
| nashua.dmevals.local | C:\Windows\Temp\Rar.exe | 1 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | malicious | Renamed WinRAR run from Temp to password-protect the staged credential archive. |
| nashua.dmevals.local | C:\Windows\Temp\sdelete64.exe | 3 | C:\Windows\System32\cmd.exe | malicious | Anti-forensics wiping Rar.exe and working.zip on nashua. |
| nashua.dmevals.local | C:\WindowsAzure\Packages\CollectGuestLogs.exe | 1 | C:\WindowsAzure\Packages\WaAppAgent.exe | benign | Azure guest agent log collector, routine. |
| newyork.dmevals.local | C:\Windows\System32\conhost.exe | 3 | C:\WindowsAzure\Packages\CollectGuestLogs.exe, C:\Windows\System32\cmd.exe, C:\W… | benign | Console host for normal Azure/cmd children. |
| scranton.dmevals.local | C:\Packages\Plugins\Microsoft.Azure.NetworkWatcher.NetworkWatcherAgentWindows\1.… | 4 | C:\Windows\System32\cmd.exe, C:\Windows\System32\services.exe | benign | Azure Network Watcher extension, routine. |
| scranton.dmevals.local | C:\Packages\Plugins\Microsoft.Azure.Security.IaaSAntimalware\1.5.5.9\Antimalware… | 1 | C:\WindowsAzure\Packages\GuestAgent\WindowsAzureGuestAgent.exe | benign | Azure antimalware extension config, routine. |
| scranton.dmevals.local | C:\Packages\Plugins\Microsoft.Compute.CustomScriptExtension\1.10.5\bin\CustomScr… | 1 | C:\Windows\System32\cmd.exe | benign | Azure custom script extension handler, routine. |
| scranton.dmevals.local | C:\Packages\Plugins\Microsoft.Compute.JsonADDomainExtension\1.3.2\bin\JsonADDoma… | 1 | C:\Windows\System32\cmd.exe | benign | Azure domain-join extension, routine. |
| scranton.dmevals.local | C:\Program Files (x86)\Google\Update\1.3.35.452\GoogleCrashHandler.exe | 2 | C:\Program Files (x86)\Google\Update\GoogleUpdate.exe | benign | Google Update crash handler, routine. |
| scranton.dmevals.local | C:\Program Files (x86)\Google\Update\1.3.35.452\GoogleCrashHandler64.exe | 2 | C:\Program Files (x86)\Google\Update\GoogleUpdate.exe | benign | Google Update crash handler, routine. |
| scranton.dmevals.local | C:\Program Files (x86)\Google\Update\GoogleUpdate.exe | 3 | C:\Program Files (x86)\Google\Update\GoogleUpdate.exe, C:\Windows\System32\servi… | benign | Google Update service, routine. |
| scranton.dmevals.local | C:\Program Files\SysinternalsSuite\accessChk.exe | 1 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | malicious | Attacker-downloaded tool run by PowerShell, created passwordsDB and queried LSA key. |
| scranton.dmevals.local | C:\Program Files\SysinternalsSuite\PsExec64.exe | 4 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | malicious | Used with plaintext password to launch the python payload on NASHUA. |
| scranton.dmevals.local | C:\Program Files\SysinternalsSuite\sdelete64.exe | 3 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | malicious | Anti-forensics wiping the stager .scr, Draft.Zip and SysinternalsSuite.zip. |
| scranton.dmevals.local | C:\Program Files\Windows Defender\MsMpEng.exe | 1 | C:\Windows\System32\services.exe | benign | Defender engine scanning LSASS, expected. |
| scranton.dmevals.local | C:\Program Files\Windows Defender\NisSrv.exe | 2 | C:\Windows\System32\services.exe | benign | Defender network inspection service, routine. |
| scranton.dmevals.local | C:\ProgramData\victim\â€®cod.3aka3.scr | 1 | C:\Windows\explorer.exe | malicious | Masqueraded .scr stager in ProgramData\victim launched from explorer, spawned cmd/powershell. |
| scranton.dmevals.local | C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe | 2 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | malicious | PowerShell compiled in-memory DLLs from Temp cmdline files. |
| scranton.dmevals.local | C:\Windows\System32\hostui.exe | 1 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | suspicious | Launched by PowerShell with -verb runas to trigger a UAC prompt. |
| scranton.dmevals.local | C:\Windows\System32\sdclt.exe | 3 | C:\Windows\System32\cmd.exe | suspicious | UAC-bypass-capable binary spawned three times by cmd during the intrusion. |
| scranton.dmevals.local | C:\WindowsAzure\Packages\GuestAgent\BfeToolWin8.exe | 1 | C:\WindowsAzure\Packages\GuestAgent\WindowsAzureGuestAgent.exe | benign | Azure guest agent firewall tool, routine. |
| scranton.dmevals.local | C:\WindowsAzure\Packages\GuestAgent\FindVolume\FindVolume.exe | 1 | C:\WindowsAzure\Packages\GuestAgent\WindowsAzureGuestAgent.exe | benign | Azure guest agent volume helper, routine. |
| scranton.dmevals.local | C:\WindowsAzure\Packages\GuestAgent\WindowsAzureGuestAgent.exe | 1 | C:\Windows\System32\services.exe | benign | Azure guest agent service, routine. |
| scranton.dmevals.local | C:\WindowsAzure\Packages\Telemetry\WindowsAzureTelemetryService.exe | 1 | C:\Windows\System32\services.exe | benign | Azure telemetry service, routine. |
| scranton.dmevals.local | C:\WindowsAzure\Packages\WaAppAgent.exe | 1 | C:\Windows\System32\services.exe | benign | Azure agent host, routine. |
| scranton.dmevals.local | C:\WindowsAzure\SecAgent\WaSecAgentProv.exe | 2 | C:\WindowsAzure\Packages\WaAppAgent.exe | benign | Azure security agent provider, routine. |
| scranton.dmevals.local | C:\WindowsAzure\WindowsAzureNetAgent_1.0.0.143\WindowsAzureNetAgent\Plugins\VFPl… | 1 | C:\WindowsAzure\WindowsAzureNetAgent_1.0.0.143\WindowsAzureNetAgent\WindowsAzure… | benign | Azure network agent plugin, routine. |
| scranton.dmevals.local | C:\WindowsAzure\WindowsAzureNetAgent_1.0.0.143\WindowsAzureNetAgent\WindowsAzure… | 1 | C:\Windows\System32\services.exe | benign | Azure network agent service, routine. |

## Technique conclusions

One line per technique in scope: status from the triage of its family; `not_observed` = checked, nothing found; `not_observable` = no dataset records it.

| Technique | Status | Reason |
|---|---|---|
| T1003 OS Credential Dumping | malicious | Credential-access tooling and LSASS handle requests with full-access masks were performed by user pbeesly on scranton and nashua inside a hands-on-keyboard intrusion (PowerShell toolkit psversion.ps1/readme.ps1 with keys… |
| T1003.001 LSASS Memory | malicious | python.exe on nashua opened lsass 0x1f3fff. |
| T1003.002 Security Account Manager | benign | SAM/SAM_DOMAIN/SAM_ALIAS handles and HKLM\SAM\SAM\Domains\Account\F write came from lsass.exe as SCRANTON$ during an LSA restart; no reg save, esentutl or hive copies found. |
| T1003.003 NTDS | not_observed | No NTDS.dit file creation, ntdsutil/vssadmin/diskshadow command lines, or shadow-copy activity in Sysmon, Security, PowerShell or windows.other. |
| T1003.004 LSA Secrets | not_observed | No SECURITY hive/Policy Secrets handle events, no reg save HKLM\SECURITY, no lsadump/secrets command lines or script blocks. |
| T1003.005 Cached Domain Credentials | benign | HKLM\SECURITY\Cache\NL$1 writes on nashua were made by lsass.exe itself (normal cached-credential maintenance); no external cache read or mscache/DCC2 tooling observed. |
| T1003.006 DCSync | not_observed | No drsuapi/lsadump/dcsync command lines or PowerShell script blocks; no directory replication abuse in available telemetry. |
| T1040 Network Sniffing | benign | The only packet-capture activity in the data is the Azure Network Watcher agent's own netsh trace on scranton.dmevals.local (SYSTEM, parent NetworkWatcherAgent.exe /service), i.e. platform telemetry. No tcpdump/windump/w… |
| T1056 Input Capture | suspicious | LSASS handle requests and SAM object access are present, but the only non-OS, non-cmdlet LSASS access is the malicious PowerShell on scranton (reported under T1056.004); the rest are OS/Azure/Defender processes and a ben… |
| T1056.001 Keylogging | malicious | Get-Keystrokes and Get-Clipboard on scranton. |
| T1056.002 GUI Input Capture | not_observed | No Get-Credential/Read-Host/prompt-based credential capture; the only credential object is a hardcoded PSCredential used for WebDAV exfiltration. |
| T1056.003 Web Portal Capture | not_observed | No IIS/wwwroot/login page writes, w3wp activity, or HTTP POSTs; zeek window does not overlap the Windows data. |
| T1056.004 Credential API Hooking | malicious | Hidden steganography-decoding PowerShell (PID 2976, pbeesly) spawned from a malicious .scr opened lsass.exe with 0x1F3FFF and 0x1FFFFF full access on scranton.dmevals.local at 03:05:16Z. |
| T1110 Brute Force | not_observed | Zero 4625/4771/4776-failure/4740 events in windows.security; the only 4776 is a successful validation (Error Code 0x0) for pbeesly on newyork. No lockout or failed-auth messages in windows.other. |
| T1110.001 Password Guessing | not_observed | No failed logons and no password-referencing command lines or script blocks; the single credential validation succeeded. |
| T1110.002 Password Cracking | suspicious | PowerShell.exe on scranton opened lsass.exe with 0x1fffff/0x1f3fff and wsmprovhost.exe on nashua with 0x1f3fff, consistent with hash extraction for offline cracking, but no cracking tools, wordlists or potfiles were foun… |
| T1110.003 Password Spraying | not_observed | No 4625 failures or lockouts; 4648 events are pbeesly/PSEXESVC reuse of known credentials, and no user-list spray tooling appears in process or script-block data. |
| T1110.004 Credential Stuffing | not_observed | No failed authentication to indicate replay of stolen credential lists; credential theft on scranton/nashua was local collection (private keys, keystrokes, password-named files archived with Rar). |
| T1111 Multi-Factor Authentication Interception | not_observed | No MFA/smart-card/token interception artifacts in any dataset. The 4648 explicit-credential logons are pbeesly used by PSEXESVC.exe/svchost.exe plus routine DWM-/UMFD-/machine-account logons; 'Credential' registry hits a… |
| T1187 Forced Authentication | malicious | Host 10.0.1.4 (scranton) probed 192.168.0.4 on SMB 445/139 (all REJ), then used the Windows WebDAV redirector (DavClnt / Microsoft-WebDAV-MiniRedir/10.0.18362) to issue OPTIONS/PROPFIND/PROPPATCH/PUT/LOCK against /webdav… |
| T1212 Exploitation for Credential Access | malicious | Two independent lsass accesses with near-full rights (0x1FFFFF/0x1F3FFF) came from attacker-controlled PowerShell: a hidden, execution-policy-bypass steganographic stager spawned by control.exe on scranton (PID 2976, use… |
| T1539 Steal Web Session Cookie | malicious | Edge processes opened 0x1f3fff on nashua. |
| T1552 Unsecured Credentials | malicious | accesschk passwordsDB and credential file collection. |
| T1552.001 Credentials In Files | malicious | Plaintext password on PsExec64 command line. |
| T1552.002 Credentials in Registry | benign | All registry Password/Credential value sets came from svchost.exe, lsass.exe, services.exe and winlogon.exe performing normal Windows/IdentityCRL/CredentialGuard/service operations; no credential harvesting in the regist… |
| T1552.003 Shell History | not_observed | No process command line or file-access event referencing consolehost_history or other shell history files was returned in the sysmon or security datasets. |
| T1552.004 Private Keys | malicious | Private keys exported to .pfx and staged in 7z. |
| T1552.006 Group Policy Preferences | benign | Zeek smb_files shows only routine SYSVOL gpt.ini and GptTmpl.inf reads by two hosts during Group Policy processing; no Groups.xml/Services.xml cpassword access, and the zeek window does not overlap the Windows telemetry. |
| T1555 Credentials from Password Stores | malicious | Credential stores targeted via LSASS and browser access. |
| T1555.003 Credentials from Web Browsers | malicious | Edge processes opened with full access on nashua. |
| T1555.004 Windows Credential Manager | not_observed | No vaultcmd/cmdkey/DPAPI/Credential Manager activity; LSASS handle stacking shows only svchost, Azure antimalware/telemetry, Defender and boot-time system processes. |
| T1555.005 Password Managers | not_observed | No KeePass/1Password/Bitwarden/LastPass processes, files, handles, command lines or messages in any dataset. |
| T1556 Modify Authentication Process | benign | 326 LSASS handle events are 293x 0x1000 from svchost.exe/Azure agents; rare high masks trace to lsm.dll, basesrv/CSRSRV and sysmain.dll. No registry, command-line or script-block evidence of authentication-process modifi… |
| T1556.001 Domain Controller Authentication | benign | Type-3 logons are NEWYORK$ machine-account traffic; 4648 explicit-credential logons are pbeesly -> NASHUA and PSEXESVC on nashua using pbeesly's own credentials (PsExec), not injected credentials. |
| T1556.002 Password Filter DLL | not_observed | No Notification Packages/Password registry write, no PasswordFilter command line or script block, no System32 .dll creation; only service installs are PSEXESVC and javamtsup.exe. |
| T1556.005 Reversible Encryption | not_observed | No 4739, no Reversible/Set-ADUser/dsmod command lines or script blocks; only built-in AD module help text on newyork. |
| T1556.006 Multi-Factor Authentication | not_observed | No 4739/5136/4738; Authentication registry writes are LogonUI session bookkeeping and CredentialEnrollmentManagerUserSvc service keys. |
| T1556.007 Hybrid Identity | not_observed | No 5136 directory changes and no Connect-MsolService/Connect-AzureAD script blocks; dsregcmd.exe only loaded cryptdll.dll. |
| T1556.008 Network Provider DLL | not_observed | No NetworkProvider registry writes or New-ItemProperty script blocks; credential-path registry writes are MuiCache and Winlogon PasswordExpiryNotification. |
| T1557 Adversary-in-the-Middle | not_observed | No AiTM positioning found. Network-related hits were benign (Azure NetworkWatcher netsh trace, DHCP client svchost). The malicious activity present is PsExec lateral movement with plaintext credentials, a different techn… |
| T1557.001 Name Resolution Poisoning and SMB Relay | not_observed | No LLMNR/NBT-NS poisoning or SMB relay: WPAD lookups NXDOMAIN, NetBIOS broadcasts normal, SMB sessions Kerberos/GSSAPI-authenticated to the DC and 10.0.1.6; zero PowerShell hits for responder/mitm/llmnr/nbt-ns and no DNS… |
| T1557.002 ARP Cache Poisoning | not_observed | No ARP poisoning: MAC/IP pairings consistent per host, 12:34:56:78:9a:bc is a synthetic capture-environment MAC, no MAC claiming multiple IPs, no arp/netsh interface commands executed. |
| T1557.003 DHCP Spoofing | not_observed | No DHCP spoofing: no DHCP event codes in windows.other, no dhcp log type in Zeek, no UDP 67/68 connections, no Dhcp references in PowerShell; only the legitimate DHCP client service. |
| T1558 Steal or Forge Kerberos Tickets | malicious | PowerShell PID 2976 on scranton.dmevals.local opened lsass.exe with 0x1f3fff/0x1fffff (full access) at 03:05:16Z inside a hidden, IEX-decoded intrusion session, and krbtgt service tickets were requested for pbeesly and S… |
| T1558.001 Golden Ticket | not_observed | All 4769 tickets are AES256 (0x12) with Status 0x0; no RC4 downgrade, no forged-principal 4672 logons, no golden-ticket tooling in script blocks. |
| T1558.002 Silver Ticket | not_observed | TGS requests are for machine accounts and krbtgt only, all AES256 and successful; no silver-ticket/SPN abuse indicators. |
| T1558.003 Kerberoasting | not_observed | No Kerberoast/Rubeus script blocks and no RC4 service-ticket requests for user SPNs. |
| T1558.004 AS-REP Roasting | not_observed | Zeek kerberos shows KDC_ERR_PREAUTH_REQUIRED followed by successful AES256 AS exchanges, i.e. pre-auth enforced; no AS-REP roasting tooling. |
| T1606 Forge Web Credentials | suspicious | Malicious credential access on scranton.dmevals.local (PowerShell full-access LSASS open 0x1FFFFF, certificate/private-key export to .pfx, keystroke and clipboard capture, staging archive) provides the material for forgi… |
| T1606.001 Web Cookies | not_observed | No forged or injected web cookie activity: the only cookie-path file event is a benign svchost INetCookies write, and no cookie/session strings appear in PowerShell script blocks or Zeek HTTP. |
| T1606.002 SAML Tokens | not_observed | No SAML assertion, token or ADFS traffic in any dataset; certificate/private-key export on scranton is a plausible precursor but token forgery itself was not observed. |
| T1621 Multi-Factor Authentication Request Generatio… | not_observed | No MFA/2FA/authenticator/push activity in any dataset: windows.security has zero 4625 failures and no MFA-related logon process names; PowerShell 4104 blocks contain no MFA/2FA/authenticator content (only a PowerShellGet… |
| T1649 Steal or Forge Authentication Certificates | malicious | Get-PrivateKeys exported LocalMachine certs to .pfx. |

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
| T1552.002 Credentials in Registry | 3 hits | 1 hits | 1000 hits | 17716 hits | n/a |
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

Every MCP tool call of this run (1292), in order (source: mcp_audit.jsonl written by the MCP server).

| Query | Phase | Tool | Arguments | Hits / rows | Cited by |
|---|---|---|---|---|---|
| q-05f3925205 | scope | list_data_sources | {} | None |  |
| q-bb7bd85ed4 | scope | get_registry | {} | None |  |
| q-a5b5f3d18c | scope | get_fields | {"dataset": "windows.other", "prefix": ""} | None |  |
| q-ac6732c9dd | scope | get_fields | {"dataset": "windows.powershell", "prefix": ""} | None |  |
| q-ca131261a0 | scope | get_fields | {"dataset": "windows.security", "prefix": ""} | None |  |
| q-0e0be79605 | scope | get_fields | {"dataset": "windows.sysmon", "prefix": ""} | None |  |
| q-88dbf62910 | scope | get_fields | {"dataset": "zeek", "prefix": ""} | None |  |
| q-5f5fb45d7e | check C001 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 447 |  |
| q-9bda1bdbc7 | check C002 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-a38fbf9e03 | check C003 | aggregate | {"dataset": "windows.security", "field": "win.ObjectType", "query": "event.code:(4656 OR 4663 OR 4670)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 10977 |  |
| q-2dbbf74949 | check C004 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 460 |  |
| q-b1015c03f9 | check C005 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*lsass* OR powershell.script_block_text:*mimikatz* OR powershell.script_block_text:*sekurlsa* OR powershell.script_block_text:*DumpCreds*)", "time_from": null, "time_… | 0 |  |
| q-40c5746359 | check C006 | search | {"dataset": "windows.other", "query": "message:(*lsass* OR *mimikatz* OR *sekurlsa* OR *procdump*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "p… | 0 |  |
| q-7e2e9b51e4 | check C007 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-cf07e3c038 | check C008 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 326 |  |
| q-d5cdf0217a | check C009 | aggregate | {"dataset": "windows.sysmon", "field": "win.SourceImage", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-0ac2233898 | check C010 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*lsass* OR file.path:*.dmp)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "pro… | 2 |  |
| q-faf8a99325 | check C011 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*lsass* OR process.command_line:*comsvcs* OR process.command_line:*MiniDump*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dat… | 1 |  |
| q-a7bc805681 | check C012 | search | {"dataset": "windows.sysmon", "query": "event.code:(13 OR 14) AND registry.path:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.comm… | 0 |  |
| q-86bc50f91a | check C013 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4673", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 934 |  |
| q-e3bebb2761 | check C014 | search | {"dataset": "windows.security", "query": "event.code:4656 AND win.ObjectName:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command… | 13 |  |
| q-bbed5de2ef | check C015 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*lsass* OR powershell.script_block_text:*MiniDump* OR powershell.script_block_text:*Invoke-Mimikatz*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "… | 0 |  |
| q-d722bada3a | check C016 | search | {"dataset": "windows.other", "query": "message:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 0 |  |
| q-e61c499f9f | check C017 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*SAM* OR file.path:*SECURITY* OR file.path:*SYSTEM*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "… | 3 |  |
| q-4223fee7d3 | check C018 | search | {"dataset": "windows.sysmon", "query": "event.code:(13 OR 14) AND (registry.path:*SAM* OR registry.path:*SECURITY*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "proces… | 7 | F03 |
| q-8639b2d609 | check C019 | search | {"dataset": "windows.sysmon", "query": "event.code:2 AND (process.command_line:*SAM* OR process.command_line:*reg*save*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "p… | 0 |  |
| q-37af6e1554 | check C020 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*reg save* OR process.command_line:*save*hklm* OR process.command_line:*SAM*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dat… | 0 |  |
| q-bc94ce0a8f | check C021 | aggregate | {"dataset": "windows.security", "field": "process.command_line", "query": "event.code:4688 AND (process.command_line:*reg* OR process.command_line:*save*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 6 |  |
| q-44ff0075ed | check C022 | search | {"dataset": "windows.security", "query": "event.code:(4656 OR 4663) AND (win.ObjectName:*SAM* OR win.ObjectName:*SECURITY*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name",… | 10 |  |
| q-1b299314b3 | check C023 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*SAM* OR powershell.script_block_text:*reg save* OR powershell.script_block_text:*hive*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "… | 2 |  |
| q-6b120a5e8d | check C024 | search | {"dataset": "windows.other", "query": "message:(*SAM* OR *SECURITY hive* OR *reg save*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.comm… | 0 |  |
| q-7a36bb7e04 | check C025 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*ntds* OR file.path:*NTDS*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "pro… | 0 |  |
| q-8a6f34512c | check C026 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*ntds* OR process.command_line:*vssadmin* OR process.command_line:*ntdsutil* OR process.command_line:*diskshadow*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "ho… | 0 |  |
| q-787bb658f2 | check C027 | search | {"dataset": "windows.sysmon", "query": "event.code:2 AND file.path:*ntds*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "so… | 0 |  |
| q-789d5cdd1a | check C028 | aggregate | {"dataset": "windows.security", "field": "process.command_line", "query": "event.code:4688 AND (process.command_line:*ntds* OR process.command_line:*vssadmin* OR process.command_line:*diskshadow*)", "time_from": null, "time_to": null, "size": 50, "sub_field": … | 0 |  |
| q-bd738f4f5f | check C029 | search | {"dataset": "windows.other", "query": "message:(*shadow* OR *VSS* OR *ntds*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 0 |  |
| q-acc00d41fe | check C030 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*ntds* OR powershell.script_block_text:*diskshadow* OR powershell.script_block_text:*vssadmin*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.n… | 0 |  |
| q-ca0926a954 | check C031 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 326 |  |
| q-fddcabfe9d | check C032 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*secrets* OR process.command_line:*lsadump* OR process.command_line:*reg save*HKLM\\\\SECURITY*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observe… | 0 |  |
| q-b2e23604d5 | check C033 | search | {"dataset": "windows.sysmon", "query": "event.code:7 AND win.ImageLoaded:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_lin… | 1 |  |
| q-fb77f643af | check C034 | search | {"dataset": "windows.security", "query": "event.code:(4656 OR 4663 OR 4670) AND win.ObjectName:*SECURITY*Policy*Secrets*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "p… | 0 |  |
| q-f84d6f69d7 | check C035 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:(4656 OR 4663 OR 4670) AND win.ObjectName:*Secrets*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-eeb1f4dbb5 | check C036 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*Secrets* OR powershell.script_block_text:*lsadump* OR powershell.script_block_text:*LSA*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name",… | 0 |  |
| q-ec292af69f | check C037 | search | {"dataset": "windows.other", "query": "message:(*Secrets* OR *LSA* OR *lsadump*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_lin… | 0 |  |
| q-6c6014acc5 | check C038 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 326 |  |
| q-389b24a5c0 | check C039 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*cache* OR process.command_line:*DCC2* OR process.command_line:*mscache* OR process.command_line:*cachedump*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.na… | 4 |  |
| q-6ab9ae8c02 | check C040 | search | {"dataset": "windows.security", "query": "event.code:(4656 OR 4663 OR 4670) AND (win.ObjectName:*Cache* OR win.ObjectName:*SECURITY*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "u… | 0 |  |
| q-3ac46663fb | check C041 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:(4656 OR 4663 OR 4670) AND win.ObjectName:*Cache*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-07866212e5 | check C042 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*cache* OR powershell.script_block_text:*DCC2* OR powershell.script_block_text:*mscache*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", … | 0 |  |
| q-af809c0773 | check C043 | search | {"dataset": "windows.other", "query": "message:(*cached*credential* OR *mscache* OR *DCC2*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.… | 0 |  |
| q-2c44259aac | check C044 | count | {"dataset": "windows.security", "query": "event.code:4662", "time_from": null, "time_to": null} | 7 |  |
| q-d15cc9fd97 | check C045 | aggregate | {"dataset": "windows.security", "field": "win.AccessMask", "query": "event.code:4662", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 7 |  |
| q-6233003802 | check C046 | aggregate | {"dataset": "windows.security", "field": "win.SubjectUserName", "query": "event.code:4662", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 7 |  |
| q-8128dc8b45 | check C047 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*drsuapi* OR process.command_line:*lsadump* OR process.command_line:*dcsync*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dat… | 0 |  |
| q-62e917b2bd | check C048 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*DCSync* OR powershell.script_block_text:*lsadump* OR powershell.script_block_text:*drsuapi*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.nam… | 0 |  |
| q-1c35d1540d | check C049 | search | {"dataset": "windows.other", "query": "event.code:7045 OR event.code:5858 OR event.code:5857", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process… | 90 |  |
| q-44561c876c | check C050 | search | {"dataset": "zeek", "query": "event.action:dce_rpc AND (zeek.operation:*DRSUAPI* OR zeek.endpoint:*drsuapi* OR zeek.named_pipe:*drsuapi*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code"… | 9 |  |
| q-68b32720ca | check C051 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 460 |  |
| q-7a30906a05 | check C052 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*pcap* OR process.command_line:*sniff* OR process.command_line:*promisc*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.da… | 0 |  |
| q-e13a48a594 | check C053 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-2a13d04783 | check C054 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.executable:*tcpdump* OR process.executable:*windump* OR process.executable:*wireshark* OR process.executable:*rawcap* OR process.executable:*npcap*)", "time_from": null, "time_to": null, "fields… | 0 |  |
| q-5bda4cf8b6 | check C055 | search | {"dataset": "windows.sysmon", "query": "event.code:6 AND (win.Image:*npcap* OR win.Image:*pcap* OR win.Image:*winpcap*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "pr… | 0 |  |
| q-524ee136d2 | check C056 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*pcap* OR powershell.script_block_text:*sniff* OR powershell.script_block_text:*promiscuous*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.nam… | 0 |  |
| q-a0d0bbb121 | check C057 | search | {"dataset": "zeek", "query": "event.action:conn AND network.transport:icmp", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "s… | 0 |  |
| q-ad2b42f8db | check C058 | aggregate | {"dataset": "windows.security", "field": "win.ObjectType", "query": "event.code:4656 OR event.code:4663 OR event.code:4670", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 10977 |  |
| q-16a64f37d9 | check C059 | aggregate | {"dataset": "windows.security", "field": "win.AccessMask", "query": "event.code:4656 OR event.code:4663", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 10834 |  |
| q-df8cb73d19 | check C060 | search | {"dataset": "windows.security", "query": "event.code:4656 AND (win.ObjectName:*lsass* OR win.ObjectName:*credential* OR win.ObjectName:*SAM*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.c… | 23 |  |
| q-a54c8c032b | check C061 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-6a2db8feeb | check C062 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-e0fe78d5a4 | check C063 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND (win.GrantedAccess:0x1010 OR win.GrantedAccess:0x1410 OR win.GrantedAccess:0x1438 OR win.GrantedAccess:0x143a)", "time_from": null, "time_to": null, "fields": ["@timestamp", … | 0 |  |
| q-9239d8f625 | check C064 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*Get-Credential* OR powershell.script_block_text:*CredentialManager* OR powershell.script_block_text:*keylog*)", "time_from": null, "time_to": null, "fields": ["@time… | 0 |  |
| q-ec22d5e1fe | check C065 | search | {"dataset": "windows.other", "query": "event.code:7045 OR event.code:5858 OR event.code:5857", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process… | 90 |  |
| q-390ec17687 | check C066 | search | {"dataset": "zeek", "query": "event.action:http AND http.request.method:POST", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 0 |  |
| q-f9e5c568d5 | check C067 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-6c8e8c1d61 | check C068 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND (win.TargetImage:*lsass* OR win.TargetImage:*winlogon* OR win.TargetImage:*explorer*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event… | 470 |  |
| q-e77b7c4d62 | check C069 | search | {"dataset": "windows.sysmon", "query": "event.code:13 AND (registry.path:*Keyboard* OR registry.path:*keylog* OR registry.path:*Scancode*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code… | 26 |  |
| q-ced350e608 | check C070 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*keylog* OR process.command_line:*GetAsyncKeyState* OR process.command_line:*SetWindowsHookEx*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer… | 0 |  |
| q-a3a40f7a4d | check C071 | aggregate | {"dataset": "windows.security", "field": "win.ObjectType", "query": "event.code:4656 OR event.code:4663 OR event.code:4670", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 10977 |  |
| q-0f1741237f | check C072 | search | {"dataset": "windows.security", "query": "event.code:4656 AND (win.ObjectName:*lsass* OR win.ObjectName:*winlogon*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "proces… | 13 |  |
| q-de82bef8e7 | check C073 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-1b32f66efe | check C074 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*keylog* OR powershell.script_block_text:*GetAsyncKeyState* OR powershell.script_block_text:*SetWindowsHookEx*)", "time_from": null, "time_to": null, "fields": ["@tim… | 0 |  |
| q-ebba2bfe87 | check C075 | search | {"dataset": "zeek", "query": "event.action:http AND http.request.method:POST", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 0 |  |
| q-601632bc46 | check C076 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*Credential* OR powershell.script_block_text:*Prompt* OR powershell.script_block_text:*Read-Host*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "hos… | 0 |  |
| q-be4aa9863f | check C077 | aggregate | {"dataset": "windows.powershell", "field": "win.ScriptBlockId", "query": "event.code:4104", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 414 |  |
| q-977da1058f | check C078 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*Credential* OR process.command_line:*prompt* OR process.command_line:*consent*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.… | 3 |  |
| q-9a4bf68bfe | check C079 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 447 |  |
| q-f4f9b4c23f | check C080 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*Credential* OR process.command_line:*prompt*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user… | 0 |  |
| q-96332edb0b | check C081 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 460 |  |
| q-e185c217a0 | check C082 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-f34ade294c | check C083 | search | {"dataset": "zeek", "query": "event.action:http AND http.request.method:POST", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 0 |  |
| q-bb8d63fe59 | check C084 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*login* OR file.path:*portal* OR file.path:*wwwroot* OR file.path:*inetpub*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "eve… | 0 |  |
| q-1d66ddd4af | check C085 | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 1649 |  |
| q-933a2f0352 | check C086 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*iis* OR process.command_line:*w3wp* OR process.command_line:*wwwroot*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset",… | 0 |  |
| q-b2369de431 | check C087 | search | {"dataset": "windows.security", "query": "event.code:4663 AND (win.ObjectName:*wwwroot* OR win.ObjectName:*inetpub* OR win.ObjectName:*login*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.… | 0 |  |
| q-6b6ed69ce4 | check C088 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 5337 |  |
| q-b71268c17c | check C089 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*wwwroot* OR powershell.script_block_text:*login* OR powershell.script_block_text:*credential*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.n… | 0 |  |
| q-0980061a5e | check C090 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-5025f26dd6 | check C091 | search | {"dataset": "zeek", "query": "event.action:http AND (url.original:*login* OR url.original:*portal*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "… | 0 |  |
| q-05e9f4ee36 | check C092 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-04b048d2f0 | check C093 | aggregate | {"dataset": "windows.sysmon", "field": "win.SourceImage", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-1124b32333 | check C094 | aggregate | {"dataset": "windows.sysmon", "field": "win.ImageLoaded", "query": "event.code:7", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 20259 |  |
| q-1e37fafda1 | check C095 | search | {"dataset": "windows.sysmon", "query": "event.code:8", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinatio… | 95 |  |
| q-53d1acf7e9 | check C096 | aggregate | {"dataset": "windows.security", "field": "win.CallerProcessName", "query": "event.code:4656 AND win.ObjectType:*Process*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 13 |  |
| q-1059121587 | check C097 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:*hook* OR powershell.script_block_text:*SetWindowsHookEx* OR powershell.script_block_text:*MiniDump*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.… | 0 |  |
| q-8c193f4030 | check C098 | search | {"dataset": "windows.other", "query": "message:*hook* OR message:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "sou… | 0 |  |
| q-5566f63642 | check C099 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-22144e4aaf | check C100 | aggregate | {"dataset": "windows.security", "field": "source.ip", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-2ac5bedf18 | check C101 | timeline | {"dataset": "windows.security", "query": "event.code:4625", "interval": "1m", "time_from": null, "time_to": null} | 0 |  |
| q-d0c9092339 | check C102 | search | {"dataset": "windows.other", "query": "message:*logon* OR message:*password*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 2 |  |
| q-576e13011f | check C103 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:*Credential* OR powershell.script_block_text:*Password*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.n… | 0 |  |
| q-701032ea78 | check C104 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*net* OR process.command_line:*login*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 30 |  |
| q-94310a9606 | check C105 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-7432767915 | check C106 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 0 |  |
| q-f0b033b285 | check C107 | timeline | {"dataset": "windows.security", "query": "event.code:4625", "interval": "1m", "time_from": null, "time_to": null} | 0 |  |
| q-e057b4cf9e | check C108 | search | {"dataset": "windows.other", "query": "message:*4625* OR message:*failed*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "so… | 2 | F14 |
| q-8ba969cf63 | check C109 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:*Password* OR powershell.script_block_text:*Credential*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.n… | 0 |  |
| q-ae5d2d59e7 | check C110 | aggregate | {"dataset": "windows.sysmon", "field": "process.command_line", "query": "event.code:1 AND process.command_line:*password*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-d6ccd3991a | check C111 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 OR event.code:4656 OR event.code:4670", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 10977 |  |
| q-d585b2f1c3 | check C112 | aggregate | {"dataset": "windows.security", "field": "win.ProcessName", "query": "event.code:4663 AND (win.ObjectName:*SAM* OR win.ObjectName:*SECURITY*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-ddce7951b2 | check C113 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*hash* OR process.command_line:*crack*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-629790044a | check C114 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND (win.TargetFilename:*.txt OR win.TargetFilename:*.pot)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 20 |  |
| q-3fca488072 | check C115 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10 AND (win.TargetImage:*lsass* OR win.TargetImage:*SAM*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-b7e813c220 | check C116 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:*hash* OR powershell.script_block_text:*ConvertTo-SecureString*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code",… | 0 |  |
| q-60a4f860cd | check C117 | search | {"dataset": "windows.other", "query": "message:*SAM* OR message:*hash*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "sourc… | 1 |  |
| q-4fdc100b98 | check C118 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-855227356b | check C119 | aggregate | {"dataset": "windows.security", "field": "source.ip", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-5201e9bdec | check C120 | search | {"dataset": "windows.security", "query": "event.code:4648", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 15 | F17 |
| q-a0c257b754 | check C121 | timeline | {"dataset": "windows.security", "query": "event.code:4625", "interval": "1m", "time_from": null, "time_to": null} | 0 |  |
| q-58634eef9f | check C122 | search | {"dataset": "windows.other", "query": "message:*logon* OR message:*account*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "… | 7 | F17 |
| q-686890fb58 | check C123 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:*Password* OR powershell.script_block_text:*Credential*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.n… | 0 |  |
| q-9fb4e1fe7e | check C124 | aggregate | {"dataset": "windows.sysmon", "field": "process.command_line", "query": "event.code:1 AND process.command_line:*user*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1 |  |
| q-163c1d0f1b | check C125 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-27dd4372b3 | check C126 | aggregate | {"dataset": "windows.security", "field": "source.ip", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-ef2522503c | check C127 | timeline | {"dataset": "windows.security", "query": "event.code:4625", "interval": "1m", "time_from": null, "time_to": null} | 0 |  |
| q-06516f36d4 | check C128 | search | {"dataset": "windows.other", "query": "message:*logon* OR message:*credential*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line"… | 4 |  |
| q-b1cb9eeb52 | check C129 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:*Credential* OR powershell.script_block_text:*Password*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.n… | 0 |  |
| q-bb7f1ec243 | check C130 | aggregate | {"dataset": "windows.sysmon", "field": "process.command_line", "query": "event.code:1 AND process.command_line:*password*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-ddce74f7b9 | check C131 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 297 |  |
| q-85d49d3723 | check C132 | search | {"dataset": "windows.security", "query": "event.code:4648", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 15 |  |
| q-9c7c3acb8c | check C133 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-6acc84e640 | check C134 | search | {"dataset": "windows.sysmon", "query": "event.code:13 AND registry.path:*Credential*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command… | 11 | F19 |
| q-18946cbeeb | check C135 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND powershell.script_block_text:*Credential*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executab… | 0 |  |
| q-39d7464c05 | check C136 | search | {"dataset": "windows.other", "query": "message:*Credential*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "des… | 2 | F19 |
| q-c98dadd755 | check C137 | aggregate | {"dataset": "windows.security", "field": "win.ObjectType", "query": "event.code:4656 OR event.code:4663 OR event.code:4670", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 10977 |  |
| q-3a1eca9fb6 | check C138 | search | {"dataset": "windows.security", "query": "event.code:5140 OR event.code:5145", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 163 | F21 |
| q-1e68f498f4 | check C139 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1649 |  |
| q-b7c2867b60 | check C140 | search | {"dataset": "windows.sysmon", "query": "event.code:3 AND (destination.port:445 OR destination.port:139)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable… | 66 | F21 |
| q-17f6e038c0 | check C141 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*445* OR powershell.script_block_text:*WebDAV* OR powershell.script_block_text:*NTLM*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "ob… | 0 |  |
| q-1135d55d4b | check C142 | search | {"dataset": "windows.other", "query": "message:*445* OR message:*WebDAV*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "sou… | 0 |  |
| q-395e3c8114 | check C143 | aggregate | {"dataset": "zeek", "field": "destination.port", "query": "event.action:conn AND (destination.port:445 OR destination.port:139)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 50 |  |
| q-4aeadc723a | check C144 | search | {"dataset": "zeek", "query": "event.action:http AND (http.request.method:PROPFIND OR http.request.method:MOVE OR http.request.method:OPTIONS)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.c… | 36 |  |
| q-65d3d6445e | check C145 | aggregate | {"dataset": "windows.security", "field": "event.code", "query": "event.code:4768 OR event.code:4769 OR event.code:4770", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 42 |  |
| q-3d310d8088 | check C146 | search | {"dataset": "windows.security", "query": "event.code:4769", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 28 |  |
| q-8aa7593ec1 | check C147 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-d918b034c8 | check C148 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.GrantedAccess:*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line",… | 39283 |  |
| q-878275ec70 | check C149 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*Invoke-* OR powershell.script_block_text:*Exploit*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "ev… | 0 |  |
| q-96096c7ec2 | check C150 | search | {"dataset": "windows.other", "query": "message:*exploit*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destin… | 0 |  |
| q-c1140839e5 | check C151 | search | {"dataset": "zeek", "query": "event.action:notice OR event.action:weird", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "sour… | 14 |  |
| q-e392618238 | check C152 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 460 |  |
| q-a90e0a1778 | check C153 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*cookie* OR process.command_line:*Cookie*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.nam… | 5 | F26 |
| q-108b70396b | check C154 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1649 |  |
| q-775934eaab | check C155 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (win.TargetFilename:*Cookies* OR win.TargetFilename:*cookie*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "pr… | 1 |  |
| q-cebc3b8b68 | check C156 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-97c98f560e | check C157 | search | {"dataset": "windows.sysmon", "query": "event.code:2 AND (win.TargetFilename:*Cookies* OR win.TargetFilename:*cookie*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "pro… | 0 |  |
| q-c99fb742ce | check C158 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*cookie* OR powershell.script_block_text:*Cookie*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "even… | 0 |  |
| q-0bf993ca97 | check C159 | search | {"dataset": "windows.other", "query": "message:*cookie*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destina… | 0 |  |
| q-a3e598cd4d | check C160 | search | {"dataset": "zeek", "query": "event.action:http AND http.request.method:GET", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "… | 2 |  |
| q-91aa0ec0e2 | check C161 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 460 |  |
| q-1da811e33c | check C162 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*password* OR process.command_line:*credential* OR process.command_line:*unattend*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name",… | 0 |  |
| q-2d92d46b6f | check C163 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1649 |  |
| q-cf0e30baca | check C164 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (win.TargetFilename:*unattend* OR win.TargetFilename:*password* OR win.TargetFilename:*credential*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.da… | 1 |  |
| q-a42a357b79 | check C165 | aggregate | {"dataset": "windows.sysmon", "field": "registry.path", "query": "event.code:13 OR event.code:14", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 17541 |  |
| q-4d5d637cba | check C166 | search | {"dataset": "windows.sysmon", "query": "event.code:13 AND (registry.path:*Password* OR registry.path:*Credential*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process… | 17 | F29 |
| q-cf60d979d0 | check C167 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*password* OR powershell.script_block_text:*credential*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset",… | 0 |  |
| q-6a3bd4f2ef | check C168 | search | {"dataset": "windows.other", "query": "message:*password*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 0 |  |
| q-c2adaf3db5 | check C169 | search | {"dataset": "zeek", "query": "event.action:smb_files", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinatio… | 12 |  |
| q-2cd24b9596 | check C170 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 297 |  |
| q-cd3644a52b | check C171 | search | {"dataset": "windows.security", "query": "event.code:4648", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 15 |  |
| q-6b35dd04ca | check C172 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 447 |  |
| q-9912531c95 | check C173 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*password* OR process.command_line:*credential* OR process.command_line:*config*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event… | 8 |  |
| q-1d2458f365 | check C174 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1649 |  |
| q-8aa11ce4b8 | check C175 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (win.TargetFilename:*.config OR win.TargetFilename:*.xml OR win.TargetFilename:*.txt)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event… | 44 |  |
| q-678048f738 | check C176 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*Get-Content* OR powershell.script_block_text:*Select-String*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dat… | 0 |  |
| q-2dad1786e2 | check C177 | search | {"dataset": "windows.other", "query": "message:*password*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 0 |  |
| q-d8ea7e0782 | check C178 | search | {"dataset": "zeek", "query": "event.action:smb_files", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinatio… | 12 |  |
| q-416861268c | check C179 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"13\" AND (TO_LOWER(registry.path) LIKE \"*\\\\sam\\\\*\" OR TO_LOWER(registry.path) LIKE \"*\\\\security\\\\*\" OR TO_LOWER(registry.path) LIKE \"*password*\" OR TO_LOWER… | ERROR |  |
| q-d360af92a3 | check C179 (repaired) | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"13\" AND (TO_LOWER(registry.path) LIKE \"*sam*\" OR TO_LOWER(registry.path) LIKE \"*security*\" OR TO_LOWER(registry.path) LIKE \"*password*\" OR TO_LOWER(registry.path) … | 170 |  |
| q-d00a30967c | check C180 | aggregate | {"dataset": "windows.sysmon", "field": "registry.path", "query": "event.code:13", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 17541 |  |
| q-bdc021fb99 | check C181 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*reg query*\" OR TO_LOWER(process.command_line) LIKE \"*reg save*\" OR TO_LOWER(process.command_line) LIKE \"*\\\\sam*\" OR… | ERROR |  |
| q-8a19776d39 | check C181 (repaired) | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*reg query*\" OR TO_LOWER(process.command_line) LIKE \"*reg save*\" OR TO_LOWER(process.command_line) LIKE \"*sam*\" OR TO_… | 5 |  |
| q-4a5ddf515a | check C182 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4663\",\"4656\",\"4670\",\"4658\") AND (TO_LOWER(win.ObjectName) LIKE \"*\\\\sam*\" OR TO_LOWER(win.ObjectName) LIKE \"*\\\\security*\" OR TO_LOWER(win.ObjectName) LIK… | ERROR |  |
| q-9f5e687c4b | check C182 (repaired) | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4663\",\"4656\",\"4670\",\"4658\") AND (TO_LOWER(win.ObjectName) LIKE \"*sam*\" OR TO_LOWER(win.ObjectName) LIKE \"*security*\" OR TO_LOWER(win.ObjectName) LIKE \"*lsa… | 500 |  |
| q-f3ac3baa62 | check C183 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code IN (\"4103\",\"4104\") AND (TO_LOWER(COALESCE(powershell.script_block_text, win.ScriptBlockText, \"\")) LIKE \"*reg query*\" OR TO_LOWER(COALESCE(powershell.script_block_t… | ERROR |  |
| q-6aa55a58c3 | check C183 (repaired) | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code IN (\"4103\",\"4104\") AND (TO_LOWER(COALESCE(win.ScriptBlockText, \"\")) LIKE \"*reg query*\" OR TO_LOWER(COALESCE(win.ScriptBlockText, \"\")) LIKE \"*reg save*\" OR TO_L… | 1 |  |
| q-83cde3a94b | check C184 | esql | {"query": "FROM logs-windows.other-default METADATA _id, _index \| WHERE TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*\\\\sam*\" OR TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*\\\\security*\" OR TO_LOWER(COALESCE(message, win.Message, \"\"… | ERROR |  |
| q-304dded722 | check C184 (repaired) | esql | {"query": "FROM logs-windows.other-default METADATA _id, _index \| WHERE TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*\\\\\\\\sam*\" OR TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*\\\\\\\\security*\" OR TO_LOWER(COALESCE(message, win.Messa… | 3 |  |
| q-4fe2f55f23 | check C185 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code IN (\"4103\",\"4104\") AND (TO_LOWER(COALESCE(powershell.script_block_text, win.ScriptBlockText, \"\")) LIKE \"*history*\" OR TO_LOWER(COALESCE(powershell.script_block_tex… | ERROR |  |
| q-a873f15996 | check C185 (repaired) | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code IN (\"4103\",\"4104\") AND (TO_LOWER(COALESCE(win.ScriptBlockText, \"\")) LIKE \"*history*\" OR TO_LOWER(COALESCE(win.ScriptBlockText, \"\")) LIKE \"*consolehost_history*\… | 1 |  |
| q-e5b6adcdf7 | check C186 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*consolehost_history*\" OR TO_LOWER(process.command_line) LIKE \"*psreadline*\" OR TO_LOWER(process.command_line) LIKE \"*h… | 0 |  |
| q-bd3fab3dcc | check C187 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*consolehost_history*\" OR TO_LOWER(file.path) LIKE \"*psreadline*\" OR TO_LOWER(file.path) LIKE \"*\\\\history*\" OR TO_LOWER(file.p… | ERROR |  |
| q-49e6f6a9d7 | check C187 (repaired) | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*consolehost_history*\" OR TO_LOWER(file.path) LIKE \"*psreadline*\" OR TO_LOWER(file.path) LIKE \"*history*\" OR TO_LOWER(file.path)… | 15 |  |
| q-0c43af85fa | check C188 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4663\",\"4656\",\"4658\") AND (TO_LOWER(win.ObjectName) LIKE \"*consolehost_history*\" OR TO_LOWER(win.ObjectName) LIKE \"*psreadline*\" OR TO_LOWER(win.ObjectName) LI… | 0 |  |
| q-3aa885d6ce | check C189 | esql | {"query": "FROM logs-windows.other-default METADATA _id, _index \| WHERE TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*history*\" OR TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*psreadline*\" \| KEEP @timestamp, host.name, event.code, messag… | 5 |  |
| q-4088aeaaed | check C190 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*.key\" OR TO_LOWER(file.path) LIKE \"*.pgp\" OR TO_LOWER(file.path) LIKE \"*.gpg\" OR TO_LOWER(file.path) LIKE \"*.ppk\" OR TO_LOWER… | 1 |  |
| q-4d26d64799 | check C191 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*.pem*\" OR TO_LOWER(process.command_line) LIKE \"*.pfx*\" OR TO_LOWER(process.command_line) LIKE \"*.p12*\" OR TO_LOWER(pr… | 0 |  |
| q-dd0e4d8504 | check C192 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"5145\" AND (TO_LOWER(win.RelativeTargetName) LIKE \"*.key\" OR TO_LOWER(win.RelativeTargetName) LIKE \"*.pem\" OR TO_LOWER(win.RelativeTargetName) LIKE \"*.pfx\" OR TO_… | 0 |  |
| q-2c5c4ee2d1 | check C193 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4663\",\"4656\",\"4658\") AND (TO_LOWER(win.ObjectName) LIKE \"*.key\" OR TO_LOWER(win.ObjectName) LIKE \"*.pem\" OR TO_LOWER(win.ObjectName) LIKE \"*.pfx\" OR TO_LOWE… | 0 |  |
| q-dfb46bee68 | check C194 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code IN (\"4103\",\"4104\") AND (TO_LOWER(COALESCE(powershell.script_block_text, win.ScriptBlockText, \"\")) LIKE \"*.pem*\" OR TO_LOWER(COALESCE(powershell.script_block_text, … | ERROR |  |
| q-1a0a26d610 | check C194 (repaired) | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code IN (\"4103\",\"4104\") AND (TO_LOWER(COALESCE(win.ScriptBlockText, \"\")) LIKE \"*.pem*\" OR TO_LOWER(COALESCE(win.ScriptBlockText, \"\")) LIKE \"*.pfx*\" OR TO_LOWER(COAL… | 2 |  |
| q-70ce5253a4 | check C195 | esql | {"query": "FROM logs-windows.other-default METADATA _id, _index \| WHERE TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*.pem*\" OR TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*.pfx*\" OR TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*… | 0 |  |
| q-a1042ed368 | check C196 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code IN (\"4103\",\"4104\") AND (TO_LOWER(COALESCE(powershell.script_block_text, win.ScriptBlockText, \"\")) LIKE \"*groups.xml*\" OR TO_LOWER(COALESCE(powershell.script_block_… | ERROR |  |
| q-cd5ba303c6 | check C196 (repaired) | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code IN (\"4103\",\"4104\") AND (TO_LOWER(COALESCE(win.ScriptBlockText, \"\")) LIKE \"*groups.xml*\" OR TO_LOWER(COALESCE(win.ScriptBlockText, \"\")) LIKE \"*sysvol*\" OR TO_LO… | 32 |  |
| q-f7a3b2926b | check C197 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*sysvol*\" OR TO_LOWER(process.command_line) LIKE \"*groups.xml*\" OR TO_LOWER(process.command_line) LIKE \"*cpassword*\" O… | 0 |  |
| q-fbcd245711 | check C198 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*groups.xml*\" OR TO_LOWER(file.path) LIKE \"*sysvol*\" OR TO_LOWER(file.path) LIKE \"*gpprefdecrypt*\" OR TO_LOWER(file.path) LIKE \… | 22 |  |
| q-cc4ffd458a | check C199 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"5145\" AND (TO_LOWER(win.RelativeTargetName) LIKE \"*groups.xml*\" OR TO_LOWER(win.ShareName) LIKE \"*sysvol*\" OR TO_LOWER(win.ShareName) LIKE \"*netlogon*\") \| KEEP … | 56 |  |
| q-010efc5ee4 | check C200 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4663\",\"4656\",\"4658\") AND (TO_LOWER(win.ObjectName) LIKE \"*groups.xml*\" OR TO_LOWER(win.ObjectName) LIKE \"*sysvol*\" OR TO_LOWER(win.ObjectName) LIKE \"*gpp*\")… | 0 |  |
| q-f0931631cf | check C201 | esql | {"query": "FROM logs-windows.other-default METADATA _id, _index \| WHERE TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*sysvol*\" OR TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*groups.xml*\" OR TO_LOWER(COALESCE(message, win.Message, \"\")) … | 0 |  |
| q-c3ea877e43 | check C202 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND (TO_LOWER(win.TargetImage) LIKE \"*lsass.exe\" OR TO_LOWER(win.SourceImage) LIKE \"*lsass.exe\") \| KEEP @timestamp, host.name, user.name, win.SourceImage, win.T… | 500 |  |
| q-4f2bde701c | check C203 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass.exe", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-fe66b213d4 | check C204 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*sekurlsa*\" OR TO_LOWER(process.command_line) LIKE \"*lsadump*\" OR TO_LOWER(process.command_line) LIKE \"*mimikatz*\" OR … | 0 |  |
| q-396d12c230 | check C205 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4663\",\"4656\",\"4670\",\"4658\") AND (TO_LOWER(win.ObjectName) LIKE \"*\\\\protect\\\\*\" OR TO_LOWER(win.ObjectName) LIKE \"*credential*\" OR TO_LOWER(win.ObjectNam… | ERROR |  |
| q-09a1bcb59d | check C205 (repaired) | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4663\",\"4656\",\"4670\",\"4658\") AND (TO_LOWER(win.ObjectName) LIKE \"*protect*\" OR TO_LOWER(win.ObjectName) LIKE \"*credential*\" OR TO_LOWER(win.ObjectName) LIKE … | 19 | F32 |
| q-76b9b2ce72 | check C206 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4688\" AND (TO_LOWER(process.command_line) LIKE \"*sekurlsa*\" OR TO_LOWER(process.command_line) LIKE \"*lsadump*\" OR TO_LOWER(process.command_line) LIKE \"*mimikatz*\… | 0 |  |
| q-7fe3f7edac | check C207 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code IN (\"4103\",\"4104\") AND (TO_LOWER(COALESCE(powershell.script_block_text, win.ScriptBlockText, \"\")) LIKE \"*sekurlsa*\" OR TO_LOWER(COALESCE(powershell.script_block_te… | ERROR |  |
| q-83c3202ab4 | check C207 (repaired) | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code IN (\"4103\",\"4104\") AND (TO_LOWER(COALESCE(win.ScriptBlockText, \"\")) LIKE \"*sekurlsa*\" OR TO_LOWER(COALESCE(win.ScriptBlockText, \"\")) LIKE \"*lsadump*\" OR TO_LOW… | 5 |  |
| q-a471516865 | check C208 | esql | {"query": "FROM logs-windows.other-default METADATA _id, _index \| WHERE TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*lsass*\" OR TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*credential*\" OR TO_LOWER(COALESCE(message, win.Message, \"\")) L… | 2 | F32 |
| q-1050c78f5c | check C209 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*login data*\" OR TO_LOWER(process.command_line) LIKE \"*\\\\google\\\\chrome\\\\user data*\" OR TO_LOWER(process.command_l… | ERROR |  |
| q-aacc019d1d | check C209 (repaired) | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*login data*\" OR TO_LOWER(process.command_line) LIKE \"*google*chrome*user data*\" OR TO_LOWER(process.command_line) LIKE … | 0 |  |
| q-a30f07070b | check C210 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*login data*\" OR TO_LOWER(file.path) LIKE \"*logins.json*\" OR TO_LOWER(file.path) LIKE \"*key3.db*\" OR TO_LOWER(file.path) LIKE \"… | ERROR |  |
| q-5af174b02c | check C210 (repaired) | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*login data*\" OR TO_LOWER(file.path) LIKE \"*logins.json*\" OR TO_LOWER(file.path) LIKE \"*key3.db*\" OR TO_LOWER(file.path) LIKE \"… | 0 |  |
| q-5faa2bb836 | check C211 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND (TO_LOWER(win.TargetImage) LIKE \"*chrome.exe\" OR TO_LOWER(win.TargetImage) LIKE \"*firefox.exe\" OR TO_LOWER(win.TargetImage) LIKE \"*msedge.exe\" OR TO_LOWER(… | 0 |  |
| q-c0a2a91c72 | check C212 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4663\",\"4656\",\"4658\") AND (TO_LOWER(win.ObjectName) LIKE \"*login data*\" OR TO_LOWER(win.ObjectName) LIKE \"*logins.json*\" OR TO_LOWER(win.ObjectName) LIKE \"*ke… | ERROR |  |
| q-885daaa0f2 | check C212 (repaired) | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4663\",\"4656\",\"4658\") AND (TO_LOWER(win.ObjectName) LIKE \"*login data*\" OR TO_LOWER(win.ObjectName) LIKE \"*logins.json*\" OR TO_LOWER(win.ObjectName) LIKE \"*ke… | 0 |  |
| q-5c48bdc4e5 | check C213 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code IN (\"4103\",\"4104\") AND (TO_LOWER(COALESCE(powershell.script_block_text, win.ScriptBlockText, \"\")) LIKE \"*login data*\" OR TO_LOWER(COALESCE(powershell.script_block_… | ERROR |  |
| q-889efd94fe | check C213 (repaired) | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code IN (\"4103\",\"4104\") AND (TO_LOWER(COALESCE(win.ScriptBlockText, \"\")) LIKE \"*login data*\" OR TO_LOWER(COALESCE(win.ScriptBlockText, \"\")) LIKE \"*logins.json*\" OR … | 0 |  |
| q-25ad2dec52 | check C214 | esql | {"query": "FROM logs-windows.other-default METADATA _id, _index \| WHERE TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*login data*\" OR TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*logins.json*\" OR TO_LOWER(COALESCE(message, win.Message, \"… | 0 |  |
| q-08c020b92c | check C215 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 326 | F32 |
| q-6cbff3dcc7 | check C216 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-01791faf4c | check C217 | search | {"dataset": "windows.sysmon", "query": "event.code:15 AND file.path:*Credentials*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 0 |  |
| q-b6ee667122 | check C218 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*vault* OR process.command_line:*Credential* OR process.command_line:*cmdkey*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "eve… | 0 |  |
| q-b2f1f17f17 | check C219 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*Credential* OR powershell.script_block_text:*vault* OR powershell.script_block_text:*cmdkey*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.na… | 0 |  |
| q-3616552332 | check C220 | search | {"dataset": "windows.other", "query": "message:*Credential* OR message:*vault*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line"… | 2 |  |
| q-1b1f67ecc2 | check C221 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.executable:*keepass* OR process.executable:*1password* OR process.executable:*bitwarden* OR process.executable:*lastpass* OR process.executable:*dashlane*)", "time_from": null, "time_to": null, … | 0 |  |
| q-ff92fdffaf | check C222 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*keepass* OR file.path:*1password* OR file.path:*bitwarden* OR file.path:*lastpass*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.datase… | 0 |  |
| q-5ae4a9b545 | check C223 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND (win.TargetImage:*keepass* OR win.TargetImage:*1password* OR win.TargetImage:*bitwarden*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "e… | 0 |  |
| q-d91408da5e | check C224 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*keepass* OR process.command_line:*1password* OR process.command_line:*bitwarden* OR process.command_line:*kdbx*)", "time_from": null, "time_to": null, "fields": ["@timestamp",… | 0 |  |
| q-c52f317a7a | check C225 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*keepass* OR powershell.script_block_text:*kdbx* OR powershell.script_block_text:*1password* OR powershell.script_block_text:*bitwarden*)", "time_from": null, "time_t… | 0 |  |
| q-921a005b11 | check C226 | search | {"dataset": "windows.other", "query": "message:*keepass* OR message:*1password* OR message:*bitwarden* OR message:*kdbx*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "p… | 0 |  |
| q-999d3bc4a7 | check C227 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 326 |  |
| q-739f046515 | check C228 | aggregate | {"dataset": "windows.sysmon", "field": "win.SourceImage", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-ec707aa897 | check C229 | search | {"dataset": "windows.sysmon", "query": "event.code:7 AND (win.ImageLoaded:*lsass* OR win.ImageLoaded:*cryptdll* OR win.ImageLoaded:*sam* OR win.ImageLoaded:*msv1_0*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "… | 77 | F38 |
| q-8c0023d6d1 | check C230 | search | {"dataset": "windows.security", "query": "event.code:4657 AND (win.ObjectName:*lsass* OR win.ObjectName:*cryptdll* OR win.ObjectName:*msv1_0* OR win.ObjectName:*sam*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", … | 0 |  |
| q-61e06d7e80 | check C231 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*lsass* OR process.command_line:*cryptdll* OR process.command_line:*msv1_0*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event… | 0 |  |
| q-1d86fa4fae | check C232 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*lsass* OR powershell.script_block_text:*cryptdll* OR powershell.script_block_text:*msv1_0* OR powershell.script_block_text:*SecurityPackages*)", "time_from": null, "… | 0 |  |
| q-1c2afd66e7 | check C233 | search | {"dataset": "windows.other", "query": "message:*lsass* OR message:*cryptdll* OR message:*msv1_0*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "pro… | 0 |  |
| q-9435033a53 | check C234 | search | {"dataset": "windows.security", "query": "event.code:4624 AND win.LogonType:3", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line",… | 218 | F34 |
| q-17135ecd7d | check C235 | search | {"dataset": "windows.security", "query": "event.code:4648", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 15 | F34 |
| q-7d99263e98 | check C236 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4624 OR event.code:4648", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 312 |  |
| q-5c17747a35 | check C237 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 326 |  |
| q-fa6c7de2d0 | check C238 | search | {"dataset": "windows.sysmon", "query": "event.code:7 AND (win.ImageLoaded:*lsass* OR win.ImageLoaded:*cryptdll*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.e… | 33 |  |
| q-a97e375c85 | check C239 | search | {"dataset": "windows.other", "query": "message:*lsass* OR message:*cryptdll*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 0 |  |
| q-dd57498614 | check C240 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*lsass* OR powershell.script_block_text:*cryptdll* OR powershell.script_block_text:*Skeleton* OR powershell.script_block_text:*DCShadow*)", "time_from": null, "time_t… | 0 |  |
| q-1ddfa5da83 | check C241 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*System32* AND (file.path:*.dll))", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable"… | 0 |  |
| q-fc9cd41597 | check C242 | search | {"dataset": "windows.sysmon", "query": "event.code:7 AND (win.ImageLoaded:*lsass* OR win.ImageLoaded:*cryptdll*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.e… | 33 |  |
| q-02dd641da2 | check C243 | search | {"dataset": "windows.security", "query": "event.code:4657 AND (win.ObjectName:*Notification\\ Packages* OR win.ObjectName:*Password* OR win.ObjectName:*lsass*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.… | 0 |  |
| q-6f87f05170 | check C244 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*Notification* OR process.command_line:*PasswordFilter*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.co… | 0 |  |
| q-8823cb4931 | check C245 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*Notification* OR powershell.script_block_text:*PasswordFilter* OR powershell.script_block_text:*lsass*)", "time_from": null, "time_to": null, "fields": ["@timestamp"… | 0 |  |
| q-0c35d6c1d3 | check C246 | search | {"dataset": "windows.other", "query": "message:*Notification* OR message:*PasswordFilter* OR message:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.execu… | 10 |  |
| q-4b7b1ab96f | check C247 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*AllowReversiblePasswordEncryption* OR powershell.script_block_text:*ReversibleEncryption* OR powershell.script_block_text:*Set-ADUser*)", "time_from": null, "time_to… | 0 |  |
| q-d2d2ddb279 | check C248 | search | {"dataset": "windows.powershell", "query": "event.code:4103 AND (message:*AllowReversiblePasswordEncryption* OR message:*ReversibleEncryption*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event… | 0 |  |
| q-3b7fe75f73 | check C249 | search | {"dataset": "windows.security", "query": "event.code:4739", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 0 |  |
| q-23f4bc924b | check C250 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*Reversible* OR process.command_line:*Set-ADUser* OR process.command_line:*dsmod*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", … | 0 |  |
| q-f257341209 | check C251 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*Reversible* OR process.command_line:*Set-ADUser* OR process.command_line:*dsmod*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "even… | 0 |  |
| q-f176632680 | check C252 | search | {"dataset": "windows.other", "query": "message:*Reversible* OR message:*AllowReversiblePasswordEncryption*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executa… | 0 |  |
| q-c56ec66383 | check C253 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(powershell.script_block_text) LIKE \"*set-aduser*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*set-adauthenticationpolicy*\" OR TO_LOWER(powershell.script_block_text)… | ERROR |  |
| q-f05171c2b4 | check C253 (repaired) | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*set-aduser*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*set-adauthenticationpolicy*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*strongauthenticati… | 1 |  |
| q-9794139729 | check C254 | count | {"dataset": "windows.security", "query": "event.code:4739", "time_from": null, "time_to": null} | 0 |  |
| q-4d1841087d | check C255 | aggregate | {"dataset": "windows.security", "field": "win.ObjectType", "query": "event.code:5136 OR event.code:4739", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-abd061c1be | check C256 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*set-aduser*\" OR TO_LOWER(process.command_line) LIKE \"*set-adauthenticationpolicy*\" OR TO_LOWER(process.command_line) LI… | 0 |  |
| q-6c96479989 | check C257 | search | {"dataset": "windows.other", "query": "event.code:4739 OR event.code:5136 OR event.code:4738", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process… | 0 |  |
| q-bb024a1fdd | check C258 | aggregate | {"dataset": "windows.security", "field": "win.LogonProcessName", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 297 |  |
| q-b5c8f753e2 | check C259 | aggregate | {"dataset": "windows.security", "field": "win.AuthenticationPackageName", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 297 |  |
| q-ef5c6e087c | check C260 | count | {"dataset": "windows.security", "query": "event.code:5136", "time_from": null, "time_to": null} | 0 |  |
| q-f687d9f039 | check C261 | aggregate | {"dataset": "windows.sysmon", "field": "win.ImageLoaded", "query": "event.code:7", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 20259 |  |
| q-db515b0ffb | check C262 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(powershell.script_block_text) LIKE \"*connect-msolservice*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*connect-azuread*\" OR TO_LOWER(powershell.script_block_text) L… | ERROR |  |
| q-6a26959a6e | check C262 (repaired) | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*connect-msolservice*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*connect-azuread*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*new-azuread*\" OR TO… | 0 |  |
| q-818c1386ba | check C263 | search | {"dataset": "windows.other", "query": "event.code:5136 OR event.code:4739 OR event.code:4738", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process… | 0 |  |
| q-209ebfef40 | check C264 | count | {"dataset": "windows.security", "query": "event.code:4657", "time_from": null, "time_to": null} | 36 |  |
| q-e710a629cc | check C265 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4657\" AND (TO_LOWER(win.ObjectName) LIKE \"*networkprovider*\" OR TO_LOWER(win.ObjectName) LIKE \"*credential*\" OR TO_LOWER(win.ObjectName) LIKE \"*winlogon*\") \| KE… | 0 |  |
| q-c74ef65553 | check C266 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*networkprovider*\" OR TO_LOWER(file.path) LIKE \"*system32*credential*\" OR TO_LOWER(file.path) LIKE \"*winlogon*\") \| KEEP @timest… | 1 |  |
| q-28aa68f05d | check C267 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 39283 |  |
| q-f49842d30c | check C268 | aggregate | {"dataset": "windows.sysmon", "field": "win.ImageLoaded", "query": "event.code:7", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 20259 |  |
| q-91b3437994 | check C269 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(powershell.script_block_text) LIKE \"*networkprovider*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*new-itemproperty*\" OR TO_LOWER(powershell.script_block_text) LIKE… | ERROR |  |
| q-db67d49c69 | check C269 (repaired) | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*networkprovider*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*new-itemproperty*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*reg add*\" \| KEEP @tim… | 0 |  |
| q-216a3556d4 | check C270 | search | {"dataset": "windows.other", "query": "event.code:4657 OR event.code:11 OR event.code:7", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.comm… | 4 |  |
| q-4a0a7a745e | check C271 | aggregate | {"dataset": "windows.security", "field": "win.ObjectType", "query": "event.code:4663 OR event.code:4670 OR event.code:4656", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 10977 |  |
| q-07d95e7913 | check C272 | aggregate | {"dataset": "windows.security", "field": "win.ProcessName", "query": "event.code:4663 OR event.code:4670 OR event.code:4656", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 10977 |  |
| q-5fbea60737 | check C273 | aggregate | {"dataset": "windows.sysmon", "field": "win.DestinationHostname", "query": "event.code:3", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 1229 |  |
| q-c5650dc4c2 | check C274 | aggregate | {"dataset": "windows.sysmon", "field": "win.QueryName", "query": "event.code:22", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 81 |  |
| q-a30fb6e79c | check C275 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(powershell.script_block_text) LIKE \"*responder*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*mitm*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*arpspoof*\" OR… | ERROR |  |
| q-75173b1023 | check C275 (repaired) | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*responder*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*mitm*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*arpspoof*\" OR TO_LOWER(win.ScriptBlockTe… | 0 |  |
| q-e8de953a97 | check C276 | search | {"dataset": "windows.other", "query": "event.code:4663 OR event.code:4670 OR event.code:4656 OR event.code:3 OR event.code:22", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name… | 2 |  |
| q-a4f7303c29 | check C277 | aggregate | {"dataset": "zeek", "field": "zeek.conn_state", "query": "event.action:conn", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 613 |  |
| q-2066837a09 | check C278 | aggregate | {"dataset": "zeek", "field": "zeek.service", "query": "event.action:conn", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 613 |  |
| q-e0d5fabd5c | check C279 | count | {"dataset": "windows.security", "query": "event.code:4697", "time_from": null, "time_to": null} | 23 |  |
| q-294b8167a9 | check C280 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4657\" AND TO_LOWER(win.ObjectName) LIKE \"*dnsclient*\" \| KEEP @timestamp, host.name, user.name, win.ObjectName, win.NewValue, _id, _index"} | 0 |  |
| q-a2847e30e1 | check C281 | aggregate | {"dataset": "windows.sysmon", "field": "win.DestinationHostname", "query": "event.code:3", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 1229 |  |
| q-ecfa195dda | check C282 | aggregate | {"dataset": "windows.sysmon", "field": "win.QueryName", "query": "event.code:22", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 81 |  |
| q-052197de34 | check C283 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(powershell.script_block_text) LIKE \"*llmnr*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*nbt-ns*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*responder*\" OR … | ERROR |  |
| q-c35a611e93 | check C283 (repaired) | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*llmnr*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*nbt-ns*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*responder*\" OR TO_LOWER(win.ScriptBlockTex… | 0 |  |
| q-ba9ccc2e1e | check C284 | search | {"dataset": "windows.other", "query": "event.code:4697 OR event.code:4657 OR event.code:3 OR event.code:22", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executa… | 2 |  |
| q-2dd9413c3f | check C285 | aggregate | {"dataset": "zeek", "field": "zeek.id_resp_h", "query": "event.action:conn AND zeek.service:smb", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-1ec357d176 | check C286 | aggregate | {"dataset": "zeek", "field": "zeek.query", "query": "event.action:dns", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 53 |  |
| q-644cd4ad1c | check C287 | aggregate | {"dataset": "windows.sysmon", "field": "win.DestinationHostname", "query": "event.code:3", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 1229 |  |
| q-813bdc125c | check C288 | aggregate | {"dataset": "windows.sysmon", "field": "win.QueryName", "query": "event.code:22", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 81 |  |
| q-5c5ec46036 | check C289 | aggregate | {"dataset": "windows.security", "field": "win.ProcessName", "query": "event.code:4663 OR event.code:4670 OR event.code:4656", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 10977 |  |
| q-4d3d9351a3 | check C290 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(powershell.script_block_text) LIKE \"*arp*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*netsh interface*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*get-netne… | ERROR |  |
| q-a602e78194 | check C290 (repaired) | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*arp*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*netsh interface*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*get-netneighbor*\" OR TO_LOWER(win.S… | 0 |  |
| q-8d57a7e2ec | check C291 | search | {"dataset": "windows.other", "query": "event.code:3 OR event.code:22 OR event.code:4663 OR event.code:4670", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executa… | 2 |  |
| q-94b5cc027a | check C292 | aggregate | {"dataset": "zeek", "field": "zeek.orig_l2_addr", "query": "event.action:conn", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 613 |  |
| q-2988132b9f | check C293 | aggregate | {"dataset": "zeek", "field": "zeek.resp_l2_addr", "query": "event.action:conn", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 613 |  |
| q-a04c820083 | check C294 | search | {"dataset": "windows.other", "query": "event.code:(1341 OR 1342 OR 1020 OR 1063)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_lin… | 0 |  |
| q-72fd51dc67 | check C295 | aggregate | {"dataset": "windows.other", "field": "event.code", "query": "*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 216 |  |
| q-9c09b6b9e9 | check C296 | search | {"dataset": "windows.security", "query": "event.code:5156 AND win.Direction:Inbound", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_… | 0 |  |
| q-729c002b7d | check C297 | aggregate | {"dataset": "windows.sysmon", "field": "destination.port", "query": "event.code:3", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1229 |  |
| q-373d8cd684 | check C298 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:(*Dhcp* OR *dhcp*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.… | 0 |  |
| q-e60ce4afd9 | check C299 | aggregate | {"dataset": "zeek", "field": "event.action", "query": "*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 2140 |  |
| q-d842d7e84f | check C300 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4672", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 212 |  |
| q-a499a81d49 | check C301 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 297 |  |
| q-c9def1bba4 | check C302 | search | {"dataset": "windows.security", "query": "event.code:4634", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 236 |  |
| q-3531d8e89b | check C303 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-09da46a819 | check C304 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-e1ec1fa44e | check C305 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:(*kerberos* OR *Kerberos* OR *ticket* OR *Ticket*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name",… | 0 |  |
| q-d10d3178be | check C306 | search | {"dataset": "windows.other", "query": "event.code:(7045 OR 7040)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip",… | 9 |  |
| q-85a6a63dc3 | check C307 | aggregate | {"dataset": "zeek", "field": "zeek.request_type", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 35 |  |
| q-16d8057f44 | check C308 | search | {"dataset": "windows.security", "query": "event.code:4769", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 28 |  |
| q-d2d02d156e | check C309 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4672", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 212 |  |
| q-c8491b45a6 | check C310 | aggregate | {"dataset": "windows.security", "field": "win.TicketEncryptionType", "query": "event.code:4769", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 28 |  |
| q-62addf7ab1 | check C311 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-ed80d788d3 | check C312 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:(*golden* OR *Golden* OR *krbtgt* OR *KRBTGT*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "pr… | 0 |  |
| q-42e2aadcea | check C313 | aggregate | {"dataset": "windows.other", "field": "event.code", "query": "*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 216 |  |
| q-f24036afe9 | check C314 | aggregate | {"dataset": "zeek", "field": "zeek.request_type", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 35 |  |
| q-c85058ffb3 | check C315 | search | {"dataset": "windows.security", "query": "event.code:4769", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 28 |  |
| q-161473525a | check C316 | aggregate | {"dataset": "windows.security", "field": "win.ServiceName", "query": "event.code:4769", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 28 |  |
| q-59d4d70fa9 | check C317 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4672", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 212 |  |
| q-93a3f45bca | check C318 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-c09fe226c3 | check C319 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:(*silver* OR *Silver* OR *service ticket* OR *SPN*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name"… | 0 |  |
| q-550383b83a | check C320 | search | {"dataset": "windows.other", "query": "event.code:(7045 OR 7040)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip",… | 9 |  |
| q-beace91f94 | check C321 | aggregate | {"dataset": "zeek", "field": "zeek.request_type", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 35 |  |
| q-e3a2ac6b92 | check C322 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4769", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 28 |  |
| q-939f3f1c90 | check C323 | aggregate | {"dataset": "windows.security", "field": "win.TicketEncryptionType", "query": "event.code:4769", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 28 |  |
| q-7a30e3b201 | check C324 | search | {"dataset": "windows.security", "query": "event.code:4648", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 15 |  |
| q-14ec46b9b8 | check C325 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 297 |  |
| q-f1bd7b23ae | check C326 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-2e91fcdf4d | check C327 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:(*Kerberoast* OR *kerberoast* OR *Invoke-Kerberoast* OR *Rubeus*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code… | 0 |  |
| q-49427e802d | check C328 | aggregate | {"dataset": "windows.other", "field": "event.code", "query": "*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 216 |  |
| q-a18c63961b | check C329 | aggregate | {"dataset": "zeek", "field": "zeek.request_type", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 35 |  |
| q-c0ff11041d | check C330 | search | {"dataset": "windows.security", "query": "event.code:4768", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 14 |  |
| q-a4f25f7c6c | check C331 | aggregate | {"dataset": "windows.security", "field": "win.PreAuthType", "query": "event.code:4768", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 14 |  |
| q-9f192eff40 | check C332 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4768", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 14 |  |
| q-eaa7ce84ea | check C333 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 447 |  |
| q-1a86e28d32 | check C334 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:(*AS-REP* OR *asrep* OR *GetNPUsers* OR *DontRequirePreAuth*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "… | 0 |  |
| q-87a56d8487 | check C335 | aggregate | {"dataset": "windows.other", "field": "event.code", "query": "*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 216 |  |
| q-e3ad18313f | check C336 | aggregate | {"dataset": "zeek", "field": "zeek.request_type", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 35 |  |
| q-7a1455ecdb | check C337 | aggregate | {"dataset": "windows.security", "field": "win.LogonProcessName", "query": "event.code:4624 OR event.code:4648", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 312 |  |
| q-d8596b62b0 | check C338 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-d31dba95c9 | check C339 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*cookie* OR powershell.script_block_text:*token* OR powershell.script_block_text:*SAML*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "… | 0 |  |
| q-b930df1b9a | check C340 | search | {"dataset": "windows.other", "query": "event.code:7045 OR event.code:5857 OR event.code:5858", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process… | 90 |  |
| q-8017c00f6e | check C341 | aggregate | {"dataset": "zeek", "field": "event.action", "query": "event.action:http OR event.action:ssl OR event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 475 |  |
| q-0d3635552b | check C342 | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11 AND (file.path:*cookie* OR file.path:*Cookies*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1 |  |
| q-d2bfb67065 | check C343 | aggregate | {"dataset": "windows.security", "field": "win.LogonProcessName", "query": "event.code:4624 OR event.code:4648", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 312 |  |
| q-fd4b7ce121 | check C344 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*cookie* OR powershell.script_block_text:*Set-Cookie* OR powershell.script_block_text:*session*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.… | 0 |  |
| q-deeccc7146 | check C345 | search | {"dataset": "windows.other", "query": "event.code:11 OR event.code:16", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source… | 9 |  |
| q-f34d6c2d06 | check C346 | search | {"dataset": "zeek", "query": "event.action:http AND http.request.method:*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "so… | 62 |  |
| q-74169dd5f4 | check C347 | aggregate | {"dataset": "windows.security", "field": "win.LogonProcessName", "query": "event.code:4624 OR event.code:4648", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 312 |  |
| q-636746b7d5 | check C348 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*SAML* OR powershell.script_block_text:*NotOnOrAfter* OR powershell.script_block_text:*Assertion*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "hos… | 0 |  |
| q-9ae16237b8 | check C349 | search | {"dataset": "windows.other", "query": "event.code:7045 OR event.code:5857 OR event.code:5858", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process… | 90 |  |
| q-05dacb1f29 | check C350 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*saml* OR process.command_line:*token* OR process.command_line:*cert*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-507c3ba844 | check C351 | search | {"dataset": "zeek", "query": "event.action:http AND (url.original:*saml* OR url.original:*adfs* OR url.original:*token*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "p… | 0 |  |
| q-6efae2d175 | check C352 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-30dfd1e5a5 | check C353 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-fdd173cc42 | check C354 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*MFA* OR powershell.script_block_text:*2FA* OR powershell.script_block_text:*Authenticator*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name… | 0 |  |
| q-52aa0440f3 | check C355 | search | {"dataset": "windows.other", "query": "event.code:4625 OR event.code:5857 OR event.code:5858", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process… | 85 | F52 |
| q-cff2fc24b8 | check C356 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*login* OR process.command_line:*auth* OR process.command_line:*mfa*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-48e910998c | check C357 | search | {"dataset": "zeek", "query": "event.action:http AND (url.original:*login* OR url.original:*auth* OR url.original:*mfa*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "pr… | 0 |  |
| q-6b013b29cd | check C358 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4657", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 36 |  |
| q-fd87c3ce3a | check C359 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4768", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 14 |  |
| q-2d5f4f8e9a | check C360 | aggregate | {"dataset": "windows.sysmon", "field": "registry.path", "query": "event.code:13 AND (registry.path:*Certificate* OR registry.path:*Crypto* OR registry.path:*Keys*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1133 |  |
| q-c5d9b0b3ff | check C361 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*Certificate* OR powershell.script_block_text:*Export-PfxCertificate* OR powershell.script_block_text:*New-SelfSignedCertificate*)", "time_from": null, "time_to": nul… | 0 |  |
| q-362ce1bffb | check C362 | search | {"dataset": "windows.other", "query": "event.code:7045 OR event.code:5857 OR event.code:5858", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process… | 90 |  |
| q-7e175d7b18 | check C363 | aggregate | {"dataset": "zeek", "field": "zeek.certificate_subject", "query": "event.action:x509", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 378 |  |
| q-5d29bae4fd | triage T1003 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND NOT win.GrantedAccess:(0x1000 OR 0x1400)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "process.executable", "win.SourceImage", "win.GrantedAcce… | 9 | F01 |
| q-2a6ecde853 | triage T1003 step 1 | search | {"dataset": "windows.security", "query": "event.code:(4656 OR 4663 OR 4670) AND win.ObjectType:(SAM_DOMAIN OR SAM_SERVER OR SAM_ALIAS OR Process)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "user.name", "process.ex… | 40 | F01, F02 |
| q-fe0f79fff7 | triage T1003 step 2 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy0A4ua"} | None | F01 |
| q-014f0def43 | triage T1003 step 2 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBux8Gu0"} | None | F01 |
| q-e9583616d8 | triage T1003 step 2 | search | {"dataset": "windows.powershell", "query": "event.code:(4104 OR 4103 OR 800) AND (win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*MiniDump* OR win.ScriptBlockText:*OpenProcess* OR win.ScriptBlockText:*Get-Process* OR win.ScriptBlockText:*Dump* OR win.Scrip… | 6 |  |
| q-bb1eb242de | triage T1003 step 3 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRZ7r-"} | None | F01 |
| q-c58edc5e3b | triage T1003 step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == 4104 AND user.name == \"pbeesly\" \| KEEP @timestamp, host.name, _id, _index, win.Path, win.ScriptBlockText \| SORT @timestamp ASC \| LIMIT 40"} | ERROR |  |
| q-9866706d82 | triage T1003 step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND user.name == \"pbeesly\" \| KEEP @timestamp, host.name, _id, _index, win.Path, win.ScriptBlockText \| SORT @timestamp ASC \| LIMIT 40"} | 40 |  |
| q-dfa9486f75 | triage T1003 step 5 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND user.name == \"pbeesly\" AND @timestamp > \"2020-05-02T03:01:51.000Z\" \| KEEP @timestamp, host.name, _id, _index, win.Path, win.ScriptBlockText \| SORT @t… | 60 |  |
| q-4d190c2982 | triage T1003 step 6 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND @timestamp >= \"2020-05-02T03:04:00.000Z\" AND @timestamp <= \"2020-05-02T03:20:00.000Z\" \| KEEP @timestamp, host.name, _id, _index, user.name, process.executabl… | 60 | F04 |
| q-343a985f75 | triage T1003 step 6 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND user.name == \"pbeesly\" AND @timestamp > \"2020-05-02T03:06:47.000Z\" \| KEEP @timestamp, host.name, _id, _index, win.Path, win.ScriptBlockText \| SORT @t… | 60 | F01 |
| q-c264e2de9c | triage T1003 step 7 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND user.name == \"pbeesly\" AND @timestamp > \"2020-05-02T03:09:04.000Z\" \| KEEP @timestamp, host.name, _id, _index, win.Path, win.ScriptBlockText \| SORT @t… | 34 | F06 |
| q-0179d57e49 | triage T1003 step 7 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"13\" AND @timestamp >= \"2020-05-02T03:18:00.000Z\" AND @timestamp <= \"2020-05-02T03:22:00.000Z\" \| KEEP @timestamp, host.name, _id, _index, process.executable, registr… | 40 |  |
| q-0247f87418 | triage T1003 step 8 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"13\" AND process.executable LIKE \"*lsass.exe\" AND @timestamp >= \"2020-05-02T03:19:00.000Z\" AND @timestamp <= \"2020-05-02T03:20:00.000Z\" \| KEEP @timestamp, host.nam… | 8 | F02, F05 |
| q-c894a4d146 | triage T1003 step 8 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4688\" AND @timestamp >= \"2020-05-02T03:04:00.000Z\" AND @timestamp <= \"2020-05-02T03:22:00.000Z\" \| KEEP @timestamp, host.name, _id, _index, user.name, process.exec… | 60 |  |
| q-b9b6d19d77 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy0A4ua"} | None |  |
| q-85729f7d05 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy0A4ua"} | None |  |
| q-e717859679 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy0A4uc"} | None |  |
| q-bd4e0dad1f | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBux8Gu0"} | None |  |
| q-12766f43b9 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBux8Gu0"} | None |  |
| q-cc29934f92 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None |  |
| q-c25c44ff1a | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-9a2a74a749 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-7a189a5cab | triage T1003 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRZ7r-"} | None |  |
| q-03a9a464da | triage T1003 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLr9"} | None |  |
| q-8d2798c441 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBudp5HI"} | None |  |
| q-28da5bffb3 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuWmZPb"} | None |  |
| q-da0762e766 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuv695R"} | None |  |
| q-71f9b273f5 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnqqYem"} | None |  |
| q-6332b4e5f0 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnaXZbu"} | None |  |
| q-87713dcb8e | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBox14nu"} | None |  |
| q-a1fe2eea10 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn44l3s"} | None |  |
| q-a8ae1ba022 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoGKqgM"} | None |  |
| q-b6a5be736e | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnfdUsq"} | None |  |
| q-9a192b5890 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByCVdVX"} | None |  |
| q-6dd632a0db | triage T1040 step 1 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.executable:*NetworkWatcher* OR process.executable:*PsExec* OR process.executable:*sdelete* OR process.executable:*python* OR process.executable:*PSEXESVC*)", "time_from": null, "time_to": n… | 23 |  |
| q-cbaba6eed1 | triage T1040 step 1 | aggregate | {"dataset": "windows.sysmon", "field": "win.Image", "query": "event.code:6", "time_from": null, "time_to": null, "size": 60, "sub_field": null} | 0 |  |
| q-cb35702274 | triage T1040 step 2 | search | {"dataset": "windows.sysmon", "query": "process.executable:*python* OR process.parent.executable:*python* OR win.Image:*python*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "event.code", "process.executable", "proces… | 520 |  |
| q-386c7ae461 | triage T1040 step 2 | search | {"dataset": "windows.security", "query": "process.executable:*NetworkWatcher* OR win.ServiceFileName:*NetworkWatcher* OR win.ImagePath:*NetworkWatcher*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "event.code", "proc… | 23 | F07 |
| q-65393b3954 | triage T1040 step 3 | search | {"dataset": "windows.sysmon", "query": "process.executable:*python* AND (event.code:3 OR event.code:22 OR event.code:11 OR event.code:17 OR event.code:18 OR event.code:2)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", … | 381 | F08 |
| q-2d6f9adf03 | triage T1040 step 3 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*python* OR win.ScriptBlockText:*PsExec* OR win.ScriptBlockText:*NASHUA* OR win.ScriptBlockText:*pbeesly*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host… | 7 | F08 |
| q-2909de4eec | triage T1040 step 4 | search | {"dataset": "windows.sysmon", "query": "process.executable:*python* AND (event.code:3 OR event.code:22)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "event.code", "process.executable", "destination.ip", "destination.… | 348 | F08 |
| q-17fcfe7984 | triage T1040 step 4 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*SeaDuke* OR win.ScriptBlockText:*Invoke-SeaDukeStage*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "event.code", "process.command… | 1 | F08 |
| q-13bc2bb9bc | triage T1040 step 5 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoz4j7h"} | None | F08 |
| q-1c5b8b6b31 | triage T1040 step 5 | search | {"dataset": "windows.sysmon", "query": "process.command_line:(*pcap* OR *sniff* OR *promisc* OR *raw* OR *dumpcap* OR *netsh* OR *capture*) OR win.Image:(*pcap* OR *npcap* OR *winpcap* OR *dumpcap*) OR win.TargetFilename:(*pcap* OR *npcap* OR *winpcap*)", "tim… | 3 | F07 |
| q-a78d796593 | triage T1040 step 6 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnvvDAD"} | None | F07 |
| q-6958076a01 | triage T1040 step 6 | search | {"dataset": "windows.sysmon", "query": "host.name:scranton.dmevals.local AND (@timestamp:[2020-05-02T03:18:00.000Z TO 2020-05-02T03:21:00.000Z]) AND (event.code:1 OR event.code:11)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "us… | 355 |  |
| q-5bf7c3a85f | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnvvDAD"} | None |  |
| q-3e96fc91ed | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnvvDAD"} | None |  |
| q-7b2049fe7f | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnkjXIW"} | None |  |
| q-f6fa46599e | triage T1040 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBufr2mN"} | None |  |
| q-841350ee75 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByDV_QB"} | None |  |
| q-d9ff65c220 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByCVdVX"} | None |  |
| q-11b8ce1273 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoz4j7h"} | None |  |
| q-c37d5d8dd3 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnyzTy7"} | None |  |
| q-83f6b0341c | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBow16Q8"} | None |  |
| q-0dafc00bcf | triage T1056 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND NOT win.GrantedAccess:0x1000 AND NOT win.GrantedAccess:0x1400", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "process.executable", "process.comma… | 9 | F09 |
| q-397720dc41 | triage T1056 step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 10 AND win.TargetImage LIKE \"*lsass*\" \| STATS c = COUNT(*) BY win.SourceImage, win.GrantedAccess \| SORT c DESC"} | ERROR |  |
| q-ed217f100c | triage T1056 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None | F09 |
| q-4624c374b0 | triage T1056 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-3c792fa51e | triage T1056 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND win.TargetImage LIKE \"*lsass*\" \| STATS c = COUNT(*) BY win.SourceImage, win.GrantedAccess \| SORT c DESC"} | 15 |  |
| q-548f4c63a7 | triage T1056 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (process.pid == 2976 OR win.ProcessId == \"2976\" OR process.command_line LIKE \"*lsass*\" OR process.command_line LIKE \"*MiniDump*\" OR process.command_line LIK… | 2 | F09 |
| q-8118f843e6 | triage T1056 step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (win.ScriptBlockText LIKE \"*lsass*\" OR win.ScriptBlockText LIKE \"*MiniDump*\" OR win.ScriptBlockText LIKE \"*Dump*\" OR win.ScriptBlockText LIKE \"*Cred… | 3 | F12 |
| q-f6911aa707 | triage T1056 step 4 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBorwtwa"} | None |  |
| q-b2a5c856ff | triage T1056 step 4 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByPYrDh"} | None |  |
| q-9e886773ee | triage T1056 step 5 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None | F10 |
| q-18382da5de | triage T1056 step 5 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBudp5HI"} | None | F10 |
| q-d790701ca9 | triage T1056 step 6 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE host.name == \"nashua.dmevals.local\" AND event.code == \"4104\" \| KEEP @timestamp, win.ScriptBlockText, _id, _index \| LIMIT 20"} | 11 | F10 |
| q-2df377002a | triage T1056 step 6 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (file.path LIKE \"*monkey*\" OR file.path LIKE \"*keylog*\" OR file.path LIKE \"*hook*\" OR file.path LIKE \"*capture*\") \| KEEP @timestamp, host.name, file.pat… | 1 | F09, F11, F13 |
| q-9dc04a0fd6 | triage T1056 step 7 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBouy-nD"} | None |  |
| q-5d0a6b8f63 | triage T1056 step 7 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (process.command_line LIKE \"*GetAsyncKeyState*\" OR process.command_line LIKE \"*SetWindowsHookEx*\" OR process.command_line LIKE \"*keylog*\" OR process.command… | 0 |  |
| q-b6af17804f | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBouy-nD"} | None |  |
| q-a0494c14db | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBouy-nD"} | None |  |
| q-cf7e5f685b | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBorwtwa"} | None |  |
| q-e226722ee3 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None |  |
| q-21beebf64c | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None |  |
| q-46456d64a2 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-91144086ff | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None |  |
| q-dcdf1709cf | triage T1056 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBudp5HI"} | None |  |
| q-27a045906d | triage T1056 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBudp5HI"} | None |  |
| q-5e40f3e607 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-731b0bc67e | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-92697cf53a | triage T1056 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByCVtlI"} | None |  |
| q-59ee12147b | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBouy-nD"} | None |  |
| q-6bb877b7c8 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByPYrDh"} | None |  |
| q-e7bea8b93a | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBouy-nD"} | None |  |
| q-95d2ca840b | triage T1110 step 1 | count | {"dataset": "windows.security", "query": "event.code:4625 OR event.code:4771 OR event.code:4776 OR event.code:4740", "time_from": null, "time_to": null} | 1 |  |
| q-cbede10d7c | triage T1110 step 1 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 30, "sub_field": "win.GrantedAccess"} | 326 |  |
| q-ceed1cb87c | triage T1110 step 1 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 30, "sub_field": "win.LogonType"} | 297 |  |
| q-59491a9664 | triage T1110 step 2 | search | {"dataset": "windows.security", "query": "event.code:4625 OR event.code:4771 OR event.code:4776 OR event.code:4740", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process… | 1 | F14, F15 |
| q-46d48f5e72 | triage T1110 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND (process.executable:*PowerShell* OR process.executable:*wsmprovhost*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "process.executable", "proce… | 5 | F16 |
| q-91cf7dfa6d | triage T1110 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None | F16 |
| q-7148e001fa | triage T1110 step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*lsass*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*minidump*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*comsvcs*\" OR… | 0 |  |
| q-ea966cd1a9 | triage T1110 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*lsass*\" OR TO_LOWER(process.command_line) LIKE \"*dump*\" OR TO_LOWER(process.command_line) LIKE \"*comsvcs*\" OR TO_LOWE… | 1 |  |
| q-cdfbf4a968 | triage T1110 step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND host.name == \"scranton.dmevals.local\" AND @timestamp >= \"2020-05-02T03:04:00.000Z\" AND @timestamp <= \"2020-05-02T03:07:00.000Z\" \| KEEP @timestamp, h… | 20 | F15 |
| q-605f59a70e | triage T1110 step 5 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLr9"} | None |  |
| q-fb3ded11cd | triage T1110 step 5 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND host.name == \"nashua.dmevals.local\" \| KEEP @timestamp, host.name, user.name, win.ScriptBlockText, _id, _index \| LIMIT 25"} | 11 | F17, F18 |
| q-3ad32b7687 | triage T1110 step 6 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND host.name == \"scranton.dmevals.local\" AND @timestamp >= \"2020-05-02T03:00:00.000Z\" AND @timestamp <= \"2020-05-02T03:05:30.000Z\" \| KEEP @timestamp, h… | 25 | F18 |
| q-ef6502aa6f | triage T1110 step 6 | aggregate | {"dataset": "windows.security", "field": "source.ip", "query": "event.code:4624 AND win.LogonType:3", "time_from": null, "time_to": null, "size": 20, "sub_field": "win.TargetUserName"} | 218 |  |
| q-e37d5f0348 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuTlU_q"} | None |  |
| q-ef8182c2d4 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeBwdMB0P"} | None |  |
| q-dabf88f2e1 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuTlU_q"} | None |  |
| q-5dce620091 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLr9"} | None |  |
| q-de4f66423d | triage T1110 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-a38210a797 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None |  |
| q-e2264912d6 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-f602e926b9 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoXbqWA"} | None |  |
| q-38757efb18 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuu5GRH"} | None |  |
| q-d4698ccab0 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeBwdMB0i"} | None |  |
| q-b34fd4ba02 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByCVtlI"} | None |  |
| q-4f31b152e6 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-801c4ebc48 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByDVjze"} | None |  |
| q-6bb9be0d05 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByCVMj0"} | None |  |
| q-e6bd1d90f9 | triage T1111 step 1 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND win.TargetImage:*lsass.exe", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-3a3701e45c | triage T1111 step 1 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4648", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 15 |  |
| q-f9bad7c42c | triage T1111 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass.exe AND (process.executable:*powershell.exe OR process.executable:*wsmprovhost.exe)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "e… | 3 | F19 |
| q-297f0bbc06 | triage T1111 step 2 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuu5GRH"} | None | F19 |
| q-77e5a3571c | triage T1111 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-0c0b735af2 | triage T1111 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoXbqWA"} | None |  |
| q-ae98834b6e | triage T1111 step 4 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*MiniDump* OR win.ScriptBlockText:*sekurlsa* OR win.ScriptBlockText:*Invoke-Mimikatz* OR win.ScriptBlockText:*Credential*)", "time_from": null, … | 3 |  |
| q-bc8f3c883c | triage T1111 step 4 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4624 AND win.TargetUserName:pbeesly", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 30 |  |
| q-b7ebf73c1c | triage T1111 step 5 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByPYrDh"} | None | F19 |
| q-31cb741862 | triage T1111 step 5 | search | {"dataset": "windows.security", "query": "event.code:4624 AND win.TargetUserName:pbeesly AND win.LogonType:10", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.exec… | 2 |  |
| q-d4fbe24ef1 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-a73414b076 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-b14c9c6731 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-f83271f41f | triage T1111 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoXbqWA"} | None |  |
| q-435a182d42 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuu5GRH"} | None |  |
| q-174806cfe8 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuu5GRH"} | None |  |
| q-7d18d332b2 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnfdUsq"} | None |  |
| q-d0ed26dd81 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnQM1oU"} | None |  |
| q-23431e115f | triage T1111 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeBwdMB1A"} | None |  |
| q-4674511cd1 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByPYrDh"} | None |  |
| q-88bcce2a3b | triage T1187 step 1 | aggregate | {"dataset": "windows.security", "field": "win.ShareName", "query": "event.code:5140 OR event.code:5145", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 163 |  |
| q-2f8d122e02 | triage T1187 step 1 | aggregate | {"dataset": "windows.sysmon", "field": "destination.ip", "query": "event.code:3 AND (destination.port:445 OR destination.port:139)", "time_from": null, "time_to": null, "size": 50, "sub_field": "process.executable"} | 66 |  |
| q-137c3c8972 | triage T1187 step 1 | aggregate | {"dataset": "zeek", "field": "destination.ip", "query": "event.action:conn AND (destination.port:445 OR destination.port:139)", "time_from": null, "time_to": null, "size": 50, "sub_field": "source.ip"} | 50 |  |
| q-bac0042b85 | triage T1187 step 1 | aggregate | {"dataset": "zeek", "field": "http.request.method", "query": "event.action:http", "time_from": null, "time_to": null, "size": 50, "sub_field": "url.domain"} | 62 |  |
| q-fe98ad2cf6 | triage T1187 step 2 | search | {"dataset": "zeek", "query": "event.action:http AND http.request.method:PROPFIND", "time_from": null, "time_to": null, "fields": ["@timestamp", "source.ip", "destination.ip", "destination.port", "http.request.method", "url.original", "url.domain", "user_agent.… | 26 |  |
| q-3766a99c59 | triage T1187 step 2 | search | {"dataset": "zeek", "query": "event.action:conn AND destination.ip:192.168.0.4", "time_from": null, "time_to": null, "fields": ["@timestamp", "source.ip", "destination.ip", "destination.port", "network.transport", "zeek.service", "zeek.duration", "zeek.orig_by… | 392 | F20 |
| q-0d955bf9c8 | triage T1187 step 3 | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgh9V"} | None | F20 |
| q-5187e20aca | triage T1187 step 3 | search | {"dataset": "zeek", "query": "event.action:http AND (http.request.method:PUT OR http.request.method:OPTIONS OR http.request.method:LOCK)", "time_from": null, "time_to": null, "fields": ["@timestamp", "source.ip", "destination.ip", "destination.port", "http.req… | 20 | F20 |
| q-2ce408ae43 | triage T1187 step 3 | search | {"dataset": "windows.security", "query": "event.code:5140 AND win.ShareName:*ADMIN$*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "user.name", "source.ip", "win.ShareName", "win.ShareLocalPath", "win.ObjectName", "w… | 9 | F20 |
| q-dd784e2452 | triage T1187 step 4 | search | {"dataset": "windows.sysmon", "query": "event.code:3 AND destination.ip:10.0.1.6", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "user.name", "process.executable", "process.command_line", "destination.ip", "destination… | 62 |  |
| q-610c35c330 | triage T1187 step 4 | search | {"dataset": "windows.security", "query": "event.code:5140 AND source.ip:10.0.1.4", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "user.name", "source.ip", "win.ShareName", "win.ObjectName", "win.AccessMask", "win.IpAdd… | 19 | F20 |
| q-d546c3e775 | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgR9D"} | None |  |
| q-71e01fd8a8 | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgR9D"} | None |  |
| q-39d0cfac55 | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgR9H"} | None |  |
| q-da2daf4036 | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgR9H"} | None |  |
| q-d0380cec05 | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgh9V"} | None |  |
| q-cc9d40d3ae | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgh9V"} | None |  |
| q-fc8c37ce63 | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgh8V"} | None |  |
| q-8715cbdb4b | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgh8V"} | None |  |
| q-1418427d6a | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgR_2"} | None |  |
| q-2e4502bdff | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgR_2"} | None |  |
| q-fe9f5031f1 | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgh-i"} | None |  |
| q-ec5eea3c4b | triage T1187 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuv5CHS"} | None |  |
| q-4d259eac34 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuv5CHS"} | None |  |
| q-1239d5bba2 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuv5CHS"} | None |  |
| q-924035576f | triage T1187 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy8KXgw"} | None |  |
| q-a7b503e836 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy7JbTW"} | None |  |
| q-506d2c7cce | triage T1187 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy7JbTW"} | None |  |
| q-b19cea1afb | triage T1187 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoSWKN8"} | None |  |
| q-5a36fca15a | triage T1187 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoSWKN8"} | None |  |
| q-4c023ca2e0 | triage T1212 step 1 | aggregate | {"dataset": "windows.sysmon", "field": "win.SourceImage", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-d2ebb6b170 | triage T1212 step 1 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-4b892f3097 | triage T1212 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND (win.GrantedAccess:0x1fffff OR win.GrantedAccess:0x1f3fff OR win.GrantedAccess:0x101001 OR win.GrantedAccess:0x1000000 OR win.GrantedAccess:0x3000)", "time_from": null, "time… | 9 | F22, F24 |
| q-1f0f9b5ce5 | triage T1212 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND (win.SourceImage:*PowerShell* OR win.SourceImage:*wsmprovhost* OR win.SourceImage:*wininit* OR win.SourceImage:*csrss*)", "time_from": null, "time_to": null, "fields": ["@tim… | 8 |  |
| q-8d314fe1ed | triage T1212 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None | F22 |
| q-b883aef126 | triage T1212 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None | F23 |
| q-80df5efa19 | triage T1212 step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == 4104 \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*lsass*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*minidump*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*sekurlsa*\" O… | ERROR |  |
| q-4161ba7d00 | triage T1212 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 1 AND (process.pid == 2976 OR process.pid == 7720 OR process.pid == 3876) \| KEEP @timestamp, host.name, process.pid, process.executable, process.command_line, process.pare… | ERROR |  |
| q-8a21adfb6c | triage T1212 step 5 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*lsass*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*minidump*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*sekurlsa*… | 5 |  |
| q-c2b5afd30f | triage T1212 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (process.pid == 2976 OR process.pid == 7720 OR process.pid == 3876) \| KEEP @timestamp, host.name, process.pid, process.executable, process.command_line, process.… | 4 | F23 |
| q-fd61b4b0b7 | triage T1212 step 6 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBorwtwa"} | None | F22 |
| q-2a4d6f1a0b | triage T1212 step 6 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByPYrDh"} | None |  |
| q-1bd76db01c | triage T1212 step 7 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnrrZmZ"} | None | F24 |
| q-84c033f764 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBorwtwa"} | None |  |
| q-fb90a928c3 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBorwtwa"} | None |  |
| q-1e48ba4cfd | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-a2415c20cf | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-a486698dad | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-5302cd2d7f | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None |  |
| q-b6660f38d7 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-908d949bea | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-3d0e2f60f3 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-7602b7109f | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBo05D7L"} | None |  |
| q-1d6806107f | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBo05D7L"} | None |  |
| q-0960c07315 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnrrZmZ"} | None |  |
| q-10efe75fab | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnrrZmZ"} | None |  |
| q-6aa664a220 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnqqYet"} | None |  |
| q-4b7476811f | triage T1539 step 1 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBi-6ySm"} | None | F26 |
| q-f704cb3138 | triage T1539 step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 10 AND TO_LOWER(win.TargetImage) LIKE \"*edge*\" \| STATS c = COUNT(*) BY win.SourceImage, win.GrantedAccess \| SORT c DESC \| LIMIT 30"} | ERROR |  |
| q-42fad4711e | triage T1539 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND TO_LOWER(win.TargetImage) LIKE \"*edge*\" \| STATS c = COUNT(*) BY win.SourceImage, win.GrantedAccess \| SORT c DESC \| LIMIT 30"} | 30 |  |
| q-90b7b676ad | triage T1539 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND (TO_LOWER(win.TargetImage) LIKE \"*edge*\" OR TO_LOWER(win.TargetImage) LIKE \"*chrome*\" OR TO_LOWER(win.TargetImage) LIKE \"*firefox*\" OR TO_LOWER(win.TargetI… | 40 | F26 |
| q-8cb41ee666 | triage T1539 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND (TO_LOWER(win.TargetImage) LIKE \"*edge*\" OR TO_LOWER(win.TargetImage) LIKE \"*chrome*\" OR TO_LOWER(win.TargetImage) LIKE \"*firefox*\" OR TO_LOWER(win.TargetI… | 17 |  |
| q-34be878ebe | triage T1539 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND TO_LOWER(win.SourceImage) LIKE \"*powershell*\" AND (TO_LOWER(win.TargetImage) LIKE \"*edge*\" OR TO_LOWER(win.TargetImage) LIKE \"*chrome*\" OR TO_LOWER(win.Tar… | 9 | F25 |
| q-3f79ed5c57 | triage T1539 step 4 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUWX"} | None |  |
| q-a3de8c738c | triage T1539 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND TO_LOWER(process.executable) LIKE \"*powershell*\" \| KEEP @timestamp, host.name, user.name, process.executable, process.command_line, process.parent.executable, … | 12 | F25 |
| q-b9aec4c171 | triage T1539 step 5 | esql | {"query": "FROM logs-windows.powershell METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*edge*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*cookie*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*login data*\" OR TO_LOWE… | ERROR |  |
| q-f3f9bbb719 | triage T1539 step 6 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*edge*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*cookie*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*login data*\" OR… | 0 |  |
| q-0819804e03 | triage T1539 step 7 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" \| KEEP @timestamp, host.name, user.name, win.ScriptBlockId, win.ScriptBlockText, _id, _index \| SORT @timestamp ASC \| LIMIT 15"} | 15 |  |
| q-02fe9b4c75 | triage T1539 step 8 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*edge*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*cookie*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*login data*\" OR… | 0 |  |
| q-6b7bbdf3d1 | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUWX"} | None |  |
| q-1ad13d2f3e | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUWX"} | None |  |
| q-4220e74185 | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUWX"} | None |  |
| q-9b0c41810f | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUWe"} | None |  |
| q-aa38cc9a9c | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUWf"} | None |  |
| q-cd2e2642db | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBorwtwa"} | None |  |
| q-ce8f9f2fc7 | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBi-6ySm"} | None |  |
| q-58568645fd | triage T1539 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBur1GH0"} | None |  |
| q-303eaf5523 | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBow06T9"} | None |  |
| q-3387e0694f | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBotx_LQ"} | None |  |
| q-7f2ec55667 | triage T1552 step 1 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoNRGHl"} | None | F27 |
| q-34a1144b0c | triage T1552 step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*accesschk*\" OR TO_LOWER(process.command_line) LIKE \"*passwords*\" OR TO_LOWER(process.command_line) LIKE \"*psexec*\" OR… | 11 | F27, F28 |
| q-c168fa5d14 | triage T1552 step 2 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*accesschk*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*psexec*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*passwordsdb… | 8 | F28 |
| q-0c5e542dfd | triage T1552 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*rar.exe*\" OR TO_LOWER(process.command_line) LIKE \"*working.zip*\" OR TO_LOWER(process.command_line) LIKE \"*draft.zip*\"… | 16 | F28 |
| q-2fe7530ff8 | triage T1552 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE (event.code == \"11\" OR event.code == \"23\" OR event.code == \"15\") AND (TO_LOWER(win.TargetFilename) LIKE \"*passwordsdb*\" OR TO_LOWER(win.TargetFilename) LIKE \"*accesschk*\" OR TO… | 21 |  |
| q-6b8d5f01dd | triage T1552 step 3 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4663\",\"4656\",\"4658\") AND (TO_LOWER(win.ObjectName) LIKE \"*passwordsdb*\" OR TO_LOWER(win.ObjectName) LIKE \"*accesschk*\" OR TO_LOWER(win.ObjectName) LIKE \"*wor… | 0 |  |
| q-3ffe7e83d6 | triage T1552 step 4 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4688\",\"4663\",\"4656\") AND (TO_LOWER(process.executable) LIKE \"*accesschk*\" OR TO_LOWER(win.NewProcessName) LIKE \"*accesschk*\" OR TO_LOWER(win.ProcessName) LIKE… | 3 | F27 |
| q-ecf904adc0 | triage T1552 step 4 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuu5GRH"} | None | F28 |
| q-46d894a4c4 | triage T1552 step 5 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy4FbJN"} | None | F27 |
| q-a61aa30d0c | triage T1552 step 5 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"smb_files\" \| KEEP @timestamp, observer.name, source.ip, destination.ip, zeek.filename, zeek.path, zeek.action, zeek.name, zeek.share_type, _id, _index \| SORT @timestamp"} | 12 | F30 |
| q-6424bdeceb | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoNRGHl"} | None |  |
| q-297c9c1a17 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoNRGHW"} | None |  |
| q-a2c6896867 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy4FbJN"} | None |  |
| q-7a7aba323d | triage T1552 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy4FbJN"} | None |  |
| q-7d19218173 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy4FbJN"} | None |  |
| q-e4fb20693d | triage T1552 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy1A5nE"} | None |  |
| q-ae04ed14c2 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoz4z4i"} | None |  |
| q-1e06bcf261 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByCVdVX"} | None |  |
| q-c4d56f46c6 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuu5GRH"} | None |  |
| q-a14a47c39d | triage T1552 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuu5GRH"} | None |  |
| q-7c9ccc4f00 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoz4j7h"} | None |  |
| q-ce0e952bf7 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBow1qSj"} | None |  |
| q-39c0ddc83a | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoKOGL_"} | None |  |
| q-1aaea03a92 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnfdUsq"} | None |  |
| q-3fb4b00321 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnQM1oP"} | None |  |
| q-12399e98a1 | triage T1552 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgR8g"} | None |  |
| q-d6e371b729 | triage T1552 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgh8M"} | None |  |
| q-02f493e508 | triage T1552 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeByNiUGh"} | None |  |
| q-8187f335d2 | triage T1555 step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND TO_LOWER(win.TargetImage) LIKE \"*lsass.exe\" AND win.GrantedAccess IN (\"0x1fffff\",\"0x1f3fff\",\"0x101001\",\"0x1000000\",\"0x3000\",\"0x1400\") \| KEEP @time… | 33 | F31, F32 |
| q-2a904380fb | triage T1555 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByPYrDh"} | None |  |
| q-d2e9732a7f | triage T1555 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None | F31 |
| q-7892708f7d | triage T1555 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None | F31 |
| q-ae4b1b1d87 | triage T1555 step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code IN (\"4104\",\"4103\",\"800\") AND (TO_LOWER(COALESCE(win.ScriptBlockText, process.command_line, \"\")) LIKE \"*lsass*\" OR TO_LOWER(COALESCE(win.ScriptBlockText, process.… | 3 | F31 |
| q-654f1179c8 | triage T1555 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*vault*\" OR TO_LOWER(process.command_line) LIKE \"*cmdkey*\" OR TO_LOWER(process.command_line) LIKE \"*dpapi*\" OR TO_LOWE… | 0 |  |
| q-4209a0bfba | triage T1555 step 4 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-669157b78f | triage T1555 step 4 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4624\",\"4672\",\"4688\") AND user.name == \"pbeesly\" \| KEEP @timestamp, host.name, event.code, user.name, win.LogonType, win.IpAddress, win.ProcessName, process.com… | 137 | F31 |
| q-46d2d53f64 | triage T1555 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND TO_LOWER(win.TargetImage) LIKE \"*lsass.exe\" \| STATS cnt = COUNT(*) BY win.SourceImage, win.GrantedAccess \| SORT cnt DESC"} | 15 |  |
| q-06f0cc4e95 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-b1223d40ea | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-260d27b224 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-82fc3860a8 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-779792b449 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-61c9a0103d | triage T1555 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByEVwPJ"} | None |  |
| q-c3a24cd78a | triage T1555 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuv5SEZ"} | None |  |
| q-d119084a7f | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBov0sHE"} | None |  |
| q-d30d1fa61c | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnUQthh"} | None |  |
| q-fa7170736a | triage T1555 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBudppHD"} | None |  |
| q-776558e5ce | triage T1555 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeBwdMB1A"} | None |  |
| q-faa68c2ff7 | triage T1556 step 1 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 326 |  |
| q-9357701a3e | triage T1556 step 1 | aggregate | {"dataset": "windows.sysmon", "field": "win.SourceImage", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 30, "sub_field": "host.name"} | 326 |  |
| q-2a5c19c191 | triage T1556 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND (win.GrantedAccess:0x1fffff OR win.GrantedAccess:0x101001 OR win.GrantedAccess:0x1f3fff OR win.GrantedAccess:0x1000000 OR win.GrantedAccess:0x3000)", "time_from": null, "time… | 9 | F33 |
| q-7d7a5751b7 | triage T1556 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND win.SourceImage:*PowerShell*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "win.SourceImage", "win.GrantedAccess", "win.CallTrace", "user.name",… | 4 |  |
| q-ef9db801fc | triage T1556 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None | F33 |
| q-38b6e6965a | triage T1556 step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE @timestamp >= \"2020-05-02T03:04:00.000Z\" AND @timestamp <= \"2020-05-02T03:06:30.000Z\" AND host.name == \"scranton.dmevals.local\" AND (event.code == \"4104\" OR event.code == \"4… | 40 | F33 |
| q-69b49a752f | triage T1556 step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*minidump*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*lsass*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*sekurlsa*\" O… | 6 | F36 |
| q-0c93be38e8 | triage T1556 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*lsass*\" OR TO_LOWER(process.command_line) LIKE \"*minidump*\" OR TO_LOWER(process.command_line) LIKE \"*procdump*\" OR TO… | 1 |  |
| q-030749183c | triage T1556 step 5 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-eaba8c19f2 | triage T1556 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"13\" AND (TO_LOWER(registry.path) LIKE \"*lsa*\" OR TO_LOWER(registry.path) LIKE \"*notification packages*\" OR TO_LOWER(registry.path) LIKE \"*password*\" OR TO_LOWER(re… | 40 | F37, F39 |
| q-95d8e7cdbd | triage T1556 step 6 | esql | {"query": "FROM logs-windows.other-default METADATA _id, _index \| WHERE event.code == \"7045\" OR event.code == \"4697\" \| KEEP @timestamp, host.name, win.ServiceName, win.ImagePath, win.ServiceType, win.StartType, user.name, _id, _index \| LIMIT 20"} | 5 | F35 |
| q-642acd5a6c | triage T1556 step 6 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4648\" \| KEEP @timestamp, host.name, user.name, process.executable, win.TargetServerName, win.TargetUserName, win.SubjectUserName, _id, _index \| LIMIT 20"} | 15 | F34 |
| q-563a21af73 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-e97007b938 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-160a9ea96c | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnrrZmZ"} | None |  |
| q-cebc02838d | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnqqYet"} | None |  |
| q-b4acdda7e8 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRarrZ"} | None |  |
| q-cf82bd8087 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy3Dxwo"} | None |  |
| q-2c1969725e | triage T1556 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuu5GRH"} | None |  |
| q-5449fe5f11 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBumxOdt"} | None |  |
| q-4040377382 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeBwdMB02"} | None |  |
| q-6b722339f8 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeBwdLx2Z"} | None |  |
| q-05ea72ec28 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByEVwPx"} | None |  |
| q-7305a5ba74 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBjD_woi"} | None |  |
| q-c75af52345 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnQM1oU"} | None |  |
| q-fe43b3ce8c | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoGKaib"} | None |  |
| q-397919c389 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBi85CSi"} | None |  |
| q-5b7f646128 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBi96CXA"} | None |  |
| q-3b452635bc | triage T1557 step 1 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"conn\" AND (zeek.orig_l2_addr == \"fc:bd:67:e1:a9:c1\" OR zeek.resp_l2_addr == \"12:34:56:78:9a:bc\") \| KEEP @timestamp, source.ip, destination.ip, destination.port, zeek.servic… | 60 |  |
| q-a249fca169 | triage T1557 step 1 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"dns\" AND (zeek.query LIKE \"*wpad*\" OR zeek.query LIKE \"*NASHUA*\" OR zeek.query LIKE \"*SCRANTON*\") \| KEEP @timestamp, source.ip, destination.ip, zeek.query, zeek.answers, … | 14 | F41 |
| q-a703824df9 | triage T1557 step 2 | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgR_N"} | None | F42 |
| q-3c9537d2a8 | triage T1557 step 2 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"conn\" AND zeek.service LIKE \"*smb*\" \| KEEP @timestamp, source.ip, destination.ip, destination.port, zeek.service, zeek.orig_l2_addr, zeek.resp_l2_addr, zeek.conn_state, _id, … | 16 | F41 |
| q-d1a20cbb44 | triage T1557 step 3 | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeByOkBkA"} | None | F42 |
| q-22874b9eba | triage T1557 step 3 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4697\" \| KEEP @timestamp, host.name, user.name, win.ServiceName, win.ServiceFileName, win.ServiceAccount, _id, _index \| LIMIT 30"} | 23 | F41 |
| q-12ca4dd338 | triage T1557 step 4 | esql | {"query": "FROM logs-windows.other-default METADATA _id, _index \| WHERE event.code == \"7045\" \| KEEP @timestamp, host.name, user.name, win.ServiceName, win.ImagePath, win.ServiceType, win.StartType, _id, _index \| LIMIT 20"} | 5 |  |
| q-a7ba6322d7 | triage T1557 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*javamtsup*\" OR TO_LOWER(process.executable) LIKE \"*javamtsup*\" OR TO_LOWER(process.command_line) LIKE \"*psexec*\" OR T… | 5 | F40 |
| q-ed151cc6d8 | triage T1557 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*netsh*\" OR TO_LOWER(process.command_line) LIKE \"*arp *\" OR TO_LOWER(process.command_line) LIKE \"*dhcp*\" OR TO_LOWER(p… | 8 | F40, F43 |
| q-d4a51af2fc | triage T1557 step 5 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"5145\" \| KEEP @timestamp, host.name, user.name, win.ShareName, win.RelativeTargetName, win.IpAddress, win.SubjectUserName, _id, _index \| LIMIT 40"} | 40 |  |
| q-4352c60d2f | triage T1557 step 6 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND TO_LOWER(file.path) LIKE \"*python.exe*\" \| KEEP @timestamp, host.name, user.name, file.path, process.executable, _id, _index \| LIMIT 20"} | 7 |  |
| q-9eac75d546 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoz3z5O"} | None |  |
| q-d120d1dd29 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnvvDAD"} | None |  |
| q-28748b89ea | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnmk3GC"} | None |  |
| q-018f76e94b | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgR-T"} | None |  |
| q-24fb5e7050 | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgR-Z"} | None |  |
| q-6a93877e20 | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgR_V"} | None |  |
| q-fc8c15d326 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBumxOeO"} | None |  |
| q-0519825e42 | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeByOkBkA"} | None |  |
| q-dbde31b95d | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgR_N"} | None |  |
| q-347af2fb6a | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgR_N"} | None |  |
| q-29e220e9d2 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnmk3GC"} | None |  |
| q-d2e5f3bf78 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnvvDAD"} | None |  |
| q-9ea4ffe483 | triage T1558 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND (win.GrantedAccess:0x1fffff OR win.GrantedAccess:0x101001 OR win.GrantedAccess:0x1f3fff OR win.GrantedAccess:0x1000000 OR win.GrantedAccess:0x3000 OR win.GrantedAccess:0x1400… | 33 | F44 |
| q-e1cc491a98 | triage T1558 step 1 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy4FbJD"} | None | F44, F45 |
| q-e4c4ef261c | triage T1558 step 2 | search | {"dataset": "windows.sysmon", "query": "host.name:scranton.dmevals.local AND (process.executable:*powershell* OR process.parent.executable:*powershell* OR process.executable:*Temp* OR process.executable:*PSEXESVC* OR process.executable:*wsmprovhost*)", "time_f… | 22203 |  |
| q-c5fb84d028 | triage T1558 step 2 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == 4769 \| KEEP @timestamp, host.name, win.TargetUserName, win.ServiceName, win.TicketEncryptionType, win.TicketOptions, win.Status, source.ip, _id, _index \| SORT @timestam… | ERROR |  |
| q-b971461e4f | triage T1558 step 3 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4769\" \| KEEP @timestamp, host.name, win.TargetUserName, win.ServiceName, win.TicketEncryptionType, win.TicketOptions, win.Status, source.ip, _id, _index \| SORT @time… | 28 | F44, F45, F46, F47 |
| q-0d9668d467 | triage T1558 step 3 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*lsass* OR process.command_line:*sekurlsa* OR process.command_line:*ticket* OR process.command_line:*kerberos* OR process.command_line:*krbtgt* OR process.command_line:*Invoke-* OR … | 2 |  |
| q-848478342c | triage T1558 step 4 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBizx7td"} | None |  |
| q-d7e461e862 | triage T1558 step 4 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None | F44 |
| q-677756f18b | triage T1558 step 5 | search | {"dataset": "windows.sysmon", "query": "host.name:scranton.dmevals.local AND (process.pid:2976 OR process.parent.pid:2976 OR win.ProcessId:2976)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "process.executable", "process.command_… | 546 | F44 |
| q-1583f37880 | triage T1558 step 5 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" \| KEEP @timestamp, host.name, win.ScriptBlockText, _id, _index \| SORT @timestamp ASC"} | 414 |  |
| q-bf10e47234 | triage T1558 step 6 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND @timestamp >= \"2020-05-02T03:01:30.000Z\" AND @timestamp <= \"2020-05-02T03:22:00.000Z\" \| KEEP @timestamp, host.name, win.ScriptBlockText, _id, _index \… | 375 |  |
| q-5c45c47419 | triage T1558 step 7 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND host.name == \"scranton.dmevals.local\" AND @timestamp >= \"2020-05-02T03:01:30.000Z\" AND @timestamp <= \"2020-05-02T03:22:00.000Z\" \| KEEP @timestamp, h… | 108 | F44 |
| q-ec2d02d4e2 | triage T1558 step 7 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"kerberos\" \| KEEP @timestamp, zeek.id_orig_h, zeek.id_resp_h, zeek.request_type, zeek.client, zeek.service, zeek.success, zeek.error_msg, zeek.cipher, _id, _index \| SORT @times… | 35 | F48 |
| q-a170135805 | triage T1558 step 8 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND host.name == \"scranton.dmevals.local\" AND @timestamp >= \"2020-05-02T03:06:42.000Z\" \| KEEP @timestamp, host.name, win.ScriptBlockText, _id, _index \| S… | 69 |  |
| q-37e1c324c9 | triage T1558 step 8 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4624\" AND win.LogonType == \"10\" \| KEEP @timestamp, host.name, win.TargetUserName, win.LogonType, win.IpAddress, win.Workstation, win.AuthenticationPackageName, _id,… | 2 |  |
| q-0cb4e68a0e | triage T1558 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-c57448383b | triage T1558 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None |  |
| q-1ca43a0a70 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBorwtwa"} | None |  |
| q-d61afde1da | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy4FbJD"} | None |  |
| q-761370ba7e | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuw7KBe"} | None |  |
| q-43bbd10e5c | triage T1558 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-055dd0e863 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy4FbJD"} | None |  |
| q-0b7cb0c3f5 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuw7KBe"} | None |  |
| q-0cb3780759 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuw7KBe"} | None |  |
| q-145c3d8c9a | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuv5SEr"} | None |  |
| q-c506877365 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuv5SEr"} | None |  |
| q-64388a33c8 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy8J3fS"} | None |  |
| q-4d3897db9e | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy8J3fS"} | None |  |
| q-b9a447a71e | triage T1558 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgh9J"} | None |  |
| q-4e8e74d2d3 | triage T1558 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgh9K"} | None |  |
| q-83f578e1dd | triage T1606 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND (win.GrantedAccess:\"0x1fffff\" OR win.GrantedAccess:\"0x101001\" OR win.GrantedAccess:\"0x1f3fff\" OR win.GrantedAccess:\"0x1000000\" OR win.GrantedAccess:\"0x3000\")", "tim… | 9 | F49 |
| q-b39a75abd1 | triage T1606 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*cookie* OR file.path:*Cookies*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "process.executable", "process.command_line", "file.path", "user.name"], "size": 1… | 1 | F50 |
| q-ecedebc455 | triage T1606 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-a88049468b | triage T1606 step 2 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == 4104 AND @timestamp >= \"2020-05-02T03:00:00.000Z\" AND @timestamp <= \"2020-05-02T03:12:00.000Z\" \| KEEP @timestamp, host.name, user.name, win.ScriptBlockId, win.Scri… | ERROR |  |
| q-c77c68b965 | triage T1606 step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND @timestamp >= \"2020-05-02T03:00:00.000Z\" AND @timestamp <= \"2020-05-02T03:12:00.000Z\" \| KEEP @timestamp, host.name, user.name, win.ScriptBlockId, win.… | 30 |  |
| q-659f812f34 | triage T1606 step 3 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND host.name:scranton.dmevals.local AND process.pid:2976", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "process.executable", "process.command_line", "process.parent.executable"… | 1 | F49 |
| q-9c5bc2354e | triage T1606 step 4 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND host.name:scranton.dmevals.local AND (process.command_line:*lsass* OR process.command_line:*minidump* OR process.command_line:*comsvcs* OR process.command_line:*procdump* OR process.command_line:*credent… | 1 |  |
| q-e5b7ae3f11 | triage T1606 step 4 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*.pfx OR file.path:*.bmp OR file.path:*.png OR file.path:*OfficeSupplies*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "process.executable", "process.command_l… | 6 | F49, F51 |
| q-d42ca3e4af | triage T1606 step 5 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND @timestamp >= \"2020-05-02T03:04:00.000Z\" AND @timestamp <= \"2020-05-02T03:07:00.000Z\" \| KEEP @timestamp, host.name, user.name, win.ScriptBlockId, win.… | 25 |  |
| q-62449c65a1 | triage T1606 step 5 | search | {"dataset": "windows.security", "query": "event.code:4648 OR (event.code:4624 AND win.LogonType:9)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "user.name", "win.TargetUserName", "win.LogonProcessName", "win.IpAddre… | 15 | F49 |
| q-263124c9d7 | triage T1606 step 6 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnaXZbs"} | None |  |
| q-ee13c7a5de | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-9bc70e6711 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-e9b4ec93ec | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None |  |
| q-dfe79ec965 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBorwtwa"} | None |  |
| q-d473cb97d9 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQkXH"} | None |  |
| q-5ddf306bd5 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBo05T5k"} | None |  |
| q-272227c685 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuu5GRH"} | None |  |
| q-ef18aafcd7 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBi-6ySm"} | None |  |
| q-2b017dec19 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBi-6ySm"} | None |  |
| q-5a34909145 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQkXH"} | None |  |
| q-2ae890c880 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQkXH"} | None |  |
| q-b12b785553 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoHL6FX"} | None |  |
| q-ef5d49ca70 | triage T1621 step 1 | aggregate | {"dataset": "windows.other", "field": "event.code", "query": "event.code:4625 OR event.code:5857 OR event.code:5858", "time_from": null, "time_to": null, "size": 20, "sub_field": "host.name"} | 85 |  |
| q-53e3504226 | triage T1621 step 1 | aggregate | {"dataset": "windows.other", "field": "win.Operation", "query": "event.code:5857 OR event.code:5858 OR event.code:5860", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 88 |  |
| q-5a30008c0e | triage T1621 step 2 | search | {"dataset": "windows.other", "query": "event.code:5857", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "user.name", "message", "win.Operation", "win.ClientMachine", "win.param1", "win.param2"], "size": 10, "sort": "asc… | 36 | F52 |
| q-ecf600f59e | triage T1621 step 2 | esql | {"query": "FROM logs-windows.other-default METADATA _id, _index \| WHERE event.code == 5858 AND host.name == \"scranton.dmevals.local\" \| KEEP @timestamp, host.name, user.name, message, _id, _index"} | ERROR |  |
| q-3d291d92f4 | triage T1621 step 3 | esql | {"query": "FROM logs-windows.other-default METADATA _id, _index \| WHERE event.code == \"5858\" AND host.name == \"scranton.dmevals.local\" \| KEEP @timestamp, host.name, user.name, message, _id, _index"} | 1 | F52 |
| q-f45c4a87b9 | triage T1621 step 3 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4624\",\"4625\",\"4648\",\"4672\") AND (TO_LOWER(win.TargetUserName) LIKE \"*mfa*\" OR TO_LOWER(win.TargetUserName) LIKE \"*auth*\" OR TO_LOWER(win.LogonProcessName) L… | 0 |  |
| q-e8abc252e7 | triage T1621 step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*mfa*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*2fa*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*authenticator*\" OR … | 1 |  |
| q-7d207684a6 | triage T1621 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*mfa*\" OR TO_LOWER(process.command_line) LIKE \"*2fa*\" OR TO_LOWER(process.command_line) LIKE \"*authenticator*\" OR TO_L… | 0 |  |
| q-86498d0c23 | triage T1621 step 5 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByOXiqV"} | None | F52 |
| q-7a2f704ad6 | triage T1621 step 5 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4624\" \| STATS c = COUNT(*) BY win.LogonType, win.LogonProcessName, win.AuthenticationPackageName \| SORT c DESC"} | 6 |  |
| q-0ac7e1a725 | triage T1621 step 6 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4624\" AND win.LogonType == \"10\" \| KEEP @timestamp, host.name, win.TargetUserName, win.IpAddress, win.Workstation, win.LogonProcessName, _id, _index"} | 2 |  |
| q-71c1155121 | triage T1621 step 6 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4624\" AND win.LogonType == \"3\" AND win.AuthenticationPackageName == \"NTLM\" \| KEEP @timestamp, host.name, win.TargetUserName, win.IpAddress, win.Workstation, _id, … | 1 |  |
| q-e4a2fb0e9b | triage T1621 step 7 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBufr2mI"} | None | F52 |
| q-7fe33e482e | triage T1621 step 7 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBudppFY"} | None | F52 |
| q-2d195b1c8f | triage T1621 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeBwdLx2X"} | None |  |
| q-28842f4d0a | triage T1621 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeBwdMB0b"} | None |  |
| q-eb8605c45a | triage T1621 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeBwdMB1I"} | None |  |
| q-b6319c3c0f | triage T1621 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByOXiqV"} | None |  |
| q-46b3ab88e8 | triage T1621 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBufr2mI"} | None |  |
| q-84bc652072 | triage T1621 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBudppFY"} | None |  |
| q-41ebb4155c | triage T1649 step 1 | search | {"dataset": "windows.security", "query": "event.code:4657 AND win.ObjectName:*SystemCertificates*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "pr… | 1 |  |
| q-43672a8d16 | triage T1649 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:13 AND registry.path:*SystemCertificates*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process… | 19 | F53, F54 |
| q-26e17f8678 | triage T1649 step 1 | search | {"dataset": "windows.security", "query": "event.code:4768", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 14 | F54 |
| q-caaeae99be | triage T1649 step 2 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Cert* OR win.ScriptBlockText:*Pfx* OR win.ScriptBlockText:*Crypto* OR win.ScriptBlockText:*X509*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", … | 1 |  |
| q-6d68c3286f | triage T1649 step 2 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuu4mRU"} | None | F54 |
| q-819e5143cb | triage T1649 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*Cert* OR process.command_line:*certutil* OR process.command_line:*Pfx* OR process.command_line:*Crypto*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name",… | 1 |  |
| q-fb63d989b6 | triage T1649 step 3 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None | F53 |
| q-c45a1b642b | triage T1649 step 3 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*pfx OR file.path:*Downloads*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "… | 314 |  |
| q-ba4ef36d7b | triage T1649 step 4 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND file.path:*.pfx", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "so… | 1 | F53 |
| q-2f3eff0691 | triage T1649 step 4 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Get-PrivateKeys* OR win.ScriptBlockText:*Export-PfxCertificate* OR win.ScriptBlockText:*readme.ps1*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name… | 4 | F53 |
| q-17cb16b0f4 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-17c7ac3b46 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-5ed66f481a | triage T1649 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-bb2a2a6a69 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLrb"} | None |  |
| q-d6206b64f9 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRarqv"} | None |  |
| q-0585b38855 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaboh"} | None |  |
| q-74b1988f1e | triage T1649 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQkXH"} | None |  |
| q-5f9587c9be | triage T1649 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQkXN"} | None |  |
| q-f840e75ee9 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoNQ2BV"} | None |  |
| q-6ac3b84e3b | triage T1649 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuu4mRU"} | None |  |
| q-f4bfed8050 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuu4mRU"} | None |  |
| q-267952b38b | triage T1649 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBogld9W"} | None |  |
| q-864a83b91b | triage T1649 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuy-fsg"} | None |  |
| q-8a038a85ac | triage T1649 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBus3Fam"} | None |  |
| q-9c6e3e9127 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy0A4ua"} | None |  |
| q-26edefb75e | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy0A4ua"} | None |  |
| q-cc06bd9f91 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy0A4uc"} | None |  |
| q-5c7b38e643 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBux8Gu0"} | None |  |
| q-68e7313189 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBux8Gu0"} | None |  |
| q-acfaa99d2c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None |  |
| q-5c2a52cb01 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-1f3ea9d6bf | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-83c2c216e1 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRZ7r-"} | None |  |
| q-8d5dcb092b | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLr9"} | None |  |
| q-7291dc090c | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBudp5HI"} | None |  |
| q-2b3d68d00b | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuWmZPb"} | None |  |
| q-e7ae4273bc | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuv695R"} | None |  |
| q-bcb6d7b046 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnqqYem"} | None |  |
| q-cd91d930eb | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnaXZbu"} | None |  |
| q-79c9248644 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBox14nu"} | None |  |
| q-4385431c95 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn44l3s"} | None |  |
| q-be424f98e6 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoGKqgM"} | None |  |
| q-86b792e51c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnfdUsq"} | None |  |
| q-1160adea57 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByCVdVX"} | None |  |
| q-ac150d2a87 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnvvDAD"} | None |  |
| q-152ab33fd3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnvvDAD"} | None |  |
| q-dcb0f9e675 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnkjXIW"} | None |  |
| q-c2a7fc8024 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBufr2mN"} | None |  |
| q-d9d4479aa6 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByDV_QB"} | None |  |
| q-d26d1e4669 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByCVdVX"} | None |  |
| q-57d6963fc2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoz4j7h"} | None |  |
| q-91ed7bacb8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnyzTy7"} | None |  |
| q-5be7791808 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBow16Q8"} | None |  |
| q-e17e355265 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBouy-nD"} | None |  |
| q-cbcfb02924 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBouy-nD"} | None |  |
| q-87a044efd8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBorwtwa"} | None |  |
| q-afa1386a93 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None |  |
| q-90562a03af | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None |  |
| q-65892d3b8f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-be890ec61b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None |  |
| q-5c46c40a3a | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBudp5HI"} | None |  |
| q-38444ea697 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBudp5HI"} | None |  |
| q-5dadece9dd | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-f3fe592692 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-01c4791328 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByCVtlI"} | None |  |
| q-bbddc58d41 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBouy-nD"} | None |  |
| q-1c2e61c685 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByPYrDh"} | None |  |
| q-89e38fd69b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBouy-nD"} | None |  |
| q-9f04de8a02 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuTlU_q"} | None |  |
| q-796f300bfd | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeBwdMB0P"} | None |  |
| q-8b095be71e | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuTlU_q"} | None |  |
| q-e2613baea2 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLr9"} | None |  |
| q-b8aceccb46 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-456caff0f7 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None |  |
| q-8adfd47027 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-b002c749a2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoXbqWA"} | None |  |
| q-439b4474b0 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuu5GRH"} | None |  |
| q-da3fc6ebc5 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeBwdMB0i"} | None |  |
| q-55d725fe8d | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByCVtlI"} | None |  |
| q-9797ce5bb2 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-14778a7855 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByDVjze"} | None |  |
| q-1674ea469e | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByCVMj0"} | None |  |
| q-b07f73f8d7 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-ef6f209439 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-14d441e847 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-38a0e800c3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoXbqWA"} | None |  |
| q-ad65b86662 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuu5GRH"} | None |  |
| q-298adb45f8 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuu5GRH"} | None |  |
| q-87cc9a6685 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnfdUsq"} | None |  |
| q-59ee353fe0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnQM1oU"} | None |  |
| q-dbb82fa3a0 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeBwdMB1A"} | None |  |
| q-ed8ef34673 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByPYrDh"} | None |  |
| q-be7781ca73 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgR9D"} | None |  |
| q-2a2c1b32e8 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgR9D"} | None |  |
| q-6d49ffe238 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgR9H"} | None |  |
| q-4450b982f0 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgR9H"} | None |  |
| q-936e552f57 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgh9V"} | None |  |
| q-5e48f0011c | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgh9V"} | None |  |
| q-78ce405bb6 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgh8V"} | None |  |
| q-ec472ceae8 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgh8V"} | None |  |
| q-fdf6291442 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgR_2"} | None |  |
| q-4dc6f89e85 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgR_2"} | None |  |
| q-621c159e2b | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgh-i"} | None |  |
| q-eafc1c0190 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuv5CHS"} | None |  |
| q-308ddb7d59 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuv5CHS"} | None |  |
| q-92ee577b70 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuv5CHS"} | None |  |
| q-f54c8e0d89 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy8KXgw"} | None |  |
| q-1b1729471d | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy7JbTW"} | None |  |
| q-f4c577adce | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy7JbTW"} | None |  |
| q-49d5139a2e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoSWKN8"} | None |  |
| q-2667634b7f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoSWKN8"} | None |  |
| q-1cc3ec0f8d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBorwtwa"} | None |  |
| q-224fed2aff | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBorwtwa"} | None |  |
| q-fbbb447164 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-b22c59b3ee | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-1d35a0b734 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-0608d4d17b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None |  |
| q-014f2bd5c4 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-29b1e31776 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-c0d948ee73 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-df841ed87b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBo05D7L"} | None |  |
| q-b6752ea098 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBo05D7L"} | None |  |
| q-413ba803f2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnrrZmZ"} | None |  |
| q-cd6f3e7ecc | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnrrZmZ"} | None |  |
| q-0d51e8fa2b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnqqYet"} | None |  |
| q-4841794e6a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUWX"} | None |  |
| q-3ff15f4843 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUWX"} | None |  |
| q-9d15ecfb1b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUWX"} | None |  |
| q-9316375a84 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUWe"} | None |  |
| q-931e5b43ed | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUWf"} | None |  |
| q-571811062e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBorwtwa"} | None |  |
| q-9c7c605541 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBi-6ySm"} | None |  |
| q-b26ef035ae | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBur1GH0"} | None |  |
| q-e70fbd7a82 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBow06T9"} | None |  |
| q-5b7d315284 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBotx_LQ"} | None |  |
| q-58e5dd56fe | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoNRGHl"} | None |  |
| q-a0e14a6f53 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoNRGHW"} | None |  |
| q-c91183fc99 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy4FbJN"} | None |  |
| q-26788801cd | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy4FbJN"} | None |  |
| q-29d49d1e4a | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy4FbJN"} | None |  |
| q-7da8d24af2 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy1A5nE"} | None |  |
| q-bec764308f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoz4z4i"} | None |  |
| q-6efdc8639d | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByCVdVX"} | None |  |
| q-b83d705637 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuu5GRH"} | None |  |
| q-d4cbd7185e | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuu5GRH"} | None |  |
| q-05ed1329e1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoz4j7h"} | None |  |
| q-1f8a3b5212 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBow1qSj"} | None |  |
| q-f104b4321b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoKOGL_"} | None |  |
| q-95766c8dce | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnfdUsq"} | None |  |
| q-701a1b5c77 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnQM1oP"} | None |  |
| q-130e4ff5ab | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgR8g"} | None |  |
| q-87096d521f | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgh8M"} | None |  |
| q-b9ab7ee587 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeByNiUGh"} | None |  |
| q-a6cc156680 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-05206957d1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-b8b6afeea7 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-ba5508048a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-d4799c3fa6 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-487fb20e8f | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByEVwPJ"} | None |  |
| q-f403f0b8c7 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuv5SEZ"} | None |  |
| q-3c2058c58b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBov0sHE"} | None |  |
| q-d708d7e7f3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnUQthh"} | None |  |
| q-b6390df9b8 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBudppHD"} | None |  |
| q-3f7a236e82 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeBwdMB1A"} | None |  |
| q-b2030bb894 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-22e83e5918 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-e42c259e89 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnrrZmZ"} | None |  |
| q-0e5800054f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnqqYet"} | None |  |
| q-47c1c06247 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRarrZ"} | None |  |
| q-04fa0ee5d2 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy3Dxwo"} | None |  |
| q-3f06957775 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuu5GRH"} | None |  |
| q-f21d2e1549 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBumxOdt"} | None |  |
| q-1ee3d2e3b6 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeBwdMB02"} | None |  |
| q-26bd6046a7 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeBwdLx2Z"} | None |  |
| q-021f9a1e71 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByEVwPx"} | None |  |
| q-b4ca4ffa7f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBjD_woi"} | None |  |
| q-36adac07d0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnQM1oU"} | None |  |
| q-35567a3a0c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoGKaib"} | None |  |
| q-bbe8ef025d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBi85CSi"} | None |  |
| q-0a9a61a32e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBi96CXA"} | None |  |
| q-899eb6582b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoz3z5O"} | None |  |
| q-736212d6a0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnvvDAD"} | None |  |
| q-36a5c1b53a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnmk3GC"} | None |  |
| q-d39cb54507 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgR-T"} | None |  |
| q-670066b6c1 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgR-Z"} | None |  |
| q-231eccfba9 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgR_V"} | None |  |
| q-b4b1b4f371 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBumxOeO"} | None |  |
| q-86165b66a0 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeByOkBkA"} | None |  |
| q-a3ffee8cd4 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgR_N"} | None |  |
| q-019975127e | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgR_N"} | None |  |
| q-d4262325d8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnmk3GC"} | None |  |
| q-a782d2100e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnvvDAD"} | None |  |
| q-8219e503dc | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-66017878aa | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None |  |
| q-a55df5948b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBorwtwa"} | None |  |
| q-0ef3fc10ce | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy4FbJD"} | None |  |
| q-bf3e9eb3a2 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuw7KBe"} | None |  |
| q-1067b5fa00 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-8d33b0e2ec | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy4FbJD"} | None |  |
| q-94d68eac53 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuw7KBe"} | None |  |
| q-9e6bbc01af | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuw7KBe"} | None |  |
| q-aa43f04464 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuv5SEr"} | None |  |
| q-31ac5df1fc | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuv5SEr"} | None |  |
| q-6e2a802183 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy8J3fS"} | None |  |
| q-6ea1c2c33a | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy8J3fS"} | None |  |
| q-20c98c5c11 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgh9J"} | None |  |
| q-2d82b28165 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgh9K"} | None |  |
| q-60048f5bde | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-fba597ee34 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-74b90cadf0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None |  |
| q-f7822dfc89 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBorwtwa"} | None |  |
| q-76cc1108d3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQkXH"} | None |  |
| q-bdefd9dd88 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBo05T5k"} | None |  |
| q-20723a72f1 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuu5GRH"} | None |  |
| q-6e621ce75f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBi-6ySm"} | None |  |
| q-ab7ae4f1b3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBi-6ySm"} | None |  |
| q-cc3348044e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQkXH"} | None |  |
| q-f4a7ead325 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQkXH"} | None |  |
| q-70d5afada3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoHL6FX"} | None |  |
| q-f6146bdc9f | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeBwdLx2X"} | None |  |
| q-5590a071f2 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeBwdMB0b"} | None |  |
| q-022569d109 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeBwdMB1I"} | None |  |
| q-dee5802faa | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByOXiqV"} | None |  |
| q-9d11183f12 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBufr2mI"} | None |  |
| q-55c9e6ff5e | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBudppFY"} | None |  |
| q-4014886dcb | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-85c8572926 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-e8192dfea8 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-8f3a93d520 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLrb"} | None |  |
| q-b4b2a99c88 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRarqv"} | None |  |
| q-1fc8d3183e | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaboh"} | None |  |
| q-19d405119b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQkXH"} | None |  |
| q-fb5ee24e40 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQkXN"} | None |  |
| q-0f9468ebf1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoNQ2BV"} | None |  |
| q-65a2258ec5 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuu4mRU"} | None |  |
| q-a32034d1e2 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuu4mRU"} | None |  |
| q-41cb52715f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBogld9W"} | None |  |
| q-513c51c5d7 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuy-fsg"} | None |  |
| q-dc33bf2c23 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBus3Fam"} | None |  |
| q-c92c4eb272 | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND host.name:\"nashua.dmevals.local\"", "time_from": "2020-05-02T02:54:23+00:00", "time_to": "2020-05-02T03:31:19.395000+00:00", "size": 100, "sub_field": "process.parent.exec… | 61 |  |
| q-1e5fcb45dd | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11 AND host.name:\"nashua.dmevals.local\"", "time_from": "2020-05-02T02:54:23+00:00", "time_to": "2020-05-02T03:31:19.395000+00:00", "size": 100, "sub_field": "process.executable"} | 249 |  |
| q-f0d34b9fe8 | pivot seed | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND host.name:\"nashua.dmevals.local\"", "time_from": "2020-05-02T02:54:23+00:00", "time_to": "2020-05-02T03:31:19.395000+00:00", "size": 100, "sub_field": "process.parent… | 63 |  |
| q-20d698476f | pivot seed | aggregate | {"dataset": "windows.powershell", "field": "event.code", "query": "host.name:\"nashua.dmevals.local\"", "time_from": "2020-05-02T02:54:23+00:00", "time_to": "2020-05-02T03:31:19.395000+00:00", "size": 100, "sub_field": null} | 192 |  |
| q-a903efd0db | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND host.name:\"newyork.dmevals.local\"", "time_from": "2020-05-02T02:46:43+00:00", "time_to": "2020-05-02T03:34:13+00:00", "size": 100, "sub_field": "process.parent.executable… | 18 |  |
| q-f22b659bd6 | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11 AND host.name:\"newyork.dmevals.local\"", "time_from": "2020-05-02T02:46:43+00:00", "time_to": "2020-05-02T03:34:13+00:00", "size": 100, "sub_field": "process.executable"} | 81 |  |
| q-ef9ea15bcb | pivot seed | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND host.name:\"newyork.dmevals.local\"", "time_from": "2020-05-02T02:46:43+00:00", "time_to": "2020-05-02T03:34:13+00:00", "size": 100, "sub_field": "process.parent.execu… | 18 |  |
| q-13ebe1533d | pivot seed | aggregate | {"dataset": "windows.powershell", "field": "event.code", "query": "host.name:\"newyork.dmevals.local\"", "time_from": "2020-05-02T02:46:43+00:00", "time_to": "2020-05-02T03:34:13+00:00", "size": 100, "sub_field": null} | 2185 |  |
| q-bf64a326f6 | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND host.name:\"scranton.dmevals.local\"", "time_from": "2020-05-02T02:42:00.933000+00:00", "time_to": "2020-05-02T03:26:18.784000+00:00", "size": 100, "sub_field": "process.pa… | 359 |  |
| q-a38f1d1473 | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11 AND host.name:\"scranton.dmevals.local\"", "time_from": "2020-05-02T02:42:00.933000+00:00", "time_to": "2020-05-02T03:26:18.784000+00:00", "size": 100, "sub_field": "process.executable… | 1274 |  |
| q-155515247e | pivot seed | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND host.name:\"scranton.dmevals.local\"", "time_from": "2020-05-02T02:42:00.933000+00:00", "time_to": "2020-05-02T03:26:18.784000+00:00", "size": 100, "sub_field": "proce… | 370 |  |
| q-900b12ef00 | pivot seed | aggregate | {"dataset": "windows.powershell", "field": "event.code", "query": "host.name:\"scranton.dmevals.local\"", "time_from": "2020-05-02T02:42:00.933000+00:00", "time_to": "2020-05-02T03:26:18.784000+00:00", "size": 100, "sub_field": null} | 8602 |  |
| q-271d43c365 | pivot step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND host.name == \"nashua.dmevals.local\" AND (process.executable LIKE \"*python.exe\" OR process.executable LIKE \"*Rar.exe\" OR process.executable LIKE \"*sdelete64… | 10 | F55 |
| q-a406ca9b70 | pivot step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND host.name == \"scranton.dmevals.local\" AND (process.executable LIKE \"*csc.exe\" OR process.executable LIKE \"*hostui.exe\" OR process.executable LIKE \"*sdclt.e… | 15 | F56, F61, F62, F63, F64, F65 |
| q-1c78eb56f2 | pivot step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE host.name == \"nashua.dmevals.local\" AND (process.executable LIKE \"*python.exe\" OR process.executable LIKE \"*Rar.exe\" OR process.executable LIKE \"*powershell.exe\" OR process.execu… | ERROR |  |
| q-63fa2c9aa5 | pivot step 2 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE host.name == \"nashua.dmevals.local\" AND event.code == \"4104\" \| KEEP @timestamp, user.name, powershell.file.script_block_text, _id, _index \| SORT @timestamp"} | ERROR |  |
| q-5bc0b55795 | pivot step 3 | get_fields | {"dataset": "windows.powershell", "prefix": ""} | None |  |
| q-6e7fec93c1 | pivot step 3 | get_fields | {"dataset": "windows.sysmon", "prefix": ""} | None |  |
| q-88b5a0a7f1 | pivot step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE host.name == \"nashua.dmevals.local\" AND (process.executable LIKE \"*python.exe\" OR process.executable LIKE \"*Rar.exe\" OR process.executable LIKE \"*powershell.exe\" OR process.execu… | 500 | F55, F57 |
| q-87498e0161 | pivot step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE host.name == \"nashua.dmevals.local\" AND event.code == \"4104\" \| KEEP @timestamp, user.name, win.ScriptBlockText, _id, _index \| SORT @timestamp"} | 11 | F58 |
| q-75c4c1fe24 | pivot step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE host.name == \"nashua.dmevals.local\" AND process.executable LIKE \"*python.exe\" AND event.code IN (\"3\",\"11\",\"22\",\"23\",\"10\",\"1\") \| KEEP @timestamp, event.code, process.exec… | 391 |  |
| q-f194f304f9 | pivot step 5 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE host.name == \"scranton.dmevals.local\" AND event.code == \"4104\" AND (win.ScriptBlockText LIKE \"*lsass*\" OR win.ScriptBlockText LIKE \"*pfx*\" OR win.ScriptBlockText LIKE \"*Priv… | 3 |  |
| q-811152a628 | pivot step 6 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (file.path LIKE \"*.pfx\" OR file.path LIKE \"*.7z\" OR file.path LIKE \"*.zip\" OR file.path LIKE \"*passwordsDB*\" OR file.path LIKE \"*.kirbi\" OR file.path L… | 14 | F60, F61 |
| q-5e11f5128f | pivot step 6 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND (win.TargetImage LIKE \"*lsass*\" OR win.TargetImage LIKE \"*MicrosoftEdge*\" OR win.TargetImage LIKE \"*vault*\" OR win.TargetImage LIKE \"*Credential*\") \| KE… | 500 |  |
| q-76cf0ca21e | pivot step 7 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE host.name == \"newyork.dmevals.local\" AND event.code == \"4104\" AND (win.ScriptBlockText LIKE \"*lsass*\" OR win.ScriptBlockText LIKE \"*pfx*\" OR win.ScriptBlockText LIKE \"*Priva… | 24 |  |
| q-767561c97a | pivot step 7 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4663\",\"4656\",\"4661\") AND (win.ObjectName LIKE \"*SAM*\" OR win.ObjectName LIKE \"*SECURITY*\" OR win.ObjectName LIKE \"*lsass*\" OR win.ObjectName LIKE \"*LSA*\" … | 31 |  |
| q-ffff1f7f8b | pivot step 8 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE host.name == \"scranton.dmevals.local\" AND event.code == \"4104\" AND @timestamp >= \"2020-05-02T03:00:00Z\" AND @timestamp <= \"2020-05-02T03:09:00Z\" \| KEEP @timestamp, user.name… | 95 |  |
| q-2ca31d8fb2 | pivot step 8 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4656\",\"4663\") AND win.ObjectName LIKE \"*SAM*\" AND win.ProcessName NOT LIKE \"*lsass.exe\" \| KEEP @timestamp, host.name, user.name, event.code, win.ObjectName, wi… | 0 |  |
| q-d70255cf90 | pivot step 9 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE host.name == \"scranton.dmevals.local\" AND event.code == \"4104\" AND @timestamp >= \"2020-05-02T03:05:25Z\" AND @timestamp <= \"2020-05-02T03:22:00Z\" \| KEEP @timestamp, user.name… | 81 | F59, F60 |
| q-2bc81b0ad2 | pivot step 9 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND host.name == \"scranton.dmevals.local\" AND (file.path LIKE \"*readme*\" OR file.path LIKE \"*Sysinternals*\" OR file.path LIKE \"*victim*\" OR file.path LIKE \"… | 313 |  |
| q-58c74cb32c | pivot step 10 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnyzTy7"} | None | F55 |
| q-50076c0b7c | pivot step 10 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBow1qSj"} | None | F58 |
| q-665af65f27 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-bfab59d53f | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnyzTy7"} | None |  |
| q-d3de92b345 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoz4j7h"} | None |  |
| q-44141912cf | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoz4z4i"} | None |  |
| q-0a50264997 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBox2Il2"} | None |  |
| q-034fa2c2ea | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBox2Il3"} | None |  |
| q-ae03bd1f30 | pivot verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByDVjze"} | None |  |
| q-7d18f2999b | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBow1qSj"} | None |  |
| q-bd900779e3 | pivot verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLr9"} | None |  |
| q-932f410d24 | pivot verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLr6"} | None |  |
| q-db7732a66e | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQkXH"} | None |  |
| q-813e9c6750 | pivot verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByPYrDh"} | None |  |
| q-b20b6241fd | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy0A4ua"} | None |  |
| q-764c118ded | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy0A4ua"} | None |  |
| q-9b15d352e1 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy0A4uc"} | None |  |
| q-9cf67fddc4 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBux8Gu0"} | None |  |
| q-392bd45531 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBux8Gu0"} | None |  |
| q-b55044b29f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None |  |
| q-7da4707a1c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-41142ee78b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-297ae9157e | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRZ7r-"} | None |  |
| q-5712fc6cec | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLr9"} | None |  |
| q-afd206099a | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBudp5HI"} | None |  |
| q-eaa862ffda | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuWmZPb"} | None |  |
| q-0afb0b30d2 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuv695R"} | None |  |
| q-08d4963fca | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnqqYem"} | None |  |
| q-c5948922e5 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnaXZbu"} | None |  |
| q-886d707059 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBox14nu"} | None |  |
| q-fb83ff8e3a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn44l3s"} | None |  |
| q-1fc9185178 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoGKqgM"} | None |  |
| q-92f3144282 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnfdUsq"} | None |  |
| q-9ab11c25c2 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByCVdVX"} | None |  |
| q-1692e04310 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnvvDAD"} | None |  |
| q-70d28971df | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnvvDAD"} | None |  |
| q-7bc8543ff2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnkjXIW"} | None |  |
| q-3131ea6efe | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBufr2mN"} | None |  |
| q-18cfc5678a | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByDV_QB"} | None |  |
| q-9d9fc85d3c | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByCVdVX"} | None |  |
| q-0fd4da392b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoz4j7h"} | None |  |
| q-a03dbd8195 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnyzTy7"} | None |  |
| q-692c7c0d94 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBow16Q8"} | None |  |
| q-7a22b3f79d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBouy-nD"} | None |  |
| q-cb11682141 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBouy-nD"} | None |  |
| q-1e3783d056 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBorwtwa"} | None |  |
| q-063debe652 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None |  |
| q-36f61f5ce0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None |  |
| q-3c6eaacdff | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-5057517358 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None |  |
| q-05855a512f | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBudp5HI"} | None |  |
| q-e88cbe8fe9 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBudp5HI"} | None |  |
| q-73c7f175a5 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-4b2a7b09ad | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-d50c015b1d | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByCVtlI"} | None |  |
| q-34d1c79c7c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBouy-nD"} | None |  |
| q-15d778a120 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByPYrDh"} | None |  |
| q-2f8b1b5f6e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBouy-nD"} | None |  |
| q-3a91800d4b | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuTlU_q"} | None |  |
| q-b9d1ed8a33 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeBwdMB0P"} | None |  |
| q-a163920caa | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuTlU_q"} | None |  |
| q-8e19d23732 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLr9"} | None |  |
| q-34e36d2558 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-4553cdc6f1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None |  |
| q-29a9e7009a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-76d3caa689 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoXbqWA"} | None |  |
| q-a32b541f13 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuu5GRH"} | None |  |
| q-c1aa0f395a | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeBwdMB0i"} | None |  |
| q-f7c5a5181c | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByCVtlI"} | None |  |
| q-72a50498f5 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-796a11a7ce | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByDVjze"} | None |  |
| q-1b5ac7f5c6 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByCVMj0"} | None |  |
| q-b281b13a17 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-aa74347570 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-39836043db | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-8ab85058d0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoXbqWA"} | None |  |
| q-ba3a994eed | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuu5GRH"} | None |  |
| q-af2c9f3129 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuu5GRH"} | None |  |
| q-0dfa83b8b2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnfdUsq"} | None |  |
| q-0004ccb6d7 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnQM1oU"} | None |  |
| q-9d5e41a0e1 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeBwdMB1A"} | None |  |
| q-1151826393 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByPYrDh"} | None |  |
| q-5d0672a570 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgR9D"} | None |  |
| q-4529b67eae | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgR9D"} | None |  |
| q-f89e69d627 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgR9H"} | None |  |
| q-3f96673fda | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgR9H"} | None |  |
| q-f0263b6f5d | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgh9V"} | None |  |
| q-1d05bacd04 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgh9V"} | None |  |
| q-915e67898e | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgh8V"} | None |  |
| q-35b34c888b | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgh8V"} | None |  |
| q-d569ddcd9a | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgR_2"} | None |  |
| q-3fa84d80dc | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgR_2"} | None |  |
| q-ce6c443ee5 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgh-i"} | None |  |
| q-4d36dc60c7 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuv5CHS"} | None |  |
| q-f14c44eabe | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuv5CHS"} | None |  |
| q-fef0a08a70 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuv5CHS"} | None |  |
| q-b5c3ac98b2 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy8KXgw"} | None |  |
| q-6113be4e20 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy7JbTW"} | None |  |
| q-57924c56f4 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy7JbTW"} | None |  |
| q-c70bcb4496 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoSWKN8"} | None |  |
| q-176ee9fb63 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoSWKN8"} | None |  |
| q-13fb3bc5a8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBorwtwa"} | None |  |
| q-5f1f1c70c2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBorwtwa"} | None |  |
| q-63803ab270 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-84422e8eae | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-2e21110fd2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-8f07fb4cbb | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None |  |
| q-1f8b111050 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-a58a5eebac | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-fbaf1ab00d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-18ed92c8b7 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBo05D7L"} | None |  |
| q-b30cdb6f97 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBo05D7L"} | None |  |
| q-c124661fc7 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnrrZmZ"} | None |  |
| q-4797a12634 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnrrZmZ"} | None |  |
| q-cec8b02dc2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnqqYet"} | None |  |
| q-43920b8c6a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUWX"} | None |  |
| q-e08915e35e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUWX"} | None |  |
| q-c302838d2e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUWX"} | None |  |
| q-a9204cf3e2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUWe"} | None |  |
| q-3a76173ffa | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUWf"} | None |  |
| q-e76c3ea9e3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBorwtwa"} | None |  |
| q-ea37c41788 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBi-6ySm"} | None |  |
| q-d804337b6f | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBur1GH0"} | None |  |
| q-c2e3d89bcd | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBow06T9"} | None |  |
| q-b7849fee69 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBotx_LQ"} | None |  |
| q-5b504c8893 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoNRGHl"} | None |  |
| q-a803e737d4 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoNRGHW"} | None |  |
| q-f6aa5e226f | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy4FbJN"} | None |  |
| q-ff0a903daa | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy4FbJN"} | None |  |
| q-e5a54b1687 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy4FbJN"} | None |  |
| q-aaffb1fe32 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy1A5nE"} | None |  |
| q-04932ffa0a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoz4z4i"} | None |  |
| q-17d4be0603 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByCVdVX"} | None |  |
| q-133856880b | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuu5GRH"} | None |  |
| q-1828687980 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuu5GRH"} | None |  |
| q-a9fd3f6b12 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoz4j7h"} | None |  |
| q-bb96325bfe | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBow1qSj"} | None |  |
| q-a20909b903 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoKOGL_"} | None |  |
| q-a8427e10a4 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnfdUsq"} | None |  |
| q-bdea9838a5 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnQM1oP"} | None |  |
| q-26337884de | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgR8g"} | None |  |
| q-f0ef19d95d | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgh8M"} | None |  |
| q-44ba227f56 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeByNiUGh"} | None |  |
| q-b161f09632 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-db6776433f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-8d7e7a97ad | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-194416cb6e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-9e82803168 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-8441fc4c69 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByEVwPJ"} | None |  |
| q-a4028c9138 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuv5SEZ"} | None |  |
| q-7dc027609e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBov0sHE"} | None |  |
| q-7de176cf26 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnUQthh"} | None |  |
| q-3410d5d3ba | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBudppHD"} | None |  |
| q-6bbe550aca | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeBwdMB1A"} | None |  |
| q-52516208ae | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-efebdc5a36 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-a3e2d875fb | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnrrZmZ"} | None |  |
| q-2ca2a0b79f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnqqYet"} | None |  |
| q-233cd22daf | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRarrZ"} | None |  |
| q-870aa3da31 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy3Dxwo"} | None |  |
| q-cb706ca978 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuu5GRH"} | None |  |
| q-a7a37d0ddb | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBumxOdt"} | None |  |
| q-a410f56fa1 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeBwdMB02"} | None |  |
| q-98806c5b66 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeBwdLx2Z"} | None |  |
| q-aa216c18f8 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByEVwPx"} | None |  |
| q-f831e3b49a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBjD_woi"} | None |  |
| q-a08379bb8c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnQM1oU"} | None |  |
| q-c97d1cea6e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoGKaib"} | None |  |
| q-b9de75894c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBi85CSi"} | None |  |
| q-71614141cc | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBi96CXA"} | None |  |
| q-37895de933 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoz3z5O"} | None |  |
| q-1fe32f3592 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnvvDAD"} | None |  |
| q-09e42e2dd0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnmk3GC"} | None |  |
| q-4d6dd7250c | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgR-T"} | None |  |
| q-73e83b03de | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgR-Z"} | None |  |
| q-6eaaa6b905 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgR_V"} | None |  |
| q-81c0d50724 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBumxOeO"} | None |  |
| q-6529874448 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeByOkBkA"} | None |  |
| q-63e2ee82b9 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgR_N"} | None |  |
| q-ec3acaeb09 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgR_N"} | None |  |
| q-032becac88 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnmk3GC"} | None |  |
| q-21d25cb989 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnvvDAD"} | None |  |
| q-ae717608e7 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-9d87f443c9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None |  |
| q-b9667a9c25 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBorwtwa"} | None |  |
| q-c9191063d6 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy4FbJD"} | None |  |
| q-0e6e6dcdbc | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuw7KBe"} | None |  |
| q-213773691c | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-64de9084b0 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy4FbJD"} | None |  |
| q-1bf47d765f | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuw7KBe"} | None |  |
| q-383af58098 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuw7KBe"} | None |  |
| q-03cc0cc13f | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuv5SEr"} | None |  |
| q-671264014e | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuv5SEr"} | None |  |
| q-3367dab2d0 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy8J3fS"} | None |  |
| q-3fe10bf4cb | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy8J3fS"} | None |  |
| q-0a7c2a14b7 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgh9J"} | None |  |
| q-c214db2369 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgh9K"} | None |  |
| q-752450ad6e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-e9db3dcafd | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-d2e0a8efa9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None |  |
| q-63659cee8c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBorwtwa"} | None |  |
| q-56dd9c32b7 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQkXH"} | None |  |
| q-95fc241792 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBo05T5k"} | None |  |
| q-fc0516e6bf | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuu5GRH"} | None |  |
| q-8437bab5eb | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBi-6ySm"} | None |  |
| q-21598c307e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBi-6ySm"} | None |  |
| q-4df234a13c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQkXH"} | None |  |
| q-3299287410 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQkXH"} | None |  |
| q-796c59bb96 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoHL6FX"} | None |  |
| q-a643d9d2ec | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeBwdLx2X"} | None |  |
| q-35d63bbdba | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeBwdMB0b"} | None |  |
| q-4e59082206 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeBwdMB1I"} | None |  |
| q-6282e82f09 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByOXiqV"} | None |  |
| q-4d503ce313 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBufr2mI"} | None |  |
| q-f71eb6c740 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBudppFY"} | None |  |
| q-5d02e57713 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-ef4b424851 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-34bad25ac7 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-bc5588335f | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLrb"} | None |  |
| q-6a4d71e696 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRarqv"} | None |  |
| q-a6b80f1d2d | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaboh"} | None |  |
| q-cdbaf61c5b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQkXH"} | None |  |
| q-2d5959a85c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQkXN"} | None |  |
| q-67035e3b6a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoNQ2BV"} | None |  |
| q-de456b9068 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuu4mRU"} | None |  |
| q-90c433123c | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuu4mRU"} | None |  |
| q-96420f51df | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBogld9W"} | None |  |
| q-3c39daeb04 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuy-fsg"} | None |  |
| q-bb7a7e10e5 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBus3Fam"} | None |  |
| q-0e986122af | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-ee0120f520 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnyzTy7"} | None |  |
| q-69923b21f8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoz4j7h"} | None |  |
| q-81eb634bb2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoz4z4i"} | None |  |
| q-2812589b87 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBox2Il2"} | None |  |
| q-4533af0cfa | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBox2Il3"} | None |  |
| q-74421fd48d | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByDVjze"} | None |  |
| q-507de027ca | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBow1qSj"} | None |  |
| q-0e5822b39d | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLr9"} | None |  |
| q-0a326449d1 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLr6"} | None |  |
| q-b597db60d8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQkXH"} | None |  |
| q-32723b8504 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByPYrDh"} | None |  |
| q-977f1df415 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoNRGHW"} | None |  |
| q-256349ac5f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoNRGHl"} | None |  |
| q-fe206218ad | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBow1KRR"} | None |  |
| q-e23731bc55 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBow1KRR"} | None |  |
| q-229086a346 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBorwNwU"} | None |  |
| q-558a9f3112 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBi30hQJ"} | None |  |
| q-e416a26de0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBosxOR1"} | None |  |

## Verification

Evidence items cited: 234; confirmed against the stored events: 234; rejected: 0. Each item was re-fetched with get_event; it is confirmed only if the event exists, the cited field holds the cited value, and the cited query_id is a query of this run that returned that event.
Evidence sent back to the agents for correction during the run: 2 item(s) in 1 submission(s) (one correction round each; what still failed was rejected).

## Limitations

- Findings describe what the stored logs show; activity these sources did not log cannot be seen.
- Datasets with non-overlapping time windows (see Data examined) were analysed separately.
- Long field values are shortened in this report; full events are retrievable by _index/_id.
