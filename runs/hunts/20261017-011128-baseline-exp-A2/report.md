# Threat hunt report — 20261017-011128-baseline-exp-A2

**Hypothesis:** An adversary who compromised Windows hosts in this network stole credentials from them (MITRE ATT&CK tactic: Credential Access).

**Verdict: Confirmed** — The credential-access hypothesis is confirmed by F01: on scranton.dmevals.local, a hidden PowerShell process launched by control.exe from a steganographic payload in monkey.png accessed lsass.exe with full-access masks 0x1f3fff and 0x1fffff and injected an unbacked remote thread into LSASS (Sysmon EID 10 and EID 8, StartModule '-'), which is a high-confidence T1003.001 LSASS credential dumping pattern. Independent Security EID 4656 corroborates the same handle requests. The same activity chain also compiled C# in memory, wrote a .pfx, and then used PsExec64 with the cleartext password of DMEVALS\pbeesly against NASHUA, further supporting credential theft and reuse. F02-F04 are benign/not-evidenced for Get-Process -IncludeUserName, SAM hive dumping, and Kerberoasting, but they do not refute the confirmed LSASS credential dumping. Thus the hypothesis that an adversary stole credentials from compromised Windows hosts is confirmed.

Verdict method: LLM judgement

| Run | Value |
|---|---|
| Profile | baseline (thinking=True, temperature=n/a (ignored in thinking mode)) |
| Model | deepseek-flash |
| Started / finished (UTC) | 2026-10-16T17:11:28+00:00 / 2026-10-16T17:15:22+00:00 (233.9 s) |
| LLM calls / tokens | 23 / {'prompt': 1116504, 'completion': 44210} |
| MCP tool calls | 92 (server tools: list_data_sources, get_fields, search, count, aggregate, timeline, esql, get_event, get_registry) |
| ATT&CK tactics | credential-access — An adversary with access to Windows hosts on this network stole credentials from those hosts. |

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

## Findings

### F01 · malicious / high · T1003.001 · LSASS memory accessed with full-access masks and an unbacked remote thread injected by PowerShell on scranton

Evidence status: **verified**

On 2020-05-02 03:05:16 UTC on scranton.dmevals.local, C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe (PID 2976, user DMEVALS\pbeesly) opened C:\Windows\System32\lsass.exe (PID 736) with GrantedAccess 0x1f3fff and 0x1fffff (Sysmon EID 10) and created a remote thread in it (Sysmon EID 8, NewThreadId 912) starting at 0x00000117610E0000 with StartModule '-' (code in unbacked memory). Security EID 4656 independently shows the same PowerShell process (SubjectUserName pbeesly) requesting handles to \Device\HarddiskVolume2\Windows\System32\lsass.exe with AccessMask 0x1f3fff and 0x1fffff at 23:05:16 local (=03:05:16Z). That PowerShell process was launched at 02:58:44 by C:\Windows\System32\control.exe with a hidden command line that decodes an ASCII payload from C:\Users\pbeesly\Downloads\monkey.png (steganography) and IEXes it, and it then compiled C# in memory via csc.exe (Temp\RES2758.tmp) and wrote a .pfx to Downloads. A second in-memory loader (reflective delegate via UnsafeNativeMethods.GetProcAddress plus a base64 shellcode blob) was logged for the same host/user at 03:21:29 after the 03:18:30 restart initiated by pbeesly. This is LSASS memory access/credential dumping (T1003.001) on scranton by the pbeesly session; the same account then used PsExec64 with the cleartext password of dmevals\pbeesly against \\NASHUA (PSEXESVC installed 4x on nashua, python.exe run from C:\Windows\Temp).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.TargetImage | C:\Windows\System32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R-k13z | q-f4c29ad6db | ok |
| 2 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.StartAddress | 0x00000117610E0000 | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R-k13z | q-f4c29ad6db | ok |
| 3 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.StartModule | - | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R-k13z | q-f4c29ad6db | ok |
| 4 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R-k13y | q-8d60eda11f | ok |
| 5 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R-k131 | q-8d60eda11f | ok |
| 6 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | win.AccessMask | 0x1fffff | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YldM_p | q-aa37985c0c | ok |
| 7 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | win.AccessMask | 0x1f3fff | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YldM_i | q-aa37985c0c | ok |
| 8 | 2020-05-02 02:58:44.325Z | scranton.dmevals.local | windows.sysmon | process.command_line | "PowerShell.exe" -noni -noexit -ep bypass -window hidden -c "sal a New-Object;Add-Type -AssemblyName 'System.Drawing'; $g=a System.Drawing.Bitmap('C:\Users\pbee… | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1WdFNhN | q-8957457cdc | ok |
| 9 | 2020-05-02 02:58:45.589Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Users\pbeesly\AppData\Local\Temp\RES2758.tmp | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1WdEtgZ | q-3c765ade11 | ok |
| 10 | 2020-05-02 03:21:29.000Z | scranton.dmevals.local | windows.powershell | powershell.script_block_text | function jzI {  	Param ($yKR, $cq)		  	$vvA = ([AppDomain]::CurrentDomain.GetAssemblies() \| Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[… | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1bzyNfQ | q-b2c1ad2d88 | ok |

### F02 · benign / medium · T1003.001 · wsmprovhost.exe full-access handle to LSASS on nashua is Get-Process -IncludeUserName enumeration (benign)

Evidence status: **verified**

On 2020-05-02 03:09:29 UTC on nashua.dmevals.local, C:\windows\system32\wsmprovhost.exe (PID 7720, pbeesly PS-remoting session) accessed C:\windows\system32\lsass.exe with GrantedAccess 0x1f3fff. The same 0x1f3fff mask was requested against a long list of unrelated processes (ApplicationFrameHost.exe, browser_broker.exe, conhost.exe, ctfmon.exe, DllHost.exe, dwm.exe, Explorer.EXE, fontdrvhost.exe, LogonUI.exe), and the PS remoting script block recorded at 03:09:28 on nashua is 'Get-Process -IncludeUserName \| Select-Object UserName,SessionId \| ...' - the standard signature of Get-Process -IncludeUserName enumerating process owners, not targeted LSASS reading. No dump write or remote thread into lsass exists for this host (Sysmon EID 8 query for nashua returned nothing).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1RrM7IJ | q-6f00616213 | ok |
| 2 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1RrM7IJ | q-6f00616213 | ok |
| 3 | 2020-05-02 03:09:29.384Z | nashua.dmevals.local | windows.sysmon | win.TargetImage | C:\windows\system32\ApplicationFrameHost.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1RsM6Q6 | q-4917a7f783 | ok |
| 4 | 2020-05-02 03:09:28.000Z | nashua.dmevals.local | windows.powershell | powershell.script_block_text |  Get-Process -IncludeUserName \| Select-Object UserName,SessionId \| Where-Object { $_.UserName -like "*\$env:USERNAME" } \| Sort-Object SessionId -Unique  | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1bsxh3J | q-f9bdbc4c13 | ok |

### F03 · benign / medium · T1003.002 · Only lsass.exe itself wrote to the SAM hive; no SAM dump or hive copy observed

Evidence status: **verified**

Registry-write telemetry matching *SAM* on 2020-05-02 contains only two events, both on scranton.dmevals.local: lsass.exe setting HKLM\SAM\SAM\Domains\Account\F at 03:19:10 (immediately after the 03:18:30 restart initiated by pbeesly) and LogonUI.exe setting the LogonUI\SessionData\2\LoggedOnSAMUser value at 03:20:46 - i.e. legitimate post-logon SAM bookkeeping by the SAM owner process. No hive extraction tooling was observed: Security 4688 has no reg.exe/reg save, esentutl, ntdsutil or vssadmin executions, and no file-create event writes the SAM/SECURITY/SYSTEM hive files. SAM-hash theft is therefore not demonstrated in this window (LSASS itself was attacked instead - see the T1003.001 finding).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:10.368Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1NY3HhA | q-6732500511 | ok |
| 2 | 2020-05-02 03:19:10.368Z | scranton.dmevals.local | windows.sysmon | message | Registry value set:  RuleName: -  EventType: SetValue  UtcTime: 2020-05-02 03:19:10.368  ProcessGuid: {47ab858c-e6ad-5eac-0c00-000000000500}  ProcessId: 748  Im… | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1NY3HhA | q-6732500511 | ok |
| 3 | 2020-05-02 03:18:30.000Z | scranton.dmevals.local | windows.other | message | The process C:\Windows\System32\RuntimeBroker.exe (SCRANTON) has initiated the restart of computer SCRANTON on behalf of user DMEVALS\pbeesly for the following … | .ds-logs-windows.other-default-2026.10.16-000001 / AaFFkdQ25mySA1aOnx2d | q-e6cfba11bd | ok |

### F04 · benign / medium · T1558.003 · Kerberos ticketing is AES256-only service/TGT traffic - no RC4 Kerberoasting pattern

Evidence status: **verified**

In windows.security the 28 Kerberos service-ticket requests (EID 4769) are all TicketEncryptionType 0x12 (AES256) for user pbeesly@DMEVALS.LOCAL against machine accounts (ServiceName NEWYORK$, NASHUA$, krbtgt) with Status 0x0, and the 14 TGT requests (EID 4768) are likewise 0x12 for pbeesly/krbtgt - no RC4 (0x17/0x18) ticket storm and no anomalous service SPNs, so Kerberoasting is not evidenced. In the separate, non-overlapping zeek capture window (2020-04-30) every Kerberos record carries cipher aes256-cts-hmac-sha1-96 and the only failures are AS-REQ exchanges answered with KDC_ERR_PREAUTH_REQUIRED for pbeesly (normal pre-authentication, which also argues against AS-REP roasting of that account).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:04.000Z | newyork.dmevals.local | windows.security | win.TicketEncryptionType | 0x12 | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YhYtYv | q-4d88b6f37f | ok |
| 2 | 2020-05-02 03:04:04.000Z | newyork.dmevals.local | windows.security | win.ServiceName | NEWYORK$ | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YhYtYv | q-4d88b6f37f | ok |
| 3 | 2020-04-30 00:24:19.110Z | simplerockbuild.simplerock.lan | zeek | message | {"@stream":"kerberos","@system":"simplerockbuild.simplerock.lan","@proc":"zeek","ts":1588206259.11049,"uid":"C6f4oNkbm2Uhvs1Q5","id_orig_h":"10.0.1.4","id_orig_… | .ds-logs-zeek-default-2026.10.16-000001 / AaFFktQ25mySA1aO8Idf | q-d16a0b10de | ok |

## Technique conclusions

One line per technique in scope: status from the triage of its family; `not_observed` = checked, nothing found; `not_observable` = no dataset records it.

| Technique | Status | Reason |
|---|---|---|
| T1003.001 OS Credential Dumping: LSASS Memory | not_triaged | 5 checks, 978 hits |
| T1003.002 OS Credential Dumping: Security Account Manag… | not_triaged | 3 checks, 2 hits |
| T1003.003 OS Credential Dumping: NTDS | not_observed | 3 checks, 0 hits |
| T1003.004 OS Credential Dumping: LSA Secrets / Cached D… | not_triaged | 2 checks, 6625 hits |
| T1558.003 Steal or Forge Kerberos Tickets: Kerberoastin… | not_triaged | 3 checks, 70 hits |

## Coverage

Cells: number of hits of the planned checks, `n/a` (reason in report.json), or GAP.

| Technique | windows.other | windows.powershell | windows.security | windows.sysmon | zeek |
|---|---|---|---|---|---|
| T1003.001 OS Credential Dumping: LSASS Memory | — | 0 hits | — | 978 hits | — |
| T1003.002 OS Credential Dumping: Security Account Manag… | — | — | 0 hits | 2 hits | — |
| T1003.003 OS Credential Dumping: NTDS | — | — | 0 hits | 0 hits | — |
| T1003.004 OS Credential Dumping: LSA Secrets / Cached D… | 0 hits | — | — | 6625 hits | — |
| T1558.003 Steal or Forge Kerberos Tickets: Kerberoastin… | — | — | 28 hits | — | 42 hits |

Cells: 10, gaps: 0.

## Queries

Every MCP tool call of this run (88), in order (source: mcp_audit.jsonl written by the MCP server).

| Query | Phase | Tool | Arguments | Hits / rows | Cited by |
|---|---|---|---|---|---|
| q-c1d5f3128e | scope | list_data_sources | {} | None |  |
| q-9032cbb4f4 | scope | get_registry | {} | None |  |
| q-ac94c9ed11 | scope | get_fields | {"dataset": "windows.other", "prefix": ""} | None |  |
| q-22d7b9c81d | scope | get_fields | {"dataset": "windows.powershell", "prefix": ""} | None |  |
| q-6064715925 | scope | get_fields | {"dataset": "windows.security", "prefix": ""} | None |  |
| q-1db807639d | scope | get_fields | {"dataset": "windows.sysmon", "prefix": ""} | None |  |
| q-558f1b7709 | scope | get_fields | {"dataset": "zeek", "prefix": ""} | None |  |
| q-0c41343298 | check C001 (repaired) | aggregate | {"dataset": "windows.sysmon", "field": "win.SourceImage", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 326 |  |
| q-7c6a6e8483 | check C002 (repaired) | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 326 |  |
| q-27c2eea47e | check C003 | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == \"10\" AND TO_LOWER(win.TargetImage) LIKE \"*lsass*\" \| KEEP @timestamp, host.name, win.SourceImage, win.TargetImage, win.GrantedAccess, win.CallTrace, _id, _index"} | ERROR |  |
| q-c55d9268d6 | check C003 (repaired) | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND TO_LOWER(win.TargetImage) LIKE \"*lsass*\" \| KEEP @timestamp, host.name, win.SourceImage, win.TargetImage, win.GrantedAccess, win.CallTrace, _id, _index"} | 326 |  |
| q-781f2b0f8c | check C004 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*comsvcs* OR process.command_line:*MiniDump* OR process.command_line:*procdump* OR process.command_line:*mimikatz* OR process.command_line:*sekurlsa*)", "time_from": null, "time_to"… | 0 |  |
| q-5a94cc01ae | check C005 | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(powershell.script_block_text) LIKE \"*mimikatz*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*sekurlsa*\" OR TO_LOWER(powershell.script_block_text) LIKE… | ERROR |  |
| q-0d9c585271 | check C005 (repaired) | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(powershell.script_block_text) LIKE \"*mimikatz*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*sekurlsa*\" OR TO_LOWER(powershell.script_blo… | 0 |  |
| q-6732500511 | check C006 | search | {"dataset": "windows.sysmon", "query": "event.code:13 AND win.TargetObject:*SAM*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_lin… | 2 | F03 |
| q-d6416ffeb8 | check C007 | search | {"dataset": "windows.security", "query": "event.code:4663 AND win.ObjectName:*SAM*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_l… | 0 |  |
| q-78c35491a2 | check C008 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*reg save* OR process.command_line:*esentutl* OR process.command_line:*\\\\SAM\\\\* OR process.command_line:*SYSTEM*)", "time_from": null, "time_to": null, "fields": ["@timestamp", … | 0 |  |
| q-ae9a5f06b4 | check C009 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (win.TargetFilename:*ntds.dit* OR file.path:*ntds.dit*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.… | 0 |  |
| q-00ebd8ebb4 | check C010 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*ntdsutil* OR process.command_line:*\"ac i ntds\"* OR process.command_line:*vssadmin*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "… | 0 |  |
| q-5a8d82fcfc | check C011 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*ntdsutil* OR process.command_line:*esentutl*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user… | 0 |  |
| q-350bf7377b | check C012 (repaired) | aggregate | {"dataset": "windows.security", "field": "event.code", "query": "event.code:4769", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 28 |  |
| q-a10ad7719d | check C013 (repaired) | aggregate | {"dataset": "zeek", "field": "zeek.cipher", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 35 |  |
| q-d16a0b10de | check C014 | search | {"dataset": "zeek", "query": "event.action:kerberos AND (zeek.error_msg:* OR zeek.success:false)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "pro… | 7 | F04 |
| q-d944586364 | check C015 | search | {"dataset": "windows.sysmon", "query": "event.code:13 AND (win.TargetObject:*SECURITY\\\\Policy\\\\Secrets* OR win.TargetObject:*LSA* OR win.TargetObject:*Cache*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "eve… | 6625 |  |
| q-119d32bea5 | check C016 | search | {"dataset": "windows.other", "query": "event.code:1 AND (process.command_line:*lsass* OR process.command_line:*dump* OR process.command_line:*credentials*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.data… | 0 |  |
| q-8d60eda11f | investigate step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND (win.GrantedAccess:0x1f3fff OR win.GrantedAccess:0x1fffff OR win.GrantedAccess:0x101001 OR win.GrantedAccess:0x1000000 OR win.GrantedAccess:0x3000)", "time_from": null, "time… | 9 | F01 |
| q-788df0a48b | investigate step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*lsass* OR process.command_line:*procdump* OR process.command_line:*mimikatz* OR process.command_line:*sekurlsa*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "hos… | 1 |  |
| q-4d88b6f37f | investigate step 1 | search | {"dataset": "windows.security", "query": "event.code:4769", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "win.TargetUserName", "win.ServiceName", "win.IpAddress", "win.TicketEncryptionType", "win.TicketOptions", "win.Status", "win.… | 28 | F04 |
| q-be60fd7c72 | investigate step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE TO_LOWER(process.executable) LIKE \"%wsmprovhost%\" \| KEEP @timestamp, host.name, event.code, process.executable, process.command_line, process.parent.executable, user.name, _id, _index… | 0 |  |
| q-fef861f62f | investigate step 2 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:(*lsass* OR *Mimikatz* OR *sekurlsa* OR *DumpCreds* OR *Credential* OR *Dump* OR *password*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "pow… | 3 |  |
| q-f367f18257 | investigate step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND host.name:scranton.dmevals.local AND (process.executable:*PowerShell* OR process.executable:*powershell*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "process.executable",… | 11 |  |
| q-266a7a4654 | investigate step 2 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*lsass* OR process.command_line:*Invoke-Mimikatz* OR process.command_line:*DumpCreds* OR process.command_line:*sekurlsa* OR process.command_line:*procdump*)", "time_from": null… | 0 |  |
| q-fc0ab32eab | investigate step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND TO_LOWER(win.TargetImage) LIKE \"*lsass*\" AND TO_LOWER(win.SourceImage) LIKE \"%powershell%\" \| KEEP @timestamp, host.name, win.SourceImage, win.GrantedAccess,… | 0 |  |
| q-943ad46667 | investigate step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND host.name == \"scranton.dmevals.local\" \| KEEP @timestamp, host.name, user.name, powershell.script_block_text, win.ScriptBlockId, _id, _index"} | 146 |  |
| q-6549397b97 | investigate step 3 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:(*Mini* OR *Katz* OR *nanodump* OR *SafetyKatz* OR *lsass* OR *SAM* OR *dump*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "powershell.script… | 6 |  |
| q-790cb17ee9 | investigate step 4 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1bzydoz"} | None |  |
| q-b2c1ad2d88 | investigate step 4 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1bzyNfQ"} | None | F01 |
| q-6f00616213 | investigate step 4 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrM7IJ"} | None | F02 |
| q-4e7173051d | investigate step 4 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*reg\\ save* OR process.command_line:*ntds* OR process.command_line:*vssadmin* OR process.command_line:*esentutl* OR process.command_line:*comsvcs* OR process.command_line:*SAM… | 0 |  |
| q-5a8e35cccb | investigate step 5 | search | {"dataset": "windows.sysmon", "query": "event.code:13 AND win.TargetObject:*Policy\\\\Secrets*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "process.executable", "win.TargetObject", "win.Details", "message"], "size": 20, "sort": … | 0 |  |
| q-450d96ca89 | investigate step 5 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (win.TargetFilename:*.dmp OR win.TargetFilename:*lsass* OR win.TargetFilename:*SAM* OR win.TargetFilename:*.kirbi OR win.TargetFilename:*.zip OR win.TargetFilename:*.7z)", "time_from": null, "time_to": … | 8 |  |
| q-bc2b5e3ddd | investigate step 5 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688", "time_from": null, "time_to": null, "size": 40, "sub_field": null} | 460 |  |
| q-61fa0be03b | investigate step 5 | search | {"dataset": "windows.sysmon", "query": "event.code:8", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "win.SourceImage", "win.TargetImage", "win.StartAddress", "win.StartModule", "process.executable"], "size": 25, "sort": "asc"} | 95 |  |
| q-5667fee559 | investigate step 6 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND host.name:scranton.dmevals.local", "time_from": "2020-05-02T02:57:00.000Z", "time_to": "2020-05-02T03:07:00.000Z", "fields": ["@timestamp", "host.name", "user.name", "powershell.script_block_text"… | 80 |  |
| q-ec6d66c30d | investigate step 6 | aggregate | {"dataset": "zeek", "field": "zeek.operation", "query": "event.action:dce_rpc", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 123 |  |
| q-0d2a479edc | investigate step 6 | search | {"dataset": "zeek", "query": "zeek.operation:(*DRS* OR *drsuapi* OR *Drsuapi*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "observer.name", "source.ip", "destination.ip", "zeek.operation", "zeek.endpoint", "zeek.named_pipe", "message"], "siz… | 9 |  |
| q-56cf64769d | investigate step 6 | search | {"dataset": "windows.other", "query": "event.code:(7045 OR 7040 OR 5857 OR 5858 OR 2004 OR 2006)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "win.ServiceName", "win.ImagePath", "win.ServiceType", "win.param1", "win… | 102 |  |
| q-8957457cdc | investigate step 7 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND host.name:scranton.dmevals.local AND process.pid:2976", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "process.executable", "process.command_line", "process.parent.executable"… | 1 | F01 |
| q-9689874317 | investigate step 7 | count | {"dataset": "windows.security", "query": "event.code:4662 OR event.code:4768 OR event.code:4648", "time_from": null, "time_to": null} | 36 |  |
| q-b70b9ec093 | investigate step 7 | search | {"dataset": "windows.sysmon", "query": "event.code:13 AND (win.TargetObject:*SECURITY\\\\Cache* OR win.TargetObject:*SECURITY\\\\Policy* OR win.TargetObject:*SECURITY\\\\Secrets*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "pro… | 5 |  |
| q-3c765ade11 | investigate step 7 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (win.TargetFilename:*ntds.dit* OR win.TargetFilename:*config\\\\SAM* OR win.TargetFilename:*config\\\\SECURITY* OR win.TargetFilename:*config\\\\SYSTEM* OR win.TargetFilename:*\\\\Temp\\\\*.tmp)", "time… | 18 | F01 |
| q-e6cfba11bd | investigate step 8 | search | {"dataset": "windows.other", "query": "event.code:(7045 OR 1074 OR 6005 OR 6006 OR 6008 OR 7031 OR 7034)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "win.ServiceName", "win.ImagePath", "win.ServiceType", "user.name… | 8 | F03 |
| q-0b80dc8674 | investigate step 8 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND host.name:nashua.dmevals.local AND (process.executable:*python* OR process.executable:*wsmprovhost* OR process.executable:*psexesvc* OR process.executable:*rar* OR process.executable:*sdelete*)", "time_f… | 9 |  |
| q-325ff08291 | investigate step 8 | search | {"dataset": "windows.security", "query": "event.code:4661", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "win.ObjectType", "win.ObjectName", "win.ProcessName", "win.SubjectUserName", "win.AccessMask", "win.PrivilegeList"], "size": … | 37 |  |
| q-5aaadae8fc | investigate step 8 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND host.name:scranton.dmevals.local", "time_from": "2020-05-02T03:04:00.000Z", "time_to": "2020-05-02T03:07:00.000Z", "fields": ["@timestamp", "process.executable", "process.command_line", "process.parent.e… | 19 |  |
| q-f4c29ad6db | investigate step 9 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k13z"} | None | F01 |
| q-cc10f528bf | investigate step 9 | search | {"dataset": "windows.sysmon", "query": "event.code:8 AND host.name:nashua.dmevals.local", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "win.SourceImage", "win.TargetImage", "win.StartAddress", "win.StartModule", "win.SourceProcessI… | 0 |  |
| q-f9bdbc4c13 | investigate step 9 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND host.name:nashua.dmevals.local", "time_from": "2020-05-02T03:05:00.000Z", "time_to": "2020-05-02T03:18:00.000Z", "fields": ["@timestamp", "host.name", "user.name", "powershell.script_block_text"],… | 11 | F02 |
| q-e5b4473e8e | investigate step 9 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND win.GrantedAccess:0x1400", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "win.SourceImage", "win.GrantedAccess", "win.SourceProcessId"], "size": 2… | 24 |  |
| q-3db073d6da | investigate step 10 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(COALESCE(powershell.script_block_text, \"\")) LIKE \"*mimikatz*\" OR TO_LOWER(COALESCE(powershell.script_block_text, \"\")) LIKE \"*minidump*\" OR TO_LOWER(COALESCE(powershe… | 0 |  |
| q-d9407c1441 | investigate step 10 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND host.name:scranton.dmevals.local", "time_from": "2020-05-02T03:04:30.000Z", "time_to": "2020-05-02T03:06:30.000Z", "fields": ["@timestamp", "process.executable", "win.TargetFilename", "user.name"], "siz… | 47 |  |
| q-4917a7f783 | investigate step 10 | search | {"dataset": "windows.sysmon", "query": "event.code:(10 OR 8) AND win.SourceImage:*wsmprovhost*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "win.SourceImage", "win.TargetImage", "win.GrantedAccess", "win.StartModule", "win.StartA… | 120 | F02 |
| q-aa37985c0c | investigate step 11 | search | {"dataset": "windows.security", "query": "event.code:(4656 OR 4663) AND win.ObjectType:Process AND win.ObjectName:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "win.ProcessName", "win.SubjectUserName", "win.ObjectName", "w… | 19 | F01 |
| q-1783e27ee1 | investigate step 11 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4656 AND win.ObjectType:Process", "time_from": null, "time_to": null, "size": 15, "sub_field": null} | 13 |  |
| q-3ad7d08e52 | investigate step 12 | aggregate | {"dataset": "windows.security", "field": "event.code", "query": "event.code:4662 OR event.code:4768 OR event.code:4648", "time_from": null, "time_to": null, "size": 10, "sub_field": null} | 36 |  |
| q-61e91202bd | investigate step 12 | search | {"dataset": "windows.security", "query": "event.code:(4662 OR 4768 OR 4648)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "win.TargetUserName", "win.ServiceName", "win.SubjectUserName", "win.Properties", "win.IpAddre… | 36 |  |
| q-8a15998c3f | investigate step 13 | search | {"dataset": "windows.sysmon", "query": "win.TargetFilename:(*passw* OR *credential* OR *secrets*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "process.executable", "win.TargetFilename", "user.name"], "size": 30, "s… | 5 |  |
| q-0a17ecdf5e | investigate step 13 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND host.name:scranton.dmevals.local AND process.executable:(*accesschk* OR *procdump* OR *SharpHound* OR *csc.exe*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "process.executable", "proc… | 2 |  |
| q-60f545b93d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k13z"} | None |  |
| q-9318c391b3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k13z"} | None |  |
| q-c104dfc412 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k13z"} | None |  |
| q-a2d4b7f6db | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k13y"} | None |  |
| q-b8edcc868d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-e2c8f655b9 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YldM_p"} | None |  |
| q-a20fd81606 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YldM_i"} | None |  |
| q-d15882b7ec | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1WdFNhN"} | None |  |
| q-5522c6c90e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1WdEtgZ"} | None |  |
| q-ffdbc1831e | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1bzyNfQ"} | None |  |
| q-7b37a226e4 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrM7IJ"} | None |  |
| q-f90d693aaa | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrM7IJ"} | None |  |
| q-d0265082ff | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RsM6Q6"} | None |  |
| q-ae683dad73 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1bsxh3J"} | None |  |
| q-67e3bc1e1a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NY3HhA"} | None |  |
| q-42aa5dbe02 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NY3HhA"} | None |  |
| q-f08ca7aec4 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx2d"} | None |  |
| q-215a667dc6 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YhYtYv"} | None |  |
| q-80c27abc6e | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YhYtYv"} | None |  |
| q-1e2b8c4463 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8Idf"} | None |  |

## Verification

Evidence items cited: 20; confirmed against the stored events: 20; rejected: 0. Each item was re-fetched with get_event; it is confirmed only if the event exists, the cited field holds the cited value, and the cited query_id is a query of this run that returned that event.
Evidence sent back to the agents for correction during the run: 0 item(s) in 0 submission(s) (one correction round each; what still failed was rejected).

## Limitations

- Findings describe what the stored logs show; activity these sources did not log cannot be seen.
- Datasets with non-overlapping time windows (see Data examined) were analysed separately.
- Long field values are shortened in this report; full events are retrievable by _index/_id.
