# Threat hunt report — 20261017-010835-baseline-exp-A1

**Hypothesis:** An adversary who compromised Windows hosts in this network stole credentials from them (MITRE ATT&CK tactic: Credential Access).

**Verdict: Confirmed** — The hunt hypothesis is confirmed by multiple verified, high-confidence Credential Access findings on compromised Windows hosts. F01 shows non-system PowerShell and WinRM host processes opening lsass.exe with full/VM-read access on scranton and nashua, consistent with credential dumping via LSASS memory access. F02 shows attacker PowerShell exporting LocalMachine certificate private keys to .pfx files, archiving them, exfiltrating the archive to a WebDAV share, and deleting artifacts. F03 shows Get-Keystrokes/Keystroke-Check keylogger execution in the same pbeesly session, with a minor verification discrepancy due to truncation in the claimed script block but the stored value supports the activity. F04 shows clipboard harvesting in the same compromised session. F05 shows cleartext domain credentials passed on PsExec command lines and reused for lateral movement to nashua. Together these corroborate an adversary stealing credentials from Windows hosts, so the verdict is Confirmed.

Verdict method: LLM judgement

| Run | Value |
|---|---|
| Profile | baseline (thinking=True, temperature=n/a (ignored in thinking mode)) |
| Model | deepseek-flash |
| Started / finished (UTC) | 2026-10-16T17:08:35+00:00 / 2026-10-16T17:10:43+00:00 (127.8 s) |
| LLM calls / tokens | 17 / {'prompt': 496331, 'completion': 23147} |
| MCP tool calls | 55 (server tools: list_data_sources, get_fields, search, count, aggregate, timeline, esql, get_event, get_registry) |
| ATT&CK tactics | credential-access — An adversary who has compromised Windows hosts on this network stole credentials from those hosts. |

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

### F01 · malicious / high · T1003.001 · Non-system PowerShell and WinRM host processes opened lsass.exe with full/VM-read access on scranton and nashua

Evidence status: **verified**

On SCRANTON.dmevals.local the hidden loader PowerShell.exe (PID 2976, user pbeesly) opened C:\windows\system32\lsass.exe with GrantedAccess 0x1f3fff and 0x1fffff at 2020-05-02T03:05:16Z (Sysmon EID 10; Security 4656 AccessMask 0x1fffff/0x1f3fff; 4663 AccessMask 0x10 = PROCESS_VM_READ). The same pattern repeats on NASHUA.dmevals.local at 2020-05-02T03:09:29Z from wsmprovhost.exe (WinRM remote PowerShell shell) as user pbeesly with AccessMask 0x1f3fff. Elsewhere in the same window lsass handles are only held by system/AV processes (wininit.exe, csrss.exe, svchost.exe 0x1000/0x101001, MsMpEng.exe, CollectGuestLogs.exe), so these two pbeesly handles stand out as lsass memory access used to read credential material.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R-k131 | q-1f868534ff | ok |
| 2 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R-k13y | q-1f868534ff | ok |
| 3 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.TargetImage | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R-k131 | q-1f868534ff | ok |
| 4 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | win.AccessMask | 0x1f3fff | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YldM_i | q-d5f9c80dba | ok |
| 5 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | win.AccessMask | 0x1fffff | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YldM_p | q-d5f9c80dba | ok |
| 6 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | win.ProcessName | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YldM_i | q-d5f9c80dba | ok |
| 7 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | win.AccessMask | 0x10 | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YldM_j | q-d5f9c80dba | ok |
| 8 | 2020-05-02 03:09:29.000Z | nashua.dmevals.local | windows.security | win.ProcessName | C:\Windows\System32\wsmprovhost.exe | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YjaXaO | q-d5f9c80dba | ok |
| 9 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1RrM7IJ | q-1f868534ff | ok |
| 10 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1RrM7IJ | q-1f868534ff | ok |

### F03 · malicious / high · T1056.001 · Get-Keystrokes keylogger executed in the pbeesly PowerShell session on scranton

Evidence status: **NOT verified (1/2 evidence items)**

At 2020-05-02T03:06:59Z on SCRANTON.dmevals.local PowerShell PID 3852 (user pbeesly) executed Get-Keystrokes followed by View-Job -JobName "Keystrokes", and at 03:06:47Z the same session ran Keystroke-Check, which enumerates running AV/security products (avp, acs, AvastSvc, nod32krn, ekern ...) before capturing input. The captured keystrokes are a credential-capture primitive used alongside the lsass access in the same session.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:06:59.000Z | scranton.dmevals.local | windows.powershell | powershell.script_block_text | Get-Keystrokes;Start-Sleep -Seconds 15;View-Job -JobName "Keystrokes" | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b21_Tx | q-0bbd4b0940 | ok |
| 2 | 2020-05-02 03:06:47.000Z | scranton.dmevals.local | windows.powershell | powershell.script_block_text | function Keystroke-Check {     Get-Process \| Where-Object { $_.ProcessName -Eq "avp" -or $_.ProcessName -Eq "acs" -or $_.ProcessName -Eq "outpost" -or $_.Proce… | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b21_R0 | q-e158663471 | FAILED: claimed value differs from the stored value |

### F04 · malicious / medium · T1115 · Clipboard harvested in the same compromised PowerShell session

Evidence status: **verified**

At 2020-05-02T03:06:42Z on SCRANTON.dmevals.local PowerShell PID 3852 (user pbeesly) ran Get-Clipboard, collecting clipboard contents (frequently passwords) as part of the same credential-collection script set that performed the lsass access and private-key export.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:06:42.000Z | scranton.dmevals.local | windows.powershell | powershell.script_block_text | Get-Clipboard | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b21_Qp | q-0bbd4b0940 | ok |

### F02 · malicious / high · T1552.004 · Attacker script exported LocalMachine certificate private keys to .pfx files, then archived and exfiltrated the collection

Evidence status: **verified**

On SCRANTON.dmevals.local user pbeesly loaded C:\Program Files\SysinternalsSuite\readme.ps1 which defines Get-PrivateKeys: it enumerates cert:\LocalMachine, exports every certificate with a thumbprint to $env:USERPROFILE\Downloads\<random>.pfx protected with the hardcoded password "saribas", and writes the keys to disk (Sysmon EID 11 created C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx at 03:04:57Z). The staged private keys were then compressed by psversion.ps1's Invoke-Exfil (Compress-7Zip of the whole Downloads dir into %APPDATA%\OfficeSupplies.7z, created 03:08:35Z) and the archive copied to \\192.168.0.4\webdav before Invoke-BeachCleanup deleted the .pfx/.bmp/.png/.7z artifacts.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | powershell.script_block_text | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b21vS3 | q-cd3922bb49 | ok |
| 2 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\readme.ps1 | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b21vS3 | q-cd3922bb49 | ok |
| 3 | 2020-05-02 03:04:57.460Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R_lUAH | q-96e515cb9f | ok |
| 4 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | powershell.script_block_text | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b10BXt | q-e60b3e4b69 | ok |
| 5 | 2020-05-02 03:08:35.270Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Users\pbeesly\AppData\Roaming\OfficeSupplies.7z | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1RtN3py | q-96e515cb9f | ok |
| 6 | 2020-05-02 03:08:51.000Z | scranton.dmevals.local | windows.powershell | powershell.script_block_text | function Invoke-BeachCleanup {     Write-Host "[*] Cleaning up"     Remove-Item -Path "$env:USERPROFILE\Downloads\*.pfx" -Force     Remove-Item -Path "$env:USER… | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1bsxh3C | q-e158663471 | ok |

### F05 · suspicious / high · T1552.001 · Cleartext domain credentials for dmevals\pbeesly passed on a command line to PsExec for lateral movement

Evidence status: **verified**

On SCRANTON.dmevals.local, from the cwd C:\Program Files\SysinternalsSuite, the pbeesly PowerShell session repeatedly ran PsExec64.exe against \\NASHUA with the cleartext password for dmevals\pbeesly on the command line ("-u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe"), first at 03:11:18Z and again at 03:12:25Z, 03:13:28Z and 03:14:42Z. The credential material is exposed in process command lines/logs and was reused to run the dropped implant C:\Windows\Temp\python.exe on nashua under PSEXESVC.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:18.784Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\PsExec64.exe" -accepteula \\NASHUA -u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1RqK7jn | q-923d74900e | ok |
| 2 | 2020-05-02 03:11:40.213Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1RpKsKx | q-923d74900e | ok |
| 3 | 2020-05-02 03:11:40.213Z | nashua.dmevals.local | windows.sysmon | process.parent.executable | C:\Windows\PSEXESVC.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1RpKsKx | q-923d74900e | ok |

## Technique conclusions

One line per technique in scope: status from the triage of its family; `not_observed` = checked, nothing found; `not_observable` = no dataset records it.

| Technique | Status | Reason |
|---|---|---|

## Coverage

Cells: number of hits of the planned checks, `n/a` (reason in report.json), or GAP.

| Technique | windows.other | windows.powershell | windows.security | windows.sysmon | zeek |
|---|---|---|---|---|---|

Cells: 0, gaps: 0.

## Queries

Every MCP tool call of this run (55), in order (source: mcp_audit.jsonl written by the MCP server).

| Query | Phase | Tool | Arguments | Hits / rows | Cited by |
|---|---|---|---|---|---|
| q-0fc5c3b3c4 | scope | list_data_sources | {} | None |  |
| q-3d5e1d9e0b | scope | get_registry | {} | None |  |
| q-4073944a83 | scope | get_fields | {"dataset": "windows.other", "prefix": ""} | None |  |
| q-38952ea967 | scope | get_fields | {"dataset": "windows.powershell", "prefix": ""} | None |  |
| q-cbc8b03bae | scope | get_fields | {"dataset": "windows.security", "prefix": ""} | None |  |
| q-90ca6cbc0b | scope | get_fields | {"dataset": "windows.sysmon", "prefix": ""} | None |  |
| q-7891b781d0 | scope | get_fields | {"dataset": "zeek", "prefix": ""} | None |  |
| q-79f43352da | investigate step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "win.SourceImage", "win.TargetImage", "win.GrantedAccess", "process.pid", "user.name"], "size": 50, "s… | 326 |  |
| q-c432c52b37 | investigate step 1 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 40, "sub_field": "win.SourceImage"} | 326 |  |
| q-1f868534ff | investigate step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND NOT win.GrantedAccess:(0x1000 OR 0x1400)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "win.SourceImage", "win.TargetImage", "win.GrantedAccess"… | 9 | F01 |
| q-8e84603217 | investigate step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*lsass* OR process.command_line:*dump* OR process.command_line:*mimikatz* OR process.command_line:*comsvcs* OR process.command_line:*MiniDump* OR process.command_line:*procdump*)", … | 1 |  |
| q-dab2a39677 | investigate step 3 | search | {"dataset": "windows.other", "query": "event.code:(7045 OR 7036 OR 7040 OR 1074 OR 6005 OR 6006 OR 16)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "message", "win.ServiceName", "win.ImagePath", "win.param1", "win.p… | 25 |  |
| q-8af021dbd0 | investigate step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(powershell.script_block_text) LIKE \"*lsass*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*minidump*\" OR TO_LOWER(powershell.script_block_… | 5 |  |
| q-cda6b59b2f | investigate step 4 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "from-previous"} | ERROR |  |
| q-92bbfe33b2 | investigate step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (user.name == \"pbeesly\" OR TO_LOWER(powershell.script_block_text) LIKE \"*invoke-exfil*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*invoke-mimika… | 30 |  |
| q-1ff162e85a | investigate step 5 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND process.executable:*powershell.exe AND host.name:scranton.dmevals.local", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "process.pid", "process.command_line", "process.parent.… | 11 |  |
| q-79a2337271 | investigate step 5 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND host.name == \"scranton.dmevals.local\" AND @timestamp >= \"2020-05-02T03:02:00.000Z\" AND @timestamp <= \"2020-05-02T03:07:00.000Z\" \| KEEP @timestamp, h… | 40 |  |
| q-96e515cb9f | investigate step 6 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*.dmp OR file.path:*lsass* OR file.path:*.png OR file.path:*.pfx OR file.path:*.zip OR file.path:*.7z OR file.path:*.rar OR file.path:*.bmp)", "time_from": null, "time_to": null, "fields": ["… | 13 | F02 |
| q-d5f9c80dba | investigate step 6 | search | {"dataset": "windows.security", "query": "win.ObjectName:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "win.ObjectName", "win.ObjectType", "win.AccessMask", "win.AccessList", "win.ProcessName", "win.SubjectUs… | 19 | F01 |
| q-0bbd4b0940 | investigate step 7 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (powershell.script_block_text LIKE \"*Get-PrivateKeys*\" OR powershell.script_block_text LIKE \"*Get-Keystrokes*\" OR powershell.script_block_text LIKE \"*… | 6 | F03, F04 |
| q-5183c7f8dc | investigate step 7 | search | {"dataset": "windows.security", "query": "event.code:4673 AND win.PrivilegeList:*SeDebugPrivilege*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "win.ProcessName", "win.SubjectUserName", "win.PrivilegeList", "win.Obj… | 0 |  |
| q-64a132804e | investigate step 8 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE powershell.script_block_text LIKE \"*MiniDumpWriteDump*\" OR powershell.script_block_text LIKE \"*lsass*\" OR powershell.script_block_text LIKE \"*sekurlsa*\" OR powershell.script_bl… | 0 |  |
| q-e4a91c7e28 | investigate step 8 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE host.name == \"nashua.dmevals.local\" AND @timestamp >= \"2020-05-02T03:08:00.000Z\" AND @timestamp <= \"2020-05-02T03:20:00.000Z\" AND event.code IN (\"4104\",\"4103\") \| KEEP _id,… | 40 |  |
| q-923d74900e | investigate step 9 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.executable:*python* OR process.executable:*\\\\Windows\\\\Temp\\\\* OR process.command_line:*python*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "process.executa… | 13 | F05 |
| q-0897480f5f | investigate step 9 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:11 AND host.name:nashua.dmevals.local", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 249 |  |
| q-c823febfea | investigate step 10 | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11 AND process.executable:*python.exe", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 19 |  |
| q-726be182f2 | investigate step 10 | search | {"dataset": "windows.sysmon", "query": "win.SourceImage:*python*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "win.SourceImage", "win.TargetImage", "win.GrantedAccess", "process.pid", "user.name", "win.CallTrace"], "size": 30, "s… | 3 |  |
| q-799ca29f67 | investigate step 11 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*reg save* OR process.command_line:*ntdsutil* OR process.command_line:*vssadmin* OR process.command_line:*esentutl* OR process.command_line:*SAM* OR process.command_line:*hive*)", "… | 0 |  |
| q-b652ba0111 | investigate step 11 | search | {"dataset": "windows.security", "query": "win.ObjectName:(*SAM* OR *SECURITY* OR *SYSTEM.hive* OR *vault* OR *Credentials*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "win.ObjectName", "win.ObjectType", "win.Proce… | 10 |  |
| q-cd3922bb49 | investigate step 12 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None | F02 |
| q-e60b3e4b69 | investigate step 12 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None | F02 |
| q-e158663471 | investigate step 13 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE powershell.script_block_text LIKE \"*Invoke-BeachCleanup*\" OR powershell.script_block_text LIKE \"*Show-TargetScreen*\" OR powershell.script_block_text LIKE \"*Keystroke-Check*\" OR… | 4 | F02, F03 |
| q-72c45b8210 | investigate step 13 | aggregate | {"dataset": "windows.other", "field": "message", "query": "event.code:(5857 OR 5858)", "time_from": null, "time_to": null, "size": 15, "sub_field": null} | ERROR |  |
| q-b07eebb4d2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-99cbf23537 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k13y"} | None |  |
| q-20bf3fe234 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-e20f40a18e | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YldM_i"} | None |  |
| q-b837a4bebe | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YldM_p"} | None |  |
| q-722e8bb186 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YldM_i"} | None |  |
| q-26d02af2c4 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YldM_j"} | None |  |
| q-d44ded3a84 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YjaXaO"} | None |  |
| q-f5478acd42 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrM7IJ"} | None |  |
| q-d97d4ace4f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrM7IJ"} | None |  |
| q-3b2b76ca42 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None |  |
| q-21f9ddd031 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None |  |
| q-08aceb3333 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R_lUAH"} | None |  |
| q-2c663b5116 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-8b3caf0f84 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RtN3py"} | None |  |
| q-161869b0a5 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1bsxh3C"} | None |  |
| q-cf9028550c | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21_Tx"} | None |  |
| q-a05e9eb859 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21_R0"} | None |  |
| q-fa9be8605f | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21_Qp"} | None |  |
| q-fcc8a31036 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RqK7jn"} | None |  |
| q-951c237cb6 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RpKsKx"} | None |  |
| q-de3d2b3ccb | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RpKsKx"} | None |  |

## Verification

Evidence items cited: 22; confirmed against the stored events: 21; rejected: 1. Each item was re-fetched with get_event; it is confirmed only if the event exists, the cited field holds the cited value, and the cited query_id is a query of this run that returned that event.
Evidence sent back to the agents for correction during the run: 0 item(s) in 0 submission(s) (one correction round each; what still failed was rejected).

## Limitations

- Findings describe what the stored logs show; activity these sources did not log cannot be seen.
- Datasets with non-overlapping time windows (see Data examined) were analysed separately.
- Long field values are shortened in this report; full events are retrievable by _index/_id.
