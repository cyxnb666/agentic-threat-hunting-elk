# Threat hunt report — 20261017-075714-converged-exp-B3-playbook

**Hypothesis:** An adversary who compromised Windows hosts in this network stole credentials from them (MITRE ATT&CK tactic: Credential Access).

**Verdict: Confirmed** — 7 in-scope incident(s) of verified malicious findings (confidence >= medium): I01 T1003.001 (F01, F10, F22, F25, F35, F37, F39, F45), I02 T1003.001 (F57), I03 T1003.002 (F31, F56), I04 T1187 (F23), I06 T1552.001 (F58), I07 T1555.003 (F59), I09 T1649 (F54)

Verdict method: rules over verified evidence (Confirmed if >=1 in-scope incident of verified malicious findings (confidence >= medium); Inconclusive if only suspicious incidents or coverage gaps; Refuted if full coverage and no malicious/suspicious finding)

| Run | Value |
|---|---|
| Profile | converged (thinking=False, temperature=0.0) |
| Model | deepseek-flash |
| Started / finished (UTC) | 2026-10-16T23:57:14+00:00 / 2026-10-17T00:04:14+00:00 (419.5 s) |
| LLM calls / tokens | 119 / {'prompt': 3535001, 'completion': 81686} |
| MCP tool calls | 1126 (server tools: list_data_sources, get_fields, search, count, aggregate, timeline, esql, get_event, get_registry) |
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
| I01 | T1003.001 | yes | malicious/high | F01, F10, F22, F25, F35, F37, F39, F45 | LSASS memory access with full-access masks by PowerShell on scranton and wsmprovhost on nashua |
| I02 | T1003.001 | yes | malicious/medium | F57 | lsass.exe writes C:\Windows\debug\PASSWD.LOG on scranton |
| I03 | T1003.002 | yes | malicious/high | F31, F56 | Sysinternals pspasswd/accesschk credential collection creating 'passwordsDB' on scranton |
| I04 | T1187 | yes | malicious/high | F23 | Forced authentication via SMB/WebDAV coercion from scranton to attacker-controlled 192.168.0.4 |
| I05 | T1552.001 | yes | suspicious/medium | F32 | Explicit-credential logons (4648) using pbeesly credentials via PsExec |
| I06 | T1552.001 | yes | malicious/high | F58 | Hardcoded credentials in Invoke-Exfil used to mount attacker WebDAV share |
| I07 | T1555.003 | yes | malicious/medium | F59 | Rar.exe password-protected archive of credential-bearing loot on nashua |
| I08 | T1558.001 | yes | suspicious/medium | F46 | Anomalous krbtgt service-ticket requests from SCRANTON$ on newyork |
| I09 | T1649 | yes | malicious/high | F54 | PowerShell Get-PrivateKeys exports LocalMachine certificates to .pfx files on scranton |
| I10 | out-of-scope:T1021.002 | no | suspicious/high | F09 | Related malicious activity in window is not network sniffing (PsExec lateral movement, python C2, screen capture) |
| I11 | out-of-scope:T1204 | no | malicious/high | F11 | Intrusion chain on scranton: malicious .scr, hidden PowerShell, Invoke-Exfil, sdelete cleanup |

## Findings

### F01 · malicious / high · T1003.001 · LSASS memory accessed with full-access mask (0x1F3FFF) by attacker PowerShell on scranton and via WinRM on nashua

Evidence status: **verified**

On scranton.dmevals.local, PowerShell.exe (PID 2976, user pbeesly) opened lsass.exe (PID 736) with GrantedAccess 0x1F3FFF at 2020-05-02T03:05:16.623Z, and again with 0x1FFFFF at 03:05:16.654Z. The matching Security 4656 event (record 73759) shows the same process requesting AccessMask 0x1F3FFF on \Device\HarddiskVolume2\Windows\System32\lsass.exe, explicitly including 'Read from process memory' and 'Write to process memory' — the access pattern of an LSASS memory dump. This occurred inside a pbeesly PowerShell session that also ran attacker tooling (Invoke-Discovery, Invoke-Persistence, Get-PrivateKeys, Invoke-ScreenCapture, accesschk.exe). On nashua.dmevals.local, wsmprovhost.exe (PID 7720, WinRM remote PowerShell, user pbeesly) opened lsass.exe (PID 728) with GrantedAccess 0x1F3FFF at 03:09:29.430Z, the same full-access LSASS read via remote PowerShell. The remaining LSASS opens (svchost.exe 0x1000, WindowsAzureTelemetryService.exe 0x1400, wininit/csrss at process start) are normal system behaviour.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R-k13y | q-1877b3010f | ok |
| 2 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R-k13y | q-1877b3010f | ok |
| 3 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R-k131 | q-af118f9f16 | ok |
| 4 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | win.AccessMask | 0x1f3fff | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YldM_i | q-2f4d43ee35 | ok |
| 5 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | win.ObjectName | \Device\HarddiskVolume2\Windows\System32\lsass.exe | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YldM_i | q-2f4d43ee35 | ok |
| 6 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1RrM7IJ | q-d88846d392 | ok |
| 7 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1RrM7IJ | q-d88846d392 | ok |
| 8 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | powershell.script_block_text | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b21vS3 | q-b7c50359ed | ok |

### F57 · malicious / medium · T1003.001 · lsass.exe wrote C:\Windows\debug\PASSWD.LOG on scranton

Evidence status: **verified**

On scranton.dmevals.local at 03:19:09, lsass.exe (pid 748, SYSTEM) created C:\Windows\debug\PASSWD.LOG. A password log written by lsass in the debug directory is consistent with credential material being written out during the intrusion window, distinct from the previously anchored LSASS handle-access findings.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:09.994Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Windows\debug\PASSWD.LOG | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1NY3Hhd | q-690a363f10 | ok |
| 2 | 2020-05-02 03:19:09.994Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1NY3Hhd | q-a8d4368cff | ok |

### F56 · malicious / high · T1003.002 · Sysinternals pspasswd downloaded and accesschk used to create 'passwordsDB' on scranton

Evidence status: **verified**

On scranton.dmevals.local, PowerShell (pid 3876, user pbeesly) wrote Sysinternals pspasswd64.exe/pspasswd.exe into C:\Users\pbeesly\Downloads\SysinternalsSuite at 03:00:28-03:00:32, then accesschk.exe (pid 9204) created a file named 'passwordsDB' in C:\Program Files\SysinternalsSuite at 03:04:35. pspasswd is a password-reset/credential tool and the 'passwordsDB' artifact indicates local account credential material was being collected on the host.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:00:28.986Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Users\pbeesly\Downloads\SysinternalsSuite\pspasswd64.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1SIw95- | q-690a363f10 | ok |
| 2 | 2020-05-02 03:00:32.048Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Users\pbeesly\Downloads\SysinternalsSuite\pspasswd.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1SIwt7A | q-690a363f10 | ok |
| 3 | 2020-05-02 03:04:35.069Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Program Files\SysinternalsSuite\passwordsDB | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R_lkD8 | q-690a363f10 | ok |

### F11 · malicious / high · T1056 · Intrusion chain on scranton: malicious .scr, hidden PowerShell, Invoke-Exfil, sdelete cleanup

Evidence status: **verified**

On scranton.dmevals.local a malicious screen-saver C:\ProgramData\victim\...cod.3aka3.scr was launched from explorer.exe, spawning cmd.exe then powershell.exe. The PowerShell session (user pbeesly) executed a hidden, execution-policy-bypassed command that decoded a payload from C:\Users\pbeesly\Downloads\monkey.png, compiled code with csc.exe, ran Invoke-Discovery and Invoke-Exfil (which embeds a hardcoded credential and exfiltrates to \\192.168.0.4\webdav), and deleted the .scr with sdelete64.exe. This is the surrounding credential-access campaign context.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:55:56.000Z | scranton.dmevals.local | windows.security | process.executable | C:\ProgramData\victim\â€®cod.3aka3.scr | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YrjwVo | q-49983bc9ce | ok |
| 2 | 2020-05-02 02:58:44.000Z | scranton.dmevals.local | windows.security | process.command_line | "PowerShell.exe" -noni -noexit -ep bypass -window hidden -c "sal a New-Object;Add-Type -AssemblyName 'System.Drawing'; $g=a System.Drawing.Bitmap('C:\Users\pbee… | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YsmIMu | q-49983bc9ce | ok |
| 3 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | powershell.script_block_text | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b10BXt | q-8ac07031dc | ok |
| 4 | 2020-05-02 03:02:04.000Z | scranton.dmevals.local | windows.security | process.command_line | "C:\Program Files\SysinternalsSuite\sdelete64.exe" /accepteula C:\programdata\victim\???cod.3aka3.scr | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YiZqBf | q-49983bc9ce | ok |

### F10 · malicious / high · T1056.004 · PowerShell opens LSASS with PROCESS_ALL_ACCESS (0x1FFFFF) on scranton during intrusion chain

Evidence status: **verified**

On scranton.dmevals.local, PowerShell.exe (PID 2976) opened C:\windows\system32\lsass.exe with GrantedAccess 0x1FFFFF (PROCESS_ALL_ACCESS) at 2020-05-02T03:05:16.654Z, and a 4663 event at 03:05:16 records the same powershell.exe reading lsass with AccessMask 0x10 (PROCESS_VM_READ). This is the credential-access step of an active intrusion: the same host/user (pbeesly) ran a hidden, execution-policy-bypassed PowerShell payload decoded from monkey.png, compiled code via csc.exe, ran Invoke-Discovery and Invoke-Exfil, and cleaned up with sdelete64.exe. Full-access handle to LSASS is the hallmark of credential API hooking / memory read for credential theft.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R-k131 | q-efa247c1eb | ok |
| 2 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.TargetImage | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R-k131 | q-efa247c1eb | ok |
| 3 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R-k131 | q-efa247c1eb | ok |
| 4 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | win.AccessMask | 0x10 | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YldM_j | q-7f5461a895 | ok |
| 5 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | win.ProcessName | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YldM_j | q-7f5461a895 | ok |
| 6 | 2020-05-02 02:58:44.325Z | scranton.dmevals.local | windows.sysmon | process.command_line | "PowerShell.exe" -noni -noexit -ep bypass -window hidden -c "sal a New-Object;Add-Type -AssemblyName 'System.Drawing'; $g=a System.Drawing.Bitmap('C:\Users\pbee… | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1WdFNhN | q-d776b2c8e3 | ok |

### F23 · malicious / high · T1187 · Forced authentication via WebDAV/UNC coercion from scranton host (10.0.1.4) to attacker-controlled 192.168.0.4

Evidence status: **verified**

On 2020-04-30 between 00:32:14 and 00:32:22, host 10.0.1.4 (scranton.dmevals.local) attempted SMB to 192.168.0.4 on port 445 and was rejected (conn_state REJ, history 'Sr', 5 attempts 00:32:14.891-00:32:17.069). It then fell back to WebDAV over HTTP port 80 using the Windows WebDAV redirector (user_agent 'Microsoft-WebDAV-MiniRedir/10.0.18362'), issuing OPTIONS/PROPFIND/PUT/LOCK/PROPPATCH/HEAD/UNLOCK against http://192.168.0.4/webdav/ and successfully creating /webdav/OfficeSupplies.7z (PUT -> 201 Created). The PUT request carried an AUTHORIZATION header, i.e. the victim host transmitted credentials to the attacker-controlled server. This is the classic T1187 forced-authentication pattern: a UNC/WebDAV path (\\192.168.0.4\webdav\OfficeSupplies.7z) coerces the victim into authenticating to an attacker listener, leaking NTLM material. The activity is preceded by PowerShell Gallery / oneget CDN access (www.powershellgallery.com, onegetcdn.azureedge.net, go.microsoft.com at 00:31-00:32), consistent with a package-install or scripted workflow used to trigger the coercion. All 36 WebDAV requests originate solely from 10.0.1.4 to 192.168.0.4.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-04-30 00:32:14.891Z | simplerockbuild.simplerock.lan | zeek | zeek.conn_state | REJ | .ds-logs-zeek-default-2026.10.16-000001 / AaFFktQ25mySA1aO8IdC | q-cf7a7df057 | ok |
| 2 | 2020-04-30 00:32:14.891Z | simplerockbuild.simplerock.lan | zeek | destination.port | 445 | .ds-logs-zeek-default-2026.10.16-000001 / AaFFktQ25mySA1aO8IdC | q-cf7a7df057 | ok |
| 3 | 2020-04-30 00:32:21.422Z | simplerockbuild.simplerock.lan | zeek | user_agent.original | Microsoft-WebDAV-MiniRedir/10.0.18362 | .ds-logs-zeek-default-2026.10.16-000001 / AaFFktQ25mySA1aO8Ieh | q-30cd9557d2 | ok |
| 4 | 2020-04-30 00:32:21.422Z | simplerockbuild.simplerock.lan | zeek | zeek.uri | /webdav | .ds-logs-zeek-default-2026.10.16-000001 / AaFFktQ25mySA1aO8Ieh | q-30cd9557d2 | ok |
| 5 | 2020-04-30 00:32:21.918Z | simplerockbuild.simplerock.lan | zeek | zeek.method | PUT | .ds-logs-zeek-default-2026.10.16-000001 / AaFFktQ25mySA1aO74fI | q-887b2e2abc | ok |
| 6 | 2020-04-30 00:32:21.918Z | simplerockbuild.simplerock.lan | zeek | zeek.uri | /webdav/OfficeSupplies.7z | .ds-logs-zeek-default-2026.10.16-000001 / AaFFktQ25mySA1aO74fI | q-887b2e2abc | ok |
| 7 | 2020-04-30 00:32:21.918Z | simplerockbuild.simplerock.lan | zeek | zeek.client_header_names | ["CONNECTION", "USER-AGENT", "TRANSLATE", "CONTENT-LENGTH", "HOST", "AUTHORIZATION"] | .ds-logs-zeek-default-2026.10.16-000001 / AaFFktQ25mySA1aO74fI | q-887b2e2abc | ok |
| 8 | 2020-04-30 00:32:21.918Z | simplerockbuild.simplerock.lan | zeek | zeek.client_header_names | ["CONNECTION", "USER-AGENT", "TRANSLATE", "CONTENT-LENGTH", "HOST", "AUTHORIZATION"] | .ds-logs-zeek-default-2026.10.16-000001 / AaFFktQ25mySA1aO74fI | q-887b2e2abc | ok |
| 9 | 2020-04-30 00:32:21.895Z | simplerockbuild.simplerock.lan | zeek | zeek.uri | /webdav/OfficeSupplies.7z | .ds-logs-zeek-default-2026.10.16-000001 / AaFFktQ25mySA1aO8Iej | q-7cf7d337f9 | ok |
| 10 | 2020-04-30 00:32:21.895Z | simplerockbuild.simplerock.lan | zeek | http.response.status_code | 401 | .ds-logs-zeek-default-2026.10.16-000001 / AaFFktQ25mySA1aO8Iej | q-7cf7d337f9 | ok |

### F25 · malicious / high · T1212 · PowerShell Remoting (wsmprovhost.exe) opened full-access handles to lsass and other processes on NASHUA during SeaDuke stage execution

Evidence status: **verified**

On 2020-05-02 at 03:09:29, on host nashua.dmevals.local, the PowerShell Remoting host process C:\windows\system32\wsmprovhost.exe (PID 7720, running as SYSTEM) opened a handle to C:\windows\system32\lsass.exe (PID 728) with GrantedAccess 0x1F3FFF (PROCESS_ALL_ACCESS), with a call trace through System.ni.dll and Microsoft.PowerShell.Commands.Management.ni.dll. In the same second it opened 0x1f3fff handles to many other processes (winlogon.exe, vssvc.exe, Sysmon.exe, svchost.exe, taskhostw.exe, WUDFHost.exe, etc.). This burst of full-access process handles from a remoting host is consistent with in-memory credential access / process dumping. It immediately follows the operator command 'Invoke-SeaDukeStage -ComputerName NASHUA' issued from scranton.dmevals.local by user pbeesly at 03:10:22 (and preceded by remote process/user enumeration against NASHUA at 03:09:23). The activity is part of a broader hands-on-keyboard intrusion (discovery, persistence, screen capture, exfil) on the DMEVALS hosts.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1RrM7IJ | q-f2675c211f | ok |
| 2 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1RrM7IJ | q-f2675c211f | ok |
| 3 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.TargetImage | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1RrM7IJ | q-f2675c211f | ok |
| 4 | 2020-05-02 03:09:29.634Z | nashua.dmevals.local | windows.sysmon | win.TargetImage | C:\windows\system32\winlogon.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1RrMrJI | q-e5894b67d2 | ok |
| 5 | 2020-05-02 03:09:29.634Z | nashua.dmevals.local | windows.sysmon | win.TargetImage | C:\windows\system32\vssvc.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1RrMrJ3 | q-e5894b67d2 | ok |
| 6 | 2020-05-02 03:10:22.000Z | scranton.dmevals.local | windows.powershell | powershell.script_block_text | Invoke-SeaDukeStage -ComputerName NASHUA | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1bsxQxZ | q-a87cd7cf5c | ok |
| 7 | 2020-05-02 03:09:23.000Z | scranton.dmevals.local | windows.powershell | powershell.script_block_text | Invoke-Command -ComputerName NASHUA -ScriptBlock { Get-Process -IncludeUserName \| Select-Object UserName,SessionId \| Where-Object { $_.UserName -like "*\$env:… | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1bsxQxS | q-044ba8606b | ok |

### F31 · malicious / medium · T1552 · Sysinternals accesschk.exe run by pbeesly creates 'passwordsDB' file on scranton

Evidence status: **verified**

On scranton.dmevals.local, user DMEVALS\pbeesly (LogonId 0x372e81, IntegrityLevel High) ran a PowerShell session that downloaded and extracted SysinternalsSuite, then executed C:\Program Files\SysinternalsSuite\accesschk.exe (PID 9204, parent powershell.exe PID 3876). Immediately after launch, accesschk.exe created the file C:\Program Files\SysinternalsSuite\passwordsDB (Sysmon event 11, 2020-05-02T03:04:35Z). The same session also used sdelete64.exe to securely delete files including C:\programdata\victim\???cod.3aka3.scr and C:\Users\pbeesly\AppData\Roaming\Draft.Zip, consistent with an operator staging credential-access tooling and wiping artifacts. The 'passwordsDB' filename strongly suggests credential harvesting.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:35.069Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Program Files\SysinternalsSuite\passwordsDB | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R_lkD8 | q-92801ff802 | ok |
| 2 | 2020-05-02 03:04:34.951Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\accesschk.exe" | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R_lkD_ | q-05091db476 | ok |
| 3 | 2020-05-02 03:04:34.951Z | scranton.dmevals.local | windows.sysmon | user.name | pbeesly | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R_lkD_ | q-05091db476 | ok |
| 4 | 2020-05-02 03:04:34.000Z | scranton.dmevals.local | windows.powershell | powershell.script_block_text | &amp; "C:\Program Files\SysinternalsSuite\accesschk.exe" | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b21_RG | q-9cd8115e1e | ok |
| 5 | 2020-05-02 03:02:04.324Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\sdelete64.exe" /accepteula C:\programdata\victim\???cod.3aka3.scr | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1SEqWk4 | q-b82104ecf8 | ok |

### F58 · malicious / high · T1552.001 · Hardcoded credentials in Invoke-Exfil script used to mount attacker WebDAV share

Evidence status: **verified**

On scranton.dmevals.local, PowerShell script block 'Invoke-Exfil' (user pbeesly, pid 3852) contains an embedded plaintext credential ($UserName = "cozy", $Password = "MyCozyPassw0rd!") used to create a PSCredential and map \\192.168.0.4\webdav, then copy the compressed loot archive OfficeSupplies.7z to it. This is credential material embedded in the attacker tooling and used for exfiltration.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b10BXt | q-a942cca6e5 | ok |
| 2 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b10BXt | q-a942cca6e5 | ok |

### F35 · malicious / high · T1555 · LSASS memory accessed with full process rights by PowerShell/wsmprovhost as user pbeesly

Evidence status: **verified**

On scranton.dmevals.local, PowerShell.exe running as user pbeesly opened lsass.exe with GrantedAccess 0x1FFFFF and 0x1F3FFF at 2020-05-02T03:05:16 (Sysmon event 10), and Security 4656 confirms pbeesly/powershell.exe requesting AccessMask 0x1FFFFF on \Device\HarddiskVolume2\Windows\System32\lsass.exe including 'Read from process memory'. On nashua.dmevals.local, wsmprovhost.exe (remote PowerShell) as pbeesly opened lsass.exe with 0x1F3FFF at 03:09:29, confirmed by Security 4656 (AccessMask 0x1F3FFF). These are the classic access masks used to read credential material from LSASS memory. The same user then ran sdelete64.exe to wipe archives (working.zip, Rar.exe, Draft.Zip), consistent with credential theft followed by anti-forensics.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R-k131 | q-839936518e | ok |
| 2 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R-k13y | q-839936518e | ok |
| 3 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1RrM7IJ | q-839936518e | ok |
| 4 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1RrM7IJ | q-839936518e | ok |
| 5 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | win.AccessMask | 0x1fffff | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YldM_p | q-c768060f3e | ok |
| 6 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | win.ProcessName | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YldM_p | q-c768060f3e | ok |
| 7 | 2020-05-02 03:09:29.000Z | nashua.dmevals.local | windows.security | win.AccessMask | 0x1f3fff | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YjaXaO | q-6dc3beb1aa | ok |
| 8 | 2020-05-02 03:09:29.000Z | nashua.dmevals.local | windows.security | win.ProcessName | C:\Windows\System32\wsmprovhost.exe | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YjaXaO | q-6dc3beb1aa | ok |
| 9 | 2020-05-02 03:17:18.030Z | nashua.dmevals.local | windows.sysmon | process.command_line | .\sdelete64.exe  /accepteula "C:\Users\pbeesly\AppData\Roaming\working.zip"  | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1Nc7emY | q-1c1ac4ce0e | ok |

### F59 · malicious / medium · T1555.003 · Rar.exe used with password to archive credential-bearing loot on nashua

Evidence status: **verified**

On nashua.dmevals.local, C:\Windows\Temp\Rar.exe (user pbeesly) was run by PowerShell at 03:16:19 with command line 'a -hpfGzq5yKw C:\Users\pbeesly\Desktop\working.zip C:\Users\pbeesly\AppData\Roaming\working.zip', password-protecting an archive of collected data; sdelete64 then wiped the archive and Rar.exe. This is staging of harvested data (consistent with credential/browser-store collection) for exfiltration.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:16:19.395Z | nashua.dmevals.local | windows.sysmon | process.command_line | "C:\Windows\Temp\Rar.exe" a -hpfGzq5yKw C:\Users\pbeesly\Desktop\working.zip C:\Users\pbeesly\AppData\Roaming\working.zip | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1RhBpvd | q-738bfa6198 | ok |
| 2 | 2020-05-02 03:17:18.030Z | nashua.dmevals.local | windows.sysmon | process.command_line | .\sdelete64.exe  /accepteula "C:\Users\pbeesly\AppData\Roaming\working.zip"  | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1Nc7emY | q-738bfa6198 | ok |

### F37 · malicious / medium · T1555.004 · LSASS handle access consistent with Credential Manager/DPAPI harvesting; no vaultcmd/cmdkey usage

Evidence status: **verified**

The full-access LSASS handles opened by pbeesly's PowerShell (scranton, 0x1FFFFF) and wsmprovhost (nashua, 0x1F3FFF) are the mechanism by which Windows Credential Manager/DPAPI secrets held in LSASS memory are harvested. No explicit vaultcmd/cmdkey command lines or Credentials-file writes were observed (those checks returned zero hits), and the only 'Credential' text in windows.other was a benign 'Credential Guard configuration: 0x0, 0' event on scranton. The LSASS access itself is the malicious indicator.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.TargetImage | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R-k131 | q-839936518e | ok |
| 2 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | win.ObjectName | \Device\HarddiskVolume2\Windows\System32\lsass.exe | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YldM_p | q-c768060f3e | ok |
| 3 | 2020-05-02 03:19:09.000Z | scranton.dmevals.local | windows.other | message | Credential Guard configuration: 0x0, 0 | .ds-logs-windows.other-default-2026.10.16-000001 / AaFFkdQ25mySA1aOnx1Y | q-e5bfb63f16 | ok |

### F39 · malicious / high · T1556 · LSASS credential dumping via PowerShell on scranton.dmevals.local

Evidence status: **verified**

On 2020-05-02 03:05:16 UTC, PowerShell.exe (PID 2976) on scranton.dmevals.local opened lsass.exe (PID 736) with GrantedAccess 0x1fffff and 0x1f3fff (PROCESS_ALL_ACCESS / full read-write), the classic signature of an in-memory credential dump. This is the same host where user pbeesly ran a malicious PowerShell chain minutes later (03:21:27-03:21:29): a registry-stored payload read from HKLM:\SOFTWARE\Javasoft 'value Supplement' piped to Invoke-Expression, an obfuscated P/Invoke helper resolving GetProcAddress/GetModuleHandle, and a Gzip+Base64 hidden PowerShell launcher. The LSASS handle access is the credential-theft step of this intrusion; it is not a modification of the authentication process itself (no password filter, reversible encryption, MFA, hybrid identity or network provider DLL changes were observed).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R-k131 | q-adbf3ef6a2 | ok |
| 2 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R-k131 | q-adbf3ef6a2 | ok |
| 3 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R-k13y | q-adbf3ef6a2 | ok |
| 4 | 2020-05-02 03:21:28.000Z | scranton.dmevals.local | windows.powershell | powershell.script_block_text | Get-ItemPropertyValue 'HKLM:\\SOFTWARE\Javasoft' 'value Supplement' \| Invoke-Expression | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1bzydqQ | q-1474e4ff22 | ok |
| 5 | 2020-05-02 03:21:29.000Z | scranton.dmevals.local | windows.powershell | powershell.script_block_text | if([IntPtr]::Size -eq 4){$b=$env:windir+'\sysnative\WindowsPowerShell\v1.0\powershell.exe'}else{$b='powershell.exe'};$s=New-Object System.Diagnostics.ProcessSta… | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1bzyNRW | q-1474e4ff22 | ok |
| 6 | 2020-05-02 03:21:29.000Z | scranton.dmevals.local | windows.powershell | powershell.script_block_text | function jzI {  	Param ($yKR, $cq)		  	$vvA = ([AppDomain]::CurrentDomain.GetAssemblies() \| Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[… | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1bzydoz | q-1474e4ff22 | ok |

### F45 · malicious / high · T1558 · LSASS memory access with full access mask by PowerShell on scranton — Kerberos ticket theft precursor

Evidence status: **verified**

On scranton.dmevals.local, user pbeesly ran a fileless credential-theft chain: hostui.bat -> hostui.exe (runas) -> powershell.exe -c "Get-ItemPropertyValue 'HKLM:\\SOFTWARE\Javasoft' 'value Supplement' \| Invoke-Expression", which decoded a base64/gzip loader and a reflective shellcode loader (GetProcAddress/ReflectedDelegate). The PowerShell process then opened lsass.exe with GrantedAccess 0x1FFFFF (PROCESS_ALL_ACCESS), the access mask used to read Kerberos TGT/TGS tickets and other secrets from LSASS memory. On nashua.dmevals.local, wsmprovhost.exe (WinRM) also opened lsass.exe with 0x1F3FFF. These are the credential-access actions that precede Kerberos ticket theft.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R-k131 | q-7ce1c38f9d | ok |
| 2 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.TargetImage | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R-k131 | q-7ce1c38f9d | ok |
| 3 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1RrM7IJ | q-7ce1c38f9d | ok |
| 4 | 2020-05-02 03:21:27.859Z | scranton.dmevals.local | windows.sysmon | process.command_line | powershell.exe -c "Get-ItemPropertyValue 'HKLM:\\SOFTWARE\Javasoft' 'value Supplement' \| Invoke-Expression" | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1MtUEbK | q-278c996958 | ok |
| 5 | 2020-05-02 03:21:29.000Z | scranton.dmevals.local | windows.powershell | powershell.script_block_text | function jzI {  	Param ($yKR, $cq)		  	$vvA = ([AppDomain]::CurrentDomain.GetAssemblies() \| Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[… | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1bzyNfQ | q-66d0cc32c0 | ok |

### F54 · malicious / high · T1649 · PowerShell Get-PrivateKeys exports all LocalMachine certificates to .pfx files on scranton.dmevals.local

Evidence status: **verified**

On 2020-05-02 at 03:04:56 UTC, user pbeesly on scranton.dmevals.local executed a PowerShell script block (ScriptBlock ID 9d153741-75c3-4062-afe3-aeca0aee611b, Path C:\Program Files\SysinternalsSuite\readme.ps1) defining function Get-PrivateKeys. The function recursively enumerates cert:\LocalMachine, and for every certificate with a Thumbprint exports it with Export-PfxCertificate to a randomly named .pfx in $env:USERPROFILE\Downloads, protected by the hardcoded password 'saribas'. One second later (03:04:57.460) Sysmon recorded powershell.exe (PID 3876) creating C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx, and at 03:04:57.428 the same powershell.exe read HKLM\SOFTWARE\Microsoft\SystemCertificates\MY\Certificates\48B5E43D09D080DF8863152FD22ED7C43443D499\Blob and the Remote Desktop certificate Blob. A companion function Invoke-BeachCleanup (03:08:51) deletes the exported *.pfx (and *.bmp/*.png/OfficeSupplies.7z) from Downloads, indicating deliberate anti-forensic cleanup. This is theft of authentication certificates/private keys (T1649).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | powershell.script_block_text | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b21vS3 | q-77e57f6b56 | ok |
| 2 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\readme.ps1 | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b21vS3 | q-77e57f6b56 | ok |
| 3 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | user.name | pbeesly | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b21vS3 | q-77e57f6b56 | ok |
| 4 | 2020-05-02 03:04:57.460Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R_lUAH | q-43069a2333 | ok |
| 5 | 2020-05-02 03:04:57.460Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\WindowsPowerShell\v1.0\powershell.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R_lUAH | q-43069a2333 | ok |
| 6 | 2020-05-02 03:04:57.428Z | scranton.dmevals.local | windows.sysmon | registry.path | HKLM\SOFTWARE\Microsoft\SystemCertificates\MY\Certificates\48B5E43D09D080DF8863152FD22ED7C43443D499\Blob | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R_lED5 | q-f58bcb0592 | ok |
| 7 | 2020-05-02 03:08:51.000Z | scranton.dmevals.local | windows.powershell | powershell.script_block_text | function Invoke-BeachCleanup {     Write-Host "[*] Cleaning up"     Remove-Item -Path "$env:USERPROFILE\Downloads\*.pfx" -Force     Remove-Item -Path "$env:USER… | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1bsxh3C | q-15e968ca07 | ok |

### F09 · suspicious / high · T1040 · Related malicious activity in window is not network sniffing (PsExec lateral movement, python C2, screen capture)

Evidence status: **verified**

The same window contains clearly malicious activity that is NOT T1040: on scranton.dmevals.local user pbeesly ran PsExec64.exe with plaintext credentials (dmevals\pbeesly / Fl0nk3rt0n!T0by) to \\NASHUA, spawning C:\Windows\Temp\python.exe via PSEXESVC on nashua.dmevals.local; that python.exe beaconed to 192.168.0.4:8443 over TCP. PowerShell also performed screen capture and image-steganography decoding, and sdelete64 was used to wipe files. These are credential access / lateral movement / C2 behaviors, not packet sniffing, so they do not support the T1040 hypothesis.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:18.000Z | scranton.dmevals.local | windows.security | process.command_line | "C:\Program Files\SysinternalsSuite\PsExec64.exe" -accepteula \\NASHUA -u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YcSP1_ | q-499cc31885 | ok |
| 2 | 2020-05-02 03:15:05.142Z | nashua.dmevals.local | windows.sysmon | destination.ip | 192.168.0.4 | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1RjDSP- | q-8f80c45dde | ok |
| 3 | 2020-05-02 03:15:05.142Z | nashua.dmevals.local | windows.sysmon | destination.port | 8443 | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1RjDSP- | q-8f80c45dde | ok |
| 4 | 2020-05-02 02:58:45.000Z | scranton.dmevals.local | windows.powershell | powershell.script_block_text | sal a New-Object;Add-Type -AssemblyName 'System.Drawing'; $g=a System.Drawing.Bitmap('C:\Users\pbeesly\Downloads\monkey.png');$o=a Byte[] 4480;for($i=0; $i -le … | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b87aMP | q-84c160d472 | ok |

### F22 · suspicious / medium · T1111 · LSASS credential access observed (T1003-like), not MFA interception

Evidence status: **verified**

Although not MFA interception, the closest credential-access activity is LSASS process access. On scranton.dmevals.local, PowerShell.exe (PID 2976) opened lsass.exe with GrantedAccess 0x1FFFFF (full access) and 0x1f3fff at 2020-05-02T03:05:16, and wsmprovhost.exe opened lsass.exe with 0x1f3fff on nashua.dmevals.local at 03:09:29. These high-access LSASS reads are consistent with credential dumping (T1003), not T1111. The remaining 300+ lsass accesses are low-access (0x1000/0x1400) from svchost.exe and security products and are benign.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R-k131 | q-ad355c132e | ok |
| 2 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R-k131 | q-ad355c132e | ok |
| 3 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1RrM7IJ | q-ea7f2521b2 | ok |

### F32 · suspicious / medium · T1552.001 · Explicit-credential logons (4648) using pbeesly credentials via PsExec

Evidence status: **verified**

windows.security shows repeated event 4648 'logon attempted using explicit credentials' for account pbeesly (DMEVALS/DMEVALS.LOCAL) originating from source.ip 10.0.1.6 on scranton.dmevals.local and via C:\Windows\PSEXESVC.exe on nashua.dmevals.local. These explicit-credential logons are consistent with an operator reusing harvested credentials to move laterally, though they could also reflect legitimate admin activity. No file-based credential source (unattend.xml, web.config) was observed being read.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:40.000Z | nashua.dmevals.local | windows.security | process.executable | C:\Windows\PSEXESVC.exe | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YogQzA | q-d74edeaf28 | ok |
| 2 | 2020-05-02 03:11:18.000Z | scranton.dmevals.local | windows.security | user.name | pbeesly | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YcSP2J | q-d74edeaf28 | ok |
| 3 | 2020-05-02 03:11:18.000Z | scranton.dmevals.local | windows.security | source.ip | 10.0.1.6 | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YcSP2J | q-d74edeaf28 | ok |

### F46 · suspicious / medium · T1558.001 · Anomalous krbtgt service-ticket requests from SCRANTON$ on newyork

Evidence status: **verified**

On newyork.dmevals.local, the machine account SCRANTON$@DMEVALS.LOCAL requested Kerberos service tickets for the krbtgt service (Service ID S-1-5-21-1830255721-3727074217-2423397540-502) with TicketOptions 0x60810010, alongside repeated TGS requests for NEWYORK$, SCRANTON$ and WEC$. Requests for a krbtgt service ticket are unusual and are consistent with forged/abused ticket activity (golden-ticket style). All 28 4769 events used encryption type 0x12 (AES256), so no RC4 downgrade was observed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:15.000Z | newyork.dmevals.local | windows.security | win.ServiceName | krbtgt | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YTK7vi | q-097917b3e6 | ok |
| 2 | 2020-05-02 03:19:15.000Z | newyork.dmevals.local | windows.security | win.TicketOptions | 0x60810010 | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YTK7vi | q-097917b3e6 | ok |
| 3 | 2020-05-02 03:04:04.000Z | newyork.dmevals.local | windows.security | user.name | pbeesly@DMEVALS.LOCAL | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YhYtYx | q-097917b3e6 | ok |
| 4 | 2020-05-02 03:19:13.000Z | newyork.dmevals.local | windows.security | user.name | SCRANTON$@DMEVALS.LOCAL | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YOGdm5 | q-097917b3e6 | ok |

### F02 · benign / high · T1003.002 · SAM registry access and HKLM\SECURITY\Cache writes are all by lsass.exe (SYSTEM) — benign

Evidence status: **verified**

Security 4656 events show SAM_SERVER (Object Name 'SAM'), SAM_DOMAIN ('SCRANTON') and SAM_ALIAS handle requests on scranton.dmevals.local, but every one is issued by lsass.exe itself under account SCRANTON$ (S-1-5-18, Logon ID 0x3E7) — normal LSA operation, not an external dumping tool. Likewise the Sysmon event.code 13 registry writes to HKLM\SECURITY\Cache\NL$1 on nashua (PID 728) and scranton (PID 748) are performed by lsass.exe, the legitimate owner of the SECURITY hive cache. No reg save / hive-copy of SAM or SECURITY was observed (C019/C020/C024 zero hits).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:21.000Z | scranton.dmevals.local | windows.security | win.ObjectType | SAM_SERVER | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YWMnGq | q-c5f7bb1b52 | ok |
| 2 | 2020-05-02 03:19:21.000Z | scranton.dmevals.local | windows.security | process.executable | C:\Windows\System32\lsass.exe | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YWMnGq | q-c5f7bb1b52 | ok |
| 3 | 2020-05-02 03:11:40.144Z | nashua.dmevals.local | windows.sysmon | win.TargetObject | HKLM\SECURITY\Cache\NL$1 | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1RpKsLE | q-c5ee98d9a1 | ok |
| 4 | 2020-05-02 03:11:40.144Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1RpKsLE | q-c5ee98d9a1 | ok |

### F03 · benign / high · T1003.003 · No NTDS / VSS / ntdsutil activity observed

Evidence status: **verified**

No file creations matching ntds, no process command lines referencing ntdsutil/vssadmin/diskshadow, and no shadow-copy or NTDS.dit artifacts were found in windows.sysmon, windows.security, windows.other or windows.powershell (checks C025-C030 all zero hits). No evidence of NTDS credential dumping in this dataset.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:21:28.476Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Windows\Prefetch\SECURITYHEALTHSYSTRAY.EXE-41AD6DE1.pf | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1MtUmZF | q-0b9dee663d | ok |

### F04 · benign / high · T1003.004 · No LSA Secrets dumping observed

Evidence status: **verified**

No process command lines referencing secrets/lsadump/reg save HKLM\SECURITY, no handle requests to SECURITY Policy Secrets objects, and no PowerShell script blocks referencing lsadump/LSA secrets were found (checks C032, C034-C037 all zero hits). The only SECURITY-hive activity is lsass.exe's own writes to HKLM\SECURITY\Cache\NL$1, which is normal.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:20:46.691Z | scranton.dmevals.local | windows.sysmon | win.TargetObject | HKLM\SECURITY\Cache\NL$1 | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1NAd3XG | q-c5ee98d9a1 | ok |

### F05 · benign / high · T1003.005 · No cached domain credential dumping observed

Evidence status: **verified**

No handle requests to Cache/SECURITY objects by non-lsass processes, and no PowerShell or other-log references to mscache/DCC2/cached credentials were found (checks C040-C043 all zero hits). The HKLM\SECURITY\Cache\NL$1 writes are performed by lsass.exe itself, i.e. normal cache maintenance, not extraction.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:12:46.768Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1RoJ7pL | q-c5ee98d9a1 | ok |

### F06 · benign / high · T1003.006 · No DCSync / DRSUAPI replication activity observed

Evidence status: **verified**

No process command lines referencing drsuapi/lsadump/dcsync and no PowerShell script blocks referencing DCSync/lsadump/drsuapi were found (checks C047, C048 zero hits). No evidence of directory-services replication abuse in this dataset.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.TargetImage | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R-k13y | q-1877b3010f | ok |

### F07 · benign / high · T1040 · Azure Network Watcher packet capture on scranton.dmevals.local (benign)

Evidence status: **verified**

On 2020-05-01 23:19 (2020-05-02T03:19Z) on scranton.dmevals.local, the legitimate Azure NetworkWatcherAgent.exe (running as SYSTEM, parent services.exe) launched netsh.exe with 'trace start capture=yes' writing an .etl capture file to C:\windows\TEMP, then 'netsh trace stop' ~7s later. This is the standard Azure Network Watcher packet-capture feature, not adversary sniffing. No sniffing tools (tcpdump/windump/wireshark/rawcap/dumpcap), no pcap/npcap/winpcap driver loads, and no promiscuous-mode or raw-socket indicators were found in any dataset.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:17.000Z | scranton.dmevals.local | windows.security | process.command_line | C:\windows\system32\netsh.exe trace start capture=yes traceFile="C:\windows\TEMP\E7116ECA-DFE6-43C7-8FA8-8D3AC5AA8726\B91E06C5-1C7C-4830-9A76-74FA211560A7.etl" | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YYOcv1 | q-c390777c52 | ok |
| 2 | 2020-05-02 03:19:17.000Z | scranton.dmevals.local | windows.security | process.parent.executable | C:\Packages\Plugins\Microsoft.Azure.NetworkWatcher.NetworkWatcherAgentWindows\1.4.1421.1\NetworkWatcherAgent\NetworkWatcherAgent.exe | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YYOcv1 | q-c390777c52 | ok |
| 3 | 2020-05-02 03:19:24.000Z | scranton.dmevals.local | windows.security | process.command_line | C:\windows\system32\netsh.exe trace stop | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YWMXHe | q-666650c35e | ok |
| 4 | 2020-05-02 03:19:17.154Z | scranton.dmevals.local | windows.sysmon | user.name | SYSTEM | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1NW1Kgv | q-05fd5e6ab1 | ok |

### F08 · benign / high · T1040 · No network sniffing tooling or capture drivers observed

Evidence status: **verified**

Searches across windows.sysmon (process creation and image loads), windows.security (4688), windows.powershell (4104) and windows.other (7045) returned no tcpdump/windump/wireshark/rawcap/dumpcap execution, no pcap/npcap/winpcap driver image loads, no promiscuous-mode or raw-socket command lines, and no capture-driver service installations. The only capture-related service installs were PSEXESVC and a Java support service, unrelated to sniffing. T1040 activity is therefore not observed beyond the benign Azure capture above.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:39.000Z | nashua.dmevals.local | windows.other | message | A service was installed in the system.    Service Name:  PSEXESVC  Service File Name:  %SystemRoot%\PSEXESVC.exe  Service Type:  user mode service  Service Star… | .ds-logs-windows.other-default-2026.10.16-000001 / AaFFkdQ25mySA1aOnx2T | q-d758cd2f87 | ok |

### F12 · benign / medium · T1056.001 · No keylogging artifacts observed

Evidence status: **verified**

No keylogger indicators were found: no process command lines referencing keylog/GetAsyncKeyState/SetWindowsHookEx, and no PowerShell script blocks referencing keylogging APIs. The LSASS/winlogon process-access events observed are dominated by benign 0x1000 (PROCESS_QUERY_LIMITED_INFORMATION) accesses from svchost.exe, wsmprovhost.exe, MsMpEng.exe and CollectGuestLogs.exe. No evidence of input capture via keylogging.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:56:14.000Z | utica.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1000 | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1WhJHLy | q-3e0f86c7a5 | ok |
| 2 | 2020-05-02 02:56:14.000Z | utica.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\svchost.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1WhJHLy | q-3e0f86c7a5 | ok |

### F13 · benign / medium · T1056.002 · No GUI input capture observed

Evidence status: **verified**

No 4688 process creation with credential/prompt command lines and no GUI input-capture tooling was observed. The only credential-related PowerShell activity is the Invoke-Exfil script using a hardcoded PSCredential, which is exfiltration rather than GUI input capture.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | powershell.script_block_text | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b10BXt | q-8ac07031dc | ok |

### F14 · benign / medium · T1056.003 · No web portal capture observed

Evidence status: **verified**

No file writes to login/portal/wwwroot/inetpub paths, no IIS/w3wp process command lines, no 4663 access to wwwroot/inetpub/login objects, and no HTTP POST or login/portal URLs in the zeek dataset. No evidence of web portal credential capture.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | win.ObjectName | \Device\HarddiskVolume2\Windows\System32\lsass.exe | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YldM_j | q-7f5461a895 | ok |

### F15 · benign / high · T1110 · No brute-force authentication activity observed on any Windows host

Evidence status: **verified**

Across windows.security (41002 events, 02:55-03:28Z), windows.other, windows.powershell and windows.sysmon there is no evidence of brute-force authentication. The only authentication-failure-adjacent events are benign: a single 4776 credential validation for pbeesly on newyork.dmevals.local with Status 0x0 (success), and a 4648 explicit-credential logon. No 4625 failed-logon, 4740 lockout or 4771 events exist in the dataset. The 'logon/password' message hits in windows.other are a Customer Experience Improvement Program logon notification and an RDP session logon succeeded for DMEVALS\pbeesly.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:20:40.000Z | newyork.dmevals.local | windows.security | win.Status | 0x0 | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YQHwYC | q-5fbd76c846 | ok |
| 2 | 2020-05-02 03:20:48.000Z | scranton.dmevals.local | windows.other | message | Remote Desktop Services: Session logon succeeded:    User: DMEVALS\pbeesly  Session ID: 2  Source Network Address: 172.18.39.2 | .ds-logs-windows.other-default-2026.10.16-000001 / AaFFkdQ25mySA1aOnx0y | q-54bbdca7dc | ok |

### F16 · benign / high · T1110.001 · No password-guessing activity; PowerShell 'password' hits are credential theft/exfil scripts

Evidence status: **verified**

No failed-logon (4625) events exist, so there is no password guessing. The PowerShell script-block hits containing 'Password'/'Credential' are not guessing loops: on scranton.dmevals.local user pbeesly ran Get-PrivateKeys (exports .pfx certs using a hardcoded password 'saribas') and Invoke-Exfil (hardcoded creds 'cozy'/'MyCozyPassw0rd!' to map a WebDAV share). These are credential access/exfiltration behaviour, not T1110.001. The windows.other 'failed' hits are a crash-dump init message and a PTR registration failure.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | powershell.script_block_text | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b21vS3 | q-39a23b732c | ok |
| 2 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | powershell.script_block_text | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b10BXt | q-98fbfb3205 | ok |

### F17 · benign / high · T1110.002 · No password-cracking activity; SAM/lsass access is normal OS behaviour

Evidence status: **verified**

The 326 sysmon event.code 10 handle-opens to C:\windows\system32\lsass.exe are dominated by svchost.exe with GrantedAccess 0x1000 (query-limited) plus Azure antimalware/telemetry agents with 0x1400 - normal. The 10 'SAM' object accesses (event.code 4656) are all performed by C:\Windows\System32\lsass.exe itself with AccessMask 0xf003f, i.e. the OS accessing its own SAM hive, not an attacker dumping it. No cracking tools, wordlists or potfiles were created (the .txt file creations are Cortana/Edge/WER/Sysinternals artifacts).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:20:46.000Z | scranton.dmevals.local | windows.security | win.ProcessName | C:\Windows\System32\lsass.exe | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YJECPG | q-4a203cb9f5 | ok |
| 2 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R-k131 | q-5d192736ef | ok |

### F18 · benign / high · T1110.003 · No password-spraying; 4648 explicit-credential logons are PsExec lateral movement

Evidence status: **verified**

There are no 4625 failures and no account lockouts, so no spraying occurred. The 15 event.code 4648 explicit-credential logons show pbeesly authenticating via C:\Windows\PSEXESVC.exe on nashua.dmevals.local (4x) and via svchost.exe on scranton.dmevals.local, alongside routine DWM/UMFD/SCRANTON$ winlogon/taskhostw logons. This is PsExec-based lateral movement using already-known credentials (T1021.002/T1078), not password spraying.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:40.000Z | nashua.dmevals.local | windows.security | win.ProcessName | C:\Windows\PSEXESVC.exe | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YogQzA | q-abe0c75a82 | ok |
| 2 | 2020-05-02 03:11:39.000Z | nashua.dmevals.local | windows.other | message | A service was installed in the system.    Service Name:  PSEXESVC  Service File Name:  %SystemRoot%\PSEXESVC.exe  Service Type:  user mode service  Service Star… | .ds-logs-windows.other-default-2026.10.16-000001 / AaFFkdQ25mySA1aOnx2T | q-1426d1d089 | ok |

### F19 · benign / high · T1110.004 · No credential-stuffing activity observed

Evidence status: **verified**

Credential stuffing requires repeated authentication attempts against many accounts; the dataset contains zero 4625 failed-logon events and zero lockouts. The only credential-validation event is a single successful 4776 for pbeesly on newyork.dmevals.local (Status 0x0). No stuffing tooling or command lines referencing password lists were found in sysmon process creation.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:20:40.000Z | newyork.dmevals.local | windows.security | win.TargetUserName | pbeesly | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YQHwYC | q-5fbd76c846 | ok |

### F20 · benign / high · T1111 · No MFA interception artifacts; 'Credential' hits are benign Windows internals

Evidence status: **verified**

All events matching 'Credential' in this window are normal Windows behaviour, not MFA interception. On scranton.dmevals.local, lsass.exe set HKLM\System\CurrentControlSet\Control\DeviceGuard\Scenarios\CredentialGuard\Enabled to 0x00000000 (Credential Guard config), and services.exe registered the built-in CredentialEnrollmentManagerUserSvc_13619b service (ImagePath C:\windows\system32\CredentialEnrollmentManager.exe) plus MuiCache entries for CredentialEnrollmentManager.exe. windows.other shows 'Credential Guard configuration: 0x0, 0' on scranton. No smart-card, OTP, token-provider, or credential-provider interception activity was observed on any host.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:09.865Z | scranton.dmevals.local | windows.sysmon | win.TargetObject | HKLM\System\CurrentControlSet\Control\DeviceGuard\Scenarios\CredentialGuard\Enabled | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1NY3HhV | q-22617cd954 | ok |
| 2 | 2020-05-02 03:20:48.264Z | scranton.dmevals.local | windows.sysmon | win.Details | C:\windows\system32\CredentialEnrollmentManager.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1NDgh5J | q-22617cd954 | ok |
| 3 | 2020-05-02 03:19:09.000Z | scranton.dmevals.local | windows.other | message | Credential Guard configuration: 0x0, 0 | .ds-logs-windows.other-default-2026.10.16-000001 / AaFFkdQ25mySA1aOnx1Y | q-c80c23cdec | ok |

### F21 · benign / medium · T1111 · PowerShell script block referencing credentials is exfiltration tooling, not MFA interception

Evidence status: **verified**

The only PowerShell script block referencing 'Credential' is an Invoke-Exfil function on scranton.dmevals.local (user pbeesly, path C:\Program Files\SysinternalsSuite\psversion.ps1). It builds a PSCredential from a hardcoded username/password, maps a WebDAV drive to \\192.168.0.4\webdav and copies a password-protected 7z archive there. This is data exfiltration (T1041/T1560), not MFA interception — it uses credentials rather than intercepting an MFA factor.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | powershell.script_block_text | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b10BXt | q-c72c0d7d54 | ok |
| 2 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\psversion.ps1 | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b10BXt | q-c72c0d7d54 | ok |

### F24 · benign / medium · T1187 · Inbound SMB share access on newyork.dmevals.local is normal domain SYSVOL/DFS replication traffic

Evidence status: **verified**

The 5140/5145 share-access events on newyork.dmevals.local are machine-account (NEWYORK$, SCRANTON$) accesses to the \\*\SYSVOL share path \??\F:\SYSVOL\sysvol, sourced from link-local IPv6 (fe80::e40c:95b6:b0a7:6429) and from 10.0.1.4. These are routine domain-controller SYSVOL/Group Policy and DFS replication reads by computer accounts, not attacker-forced authentication. The corresponding Sysmon event.code 3 SMB connections (ports 445/139) are System process (PID 4) connections between domain hosts (10.0.1.4/10.0.1.6/10.0.1.10 -> 10.0.0.4), consistent with normal AD/SMB traffic. No attacker-controlled listener or credential capture is evident in these events.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:56:47.000Z | newyork.dmevals.local | windows.security | event.code | 5145 | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YsmIPl | q-367bca958e | ok |
| 2 | 2020-05-02 02:56:47.000Z | newyork.dmevals.local | windows.security | user.name | NEWYORK$ | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YsmIPl | q-367bca958e | ok |
| 3 | 2020-05-02 03:01:43.000Z | newyork.dmevals.local | windows.security | user.name | SCRANTON$ | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YcRSol | q-367bca958e | ok |
| 4 | 2020-05-02 03:01:43.033Z | scranton.dmevals.local | windows.sysmon | process.executable | System | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1SEqmrA | q-e7ab742010 | ok |
| 5 | 2020-05-02 03:01:43.033Z | scranton.dmevals.local | windows.sysmon | destination.ip | 10.0.0.4 | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1SEqmrA | q-e7ab742010 | ok |

### F26 · benign / medium · T1212 · Kerberos service-ticket (4769) activity on newyork.dmevals.local is normal domain authentication, not exploitation

Evidence status: **verified**

The Kerberos service-ticket-request events (event.code 4769) on newyork.dmevals.local are routine domain authentication: machine account SCRANTON$@DMEVALS.LOCAL requesting a ticket for service NEWYORK$ from client address ::ffff:10.0.1.4, with Ticket Encryption Type 0x12 (AES256) and Failure Code 0x0. This is standard TGS traffic with no anomalous encryption downgrade or ticket-forging pattern, reflecting normal Kerberos authentication in the DMEVALS domain rather than exploitation for credential access.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:13.000Z | newyork.dmevals.local | windows.security | event.code | 4769 | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YOGdm5 | q-f81c6bc1ad | ok |
| 2 | 2020-05-02 03:19:13.000Z | newyork.dmevals.local | windows.security | message | A Kerberos service ticket was requested.    Account Information:  	Account Name:		SCRANTON$@DMEVALS.LOCAL  	Account Domain:		DMEVALS.LOCAL  	Logon GUID:		{4b3ec… | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YOGdm5 | q-f81c6bc1ad | ok |
| 3 | 2020-05-02 03:19:13.000Z | newyork.dmevals.local | windows.security | user.name | SCRANTON$@DMEVALS.LOCAL | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YOGdm5 | q-f81c6bc1ad | ok |

### F27 · benign / medium · T1212 · svchost.exe 0x1000 process-access events are routine Windows behaviour

Evidence status: **verified**

The overwhelming majority of Sysmon event.code 10 process-access events (39283 total) are C:\windows\system32\svchost.exe opening handles with GrantedAccess 0x1000 (PROCESS_QUERY_LIMITED_INFORMATION) to other svchost.exe instances and to lsass.exe. This is normal Windows service-host behaviour (e.g. service status queries) and is not indicative of credential-access exploitation. The anomalous outlier is the wsmprovhost.exe 0x1f3fff burst reported separately.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:55:23.551Z | utica.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1000 | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1WiJ0Te | q-19e90eb69c | ok |
| 2 | 2020-05-02 03:24:18.178Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\svchost.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1MuaKzP | q-f2675c211f | ok |
| 3 | 2020-05-02 03:24:18.178Z | nashua.dmevals.local | windows.sysmon | win.TargetImage | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1MuaKzP | q-f2675c211f | ok |

### F28 · benign / high · T1539 · WebDAV DavSetCookie activity is not browser session-cookie theft

Evidence status: **verified**

On scranton.dmevals.local, user pbeesly spawned rundll32.exe running davclnt.dll,DavSetCookie against 192.168.0.4 http://192.168.0.4/webdav (5 process-creation events, 2020-05-01T23:08:50 to 23:10:23 local). This is the Windows WebDAV client setting a WebDAV authentication cookie for a mounted WebDAV share, not theft of a browser web session cookie. The parent process is svchost.exe and the command line contains no browser profile or cookie-database path.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:08:50.000Z | scranton.dmevals.local | windows.security | process.command_line | rundll32.exe C:\windows\system32\davclnt.dll,DavSetCookie 192.168.0.4 http://192.168.0.4/webdav | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YeU-Dp | q-06e76ced0b | ok |
| 2 | 2020-05-02 03:08:50.000Z | scranton.dmevals.local | windows.security | process.parent.executable | C:\Windows\System32\svchost.exe | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YeU-Dp | q-4cd3449c99 | ok |
| 3 | 2020-05-02 03:10:23.154Z | scranton.dmevals.local | windows.sysmon | process.command_line | rundll32.exe C:\windows\system32\davclnt.dll,DavSetCookie 192.168.0.4 http://192.168.0.4/webdav | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1RrMLE_ | q-ecc6942360 | ok |

### F29 · benign / high · T1539 · INetCookies file creation is a Windows WARP JIT service artifact

Evidence status: **verified**

The only Sysmon file-creation event matching *cookie* is svchost.exe (PID 7200, SYSTEM) creating C:\Windows\ServiceProfiles\LocalService\AppData\Local\Packages\warp_jit_db4a1097-b484-4973-bbf2-a04208ecd4d4\AC\INetCookies on scranton.dmevals.local at 2020-05-02T03:21:05.681Z. This is the Windows WARP JIT service package's own INetCookies store under the LocalService service profile, not a browser cookie database (no Chrome/Edge/Firefox profile path).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:21:05.681Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Windows\ServiceProfiles\LocalService\AppData\Local\Packages\warp_jit_db4a1097-b484-4973-bbf2-a04208ecd4d4\AC\INetCookies | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1MsOhX7 | q-cc933c2efd | ok |
| 2 | 2020-05-02 03:21:05.681Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\System32\svchost.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1MsOhX7 | q-48c1ac70f9 | ok |

### F30 · benign / high · T1539 · No access to browser cookie stores or credential-stealer tooling

Evidence status: **verified**

Targeted hunts found no theft of web session cookies. Sysmon file-creation (event 11) matching *cookies*/*login data*/*web data*/*cookies.sqlite* returned only the single WARP JIT INetCookies artifact; Sysmon process-access (event 10) to Edge/Chrome/Firefox/IEXPLORE targets returned only routine Explorer.EXE and svchost.exe read accesses (GrantedAccess 0x2000/0x3000) consistent with normal browser launch; Security 4663 object-access to cookie/login-data/browser paths returned zero rows; PowerShell script blocks matching *cookie*/*login data* returned zero rows. The credential-related activity present in the window is password-based lateral movement (PsExec64.exe with a cleartext password to \\NASHUA), which is not T1539.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:24:23.993Z | nashua.dmevals.local | windows.sysmon | win.TargetImage | C:\Windows\SystemApps\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\MicrosoftEdge.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1Muar8B | q-253e1e3c9c | ok |
| 2 | 2020-05-02 03:24:23.993Z | nashua.dmevals.local | windows.sysmon | win.GrantedAccess | 0x2000 | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1Muar8B | q-253e1e3c9c | ok |
| 3 | 2020-05-02 03:14:42.601Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\PsExec64.exe" -accepteula \\NASHUA -u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1RkEAFq | q-ecfb3b1570 | ok |

### F34 · benign / high · T1552.002 · Registry Password/Credential value sets are OS-internal, not credential harvesting

Evidence status: **verified**

Sysmon event 13 registry value sets matching Password/Credential were all written by legitimate system processes: svchost.exe writing HKU\.DEFAULT\Software\Microsoft\IdentityCRL\ProviderPasswordLength/CharacterGroups, lsass.exe writing the DeviceGuard CredentialGuard Enabled value, services.exe creating the CredentialEnrollmentManagerUserSvc service keys, and winlogon.exe writing Winlogon\PasswordExpiryNotification. None represent an adversary storing or reading credentials in the registry.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:28.255Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\svchost.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R8i4gn | q-537a437cfb | ok |
| 2 | 2020-05-02 03:19:09.865Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1NY3HhV | q-537a437cfb | ok |
| 3 | 2020-05-02 03:21:20.841Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\winlogon.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1MtSxRG | q-537a437cfb | ok |

### F33 · benign / high · T1552.006 · Group Policy Preferences / SecEdit files accessed only by normal svchost Group Policy processing

Evidence status: **verified**

Sysmon file-creation events for GptTmpl.inf and the sysvol GroupPolicy DataStore path on scranton.dmevals.local and nashua.dmevals.local were all generated by C:\windows\system32\svchost.exe (the Group Policy client), which is normal Windows Group Policy refresh behavior. Zeek smb_files records show SMB FILE_OPEN of \\NEWYORK.dmevals.local\sysvol ...\GptTmpl.inf from 10.0.1.4 and 10.0.1.6, also consistent with routine GPO retrieval. No Groups.xml with cpassword was observed and no non-standard process read these files.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:01:43.091Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Windows\System32\GroupPolicy\DataStore\0\sysvol\dmevals.local\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.in… | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1SFrDbU | q-0c0fe9b9aa | ok |
| 2 | 2020-05-02 03:01:43.091Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\svchost.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1SFrDbU | q-0c0fe9b9aa | ok |
| 3 | 2020-04-30 00:12:01.673Z | simplerockbuild.simplerock.lan | zeek | source.ip | 10.0.1.4 | .ds-logs-zeek-default-2026.10.16-000001 / AaFFktQ25mySA1aO8IeP | q-e5a5f91f87 | ok |

### F38 · benign / high · T1555 · Benign LSASS access by system processes and Azure guest tooling

Evidence status: **verified**

Most LSASS handle events are routine: wininit.exe/csrss.exe opening lsass.exe with 0x1FFFFF at scranton 03:19:09 (process startup), svchost.exe with 0x101001, CollectGuestLogs.exe (C:\WindowsAzure\Packages) with 0x1410/0x10 on scranton/utica/newyork/nashua, and Windows Defender MsMpEng.exe with 0x1FFFFF on scranton. The sdelete64.exe LSASS event on nashua is LSASS (SourceImage lsass.exe) accessing sdelete64.exe via lsasrv.dll/SspiSrv.dll/RPCRT4.dll — normal SSPI/RPC, not sdelete reading LSASS. These are expected system behaviours, not credential theft.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:09.803Z | scranton.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\wininit.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1NY3HhM | q-839936518e | ok |
| 2 | 2020-05-02 03:18:34.438Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x101001 | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1WpS5PW | q-839936518e | ok |
| 3 | 2020-05-02 03:22:38.000Z | nashua.dmevals.local | windows.security | win.ProcessName | C:\WindowsAzure\Packages\CollectGuestLogs.exe | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YEBswS | q-43550ffe48 | ok |
| 4 | 2020-05-02 03:20:15.000Z | scranton.dmevals.local | windows.security | win.ProcessName | C:\Program Files\Windows Defender\MsMpEng.exe | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YGClc_ | q-43550ffe48 | ok |
| 5 | 2020-05-02 03:17:18.071Z | nashua.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1Nc7emR | q-7ea54dd923 | ok |

### F36 · benign / medium · T1555.003 · No browser credential-store access observed

Evidence status: **verified**

Checks for browser credential artifacts (Login Data, logins.json, cookies) in Sysmon process/file events, Security object access, PowerShell script blocks and other channels returned no hits. The only file event matching a cookie path was a benign system file (INetCookies under the LocalService WARP JIT package profile) on scranton, not a browser credential store. No evidence of web-browser credential theft in the available windows.sysmon/security/powershell/other data.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:21:05.681Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Windows\ServiceProfiles\LocalService\AppData\Local\Packages\warp_jit_db4a1097-b484-4973-bbf2-a04208ecd4d4\AC\INetCookies | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1MsOhX7 | q-5fb3d41f0f | ok |

### F40 · benign / medium · T1556.001 · Machine-account Kerberos network logons (normal DC authentication, no backdoor)

Evidence status: **verified**

The 218 LogonType 3 (network) 4624 events are dominated by machine-account Kerberos logons: NEWYORK$ (from ::1, fe80::e40c:95b6:b0a7:6429, 10.0.0.4), SCRANTON$ (10.0.1.4), NASHUA$ (10.0.1.6), UTICA$ (10.0.1.5) and WEC$ (10.0.1.10), all with LogonProcessName 'Kerberos'. These are routine computer-account authentications between domain members and the DC, not evidence of a DC authentication backdoor. The only non-machine account is pbeesly (13 logons from 10.0.1.4, 5 with no source, 1 from 10.0.1.6, 1 NtLmSsp from 172.18.39.2), consistent with the compromised user's lateral movement rather than a modified DC authentication process. No 4648 explicit-credential logon to a domain controller or Skeleton Key-style anomaly was observed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:55:54.000Z | newyork.dmevals.local | windows.security | user.name | NEWYORK$ | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YsmoMw | q-173c62e211 | ok |
| 2 | 2020-05-02 02:55:54.000Z | newyork.dmevals.local | windows.security | win.LogonType | 3 | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YsmoMw | q-173c62e211 | ok |
| 3 | 2020-05-02 02:56:47.000Z | newyork.dmevals.local | windows.security | source.ip | 10.0.0.4 | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1Yph4sy | q-173c62e211 | ok |

### F41 · benign / medium · T1557 · No adversary-in-the-middle activity observed; Zeek MAC anomalies are capture artifacts

Evidence status: **verified**

Across windows.security, windows.sysmon, windows.other, windows.powershell and zeek there is no evidence of an adversary positioned in the middle. The only network-level oddity is in the zeek capture (2020-04-30 window): responder MAC 12:34:56:78:9a:bc answers for many unrelated destination IPs (192.168.0.4, 10.0.0.4, 10.0.1.6, 192.168.0.5) and source 10.0.1.4 appears with two MACs (00:0d:3a:4d:42:f2 and fc:bd:67:e1:a9:c1). 12:34:56:78:9a:bc is a synthetic/placeholder MAC, so this is a capture artifact rather than a real host impersonating others. SMB/RPC traffic is normal domain activity (SAMR/LSAR to the DC, IPC$ mapping).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-04-30 00:39:55.956Z | simplerockbuild.simplerock.lan | zeek | zeek.resp_l2_addr | 12:34:56:78:9a:bc | .ds-logs-zeek-default-2026.10.16-000001 / AaFFktQ25mySA1aO8YcL | q-11f631048b | ok |
| 2 | 2020-04-30 00:45:00.042Z | bobs.bigwheel.local | zeek | zeek.orig_l2_addr | fc:bd:67:e1:a9:c1 | .ds-logs-zeek-default-2026.10.16-000001 / AaFFktQ25mySA1bi_UDc | q-45b0c32960 | ok |
| 3 | 2020-04-30 00:36:38.977Z | simplerockbuild.simplerock.lan | zeek | zeek.path | \\NEWYORK.dmevals.local\IPC$ | .ds-logs-zeek-default-2026.10.16-000001 / AaFFktQ25mySA1aO8IeN | q-14d46f28da | ok |

### F42 · benign / medium · T1557.001 · No name-resolution poisoning or SMB relay; service installs are built-in/PSEXESVC

Evidence status: **verified**

Sysmon DNS queries (event 22) show only normal lookups (host FQDNs, LDAP SRV records, Microsoft telemetry, wpad) with no LLMNR/NBT-NS-style poisoning, and no Responder/MITM/LLMNR/NBT-NS strings appear in PowerShell script blocks. The 23 event.code 4697 service installations are Windows built-in per-user services (svchost UnistackSvcGroup etc.) plus PSEXESVC (%SystemRoot%\PSEXESVC.exe, installed by user pbeesly on nashua) and javamtsup (C:\Windows\System32\javamtsup.exe on scranton) — these are lateral-movement/execution artifacts, not SMB relay. Zeek SMB/RPC is normal domain traffic.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:12:46.000Z | nashua.dmevals.local | windows.security | win.ServiceName | PSEXESVC | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YcRyrP | q-748e7fe76c | ok |
| 2 | 2020-05-02 03:04:15.000Z | scranton.dmevals.local | windows.security | win.ServiceFileName | C:\Windows\System32\javamtsup.exe | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YhYtY9 | q-748e7fe76c | ok |
| 3 | 2020-04-30 00:35:04.526Z | simplerockbuild.simplerock.lan | zeek | zeek.operation | LsarEnumerateTrustedDomains | .ds-logs-zeek-default-2026.10.16-000001 / AaFFktQ25mySA1aO8Ifg | q-14d46f28da | ok |

### F43 · benign / medium · T1557.002 · No ARP cache poisoning; duplicate MAC-to-IP mappings are capture artifacts

Evidence status: **verified**

Stacking source and responder MACs in the zeek conn log shows no host claiming multiple IPs in a way consistent with ARP spoofing. Source 10.0.1.4 appears with two MACs (00:0d:3a:4d:42:f2 and fc:bd:67:e1:a9:c1) and the responder 12:34:56:78:9a:bc (a synthetic placeholder MAC) answers for several distinct IPs — both are artifacts of the capture rather than gratuitous ARP. No ARP/netsh interface manipulation appears in PowerShell script blocks, and no ARP-related object access stands out in windows.security.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-04-30 00:39:55.956Z | simplerockbuild.simplerock.lan | zeek | zeek.resp_l2_addr | 12:34:56:78:9a:bc | .ds-logs-zeek-default-2026.10.16-000001 / AaFFktQ25mySA1aO8YcL | q-11f631048b | ok |
| 2 | 2020-04-30 00:45:00.042Z | bobs.bigwheel.local | zeek | zeek.orig_l2_addr | fc:bd:67:e1:a9:c1 | .ds-logs-zeek-default-2026.10.16-000001 / AaFFktQ25mySA1bi_UDc | q-45b0c32960 | ok |

### F47 · benign / medium · T1558.002 · No silver-ticket evidence observed

Evidence status: **verified**

The 4769 service-ticket requests on newyork.dmevals.local were all issued by the KDC with encryption type 0x12 (AES256) and normal TicketOptions; no service tickets were observed being used without a corresponding KDC-issued request, and no forged service-ticket artifacts (e.g. anomalous SPN usage) were found. No silver-ticket activity is evident in the retrieved events.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:04.000Z | newyork.dmevals.local | windows.security | win.TicketEncryptionType | 0x12 | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YhYtYv | q-097917b3e6 | ok |

### F48 · benign / medium · T1558.003 · No Kerberoasting pattern observed

Evidence status: **verified**

Zeek Kerberos records (2020-04-30 window, non-overlapping with the Windows data) show only normal pbeesly AS/TGS traffic to krbtgt, cifs/NASHUA, host/nashua.dmevals.local, HTTP/NASHUA and ldap/NEWYORK, with KDC_ERR_PREAUTH_REQUIRED on AS requests. No mass SPN service-ticket requests or RC4 (etype 23) downgrade typical of Kerberoasting were seen, and no Kerberoast/Rubeus/Invoke-Kerberoast strings appeared in PowerShell script blocks.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-04-30 00:37:53.342Z | simplerockbuild.simplerock.lan | zeek | zeek.service | cifs/NASHUA | .ds-logs-zeek-default-2026.10.16-000001 / AaFFktQ25mySA1aO8IeS | q-34086f867f | ok |
| 2 | 2020-04-30 00:40:22.436Z | simplerockbuild.simplerock.lan | zeek | zeek.error_msg | KDC_ERR_PREAUTH_REQUIRED | .ds-logs-zeek-default-2026.10.16-000001 / AaFFktQ25mySA1aO8Idd | q-34086f867f | ok |

### F49 · benign / medium · T1558.004 · No AS-REP Roasting evidence observed

Evidence status: **verified**

Zeek Kerberos AS requests all returned KDC_ERR_PREAUTH_REQUIRED (pre-authentication required) before succeeding, indicating accounts are not configured with 'Do not require Kerberos preauthentication'. No AS-REP roasting tooling strings (AS-REP, GetNPUsers, DontRequirePreAuth) were found in PowerShell script blocks.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-04-30 00:37:53.330Z | simplerockbuild.simplerock.lan | zeek | zeek.error_msg | KDC_ERR_PREAUTH_REQUIRED | .ds-logs-zeek-default-2026.10.16-000001 / AaFFktQ25mySA1aO8IeQ | q-34086f867f | ok |

### F50 · benign / high · T1606 · No web-credential forging activity; keyword hits are benign PowerShell resource strings

Evidence status: **verified**

The only PowerShell 4104 script blocks matching cookie/token/SAML keywords on scranton.dmevals.local are benign: a Sysinternals readme.ps1 helper (Get-AttributesMask, user pbeesly) and PowerShellGet localized resource strings (PSScriptInfo/Authenticode messages). LSASS process-access events with elevated masks (0x1fffff, 0x1f3fff, 0x101001) originate from legitimate SYSTEM processes (wininit.exe, csrss.exe, svchost.exe) and a SYSTEM-context PowerShell.exe whose call trace is ntdll.dll/KERNELBASE.dll, not a credential-dumping tool. Logon process names are normal (Kerberos 217, Advapi 76, User32 2, NtLmSsp 1). No forged web credential material was observed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:04.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\readme.ps1 | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b22vQJ | q-e601fdbcd8 | ok |
| 2 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.CallTrace | C:\windows\SYSTEM32\ntdll.dll+9c584\|C:\windows\System32\KERNELBASE.dll+2732e\|UNKNOWN(000001996D28200D) | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R-k131 | q-33e441e5c5 | ok |
| 3 | 2020-05-02 03:19:09.803Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\wininit.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1NY3HhM | q-d445128774 | ok |

### F51 · benign / high · T1606.001 · Single cookie-path file event is a benign Windows service-profile INetCookies file

Evidence status: **verified**

The only Sysmon file-creation event matching a cookie path is C:\Windows\ServiceProfiles\LocalService\AppData\Local\Packages\warp_jit_db4a1097-b484-4973-bbf2-a04208ecd4d4\AC\INetCookies on scranton.dmevals.local, created by C:\windows\System32\svchost.exe (LocalService profile). This is normal Windows service-profile cookie storage, not browser cookie theft or forging. No Set-Cookie/session manipulation was found in PowerShell script blocks.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:21:05.681Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Windows\ServiceProfiles\LocalService\AppData\Local\Packages\warp_jit_db4a1097-b484-4973-bbf2-a04208ecd4d4\AC\INetCookies | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1MsOhX7 | q-4449b4634d | ok |
| 2 | 2020-05-02 03:21:05.681Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\System32\svchost.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1MsOhX7 | q-4449b4634d | ok |

### F52 · benign / high · T1606.002 · No SAML token forging artifacts in PowerShell, Sysmon or Zeek

Evidence status: **verified**

No SAML/Assertion/NotOnOrAfter content appears in any PowerShell 4104 script block (the only keyword matches are PowerShellGet Authenticode resource strings), no saml/token/cert command lines appear in Sysmon process-creation events, and no saml/adfs/token URLs appear in Zeek HTTP requests. The Zeek window (2020-04-30) contains only WebDAV OPTIONS/PROPFIND traffic (user agent Microsoft-WebDAV-MiniRedir) and does not overlap the Windows host windows. No SAML token forging was observed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:08:09.000Z | scranton.dmevals.local | windows.powershell | powershell.script_block_text |  parameter is missing for adding the metadata to the script file. Try again after specifying the description.  UnableToAddPSScriptInfo=Unable to add PSScriptInf… | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b0zgg- | q-95c34ac38c | ok |
| 2 | 2020-04-30 00:32:21.533Z | simplerockbuild.simplerock.lan | zeek | user_agent.original | Microsoft-WebDAV-MiniRedir/10.0.18362 | .ds-logs-zeek-default-2026.10.16-000001 / AaFFktQ25mySA1aO74fL | q-7077dbcb12 | ok |

### F53 · benign / high · T1621 · WMI provider lifecycle events (5857/5858) on newyork.dmevals.local are routine, not MFA request generation

Evidence status: **verified**

The only T1621 check with hits (C355, windows.other, event.code 5857/5858) returned routine WMI activity on newyork.dmevals.local. Event 5857 records WMI providers starting successfully (result code 0x0) inside wmiprvse.exe (e.g. dsccore, CIMWin32, StorageWMI, SppProvider), and event 5858 records SYSTEM-initiated IWbemServices::DeleteInstance operations against Root\Rsop\Computer RSOP_ExtensionStatus with ResultCode 0x80041002 (object not found) — a normal Group Policy RSOP cleanup pattern. No MFA/2FA/authenticator push, phone-call, or repeated authentication-request artifacts appear in any dataset. There are no 4625 failed-logon events in windows.security, and no MFA-related strings in PowerShell script blocks or Sysmon process command lines.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:01:28.000Z | newyork.dmevals.local | windows.other | message | dsccore provider started with result code 0x0. HostProcess = wmiprvse.exe; ProcessID = 5344; ProviderPath = %systemroot%\system32\DscCore.dll | .ds-logs-windows.other-default-2026.10.16-000001 / AaFFkdQ25mySA1aOnx21 | q-5a476f2d02 | ok |
| 2 | 2020-05-02 02:56:47.000Z | newyork.dmevals.local | windows.other | message | Id = {C11E1664-7828-4AD0-B23A-0FCEF0EA26C0}; ClientMachine = NEWYORK; User = NT AUTHORITY\SYSTEM; ClientProcessId = 1588; Component = Unknown; Operation = Start… | .ds-logs-windows.other-default-2026.10.16-000001 / AaFFkdQ25mySA1aOnx1E | q-3dbd4be59e | ok |
| 3 | 2020-05-02 03:01:30.000Z | newyork.dmevals.local | windows.other | message | CIMWin32 provider started with result code 0x0. HostProcess = wmiprvse.exe; ProcessID = 4292; ProviderPath = %systemroot%\system32\wbem\cimwin32.dll | .ds-logs-windows.other-default-2026.10.16-000001 / AaFFkdQ25mySA1aOnx07 | q-5a476f2d02 | ok |

### F55 · benign / high · T1649 · Routine OS certificate-store registry writes by svchost/lsass/taskhostw (benign)

Evidence status: **verified**

The bulk of the 1133 registry writes matching *Certificate*/*Crypto*/*Keys* are normal Windows certificate-store maintenance: svchost.exe and lsass.exe updating AuthRoot and 'Windows Live ID Token Issuer' certificate Blobs on nashua.dmevals.local, taskhostw.exe writing per-user ACRS PhysicalStores values on scranton.dmevals.local, and smss.exe creating the WOW6432Node SystemCertificates symbolic link. These are system processes, not the attacker's PowerShell, and represent expected certificate-store activity rather than certificate theft or forging.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:16:19.447Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\svchost.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1RhBptB | q-f58bcb0592 | ok |
| 2 | 2020-05-02 02:59:37.453Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1SS5_B3 | q-f58bcb0592 | ok |
| 3 | 2020-05-02 03:20:49.745Z | scranton.dmevals.local | windows.sysmon | registry.path | HKU\S-1-5-21-1830255721-3727074217-2423397540-1107\Software\Microsoft\SystemCertificates\ACRS\PhysicalStores\.LocalMachine\OpenStoreProvider | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1NDgB6i | q-f58bcb0592 | ok |

### F44 · not_observed / medium · T1557.003 · No DHCP spoofing; no DHCP telemetry present in any dataset

Evidence status: **verified**

No DHCP-related activity is observable. The zeek capture contains no dhcp log type (only conn/files/ssl/x509/dce_rpc/http/dns/kerberos/dpd/smb_files/weird/smb_mapping/notice/pe). windows.other contains no DHCP event codes (1341/1342/1020/1063). Sysmon network connections (event 3) show no DHCP ports 67/68. No DHCP strings appear in PowerShell script blocks. The only broadcast traffic is normal NetBIOS name service (137/138) from System.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:21:54.892Z | nashua.dmevals.local | windows.sysmon | destination.port | 137 | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1MsPmId | q-d21f40cea1 | ok |
| 2 | 2020-05-02 03:10:45.997Z | newyork.dmevals.local | windows.sysmon | destination.port | 138 | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1RqLLj_ | q-d21f40cea1 | ok |

## Technique conclusions

One line per technique in scope: status from the triage of its family; `not_observed` = checked, nothing found; `not_observable` = no dataset records it.

| Technique | Status | Reason |
|---|---|---|
| T1003 OS Credential Dumping | malicious | LSASS memory was opened with full-access masks (0x1F3FFF/0x1FFFFF) by attacker-controlled PowerShell on scranton and wsmprovhost on nashua, consistent with OS credential dumping. |
| T1003.001 LSASS Memory | malicious | lsass.exe created C:\Windows\debug\PASSWD.LOG on scranton at 03:19:09, consistent with credential material written by LSASS. |
| T1003.002 Security Account Manager | malicious | pspasswd64/pspasswd.exe written to Downloads by PowerShell and accesschk.exe created 'passwordsDB' on scranton — local credential collection tooling. |
| T1003.003 NTDS | not_observed | No ntds/NTDS.dit file creation, no ntdsutil/vssadmin/diskshadow command lines, no shadow-copy artifacts. |
| T1003.004 LSA Secrets | not_observed | No lsadump/secrets command lines, no SECURITY Policy Secrets handle requests, no LSA-secret PowerShell blocks. |
| T1003.005 Cached Domain Credentials | not_observed | No non-lsass access to Cache/SECURITY objects and no mscache/DCC2/cached-credential references. |
| T1003.006 DCSync | not_observed | No drsuapi/dcsync/lsadump command lines or PowerShell script blocks indicating directory replication abuse. |
| T1040 Network Sniffing | benign | The only packet-capture activity is the legitimate Azure NetworkWatcherAgent.exe invoking 'netsh trace start capture=yes' on scranton.dmevals.local (SYSTEM, parent services.exe), immediately followed by 'netsh trace stop… |
| T1056 Input Capture | malicious | Active intrusion chain on scranton.dmevals.local: malicious .scr -> cmd -> hidden bypassed PowerShell decoding monkey.png payload, Invoke-Discovery/Invoke-Exfil, sdelete64 cleanup, culminating in full-access LSASS handle… |
| T1056.001 Keylogging | not_observed | No keylogger command lines, script blocks, or hooking APIs found; LSASS/winlogon accesses are benign 0x1000 query-limited-info from system processes. |
| T1056.002 GUI Input Capture | not_observed | No GUI input-capture tooling or credential-prompt process creations observed. |
| T1056.003 Web Portal Capture | not_observed | No web portal/login/wwwroot/inetpub artifacts, no IIS processes, no HTTP POST or login URLs in zeek. |
| T1056.004 Credential API Hooking | malicious | PowerShell.exe opened lsass.exe with GrantedAccess 0x1FFFFF (PROCESS_ALL_ACCESS) and read it with AccessMask 0x10 on scranton, consistent with credential API hooking/memory read for credential theft. |
| T1110 Brute Force | not_observed | No 4625/4740/4771 events; only a successful 4776 (Status 0x0) and benign logon notifications. No brute-force pattern. |
| T1110.001 Password Guessing | not_observed | Zero failed logons; PowerShell 'password' hits are credential theft/exfil scripts (Get-PrivateKeys, Invoke-Exfil), not guessing. |
| T1110.002 Password Cracking | not_observed | SAM hive accessed only by lsass.exe itself (AccessMask 0xf003f); lsass handle opens are normal svchost/AV agents; no cracking tools or wordlist/potfile artifacts. |
| T1110.003 Password Spraying | not_observed | No failed logons or lockouts; 4648 explicit-credential logons are PsExec lateral movement by pbeesly, not spraying. |
| T1110.004 Credential Stuffing | not_observed | No repeated authentication attempts against multiple accounts; only one successful 4776 credential validation. |
| T1111 Multi-Factor Authentication Interception | not_observed | No MFA interception activity found. All 'Credential' matches are benign Windows internals (Credential Guard config, CredentialEnrollmentManager service registration, MuiCache). No smart-card/OTP/token-provider or credent… |
| T1187 Forced Authentication | malicious | Host 10.0.1.4 (scranton) was coerced into authenticating to attacker-controlled 192.168.0.4: SMB/445 attempts were rejected (REJ), then the Windows WebDAV redirector (Microsoft-WebDAV-MiniRedir/10.0.18362) issued OPTIONS… |
| T1212 Exploitation for Credential Access | malicious | On nashua.dmevals.local at 2020-05-02T03:09:29, PowerShell Remoting host wsmprovhost.exe (SYSTEM) opened a full-access (0x1F3FFF) handle to lsass.exe and to many other processes (winlogon, vssvc, Sysmon, svchost), immedi… |
| T1539 Steal Web Session Cookie | not_observed | All cookie-related hits are benign: WebDAV DavSetCookie (davclnt.dll) process creations on scranton.dmevals.local and a Windows WARP JIT service INetCookies file creation. No access to browser cookie databases (Chrome/Ed… |
| T1552 Unsecured Credentials | malicious | pbeesly on scranton ran Sysinternals accesschk.exe which created a file named 'passwordsDB', alongside sdelete64 artifact wiping, indicating credential-access tooling. |
| T1552.001 Credentials In Files | malicious | Invoke-Exfil script embeds plaintext credential cozy/MyCozyPassw0rd! used to mount attacker WebDAV share for exfil. |
| T1552.002 Credentials in Registry | benign | All Password/Credential registry writes were by svchost/lsass/services/winlogon OS components, not adversary activity. |
| T1552.003 Shell History | not_observed | No consolehost_history or shell history file access in sysmon or security datasets. |
| T1552.004 Private Keys | malicious | Get-PrivateKeys exported LocalMachine certificates to .pfx (coyn5igj.3io.pfx) on scranton — private key material theft (already anchored as T1649). |
| T1552.006 Group Policy Preferences | benign | GptTmpl.inf/sysvol GPP file access was performed by svchost.exe Group Policy processing and routine SMB GPO retrieval; no Groups.xml cpassword abuse. |
| T1555 Credentials from Password Stores | malicious | PowerShell.exe (pbeesly) on scranton opened lsass.exe with 0x1FFFFF/0x1F3FFF and wsmprovhost.exe (pbeesly) on nashua opened lsass.exe with 0x1F3FFF, both including 'Read from process memory' (Sysmon 10 + Security 4656), … |
| T1555.003 Credentials from Web Browsers | suspicious | Password-protected Rar archive of collected data staged on nashua then wiped with sdelete; consistent with browser/credential store harvesting but the source files were not directly observed. |
| T1555.004 Windows Credential Manager | malicious | Full-access LSASS handles by pbeesly's PowerShell/wsmprovhost are the mechanism for harvesting Credential Manager/DPAPI secrets from LSASS memory; no explicit vaultcmd/cmdkey usage seen. |
| T1555.005 Password Managers | not_observed | No password-manager executables, files or script references (keepass/1password/bitwarden/lastpass/kdbx) in any dataset. |
| T1556 Modify Authentication Process | suspicious | PowerShell.exe on scranton.dmevals.local opened lsass.exe with 0x1fffff/0x1f3fff (PROCESS_ALL_ACCESS) at 03:05:16, and user pbeesly ran a malicious PowerShell chain (registry-stored payload via HKLM:\SOFTWARE\Javasoft ->… |
| T1556.001 Domain Controller Authentication | not_observed | LogonType 3 4624 events are routine machine-account Kerberos logons (NEWYORK$, SCRANTON$, NASHUA$, UTICA$, WEC$); no DC authentication backdoor or Skeleton-Key-style anomaly was found. |
| T1556.002 Password Filter DLL | not_observed | No 4657 registry change to Notification Packages/lsass keys, no 4688/4104 referencing password filter DLLs. |
| T1556.005 Reversible Encryption | not_observed | No 4739, no Reversible/Set-ADUser/dsmod command lines, no AllowReversiblePasswordEncryption references. |
| T1556.006 Multi-Factor Authentication | not_observed | No 4739/5136/4738 and no Set-ADUser/Set-ADAccountControl activity indicating MFA modification. |
| T1556.007 Hybrid Identity | not_observed | No 5136/4739/4738 and no Connect-MsolService or cloud-identity cmdlet usage. |
| T1556.008 Network Provider DLL | not_observed | No 4657 NetworkProvider/Credential registry changes and no PowerShell referencing NetworkProvider DLLs. |
| T1557 Adversary-in-the-Middle | benign | No AiTM positioning observed; the only network anomaly (placeholder responder MAC 12:34:56:78:9a:bc answering for many IPs) is a zeek capture artifact, and SMB/RPC traffic is normal domain activity. |
| T1557.001 Name Resolution Poisoning and SMB Relay | benign | No LLMNR/NBT-NS poisoning or SMB relay; DNS queries are normal, no Responder/MITM tooling in PowerShell, and 4697 service installs are built-in services plus PSEXESVC/javamtsup (lateral movement, not relay). |
| T1557.002 ARP Cache Poisoning | benign | No ARP cache poisoning; duplicate MAC-to-IP mappings in zeek are capture artifacts (synthetic placeholder MAC), and no ARP/netsh manipulation appears in PowerShell. |
| T1557.003 DHCP Spoofing | not_observed | No DHCP telemetry exists in any dataset: no dhcp log type in zeek, no DHCP event codes in windows.other, no ports 67/68 in Sysmon, no DHCP strings in PowerShell. |
| T1558 Steal or Forge Kerberos Tickets | malicious | PowerShell.exe on scranton opened lsass.exe with GrantedAccess 0x1FFFFF and wsmprovhost.exe on nashua opened lsass.exe with 0x1F3FFF, following a fileless registry->Invoke-Expression loader and reflective shellcode loade… |
| T1558.001 Golden Ticket | suspicious | SCRANTON$@DMEVALS.LOCAL requested krbtgt service tickets (Service ID ...-502, TicketOptions 0x60810010) on newyork.dmevals.local, an unusual TGS request pattern consistent with forged/abused ticket activity; no RC4 downg… |
| T1558.002 Silver Ticket | not_observed | All 4769 service tickets were KDC-issued with AES256 (0x12) and normal options; no forged service-ticket usage artifacts found. |
| T1558.003 Kerberoasting | not_observed | Zeek Kerberos shows only normal AS/TGS traffic with preauth required; no mass SPN requests, RC4 downgrade, or Kerberoast tooling strings. |
| T1558.004 AS-REP Roasting | not_observed | All AS requests returned KDC_ERR_PREAUTH_REQUIRED; no AS-REP roasting tooling or preauth-disabled accounts observed. |
| T1606 Forge Web Credentials | not_observed | No forged web credential material. Keyword hits in PowerShell 4104 are benign Sysinternals readme.ps1 and PowerShellGet resource strings; LSASS access with high masks comes from legitimate SYSTEM processes (wininit/csrss… |
| T1606.001 Web Cookies | not_observed | Only cookie-path file event is a benign Windows service-profile INetCookies file created by svchost.exe; no browser cookie theft or Set-Cookie/session manipulation found. |
| T1606.002 SAML Tokens | not_observed | Zero hits for SAML/Assertion/NotOnOrAfter in PowerShell, no saml/token/cert command lines in Sysmon, no saml/adfs/token URLs in Zeek HTTP. |
| T1621 Multi-Factor Authentication Request Generatio… | not_observed | No MFA request generation activity found. The only hit (C355, windows.other 5857/5858) is routine WMI provider startup and RSOP DeleteInstance cleanup by SYSTEM on newyork.dmevals.local. No 4625 failed logons in windows.… |
| T1649 Steal or Forge Authentication Certificates | malicious | PowerShell Get-PrivateKeys on scranton.dmevals.local (user pbeesly) enumerated cert:\LocalMachine and exported certificates to a password-protected .pfx in Downloads (confirmed by Sysmon file-create of coyn5igj.3io.pfx b… |

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

Every MCP tool call of this run (1126), in order (source: mcp_audit.jsonl written by the MCP server).

| Query | Phase | Tool | Arguments | Hits / rows | Cited by |
|---|---|---|---|---|---|
| q-8a536b8ab0 | scope | list_data_sources | {} | None |  |
| q-976142f0a6 | scope | get_registry | {} | None |  |
| q-369c13ac2d | scope | get_fields | {"dataset": "windows.other", "prefix": ""} | None |  |
| q-d7dea6b135 | scope | get_fields | {"dataset": "windows.powershell", "prefix": ""} | None |  |
| q-7829a9fa2d | scope | get_fields | {"dataset": "windows.security", "prefix": ""} | None |  |
| q-608148e328 | scope | get_fields | {"dataset": "windows.sysmon", "prefix": ""} | None |  |
| q-6e7cf29331 | scope | get_fields | {"dataset": "zeek", "prefix": ""} | None |  |
| q-fe97b1b0ac | check C001 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 447 |  |
| q-7f70104f89 | check C002 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-08aa1e58e6 | check C003 | aggregate | {"dataset": "windows.security", "field": "win.ObjectType", "query": "event.code:(4656 OR 4663 OR 4670)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 10977 |  |
| q-e77f161036 | check C004 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 460 |  |
| q-a0a1b8e1f7 | check C005 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*lsass* OR powershell.script_block_text:*mimikatz* OR powershell.script_block_text:*sekurlsa* OR powershell.script_block_text:*DumpCreds*)", "time_from": null, "time_… | 0 |  |
| q-fc3ebc519c | check C006 | search | {"dataset": "windows.other", "query": "message:(*lsass* OR *mimikatz* OR *sekurlsa* OR *procdump*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "p… | 0 |  |
| q-c476801ba8 | check C007 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-e7acf6d2c1 | check C008 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 326 |  |
| q-31734341de | check C009 | aggregate | {"dataset": "windows.sysmon", "field": "win.SourceImage", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-67d5a779b6 | check C010 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*lsass* OR file.path:*.dmp)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "pro… | 2 |  |
| q-ca14a22bab | check C011 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*lsass* OR process.command_line:*comsvcs* OR process.command_line:*MiniDump*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dat… | 1 |  |
| q-5e63ccff58 | check C012 | search | {"dataset": "windows.sysmon", "query": "event.code:(13 OR 14) AND registry.path:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.comm… | 0 |  |
| q-7f9395e533 | check C013 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4673", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 934 |  |
| q-2df93075f4 | check C014 | search | {"dataset": "windows.security", "query": "event.code:4656 AND win.ObjectName:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command… | 13 |  |
| q-f1686cc731 | check C015 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*lsass* OR powershell.script_block_text:*MiniDump* OR powershell.script_block_text:*Invoke-Mimikatz*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "… | 0 |  |
| q-ae0f1deb5d | check C016 | search | {"dataset": "windows.other", "query": "message:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 0 |  |
| q-0b9dee663d | check C017 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*SAM* OR file.path:*SECURITY* OR file.path:*SYSTEM*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "… | 3 | F03 |
| q-43d3b82f12 | check C018 | search | {"dataset": "windows.sysmon", "query": "event.code:(13 OR 14) AND (registry.path:*SAM* OR registry.path:*SECURITY*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "proces… | 7 |  |
| q-ac0f85db23 | check C019 | search | {"dataset": "windows.sysmon", "query": "event.code:2 AND (process.command_line:*SAM* OR process.command_line:*reg*save*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "p… | 0 |  |
| q-5eb98be226 | check C020 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*reg save* OR process.command_line:*save*hklm* OR process.command_line:*SAM*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dat… | 0 |  |
| q-83594f3f1f | check C021 | aggregate | {"dataset": "windows.security", "field": "process.command_line", "query": "event.code:4688 AND (process.command_line:*reg* OR process.command_line:*save*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 6 |  |
| q-2fd4bfa2c7 | check C022 | search | {"dataset": "windows.security", "query": "event.code:(4656 OR 4663) AND (win.ObjectName:*SAM* OR win.ObjectName:*SECURITY*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name",… | 10 |  |
| q-181e4bc843 | check C023 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*SAM* OR powershell.script_block_text:*reg save* OR powershell.script_block_text:*hive*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "… | 11 |  |
| q-980390a2fb | check C024 | search | {"dataset": "windows.other", "query": "message:(*SAM* OR *SECURITY hive* OR *reg save*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.comm… | 0 |  |
| q-2bf4e2afc1 | check C025 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*ntds* OR file.path:*NTDS*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "pro… | 0 |  |
| q-bbe020b38a | check C026 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*ntds* OR process.command_line:*vssadmin* OR process.command_line:*ntdsutil* OR process.command_line:*diskshadow*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "ho… | 0 |  |
| q-0e69c7cbf2 | check C027 | search | {"dataset": "windows.sysmon", "query": "event.code:2 AND file.path:*ntds*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "so… | 0 |  |
| q-5f69c233fe | check C028 | aggregate | {"dataset": "windows.security", "field": "process.command_line", "query": "event.code:4688 AND (process.command_line:*ntds* OR process.command_line:*vssadmin* OR process.command_line:*diskshadow*)", "time_from": null, "time_to": null, "size": 50, "sub_field": … | 0 |  |
| q-267a794f03 | check C029 | search | {"dataset": "windows.other", "query": "message:(*shadow* OR *VSS* OR *ntds*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 0 |  |
| q-85690e41b7 | check C030 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*ntds* OR powershell.script_block_text:*diskshadow* OR powershell.script_block_text:*vssadmin*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.n… | 0 |  |
| q-b3d650bf97 | check C031 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 326 |  |
| q-637f0d4ae3 | check C032 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*secrets* OR process.command_line:*lsadump* OR process.command_line:*reg save*HKLM\\\\SECURITY*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observe… | 0 |  |
| q-5a9d914346 | check C033 | search | {"dataset": "windows.sysmon", "query": "event.code:7 AND win.ImageLoaded:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_lin… | 1 |  |
| q-d88c97549f | check C034 | search | {"dataset": "windows.security", "query": "event.code:(4656 OR 4663 OR 4670) AND win.ObjectName:*SECURITY*Policy*Secrets*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "p… | 0 |  |
| q-d34a01e3bc | check C035 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:(4656 OR 4663 OR 4670) AND win.ObjectName:*Secrets*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-2dcce9ed2c | check C036 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*Secrets* OR powershell.script_block_text:*lsadump* OR powershell.script_block_text:*LSA*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name",… | 0 |  |
| q-fea615a147 | check C037 | search | {"dataset": "windows.other", "query": "message:(*Secrets* OR *LSA* OR *lsadump*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_lin… | 0 |  |
| q-92c56095f1 | check C038 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 326 |  |
| q-f8afa70f1a | check C039 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*cache* OR process.command_line:*DCC2* OR process.command_line:*mscache* OR process.command_line:*cachedump*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.na… | 4 |  |
| q-1cc91e442b | check C040 | search | {"dataset": "windows.security", "query": "event.code:(4656 OR 4663 OR 4670) AND (win.ObjectName:*Cache* OR win.ObjectName:*SECURITY*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "u… | 0 |  |
| q-19e4c283e6 | check C041 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:(4656 OR 4663 OR 4670) AND win.ObjectName:*Cache*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-ccd917e272 | check C042 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*cache* OR powershell.script_block_text:*DCC2* OR powershell.script_block_text:*mscache*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", … | 0 |  |
| q-fc8cc01e81 | check C043 | search | {"dataset": "windows.other", "query": "message:(*cached*credential* OR *mscache* OR *DCC2*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.… | 0 |  |
| q-43d121c7c6 | check C044 | count | {"dataset": "windows.security", "query": "event.code:4662", "time_from": null, "time_to": null} | 7 |  |
| q-e05561860c | check C045 | aggregate | {"dataset": "windows.security", "field": "win.AccessMask", "query": "event.code:4662", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 7 |  |
| q-7add614f8b | check C046 | aggregate | {"dataset": "windows.security", "field": "win.SubjectUserName", "query": "event.code:4662", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 7 |  |
| q-80ba47b830 | check C047 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*drsuapi* OR process.command_line:*lsadump* OR process.command_line:*dcsync*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dat… | 0 |  |
| q-6a8b553ea9 | check C048 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*DCSync* OR powershell.script_block_text:*lsadump* OR powershell.script_block_text:*drsuapi*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.nam… | 0 |  |
| q-03dde23e67 | check C049 | search | {"dataset": "windows.other", "query": "event.code:7045 OR event.code:5858 OR event.code:5857", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process… | 90 |  |
| q-78ce050bf3 | check C050 | search | {"dataset": "zeek", "query": "event.action:dce_rpc AND (zeek.operation:*DRSUAPI* OR zeek.endpoint:*drsuapi* OR zeek.named_pipe:*drsuapi*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code"… | 9 |  |
| q-b2c707b443 | check C051 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 460 |  |
| q-003c0aad1d | check C052 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*pcap* OR process.command_line:*sniff* OR process.command_line:*promisc*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.da… | 0 |  |
| q-d758cd2f87 | check C053 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 | F08 |
| q-fd0d0cb5d5 | check C054 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.executable:*tcpdump* OR process.executable:*windump* OR process.executable:*wireshark* OR process.executable:*rawcap* OR process.executable:*npcap*)", "time_from": null, "time_to": null, "fields… | 0 |  |
| q-1d9cd657f7 | check C055 | search | {"dataset": "windows.sysmon", "query": "event.code:6 AND (win.Image:*npcap* OR win.Image:*pcap* OR win.Image:*winpcap*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "pr… | 0 |  |
| q-c08fe901dc | check C056 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*pcap* OR powershell.script_block_text:*sniff* OR powershell.script_block_text:*promiscuous*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.nam… | 0 |  |
| q-56878ee531 | check C057 | search | {"dataset": "zeek", "query": "event.action:conn AND network.transport:icmp", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "s… | 0 |  |
| q-27100487a1 | check C058 | aggregate | {"dataset": "windows.security", "field": "win.ObjectType", "query": "event.code:4656 OR event.code:4663 OR event.code:4670", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 10977 |  |
| q-943d1842bd | check C059 | aggregate | {"dataset": "windows.security", "field": "win.AccessMask", "query": "event.code:4656 OR event.code:4663", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 10834 |  |
| q-8d86d39c18 | check C060 | search | {"dataset": "windows.security", "query": "event.code:4656 AND (win.ObjectName:*lsass* OR win.ObjectName:*credential* OR win.ObjectName:*SAM*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.c… | 23 |  |
| q-4f3e6a3d00 | check C061 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-816f6e1b97 | check C062 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-4d3cbee818 | check C063 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND (win.GrantedAccess:0x1010 OR win.GrantedAccess:0x1410 OR win.GrantedAccess:0x1438 OR win.GrantedAccess:0x143a)", "time_from": null, "time_to": null, "fields": ["@timestamp", … | 0 |  |
| q-57a4a33ce6 | check C064 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*Get-Credential* OR powershell.script_block_text:*CredentialManager* OR powershell.script_block_text:*keylog*)", "time_from": null, "time_to": null, "fields": ["@time… | 0 |  |
| q-20beeb2eb7 | check C065 | search | {"dataset": "windows.other", "query": "event.code:7045 OR event.code:5858 OR event.code:5857", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process… | 90 |  |
| q-64e90af9bf | check C066 | search | {"dataset": "zeek", "query": "event.action:http AND http.request.method:POST", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 0 |  |
| q-fde82dc585 | check C067 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-3e0f86c7a5 | check C068 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND (win.TargetImage:*lsass* OR win.TargetImage:*winlogon* OR win.TargetImage:*explorer*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event… | 470 | F12 |
| q-cf63b6e7f6 | check C069 | search | {"dataset": "windows.sysmon", "query": "event.code:13 AND (registry.path:*Keyboard* OR registry.path:*keylog* OR registry.path:*Scancode*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code… | 26 |  |
| q-22c37ba34f | check C070 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*keylog* OR process.command_line:*GetAsyncKeyState* OR process.command_line:*SetWindowsHookEx*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer… | 0 |  |
| q-cd68eff5c6 | check C071 | aggregate | {"dataset": "windows.security", "field": "win.ObjectType", "query": "event.code:4656 OR event.code:4663 OR event.code:4670", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 10977 |  |
| q-68a40c56f5 | check C072 | search | {"dataset": "windows.security", "query": "event.code:4656 AND (win.ObjectName:*lsass* OR win.ObjectName:*winlogon*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "proces… | 13 |  |
| q-52915b8249 | check C073 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-e9822dd2fd | check C074 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*keylog* OR powershell.script_block_text:*GetAsyncKeyState* OR powershell.script_block_text:*SetWindowsHookEx*)", "time_from": null, "time_to": null, "fields": ["@tim… | 0 |  |
| q-9345d51cc8 | check C075 | search | {"dataset": "zeek", "query": "event.action:http AND http.request.method:POST", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 0 |  |
| q-02ce0fb8d0 | check C076 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*Credential* OR powershell.script_block_text:*Prompt* OR powershell.script_block_text:*Read-Host*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "hos… | 4 |  |
| q-ec437c742e | check C077 | aggregate | {"dataset": "windows.powershell", "field": "win.ScriptBlockId", "query": "event.code:4104", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 414 |  |
| q-241e659e36 | check C078 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*Credential* OR process.command_line:*prompt* OR process.command_line:*consent*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.… | 3 |  |
| q-6145053c1f | check C079 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 447 |  |
| q-6bcbdff0c3 | check C080 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*Credential* OR process.command_line:*prompt*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user… | 0 |  |
| q-0d65815af0 | check C081 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 460 |  |
| q-f945e360ae | check C082 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-25079a23a8 | check C083 | search | {"dataset": "zeek", "query": "event.action:http AND http.request.method:POST", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 0 |  |
| q-8948a64b05 | check C084 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*login* OR file.path:*portal* OR file.path:*wwwroot* OR file.path:*inetpub*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "eve… | 0 |  |
| q-a4d41eaf7d | check C085 | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 1649 |  |
| q-1a6354f50f | check C086 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*iis* OR process.command_line:*w3wp* OR process.command_line:*wwwroot*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset",… | 0 |  |
| q-67b230431d | check C087 | search | {"dataset": "windows.security", "query": "event.code:4663 AND (win.ObjectName:*wwwroot* OR win.ObjectName:*inetpub* OR win.ObjectName:*login*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.… | 0 |  |
| q-538d214e79 | check C088 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 5337 |  |
| q-bd722a8c8d | check C089 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*wwwroot* OR powershell.script_block_text:*login* OR powershell.script_block_text:*credential*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.n… | 4 |  |
| q-ca3f82a4c5 | check C090 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-40722ead7d | check C091 | search | {"dataset": "zeek", "query": "event.action:http AND (url.original:*login* OR url.original:*portal*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "… | 0 |  |
| q-dd3a7300f2 | check C092 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-a584afd779 | check C093 | aggregate | {"dataset": "windows.sysmon", "field": "win.SourceImage", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-a58a77a0e7 | check C094 | aggregate | {"dataset": "windows.sysmon", "field": "win.ImageLoaded", "query": "event.code:7", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 20259 |  |
| q-a906d49228 | check C095 | search | {"dataset": "windows.sysmon", "query": "event.code:8", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinatio… | 95 |  |
| q-12c29599b1 | check C096 | aggregate | {"dataset": "windows.security", "field": "win.CallerProcessName", "query": "event.code:4656 AND win.ObjectType:*Process*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 13 |  |
| q-420776c733 | check C097 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:*hook* OR powershell.script_block_text:*SetWindowsHookEx* OR powershell.script_block_text:*MiniDump*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.… | 0 |  |
| q-9b6d165f84 | check C098 | search | {"dataset": "windows.other", "query": "message:*hook* OR message:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "sou… | 0 |  |
| q-143fa8bc3e | check C099 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-fc41a277e7 | check C100 | aggregate | {"dataset": "windows.security", "field": "source.ip", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-6cd6580e3a | check C101 | timeline | {"dataset": "windows.security", "query": "event.code:4625", "interval": "1m", "time_from": null, "time_to": null} | 0 |  |
| q-54bbdca7dc | check C102 | search | {"dataset": "windows.other", "query": "message:*logon* OR message:*password*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 2 | F15 |
| q-9c611e616f | check C103 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:*Credential* OR powershell.script_block_text:*Password*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.n… | 4 |  |
| q-5d9a87c229 | check C104 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*net* OR process.command_line:*login*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 30 |  |
| q-0cc4078e1e | check C105 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-065ef25905 | check C106 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 0 |  |
| q-d46fbd6cd2 | check C107 | timeline | {"dataset": "windows.security", "query": "event.code:4625", "interval": "1m", "time_from": null, "time_to": null} | 0 |  |
| q-fc496651a1 | check C108 | search | {"dataset": "windows.other", "query": "message:*4625* OR message:*failed*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "so… | 2 |  |
| q-41f782fdbc | check C109 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:*Password* OR powershell.script_block_text:*Credential*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.n… | 4 |  |
| q-64ac27475e | check C110 | aggregate | {"dataset": "windows.sysmon", "field": "process.command_line", "query": "event.code:1 AND process.command_line:*password*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-0206221025 | check C111 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 OR event.code:4656 OR event.code:4670", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 10977 |  |
| q-13bbdea05e | check C112 | aggregate | {"dataset": "windows.security", "field": "win.ProcessName", "query": "event.code:4663 AND (win.ObjectName:*SAM* OR win.ObjectName:*SECURITY*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-9bc61c57eb | check C113 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*hash* OR process.command_line:*crack*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-4c86672c71 | check C114 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND (win.TargetFilename:*.txt OR win.TargetFilename:*.pot)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 20 |  |
| q-e6252c37dc | check C115 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10 AND (win.TargetImage:*lsass* OR win.TargetImage:*SAM*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-89aa884b3d | check C116 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:*hash* OR powershell.script_block_text:*ConvertTo-SecureString*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code",… | 12 |  |
| q-8b07e73aa6 | check C117 | search | {"dataset": "windows.other", "query": "message:*SAM* OR message:*hash*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "sourc… | 1 |  |
| q-0496707488 | check C118 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-f9f57d3839 | check C119 | aggregate | {"dataset": "windows.security", "field": "source.ip", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-5125be33b6 | check C120 | search | {"dataset": "windows.security", "query": "event.code:4648", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 15 |  |
| q-453262dc80 | check C121 | timeline | {"dataset": "windows.security", "query": "event.code:4625", "interval": "1m", "time_from": null, "time_to": null} | 0 |  |
| q-92ef96e2e7 | check C122 | search | {"dataset": "windows.other", "query": "message:*logon* OR message:*account*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "… | 7 |  |
| q-b42ea6ba40 | check C123 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:*Password* OR powershell.script_block_text:*Credential*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.n… | 4 |  |
| q-47b316a273 | check C124 | aggregate | {"dataset": "windows.sysmon", "field": "process.command_line", "query": "event.code:1 AND process.command_line:*user*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1 |  |
| q-14b21a0d7a | check C125 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-4667bcaca5 | check C126 | aggregate | {"dataset": "windows.security", "field": "source.ip", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-f206d5cc12 | check C127 | timeline | {"dataset": "windows.security", "query": "event.code:4625", "interval": "1m", "time_from": null, "time_to": null} | 0 |  |
| q-d78fd6be3d | check C128 | search | {"dataset": "windows.other", "query": "message:*logon* OR message:*credential*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line"… | 4 |  |
| q-cadaf7ce47 | check C129 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:*Credential* OR powershell.script_block_text:*Password*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.n… | 4 |  |
| q-bc0d2ccb96 | check C130 | aggregate | {"dataset": "windows.sysmon", "field": "process.command_line", "query": "event.code:1 AND process.command_line:*password*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-eb032686d4 | check C131 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 297 |  |
| q-a106f0fa20 | check C132 | search | {"dataset": "windows.security", "query": "event.code:4648", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 15 |  |
| q-007924b127 | check C133 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-22617cd954 | check C134 | search | {"dataset": "windows.sysmon", "query": "event.code:13 AND registry.path:*Credential*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command… | 11 | F20 |
| q-7443da4d54 | check C135 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND powershell.script_block_text:*Credential*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executab… | 3 |  |
| q-c80c23cdec | check C136 | search | {"dataset": "windows.other", "query": "message:*Credential*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "des… | 2 | F20 |
| q-585f6bb820 | check C137 | aggregate | {"dataset": "windows.security", "field": "win.ObjectType", "query": "event.code:4656 OR event.code:4663 OR event.code:4670", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 10977 |  |
| q-367bca958e | check C138 | search | {"dataset": "windows.security", "query": "event.code:5140 OR event.code:5145", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 163 | F24 |
| q-1b2a029247 | check C139 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1649 |  |
| q-e7ab742010 | check C140 | search | {"dataset": "windows.sysmon", "query": "event.code:3 AND (destination.port:445 OR destination.port:139)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable… | 66 | F24 |
| q-5edf451916 | check C141 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*445* OR powershell.script_block_text:*WebDAV* OR powershell.script_block_text:*NTLM*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "ob… | 0 |  |
| q-1c8c02a209 | check C142 | search | {"dataset": "windows.other", "query": "message:*445* OR message:*WebDAV*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "sou… | 0 |  |
| q-94ed6e1c6d | check C143 | aggregate | {"dataset": "zeek", "field": "destination.port", "query": "event.action:conn AND (destination.port:445 OR destination.port:139)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 50 |  |
| q-f14d720866 | check C144 | search | {"dataset": "zeek", "query": "event.action:http AND (http.request.method:PROPFIND OR http.request.method:MOVE OR http.request.method:OPTIONS)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.c… | 36 |  |
| q-caeee76e88 | check C145 | aggregate | {"dataset": "windows.security", "field": "event.code", "query": "event.code:4768 OR event.code:4769 OR event.code:4770", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 42 |  |
| q-49ad0ccfd9 | check C146 | search | {"dataset": "windows.security", "query": "event.code:4769", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 28 |  |
| q-ba8c3359fc | check C147 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-19e90eb69c | check C148 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.GrantedAccess:*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line",… | 39283 | F27 |
| q-af9cd4edad | check C149 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*Invoke-* OR powershell.script_block_text:*Exploit*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "ev… | 16 |  |
| q-3d537fb3a4 | check C150 | search | {"dataset": "windows.other", "query": "message:*exploit*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destin… | 0 |  |
| q-44f5de5fe1 | check C151 | search | {"dataset": "zeek", "query": "event.action:notice OR event.action:weird", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "sour… | 14 |  |
| q-95d59dc6a8 | check C152 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 460 |  |
| q-06e76ced0b | check C153 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*cookie* OR process.command_line:*Cookie*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.nam… | 5 | F28 |
| q-f0eb1e4a20 | check C154 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1649 |  |
| q-cc933c2efd | check C155 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (win.TargetFilename:*Cookies* OR win.TargetFilename:*cookie*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "pr… | 1 | F29 |
| q-5f47730796 | check C156 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-2403755640 | check C157 | search | {"dataset": "windows.sysmon", "query": "event.code:2 AND (win.TargetFilename:*Cookies* OR win.TargetFilename:*cookie*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "pro… | 0 |  |
| q-bb10b8d19a | check C158 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*cookie* OR powershell.script_block_text:*Cookie*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "even… | 0 |  |
| q-9eac2a1e26 | check C159 | search | {"dataset": "windows.other", "query": "message:*cookie*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destina… | 0 |  |
| q-2dca429b9c | check C160 | search | {"dataset": "zeek", "query": "event.action:http AND http.request.method:GET", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "… | 2 |  |
| q-9b8affda1a | check C161 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 460 |  |
| q-185ac54843 | check C162 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*password* OR process.command_line:*credential* OR process.command_line:*unattend*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name",… | 0 |  |
| q-f8892a6a21 | check C163 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1649 |  |
| q-92801ff802 | check C164 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (win.TargetFilename:*unattend* OR win.TargetFilename:*password* OR win.TargetFilename:*credential*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.da… | 1 | F31 |
| q-4a9b5ea69b | check C165 | aggregate | {"dataset": "windows.sysmon", "field": "registry.path", "query": "event.code:13 OR event.code:14", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 17541 |  |
| q-537a437cfb | check C166 | search | {"dataset": "windows.sysmon", "query": "event.code:13 AND (registry.path:*Password* OR registry.path:*Credential*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process… | 17 | F34 |
| q-167f1247ce | check C167 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*password* OR powershell.script_block_text:*credential*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset",… | 2 |  |
| q-33f4ec322b | check C168 | search | {"dataset": "windows.other", "query": "message:*password*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 0 |  |
| q-e5a5f91f87 | check C169 | search | {"dataset": "zeek", "query": "event.action:smb_files", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinatio… | 12 | F33 |
| q-d4996d93ef | check C170 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 297 |  |
| q-d74edeaf28 | check C171 | search | {"dataset": "windows.security", "query": "event.code:4648", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 15 | F32 |
| q-7fe545a996 | check C172 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 447 |  |
| q-693621dc87 | check C173 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*password* OR process.command_line:*credential* OR process.command_line:*config*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event… | 8 |  |
| q-57e0d90a16 | check C174 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1649 |  |
| q-ab16edc9e8 | check C175 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (win.TargetFilename:*.config OR win.TargetFilename:*.xml OR win.TargetFilename:*.txt)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event… | 44 |  |
| q-c392f661b9 | check C176 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*Get-Content* OR powershell.script_block_text:*Select-String*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dat… | 1 |  |
| q-f049133960 | check C177 | search | {"dataset": "windows.other", "query": "message:*password*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 0 |  |
| q-1ed9c738d5 | check C178 | search | {"dataset": "zeek", "query": "event.action:smb_files", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinatio… | 12 |  |
| q-e10ab2a811 | check C179 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"13\" AND (TO_LOWER(registry.path) LIKE \"*\\\\sam\\\\*\" OR TO_LOWER(registry.path) LIKE \"*\\\\security\\\\*\" OR TO_LOWER(registry.path) LIKE \"*password*\" OR TO_LOWER… | ERROR |  |
| q-b580e01c6a | check C179 (repaired) | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"13\" AND (TO_LOWER(registry.path) LIKE \"*\\\\\\\\sam\\\\\\\\*\" OR TO_LOWER(registry.path) LIKE \"*\\\\\\\\security\\\\\\\\*\" OR TO_LOWER(registry.path) LIKE \"*passwor… | 60 |  |
| q-5650158e17 | check C180 | aggregate | {"dataset": "windows.sysmon", "field": "registry.path", "query": "event.code:13", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 17541 |  |
| q-f31fbc0afa | check C181 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*reg query*\" OR TO_LOWER(process.command_line) LIKE \"*reg save*\" OR TO_LOWER(process.command_line) LIKE \"*\\\\sam*\" OR… | ERROR |  |
| q-9d2df0627f | check C181 (repaired) | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*reg query*\" OR TO_LOWER(process.command_line) LIKE \"*reg save*\" OR TO_LOWER(process.command_line) LIKE \"*sam*\" OR TO_… | 5 |  |
| q-872427c27b | check C182 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4663\",\"4656\",\"4670\",\"4658\") AND (TO_LOWER(win.ObjectName) LIKE \"*\\\\sam*\" OR TO_LOWER(win.ObjectName) LIKE \"*\\\\security*\" OR TO_LOWER(win.ObjectName) LIK… | ERROR |  |
| q-b8fd806aed | check C182 (repaired) | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4663\",\"4656\",\"4670\",\"4658\") AND (TO_LOWER(win.ObjectName) LIKE \"*\\\\\\\\sam*\" OR TO_LOWER(win.ObjectName) LIKE \"*\\\\\\\\security*\" OR TO_LOWER(win.ObjectN… | 500 |  |
| q-22c4b7ba68 | check C183 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code IN (\"4103\",\"4104\") AND (TO_LOWER(COALESCE(powershell.script_block_text, win.ScriptBlockText, \"\")) LIKE \"*reg query*\" OR TO_LOWER(COALESCE(powershell.script_block_t… | 1 |  |
| q-67f8acdfde | check C184 | esql | {"query": "FROM logs-windows.other-default METADATA _id, _index \| WHERE TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*\\\\sam*\" OR TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*\\\\security*\" OR TO_LOWER(COALESCE(message, win.Message, \"\"… | ERROR |  |
| q-61f27d5612 | check C184 (repaired) | esql | {"query": "FROM logs-windows.other-default METADATA _id, _index \| WHERE TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*sam*\" OR TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*security*\" OR TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE … | 12 |  |
| q-1eafe5ae04 | check C185 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code IN (\"4103\",\"4104\") AND (TO_LOWER(COALESCE(powershell.script_block_text, win.ScriptBlockText, \"\")) LIKE \"*history*\" OR TO_LOWER(COALESCE(powershell.script_block_tex… | 1 |  |
| q-aaa24e7398 | check C186 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*consolehost_history*\" OR TO_LOWER(process.command_line) LIKE \"*psreadline*\" OR TO_LOWER(process.command_line) LIKE \"*h… | 0 |  |
| q-2708b27511 | check C187 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*consolehost_history*\" OR TO_LOWER(file.path) LIKE \"*psreadline*\" OR TO_LOWER(file.path) LIKE \"*\\\\history*\" OR TO_LOWER(file.p… | ERROR |  |
| q-eae4557829 | check C187 (repaired) | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*consolehost_history*\" OR TO_LOWER(file.path) LIKE \"*psreadline*\" OR TO_LOWER(file.path) LIKE \"*history*\" OR TO_LOWER(file.path)… | 15 |  |
| q-b1fdb6a9ca | check C188 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4663\",\"4656\",\"4658\") AND (TO_LOWER(win.ObjectName) LIKE \"*consolehost_history*\" OR TO_LOWER(win.ObjectName) LIKE \"*psreadline*\" OR TO_LOWER(win.ObjectName) LI… | 0 |  |
| q-c1415456ca | check C189 | esql | {"query": "FROM logs-windows.other-default METADATA _id, _index \| WHERE TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*history*\" OR TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*psreadline*\" \| KEEP @timestamp, host.name, event.code, messag… | 5 |  |
| q-af8abc0b8b | check C190 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*.key\" OR TO_LOWER(file.path) LIKE \"*.pgp\" OR TO_LOWER(file.path) LIKE \"*.gpg\" OR TO_LOWER(file.path) LIKE \"*.ppk\" OR TO_LOWER… | 1 |  |
| q-554f1aeac6 | check C191 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*.pem*\" OR TO_LOWER(process.command_line) LIKE \"*.pfx*\" OR TO_LOWER(process.command_line) LIKE \"*.p12*\" OR TO_LOWER(pr… | 0 |  |
| q-7cb6fb16fe | check C192 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"5145\" AND (TO_LOWER(win.RelativeTargetName) LIKE \"*.key\" OR TO_LOWER(win.RelativeTargetName) LIKE \"*.pem\" OR TO_LOWER(win.RelativeTargetName) LIKE \"*.pfx\" OR TO_… | 0 |  |
| q-d3244b6477 | check C193 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4663\",\"4656\",\"4658\") AND (TO_LOWER(win.ObjectName) LIKE \"*.key\" OR TO_LOWER(win.ObjectName) LIKE \"*.pem\" OR TO_LOWER(win.ObjectName) LIKE \"*.pfx\" OR TO_LOWE… | 0 |  |
| q-f03a389202 | check C194 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code IN (\"4103\",\"4104\") AND (TO_LOWER(COALESCE(powershell.script_block_text, win.ScriptBlockText, \"\")) LIKE \"*.pem*\" OR TO_LOWER(COALESCE(powershell.script_block_text, … | 2 |  |
| q-b9aeb6cda9 | check C195 | esql | {"query": "FROM logs-windows.other-default METADATA _id, _index \| WHERE TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*.pem*\" OR TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*.pfx*\" OR TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*… | 0 |  |
| q-ff8e97f9bb | check C196 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code IN (\"4103\",\"4104\") AND (TO_LOWER(COALESCE(powershell.script_block_text, win.ScriptBlockText, \"\")) LIKE \"*groups.xml*\" OR TO_LOWER(COALESCE(powershell.script_block_… | 32 |  |
| q-afb19e6e44 | check C197 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*sysvol*\" OR TO_LOWER(process.command_line) LIKE \"*groups.xml*\" OR TO_LOWER(process.command_line) LIKE \"*cpassword*\" O… | 0 |  |
| q-420f6f719d | check C198 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*groups.xml*\" OR TO_LOWER(file.path) LIKE \"*sysvol*\" OR TO_LOWER(file.path) LIKE \"*gpprefdecrypt*\" OR TO_LOWER(file.path) LIKE \… | 22 |  |
| q-30f7b0b3cf | check C199 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"5145\" AND (TO_LOWER(win.RelativeTargetName) LIKE \"*groups.xml*\" OR TO_LOWER(win.ShareName) LIKE \"*sysvol*\" OR TO_LOWER(win.ShareName) LIKE \"*netlogon*\") \| KEEP … | 56 |  |
| q-d04e13bdbe | check C200 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4663\",\"4656\",\"4658\") AND (TO_LOWER(win.ObjectName) LIKE \"*groups.xml*\" OR TO_LOWER(win.ObjectName) LIKE \"*sysvol*\" OR TO_LOWER(win.ObjectName) LIKE \"*gpp*\")… | 0 |  |
| q-6336ba4e1c | check C201 | esql | {"query": "FROM logs-windows.other-default METADATA _id, _index \| WHERE TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*sysvol*\" OR TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*groups.xml*\" OR TO_LOWER(COALESCE(message, win.Message, \"\")) … | 0 |  |
| q-a2a6e05d36 | check C202 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND (TO_LOWER(win.TargetImage) LIKE \"*lsass.exe\" OR TO_LOWER(win.SourceImage) LIKE \"*lsass.exe\") \| KEEP @timestamp, host.name, user.name, win.SourceImage, win.T… | 500 |  |
| q-a20dbbfed4 | check C203 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass.exe", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-14e3853af9 | check C204 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*sekurlsa*\" OR TO_LOWER(process.command_line) LIKE \"*lsadump*\" OR TO_LOWER(process.command_line) LIKE \"*mimikatz*\" OR … | 0 |  |
| q-a5bd047fae | check C205 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4663\",\"4656\",\"4670\",\"4658\") AND (TO_LOWER(win.ObjectName) LIKE \"*\\\\protect\\\\*\" OR TO_LOWER(win.ObjectName) LIKE \"*credential*\" OR TO_LOWER(win.ObjectNam… | ERROR |  |
| q-43550ffe48 | check C205 (repaired) | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4663\",\"4656\",\"4670\",\"4658\") AND (TO_LOWER(win.ObjectName) LIKE \"*protect*\" OR TO_LOWER(win.ObjectName) LIKE \"*credential*\" OR TO_LOWER(win.ObjectName) LIKE … | 19 | F38 |
| q-3e9e8a1d42 | check C206 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4688\" AND (TO_LOWER(process.command_line) LIKE \"*sekurlsa*\" OR TO_LOWER(process.command_line) LIKE \"*lsadump*\" OR TO_LOWER(process.command_line) LIKE \"*mimikatz*\… | 0 |  |
| q-ba2211f31a | check C207 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code IN (\"4103\",\"4104\") AND (TO_LOWER(COALESCE(powershell.script_block_text, win.ScriptBlockText, \"\")) LIKE \"*sekurlsa*\" OR TO_LOWER(COALESCE(powershell.script_block_te… | 5 |  |
| q-7147ac0c9b | check C208 | esql | {"query": "FROM logs-windows.other-default METADATA _id, _index \| WHERE TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*lsass*\" OR TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*credential*\" OR TO_LOWER(COALESCE(message, win.Message, \"\")) L… | 2 |  |
| q-3674856cc9 | check C209 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*login data*\" OR TO_LOWER(process.command_line) LIKE \"*\\\\google\\\\chrome\\\\user data*\" OR TO_LOWER(process.command_l… | ERROR |  |
| q-341a62e519 | check C209 (repaired) | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*login data*\" OR TO_LOWER(process.command_line) LIKE \"*google*chrome*user data*\" OR TO_LOWER(process.command_line) LIKE … | 0 |  |
| q-fa964960d5 | check C210 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*login data*\" OR TO_LOWER(file.path) LIKE \"*logins.json*\" OR TO_LOWER(file.path) LIKE \"*key3.db*\" OR TO_LOWER(file.path) LIKE \"… | ERROR |  |
| q-9a1291e3df | check C210 (repaired) | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*login data*\" OR TO_LOWER(file.path) LIKE \"*logins.json*\" OR TO_LOWER(file.path) LIKE \"*key3.db*\" OR TO_LOWER(file.path) LIKE \"… | 0 |  |
| q-e67b5eef09 | check C211 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND (TO_LOWER(win.TargetImage) LIKE \"*chrome.exe\" OR TO_LOWER(win.TargetImage) LIKE \"*firefox.exe\" OR TO_LOWER(win.TargetImage) LIKE \"*msedge.exe\" OR TO_LOWER(… | 0 |  |
| q-a7b89c8b19 | check C212 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4663\",\"4656\",\"4658\") AND (TO_LOWER(win.ObjectName) LIKE \"*login data*\" OR TO_LOWER(win.ObjectName) LIKE \"*logins.json*\" OR TO_LOWER(win.ObjectName) LIKE \"*ke… | ERROR |  |
| q-4a5f752586 | check C212 (repaired) | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4663\",\"4656\",\"4658\") AND (TO_LOWER(win.ObjectName) LIKE \"*login data*\" OR TO_LOWER(win.ObjectName) LIKE \"*logins.json*\" OR TO_LOWER(win.ObjectName) LIKE \"*ke… | 0 |  |
| q-e06bdda940 | check C213 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code IN (\"4103\",\"4104\") AND (TO_LOWER(COALESCE(powershell.script_block_text, win.ScriptBlockText, \"\")) LIKE \"*login data*\" OR TO_LOWER(COALESCE(powershell.script_block_… | 0 |  |
| q-40031a3bd4 | check C214 | esql | {"query": "FROM logs-windows.other-default METADATA _id, _index \| WHERE TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*login data*\" OR TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*logins.json*\" OR TO_LOWER(COALESCE(message, win.Message, \"… | 0 |  |
| q-b3595a0a5e | check C215 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 326 |  |
| q-59b6168dbe | check C216 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-a263da2a6c | check C217 | search | {"dataset": "windows.sysmon", "query": "event.code:15 AND file.path:*Credentials*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 0 |  |
| q-1df9e5b8b0 | check C218 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*vault* OR process.command_line:*Credential* OR process.command_line:*cmdkey*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "eve… | 0 |  |
| q-2e68af6fa7 | check C219 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*Credential* OR powershell.script_block_text:*vault* OR powershell.script_block_text:*cmdkey*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.na… | 3 |  |
| q-e5bfb63f16 | check C220 | search | {"dataset": "windows.other", "query": "message:*Credential* OR message:*vault*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line"… | 2 | F37 |
| q-60fed92948 | check C221 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.executable:*keepass* OR process.executable:*1password* OR process.executable:*bitwarden* OR process.executable:*lastpass* OR process.executable:*dashlane*)", "time_from": null, "time_to": null, … | 0 |  |
| q-a734cc392a | check C222 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*keepass* OR file.path:*1password* OR file.path:*bitwarden* OR file.path:*lastpass*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.datase… | 0 |  |
| q-49b726ac70 | check C223 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND (win.TargetImage:*keepass* OR win.TargetImage:*1password* OR win.TargetImage:*bitwarden*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "e… | 0 |  |
| q-3d34283bde | check C224 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*keepass* OR process.command_line:*1password* OR process.command_line:*bitwarden* OR process.command_line:*kdbx*)", "time_from": null, "time_to": null, "fields": ["@timestamp",… | 0 |  |
| q-b358475404 | check C225 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*keepass* OR powershell.script_block_text:*kdbx* OR powershell.script_block_text:*1password* OR powershell.script_block_text:*bitwarden*)", "time_from": null, "time_t… | 0 |  |
| q-749f0bf956 | check C226 | search | {"dataset": "windows.other", "query": "message:*keepass* OR message:*1password* OR message:*bitwarden* OR message:*kdbx*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "p… | 0 |  |
| q-c1036766c1 | check C227 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 326 |  |
| q-b7e647baf2 | check C228 | aggregate | {"dataset": "windows.sysmon", "field": "win.SourceImage", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-726d09e771 | check C229 | search | {"dataset": "windows.sysmon", "query": "event.code:7 AND (win.ImageLoaded:*lsass* OR win.ImageLoaded:*cryptdll* OR win.ImageLoaded:*sam* OR win.ImageLoaded:*msv1_0*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "… | 77 |  |
| q-a3001ed072 | check C230 | search | {"dataset": "windows.security", "query": "event.code:4657 AND (win.ObjectName:*lsass* OR win.ObjectName:*cryptdll* OR win.ObjectName:*msv1_0* OR win.ObjectName:*sam*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", … | 0 |  |
| q-8c8048f3eb | check C231 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*lsass* OR process.command_line:*cryptdll* OR process.command_line:*msv1_0*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event… | 0 |  |
| q-1541553aab | check C232 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*lsass* OR powershell.script_block_text:*cryptdll* OR powershell.script_block_text:*msv1_0* OR powershell.script_block_text:*SecurityPackages*)", "time_from": null, "… | 0 |  |
| q-0ffe0d1393 | check C233 | search | {"dataset": "windows.other", "query": "message:*lsass* OR message:*cryptdll* OR message:*msv1_0*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "pro… | 0 |  |
| q-173c62e211 | check C234 | search | {"dataset": "windows.security", "query": "event.code:4624 AND win.LogonType:3", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line",… | 218 | F40 |
| q-24eb559974 | check C235 | search | {"dataset": "windows.security", "query": "event.code:4648", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 15 |  |
| q-1928e25042 | check C236 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4624 OR event.code:4648", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 312 |  |
| q-2d081acfc7 | check C237 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 326 |  |
| q-144d6a82a2 | check C238 | search | {"dataset": "windows.sysmon", "query": "event.code:7 AND (win.ImageLoaded:*lsass* OR win.ImageLoaded:*cryptdll*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.e… | 33 |  |
| q-0adfdf6d22 | check C239 | search | {"dataset": "windows.other", "query": "message:*lsass* OR message:*cryptdll*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 0 |  |
| q-6f0820af94 | check C240 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*lsass* OR powershell.script_block_text:*cryptdll* OR powershell.script_block_text:*Skeleton* OR powershell.script_block_text:*DCShadow*)", "time_from": null, "time_t… | 0 |  |
| q-3afbaea652 | check C241 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*System32* AND (file.path:*.dll))", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable"… | 0 |  |
| q-2f22b77871 | check C242 | search | {"dataset": "windows.sysmon", "query": "event.code:7 AND (win.ImageLoaded:*lsass* OR win.ImageLoaded:*cryptdll*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.e… | 33 |  |
| q-dd8271af7d | check C243 | search | {"dataset": "windows.security", "query": "event.code:4657 AND (win.ObjectName:*Notification\\ Packages* OR win.ObjectName:*Password* OR win.ObjectName:*lsass*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.… | 0 |  |
| q-222f78255c | check C244 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*Notification* OR process.command_line:*PasswordFilter*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.co… | 0 |  |
| q-e10cf644eb | check C245 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*Notification* OR powershell.script_block_text:*PasswordFilter* OR powershell.script_block_text:*lsass*)", "time_from": null, "time_to": null, "fields": ["@timestamp"… | 0 |  |
| q-81754cfdc1 | check C246 | search | {"dataset": "windows.other", "query": "message:*Notification* OR message:*PasswordFilter* OR message:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.execu… | 10 |  |
| q-2455efc05c | check C247 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*AllowReversiblePasswordEncryption* OR powershell.script_block_text:*ReversibleEncryption* OR powershell.script_block_text:*Set-ADUser*)", "time_from": null, "time_to… | 1 |  |
| q-32b15d04b7 | check C248 | search | {"dataset": "windows.powershell", "query": "event.code:4103 AND (message:*AllowReversiblePasswordEncryption* OR message:*ReversibleEncryption*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event… | 0 |  |
| q-0eab184ae3 | check C249 | search | {"dataset": "windows.security", "query": "event.code:4739", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 0 |  |
| q-d2197dcc99 | check C250 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*Reversible* OR process.command_line:*Set-ADUser* OR process.command_line:*dsmod*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", … | 0 |  |
| q-ae99c2d226 | check C251 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*Reversible* OR process.command_line:*Set-ADUser* OR process.command_line:*dsmod*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "even… | 0 |  |
| q-82036a0a0b | check C252 | search | {"dataset": "windows.other", "query": "message:*Reversible* OR message:*AllowReversiblePasswordEncryption*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executa… | 0 |  |
| q-15fd9feab0 | check C253 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(powershell.script_block_text) LIKE \"*set-aduser*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*set-adauthenticationpolicy*\" OR TO_LOWER(powershell.script_block_text)… | 1 |  |
| q-7cb9a85cd2 | check C254 | count | {"dataset": "windows.security", "query": "event.code:4739", "time_from": null, "time_to": null} | 0 |  |
| q-e74f46e032 | check C255 | aggregate | {"dataset": "windows.security", "field": "win.ObjectType", "query": "event.code:5136 OR event.code:4739", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-7278800f4c | check C256 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*set-aduser*\" OR TO_LOWER(process.command_line) LIKE \"*set-adauthenticationpolicy*\" OR TO_LOWER(process.command_line) LI… | 0 |  |
| q-e25c287f3b | check C257 | search | {"dataset": "windows.other", "query": "event.code:4739 OR event.code:5136 OR event.code:4738", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process… | 0 |  |
| q-ee375b1209 | check C258 | aggregate | {"dataset": "windows.security", "field": "win.LogonProcessName", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 297 |  |
| q-0b6d6780b1 | check C259 | aggregate | {"dataset": "windows.security", "field": "win.AuthenticationPackageName", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 297 |  |
| q-6654fbdfd1 | check C260 | count | {"dataset": "windows.security", "query": "event.code:5136", "time_from": null, "time_to": null} | 0 |  |
| q-25611df3e8 | check C261 | aggregate | {"dataset": "windows.sysmon", "field": "win.ImageLoaded", "query": "event.code:7", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 20259 |  |
| q-19931e22f4 | check C262 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(powershell.script_block_text) LIKE \"*connect-msolservice*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*connect-azuread*\" OR TO_LOWER(powershell.script_block_text) L… | 0 |  |
| q-3b6106c5af | check C263 | search | {"dataset": "windows.other", "query": "event.code:5136 OR event.code:4739 OR event.code:4738", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process… | 0 |  |
| q-3c09a53a0e | check C264 | count | {"dataset": "windows.security", "query": "event.code:4657", "time_from": null, "time_to": null} | 36 |  |
| q-fea3bb922b | check C265 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4657\" AND (TO_LOWER(win.ObjectName) LIKE \"*networkprovider*\" OR TO_LOWER(win.ObjectName) LIKE \"*credential*\" OR TO_LOWER(win.ObjectName) LIKE \"*winlogon*\") \| KE… | 0 |  |
| q-f0d1dff6fe | check C266 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*networkprovider*\" OR TO_LOWER(file.path) LIKE \"*system32*credential*\" OR TO_LOWER(file.path) LIKE \"*winlogon*\") \| KEEP @timest… | 1 |  |
| q-c7eee28c61 | check C267 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 39283 |  |
| q-c86c366270 | check C268 | aggregate | {"dataset": "windows.sysmon", "field": "win.ImageLoaded", "query": "event.code:7", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 20259 |  |
| q-60a21a2cba | check C269 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(powershell.script_block_text) LIKE \"*networkprovider*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*new-itemproperty*\" OR TO_LOWER(powershell.script_block_text) LIKE… | 0 |  |
| q-954e4f2898 | check C270 | search | {"dataset": "windows.other", "query": "event.code:4657 OR event.code:11 OR event.code:7", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.comm… | 4 |  |
| q-eadc0a1d92 | check C271 | aggregate | {"dataset": "windows.security", "field": "win.ObjectType", "query": "event.code:4663 OR event.code:4670 OR event.code:4656", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 10977 |  |
| q-e8161d1047 | check C272 | aggregate | {"dataset": "windows.security", "field": "win.ProcessName", "query": "event.code:4663 OR event.code:4670 OR event.code:4656", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 10977 |  |
| q-316c230659 | check C273 | aggregate | {"dataset": "windows.sysmon", "field": "win.DestinationHostname", "query": "event.code:3", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 1229 |  |
| q-27509082c8 | check C274 | aggregate | {"dataset": "windows.sysmon", "field": "win.QueryName", "query": "event.code:22", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 81 |  |
| q-3dc8c6239d | check C275 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(powershell.script_block_text) LIKE \"*responder*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*mitm*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*arpspoof*\" OR… | 0 |  |
| q-59b76e9dd8 | check C276 | search | {"dataset": "windows.other", "query": "event.code:4663 OR event.code:4670 OR event.code:4656 OR event.code:3 OR event.code:22", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name… | 2 |  |
| q-caa763340f | check C277 | aggregate | {"dataset": "zeek", "field": "zeek.conn_state", "query": "event.action:conn", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 613 |  |
| q-9059a5825d | check C278 | aggregate | {"dataset": "zeek", "field": "zeek.service", "query": "event.action:conn", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 613 |  |
| q-a6886b44ff | check C279 | count | {"dataset": "windows.security", "query": "event.code:4697", "time_from": null, "time_to": null} | 23 |  |
| q-2030e1b5f9 | check C280 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4657\" AND TO_LOWER(win.ObjectName) LIKE \"*dnsclient*\" \| KEEP @timestamp, host.name, user.name, win.ObjectName, win.NewValue, _id, _index"} | 0 |  |
| q-ffde8d2c69 | check C281 | aggregate | {"dataset": "windows.sysmon", "field": "win.DestinationHostname", "query": "event.code:3", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 1229 |  |
| q-ec02ad1b35 | check C282 | aggregate | {"dataset": "windows.sysmon", "field": "win.QueryName", "query": "event.code:22", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 81 |  |
| q-f3a3a265e3 | check C283 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(powershell.script_block_text) LIKE \"*llmnr*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*nbt-ns*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*responder*\" OR … | 0 |  |
| q-866ad057f3 | check C284 | search | {"dataset": "windows.other", "query": "event.code:4697 OR event.code:4657 OR event.code:3 OR event.code:22", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executa… | 2 |  |
| q-ccb0544ebe | check C285 | aggregate | {"dataset": "zeek", "field": "zeek.id_resp_h", "query": "event.action:conn AND zeek.service:smb", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-f9e62ea533 | check C286 | aggregate | {"dataset": "zeek", "field": "zeek.query", "query": "event.action:dns", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 53 |  |
| q-540f547166 | check C287 | aggregate | {"dataset": "windows.sysmon", "field": "win.DestinationHostname", "query": "event.code:3", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 1229 |  |
| q-de2527184c | check C288 | aggregate | {"dataset": "windows.sysmon", "field": "win.QueryName", "query": "event.code:22", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 81 |  |
| q-92186b06bb | check C289 | aggregate | {"dataset": "windows.security", "field": "win.ProcessName", "query": "event.code:4663 OR event.code:4670 OR event.code:4656", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 10977 |  |
| q-83ab616425 | check C290 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(powershell.script_block_text) LIKE \"*arp*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*netsh interface*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*get-netne… | 0 |  |
| q-c2b72077b9 | check C291 | search | {"dataset": "windows.other", "query": "event.code:3 OR event.code:22 OR event.code:4663 OR event.code:4670", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executa… | 2 |  |
| q-28edcfeffa | check C292 | aggregate | {"dataset": "zeek", "field": "zeek.orig_l2_addr", "query": "event.action:conn", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 613 |  |
| q-7b80b1d85e | check C293 | aggregate | {"dataset": "zeek", "field": "zeek.resp_l2_addr", "query": "event.action:conn", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 613 |  |
| q-30b3247c4d | check C294 | search | {"dataset": "windows.other", "query": "event.code:(1341 OR 1342 OR 1020 OR 1063)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_lin… | 0 |  |
| q-f72697e4fa | check C295 | aggregate | {"dataset": "windows.other", "field": "event.code", "query": "*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 216 |  |
| q-b5e6c21db7 | check C296 | search | {"dataset": "windows.security", "query": "event.code:5156 AND win.Direction:Inbound", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_… | 0 |  |
| q-adf47ac81b | check C297 | aggregate | {"dataset": "windows.sysmon", "field": "destination.port", "query": "event.code:3", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1229 |  |
| q-2253678acf | check C298 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:(*Dhcp* OR *dhcp*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.… | 0 |  |
| q-c44b9e4f08 | check C299 | aggregate | {"dataset": "zeek", "field": "event.action", "query": "*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 2140 |  |
| q-fe6d27a7ed | check C300 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4672", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 212 |  |
| q-368faf51b1 | check C301 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 297 |  |
| q-44da23674e | check C302 | search | {"dataset": "windows.security", "query": "event.code:4634", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 236 |  |
| q-9cc4c10d7d | check C303 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-ece46045c3 | check C304 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-f4da71f568 | check C305 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:(*kerberos* OR *Kerberos* OR *ticket* OR *Ticket*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name",… | 0 |  |
| q-1ea4966e06 | check C306 | search | {"dataset": "windows.other", "query": "event.code:(7045 OR 7040)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip",… | 9 |  |
| q-04b09a15be | check C307 | aggregate | {"dataset": "zeek", "field": "zeek.request_type", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 35 |  |
| q-1a2121e85d | check C308 | search | {"dataset": "windows.security", "query": "event.code:4769", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 28 |  |
| q-ef3535123d | check C309 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4672", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 212 |  |
| q-3a20a9211e | check C310 | aggregate | {"dataset": "windows.security", "field": "win.TicketEncryptionType", "query": "event.code:4769", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 28 |  |
| q-ba8feb24ef | check C311 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-f272f69156 | check C312 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:(*golden* OR *Golden* OR *krbtgt* OR *KRBTGT*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "pr… | 0 |  |
| q-04562d5070 | check C313 | aggregate | {"dataset": "windows.other", "field": "event.code", "query": "*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 216 |  |
| q-5a69fddd88 | check C314 | aggregate | {"dataset": "zeek", "field": "zeek.request_type", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 35 |  |
| q-e6ed3c0855 | check C315 | search | {"dataset": "windows.security", "query": "event.code:4769", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 28 |  |
| q-e6db41206d | check C316 | aggregate | {"dataset": "windows.security", "field": "win.ServiceName", "query": "event.code:4769", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 28 |  |
| q-555627fe23 | check C317 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4672", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 212 |  |
| q-118aa46dbb | check C318 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-d0d2b6d98a | check C319 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:(*silver* OR *Silver* OR *service ticket* OR *SPN*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name"… | 0 |  |
| q-234a816de8 | check C320 | search | {"dataset": "windows.other", "query": "event.code:(7045 OR 7040)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip",… | 9 |  |
| q-3ae831ccf9 | check C321 | aggregate | {"dataset": "zeek", "field": "zeek.request_type", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 35 |  |
| q-4e30d04378 | check C322 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4769", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 28 |  |
| q-c6c19dba68 | check C323 | aggregate | {"dataset": "windows.security", "field": "win.TicketEncryptionType", "query": "event.code:4769", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 28 |  |
| q-c8719c8b9f | check C324 | search | {"dataset": "windows.security", "query": "event.code:4648", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 15 |  |
| q-921b6a3082 | check C325 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 297 |  |
| q-3ed5b1a6a7 | check C326 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-0767c7dac9 | check C327 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:(*Kerberoast* OR *kerberoast* OR *Invoke-Kerberoast* OR *Rubeus*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code… | 0 |  |
| q-3e44365622 | check C328 | aggregate | {"dataset": "windows.other", "field": "event.code", "query": "*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 216 |  |
| q-8614a7ace1 | check C329 | aggregate | {"dataset": "zeek", "field": "zeek.request_type", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 35 |  |
| q-5fb37a0b10 | check C330 | search | {"dataset": "windows.security", "query": "event.code:4768", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 14 |  |
| q-3ee2be2bc6 | check C331 | aggregate | {"dataset": "windows.security", "field": "win.PreAuthType", "query": "event.code:4768", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 14 |  |
| q-2771502b38 | check C332 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4768", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 14 |  |
| q-b21530b3e8 | check C333 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 447 |  |
| q-ab22fb4877 | check C334 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:(*AS-REP* OR *asrep* OR *GetNPUsers* OR *DontRequirePreAuth*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "… | 0 |  |
| q-16e40dcbab | check C335 | aggregate | {"dataset": "windows.other", "field": "event.code", "query": "*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 216 |  |
| q-493f6d1d50 | check C336 | aggregate | {"dataset": "zeek", "field": "zeek.request_type", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 35 |  |
| q-fbb6e58994 | check C337 | aggregate | {"dataset": "windows.security", "field": "win.LogonProcessName", "query": "event.code:4624 OR event.code:4648", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 312 |  |
| q-d22e5ce6d2 | check C338 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-823a3069f6 | check C339 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*cookie* OR powershell.script_block_text:*token* OR powershell.script_block_text:*SAML*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "… | 1 |  |
| q-019fd36a35 | check C340 | search | {"dataset": "windows.other", "query": "event.code:7045 OR event.code:5857 OR event.code:5858", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process… | 90 |  |
| q-aefa207be5 | check C341 | aggregate | {"dataset": "zeek", "field": "event.action", "query": "event.action:http OR event.action:ssl OR event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 475 |  |
| q-89395090e4 | check C342 | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11 AND (file.path:*cookie* OR file.path:*Cookies*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1 |  |
| q-3bfaf6f966 | check C343 | aggregate | {"dataset": "windows.security", "field": "win.LogonProcessName", "query": "event.code:4624 OR event.code:4648", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 312 |  |
| q-2bcc253af6 | check C344 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*cookie* OR powershell.script_block_text:*Set-Cookie* OR powershell.script_block_text:*session*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.… | 1 |  |
| q-29ac84534b | check C345 | search | {"dataset": "windows.other", "query": "event.code:11 OR event.code:16", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source… | 9 |  |
| q-7077dbcb12 | check C346 | search | {"dataset": "zeek", "query": "event.action:http AND http.request.method:*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "so… | 62 | F52 |
| q-05a40a2040 | check C347 | aggregate | {"dataset": "windows.security", "field": "win.LogonProcessName", "query": "event.code:4624 OR event.code:4648", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 312 |  |
| q-c517f029a3 | check C348 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*SAML* OR powershell.script_block_text:*NotOnOrAfter* OR powershell.script_block_text:*Assertion*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "hos… | 0 |  |
| q-16c92c5ad3 | check C349 | search | {"dataset": "windows.other", "query": "event.code:7045 OR event.code:5857 OR event.code:5858", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process… | 90 |  |
| q-d257b20376 | check C350 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*saml* OR process.command_line:*token* OR process.command_line:*cert*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-0cc282fb07 | check C351 | search | {"dataset": "zeek", "query": "event.action:http AND (url.original:*saml* OR url.original:*adfs* OR url.original:*token*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "p… | 0 |  |
| q-ee090c41b2 | check C352 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-ea1c7dc6a2 | check C353 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-95fea4388f | check C354 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*MFA* OR powershell.script_block_text:*2FA* OR powershell.script_block_text:*Authenticator*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name… | 0 |  |
| q-da0d9095bd | check C355 | search | {"dataset": "windows.other", "query": "event.code:4625 OR event.code:5857 OR event.code:5858", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process… | 85 |  |
| q-2d68822ac5 | check C356 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*login* OR process.command_line:*auth* OR process.command_line:*mfa*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-b594c79517 | check C357 | search | {"dataset": "zeek", "query": "event.action:http AND (url.original:*login* OR url.original:*auth* OR url.original:*mfa*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "pr… | 0 |  |
| q-e4acbc68a5 | check C358 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4657", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 36 |  |
| q-e7fef29209 | check C359 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4768", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 14 |  |
| q-6a6a0ad85a | check C360 | aggregate | {"dataset": "windows.sysmon", "field": "registry.path", "query": "event.code:13 AND (registry.path:*Certificate* OR registry.path:*Crypto* OR registry.path:*Keys*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1133 |  |
| q-6798bd6490 | check C361 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*Certificate* OR powershell.script_block_text:*Export-PfxCertificate* OR powershell.script_block_text:*New-SelfSignedCertificate*)", "time_from": null, "time_to": nul… | 1 |  |
| q-5c3033d9bb | check C362 | search | {"dataset": "windows.other", "query": "event.code:7045 OR event.code:5857 OR event.code:5858", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process… | 90 |  |
| q-5173abdeb7 | check C363 | aggregate | {"dataset": "zeek", "field": "zeek.certificate_subject", "query": "event.action:x509", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 378 |  |
| q-af118f9f16 | triage T1003 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND (win.GrantedAccess:0x1fffff OR win.GrantedAccess:0x101001 OR win.GrantedAccess:0x1f3fff OR win.GrantedAccess:0x1000000 OR win.GrantedAccess:0x3000 OR win.GrantedAccess:0x1400… | 33 | F01 |
| q-c5ee98d9a1 | triage T1003 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:13 AND registry.path:*SECURITY*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_l… | 5 | F02, F04, F05 |
| q-1877b3010f | triage T1003 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k13y"} | None | F01, F06 |
| q-d88846d392 | triage T1003 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrM7IJ"} | None | F01 |
| q-c5f7bb1b52 | triage T1003 step 2 | search | {"dataset": "windows.security", "query": "event.code:(4656 OR 4663 OR 4670) AND (win.ObjectType:SAM_DOMAIN OR win.ObjectType:SAM_SERVER OR win.ObjectType:SAM_ALIAS)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "e… | 21 | F02 |
| q-b4860046b3 | triage T1003 step 3 | search | {"dataset": "windows.powershell", "query": "event.code:4104", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "powershell.script_block_text"], "size": 30, "sort": "asc"} | 414 |  |
| q-2f4d43ee35 | triage T1003 step 3 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YldM_i"} | None | F01 |
| q-b7c50359ed | triage T1003 step 4 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND @timestamp:[2020-05-02T03:04:00.000Z TO 2020-05-02T03:10:00.000Z]", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "powershell.script_block_text"], "size": … | 77 | F01 |
| q-5e2e8ca3d0 | triage T1003 step 4 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND process.parent.executable:*wsmprovhost*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "process.executable", "process.command_line", "process.parent.executable"]… | 0 |  |
| q-5c52bb9b40 | triage T1003 step 5 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND @timestamp:[2020-05-02T03:05:00.000Z TO 2020-05-02T03:06:30.000Z]", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "powershell.script_block_text"], "size": … | 13 |  |
| q-e2112f0da1 | triage T1003 step 5 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.executable:*wsmprovhost* OR process.parent.executable:*wsmprovhost* OR process.command_line:*Invoke-* OR process.command_line:*MiniDump*)", "time_from": null, "time_to": null, "fields": ["@times… | 2 |  |
| q-77e8f9b812 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k13y"} | None |  |
| q-d04176f9ed | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k13y"} | None |  |
| q-004737e4ce | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-64b1d590f4 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YldM_i"} | None |  |
| q-9e2aa97073 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YldM_i"} | None |  |
| q-b07a0eaa1b | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrM7IJ"} | None |  |
| q-b59b6bff9f | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrM7IJ"} | None |  |
| q-69c1744126 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None |  |
| q-dd269f625c | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YWMnGq"} | None |  |
| q-82ccfdbdde | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YWMnGq"} | None |  |
| q-3b6dacc59f | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RpKsLE"} | None |  |
| q-6593ab6eb5 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RpKsLE"} | None |  |
| q-40d3d6f733 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MtUmZF"} | None |  |
| q-ff52d8471e | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NAd3XG"} | None |  |
| q-a86c165a21 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RoJ7pL"} | None |  |
| q-3eb3f0d6e5 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k13y"} | None |  |
| q-4c91237bda | triage T1040 step 1 | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx2I"} | None |  |
| q-c390777c52 | triage T1040 step 1 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.executable:*NetworkWatcher* OR process.executable:*logman* OR process.executable:*netsh* OR process.executable:*pktmon*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host… | 13 | F07 |
| q-666650c35e | triage T1040 step 2 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*capture* OR process.command_line:*trace* OR process.command_line:*etl*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "process.execu… | 4 | F07 |
| q-05fd5e6ab1 | triage T1040 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*capture* OR process.command_line:*netsh* OR process.command_line:*pktmon* OR process.command_line:*NetworkWatcher*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "… | 7 | F07 |
| q-499cc31885 | triage T1040 step 3 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.executable:*python* OR process.executable:*PsExec* OR process.executable:*PSEXESVC* OR process.executable:*sdelete*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.nam… | 19 | F09 |
| q-cb82701d11 | triage T1040 step 3 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.executable:*python* OR process.executable:*PsExec* OR process.executable:*PSEXESVC*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "process.executable"… | 13 |  |
| q-8f80c45dde | triage T1040 step 4 | search | {"dataset": "windows.sysmon", "query": "event.code:3 AND process.executable:*python*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "process.executable", "process.command_line", "destination.ip", "destination.port", "n… | 348 | F09 |
| q-84c160d472 | triage T1040 step 4 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*socket* OR powershell.script_block_text:*sniff* OR powershell.script_block_text:*pcap* OR powershell.script_block_text:*raw* OR powershell.script_block_text:*promisc… | 5 | F09 |
| q-883e443450 | triage T1040 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*sniff*\" OR TO_LOWER(process.command_line) LIKE \"*promisc*\" OR TO_LOWER(process.command_line) LIKE \"*pcap*\" OR TO_LOWE… | 0 |  |
| q-67b2f0e190 | triage T1040 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"6\" AND (TO_LOWER(win.Image) LIKE \"*pcap*\" OR TO_LOWER(win.Image) LIKE \"*npcap*\" OR TO_LOWER(win.Image) LIKE \"*winpcap*\") \| KEEP @timestamp, host.name, win.Image, … | 0 |  |
| q-8a167d33e8 | triage T1040 step 6 | search | {"dataset": "windows.other", "query": "event.code:7045 AND (win.ServiceName:*Network* OR win.ServiceName:*Watcher* OR win.ImagePath:*NetworkWatcher*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "win.ServiceName", "w… | 0 |  |
| q-4557aaad4f | triage T1040 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YYOcv1"} | None |  |
| q-fec9198173 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YYOcv1"} | None |  |
| q-e0572db1bb | triage T1040 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YWMXHe"} | None |  |
| q-a1985b86f8 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NW1Kgv"} | None |  |
| q-c76710bec4 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx2T"} | None |  |
| q-b091038c16 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YcSP1_"} | None |  |
| q-1141b1de25 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RjDSP-"} | None |  |
| q-f62cb5a42f | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RjDSP-"} | None |  |
| q-712801c5d1 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b87aMP"} | None |  |
| q-171de33e85 | triage T1056 step 1 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1SIwN6W"} | None |  |
| q-2c850c0964 | triage T1056 step 1 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YldM_i"} | None |  |
| q-d744f88e96 | triage T1056 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 10 AND win.TargetImage LIKE \"*lsass*\" AND win.GrantedAccess != \"0x1000\" AND win.GrantedAccess != \"0x1400\" \| KEEP @timestamp, host.name, process.executable, win.Sourc… | ERROR |  |
| q-fee30fe08d | triage T1056 step 2 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == 4104 \| WHERE powershell.script_block_text LIKE \"*lsass*\" OR powershell.script_block_text LIKE \"*Credential*\" OR powershell.script_block_text LIKE \"*MiniDump*\" OR… | ERROR |  |
| q-efa247c1eb | triage T1056 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND win.TargetImage LIKE \"*lsass*\" AND win.GrantedAccess != \"0x1000\" AND win.GrantedAccess != \"0x1400\" \| KEEP @timestamp, host.name, process.executable, win.S… | 9 | F10 |
| q-8ac07031dc | triage T1056 step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" \| WHERE powershell.script_block_text LIKE \"*lsass*\" OR powershell.script_block_text LIKE \"*Credential*\" OR powershell.script_block_text LIKE \"*MiniDump*\… | 3 | F11, F13 |
| q-3d9d1f29f0 | triage T1056 step 4 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-34ea4f933f | triage T1056 step 4 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-8c821be764 | triage T1056 step 5 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE @timestamp >= \"2020-05-02T03:04:00.000Z\" AND @timestamp <= \"2020-05-02T03:10:00.000Z\" AND host.name == \"scranton.dmevals.local\" \| KEEP @timestamp, event.code, user.name, power… | 500 |  |
| q-49983bc9ce | triage T1056 step 5 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4688\" AND host.name == \"scranton.dmevals.local\" \| KEEP @timestamp, user.name, process.executable, process.command_line, win.ParentProcessName, _id, _index \| SORT @… | 370 | F11 |
| q-7f5461a895 | triage T1056 step 6 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4663\" AND win.ObjectType == \"Process\" \| KEEP @timestamp, host.name, user.name, win.ObjectName, win.AccessMask, win.ProcessName, _id, _index \| SORT @timestamp ASC"} | 6 | F10, F14 |
| q-d776b2c8e3 | triage T1056 step 6 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (process.command_line LIKE \"*monkey*\" OR process.command_line LIKE \"*noni*\" OR process.command_line LIKE \"*bypass*\" OR process.command_line LIKE \"*lsass*\"… | 2 | F10 |
| q-7d1c18510c | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-4209728e70 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-ebb55d06f9 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-f2dd240d2d | triage T1056 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YldM_j"} | None |  |
| q-5891377ac4 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YldM_j"} | None |  |
| q-4ea4583e6c | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1WdFNhN"} | None |  |
| q-9cfa7bb6a7 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YrjwVo"} | None |  |
| q-94daa64b56 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YsmIMu"} | None |  |
| q-f9462f3f61 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-5c298adf48 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YiZqBf"} | None |  |
| q-131a4a58d5 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1WhJHLy"} | None |  |
| q-6f8a758599 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1WhJHLy"} | None |  |
| q-0eb7218f4e | triage T1056 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-e6bff2b2d0 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YldM_j"} | None |  |
| q-39a23b732c | triage T1110 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None | F16 |
| q-98fbfb3205 | triage T1110 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None | F16 |
| q-abe0c75a82 | triage T1110 step 1 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YogQzA"} | None | F18 |
| q-1426d1d089 | triage T1110 step 1 | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx2T"} | None | F18 |
| q-c438513e2b | triage T1110 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND win.TargetImage LIKE \"*lsass*\" \| STATS c = COUNT(*) BY process.executable, win.GrantedAccess, host.name \| SORT c DESC \| LIMIT 30"} | 18 |  |
| q-f99d4f1fce | triage T1110 step 2 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4663\" AND win.ObjectName LIKE \"*SAM*\" \| KEEP @timestamp, host.name, win.ObjectName, win.ProcessName, win.AccessMask, user.name, _id, _index \| LIMIT 20"} | 0 |  |
| q-dd59e83d07 | triage T1110 step 2 | count | {"dataset": "windows.security", "query": "event.code:4625 OR event.code:4771 OR event.code:4776 OR event.code:4740", "time_from": null, "time_to": null} | 1 |  |
| q-5fbd76c846 | triage T1110 step 3 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4625\" OR event.code == \"4771\" OR event.code == \"4776\" OR event.code == \"4740\" \| KEEP @timestamp, host.name, event.code, win.TargetUserName, source.ip, win.Logon… | 1 | F15, F19 |
| q-4a203cb9f5 | triage T1110 step 3 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE win.ObjectName == \"SAM\" \| KEEP @timestamp, host.name, event.code, win.ObjectName, win.ProcessName, win.AccessMask, user.name, _id, _index \| LIMIT 15"} | 10 | F17 |
| q-5d192736ef | triage T1110 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND win.TargetImage LIKE \"*lsass*\" AND win.GrantedAccess IN (\"0x1fffff\",\"0x1f3fff\",\"0x101001\",\"0x3000\") \| KEEP @timestamp, host.name, process.executable, … | 8 | F17 |
| q-c3c788ff93 | triage T1110 step 4 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4648\" \| STATS c = COUNT(*) BY win.TargetUserName, win.ProcessName, host.name \| SORT c DESC \| LIMIT 20"} | 9 |  |
| q-9c61999de3 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YQHwYC"} | None |  |
| q-4c8f2b92e2 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx0y"} | None |  |
| q-dcef9b221d | triage T1110 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None |  |
| q-7367afabc1 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-1a878871dd | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YJECPG"} | None |  |
| q-6a25116548 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-cf8667d463 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YogQzA"} | None |  |
| q-13bff3f713 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx2T"} | None |  |
| q-ab92ff1737 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YQHwYC"} | None |  |
| q-8adaa2aaf0 | triage T1111 step 1 | search | {"dataset": "windows.security", "query": "event.code:4624 AND win.LogonType:2", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "win.LogonType", "win.AuthenticationPackageName", "win.LogonProcessName", "source.ip", "win.I… | 15 |  |
| q-305f0e787c | triage T1111 step 1 | search | {"dataset": "windows.security", "query": "event.code:4624 AND win.LogonType:10", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "win.LogonType", "win.AuthenticationPackageName", "win.LogonProcessName", "source.ip", "win.… | 2 |  |
| q-df77e3b821 | triage T1111 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "process.executable", "win.TargetImage", "win.GrantedAccess", "user.name"], "size": 30, "sort": "asc"} | 326 |  |
| q-8cca856550 | triage T1111 step 2 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 326 |  |
| q-393245df5e | triage T1111 step 2 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 326 |  |
| q-c72c0d7d54 | triage T1111 step 2 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None | F21 |
| q-ea7f2521b2 | triage T1111 step 3 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND (win.GrantedAccess:0x1fffff OR win.GrantedAccess:0x1f3fff OR win.GrantedAccess:0x101001 OR win.GrantedAccess:0x1000000 OR win.GrantedAccess:0x3000)", "time_from": null, "time… | 9 | F22 |
| q-f692373661 | triage T1111 step 3 | search | {"dataset": "windows.security", "query": "event.code:4648 AND (win.TargetServerName:* OR win.TargetUserName:pbeesly)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "win.TargetUserName", "win.LogonType", "win.Authentica… | 15 |  |
| q-ad355c132e | triage T1111 step 4 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None | F22 |
| q-71fde52a84 | triage T1111 step 4 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND process.executable:*PowerShell*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "process.executable", "process.command_line", "win.TargetImage", "… | 4 |  |
| q-d4015bf689 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NY3HhV"} | None |  |
| q-26e60d04dc | triage T1111 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NDgh5J"} | None |  |
| q-e7bebc2e7b | triage T1111 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx1Y"} | None |  |
| q-f989ea964f | triage T1111 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-2889f82b85 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-55137847ae | triage T1111 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-7b8bec86b7 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-6fff4dab23 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrM7IJ"} | None |  |
| q-30cd9557d2 | triage T1187 step 1 | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8Ieh"} | None | F23 |
| q-7cf7d337f9 | triage T1187 step 1 | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8Iej"} | None | F23 |
| q-1aa1701150 | triage T1187 step 1 | aggregate | {"dataset": "zeek", "field": "destination.ip", "query": "event.action:http AND (http.request.method:PROPFIND OR http.request.method:OPTIONS OR http.request.method:MOVE)", "time_from": null, "time_to": null, "size": 20, "sub_field": "source.ip"} | 36 |  |
| q-b956684c7f | triage T1187 step 1 | aggregate | {"dataset": "zeek", "field": "user_agent.original", "query": "event.action:http", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 62 |  |
| q-36526ca3c5 | triage T1187 step 2 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE source.ip == \"10.0.1.4\" \| KEEP @timestamp, event.action, destination.ip, destination.port, url.original, http.request.method, user_agent.original, zeek.uri, zeek.status_code, _id, _index \| SOR… | 60 |  |
| q-f5a346a088 | triage T1187 step 2 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"dns\" \| KEEP @timestamp, source.ip, dns.question.name, _id, _index \| SORT @timestamp ASC \| LIMIT 60"} | 53 |  |
| q-2e88e01479 | triage T1187 step 3 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"http\" \| KEEP @timestamp, source.ip, destination.ip, destination.port, http.request.method, url.original, user_agent.original, http.response.status_code, _id, _index \| SORT @ti… | 62 |  |
| q-7773ec81a0 | triage T1187 step 3 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"conn\" AND destination.port == 445 \| KEEP @timestamp, source.ip, destination.ip, destination.port, zeek.conn_state, zeek.history, _id, _index \| SORT @timestamp ASC \| LIMIT 60"… | 45 |  |
| q-cf7a7df057 | triage T1187 step 4 | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8IdC"} | None | F23 |
| q-9007915f8f | triage T1187 step 4 | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO74el"} | None |  |
| q-887b2e2abc | triage T1187 step 4 | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO74fI"} | None | F23 |
| q-ec812e7eb2 | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8IdC"} | None |  |
| q-6291127d5c | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8IdC"} | None |  |
| q-a690066fae | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8Ieh"} | None |  |
| q-c031dcaba7 | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8Ieh"} | None |  |
| q-29ad44f051 | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO74fI"} | None |  |
| q-6a498b7f61 | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO74fI"} | None |  |
| q-fc787a8bd9 | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO74fI"} | None |  |
| q-8f8b5ae74e | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8Iej"} | None |  |
| q-c860910c7a | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8Iej"} | None |  |
| q-62c4902f46 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YsmIPl"} | None |  |
| q-4141899230 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YsmIPl"} | None |  |
| q-c0435e4f63 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YcRSol"} | None |  |
| q-3f838174ad | triage T1187 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1SEqmrA"} | None |  |
| q-cfae541b49 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1SEqmrA"} | None |  |
| q-2e49683a13 | triage T1212 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-3ca4afb006 | triage T1212 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1bsxQxZ"} | None |  |
| q-194a24a3d7 | triage T1212 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21_RQ"} | None |  |
| q-044ba8606b | triage T1212 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1bsxQxS"} | None | F25 |
| q-03ee949c12 | triage T1212 step 2 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == 4104 AND powershell.script_block_text LIKE \"*SeaDuke*\" \| KEEP @timestamp, host.name, user.name, powershell.script_block_text, _id, _index"} | ERROR |  |
| q-d3c22e8606 | triage T1212 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 10 AND win.TargetImage LIKE \"*lsass*\" \| KEEP @timestamp, host.name, process.executable, win.TargetImage, win.GrantedAccess, _id, _index"} | ERROR |  |
| q-a87cd7cf5c | triage T1212 step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND powershell.script_block_text LIKE \"*SeaDuke*\" \| KEEP @timestamp, host.name, user.name, powershell.script_block_text, _id, _index"} | 1 | F25 |
| q-f2675c211f | triage T1212 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND win.TargetImage LIKE \"*lsass*\" \| KEEP @timestamp, host.name, process.executable, win.TargetImage, win.GrantedAccess, _id, _index"} | 326 | F25, F27 |
| q-f3c26efedf | triage T1212 step 4 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrM7IJ"} | None |  |
| q-a1b3c512da | triage T1212 step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (powershell.script_block_text LIKE \"*SeaDuke*\" OR powershell.script_block_text LIKE \"*lsass*\" OR powershell.script_block_text LIKE \"*Credential*\" OR … | 4 |  |
| q-d27260c30f | triage T1212 step 5 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND powershell.script_block_text LIKE \"*SeaDukeStage*\" \| KEEP @timestamp, host.name, user.name, powershell.script_block_text, _id, _index"} | 1 |  |
| q-e5894b67d2 | triage T1212 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND win.GrantedAccess LIKE \"*1f3fff*\" OR win.GrantedAccess LIKE \"*1F3FFF*\" \| KEEP @timestamp, host.name, process.executable, win.TargetImage, win.GrantedAccess,… | 122 | F25 |
| q-7f8a510cfe | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrM7IJ"} | None |  |
| q-0395c6a348 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrM7IJ"} | None |  |
| q-f894ad609e | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrM7IJ"} | None |  |
| q-ec8ab59e75 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrMrJI"} | None |  |
| q-dba5961238 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrMrJ3"} | None |  |
| q-dd9378da30 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1bsxQxZ"} | None |  |
| q-bad60f7ad9 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1bsxQxS"} | None |  |
| q-abc643f071 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YtYv"} | ERROR |  |
| q-b36039f3db | triage T1212 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YtYx"} | ERROR |  |
| q-0def684fb2 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YOGdm5"} | None |  |
| q-8852d1a069 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1WiJ0Te"} | None |  |
| q-bec9784577 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MuaKzP"} | None |  |
| q-d0b7b5d6b7 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MuaKzP"} | None |  |
| q-b7d07bcee0 | triage T1212 step 7 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YtYv"} | ERROR |  |
| q-f81c6bc1ad | triage T1212 step 7 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YOGdm5"} | None | F26 |
| q-48c1ac70f9 | triage T1539 step 1 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MsOhX7"} | None | F29 |
| q-4cd3449c99 | triage T1539 step 1 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YeU-Dp"} | None | F28 |
| q-8353c2520d | triage T1539 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 11 AND (TO_LOWER(win.TargetFilename) LIKE \"*cookies*\" OR TO_LOWER(win.TargetFilename) LIKE \"*login data*\" OR TO_LOWER(win.TargetFilename) LIKE \"*web data*\" OR TO_LOWE… | ERROR |  |
| q-55a1e96260 | triage T1539 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 1 AND (TO_LOWER(process.command_line) LIKE \"*cookie*\" OR TO_LOWER(process.command_line) LIKE \"*login data*\" OR TO_LOWER(process.command_line) LIKE \"*chrome*\" OR TO_LO… | ERROR |  |
| q-bf53c2151a | triage T1539 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(win.TargetFilename) LIKE \"*cookies*\" OR TO_LOWER(win.TargetFilename) LIKE \"*login data*\" OR TO_LOWER(win.TargetFilename) LIKE \"*web data*\" OR TO_… | 1 |  |
| q-ecc6942360 | triage T1539 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*cookie*\" OR TO_LOWER(process.command_line) LIKE \"*login data*\" OR TO_LOWER(process.command_line) LIKE \"*chrome*\" OR T… | 8 | F28 |
| q-ecfb3b1570 | triage T1539 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.executable) LIKE \"*python*\" OR TO_LOWER(process.executable) LIKE \"*sdelete*\" OR TO_LOWER(process.executable) LIKE \"*psexec*\" OR TO_LOWER(p… | 20 | F30 |
| q-253e1e3c9c | triage T1539 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND (TO_LOWER(win.TargetImage) LIKE \"*edge*\" OR TO_LOWER(win.TargetImage) LIKE \"*chrome*\" OR TO_LOWER(win.TargetImage) LIKE \"*firefox*\" OR TO_LOWER(win.TargetI… | 374 | F30 |
| q-cdad099f05 | triage T1539 step 5 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4663\" AND (TO_LOWER(win.ObjectName) LIKE \"*cookies*\" OR TO_LOWER(win.ObjectName) LIKE \"*login data*\" OR TO_LOWER(win.ObjectName) LIKE \"*web data*\" OR TO_LOWER(wi… | 0 |  |
| q-db41a3daae | triage T1539 step 5 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(powershell.script_block_text) LIKE \"*cookie*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*login data*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*session*\" … | 36 |  |
| q-f9c4e50b69 | triage T1539 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YeU-Dp"} | None |  |
| q-616e965e34 | triage T1539 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YeU-Dp"} | None |  |
| q-2eaa60d71c | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrMLE_"} | None |  |
| q-e7181f318c | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MsOhX7"} | None |  |
| q-22c22565bc | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MsOhX7"} | None |  |
| q-580786c969 | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1Muar8B"} | None |  |
| q-b4737d9347 | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1Muar8B"} | None |  |
| q-44508dd25c | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RkEAFq"} | None |  |
| q-6a19e8e26b | triage T1552 step 1 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R_lkD8"} | None |  |
| q-39018e8f70 | triage T1552 step 1 | search | {"dataset": "windows.sysmon", "query": "process.executable:*accesschk* OR process.command_line:*accesschk*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executa… | 2 |  |
| q-7c5cbadf38 | triage T1552 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND win.TargetFilename:*passwordsDB*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.c… | 1 |  |
| q-05091db476 | triage T1552 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*passwordsDB* OR process.command_line:*accesschk*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.… | 1 | F31 |
| q-f579d22937 | triage T1552 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R_lkD_"} | None |  |
| q-0c0fe9b9aa | triage T1552 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (win.TargetFilename:*GptTmpl* OR win.TargetFilename:*Groups.xml* OR win.TargetFilename:*sysvol*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.datas… | 22 | F33 |
| q-77d990e343 | triage T1552 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*sysvol* OR process.command_line:*Groups.xml* OR process.command_line:*GptTmpl*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.… | 0 |  |
| q-9cd8115e1e | triage T1552 step 3 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*accesschk* OR powershell.script_block_text:*passwordsDB* OR powershell.script_block_text:*Sysinternals*)", "time_from": null, "time_to": null, "fields": ["@timestamp… | 6 | F31 |
| q-b82104ecf8 | triage T1552 step 3 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND process.parent.executable:*powershell* AND user.name:pbeesly", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "proc… | 24 | F31 |
| q-222646105e | triage T1552 step 3 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND win.TargetFilename:*SysinternalsSuite*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "pro… | 311 |  |
| q-8459d73376 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R_lkD8"} | None |  |
| q-376e303e42 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R_lkD_"} | None |  |
| q-58fccf67ee | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R_lkD_"} | None |  |
| q-73a4369942 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21_RG"} | None |  |
| q-cfa25cf1d0 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1SEqWk4"} | None |  |
| q-5d02b9eb69 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YogQzA"} | None |  |
| q-b956bdb87e | triage T1552 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YcSP2J"} | None |  |
| q-d946fb4b8b | triage T1552 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YcSP2J"} | None |  |
| q-cbf8af95ed | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1SFrDbU"} | None |  |
| q-4378ebbed6 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1SFrDbU"} | None |  |
| q-92bfe6ed38 | triage T1552 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8IeP"} | None |  |
| q-03c9b10975 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R8i4gn"} | None |  |
| q-710c2ff80c | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NY3HhV"} | None |  |
| q-315b9c5633 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MtSxRG"} | None |  |
| q-c0dd8e9800 | triage T1555 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-5ad414765d | triage T1555 step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND win.GrantedAccess IN (\"0x1fffff\",\"0x1f3fff\",\"0x101001\",\"0x1000000\",\"0x3000\") \| KEEP @timestamp, host.name, user.name, win.SourceImage, win.TargetImage… | 500 |  |
| q-c768060f3e | triage T1555 step 2 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YldM_p"} | None | F35, F37 |
| q-7ea54dd923 | triage T1555 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1Nc7emR"} | None | F38 |
| q-6dc3beb1aa | triage T1555 step 3 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YjaXaO"} | None | F35 |
| q-1c1ac4ce0e | triage T1555 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.executable) LIKE \"*sdelete*\" OR TO_LOWER(process.command_line) LIKE \"*sdelete*\" OR TO_LOWER(process.command_line) LIKE \"*lsass*\" OR TO_LOW… | 7 | F35 |
| q-839936518e | triage T1555 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND win.TargetImage LIKE \"*lsass*\" AND win.GrantedAccess IN (\"0x1fffff\",\"0x1f3fff\",\"0x101001\") \| KEEP @timestamp, host.name, user.name, win.SourceImage, win… | 7 | F35, F37, F38 |
| q-5fb3d41f0f | triage T1555 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*login data*\" OR TO_LOWER(file.path) LIKE \"*logins.json*\" OR TO_LOWER(file.path) LIKE \"*cookies*\" OR TO_LOWER(file.path) LIKE \"… | 1 | F36 |
| q-4d29458218 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-6184a2915f | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k13y"} | None |  |
| q-973bf8c323 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrM7IJ"} | None |  |
| q-ab878d6da6 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrM7IJ"} | None |  |
| q-6b4323bf24 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YldM_p"} | None |  |
| q-de14f4717d | triage T1555 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YldM_p"} | None |  |
| q-0db552a93c | triage T1555 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YjaXaO"} | None |  |
| q-9b9743cf9c | triage T1555 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YjaXaO"} | None |  |
| q-f603070066 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1Nc7emY"} | None |  |
| q-8e05af7393 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MsOhX7"} | None |  |
| q-b4f327821c | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-253a68945e | triage T1555 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YldM_p"} | None |  |
| q-b0c43ac078 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx1Y"} | None |  |
| q-5775f60a4c | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NY3HhM"} | None |  |
| q-40113d34f0 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1WpS5PW"} | None |  |
| q-c154ffa8d4 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YEBswS"} | None |  |
| q-abae9fb903 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YGClc_"} | None |  |
| q-096b890532 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1Nc7emR"} | None |  |
| q-911db0b5b7 | triage T1556 step 1 | aggregate | {"dataset": "windows.sysmon", "field": "win.SourceImage", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": "win.GrantedAccess"} | 326 |  |
| q-adbf3ef6a2 | triage T1556 step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND TO_LOWER(win.TargetImage) LIKE \"*lsass*\" AND TO_LOWER(win.SourceImage) LIKE \"*powershell*\" \| KEEP @timestamp, host.name, win.SourceImage, win.TargetImage, w… | 4 | F39 |
| q-9a2c79157e | triage T1556 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-720d8dcfb1 | triage T1556 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k13y"} | None |  |
| q-1474e4ff22 | triage T1556 step 2 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" \| KEEP @timestamp, host.name, powershell.script_block_text, _id, _index \| LIMIT 60"} | 60 | F39 |
| q-89ce16b045 | triage T1556 step 3 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1bzyNRW"} | None |  |
| q-e56ca4c308 | triage T1556 step 3 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1bzydoz"} | None |  |
| q-d992960a91 | triage T1556 step 3 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1bzydqQ"} | None |  |
| q-0cbc9d9556 | triage T1556 step 4 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YogQzA"} | None |  |
| q-ade0fa3086 | triage T1556 step 4 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4624\" AND win.LogonType == \"3\" \| STATS c = COUNT(*) BY win.TargetUserName, win.LogonProcessName, source.ip \| SORT c DESC \| LIMIT 30"} | 15 |  |
| q-339bc8e6bc | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-f948dd1ddc | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-8255089d37 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k13y"} | None |  |
| q-ec6fbe8ec8 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1bzydqQ"} | None |  |
| q-0b81f53c5a | triage T1556 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1bzyNRW"} | None |  |
| q-1b74031bfe | triage T1556 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1bzydoz"} | None |  |
| q-11f9f65fe5 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YsmoMw"} | None |  |
| q-56b3ee970a | triage T1556 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YsmoMw"} | None |  |
| q-5fad0d18ac | triage T1556 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1Yph4sy"} | None |  |
| q-11f631048b | triage T1557 step 1 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"conn\" \| KEEP @timestamp, source.ip, destination.ip, destination.port, zeek.orig_l2_addr, zeek.resp_l2_addr, zeek.service, zeek.conn_state, _id, _index \| LIMIT 50"} | 50 | F41, F43 |
| q-1d50c8bc1e | triage T1557 step 1 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"conn\" \| STATS cnt = COUNT(*) BY zeek.orig_l2_addr, source.ip \| SORT cnt DESC \| LIMIT 50"} | 3 |  |
| q-45b0c32960 | triage T1557 step 2 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"conn\" AND zeek.orig_l2_addr == \"fc:bd:67:e1:a9:c1\" \| KEEP @timestamp, source.ip, destination.ip, destination.port, zeek.orig_l2_addr, zeek.resp_l2_addr, zeek.service, zeek.co… | 44 | F41, F43 |
| q-892fda3863 | triage T1557 step 2 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"conn\" \| STATS cnt = COUNT(*) BY zeek.resp_l2_addr, destination.ip \| SORT cnt DESC \| LIMIT 50"} | 6 |  |
| q-14d46f28da | triage T1557 step 3 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"smb_files\" OR event.action == \"smb_mapping\" OR event.action == \"dce_rpc\" \| KEEP @timestamp, source.ip, destination.ip, zeek.path, zeek.name, zeek.share_type, zeek.operation… | 40 | F41, F42 |
| q-14cc569810 | triage T1557 step 3 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4624\" AND win.LogonType == \"3\" \| STATS cnt = COUNT(*) BY win.TargetUserName, source.ip, host.name \| SORT cnt DESC \| LIMIT 40"} | 16 |  |
| q-748e7fe76c | triage T1557 step 4 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4697\" \| KEEP @timestamp, host.name, user.name, win.ServiceName, win.ServiceFileName, win.ServiceType, win.ServiceStartType, _id, _index \| LIMIT 30"} | 23 | F42 |
| q-d21f40cea1 | triage T1557 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"3\" AND (destination.port == 67 OR destination.port == 68 OR destination.port == 137 OR destination.port == 138 OR destination.port == 5355) \| KEEP @timestamp, host.name… | 24 | F44 |
| q-eb8b9109a0 | triage T1557 step 5 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"5156\" OR event.code == \"5154\" OR event.code == \"5158\" \| STATS cnt = COUNT(*) BY win.Direction, destination.port, win.Protocol \| SORT cnt DESC \| LIMIT 40"} | 40 |  |
| q-e277563fda | triage T1557 step 5 | esql | {"query": "FROM logs-windows.other-default METADATA _id, _index \| WHERE event.code == \"7045\" OR event.code == \"7040\" OR event.code == \"7036\" \| KEEP @timestamp, host.name, user.name, win.ServiceName, win.ImagePath, win.ServiceType, win.StartType, _id, _… | 17 |  |
| q-b9c95d877a | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8YcL"} | None |  |
| q-c5bafc0024 | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1bi_UDc"} | None |  |
| q-72f53c06a1 | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8IeN"} | None |  |
| q-022b236319 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YcRyrP"} | None |  |
| q-1db14f2121 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YhYtY9"} | None |  |
| q-f44a11a493 | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8Ifg"} | None |  |
| q-6b90e920fb | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8YcL"} | None |  |
| q-8a5296d780 | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1bi_UDc"} | None |  |
| q-238926582d | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MsPmId"} | None |  |
| q-3bfbe58680 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RqLLj_"} | None |  |
| q-7ce1c38f9d | triage T1558 step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND TO_LOWER(win.TargetImage) LIKE \"*lsass*\" AND win.GrantedAccess IN (\"0x1fffff\", \"0x101001\", \"0x1f3fff\", \"0x1000000\", \"0x3000\") \| KEEP @timestamp, hos… | 9 | F45 |
| q-097917b3e6 | triage T1558 step 1 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4769\" \| KEEP @timestamp, host.name, user.name, win.ServiceName, win.TicketEncryptionType, win.TicketOptions, source.ip, _id, _index"} | 28 | F46, F47 |
| q-36de369cb4 | triage T1558 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-82d565e428 | triage T1558 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrM7IJ"} | None |  |
| q-bca0360b79 | triage T1558 step 2 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" \| WHERE TO_LOWER(powershell.script_block_text) LIKE \"*kerber*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*ticket*\" OR TO_LOWER(powershell.script_blo… | 0 |  |
| q-a688964fae | triage T1558 step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" \| KEEP @timestamp, host.name, user.name, powershell.script_block_text, _id, _index \| LIMIT 50"} | 50 |  |
| q-5cc865ce6c | triage T1558 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*lsass*\" OR TO_LOWER(process.command_line) LIKE \"*kerber*\" OR TO_LOWER(process.command_line) LIKE \"*ticket*\" OR TO_LOW… | 2 |  |
| q-4485375eb8 | triage T1558 step 4 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1bzyNRW"} | None |  |
| q-66d0cc32c0 | triage T1558 step 4 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1bzyNfQ"} | None | F45 |
| q-b98e1df2b3 | triage T1558 step 5 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4624\" AND (win.TargetUserName LIKE \"*pbeesly*\" OR win.TargetUserName LIKE \"*SCRANTON*\") \| KEEP @timestamp, host.name, win.TargetUserName, win.LogonType, win.IpAdd… | 67 |  |
| q-278c996958 | triage T1558 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND host.name == \"scranton.dmevals.local\" \| KEEP @timestamp, user.name, process.executable, process.command_line, process.parent.executable, _id, _index"} | 359 | F45 |
| q-34086f867f | triage T1558 step 6 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"kerberos\" \| KEEP @timestamp, zeek.client, zeek.request_type, zeek.service, zeek.success, zeek.error_msg, zeek.id_orig_h, zeek.id_resp_h, _id, _index"} | 35 | F48, F49 |
| q-73cb39046f | triage T1558 step 6 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4672\" \| KEEP @timestamp, host.name, win.TargetUserName, win.PrivilegeList, _id, _index \| LIMIT 30"} | 30 |  |
| q-fee7fc0f10 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-4ea67ae832 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-03068f2ccb | triage T1558 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrM7IJ"} | None |  |
| q-76f733003c | triage T1558 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MtUEbK"} | None |  |
| q-0d48c962d1 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1bzyNfQ"} | None |  |
| q-0394c80875 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YTK7vi"} | None |  |
| q-2495ae267f | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YTK7vi"} | None |  |
| q-5c06dff540 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YhYtYx"} | None |  |
| q-1dd5eaa175 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YOGdm5"} | None |  |
| q-8c17c5356d | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YhYtYv"} | None |  |
| q-6b83145984 | triage T1558 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8IeS"} | None |  |
| q-f26e020e3d | triage T1558 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8Idd"} | None |  |
| q-1174d8c5bb | triage T1558 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8IeQ"} | None |  |
| q-e601fdbcd8 | triage T1606 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b22vQJ"} | None | F50 |
| q-0c3e43c294 | triage T1606 step 1 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND win.TargetImage:*lsass* AND (win.GrantedAccess:0x1fffff OR win.GrantedAccess:0x101001 OR win.GrantedAccess:0x1f3fff OR win.GrantedAccess:0x1000000 OR win.GrantedAccess:0x3… | 33 |  |
| q-d445128774 | triage T1606 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND (win.GrantedAccess:0x1fffff OR win.GrantedAccess:0x101001 OR win.GrantedAccess:0x1f3fff OR win.GrantedAccess:0x1000000 OR win.GrantedAccess:0x3000)", "time_from": null, "time… | 9 | F50 |
| q-4449b4634d | triage T1606 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*cookie* OR file.path:*Cookies*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "file.path", "process.executable", "process.command_line", "user.name"], "size": 1… | 1 | F51 |
| q-33e441e5c5 | triage T1606 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None | F50 |
| q-c02528a437 | triage T1606 step 3 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*lsass* OR powershell.script_block_text:*MiniDump* OR powershell.script_block_text:*credential* OR powershell.script_block_text:*Invoke-Mimikatz* OR powershell.script… | 2 |  |
| q-854e1ae253 | triage T1606 step 4 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND process.executable:*PowerShell*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "process.executable", "process.command_line", "process.parent.executable", "user.name"], "size"… | 12 |  |
| q-a193a2641a | triage T1606 step 4 | aggregate | {"dataset": "windows.powershell", "field": "win.Path", "query": "event.code:4104", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 414 |  |
| q-e88fb8bd36 | triage T1606 step 5 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == 4104 \| WHERE TO_LOWER(powershell.script_block_text) LIKE \"*cookie*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*saml*\" OR TO_LOWER(powershell.script_block_tex… | ERROR |  |
| q-1a64ad0da2 | triage T1606 step 5 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4624 AND win.LogonType:3", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 218 |  |
| q-3c1160b2f4 | triage T1606 step 6 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" \| WHERE TO_LOWER(powershell.script_block_text) LIKE \"*cookie*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*saml*\" OR TO_LOWER(powershell.script_block… | 4 |  |
| q-95c34ac38c | triage T1606 step 7 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b0zgg-"} | None | F52 |
| q-eee4734d3b | triage T1606 step 7 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b0zggh"} | None |  |
| q-09cac61dc4 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b22vQJ"} | None |  |
| q-c281fe489b | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-bdd012244e | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NY3HhM"} | None |  |
| q-c181f034b4 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MsOhX7"} | None |  |
| q-5da9cfe4ac | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MsOhX7"} | None |  |
| q-62628c0870 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b0zgg-"} | None |  |
| q-e0ca9d3ff8 | triage T1606 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO74fL"} | None |  |
| q-07c37d01a1 | triage T1621 step 1 | aggregate | {"dataset": "windows.other", "field": "event.code", "query": "*", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 216 |  |
| q-89e149c4d6 | triage T1621 step 1 | aggregate | {"dataset": "windows.other", "field": "win.Operation", "query": "event.code:5857 OR event.code:5858 OR event.code:5860", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 88 |  |
| q-5a476f2d02 | triage T1621 step 2 | search | {"dataset": "windows.other", "query": "event.code:5857", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "user.name", "message", "win.Operation", "win.ClientProcessId", "win.ProviderName"], "size": 10, "sort": "asc"} | 36 | F53 |
| q-3dbd4be59e | triage T1621 step 2 | search | {"dataset": "windows.other", "query": "event.code:5858", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "user.name", "message", "win.Operation", "win.ClientProcessId"], "size": 5, "sort": "asc"} | 49 | F53 |
| q-a4ea2d8294 | triage T1621 step 3 | search | {"dataset": "windows.other", "query": "event.code:7045 OR event.code:1074 OR event.code:1500 OR event.code:20523", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "user.name", "message", "win.ServiceName", "win.ImagePath… | 10 |  |
| q-b309ee417a | triage T1621 step 3 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4625\",\"4771\",\"4776\",\"4648\",\"4624\") \| STATS c = COUNT(*) BY event.code, win.TargetUserName, win.LogonType, host.name \| SORT c DESC \| LIMIT 30"} | 30 |  |
| q-da53915fdc | triage T1621 step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(powershell.script_block_text) LIKE \"*mfa*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*2fa*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*authenticator*\" OR T… | 0 |  |
| q-5331bc1476 | triage T1621 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*mfa*\" OR TO_LOWER(process.command_line) LIKE \"*2fa*\" OR TO_LOWER(process.command_line) LIKE \"*authenticator*\" OR TO_L… | 0 |  |
| q-c253b061d8 | triage T1621 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx21"} | None |  |
| q-56188233ee | triage T1621 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx1E"} | None |  |
| q-6174f609b5 | triage T1621 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx07"} | None |  |
| q-77e57f6b56 | triage T1649 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None | F54 |
| q-f989d2a2b3 | triage T1649 step 1 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*PrivateKey* OR powershell.script_block_text:*cert:\\\\* OR powershell.script_block_text:*Export* OR powershell.script_block_text:*Thumbprint*)", "time_from": null, "… | ERROR |  |
| q-d31f0a7b68 | triage T1649 step 2 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == 4104 AND TO_LOWER(powershell.script_block_text) LIKE \"*pfx*\" \| KEEP @timestamp, host.name, user.name, _id, _index, powershell.script_block_text"} | ERROR |  |
| q-d9f8aad72f | triage T1649 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 11 AND TO_LOWER(file.path) LIKE \"*.pfx*\" \| KEEP @timestamp, host.name, user.name, process.executable, file.path, _id, _index"} | ERROR |  |
| q-15e968ca07 | triage T1649 step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND TO_LOWER(powershell.script_block_text) LIKE \"*pfx*\" \| KEEP @timestamp, host.name, user.name, _id, _index, powershell.script_block_text"} | 2 | F54 |
| q-43069a2333 | triage T1649 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND TO_LOWER(file.path) LIKE \"*.pfx*\" \| KEEP @timestamp, host.name, user.name, process.executable, file.path, _id, _index"} | 1 | F54 |
| q-f2b05274b8 | triage T1649 step 4 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R_lUAH"} | None |  |
| q-f2a45ff542 | triage T1649 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND TO_LOWER(process.command_line) LIKE \"*readme.ps1*\" \| KEEP @timestamp, host.name, user.name, process.executable, process.command_line, process.parent.executable… | 0 |  |
| q-f58bcb0592 | triage T1649 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"13\" AND registry.path LIKE \"*SystemCertificates*\" \| KEEP @timestamp, host.name, user.name, process.executable, registry.path, registry.data.strings, _id, _index"} | 19 | F54, F55 |
| q-14a4708f74 | triage T1649 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*get-privatekeys*\" OR TO_LOWER(process.command_line) LIKE \"*beachcleanup*\" OR TO_LOWER(process.command_line) LIKE \"*rea… | 0 |  |
| q-c4bfc029ac | triage T1649 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None |  |
| q-af2349ad66 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None |  |
| q-1dcd5d1332 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None |  |
| q-6b2f016b8f | triage T1649 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R_lUAH"} | None |  |
| q-c5220ac0ee | triage T1649 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R_lUAH"} | None |  |
| q-e49c4d503c | triage T1649 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R_lED5"} | None |  |
| q-5fe405653e | triage T1649 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1bsxh3C"} | None |  |
| q-0b5f637aeb | triage T1649 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RhBptB"} | None |  |
| q-f3e7f1a1be | triage T1649 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1SS5_B3"} | None |  |
| q-4a7ef3aa9b | triage T1649 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NDgB6i"} | None |  |
| q-cbdecee02c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k13y"} | None |  |
| q-f7b984b8e7 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k13y"} | None |  |
| q-6fc775a13d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-163f0b9128 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YldM_i"} | None |  |
| q-ec5922a36b | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YldM_i"} | None |  |
| q-8cbce4522a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrM7IJ"} | None |  |
| q-622b37dbd5 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrM7IJ"} | None |  |
| q-30615fa46d | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None |  |
| q-eeb230ffda | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YWMnGq"} | None |  |
| q-18096ef698 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YWMnGq"} | None |  |
| q-c70acdbafe | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RpKsLE"} | None |  |
| q-603564fb8b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RpKsLE"} | None |  |
| q-353a0ac7a5 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MtUmZF"} | None |  |
| q-3de7ec59aa | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NAd3XG"} | None |  |
| q-042209a337 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RoJ7pL"} | None |  |
| q-9a75d3039a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k13y"} | None |  |
| q-2ac16259ce | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YYOcv1"} | None |  |
| q-e3facbe95c | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YYOcv1"} | None |  |
| q-a4182e4c4c | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YWMXHe"} | None |  |
| q-133f8420d7 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NW1Kgv"} | None |  |
| q-5506374c14 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx2T"} | None |  |
| q-30a29a8bee | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YcSP1_"} | None |  |
| q-fee52aaeac | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RjDSP-"} | None |  |
| q-7a0ef4ee6a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RjDSP-"} | None |  |
| q-c3f0803f75 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b87aMP"} | None |  |
| q-fb918a52fd | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-f206fe449e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-e269a0b9b0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-8227798871 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YldM_j"} | None |  |
| q-d58862dc13 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YldM_j"} | None |  |
| q-98a75b6b92 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1WdFNhN"} | None |  |
| q-b6536d8101 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YrjwVo"} | None |  |
| q-87c08c356c | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YsmIMu"} | None |  |
| q-e6de508e34 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-89002f8359 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YiZqBf"} | None |  |
| q-fb3b5ec77d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1WhJHLy"} | None |  |
| q-cd58bd1ab5 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1WhJHLy"} | None |  |
| q-a3a6235d22 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-f1f7deaed8 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YldM_j"} | None |  |
| q-0ceb6f25dc | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YQHwYC"} | None |  |
| q-2fb8739b82 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx0y"} | None |  |
| q-0782a7b4fc | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None |  |
| q-415c664d6f | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-f00b5c38a5 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YJECPG"} | None |  |
| q-8ceec2ad9b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-aa5b052a19 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YogQzA"} | None |  |
| q-ab88fd7fd6 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx2T"} | None |  |
| q-c2e2328dbe | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YQHwYC"} | None |  |
| q-b80c2f8e2c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NY3HhV"} | None |  |
| q-87abdb3673 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NDgh5J"} | None |  |
| q-92258c1987 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx1Y"} | None |  |
| q-f1a3c0780d | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-2dafa835d0 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-092c263cd2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-fb1c0630c2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-e0577c0bef | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrM7IJ"} | None |  |
| q-5611d27bde | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8IdC"} | None |  |
| q-f5a942af3a | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8IdC"} | None |  |
| q-467612ae31 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8Ieh"} | None |  |
| q-1467ba7b3a | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8Ieh"} | None |  |
| q-a0ee0aa0e6 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO74fI"} | None |  |
| q-bbf86b6dd6 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO74fI"} | None |  |
| q-2a2fad0717 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO74fI"} | None |  |
| q-d0e517fcc3 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO74fI"} | None |  |
| q-ea21f9f9ed | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8Iej"} | None |  |
| q-13364fb45a | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8Iej"} | None |  |
| q-bec785cc3b | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YsmIPl"} | None |  |
| q-2844293b22 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YsmIPl"} | None |  |
| q-6c4e4dbe56 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YcRSol"} | None |  |
| q-8eae461c7b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1SEqmrA"} | None |  |
| q-d868159311 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1SEqmrA"} | None |  |
| q-92523abfce | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrM7IJ"} | None |  |
| q-eb08d46298 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrM7IJ"} | None |  |
| q-78eb91a351 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrM7IJ"} | None |  |
| q-aabf040784 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrMrJI"} | None |  |
| q-9a4758691b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrMrJ3"} | None |  |
| q-5e9ba1c3bd | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1bsxQxZ"} | None |  |
| q-579b4adbfb | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1bsxQxS"} | None |  |
| q-263055d47c | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YOGdm5"} | None |  |
| q-719390fed8 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YOGdm5"} | None |  |
| q-247c48fd10 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YOGdm5"} | None |  |
| q-b2e83f6a17 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1WiJ0Te"} | None |  |
| q-6c412dd470 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MuaKzP"} | None |  |
| q-db89b22810 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MuaKzP"} | None |  |
| q-30eedcf4a8 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YeU-Dp"} | None |  |
| q-2d3974f0c9 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YeU-Dp"} | None |  |
| q-b9394c6f6b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrMLE_"} | None |  |
| q-4be465c48a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MsOhX7"} | None |  |
| q-3932c96e7f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MsOhX7"} | None |  |
| q-4bb2d86684 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1Muar8B"} | None |  |
| q-e8b2e66ac2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1Muar8B"} | None |  |
| q-a5a92efcde | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RkEAFq"} | None |  |
| q-29c10fcae8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R_lkD8"} | None |  |
| q-de7d006449 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R_lkD_"} | None |  |
| q-7e223a12e0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R_lkD_"} | None |  |
| q-4dfb34f6dd | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21_RG"} | None |  |
| q-c86fdc16c8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1SEqWk4"} | None |  |
| q-b3b9b11e7c | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YogQzA"} | None |  |
| q-6140c02b89 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YcSP2J"} | None |  |
| q-864b057d81 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YcSP2J"} | None |  |
| q-f8eba985f4 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1SFrDbU"} | None |  |
| q-72e4cabb00 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1SFrDbU"} | None |  |
| q-3a056d5442 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8IeP"} | None |  |
| q-27a622005c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R8i4gn"} | None |  |
| q-2b823af6e2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NY3HhV"} | None |  |
| q-f90938791b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MtSxRG"} | None |  |
| q-c0ec51cb8e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-5ab890cd63 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k13y"} | None |  |
| q-109de6e8ad | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrM7IJ"} | None |  |
| q-4a360c8fb2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrM7IJ"} | None |  |
| q-700d8652d7 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YldM_p"} | None |  |
| q-81cd3301fb | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YldM_p"} | None |  |
| q-ad2e6468e5 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YjaXaO"} | None |  |
| q-322d6ce7bd | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YjaXaO"} | None |  |
| q-767679c714 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1Nc7emY"} | None |  |
| q-0cabc9aae1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MsOhX7"} | None |  |
| q-daf6fb0ef3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-94d98bf04b | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YldM_p"} | None |  |
| q-cbd4d0ec26 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx1Y"} | None |  |
| q-c9bae699c4 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NY3HhM"} | None |  |
| q-8c486edaae | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1WpS5PW"} | None |  |
| q-44514095c9 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YEBswS"} | None |  |
| q-67d4ce1ca0 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YGClc_"} | None |  |
| q-74c368ffe1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1Nc7emR"} | None |  |
| q-e33e65f1e4 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-a674808fba | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-fba10e8203 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k13y"} | None |  |
| q-8015892baf | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1bzydqQ"} | None |  |
| q-c153f51095 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1bzyNRW"} | None |  |
| q-b11d687283 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1bzydoz"} | None |  |
| q-07a6a4fdcf | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YsmoMw"} | None |  |
| q-16700d4f75 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YsmoMw"} | None |  |
| q-e82caa09ef | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1Yph4sy"} | None |  |
| q-06fec336ab | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8YcL"} | None |  |
| q-f04688586b | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1bi_UDc"} | None |  |
| q-1987821f88 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8IeN"} | None |  |
| q-ce40b0c52a | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YcRyrP"} | None |  |
| q-1d42b37a32 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YhYtY9"} | None |  |
| q-194d8cbb81 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8Ifg"} | None |  |
| q-a41040a25b | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8YcL"} | None |  |
| q-720a0d237e | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1bi_UDc"} | None |  |
| q-11831bdecc | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MsPmId"} | None |  |
| q-dc0532db08 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RqLLj_"} | None |  |
| q-9872a9743c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-5b52d7a99f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-b68ce7295f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrM7IJ"} | None |  |
| q-ef00b15d6d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MtUEbK"} | None |  |
| q-8e1a38cfa7 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1bzyNfQ"} | None |  |
| q-9641be47dc | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YTK7vi"} | None |  |
| q-7a41550f87 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YTK7vi"} | None |  |
| q-89198161be | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YhYtYx"} | None |  |
| q-8276108c3a | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YOGdm5"} | None |  |
| q-3dff9e7a7a | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YhYtYv"} | None |  |
| q-eb771455a0 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8IeS"} | None |  |
| q-e1e673bf81 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8Idd"} | None |  |
| q-89b7bc9600 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8IeQ"} | None |  |
| q-a6be275f14 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b22vQJ"} | None |  |
| q-67db28c66f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-258a953d7e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NY3HhM"} | None |  |
| q-7cdf57b758 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MsOhX7"} | None |  |
| q-80d59e730b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MsOhX7"} | None |  |
| q-bd3d102808 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b0zgg-"} | None |  |
| q-3a3716ee9f | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO74fL"} | None |  |
| q-433df9156e | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx21"} | None |  |
| q-23bf2ffe9b | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx1E"} | None |  |
| q-99b06716e3 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx07"} | None |  |
| q-85f1b98e06 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None |  |
| q-a4f4d6d47e | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None |  |
| q-92a349b34d | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None |  |
| q-b8b9371637 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R_lUAH"} | None |  |
| q-859d98a2d1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R_lUAH"} | None |  |
| q-1434b67374 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R_lED5"} | None |  |
| q-95a9b0dfaa | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1bsxh3C"} | None |  |
| q-b94ecde6f1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RhBptB"} | None |  |
| q-7019d767a1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1SS5_B3"} | None |  |
| q-06714706ce | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NDgB6i"} | None |  |
| q-ac0f6c4393 | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND host.name:\"nashua.dmevals.local\"", "time_from": "2020-05-02T02:54:29+00:00", "time_to": "2020-05-02T03:32:18.030000+00:00", "size": 100, "sub_field": "process.parent.exec… | 61 |  |
| q-2afb221031 | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11 AND host.name:\"nashua.dmevals.local\"", "time_from": "2020-05-02T02:54:29+00:00", "time_to": "2020-05-02T03:32:18.030000+00:00", "size": 100, "sub_field": "process.executable"} | 249 |  |
| q-8b11b1be54 | pivot seed | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND host.name:\"nashua.dmevals.local\"", "time_from": "2020-05-02T02:54:29+00:00", "time_to": "2020-05-02T03:32:18.030000+00:00", "size": 100, "sub_field": "process.parent… | 63 |  |
| q-55cbd13856 | pivot seed | aggregate | {"dataset": "windows.powershell", "field": "event.code", "query": "host.name:\"nashua.dmevals.local\"", "time_from": "2020-05-02T02:54:29+00:00", "time_to": "2020-05-02T03:32:18.030000+00:00", "size": 100, "sub_field": null} | 192 |  |
| q-fd9def1582 | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND host.name:\"newyork.dmevals.local\"", "time_from": "2020-05-02T02:49:04+00:00", "time_to": "2020-05-02T03:34:15+00:00", "size": 100, "sub_field": "process.parent.executable… | 18 |  |
| q-36359f8f2b | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11 AND host.name:\"newyork.dmevals.local\"", "time_from": "2020-05-02T02:49:04+00:00", "time_to": "2020-05-02T03:34:15+00:00", "size": 100, "sub_field": "process.executable"} | 81 |  |
| q-721bf11dd0 | pivot seed | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND host.name:\"newyork.dmevals.local\"", "time_from": "2020-05-02T02:49:04+00:00", "time_to": "2020-05-02T03:34:15+00:00", "size": 100, "sub_field": "process.parent.execu… | 18 |  |
| q-589fc3ba37 | pivot seed | aggregate | {"dataset": "windows.powershell", "field": "event.code", "query": "host.name:\"newyork.dmevals.local\"", "time_from": "2020-05-02T02:49:04+00:00", "time_to": "2020-05-02T03:34:15+00:00", "size": 100, "sub_field": null} | 2185 |  |
| q-84ea52d493 | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND host.name:\"scranton.dmevals.local\"", "time_from": "2020-05-02T02:40:56+00:00", "time_to": "2020-05-02T03:36:29+00:00", "size": 100, "sub_field": "process.parent.executabl… | 359 |  |
| q-1752763204 | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11 AND host.name:\"scranton.dmevals.local\"", "time_from": "2020-05-02T02:40:56+00:00", "time_to": "2020-05-02T03:36:29+00:00", "size": 100, "sub_field": "process.executable"} | 1276 |  |
| q-597a5f987e | pivot seed | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND host.name:\"scranton.dmevals.local\"", "time_from": "2020-05-02T02:40:56+00:00", "time_to": "2020-05-02T03:36:29+00:00", "size": 100, "sub_field": "process.parent.exec… | 370 |  |
| q-1192ba2449 | pivot seed | aggregate | {"dataset": "windows.powershell", "field": "event.code", "query": "host.name:\"scranton.dmevals.local\"", "time_from": "2020-05-02T02:40:56+00:00", "time_to": "2020-05-02T03:36:29+00:00", "size": 100, "sub_field": null} | 8602 |  |
| q-dacff39b58 | pivot step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*passw*\" OR TO_LOWER(file.path) LIKE \"*.pfx\" OR TO_LOWER(file.path) LIKE \"*.kirbi\" OR TO_LOWER(file.path) LIKE \"*.dmp\" OR TO_L… | ERROR |  |
| q-3af9e77d57 | pivot step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.executable) LIKE \"*\\\\temp\\\\*\" OR TO_LOWER(process.executable) LIKE \"*\\\\programdata\\\\*\" OR TO_LOWER(process.executable) LIKE \"*\\\\u… | ERROR |  |
| q-690a363f10 | pivot step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*passw*\" OR TO_LOWER(file.path) LIKE \"*.pfx\" OR TO_LOWER(file.path) LIKE \"*.kirbi\" OR TO_LOWER(file.path) LIKE \"*.dmp\" OR TO_L… | 11 | F56, F57 |
| q-738bfa6198 | pivot step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.executable) LIKE \"*\\\\\\\\temp\\\\\\\\*\" OR TO_LOWER(process.executable) LIKE \"*\\\\\\\\programdata\\\\\\\\*\" OR TO_LOWER(process.executabl… | 10 | F59 |
| q-a8d4368cff | pivot step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NY3Hhd"} | None | F57 |
| q-adb4ab08bd | pivot step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R_lkD8"} | None |  |
| q-0278ba9e45 | pivot step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R_lUAH"} | None |  |
| q-21738568dc | pivot step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1SIw95-"} | None |  |
| q-c1392136d9 | pivot step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(winlog.event_data.ScriptBlockText) LIKE \"*passw*\" OR TO_LOWER(winlog.event_data.ScriptBlockText) LIKE \"*credential*\" OR TO_LOWER(winlog.event… | ERROR |  |
| q-e5b86ff9ec | pivot step 4 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4648\" \| KEEP @timestamp, host.name, user.name, winlog.event_data.TargetUserName, winlog.event_data.TargetServerName, winlog.event_data.ProcessName, _id, _index \| SOR… | ERROR |  |
| q-8e1fe2bc87 | pivot step 5 | get_fields | {"dataset": "windows.powershell", "prefix": ""} | None |  |
| q-fa6b24544b | pivot step 5 | get_fields | {"dataset": "windows.security", "prefix": ""} | None |  |
| q-a942cca6e5 | pivot step 6 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*passw*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*credential*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*lsass*\" OR… | 15 | F58 |
| q-c5e927a577 | pivot step 6 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4648\" \| KEEP @timestamp, host.name, user.name, win.TargetUserName, win.TargetServerName, win.ProcessName, _id, _index \| SORT @timestamp ASC"} | 15 |  |
| q-0f5328a009 | pivot step 7 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-e6b369f5fb | pivot step 7 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4663\" AND (TO_LOWER(win.ObjectName) LIKE \"*sam*\" OR TO_LOWER(win.ObjectName) LIKE \"*security*\" OR TO_LOWER(win.ObjectName) LIKE \"*lsass*\" OR TO_LOWER(win.ObjectN… | 6 |  |
| q-ad5388690b | pivot step 8 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*pspasswd*\" OR TO_LOWER(process.command_line) LIKE \"*reg save*\" OR TO_LOWER(process.command_line) LIKE \"*sam*\" OR TO_L… | 1 |  |
| q-027484a219 | pivot step 8 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*\\\\\\\\config\\\\\\\\sam*\" OR TO_LOWER(file.path) LIKE \"*\\\\\\\\config\\\\\\\\security*\" OR TO_LOWER(file.path) LIKE \"*\\\\\\\… | 336 |  |
| q-1fb392d8e8 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1SIw95-"} | None |  |
| q-af7a24c3de | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1SIwt7A"} | None |  |
| q-5b8fc61096 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R_lkD8"} | None |  |
| q-9bb3858449 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NY3Hhd"} | None |  |
| q-d84d6be8c0 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NY3Hhd"} | None |  |
| q-b5555cefe3 | pivot verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-c33d302313 | pivot verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-5e6c548290 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RhBpvd"} | None |  |
| q-565b2e60c6 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1Nc7emY"} | None |  |
| q-77ce1f17a3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k13y"} | None |  |
| q-fa0ab71ae5 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k13y"} | None |  |
| q-efe74cf695 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-71681f9adf | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YldM_i"} | None |  |
| q-fdf941d4e0 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YldM_i"} | None |  |
| q-ed65f282a4 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrM7IJ"} | None |  |
| q-f16659461d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrM7IJ"} | None |  |
| q-9bd50f92fd | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None |  |
| q-c162f58acc | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YWMnGq"} | None |  |
| q-52968b4b54 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YWMnGq"} | None |  |
| q-5f2ea07323 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RpKsLE"} | None |  |
| q-4505382743 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RpKsLE"} | None |  |
| q-26b1190e24 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MtUmZF"} | None |  |
| q-73c826c48b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NAd3XG"} | None |  |
| q-75e1650544 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RoJ7pL"} | None |  |
| q-a76057ad2b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k13y"} | None |  |
| q-c02b7b0368 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YYOcv1"} | None |  |
| q-25f70adbc6 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YYOcv1"} | None |  |
| q-4bb5f38c81 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YWMXHe"} | None |  |
| q-fa21511b1d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NW1Kgv"} | None |  |
| q-561cd9e3c2 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx2T"} | None |  |
| q-35e59dcaa1 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YcSP1_"} | None |  |
| q-765f157fbc | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RjDSP-"} | None |  |
| q-2c6babad0d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RjDSP-"} | None |  |
| q-efc935587d | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b87aMP"} | None |  |
| q-0ba44ae631 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-0f28f917b5 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-42d6164d7a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-82636f5265 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YldM_j"} | None |  |
| q-954c29167d | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YldM_j"} | None |  |
| q-26921f02a1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1WdFNhN"} | None |  |
| q-f04bbf1ba3 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YrjwVo"} | None |  |
| q-a060bb30b0 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YsmIMu"} | None |  |
| q-2d57378fdd | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-01a63dc0e9 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YiZqBf"} | None |  |
| q-16178cddd6 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1WhJHLy"} | None |  |
| q-9fb1eddd97 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1WhJHLy"} | None |  |
| q-2620c5957a | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-088ecf1353 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YldM_j"} | None |  |
| q-4f21dabe22 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YQHwYC"} | None |  |
| q-bff92e5a3b | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx0y"} | None |  |
| q-859267a8b3 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None |  |
| q-aabdcdde98 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-227b363dd7 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YJECPG"} | None |  |
| q-214ed59bf9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-556701d9cb | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YogQzA"} | None |  |
| q-81beb246bb | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx2T"} | None |  |
| q-228371cc96 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YQHwYC"} | None |  |
| q-2fef245ba4 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NY3HhV"} | None |  |
| q-4395ecb233 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NDgh5J"} | None |  |
| q-31633fe6bf | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx1Y"} | None |  |
| q-34f3adb2d7 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-22d7b88ce5 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-a754cb90e5 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-20ffd4327e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-1007ef80c7 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrM7IJ"} | None |  |
| q-0e7f5c13da | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8IdC"} | None |  |
| q-484e8d1b3e | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8IdC"} | None |  |
| q-e4f430d437 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8Ieh"} | None |  |
| q-b1df366e97 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8Ieh"} | None |  |
| q-b498b6d50f | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO74fI"} | None |  |
| q-2960d426b5 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO74fI"} | None |  |
| q-2e10389ec6 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO74fI"} | None |  |
| q-c91ca86527 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO74fI"} | None |  |
| q-6f19112a3f | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8Iej"} | None |  |
| q-046ea0d1d8 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8Iej"} | None |  |
| q-053f13f70c | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YsmIPl"} | None |  |
| q-9f11abd9b4 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YsmIPl"} | None |  |
| q-ca2be08d2a | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YcRSol"} | None |  |
| q-8531514bc4 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1SEqmrA"} | None |  |
| q-f32ff46c93 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1SEqmrA"} | None |  |
| q-c8088afe0f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrM7IJ"} | None |  |
| q-a84a30cf66 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrM7IJ"} | None |  |
| q-526c8ebe50 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrM7IJ"} | None |  |
| q-41da56f24a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrMrJI"} | None |  |
| q-5fb8e76315 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrMrJ3"} | None |  |
| q-3f3c0a690d | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1bsxQxZ"} | None |  |
| q-2f6f4e70bc | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1bsxQxS"} | None |  |
| q-aafe308c1c | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YOGdm5"} | None |  |
| q-40f4d732ca | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YOGdm5"} | None |  |
| q-b1ec637680 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YOGdm5"} | None |  |
| q-53051b2c08 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1WiJ0Te"} | None |  |
| q-8edacdf4a8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MuaKzP"} | None |  |
| q-eb2da1467b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MuaKzP"} | None |  |
| q-085305d9b0 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YeU-Dp"} | None |  |
| q-3dbd590ca2 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YeU-Dp"} | None |  |
| q-8c01d72714 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrMLE_"} | None |  |
| q-35d04f0f58 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MsOhX7"} | None |  |
| q-d43e481848 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MsOhX7"} | None |  |
| q-9ffd6aba16 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1Muar8B"} | None |  |
| q-74621419d4 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1Muar8B"} | None |  |
| q-e7665c4c24 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RkEAFq"} | None |  |
| q-2d38c73508 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R_lkD8"} | None |  |
| q-1165f90f6d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R_lkD_"} | None |  |
| q-c8b2be0b4a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R_lkD_"} | None |  |
| q-e42188981b | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21_RG"} | None |  |
| q-ae795d0485 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1SEqWk4"} | None |  |
| q-03410b5516 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YogQzA"} | None |  |
| q-fef65cc244 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YcSP2J"} | None |  |
| q-b06b1a3cca | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YcSP2J"} | None |  |
| q-21398ab30d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1SFrDbU"} | None |  |
| q-6d046b405e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1SFrDbU"} | None |  |
| q-9a4f475326 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8IeP"} | None |  |
| q-bab48d3e5a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R8i4gn"} | None |  |
| q-ed047e79f5 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NY3HhV"} | None |  |
| q-870caffc2c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MtSxRG"} | None |  |
| q-5b3277159a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-012a819411 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k13y"} | None |  |
| q-7e1a1eb12d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrM7IJ"} | None |  |
| q-9c537f4a68 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrM7IJ"} | None |  |
| q-5c6f9a5a34 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YldM_p"} | None |  |
| q-fffd4ddcb0 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YldM_p"} | None |  |
| q-10906c40b1 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YjaXaO"} | None |  |
| q-217298cc8b | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YjaXaO"} | None |  |
| q-e34017ea2c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1Nc7emY"} | None |  |
| q-6979854830 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MsOhX7"} | None |  |
| q-b809de7019 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-c24cfb66bd | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YldM_p"} | None |  |
| q-5340640ef7 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx1Y"} | None |  |
| q-21eed60284 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NY3HhM"} | None |  |
| q-d99e1289a7 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1WpS5PW"} | None |  |
| q-5b6d628030 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YEBswS"} | None |  |
| q-01621d43d9 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YGClc_"} | None |  |
| q-85f055c410 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1Nc7emR"} | None |  |
| q-6162bd863f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-d628992508 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-551d4fb463 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k13y"} | None |  |
| q-17f6afb4cf | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1bzydqQ"} | None |  |
| q-382935f39e | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1bzyNRW"} | None |  |
| q-49d86e8023 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1bzydoz"} | None |  |
| q-9ae62ca697 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YsmoMw"} | None |  |
| q-752d0d98b3 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YsmoMw"} | None |  |
| q-85826319e6 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1Yph4sy"} | None |  |
| q-ec54cbaa6a | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8YcL"} | None |  |
| q-b70b0413a6 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1bi_UDc"} | None |  |
| q-fdfdd248b4 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8IeN"} | None |  |
| q-cccc47290e | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YcRyrP"} | None |  |
| q-9a4e5aeadc | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YhYtY9"} | None |  |
| q-219c6f952c | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8Ifg"} | None |  |
| q-69f8cc17a4 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8YcL"} | None |  |
| q-8b52436f19 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1bi_UDc"} | None |  |
| q-fe5484782d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MsPmId"} | None |  |
| q-31d75b8a7e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RqLLj_"} | None |  |
| q-dd7b3f03c3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-f0ee83cdf9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-03f2ef19ff | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrM7IJ"} | None |  |
| q-09f3c77aed | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MtUEbK"} | None |  |
| q-cafade2361 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1bzyNfQ"} | None |  |
| q-5be29f6828 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YTK7vi"} | None |  |
| q-dac6f71b27 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YTK7vi"} | None |  |
| q-f933ec46ab | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YhYtYx"} | None |  |
| q-c1086c4cb3 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YOGdm5"} | None |  |
| q-4892920961 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YhYtYv"} | None |  |
| q-d483cf21b1 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8IeS"} | None |  |
| q-eea8d80312 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8Idd"} | None |  |
| q-2e82c7de46 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8IeQ"} | None |  |
| q-bc9023e737 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b22vQJ"} | None |  |
| q-779f11174a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-b3c897e1b1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NY3HhM"} | None |  |
| q-ac29e9a1f4 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MsOhX7"} | None |  |
| q-ae62e8cdc3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MsOhX7"} | None |  |
| q-928fcba395 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b0zgg-"} | None |  |
| q-f71d690c61 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO74fL"} | None |  |
| q-af01a7e1a4 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx21"} | None |  |
| q-9ae194065b | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx1E"} | None |  |
| q-9e09ea7e7d | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx07"} | None |  |
| q-75849a32f9 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None |  |
| q-41a69d4a83 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None |  |
| q-b16a3ed99b | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None |  |
| q-544a7e809f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R_lUAH"} | None |  |
| q-7b2c6f2316 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R_lUAH"} | None |  |
| q-4f28aec4d4 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R_lED5"} | None |  |
| q-7fdcb5f956 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1bsxh3C"} | None |  |
| q-3fd10b6f1b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RhBptB"} | None |  |
| q-7f21d5dbde | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1SS5_B3"} | None |  |
| q-8b297af16d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NDgB6i"} | None |  |
| q-2f4f34fc6d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1SIw95-"} | None |  |
| q-5db033fc47 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1SIwt7A"} | None |  |
| q-4fb4155026 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R_lkD8"} | None |  |
| q-3d2da74e91 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NY3Hhd"} | None |  |
| q-37fb504b28 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NY3Hhd"} | None |  |
| q-55f6a24e3c | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-cb4e310eb4 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-cea0aa14dd | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RhBpvd"} | None |  |
| q-4295d4892f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1Nc7emY"} | None |  |

## Verification

Evidence items cited: 185; confirmed against the stored events: 185; rejected: 0. Each item was re-fetched with get_event; it is confirmed only if the event exists, the cited field holds the cited value, and the cited query_id is a query of this run that returned that event.
Evidence sent back to the agents for correction during the run: 8 item(s) in 6 submission(s) (one correction round each; what still failed was rejected).

## Limitations

- Findings describe what the stored logs show; activity these sources did not log cannot be seen.
- Datasets with non-overlapping time windows (see Data examined) were analysed separately.
- Long field values are shortened in this report; full events are retrievable by _index/_id.
