# Threat hunt report — 20261017-010833-converged-exp-B1

**Hypothesis:** An adversary who compromised Windows hosts in this network stole credentials from them (MITRE ATT&CK tactic: Credential Access).

**Verdict: Confirmed** — 9 in-scope incident(s) of verified malicious findings (confidence >= medium): I01 T1003.001 (F01, F08, F33, F36, F47, F52), I02 T1003.001 (F10, F20, F34), I04 T1056.001 (F07), I05 T1056.002 (F09), I06 T1187 (F18), I08 T1552 (F28, F62), I09 T1552.001 (F61), I10 T1552.004 (F27, F64), I12 T1649 (F58, F59)

Verdict method: rules over verified evidence (Confirmed if >=1 in-scope incident of verified malicious findings (confidence >= medium); Inconclusive if only suspicious incidents or coverage gaps; Refuted if full coverage and no malicious/suspicious finding)

| Run | Value |
|---|---|
| Profile | converged (thinking=False, temperature=0.0) |
| Model | deepseek-flash |
| Started / finished (UTC) | 2026-10-16T17:08:33+00:00 / 2026-10-16T17:18:05+00:00 (571.5 s) |
| LLM calls / tokens | 129 / {'prompt': 3557376, 'completion': 112210} |
| MCP tool calls | 1118 (server tools: list_data_sources, get_fields, search, count, aggregate, timeline, esql, get_event, get_registry) |
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
| I01 | T1003.001 | yes | malicious/high | F01, F08, F33, F36, F47, F52 | PowerShell opened LSASS with full access on scranton (credential dumping) |
| I02 | T1003.001 | yes | malicious/high | F10, F20, F34 | Remote PowerShell session opened LSASS with full access on nashua |
| I03 | T1003.002 | yes | suspicious/low | F02 | LSASS wrote SAM account data on scranton |
| I04 | T1056.001 | yes | malicious/high | F07 | PowerShell Get-Keystrokes keylogger on scranton |
| I05 | T1056.002 | yes | malicious/medium | F09 | Invoke-ScreenCapture GUI capture on scranton |
| I06 | T1187 | yes | malicious/high | F18 | WebDAV forced-authentication coercion from scranton to 192.168.0.4 |
| I07 | T1187 | yes | suspicious/medium | F19 | Credential-bearing SMB share access from 10.0.1.4 to SYSVOL/IPC$/ADMIN$ |
| I08 | T1552 | yes | malicious/medium | F28, F62 | accesschk.exe created a file named passwordsDB on scranton |
| I09 | T1552.001 | yes | malicious/high | F61 | Sysinternals pspasswd credential tooling staged on scranton |
| I10 | T1552.004 | yes | malicious/high | F27, F64 | Get-PrivateKeys exported machine certificates to .pfx on scranton |
| I11 | T1558.003 | yes | suspicious/medium | F48 | Kerberos service-ticket requests for krbtgt and machine accounts by pbeesly (RC4) |
| I12 | T1649 | yes | malicious/high | F58, F59 | Get-PrivateKeys certificate theft and Invoke-BeachCleanup anti-forensic cleanup |
| I13 | out-of-scope:T1021 | no | suspicious/medium | F14 | No password spraying; 4648 explicit-credential logons are PsExec lateral movement |
| I14 | out-of-scope:T1021 | no | malicious/high | F21 | PsExec with cleartext credentials to NASHUA before LSASS access |
| I15 | out-of-scope:T1041 | no | malicious/medium | F17 | Invoke-Exfil WebDAV exfiltration with hardcoded credentials (not MFA interception) |
| I16 | out-of-scope:T1041 | no | suspicious/medium | F26 | Adjacent credential/exfil activity is not web session cookie theft |

## Findings

### F01 · malicious / high · T1003.001 · PowerShell.exe opened LSASS with PROCESS_ALL_ACCESS on scranton

Evidence status: **verified**

On scranton.dmevals.local at 2020-05-02T03:05:16, PowerShell.exe (PID 2976, SourceProcessGUID {47ab858c-e1e4-5eac-b803-000000000400}) opened lsass.exe (PID 736) with GrantedAccess 0x1FFFFF (PROCESS_ALL_ACCESS) and 0x1F3FFF within the same second. This is the access mask required to read LSASS memory for credential dumping and is not normal for PowerShell. It occurs in the same session/user context (pbeesly) that ran the Invoke-Exfil PowerShell script on this host, indicating an adversary dumping credentials.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R-k131 | q-536b06af07 | ok |
| 2 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R-k131 | q-536b06af07 | ok |
| 3 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R-k13y | q-4689b4f321 | ok |
| 4 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1RrM7IJ | q-9e4b61e145 | ok |
| 5 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1RrM7IJ | q-9e4b61e145 | ok |

### F08 · malicious / high · T1056 · PowerShell full-access handle to LSASS and private-key/clipboard capture on scranton

Evidence status: **verified**

On 2020-05-02 at 03:05:16 UTC on scranton.dmevals.local, PowerShell.exe (PID 2976, entity {47ab858c-e1e4-5eac-b803-000000000400}) opened lsass.exe (PID 736) with GrantedAccess 0x1F3FFF and then 0x1FFFFF — full process access consistent with reading credential memory. In the same session user pbeesly ran 'Get-PrivateKeys' (dumping certificate private keys to .pfx files using a hardcoded password 'saribas'), 'Get-Clipboard', and 'Invoke-ScreenCapture'. Together these are input/credential capture actions on the host.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R-k13y | q-07d1942058 | ok |
| 2 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R-k131 | q-07d1942058 | ok |
| 3 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | powershell.script_block_text | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b21vS3 | q-69014be8f1 | ok |

### F07 · malicious / high · T1056.001 · PowerShell Get-Keystrokes keylogger executed by pbeesly on scranton

Evidence status: **verified**

On 2020-05-02 at 03:06:59 UTC on scranton.dmevals.local, user pbeesly executed the PowerShell command 'Get-Keystrokes;Start-Sleep -Seconds 15;View-Job -JobName "Keystrokes"' (PowerShell script-block logging event 4104, ScriptBlockId 7c8ce66d-dd1a-4a72-8e88-42dd7ff48c74). Immediately before, at 03:06:47, the same user defined a 'Keystroke-Check' function that enumerates known antivirus processes (avp, acs, outpost, mcvsescn, mcods, navapsvc, kav, AvastSvc, AvastUi, nod32krn, nod32, ekern, dwengine, MsMpEng, msseces, ekrn, savservice, scfservice, savadminservice) — a hallmark anti-AV check of the Get-Keystrokes keylogger tool. The job was later viewed (03:07:36) and removed (03:07:49). This is a keylogger capturing keystrokes on the host.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:06:59.000Z | scranton.dmevals.local | windows.powershell | powershell.script_block_text | Get-Keystrokes;Start-Sleep -Seconds 15;View-Job -JobName "Keystrokes" | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b21_Tx | q-69014be8f1 | ok |
| 2 | 2020-05-02 03:06:47.000Z | scranton.dmevals.local | windows.powershell | powershell.script_block_text | function Keystroke-Check {     Get-Process \| Where-Object { $_.ProcessName -Eq "avp" -or $_.ProcessName -Eq "acs" -or $_.ProcessName -Eq "outpost" -or $_.Proce… | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b21_R0 | q-5d98674fda | ok |
| 3 | 2020-05-02 03:06:42.000Z | scranton.dmevals.local | windows.powershell | powershell.script_block_text | Get-Clipboard | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b21_Qp | q-5d98674fda | ok |

### F09 · malicious / medium · T1056.002 · Invoke-ScreenCapture GUI capture function executed by pbeesly on scranton

Evidence status: **verified**

On 2020-05-02 at 03:05:53 UTC on scranton.dmevals.local, user pbeesly defined and invoked an 'Invoke-ScreenCapture' function that uses System.Windows.Forms.SystemInformation::VirtualScreen and System.Drawing to repeatedly capture the screen to .bmp files in the user's Downloads folder, then ran 'Invoke-ScreenCapture;Start-Sleep -Seconds 3;View-Job -JobName "Screenshot"'. This is GUI/screen input capture on the host.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:53.000Z | scranton.dmevals.local | windows.powershell | powershell.script_block_text | Invoke-ScreenCapture;Start-Sleep -Seconds 3;View-Job -JobName "Screenshot" | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b22PTB | q-69014be8f1 | ok |
| 2 | 2020-05-02 03:05:53.000Z | scranton.dmevals.local | windows.powershell | powershell.script_block_text | function Invoke-ScreenCapture # https://www.pdq.com/blog/capturing-screenshots-with-powershell-and-net/ {     Start-Job -Name "Screenshot" -ScriptBlock {       … | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b21vTv | q-69014be8f1 | ok |

### F17 · malicious / medium · T1111 · PowerShell Invoke-Exfil script uses hardcoded credentials for WebDAV exfiltration (not MFA interception)

Evidence status: **verified**

On scranton.dmevals.local, user pbeesly executed a PowerShell script block (event 4104) defining function Invoke-Exfil that compresses the user's Downloads folder with 7Zip4Powershell and exfiltrates it to a WebDAV share at \\192.168.0.4\webdav using hardcoded credentials (username 'cozy', password 'MyCozyPassw0rd!'). This is credential use and data exfiltration, not MFA interception, so it does not substantiate T1111; it is reported here as the only genuinely malicious artifact surfaced by the T1111 hunt.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | powershell.script_block_text | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b10BXt | q-3ef5d73c40 | ok |
| 2 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | user.name | pbeesly | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b10BXt | q-3ef5d73c40 | ok |

### F18 · malicious / high · T1187 · WebDAV forced-authentication coercion from scranton (10.0.1.4) to 192.168.0.4

Evidence status: **verified**

Host 10.0.1.4 (scranton.dmevals.local) attempted SMB to 192.168.0.4 on ports 445 and 139, all of which were rejected (zeek.conn_state REJ), then immediately fell back to WebDAV over HTTP port 80. The first probe used the 'DavClnt' user agent (OPTIONS / -> 403), followed by a sustained series of 'Microsoft-WebDAV-MiniRedir/10.0.18362' requests (OPTIONS, PROPFIND, PUT, LOCK, HEAD) against /webdav and /webdav/OfficeSupplies.7z, many answered 401 Unauthorized before succeeding (PUT 201/204, LOCK 200, HEAD 200, PROPFIND 207). This SMB-reject-then-WebDAV-fallback sequence with the Windows WebDAV redirector user agent is the classic T1187 forced-authentication pattern used to coerce a victim host into authenticating to an attacker-controlled WebDAV/SMB listener and leak NTLM credentials. All 36 WebDAV method requests in the dataset originate solely from 10.0.1.4 to 192.168.0.4.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-04-30 00:32:14.891Z | simplerockbuild.simplerock.lan | zeek | zeek.conn_state | REJ | .ds-logs-zeek-default-2026.10.16-000001 / AaFFktQ25mySA1aO8IdC | q-5273cdc1f0 | ok |
| 2 | 2020-04-30 00:32:18.095Z | simplerockbuild.simplerock.lan | zeek | user_agent.original | DavClnt | .ds-logs-zeek-default-2026.10.16-000001 / AaFFktQ25mySA1aO8Idl | q-5273cdc1f0 | ok |
| 3 | 2020-04-30 00:32:21.422Z | simplerockbuild.simplerock.lan | zeek | user_agent.original | Microsoft-WebDAV-MiniRedir/10.0.18362 | .ds-logs-zeek-default-2026.10.16-000001 / AaFFktQ25mySA1aO8Ieh | q-93f80f8c4a | ok |
| 4 | 2020-04-30 00:32:21.422Z | simplerockbuild.simplerock.lan | zeek | http.response.status_code | 401 | .ds-logs-zeek-default-2026.10.16-000001 / AaFFktQ25mySA1aO8Ieh | q-93f80f8c4a | ok |
| 5 | 2020-04-30 00:32:21.895Z | simplerockbuild.simplerock.lan | zeek | url.original | /webdav/OfficeSupplies.7z | .ds-logs-zeek-default-2026.10.16-000001 / AaFFktQ25mySA1aO8Iej | q-fb21f940d5 | ok |
| 6 | 2020-04-30 00:32:21.918Z | simplerockbuild.simplerock.lan | zeek | http.request.method | PUT | .ds-logs-zeek-default-2026.10.16-000001 / AaFFktQ25mySA1aO74fI | q-5273cdc1f0 | ok |
| 7 | 2020-04-30 00:32:21.918Z | simplerockbuild.simplerock.lan | zeek | http.response.status_code | 201 | .ds-logs-zeek-default-2026.10.16-000001 / AaFFktQ25mySA1aO74fI | q-5273cdc1f0 | ok |
| 8 | 2020-04-30 00:32:14.891Z | simplerockbuild.simplerock.lan | zeek | destination.port | 445 | .ds-logs-zeek-default-2026.10.16-000001 / AaFFktQ25mySA1aO8IdC | q-5273cdc1f0 | ok |

### F20 · malicious / high · T1212 · PowerShell remoting host (wsmprovhost.exe) opened LSASS with full access on NASHUA during attacker session

Evidence status: **verified**

On nashua.dmevals.local at 2020-05-02T03:09:29.430Z, wsmprovhost.exe (PID 7720, the WinRM/PowerShell-remoting host) opened C:\windows\system32\lsass.exe (PID 728) with GrantedAccess 0x1f3fff (full access). The call trace runs through PowerShell's Microsoft.PowerShell.Commands.Management.ni.dll, i.e. the access was driven by a PowerShell command executed in the remoting session, not by an OS component. This is the only non-system/non-AV process to touch LSASS in the dataset. It occurred seconds after user pbeesly ran 'Invoke-Command -ComputerName NASHUA -ScriptBlock { Get-Process -IncludeUserName ... }' from scranton, and the same pbeesly session on NASHUA then enumerated and archived credential-relevant files (*pass*, *login*, *admin*, *vpn) with Compress-Archive/Rar.exe. This is consistent with exploitation/abuse of the remoting channel to reach credential material in LSASS.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1RrM7IJ | q-85f1040662 | ok |
| 2 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.TargetImage | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1RrM7IJ | q-85f1040662 | ok |
| 3 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1RrM7IJ | q-85f1040662 | ok |
| 4 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.CallTrace | C:\windows\SYSTEM32\ntdll.dll+9c584\|C:\windows\System32\KERNELBASE.dll+2732e\|C:\windows\assembly\NativeImages_v4.0.30319_64\System\9803982d7bc887e2745bff18a43… | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1RrM7IJ | q-ce5ccd5d41 | ok |
| 5 | 2020-05-02 03:09:28.000Z | nashua.dmevals.local | windows.powershell | powershell.script_block_text |  Get-Process -IncludeUserName \| Select-Object UserName,SessionId \| Where-Object { $_.UserName -like "*\$env:USERNAME" } \| Sort-Object SessionId -Unique  | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1bsxh3J | q-24bcd3dbc2 | ok |
| 6 | 2020-05-02 03:15:59.000Z | nashua.dmevals.local | windows.powershell | powershell.script_block_text | $env:APPDATA;$files=ChildItem -Path $env:USERPROFILE\ -Include *.doc,*.xps,*.xls,*.ppt,*.pps,*.wps,*.wpd,*.ods,*.odt,*.lwp,*.jtd,*.pdf,*.zip,*.rar,*.docx,*.url,… | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1bsxhdc | q-24bcd3dbc2 | ok |

### F21 · malicious / high · T1212 · Attacker used PsExec with cleartext credentials to reach NASHUA before the LSASS access

Evidence status: **verified**

From scranton.dmevals.local, user pbeesly repeatedly launched PsExec64.exe against \\NASHUA supplying the account password in cleartext on the command line ('-u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe') at 03:11:18, 03:12:25, 03:13:28 and 03:14:42. This lateral movement to NASHUA precedes the wsmprovhost.exe LSASS access at 03:09:29 and the file-collection/archiving activity on NASHUA, showing the operator already held valid credentials and was operating interactively on the remote host.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:14:42.601Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\PsExec64.exe" -accepteula \\NASHUA -u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1RkEAFq | q-e499090ff7 | ok |
| 2 | 2020-05-02 03:14:42.601Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\Program Files\SysinternalsSuite\PsExec64.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1RkEAFq | q-e499090ff7 | ok |
| 3 | 2020-05-02 03:14:42.601Z | scranton.dmevals.local | windows.sysmon | host.name | scranton.dmevals.local | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1RkEAFq | q-e499090ff7 | ok |

### F62 · malicious / medium · T1552 · accesschk.exe wrote a file named passwordsDB on scranton

Evidence status: **verified**

On scranton.dmevals.local, accesschk.exe (PID 9204, launched by powershell.exe as DMEVALS\pbeesly, High integrity) created a file named 'passwordsDB' in C:\Program Files\SysinternalsSuite at 03:04:35. The filename strongly suggests a credential store being written by the attacker's tooling. This is a new artifact beyond the anchors.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:35.069Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Program Files\SysinternalsSuite\passwordsDB | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R_lkD8 | q-77b0453cbe | ok |
| 2 | 2020-05-02 03:04:34.951Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\Program Files\SysinternalsSuite\accessChk.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R_lkD_ | q-11d7cca501 | ok |
| 3 | 2020-05-02 03:04:34.951Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\accesschk.exe" | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R_lkD_ | q-11d7cca501 | ok |

### F61 · malicious / high · T1552.001 · Sysinternals pspasswd.exe/pspasswd64.exe staged in Downloads\SysinternalsSuite on scranton

Evidence status: **verified**

On scranton.dmevals.local, the attacker's PowerShell (PID 3876, user pbeesly) wrote Sysinternals password-reset/credential tooling pspasswd64.exe and pspasswd.exe (plus their __MACOSX resource-fork copies) into C:\Users\pbeesly\Downloads\SysinternalsSuite at 03:00:28-03:00:32. pspasswd is a credential-manipulation tool; staging it alongside the other Sysinternals tools used in this intrusion is consistent with credential access. This is new relative to the anchors (which covered LSASS/SAM/certificate theft but not pspasswd staging).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:00:28.986Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Users\pbeesly\Downloads\SysinternalsSuite\pspasswd64.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1SIw95- | q-1eb9d31bec | ok |
| 2 | 2020-05-02 03:00:32.048Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Users\pbeesly\Downloads\SysinternalsSuite\pspasswd.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1SIwt7A | q-dc00671ecf | ok |
| 3 | 2020-05-02 03:00:28.986Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\WindowsPowerShell\v1.0\powershell.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1SIw95- | q-1eb9d31bec | ok |

### F63 · malicious / high · T1552.001 · Invoke-Exfil script embeds hardcoded cleartext credentials for WebDAV exfil

Evidence status: **NOT verified (1/2 evidence items)** — excluded from the verdict

On scranton.dmevals.local, a PowerShell script block (user pbeesly, script path C:\Program Files\SysinternalsSuite\psversion.ps1) defines Invoke-Exfil, which compresses the Downloads folder with password 'lolol' and maps a WebDAV drive to \\192.168.0.4\webdav using hardcoded credentials (user 'cozy', password 'MyCozyPassw0rd!'). This is unsecured-credential material embedded in the attacker's toolkit, new relative to the anchors.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | powershell.script_block_text | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b10BXt | q-8fcc7621b2 | ok |
| 2 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | winlog.event_data.ScriptBlockText | None | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b10BXt | q-8fcc7621b2 | FAILED: field winlog.event_data.ScriptBlockText not in the event |

### F27 · malicious / high · T1552.004 · PowerShell Get-PrivateKeys script exported machine certificates to .pfx on scranton

Evidence status: **verified**

On scranton.dmevals.local, user pbeesly ran a PowerShell script block (ScriptBlock ID 9d153741-75c3-4062-afe3-aeca0aee611b, Path C:\Program Files\SysinternalsSuite\readme.ps1) defining function Get-PrivateKeys. It enumerates cert:\LocalMachine recursively and calls Export-PfxCertificate for every certificate with a Thumbprint, writing each to $env:USERPROFILE\Downloads\<random>.pfx protected by the hardcoded password 'saribas'. The script executed: powershell.exe created C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx at 03:04:57 and the file was later accessed/deleted at 03:08:51. This is direct private-key/certificate theft (T1552.004).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | powershell.script_block_text | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b21vS3 | q-56d665ba8f | ok |
| 2 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\readme.ps1 | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b21vS3 | q-20fa13c1c1 | ok |
| 3 | 2020-05-02 03:04:57.460Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R_lUAH | q-e93fd84ad4 | ok |
| 4 | 2020-05-02 03:08:51.489Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\WindowsPowerShell\v1.0\powershell.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1RsNaXs | q-e93fd84ad4 | ok |

### F64 · malicious / high · T1552.004 · Get-PrivateKeys exports LocalMachine certificates to .pfx with hardcoded password on scranton

Evidence status: **verified**

On scranton.dmevals.local, PowerShell (user pbeesly) executed Get-PrivateKeys, which enumerates cert:\LocalMachine recursively and exports each certificate's private key to a .pfx protected by the hardcoded password 'saribas'. This is certificate private-key theft (unsecured private keys), consistent with the anchor but adds the hardcoded export password detail.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | powershell.script_block_text | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b21vS3 | q-5735b03caf | ok |
| 2 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | powershell.script_block_text | Get-PrivateKeys | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b21vTX | q-5735b03caf | ok |

### F33 · malicious / high · T1555 · pbeesly PowerShell toolkit opens LSASS with full access and exports certificate private keys on SCRANTON

Evidence status: **verified**

On 2020-05-02 between 03:04 and 03:09 UTC, user pbeesly on scranton.dmevals.local ran a PowerShell toolkit (loaded from C:\Program Files\SysinternalsSuite\psversion.ps1 / readme.ps1) that included credential-access functions. At 03:05:16 the PowerShell process opened a handle to \Device\HarddiskVolume2\Windows\System32\lsass.exe with AccessMask 0x1FFFFF (full access incl. read/write process memory), and Sysmon recorded the same PowerShell.exe->lsass.exe access with GrantedAccess 0x1fffff and 0x1f3fff. The same session defined and invoked Get-PrivateKeys, which enumerates cert:\LocalMachine and exports every certificate with a private key to .pfx files in the user's Downloads folder using the hardcoded password 'saribas'. This is credential/secret theft from the host's password/certificate stores, followed by staging (Invoke-Exfil compressing Downloads to OfficeSupplies.7z and copying to \\192.168.0.4\webdav) and cleanup (Invoke-BeachCleanup deleting *.pfx).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | win.AccessMask | 0x1fffff | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YldM_p | q-572a799e9d | ok |
| 2 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | win.ObjectName | \Device\HarddiskVolume2\Windows\System32\lsass.exe | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YldM_p | q-572a799e9d | ok |
| 3 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R-k131 | q-44b076bf41 | ok |
| 4 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R-k131 | q-44b076bf41 | ok |
| 5 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | powershell.script_block_text | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b21vS3 | q-f76e6ab251 | ok |
| 6 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | powershell.script_block_text | Get-PrivateKeys | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b21vTX | q-d5910618f6 | ok |

### F34 · malicious / medium · T1555.004 · Remote WMI/PowerShell LSASS handle with 0x1f3fff on NASHUA by pbeesly

Evidence status: **verified**

At 03:09:29 UTC on nashua.dmevals.local, wsmprovhost.exe (the host process for PowerShell Remoting) running as pbeesly requested a handle to \Device\HarddiskVolume2\Windows\System32\lsass.exe with AccessMask 0x1F3FFF (read/write process memory, duplicate handle, create thread). Sysmon corroborates wsmprovhost.exe->lsass.exe with GrantedAccess 0x1f3fff at 03:09:29.430. This is the same actor (pbeesly) who minutes earlier on SCRANTON opened LSASS with full access and exported certificate private keys, and who at 03:09:23 ran Invoke-Command -ComputerName NASHUA. Access to LSASS memory is the mechanism used to harvest Windows Credential Manager / DPAPI secrets, though no explicit vault/DPAPI object access was logged.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:09:29.000Z | nashua.dmevals.local | windows.security | win.AccessMask | 0x1f3fff | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YjaXaO | q-34ccde9201 | ok |
| 2 | 2020-05-02 03:09:29.000Z | nashua.dmevals.local | windows.security | win.ProcessName | C:\Windows\System32\wsmprovhost.exe | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YjaXaO | q-34ccde9201 | ok |
| 3 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1RrM7IJ | q-44b076bf41 | ok |
| 4 | 2020-05-02 03:09:23.000Z | scranton.dmevals.local | windows.powershell | powershell.script_block_text | Invoke-Command -ComputerName NASHUA -ScriptBlock { Get-Process -IncludeUserName \| Select-Object UserName,SessionId \| Where-Object { $_.UserName -like "*\$env:… | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1bsxQxS | q-b83fa21f54 | ok |

### F47 · malicious / high · T1558 · LSASS credential access by PowerShell on scranton during active intrusion

Evidence status: **verified**

On scranton.dmevals.local a malicious screen-saver (C:\ProgramData\victim\â€®cod.3aka3.scr) launched from explorer.exe spawned cmd.exe then powershell.exe, which ran an obfuscated stager (bitmap-decoded IEX), C# VirtualAlloc/CreateThread shellcode, discovery, persistence, private-key theft, screen capture and sdelete anti-forensics. At 2020-05-02T03:05:16 PowerShell.exe (PID 2976) opened lsass.exe (PID 736) with GrantedAccess 0x1f3fff and 0x1fffff (full access), the credential-access step that precedes Kerberos ticket theft/forging.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R-k131 | q-438b4ab72b | ok |
| 2 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R-k13y | q-438b4ab72b | ok |
| 3 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.TargetImage | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R-k131 | q-f6b5ef3056 | ok |
| 4 | 2020-05-02 02:55:56.157Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\ProgramData\victim\â€®cod.3aka3.scr | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1WiJkSG | q-251fa07937 | ok |
| 5 | 2020-05-02 02:58:45.000Z | scranton.dmevals.local | windows.powershell | powershell.script_block_text | sal a New-Object;Add-Type -AssemblyName 'System.Drawing'; $g=a System.Drawing.Bitmap('C:\Users\pbeesly\Downloads\monkey.png');$o=a Byte[] 4480;for($i=0; $i -le … | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b87aMP | q-07f5434bc1 | ok |

### F58 · malicious / high · T1649 · PowerShell Get-PrivateKeys exports all LocalMachine certificates to .pfx files (certificate theft)

Evidence status: **verified**

On scranton.dmevals.local, user pbeesly ran a PowerShell script block defining function Get-PrivateKeys that recursively enumerates cert:\LocalMachine, and for every certificate with a Thumbprint exports it via Export-PfxCertificate to a randomly-named .pfx file under $env:USERPROFILE\Downloads, protected by the hardcoded password 'saribas'. The script was invoked from C:\Program Files\SysinternalsSuite\readme.ps1 (ScriptBlock ID 9d153741-75c3-4062-afe3-aeca0aee611b) at 2020-05-01T23:04:56. Sysmon confirms the resulting artifact: powershell.exe (PID 3876) created C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx at 2020-05-02T03:04:57.460Z. This is theft of authentication certificates/private keys from the host certificate store, matching T1649.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | powershell.script_block_text | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b21vS3 | q-d4cc4af4ca | ok |
| 2 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\readme.ps1 | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b21vS3 | q-d4cc4af4ca | ok |
| 3 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | user.name | pbeesly | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b21vS3 | q-d4cc4af4ca | ok |
| 4 | 2020-05-02 03:04:57.460Z | scranton.dmevals.local | windows.sysmon | message | File created:  RuleName: -  UtcTime: 2020-05-02 03:04:57.460  ProcessGuid: {47ab858c-e23d-5eac-c603-000000000400}  ProcessId: 3876  Image: C:\windows\system32\W… | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R_lUAH | q-99d97415d9 | ok |
| 5 | 2020-05-02 03:04:57.460Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\WindowsPowerShell\v1.0\powershell.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R_lUAH | q-99d97415d9 | ok |

### F59 · malicious / high · T1649 · PowerShell Invoke-BeachCleanup removes stolen .pfx and staging artifacts

Evidence status: **verified**

On scranton.dmevals.local, user pbeesly executed a second PowerShell script block defining function Invoke-BeachCleanup (ScriptBlock ID 31f21f1d-9199-4d21-9ea8-c29b97841202, from C:\Program Files\SysinternalsSuite\psversion.ps1) at 2020-05-01T23:08:51. It deletes $env:USERPROFILE\Downloads\*.pfx (the exported certificate files), plus *.bmp, *.png and $env:APPDATA\OfficeSupplies.7z, i.e. anti-forensic cleanup of the certificate-theft artifacts. This directly follows and complements the Get-PrivateKeys export.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:08:51.000Z | scranton.dmevals.local | windows.powershell | powershell.script_block_text | function Invoke-BeachCleanup {     Write-Host "[*] Cleaning up"     Remove-Item -Path "$env:USERPROFILE\Downloads\*.pfx" -Force     Remove-Item -Path "$env:USER… | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1bsxh3C | q-cc81b35bce | ok |
| 2 | 2020-05-02 03:08:51.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\psversion.ps1 | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1bsxh3C | q-cc81b35bce | ok |
| 3 | 2020-05-02 03:08:51.000Z | scranton.dmevals.local | windows.powershell | user.name | pbeesly | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1bsxh3C | q-cc81b35bce | ok |

### F02 · suspicious / low · T1003.002 · LSASS wrote SAM account data on scranton

Evidence status: **verified**

On scranton.dmevals.local at 2020-05-02T03:19:10, lsass.exe (PID 748) set the registry value HKLM\SAM\SAM\Domains\Account\F. This is the SAM account database key. The write is performed by lsass.exe itself (the legitimate owner of the SAM hive), so it is consistent with normal OS behavior rather than an external dumping tool; no reg save / hive-copy activity was observed. Recorded as suspicious context only.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:10.368Z | scranton.dmevals.local | windows.sysmon | win.TargetObject | HKLM\SAM\SAM\Domains\Account\F | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1NY3HhA | q-c7c8902c52 | ok |
| 2 | 2020-05-02 03:19:10.368Z | scranton.dmevals.local | windows.sysmon | win.Image | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1NY3HhA | q-c7c8902c52 | ok |

### F10 · suspicious / medium · T1056.004 · wsmprovhost.exe remote PowerShell session opened LSASS with full access on nashua

Evidence status: **verified**

On 2020-05-02 at 03:09:29 UTC on nashua.dmevals.local, wsmprovhost.exe (PID 7720, entity {5aa8ec29-e463-5eac-6303-000000000400}) — the host process for remote PowerShell (WinRM) sessions — opened lsass.exe (PID 728) with GrantedAccess 0x1F3FFF. The call trace runs through Microsoft.PowerShell.Commands.Management.ni.dll, indicating a PowerShell cmdlet in a remote session requested full access to LSASS memory. This is consistent with credential API access from a remote PowerShell session, though no explicit hooking DLL was observed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1RrM7IJ | q-07d1942058 | ok |
| 2 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1RrM7IJ | q-07d1942058 | ok |

### F14 · suspicious / medium · T1110.003 · No password-spraying activity; 4648 explicit-credential logons are PSEXESVC lateral movement

Evidence status: **verified**

No 4625 events exist (C118/C119/C121 zero hits), so there is no spray pattern. The 15 event.code 4648 explicit-credential logons show pbeesly credentials being reused: on scranton from source.ip 10.0.1.6 to Target Server NASHUA over port 445 (cifs/NASHUA), and on nashua via C:\Windows\PSEXESVC.exe (PsExec service installed repeatedly per 7045 events). This is credential reuse for lateral movement, not password spraying.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:18.000Z | scranton.dmevals.local | windows.security | message | A logon was attempted using explicit credentials.    Subject:  	Security ID:		S-1-5-21-1830255721-3727074217-2423397540-1107  	Account Name:		pbeesly  	Account … | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YcSP2J | q-9eecc0741d | ok |
| 2 | 2020-05-02 03:11:40.000Z | nashua.dmevals.local | windows.security | process.executable | C:\Windows\PSEXESVC.exe | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YogQzA | q-86d1e8a14e | ok |

### F19 · suspicious / medium · T1187 · Credential-bearing SMB share access from 10.0.1.4 to SYSVOL/IPC$/ADMIN$

Evidence status: **verified**

The same source 10.0.1.4 (scranton.dmevals.local) generated network share access events on newyork.dmevals.local and nashua.dmevals.local, reaching \\*\SYSVOL, \\*\IPC$ and \\*\ADMIN$ with access masks such as 0x120089/0x12019f/0x17019f (read/write/execute-style masks) as accounts SCRANTON$ and pbeesly. This is consistent with the credential-bearing SMB activity that accompanies the WebDAV coercion, though SYSVOL/IPC$/ADMIN$ access is also common in legitimate domain administration, so it is assessed as suspicious rather than definitively malicious on its own.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:01:43.000Z | newyork.dmevals.local | windows.security | win.ShareName | \\*\SYSVOL | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1Yldc_Q | q-d939401643 | ok |
| 2 | 2020-05-02 03:01:43.000Z | newyork.dmevals.local | windows.security | source.ip | 10.0.1.4 | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1Yldc_Q | q-d939401643 | ok |
| 3 | 2020-05-02 03:10:23.000Z | nashua.dmevals.local | windows.security | win.ShareName | \\*\ADMIN$ | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YjaXZN | q-d939401643 | ok |
| 4 | 2020-05-02 03:10:23.000Z | nashua.dmevals.local | windows.security | user.name | pbeesly | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YjaXZN | q-d939401643 | ok |
| 5 | 2020-05-02 03:04:04.000Z | newyork.dmevals.local | windows.security | win.AccessMask | 0x12019f | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YhYtY1 | q-d939401643 | ok |

### F26 · suspicious / medium · T1539 · Adjacent credential/exfil activity found but it is not web session cookie theft

Evidence status: **verified**

While hunting T1539 I observed related attacker activity that is NOT cookie theft: on scranton.dmevals.local, pbeesly ran PsExec64.exe with plaintext credentials ('-u dmevals\pbeesly -p Fl0nk3rt0n!T0by') to execute C:\Windows\Temp\python.exe on \\NASHUA, and a PowerShell script block 'Invoke-Exfil' (Path C:\Program Files\SysinternalsSuite\psversion.ps1) that 7-Zips the user's Downloads folder with a password and copies it to a WebDAV share at \\192.168.0.4\webdav using hardcoded credentials. sdelete64.exe was then used to delete archives (working.zip, Draft.Zip, SysinternalsSuite.zip). This is credential use and data exfiltration, not theft of web session cookies, so it does not satisfy T1539.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:14:42.601Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\PsExec64.exe" -accepteula \\NASHUA -u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1RkEAFq | q-0f1c6e136c | ok |
| 2 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | powershell.script_block_text | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b10BXt | q-ec9ad2f63f | ok |
| 3 | 2020-05-02 03:17:18.030Z | nashua.dmevals.local | windows.sysmon | process.command_line | .\sdelete64.exe  /accepteula "C:\Users\pbeesly\AppData\Roaming\working.zip"  | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1Nc7emY | q-0f1c6e136c | ok |

### F28 · suspicious / low · T1552 · accesschk.exe created a file named passwordsDB on scranton

Evidence status: **verified**

On scranton.dmevals.local, pbeesly launched C:\Program Files\SysinternalsSuite\accessChk.exe (PID 9204) at 03:04:34, and one second later the process created the file C:\Program Files\SysinternalsSuite\passwordsDB. The name is credential-themed, but accesschk is a legitimate Sysinternals ACL-inspection tool and the created file sits in its own install directory, consistent with a tool output/log artifact rather than harvested credentials. No credential content was observed in the file. Treated as suspicious-but-unconfirmed for T1552.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:35.069Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Program Files\SysinternalsSuite\passwordsDB | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R_lkD8 | q-3801064bda | ok |
| 2 | 2020-05-02 03:04:34.951Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\accesschk.exe" | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R_lkD_ | q-964a8da407 | ok |

### F36 · suspicious / high · T1556 · LSASS accessed with PROCESS_ALL_ACCESS by PowerShell on scranton — credential theft, not authentication-process modification

Evidence status: **verified**

On scranton.dmevals.local at 2020-05-02T03:05:16Z, PowerShell.exe (PID 2976, running as SYSTEM) opened lsass.exe (PID 736) with GrantedAccess 0x1FFFFF (PROCESS_ALL_ACCESS) and 0x1f3fff, the classic handle access used to read credential material from LSASS. The same host/user context (pbeesly) also ran an Invoke-Exfil PowerShell script (03:08:02Z) that compresses data and copies it to a WebDAV share, and performed PsExec-style explicit-credential logons to nashua.dmevals.local. This is credential theft / lateral movement (T1003/T1021), NOT modification of the authentication process: no writes to LSA Notification Packages, Authentication Packages, Security Packages, NetworkProvider, PasswordFilter, or reversible-encryption settings were observed. The bulk of LSASS handle events (289 from svchost.exe with 0x1000, plus Azure antimalware/telemetry with 0x1400) are benign system behaviour.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R-k131 | q-f4406fa06d | ok |
| 2 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R-k131 | q-f4406fa06d | ok |
| 3 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.TargetImage | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R-k131 | q-f4406fa06d | ok |
| 4 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | powershell.script_block_text | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b10BXt | q-20df2f6bda | ok |
| 5 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | user.name | pbeesly | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b10BXt | q-20df2f6bda | ok |

### F48 · suspicious / medium · T1558.003 · Kerberos service-ticket requests for krbtgt and machine accounts by pbeesly (RC4)

Evidence status: **verified**

On newyork.dmevals.local the account pbeesly@DMEVALS.LOCAL requested Kerberos service tickets (event 4769) for machine accounts NEWYORK$, NASHUA$, SCRANTON$, WEC$ and notably for the krbtgt service (S-1-5-21-1830255721-3727074217-2423397540-502) with TicketOptions 0x60810010, all with TicketEncryptionType 0x12 (RC4). The repeated TGS requests for krbtgt and host SPNs from a single user, in the same window as the scranton credential-access activity, are consistent with Kerberoasting-style ticket harvesting, though no forged-ticket artifacts were observed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:04.000Z | newyork.dmevals.local | windows.security | win.ServiceName | krbtgt | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YhYtYx | q-45c1d06ea8 | ok |
| 2 | 2020-05-02 03:04:04.000Z | newyork.dmevals.local | windows.security | win.TicketEncryptionType | 0x12 | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YhYtYx | q-45c1d06ea8 | ok |
| 3 | 2020-05-02 03:04:04.000Z | newyork.dmevals.local | windows.security | win.TicketOptions | 0x60810010 | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YhYtYx | q-45c1d06ea8 | ok |
| 4 | 2020-05-02 03:09:23.000Z | newyork.dmevals.local | windows.security | win.ServiceName | NASHUA$ | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YjanYM | q-45c1d06ea8 | ok |
| 5 | 2020-05-02 03:04:04.000Z | newyork.dmevals.local | windows.security | user.name | pbeesly@DMEVALS.LOCAL | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YhYtYx | q-45c1d06ea8 | ok |

### F52 · suspicious / medium · T1606 · Credential-access intrusion chain on scranton (LSASS access + hidden PowerShell) — no web-credential forging observed

Evidence status: **verified**

On scranton.dmevals.local (user pbeesly) a hidden, obfuscated PowerShell was launched from control.exe ("PowerShell.exe" -noni -noexit -ep bypass -window hidden -c ... System.Drawing.Bitmap('C:\Users\pbeesly\Downloads\monkey.png') ... IEX(...)), a steganographic loader. Shortly after, PowerShell.exe (PID 2976) opened lsass.exe with GrantedAccess 0x1FFFFF (PROCESS_ALL_ACCESS) and 0x1f3fff, consistent with credential material access. A later script block (Invoke-Exfil) compresses the Downloads folder with a password and copies it to a WebDAV share \\192.168.0.4\webdav using hardcoded credentials. This is credential theft and exfiltration activity, but no artifact of forging web cookies or SAML tokens (T1606) was observed — the LSASS access is credential dumping, not web-credential forgery.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R-k131 | q-d716375932 | ok |
| 2 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R-k131 | q-a7e5f7c291 | ok |
| 3 | 2020-05-02 02:58:44.325Z | scranton.dmevals.local | windows.sysmon | process.command_line | "PowerShell.exe" -noni -noexit -ep bypass -window hidden -c "sal a New-Object;Add-Type -AssemblyName 'System.Drawing'; $g=a System.Drawing.Bitmap('C:\Users\pbee… | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1WdFNhN | q-9d50be5802 | ok |
| 4 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | powershell.script_block_text | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b10BXt | q-8ea8584def | ok |

### F03 · benign / medium · T1003.005 · LSASS updated cached domain credential store (HKLM\SECURITY\Cache\NL$1)

Evidence status: **verified**

lsass.exe repeatedly set HKLM\SECURITY\Cache\NL$1 on nashua.dmevals.local (03:11:40, 03:12:46, 03:13:49, 03:15:03) and on scranton.dmevals.local (03:20:46). The SECURITY\Cache\NL$ keys are the cached domain credential store, but the writes are made by lsass.exe itself, which legitimately maintains this cache during logon. No external process read or copied the hive, so this reflects normal OS credential-cache maintenance rather than dumping.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:40.144Z | nashua.dmevals.local | windows.sysmon | win.TargetObject | HKLM\SECURITY\Cache\NL$1 | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1RpKsLE | q-0b5b52c581 | ok |
| 2 | 2020-05-02 03:11:40.144Z | nashua.dmevals.local | windows.sysmon | win.Image | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1RpKsLE | q-0b5b52c581 | ok |
| 3 | 2020-05-02 03:20:46.691Z | scranton.dmevals.local | windows.sysmon | win.TargetObject | HKLM\SECURITY\Cache\NL$1 | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1NAd3XG | q-0b5b52c581 | ok |

### F04 · benign / high · T1040 · Azure Network Watcher packet capture via netsh trace on scranton.dmevals.local

Evidence status: **verified**

The only packet-capture activity in the dataset is the legitimate Azure Network Watcher agent. On scranton.dmevals.local, NetworkWatcherAgent.exe (running as SYSTEM, parent services.exe) launched 'netsh.exe trace start capture=yes traceFile="C:\windows\TEMP\...\*.etl"' at 2020-05-02T03:19:17Z and 'netsh.exe trace stop' at 03:19:24Z. The agent binary resides under C:\Packages\Plugins\Microsoft.Azure.NetworkWatcher.NetworkWatcherAgentWindows\1.4.1421.1\NetworkWatcherAgent\ and was also invoked with /service, Install /service /autoStart, Start /service /autoStart and Test /service /autoStart. This is Azure platform diagnostic capture, not adversary sniffing.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:17.154Z | scranton.dmevals.local | windows.sysmon | process.command_line | C:\windows\system32\netsh.exe trace start capture=yes traceFile="C:\windows\TEMP\E7116ECA-DFE6-43C7-8FA8-8D3AC5AA8726\B91E06C5-1C7C-4830-9A76-74FA211560A7.etl" | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1NW1Kgv | q-b129e3a347 | ok |
| 2 | 2020-05-02 03:19:17.154Z | scranton.dmevals.local | windows.sysmon | process.parent.executable | C:\Packages\Plugins\Microsoft.Azure.NetworkWatcher.NetworkWatcherAgentWindows\1.4.1421.1\NetworkWatcherAgent\NetworkWatcherAgent.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1NW1Kgv | q-b129e3a347 | ok |
| 3 | 2020-05-02 03:19:13.877Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Packages\Plugins\Microsoft.Azure.NetworkWatcher.NetworkWatcherAgentWindows\1.4.1421.1\NetworkWatcherAgent\NetworkWatcherAgent.exe" /service | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1WpSJN6 | q-5c1c3a9ea4 | ok |
| 4 | 2020-05-02 03:19:17.000Z | scranton.dmevals.local | windows.security | process.command_line | C:\windows\system32\netsh.exe trace start capture=yes traceFile="C:\windows\TEMP\E7116ECA-DFE6-43C7-8FA8-8D3AC5AA8726\B91E06C5-1C7C-4830-9A76-74FA211560A7.etl" | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YYOcv1 | q-7ce0ddd857 | ok |

### F05 · benign / high · T1040 · Azure Guest Agent ETW trace collection via logman on scranton.dmevals.local

Evidence status: **verified**

logman.exe was used on scranton.dmevals.local to create/start/stop ETW trace sessions (GAEvents, RTEvents, WindowsAzure-GuestAgent-Diagnostic) writing to C:\WindowsAzure\Logs\*.etl, all with parent C:\WindowsAzure\Packages\WaAppAgent.exe. This is the standard Azure Windows Guest Agent diagnostic tracing, not adversary network sniffing.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:29.000Z | scranton.dmevals.local | windows.security | process.command_line | "logman.exe" create trace GAEvents -max 50 -f bincirc -o C:\WindowsAzure\Logs\WaAppAgent.etl -p "{3000b92b-ca8b-4269-90ea-c4185ee09e92}" | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YXONNh | q-7ce0ddd857 | ok |
| 2 | 2020-05-02 03:19:41.000Z | scranton.dmevals.local | windows.security | process.command_line | "logman.exe" create trace RTEvents -max 50 -f bincirc -o C:\WindowsAzure\Logs\RuntimeEvents.etl -pf C:\WindowsAzure\Packages\GuestAgent\ProviderGuids.txt | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YKEhta | q-7ce0ddd857 | ok |
| 3 | 2020-05-02 03:19:29.878Z | scranton.dmevals.local | windows.sysmon | process.parent.executable | C:\WindowsAzure\Packages\WaAppAgent.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1NUxiiK | q-b129e3a347 | ok |

### F06 · benign / high · T1040 · No sniffing tools, capture drivers, or promiscuous-mode activity observed

Evidence status: **verified**

Hunting for classic network-sniffing artifacts returned nothing: no tcpdump/windump/wireshark/rawcap/dumpcap/tshark/pktmon process executions, no npcap/winpcap/pcap driver image loads (sysmon event 6 = 0 hits), and no promiscuous/raw-socket command lines. The single 'raw' command-line match was a PowerShell steganography loader (System.Drawing bitmap decode + IEX), unrelated to sniffing. Zeek showed only routine weird/notice events (self-signed SSL certs), no ICMP tunneling or sniffing indicators. The PsExec/sdelete64 activity on scranton is lateral movement/anti-forensics, not T1040.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:58:44.325Z | scranton.dmevals.local | windows.sysmon | process.command_line | "PowerShell.exe" -noni -noexit -ep bypass -window hidden -c "sal a New-Object;Add-Type -AssemblyName 'System.Drawing'; $g=a System.Drawing.Bitmap('C:\Users\pbee… | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1WdFNhN | q-b5397de07d | ok |
| 2 | 2020-04-30 00:15:18.392Z | simplerockbuild.simplerock.lan | zeek | zeek.note | SSL::Invalid_Server_Cert | .ds-logs-zeek-default-2026.10.16-000001 / AaFFktQ25mySA1aO74el | q-0034eff2a2 | ok |

### F11 · benign / high · T1110 · No brute-force authentication activity observed; credential access on scranton used LSASS memory access instead

Evidence status: **verified**

Across windows.security (41002 events, 02:55-03:28Z) there are zero 4625 failed-logon events, so no brute-force authentication pattern exists. The only 'logon/password' hits in windows.other are benign (RDP session logon succeeded for DMEVALS\pbeesly, Customer Experience logon notification, PTR registration failure). The genuine credential-access activity on scranton.dmevals.local is LSASS memory access by PowerShell.exe (GrantedAccess 0x1FFFFF) and a Get-PrivateKeys certificate-export script, which are not brute-force techniques.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:20:48.000Z | scranton.dmevals.local | windows.other | message | Remote Desktop Services: Session logon succeeded:    User: DMEVALS\pbeesly  Session ID: 2  Source Network Address: 172.18.39.2 | .ds-logs-windows.other-default-2026.10.16-000001 / AaFFkdQ25mySA1aOnx0y | q-969d27afcc | ok |
| 2 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R-k131 | q-bf69cce890 | ok |

### F12 · benign / high · T1110.001 · No password-guessing activity; no failed logons and no password-iterating scripts

Evidence status: **verified**

No 4625 events exist in windows.security (C105/C106/C107 zero hits), and no process command line containing 'password' was found in sysmon (C110 zero hits). The PowerShell script blocks matching 'Password'/'Credential' are benign: a Get-PrivateKeys function using ConvertTo-SecureString with a hardcoded string to export PFX certificates, and an Invoke-Exfil function using a 7-Zip archive password. None iterate over candidate passwords.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | powershell.script_block_text | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b21vS3 | q-e6baa287b4 | ok |
| 2 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | powershell.script_block_text | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b10BXt | q-b0f00c1d76 | ok |

### F13 · benign / high · T1110.002 · No offline password-cracking artifacts; LSASS handle opens are the credential-access mechanism

Evidence status: **verified**

No SAM/SECURITY hive reads under 4663/4656/4670 (C112 zero hits; the 'SAM' ObjectName values are benign registry key names). No wordlist/potfile creation (C114 shows only OS/WER/Cortana/Sysinternals text files). No hash/crack tooling command lines (C113 zero hits). The 326 lsass handle opens (C115) are dominated by svchost.exe with GrantedAccess 0x1000 (benign), but PowerShell.exe opened lsass.exe with 0x1FFFFF (PROCESS_ALL_ACCESS) on scranton at 03:05:16 — a credential-dumping indicator, not password cracking.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.TargetImage | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R-k131 | q-bf69cce890 | ok |
| 2 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R-k131 | q-bf69cce890 | ok |

### F15 · benign / high · T1110.004 · No credential-stuffing activity; no failed logons and no leaked-credential reuse pattern

Evidence status: **verified**

No 4625 events exist in windows.security (C125/C126/C127 zero hits) and no password-bearing command lines in sysmon (C130 zero hits). There is no evidence of stuffing lists or repeated authentication attempts against multiple accounts. The only credential reuse is pbeesly's own valid credentials used via PsExec/4648 for lateral movement, which is not credential stuffing.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:40.000Z | nashua.dmevals.local | windows.security | win.TargetUserName | pbeesly | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YogQzA | q-86d1e8a14e | ok |

### F16 · benign / high · T1111 · No MFA interception activity; 'Credential' hits are benign Windows internals

Evidence status: **verified**

Hunting for T1111 (Multi-Factor Authentication Interception) across windows.security, windows.sysmon, windows.powershell and windows.other produced no evidence of MFA/token/smart-card interception. All 'Credential'-related hits are standard Windows components: Wininit event 14 logging 'Credential Guard configuration: 0x0, 0' (Credential Guard disabled) on scranton, lsass.exe setting HKLM\System\CurrentControlSet\Control\DeviceGuard\Scenarios\CredentialGuard\Enabled to 0x00000000 at boot, and services.exe registering the built-in CredentialEnrollmentManagerUserSvc service. Explicit-credential logons (4648) are dominated by user pbeesly via C:\Windows\PSEXESVC.exe (PsExec) and normal winlogon/svchost/taskhostw processes. LSASS handle access (Sysmon 10) is almost entirely svchost.exe/powershell.exe with GrantedAccess 0x1000 (PROCESS_QUERY_LIMITED_INFORMATION), consistent with benign security tooling. No MFA provider, OTP, smart-card or token-interception artifacts were observed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:09.000Z | scranton.dmevals.local | windows.other | message | Credential Guard configuration: 0x0, 0 | .ds-logs-windows.other-default-2026.10.16-000001 / AaFFkdQ25mySA1aOnx1Y | q-f3926dad33 | ok |
| 2 | 2020-05-02 03:19:09.865Z | scranton.dmevals.local | windows.sysmon | message | Registry value set:  RuleName: -  EventType: SetValue  UtcTime: 2020-05-02 03:19:09.865  ProcessGuid: {47ab858c-e6ad-5eac-0c00-000000000500}  ProcessId: 748  Im… | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1NY3HhV | q-85ce8c20ac | ok |
| 3 | 2020-05-02 03:20:48.264Z | scranton.dmevals.local | windows.sysmon | message | Registry value set:  RuleName: -  EventType: SetValue  UtcTime: 2020-05-02 03:20:48.264  ProcessGuid: {47ab858c-e6ad-5eac-0b00-000000000500}  ProcessId: 736  Im… | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1NDgh5J | q-85ce8c20ac | ok |
| 4 | 2020-05-02 03:11:40.000Z | nashua.dmevals.local | windows.security | process.executable | C:\Windows\PSEXESVC.exe | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YogQzA | q-d0322b149c | ok |
| 5 | 2020-05-02 03:01:03.622Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1000 | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1SIwN6W | q-b1a09b48af | ok |

### F22 · benign / high · T1212 · Routine LSASS handle accesses by system/AV/telemetry processes are benign

Evidence status: **verified**

The bulk of Sysmon event 10 hits targeting lsass.exe come from legitimate components: svchost.exe with GrantedAccess 0x1000 (query-limited), Microsoft Azure IaaSAntimalware AntimalwareConfig.exe and WindowsAzureTelemetryService.exe with 0x1400/0x1000, and wininit.exe/csrss.exe with 0x1fffff at boot. These are normal OS/security-product behaviours and are not exploitation for credential access.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:20:41.869Z | scranton.dmevals.local | windows.sysmon | win.SourceImage | C:\Packages\Plugins\Microsoft.Azure.Security.IaaSAntimalware\1.5.5.9\AntimalwareConfig.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1NAenUm | q-85f1040662 | ok |
| 2 | 2020-05-02 03:19:09.803Z | scranton.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\wininit.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1NY3HhM | q-85f1040662 | ok |
| 3 | 2020-05-02 03:24:18.178Z | nashua.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1000 | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1MuaKzP | q-65240743fa | ok |

### F23 · benign / high · T1539 · WebDAV DavSetCookie process creation is benign WebDAV client cookie handling

Evidence status: **verified**

On scranton.dmevals.local, user pbeesly, rundll32.exe was spawned by svchost.exe with command line 'rundll32.exe C:\windows\system32\davclnt.dll,DavSetCookie 192.168.0.4 http://192.168.0.4/webdav' (5 occurrences, 2020-05-01 23:08:50 to 23:10:23). This is the standard Windows WebDAV client (davclnt.dll) setting a WebDAV cookie for the mapped http://192.168.0.4/webdav share, not theft of a browser session cookie. The same command line appears in Sysmon process-creation events on the same host.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:08:50.000Z | scranton.dmevals.local | windows.security | process.command_line | rundll32.exe C:\windows\system32\davclnt.dll,DavSetCookie 192.168.0.4 http://192.168.0.4/webdav | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YeU-Dp | q-df96e88075 | ok |
| 2 | 2020-05-02 03:10:23.154Z | scranton.dmevals.local | windows.sysmon | process.command_line | rundll32.exe C:\windows\system32\davclnt.dll,DavSetCookie 192.168.0.4 http://192.168.0.4/webdav | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1RrMLE_ | q-8bbed1db05 | ok |

### F24 · benign / high · T1539 · INetCookies file creation by svchost is a WARP JIT service package artifact

Evidence status: **verified**

On scranton.dmevals.local, svchost.exe (PID 7200, SYSTEM) created C:\Windows\ServiceProfiles\LocalService\AppData\Local\Packages\warp_jit_db4a1097-b484-4973-bbf2-a04208ecd4d4\AC\INetCookies at 2020-05-02T03:21:05.681Z. This is a per-package WinINet cookie store under the LocalService service profile for the Windows WARP JIT package, created by a system service, not a browser session cookie being stolen. No browser cookie database (Chrome/Edge/Firefox Cookies, Login Data, WebCache) was created or accessed anywhere in the dataset.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:21:05.681Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Windows\ServiceProfiles\LocalService\AppData\Local\Packages\warp_jit_db4a1097-b484-4973-bbf2-a04208ecd4d4\AC\INetCookies | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1MsOhX7 | q-5fa480680f | ok |
| 2 | 2020-05-02 03:21:05.681Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\System32\svchost.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1MsOhX7 | q-4e1df2510b | ok |

### F25 · benign / high · T1539 · No browser cookie-store access or cookie-stealing tooling observed

Evidence status: **verified**

Across windows.sysmon, windows.security, windows.powershell and windows.other, the only 'cookie'-related artifacts are the benign WebDAV DavSetCookie and the WARP JIT INetCookies file. Sysmon process-access (event 10) to browser processes (MicrosoftEdge.exe, MicrosoftEdgeCP.exe, MicrosoftEdgeSH.exe) and lsass.exe came only from svchost.exe and Explorer.EXE with routine access masks (0x1000, 0x2000, 0x3000), consistent with normal system operation rather than memory scraping for session cookies. No PowerShell script block, process command line, or file creation referenced browser cookie databases or cookie-theft utilities.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:24:23.993Z | nashua.dmevals.local | windows.sysmon | win.GrantedAccess | 0x2000 | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1Muar8B | q-6623997d8c | ok |
| 2 | 2020-05-02 03:24:18.178Z | nashua.dmevals.local | windows.sysmon | win.TargetImage | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1MuaKzP | q-6623997d8c | ok |

### F30 · benign / medium · T1552.001 · Explicit-credential logons (4648) by pbeesly to NASHUA via PsExec

Evidence status: **verified**

15 event.code 4648 explicit-credential logons were observed. pbeesly on scranton.dmevals.local used explicit credentials targeting server NASHUA, and on nashua.dmevals.local C:\Windows\PSEXESVC.exe performed 4648 logons as pbeesly to localhost. The remaining 4648s are routine winlogon/taskhostw DWM/UMFD/machine-account logons. This reflects PsExec-based lateral movement using pbeesly's own credentials, not credentials harvested from files; no file-based credential source was observed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:12:25.000Z | scranton.dmevals.local | windows.security | win.TargetServerName | NASHUA | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YcSCou | q-82543b2d17 | ok |
| 2 | 2020-05-02 03:11:40.000Z | nashua.dmevals.local | windows.security | process.executable | C:\Windows\PSEXESVC.exe | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YogQzA | q-82543b2d17 | ok |

### F31 · benign / high · T1552.002 · Registry Password/Credential value sets are OS-internal, not credential storage

Evidence status: **verified**

17 Sysmon event.code 13 registry value sets matched Password/Credential paths. All are legitimate OS activity: svchost.exe setting HKU\.DEFAULT\Software\Microsoft\IdentityCRL\ProviderPasswordLength/CharacterGroups on nashua and scranton, lsass.exe setting DeviceGuard\Scenarios\CredentialGuard\Enabled, services.exe registering CredentialEnrollmentManagerUserSvc, and winlogon.exe setting Winlogon\PasswordExpiryNotification. No adversary-written credential values were found.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:28.255Z | nashua.dmevals.local | windows.sysmon | win.TargetObject | HKU\.DEFAULT\Software\Microsoft\IdentityCRL\ProviderPasswordLength | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R8i4gn | q-f719d9bbad | ok |
| 2 | 2020-05-02 03:19:09.865Z | scranton.dmevals.local | windows.sysmon | win.TargetObject | HKLM\System\CurrentControlSet\Control\DeviceGuard\Scenarios\CredentialGuard\Enabled | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1NY3HhV | q-f719d9bbad | ok |

### F32 · benign / medium · T1552.003 · No shell-history credential access observed

Evidence status: **verified**

No events referencing consolehost_history or PowerShell history files were found in windows.sysmon process-creation or windows.security file-access data. No shell-history credential collection was observed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:34.951Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\accesschk.exe" | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R_lkD_ | q-964a8da407 | ok |

### F29 · benign / high · T1552.006 · SMB reads of GptTmpl.inf from Default Domain Policy by machine accounts

Evidence status: **verified**

Zeek smb_files records show hosts 10.0.1.4 and 10.0.1.6 opening \\NEWYORK.dmevals.local\sysvol paths including dmevals.local\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf. Windows security 5145 events on newyork.dmevals.local show the same GptTmpl.inf read by machine accounts SCRANTON$ and NASHUA$. This is the standard Default Domain Policy GUID being read during normal Group Policy processing by computer accounts, not GPP cpassword harvesting (no Groups.xml/cpassword access observed).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-04-30 00:20:49.313Z | bobs.bigwheel.local | zeek | message | {"@stream":"smb_files","@system":"bobs.bigwheel.local","@proc":"zeek","ts":1588206049.313572,"uid":"CF37FuG0Jho600cAa","id_orig_h":"10.0.1.6","id_orig_p":56957,… | .ds-logs-zeek-default-2026.10.16-000001 / AaFFktQ25mySA1bh-ZaM | q-df524d5a76 | ok |
| 2 | 2020-05-02 03:19:16.000Z | newyork.dmevals.local | windows.security | win.SubjectUserName | SCRANTON$ | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YTK7vy | q-ec5aa7f16a | ok |

### F35 · benign / high · T1555 · Benign LSASS handle accesses by system processes

Evidence status: **verified**

The majority of LSASS process-access events are routine: svchost.exe, services.exe, csrss.exe, wininit.exe, taskhostw.exe, RuntimeBroker.exe, backgroundTaskHost.exe, dsregcmd.exe, sppsvc.exe, wmiprvse.exe and Windows Defender MsMpEng.exe opening lsass.exe with GrantedAccess 0x1000/0x1400/0x1478/0x1fffff as part of normal OS operation. Also benign is lsass.exe itself opening C:\Windows\Temp\sdelete64.exe (0x1478) — the reverse direction, part of SDelete's normal operation. The WindowsAzure CollectGuestLogs.exe reading lsass.exe (0x1410) on all four hosts is Azure guest-log collection. These are not credential theft.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:17:18.071Z | nashua.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1Nc7emR | q-2bfd8b5695 | ok |
| 2 | 2020-05-02 03:17:18.071Z | nashua.dmevals.local | windows.sysmon | win.TargetImage | C:\Windows\Temp\sdelete64.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1Nc7emR | q-2bfd8b5695 | ok |
| 3 | 2020-05-02 03:22:38.000Z | nashua.dmevals.local | windows.security | win.ProcessName | C:\WindowsAzure\Packages\CollectGuestLogs.exe | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YEBswS | q-4463720da5 | ok |
| 4 | 2020-05-02 03:20:15.000Z | scranton.dmevals.local | windows.security | win.ProcessName | C:\Program Files\Windows Defender\MsMpEng.exe | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YGClc_ | q-4463720da5 | ok |

### F37 · benign / high · T1556.001 · Network logons are machine-account/DC replication traffic, no DC authentication backdoor

Evidence status: **verified**

The 218 LogonType 3 (network) 4624 events are dominated by the machine account NEWYORK$ logging on to newyork.dmevals.local from ::1, fe80:: and 10.0.0.4 — normal computer-account/DC authentication traffic. The 15 explicit-credential 4648 events are pbeesly authenticating to NASHUA via PSEXESVC.exe (lateral movement) and routine winlogon DWM/UMFD localhost logons. No evidence of a domain-controller authentication backdoor (no Skeleton Key / DSRM / authentication-package tampering).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:55:54.000Z | newyork.dmevals.local | windows.security | user.name | NEWYORK$ | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YsmoMw | q-1e8c959cfd | ok |
| 2 | 2020-05-02 03:11:40.000Z | nashua.dmevals.local | windows.security | process.executable | C:\Windows\PSEXESVC.exe | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YogQzA | q-dbd8da38a5 | ok |

### F38 · benign / high · T1556.002 · No password filter DLL registered or dropped

Evidence status: **verified**

No file creation of a DLL into System32 matching cryptdll/msv1_0/samlib/passwordfilter/networkprovider (0 hits), no 4657 registry change to Notification Packages or Password keys (0 hits), and no 4688/4104 referencing Notification/PasswordFilter (0 hits). No password filter DLL was installed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:01:42.236Z | scranton.dmevals.local | windows.sysmon | win.ImageLoaded | C:\Windows\System32\samlib.dll | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1SFrjaS | q-eac992f265 | ok |

### F39 · benign / high · T1556.005 · No reversible-encryption setting enabled

Evidence status: **verified**

Event 4739 (domain policy change) returned 0 hits, and no 4688/4104/sysmon process command line referenced Reversible/AllowReversiblePasswordEncryption/Set-ADUser/dsmod. No account was configured to store a reversibly-encrypted password.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:09.865Z | scranton.dmevals.local | windows.sysmon | registry.path | HKLM\System\CurrentControlSet\Control\Lsa\LsaCfgFlagsDefault | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1NY3HhS | q-6056352c55 | ok |

### F40 · benign / high · T1556.006 · No MFA configuration tampering

Evidence status: **verified**

No 4739/5136/4738 events (0 hits) and no Set-ADUser/Set-ADAuthenticationPolicy command lines. The only Authentication-related registry writes are routine LogonUI/FaceLogon session state written by LogonUI.exe and RuntimeBroker.exe, not MFA policy changes.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:20:46.756Z | scranton.dmevals.local | windows.sysmon | registry.path | HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\UserSwitch\Enabled | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1M_d1eR | q-6056352c55 | ok |

### F41 · benign / high · T1556.007 · No hybrid-identity / cloud-auth modification

Evidence status: **verified**

No 5136 directory-service changes (0 hits) and no Connect-MsolService/Connect-AzureAD/Set-AzureAD* PowerShell (0 hits). The dsregcmd.exe image load of cryptdll.dll on newyork is a normal device-registration operation, not hybrid-identity tampering.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:06:14.783Z | newyork.dmevals.local | windows.sysmon | process.executable | C:\Windows\System32\dsregcmd.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1R5ewC0 | q-eac992f265 | ok |

### F42 · benign / high · T1556.008 · No network provider DLL registered

Evidence status: **verified**

No 4657 registry change to NetworkProvider/Credential keys (0 hits) and no PowerShell referencing NetworkProvider/New-Item for a provider DLL (0 hits). No rogue network provider DLL was installed to capture credentials.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:09.834Z | scranton.dmevals.local | windows.sysmon | registry.path | HKLM\System\CurrentControlSet\Control\Lsa\LsaPid | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1NY3HhQ | q-6056352c55 | ok |

### F43 · benign / medium · T1557 · No adversary-in-the-middle activity observed; network/name-resolution events are benign Azure agent and domain traffic

Evidence status: **verified**

Across windows.security, windows.sysmon, windows.other and zeek there is no evidence of an adversary positioning in the middle of network traffic. The only network-configuration commands on the Windows hosts (arp.exe /a, route.exe print, netsh trace start/stop) were all spawned by legitimate Azure guest agents (WaAppAgent.exe, WindowsAzureTelemetryService.exe, WindowsAzureGuestAgent.exe, NetworkWatcherAgent.exe) on scranton.dmevals.local, i.e. routine Azure VM telemetry. DNS resolution (Sysmon 22) resolved only legitimate names to the domain controller 10.0.0.4 and Microsoft endpoints. SMB/RPC activity (5140/5145) was standard machine-account access to IPC$/SYSVOL (lsarpc/samr) between domain hosts. No relay, poisoning or interception tooling was found.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:20:04.471Z | scranton.dmevals.local | windows.sysmon | process.command_line | "arp.exe" /a | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1NKneCu | q-a15f14403e | ok |
| 2 | 2020-05-02 03:20:04.471Z | scranton.dmevals.local | windows.sysmon | process.parent.executable | C:\WindowsAzure\Packages\WaAppAgent.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1NKneCu | q-a15f14403e | ok |
| 3 | 2020-05-02 03:19:17.154Z | scranton.dmevals.local | windows.sysmon | process.parent.executable | C:\Packages\Plugins\Microsoft.Azure.NetworkWatcher.NetworkWatcherAgentWindows\1.4.1421.1\NetworkWatcherAgent\NetworkWatcherAgent.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1NW1Kgv | q-a15f14403e | ok |
| 4 | 2020-05-02 03:22:32.000Z | newyork.dmevals.local | windows.security | win.ShareName | \\*\IPC$ | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YDAqy3 | q-ce6d056ad5 | ok |

### F44 · benign / medium · T1557.001 · No name-resolution poisoning or SMB relay; DNS and SMB activity is normal domain traffic

Evidence status: **verified**

Sysmon DNS query events (event.code 22) on scranton/newyork/nashua resolved only legitimate names: the domain controller NEWYORK.dmevals.local -> 10.0.0.4, localhost, wec.dmevals.local -> 10.0.1.10, and Microsoft telemetry endpoints. No LLMNR/NBT-NS-style lookups or responses from unauthorized hosts were seen. The 4697/7045 service-install events were PsExec (PSEXESVC) and a 'Java(TM) Virtual Machine Support Service' (javamtsup.exe) — lateral movement/execution, not name-resolution poisoning or SMB relay. Zeek SMB activity (smb_mapping to \\NEWYORK.dmevals.local\IPC$, kerberos cifs/NASHUA) is standard domain authentication. No relay tooling in PowerShell script blocks.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:25:31.291Z | nashua.dmevals.local | windows.sysmon | win.QueryName | NEWYORK.dmevals.local | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1MubN05 | q-1c45f20b26 | ok |
| 2 | 2020-05-02 03:25:31.291Z | nashua.dmevals.local | windows.sysmon | win.QueryResults | ::ffff:10.0.0.4; | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1MubN05 | q-1c45f20b26 | ok |
| 3 | 2020-05-02 03:15:03.000Z | nashua.dmevals.local | windows.other | win.ServiceName | PSEXESVC | .ds-logs-windows.other-default-2026.10.16-000001 / AaFFkdQ25mySA1aOnx2W | q-7339ac9ca0 | ok |
| 4 | 2020-04-30 00:36:38.977Z | simplerockbuild.simplerock.lan | zeek | zeek.path | \\NEWYORK.dmevals.local\IPC$ | .ds-logs-zeek-default-2026.10.16-000001 / AaFFktQ25mySA1aO8IeN | q-1e8811aeeb | ok |

### F45 · benign / medium · T1557.002 · No ARP cache poisoning; MAC anomalies are synthetic/placeholder values and arp.exe runs are Azure agent telemetry

Evidence status: **verified**

Zeek conn records show source IP 10.0.1.4 with two different source MACs (00:0d:3a:4d:42:f2 and fc:bd:67:e1:a9:c1) and a responder MAC of 12:34:56:78:9a:bc. The 12:34:56:78:9a:bc address is a well-known synthetic/placeholder MAC used in Zeek test data, and fc:bd:67:e1:a9:c1 is a locally-administered/randomized MAC — neither indicates a single attacker MAC claiming multiple IPs. The only ARP-related commands on the Windows hosts were 'arp.exe /a' invocations, all spawned by legitimate Azure guest agents (WaAppAgent.exe, WindowsAzureTelemetryService.exe, WindowsAzureGuestAgent.exe) on scranton.dmevals.local, i.e. routine Azure VM telemetry rather than attacker ARP reconnaissance.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-04-30 00:44:52.044Z | simplerockbuild.simplerock.lan | zeek | zeek.resp_l2_addr | 12:34:56:78:9a:bc | .ds-logs-zeek-default-2026.10.16-000001 / AaFFktQ25mySA1aO8YcB | q-76c7504703 | ok |
| 2 | 2020-04-30 00:45:00.042Z | bobs.bigwheel.local | zeek | zeek.orig_l2_addr | fc:bd:67:e1:a9:c1 | .ds-logs-zeek-default-2026.10.16-000001 / AaFFktQ25mySA1bi_UDc | q-b90caebd30 | ok |
| 3 | 2020-05-02 03:19:40.288Z | scranton.dmevals.local | windows.sysmon | process.parent.executable | C:\WindowsAzure\Packages\Telemetry\WindowsAzureTelemetryService.exe | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1NNo5A0 | q-a15f14403e | ok |
| 4 | 2020-05-02 03:19:25.370Z | scranton.dmevals.local | windows.sysmon | process.command_line | "arp.exe" /a | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1NUyf30 | q-a15f14403e | ok |

### F46 · benign / medium · T1557.003 · No DHCP spoofing; no DHCP-related events or traffic observed

Evidence status: **verified**

No DHCP spoofing indicators exist in the data. The windows.other System channel contains no DHCP-related event codes (1341/1342/1020/1063) — the stacked event codes are unrelated (5858/5857/7045/7040 etc.). Sysmon network-connect destination ports (event.code 3) show no DHCP traffic (no ports 67/68); the observed ports are normal (8443, 389, 88, 53, 135, 445, 443). The Zeek capture contains no dhcp log type (only conn/files/ssl/x509/dce_rpc/http/dns/kerberos/smb_*). The Dhcp client service (svchost -s Dhcp) start on scranton is a normal service start.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:04.000Z | scranton.dmevals.local | windows.other | event.code | 3 | .ds-logs-windows.other-default-2026.10.16-000001 / AaFFkdQ25mySA1aOnx1V | q-2251a801cd | ok |
| 2 | 2020-05-02 03:19:11.533Z | scranton.dmevals.local | windows.sysmon | process.command_line | C:\windows\system32\svchost.exe -k LocalServiceNetworkRestricted -p -s Dhcp | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1NY2Xjg | q-907bf223a4 | ok |
| 3 | 2020-04-30 00:45:00.760Z | simplerockbuild.simplerock.lan | zeek | event.action | conn | .ds-logs-zeek-default-2026.10.16-000001 / AaFFktQ25mySA1aO8If9 | q-76c7504703 | ok |

### F49 · benign / medium · T1558.001 · No golden-ticket indicators observed

Evidence status: **verified**

No evidence of golden-ticket forging was found. All 28 Kerberos service-ticket requests (4769) used TicketEncryptionType 0x12 (RC4) with normal TicketOptions; there were no 4768/4769 anomalies, no krbtgt hash theft artifacts, and no PowerShell script blocks referencing golden/krbtgt (C312 zero hits). The krbtgt TGS requests seen are ordinary service-ticket requests, not forged TGTs.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:04.000Z | newyork.dmevals.local | windows.security | win.TicketEncryptionType | 0x12 | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YhYtYx | q-45c1d06ea8 | ok |

### F50 · benign / medium · T1558.002 · No silver-ticket indicators observed

Evidence status: **verified**

No evidence of silver-ticket forging. The 4769 service-ticket requests for host SPNs (NEWYORK$, NASHUA$, SCRANTON$, WEC$) all carry normal TicketOptions and RC4 encryption and were issued by the KDC with Failure Code 0x0; no PowerShell script blocks referencing silver/service-ticket/SPN forging were found (C319 zero hits).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:04.000Z | newyork.dmevals.local | windows.security | win.Status | 0x0 | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YhYtYx | q-c03d527973 | ok |

### F51 · benign / medium · T1558.004 · No AS-REP roasting indicators observed

Evidence status: **verified**

No evidence of AS-REP roasting. No PowerShell script blocks referencing AS-REP/asrep/GetNPUsers/DontRequirePreAuth were found (C334 zero hits), and no anomalous AS-REP request patterns were observed in the available data.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:04.000Z | newyork.dmevals.local | windows.security | event.code | 4769 | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YhYtYx | q-c03d527973 | ok |

### F53 · benign / high · T1606.001 · Cookie-related hits are benign Windows service artifacts; no cookie forging observed

Evidence status: **verified**

The only cookie-related file event is a svchost.exe creating C:\Windows\ServiceProfiles\LocalService\AppData\Local\Packages\warp_jit_...\AC\INetCookies on scranton — a normal Windows service-profile INetCookies store, not browser cookie theft or forgery. The single PowerShell 4104 hit matching 'cookie/token/session' is a benign Sysinternals readme.ps1 helper (Get-AttributesMask) that merely documents SE_GROUP_LOGON_ID token attributes. No Set-Cookie manipulation, session-token forging, or browser cookie tampering was observed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:21:05.681Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Windows\ServiceProfiles\LocalService\AppData\Local\Packages\warp_jit_db4a1097-b484-4973-bbf2-a04208ecd4d4\AC\INetCookies | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1MsOhX7 | q-985ba4ae70 | ok |
| 2 | 2020-05-02 03:04:04.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\readme.ps1 | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1b22vQJ | q-444ad2d020 | ok |

### F54 · benign / high · T1606.002 · No SAML token forging artifacts; PowerShell hits are benign AD DSC module

Evidence status: **verified**

No SAML/Assertion/NotOnOrAfter artifacts were found in PowerShell script blocks, process command lines, or Zeek HTTP URLs (checks C348/C350/C351 returned zero hits). The PowerShell 4104 events on newyork.dmevals.local (SYSTEM) are the benign xActiveDirectory DSC resource module MSFT_xADCommon.ps1 (Get-ADCommonParameters), and the windows.other 5857/5858 events are routine WMI RSOP DeleteInstance operations by SYSTEM. No forged SAML token activity was observed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:16:32.000Z | newyork.dmevals.local | windows.powershell | win.Path | C:\Program Files\WindowsPowerShell\Modules\xActiveDirectory\DscResources\MSFT_xADCommon\MSFT_xADCommon.ps1 | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1bsx-ky | q-b58440bef2 | ok |
| 2 | 2020-05-02 02:56:47.000Z | newyork.dmevals.local | windows.other | message | Id = {C11E1664-7828-4AD0-B23A-0FCEF0EA26C0}; ClientMachine = NEWYORK; User = NT AUTHORITY\SYSTEM; ClientProcessId = 1588; Component = Unknown; Operation = Start… | .ds-logs-windows.other-default-2026.10.16-000001 / AaFFkdQ25mySA1aOnx1E | q-cb516a1527 | ok |

### F55 · benign / high · T1621 · WMI provider/RSOP activity in windows.other is routine, not MFA request generation

Evidence status: **verified**

The only check with hits (C355) returned 85 events in windows.other matching event.code 4625/5857/5858. All retrieved events are routine WMI activity: event.code 5857 'provider started with result code 0x0' for standard providers (WMIProv, BcdProv, SppProvider, CIMWin32, StorageWMI, dnsclientcim, ProtectionManagement) hosted in wmiprvse.exe, and event.code 5858 IWbemServices::DeleteInstance operations against Root\Rsop\Computer RSOP_ExtensionStatus (ResultCode 0x80041002) on newyork.dmevals.local, plus one ExecNotificationQuery for Win32_ProcessStartTrace on scranton.dmevals.local. None of this relates to multi-factor authentication request generation; there are no MFA/2FA/authenticator prompts, no repeated authentication challenges, and no failed-logon bursts. No 4625 events exist in windows.security at all.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:56:47.000Z | newyork.dmevals.local | windows.other | message | Id = {C11E1664-7828-4AD0-B23A-0FCEF0EA26C0}; ClientMachine = NEWYORK; User = NT AUTHORITY\SYSTEM; ClientProcessId = 1588; Component = Unknown; Operation = Start… | .ds-logs-windows.other-default-2026.10.16-000001 / AaFFkdQ25mySA1aOnx1E | q-a9a0ec98f8 | ok |
| 2 | 2020-05-02 02:56:47.000Z | newyork.dmevals.local | windows.other | event.code | 5858 | .ds-logs-windows.other-default-2026.10.16-000001 / AaFFkdQ25mySA1aOnx1E | q-a9a0ec98f8 | ok |
| 3 | 2020-05-02 02:56:47.000Z | newyork.dmevals.local | windows.other | host.name | newyork.dmevals.local | .ds-logs-windows.other-default-2026.10.16-000001 / AaFFkdQ25mySA1aOnx1E | q-a9a0ec98f8 | ok |

### F56 · benign / high · T1621 · No failed-logon or authentication-challenge burst in windows.security

Evidence status: **verified**

Aggregating windows.security authentication events shows no 4625 (failed logon) events at all, and only a single 4776 credential-validation event (for pbeesly on newyork.dmevals.local). Successful logons (4624) are dominated by machine accounts (NEWYORK$, SCRANTON$, NASHUA$, UTICA$, WEC$) and SYSTEM, with pbeesly as the only interactive user. The 4648 explicit-credential events are routine (winlogon.exe for DWM/UMFD session accounts, taskhostw.exe, svchost.exe, and PSEXESVC.exe for pbeesly). This pattern is normal Windows authentication, not the repeated authentication-prompt flood characteristic of MFA request generation.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:20:40.000Z | newyork.dmevals.local | windows.security | event.code | 4776 | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YQHwYC | q-a2886893fe | ok |
| 2 | 2020-05-02 03:20:40.000Z | newyork.dmevals.local | windows.security | win.TargetUserName | pbeesly | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YQHwYC | q-a2886893fe | ok |
| 3 | 2020-05-02 03:12:46.000Z | nashua.dmevals.local | windows.security | process.executable | C:\Windows\PSEXESVC.exe | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YcSCoM | q-b4601ca6d9 | ok |

### F57 · benign / high · T1621 · PowerShell and Sysmon keyword hits are benign Windows components

Evidence status: **verified**

The PowerShell 4104 hits matching 'authenticat' are a Microsoft module manifest (ModuleVersion 2.16.0.0, Author 'Microsoft Corporation') on newyork.dmevals.local, not MFA tooling. The Sysmon process-creation hits matching 'push' are the legitimate Windows services PushToInstall (svchost.exe -k netsvcs -p -s PushToInstall, started via sc.exe start pushtoinstall registration) and dmwappushservice on scranton.dmevals.local. Neither is an MFA push-notification generator. Zeek shows no MFA/identity-provider traffic (no okta/duo/mfa DNS queries or login/auth URLs); its 2140 events are conn/files/ssl/x509/dce_rpc/http/dns/kerberos/smb, with no authentication-prompt activity.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:16:32.000Z | newyork.dmevals.local | windows.powershell | event.code | 4104 | .ds-logs-windows.powershell-default-2026.10.16-000001 / AaFFkdQ25mySA1bsx-kn | q-1809e7ccc7 | ok |
| 2 | 2020-05-02 03:22:11.866Z | scranton.dmevals.local | windows.sysmon | process.command_line | C:\windows\System32\svchost.exe -k netsvcs -p -s PushToInstall | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1MtWeH6 | q-dee15f7f26 | ok |
| 3 | 2020-05-02 03:02:46.072Z | scranton.dmevals.local | windows.sysmon | process.command_line | C:\windows\system32\svchost.exe -k netsvcs -p -s dmwappushservice | .ds-logs-windows.sysmon-default-2026.10.16-000001 / AaFFkNQ25mySA1SDpoh0 | q-dee15f7f26 | ok |

### F60 · benign / medium · T1649 · SystemCertificates ROOT certificate blob modified on nashua (benign OS certificate store activity)

Evidence status: **verified**

On nashua.dmevals.local a single registry value modification (event 4657) touched \REGISTRY\MACHINE\SOFTWARE\Microsoft\SystemCertificates\ROOT\Certificates\BE36A4562FB2EE05DBB3D32323ADF445084ED656 (Blob), performed by account NASHUA$ (S-1-5-18, Logon ID 0x3E7) with process C:\Windows\Sysmon.exe. This is a single SYSTEM-context write to the machine ROOT certificate store, consistent with normal OS certificate-store maintenance rather than attacker certificate forging; no corresponding export/forging tooling was observed on nashua.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:16:19.000Z | nashua.dmevals.local | windows.security | win.ObjectName | \REGISTRY\MACHINE\SOFTWARE\Microsoft\SystemCertificates\ROOT\Certificates\BE36A4562FB2EE05DBB3D32323ADF445084ED656 | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YeUuC- | q-3c68132d3d | ok |
| 2 | 2020-05-02 03:16:19.000Z | nashua.dmevals.local | windows.security | user.name | NASHUA$ | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YeUuC- | q-3c68132d3d | ok |
| 3 | 2020-05-02 03:16:19.000Z | nashua.dmevals.local | windows.security | process.executable | C:\Windows\Sysmon.exe | .ds-logs-windows.security-default-2026.10.16-000001 / AaFFkdQ25mySA1YeUuC- | q-3c68132d3d | ok |

## Technique conclusions

One line per technique in scope: status from the triage of its family; `not_observed` = checked, nothing found; `not_observable` = no dataset records it.

| Technique | Status | Reason |
|---|---|---|
| T1003 OS Credential Dumping | malicious | LSASS memory was accessed with PROCESS_ALL_ACCESS by PowerShell.exe on scranton, consistent with OS credential dumping. |
| T1003.001 LSASS Memory | malicious | PowerShell.exe (PID 2976) opened lsass.exe with GrantedAccess 0x1FFFFF/0x1F3FFF on scranton at 03:05:16; wsmprovhost.exe opened lsass with 0x1F3FFF on nashua at 03:09:29. |
| T1003.002 Security Account Manager | suspicious | lsass.exe wrote HKLM\SAM\SAM\Domains\Account\F on scranton, but by the legitimate hive owner; no external hive copy observed. |
| T1003.003 NTDS | not_observed | No NTDS.dit access, vssadmin/diskshadow/ntdsutil activity or ntds file creation found in any dataset. |
| T1003.004 LSA Secrets | not_observed | No LSA Secrets (SECURITY\Policy\Secrets) access or lsadump/reg save activity found. |
| T1003.005 Cached Domain Credentials | benign | HKLM\SECURITY\Cache\NL$1 writes were performed by lsass.exe itself, normal cached-credential maintenance. |
| T1003.006 DCSync | not_observed | No DCSync/drsuapi/lsadump command lines or replication activity found in sysmon or powershell. |
| T1040 Network Sniffing | benign | The only packet-capture activity is the legitimate Azure Network Watcher agent (NetworkWatcherAgent.exe -> netsh trace start capture=yes) and Azure Guest Agent logman ETW traces on scranton.dmevals.local, both running as… |
| T1056 Input Capture | malicious | PowerShell.exe on scranton opened LSASS with full access (0x1f3fff/0x1fffff) and pbeesly ran Get-PrivateKeys/Get-Clipboard/Invoke-ScreenCapture — credential and input capture on the host. |
| T1056.001 Keylogging | malicious | pbeesly executed Get-Keystrokes (with a preceding Keystroke-Check AV-enumeration function) on scranton.dmevals.local — a PowerShell keylogger. |
| T1056.002 GUI Input Capture | malicious | pbeesly defined and invoked Invoke-ScreenCapture using System.Windows.Forms/System.Drawing to capture the screen on scranton.dmevals.local. |
| T1056.003 Web Portal Capture | not_observed | No web-portal capture artifacts: zero hits for IIS/wwwroot/inetpub/login file or process activity, and no HTTP POST in the zeek window. |
| T1056.004 Credential API Hooking | suspicious | wsmprovhost.exe (remote PowerShell) opened LSASS with 0x1f3fff on nashua via a PowerShell Management cmdlet call trace, but no hooking DLL or explicit API-hook artifact was observed. |
| T1110 Brute Force | not_observed | Zero 4625 failed-logon events in windows.security; no brute-force authentication pattern. Credential access present on scranton is LSASS memory access (0x1FFFFF) and cert export, not brute force. |
| T1110.001 Password Guessing | not_observed | No 4625 events and no password-iterating scripts; PowerShell Password/Credential hits are benign cert-export and 7-Zip archive password usage. |
| T1110.002 Password Cracking | not_observed | No SAM/SECURITY hive reads, no wordlist/potfile creation, no hash/crack tooling. LSASS handle opens are the credential-access mechanism, not offline cracking. |
| T1110.003 Password Spraying | not_observed | No 4625 events, so no spray pattern. 4648 explicit-credential logons reflect pbeesly credential reuse via PSEXESVC for lateral movement, not spraying. |
| T1110.004 Credential Stuffing | not_observed | No 4625 events and no password-bearing command lines; no stuffing list or multi-account authentication attempts observed. |
| T1111 Multi-Factor Authentication Interception | not_observed | No MFA/token/smart-card interception artifacts in any dataset. All 'Credential' hits are benign Windows internals (Credential Guard disabled config, CredentialEnrollmentManagerUserSvc service registration, lsass DeviceGu… |
| T1187 Forced Authentication | malicious | Host 10.0.1.4 (scranton.dmevals.local) attempted SMB to 192.168.0.4 on 445/139 (all REJ), then fell back to WebDAV over HTTP port 80 using the DavClnt and Microsoft-WebDAV-MiniRedir/10.0.18362 user agents, issuing OPTION… |
| T1212 Exploitation for Credential Access | malicious | On nashua.dmevals.local, wsmprovhost.exe (PowerShell remoting host) opened lsass.exe with GrantedAccess 0x1f3fff via PowerShell's Management module at 03:09:29, the only non-system/non-AV LSASS access in the dataset. It … |
| T1539 Steal Web Session Cookie | not_observed | All cookie-related hits are benign: WebDAV client DavSetCookie (davclnt.dll) process creations on scranton.dmevals.local and a WARP JIT service-package INetCookies file created by svchost.exe. No browser cookie database … |
| T1552 Unsecured Credentials | malicious | accesschk.exe wrote a file named passwordsDB in C:\Program Files\SysinternalsSuite on scranton. |
| T1552.001 Credentials In Files | malicious | pspasswd.exe/pspasswd64.exe staged in Downloads\SysinternalsSuite and hardcoded cleartext credentials (cozy/MyCozyPassw0rd!) embedded in the Invoke-Exfil script on scranton. |
| T1552.002 Credentials in Registry | benign | All Password/Credential registry value sets are legitimate OS activity by svchost/lsass/services/winlogon; no adversary credential storage. |
| T1552.003 Shell History | not_observed | No consolehost_history or shell-history file access found in sysmon or security data. |
| T1552.004 Private Keys | malicious | Get-PrivateKeys exported LocalMachine certificate private keys to .pfx using hardcoded password 'saribas' on scranton. |
| T1552.006 Group Policy Preferences | benign | GptTmpl.inf reads from the Default Domain Policy GUID are normal Group Policy processing by machine accounts; no Groups.xml/cpassword access. |
| T1555 Credentials from Password Stores | malicious | pbeesly's PowerShell on SCRANTON opened LSASS with AccessMask 0x1FFFFF (full access) and ran Get-PrivateKeys exporting all machine certificate private keys to .pfx files with hardcoded password 'saribas'; staged via Invo… |
| T1555.003 Credentials from Web Browsers | not_observed | All browser credential-store checks (Login Data, logins.json, browser process/file access) returned zero hits across sysmon, security, powershell and other datasets. |
| T1555.004 Windows Credential Manager | suspicious | wsmprovhost.exe as pbeesly opened LSASS with 0x1f3fff on NASHUA (read/write process memory) shortly after the SCRANTON LSASS full-access event; LSASS memory access is the mechanism for harvesting Credential Manager/DPAPI… |
| T1555.005 Password Managers | not_observed | All password-manager checks (keepass/1password/bitwarden/lastpass/kdbx) returned zero hits across all four datasets. |
| T1556 Modify Authentication Process | not_observed | LSASS was accessed with PROCESS_ALL_ACCESS (0x1fffff) by PowerShell on scranton, but this is credential theft (T1003), not modification of the authentication process. No authentication-process components were altered. |
| T1556.001 Domain Controller Authentication | not_observed | LogonType 3 traffic is machine-account/DC authentication; 4648 events are PsExec lateral movement and routine winlogon logons. No DC authentication backdoor. |
| T1556.002 Password Filter DLL | not_observed | No password filter DLL dropped into System32 and no Notification Packages registry change (0 hits). |
| T1556.005 Reversible Encryption | not_observed | No 4739 policy change and no reversible-encryption configuration commands (0 hits). |
| T1556.006 Multi-Factor Authentication | not_observed | No 4739/5136/4738 events and no MFA policy modification commands (0 hits). |
| T1556.007 Hybrid Identity | not_observed | No 5136 directory changes and no cloud/hybrid identity PowerShell cmdlets (0 hits). |
| T1556.008 Network Provider DLL | not_observed | No NetworkProvider registry change and no network provider DLL installation (0 hits). |
| T1557 Adversary-in-the-Middle | not_observed | No AiTM positioning found: network-config commands (arp/route/netsh) were all spawned by legitimate Azure guest agents; DNS and SMB traffic is normal domain activity. |
| T1557.001 Name Resolution Poisoning and SMB Relay | not_observed | No LLMNR/NBT-NS poisoning or SMB relay: DNS queries resolved only legitimate names to the DC 10.0.0.4; 4697/7045 installs were PsExec/javamtsup (lateral movement), not relay; SMB was standard domain IPC$/SYSVOL access. |
| T1557.002 ARP Cache Poisoning | not_observed | No ARP cache poisoning: the anomalous MACs are synthetic/placeholder (12:34:56:78:9a:bc) and randomized (fc:bd:67:e1:a9:c1); arp.exe /a runs were Azure agent telemetry, not attacker reconnaissance. |
| T1557.003 DHCP Spoofing | not_observed | No DHCP spoofing: no DHCP event codes (1341/1342/1020/1063) in windows.other, no DHCP ports 67/68 in Sysmon network connects, and no dhcp log type in the Zeek capture. |
| T1558 Steal or Forge Kerberos Tickets | malicious | PowerShell.exe (PID 2976) on scranton.dmevals.local opened lsass.exe with GrantedAccess 0x1f3fff/0x1fffff during an active intrusion chain (malicious .scr -> cmd -> powershell stager), the credential-access step enabling… |
| T1558.001 Golden Ticket | not_observed | No golden-ticket artifacts: no krbtgt hash theft, no anomalous TGT forging, no golden/krbtgt references in PowerShell (C312 zero hits). |
| T1558.002 Silver Ticket | not_observed | No silver-ticket artifacts: 4769 host-SPN requests are normal KDC-issued RC4 tickets with Failure Code 0x0; no silver/SPN forging scripts (C319 zero hits). |
| T1558.003 Kerberoasting | suspicious | pbeesly@DMEVALS.LOCAL on newyork.dmevals.local requested TGS tickets for krbtgt and multiple machine accounts, all RC4 (0x12), consistent with Kerberoasting-style ticket harvesting. |
| T1558.004 AS-REP Roasting | not_observed | No AS-REP roasting indicators; no AS-REP/GetNPUsers/DontRequirePreAuth references in PowerShell (C334 zero hits). |
| T1606 Forge Web Credentials | not_observed | Credential-access activity (LSASS access 0x1FFFFF by PowerShell, hidden steganographic PowerShell loader, WebDAV exfiltration) was observed on scranton, but no artifact of forging web credentials (cookie/SAML/token minti… |
| T1606.001 Web Cookies | not_observed | Only cookie-related event is a benign svchost INetCookies service-profile file; the matching PowerShell script block is a benign Sysinternals readme.ps1. No cookie forging or session-token manipulation observed. |
| T1606.002 SAML Tokens | not_observed | Zero hits for SAML/Assertion/NotOnOrAfter in PowerShell, process command lines, or Zeek HTTP URLs. PowerShell 4104 hits are the benign xActiveDirectory DSC module; windows.other 5857/5858 are routine WMI RSOP operations. |
| T1621 Multi-Factor Authentication Request Generatio… | not_observed | No MFA request generation activity found. windows.security contains zero 4625 failed logons and only one 4776 (pbeesly); no authentication-challenge flood. The sole hit (C355, windows.other) is routine WMI provider start… |
| T1649 Steal or Forge Authentication Certificates | malicious | On scranton.dmevals.local, user pbeesly ran a PowerShell Get-PrivateKeys function that recursively enumerated cert:\LocalMachine and exported every certificate with a thumbprint via Export-PfxCertificate to randomly-name… |

## Context (outside the hypothesis)

Activity reported under techniques outside the hypothesis' scope. Not verified, not part of the verdict.

- T1070.004 · malicious/high · Invoke-BeachCleanup deletes stolen .pfx/.bmp/.png and staged archive on scranton (pivot)
- T1070.004 · malicious/high · Invoke-BeachCleanup deletes stolen .pfx/.bmp/.png and staged archive on scranton (pivot)

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

Every MCP tool call of this run (1118), in order (source: mcp_audit.jsonl written by the MCP server).

| Query | Phase | Tool | Arguments | Hits / rows | Cited by |
|---|---|---|---|---|---|
| q-686f3167f9 | scope | list_data_sources | {} | None |  |
| q-6beb134912 | scope | get_registry | {} | None |  |
| q-3c44dc1de9 | scope | get_fields | {"dataset": "windows.other", "prefix": ""} | None |  |
| q-fc2df3bfb0 | scope | get_fields | {"dataset": "windows.powershell", "prefix": ""} | None |  |
| q-ac82649074 | scope | get_fields | {"dataset": "windows.security", "prefix": ""} | None |  |
| q-ecdccf5165 | scope | get_fields | {"dataset": "windows.sysmon", "prefix": ""} | None |  |
| q-ed5ba0ee19 | scope | get_fields | {"dataset": "zeek", "prefix": ""} | None |  |
| q-81c2c9df8f | check C001 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 447 |  |
| q-b42fd1f843 | check C002 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-d2424701f1 | check C003 | aggregate | {"dataset": "windows.security", "field": "win.ObjectType", "query": "event.code:(4656 OR 4663 OR 4670)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 10977 |  |
| q-1433e32e49 | check C004 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 460 |  |
| q-8807eb4283 | check C005 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*lsass* OR powershell.script_block_text:*mimikatz* OR powershell.script_block_text:*sekurlsa* OR powershell.script_block_text:*DumpCreds*)", "time_from": null, "time_… | 0 |  |
| q-7d152957e2 | check C006 | search | {"dataset": "windows.other", "query": "message:(*lsass* OR *mimikatz* OR *sekurlsa* OR *procdump*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "p… | 0 |  |
| q-17b5ff5721 | check C007 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-a92534fd2d | check C008 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 326 |  |
| q-16551aad69 | check C009 | aggregate | {"dataset": "windows.sysmon", "field": "win.SourceImage", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-f2e9ee4cc4 | check C010 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*lsass* OR file.path:*.dmp)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "pro… | 2 |  |
| q-106f350f16 | check C011 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*lsass* OR process.command_line:*comsvcs* OR process.command_line:*MiniDump*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dat… | 1 |  |
| q-d8c6cb8615 | check C012 | search | {"dataset": "windows.sysmon", "query": "event.code:(13 OR 14) AND registry.path:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.comm… | 0 |  |
| q-c1a13f4df0 | check C013 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4673", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 934 |  |
| q-fc7fe8902a | check C014 | search | {"dataset": "windows.security", "query": "event.code:4656 AND win.ObjectName:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command… | 13 |  |
| q-9b5a843142 | check C015 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*lsass* OR powershell.script_block_text:*MiniDump* OR powershell.script_block_text:*Invoke-Mimikatz*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "… | 0 |  |
| q-86a19e1d61 | check C016 | search | {"dataset": "windows.other", "query": "message:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 0 |  |
| q-9fad29cedf | check C017 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*SAM* OR file.path:*SECURITY* OR file.path:*SYSTEM*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "… | 3 |  |
| q-e244e5fd37 | check C018 | search | {"dataset": "windows.sysmon", "query": "event.code:(13 OR 14) AND (registry.path:*SAM* OR registry.path:*SECURITY*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "proces… | 7 |  |
| q-d10503889c | check C019 | search | {"dataset": "windows.sysmon", "query": "event.code:2 AND (process.command_line:*SAM* OR process.command_line:*reg*save*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "p… | 0 |  |
| q-f64591bd52 | check C020 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*reg save* OR process.command_line:*save*hklm* OR process.command_line:*SAM*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dat… | 0 |  |
| q-f0d4410ed1 | check C021 | aggregate | {"dataset": "windows.security", "field": "process.command_line", "query": "event.code:4688 AND (process.command_line:*reg* OR process.command_line:*save*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 6 |  |
| q-fe111bae53 | check C022 | search | {"dataset": "windows.security", "query": "event.code:(4656 OR 4663) AND (win.ObjectName:*SAM* OR win.ObjectName:*SECURITY*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name",… | 10 |  |
| q-91e243ff90 | check C023 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*SAM* OR powershell.script_block_text:*reg save* OR powershell.script_block_text:*hive*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "… | 11 |  |
| q-a21b0fef81 | check C024 | search | {"dataset": "windows.other", "query": "message:(*SAM* OR *SECURITY hive* OR *reg save*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.comm… | 0 |  |
| q-2d2ab54738 | check C025 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*ntds* OR file.path:*NTDS*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "pro… | 0 |  |
| q-9db71c868b | check C026 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*ntds* OR process.command_line:*vssadmin* OR process.command_line:*ntdsutil* OR process.command_line:*diskshadow*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "ho… | 0 |  |
| q-07bef69851 | check C027 | search | {"dataset": "windows.sysmon", "query": "event.code:2 AND file.path:*ntds*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "so… | 0 |  |
| q-2681274f8f | check C028 | aggregate | {"dataset": "windows.security", "field": "process.command_line", "query": "event.code:4688 AND (process.command_line:*ntds* OR process.command_line:*vssadmin* OR process.command_line:*diskshadow*)", "time_from": null, "time_to": null, "size": 50, "sub_field": … | 0 |  |
| q-11151f3c7c | check C029 | search | {"dataset": "windows.other", "query": "message:(*shadow* OR *VSS* OR *ntds*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 0 |  |
| q-226bb31b9e | check C030 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*ntds* OR powershell.script_block_text:*diskshadow* OR powershell.script_block_text:*vssadmin*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.n… | 0 |  |
| q-6fb111588c | check C031 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 326 |  |
| q-26903c25c3 | check C032 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*secrets* OR process.command_line:*lsadump* OR process.command_line:*reg save*HKLM\\\\SECURITY*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observe… | 0 |  |
| q-aac32bbff3 | check C033 | search | {"dataset": "windows.sysmon", "query": "event.code:7 AND win.ImageLoaded:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_lin… | 1 |  |
| q-de9306687c | check C034 | search | {"dataset": "windows.security", "query": "event.code:(4656 OR 4663 OR 4670) AND win.ObjectName:*SECURITY*Policy*Secrets*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "p… | 0 |  |
| q-eab8e396e1 | check C035 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:(4656 OR 4663 OR 4670) AND win.ObjectName:*Secrets*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-8205068e0e | check C036 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*Secrets* OR powershell.script_block_text:*lsadump* OR powershell.script_block_text:*LSA*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name",… | 0 |  |
| q-26c9a43cb8 | check C037 | search | {"dataset": "windows.other", "query": "message:(*Secrets* OR *LSA* OR *lsadump*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_lin… | 0 |  |
| q-d229b7f2a0 | check C038 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 326 |  |
| q-bf7a7dcafb | check C039 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*cache* OR process.command_line:*DCC2* OR process.command_line:*mscache* OR process.command_line:*cachedump*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.na… | 4 |  |
| q-bea08a9c6e | check C040 | search | {"dataset": "windows.security", "query": "event.code:(4656 OR 4663 OR 4670) AND (win.ObjectName:*Cache* OR win.ObjectName:*SECURITY*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "u… | 0 |  |
| q-f5fc5bd15c | check C041 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:(4656 OR 4663 OR 4670) AND win.ObjectName:*Cache*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-b8b9a702b0 | check C042 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*cache* OR powershell.script_block_text:*DCC2* OR powershell.script_block_text:*mscache*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", … | 0 |  |
| q-32fcb5bc16 | check C043 | search | {"dataset": "windows.other", "query": "message:(*cached*credential* OR *mscache* OR *DCC2*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.… | 0 |  |
| q-7c199c2fd4 | check C044 | count | {"dataset": "windows.security", "query": "event.code:4662", "time_from": null, "time_to": null} | 7 |  |
| q-0328d434e2 | check C045 | aggregate | {"dataset": "windows.security", "field": "win.AccessMask", "query": "event.code:4662", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 7 |  |
| q-521a389ea3 | check C046 | aggregate | {"dataset": "windows.security", "field": "win.SubjectUserName", "query": "event.code:4662", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 7 |  |
| q-4e8f9920af | check C047 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*drsuapi* OR process.command_line:*lsadump* OR process.command_line:*dcsync*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dat… | 0 |  |
| q-172a899004 | check C048 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*DCSync* OR powershell.script_block_text:*lsadump* OR powershell.script_block_text:*drsuapi*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.nam… | 0 |  |
| q-44560b776f | check C049 | search | {"dataset": "windows.other", "query": "event.code:7045 OR event.code:5858 OR event.code:5857", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process… | 90 |  |
| q-cdad8d55db | check C050 | search | {"dataset": "zeek", "query": "event.action:dce_rpc AND (zeek.operation:*DRSUAPI* OR zeek.endpoint:*drsuapi* OR zeek.named_pipe:*drsuapi*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code"… | 9 |  |
| q-9990c79c1d | check C051 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 460 |  |
| q-c818a8f958 | check C052 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*pcap* OR process.command_line:*sniff* OR process.command_line:*promisc*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.da… | 0 |  |
| q-037407595f | check C053 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-d356471d26 | check C054 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.executable:*tcpdump* OR process.executable:*windump* OR process.executable:*wireshark* OR process.executable:*rawcap* OR process.executable:*npcap*)", "time_from": null, "time_to": null, "fields… | 0 |  |
| q-aa65f922c5 | check C055 | search | {"dataset": "windows.sysmon", "query": "event.code:6 AND (win.Image:*npcap* OR win.Image:*pcap* OR win.Image:*winpcap*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "pr… | 0 |  |
| q-408eb9b354 | check C056 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*pcap* OR powershell.script_block_text:*sniff* OR powershell.script_block_text:*promiscuous*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.nam… | 0 |  |
| q-557d298610 | check C057 | search | {"dataset": "zeek", "query": "event.action:conn AND network.transport:icmp", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "s… | 0 |  |
| q-9235a7f2fc | check C058 | aggregate | {"dataset": "windows.security", "field": "win.ObjectType", "query": "event.code:4656 OR event.code:4663 OR event.code:4670", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 10977 |  |
| q-cb24fd1994 | check C059 | aggregate | {"dataset": "windows.security", "field": "win.AccessMask", "query": "event.code:4656 OR event.code:4663", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 10834 |  |
| q-eea7752e61 | check C060 | search | {"dataset": "windows.security", "query": "event.code:4656 AND (win.ObjectName:*lsass* OR win.ObjectName:*credential* OR win.ObjectName:*SAM*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.c… | 23 |  |
| q-64304d3b7f | check C061 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-f549525c53 | check C062 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-1c89beee6a | check C063 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND (win.GrantedAccess:0x1010 OR win.GrantedAccess:0x1410 OR win.GrantedAccess:0x1438 OR win.GrantedAccess:0x143a)", "time_from": null, "time_to": null, "fields": ["@timestamp", … | 0 |  |
| q-b3ee64a47f | check C064 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*Get-Credential* OR powershell.script_block_text:*CredentialManager* OR powershell.script_block_text:*keylog*)", "time_from": null, "time_to": null, "fields": ["@time… | 0 |  |
| q-3b192fb17b | check C065 | search | {"dataset": "windows.other", "query": "event.code:7045 OR event.code:5858 OR event.code:5857", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process… | 90 |  |
| q-e08108b822 | check C066 | search | {"dataset": "zeek", "query": "event.action:http AND http.request.method:POST", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 0 |  |
| q-7e5e2418c2 | check C067 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-b230a1d1a3 | check C068 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND (win.TargetImage:*lsass* OR win.TargetImage:*winlogon* OR win.TargetImage:*explorer*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event… | 470 |  |
| q-dcfaa9fad2 | check C069 | search | {"dataset": "windows.sysmon", "query": "event.code:13 AND (registry.path:*Keyboard* OR registry.path:*keylog* OR registry.path:*Scancode*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code… | 26 |  |
| q-c08a7dadcd | check C070 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*keylog* OR process.command_line:*GetAsyncKeyState* OR process.command_line:*SetWindowsHookEx*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer… | 0 |  |
| q-2bcf9ec1bc | check C071 | aggregate | {"dataset": "windows.security", "field": "win.ObjectType", "query": "event.code:4656 OR event.code:4663 OR event.code:4670", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 10977 |  |
| q-045e7c018a | check C072 | search | {"dataset": "windows.security", "query": "event.code:4656 AND (win.ObjectName:*lsass* OR win.ObjectName:*winlogon*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "proces… | 13 |  |
| q-542c5a41df | check C073 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-009f5e5f1f | check C074 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*keylog* OR powershell.script_block_text:*GetAsyncKeyState* OR powershell.script_block_text:*SetWindowsHookEx*)", "time_from": null, "time_to": null, "fields": ["@tim… | 0 |  |
| q-e357e29eed | check C075 | search | {"dataset": "zeek", "query": "event.action:http AND http.request.method:POST", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 0 |  |
| q-742c696963 | check C076 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*Credential* OR powershell.script_block_text:*Prompt* OR powershell.script_block_text:*Read-Host*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "hos… | 4 |  |
| q-8af9195a7e | check C077 | aggregate | {"dataset": "windows.powershell", "field": "win.ScriptBlockId", "query": "event.code:4104", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 414 |  |
| q-cb4e89a67e | check C078 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*Credential* OR process.command_line:*prompt* OR process.command_line:*consent*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.… | 3 |  |
| q-a7bc5870f5 | check C079 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 447 |  |
| q-bfe33cf761 | check C080 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*Credential* OR process.command_line:*prompt*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user… | 0 |  |
| q-a54b09fcaa | check C081 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 460 |  |
| q-5d759f49c5 | check C082 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-139a607894 | check C083 | search | {"dataset": "zeek", "query": "event.action:http AND http.request.method:POST", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 0 |  |
| q-a63a8cab2f | check C084 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*login* OR file.path:*portal* OR file.path:*wwwroot* OR file.path:*inetpub*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "eve… | 0 |  |
| q-575c9189bd | check C085 | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 1649 |  |
| q-3fdaa8252e | check C086 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*iis* OR process.command_line:*w3wp* OR process.command_line:*wwwroot*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset",… | 0 |  |
| q-b855657b64 | check C087 | search | {"dataset": "windows.security", "query": "event.code:4663 AND (win.ObjectName:*wwwroot* OR win.ObjectName:*inetpub* OR win.ObjectName:*login*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.… | 0 |  |
| q-68b8c5ba51 | check C088 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 5337 |  |
| q-36c0925662 | check C089 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*wwwroot* OR powershell.script_block_text:*login* OR powershell.script_block_text:*credential*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.n… | 4 |  |
| q-7be827857c | check C090 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-0031472366 | check C091 | search | {"dataset": "zeek", "query": "event.action:http AND (url.original:*login* OR url.original:*portal*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "… | 0 |  |
| q-ec8113137a | check C092 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-8f7d78a81f | check C093 | aggregate | {"dataset": "windows.sysmon", "field": "win.SourceImage", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-16b6a622ca | check C094 | aggregate | {"dataset": "windows.sysmon", "field": "win.ImageLoaded", "query": "event.code:7", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 20259 |  |
| q-67b9400d56 | check C095 | search | {"dataset": "windows.sysmon", "query": "event.code:8", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinatio… | 95 |  |
| q-3efdcb6d50 | check C096 | aggregate | {"dataset": "windows.security", "field": "win.CallerProcessName", "query": "event.code:4656 AND win.ObjectType:*Process*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 13 |  |
| q-aa42a00452 | check C097 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:*hook* OR powershell.script_block_text:*SetWindowsHookEx* OR powershell.script_block_text:*MiniDump*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.… | 0 |  |
| q-8c0eb84398 | check C098 | search | {"dataset": "windows.other", "query": "message:*hook* OR message:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "sou… | 0 |  |
| q-981df633cb | check C099 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-32b203d5b7 | check C100 | aggregate | {"dataset": "windows.security", "field": "source.ip", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-dbd56dd0af | check C101 | timeline | {"dataset": "windows.security", "query": "event.code:4625", "interval": "1m", "time_from": null, "time_to": null} | 0 |  |
| q-969d27afcc | check C102 | search | {"dataset": "windows.other", "query": "message:*logon* OR message:*password*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 2 | F11 |
| q-25f7ed39e5 | check C103 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:*Credential* OR powershell.script_block_text:*Password*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.n… | 4 |  |
| q-a5c484469b | check C104 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*net* OR process.command_line:*login*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 30 |  |
| q-0d6eae974b | check C105 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-2deb775b77 | check C106 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 0 |  |
| q-7473fe06b8 | check C107 | timeline | {"dataset": "windows.security", "query": "event.code:4625", "interval": "1m", "time_from": null, "time_to": null} | 0 |  |
| q-1d8811800c | check C108 | search | {"dataset": "windows.other", "query": "message:*4625* OR message:*failed*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "so… | 2 |  |
| q-815ca7315c | check C109 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:*Password* OR powershell.script_block_text:*Credential*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.n… | 4 |  |
| q-8e033c5e62 | check C110 | aggregate | {"dataset": "windows.sysmon", "field": "process.command_line", "query": "event.code:1 AND process.command_line:*password*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-fc3b1481b4 | check C111 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 OR event.code:4656 OR event.code:4670", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 10977 |  |
| q-2be609b9d9 | check C112 | aggregate | {"dataset": "windows.security", "field": "win.ProcessName", "query": "event.code:4663 AND (win.ObjectName:*SAM* OR win.ObjectName:*SECURITY*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-e1b5973d0c | check C113 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*hash* OR process.command_line:*crack*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-1d3d556d65 | check C114 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND (win.TargetFilename:*.txt OR win.TargetFilename:*.pot)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 20 |  |
| q-4bfd426073 | check C115 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10 AND (win.TargetImage:*lsass* OR win.TargetImage:*SAM*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-42ca9f461e | check C116 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:*hash* OR powershell.script_block_text:*ConvertTo-SecureString*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code",… | 12 |  |
| q-19102c9f5b | check C117 | search | {"dataset": "windows.other", "query": "message:*SAM* OR message:*hash*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "sourc… | 1 |  |
| q-178a56a0d1 | check C118 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-56aa9448a5 | check C119 | aggregate | {"dataset": "windows.security", "field": "source.ip", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-42ce85e9cb | check C120 | search | {"dataset": "windows.security", "query": "event.code:4648", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 15 |  |
| q-c16f841c1b | check C121 | timeline | {"dataset": "windows.security", "query": "event.code:4625", "interval": "1m", "time_from": null, "time_to": null} | 0 |  |
| q-a6f7aeee1f | check C122 | search | {"dataset": "windows.other", "query": "message:*logon* OR message:*account*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "… | 7 |  |
| q-1cc72c98a5 | check C123 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:*Password* OR powershell.script_block_text:*Credential*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.n… | 4 |  |
| q-141bcb5722 | check C124 | aggregate | {"dataset": "windows.sysmon", "field": "process.command_line", "query": "event.code:1 AND process.command_line:*user*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1 |  |
| q-fd70da0e9a | check C125 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-aa07490579 | check C126 | aggregate | {"dataset": "windows.security", "field": "source.ip", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-d05f7a010a | check C127 | timeline | {"dataset": "windows.security", "query": "event.code:4625", "interval": "1m", "time_from": null, "time_to": null} | 0 |  |
| q-9adc0e1e2d | check C128 | search | {"dataset": "windows.other", "query": "message:*logon* OR message:*credential*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line"… | 4 |  |
| q-a69bd58d55 | check C129 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:*Credential* OR powershell.script_block_text:*Password*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.n… | 4 |  |
| q-ffa90a9f61 | check C130 | aggregate | {"dataset": "windows.sysmon", "field": "process.command_line", "query": "event.code:1 AND process.command_line:*password*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-0aadce5265 | check C131 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 297 |  |
| q-d0322b149c | check C132 | search | {"dataset": "windows.security", "query": "event.code:4648", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 15 | F16 |
| q-bb4b00d22e | check C133 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-85ce8c20ac | check C134 | search | {"dataset": "windows.sysmon", "query": "event.code:13 AND registry.path:*Credential*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command… | 11 | F16 |
| q-86f1e2e935 | check C135 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND powershell.script_block_text:*Credential*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executab… | 3 |  |
| q-010dd9f3ef | check C136 | search | {"dataset": "windows.other", "query": "message:*Credential*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "des… | 2 |  |
| q-c6f5c2ab3e | check C137 | aggregate | {"dataset": "windows.security", "field": "win.ObjectType", "query": "event.code:4656 OR event.code:4663 OR event.code:4670", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 10977 |  |
| q-6408568a99 | check C138 | search | {"dataset": "windows.security", "query": "event.code:5140 OR event.code:5145", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 163 |  |
| q-55696aa3b2 | check C139 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1649 |  |
| q-a0c7d5d69d | check C140 | search | {"dataset": "windows.sysmon", "query": "event.code:3 AND (destination.port:445 OR destination.port:139)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable… | 66 |  |
| q-9f4227f242 | check C141 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*445* OR powershell.script_block_text:*WebDAV* OR powershell.script_block_text:*NTLM*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "ob… | 0 |  |
| q-fe84a30a47 | check C142 | search | {"dataset": "windows.other", "query": "message:*445* OR message:*WebDAV*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "sou… | 0 |  |
| q-8a3adc2e3c | check C143 | aggregate | {"dataset": "zeek", "field": "destination.port", "query": "event.action:conn AND (destination.port:445 OR destination.port:139)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 50 |  |
| q-0bfad85a5f | check C144 | search | {"dataset": "zeek", "query": "event.action:http AND (http.request.method:PROPFIND OR http.request.method:MOVE OR http.request.method:OPTIONS)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.c… | 36 |  |
| q-e4c59cde00 | check C145 | aggregate | {"dataset": "windows.security", "field": "event.code", "query": "event.code:4768 OR event.code:4769 OR event.code:4770", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 42 |  |
| q-cef6d33f19 | check C146 | search | {"dataset": "windows.security", "query": "event.code:4769", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 28 |  |
| q-b7ab7ac6aa | check C147 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-46040ccf7e | check C148 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.GrantedAccess:*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line",… | 39283 |  |
| q-9415d0dd45 | check C149 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*Invoke-* OR powershell.script_block_text:*Exploit*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "ev… | 16 |  |
| q-a7f26a69e5 | check C150 | search | {"dataset": "windows.other", "query": "message:*exploit*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destin… | 0 |  |
| q-8c5e21557d | check C151 | search | {"dataset": "zeek", "query": "event.action:notice OR event.action:weird", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "sour… | 14 |  |
| q-b0e9fa2cae | check C152 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 460 |  |
| q-df96e88075 | check C153 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*cookie* OR process.command_line:*Cookie*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.nam… | 5 | F23 |
| q-fd3f11ff57 | check C154 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1649 |  |
| q-5fa480680f | check C155 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (win.TargetFilename:*Cookies* OR win.TargetFilename:*cookie*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "pr… | 1 | F24 |
| q-b5049c43dc | check C156 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-c118907197 | check C157 | search | {"dataset": "windows.sysmon", "query": "event.code:2 AND (win.TargetFilename:*Cookies* OR win.TargetFilename:*cookie*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "pro… | 0 |  |
| q-51cf1dc915 | check C158 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*cookie* OR powershell.script_block_text:*Cookie*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "even… | 0 |  |
| q-944744660a | check C159 | search | {"dataset": "windows.other", "query": "message:*cookie*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destina… | 0 |  |
| q-1c56bf87c6 | check C160 | search | {"dataset": "zeek", "query": "event.action:http AND http.request.method:GET", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "… | 2 |  |
| q-31dc2aec2a | check C161 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 460 |  |
| q-4e1ca6793d | check C162 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*password* OR process.command_line:*credential* OR process.command_line:*unattend*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name",… | 0 |  |
| q-d010c9bac9 | check C163 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1649 |  |
| q-689c118814 | check C164 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (win.TargetFilename:*unattend* OR win.TargetFilename:*password* OR win.TargetFilename:*credential*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.da… | 1 |  |
| q-8e7e519bf1 | check C165 | aggregate | {"dataset": "windows.sysmon", "field": "registry.path", "query": "event.code:13 OR event.code:14", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 17541 |  |
| q-f719d9bbad | check C166 | search | {"dataset": "windows.sysmon", "query": "event.code:13 AND (registry.path:*Password* OR registry.path:*Credential*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process… | 17 | F31 |
| q-34a383a548 | check C167 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*password* OR powershell.script_block_text:*credential*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset",… | 2 |  |
| q-1151bad2e7 | check C168 | search | {"dataset": "windows.other", "query": "message:*password*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 0 |  |
| q-df524d5a76 | check C169 | search | {"dataset": "zeek", "query": "event.action:smb_files", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinatio… | 12 | F29 |
| q-911641df7c | check C170 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 297 |  |
| q-09573ffce1 | check C171 | search | {"dataset": "windows.security", "query": "event.code:4648", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 15 |  |
| q-9425fced6c | check C172 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 447 |  |
| q-0ec8723f4e | check C173 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*password* OR process.command_line:*credential* OR process.command_line:*config*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event… | 8 |  |
| q-724f80143b | check C174 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1649 |  |
| q-8c33284637 | check C175 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (win.TargetFilename:*.config OR win.TargetFilename:*.xml OR win.TargetFilename:*.txt)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event… | 44 |  |
| q-26378e655a | check C176 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*Get-Content* OR powershell.script_block_text:*Select-String*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dat… | 1 |  |
| q-de655fdeaf | check C177 | search | {"dataset": "windows.other", "query": "message:*password*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 0 |  |
| q-99b9cb676e | check C178 | search | {"dataset": "zeek", "query": "event.action:smb_files", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinatio… | 12 |  |
| q-b2e15fe707 | check C179 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"13\" AND (TO_LOWER(registry.path) LIKE \"*\\\\sam\\\\*\" OR TO_LOWER(registry.path) LIKE \"*\\\\security\\\\*\" OR TO_LOWER(registry.path) LIKE \"*password*\" OR TO_LOWER… | ERROR |  |
| q-77f9e6b563 | check C179 (repaired) | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"13\" AND (TO_LOWER(registry.path) LIKE \"*\\\\\\\\sam\\\\\\\\*\" OR TO_LOWER(registry.path) LIKE \"*\\\\\\\\security\\\\\\\\*\" OR TO_LOWER(registry.path) LIKE \"*passwor… | 60 |  |
| q-eebbb9cdd8 | check C180 | aggregate | {"dataset": "windows.sysmon", "field": "registry.path", "query": "event.code:13", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 17541 |  |
| q-2e6f9620cd | check C181 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*reg query*\" OR TO_LOWER(process.command_line) LIKE \"*reg save*\" OR TO_LOWER(process.command_line) LIKE \"*\\\\sam*\" OR… | ERROR |  |
| q-e697d28f7b | check C181 (repaired) | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*reg query*\" OR TO_LOWER(process.command_line) LIKE \"*reg save*\" OR TO_LOWER(process.command_line) LIKE \"*sam*\" OR TO_… | 5 |  |
| q-44b9231d13 | check C182 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4663\",\"4656\",\"4670\",\"4658\") AND (TO_LOWER(win.ObjectName) LIKE \"*\\\\sam*\" OR TO_LOWER(win.ObjectName) LIKE \"*\\\\security*\" OR TO_LOWER(win.ObjectName) LIK… | ERROR |  |
| q-ae77bb3c11 | check C182 (repaired) | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4663\",\"4656\",\"4670\",\"4658\") AND (TO_LOWER(win.ObjectName) LIKE \"*sam*\" OR TO_LOWER(win.ObjectName) LIKE \"*security*\" OR TO_LOWER(win.ObjectName) LIKE \"*lsa… | 500 |  |
| q-65efd5f320 | check C183 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code IN (\"4103\",\"4104\") AND (TO_LOWER(COALESCE(powershell.script_block_text, win.ScriptBlockText, \"\")) LIKE \"*reg query*\" OR TO_LOWER(COALESCE(powershell.script_block_t… | 1 |  |
| q-18dce01f47 | check C184 | esql | {"query": "FROM logs-windows.other-default METADATA _id, _index \| WHERE TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*\\\\sam*\" OR TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*\\\\security*\" OR TO_LOWER(COALESCE(message, win.Message, \"\"… | ERROR |  |
| q-7bd65d82c2 | check C184 (repaired) | esql | {"query": "FROM logs-windows.other-default METADATA _id, _index \| WHERE TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*sam*\" OR TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*security*\" OR TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE … | 12 |  |
| q-f7de3cd780 | check C185 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code IN (\"4103\",\"4104\") AND (TO_LOWER(COALESCE(powershell.script_block_text, win.ScriptBlockText, \"\")) LIKE \"*history*\" OR TO_LOWER(COALESCE(powershell.script_block_tex… | 1 |  |
| q-b06e10163c | check C186 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*consolehost_history*\" OR TO_LOWER(process.command_line) LIKE \"*psreadline*\" OR TO_LOWER(process.command_line) LIKE \"*h… | 0 |  |
| q-ad3f82f0c3 | check C187 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*consolehost_history*\" OR TO_LOWER(file.path) LIKE \"*psreadline*\" OR TO_LOWER(file.path) LIKE \"*\\\\history*\" OR TO_LOWER(file.p… | ERROR |  |
| q-69eede3864 | check C187 (repaired) | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*consolehost_history*\" OR TO_LOWER(file.path) LIKE \"*psreadline*\" OR TO_LOWER(file.path) LIKE \"*history*\" OR TO_LOWER(file.path)… | 15 |  |
| q-ebf3320f20 | check C188 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4663\",\"4656\",\"4658\") AND (TO_LOWER(win.ObjectName) LIKE \"*consolehost_history*\" OR TO_LOWER(win.ObjectName) LIKE \"*psreadline*\" OR TO_LOWER(win.ObjectName) LI… | 0 |  |
| q-d20495df0b | check C189 | esql | {"query": "FROM logs-windows.other-default METADATA _id, _index \| WHERE TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*history*\" OR TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*psreadline*\" \| KEEP @timestamp, host.name, event.code, messag… | 5 |  |
| q-05746c5d2c | check C190 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*.key\" OR TO_LOWER(file.path) LIKE \"*.pgp\" OR TO_LOWER(file.path) LIKE \"*.gpg\" OR TO_LOWER(file.path) LIKE \"*.ppk\" OR TO_LOWER… | 1 |  |
| q-9220a2bb4f | check C191 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*.pem*\" OR TO_LOWER(process.command_line) LIKE \"*.pfx*\" OR TO_LOWER(process.command_line) LIKE \"*.p12*\" OR TO_LOWER(pr… | 0 |  |
| q-f9802b2b56 | check C192 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"5145\" AND (TO_LOWER(win.RelativeTargetName) LIKE \"*.key\" OR TO_LOWER(win.RelativeTargetName) LIKE \"*.pem\" OR TO_LOWER(win.RelativeTargetName) LIKE \"*.pfx\" OR TO_… | 0 |  |
| q-233fc419b1 | check C193 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4663\",\"4656\",\"4658\") AND (TO_LOWER(win.ObjectName) LIKE \"*.key\" OR TO_LOWER(win.ObjectName) LIKE \"*.pem\" OR TO_LOWER(win.ObjectName) LIKE \"*.pfx\" OR TO_LOWE… | 0 |  |
| q-c630bca36e | check C194 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code IN (\"4103\",\"4104\") AND (TO_LOWER(COALESCE(powershell.script_block_text, win.ScriptBlockText, \"\")) LIKE \"*.pem*\" OR TO_LOWER(COALESCE(powershell.script_block_text, … | 2 |  |
| q-bb1ca711d0 | check C195 | esql | {"query": "FROM logs-windows.other-default METADATA _id, _index \| WHERE TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*.pem*\" OR TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*.pfx*\" OR TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*… | 0 |  |
| q-a3ac42cfc7 | check C196 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code IN (\"4103\",\"4104\") AND (TO_LOWER(COALESCE(powershell.script_block_text, win.ScriptBlockText, \"\")) LIKE \"*groups.xml*\" OR TO_LOWER(COALESCE(powershell.script_block_… | 32 |  |
| q-829da2172d | check C197 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*sysvol*\" OR TO_LOWER(process.command_line) LIKE \"*groups.xml*\" OR TO_LOWER(process.command_line) LIKE \"*cpassword*\" O… | 0 |  |
| q-2154c29a81 | check C198 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*groups.xml*\" OR TO_LOWER(file.path) LIKE \"*sysvol*\" OR TO_LOWER(file.path) LIKE \"*gpprefdecrypt*\" OR TO_LOWER(file.path) LIKE \… | 22 |  |
| q-647e29d338 | check C199 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"5145\" AND (TO_LOWER(win.RelativeTargetName) LIKE \"*groups.xml*\" OR TO_LOWER(win.ShareName) LIKE \"*sysvol*\" OR TO_LOWER(win.ShareName) LIKE \"*netlogon*\") \| KEEP … | 56 |  |
| q-ece3224788 | check C200 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4663\",\"4656\",\"4658\") AND (TO_LOWER(win.ObjectName) LIKE \"*groups.xml*\" OR TO_LOWER(win.ObjectName) LIKE \"*sysvol*\" OR TO_LOWER(win.ObjectName) LIKE \"*gpp*\")… | 0 |  |
| q-394a87cd80 | check C201 | esql | {"query": "FROM logs-windows.other-default METADATA _id, _index \| WHERE TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*sysvol*\" OR TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*groups.xml*\" OR TO_LOWER(COALESCE(message, win.Message, \"\")) … | 0 |  |
| q-3a8a06e15e | check C202 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND (TO_LOWER(win.TargetImage) LIKE \"*lsass.exe\" OR TO_LOWER(win.SourceImage) LIKE \"*lsass.exe\") \| KEEP @timestamp, host.name, user.name, win.SourceImage, win.T… | 500 |  |
| q-b153708fa2 | check C203 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass.exe", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-86ebb58e53 | check C204 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*sekurlsa*\" OR TO_LOWER(process.command_line) LIKE \"*lsadump*\" OR TO_LOWER(process.command_line) LIKE \"*mimikatz*\" OR … | 0 |  |
| q-7bb990346f | check C205 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4663\",\"4656\",\"4670\",\"4658\") AND (TO_LOWER(win.ObjectName) LIKE \"*\\\\protect\\\\*\" OR TO_LOWER(win.ObjectName) LIKE \"*credential*\" OR TO_LOWER(win.ObjectNam… | ERROR |  |
| q-4463720da5 | check C205 (repaired) | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4663\",\"4656\",\"4670\",\"4658\") AND (TO_LOWER(win.ObjectName) LIKE \"*protect*\" OR TO_LOWER(win.ObjectName) LIKE \"*credential*\" OR TO_LOWER(win.ObjectName) LIKE … | 19 | F35 |
| q-466b541a12 | check C206 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4688\" AND (TO_LOWER(process.command_line) LIKE \"*sekurlsa*\" OR TO_LOWER(process.command_line) LIKE \"*lsadump*\" OR TO_LOWER(process.command_line) LIKE \"*mimikatz*\… | 0 |  |
| q-b397e8a898 | check C207 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code IN (\"4103\",\"4104\") AND (TO_LOWER(COALESCE(powershell.script_block_text, win.ScriptBlockText, \"\")) LIKE \"*sekurlsa*\" OR TO_LOWER(COALESCE(powershell.script_block_te… | 5 |  |
| q-7d34e48cfa | check C208 | esql | {"query": "FROM logs-windows.other-default METADATA _id, _index \| WHERE TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*lsass*\" OR TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*credential*\" OR TO_LOWER(COALESCE(message, win.Message, \"\")) L… | 2 |  |
| q-9b3182d736 | check C209 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*login data*\" OR TO_LOWER(process.command_line) LIKE \"*\\\\google\\\\chrome\\\\user data*\" OR TO_LOWER(process.command_l… | ERROR |  |
| q-85d79d36a7 | check C209 (repaired) | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*login data*\" OR TO_LOWER(process.command_line) LIKE \"*google*chrome*user data*\" OR TO_LOWER(process.command_line) LIKE … | 0 |  |
| q-152502cf34 | check C210 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*login data*\" OR TO_LOWER(file.path) LIKE \"*logins.json*\" OR TO_LOWER(file.path) LIKE \"*key3.db*\" OR TO_LOWER(file.path) LIKE \"… | ERROR |  |
| q-070c3edc8b | check C210 (repaired) | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*login data*\" OR TO_LOWER(file.path) LIKE \"*logins.json*\" OR TO_LOWER(file.path) LIKE \"*key3.db*\" OR TO_LOWER(file.path) LIKE \"… | 0 |  |
| q-ea1d9d7c25 | check C211 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND (TO_LOWER(win.TargetImage) LIKE \"*chrome.exe\" OR TO_LOWER(win.TargetImage) LIKE \"*firefox.exe\" OR TO_LOWER(win.TargetImage) LIKE \"*msedge.exe\" OR TO_LOWER(… | 0 |  |
| q-37748fd384 | check C212 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4663\",\"4656\",\"4658\") AND (TO_LOWER(win.ObjectName) LIKE \"*login data*\" OR TO_LOWER(win.ObjectName) LIKE \"*logins.json*\" OR TO_LOWER(win.ObjectName) LIKE \"*ke… | ERROR |  |
| q-dbc02fb546 | check C212 (repaired) | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4663\",\"4656\",\"4658\") AND (TO_LOWER(win.ObjectName) LIKE \"*login data*\" OR TO_LOWER(win.ObjectName) LIKE \"*logins.json*\" OR TO_LOWER(win.ObjectName) LIKE \"*ke… | 0 |  |
| q-1fa003c4a5 | check C213 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code IN (\"4103\",\"4104\") AND (TO_LOWER(COALESCE(powershell.script_block_text, win.ScriptBlockText, \"\")) LIKE \"*login data*\" OR TO_LOWER(COALESCE(powershell.script_block_… | 0 |  |
| q-dbd4c497c8 | check C214 | esql | {"query": "FROM logs-windows.other-default METADATA _id, _index \| WHERE TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*login data*\" OR TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*logins.json*\" OR TO_LOWER(COALESCE(message, win.Message, \"… | 0 |  |
| q-c5d12931c7 | check C215 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 326 |  |
| q-a151aca8ed | check C216 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-06b0f4e8c7 | check C217 | search | {"dataset": "windows.sysmon", "query": "event.code:15 AND file.path:*Credentials*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 0 |  |
| q-26602d99b0 | check C218 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*vault* OR process.command_line:*Credential* OR process.command_line:*cmdkey*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "eve… | 0 |  |
| q-15cbd7839c | check C219 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*Credential* OR powershell.script_block_text:*vault* OR powershell.script_block_text:*cmdkey*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.na… | 3 |  |
| q-f80a3fbe8c | check C220 | search | {"dataset": "windows.other", "query": "message:*Credential* OR message:*vault*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line"… | 2 |  |
| q-033c915b6c | check C221 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.executable:*keepass* OR process.executable:*1password* OR process.executable:*bitwarden* OR process.executable:*lastpass* OR process.executable:*dashlane*)", "time_from": null, "time_to": null, … | 0 |  |
| q-13ea923cbb | check C222 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*keepass* OR file.path:*1password* OR file.path:*bitwarden* OR file.path:*lastpass*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.datase… | 0 |  |
| q-de9474181f | check C223 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND (win.TargetImage:*keepass* OR win.TargetImage:*1password* OR win.TargetImage:*bitwarden*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "e… | 0 |  |
| q-c08bd7131e | check C224 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*keepass* OR process.command_line:*1password* OR process.command_line:*bitwarden* OR process.command_line:*kdbx*)", "time_from": null, "time_to": null, "fields": ["@timestamp",… | 0 |  |
| q-9228200f32 | check C225 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*keepass* OR powershell.script_block_text:*kdbx* OR powershell.script_block_text:*1password* OR powershell.script_block_text:*bitwarden*)", "time_from": null, "time_t… | 0 |  |
| q-171b658cdd | check C226 | search | {"dataset": "windows.other", "query": "message:*keepass* OR message:*1password* OR message:*bitwarden* OR message:*kdbx*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "p… | 0 |  |
| q-06ce89255c | check C227 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 326 |  |
| q-6d00aeac6d | check C228 | aggregate | {"dataset": "windows.sysmon", "field": "win.SourceImage", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-eac992f265 | check C229 | search | {"dataset": "windows.sysmon", "query": "event.code:7 AND (win.ImageLoaded:*lsass* OR win.ImageLoaded:*cryptdll* OR win.ImageLoaded:*sam* OR win.ImageLoaded:*msv1_0*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "… | 77 | F38, F41 |
| q-5bcf28edc5 | check C230 | search | {"dataset": "windows.security", "query": "event.code:4657 AND (win.ObjectName:*lsass* OR win.ObjectName:*cryptdll* OR win.ObjectName:*msv1_0* OR win.ObjectName:*sam*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", … | 0 |  |
| q-496d3d3633 | check C231 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*lsass* OR process.command_line:*cryptdll* OR process.command_line:*msv1_0*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event… | 0 |  |
| q-375b7c2f2b | check C232 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*lsass* OR powershell.script_block_text:*cryptdll* OR powershell.script_block_text:*msv1_0* OR powershell.script_block_text:*SecurityPackages*)", "time_from": null, "… | 0 |  |
| q-be8e345b8d | check C233 | search | {"dataset": "windows.other", "query": "message:*lsass* OR message:*cryptdll* OR message:*msv1_0*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "pro… | 0 |  |
| q-1e8c959cfd | check C234 | search | {"dataset": "windows.security", "query": "event.code:4624 AND win.LogonType:3", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line",… | 218 | F37 |
| q-e0c95982d3 | check C235 | search | {"dataset": "windows.security", "query": "event.code:4648", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 15 |  |
| q-a0929aa35a | check C236 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4624 OR event.code:4648", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 312 |  |
| q-b6912c49de | check C237 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 326 |  |
| q-04398be7f6 | check C238 | search | {"dataset": "windows.sysmon", "query": "event.code:7 AND (win.ImageLoaded:*lsass* OR win.ImageLoaded:*cryptdll*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.e… | 33 |  |
| q-7677eee737 | check C239 | search | {"dataset": "windows.other", "query": "message:*lsass* OR message:*cryptdll*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 0 |  |
| q-b95fd60fb2 | check C240 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*lsass* OR powershell.script_block_text:*cryptdll* OR powershell.script_block_text:*Skeleton* OR powershell.script_block_text:*DCShadow*)", "time_from": null, "time_t… | 0 |  |
| q-873e88f2d5 | check C241 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*System32* AND (file.path:*.dll))", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable"… | 0 |  |
| q-11f194abf1 | check C242 | search | {"dataset": "windows.sysmon", "query": "event.code:7 AND (win.ImageLoaded:*lsass* OR win.ImageLoaded:*cryptdll*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.e… | 33 |  |
| q-e2ee629a22 | check C243 | search | {"dataset": "windows.security", "query": "event.code:4657 AND (win.ObjectName:*Notification\\ Packages* OR win.ObjectName:*Password* OR win.ObjectName:*lsass*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.… | 0 |  |
| q-a8f98c9234 | check C244 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*Notification* OR process.command_line:*PasswordFilter*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.co… | 0 |  |
| q-48d9d19f52 | check C245 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*Notification* OR powershell.script_block_text:*PasswordFilter* OR powershell.script_block_text:*lsass*)", "time_from": null, "time_to": null, "fields": ["@timestamp"… | 0 |  |
| q-6af425a8c7 | check C246 | search | {"dataset": "windows.other", "query": "message:*Notification* OR message:*PasswordFilter* OR message:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.execu… | 10 |  |
| q-f149acbba8 | check C247 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*AllowReversiblePasswordEncryption* OR powershell.script_block_text:*ReversibleEncryption* OR powershell.script_block_text:*Set-ADUser*)", "time_from": null, "time_to… | 1 |  |
| q-36bf75f3a3 | check C248 | search | {"dataset": "windows.powershell", "query": "event.code:4103 AND (message:*AllowReversiblePasswordEncryption* OR message:*ReversibleEncryption*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event… | 0 |  |
| q-6bd57916c8 | check C249 | search | {"dataset": "windows.security", "query": "event.code:4739", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 0 |  |
| q-0c0108fe4b | check C250 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*Reversible* OR process.command_line:*Set-ADUser* OR process.command_line:*dsmod*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", … | 0 |  |
| q-71239d8ea4 | check C251 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*Reversible* OR process.command_line:*Set-ADUser* OR process.command_line:*dsmod*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "even… | 0 |  |
| q-8f2ab5ee18 | check C252 | search | {"dataset": "windows.other", "query": "message:*Reversible* OR message:*AllowReversiblePasswordEncryption*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executa… | 0 |  |
| q-516bd2d0aa | check C253 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(powershell.script_block_text) LIKE \"*set-aduser*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*set-adauthenticationpolicy*\" OR TO_LOWER(powershell.script_block_text)… | 1 |  |
| q-0d99224ae7 | check C254 | count | {"dataset": "windows.security", "query": "event.code:4739", "time_from": null, "time_to": null} | 0 |  |
| q-c65e4a818b | check C255 | aggregate | {"dataset": "windows.security", "field": "win.ObjectType", "query": "event.code:5136 OR event.code:4739", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-f450b9c8d2 | check C256 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*set-aduser*\" OR TO_LOWER(process.command_line) LIKE \"*set-adauthenticationpolicy*\" OR TO_LOWER(process.command_line) LI… | 0 |  |
| q-9e755e9681 | check C257 | search | {"dataset": "windows.other", "query": "event.code:4739 OR event.code:5136 OR event.code:4738", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process… | 0 |  |
| q-38250afb2f | check C258 | aggregate | {"dataset": "windows.security", "field": "win.LogonProcessName", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 297 |  |
| q-a7dca9f15b | check C259 | aggregate | {"dataset": "windows.security", "field": "win.AuthenticationPackageName", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 297 |  |
| q-cea6e2259c | check C260 | count | {"dataset": "windows.security", "query": "event.code:5136", "time_from": null, "time_to": null} | 0 |  |
| q-8ff7c3cfb5 | check C261 | aggregate | {"dataset": "windows.sysmon", "field": "win.ImageLoaded", "query": "event.code:7", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 20259 |  |
| q-d927734cc1 | check C262 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(powershell.script_block_text) LIKE \"*connect-msolservice*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*connect-azuread*\" OR TO_LOWER(powershell.script_block_text) L… | 0 |  |
| q-69dfe48f74 | check C263 | search | {"dataset": "windows.other", "query": "event.code:5136 OR event.code:4739 OR event.code:4738", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process… | 0 |  |
| q-cec807731d | check C264 | count | {"dataset": "windows.security", "query": "event.code:4657", "time_from": null, "time_to": null} | 36 |  |
| q-0fc9fc75c6 | check C265 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4657\" AND (TO_LOWER(win.ObjectName) LIKE \"*networkprovider*\" OR TO_LOWER(win.ObjectName) LIKE \"*credential*\" OR TO_LOWER(win.ObjectName) LIKE \"*winlogon*\") \| KE… | 0 |  |
| q-182014ba51 | check C266 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*networkprovider*\" OR TO_LOWER(file.path) LIKE \"*system32*credential*\" OR TO_LOWER(file.path) LIKE \"*winlogon*\") \| KEEP @timest… | 1 |  |
| q-bcabc24963 | check C267 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 39283 |  |
| q-4be3a86602 | check C268 | aggregate | {"dataset": "windows.sysmon", "field": "win.ImageLoaded", "query": "event.code:7", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 20259 |  |
| q-e4249db643 | check C269 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(powershell.script_block_text) LIKE \"*networkprovider*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*new-itemproperty*\" OR TO_LOWER(powershell.script_block_text) LIKE… | 0 |  |
| q-50f2207ebe | check C270 | search | {"dataset": "windows.other", "query": "event.code:4657 OR event.code:11 OR event.code:7", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.comm… | 4 |  |
| q-d65c9898ce | check C271 | aggregate | {"dataset": "windows.security", "field": "win.ObjectType", "query": "event.code:4663 OR event.code:4670 OR event.code:4656", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 10977 |  |
| q-747efe332f | check C272 | aggregate | {"dataset": "windows.security", "field": "win.ProcessName", "query": "event.code:4663 OR event.code:4670 OR event.code:4656", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 10977 |  |
| q-37c2f66f46 | check C273 | aggregate | {"dataset": "windows.sysmon", "field": "win.DestinationHostname", "query": "event.code:3", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 1229 |  |
| q-348a382c82 | check C274 | aggregate | {"dataset": "windows.sysmon", "field": "win.QueryName", "query": "event.code:22", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 81 |  |
| q-9d00826971 | check C275 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(powershell.script_block_text) LIKE \"*responder*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*mitm*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*arpspoof*\" OR… | 0 |  |
| q-2251a801cd | check C276 | search | {"dataset": "windows.other", "query": "event.code:4663 OR event.code:4670 OR event.code:4656 OR event.code:3 OR event.code:22", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name… | 2 | F46 |
| q-602a63cd4f | check C277 | aggregate | {"dataset": "zeek", "field": "zeek.conn_state", "query": "event.action:conn", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 613 |  |
| q-b24da0978a | check C278 | aggregate | {"dataset": "zeek", "field": "zeek.service", "query": "event.action:conn", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 613 |  |
| q-71fbb9c29a | check C279 | count | {"dataset": "windows.security", "query": "event.code:4697", "time_from": null, "time_to": null} | 23 |  |
| q-cb9037693b | check C280 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4657\" AND TO_LOWER(win.ObjectName) LIKE \"*dnsclient*\" \| KEEP @timestamp, host.name, user.name, win.ObjectName, win.NewValue, _id, _index"} | 0 |  |
| q-720a1e0fec | check C281 | aggregate | {"dataset": "windows.sysmon", "field": "win.DestinationHostname", "query": "event.code:3", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 1229 |  |
| q-b7f8b7afee | check C282 | aggregate | {"dataset": "windows.sysmon", "field": "win.QueryName", "query": "event.code:22", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 81 |  |
| q-f7a0bd5e16 | check C283 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(powershell.script_block_text) LIKE \"*llmnr*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*nbt-ns*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*responder*\" OR … | 0 |  |
| q-8f1c57f13a | check C284 | search | {"dataset": "windows.other", "query": "event.code:4697 OR event.code:4657 OR event.code:3 OR event.code:22", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executa… | 2 |  |
| q-d4b0013229 | check C285 | aggregate | {"dataset": "zeek", "field": "zeek.id_resp_h", "query": "event.action:conn AND zeek.service:smb", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-42b2dca2ae | check C286 | aggregate | {"dataset": "zeek", "field": "zeek.query", "query": "event.action:dns", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 53 |  |
| q-5e1802de67 | check C287 | aggregate | {"dataset": "windows.sysmon", "field": "win.DestinationHostname", "query": "event.code:3", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 1229 |  |
| q-3f2d483075 | check C288 | aggregate | {"dataset": "windows.sysmon", "field": "win.QueryName", "query": "event.code:22", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 81 |  |
| q-b4d2f01443 | check C289 | aggregate | {"dataset": "windows.security", "field": "win.ProcessName", "query": "event.code:4663 OR event.code:4670 OR event.code:4656", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 10977 |  |
| q-12b89d7c11 | check C290 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(powershell.script_block_text) LIKE \"*arp*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*netsh interface*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*get-netne… | 0 |  |
| q-8bcf7fa1b6 | check C291 | search | {"dataset": "windows.other", "query": "event.code:3 OR event.code:22 OR event.code:4663 OR event.code:4670", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executa… | 2 |  |
| q-863a2c2ee2 | check C292 | aggregate | {"dataset": "zeek", "field": "zeek.orig_l2_addr", "query": "event.action:conn", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 613 |  |
| q-8e79ee3c1b | check C293 | aggregate | {"dataset": "zeek", "field": "zeek.resp_l2_addr", "query": "event.action:conn", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 613 |  |
| q-41d1d383f7 | check C294 | search | {"dataset": "windows.other", "query": "event.code:(1341 OR 1342 OR 1020 OR 1063)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_lin… | 0 |  |
| q-51f2b91496 | check C295 | aggregate | {"dataset": "windows.other", "field": "event.code", "query": "*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 216 |  |
| q-6775b64db2 | check C296 | search | {"dataset": "windows.security", "query": "event.code:5156 AND win.Direction:Inbound", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_… | 0 |  |
| q-3566dc9eb5 | check C297 | aggregate | {"dataset": "windows.sysmon", "field": "destination.port", "query": "event.code:3", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1229 |  |
| q-d5a7cbeec5 | check C298 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:(*Dhcp* OR *dhcp*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.… | 0 |  |
| q-316d2a4f45 | check C299 | aggregate | {"dataset": "zeek", "field": "event.action", "query": "*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 2140 |  |
| q-100f46803f | check C300 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4672", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 212 |  |
| q-d5544409f3 | check C301 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 297 |  |
| q-d990b59e30 | check C302 | search | {"dataset": "windows.security", "query": "event.code:4634", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 236 |  |
| q-4eacb4a98b | check C303 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-fe798f2eed | check C304 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-56cccf535c | check C305 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:(*kerberos* OR *Kerberos* OR *ticket* OR *Ticket*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name",… | 0 |  |
| q-ef8d9349cb | check C306 | search | {"dataset": "windows.other", "query": "event.code:(7045 OR 7040)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip",… | 9 |  |
| q-4cef00f065 | check C307 | aggregate | {"dataset": "zeek", "field": "zeek.request_type", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 35 |  |
| q-fbe685f75c | check C308 | search | {"dataset": "windows.security", "query": "event.code:4769", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 28 |  |
| q-865acc8838 | check C309 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4672", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 212 |  |
| q-83c5e6dc69 | check C310 | aggregate | {"dataset": "windows.security", "field": "win.TicketEncryptionType", "query": "event.code:4769", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 28 |  |
| q-de713221db | check C311 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-e9ea7631d0 | check C312 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:(*golden* OR *Golden* OR *krbtgt* OR *KRBTGT*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "pr… | 0 |  |
| q-5ee8a870a6 | check C313 | aggregate | {"dataset": "windows.other", "field": "event.code", "query": "*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 216 |  |
| q-107968b585 | check C314 | aggregate | {"dataset": "zeek", "field": "zeek.request_type", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 35 |  |
| q-c4b6d13f81 | check C315 | search | {"dataset": "windows.security", "query": "event.code:4769", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 28 |  |
| q-260d27a8f7 | check C316 | aggregate | {"dataset": "windows.security", "field": "win.ServiceName", "query": "event.code:4769", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 28 |  |
| q-03af8d2500 | check C317 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4672", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 212 |  |
| q-55674f86c2 | check C318 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-a21a3029be | check C319 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:(*silver* OR *Silver* OR *service ticket* OR *SPN*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name"… | 0 |  |
| q-ea34fa2da5 | check C320 | search | {"dataset": "windows.other", "query": "event.code:(7045 OR 7040)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip",… | 9 |  |
| q-d248a0a493 | check C321 | aggregate | {"dataset": "zeek", "field": "zeek.request_type", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 35 |  |
| q-1215d6e259 | check C322 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4769", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 28 |  |
| q-86a7166d53 | check C323 | aggregate | {"dataset": "windows.security", "field": "win.TicketEncryptionType", "query": "event.code:4769", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 28 |  |
| q-c3e94dc930 | check C324 | search | {"dataset": "windows.security", "query": "event.code:4648", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 15 |  |
| q-061f631ca8 | check C325 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 297 |  |
| q-80abaed45d | check C326 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-5073b9ec8b | check C327 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:(*Kerberoast* OR *kerberoast* OR *Invoke-Kerberoast* OR *Rubeus*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code… | 0 |  |
| q-398ac92804 | check C328 | aggregate | {"dataset": "windows.other", "field": "event.code", "query": "*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 216 |  |
| q-0015510b7a | check C329 | aggregate | {"dataset": "zeek", "field": "zeek.request_type", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 35 |  |
| q-56c90287f0 | check C330 | search | {"dataset": "windows.security", "query": "event.code:4768", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 14 |  |
| q-0d59cda68c | check C331 | aggregate | {"dataset": "windows.security", "field": "win.PreAuthType", "query": "event.code:4768", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 14 |  |
| q-48f26e8b46 | check C332 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4768", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 14 |  |
| q-d799ca3597 | check C333 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 447 |  |
| q-1d768c7d05 | check C334 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:(*AS-REP* OR *asrep* OR *GetNPUsers* OR *DontRequirePreAuth*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "… | 0 |  |
| q-279214dce9 | check C335 | aggregate | {"dataset": "windows.other", "field": "event.code", "query": "*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 216 |  |
| q-61ba1cb0ce | check C336 | aggregate | {"dataset": "zeek", "field": "zeek.request_type", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 35 |  |
| q-4fc281dcff | check C337 | aggregate | {"dataset": "windows.security", "field": "win.LogonProcessName", "query": "event.code:4624 OR event.code:4648", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 312 |  |
| q-2b39e86b15 | check C338 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-3d1fd5628d | check C339 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*cookie* OR powershell.script_block_text:*token* OR powershell.script_block_text:*SAML*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "… | 1 |  |
| q-cb516a1527 | check C340 | search | {"dataset": "windows.other", "query": "event.code:7045 OR event.code:5857 OR event.code:5858", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process… | 90 | F54 |
| q-89fc29cac6 | check C341 | aggregate | {"dataset": "zeek", "field": "event.action", "query": "event.action:http OR event.action:ssl OR event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 475 |  |
| q-92c83378c7 | check C342 | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11 AND (file.path:*cookie* OR file.path:*Cookies*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1 |  |
| q-8c8e5ec98e | check C343 | aggregate | {"dataset": "windows.security", "field": "win.LogonProcessName", "query": "event.code:4624 OR event.code:4648", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 312 |  |
| q-ed7b3e8548 | check C344 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*cookie* OR powershell.script_block_text:*Set-Cookie* OR powershell.script_block_text:*session*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.… | 1 |  |
| q-1f7db394f8 | check C345 | search | {"dataset": "windows.other", "query": "event.code:11 OR event.code:16", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source… | 9 |  |
| q-15c6a20621 | check C346 | search | {"dataset": "zeek", "query": "event.action:http AND http.request.method:*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "so… | 62 |  |
| q-b8d6f769f7 | check C347 | aggregate | {"dataset": "windows.security", "field": "win.LogonProcessName", "query": "event.code:4624 OR event.code:4648", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 312 |  |
| q-88904bbe39 | check C348 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*SAML* OR powershell.script_block_text:*NotOnOrAfter* OR powershell.script_block_text:*Assertion*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "hos… | 0 |  |
| q-46f26a4fe9 | check C349 | search | {"dataset": "windows.other", "query": "event.code:7045 OR event.code:5857 OR event.code:5858", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process… | 90 |  |
| q-23ad867156 | check C350 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*saml* OR process.command_line:*token* OR process.command_line:*cert*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-d65d74d76d | check C351 | search | {"dataset": "zeek", "query": "event.action:http AND (url.original:*saml* OR url.original:*adfs* OR url.original:*token*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "p… | 0 |  |
| q-65ace018b9 | check C352 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-38a35e958a | check C353 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-ebd23e251f | check C354 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*MFA* OR powershell.script_block_text:*2FA* OR powershell.script_block_text:*Authenticator*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name… | 0 |  |
| q-a9a0ec98f8 | check C355 | search | {"dataset": "windows.other", "query": "event.code:4625 OR event.code:5857 OR event.code:5858", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process… | 85 | F55 |
| q-4c28049750 | check C356 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*login* OR process.command_line:*auth* OR process.command_line:*mfa*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-43f7544b12 | check C357 | search | {"dataset": "zeek", "query": "event.action:http AND (url.original:*login* OR url.original:*auth* OR url.original:*mfa*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "pr… | 0 |  |
| q-7c6e00d495 | check C358 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4657", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 36 |  |
| q-2a9573b074 | check C359 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4768", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 14 |  |
| q-8aeb7fc85c | check C360 | aggregate | {"dataset": "windows.sysmon", "field": "registry.path", "query": "event.code:13 AND (registry.path:*Certificate* OR registry.path:*Crypto* OR registry.path:*Keys*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1133 |  |
| q-1ac26923ec | check C361 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*Certificate* OR powershell.script_block_text:*Export-PfxCertificate* OR powershell.script_block_text:*New-SelfSignedCertificate*)", "time_from": null, "time_to": nul… | 1 |  |
| q-9fa6a93462 | check C362 | search | {"dataset": "windows.other", "query": "event.code:7045 OR event.code:5857 OR event.code:5858", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process… | 90 |  |
| q-52122e7dec | check C363 | aggregate | {"dataset": "zeek", "field": "zeek.certificate_subject", "query": "event.action:x509", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 378 |  |
| q-06a9c14680 | triage T1003 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND (win.GrantedAccess:0x1fffff OR win.GrantedAccess:0x101001 OR win.GrantedAccess:0x1f3fff OR win.GrantedAccess:0x1000000 OR win.GrantedAccess:0x3000 OR win.GrantedAccess:0x1400… | 33 |  |
| q-0b5b52c581 | triage T1003 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:(13 OR 14) AND (registry.path:*SAM* OR registry.path:*SECURITY*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "proces… | 7 | F03 |
| q-536b06af07 | triage T1003 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None | F01 |
| q-9e4b61e145 | triage T1003 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrM7IJ"} | None | F01 |
| q-ea29ccdc1e | triage T1003 step 2 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*lsass* OR powershell.script_block_text:*MiniDump* OR powershell.script_block_text:*Invoke-Mimikatz* OR powershell.script_block_text:*sekurlsa* OR powershell.script_b… | 3 |  |
| q-05e95a10ee | triage T1003 step 3 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-ce1d304a51 | triage T1003 step 3 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND process.executable:*PowerShell.exe", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.… | 0 |  |
| q-0ab6933f9f | triage T1003 step 3 | search | {"dataset": "windows.security", "query": "event.code:4688 AND process.executable:*powershell*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "proces… | 13 |  |
| q-4689b4f321 | triage T1003 step 4 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k13y"} | None | F01 |
| q-c7c8902c52 | triage T1003 step 4 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NY3HhA"} | None | F02 |
| q-d2c8eb8fa0 | triage T1003 step 4 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND process.executable:*wsmprovhost*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.co… | 1 |  |
| q-ce11abff95 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-089b191c24 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-135cd6e16f | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k13y"} | None |  |
| q-493981adb6 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrM7IJ"} | None |  |
| q-fdeebd22bf | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrM7IJ"} | None |  |
| q-afe4b45f2d | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NY3HhA"} | None |  |
| q-6250c290bb | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NY3HhA"} | None |  |
| q-c6670c12fa | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RpKsLE"} | None |  |
| q-5a344475d9 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RpKsLE"} | None |  |
| q-e4c4fac4d9 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NAd3XG"} | None |  |
| q-caaceb02b8 | triage T1040 step 1 | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx2I"} | None |  |
| q-7ce0ddd857 | triage T1040 step 1 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.executable:*NetworkWatcher* OR process.executable:*logman* OR process.executable:*netsh* OR process.executable:*pktmon*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host… | 13 | F04, F05 |
| q-1b8e606d05 | triage T1040 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:6 AND (win.Image:*pcap* OR win.Image:*npcap* OR win.Image:*winpcap* OR win.Image:*NetworkWatcher* OR win.Image:*ndis* OR win.Image:*netmon*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host… | 0 |  |
| q-b129e3a347 | triage T1040 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*trace* OR process.command_line:*capture* OR process.command_line:*pktmon* OR process.command_line:*netsh*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name… | 4 | F04, F05 |
| q-88287e22a3 | triage T1040 step 3 | search | {"dataset": "windows.sysmon", "query": "process.executable:*PsExec* OR process.executable:*PSEXESVC* OR process.executable:*sdelete*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "process.executable", "process.command… | 716 |  |
| q-6bfd87a0b6 | triage T1040 step 3 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*promisc* OR process.command_line:*raw* OR process.command_line:*sniff* OR process.command_line:*dumpcap* OR process.command_line:*windump*)", "time_from": null, "time_to": null, "f… | 1 |  |
| q-0034eff2a2 | triage T1040 step 4 | search | {"dataset": "zeek", "query": "network.transport:icmp OR event.action:notice OR event.action:weird", "time_from": null, "time_to": null, "fields": ["@timestamp", "event.action", "network.transport", "source.ip", "destination.ip", "zeek.note", "zeek.msg", "obser… | 14 | F06 |
| q-5c1c3a9ea4 | triage T1040 step 4 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.executable:*NetworkWatcher* OR process.executable:*pktmon* OR process.executable:*dumpcap* OR process.executable:*tshark*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.na… | 4 | F04 |
| q-4a92a53a90 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NW1Kgv"} | None |  |
| q-b8cf62c492 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NW1Kgv"} | None |  |
| q-c1769a7c7d | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1WpSJN6"} | None |  |
| q-3f312a1c49 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YYOcv1"} | None |  |
| q-8c233cae52 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YXONNh"} | None |  |
| q-f0939c8be3 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YKEhta"} | None |  |
| q-1f4c6edf4c | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NUxiiK"} | None |  |
| q-69c28bc686 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1WdFNhN"} | None |  |
| q-d9a84aff13 | triage T1040 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO74el"} | None |  |
| q-b5397de07d | triage T1040 step 6 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1WdFNhN"} | None | F06 |
| q-fec89a5fa4 | triage T1056 step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND win.TargetImage LIKE \"*lsass*\" \| STATS cnt = COUNT(*) BY process.executable, win.GrantedAccess, host.name \| SORT cnt DESC"} | 18 |  |
| q-07d1942058 | triage T1056 step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND win.TargetImage LIKE \"*lsass*\" AND win.GrantedAccess IN (\"0x1fffff\",\"0x101001\",\"0x1f3fff\",\"0x1000000\",\"0x3000\",\"0x1400\") \| KEEP @timestamp, host.n… | 33 | F08, F10 |
| q-6ad4b49968 | triage T1056 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k13y"} | None |  |
| q-14b6e722e4 | triage T1056 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-69014be8f1 | triage T1056 step 2 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND @timestamp >= \"2020-05-02T03:04:00.000Z\" AND @timestamp <= \"2020-05-02T03:07:00.000Z\" \| KEEP @timestamp, host.name, user.name, powershell.script_block… | 35 | F07, F08, F09 |
| q-eb6d89798f | triage T1056 step 3 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21_Tx"} | None |  |
| q-73f399bb2f | triage T1056 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrM7IJ"} | None |  |
| q-5d98674fda | triage T1056 step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE powershell.script_block_text LIKE \"*Keystroke*\" OR powershell.script_block_text LIKE \"*GetAsyncKeyState*\" OR powershell.script_block_text LIKE \"*SetWindowsHookEx*\" OR powershel… | 6 | F07 |
| q-232bb20c8d | triage T1056 step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE powershell.script_block_text LIKE \"*Get-Keystrokes*\" AND powershell.script_block_text LIKE \"*function*\" \| KEEP @timestamp, host.name, user.name, powershell.script_block_text, _i… | 0 |  |
| q-16b94dcb69 | triage T1056 step 4 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4688\" AND process.command_line LIKE \"*Keystroke*\" OR (event.code == \"4688\" AND process.command_line LIKE \"*keylog*\") \| KEEP @timestamp, host.name, user.name, pr… | 0 |  |
| q-c346b45d69 | triage T1056 step 5 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21_R0"} | None |  |
| q-8f4fb4b096 | triage T1056 step 5 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE powershell.script_block_text LIKE \"*GetAsyncKeyState*\" OR powershell.script_block_text LIKE \"*SetWindowsHookEx*\" OR powershell.script_block_text LIKE \"*GetKeyboardState*\" OR po… | 0 |  |
| q-681e16e3ab | triage T1056 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21_Tx"} | None |  |
| q-2168dfa20b | triage T1056 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21_R0"} | None |  |
| q-0ffd10474b | triage T1056 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21_Qp"} | None |  |
| q-38555e238f | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k13y"} | None |  |
| q-bae4c95d19 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-1cc9f7136b | triage T1056 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None |  |
| q-a2fc620003 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b22PTB"} | None |  |
| q-5f6505afe2 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vTv"} | None |  |
| q-15853dd375 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrM7IJ"} | None |  |
| q-3ed7bbfbdd | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrM7IJ"} | None |  |
| q-e6baa287b4 | triage T1110 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None | F12 |
| q-b0f00c1d76 | triage T1110 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None | F12 |
| q-86d1e8a14e | triage T1110 step 1 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YogQzA"} | None | F14, F15 |
| q-9eecc0741d | triage T1110 step 1 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YcSP2J"} | None | F14 |
| q-86df9c4102 | triage T1110 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND win.TargetImage LIKE \"*lsass*\" \| STATS c = COUNT(*) BY process.executable, win.GrantedAccess, host.name \| SORT c DESC \| LIMIT 30"} | 18 |  |
| q-f1c0d3b035 | triage T1110 step 2 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4663\" AND win.ObjectName LIKE \"*SAM*\" \| KEEP @timestamp, host.name, win.ObjectName, win.ProcessName, win.AccessMask, user.name, _id, _index \| LIMIT 20"} | 0 |  |
| q-acc491e8f5 | triage T1110 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND win.TargetImage LIKE \"*lsass*\" AND win.GrantedAccess IN (\"0x1fffff\",\"0x1f3fff\",\"0x101001\") \| KEEP @timestamp, host.name, process.executable, process.com… | 7 |  |
| q-40d4e3c79e | triage T1110 step 3 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4663\" AND win.ObjectName == \"SAM\" \| KEEP @timestamp, host.name, win.ObjectName, win.ProcessName, win.AccessMask, user.name, _id, _index \| LIMIT 20"} | 0 |  |
| q-bf69cce890 | triage T1110 step 4 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None | F11, F13 |
| q-c4e9dfbb0c | triage T1110 step 4 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4663\" AND win.ObjectName LIKE \"*SAM*\" \| STATS c=COUNT(*) BY win.ObjectName, win.ProcessName, host.name \| SORT c DESC \| LIMIT 20"} | 0 |  |
| q-be1d38eca7 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx0y"} | None |  |
| q-accd1a7041 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-3e715b3e56 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None |  |
| q-955e5be289 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-f6f8350893 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-c24edd6264 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-8e0a5f2272 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YcSP2J"} | None |  |
| q-16a60b2101 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YogQzA"} | None |  |
| q-938cfc03e8 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YogQzA"} | None |  |
| q-3ef5d73c40 | triage T1111 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None | F17 |
| q-cb0a67ef61 | triage T1111 step 1 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YQHQbW"} | None |  |
| q-c00dfca711 | triage T1111 step 1 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4648", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 15 |  |
| q-a520ad89be | triage T1111 step 1 | aggregate | {"dataset": "windows.security", "field": "win.LogonProcessName", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 297 |  |
| q-0cc935555a | triage T1111 step 2 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b43Sxn"} | None |  |
| q-f3926dad33 | triage T1111 step 2 | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx1Y"} | None | F16 |
| q-5dc48a3569 | triage T1111 step 2 | search | {"dataset": "windows.security", "query": "event.code:4624 AND win.LogonType:10", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "win.LogonType", "win.IpAddress", "win.Workstation", "win.AuthenticationPackageName"], "size… | 2 |  |
| q-b1a09b48af | triage T1111 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "process.executable", "win.TargetImage", "win.GrantedAccess", "user.name"], "size": 20, "sort": "asc"} | 326 | F16 |
| q-63dca3deab | triage T1111 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx1Y"} | None |  |
| q-0863460981 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NY3HhV"} | None |  |
| q-3f1c5f5e98 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NDgh5J"} | None |  |
| q-88206d0c9a | triage T1111 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YogQzA"} | None |  |
| q-a19740e63a | triage T1111 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1SIwN6W"} | None |  |
| q-1269130a5f | triage T1111 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-549fad8e3e | triage T1111 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-93f80f8c4a | triage T1187 step 1 | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8Ieh"} | None | F18 |
| q-fb21f940d5 | triage T1187 step 1 | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8Iej"} | None | F18 |
| q-28e622a158 | triage T1187 step 1 | aggregate | {"dataset": "zeek", "field": "source.ip", "query": "event.action:http AND (http.request.method:PROPFIND OR http.request.method:MOVE OR http.request.method:OPTIONS)", "time_from": null, "time_to": null, "size": 20, "sub_field": "destination.ip"} | 36 |  |
| q-1601903588 | triage T1187 step 1 | aggregate | {"dataset": "zeek", "field": "user_agent.original", "query": "event.action:http", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 62 |  |
| q-9e854f80ce | triage T1187 step 2 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"conn\" AND (destination.port == 445 OR destination.port == 139 OR destination.port == 80) \| KEEP @timestamp, source.ip, destination.ip, destination.port, zeek.conn_state, zeek.s… | 60 |  |
| q-be67167e1d | triage T1187 step 2 | aggregate | {"dataset": "zeek", "field": "destination.ip", "query": "event.action:conn AND (destination.port:445 OR destination.port:139)", "time_from": null, "time_to": null, "size": 20, "sub_field": "source.ip"} | 50 |  |
| q-76e1f33144 | triage T1187 step 2 | aggregate | {"dataset": "windows.security", "field": "win.ShareName", "query": "event.code:5140 OR event.code:5145", "time_from": null, "time_to": null, "size": 20, "sub_field": "source.ip"} | 163 |  |
| q-5273cdc1f0 | triage T1187 step 3 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE source.ip == \"10.0.1.4\" AND destination.ip == \"192.168.0.4\" \| KEEP @timestamp, event.action, destination.port, zeek.conn_state, zeek.service, url.original, http.request.method, http.response.… | 50 | F18 |
| q-01e51bf494 | triage T1187 step 3 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == 5140 OR event.code == 5145 \| WHERE source.ip == \"10.0.1.4\" \| KEEP @timestamp, host.name, event.code, user.name, source.ip, win.ShareName, win.AccessMask, _id, _index … | ERROR |  |
| q-d939401643 | triage T1187 step 4 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"5140\" OR event.code == \"5145\" \| WHERE source.ip == \"10.0.1.4\" \| KEEP @timestamp, host.name, event.code, user.name, source.ip, win.ShareName, win.AccessMask, _id,… | 40 | F19 |
| q-4d81098cab | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8IdC"} | None |  |
| q-c4c167e03f | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8Idl"} | None |  |
| q-3a4ec99775 | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8Ieh"} | None |  |
| q-36e5b0387f | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8Ieh"} | None |  |
| q-a535e5c1e2 | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8Iej"} | None |  |
| q-9cae2530f2 | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO74fI"} | None |  |
| q-fc50c103c6 | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO74fI"} | None |  |
| q-c914e75377 | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8IdC"} | None |  |
| q-f5ea8c08f8 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1Yldc_Q"} | None |  |
| q-c4d52e3b25 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1Yldc_Q"} | None |  |
| q-be22f934d6 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YjaXZN"} | None |  |
| q-e55d778012 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YjaXZN"} | None |  |
| q-e1261a4c8c | triage T1187 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YhYtY1"} | None |  |
| q-65240743fa | triage T1212 step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND win.TargetImage LIKE \"*lsass*\" \| KEEP @timestamp, host.name, process.executable, win.SourceImage, win.TargetImage, win.GrantedAccess, _id, _index \| LIMIT 50"… | 50 | F22 |
| q-166e8accf6 | triage T1212 step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND win.GrantedAccess LIKE \"*0x1*\" \| KEEP @timestamp, host.name, process.executable, win.SourceImage, win.TargetImage, win.GrantedAccess, _id, _index \| LIMIT 50"… | 50 |  |
| q-ce5ccd5d41 | triage T1212 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrM7IJ"} | None | F20 |
| q-6b7b02289c | triage T1212 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND win.GrantedAccess != \"0x1000\" \| KEEP @timestamp, host.name, process.executable, win.SourceImage, win.TargetImage, win.GrantedAccess, _id, _index \| LIMIT 50"} | 50 |  |
| q-24bcd3dbc2 | triage T1212 step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE host.name == \"nashua.dmevals.local\" AND event.code == \"4104\" \| KEEP @timestamp, host.name, user.name, powershell.script_block_text, _id, _index \| LIMIT 40"} | 11 | F20 |
| q-79147e211e | triage T1212 step 3 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4624\" AND win.LogonType == \"3\" \| KEEP @timestamp, host.name, user.name, win.LogonType, win.LogonProcessName, source.ip, win.TargetUserName, _id, _index \| LIMIT 40"… | 40 |  |
| q-85f1040662 | triage T1212 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND win.TargetImage LIKE \"*lsass*\" AND win.SourceImage NOT LIKE \"*svchost*\" \| KEEP @timestamp, host.name, win.SourceImage, win.TargetImage, win.GrantedAccess, _… | 30 | F20, F22 |
| q-e499090ff7 | triage T1212 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (process.command_line LIKE \"*lsass*\" OR process.command_line LIKE \"*Invoke-Command*\" OR process.command_line LIKE \"*NASHUA*\") \| KEEP @timestamp, host.name,… | 5 | F21 |
| q-a00e6ea337 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrM7IJ"} | None |  |
| q-d81e26fc79 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrM7IJ"} | None |  |
| q-b7e4689835 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrM7IJ"} | None |  |
| q-f73f22f23a | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrM7IJ"} | None |  |
| q-d4b7733795 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1bsxh3J"} | None |  |
| q-bd3f90797e | triage T1212 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1bsxhdc"} | None |  |
| q-4f7f01c50e | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RkEAFq"} | None |  |
| q-46ac0c2a2f | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RkEAFq"} | None |  |
| q-792ff6200c | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RkEAFq"} | None |  |
| q-e75afed1d6 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NAenUm"} | None |  |
| q-afc988c2fa | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NY3HhM"} | None |  |
| q-16295c27fa | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MuaKzP"} | None |  |
| q-4e1df2510b | triage T1539 step 1 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MsOhX7"} | None | F24 |
| q-6d7fc09ee2 | triage T1539 step 1 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YeU-Dp"} | None |  |
| q-59f5e86827 | triage T1539 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(win.TargetFilename) LIKE \"*cookies*\" OR TO_LOWER(win.TargetFilename) LIKE \"*login data*\" OR TO_LOWER(win.TargetFilename) LIKE \"*webcache*\" OR TO_… | 9 |  |
| q-6623997d8c | triage T1539 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND (TO_LOWER(win.TargetImage) LIKE \"*chrome*\" OR TO_LOWER(win.TargetImage) LIKE \"*firefox*\" OR TO_LOWER(win.TargetImage) LIKE \"*iexplore*\" OR TO_LOWER(win.Tar… | 500 | F25 |
| q-571278f80f | triage T1539 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE (event.code == \"11\" OR event.code == \"2\" OR event.code == \"23\") AND (TO_LOWER(win.TargetFilename) LIKE \"*\\\\cookies\" OR TO_LOWER(win.TargetFilename) LIKE \"*login data*\" OR TO_… | ERROR |  |
| q-8bbed1db05 | triage T1539 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*cookie*\" OR TO_LOWER(process.command_line) LIKE \"*login data*\" OR TO_LOWER(process.command_line) LIKE \"*webcache*\" OR… | 5 | F23 |
| q-aa332f7392 | triage T1539 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE (event.code == \"11\" OR event.code == \"2\" OR event.code == \"23\") AND (TO_LOWER(win.TargetFilename) LIKE \"*cookies*\" OR TO_LOWER(win.TargetFilename) LIKE \"*login data*\" OR TO_LOW… | 1 |  |
| q-0f1c6e136c | triage T1539 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.executable) LIKE \"*python*\" OR TO_LOWER(process.executable) LIKE \"*psexec*\" OR TO_LOWER(process.executable) LIKE \"*sdelete*\") \| KEEP @tim… | 15 | F26 |
| q-ec9ad2f63f | triage T1539 step 5 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(powershell.script_block_text) LIKE \"*cookie*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*login data*\" OR TO_LOWER(powershell.script_blo… | 5 | F26 |
| q-283a5850e3 | triage T1539 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(win.TargetFilename) LIKE \"*working.zip*\" OR TO_LOWER(win.TargetFilename) LIKE \"*draft.zip*\" OR TO_LOWER(win.TargetFilename) LIKE \"*rar.exe*\" OR T… | 12 |  |
| q-d7734bc6f1 | triage T1539 step 6 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-ede0f9fd3a | triage T1539 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YeU-Dp"} | None |  |
| q-b83739e7cc | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrMLE_"} | None |  |
| q-2292d64207 | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MsOhX7"} | None |  |
| q-b3fe220d31 | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MsOhX7"} | None |  |
| q-424b9e7ec5 | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1Muar8B"} | None |  |
| q-a37bfae24f | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MuaKzP"} | None |  |
| q-c95500e15c | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RkEAFq"} | None |  |
| q-f0449a2173 | triage T1539 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-bb64f347b2 | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1Nc7emY"} | None |  |
| q-3801064bda | triage T1552 step 1 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R_lkD8"} | None | F28 |
| q-964a8da407 | triage T1552 step 1 | search | {"dataset": "windows.sysmon", "query": "process.executable:*accesschk* OR process.command_line:*accesschk* OR win.TargetFilename:*passwordsDB*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.… | 2 | F28, F32 |
| q-ec5aa7f16a | triage T1552 step 2 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4663\",\"4656\",\"4658\",\"5145\") AND (TO_LOWER(win.ObjectName) LIKE \"*gpttmpl*\" OR TO_LOWER(win.ObjectName) LIKE \"*groups.xml*\" OR TO_LOWER(win.RelativeTargetNam… | 3 | F29 |
| q-72cd269062 | triage T1552 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*sysvol*\" OR TO_LOWER(process.command_line) LIKE \"*groups.xml*\" OR TO_LOWER(process.command_line) LIKE \"*gpttmpl*\" OR … | 0 |  |
| q-82543b2d17 | triage T1552 step 3 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4648\" \| KEEP @timestamp, host.name, user.name, process.executable, win.TargetUserName, win.TargetServerName, win.SubjectUserName, _id, _index \| LIMIT 20"} | 15 | F30 |
| q-f458df1a88 | triage T1552 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*password*\" OR TO_LOWER(process.command_line) LIKE \"*credential*\" OR TO_LOWER(process.command_line) LIKE \"*vault*\" OR … | 0 |  |
| q-0eb5b97538 | triage T1552 step 4 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4663\",\"4656\",\"4658\") AND (TO_LOWER(win.ObjectName) LIKE \"*\\\\\\\\config\\\\\\\\sam*\" OR TO_LOWER(win.ObjectName) LIKE \"*\\\\\\\\config\\\\\\\\security*\" OR T… | 0 |  |
| q-56d665ba8f | triage T1552 step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(powershell.script_block_text) LIKE \"*password*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*credential*\" OR TO_LOWER(powershell.script_b… | 6 | F27 |
| q-20fa13c1c1 | triage T1552 step 5 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None | F27 |
| q-e93fd84ad4 | triage T1552 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE (TO_LOWER(win.TargetFilename) LIKE \"*.pfx*\" OR TO_LOWER(win.TargetFilename) LIKE \"*.pem*\" OR TO_LOWER(win.TargetFilename) LIKE \"*.key*\" OR TO_LOWER(win.TargetFilename) LIKE \"*offi… | 4 | F27 |
| q-d9dff8e918 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None |  |
| q-8357434070 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None |  |
| q-cfa1a500e6 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R_lUAH"} | None |  |
| q-3500292614 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RsNaXs"} | None |  |
| q-056485ee84 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R_lkD8"} | None |  |
| q-5d77679dab | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R_lkD_"} | None |  |
| q-3845261a83 | triage T1552 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1bh-ZaM"} | None |  |
| q-88863cd070 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YTK7vy"} | None |  |
| q-92d1fea639 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YcSCou"} | None |  |
| q-e1740a1d4b | triage T1552 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YogQzA"} | None |  |
| q-e094a4ed85 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R8i4gn"} | None |  |
| q-2bf0ed3e57 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NY3HhV"} | None |  |
| q-800e2d7a4b | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R_lkD_"} | None |  |
| q-e9250f381e | triage T1555 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-572a799e9d | triage T1555 step 1 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YldM_p"} | None | F33 |
| q-34ccde9201 | triage T1555 step 2 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YjaXaO"} | None | F34 |
| q-2bfd8b5695 | triage T1555 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1Nc7emR"} | None | F35 |
| q-44b076bf41 | triage T1555 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND win.TargetImage LIKE \"*lsass*\" AND win.GrantedAccess IN (\"0x1fffff\",\"0x1f3fff\",\"0x101001\",\"0x1000000\",\"0x3000\") \| KEEP @timestamp, host.name, win.So… | 9 | F33, F34 |
| q-ca26d8f605 | triage T1555 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.executable) LIKE \"*sdelete*\" OR TO_LOWER(process.command_line) LIKE \"*sdelete*\" OR TO_LOWER(process.command_line) LIKE \"*procdump*\" OR TO_… | 6 |  |
| q-b4b52015c9 | triage T1555 step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code IN (\"4103\",\"4104\") AND host.name == \"scranton.dmevals.local\" AND @timestamp >= \"2020-05-02T03:04:00.000Z\" AND @timestamp <= \"2020-05-02T03:10:00.000Z\" \| KEEP @t… | 500 |  |
| q-120eb91d21 | triage T1555 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*credential*\" OR TO_LOWER(file.path) LIKE \"*vault*\" OR TO_LOWER(file.path) LIKE \"*dpapi*\" OR TO_LOWER(file.path) LIKE \"*.kdbx\"… | 0 |  |
| q-d5910618f6 | triage T1555 step 5 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND host.name == \"scranton.dmevals.local\" AND @timestamp >= \"2020-05-02T03:04:30.000Z\" AND @timestamp <= \"2020-05-02T03:06:30.000Z\" \| KEEP @timestamp, u… | 18 | F33 |
| q-b83fa21f54 | triage T1555 step 5 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(powershell.script_block_text) LIKE \"*invoke-exfil*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*invoke-beachcleanup*\" OR TO_LOWER(powers… | 16 | F34 |
| q-f76e6ab251 | triage T1555 step 6 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None | F33 |
| q-d4b3fc5767 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YldM_p"} | None |  |
| q-75c2f131e6 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YldM_p"} | None |  |
| q-f9cc1218bb | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-e6b8e335cd | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-376e609048 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None |  |
| q-bef850c18a | triage T1555 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vTX"} | None |  |
| q-838b107a5e | triage T1555 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YjaXaO"} | None |  |
| q-8f07dec1a0 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YjaXaO"} | None |  |
| q-9b51623d7f | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrM7IJ"} | None |  |
| q-3425afd14f | triage T1555 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1bsxQxS"} | None |  |
| q-7fad74aa66 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1Nc7emR"} | None |  |
| q-692868cbf6 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1Nc7emR"} | None |  |
| q-70075a326a | triage T1555 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YEBswS"} | None |  |
| q-4050fa23c2 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YGClc_"} | None |  |
| q-5c6e6864f4 | triage T1556 step 1 | aggregate | {"dataset": "windows.sysmon", "field": "win.SourceImage", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 30, "sub_field": "win.GrantedAccess"} | 326 |  |
| q-4ba225b821 | triage T1556 step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND win.TargetImage LIKE \"*lsass*\" AND win.SourceImage LIKE \"*powershell*\" \| KEEP @timestamp, host.name, win.SourceImage, win.SourceProcessId, win.GrantedAccess… | 2 |  |
| q-f4406fa06d | triage T1556 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND win.TargetImage LIKE \"*lsass*\" AND (win.SourceImage LIKE \"*PowerShell.exe\" OR win.SourceImage LIKE \"*wsmprovhost*\" OR win.SourceImage LIKE \"*wininit*\" OR… | 6 | F36 |
| q-0811c9bea3 | triage T1556 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*lsass*\" OR TO_LOWER(process.command_line) LIKE \"*sekurlsa*\" OR TO_LOWER(process.command_line) LIKE \"*mimikatz*\" OR TO… | 1 |  |
| q-d73c3012eb | triage T1556 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-20df2f6bda | triage T1556 step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(powershell.script_block_text) LIKE \"*lsass*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*credential*\" OR TO_LOWER(powershell.script_bloc… | 5 | F36 |
| q-eaf299ad92 | triage T1556 step 4 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-dbd8da38a5 | triage T1556 step 4 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4648\" \| KEEP @timestamp, host.name, user.name, process.executable, win.TargetUserName, win.TargetServerName, win.SubjectUserName, _id, _index"} | 15 | F37 |
| q-bf73ebb9c3 | triage T1556 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*system32*\" AND (TO_LOWER(file.path) LIKE \"*cryptdll*\" OR TO_LOWER(file.path) LIKE \"*msv1_0*\" OR TO_LOWER(file.path) LIKE \"*sam… | 0 |  |
| q-6056352c55 | triage T1556 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"13\" AND (TO_LOWER(registry.path) LIKE \"*lsa*\" OR TO_LOWER(registry.path) LIKE \"*notification packages*\" OR TO_LOWER(registry.path) LIKE \"*password*\" OR TO_LOWER(re… | 72 | F39, F40, F42 |
| q-5e629ed831 | triage T1556 step 6 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"13\" AND (TO_LOWER(registry.path) LIKE \"*notification packages*\" OR TO_LOWER(registry.path) LIKE \"*authentication packages*\" OR TO_LOWER(registry.path) LIKE \"*securi… | 0 |  |
| q-6707e7109f | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-b7c5ae51c7 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-adcf382318 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-cebf2f4bfc | triage T1556 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-2c2a46ed7b | triage T1556 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-6ea655727c | triage T1556 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YsmoMw"} | None |  |
| q-d6e9f04702 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YogQzA"} | None |  |
| q-d07ac84097 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1SFrjaS"} | None |  |
| q-bb154ed354 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NY3HhS"} | None |  |
| q-88d1fd6b5c | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1M_d1eR"} | None |  |
| q-5aaea04c35 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R5ewC0"} | None |  |
| q-7e24175871 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NY3HhQ"} | None |  |
| q-76c7504703 | triage T1557 step 1 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"conn\" \| KEEP @timestamp, source.ip, destination.ip, destination.port, zeek.orig_l2_addr, zeek.resp_l2_addr, zeek.service, zeek.conn_state, _id, _index \| LIMIT 20"} | 20 | F45, F46 |
| q-ab890050d5 | triage T1557 step 1 | aggregate | {"dataset": "zeek", "field": "zeek.orig_l2_addr", "query": "event.action:conn", "time_from": null, "time_to": null, "size": 50, "sub_field": "source.ip"} | 613 |  |
| q-b90caebd30 | triage T1557 step 2 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"conn\" AND zeek.orig_l2_addr == \"fc:bd:67:e1:a9:c1\" \| KEEP @timestamp, source.ip, destination.ip, destination.port, zeek.orig_l2_addr, zeek.resp_l2_addr, zeek.service, zeek.co… | 44 | F45 |
| q-7c92daa682 | triage T1557 step 2 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"conn\" AND zeek.resp_l2_addr == \"12:34:56:78:9a:bc\" \| STATS cnt = COUNT(*) BY source.ip, destination.ip, destination.port \| SORT cnt DESC \| LIMIT 30"} | 25 |  |
| q-1e8811aeeb | triage T1557 step 3 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action IN (\"smb_files\", \"smb_mapping\", \"dce_rpc\", \"kerberos\") \| KEEP @timestamp, event.action, source.ip, destination.ip, destination.port, zeek.filename, zeek.path, zeek.name, zeek… | 40 | F44 |
| q-d9c9674c39 | triage T1557 step 3 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"conn\" AND (destination.ip == \"192.168.0.4\" OR destination.ip == \"192.168.0.5\") \| KEEP @timestamp, source.ip, destination.ip, destination.port, zeek.orig_l2_addr, zeek.resp_… | 40 |  |
| q-7339ac9ca0 | triage T1557 step 4 | esql | {"query": "FROM logs-windows.other-default METADATA _id, _index \| WHERE event.code == \"7045\" OR event.code == \"7040\" \| KEEP @timestamp, host.name, event.code, win.ServiceName, win.ImagePath, win.ServiceType, win.StartType, user.name, _id, _index \| LIMIT… | 9 | F44 |
| q-b66647deed | triage T1557 step 4 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4697\" \| KEEP @timestamp, host.name, win.ServiceName, win.ServiceFileName, win.ServiceAccount, user.name, _id, _index \| LIMIT 30"} | 23 |  |
| q-907bf223a4 | triage T1557 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*netsh*\" OR TO_LOWER(process.command_line) LIKE \"*arp*\" OR TO_LOWER(process.command_line) LIKE \"*route*\" OR TO_LOWER(p… | 12 | F46 |
| q-0343814aaa | triage T1557 step 5 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4657\" \| KEEP @timestamp, host.name, win.ObjectName, win.ObjectValueName, win.NewValue, win.ProcessName, user.name, _id, _index \| LIMIT 30"} | 30 |  |
| q-a15f14403e | triage T1557 step 6 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (process.executable LIKE \"*ARP.EXE*\" OR process.executable LIKE \"*ROUTE.EXE*\" OR process.executable LIKE \"*netsh.exe*\") \| KEEP @timestamp, host.name, proce… | 8 | F43, F45 |
| q-1c45f20b26 | triage T1557 step 6 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"22\" \| KEEP @timestamp, host.name, win.QueryName, win.QueryResults, win.QueryStatus, process.executable, user.name, _id, _index \| LIMIT 40"} | 40 | F44 |
| q-ce6d056ad5 | triage T1557 step 7 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"5145\" OR event.code == \"5140\" \| KEEP @timestamp, host.name, win.ShareName, win.ShareLocalPath, win.SubjectUserName, win.IpAddress, win.RelativeTargetName, _id, _ind… | 30 | F43 |
| q-75ddb45d0e | triage T1557 step 7 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(powershell.script_block_text) LIKE \"*invoke-mimikatz*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*relay*\" OR TO_LOWER(powershell.script… | 0 |  |
| q-dba27cc874 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NKneCu"} | None |  |
| q-da5e5026ec | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NKneCu"} | None |  |
| q-6dad8f2df8 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NW1Kgv"} | None |  |
| q-c7be592a5b | triage T1557 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YDAqy3"} | None |  |
| q-40614dd14d | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MubN05"} | None |  |
| q-6c70c9507a | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MubN05"} | None |  |
| q-b72db78942 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx2W"} | None |  |
| q-5d5f5c695c | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8IeN"} | None |  |
| q-fe33c2e7c5 | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8YcB"} | None |  |
| q-4990bbbf9a | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1bi_UDc"} | None |  |
| q-de380a6479 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NNo5A0"} | None |  |
| q-3d615d457f | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NUyf30"} | None |  |
| q-73c949a100 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx1V"} | None |  |
| q-3e547091da | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NY2Xjg"} | None |  |
| q-a1b755e976 | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8If9"} | None |  |
| q-c03d527973 | triage T1558 step 1 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YhYtYx"} | None | F50, F51 |
| q-c6bce153c8 | triage T1558 step 1 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == 4769 \| KEEP @timestamp, host.name, user.name, win.ServiceName, win.TicketEncryptionType, win.TicketOptions, source.ip, _id, _index \| SORT @timestamp ASC"} | ERROR |  |
| q-45c1d06ea8 | triage T1558 step 2 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4769\" \| KEEP @timestamp, host.name, user.name, win.ServiceName, win.TicketEncryptionType, win.TicketOptions, source.ip, _id, _index \| SORT @timestamp ASC"} | 28 | F48, F49 |
| q-438b4ab72b | triage T1558 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND win.TargetImage LIKE \"*lsass*\" \| KEEP @timestamp, host.name, process.executable, win.GrantedAccess, win.SourceImage, _id, _index \| SORT @timestamp ASC"} | 326 | F47 |
| q-f6b5ef3056 | triage T1558 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None | F47 |
| q-22633466b3 | triage T1558 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k13y"} | None |  |
| q-07f5434bc1 | triage T1558 step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND host.name == \"scranton.dmevals.local\" \| KEEP @timestamp, host.name, user.name, powershell.script_block_text, _id, _index \| SORT @timestamp ASC \| LIMIT… | 30 | F47 |
| q-251fa07937 | triage T1558 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND host.name == \"scranton.dmevals.local\" \| KEEP @timestamp, host.name, user.name, process.executable, process.command_line, process.parent.executable, _id, _index… | 359 | F47 |
| q-0c7792031c | triage T1558 step 5 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND host.name == \"scranton.dmevals.local\" AND @timestamp >= \"2020-05-02T03:03:00.000Z\" AND @timestamp <= \"2020-05-02T03:10:00.000Z\" \| KEEP @timestamp, u… | 40 |  |
| q-00ddd431ec | triage T1558 step 5 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4672\" \| KEEP @timestamp, host.name, user.name, win.TargetUserName, win.PrivilegeList, _id, _index \| SORT @timestamp ASC \| LIMIT 40"} | 40 |  |
| q-dd4e0878d7 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-71979dc507 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k13y"} | None |  |
| q-9d153c21ea | triage T1558 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-ad8820f646 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1WiJkSG"} | None |  |
| q-b54a6034b6 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b87aMP"} | None |  |
| q-42bc70ef86 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YhYtYx"} | None |  |
| q-4f59068085 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YhYtYx"} | None |  |
| q-67dd3a4720 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YhYtYx"} | None |  |
| q-02bc29cfba | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YjanYM"} | None |  |
| q-3189836239 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YhYtYx"} | None |  |
| q-34280ac610 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YhYtYx"} | None |  |
| q-e8f976e777 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YhYtYx"} | None |  |
| q-05b0c80ce5 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YhYtYx"} | None |  |
| q-444ad2d020 | triage T1606 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b22vQJ"} | None | F53 |
| q-602d382a5f | triage T1606 step 1 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND win.TargetImage:*lsass* AND (win.GrantedAccess:0x1fffff OR win.GrantedAccess:0x101001 OR win.GrantedAccess:0x1f3fff OR win.GrantedAccess:0x1000000 OR win.GrantedAccess:0x3… | 33 |  |
| q-d716375932 | triage T1606 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND (win.GrantedAccess:0x1fffff OR win.GrantedAccess:0x101001 OR win.GrantedAccess:0x1f3fff OR win.GrantedAccess:0x1000000 OR win.GrantedAccess:0x3000)", "time_from": null, "time… | 9 | F52 |
| q-985ba4ae70 | triage T1606 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*cookie* OR file.path:*Cookies*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "process.executable", "process.command_line", "file.path", "user.name"], "size": 1… | 1 | F53 |
| q-a7e5f7c291 | triage T1606 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None | F52 |
| q-9083fea44c | triage T1606 step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == 4104 \| WHERE TO_LOWER(powershell.script_block_text) LIKE \"*token*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*cookie*\" OR TO_LOWER(powershell.script_block_te… | ERROR |  |
| q-5e1cb8aca6 | triage T1606 step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" \| WHERE TO_LOWER(powershell.script_block_text) LIKE \"*token*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*cookie*\" OR TO_LOWER(powershell.script_bloc… | 6 |  |
| q-9d50be5802 | triage T1606 step 4 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND process.executable:*PowerShell*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "process.executable", "process.command_line", "process.parent.executable", "process.parent.comm… | 12 | F52 |
| q-8ea8584def | triage T1606 step 5 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None | F52 |
| q-b58440bef2 | triage T1606 step 5 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1bsx-ky"} | None | F54 |
| q-d4ad63ad85 | triage T1606 step 6 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4648\" \| KEEP @timestamp, host.name, user.name, win.TargetUserName, win.LogonProcessName, win.TargetServerName, _id, _index \| LIMIT 20"} | 15 |  |
| q-d5b44640cf | triage T1606 step 6 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND process.executable LIKE \"*powershell*\" AND process.command_line LIKE \"*monkey*\" \| KEEP @timestamp, host.name, user.name, process.command_line, _id, _index \|… | 1 |  |
| q-a8ced12b9a | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-c0962883b2 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-78d5aac634 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1WdFNhN"} | None |  |
| q-ecd20225d6 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-ac07e3db96 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MsOhX7"} | None |  |
| q-d1cc51f6d1 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b22vQJ"} | None |  |
| q-20b2f17518 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1bsx-ky"} | None |  |
| q-ad64d02671 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx1E"} | None |  |
| q-5e9126c244 | triage T1621 step 1 | aggregate | {"dataset": "windows.other", "field": "event.code", "query": "*", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 216 |  |
| q-85461bb7f2 | triage T1621 step 1 | aggregate | {"dataset": "windows.other", "field": "win.Operation", "query": "event.code:5857 OR event.code:5858 OR event.code:5860", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 88 |  |
| q-0b01ce7b65 | triage T1621 step 2 | esql | {"query": "FROM logs-windows.other-default METADATA _id, _index \| WHERE event.code IN (\"5857\",\"5858\",\"5860\") \| KEEP @timestamp, host.name, event.code, user.name, message \| LIMIT 20"} | 20 |  |
| q-67b04c5660 | triage T1621 step 2 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4625\",\"4771\",\"4776\",\"4648\",\"4624\") \| STATS c = COUNT(*) BY event.code, win.TargetUserName \| SORT c DESC \| LIMIT 30"} | 22 |  |
| q-deb29cd345 | triage T1621 step 3 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4648\" \| KEEP @timestamp, host.name, win.TargetUserName, win.SubjectUserName, process.executable, win.ProcessName \| LIMIT 20"} | 15 |  |
| q-bf11315231 | triage T1621 step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code IN (\"4104\",\"4103\") AND (TO_LOWER(powershell.script_block_text) LIKE \"*mfa*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*authenticat*\" OR TO_LOWER(powershell.s… | 2 |  |
| q-8a55234c28 | triage T1621 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*mfa*\" OR TO_LOWER(process.command_line) LIKE \"*authenticat*\" OR TO_LOWER(process.command_line) LIKE \"*login*\" OR TO_L… | 3 |  |
| q-4483246eca | triage T1621 step 4 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action IN (\"http\",\"dns\",\"ssl\") AND (TO_LOWER(url.original) LIKE \"*login*\" OR TO_LOWER(url.original) LIKE \"*auth*\" OR TO_LOWER(url.original) LIKE \"*mfa*\" OR TO_LOWER(dns.question.… | 0 |  |
| q-c694f871b3 | triage T1621 step 5 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| STATS c = COUNT(*) BY event.action \| SORT c DESC \| LIMIT 20"} | 14 |  |
| q-5d34b0a807 | triage T1621 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx1E"} | None |  |
| q-c8203e3f7f | triage T1621 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx1E"} | None |  |
| q-77f1de14e7 | triage T1621 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx1E"} | None |  |
| q-5cc5fc8949 | triage T1621 verify | get_event | {"index": "logs-windows.security-default", "id": "q-67b04c5660-row"} | ERROR |  |
| q-bc333bb093 | triage T1621 verify | get_event | {"index": "logs-windows.security-default", "id": "q-67b04c5660-row"} | ERROR |  |
| q-9f5c23e076 | triage T1621 verify | get_event | {"index": "logs-windows.security-default", "id": "q-deb29cd345-row"} | ERROR |  |
| q-63897a2a32 | triage T1621 verify | get_event | {"index": "logs-windows.powershell-default", "id": "q-bf11315231-row"} | ERROR |  |
| q-ba5bed4996 | triage T1621 verify | get_event | {"index": "logs-windows.sysmon-default", "id": "q-8a55234c28-row"} | ERROR |  |
| q-eeba351676 | triage T1621 verify | get_event | {"index": "logs-windows.sysmon-default", "id": "q-8a55234c28-row"} | ERROR |  |
| q-a2886893fe | triage T1621 step 7 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4776\" \| KEEP @timestamp, host.name, event.code, win.TargetUserName, _id, _index \| LIMIT 5"} | 1 | F56 |
| q-dee15f7f26 | triage T1621 step 7 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*pushtoinstall*\" OR TO_LOWER(process.command_line) LIKE \"*dmwappushservice*\") \| KEEP @timestamp, host.name, process.com… | 3 | F57 |
| q-1809e7ccc7 | triage T1621 step 7 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND TO_LOWER(powershell.script_block_text) LIKE \"*microsoft corporation*\" \| KEEP @timestamp, host.name, event.code, _id, _index \| LIMIT 5"} | 5 | F57 |
| q-b4601ca6d9 | triage T1621 step 7 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4648\" AND process.executable LIKE \"*PSEXESVC*\" \| KEEP @timestamp, host.name, process.executable, win.TargetUserName, _id, _index \| LIMIT 5"} | 4 | F56 |
| q-d4cc4af4ca | triage T1649 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None | F58 |
| q-d1be6d4606 | triage T1649 step 1 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*cert* OR powershell.script_block_text:*PrivateKey* OR powershell.script_block_text:*Thumbprint* OR powershell.script_block_text:*pfx*)", "time_from": null, "time_to"… | 5 |  |
| q-cc81b35bce | triage T1649 step 2 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1bsxh3C"} | None | F59 |
| q-bb7f701113 | triage T1649 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*Downloads* OR file.path:*.pfx OR file.path:*.7z)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "pro… | 317 |  |
| q-99d97415d9 | triage T1649 step 3 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND file.path:*.pfx", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "so… | 1 | F58 |
| q-29b6af0eef | triage T1649 step 3 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*Get-PrivateKeys* OR process.command_line:*readme.ps1 OR process.command_line:*psversion.ps1 OR process.command_line:*Export-PfxCertificate*)", "time_from": null, "time_to": null, "… | 0 |  |
| q-a50aac922e | triage T1649 step 4 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND process.executable:*powershell* AND (process.command_line:*readme* OR process.command_line:*psversion* OR process.command_line:*Sysinternals*)", "time_from": null, "time_to": null, "fields": ["@timestamp… | 0 |  |
| q-3c68132d3d | triage T1649 step 4 | search | {"dataset": "windows.security", "query": "event.code:4657 AND win.ObjectName:*SystemCertificates*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "pr… | 1 | F60 |
| q-d2783e3e34 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None |  |
| q-8d7aae8baa | triage T1649 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None |  |
| q-a69d038b4a | triage T1649 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None |  |
| q-6bf963d68e | triage T1649 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R_lUAH"} | None |  |
| q-87f48c1fa9 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R_lUAH"} | None |  |
| q-b4a6a58869 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1bsxh3C"} | None |  |
| q-d9ec47bc23 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1bsxh3C"} | None |  |
| q-d3dd23bb64 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1bsxh3C"} | None |  |
| q-7b5b315947 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YeUuC-"} | None |  |
| q-c9b553b33e | triage T1649 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YeUuC-"} | None |  |
| q-f6a78e93fa | triage T1649 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YeUuC-"} | None |  |
| q-b57c9a628e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-5c12a55255 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-967d8e6650 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k13y"} | None |  |
| q-1521171e02 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrM7IJ"} | None |  |
| q-744f1e376e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrM7IJ"} | None |  |
| q-c88564a9d3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NY3HhA"} | None |  |
| q-0a164fe43c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NY3HhA"} | None |  |
| q-19fc6045ab | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RpKsLE"} | None |  |
| q-5351cadefa | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RpKsLE"} | None |  |
| q-25774eb2bc | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NAd3XG"} | None |  |
| q-f39f12ccc0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NW1Kgv"} | None |  |
| q-75a25152e8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NW1Kgv"} | None |  |
| q-88dc3a6649 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1WpSJN6"} | None |  |
| q-12175b481b | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YYOcv1"} | None |  |
| q-836cc37bd7 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YXONNh"} | None |  |
| q-38210c7214 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YKEhta"} | None |  |
| q-425b6d2aed | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NUxiiK"} | None |  |
| q-4961be04fa | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1WdFNhN"} | None |  |
| q-4035c162c9 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO74el"} | None |  |
| q-366f25e996 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21_Tx"} | None |  |
| q-dd708c7394 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21_R0"} | None |  |
| q-4b80ca38cc | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21_Qp"} | None |  |
| q-4840b5df25 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k13y"} | None |  |
| q-8071f06a11 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-1e345f8b07 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None |  |
| q-f7da1a1f5f | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b22PTB"} | None |  |
| q-9a8cf9b46a | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vTv"} | None |  |
| q-f2167d82d1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrM7IJ"} | None |  |
| q-ff0f24ee4b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrM7IJ"} | None |  |
| q-ef58ab44b5 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx0y"} | None |  |
| q-ea9479f671 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-64e9f354cb | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None |  |
| q-9dc75d98fe | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-7e83f90c72 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-76f815ca6d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-421bb74977 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YcSP2J"} | None |  |
| q-1dd7a6fb4f | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YogQzA"} | None |  |
| q-10f335d646 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YogQzA"} | None |  |
| q-02f9d78c62 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx1Y"} | None |  |
| q-b3f212dfb7 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NY3HhV"} | None |  |
| q-a045539aca | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NDgh5J"} | None |  |
| q-1d481f7a73 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YogQzA"} | None |  |
| q-259fe233b3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1SIwN6W"} | None |  |
| q-c9d881ebd3 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-5a1ab268f4 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-717f4d1c14 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8IdC"} | None |  |
| q-43336b4c9a | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8Idl"} | None |  |
| q-86b7508056 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8Ieh"} | None |  |
| q-87d3121ed9 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8Ieh"} | None |  |
| q-8bedd9fce8 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8Iej"} | None |  |
| q-bc11870164 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO74fI"} | None |  |
| q-cb85587955 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO74fI"} | None |  |
| q-663599d2fc | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8IdC"} | None |  |
| q-07cee0016d | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1Yldc_Q"} | None |  |
| q-cbdedbe681 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1Yldc_Q"} | None |  |
| q-c01c18c22e | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YjaXZN"} | None |  |
| q-3421726fe5 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YjaXZN"} | None |  |
| q-250a6cdda8 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YhYtY1"} | None |  |
| q-9ac3d4f794 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrM7IJ"} | None |  |
| q-a24be4e54c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrM7IJ"} | None |  |
| q-33f4427c2d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrM7IJ"} | None |  |
| q-236ce66b2a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrM7IJ"} | None |  |
| q-06960caad7 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1bsxh3J"} | None |  |
| q-20a33a6d79 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1bsxhdc"} | None |  |
| q-550428c261 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RkEAFq"} | None |  |
| q-3457f62885 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RkEAFq"} | None |  |
| q-e4e56dcb0b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RkEAFq"} | None |  |
| q-ee464ff495 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NAenUm"} | None |  |
| q-686135b5b8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NY3HhM"} | None |  |
| q-d422baed39 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MuaKzP"} | None |  |
| q-cfce98dc25 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YeU-Dp"} | None |  |
| q-6a7fb1343f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrMLE_"} | None |  |
| q-63ae660b67 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MsOhX7"} | None |  |
| q-5fa020399a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MsOhX7"} | None |  |
| q-77757a7eb1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1Muar8B"} | None |  |
| q-764b4ca09b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MuaKzP"} | None |  |
| q-0c3ad57428 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RkEAFq"} | None |  |
| q-bbddc6f383 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-ca7bff17fe | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1Nc7emY"} | None |  |
| q-09efa9159f | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None |  |
| q-51dbadcd9a | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None |  |
| q-2673b6b8d4 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R_lUAH"} | None |  |
| q-fe8433193e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RsNaXs"} | None |  |
| q-f21c147f53 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R_lkD8"} | None |  |
| q-7f479d05b5 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R_lkD_"} | None |  |
| q-e08b76497e | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1bh-ZaM"} | None |  |
| q-737d91888e | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YTK7vy"} | None |  |
| q-4f40ea839e | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YcSCou"} | None |  |
| q-611ddfc273 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YogQzA"} | None |  |
| q-ef96fd288a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R8i4gn"} | None |  |
| q-074c8e20e6 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NY3HhV"} | None |  |
| q-d0caac2d15 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R_lkD_"} | None |  |
| q-04044c4bd3 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YldM_p"} | None |  |
| q-6137698da8 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YldM_p"} | None |  |
| q-0dd1ab3de1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-2b82bf8f8d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-e504789b1d | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None |  |
| q-caed869e6d | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vTX"} | None |  |
| q-f725efa3ae | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YjaXaO"} | None |  |
| q-c9b692b7a7 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YjaXaO"} | None |  |
| q-8cdbe1b87c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrM7IJ"} | None |  |
| q-6e58b98209 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1bsxQxS"} | None |  |
| q-7850b760a8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1Nc7emR"} | None |  |
| q-e112139b6f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1Nc7emR"} | None |  |
| q-d57bb91ae3 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YEBswS"} | None |  |
| q-415d06250a | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YGClc_"} | None |  |
| q-bed003c314 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-ebaf54dcc1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-9ceceb7350 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-16e30880f9 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-faa3566ef1 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-09e1a92158 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YsmoMw"} | None |  |
| q-be38fcab7b | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YogQzA"} | None |  |
| q-01e8ff9a30 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1SFrjaS"} | None |  |
| q-b3caf55176 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NY3HhS"} | None |  |
| q-ece7341784 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1M_d1eR"} | None |  |
| q-56f63cf006 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R5ewC0"} | None |  |
| q-0f89a01945 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NY3HhQ"} | None |  |
| q-cd4ac36149 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NKneCu"} | None |  |
| q-159c08abda | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NKneCu"} | None |  |
| q-e904fa0dfb | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NW1Kgv"} | None |  |
| q-c6639086ee | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YDAqy3"} | None |  |
| q-c08c4078d8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MubN05"} | None |  |
| q-6757c94426 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MubN05"} | None |  |
| q-0c3e309ac4 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx2W"} | None |  |
| q-f039908613 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8IeN"} | None |  |
| q-96170d5f17 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8YcB"} | None |  |
| q-48527b41ec | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1bi_UDc"} | None |  |
| q-c6f3b78e02 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NNo5A0"} | None |  |
| q-aac6452f89 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NUyf30"} | None |  |
| q-53927c0d62 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx1V"} | None |  |
| q-8d2d70fa24 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NY2Xjg"} | None |  |
| q-6f47038e2a | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8If9"} | None |  |
| q-951ce3bafa | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-ffb9f7031b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k13y"} | None |  |
| q-40fd71f3b0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-ec311aab03 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1WiJkSG"} | None |  |
| q-e12253a72a | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b87aMP"} | None |  |
| q-a6ec9d86ff | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YhYtYx"} | None |  |
| q-d61484961b | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YhYtYx"} | None |  |
| q-731281ca01 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YhYtYx"} | None |  |
| q-5de352ef9e | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YjanYM"} | None |  |
| q-005c7f28f4 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YhYtYx"} | None |  |
| q-96903d6f74 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YhYtYx"} | None |  |
| q-e4e6add49b | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YhYtYx"} | None |  |
| q-232a8f043e | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YhYtYx"} | None |  |
| q-eecd66d625 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-84f2d0a0e4 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-fc2019018b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1WdFNhN"} | None |  |
| q-28aac0230e | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-a038c9a173 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MsOhX7"} | None |  |
| q-535e54585a | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b22vQJ"} | None |  |
| q-1a997db22e | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1bsx-ky"} | None |  |
| q-2611bde78d | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx1E"} | None |  |
| q-42ddb87369 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx1E"} | None |  |
| q-f946765717 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx1E"} | None |  |
| q-89a5bc4834 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx1E"} | None |  |
| q-6daffb643a | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YQHwYC"} | None |  |
| q-74fd9e9f3b | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YQHwYC"} | None |  |
| q-192682a0f2 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YcSCoM"} | None |  |
| q-6e030d8cca | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1bsx-kn"} | None |  |
| q-276812ea51 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MtWeH6"} | None |  |
| q-fcaeb780f8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1SDpoh0"} | None |  |
| q-368d2ca706 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None |  |
| q-92ec9b83c9 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None |  |
| q-3dc5f95119 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None |  |
| q-bb008b579b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R_lUAH"} | None |  |
| q-8fa553acbc | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R_lUAH"} | None |  |
| q-de54480985 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1bsxh3C"} | None |  |
| q-cf4653daa0 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1bsxh3C"} | None |  |
| q-0487a4bf64 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1bsxh3C"} | None |  |
| q-da5fc051fa | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YeUuC-"} | None |  |
| q-1b41727b84 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YeUuC-"} | None |  |
| q-513913a5f2 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YeUuC-"} | None |  |
| q-45d8797a6e | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND host.name:\"nashua.dmevals.local\"", "time_from": "2020-05-02T02:54:28+00:00", "time_to": "2020-05-02T03:32:18.030000+00:00", "size": 100, "sub_field": "process.parent.exec… | 61 |  |
| q-2f5f93408e | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11 AND host.name:\"nashua.dmevals.local\"", "time_from": "2020-05-02T02:54:28+00:00", "time_to": "2020-05-02T03:32:18.030000+00:00", "size": 100, "sub_field": "process.executable"} | 249 |  |
| q-108fc069ba | pivot seed | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND host.name:\"nashua.dmevals.local\"", "time_from": "2020-05-02T02:54:28+00:00", "time_to": "2020-05-02T03:32:18.030000+00:00", "size": 100, "sub_field": "process.parent… | 63 |  |
| q-c950d61eab | pivot seed | aggregate | {"dataset": "windows.powershell", "field": "event.code", "query": "host.name:\"nashua.dmevals.local\"", "time_from": "2020-05-02T02:54:28+00:00", "time_to": "2020-05-02T03:32:18.030000+00:00", "size": 100, "sub_field": null} | 192 |  |
| q-cf4581a7f6 | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND host.name:\"newyork.dmevals.local\"", "time_from": "2020-05-02T02:46:43+00:00", "time_to": "2020-05-02T03:24:23+00:00", "size": 100, "sub_field": "process.parent.executable… | 18 |  |
| q-aa45b4e2d0 | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11 AND host.name:\"newyork.dmevals.local\"", "time_from": "2020-05-02T02:46:43+00:00", "time_to": "2020-05-02T03:24:23+00:00", "size": 100, "sub_field": "process.executable"} | 75 |  |
| q-33684303db | pivot seed | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND host.name:\"newyork.dmevals.local\"", "time_from": "2020-05-02T02:46:43+00:00", "time_to": "2020-05-02T03:24:23+00:00", "size": 100, "sub_field": "process.parent.execu… | 18 |  |
| q-53bea05fc7 | pivot seed | aggregate | {"dataset": "windows.powershell", "field": "event.code", "query": "host.name:\"newyork.dmevals.local\"", "time_from": "2020-05-02T02:46:43+00:00", "time_to": "2020-05-02T03:24:23+00:00", "size": 100, "sub_field": null} | 2185 |  |
| q-ed13d7d661 | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND host.name:\"scranton.dmevals.local\"", "time_from": "2020-05-02T02:40:56.157000+00:00", "time_to": "2020-05-02T03:34:10.368000+00:00", "size": 100, "sub_field": "process.pa… | 359 |  |
| q-c7fb5bac55 | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11 AND host.name:\"scranton.dmevals.local\"", "time_from": "2020-05-02T02:40:56.157000+00:00", "time_to": "2020-05-02T03:34:10.368000+00:00", "size": 100, "sub_field": "process.executable… | 1276 |  |
| q-7a6e617521 | pivot seed | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND host.name:\"scranton.dmevals.local\"", "time_from": "2020-05-02T02:40:56.157000+00:00", "time_to": "2020-05-02T03:34:10.368000+00:00", "size": 100, "sub_field": "proce… | 370 |  |
| q-a6a36d095a | pivot seed | aggregate | {"dataset": "windows.powershell", "field": "event.code", "query": "host.name:\"scranton.dmevals.local\"", "time_from": "2020-05-02T02:40:56.157000+00:00", "time_to": "2020-05-02T03:34:10.368000+00:00", "size": 100, "sub_field": null} | 8602 |  |
| q-bb6935e4ce | pivot step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.executable) LIKE \"*\\\\temp\\\\*\" OR TO_LOWER(process.executable) LIKE \"*\\\\programdata\\\\*\" OR TO_LOWER(process.executable) LIKE \"*\\\\u… | ERROR |  |
| q-e64c1f1691 | pivot step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*passw*\" OR TO_LOWER(file.path) LIKE \"*.pfx\" OR TO_LOWER(file.path) LIKE \"*.kirbi\" OR TO_LOWER(file.path) LIKE \"*\\\\temp\\\\*\… | ERROR |  |
| q-2347c82e13 | pivot step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.executable) LIKE \"*\\\\\\\\temp\\\\\\\\*\" OR TO_LOWER(process.executable) LIKE \"*\\\\\\\\programdata\\\\\\\\*\" OR TO_LOWER(process.executabl… | 10 |  |
| q-90b73e1fb2 | pivot step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*passw*\" OR TO_LOWER(file.path) LIKE \"*.pfx\" OR TO_LOWER(file.path) LIKE \"*.kirbi\" OR TO_LOWER(file.path) LIKE \"*\\\\\\\\temp\\… | 262 |  |
| q-b47a470201 | pivot step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(message) LIKE \"*pspasswd*\" OR TO_LOWER(message) LIKE \"*passwordsdb*\" OR TO_LOWER(message) LIKE \"*accesschk*\" OR TO_LOWER(message) LIKE \"*s… | 23 |  |
| q-58482c90cd | pivot step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND host.name == \"scranton.dmevals.local\" AND (TO_LOWER(process.command_line) LIKE \"*pspasswd*\" OR TO_LOWER(process.command_line) LIKE \"*accesschk*\" OR TO_LOWER… | 3 |  |
| q-11d7cca501 | pivot step 4 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R_lkD_"} | None | F62 |
| q-992480f910 | pivot step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND host.name == \"scranton.dmevals.local\" AND (TO_LOWER(process.executable) LIKE \"*pspasswd*\" OR TO_LOWER(process.executable) LIKE \"*accesschk*\" OR TO_LOWER(pro… | 1 |  |
| q-33e4323aa6 | pivot step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE host.name == \"scranton.dmevals.local\" AND (TO_LOWER(file.path) LIKE \"*pspasswd*\" OR TO_LOWER(file.path) LIKE \"*passwordsdb*\" OR TO_LOWER(file.path) LIKE \"*sysinternals*\" OR TO_LO… | 500 |  |
| q-88b6bf4394 | pivot step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND host.name == \"scranton.dmevals.local\" AND (TO_LOWER(process.command_line) LIKE \"*download*\" OR TO_LOWER(process.command_line) LIKE \"*invoke-webrequest*\" OR … | 16 |  |
| q-1eb9d31bec | pivot step 6 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1SIw95-"} | None | F61 |
| q-77b0453cbe | pivot step 6 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R_lkD8"} | None | F62 |
| q-8fcc7621b2 | pivot step 6 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None | F63 |
| q-8c150206f2 | pivot step 7 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE host.name == \"scranton.dmevals.local\" AND (TO_LOWER(process.command_line) LIKE \"*pspasswd*\" OR TO_LOWER(process.command_line) LIKE \"*passwordsdb*\" OR TO_LOWER(process.command_line)… | 256 |  |
| q-5735b03caf | pivot step 7 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(message) LIKE \"*beachcleanup*\" OR TO_LOWER(message) LIKE \"*pspasswd*\" OR TO_LOWER(message) LIKE \"*passwordsdb*\" OR TO_LOWER(message) LIKE \… | 5 | F64 |
| q-77ea38171e | pivot step 8 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE (TO_LOWER(process.command_line) LIKE \"*pspasswd*\" OR TO_LOWER(process.command_line) LIKE \"*passwordsdb*\" OR TO_LOWER(process.command_line) LIKE \"*reg save*\" OR TO_LOWER(process.com… | 3 |  |
| q-dc00671ecf | pivot step 8 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*passwordsdb*\" OR TO_LOWER(file.path) LIKE \"*pspasswd*\" OR TO_LOWER(file.path) LIKE \"*.pfx\" OR TO_LOWER(file.path) LIKE \"*\\\\\… | 459 | F61 |
| q-b1339dca47 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1SIw95-"} | None |  |
| q-96e30d6627 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1SIwt7A"} | None |  |
| q-652fdbde5a | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1SIw95-"} | None |  |
| q-2d477cccdf | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R_lkD8"} | None |  |
| q-a00aba653e | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R_lkD_"} | None |  |
| q-d03f056832 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R_lkD_"} | None |  |
| q-1623d86751 | pivot verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-198e77b9bc | pivot verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-f9ccecdbb4 | pivot verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None |  |
| q-616c0fd12d | pivot verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vTX"} | None |  |
| q-c4a2297424 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-b68fef7b1e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-deff37f80f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k13y"} | None |  |
| q-e9acbe4de2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrM7IJ"} | None |  |
| q-741ef9b1a8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrM7IJ"} | None |  |
| q-09f1c07a11 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NY3HhA"} | None |  |
| q-882cc177d9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NY3HhA"} | None |  |
| q-958128afe6 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RpKsLE"} | None |  |
| q-50f0b53ac3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RpKsLE"} | None |  |
| q-61edac6bae | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NAd3XG"} | None |  |
| q-f53e3847c6 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NW1Kgv"} | None |  |
| q-23b19d98cc | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NW1Kgv"} | None |  |
| q-6eb7ab10fa | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1WpSJN6"} | None |  |
| q-48a7b997b2 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YYOcv1"} | None |  |
| q-7895fe9c0a | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YXONNh"} | None |  |
| q-b9be4a9c82 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YKEhta"} | None |  |
| q-ba2ace073f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NUxiiK"} | None |  |
| q-179c58d01d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1WdFNhN"} | None |  |
| q-3f91fb9fa4 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO74el"} | None |  |
| q-1bddd6a898 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21_Tx"} | None |  |
| q-97f0ded977 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21_R0"} | None |  |
| q-45d6f7daf5 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21_Qp"} | None |  |
| q-01754e9e52 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k13y"} | None |  |
| q-c36e0a560f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-670e58acb0 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None |  |
| q-0c9bc476d3 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b22PTB"} | None |  |
| q-70bb5ddce9 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vTv"} | None |  |
| q-d4c42a7f30 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrM7IJ"} | None |  |
| q-7d06c62902 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrM7IJ"} | None |  |
| q-cbe7271233 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx0y"} | None |  |
| q-7c1616c24e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-21930f1ccb | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None |  |
| q-aa3e9a20fe | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-8c2079557b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-0b09be264f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-654a9552ca | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YcSP2J"} | None |  |
| q-1e5646ea70 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YogQzA"} | None |  |
| q-57c864206e | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YogQzA"} | None |  |
| q-020bd0b1fa | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx1Y"} | None |  |
| q-641bc5c0c3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NY3HhV"} | None |  |
| q-770f017fc1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NDgh5J"} | None |  |
| q-483253d465 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YogQzA"} | None |  |
| q-53256d7f4a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1SIwN6W"} | None |  |
| q-ea421d9435 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-70156a1e1f | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-b46fa8e2bb | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8IdC"} | None |  |
| q-c2fdc62970 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8Idl"} | None |  |
| q-a66d3effe7 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8Ieh"} | None |  |
| q-530083b4e2 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8Ieh"} | None |  |
| q-577218679f | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8Iej"} | None |  |
| q-48ef796fd1 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO74fI"} | None |  |
| q-ef6731e712 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO74fI"} | None |  |
| q-e1610aa440 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8IdC"} | None |  |
| q-66db2e3587 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1Yldc_Q"} | None |  |
| q-204e02d4e6 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1Yldc_Q"} | None |  |
| q-f5c746f2c7 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YjaXZN"} | None |  |
| q-cee16bf1f1 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YjaXZN"} | None |  |
| q-b9b44a77f5 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YhYtY1"} | None |  |
| q-931e0170ec | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrM7IJ"} | None |  |
| q-f745ae7a99 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrM7IJ"} | None |  |
| q-19b1a9529c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrM7IJ"} | None |  |
| q-a9a23f905a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrM7IJ"} | None |  |
| q-ec3b6ef0a5 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1bsxh3J"} | None |  |
| q-e51ae4930b | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1bsxhdc"} | None |  |
| q-6c1e541a7a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RkEAFq"} | None |  |
| q-cc2d1d5cbc | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RkEAFq"} | None |  |
| q-8f6020a364 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RkEAFq"} | None |  |
| q-5ac44418ff | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NAenUm"} | None |  |
| q-49c47d30eb | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NY3HhM"} | None |  |
| q-f063c4f20f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MuaKzP"} | None |  |
| q-42c426db23 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YeU-Dp"} | None |  |
| q-eca1597fbf | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrMLE_"} | None |  |
| q-8adf3ca132 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MsOhX7"} | None |  |
| q-c69013fab2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MsOhX7"} | None |  |
| q-9fb1b16ddd | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1Muar8B"} | None |  |
| q-04ab3c007c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MuaKzP"} | None |  |
| q-40095e6a58 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RkEAFq"} | None |  |
| q-c9aa7fe1c5 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-592b3216ba | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1Nc7emY"} | None |  |
| q-d9d9c370eb | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None |  |
| q-610930afde | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None |  |
| q-3af8b0c8e2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R_lUAH"} | None |  |
| q-1da2f1199f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RsNaXs"} | None |  |
| q-ffdde1875f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R_lkD8"} | None |  |
| q-6daca7b96d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R_lkD_"} | None |  |
| q-29193646e2 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1bh-ZaM"} | None |  |
| q-8d7c5fd1fd | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YTK7vy"} | None |  |
| q-b7b3827609 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YcSCou"} | None |  |
| q-05d0c950d3 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YogQzA"} | None |  |
| q-0c52c439f1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R8i4gn"} | None |  |
| q-a68d8416e8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NY3HhV"} | None |  |
| q-f6847dc652 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R_lkD_"} | None |  |
| q-58cb563c4c | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YldM_p"} | None |  |
| q-daac0e26ad | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YldM_p"} | None |  |
| q-2c70c890ff | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-28115eddf5 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-760e0394e4 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None |  |
| q-6df712c4b7 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vTX"} | None |  |
| q-7acbb831dc | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YjaXaO"} | None |  |
| q-efe3fbf474 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YjaXaO"} | None |  |
| q-f6e244331c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1RrM7IJ"} | None |  |
| q-6fe0324fcc | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1bsxQxS"} | None |  |
| q-cf00ee1df9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1Nc7emR"} | None |  |
| q-469fd1fb23 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1Nc7emR"} | None |  |
| q-898e81e247 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YEBswS"} | None |  |
| q-8a62a45c51 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YGClc_"} | None |  |
| q-1a8ed71145 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-9f3ae97b26 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-575a6ef078 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-89f70bd3b9 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-ed2089969b | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-8e6d04e783 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YsmoMw"} | None |  |
| q-3bbc8e61e3 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YogQzA"} | None |  |
| q-a4f9f94751 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1SFrjaS"} | None |  |
| q-640c2aefb3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NY3HhS"} | None |  |
| q-484ba4c0c7 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1M_d1eR"} | None |  |
| q-ea2bfc3722 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R5ewC0"} | None |  |
| q-c741808d21 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NY3HhQ"} | None |  |
| q-a56e26130e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NKneCu"} | None |  |
| q-997279f132 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NKneCu"} | None |  |
| q-f86a97abd9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NW1Kgv"} | None |  |
| q-50d57026c4 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YDAqy3"} | None |  |
| q-5d4df52b82 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MubN05"} | None |  |
| q-31ffaa1510 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MubN05"} | None |  |
| q-b846bc75a5 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx2W"} | None |  |
| q-db65fe0ba5 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8IeN"} | None |  |
| q-3bf42b3786 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8YcB"} | None |  |
| q-9cf36cc87e | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1bi_UDc"} | None |  |
| q-65f5c4e11d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NNo5A0"} | None |  |
| q-3ea7655002 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NUyf30"} | None |  |
| q-d0f1634478 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx1V"} | None |  |
| q-c0e2ecd3c9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1NY2Xjg"} | None |  |
| q-a38191bca5 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.16-000001", "id": "AaFFktQ25mySA1aO8If9"} | None |  |
| q-b22843d17a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-93f1daef31 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k13y"} | None |  |
| q-d944d12211 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-2cae478edc | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1WiJkSG"} | None |  |
| q-bda7a8c3e8 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b87aMP"} | None |  |
| q-e30c5ac7a1 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YhYtYx"} | None |  |
| q-bb52822ad8 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YhYtYx"} | None |  |
| q-78fa6e6572 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YhYtYx"} | None |  |
| q-93124d3e06 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YjanYM"} | None |  |
| q-2dca3cb219 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YhYtYx"} | None |  |
| q-7ab5c6a21a | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YhYtYx"} | None |  |
| q-80604db529 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YhYtYx"} | None |  |
| q-a42b57e308 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YhYtYx"} | None |  |
| q-8365ed69b8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-beea293aa5 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R-k131"} | None |  |
| q-d9c061b027 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1WdFNhN"} | None |  |
| q-18dd8dafe9 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-a2ff660584 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MsOhX7"} | None |  |
| q-8367663d3e | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b22vQJ"} | None |  |
| q-6eb2ca5126 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1bsx-ky"} | None |  |
| q-c938e9e4b8 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx1E"} | None |  |
| q-3396cda77c | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx1E"} | None |  |
| q-b0349a51df | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx1E"} | None |  |
| q-89e817ce69 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1aOnx1E"} | None |  |
| q-9aa73a1a0c | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YQHwYC"} | None |  |
| q-4a2c9b5e33 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YQHwYC"} | None |  |
| q-3929378580 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YcSCoM"} | None |  |
| q-8d2083d191 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1bsx-kn"} | None |  |
| q-93db419d89 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1MtWeH6"} | None |  |
| q-21f5817d0f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1SDpoh0"} | None |  |
| q-4f7002538d | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None |  |
| q-849dfd4d19 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None |  |
| q-81d343798d | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None |  |
| q-a7a58bf5aa | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R_lUAH"} | None |  |
| q-b28aa52dcd | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R_lUAH"} | None |  |
| q-b25104f1a3 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1bsxh3C"} | None |  |
| q-ce6ed4e7a3 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1bsxh3C"} | None |  |
| q-d86aba30af | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1bsxh3C"} | None |  |
| q-08370deaf7 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YeUuC-"} | None |  |
| q-f48565f8e3 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YeUuC-"} | None |  |
| q-7bf9b1f2fd | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1YeUuC-"} | None |  |
| q-bc041469e5 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1SIw95-"} | None |  |
| q-22554e8634 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1SIwt7A"} | None |  |
| q-476c4fbbf4 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1SIw95-"} | None |  |
| q-d92bf4bb83 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R_lkD8"} | None |  |
| q-f71983c95f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R_lkD_"} | None |  |
| q-b2b4d09391 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.16-000001", "id": "AaFFkNQ25mySA1R_lkD_"} | None |  |
| q-4f6ce3d1d7 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-ff8451c0a2 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b10BXt"} | None |  |
| q-01b40560dc | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vS3"} | None |  |
| q-56d7ef0799 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.16-000001", "id": "AaFFkdQ25mySA1b21vTX"} | None |  |

## Verification

Evidence items cited: 184; confirmed against the stored events: 183; rejected: 1. Each item was re-fetched with get_event; it is confirmed only if the event exists, the cited field holds the cited value, and the cited query_id is a query of this run that returned that event.
Evidence sent back to the agents for correction during the run: 10 item(s) in 5 submission(s) (one correction round each; what still failed was rejected).

## Limitations

- Findings describe what the stored logs show; activity these sources did not log cannot be seen.
- Datasets with non-overlapping time windows (see Data examined) were analysed separately.
- Long field values are shortened in this report; full events are retrievable by _index/_id.
