# Threat hunt report — 20261020-195130-converged-rehearsal-lateral

**Hypothesis:** An adversary who compromised Windows hosts in this network moved laterally from them to other hosts in the network (MITRE ATT&CK tactic: Lateral Movement).

**Verdict: Confirmed** — 5 in-scope incident(s) of verified malicious findings (confidence >= medium): I02 T1021.002 (F01, F15), I04 T1021.006 (F02), I05 T1080 (F08), I06 T1210 (F11, F23), I07 T1570 (F20)

Verdict method: rules over verified evidence (Confirmed if >=1 in-scope incident of verified malicious findings (confidence >= medium); Inconclusive if only suspicious incidents or coverage gaps; Refuted if full coverage and no malicious/suspicious finding)

| Run | Value |
|---|---|
| Profile | converged (thinking=False, temperature=0.0) |
| Model | deepseek-flash |
| Started / finished (UTC) | 2026-10-20T11:51:30+00:00 / 2026-10-20T11:56:44+00:00 (313.6 s) |
| LLM calls / tokens | 82 / {'prompt': 2683063, 'completion': 64827} |
| MCP tool calls | 630 (server tools: list_data_sources, get_fields, search, count, aggregate, timeline, esql, get_event, get_registry) |
| ATT&CK tactics | lateral-movement — An adversary with existing access to compromised Windows hosts is using remote execution or authentication mechanisms to pivot to and gain access on additional hosts in the network. |

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
| I01 | T1021.001 | yes | suspicious/medium | F03 | RDP logon (type 10) to SCRANTON by pbeesly from 172.18.39.2 |
| I02 | T1021.002 | yes | malicious/high | F01, F15 | PsExec SMB/ADMIN$ lateral movement from SCRANTON to NASHUA with cleartext credentials |
| I03 | T1021.002 | yes | suspicious/medium | F22 | pbeesly network logons to NEWYORK and IPC$/samr access from SCRANTON and NASHUA |
| I04 | T1021.006 | yes | malicious/high | F02 | PowerShell remoting (WinRM/5985) from SCRANTON to NASHUA |
| I05 | T1080 | yes | malicious/high | F08 | python.exe written to \\NASHUA\ADMIN$ and executed remotely via PsExec |
| I06 | T1210 | yes | malicious/high | F11, F23 | PSEXESVC remote service execution on NASHUA launching unsigned python.exe |
| I07 | T1570 | yes | malicious/high | F20 | PsExec used from SCRANTON to copy PSEXESVC.exe and python.exe to NASHUA over ADMIN$ |
| I08 | out-of-scope:T1021.002 | no | malicious/high | F07 | Hands-on lateral movement scranton->nashua via PsExec; no software deployment tool used |
| I09 | out-of-scope:T1021.006 | no | malicious/high | F14 | Compromised pbeesly session on SCRANTON used WinRM/PsExec to move to NASHUA and NEWYORK |
| I10 | out-of-scope:T1059.001 | no | malicious/high | F12 | Encoded PowerShell payload (IEX from bitmap pixels) on SCRANTON |

## Findings

### F01 · malicious / high · T1021.002 · PsExec-driven SMB/ADMIN$ lateral movement from SCRANTON to NASHUA with cleartext credentials

Evidence status: **verified**

On 2020-05-01 23:09-23:15 (local), user pbeesly on scranton.dmevals.local ran PsExec64.exe from C:\Program Files\SysinternalsSuite repeatedly against \\NASHUA, passing the account password in cleartext on the command line (-u dmevals\pbeesly -p Fl0nk3rt0n!T0by) to launch C:\Windows\Temp\python.exe interactively (-i 2). The PowerShell script block for the same command was logged on SCRANTON, PsExec64.exe was spawned by powershell.exe on SCRANTON, and on nashua.dmevals.local the PSEXESVC service was installed four times (7045, ImagePath %SystemRoot%\PSEXESVC.exe, AccountName pbeesly) with PSEXESVC.exe spawned by services.exe and then launching C:\Windows\Temp\python.exe as pbeesly. nashua.dmevals.local logged nine 5140 ADMIN$ share accesses by pbeesly from 10.0.1.4 (SCRANTON), and 4648 explicit-credential logons on NASHUA show PSEXESVC.exe using pbeesly's credentials. This is classic PsExec SMB/admin-share lateral movement, preceded on SCRANTON by an Invoke-Exfil PowerShell function and followed by obfuscated in-memory PowerShell (Get-ItemPropertyValue HKLM:\SOFTWARE\Javasoft \| Invoke-Expression).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:18.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | .\PsExec64.exe -accepteula \\NASHUA -u "dmevals\pbeesly" -p "Fl0nk3rt0n!T0by" -i 2 "C:\Windows\Temp\python.exe" | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZJGiSVpshTO3IxM8t | q-b358cfa820 | ok |
| 2 | 2020-05-02 03:11:18.784Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\PsExec64.exe" -accepteula \\NASHUA -u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOtGQk7R | q-cfd0c984dc | ok |
| 3 | 2020-05-02 03:11:39.000Z | nashua.dmevals.local | windows.other | win.ServiceName | PSEXESVC | .ds-logs-windows.other-default-2026.10.20-000001 / AaFZJGiSVpshTO1pngK- | q-71bf189573 | ok |
| 4 | 2020-05-02 03:11:40.213Z | nashua.dmevals.local | windows.sysmon | process.command_line | "C:\Windows\Temp\python.exe"  | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOyESnYY | q-cfd0c984dc | ok |
| 5 | 2020-05-02 03:10:23.000Z | nashua.dmevals.local | windows.security | win.ShareName | \\*\ADMIN$ | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZI2iSVpshTO31Nirr | q-7d2a355018 | ok |
| 6 | 2020-05-02 03:11:40.000Z | nashua.dmevals.local | windows.security | process.executable | C:\Windows\PSEXESVC.exe | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZI2iSVpshTO31NCqL | q-777f24c8a8 | ok |

### F02 · malicious / high · T1021.006 · PowerShell remoting (WinRM/5985) from SCRANTON to NASHUA by pbeesly

Evidence status: **verified**

At 2020-05-01 23:09:23 on scranton.dmevals.local, pbeesly executed an Invoke-Command -ComputerName NASHUA script block that enumerated processes and session IDs on the remote host. Correspondingly, powershell.exe on SCRANTON (10.0.1.4) opened four outbound TCP connections to 10.0.1.6 (NASHUA) on port 5985 between 23:09:23 and 23:09:29, with matching inbound connections recorded on nashua.dmevals.local. This WinRM session immediately precedes the PsExec SMB execution against the same target, showing the actor probing NASHUA over WinRM before pivoting via PsExec. The Zeek capture (separate, non-overlapping window) also shows 10.0.1.4 -> 10.0.1.6:5985 flows with conn_state SF.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:09:23.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | Invoke-Command -ComputerName NASHUA -ScriptBlock { Get-Process -IncludeUserName \| Select-Object UserName,SessionId \| Where-Object { $_.UserName -like "*\$env:… | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZJGiSVpshTO3HwqHA | q-9dbbcd656b | ok |
| 2 | 2020-05-02 03:09:23.801Z | scranton.dmevals.local | windows.sysmon | destination.port | 5985 | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOyETHZ1 | q-88630afd24 | ok |
| 3 | 2020-05-02 03:09:23.881Z | nashua.dmevals.local | windows.sysmon | host.name | nashua.dmevals.local | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOyETHZ2 | q-88630afd24 | ok |
| 4 | 2020-04-30 00:33:26.283Z | bobs.bigwheel.local | zeek | destination.port | 5985 | .ds-logs-zeek-default-2026.10.20-000001 / AaFZJWiSVpshTO2e9KT- | q-0e4e186361 | ok |

### F07 · malicious / high · T1072 · Lateral movement scranton->nashua used PsExec, not a software deployment tool; no SCCM/Intune/WSUS activity observed

Evidence status: **verified**

On 2020-05-02 between 03:09 and 03:15 UTC, user pbeesly on scranton.dmevals.local performed hands-on lateral movement to nashua.dmevals.local. At 03:09:23 a PowerShell 4104 block ran 'Invoke-Command -ComputerName NASHUA' to enumerate processes/sessions, then at 03:10:22 'Invoke-SeaDukeStage -ComputerName NASHUA'. From 03:11:18 to 03:14:42 PsExec64.exe (C:\Program Files\SysinternalsSuite\PsExec64.exe, spawned by powershell.exe) was executed four times with the command line '\\NASHUA -u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe', i.e. plaintext credentials on the command line. Each run produced a 7045 PSEXESVC service install on nashua (23:11:39, 23:12:46, 23:13:49, 23:15:03 local), PSEXESVC.exe execution under SYSTEM, and C:\Windows\Temp\python.exe (SHA256 43782EC4337D8F3DDB7EA0C451B3BC4F212F84C8D5571BD0A842001C859A02AE) running as pbeesly, which unpacked a PyInstaller _MEI29522 directory. Separately on scranton, javamtsup.exe was dropped from C:\Users\pbeesly\Downloads\SysinternalsSuite\ and installed as an auto-start LocalSystem service 'Java(TM) Virtual Machine Support Service' at 23:04:15, then executed at 03:19:14 as an unsigned binary (Signed: false, Company/Description '-') masquerading as a Java component. The movement mechanism is PsExec (T1569.002/T1021.002), not a software deployment tool: no ccmexec/SMS/Intune binaries or SCCM script blocks were found (C052-C054 zero hits), and the only management-port network flows (C055) were generic 10.0.1.4 -> 192.168.0.4/192.168.0.5/10.0.1.6 traffic on 80/443 in a non-overlapping zeek window, with no 8530/8531 WSUS/SCCM traffic.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:18.784Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\PsExec64.exe" -accepteula \\NASHUA -u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOtGQk7R | q-6a1571e518 | ok |
| 2 | 2020-05-02 03:10:22.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | Invoke-SeaDukeStage -ComputerName NASHUA | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZJGiSVpshTO3JxTEc | q-449bbefe24 | ok |
| 3 | 2020-05-02 03:09:23.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | Invoke-Command -ComputerName NASHUA -ScriptBlock { Get-Process -IncludeUserName \| Select-Object UserName,SessionId \| Where-Object { $_.UserName -like "*\$env:… | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZJGiSVpshTO3HwqHA | q-449bbefe24 | ok |
| 4 | 2020-05-02 03:11:39.000Z | nashua.dmevals.local | windows.other | message | A service was installed in the system.    Service Name:  PSEXESVC  Service File Name:  %SystemRoot%\PSEXESVC.exe  Service Type:  user mode service  Service Star… | .ds-logs-windows.other-default-2026.10.20-000001 / AaFZJGiSVpshTO1pngK- | q-9140aed8ee | ok |
| 5 | 2020-05-02 03:11:40.213Z | nashua.dmevals.local | windows.sysmon | process.command_line | "C:\Windows\Temp\python.exe"  | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOyESnYY | q-6a1571e518 | ok |
| 6 | 2020-05-02 03:11:40.284Z | nashua.dmevals.local | windows.sysmon | win.Hashes | SHA1=585EB59D12A111E9291518C5CF5D3FD296C2B581,MD5=57292CE8714E2D221D9D97C9D061D332,SHA256=43782EC4337D8F3DDB7EA0C451B3BC4F212F84C8D5571BD0A842001C859A02AE,IMPHA… | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOyESXbs | q-a92235fd6e | ok |
| 7 | 2020-05-02 03:04:15.000Z | scranton.dmevals.local | windows.other | message | A service was installed in the system.    Service Name:  Java(TM) Virtual Machine Support Service  Service File Name:  C:\Windows\System32\javamtsup.exe  Servic… | .ds-logs-windows.other-default-2026.10.20-000001 / AaFZJGiSVpshTO1pngIR | q-cc8f0fa5ba | ok |
| 8 | 2020-05-02 03:19:14.134Z | scranton.dmevals.local | windows.sysmon | win.Signed | false | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOou0mUT | q-b287861b8e | ok |
| 9 | 2020-05-02 03:00:32.751Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Users\pbeesly\Downloads\SysinternalsSuite\javamtsup.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOtk0ckj | q-a92235fd6e | ok |
| 10 | 2020-04-30 00:32:18.094Z | simplerockbuild.simplerock.lan | zeek | destination.port | 80 | .ds-logs-zeek-default-2026.10.20-000001 / AaFZJWiSVpshTO037K8M | q-fbe8455f17 | ok |

### F08 · malicious / high · T1080 · pbeesly wrote python.exe to \\NASHUA\ADMIN$ (C:\Windows\Temp) from SCRANTON and executed it remotely via PsExec

Evidence status: **verified**

On 2020-05-02 at 03:10:23 UTC, user DMEVALS\pbeesly (logon 0x861A79) from source IP 10.0.1.4 (scranton.dmevals.local) accessed the ADMIN$ share on nashua.dmevals.local (share path \\??\C:\windows) with RelativeTargetName 'Temp\python.exe' and AccessMask 0x2 = 'WriteData (or AddFile)' — i.e. content was written into a share that another host then executed. The same session also opened \\*\ADMIN$ root and \\*\IPC$ on nashua, and ADMIN$ sessions from 10.0.1.4 recur at 03:11:18, 03:12:01, 03:12:25, 03:13:08, 03:13:28, 03:14:10, 03:14:42 and 03:18:20. Immediately after, scranton ran PsExec64.exe with the command line targeting \\NASHUA with the plaintext password for dmevals\pbeesly and the payload C:\Windows\Temp\python.exe (03:11:18, 03:12:25, 03:13:28, 03:14:42), and nashua spawned C:\Windows\Temp\python.exe with parent C:\Windows\PSEXESVC.exe at 03:11:40, 03:12:46, 03:13:49 and 03:15:03, plus a child python.exe at 03:15:04. The share write therefore tainted content that was executed on the remote host — T1080 in service of lateral movement. The same actor context on scranton also ran an Invoke-Exfil script block (7-Zip archive of the user's Downloads to $env:APPDATA\OfficeSupplies.7z) and a registry-based Invoke-Expression / reflective loader, indicating a compromised host staging tooling. Benign explanations were excluded for the other share hits: SYSVOL/IPC$ 5145 and 5140 activity is machine-account (SCRANTON$, NASHUA$, NEWYORK$, UTICA$, WEC$) GroupPolicy and SMB session traffic, the GPO DataStore file creations are the local GroupPolicy client cache written by svchost.exe, the zeek smb_files records are only SMB::FILE_OPEN reads of \\NEWYORK.dmevals.local\sysvol, and the Temp/ProgramData file creations are PowerShell policy-test files, csc.exe/cvtres.exe compilation artifacts and WerFault crash dumps.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:10:23.000Z | nashua.dmevals.local | windows.security | win.AccessMask | 0x2 | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZI2iSVpshTO31NyoI | q-d8d4d60795 | ok |
| 2 | 2020-05-02 03:10:23.000Z | nashua.dmevals.local | windows.security | win.RelativeTargetName | Temp\python.exe | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZI2iSVpshTO31NyoI | q-d8d4d60795 | ok |
| 3 | 2020-05-02 03:10:23.000Z | nashua.dmevals.local | windows.security | win.ShareName | \\*\ADMIN$ | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZI2iSVpshTO31NyoI | q-d8d4d60795 | ok |
| 4 | 2020-05-02 03:10:23.000Z | nashua.dmevals.local | windows.security | win.IpAddress | 10.0.1.4 | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZI2iSVpshTO31NyoI | q-d8d4d60795 | ok |
| 5 | 2020-05-02 03:10:23.000Z | nashua.dmevals.local | windows.security | win.AccessMask | 0x17019f | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZI2iSVpshTO31NyoH | q-7e14dcfeae | ok |
| 6 | 2020-05-02 03:10:23.000Z | nashua.dmevals.local | windows.security | win.ShareName | \\*\ADMIN$ | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZI2iSVpshTO31Nirr | q-29519f4dbf | ok |
| 7 | 2020-05-02 03:11:18.784Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\PsExec64.exe" -accepteula \\NASHUA -u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOtGQk7R | q-058a17c207 | ok |
| 8 | 2020-05-02 03:11:40.213Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOyESnYY | q-058a17c207 | ok |
| 9 | 2020-05-02 03:11:40.213Z | nashua.dmevals.local | windows.sysmon | process.parent.executable | C:\Windows\PSEXESVC.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOyESnYY | q-058a17c207 | ok |
| 10 | 2020-05-02 03:11:18.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | .\PsExec64.exe -accepteula \\NASHUA -u "dmevals\pbeesly" -p "Fl0nk3rt0n!T0by" -i 2 "C:\Windows\Temp\python.exe" | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZJGiSVpshTO3IxM8t | q-f5181e2713 | ok |
| 11 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZJGiSVpshTO3AvzkC | q-f5181e2713 | ok |

### F11 · malicious / high · T1210 · PsExec-style remote service execution on nashua.dmevals.local (PSEXESVC) launching an unsigned python.exe from C:\Windows\Temp

Evidence status: **verified**

On 2020-05-02 between 03:11:39 and 03:15:03 UTC, four PSEXESVC services were installed on nashua.dmevals.local by user pbeesly (event 7045, Service File Name %SystemRoot%\PSEXESVC.exe, LocalSystem, demand start). Each service start spawned C:\Windows\Temp\python.exe (Sysmon event 1, parent PSEXESVC, user DMEVALS\pbeesly, no FileVersion/Description/Company/OriginalFileName) at 03:11:40, 03:12:46, 03:13:49 and 03:15:03. The python.exe process then made repeated outbound TCP connections from 10.0.1.6 to 192.168.0.4:8443 (e.g. 03:15:05). This is remote service abuse (SMB service creation) used to execute an attacker-supplied binary on a remote host, i.e. exploitation/abuse of a remote service for lateral movement. The same pbeesly account also performed network (type 3) logons to nashua.dmevals.local from 10.0.1.4 and to newyork.dmevals.local from 10.0.1.4, and an RDP (type 10) logon to scranton.dmevals.local from 172.18.39.2 at 03:20:46 UTC, consistent with a compromised account being used to move across hosts.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:39.000Z | nashua.dmevals.local | windows.other | message | A service was installed in the system.    Service Name:  PSEXESVC  Service File Name:  %SystemRoot%\PSEXESVC.exe  Service Type:  user mode service  Service Star… | .ds-logs-windows.other-default-2026.10.20-000001 / AaFZJGiSVpshTO1pngK- | q-48321aad2f | ok |
| 2 | 2020-05-02 03:11:39.000Z | nashua.dmevals.local | windows.other | process.executable | %SystemRoot%\PSEXESVC.exe | .ds-logs-windows.other-default-2026.10.20-000001 / AaFZJGiSVpshTO1pngK- | q-48321aad2f | ok |
| 3 | 2020-05-02 03:11:40.213Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOyESnYY | q-733c56f505 | ok |
| 4 | 2020-05-02 03:11:40.213Z | nashua.dmevals.local | windows.sysmon | process.command_line | "C:\Windows\Temp\python.exe"  | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOyESnYY | q-733c56f505 | ok |
| 5 | 2020-05-02 03:15:05.142Z | nashua.dmevals.local | windows.sysmon | destination.ip | 192.168.0.4 | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOyCQ37P | q-de1dce8241 | ok |
| 6 | 2020-05-02 03:15:05.142Z | nashua.dmevals.local | windows.sysmon | destination.port | 8443 | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOyCQ37P | q-de1dce8241 | ok |
| 7 | 2020-05-02 03:20:46.000Z | scranton.dmevals.local | windows.security | win.LogonType | 10 | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZJGiSVpshTO0Gh1d1 | q-d6c89dc5fa | ok |
| 8 | 2020-05-02 03:20:46.000Z | scranton.dmevals.local | windows.security | source.ip | 172.18.39.2 | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZJGiSVpshTO0Gh1d1 | q-d6c89dc5fa | ok |

### F12 · malicious / high · T1210 · Encoded PowerShell payload (IEX from bitmap pixels) executed as pbeesly on scranton.dmevals.local

Evidence status: **verified**

At 2020-05-01T22:58:45-04:00 (2020-05-02T02:58:45Z) on scranton.dmevals.local, PowerShell event 4104 recorded a script block run as DMEVALS\pbeesly that loads C:\Users\pbeesly\Downloads\monkey.png as a System.Drawing.Bitmap, extracts bytes from the first 7 pixel rows and executes the decoded buffer with IEX. This is a steganographic/encoded loader, the post-exploitation payload stage that follows the remote-service execution chain; it is not normal administrative PowerShell.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:58:45.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | sal a New-Object;Add-Type -AssemblyName 'System.Drawing'; $g=a System.Drawing.Bitmap('C:\Users\pbeesly\Downloads\monkey.png');$o=a Byte[] 4480;for($i=0; $i -le … | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZJGiSVpshTO3V55ui | q-d559ed1872 | ok |
| 2 | 2020-05-02 02:58:45.000Z | scranton.dmevals.local | windows.powershell | user.name | pbeesly | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZJGiSVpshTO3V55ui | q-d559ed1872 | ok |

### F23 · malicious / high · T1210 · Repeated PSEXESVC service execution on NASHUA launching C:\Windows\Temp\python.exe as pbeesly

Evidence status: **verified**

SCRANTON's PsExec64.exe (run by powershell.exe as pbeesly) installed the PSEXESVC service on nashua.dmevals.local four times (03:11:39, 03:12:46, 03:13:49, 03:15:03) and each time launched C:\Windows\Temp\python.exe as pbeesly; the binary had been written to \\NASHUA\ADMIN$\Temp\python.exe from 10.0.1.4 at 03:10:23. The python payload then spawned powershell.exe, Rar.exe and sdelete64.exe on NASHUA.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:18.784Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\PsExec64.exe" -accepteula \\NASHUA -u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOtGQk7R | q-475ab78b8f | ok |
| 2 | 2020-05-02 03:11:40.213Z | nashua.dmevals.local | windows.sysmon | process.command_line | "C:\Windows\Temp\python.exe"  | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOyESnYY | q-5d1dd17a88 | ok |
| 3 | 2020-05-02 03:11:39.000Z | nashua.dmevals.local | windows.other | win.ServiceName | PSEXESVC | .ds-logs-windows.other-default-2026.10.20-000001 / AaFZJGiSVpshTO1pngK- | q-f61f572fe9 | ok |
| 4 | 2020-05-02 03:10:23.000Z | nashua.dmevals.local | windows.security | win.RelativeTargetName | Temp\python.exe | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZI2iSVpshTO31NyoH | q-ee3df1d058 | ok |

### F14 · malicious / high · T1534 · Compromised pbeesly session on SCRANTON used WinRM/PsExec to move to NASHUA and NEWYORK

Evidence status: **verified**

On 2020-05-02 the pbeesly account on scranton.dmevals.local was compromised via a malicious screen-saver (C:\ProgramData\victim\cod.3aka3.scr launched from explorer.exe at 02:55:56), which spawned cmd.exe -> powershell.exe, an sdclt.exe/control.exe UAC bypass, and a hidden PowerShell stager that decoded a payload from C:\Users\pbeesly\Downloads\monkey.png via IEX. From that foothold the attacker moved laterally: at 03:09:23 and 03:09:27 scranton's powershell.exe running as DMEVALS\pbeesly initiated TCP connections from 10.0.1.4 to 10.0.1.6:5985 (WinRM), and nashua.dmevals.local logged pbeesly network logons (4624 type 3, Kerberos) at the same seconds. On nashua, pbeesly then ran interactive PowerShell (Get-Process -IncludeUserName, cd C:\Windows\Temp, .\Rar.exe a -hpfGzq5yKw ...working.zip) and four PSEXESVC service installs (7045, %SystemRoot%\PSEXESVC.exe, LocalSystem) at 03:11:39, 03:12:46, 03:13:49 and 03:15:03. pbeesly also authenticated to newyork.dmevals.local (4624 type 3 from 10.0.1.4/10.0.1.6) between 03:04 and 03:20. The internal delivery of the malicious .scr into the victim's session and the subsequent use of that session to reach other hosts is consistent with internal spearphishing leading to lateral movement.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:55:56.157Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\ProgramData\victim\â€®cod.3aka3.scr | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOx-Nf0f | q-913e1118a4 | ok |
| 2 | 2020-05-02 02:55:56.157Z | scranton.dmevals.local | windows.sysmon | process.parent.executable | C:\Windows\explorer.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOx-Nf0f | q-913e1118a4 | ok |
| 3 | 2020-05-02 02:58:44.325Z | scranton.dmevals.local | windows.sysmon | process.command_line | "PowerShell.exe" -noni -noexit -ep bypass -window hidden -c "sal a New-Object;Add-Type -AssemblyName 'System.Drawing'; $g=a System.Drawing.Bitmap('C:\Users\pbee… | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOx6IsLb | q-913e1118a4 | ok |
| 4 | 2020-05-02 03:09:23.801Z | scranton.dmevals.local | windows.sysmon | win.Message | Network connection detected:  RuleName: -  UtcTime: 2020-05-02 03:09:23.801  ProcessGuid: {47ab858c-e374-5eac-d803-000000000400}  ProcessId: 3852  Image: C:\Win… | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOyETHZ1 | q-9d9237fae1 | ok |
| 5 | 2020-05-02 03:09:23.000Z | nashua.dmevals.local | windows.security | win.IpAddress | - | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZI2iSVpshTO32OAa5 | q-7c9757769f | ok |
| 6 | 2020-05-02 03:09:23.000Z | nashua.dmevals.local | windows.security | win.TargetUserName | pbeesly | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZI2iSVpshTO32OAa5 | q-7c9757769f | ok |
| 7 | 2020-05-02 03:11:39.000Z | nashua.dmevals.local | windows.other | win.ServiceName | PSEXESVC | .ds-logs-windows.other-default-2026.10.20-000001 / AaFZJGiSVpshTO1pngK- | q-93dc88af6d | ok |
| 8 | 2020-05-02 03:15:03.000Z | nashua.dmevals.local | windows.other | message | A service was installed in the system.    Service Name:  PSEXESVC  Service File Name:  %SystemRoot%\PSEXESVC.exe  Service Type:  user mode service  Service Star… | .ds-logs-windows.other-default-2026.10.20-000001 / AaFZJGiSVpshTO1pngJ4 | q-93dc88af6d | ok |
| 9 | 2020-05-02 03:16:19.000Z | nashua.dmevals.local | windows.powershell | win.ScriptBlockText | .\Rar.exe a -hpfGzq5yKw "$env:USERPROFILE\Desktop\working.zip" "$env:APPDATA\working.zip" | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZJGiSVpshTO3IwxnV | q-3b89ff52a7 | ok |
| 10 | 2020-05-02 03:05:53.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-ScreenCapture # https://www.pdq.com/blog/capturing-screenshots-with-powershell-and-net/ {     Start-Job -Name "Screenshot" -ScriptBlock {       … | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZJGiSVpshTO3Pzp3U | q-3d58c48516 | ok |

### F15 · malicious / high · T1550 · PsExec-driven lateral movement from SCRANTON to NASHUA using explicit pbeesly credentials

Evidence status: **verified**

On 2020-05-02 between 03:11:18Z and 03:15:03Z, on scranton.dmevals.local, a powershell.exe parent spawned C:\Program Files\SysinternalsSuite\PsExec64.exe five times with the command line targeting \\NASHUA and supplying explicit credentials (-u dmevals\pbeesly -p Fl0nk3rt0n!T0by) to launch C:\Windows\Temp\python.exe interactively. Each launch produced a 4648 explicit-credential logon on SCRANTON with Target Server Name NASHUA / cifs/NASHUA over port 445, and on nashua.dmevals.local a PSEXESVC service install (7045), a PSEXESVC.exe process, a 4648 from C:\Windows\PSEXESVC.exe, and a C:\Windows\Temp\python.exe child of PSEXESVC.exe running as DMEVALS\pbeesly. This is attacker-driven lateral movement using supplied credentials rather than alternate authentication material.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:18.784Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\PsExec64.exe" -accepteula \\NASHUA -u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOtGQk7R | q-8d59328df4 | ok |
| 2 | 2020-05-02 03:11:18.000Z | scranton.dmevals.local | windows.security | win.TargetServerName | NASHUA | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZI2iSVpshTO31NSq9 | q-2f730899e6 | ok |
| 3 | 2020-05-02 03:11:39.000Z | nashua.dmevals.local | windows.other | win.ServiceName | PSEXESVC | .ds-logs-windows.other-default-2026.10.20-000001 / AaFZJGiSVpshTO1pngK- | q-5a91e6b188 | ok |
| 4 | 2020-05-02 03:11:40.000Z | nashua.dmevals.local | windows.security | win.ProcessName | C:\Windows\PSEXESVC.exe | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZI2iSVpshTO31NCqL | q-ecb155823f | ok |
| 5 | 2020-05-02 03:11:40.213Z | nashua.dmevals.local | windows.sysmon | process.parent.executable | C:\Windows\PSEXESVC.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOyESnYY | q-6fcc3b9451 | ok |

### F20 · malicious / high · T1570 · PsExec used from SCRANTON to copy PSEXESVC.exe and python.exe to NASHUA over ADMIN$

Evidence status: **verified**

On 2020-05-02 between 03:10 and 03:18 UTC, user DMEVALS\pbeesly on scranton.dmevals.local (10.0.1.4) repeatedly launched C:\Program Files\SysinternalsSuite\PsExec64.exe from a PowerShell parent with the command line "PsExec64.exe" -accepteula \\NASHUA -u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe (four executions: 03:11:18, 03:12:25, 03:13:28, 03:14:42). The tool transfer is visible on the target: C:\Windows\Temp\python.exe was created on nashua.dmevals.local at 03:10:23 by the System process (SMB write), and Security 5145 events on NASHUA show pbeesly from source 10.0.1.4 writing PSEXESVC.exe to the ADMIN$ share (\\*\ADMIN$, Share Path \\??\C:\windows) with WriteData/AppendData access at 03:13:28 and 03:14:42, plus svcctl and PSEXESVC-SCRANTON-<pid>-stdin/stdout/stderr named-pipe access on IPC$. Each round trip produced a PSEXESVC service install (7045) on NASHUA and a C:\Windows\PSEXESVC.exe file creation, followed by C:\Windows\Temp\python.exe executing as pbeesly with parent C:\Windows\PSEXESVC.exe (03:11:40, 03:12:46, 03:13:49, 03:15:03). The transferred python.exe is a PyInstaller bundle (extracts _MEI29522 with _socket.pyd, _ssl.pyd, _hashlib.pyd at 03:15:04), i.e. a portable tool staged and executed remotely. This is a textbook lateral tool transfer: binaries copied to the remote host's ADMIN$ share and executed via a service. The plaintext password in the command line and the repeated re-copying indicate hands-on-keyboard adversary activity, not administration.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:18.784Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\PsExec64.exe" -accepteula \\NASHUA -u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOtGQk7R | q-40e9a6a695 | ok |
| 2 | 2020-05-02 03:10:23.626Z | nashua.dmevals.local | windows.sysmon | win.TargetFilename | C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOtHRU4I | q-2021e2eaa1 | ok |
| 3 | 2020-05-02 03:14:42.000Z | nashua.dmevals.local | windows.security | win.RelativeTargetName | PSEXESVC.exe | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZI2iSVpshTO30MFg4 | q-bce1fa5413 | ok |
| 4 | 2020-05-02 03:14:42.000Z | nashua.dmevals.local | windows.security | win.ShareName | \\*\ADMIN$ | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZI2iSVpshTO30MFg4 | q-bce1fa5413 | ok |
| 5 | 2020-05-02 03:11:39.000Z | nashua.dmevals.local | windows.other | win.ImagePath | %SystemRoot%\PSEXESVC.exe | .ds-logs-windows.other-default-2026.10.20-000001 / AaFZJGiSVpshTO1pngK- | q-9aee79e2ce | ok |
| 6 | 2020-05-02 03:11:40.213Z | nashua.dmevals.local | windows.sysmon | process.parent.executable | C:\Windows\PSEXESVC.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOyESnYY | q-9907a0be86 | ok |
| 7 | 2020-05-02 03:15:04.135Z | nashua.dmevals.local | windows.sysmon | win.TargetFilename | C:\Users\pbeesly\AppData\Local\Temp\_MEI29522 | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOyGVVIU | q-77f71f449d | ok |

### F03 · suspicious / medium · T1021.001 · RDP logon (type 10) to SCRANTON by pbeesly from 172.18.39.2

Evidence status: **verified**

Two 4624 logon type 10 events for pbeesly were recorded on scranton.dmevals.local at 2020-05-01 23:20:46 from source address 172.18.39.2 (LogonProcessName User32, Negotiate, WorkstationName SCRANTON), accompanied by a 4648 explicit-credential logon for pbeesly from the same address via svchost.exe targeting localhost. This is the only RDP logon in the dataset and it occurs after the PsExec/WinRM activity, consistent with the actor re-entering SCRANTON interactively. However, the source 172.18.39.2 is not one of the internal 10.0.x hosts and the workstation name matches the target itself, so it may be a local/console-equivalent session rather than a true east-west RDP pivot; no mstsc.exe execution or outbound 3389 connection from a compromised host was observed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:20:46.000Z | scranton.dmevals.local | windows.security | win.LogonType | 10 | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZJGiSVpshTO0Gh1d1 | q-191b9eedad | ok |
| 2 | 2020-05-02 03:20:46.000Z | scranton.dmevals.local | windows.security | win.IpAddress | 172.18.39.2 | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZJGiSVpshTO0Gh1d1 | q-191b9eedad | ok |
| 3 | 2020-05-02 03:20:46.000Z | scranton.dmevals.local | windows.security | win.TargetServerName | localhost | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZI2iSVpshTO3mCUhV | q-da5027889c | ok |
| 4 | 2020-05-02 03:20:46.000Z | scranton.dmevals.local | windows.security | win.LogonProcessName | User32  | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZJGiSVpshTO0Gh1d1 | q-191b9eedad | ok |

### F22 · suspicious / medium · T1021.002 · pbeesly network logons to NEWYORK (10.0.1.4 and 10.0.1.6) and IPC$/samr access from SCRANTON and NASHUA

Evidence status: **verified**

Beyond the anchored SCRANTON->NASHUA PsExec, pbeesly authenticated over the network (logon type 3, Kerberos) to newyork.dmevals.local from 10.0.1.4 (SCRANTON) at 03:04:04, 03:09:04 and 03:20:46 and from 10.0.1.6 (NASHUA) at 03:14:20, and NEWYORK logged \\*\IPC$ access with RelativeTargetName 'samr' from 10.0.1.4 at 03:04:04. No process execution, service install or file drop was observed on NEWYORK in the window, so this is remote SMB/RPC access by the compromised account rather than confirmed code execution.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:04.000Z | newyork.dmevals.local | windows.security | win.IpAddress | 10.0.1.4 | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZI2iSVpshTO39XK4V | q-7d2c09a5aa | ok |
| 2 | 2020-05-02 03:14:20.000Z | newyork.dmevals.local | windows.security | win.IpAddress | 10.0.1.6 | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZI2iSVpshTO30MVh9 | q-7d2c09a5aa | ok |
| 3 | 2020-05-02 03:04:04.000Z | newyork.dmevals.local | windows.security | win.RelativeTargetName | samr | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZI2iSVpshTO39XK4x | q-ee3df1d058 | ok |
| 4 | 2020-05-02 03:09:04.000Z | newyork.dmevals.local | windows.security | win.TargetUserName | pbeesly | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZI2iSVpshTO32OQZ1 | q-7d2c09a5aa | ok |

### F04 · benign / medium · T1021.003 · No DCOM remote-activation evidence; RPC/COM activity is baseline

Evidence status: **verified**

No DCOM lateral movement was found. The 10016 events on scranton.dmevals.local are routine COM permission failures (Windows.SecurityCenter.WscDataProtection for SYSTEM, and a ShellExperienceHost CLSID for pbeesly) from LocalHost via LRPC, not remote activation. dllhost.exe/rundll32.exe executions and ole32/combase/rpcrt4 image loads are ordinary Windows COM/RPC baseline, and no MMC20.Application, ShellBrowserWindow or DCOM script blocks were observed. Port 135/445 connections are the same SMB/RPC baseline traffic seen across the estate.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:21:16.000Z | scranton.dmevals.local | windows.other | event.code | 10016 | .ds-logs-windows.other-default-2026.10.20-000001 / AaFZJGiSVpshTO1pngJg | q-b403cde877 | ok |
| 2 | 2020-05-02 03:23:08.000Z | scranton.dmevals.local | windows.other | message | The machine-default permission settings do not grant Local Activation permission for the COM Server application with CLSID   {C2F03A33-21F5-47FA-B4BB-156362A2F2… | .ds-logs-windows.other-default-2026.10.20-000001 / AaFZJGiSVpshTO1pngJA | q-b403cde877 | ok |

### F05 · benign / high · T1021.004 · No SSH lateral movement observed

Evidence status: **verified**

No SSH activity was found in any dataset: no ssh.exe/plink/putty process creations, no outbound connections to port 22 in Sysmon or Zeek, and no SSH-related PowerShell script blocks. The network logon (type 3) events present are SMB/Kerberos machine-account authentication, not SSH-tunneled access.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:20:46.000Z | scranton.dmevals.local | windows.security | win.LogonType | 10 | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZJGiSVpshTO0Gh1d1 | q-191b9eedad | ok |
| 2 | 2020-05-02 03:20:46.000Z | scranton.dmevals.local | windows.security | win.AuthenticationPackageName | Negotiate | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZJGiSVpshTO0Gh1d1 | q-191b9eedad | ok |

### F06 · benign / high · T1021.005 · No VNC activity observed

Evidence status: **verified**

No VNC usage was detected: no vnc/tvnserver/winvnc process executions, no connections to port 5900 in Sysmon or Zeek, and no VNC-related PowerShell script blocks. Remote graphical access in this window was limited to the single RDP logon on SCRANTON.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:20:46.000Z | scranton.dmevals.local | windows.security | win.LogonProcessName | User32  | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZJGiSVpshTO0Gh1d1 | q-191b9eedad | ok |
| 2 | 2020-05-02 03:20:46.000Z | scranton.dmevals.local | windows.security | win.LogonType | 10 | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZJGiSVpshTO0Gh1d1 | q-191b9eedad | ok |

### F09 · benign / high · T1080 · SYSVOL/IPC$ share access and GPO DataStore writes are routine machine-account and GroupPolicy activity

Evidence status: **verified**

The bulk of the T1080 check hits are normal domain behaviour. All 5145 SYSVOL and IPC$ records on newyork.dmevals.local are made by machine accounts (NEWYORK$, SCRANTON$, NASHUA$, UTICA$, WEC$) reading dmevals.local\Policies\{31B2F340-...}\gpt.ini and GptTmpl.inf, and the 5140 sessions are the same machine accounts plus pbeesly's IPC$ session. The corresponding file creations under C:\Windows\System32\GroupPolicy\DataStore\0\sysvol are written by svchost.exe (the GroupPolicy client cache) on scranton and nashua, not by an attacker. In the zeek window (2020-04-30, non-overlapping with the Windows logs) the 12 smb_files records are all SMB::FILE_OPEN reads of \\NEWYORK.dmevals.local\sysvol from 10.0.1.4 and 10.0.1.6 — reads, not writes, so no shared content was tainted there. The Temp/ProgramData file creations are PowerShell __PSScriptPolicyTest_* files, csc.exe/cvtres.exe compilation artifacts under the pbeesly profile, and WerFault crash dumps on nashua. The windows.other event.code 11 hits are 'Miniport NIC ... restarted' messages, not file creates.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:01:43.000Z | newyork.dmevals.local | windows.security | win.SubjectUserName | SCRANTON$ | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZI2iSVpshTO3_ZDTc | q-28867b98c5 | ok |
| 2 | 2020-05-02 03:01:43.000Z | newyork.dmevals.local | windows.security | win.RelativeTargetName | dmevals.local\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\gpt.ini | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZI2iSVpshTO3_ZDTc | q-28867b98c5 | ok |
| 3 | 2020-05-02 02:56:47.000Z | newyork.dmevals.local | windows.security | win.ShareLocalPath | \??\F:\SYSVOL\sysvol | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZJGiSVpshTO0EfrKJ | q-29519f4dbf | ok |
| 4 | 2020-05-02 03:01:43.091Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\svchost.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOtfu-5W | q-3147fb4ed9 | ok |
| 5 | 2020-05-02 03:01:43.091Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Windows\System32\GroupPolicy\DataStore\0\sysvol\dmevals.local\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.in… | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOtfu-5W | q-3147fb4ed9 | ok |
| 6 | 2020-04-30 00:12:01.659Z | simplerockbuild.simplerock.lan | zeek | zeek.action | SMB::FILE_OPEN | .ds-logs-zeek-default-2026.10.20-000001 / AaFZJWiSVpshTO03669U | q-6f5bfe0f19 | ok |
| 7 | 2020-04-30 00:12:01.659Z | simplerockbuild.simplerock.lan | zeek | zeek.path | \\NEWYORK.dmevals.local\sysvol | .ds-logs-zeek-default-2026.10.20-000001 / AaFZJWiSVpshTO03669U | q-6f5bfe0f19 | ok |
| 8 | 2020-05-02 02:58:45.292Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Users\pbeesly\AppData\Local\Temp\qkbkqqbs\qkbkqqbs.dll | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOx5IMzh | q-5e4334dd1d | ok |
| 9 | 2020-05-02 03:02:46.000Z | scranton.dmevals.local | windows.other | message | Miniport NIC 'Microsoft Hyper-V Network Adapter' restarted | .ds-logs-windows.other-default-2026.10.20-000001 / AaFZJGiSVpshTO1pngIU | q-db28961a0e | ok |

### F10 · benign / high · T1091 · No removable-media replication observed; drive-letter and USB-related hits are OS/DFS artifacts

Evidence status: **verified**

Hunting for T1091 (Replication Through Removable Media) across windows.sysmon, windows.security, windows.powershell and windows.other (2020-05-02 02:55–03:28Z, hosts scranton/newyork/nashua/utica.dmevals.local) produced no evidence of removable-media staging or execution. The only non-C: file writes were DFSR replication metadata on newyork.dmevals.local (F:\System Volume Information\DFSR\Config\*.XML.TMP written by C:\windows\system32\DFSRs.exe, recurring ~every 5 minutes) and a D:\pagefile.sys write by smss.exe on scranton.dmevals.local — both normal OS behaviour, not removable media. No process executed from a removable drive, no USBSTOR/removable-device registry artifacts, and no autorun.inf creation were found. The 'autorun' file hits were Sysinternals Autoruns binaries extracted to C:\Users\pbeesly\Downloads\SysinternalsSuite\ by powershell.exe on scranton.dmevals.local, i.e. tooling download, not media-based replication. The MountPoints2 registry writes on scranton.dmevals.local were made by C:\windows\Explorer.EXE (SYSTEM) for volume bookkeeping. The 8 windows.other hits (event.code 2004/2006) were Windows Defender Firewall rule add/delete churn by svchost.exe for 'Usermode Font Driver Host' and 'WARP_JIT_*' rules — unrelated to removable media. Separately noted (outside T1091): the same scranton host shows PsExec64.exe with plaintext credentials targeting \\NASHUA and PSEXESVC service installs on nashua.dmevals.local, which is network-based lateral movement, not removable-media replication.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:56:48.208Z | newyork.dmevals.local | windows.sysmon | file.path | F:\System Volume Information\DFSR\Config\Volume_6936845B-3943-400C-B266-FE6A00502C0C.XML.TMP | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOx9LTM_ | q-e9b98fdb0e | ok |
| 2 | 2020-05-02 02:56:48.208Z | newyork.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\DFSRs.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOx9LTM_ | q-e9b98fdb0e | ok |
| 3 | 2020-05-02 03:19:09.192Z | scranton.dmevals.local | windows.sysmon | file.path | D:\pagefile.sys | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOow2-WM | q-e9b98fdb0e | ok |
| 4 | 2020-05-02 03:19:09.192Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\System32\smss.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOow2-WM | q-e9b98fdb0e | ok |
| 5 | 2020-05-02 03:00:33.189Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Users\pbeesly\Downloads\SysinternalsSuite\autorunsc64.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOtk0ckI | q-7d40b00256 | ok |
| 6 | 2020-05-02 03:20:52.393Z | scranton.dmevals.local | windows.sysmon | registry.path | HKU\S-1-5-21-1830255721-3727074217-2423397540-1107\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2\CPC\Volume | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOoQYU2W | q-6c98a8ee62 | ok |
| 7 | 2020-05-02 03:20:52.393Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\Explorer.EXE | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOoQYU2W | q-6c98a8ee62 | ok |
| 8 | 2020-05-02 03:21:05.000Z | scranton.dmevals.local | windows.other | win.RuleName | WARP_JIT_db4a1097-b484-4973-bbf2-a04208ecd4d4 | .ds-logs-windows.other-default-2026.10.20-000001 / AaFZJGiSVpshTO1pngJa | q-fa30b45ae6 | ok |
| 9 | 2020-05-02 03:20:43.000Z | scranton.dmevals.local | windows.other | win.RuleName | Usermode Font Driver Host | .ds-logs-windows.other-default-2026.10.20-000001 / AaFZJGiSVpshTO1pngI- | q-fa30b45ae6 | ok |
| 10 | 2020-05-02 03:13:28.297Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\PsExec64.exe" -accepteula \\NASHUA -u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOyDSG5g | q-92fd099656 | ok |
| 11 | 2020-05-02 03:15:03.000Z | nashua.dmevals.local | windows.other | win.ServiceName | PSEXESVC | .ds-logs-windows.other-default-2026.10.20-000001 / AaFZJGiSVpshTO1pngJ4 | q-4ce1af25d9 | ok |

### F13 · benign / medium · T1210 · Benign baseline: SMB/WinRM flows, service-parented processes and LSASS access are normal Windows activity

Evidence status: **verified**

The high-volume supporting hits are consistent with routine Windows operation rather than exploitation: 53 Zeek conn flows to 445/5985 (normal SMB/WinRM in a Windows domain), 248 processes spawned by services.exe/lsass.exe/svchost.exe that are overwhelmingly signed Windows components (svchost, WmiPrvSE, RuntimeBroker, taskhostw, TiWorker, Azure guest agents), and 470 Sysmon process-access events to lsass.exe/winlogon.exe typical of security products and logon processing. The 218 type-3 logons are dominated by machine accounts (NEWYORK$, SCRANTON$, NASHUA$, UTICA$, WEC$) performing normal domain authentication. Only the PSEXESVC/python.exe chain and the pbeesly remote logons stand out as anomalous.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:04.000Z | newyork.dmevals.local | windows.security | win.TargetUserName | pbeesly | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZI2iSVpshTO39XK4V | q-2b13d4317b | ok |
| 2 | 2020-05-02 03:15:05.142Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOyCQ37P | q-de1dce8241 | ok |

### F16 · benign / medium · T1550.002 · Single NTLM network logon for pbeesly on SCRANTON is not Pass-the-Hash

Evidence status: **verified**

Only one 4624 with LogonType 3 and AuthenticationPackageName NTLM exists in the whole window: on scranton.dmevals.local at 03:20:41Z for pbeesly, LogonProcessName NtLmSsp, LmPackageName NTLM V2, KeyLength 128, source 172.18.39.2, WorkstationName 10.0.1.4, LogonGuid all-zero. It is accompanied by a 4648 from svchost.exe for pbeesly to localhost and by LogonType 10 (RemoteInteractive) Negotiate logons for pbeesly from the same 172.18.39.2 address at 03:20:46Z, i.e. a normal RDP/NLA-style session, not hash reuse. All other 217 network logons are Kerberos, and the lateral movement to NASHUA used explicit plaintext credentials via PsExec (4648 with TargetLogonGuid populated), not NTLM hash material. No Pass-the-Hash signature observed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:20:41.000Z | scranton.dmevals.local | windows.security | win.AuthenticationPackageName | NTLM | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZJGiSVpshTO0NmmRM | q-c8e95e41b4 | ok |
| 2 | 2020-05-02 03:20:41.000Z | scranton.dmevals.local | windows.security | win.LmPackageName | NTLM V2 | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZJGiSVpshTO0NmmRM | q-c8e95e41b4 | ok |
| 3 | 2020-05-02 03:20:46.000Z | scranton.dmevals.local | windows.security | win.ProcessName | C:\Windows\System32\svchost.exe | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZI2iSVpshTO3mCUhV | q-6da7a9eea0 | ok |
| 4 | 2020-05-02 03:20:46.000Z | scranton.dmevals.local | windows.security | win.LogonType | 10 | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZJGiSVpshTO0Gh1d1 | q-38fc71532c | ok |

### F17 · benign / medium · T1550.003 · Kerberos logons are machine-account and normal user traffic; no Pass-the-Ticket indicators

Evidence status: **verified**

All 217 Kerberos 4624 events are LogonType 3 with LogonProcessName Kerberos and no PreAuthType values populated (aggregation returned no buckets), so the no-preauthentication indicator could not be evaluated. The Kerberos logons are dominated by machine accounts (NEWYORK$, SCRANTON$, NASHUA$, UTICA$, WEC$) from loopback, link-local and peer addresses, plus pbeesly logons on nashua.dmevals.local from 10.0.1.4 (SCRANTON) that coincide with the PsExec/WinRM activity and carry distinct per-session LogonGuids. No ticket-forging or ticket-reuse tooling was found: the PowerShell 4104 search for kerberos/ticket/Rubeus/kirbi returned zero hits, and the only credential-related script blocks were Get-PrivateKeys/Invoke-Exfil on scranton. No Pass-the-Ticket evidence.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:09:23.000Z | nashua.dmevals.local | windows.security | win.LogonProcessName | Kerberos | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZI2iSVpshTO32OAa5 | q-c43caa63ef | ok |
| 2 | 2020-05-02 03:10:23.000Z | nashua.dmevals.local | windows.security | win.IpAddress | 10.0.1.4 | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZI2iSVpshTO31NirV | q-c43caa63ef | ok |
| 3 | 2020-05-02 02:56:47.000Z | newyork.dmevals.local | windows.security | win.TargetUserName | NEWYORK$ | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZJGiSVpshTO0EfrJ2 | q-f3bf07fb95 | ok |

### F18 · benign / high · T1563 · No remote service session hijacking observed; RDP activity on scranton is a normal inbound interactive logon

Evidence status: **verified**

Across windows.security, windows.sysmon, windows.other and windows.powershell (2020-05-02 02:55–03:28Z) there is no evidence of remote service session hijacking. The only RDP-related activity is on scranton.dmevals.local: the host rebooted at 03:18:30 (1074, RuntimeBroker.exe on behalf of DMEVALS\pbeesly), the RDP-Tcp listener started at 03:19:11 (event 258), an inbound TCP connection to port 3389 from 172.18.39.2 was accepted by TermService svchost.exe (Initiated: false) at 03:20:21, followed by a LogonType 10 logon for pbeesly from 172.18.39.2 at 03:20:46 and the expected rdpclip.exe child of the TermService svchost. This is the standard sequence of a legitimate RDP session, not a takeover of an existing session. No tscon, qwinsta, 'query session' or mstsc execution exists in sysmon or PowerShell script blocks, and no 4778/4779 session reconnect events were recorded. The lateral-movement-looking hits (PSEXESVC service installs and 4648 explicit-credential logons on nashua.dmevals.local by pbeesly) are PsExec-style remote execution, which is not remote service session hijacking and is outside this technique family.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:20:21.001Z | scranton.dmevals.local | windows.sysmon | win.Initiated | false | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOoUcuTN | q-461eb8db51 | ok |
| 2 | 2020-05-02 03:20:21.001Z | scranton.dmevals.local | windows.sysmon | destination.port | 3389 | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOoUcuTN | q-461eb8db51 | ok |
| 3 | 2020-05-02 03:19:11.000Z | scranton.dmevals.local | windows.other | message | Listener RDP-Tcp has started listening | .ds-logs-windows.other-default-2026.10.20-000001 / AaFZJGiSVpshTO1pngKZ | q-1f463d76d8 | ok |
| 4 | 2020-05-02 03:18:30.000Z | scranton.dmevals.local | windows.other | message | The process C:\Windows\System32\RuntimeBroker.exe (SCRANTON) has initiated the restart of computer SCRANTON on behalf of user DMEVALS\pbeesly for the following … | .ds-logs-windows.other-default-2026.10.20-000001 / AaFZJGiSVpshTO1pngJS | q-1f463d76d8 | ok |
| 5 | 2020-05-02 03:20:46.000Z | scranton.dmevals.local | windows.security | win.LogonType | 10 | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZJGiSVpshTO0Gh1d1 | q-17b34e6972 | ok |
| 6 | 2020-05-02 03:20:46.000Z | scranton.dmevals.local | windows.security | source.ip | 172.18.39.2 | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZJGiSVpshTO0Gh1d1 | q-17b34e6972 | ok |

### F19 · benign / high · T1563.002 · No RDP session hijacking (tscon/session takeover) on any host

Evidence status: **verified**

The two LogonType 10 events in the dataset are both on scranton.dmevals.local for account pbeesly from 172.18.39.2 at 2020-05-02T03:20:46Z (one non-elevated, one elevated token), immediately preceded by the inbound 3389 connection to TermService and followed by rdpclip.exe (PID 5300, TerminalSessionId 2, parent svchost.exe -k NetworkService -s TermService) — the normal birth of a new RDP session, not the hijack of an existing one. Hijack indicators are absent: no tscon.exe, qwinsta.exe, 'query session' or mstsc.exe process creation in sysmon (only rdpclip.exe matched), no matching PowerShell script blocks, no 4778/4779 session reconnect/disconnect events, and no outbound 3389 connections from any host (the single 3389 record is inbound). The 4648 on scranton targets 'localhost' via svchost.exe, consistent with the local RDP logon itself.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:20:48.127Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\Windows\System32\rdpclip.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOodjOPq | q-5c11dd1922 | ok |
| 2 | 2020-05-02 03:20:48.127Z | scranton.dmevals.local | windows.sysmon | process.parent.command_line | C:\windows\System32\svchost.exe -k NetworkService -s TermService | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOodjOPq | q-5c11dd1922 | ok |
| 3 | 2020-05-02 03:20:48.127Z | scranton.dmevals.local | windows.sysmon | win.TerminalSessionId | 2 | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOodjOPq | q-5c11dd1922 | ok |
| 4 | 2020-05-02 03:20:46.000Z | scranton.dmevals.local | windows.security | win.TargetServerName | localhost | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZI2iSVpshTO3mCUhV | q-ed2991b2d6 | ok |
| 5 | 2020-05-02 03:20:46.000Z | scranton.dmevals.local | windows.security | process.executable | C:\Windows\System32\svchost.exe | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZI2iSVpshTO3mCUhV | q-ed2991b2d6 | ok |

### F21 · benign / medium · T1570 · Routine SYSVOL/IPC$/ADMIN$ share access by machine accounts and WEC is benign domain traffic

Evidence status: **verified**

The 42 Security 5140 share-access events and the bulk of the 121 5145 detailed-share events are ordinary domain operations: NEWYORK$ accessing \\*\SYSVOL (Share Path \\??\F:\SYSVOL\sysvol) over its own link-local IPv6 address, and machine accounts SCRANTON$ (10.0.1.4), NASHUA$ (10.0.1.6), UTICA$ (10.0.1.5) and WEC$ (10.0.1.10) touching \\*\IPC$ for samr/lsarpc RPC endpoints. These are domain-controller replication, Group Policy and Windows Event Collector traffic, not tool staging. The only ADMIN$ writes in the dataset are the pbeesly/PSEXESVC.exe transfers to NASHUA described in the malicious finding. The Zeek smb_files records (2020-04-30, non-overlapping window) show SMB file activity from 10.0.1.4 and 10.0.1.6 to 10.0.0.4 but carry no file names or hashes in the returned fields, so they cannot be tied to this transfer and are not cited as evidence of it.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:56:47.000Z | newyork.dmevals.local | windows.security | win.ShareName | \\*\SYSVOL | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZJGiSVpshTO0EfrKJ | q-3dcee2b4d9 | ok |
| 2 | 2020-05-02 03:22:32.000Z | newyork.dmevals.local | windows.security | win.RelativeTargetName | samr | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZI2iSVpshTO3cAP3I | q-03e1eb80e5 | ok |
| 3 | 2020-05-02 03:05:19.000Z | newyork.dmevals.local | windows.security | user.name | WEC$ | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZI2iSVpshTO39W66K | q-3dcee2b4d9 | ok |

## Pivot candidates

Processes the pivot reviewer had to assess (started by a script host or from outside the Windows directory, rare in the 15-minute windows around verified activity).

| Host | Executable | Starts | Parents | Assessment | Reason |
|---|---|---|---|---|---|
| nashua.dmevals.local | C:\Program Files\WindowsApps\Microsoft.SkypeApp_14.35.152.0_x64__kzf8qxf38zg5c\S… | 1 | C:\Program Files\WindowsApps\Microsoft.SkypeApp_14.35.152.0_x64__kzf8qxf38zg5c\S… | benign | Store Skype app self-restarting; its WerFault crash reports are routine and unrelated to the intrusion. |
| nashua.dmevals.local | C:\Windows\Temp\python.exe | 5 | C:\Windows\PSEXESVC.exe, C:\Windows\Temp\python.exe | malicious | Unsigned python.exe dropped into C:\Windows\Temp and launched 4x by PSEXESVC (and once by itself) as pbeesly; it then spawned powershell.exe, Rar.exe and sdelet… |
| nashua.dmevals.local | C:\Windows\Temp\Rar.exe | 1 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | malicious | WinRAR binary run from C:\Windows\Temp by powershell.exe as pbeesly to password-protect the collected working.zip (-hpfGzq5yKw); deleted afterwards with sdelete… |
| nashua.dmevals.local | C:\Windows\Temp\sdelete64.exe | 3 | C:\Windows\System32\cmd.exe | malicious | Sysinternals sdelete copied to C:\Windows\Temp by python.exe and run 3x by cmd.exe as pbeesly to securely wipe Rar.exe and both working.zip copies - anti-forens… |
| nashua.dmevals.local | C:\WindowsAzure\Packages\CollectGuestLogs.exe | 1 | C:\WindowsAzure\Packages\WaAppAgent.exe | benign | Azure guest agent diagnostic log collection, parent WaAppAgent.exe, SYSTEM. |
| scranton.dmevals.local | C:\Packages\Plugins\Microsoft.Azure.NetworkWatcher.NetworkWatcherAgentWindows\1.… | 4 | C:\Windows\System32\cmd.exe, C:\Windows\System32\services.exe | benign | Azure Network Watcher agent installed as a service; standard cloud VM telemetry. |
| scranton.dmevals.local | C:\Packages\Plugins\Microsoft.Azure.Security.IaaSAntimalware\1.5.5.9\Antimalware… | 1 | C:\WindowsAzure\Packages\GuestAgent\WindowsAzureGuestAgent.exe | benign | Azure IaaS antimalware configuration plugin started by WindowsAzureGuestAgent. |
| scranton.dmevals.local | C:\Packages\Plugins\Microsoft.Compute.CustomScriptExtension\1.10.5\bin\CustomScr… | 1 | C:\Windows\System32\cmd.exe | benign | Azure VM Custom Script Extension handler; standard guest agent plugin. |
| scranton.dmevals.local | C:\Packages\Plugins\Microsoft.Compute.JsonADDomainExtension\1.3.2\bin\JsonADDoma… | 1 | C:\Windows\System32\cmd.exe | benign | Azure AD domain-join extension used to join the host to dmevals.local; expected provisioning. |
| scranton.dmevals.local | C:\Program Files (x86)\Google\Update\1.3.35.452\GoogleCrashHandler.exe | 2 | C:\Program Files (x86)\Google\Update\GoogleUpdate.exe | benign | Google Update crash handler child of GoogleUpdate.exe; routine updater activity. |
| scranton.dmevals.local | C:\Program Files (x86)\Google\Update\1.3.35.452\GoogleCrashHandler64.exe | 2 | C:\Program Files (x86)\Google\Update\GoogleUpdate.exe | benign | Google Update crash handler child of GoogleUpdate.exe; routine updater activity. |
| scranton.dmevals.local | C:\Program Files (x86)\Google\Update\GoogleUpdate.exe | 3 | C:\Program Files (x86)\Google\Update\GoogleUpdate.exe, C:\Windows\System32\servi… | benign | Google Update service/updater started by services.exe/svchost; routine. |
| scranton.dmevals.local | C:\Program Files\SysinternalsSuite\accessChk.exe | 1 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | suspicious | Sysinternals accesschk run by powershell.exe as pbeesly at 03:04:34 and wrote C:\Program Files\SysinternalsSuite\passwordsDB - local privilege/permission reconn… |
| scranton.dmevals.local | C:\Program Files\SysinternalsSuite\PsExec64.exe | 4 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | malicious | Run 4x by powershell.exe as pbeesly with explicit credentials (\\NASHUA -u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe) - the anchored la… |
| scranton.dmevals.local | C:\Program Files\SysinternalsSuite\sdelete64.exe | 3 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | malicious | Run 3x by powershell.exe as pbeesly to wipe the dropped .scr, Draft.Zip and SysinternalsSuite.zip on SCRANTON - anti-forensic cleanup of attacker artifacts. |
| scranton.dmevals.local | C:\Program Files\Windows Defender\MsMpEng.exe | 1 | C:\Windows\System32\services.exe | benign | Windows Defender antimalware service started by services.exe. |
| scranton.dmevals.local | C:\Program Files\Windows Defender\NisSrv.exe | 2 | C:\Windows\System32\services.exe | benign | Windows Defender network inspection service started by services.exe. |
| scranton.dmevals.local | C:\ProgramData\victim\â€®cod.3aka3.scr | 1 | C:\Windows\explorer.exe | malicious | Suspiciously named .scr launched by explorer.exe as pbeesly at 02:55:56, immediately beaconing to 192.168.0.5:1234 and spawning cmd.exe/conhost - the initial im… |
| scranton.dmevals.local | C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe | 2 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | malicious | C# compiler invoked by the hidden encoded PowerShell (IEX-from-bitmap) to build payload DLLs in %TEMP% (0piklvia.dll, qkbkqqbs.dll) - payload compilation by the… |
| scranton.dmevals.local | C:\Windows\System32\hostui.exe | 1 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | suspicious | Started via 'Start-Process C:\Windows\System32\hostui.exe -verb runas' from PowerShell at 03:21:27, immediately followed by a hidden encoded PowerShell child - … |
| scranton.dmevals.local | C:\Windows\System32\sdclt.exe | 3 | C:\Windows\System32\cmd.exe | suspicious | sdclt.exe spawned 3x by cmd.exe as pbeesly at 02:58:42 and then launched control.exe - consistent with sdclt UAC-bypass abuse in the attacker's session. |
| scranton.dmevals.local | C:\WindowsAzure\Packages\GuestAgent\BfeToolWin8.exe | 1 | C:\WindowsAzure\Packages\GuestAgent\WindowsAzureGuestAgent.exe | benign | Azure guest agent firewall (BFE) helper started by WindowsAzureGuestAgent. |
| scranton.dmevals.local | C:\WindowsAzure\Packages\GuestAgent\FindVolume\FindVolume.exe | 1 | C:\WindowsAzure\Packages\GuestAgent\WindowsAzureGuestAgent.exe | benign | Azure guest agent volume discovery helper. |
| scranton.dmevals.local | C:\WindowsAzure\Packages\GuestAgent\WindowsAzureGuestAgent.exe | 1 | C:\Windows\System32\services.exe | benign | Azure Windows guest agent service; standard cloud VM component. |
| scranton.dmevals.local | C:\WindowsAzure\Packages\Telemetry\WindowsAzureTelemetryService.exe | 1 | C:\Windows\System32\services.exe | benign | Azure telemetry service started by services.exe. |
| scranton.dmevals.local | C:\WindowsAzure\Packages\WaAppAgent.exe | 1 | C:\Windows\System32\services.exe | benign | Azure agent host process started by services.exe. |
| scranton.dmevals.local | C:\WindowsAzure\SecAgent\WaSecAgentProv.exe | 2 | C:\WindowsAzure\Packages\WaAppAgent.exe | benign | Azure security agent provider started by WaAppAgent. |
| scranton.dmevals.local | C:\WindowsAzure\WindowsAzureNetAgent_1.0.0.143\WindowsAzureNetAgent\Plugins\VFPl… | 1 | C:\WindowsAzure\WindowsAzureNetAgent_1.0.0.143\WindowsAzureNetAgent\WindowsAzure… | benign | Azure network agent plugin child of WindowsAzureNetAgent. |
| scranton.dmevals.local | C:\WindowsAzure\WindowsAzureNetAgent_1.0.0.143\WindowsAzureNetAgent\WindowsAzure… | 1 | C:\Windows\System32\services.exe | benign | Azure network agent service started by services.exe. |

## Technique conclusions

One line per technique in scope: status from the triage of its family; `not_observed` = checked, nothing found; `not_observable` = no dataset records it.

| Technique | Status | Reason |
|---|---|---|
| T1021 Remote Services | malicious | Remote services used for lateral movement: PsExec over SMB/ADMIN$ and WinRM from SCRANTON (10.0.1.4) to NASHUA (10.0.1.6) by pbeesly with cleartext credentials. |
| T1021.001 Remote Desktop Protocol | suspicious | Only RDP logon in the data: type 10 for pbeesly on SCRANTON from 172.18.39.2 at 23:20:46, after the PsExec activity; no mstsc.exe or outbound 3389 from a compromised host, so pivot direction is unconfirmed. |
| T1021.002 SMB/Windows Admin Shares | suspicious | New: pbeesly type-3 Kerberos logons to NEWYORK from 10.0.1.4 (SCRANTON) and 10.0.1.6 (NASHUA) plus IPC$/samr access from 10.0.1.4; no execution observed on NEWYORK. |
| T1021.003 Distributed Component Object Model | benign | 10016 events are local LRPC COM permission failures for SYSTEM/pbeesly; no DCOM remote activation, MMC20.Application or ShellBrowserWindow script blocks. |
| T1021.004 SSH | not_observed | No ssh.exe/plink/putty executions, no port 22 connections in Sysmon or Zeek, no SSH script blocks. |
| T1021.005 VNC | not_observed | No VNC binaries, no port 5900 connections in Sysmon or Zeek, no VNC script blocks. |
| T1021.006 Windows Remote Management | malicious | Invoke-Command -ComputerName NASHUA executed by pbeesly on SCRANTON, with powershell.exe opening four connections to 10.0.1.6:5985 and matching inbound connections on NASHUA. |
| T1072 Software Deployment Tools | not_observed | No software deployment tooling was used. The lateral movement scranton->nashua was carried out with PsExec64.exe (PSEXESVC service installs, 7045) and PowerShell Invoke-Command/Invoke-SeaDukeStage, not SCCM/Intune/WSUS. … |
| T1080 Taint Shared Content | malicious | pbeesly on scranton (10.0.1.4) wrote Temp\python.exe to \\nashua\ADMIN$ with AccessMask 0x2 (WriteData/AddFile) at 03:10:23, then ran PsExec64.exe against \\NASHUA with the plaintext password to execute C:\Windows\Temp\p… |
| T1091 Replication Through Removable Media | not_observed | No removable-media activity: no execution or file writes from removable drives, no USBSTOR/removable-device registry artifacts, no autorun.inf. The only non-C: writes were DFSR replication metadata on F: (DFSRs.exe) and … |
| T1210 Exploitation of Remote Services | malicious | Remote service abuse observed: PSEXESVC services installed on nashua.dmevals.local by pbeesly spawned an unsigned C:\Windows\Temp\python.exe four times, which then beaconed to 192.168.0.4:8443; accompanied by pbeesly net… |
| T1534 Internal Spearphishing | malicious | A malicious .scr delivered into pbeesly's session on scranton (launched by explorer.exe) led to a PowerShell stager and UAC bypass; the same pbeesly session then initiated WinRM (10.0.1.4 -> 10.0.1.6:5985) to nashua, whe… |
| T1550 Use Alternate Authentication Material | malicious | PsExec64.exe on scranton.dmevals.local launched five times with explicit dmevals\pbeesly credentials against \\NASHUA, producing 4648 cifs/NASHUA logons, PSEXESVC service installs and C:\Windows\Temp\python.exe execution… |
| T1550.002 Pass the Hash | not_observed | Only one NTLM network logon exists (pbeesly on scranton, NTLM V2, paired with LogonType 10 sessions from 172.18.39.2); the lateral movement used explicit plaintext credentials, not hash reuse. |
| T1550.003 Pass the Ticket | not_observed | Kerberos logons are machine-account/peer traffic with per-session LogonGuids, PreAuthType is unpopulated, and no ticket-related PowerShell script blocks (Rubeus/kirbi/ticket) were found. |
| T1563 Remote Service Session Hijacking | benign | Only remote-service activity is a legitimate inbound RDP session on scranton.dmevals.local (listener start 03:19:11, inbound 3389 from 172.18.39.2, LogonType 10 for pbeesly, rdpclip child of TermService). No session hija… |
| T1563.002 RDP Hijacking | benign | No tscon/qwinsta/'query session'/mstsc execution in sysmon or PowerShell, no 4778/4779 events, no outbound 3389. The two Type 10 logons are a new RDP session for pbeesly on scranton preceded by the inbound 3389 connectio… |
| T1570 Lateral Tool Transfer | malicious | pbeesly on SCRANTON ran PsExec64.exe four times against \\NASHUA with plaintext credentials to execute C:\Windows\Temp\python.exe; NASHUA shows python.exe created at 03:10:23, PSEXESVC.exe written to the ADMIN$ share fro… |

## Context (outside the hypothesis)

Activity reported under techniques outside the hypothesis' scope. Not verified, not part of the verdict.

- T1074 · malicious/high · pbeesly on NASHUA collected user documents/credential-named files into working.zip and password-protected it with Rar.exe from C:\Windows\Temp (pivot)
- T1074 · malicious/high · pbeesly on NASHUA collected user documents/credential-named files into working.zip and password-protected it with Rar.exe from C:\Windows\Temp (pivot)
- T1059.001 · malicious/high · SCRANTON attacker tooling: disguised .scr implant, csc.exe payload compilation, sdclt/hostui elevation and sdelete cleanup (pivot)

## Coverage

Cells: number of hits of the planned checks, `n/a` (reason in report.json), or GAP.

| Technique | windows.other | windows.powershell | windows.security | windows.sysmon | zeek |
|---|---|---|---|---|---|
| T1021 Remote Services | 5 hits | 1 hits | 752 hits | 1755 hits | 613 hits |
| T1021.001 Remote Desktop Protocol | 9 hits | 0 hits | 4 hits | 2 hits | 0 hits |
| T1021.002 SMB/Windows Admin Shares | 5 hits | 11 hits | 423 hits | 66 hits | 45 hits |
| T1021.003 Distributed Component Object Model | 3 hits | 0 hits | 218 hits | 1110 hits | 123 hits |
| T1021.004 SSH | n/a | 0 hits | 218 hits | 0 hits | 0 hits |
| T1021.005 VNC | 5 hits | 0 hits | 2 hits | 0 hits | 0 hits |
| T1021.006 Windows Remote Management | 11 hits | 1 hits | 297 hits | 1 hits | 8 hits |
| T1072 Software Deployment Tools | 5 hits | 0 hits | 0 hits | 0 hits | 14 hits |
| T1080 Taint Shared Content | 4 hits | 11 hits | 121 hits | 256 hits | 12 hits |
| T1091 Replication Through Removable Media | 8 hits | 0 hits | 0 hits | 0 hits | n/a |
| T1210 Exploitation of Remote Services | 5 hits | 1 hits | 297 hits | 1947 hits | 53 hits |
| T1534 Internal Spearphishing | 6 hits | 10 hits | 509 hits | 0 hits | n/a |
| T1550 Use Alternate Authentication Material | 5 hits | 4 hits | 609 hits | 447 hits | 2140 hits |
| T1550.002 Pass the Hash | 5 hits | 1 hits | 220 hits | 151 hits | 613 hits |
| T1550.003 Pass the Ticket | 5 hits | 0 hits | 434 hits | 3868 hits | 35 hits |
| T1563 Remote Service Session Hijacking | 5 hits | 0 hits | 314 hits | 1229 hits | 613 hits |
| T1563.002 RDP Hijacking | 5 hits | 120 hits | 19 hits | 2 hits | 0 hits |
| T1570 Lateral Tool Transfer | 5 hits | 1 hits | 205 hits | 1656 hits | 12 hits |

Cells: 90, gaps: 0.

## Queries

Every MCP tool call of this run (630), in order (source: mcp_audit.jsonl written by the MCP server).

| Query | Phase | Tool | Arguments | Hits / rows | Cited by |
|---|---|---|---|---|---|
| q-320717c416 | scope | list_data_sources | {} | None |  |
| q-a5a295cc13 | scope | get_registry | {} | None |  |
| q-b8e710a636 | scope | get_fields | {"dataset": "windows.other", "prefix": ""} | None |  |
| q-680dbd0628 | scope | get_fields | {"dataset": "windows.powershell", "prefix": ""} | None |  |
| q-80a0482614 | scope | get_fields | {"dataset": "windows.security", "prefix": ""} | None |  |
| q-73ee1fc828 | scope | get_fields | {"dataset": "windows.sysmon", "prefix": ""} | None |  |
| q-169ec0c581 | scope | get_fields | {"dataset": "zeek", "prefix": ""} | None |  |
| q-4fa3462011 | check C001 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 297 |  |
| q-61bdcb7093 | check C002 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4624 AND (win.LogonType:3 OR win.LogonType:10)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 220 |  |
| q-bce60b2817 | check C003 | aggregate | {"dataset": "windows.security", "field": "win.IpAddress", "query": "event.code:4624 AND (win.LogonType:3 OR win.LogonType:10)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 220 |  |
| q-777f24c8a8 | check C004 | search | {"dataset": "windows.security", "query": "event.code:4648", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 15 | F01 |
| q-79a8e23a37 | check C005 | aggregate | {"dataset": "windows.sysmon", "field": "destination.port", "query": "event.code:3", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1229 |  |
| q-d427a95675 | check C006 | aggregate | {"dataset": "windows.sysmon", "field": "destination.ip", "query": "event.code:3 AND (destination.port:445 OR destination.port:3389 OR destination.port:5985 OR destination.port:5986 OR destination.port:5900)", "time_from": null, "time_to": null, "size": 50, "su… | 79 |  |
| q-f992e4eba5 | check C007 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 447 |  |
| q-17616c74b1 | check C008 | aggregate | {"dataset": "windows.powershell", "field": "host.name", "query": "event.code:4104 AND (win.ScriptBlockText:*Invoke-Command* OR win.ScriptBlockText:*Enter-PSSession* OR win.ScriptBlockText:*New-PSSession* OR win.ScriptBlockText:*winrs*)", "time_from": null, "ti… | 1 |  |
| q-b1899d3ad0 | check C009 | aggregate | {"dataset": "windows.other", "field": "win.ServiceName", "query": "event.code:7045", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 5 |  |
| q-e81d9c2991 | check C010 | aggregate | {"dataset": "zeek", "field": "destination.port", "query": "event.action:conn", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 613 |  |
| q-f5bb635f7d | check C011 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4624 AND win.LogonType:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 2 |  |
| q-83098118e9 | check C012 | aggregate | {"dataset": "windows.security", "field": "win.IpAddress", "query": "event.code:4624 AND win.LogonType:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 2 |  |
| q-c1e668d02f | check C013 | search | {"dataset": "windows.security", "query": "event.code:4778 OR event.code:4779", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 0 |  |
| q-240024b45c | check C014 | aggregate | {"dataset": "windows.sysmon", "field": "destination.ip", "query": "event.code:3 AND destination.port:3389", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1 |  |
| q-c936f564cb | check C015 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.executable:*mstsc* OR process.executable:*rdp*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1 |  |
| q-18d303e960 | check C016 | search | {"dataset": "windows.powershell", "query": "win.ScriptBlockText:*mstsc* OR win.ScriptBlockText:*3389*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable",… | 0 |  |
| q-9daa63edfe | check C017 | search | {"dataset": "windows.other", "query": "event.code:1074 OR event.code:7036", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "so… | 9 |  |
| q-05727465b1 | check C018 | aggregate | {"dataset": "zeek", "field": "destination.ip", "query": "event.action:conn AND destination.port:3389", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-f712ed5bd7 | check C019 | aggregate | {"dataset": "windows.security", "field": "win.ShareName", "query": "event.code:5140", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 42 |  |
| q-b958edd821 | check C020 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:5140", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 42 |  |
| q-2a31c5ef65 | check C021 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:5145", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 121 |  |
| q-b45a0e14cd | check C022 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4624 AND win.LogonType:3", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 218 |  |
| q-2f9b0fdee0 | check C023 | aggregate | {"dataset": "windows.sysmon", "field": "destination.ip", "query": "event.code:3 AND destination.port:445", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 66 |  |
| q-22b105a901 | check C024 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.executable:*psexec* OR process.executable:*smbexec* OR process.executable:*net.exe OR process.executable:*net1.exe)", "time_from": null, "time_to": null, "size": 5… | 0 |  |
| q-8a2c4481eb | check C025 | search | {"dataset": "windows.powershell", "query": "win.ScriptBlockText:*ADMIN$* OR win.ScriptBlockText:*\\\\\\\\*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executa… | 11 |  |
| q-a244d1db6e | check C026 | aggregate | {"dataset": "windows.other", "field": "win.ServiceName", "query": "event.code:7045", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 5 |  |
| q-9a97b80722 | check C027 | aggregate | {"dataset": "zeek", "field": "destination.ip", "query": "event.action:conn AND destination.port:445", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 45 |  |
| q-ff0466723d | check C028 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4624 AND win.LogonType:3", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 218 |  |
| q-4e0f6487e5 | check C029 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.executable:*mmc.exe* OR process.executable:*dllhost* OR process.executable:*wmiprvse* OR process.executable:*rundll32*)", "time_from": null, "time_to": null, "size… | 10 |  |
| q-6f8006a9ee | check C030 | aggregate | {"dataset": "windows.sysmon", "field": "destination.port", "query": "event.code:3 AND (destination.port:135 OR destination.port:445)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 132 |  |
| q-7f40ea4cac | check C031 | aggregate | {"dataset": "windows.sysmon", "field": "win.ImageLoaded", "query": "event.code:7 AND (win.ImageLoaded:*ole32* OR win.ImageLoaded:*combase* OR win.ImageLoaded:*rpcrt4*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 968 |  |
| q-497922d5c5 | check C032 | search | {"dataset": "windows.powershell", "query": "win.ScriptBlockText:*MMC20.Application* OR win.ScriptBlockText:*ShellBrowserWindow* OR win.ScriptBlockText:*DCOM*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.da… | 0 |  |
| q-b403cde877 | check C033 | search | {"dataset": "windows.other", "query": "event.code:10016", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destina… | 3 | F04 |
| q-446475a41d | check C034 | aggregate | {"dataset": "zeek", "field": "destination.port", "query": "event.action:dce_rpc", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 123 |  |
| q-c0d759062c | check C035 | aggregate | {"dataset": "windows.sysmon", "field": "destination.ip", "query": "event.code:3 AND destination.port:22", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-07c4016116 | check C036 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.executable:*ssh.exe* OR process.executable:*plink* OR process.executable:*putty*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-04d46a8ec8 | check C037 | search | {"dataset": "windows.powershell", "query": "win.ScriptBlockText:*ssh*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source… | 0 |  |
| q-f3ab2af5dc | check C038 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4624 AND win.LogonType:3", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 218 |  |
| q-4ad7b53e89 | check C039 | aggregate | {"dataset": "zeek", "field": "destination.ip", "query": "event.action:conn AND destination.port:22", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-d75672e372 | check C040 | aggregate | {"dataset": "windows.sysmon", "field": "destination.ip", "query": "event.code:3 AND destination.port:5900", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-246cb660d4 | check C041 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.executable:*vnc* OR process.executable:*tvnserver* OR process.executable:*winvnc*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-31a64ab396 | check C042 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4624 AND win.LogonType:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 2 |  |
| q-1714d5ee5b | check C043 | aggregate | {"dataset": "windows.other", "field": "win.ServiceName", "query": "event.code:7045", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 5 |  |
| q-22628633ca | check C044 | search | {"dataset": "windows.powershell", "query": "win.ScriptBlockText:*vnc* OR win.ScriptBlockText:*5900*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "… | 0 |  |
| q-9f08dacf44 | check C045 | aggregate | {"dataset": "zeek", "field": "destination.ip", "query": "event.action:conn AND destination.port:5900", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-702171e567 | check C046 | search | {"dataset": "windows.other", "query": "event.code:6", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destination… | 11 |  |
| q-449d348f8b | check C047 | aggregate | {"dataset": "windows.powershell", "field": "host.name", "query": "event.code:4104 AND (win.ScriptBlockText:*Invoke-Command* OR win.ScriptBlockText:*New-PSSession* OR win.ScriptBlockText:*Enter-PSSession* OR win.ScriptBlockText:*wsman*)", "time_from": null, "ti… | 1 |  |
| q-0c8eb7b9e5 | check C048 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 297 |  |
| q-777abfffb6 | check C049 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*wsmprovhost* OR process.parent.executable:*wsmprovhost*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1 |  |
| q-60ce977ce0 | check C050 | aggregate | {"dataset": "zeek", "field": "destination.port", "query": "event.action:conn AND (destination.port:5985 OR destination.port:5986)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 8 |  |
| q-1b37eaa9c7 | check C051 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-a0b0c6e32d | check C052 | aggregate | {"dataset": "windows.powershell", "field": "host.name", "query": "event.code:4104 AND (win.ScriptBlockText:*SCCM* OR win.ScriptBlockText:*ccmexec* OR win.ScriptBlockText:*Intune* OR win.ScriptBlockText:*SoftwareDistribution*)", "time_from": null, "time_to": nu… | 0 |  |
| q-51537fd0a6 | check C053 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND (process.executable:*ccmexec* OR process.executable:*Intune* OR process.executable:*SMS*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-76ff8b51bd | check C054 | aggregate | {"dataset": "windows.sysmon", "field": "process.parent.executable", "query": "event.code:1 AND (process.parent.executable:*ccmexec* OR process.parent.executable:*Intune* OR process.parent.executable:*SMS*)", "time_from": null, "time_to": null, "size": 50, "sub… | 0 |  |
| q-09118d7b6e | check C055 | aggregate | {"dataset": "zeek", "field": "destination.port", "query": "event.action:conn AND (destination.port:8530 OR destination.port:8531 OR destination.port:80 OR destination.port:443)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 14 |  |
| q-fac4dee1cd | check C056 | aggregate | {"dataset": "windows.security", "field": "win.ShareName", "query": "event.code:5145", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 121 |  |
| q-6896bfe23a | check C057 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND (file.path:*\\\\Users\\\\Public* OR file.path:*\\\\ProgramData* OR file.path:*\\\\Temp*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 256 |  |
| q-db28961a0e | check C058 | search | {"dataset": "windows.other", "query": "event.code:11", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinatio… | 4 | F09 |
| q-0ad16b83f1 | check C059 | aggregate | {"dataset": "windows.powershell", "field": "host.name", "query": "event.code:4104 AND (win.ScriptBlockText:*Copy-Item* OR win.ScriptBlockText:*Out-File* OR win.ScriptBlockText:*\\\\\\\\*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 11 |  |
| q-7d56355bc8 | check C060 | aggregate | {"dataset": "zeek", "field": "zeek.filename", "query": "event.action:smb_files", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 12 |  |
| q-643f07faf7 | check C061 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.executable:D\\\\* OR process.executable:E\\\\* OR process.executable:F\\\\* OR process.executable:G\\\\*)", "time_from": null, "time_to": null, "size": 50, "sub_fi… | 0 |  |
| q-0ffeed7b92 | check C062 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND (file.path:D\\\\* OR file.path:E\\\\* OR file.path:F\\\\* OR file.path:G\\\\*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-1454c89c52 | check C063 | search | {"dataset": "windows.other", "query": "event.code:2004 OR event.code:2006", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "so… | 8 |  |
| q-3f4ae8d41a | check C064 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND (process.executable:D\\\\* OR process.executable:E\\\\* OR process.executable:F\\\\*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-12cf2e8295 | check C065 | aggregate | {"dataset": "windows.powershell", "field": "host.name", "query": "event.code:4104 AND (win.ScriptBlockText:*D:\\\\* OR win.ScriptBlockText:*E:\\\\* OR win.ScriptBlockText:*USB*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | ERROR |  |
| q-7df23750e7 | check C065 (repaired) | aggregate | {"dataset": "windows.powershell", "field": "host.name", "query": "event.code:4104 AND (win.ScriptBlockText:*D\\:* OR win.ScriptBlockText:*E\\:* OR win.ScriptBlockText:*USB*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-3570f24f08 | check C066 | aggregate | {"dataset": "zeek", "field": "destination.port", "query": "event.action:conn AND (destination.port:445 OR destination.port:3389 OR destination.port:5985 OR destination.port:5986)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 53 |  |
| q-392be788d2 | check C067 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.parent.executable:*services.exe OR process.parent.executable:*lsass.exe OR process.parent.executable:*svchost.exe)", "time_from": null, "time_to": null, "size": 50… | 248 |  |
| q-9bcc987718 | check C068 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10 AND (win.TargetImage:*lsass.exe OR win.TargetImage:*winlogon.exe)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 470 |  |
| q-0e0c6d012f | check C069 | aggregate | {"dataset": "windows.sysmon", "field": "destination.port", "query": "event.code:3", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1229 |  |
| q-a89da83821 | check C070 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 297 |  |
| q-48321aad2f | check C071 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 | F11 |
| q-27b94825a6 | check C072 | aggregate | {"dataset": "windows.powershell", "field": "host.name", "query": "event.code:4104 AND (win.ScriptBlockText:*Invoke-Shellcode* OR win.ScriptBlockText:*DownloadString* OR win.ScriptBlockText:*IEX*)", "time_from": null, "time_to": null, "size": 50, "sub_field": n… | 1 |  |
| q-f0afe28c12 | check C073 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-3d98ecc4bf | check C074 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 297 |  |
| q-baf2edee3e | check C075 | aggregate | {"dataset": "windows.security", "field": "win.SubjectUserName", "query": "event.code:4672", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 212 |  |
| q-1427c2d6ba | check C076 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.executable:*outlook* OR process.executable:*chrome* OR process.executable:*firefox*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-f987e42c4e | check C077 | aggregate | {"dataset": "windows.powershell", "field": "host.name", "query": "event.code:4104 AND (win.ScriptBlockText:*http* OR win.ScriptBlockText:*DownloadFile* OR win.ScriptBlockText:*Invoke-WebRequest*)", "time_from": null, "time_to": null, "size": 50, "sub_field": n… | 10 |  |
| q-a54cfb185b | check C078 | search | {"dataset": "windows.other", "query": "event.code:1 OR event.code:10", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.… | 6 |  |
| q-ee3852c506 | check C079 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 297 |  |
| q-9e89ff5674 | check C080 | aggregate | {"dataset": "windows.security", "field": "win.AuthenticationPackageName", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 297 |  |
| q-e32c9b7a1b | check C081 | search | {"dataset": "windows.security", "query": "event.code:4648", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 15 |  |
| q-181df5d9a4 | check C082 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 447 |  |
| q-70d1fa1590 | check C083 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Credential* OR win.ScriptBlockText:*PSCredential* OR win.ScriptBlockText:*ConvertTo-SecureString*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name",… | 4 |  |
| q-5a91e6b188 | check C084 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 | F15 |
| q-761394c149 | check C085 | aggregate | {"dataset": "zeek", "field": "event.action", "query": "*", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 2140 |  |
| q-fca206fc92 | check C086 | aggregate | {"dataset": "windows.security", "field": "win.AuthenticationPackageName", "query": "event.code:4624 AND win.LogonType:3", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 218 |  |
| q-3d78fe372d | check C087 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4624 AND win.LogonType:3 AND win.AuthenticationPackageName:NTLM", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1 |  |
| q-668aa921b9 | check C088 | search | {"dataset": "windows.security", "query": "event.code:4624 AND win.LogonType:3 AND win.AuthenticationPackageName:NTLM", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "proce… | 1 |  |
| q-7c9c927f7e | check C089 | aggregate | {"dataset": "windows.sysmon", "field": "destination.ip", "query": "event.code:3 AND (destination.port:445 OR destination.port:135 OR destination.port:5985)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 144 |  |
| q-ac9b3654bd | check C090 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.executable:*psexec* OR process.executable:*wmic* OR process.executable:*winrs* OR process.command_line:*\\\\\\\\*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "ob… | 7 |  |
| q-f41bcdee7e | check C091 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Invoke-Command* OR win.ScriptBlockText:*New-PSSession* OR win.ScriptBlockText:*Enter-PSSession*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "… | 1 |  |
| q-fa34f7f377 | check C092 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-4aae216467 | check C093 | aggregate | {"dataset": "zeek", "field": "destination.port", "query": "event.action:conn", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 613 |  |
| q-cdc57a40ea | check C094 | aggregate | {"dataset": "windows.security", "field": "win.PreAuthType", "query": "event.code:4624 AND win.AuthenticationPackageName:Kerberos", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 217 |  |
| q-c74d6cd941 | check C095 | search | {"dataset": "windows.security", "query": "event.code:4624 AND win.AuthenticationPackageName:Kerberos", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", … | 217 |  |
| q-7b75bd95b6 | check C096 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10 AND (win.GrantedAccess:*0x40* OR win.GrantedAccess:*0x1400*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 3850 |  |
| q-fada1248e9 | check C097 | aggregate | {"dataset": "windows.sysmon", "field": "win.ImageLoaded", "query": "event.code:7 AND (win.ImageLoaded:*kerberos* OR win.ImageLoaded:*kdc*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 18 |  |
| q-95a675df1f | check C098 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*kerberos* OR win.ScriptBlockText:*ticket* OR win.ScriptBlockText:*Rubeus* OR win.ScriptBlockText:*kirbi*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host… | 0 |  |
| q-359c5ab3a4 | check C099 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-75920a84a8 | check C100 | search | {"dataset": "zeek", "query": "event.action:kerberos", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destination… | 35 |  |
| q-9ed4bfc923 | check C101 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 297 |  |
| q-82a105d94d | check C102 | search | {"dataset": "windows.security", "query": "event.code:4624 AND win.LogonType:10", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line"… | 2 |  |
| q-6fe739fbec | check C103 | search | {"dataset": "windows.security", "query": "event.code:4648", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 15 |  |
| q-735de3d5dc | check C104 | aggregate | {"dataset": "windows.sysmon", "field": "destination.port", "query": "event.code:3", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1229 |  |
| q-b5564d57cb | check C105 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.executable:*mstsc* OR process.executable:*winrs* OR process.executable:*ssh*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event… | 0 |  |
| q-7e9ade79c0 | check C106 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Enter-PSSession* OR win.ScriptBlockText:*New-PSSession*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.… | 0 |  |
| q-8a9f7455ab | check C107 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-5c570dbc6c | check C108 | aggregate | {"dataset": "zeek", "field": "destination.port", "query": "event.action:conn", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 613 |  |
| q-9494ba6dd6 | check C109 | search | {"dataset": "windows.security", "query": "event.code:4624 AND win.LogonType:10", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line"… | 2 |  |
| q-4197717d52 | check C110 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4624 AND win.LogonType:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 2 |  |
| q-50967b60cc | check C111 | search | {"dataset": "windows.security", "query": "event.code:4648", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 15 |  |
| q-490bd6b490 | check C112 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.executable:*mstsc* OR process.executable:*tscon* OR process.executable:*rdpclip*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "e… | 1 |  |
| q-24c58b3b5a | check C113 | aggregate | {"dataset": "windows.sysmon", "field": "destination.port", "query": "event.code:3 AND destination.port:3389", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1 |  |
| q-add805413a | check C114 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*tscon* OR win.ScriptBlockText:*query session* OR win.ScriptBlockText:*qwinsta*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "… | 120 |  |
| q-5cdb1022ef | check C115 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-16462c2e21 | check C116 | aggregate | {"dataset": "zeek", "field": "destination.port", "query": "event.action:conn AND destination.port:3389", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-42230757ac | check C117 | aggregate | {"dataset": "windows.security", "field": "win.ShareName", "query": "event.code:5140", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 42 |  |
| q-3dcee2b4d9 | check C118 | search | {"dataset": "windows.security", "query": "event.code:5140", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 42 | F21 |
| q-6b4602d804 | check C119 | search | {"dataset": "windows.security", "query": "event.code:5145", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 121 |  |
| q-4abefad0a5 | check C120 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1649 |  |
| q-736aaa1e87 | check C121 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (win.TargetFilename:*\\\\\\* OR win.TargetFilename:*ADMIN$* OR win.TargetFilename:*C$*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "eve… | 0 |  |
| q-5f56ef5941 | check C122 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*copy* OR process.command_line:*xcopy* OR process.command_line:*robocopy* OR process.command_line:*\\\\\\\\*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.na… | 7 |  |
| q-ccb61df1d1 | check C123 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Copy-Item* OR win.ScriptBlockText:*Invoke-WebRequest* OR win.ScriptBlockText:*Net.WebClient* OR win.ScriptBlockText:*DownloadFile*)", "time_from": null, "time_to": null, "fie… | 1 |  |
| q-6da4d40434 | check C124 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-535ea8d700 | check C125 | search | {"dataset": "zeek", "query": "event.action:smb_files", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinatio… | 12 |  |
| q-b358cfa820 | triage T1021 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3IxM8t"} | None | F01 |
| q-cfd0c984dc | triage T1021 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.executable:*PsExec* OR process.executable:*PSEXESVC* OR process.executable:*python.exe)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "process.executab… | 13 | F01 |
| q-e2bc67cbf2 | triage T1021 step 1 | search | {"dataset": "windows.security", "query": "event.code:4624 AND win.LogonType:10", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "win.TargetUserName", "win.IpAddress", "win.LogonProcessName", "win.Workstation", "win.Authe… | 2 |  |
| q-71bf189573 | triage T1021 step 1 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "win.ServiceName", "win.ImagePath", "win.ServiceType", "win.ServiceStartType", "win.AccountName"], "size": 10, "sort": "asc"} | 5 | F01 |
| q-fbe65f641f | triage T1021 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:3 AND (destination.port:445 OR destination.port:5985 OR destination.port:3389)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "process.executable", "destination.ip", "… | 79 |  |
| q-940b48c81a | triage T1021 step 2 | search | {"dataset": "windows.security", "query": "event.code:5140", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "win.ShareName", "win.IpAddress", "win.SubjectUserName", "win.AccessMask"], "size": 45, "sort": "asc"} | 42 |  |
| q-9dbbcd656b | triage T1021 step 2 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Invoke-Command* OR win.ScriptBlockText:*PSSession* OR win.ScriptBlockText:*winrs* OR win.ScriptBlockText:*Enter-PS*)", "time_from": null, "time_to": null, "fields": ["@timest… | 1 | F02 |
| q-88630afd24 | triage T1021 step 3 | search | {"dataset": "windows.sysmon", "query": "event.code:3 AND destination.port:5985", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "process.executable", "destination.ip", "destination.port", "source.ip", "win.Initiated"], "… | 12 | F02 |
| q-7d2a355018 | triage T1021 step 3 | search | {"dataset": "windows.security", "query": "event.code:5140 AND win.ShareName:*ADMIN$*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "win.ShareName", "win.IpAddress", "win.SubjectUserName", "win.AccessMask", "win.Object… | 9 | F01 |
| q-da5027889c | triage T1021 step 3 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO3mCUhV"} | None | F03 |
| q-191b9eedad | triage T1021 step 4 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO0Gh1d1"} | None | F03, F05, F06 |
| q-0e4e186361 | triage T1021 step 4 | search | {"dataset": "zeek", "query": "event.action:conn AND (destination.port:445 OR destination.port:5985)", "time_from": null, "time_to": null, "fields": ["@timestamp", "event.action", "source.ip", "destination.ip", "destination.port", "zeek.service", "zeek.conn_sta… | 53 | F02 |
| q-945959de10 | triage T1021 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3IxM8t"} | None |  |
| q-d00dbd7e2e | triage T1021 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtGQk7R"} | None |  |
| q-904d777582 | triage T1021 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO1pngK-"} | None |  |
| q-5c19d272a2 | triage T1021 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOyESnYY"} | None |  |
| q-3454c34915 | triage T1021 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO31Nirr"} | None |  |
| q-85a5116128 | triage T1021 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO31NCqL"} | None |  |
| q-8d5cc74c9e | triage T1021 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3HwqHA"} | None |  |
| q-7f77118657 | triage T1021 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOyETHZ1"} | None |  |
| q-4e8158a956 | triage T1021 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOyETHZ2"} | None |  |
| q-56709254af | triage T1021 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZJWiSVpshTO2e9KT-"} | None |  |
| q-afbbf634c8 | triage T1021 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO0Gh1d1"} | None |  |
| q-7f13ae24be | triage T1021 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO0Gh1d1"} | None |  |
| q-b0e9526017 | triage T1021 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3mCUhV"} | ERROR |  |
| q-4312d52e5d | triage T1021 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO1pngJg"} | None |  |
| q-bb2d1b6c7a | triage T1021 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO1pngJA"} | None |  |
| q-6425b34d1e | triage T1021 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO3_ZDSr"} | None |  |
| q-15481d8618 | triage T1021 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO0Gh1d1"} | None |  |
| q-3aad175091 | triage T1021 step 6 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3_ZDSr"} | ERROR |  |
| q-9140aed8ee | triage T1072 step 1 | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO1pngK-"} | None | F07 |
| q-cc8f0fa5ba | triage T1072 step 1 | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO1pngIR"} | None | F07 |
| q-fbe8455f17 | triage T1072 step 1 | search | {"dataset": "zeek", "query": "event.action:conn AND (destination.port:8530 OR destination.port:8531 OR destination.port:80 OR destination.port:443)", "time_from": null, "time_to": null, "fields": ["@timestamp", "source.ip", "destination.ip", "destination.port"… | 14 | F07 |
| q-6a1571e518 | triage T1072 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.executable) LIKE \"*psexe*\" OR TO_LOWER(process.parent.executable) LIKE \"*psexe*\" OR TO_LOWER(process.executable) LIKE \"*ccmexec*\" OR TO_LO… | 17 | F07 |
| q-963ca92a30 | triage T1072 step 2 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4688\" AND (TO_LOWER(process.executable) LIKE \"*psexe*\" OR TO_LOWER(process.executable) LIKE \"*ccmexec*\" OR TO_LOWER(process.executable) LIKE \"*javamtsup*\" OR TO_… | 13 |  |
| q-449bbefe24 | triage T1072 step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*psexec*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*nashua*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*python.exe*\" … | 6 | F07 |
| q-bd5443bc54 | triage T1072 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE (TO_LOWER(file.path) LIKE \"*javamtsup*\" OR TO_LOWER(file.path) LIKE \"*\\\\temp\\\\python.exe*\" OR TO_LOWER(process.executable) LIKE \"*\\\\temp\\\\python.exe\") \| KEEP @timestamp, h… | ERROR |  |
| q-a92235fd6e | triage T1072 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE TO_LOWER(file.path) LIKE \"*javamtsup*\" OR TO_LOWER(file.path) LIKE \"*python.exe*\" \| KEEP @timestamp, host.name, event.code, file.path, process.executable, win.Hashes, _id, _index \|… | 16 | F07 |
| q-4d27e4b9e8 | triage T1072 step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*seaduke*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*invoke-command*\" \| KEEP @timestamp, host.name, user.name, event.code, win.ScriptBlockText,… | 2 |  |
| q-b287861b8e | triage T1072 step 5 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOou0mUT"} | None | F07 |
| q-2abb39485a | triage T1072 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtGQk7R"} | None |  |
| q-fde8eb591b | triage T1072 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3JxTEc"} | None |  |
| q-7ae2600843 | triage T1072 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3HwqHA"} | None |  |
| q-9f59988ce7 | triage T1072 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO1pngK-"} | None |  |
| q-d267b19fab | triage T1072 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOyESnYY"} | None |  |
| q-9b40ab417b | triage T1072 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOyESXbs"} | None |  |
| q-60f6347ed4 | triage T1072 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO1pngIR"} | None |  |
| q-8e73585465 | triage T1072 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOou0mUT"} | None |  |
| q-abde55a919 | triage T1072 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtk0ckj"} | None |  |
| q-7360f62ff5 | triage T1072 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZJWiSVpshTO037K8M"} | None |  |
| q-f5181e2713 | triage T1080 step 1 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Copy-Item* OR win.ScriptBlockText:*Out-File* OR win.ScriptBlockText:*\\\\\\\\*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "win.… | 11 | F08 |
| q-6f5bfe0f19 | triage T1080 step 1 | search | {"dataset": "zeek", "query": "event.action:smb_files", "time_from": null, "time_to": null, "fields": ["@timestamp", "zeek.filename", "zeek.path", "zeek.action", "zeek.id_orig_h", "zeek.id_resp_h", "zeek.share_type", "zeek.size", "source.ip", "destination.ip"],… | 12 | F09 |
| q-28867b98c5 | triage T1080 step 2 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"5145\" \| KEEP @timestamp, host.name, user.name, win.ShareName, win.RelativeTargetName, win.AccessMask, win.IpAddress, win.SubjectUserName, _id, _index \| SORT @timesta… | 121 | F09 |
| q-5e4334dd1d | triage T1080 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*\\\\\\\\users\\\\\\\\public*\" OR TO_LOWER(file.path) LIKE \"*\\\\\\\\temp*\") \| KEEP @timestamp, host.name, user.name, file.path, … | 182 | F09 |
| q-7e14dcfeae | triage T1080 step 3 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO31NyoH"} | None | F08 |
| q-3147fb4ed9 | triage T1080 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*sysvol*\" OR TO_LOWER(file.path) LIKE \"*\\\\\\\\policies\\\\\\\\*\" OR TO_LOWER(file.path) LIKE \"*\\\\\\\\netlogon*\" OR TO_LOWER(… | 23 | F09 |
| q-058a17c207 | triage T1080 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.executable) LIKE \"*python*\" OR TO_LOWER(process.command_line) LIKE \"*psexec*\" OR TO_LOWER(process.command_line) LIKE \"*\\\\\\\\nashua*\") \… | 9 | F08 |
| q-29519f4dbf | triage T1080 step 4 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"5140\" \| KEEP @timestamp, host.name, user.name, win.ShareName, win.ShareLocalPath, win.IpAddress, win.SubjectUserName, _id, _index \| SORT @timestamp ASC"} | 42 | F08, F09 |
| q-d8d4d60795 | triage T1080 step 5 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO31NyoI"} | None | F08 |
| q-05f2c1fa13 | triage T1080 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO31NyoI"} | None |  |
| q-347993dc02 | triage T1080 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO31NyoI"} | None |  |
| q-0149acbabe | triage T1080 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO31NyoI"} | None |  |
| q-9ee7d276ee | triage T1080 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO31NyoI"} | None |  |
| q-6c41617f4b | triage T1080 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO31NyoH"} | None |  |
| q-a829486ec5 | triage T1080 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO31Nirr"} | None |  |
| q-7f5c8f0f02 | triage T1080 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtGQk7R"} | None |  |
| q-2004de3ead | triage T1080 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOyESnYY"} | None |  |
| q-31c7ae617a | triage T1080 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOyESnYY"} | None |  |
| q-86e24586f2 | triage T1080 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3IxM8t"} | None |  |
| q-7ca04c31ce | triage T1080 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3AvzkC"} | None |  |
| q-f0f068579b | triage T1080 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO3_ZDTc"} | None |  |
| q-4d1d80daf7 | triage T1080 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO3_ZDTc"} | None |  |
| q-40a4012560 | triage T1080 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO0EfrKJ"} | None |  |
| q-df10d85862 | triage T1080 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtfu-5W"} | None |  |
| q-cf8381505a | triage T1080 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtfu-5W"} | None |  |
| q-6c6aa7ccb9 | triage T1080 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZJWiSVpshTO03669U"} | None |  |
| q-6ea2fe621d | triage T1080 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZJWiSVpshTO03669U"} | None |  |
| q-8f2a8b661e | triage T1080 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOx5IMzh"} | None |  |
| q-a151b02c81 | triage T1080 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO1pngIU"} | None |  |
| q-8f04b8ba9c | triage T1091 step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"d:*\" OR TO_LOWER(file.path) LIKE \"e:*\" OR TO_LOWER(file.path) LIKE \"f:*\" OR TO_LOWER(file.path) LIKE \"g:*\" OR TO_LOWER(file.pa… | ERROR |  |
| q-ce04d58e83 | triage T1091 step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.executable) LIKE \"d:*\" OR TO_LOWER(process.executable) LIKE \"e:*\" OR TO_LOWER(process.executable) LIKE \"f:*\" OR TO_LOWER(process.executabl… | 0 |  |
| q-e9b98fdb0e | triage T1091 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"d:*\" OR TO_LOWER(file.path) LIKE \"e:*\" OR TO_LOWER(file.path) LIKE \"f:*\" OR TO_LOWER(file.path) LIKE \"g:*\" OR TO_LOWER(file.pa… | 15 | F10 |
| q-4418cdbd5d | triage T1091 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"6\" OR event.code == \"9\" OR event.code == \"8\" \| KEEP @timestamp, host.name, process.executable, win.ImageLoaded, win.Signed, win.Signature, win.Device, _id, _index \… | 50 |  |
| q-048d1949c6 | triage T1091 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*usb*\" OR TO_LOWER(file.path) LIKE \"*removable*\" OR TO_LOWER(file.path) LIKE \"*\\\\$recycle*\" OR TO_LOWER(file.path) LIKE \"*aut… | ERROR |  |
| q-8e8e751bdb | triage T1091 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"12\" OR event.code == \"13\" \| WHERE TO_LOWER(registry.path) LIKE \"*usbstor*\" OR TO_LOWER(registry.path) LIKE \"*\\\\enum\\\\usb*\" OR TO_LOWER(registry.path) LIKE \"*… | ERROR |  |
| q-7d40b00256 | triage T1091 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*usb*\" OR TO_LOWER(file.path) LIKE \"*removable*\" OR TO_LOWER(file.path) LIKE \"*autorun*\") \| KEEP @timestamp, host.name, file.pa… | 12 | F10 |
| q-15d363346e | triage T1091 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"12\" OR event.code == \"13\" \| WHERE TO_LOWER(registry.path) LIKE \"*usbstor*\" OR TO_LOWER(registry.path) LIKE \"*mountpoints2*\" OR TO_LOWER(registry.path) LIKE \"*por… | 30 |  |
| q-92fd099656 | triage T1091 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*sysinternals*\" OR TO_LOWER(process.command_line) LIKE \"*autorun*\" OR TO_LOWER(process.executable) LIKE \"*autorun*\") \… | 8 | F10 |
| q-fa30b45ae6 | triage T1091 step 5 | esql | {"query": "FROM logs-windows.other-default METADATA _id, _index \| WHERE event.code == \"2004\" OR event.code == \"2006\" \| KEEP @timestamp, host.name, user.name, win.RuleName, win.ModifyingApplication, win.Direction, win.Action, _id, _index \| LIMIT 20"} | 8 | F10 |
| q-6c98a8ee62 | triage T1091 step 6 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOoQYU2W"} | None | F10 |
| q-4ce1af25d9 | triage T1091 step 6 | esql | {"query": "FROM logs-windows.other-default METADATA _id, _index \| WHERE event.code == \"7045\" OR event.code == \"6\" OR event.code == \"2004\" \| KEEP @timestamp, host.name, win.ServiceName, win.ImagePath, win.RuleName, message, _id, _index \| LIMIT 20"} | 20 | F10 |
| q-ebbd35be8f | triage T1091 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOx9LTM_"} | None |  |
| q-864d1e5f5e | triage T1091 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOx9LTM_"} | None |  |
| q-c3d9835ea6 | triage T1091 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOow2-WM"} | None |  |
| q-bdefa7b5a3 | triage T1091 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOow2-WM"} | None |  |
| q-d6bd072dbd | triage T1091 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtk0ckI"} | None |  |
| q-24d426d93d | triage T1091 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOoQYU2W"} | None |  |
| q-241b2f1a80 | triage T1091 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOoQYU2W"} | None |  |
| q-98dcd242df | triage T1091 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO1pngJa"} | None |  |
| q-3e29d56c50 | triage T1091 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO1pngI-"} | None |  |
| q-ef47cc2141 | triage T1091 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOyDSG5g"} | None |  |
| q-5e82c5348d | triage T1091 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO1pngJ4"} | None |  |
| q-ad5adb1ee9 | triage T1210 step 1 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Invoke-Shellcode* OR win.ScriptBlockText:*DownloadString* OR win.ScriptBlockText:*IEX*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.… | 1 |  |
| q-0c93a296c3 | triage T1210 step 1 | search | {"dataset": "windows.security", "query": "event.code:4624 AND win.LogonType:10", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line"… | 2 |  |
| q-77c917478b | triage T1210 step 1 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4624 AND win.LogonType:3", "time_from": null, "time_to": null, "size": 30, "sub_field": "host.name"} | 218 |  |
| q-bc5e190d3d | triage T1210 step 1 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND process.parent.executable:*PSEXESVC*", "time_from": null, "time_to": null, "size": 30, "sub_field": "host.name"} | 4 |  |
| q-733c56f505 | triage T1210 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND process.parent.executable:*PSEXESVC*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "proces… | 4 | F11 |
| q-2b13d4317b | triage T1210 step 2 | search | {"dataset": "windows.security", "query": "event.code:4624 AND win.LogonType:3 AND win.TargetUserName:pbeesly", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.execu… | 20 | F13 |
| q-d559ed1872 | triage T1210 step 2 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3V55ui"} | None | F12 |
| q-67082f3ef2 | triage T1210 step 3 | search | {"dataset": "windows.sysmon", "query": "event.code:3 AND process.executable:*python.exe", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.comm… | 348 |  |
| q-09ea63418b | triage T1210 step 3 | search | {"dataset": "windows.security", "query": "event.code:4624 AND win.LogonType:3 AND win.TargetUserName:pbeesly AND host.name:nashua.dmevals.local", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event… | 13 |  |
| q-d9865c85f0 | triage T1210 step 3 | aggregate | {"dataset": "windows.sysmon", "field": "win.SourceIp", "query": "event.code:3 AND destination.port:445", "time_from": null, "time_to": null, "size": 20, "sub_field": "host.name"} | 66 |  |
| q-de1dce8241 | triage T1210 step 4 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOyCQ37P"} | None | F11, F13 |
| q-6a7349a802 | triage T1210 step 4 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO0Gh1d1"} | ERROR |  |
| q-d6c89dc5fa | triage T1210 step 5 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO0Gh1d1"} | None | F11 |
| q-71f1f22e18 | triage T1210 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO1pngK-"} | None |  |
| q-1e70434f64 | triage T1210 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO1pngK-"} | None |  |
| q-7df18696e6 | triage T1210 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOyESnYY"} | None |  |
| q-8a25a9d0c1 | triage T1210 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOyESnYY"} | None |  |
| q-0367c8f92d | triage T1210 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOyCQ37P"} | None |  |
| q-9b826e8aa1 | triage T1210 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOyCQ37P"} | None |  |
| q-4695c13bec | triage T1210 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO0Gh1d1"} | None |  |
| q-1297444a61 | triage T1210 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO0Gh1d1"} | None |  |
| q-08af7bc53d | triage T1210 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3V55ui"} | None |  |
| q-2a825e15ed | triage T1210 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3V55ui"} | None |  |
| q-b0475de7d6 | triage T1210 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO39XK4V"} | None |  |
| q-0d19cb7058 | triage T1210 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOyCQ37P"} | None |  |
| q-1331b49ab4 | triage T1534 step 1 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == 4104 AND (win.ScriptBlockText LIKE \"*http*\" OR win.ScriptBlockText LIKE \"*DownloadFile*\" OR win.ScriptBlockText LIKE \"*Invoke-WebRequest*\") \| KEEP @timestamp, ho… | ERROR |  |
| q-69e3a5e58d | triage T1534 step 1 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == 4624 AND win.TargetUserName == \"pbeesly\" \| KEEP @timestamp, host.name, win.TargetUserName, win.LogonType, win.IpAddress, win.Workstation, win.LogonProcessName, win.Aut… | ERROR |  |
| q-335ac98a0d | triage T1534 step 2 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (win.ScriptBlockText LIKE \"*http*\" OR win.ScriptBlockText LIKE \"*DownloadFile*\" OR win.ScriptBlockText LIKE \"*Invoke-WebRequest*\") \| KEEP @timestamp… | 10 |  |
| q-7c9757769f | triage T1534 step 2 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4624\" AND win.TargetUserName == \"pbeesly\" \| KEEP @timestamp, host.name, win.TargetUserName, win.LogonType, win.IpAddress, win.Workstation, win.LogonProcessName, win… | 30 | F14 |
| q-3d58c48516 | triage T1534 step 3 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3Pzp3U"} | None | F14 |
| q-913e1118a4 | triage T1534 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" \| KEEP @timestamp, host.name, user.name, process.executable, process.command_line, process.parent.executable, _id, _index \| SORT @timestamp ASC"} | 447 | F14 |
| q-12aea6cea9 | triage T1534 step 4 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4624\" AND win.LogonType IN (\"3\",\"10\") AND win.TargetUserName != \"SYSTEM\" AND win.TargetUserName != \"NEWYORK$\" AND win.TargetUserName != \"SCRANTON$\" AND win.T… | 22 |  |
| q-575f61245c | triage T1534 step 4 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"5140\",\"5145\",\"7045\",\"4697\") OR (event.code == \"4688\" AND (process.command_line LIKE \"*\\\\\\\\*\" OR process.command_line LIKE \"*net use*\" OR process.comma… | 500 |  |
| q-9303efaaf2 | triage T1534 step 5 | esql | {"query": "FROM logs-windows.other-default METADATA _id, _index \| WHERE event.code == \"7045\" OR event.code == \"7040\" OR event.code == \"1074\" \| KEEP @timestamp, host.name, user.name, event.code, win.ServiceName, win.ImagePath, win.ServiceStartType, win.… | ERROR |  |
| q-a7eeff6364 | triage T1534 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"3\" AND (destination.port == 445 OR destination.port == 5985 OR destination.port == 135 OR destination.port == 3389) \| KEEP @timestamp, host.name, user.name, process.exe… | 145 |  |
| q-93dc88af6d | triage T1534 step 6 | esql | {"query": "FROM logs-windows.other-default METADATA _id, _index \| WHERE event.code == \"7045\" OR event.code == \"7040\" OR event.code == \"1074\" \| KEEP @timestamp, host.name, user.name, event.code, win.ServiceName, win.ImagePath, message, _id, _index"} | 10 | F14 |
| q-3b89ff52a7 | triage T1534 step 6 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND host.name == \"nashua.dmevals.local\" \| KEEP @timestamp, host.name, user.name, win.ScriptBlockText, _id, _index \| SORT @timestamp ASC"} | 11 | F14 |
| q-9d9237fae1 | triage T1534 step 7 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOyETHZ1"} | None | F14 |
| q-d94fbdef81 | triage T1534 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOx-Nf0f"} | None |  |
| q-69f3a3c91b | triage T1534 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOx-Nf0f"} | None |  |
| q-fcfe2b879d | triage T1534 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOx6IsLb"} | None |  |
| q-81fc1cb77c | triage T1534 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOyETHZ1"} | None |  |
| q-9439af669a | triage T1534 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO32OAa5"} | None |  |
| q-59480736a8 | triage T1534 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO32OAa5"} | None |  |
| q-b52c32c3dd | triage T1534 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO1pngK-"} | None |  |
| q-6dce4c89d2 | triage T1534 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO1pngJ4"} | None |  |
| q-7e7ac9747f | triage T1534 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3IwxnV"} | None |  |
| q-19421a45ae | triage T1534 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3Pzp3U"} | None |  |
| q-c8e95e41b4 | triage T1550 step 1 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO0NmmRM"} | None | F16 |
| q-8d59328df4 | triage T1550 step 1 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtGQk7R"} | None | F15 |
| q-ecb155823f | triage T1550 step 1 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO31NCqL"} | None | F15 |
| q-48ea8ae07d | triage T1550 step 2 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == 4624 AND win.AuthenticationPackageName == \"Kerberos\" \| STATS c = COUNT(*) BY host.name, win.TargetUserName, win.LogonType, win.LogonProcessName, win.IpAddress \| SORT … | ERROR |  |
| q-9c8a90092d | triage T1550 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE host.name == \"nashua.dmevals.local\" AND event.code == 1 \| KEEP @timestamp, user.name, process.executable, process.command_line, process.parent.executable, _id, _index \| SORT @timesta… | ERROR |  |
| q-e892c02ea4 | triage T1550 step 3 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4624\" AND win.AuthenticationPackageName == \"Kerberos\" \| STATS c = COUNT(*) BY host.name, win.TargetUserName, win.LogonType, win.LogonProcessName, win.IpAddress \| S… | 15 |  |
| q-335e28ae28 | triage T1550 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE host.name == \"nashua.dmevals.local\" AND event.code == \"1\" \| KEEP @timestamp, user.name, process.executable, process.command_line, process.parent.executable, _id, _index \| SORT @tim… | 40 |  |
| q-c43caa63ef | triage T1550 step 4 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4624\" AND win.TargetUserName == \"pbeesly\" \| KEEP @timestamp, host.name, win.LogonType, win.AuthenticationPackageName, win.LogonProcessName, win.IpAddress, win.Works… | 30 | F17 |
| q-76648f8779 | triage T1550 step 4 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4648\" AND win.TargetUserName == \"pbeesly\" \| KEEP @timestamp, host.name, win.ProcessName, win.TargetServerName, win.SubjectUserName, win.TargetLogonGuid, _id, _index… | 9 |  |
| q-2f730899e6 | triage T1550 step 5 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO31NSq9"} | None | F15 |
| q-c37a5d6f1a | triage T1550 step 5 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE host.name == \"scranton.dmevals.local\" AND @timestamp >= \"2020-05-02T03:19:00.000Z\" AND @timestamp <= \"2020-05-02T03:22:00.000Z\" AND event.code IN (\"4624\",\"4648\",\"4672\",\"46… | 40 |  |
| q-6da7a9eea0 | triage T1550 step 6 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO3mCUhV"} | None | F16 |
| q-e882dc05ab | triage T1550 step 6 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE host.name == \"scranton.dmevals.local\" AND @timestamp >= \"2020-05-02T03:19:30.000Z\" AND @timestamp <= \"2020-05-02T03:22:00.000Z\" AND event.code IN (\"1\",\"3\") \| KEEP @timestamp, … | 40 |  |
| q-6fcc3b9451 | triage T1550 step 7 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOyESnYY"} | None | F15 |
| q-147609f290 | triage T1550 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtGQk7R"} | None |  |
| q-b751f2a49a | triage T1550 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO31NSq9"} | None |  |
| q-fef4f54c9a | triage T1550 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO1pngK-"} | None |  |
| q-9a9c5221eb | triage T1550 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO31NCqL"} | None |  |
| q-3b3c6756e5 | triage T1550 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOyESnYY"} | None |  |
| q-99f2248cf5 | triage T1550 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO0NmmRM"} | None |  |
| q-f6ef3870f3 | triage T1550 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO0NmmRM"} | None |  |
| q-519badc2a9 | triage T1550 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO3mCUhV"} | None |  |
| q-bccb52364f | triage T1550 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO0Gh1d1"} | ERROR |  |
| q-5917fba950 | triage T1550 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO32OAa5"} | None |  |
| q-625c1feebc | triage T1550 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO31NirV"} | None |  |
| q-38c1038fbe | triage T1550 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO0EfrJ2"} | ERROR |  |
| q-e4bb2dced5 | triage T1550 step 9 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO0Gh1d1"} | ERROR |  |
| q-ec96363bc2 | triage T1550 step 9 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO0EfrJ2"} | ERROR |  |
| q-38fc71532c | triage T1550 step 10 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4624\" AND win.LogonType == \"10\" \| KEEP @timestamp, host.name, win.TargetUserName, win.LogonType, win.AuthenticationPackageName, win.IpAddress, win.WorkstationName, … | 2 | F16 |
| q-f3bf07fb95 | triage T1550 step 10 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4624\" AND win.AuthenticationPackageName == \"Kerberos\" AND win.TargetUserName == \"NEWYORK$\" \| KEEP @timestamp, host.name, win.TargetUserName, win.LogonType, win.Lo… | 5 | F17 |
| q-17b34e6972 | triage T1563 step 1 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO0Gh1d1"} | None | F18 |
| q-5c11dd1922 | triage T1563 step 1 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOodjOPq"} | None | F19 |
| q-0163d0c775 | triage T1563 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:3 AND destination.port:3389", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line"… | 1 |  |
| q-4b47d18737 | triage T1563 step 1 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == 4104 AND (TO_LOWER(win.ScriptBlockText) LIKE \"*tscon*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*query session*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*qwinsta*\") … | ERROR |  |
| q-e1edc5c635 | triage T1563 step 2 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*tscon*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*query session*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*qwinsta*… | 0 |  |
| q-461eb8db51 | triage T1563 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOoUcuTN"} | None | F18 |
| q-4f62c66737 | triage T1563 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*tscon*\" OR TO_LOWER(process.command_line) LIKE \"*qwinsta*\" OR TO_LOWER(process.command_line) LIKE \"*query session*\" O… | 1 |  |
| q-1f463d76d8 | triage T1563 step 3 | esql | {"query": "FROM logs-windows.other-default METADATA _id, _index \| WHERE event.code == \"98\" OR event.code == \"1500\" OR event.code == \"1074\" OR event.code == \"10148\" OR event.code == \"10149\" OR event.code == \"258\" OR event.code == \"32\" OR event.co… | 14 | F18 |
| q-ed2991b2d6 | triage T1563 step 4 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO3mCUhV"} | None | F19 |
| q-ba660b10bc | triage T1563 step 4 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4778\" OR event.code == \"4779\" OR event.code == \"4634\" AND win.LogonType == \"10\" \| KEEP @timestamp, host.name, event.code, user.name, win.LogonType, _id, _index … | 0 |  |
| q-200133e9a5 | triage T1563 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOoUcuTN"} | None |  |
| q-dc491a8089 | triage T1563 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOoUcuTN"} | None |  |
| q-23e58f6465 | triage T1563 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO1pngKZ"} | None |  |
| q-6b9e8aee0b | triage T1563 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO1pngJS"} | None |  |
| q-fbbf247bb7 | triage T1563 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO0Gh1d1"} | None |  |
| q-fd1cf954ed | triage T1563 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO0Gh1d1"} | None |  |
| q-62eb8afcad | triage T1563 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOodjOPq"} | None |  |
| q-c20eb7f309 | triage T1563 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOodjOPq"} | None |  |
| q-b46a4b063e | triage T1563 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOodjOPq"} | None |  |
| q-65a0a2a0a4 | triage T1563 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO3mCUhV"} | None |  |
| q-adb30d6243 | triage T1563 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO3mCUhV"} | None |  |
| q-40e9a6a695 | triage T1570 step 1 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtGQk7R"} | None | F20 |
| q-9aee79e2ce | triage T1570 step 1 | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO1pngK-"} | None | F20 |
| q-deccb5d893 | triage T1570 step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 11 AND (TO_LOWER(win.TargetFilename) LIKE \"*psexesvc*\" OR TO_LOWER(win.TargetFilename) LIKE \"*python.exe*\" OR TO_LOWER(win.TargetFilename) LIKE \"*\\\\\\\\*\") \| KEEP … | ERROR |  |
| q-2e40815591 | triage T1570 step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 1 AND (TO_LOWER(process.executable) LIKE \"*psexec*\" OR TO_LOWER(process.executable) LIKE \"*python*\" OR TO_LOWER(process.command_line) LIKE \"*psexesvc*\") \| KEEP @time… | ERROR |  |
| q-accec595b2 | triage T1570 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(win.TargetFilename) LIKE \"*psexesvc*\" OR TO_LOWER(win.TargetFilename) LIKE \"*python.exe*\" OR TO_LOWER(win.TargetFilename) LIKE \"*\\\\\\\\*\") \| K… | 500 |  |
| q-9907a0be86 | triage T1570 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.executable) LIKE \"*psexec*\" OR TO_LOWER(process.executable) LIKE \"*python*\" OR TO_LOWER(process.command_line) LIKE \"*psexesvc*\" OR TO_LOWE… | 13 | F20 |
| q-77f71f449d | triage T1570 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE host.name == \"nashua.dmevals.local\" AND (TO_LOWER(win.TargetFilename) LIKE \"*python*\" OR TO_LOWER(win.TargetFilename) LIKE \"*psexesvc*\" OR TO_LOWER(win.TargetFilename) LIKE \"*temp… | 81 | F20 |
| q-03e1eb80e5 | triage T1570 step 3 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"5145\" AND (TO_LOWER(win.RelativeTargetName) LIKE \"*python*\" OR TO_LOWER(win.RelativeTargetName) LIKE \"*psexesvc*\" OR TO_LOWER(win.ShareName) LIKE \"*admin$*\" OR T… | 65 | F21 |
| q-2021e2eaa1 | triage T1570 step 4 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtHRU4I"} | None | F20 |
| q-bce1fa5413 | triage T1570 step 4 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO30MFg4"} | None | F20 |
| q-b986a07e20 | triage T1570 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtGQk7R"} | None |  |
| q-e628c3d660 | triage T1570 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtHRU4I"} | None |  |
| q-9ab5616c30 | triage T1570 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO30MFg4"} | None |  |
| q-f4689fa171 | triage T1570 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO30MFg4"} | None |  |
| q-e0ed6fc4dd | triage T1570 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO1pngK-"} | None |  |
| q-a8f611d030 | triage T1570 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOyESnYY"} | None |  |
| q-0177bc9d6f | triage T1570 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOyGVVIU"} | None |  |
| q-2b8db47b6f | triage T1570 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO0EfrKJ"} | None |  |
| q-dd2a776af3 | triage T1570 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO3cAP3I"} | None |  |
| q-e99be848b1 | triage T1570 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO39W66K"} | None |  |
| q-1372de2d5e | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3IxM8t"} | None |  |
| q-bbe8ad126f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtGQk7R"} | None |  |
| q-9f23955bb5 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO1pngK-"} | None |  |
| q-fda92feaaa | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOyESnYY"} | None |  |
| q-11a721753a | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO31Nirr"} | None |  |
| q-628deaef16 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO31NCqL"} | None |  |
| q-b85a9ec788 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3HwqHA"} | None |  |
| q-2e66ef29ec | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOyETHZ1"} | None |  |
| q-ef0ab5a932 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOyETHZ2"} | None |  |
| q-b5ac01e210 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZJWiSVpshTO2e9KT-"} | None |  |
| q-7847e1f38b | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO0Gh1d1"} | None |  |
| q-bddbf7c386 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO0Gh1d1"} | None |  |
| q-b6bfd0eab7 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO3mCUhV"} | None |  |
| q-2366768df8 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO0Gh1d1"} | None |  |
| q-ea9502ab13 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO1pngJg"} | None |  |
| q-3831f8e6aa | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO1pngJA"} | None |  |
| q-2454f4e7e6 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO0Gh1d1"} | None |  |
| q-3414c52f03 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO0Gh1d1"} | None |  |
| q-8bf0b156da | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO0Gh1d1"} | None |  |
| q-bcc0f6c73c | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO0Gh1d1"} | None |  |
| q-f20a65fafc | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtGQk7R"} | None |  |
| q-51b4a5f92f | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3JxTEc"} | None |  |
| q-073026652a | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3HwqHA"} | None |  |
| q-9acb030103 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO1pngK-"} | None |  |
| q-59c1ee24f9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOyESnYY"} | None |  |
| q-e48a6a906e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOyESXbs"} | None |  |
| q-0502916b92 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO1pngIR"} | None |  |
| q-b5e535ccde | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOou0mUT"} | None |  |
| q-41c9820170 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtk0ckj"} | None |  |
| q-de6580d9eb | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZJWiSVpshTO037K8M"} | None |  |
| q-aab2fd953a | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO31NyoI"} | None |  |
| q-c044aedbdd | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO31NyoI"} | None |  |
| q-02e7d7751b | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO31NyoI"} | None |  |
| q-8f9851ef0c | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO31NyoI"} | None |  |
| q-94b5799fc0 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO31NyoH"} | None |  |
| q-3a22619fa2 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO31Nirr"} | None |  |
| q-f3256530c8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtGQk7R"} | None |  |
| q-25c9e5b30b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOyESnYY"} | None |  |
| q-744d908eac | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOyESnYY"} | None |  |
| q-675c2ba9dd | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3IxM8t"} | None |  |
| q-09b8128449 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3AvzkC"} | None |  |
| q-ef7bfa26b3 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO3_ZDTc"} | None |  |
| q-38ca4cc42e | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO3_ZDTc"} | None |  |
| q-f2ef2e0ade | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO0EfrKJ"} | None |  |
| q-2ddd0d9ed2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtfu-5W"} | None |  |
| q-20a5481120 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtfu-5W"} | None |  |
| q-ad01520823 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZJWiSVpshTO03669U"} | None |  |
| q-ce64daac40 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZJWiSVpshTO03669U"} | None |  |
| q-d5c9d123b5 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOx5IMzh"} | None |  |
| q-e07402531b | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO1pngIU"} | None |  |
| q-b2797c7a03 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOx9LTM_"} | None |  |
| q-71e3027349 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOx9LTM_"} | None |  |
| q-7ba162834c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOow2-WM"} | None |  |
| q-14e6cf0cb4 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOow2-WM"} | None |  |
| q-a7c74ddbb1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtk0ckI"} | None |  |
| q-97a93d2fdb | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOoQYU2W"} | None |  |
| q-126993a4da | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOoQYU2W"} | None |  |
| q-9e68ff2112 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO1pngJa"} | None |  |
| q-16cf76094d | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO1pngI-"} | None |  |
| q-1aeb32e377 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOyDSG5g"} | None |  |
| q-d0418410e8 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO1pngJ4"} | None |  |
| q-c58d4c9c5b | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO1pngK-"} | None |  |
| q-12eec8e522 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO1pngK-"} | None |  |
| q-26f9d1123b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOyESnYY"} | None |  |
| q-1c276f8886 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOyESnYY"} | None |  |
| q-bf42e37e7c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOyCQ37P"} | None |  |
| q-1b18c11baf | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOyCQ37P"} | None |  |
| q-fcd12705c8 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO0Gh1d1"} | None |  |
| q-2b81a6c37c | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO0Gh1d1"} | None |  |
| q-2ec9320cb4 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3V55ui"} | None |  |
| q-f7716b9a68 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3V55ui"} | None |  |
| q-62423fd34d | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO39XK4V"} | None |  |
| q-f8bab809f3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOyCQ37P"} | None |  |
| q-536a880f4e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOx-Nf0f"} | None |  |
| q-0f7a89a82a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOx-Nf0f"} | None |  |
| q-21065f16cc | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOx6IsLb"} | None |  |
| q-f1a661a53c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOyETHZ1"} | None |  |
| q-b1d586e86d | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO32OAa5"} | None |  |
| q-ef01578612 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO32OAa5"} | None |  |
| q-33f59d9744 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO1pngK-"} | None |  |
| q-634fdaa71f | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO1pngJ4"} | None |  |
| q-fd372f63a5 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3IwxnV"} | None |  |
| q-335a066df6 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3Pzp3U"} | None |  |
| q-6b81f87815 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtGQk7R"} | None |  |
| q-fa8a69d5bd | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO31NSq9"} | None |  |
| q-825640bca9 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO1pngK-"} | None |  |
| q-dbcd10ba4f | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO31NCqL"} | None |  |
| q-3f96f029fd | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOyESnYY"} | None |  |
| q-44088966cb | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO0NmmRM"} | None |  |
| q-06d2851a1f | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO0NmmRM"} | None |  |
| q-abdd5b1be8 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO3mCUhV"} | None |  |
| q-f5cc93d833 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO0Gh1d1"} | None |  |
| q-660efb0ee0 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO32OAa5"} | None |  |
| q-c8859aadc8 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO31NirV"} | None |  |
| q-ecad806772 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO0EfrJ2"} | None |  |
| q-312a7af2b7 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOoUcuTN"} | None |  |
| q-57563a10a4 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOoUcuTN"} | None |  |
| q-d4c53a66ea | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO1pngKZ"} | None |  |
| q-4e1a7f280f | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO1pngJS"} | None |  |
| q-dcb464433b | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO0Gh1d1"} | None |  |
| q-57dda8efed | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO0Gh1d1"} | None |  |
| q-e84c2d742b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOodjOPq"} | None |  |
| q-56cab25197 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOodjOPq"} | None |  |
| q-9a9600c188 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOodjOPq"} | None |  |
| q-205877d074 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO3mCUhV"} | None |  |
| q-4393973e66 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO3mCUhV"} | None |  |
| q-12506ff2e0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtGQk7R"} | None |  |
| q-eea09600ec | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtHRU4I"} | None |  |
| q-7497a162a6 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO30MFg4"} | None |  |
| q-0278ac6532 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO30MFg4"} | None |  |
| q-98193b660a | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO1pngK-"} | None |  |
| q-8fa6d03fff | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOyESnYY"} | None |  |
| q-42746f946b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOyGVVIU"} | None |  |
| q-ce9ecbdca8 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO0EfrKJ"} | None |  |
| q-947304b4d3 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO3cAP3I"} | None |  |
| q-a041e72627 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO39W66K"} | None |  |
| q-51e0e342e6 | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND host.name:\"nashua.dmevals.local\"", "time_from": "2020-05-02T02:54:23+00:00", "time_to": "2020-05-02T03:31:19+00:00", "size": 100, "sub_field": "process.parent.executable"… | 61 |  |
| q-e10d2164b4 | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11 AND host.name:\"nashua.dmevals.local\"", "time_from": "2020-05-02T02:54:23+00:00", "time_to": "2020-05-02T03:31:19+00:00", "size": 100, "sub_field": "process.executable"} | 249 |  |
| q-4823f10625 | pivot seed | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND host.name:\"nashua.dmevals.local\"", "time_from": "2020-05-02T02:54:23+00:00", "time_to": "2020-05-02T03:31:19+00:00", "size": 100, "sub_field": "process.parent.execut… | 63 |  |
| q-5a04f9b1ba | pivot seed | aggregate | {"dataset": "windows.powershell", "field": "event.code", "query": "host.name:\"nashua.dmevals.local\"", "time_from": "2020-05-02T02:54:23+00:00", "time_to": "2020-05-02T03:31:19+00:00", "size": 100, "sub_field": null} | 192 |  |
| q-04b702e2b7 | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND host.name:\"scranton.dmevals.local\"", "time_from": "2020-05-02T02:40:56.157000+00:00", "time_to": "2020-05-02T03:35:46+00:00", "size": 100, "sub_field": "process.parent.ex… | 359 |  |
| q-6637f78582 | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11 AND host.name:\"scranton.dmevals.local\"", "time_from": "2020-05-02T02:40:56.157000+00:00", "time_to": "2020-05-02T03:35:46+00:00", "size": 100, "sub_field": "process.executable"} | 1276 |  |
| q-51b802766f | pivot seed | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND host.name:\"scranton.dmevals.local\"", "time_from": "2020-05-02T02:40:56.157000+00:00", "time_to": "2020-05-02T03:35:46+00:00", "size": 100, "sub_field": "process.pare… | 370 |  |
| q-e8308fb673 | pivot seed | aggregate | {"dataset": "windows.powershell", "field": "event.code", "query": "host.name:\"scranton.dmevals.local\"", "time_from": "2020-05-02T02:40:56.157000+00:00", "time_to": "2020-05-02T03:35:46+00:00", "size": 100, "sub_field": null} | 8602 |  |
| q-5d1dd17a88 | pivot step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND host.name == \"nashua.dmevals.local\" AND (process.executable LIKE \"*Temp*\" OR process.executable LIKE \"*PSEXESVC*\" OR process.executable LIKE \"*wsmprovhost*… | 14 | F23 |
| q-475ab78b8f | pivot step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND host.name == \"scranton.dmevals.local\" AND (process.parent.executable LIKE \"*powershell*\" OR process.executable LIKE \"*Sysinternals*\" OR process.executable L… | 27 | F23 |
| q-ef336bc315 | pivot step 2 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE host.name == \"nashua.dmevals.local\" AND event.code IN (\"4104\", \"4103\", \"800\") \| KEEP @timestamp, host.name, user.name, event.code, powershell.file.script_block_text, powersh… | ERROR |  |
| q-dc4b389e40 | pivot step 2 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4624\" AND win.logon_type IN (\"3\", \"10\") \| KEEP @timestamp, host.name, user.name, win.logon_type, source.ip, win.logon_process, _id, _index \| SORT @timestamp ASC … | ERROR |  |
| q-d368b70587 | pivot step 3 | get_fields | {"dataset": "windows.powershell", "prefix": ""} | None |  |
| q-1cab859d6e | pivot step 3 | get_fields | {"dataset": "windows.security", "prefix": "win"} | None |  |
| q-9de34185cd | pivot step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE host.name == \"nashua.dmevals.local\" AND event.code == \"4104\" \| KEEP @timestamp, host.name, user.name, event.code, win.ScriptBlockText, _id, _index \| SORT @timestamp ASC \| LIMI… | 11 |  |
| q-e33e8db8bf | pivot step 4 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4624\" AND win.LogonType IN (\"3\", \"10\") \| KEEP @timestamp, host.name, win.TargetUserName, win.LogonType, win.IpAddress, win.LogonProcessName, win.WorkstationName, … | 80 |  |
| q-7d2c09a5aa | pivot step 5 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4624\" AND win.TargetUserName LIKE \"*pbeesly*\" \| KEEP @timestamp, host.name, win.TargetUserName, win.LogonType, win.IpAddress, win.LogonProcessName, win.WorkstationN… | 30 | F22 |
| q-cd7a3e41e3 | pivot step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*pass*\" OR TO_LOWER(file.path) LIKE \"*cred*\" OR TO_LOWER(file.path) LIKE \"*working.zip*\" OR TO_LOWER(file.path) LIKE \"*draft.zi… | 29 |  |
| q-2c6fb15c07 | pivot step 6 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE host.name == \"scranton.dmevals.local\" AND (file.path LIKE \"*PASSWD*\" OR file.path LIKE \"*debug*\" OR process.executable LIKE \"*pspasswd*\" OR process.executable LIKE \"*lsass*\") \… | 30 |  |
| q-7aee9b0b1a | pivot step 6 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"3\" AND (source.ip == \"10.0.1.4\" OR source.ip == \"10.0.1.6\" OR destination.ip == \"10.0.1.4\" OR destination.ip == \"10.0.1.6\") \| KEEP @timestamp, host.name, user.n… | 60 |  |
| q-41056a664e | pivot step 7 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOs4A9h2"} | None |  |
| q-767d56ad54 | pivot step 7 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE host.name == \"newyork.dmevals.local\" AND event.code == \"1\" AND (process.executable LIKE \"*Temp*\" OR process.executable LIKE \"*PSEXESVC*\" OR process.executable LIKE \"*wsmprovhost… | 0 |  |
| q-d0bc2939cf | pivot step 8 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE host.name == \"newyork.dmevals.local\" AND event.code == \"1\" \| KEEP @timestamp, host.name, user.name, process.executable, process.command_line, process.parent.executable, _id, _index … | 18 |  |
| q-2ee417beef | pivot step 8 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE host.name == \"utica.dmevals.local\" AND event.code == \"1\" \| KEEP @timestamp, host.name, user.name, process.executable, process.command_line, process.parent.executable, _id, _index \|… | 9 |  |
| q-e91f00106c | pivot step 9 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE host.name == \"newyork.dmevals.local\" AND event.code == \"4104\" \| KEEP @timestamp, host.name, user.name, event.code, win.ScriptBlockText, _id, _index \| SORT @timestamp ASC \| LIM… | 25 |  |
| q-0b8f1abf06 | pivot step 9 | esql | {"query": "FROM logs-windows.other-default METADATA _id, _index \| WHERE event.code IN (\"7045\", \"7040\") \| KEEP @timestamp, host.name, win.ServiceName, win.ImagePath, win.ServiceFileName, win.ServiceStartType, win.ServiceAccount, event.code, _id, _index \|… | ERROR |  |
| q-f61f572fe9 | pivot step 10 | esql | {"query": "FROM logs-windows.other-default METADATA _id, _index \| WHERE event.code IN (\"7045\", \"7040\") \| KEEP @timestamp, host.name, win.ServiceName, win.ImagePath, win.param1, win.param2, event.code, _id, _index \| SORT @timestamp ASC \| LIMIT 30"} | 9 | F23 |
| q-ee3df1d058 | pivot step 10 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"5140\" OR event.code == \"5145\" \| KEEP @timestamp, host.name, win.TargetUserName, win.ShareName, win.ShareLocalPath, win.RelativeTargetName, win.IpAddress, _id, _inde… | 50 | F22, F23 |
| q-d1b742336e | pivot step 11 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOyBQa1A"} | None |  |
| q-e65c284e58 | pivot step 11 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3JxTei"} | None |  |
| q-da3b4b2c16 | pivot verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO39XK4V"} | None |  |
| q-ee086852f2 | pivot verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO30MVh9"} | None |  |
| q-5cad7c9f64 | pivot verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO39XK4x"} | None |  |
| q-29d5fbaec7 | pivot verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO0Gh1dq"} | ERROR |  |
| q-c7d2d2c76c | pivot step 13 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO0Gh1dq"} | ERROR |  |
| q-0d49fc92fd | pivot step 13 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOyGVFLW"} | None |  |
| q-df2e675470 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3IxM8t"} | None |  |
| q-dcfedafa8a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtGQk7R"} | None |  |
| q-343b9dbe1e | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO1pngK-"} | None |  |
| q-7653eae27f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOyESnYY"} | None |  |
| q-5d4ae4c5b3 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO31Nirr"} | None |  |
| q-ac044e5f5d | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO31NCqL"} | None |  |
| q-6a40e1faaa | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3HwqHA"} | None |  |
| q-5f3647f0cd | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOyETHZ1"} | None |  |
| q-62903fd9a3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOyETHZ2"} | None |  |
| q-7311c481f1 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZJWiSVpshTO2e9KT-"} | None |  |
| q-ee826c6975 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO0Gh1d1"} | None |  |
| q-39cd9e8c10 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO0Gh1d1"} | None |  |
| q-1fedfb4a97 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO3mCUhV"} | None |  |
| q-9ec7e3342a | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO0Gh1d1"} | None |  |
| q-eaf4a47843 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO1pngJg"} | None |  |
| q-0640029cd4 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO1pngJA"} | None |  |
| q-208d0e5187 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO0Gh1d1"} | None |  |
| q-67ce115139 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO0Gh1d1"} | None |  |
| q-d146732147 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO0Gh1d1"} | None |  |
| q-a1b77c2445 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO0Gh1d1"} | None |  |
| q-f8573e4bfb | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtGQk7R"} | None |  |
| q-7c661e8f16 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3JxTEc"} | None |  |
| q-f739b25fa8 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3HwqHA"} | None |  |
| q-c90774df3f | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO1pngK-"} | None |  |
| q-cb483c72f1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOyESnYY"} | None |  |
| q-d49a01b5bb | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOyESXbs"} | None |  |
| q-46a859b5bd | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO1pngIR"} | None |  |
| q-97ec1dbc86 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOou0mUT"} | None |  |
| q-d04975ec54 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtk0ckj"} | None |  |
| q-90dfdd22c7 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZJWiSVpshTO037K8M"} | None |  |
| q-923b8bf929 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO31NyoI"} | None |  |
| q-1dca8ef9a9 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO31NyoI"} | None |  |
| q-761b03ce68 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO31NyoI"} | None |  |
| q-6c1764154e | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO31NyoI"} | None |  |
| q-d6a1775334 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO31NyoH"} | None |  |
| q-daa31978ef | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO31Nirr"} | None |  |
| q-bbb648e594 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtGQk7R"} | None |  |
| q-223df7b606 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOyESnYY"} | None |  |
| q-70b4720521 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOyESnYY"} | None |  |
| q-28e96a54c2 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3IxM8t"} | None |  |
| q-ec608a07b5 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3AvzkC"} | None |  |
| q-a49f3793bb | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO3_ZDTc"} | None |  |
| q-96b0b3d5c9 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO3_ZDTc"} | None |  |
| q-45b87a25ea | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO0EfrKJ"} | None |  |
| q-db0d15d5de | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtfu-5W"} | None |  |
| q-a86c20f8e2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtfu-5W"} | None |  |
| q-21e45c68b8 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZJWiSVpshTO03669U"} | None |  |
| q-d119ca3f6e | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZJWiSVpshTO03669U"} | None |  |
| q-49490e97f0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOx5IMzh"} | None |  |
| q-2754c7e7c0 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO1pngIU"} | None |  |
| q-b3f4135ed2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOx9LTM_"} | None |  |
| q-762ffe5df0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOx9LTM_"} | None |  |
| q-0caf605ce6 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOow2-WM"} | None |  |
| q-a260ed3a18 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOow2-WM"} | None |  |
| q-b8549807d3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtk0ckI"} | None |  |
| q-a3cc2cb54d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOoQYU2W"} | None |  |
| q-6aea21a0bf | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOoQYU2W"} | None |  |
| q-771cc71cd4 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO1pngJa"} | None |  |
| q-07d72322ec | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO1pngI-"} | None |  |
| q-aea95a54e2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOyDSG5g"} | None |  |
| q-7ff1fa3aca | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO1pngJ4"} | None |  |
| q-5f68d67fd1 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO1pngK-"} | None |  |
| q-1daab2a861 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO1pngK-"} | None |  |
| q-2dc9b943f9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOyESnYY"} | None |  |
| q-668e0f9690 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOyESnYY"} | None |  |
| q-2e33be638c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOyCQ37P"} | None |  |
| q-ab9be97ecd | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOyCQ37P"} | None |  |
| q-c3dc196695 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO0Gh1d1"} | None |  |
| q-9a2917bada | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO0Gh1d1"} | None |  |
| q-b848c1fc0f | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3V55ui"} | None |  |
| q-308520b572 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3V55ui"} | None |  |
| q-b0bc25ffab | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO39XK4V"} | None |  |
| q-7cde68a208 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOyCQ37P"} | None |  |
| q-54e9328009 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOx-Nf0f"} | None |  |
| q-b7a7d82490 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOx-Nf0f"} | None |  |
| q-b5c83888b5 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOx6IsLb"} | None |  |
| q-1517c7a847 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOyETHZ1"} | None |  |
| q-63ffd433c2 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO32OAa5"} | None |  |
| q-9cfde69e83 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO32OAa5"} | None |  |
| q-c9e617220c | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO1pngK-"} | None |  |
| q-c56bbd405e | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO1pngJ4"} | None |  |
| q-2496077493 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3IwxnV"} | None |  |
| q-1dc810ade7 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3Pzp3U"} | None |  |
| q-afae3a2ddd | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtGQk7R"} | None |  |
| q-24d42e2b9a | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO31NSq9"} | None |  |
| q-0946fca297 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO1pngK-"} | None |  |
| q-a201116eb7 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO31NCqL"} | None |  |
| q-367a73a50e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOyESnYY"} | None |  |
| q-8eed34d6e9 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO0NmmRM"} | None |  |
| q-0ab41ab092 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO0NmmRM"} | None |  |
| q-1195fdd077 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO3mCUhV"} | None |  |
| q-a9cb14d9f0 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO0Gh1d1"} | None |  |
| q-d87a47977b | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO32OAa5"} | None |  |
| q-f7b4cc2f6d | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO31NirV"} | None |  |
| q-5c5e2602b6 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO0EfrJ2"} | None |  |
| q-087d5c6c65 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOoUcuTN"} | None |  |
| q-0b4982cfd0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOoUcuTN"} | None |  |
| q-7f1b399d75 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO1pngKZ"} | None |  |
| q-1a076f0136 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO1pngJS"} | None |  |
| q-8feb6b9dde | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO0Gh1d1"} | None |  |
| q-beffdc28fd | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO0Gh1d1"} | None |  |
| q-7eea1528cd | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOodjOPq"} | None |  |
| q-e825d90ca2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOodjOPq"} | None |  |
| q-c87da44298 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOodjOPq"} | None |  |
| q-53d2520280 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO3mCUhV"} | None |  |
| q-2d9373ca7f | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO3mCUhV"} | None |  |
| q-113a6f341f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtGQk7R"} | None |  |
| q-8a7800cca0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtHRU4I"} | None |  |
| q-2cf3daae5e | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO30MFg4"} | None |  |
| q-dda39ce1b1 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO30MFg4"} | None |  |
| q-2c51df05f5 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO1pngK-"} | None |  |
| q-a203a41a91 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOyESnYY"} | None |  |
| q-d204abf014 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOyGVVIU"} | None |  |
| q-161539c282 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO0EfrKJ"} | None |  |
| q-ae4be54d00 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO3cAP3I"} | None |  |
| q-d1ba94724f | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO39W66K"} | None |  |
| q-a121963ced | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO39XK4V"} | None |  |
| q-dec441838c | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO30MVh9"} | None |  |
| q-9c597614ba | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO39XK4x"} | None |  |
| q-601c13843f | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO32OQZ1"} | None |  |
| q-d0b4c5f156 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtGQk7R"} | None |  |
| q-7de45ceaf9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOyESnYY"} | None |  |
| q-cdaf4ad00f | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO1pngK-"} | None |  |
| q-8c28072ba1 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO31NyoH"} | None |  |

## Verification

Evidence items cited: 124; confirmed against the stored events: 124; rejected: 0. Each item was re-fetched with get_event; it is confirmed only if the event exists, the cited field holds the cited value, and the cited query_id is a query of this run that returned that event.
Evidence sent back to the agents for correction during the run: 6 item(s) in 4 submission(s) (one correction round each; what still failed was rejected).

## Limitations

- Findings describe what the stored logs show; activity these sources did not log cannot be seen.
- Datasets with non-overlapping time windows (see Data examined) were analysed separately.
- Long field values are shortened in this report; full events are retrievable by _index/_id.
