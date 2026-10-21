# Threat hunt report — 20261020-203014-converged-fixab-lateral

**Hypothesis:** An adversary who compromised Windows hosts in this network moved laterally from them to other hosts in the network (MITRE ATT&CK tactic: Lateral Movement).

**Verdict: Confirmed** — 5 in-scope incident(s) of verified malicious findings (confidence >= medium): I03 T1021.002 (F01, F07, F11, F16, F18), I05 T1021.006 (F02, F12), I06 T1072 (F31), I08 T1570 (F23), I09 T1570 (F27)

Verdict method: rules over verified evidence (Confirmed if >=1 in-scope incident of verified malicious findings (confidence >= medium); Inconclusive if only suspicious incidents or coverage gaps; Refuted if full coverage and no malicious/suspicious finding)

| Run | Value |
|---|---|
| Profile | converged (thinking=False, temperature=0.0) |
| Model | deepseek-flash |
| Started / finished (UTC) | 2026-10-20T12:30:14+00:00 / 2026-10-20T12:35:05+00:00 (290.7 s) |
| LLM calls / tokens | 78 / {'prompt': 2200914, 'completion': 62560} |
| MCP tool calls | 653 (server tools: list_data_sources, get_fields, search, count, aggregate, timeline, esql, get_event, get_registry) |
| ATT&CK tactics | lateral-movement — An adversary with existing access to compromised Windows hosts is using remote execution or authentication mechanisms to pivot to additional hosts on the network. |

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
| I01 | T1021.001 | yes | suspicious/low | F03 | RDP logon (LogonType 10) as pbeesly on SCRANTON from 172.18.39.2 |
| I02 | T1021.001 | yes | suspicious/medium | F28 | pbeesly interactive (LogonType 2) sessions on NASHUA following each PsExec network logon |
| I03 | T1021.002 | yes | malicious/high | F01, F07, F11, F16, F18 | PsExec over SMB ADMIN$ from SCRANTON to NASHUA with cleartext credentials, repeated 4x |
| I04 | T1021.002 | yes | suspicious/medium | F26 | pbeesly network logons to NEWYORK (DC) from SCRANTON with IPC$ access |
| I05 | T1021.006 | yes | malicious/high | F02, F12 | WinRM (port 5985) remote shell from SCRANTON to NASHUA for session/process enumeration |
| I06 | T1072 | yes | malicious/high | F31 | Attacker tooling on SCRANTON: sdclt/csc payload compilation, hostui.exe and sdelete cleanup |
| I07 | T1550.002 | yes | suspicious/medium | F19 | Single NTLM network logon for pbeesly on SCRANTON consistent with PsExec auth |
| I08 | T1570 | yes | malicious/high | F23 | PsExec tool transfer from SCRANTON to NASHUA via ADMIN$ share (PSEXESVC.exe + python.exe dropped) |
| I09 | T1570 | yes | malicious/high | F27 | Tool transfer onto NASHUA: python.exe, Rar.exe and sdelete64.exe written to C:\Windows\Temp and executed |
| I10 | T1570 | yes | suspicious/medium | F29 | Sysinternals suite downloaded to SCRANTON and accessChk.exe run for permission enumeration |
| I11 | out-of-scope:T1027 | no | malicious/high | F14 | Steganographic PowerShell loader (monkey.png) on SCRANTON |
| I12 | out-of-scope:T1048 | no | suspicious/medium | F25 | PowerShell Invoke-Exfil script on SCRANTON copies archive to remote WebDAV share |
| I13 | out-of-scope:T1560 | no | malicious/high | F13 | Post-access collection and RAR archiving on NASHUA via the remote shell |

## Findings

### F01 · malicious / high · T1021.002 · PsExec over SMB ADMIN$ from SCRANTON to NASHUA with cleartext credentials, repeated 4x

Evidence status: **verified**

On 2020-05-02 between 03:11:18 and 03:14:42 UTC, user DMEVALS\pbeesly on scranton.dmevals.local (10.0.1.4) launched C:\Program Files\SysinternalsSuite\PsExec64.exe from a PowerShell parent four times, each time targeting \\NASHUA with the password supplied on the command line (-u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe). On nashua.dmevals.local the PSEXESVC service was installed four times (7045) and 4648 explicit-credential logons were recorded with process C:\Windows\PSEXESVC.exe, and ADMIN$ (\\*\ADMIN$, Share Path \??\C:\windows) was accessed from source 10.0.1.4 by pbeesly. This is classic SMB/admin-share lateral movement with remote service creation and execution of a payload from C:\Windows\Temp.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:18.784Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\PsExec64.exe" -accepteula \\NASHUA -u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7cxoQzx | q-dad3c51741 | ok |
| 2 | 2020-05-02 03:11:18.784Z | scranton.dmevals.local | windows.sysmon | process.parent.executable | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7cxoQzx | q-dad3c51741 | ok |
| 3 | 2020-05-02 03:11:18.000Z | scranton.dmevals.local | windows.powershell | process.command_line | .\PsExec64.exe -accepteula \\NASHUA -u "dmevals\pbeesly" -p "Fl0nk3rt0n!T0by" -i 2 "C:\Windows\Temp\python.exe" | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qrRFHq | q-d834c4cc01 | ok |
| 4 | 2020-05-02 03:11:39.000Z | nashua.dmevals.local | windows.other | win.ServiceName | PSEXESVC | .ds-logs-windows.other-default-2026.10.20-000001 / AaFZR_JfH5wFd7pNHuCk | q-9276a6f139 | ok |
| 5 | 2020-05-02 03:11:18.000Z | nashua.dmevals.local | windows.security | win.ShareName | \\*\ADMIN$ | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7niyNvI | q-4e3249cc6c | ok |
| 6 | 2020-05-02 03:11:40.000Z | nashua.dmevals.local | windows.security | process.executable | C:\Windows\PSEXESVC.exe | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7niyNur | q-ac9203fe22 | ok |

### F30 · malicious / high · T1021.002 · PsExec64.exe with cleartext pbeesly credentials from SCRANTON to NASHUA (re-confirmed) and sdelete cleanup

Evidence status: **NOT verified (2/3 evidence items)** — excluded from the verdict

PsExec64.exe was run four times from PowerShell on SCRANTON (03:11:18, 03:12:25, 03:13:28, 03:14:42) with pbeesly's cleartext password to launch C:\Windows\Temp\python.exe on NASHUA; afterwards sdelete64.exe was used to wipe the stager and the downloaded tooling.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:18.784Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\PsExec64.exe" -accepteula \\NASHUA -u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7cxoQzx | q-3b9e093c52 | ok |
| 2 | 2020-05-02 03:11:18.784Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\Program Files\SysinternalsSuite\PsExec64.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7cxoQzx | q-3b9e093c52 | ok |
| 3 |  | None | None | process.command_line | "C:\Program Files\SysinternalsSuite\sdelete64.exe" /accepteula C:\programdata\victim\???cod.3aka3.scr | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7WVSlm | q-3b9e093c52 | FAILED: cited query did not return this event; event not found |

### F02 · malicious / medium · T1021.006 · PowerShell remoting (WinRM) from SCRANTON to NASHUA to enumerate sessions

Evidence status: **verified**

At 2020-05-01T23:09:23 (03:09:23 UTC) on scranton.dmevals.local, pbeesly ran Invoke-Command -ComputerName NASHUA to enumerate processes/sessions of the same user on the remote host. Sysmon recorded the matching outbound TCP connections from powershell.exe (PID 3852, 10.0.1.4) to 10.0.1.6 on port 5985 at 03:09:23-03:09:29, with the reciprocal inbound connections logged on nashua.dmevals.local. This WinRM reconnaissance immediately preceded the PsExec lateral movement to the same target.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:09:23.000Z | scranton.dmevals.local | windows.powershell | process.command_line | Invoke-Command -ComputerName NASHUA -ScriptBlock { Get-Process -IncludeUserName \| Select-Object UserName,SessionId \| Where-Object { $_.UserName -like "*\$env:… | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qrRbzS | q-d834c4cc01 | ok |
| 2 | 2020-05-02 03:09:23.801Z | scranton.dmevals.local | windows.sysmon | destination.ip | 10.0.1.6 | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7c-4MbN | q-a95c00adfc | ok |
| 3 | 2020-05-02 03:09:23.881Z | nashua.dmevals.local | windows.sysmon | host.name | nashua.dmevals.local | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7c-4MbP | q-a95c00adfc | ok |

### F07 · malicious / high · T1072 · PsExec used from scranton to deploy and run C:\Windows\Temp\python.exe on nashua (lateral movement)

Evidence status: **verified**

On 2020-05-02 between 03:11:18 and 03:15:03 UTC, user pbeesly on scranton.dmevals.local repeatedly launched C:\Program Files\SysinternalsSuite\PsExec64.exe from powershell.exe with the command line "C:\Program Files\SysinternalsSuite\PsExec64.exe" -accepteula \\NASHUA -u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe (four executions: 03:11:18, 03:12:25, 03:13:28, 03:14:42). Each execution caused the PSEXESVC service to be installed on nashua.dmevals.local (event 7045, Service File Name %SystemRoot%\PSEXESVC.exe, LocalSystem, demand start) and PSEXESVC.exe to start under services.exe, which then spawned C:\Windows\Temp\python.exe as pbeesly (03:11:40, 03:12:46, 03:13:49, 03:15:03). The python.exe process wrote a BAM UserSettings registry value for its own path, confirming execution. This is abuse of a software-deployment/remote-execution tool to move laterally from a compromised host (scranton, where sdelete64.exe was used to wipe C:\programdata\victim\???cod.3aka3.scr and other files) to nashua, with credentials passed in cleartext on the command line. No SCCM/Intune/SMS deployment-agent activity was observed (C059 zero hits); the deployment-tool artifact here is PsExec.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:18.784Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\PsExec64.exe" -accepteula \\NASHUA -u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7cxoQzx | q-10e292fc55 | ok |
| 2 | 2020-05-02 03:11:39.934Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\Windows\PSEXESVC.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7c82Oiy | q-10e292fc55 | ok |
| 3 | 2020-05-02 03:11:40.213Z | nashua.dmevals.local | windows.sysmon | process.parent.executable | C:\Windows\PSEXESVC.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7c82OhP | q-10e292fc55 | ok |
| 4 | 2020-05-02 03:11:40.213Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7c82OhP | q-10e292fc55 | ok |
| 5 | 2020-05-02 03:11:39.000Z | nashua.dmevals.local | windows.other | message | A service was installed in the system.    Service Name:  PSEXESVC  Service File Name:  %SystemRoot%\PSEXESVC.exe  Service Type:  user mode service  Service Star… | .ds-logs-windows.other-default-2026.10.20-000001 / AaFZR_JfH5wFd7pNHuCk | q-79877b0035 | ok |
| 6 | 2020-05-02 03:11:18.000Z | scranton.dmevals.local | windows.security | process.command_line | "C:\Program Files\SysinternalsSuite\PsExec64.exe" -accepteula \\NASHUA -u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7niyNv3 | q-8d3838fe54 | ok |
| 7 | 2020-05-02 03:11:40.605Z | nashua.dmevals.local | windows.sysmon | registry.path | HKLM\System\CurrentControlSet\Services\bam\State\UserSettings\S-1-5-21-1830255721-3727074217-2423397540-1107\\Device\HarddiskVolume2\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7h03AJQ | q-5aa2e0cdfa | ok |

### F31 · malicious / high · T1072 · Attacker tooling on SCRANTON: sdclt/csc payload compilation, hostui.exe and sdelete cleanup

Evidence status: **verified**

On SCRANTON the attacker chain ran sdclt.exe three times from cmd.exe (02:58:42-43), compiled payload DLLs with csc.exe from PowerShell (02:58:45 and 03:08:03), ran hostui.exe from PowerShell (03:21:27) and used sdelete64.exe to wipe the stager C:\programdata\victim\???cod.3aka3.scr, Draft.Zip and SysinternalsSuite.zip — the tooling that enabled the lateral movement to NASHUA.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:08:03.260Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe" /noconfig /fullpaths @"C:\Users\pbeesly\AppData\Local\Temp\0piklvia\0piklvia.cmdline" | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hJHlRK | q-3b9e093c52 | ok |
| 2 | 2020-05-02 02:58:45.292Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Users\pbeesly\AppData\Local\Temp\qkbkqqbs\qkbkqqbs.dll | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7htvuyT | q-747e6b9a58 | ok |
| 3 | 2020-05-02 02:58:42.401Z | scranton.dmevals.local | windows.sysmon | process.command_line | C:\windows\system32\sdclt.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7huwtP3 | q-3b9e093c52 | ok |
| 4 | 2020-05-02 03:21:27.276Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Windows\System32\hostui.exe"  | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7YE3lVE | q-3b9e093c52 | ok |
| 5 | 2020-05-02 03:02:04.324Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\sdelete64.exe" /accepteula C:\programdata\victim\???cod.3aka3.scr | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hWVSlm | q-3b9e093c52 | ok |

### F11 · malicious / high · T1091 · Lateral movement present in the data is PsExec over SMB (not removable media) from scranton to nashua

Evidence status: **verified**

While hunting T1091 I found that the actual lateral movement in this window is network-based, not removable-media based: user pbeesly on scranton.dmevals.local repeatedly ran C:\Program Files\SysinternalsSuite\PsExec64.exe with the cleartext credential -u dmevals\pbeesly -p Fl0nk3rt0n!T0by against \\NASHUA to launch C:\Windows\Temp\python.exe (03:11:18Z, 03:12:25Z, 03:13:28Z, 03:14:42Z). On nashua.dmevals.local, C:\Windows\PSEXESVC.exe was created by services.exe and spawned C:\Windows\Temp\python.exe as pbeesly, followed by C:\Windows\Temp\Rar.exe archiving working.zip with password -hpfGzq5yKw and sdelete64.exe wiping Rar.exe, working.zip and Draft.Zip. This is malicious lateral movement/execution, but it is T1021.002/T1570-style SMB service execution, not T1091 replication through removable media, so it does not substantiate the T1091 hypothesis.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:18.784Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\PsExec64.exe" -accepteula \\NASHUA -u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7cxoQzx | q-762b97d6aa | ok |
| 2 | 2020-05-02 03:12:46.846Z | nashua.dmevals.local | windows.sysmon | process.parent.executable | C:\Windows\PSEXESVC.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7cwoB6l | q-762b97d6aa | ok |
| 3 | 2020-05-02 03:16:19.395Z | nashua.dmevals.local | windows.sysmon | process.command_line | "C:\Windows\Temp\Rar.exe" a -hpfGzq5yKw C:\Users\pbeesly\Desktop\working.zip C:\Users\pbeesly\AppData\Roaming\working.zip | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7c4xY6Y | q-762b97d6aa | ok |
| 4 | 2020-05-02 03:17:41.290Z | nashua.dmevals.local | windows.sysmon | process.command_line | .\sdelete64.exe  /accepteula "C:\Users\pbeesly\Desktop\working.zip" | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7c1t6d3 | q-762b97d6aa | ok |
| 5 | 2020-05-02 03:11:39.000Z | nashua.dmevals.local | windows.security | process.executable | C:\Windows\PSEXESVC.exe | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7niyNuP | q-f31bc56ccf | ok |

### F12 · malicious / high · T1210 · WinRM (port 5985) remote-service access from compromised SCRANTON to NASHUA under user pbeesly

Evidence status: **verified**

On 2020-05-02 between 03:09:23 and 03:09:29 UTC, PowerShell (C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe) running as pbeesly on scranton.dmevals.local (10.0.1.4) made four outbound connections to 10.0.1.6 on port 5985 (WinRM). At 03:09:23.885 the same second, nashua.dmevals.local spawned wsmprovhost.exe -Embedding as pbeesly, i.e. the WinRM remote shell was established on the target. windows.security corroborates with Kerberos network logons (LogonType 3) for pbeesly on nashua.dmevals.local sourced from 10.0.1.4 at 23:10:23, 23:11:18, 23:12:25 and 23:13:28 local time. This is remote-service access to a second host, not normal System/SMB traffic (SMB to 10.0.0.4 was exclusively process 'System').

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:09:23.801Z | scranton.dmevals.local | windows.sysmon | destination.port | 5985 | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7c-4MbN | q-64cc0e0433 | ok |
| 2 | 2020-05-02 03:09:23.801Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7c-4MbN | q-64cc0e0433 | ok |
| 3 | 2020-05-02 03:09:23.801Z | scranton.dmevals.local | windows.sysmon | win.SourceIp | 10.0.1.4 | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7c-4MbN | q-64cc0e0433 | ok |
| 4 | 2020-05-02 03:09:23.885Z | nashua.dmevals.local | windows.sysmon | process.command_line | C:\windows\system32\wsmprovhost.exe -Embedding | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7c-4cYK | q-4572768bb8 | ok |
| 5 | 2020-05-02 03:10:23.000Z | nashua.dmevals.local | windows.security | win.IpAddress | 10.0.1.4 | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7niytuv | q-4ffcea3e4d | ok |
| 6 | 2020-05-02 03:10:23.000Z | nashua.dmevals.local | windows.security | win.LogonType | 3 | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7niytuv | q-4ffcea3e4d | ok |

### F13 · malicious / high · T1210 · Post-access interactive collection and RAR archiving on NASHUA via the remote shell

Evidence status: **verified**

Immediately after the WinRM session opened, PowerShell script blocks on nashua.dmevals.local as pbeesly enumerate processes (Get-Process -IncludeUserName), then at 23:15:59 local time recursively collect documents, archives, password/login/admin/VPN-named files and images from the user profile and compress them with Compress-Archive, followed by '.\Rar.exe a -hpfGzq5yKw "$env:USERPROFILE\Desktop\working.zip" "$env:APPDATA\working.zip"' from C:\Windows\Temp at 23:16:19 and 'exit'. This is hands-on-keyboard activity on the newly reached host, consistent with staging data after remote-service access.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:15:59.000Z | nashua.dmevals.local | windows.powershell | win.ScriptBlockText | $env:APPDATA;$files=ChildItem -Path $env:USERPROFILE\ -Include *.doc,*.xps,*.xls,*.ppt,*.pps,*.wps,*.wpd,*.ods,*.odt,*.lwp,*.jtd,*.pdf,*.zip,*.rar,*.docx,*.url,… | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qrRC92 | q-f8c4f2b0a6 | ok |
| 2 | 2020-05-02 03:16:19.000Z | nashua.dmevals.local | windows.powershell | win.ScriptBlockText | .\Rar.exe a -hpfGzq5yKw "$env:USERPROFILE\Desktop\working.zip" "$env:APPDATA\working.zip" | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qrRC-J | q-f8c4f2b0a6 | ok |
| 3 | 2020-05-02 03:16:10.000Z | nashua.dmevals.local | windows.powershell | win.ScriptBlockText | cd C:\Windows\Temp | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qqQm-i | q-f8c4f2b0a6 | ok |
| 4 | 2020-05-02 03:09:28.000Z | nashua.dmevals.local | windows.powershell | win.ScriptBlockText |  Get-Process -IncludeUserName \| Select-Object UserName,SessionId \| Where-Object { $_.UserName -like "*\$env:USERNAME" } \| Sort-Object SessionId -Unique  | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qrRapX | q-f8c4f2b0a6 | ok |

### F14 · malicious / high · T1210 · Steganographic PowerShell loader (monkey.png) on SCRANTON — origin of the lateral movement

Evidence status: **verified**

On scranton.dmevals.local at 2020-05-01 22:58:45 local (2020-05-02T02:58:46Z) a PowerShell 4104 script block as pbeesly decodes a bitmap C:\Users\pbeesly\Downloads\monkey.png into a byte array and executes it with IEX — a known APT29 steganography loader. This is the compromised host from which the WinRM connections to NASHUA (10.0.1.6) later originated, so it is the source of the remote-service access rather than a benign administrative script.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:58:45.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | sal a New-Object;Add-Type -AssemblyName 'System.Drawing'; $g=a System.Drawing.Bitmap('C:\Users\pbeesly\Downloads\monkey.png');$o=a Byte[] 4480;for($i=0; $i -le … | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7q0Y_4v | q-6327629e6d | ok |
| 2 | 2020-05-02 02:58:45.000Z | scranton.dmevals.local | windows.powershell | host.name | scranton.dmevals.local | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7q0Y_4v | q-6327629e6d | ok |

### F16 · malicious / high · T1534 · PsExec lateral movement from SCRANTON to NASHUA using pbeesly's plaintext credentials, followed by python.exe C2 beaconing

Evidence status: **verified**

On 2020-05-02 between 03:11:18Z and 03:15:03Z, user pbeesly on scranton.dmevals.local repeatedly launched Sysinternals PsExec64.exe from a PowerShell parent with the command line "C:\Program Files\SysinternalsSuite\PsExec64.exe" -accepteula \\NASHUA -u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe (4 executions). Each execution installed the PSEXESVC service on nashua.dmevals.local (7045 events at 23:11:39, 23:12:46, 23:13:49, 23:15:03 local time), produced a 4648 explicit-credential logon on NASHUA with Process Name C:\Windows\PSEXESVC.exe using pbeesly's credentials, and spawned C:\Windows\Temp\python.exe as pbeesly under PSEXESVC.exe. That python.exe then made hundreds of outbound connections from nashua.dmevals.local to 192.168.0.4:8443 (348 sysmon event.code 3 records for that image), i.e. the same internal host that served all 62 HTTP requests in the zeek window. Earlier on SCRANTON, pbeesly's PowerShell also ran sdelete64.exe against C:\programdata\victim\???cod.3aka3.scr, Draft.Zip, working.zip, SysinternalsSuite.zip and Rar.exe, indicating staging/anti-forensics around the same intrusion. This is attacker-driven remote execution and credential use across hosts, not normal administration.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:18.784Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\PsExec64.exe" -accepteula \\NASHUA -u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7cxoQzx | q-cd1a654ba3 | ok |
| 2 | 2020-05-02 03:11:18.784Z | scranton.dmevals.local | windows.sysmon | host.name | scranton.dmevals.local | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7cxoQzx | q-cd1a654ba3 | ok |
| 3 | 2020-05-02 03:11:39.000Z | nashua.dmevals.local | windows.other | win.ServiceName | PSEXESVC | .ds-logs-windows.other-default-2026.10.20-000001 / AaFZR_JfH5wFd7pNHuCk | q-51417f146b | ok |
| 4 | 2020-05-02 03:11:39.000Z | nashua.dmevals.local | windows.other | host.name | nashua.dmevals.local | .ds-logs-windows.other-default-2026.10.20-000001 / AaFZR_JfH5wFd7pNHuCk | q-51417f146b | ok |
| 5 | 2020-05-02 03:11:40.000Z | nashua.dmevals.local | windows.security | win.ProcessName | C:\Windows\PSEXESVC.exe | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7niyNur | q-48eefa2cf5 | ok |
| 6 | 2020-05-02 03:11:40.000Z | nashua.dmevals.local | windows.security | win.TargetUserName | pbeesly | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7niyNur | q-48eefa2cf5 | ok |
| 7 | 2020-05-02 03:11:40.213Z | nashua.dmevals.local | windows.sysmon | process.parent.executable | C:\Windows\PSEXESVC.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7c82OhP | q-cd1a654ba3 | ok |
| 8 | 2020-05-02 03:11:40.213Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7c82OhP | q-cd1a654ba3 | ok |
| 9 | 2020-05-02 03:15:05.142Z | nashua.dmevals.local | windows.sysmon | destination.ip | 192.168.0.4 | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7c5ylrT | q-17f7f4e966 | ok |
| 10 | 2020-05-02 03:15:05.142Z | nashua.dmevals.local | windows.sysmon | destination.port | 8443 | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7c5ylrT | q-17f7f4e966 | ok |
| 11 | 2020-05-02 03:02:04.324Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\sdelete64.exe" /accepteula C:\programdata\victim\???cod.3aka3.scr | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hWVSlm | q-cd1a654ba3 | ok |

### F18 · malicious / high · T1550 · PsExec lateral movement from SCRANTON to NASHUA using explicit plaintext credentials for pbeesly

Evidence status: **verified**

On 2020-05-02 between 03:11:18Z and 03:15:03Z, user pbeesly on scranton.dmevals.local repeatedly launched C:\Program Files\SysinternalsSuite\PsExec64.exe with the command line "PsExec64.exe" -accepteula \\NASHUA -u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe (four executions: 03:11:18, 03:12:25, 03:13:28, 03:14:42). Each attempt produced a matching 4648 explicit-credential logon on scranton targeting server NASHUA, a PSEXESVC service installation (7045) on nashua.dmevals.local, a PSEXESVC.exe process creation on nashua running as SYSTEM, and a 4648 on nashua from C:\Windows\PSEXESVC.exe. This is credential-based remote execution/lateral movement to a second host. The same account also ran Invoke-Command -ComputerName NASHUA from scranton at 03:09:23Z, and later used sdelete64.exe on nashua (03:16:52-03:17:41Z) to securely delete Rar.exe and working.zip, indicating anti-forensic cleanup on the target. Note: the credentials were supplied in cleartext (-u/-p), so this is use of known valid credentials rather than reuse of stolen hash/ticket material.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:18.784Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\PsExec64.exe" -accepteula \\NASHUA -u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7cxoQzx | q-4edda752cc | ok |
| 2 | 2020-05-02 03:11:39.000Z | nashua.dmevals.local | windows.other | message | A service was installed in the system.    Service Name:  PSEXESVC  Service File Name:  %SystemRoot%\PSEXESVC.exe  Service Type:  user mode service  Service Star… | .ds-logs-windows.other-default-2026.10.20-000001 / AaFZR_JfH5wFd7pNHuCk | q-a392280f3a | ok |
| 3 | 2020-05-02 03:11:39.934Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\Windows\PSEXESVC.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7c82Oiy | q-4edda752cc | ok |
| 4 | 2020-05-02 03:11:18.000Z | scranton.dmevals.local | windows.security | win.TargetServerName | NASHUA | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7niydsP | q-49cc0800a8 | ok |
| 5 | 2020-05-02 03:09:23.000Z | scranton.dmevals.local | windows.powershell | process.command_line | Invoke-Command -ComputerName NASHUA -ScriptBlock { Get-Process -IncludeUserName \| Select-Object UserName,SessionId \| Where-Object { $_.UserName -like "*\$env:… | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qrRbzS | q-e5c4fd8202 | ok |
| 6 | 2020-05-02 03:16:52.456Z | nashua.dmevals.local | windows.sysmon | process.command_line | .\sdelete64.exe  /accepteula "C:\Windows\Temp\Rar.exe" | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7cri_p- | q-4edda752cc | ok |

### F23 · malicious / high · T1570 · PsExec tool transfer from SCRANTON to NASHUA via ADMIN$ share (PSEXESVC.exe + python.exe dropped)

Evidence status: **verified**

User pbeesly (DMEVALS, SID ...-1107) on scranton.dmevals.local (10.0.1.4) repeatedly wrote tools into the ADMIN$ share (\\*\ADMIN$ -> \\??\C:\windows) of nashua.dmevals.local. At 23:10:23 local (03:10:23Z) a 5145 event shows pbeesly writing 'Temp\python.exe' with WriteData/AppendData access, and Sysmon event 11 on nashua confirms C:\Windows\Temp\python.exe was created at 03:10:23.626Z. At 23:11:18 (03:11:18Z) pbeesly wrote 'PSEXESVC.exe' to ADMIN$ (WriteData/AppendData), and Sysmon recorded C:\Windows\PSEXESVC.exe created at 03:11:18.864Z, then executed as NT AUTHORITY\SYSTEM with parent services.exe (Sysinternals PsExec v2.2, SHA256 224F549F...). This write-then-service-execute cycle repeated four times (PSEXESVC.exe created 03:11:18, 03:12:25, 03:13:28, 03:14:42Z), each followed ~20s later by a pbeesly-context C:\Windows\Temp\python.exe process on nashua. The transferred python.exe then dropped further tools into C:\Windows\Temp on nashua: Rar.exe (03:15:31Z) and sdelete64.exe (03:15:38Z). This is attacker-driven lateral tool transfer from a compromised host to a new host, not normal administration.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:18.000Z | nashua.dmevals.local | windows.security | win.RelativeTargetName | PSEXESVC.exe | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7niyNu7 | q-133ecfed5d | ok |
| 2 | 2020-05-02 03:11:18.000Z | nashua.dmevals.local | windows.security | win.ShareName | \\*\ADMIN$ | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7niyNu7 | q-133ecfed5d | ok |
| 3 | 2020-05-02 03:11:18.000Z | nashua.dmevals.local | windows.security | win.IpAddress | 10.0.1.4 | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7niyNu7 | q-133ecfed5d | ok |
| 4 | 2020-05-02 03:10:23.000Z | nashua.dmevals.local | windows.security | win.RelativeTargetName | Temp\python.exe | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7niytvL | q-cf7b110726 | ok |
| 5 | 2020-05-02 03:11:18.864Z | nashua.dmevals.local | windows.sysmon | win.TargetFilename | C:\Windows\PSEXESVC.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7h03ALx | q-09e9733b73 | ok |
| 6 | 2020-05-02 03:10:23.626Z | nashua.dmevals.local | windows.sysmon | win.TargetFilename | C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7c82-ha | q-a74fa56090 | ok |
| 7 | 2020-05-02 03:11:39.934Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\Windows\PSEXESVC.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7c82Oiy | q-f416380fba | ok |
| 8 | 2020-05-02 03:11:39.934Z | nashua.dmevals.local | windows.sysmon | process.parent.executable | C:\Windows\System32\services.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7c82Oiy | q-f416380fba | ok |
| 9 | 2020-05-02 03:15:31.530Z | nashua.dmevals.local | windows.sysmon | win.TargetFilename | C:\Windows\Temp\Rar.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7c5yloe | q-5922ed391a | ok |
| 10 | 2020-05-02 03:15:38.985Z | nashua.dmevals.local | windows.sysmon | win.TargetFilename | C:\Windows\Temp\sdelete64.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7culih9 | q-5922ed391a | ok |

### F27 · malicious / high · T1570 · Tool transfer onto NASHUA: python.exe, Rar.exe and sdelete64.exe written to C:\Windows\Temp and executed

Evidence status: **verified**

On NASHUA.dmevals.local the attacker-written C:\Windows\Temp\python.exe (dropped via PsExec) wrote C:\Windows\Temp\Rar.exe at 03:15:31 and C:\Windows\Temp\sdelete64.exe at 03:15:38, then spawned powershell.exe (03:15:48) which ran Rar.exe to create C:\Users\pbeesly\Desktop\working.zip (03:16:19) and cmd.exe (03:16:40) which ran sdelete64.exe against Rar.exe, working.zip in Roaming and Desktop. This is tool staging/transfer onto the victim host plus anti-forensic cleanup, distinct from the PSEXESVC.exe/python.exe drops already anchored.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:15:31.530Z | nashua.dmevals.local | windows.sysmon | file.path | C:\Windows\Temp\Rar.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7c5yloe | q-58f80cb511 | ok |
| 2 | 2020-05-02 03:15:38.985Z | nashua.dmevals.local | windows.sysmon | file.path | C:\Windows\Temp\sdelete64.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7culih9 | q-58f80cb511 | ok |
| 3 | 2020-05-02 03:16:19.395Z | nashua.dmevals.local | windows.sysmon | process.command_line | "C:\Windows\Temp\Rar.exe" a -hpfGzq5yKw C:\Users\pbeesly\Desktop\working.zip C:\Users\pbeesly\AppData\Roaming\working.zip | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7c4xY6Y | q-33f98ea0c0 | ok |
| 4 | 2020-05-02 03:16:52.456Z | nashua.dmevals.local | windows.sysmon | process.command_line | .\sdelete64.exe  /accepteula "C:\Windows\Temp\Rar.exe" | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7cri_p- | q-33f98ea0c0 | ok |
| 5 | 2020-05-02 03:17:18.030Z | nashua.dmevals.local | windows.sysmon | process.command_line | .\sdelete64.exe  /accepteula "C:\Users\pbeesly\AppData\Roaming\working.zip"  | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7crhzvV | q-33f98ea0c0 | ok |
| 6 | 2020-05-02 03:17:41.290Z | nashua.dmevals.local | windows.sysmon | process.command_line | .\sdelete64.exe  /accepteula "C:\Users\pbeesly\Desktop\working.zip" | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7c1t6d3 | q-33f98ea0c0 | ok |
| 7 | 2020-05-02 03:15:48.652Z | nashua.dmevals.local | windows.sysmon | process.parent.executable | C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7culihF | q-33f98ea0c0 | ok |

### F03 · suspicious / low · T1021.001 · RDP logon (LogonType 10) as pbeesly on SCRANTON from 172.18.39.2

Evidence status: **verified**

Two 4624 LogonType 10 events for pbeesly were recorded on scranton.dmevals.local at 2020-05-01T23:20:46 (03:20:46 UTC) from source address 172.18.39.2, Workstation Name SCRANTON, Logon Process User32, Authentication Package Negotiate, with a linked logon ID. The same 172.18.39.2 address also appears in a 4648 explicit-credential event on SCRANTON. No mstsc.exe execution, no 4778/4779 session events and no outbound 3389 connections from a workstation were found, so this looks like an interactive/RDP session into the compromised host rather than host-to-host RDP pivoting; it is not corroborated as lateral movement.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:20:46.000Z | scranton.dmevals.local | windows.security | win.LogonType | 10 | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7nKg4v2 | q-e010f19792 | ok |
| 2 | 2020-05-02 03:20:46.000Z | scranton.dmevals.local | windows.security | win.IpAddress | 172.18.39.2 | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7nKg4v2 | q-e010f19792 | ok |
| 3 | 2020-05-02 03:20:46.000Z | scranton.dmevals.local | windows.security | win.WorkstationName | SCRANTON | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7nKg4v2 | q-e010f19792 | ok |

### F28 · suspicious / medium · T1021.001 · pbeesly interactive (LogonType 2) sessions on NASHUA following each PsExec network logon

Evidence status: **verified**

NASHUA recorded LogonType 2 (interactive) logons for pbeesly at 03:11:40, 03:12:46, 03:13:49 and 03:15:03, each within ~20 seconds of a LogonType 3 network logon from 10.0.1.4 (SCRANTON) and of a PSEXESVC.exe service start plus C:\Windows\Temp\python.exe launch. This is the interactive-session side effect of the PsExec -i 2 remote execution, i.e. remote interactive access to NASHUA driven from the compromised SCRANTON host.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:40.000Z | nashua.dmevals.local | windows.security | winlog.logon.type | 2 | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7niyNuT | q-b30d31f62b | ok |
| 2 | 2020-05-02 03:11:18.000Z | nashua.dmevals.local | windows.security | source.ip | 10.0.1.4 | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7niyNvH | q-b30d31f62b | ok |
| 3 | 2020-05-02 03:11:39.934Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\Windows\PSEXESVC.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7c82Oiy | q-33f98ea0c0 | ok |
| 4 | 2020-05-02 03:11:40.213Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7c82OhP | q-33f98ea0c0 | ok |

### F26 · suspicious / medium · T1021.002 · pbeesly network logons to NEWYORK (DC) from SCRANTON 10.0.1.4 with IPC$ access — SMB lateral movement beyond NASHUA

Evidence status: **verified**

On 2020-05-02 between 03:04:04 and 03:20:46 NEWYORK.dmevals.local recorded six LogonType 3 (network) logons for DMEVALS\pbeesly, five sourced from 10.0.1.4 (SCRANTON, the compromised host) and one from 10.0.1.6 (NASHUA, the already-compromised second host). The 03:04:04 logon (logon id 0x5dd594, Kerberos, source port 59900) was immediately followed by a 5140 network-share access to \\*\IPC$ by pbeesly from 10.0.1.4 — the same pattern as the PsExec ADMIN$ activity against NASHUA, but against the domain controller. No process creation, service install or file write by pbeesly was observed on NEWYORK in this window, so this is SMB/remote-access reconnaissance or an attempted remote execution that did not complete in the captured data.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:04.000Z | newyork.dmevals.local | windows.security | source.ip | 10.0.1.4 | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7nq72Yy | q-9243e8a803 | ok |
| 2 | 2020-05-02 03:04:04.000Z | newyork.dmevals.local | windows.security | winlog.logon.type | 3 | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7nq72Yy | q-9243e8a803 | ok |
| 3 | 2020-05-02 03:04:04.000Z | newyork.dmevals.local | windows.security | win.AuthenticationPackageName | Kerberos | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7nq72Yy | q-5c9ae3dd54 | ok |
| 4 | 2020-05-02 03:04:04.000Z | newyork.dmevals.local | windows.security | win.ShareName | \\*\IPC$ | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7nq72Zu | q-db709d38d0 | ok |
| 5 | 2020-05-02 03:04:04.000Z | newyork.dmevals.local | windows.security | source.ip | 10.0.1.4 | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7nq72Zu | q-db709d38d0 | ok |
| 6 | 2020-05-02 03:14:20.000Z | newyork.dmevals.local | windows.security | source.ip | 10.0.1.6 | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7nixQYA | q-9243e8a803 | ok |
| 7 | 2020-05-02 03:14:20.000Z | newyork.dmevals.local | windows.security | winlog.logon.type | 3 | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7nixQYA | q-9243e8a803 | ok |

### F19 · suspicious / medium · T1550.002 · Single NTLM network logon for pbeesly on SCRANTON — consistent with PsExec NTLM auth, no pass-the-hash evidence

Evidence status: **verified**

Only one 4624 with AuthenticationPackageName NTLM exists in the whole window: pbeesly, LogonType 3, LogonProcessName 'NtLmSsp ', LmPackageName 'NTLM V2', KeyLength 128, on scranton.dmevals.local at 2020-05-01T23:20:41-04:00 (2020-05-02T03:20:41Z) from source 172.18.39.2 with WorkstationName 10.0.1.4. All other 217 network logons are Kerberos. This NTLM logon is temporally and account-wise consistent with the PsExec/alternate-credential activity by pbeesly, and the same source IP 172.18.39.2 also appears in a 4648 for pbeesly on scranton at 03:20:46Z. However, no credential-dumping precursor was found: no mimikatz/sekurlsa script blocks (C103 zero hits), and LSASS process-access events with high rights (0x1fffff) come only from csrss.exe, wininit.exe and PowerShell.exe on scranton with ordinary system call traces. The NTLM logon is therefore best explained by explicit-credential/NTLM fallback during the PsExec move rather than hash reuse; no pass-the-hash is confirmed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:20:41.000Z | scranton.dmevals.local | windows.security | win.AuthenticationPackageName | NTLM | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7nQi3T7 | q-05e6c65792 | ok |
| 2 | 2020-05-02 03:20:41.000Z | scranton.dmevals.local | windows.security | win.LogonProcessName | NtLmSsp  | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7nQi3T7 | q-02ab91ba23 | ok |
| 3 | 2020-05-02 03:20:41.000Z | scranton.dmevals.local | windows.security | win.LmPackageName | NTLM V2 | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7nQi3T7 | q-02ab91ba23 | ok |
| 4 | 2020-05-02 03:20:46.000Z | scranton.dmevals.local | windows.security | source.ip | 172.18.39.2 | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7nKg4v1 | q-49cc0800a8 | ok |
| 5 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hQQBhJ | q-f31e6158f1 | ok |

### F25 · suspicious / medium · T1570 · PowerShell Invoke-Exfil script on SCRANTON copies archive to remote WebDAV share

Evidence status: **verified**

On scranton.dmevals.local, user pbeesly executed a script block (4104, ScriptBlock ID b2b03a9c-43f0-4285-837d-f22d4600b2ae, path C:\Program Files\SysinternalsSuite\psversion.ps1) defining Invoke-Exfil: it installs 7Zip4Powershell, compresses the user's Downloads folder into %APPDATA%\OfficeSupplies.7z with password 'lolol', maps a drive to \\192.168.0.4\webdav using hardcoded credentials (cozy / MyCozyPassw0rd!) and Copy-Item's the archive there. This is file transfer to a remote share, but the direction is outbound staging/exfiltration rather than moving tools onto a victim host, so it is recorded as suspicious supporting context for the same actor on the same host rather than a T1570 tool-transfer instance.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qjPglL | q-df4efb1457 | ok |
| 2 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\psversion.ps1 | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qjPglL | q-df4efb1457 | ok |
| 3 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | host.name | scranton.dmevals.local | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qjPglL | q-df4efb1457 | ok |

### F29 · suspicious / medium · T1570 · Sysinternals suite downloaded to SCRANTON and accessChk.exe run by PowerShell for permission enumeration

Evidence status: **verified**

On SCRANTON, powershell.exe (running as pbeesly) downloaded SysinternalsSuite.zip to C:\Users\pbeesly\Downloads at 02:59:42, extracted it, and at 03:04:34 executed accesschk.exe from C:\Program Files\SysinternalsSuite with no arguments — permission enumeration on the compromised host immediately before the PsExec lateral movement to NASHUA.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:34.951Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\accesschk.exe" | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hRQwNZ | q-3b9e093c52 | ok |
| 2 | 2020-05-02 03:04:34.951Z | scranton.dmevals.local | windows.sysmon | process.parent.executable | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hRQwNZ | q-3b9e093c52 | ok |
| 3 | 2020-05-02 02:59:42.544Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Users\pbeesly\Downloads\SysinternalsSuite.zip | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hjk9tr | q-747e6b9a58 | ok |

### F04 · benign / medium · T1021.003 · No DCOM lateral movement observed

Evidence status: **verified**

No DCOM lateral-movement artifacts were found: no 4624 LogonType 3 with svchost process name, no MMC20.Application/ShellWindows/ShellBrowserWindow script blocks, and no DCOM-related service or process creation. The only Invoke-CimMethod reference is a benign alias definition (Set-Alias -Name icim -Value Invoke-CimMethod) in profile scripts on newyork and scranton.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:01:35.000Z | newyork.dmevals.local | windows.powershell | process.command_line | Set-Alias -Name icim -Value Invoke-CimMethod -Option ReadOnly, AllScope -ErrorAction SilentlyContinue | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qwTlue | q-ecb946390c | ok |

### F05 · benign / high · T1021.004 · No SSH lateral movement observed

Evidence status: **verified**

No outbound connections to port 22 in sysmon or zeek, no sshd/SSH service installation, and no ssh/plink/New-PSSession -HostName script blocks were found in either time window.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-04-30 00:06:38.903Z | simplerockbuild.simplerock.lan | zeek | destination.port | 445 | .ds-logs-zeek-default-2026.10.20-000001 / AaFZSPJfH5wFd7o_aFZ1 | q-ab82db0de1 | ok |

### F06 · benign / high · T1021.005 · No VNC lateral movement observed

Evidence status: **verified**

No connections to port 5900, no vnc/tvnserver binaries or services, and no VNC-related PowerShell script blocks were found in any dataset.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:09:23.801Z | scranton.dmevals.local | windows.sysmon | destination.port | 5985 | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7c-4MbN | q-a95c00adfc | ok |

### F08 · benign / high · T1072 · Azure guest-agent, logman and javamtsup service activity on scranton is benign platform behaviour

Evidence status: **verified**

The remaining deployment-tool-like hits are normal Windows/Azure platform activity, not adversary deployment. On scranton.dmevals.local, logman.exe was invoked by C:\WindowsAzure\Packages\WaAppAgent.exe to stop/create/start the GAEvents and RTEvents ETW traces (03:18:38-03:19:44), and the javamtsup.exe service (installed 2020-05-01 23:04:15 by pbeesly as 'Java(TM) Virtual Machine Support Service') started under services.exe at 03:19:14 and spawned rundll32.exe. hostui.exe was started by powershell.exe at 03:21:27. These are consistent with the Azure guest agent and OS service lifecycle; no SCCM/Intune/SMS deployment agent was found (C059 returned zero hits), and the only genuine deployment-tool abuse in this window is the PsExec activity reported separately.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:41.076Z | scranton.dmevals.local | windows.sysmon | process.command_line | "logman.exe" create trace RTEvents -max 50 -f bincirc -o C:\WindowsAzure\Logs\RuntimeEvents.etl -pf C:\WindowsAzure\Packages\GuestAgent\ProviderGuids.txt | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7cfUP4A | q-849c3b3ee9 | ok |
| 2 | 2020-05-02 03:19:14.118Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\Windows\System32\javamtsup.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7cxpAy5 | q-849c3b3ee9 | ok |
| 3 | 2020-05-02 03:04:15.000Z | scranton.dmevals.local | windows.other | message | A service was installed in the system.    Service Name:  Java(TM) Virtual Machine Support Service  Service File Name:  C:\Windows\System32\javamtsup.exe  Servic… | .ds-logs-windows.other-default-2026.10.20-000001 / AaFZR_JfH5wFd7pNHuDg | q-79877b0035 | ok |

### F09 · benign / medium · T1080 · No tainted shared content: SYSVOL/ADMIN$ access is read-only GPO reads plus PsExec service drops, not writes to shared content

Evidence status: **verified**

Across 2020-05-02 02:55-03:28Z on newyork/nashua/scranton/utica.dmevals.local, all 121 event.code 5145 share-access events and 42 event.code 5140 share-connect events resolve to SYSVOL (56/13), IPC$ (45/20) and ADMIN$ (20/9). Every SYSVOL access carries read-only masks (0x100081 SYNCHRONIZE/ReadData/ReadAttributes, 0x120089) against GPO paths such as dmevals.local\Policies\{31B2F340-...}\Machine and gpt.ini, performed by machine accounts NEWYORK$, SCRANTON$, NASHUA$ and UTICA$. The non-overlapping Zeek window (2020-04-30 00:06-00:45Z) shows the same pattern from the network side: all 12 smb_files records are SMB::FILE_OPEN on \\NEWYORK.dmevals.local\sysvol (gpt.ini, GptTmpl.inf) with no write, rename or delete actions. No file was written into SYSVOL or any other share, so shared content was not tainted. The only share writes observed are pbeesly from 10.0.1.4 (scranton) writing PSEXESVC.exe and Temp\python.exe into nashua's ADMIN$ with mask 0x2 (WriteData/AddFile) at 03:10-03:18Z, accompanied by PSEXESVC service installs (7045) and PSEXESVC stdin/stdout/stderr pipes - that is PsExec-style remote execution (T1021.002/T1569.002), not T1080. Sysmon event.code 11 file creations contain no UNC/network paths (all local Prefetch, ServiceState, DFSR config and user temp files), and the single PowerShell 4104 hit is an Invoke-Exfil routine that maps \\192.168.0.4\webdav and copies OfficeSupplies.7z out (exfiltration), not content placed on a share for other users to execute.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:01:43.000Z | newyork.dmevals.local | windows.security | win.AccessMask | 0x100081 | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7ns-ApD | q-1fdfadec32 | ok |
| 2 | 2020-05-02 03:01:43.000Z | newyork.dmevals.local | windows.security | win.RelativeTargetName | dmevals.local\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\Machine | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7ns-ApD | q-1fdfadec32 | ok |
| 3 | 2020-05-02 03:01:43.000Z | newyork.dmevals.local | windows.security | win.ShareName | \\*\SYSVOL | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7ns-ApD | q-1fdfadec32 | ok |
| 4 | 2020-05-02 02:56:47.000Z | newyork.dmevals.local | windows.security | win.ShareName | \\*\SYSVOL | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7rxEjIW | q-4502c1a1f3 | ok |
| 5 | 2020-05-02 03:04:15.000Z | scranton.dmevals.local | windows.other | win.ImagePath | C:\Windows\System32\javamtsup.exe | .ds-logs-windows.other-default-2026.10.20-000001 / AaFZR_JfH5wFd7pNHuDg | q-da75090822 | ok |
| 6 | 2020-05-02 03:11:39.000Z | nashua.dmevals.local | windows.other | win.ImagePath | %SystemRoot%\PSEXESVC.exe | .ds-logs-windows.other-default-2026.10.20-000001 / AaFZR_JfH5wFd7pNHuCk | q-da75090822 | ok |
| 7 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qjPglL | q-49167d2324 | ok |
| 8 | 2020-05-02 02:56:14.969Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Users\pbeesly\AppData\Local\Temp\__PSScriptPolicyTest_0gslifez.da2.ps1 | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hx0G9q | q-25c81b3109 | ok |

### F10 · benign / high · T1091 · No removable-media replication observed; D:/F: volume writes are fixed-disk DFSR and pagefile activity

Evidence status: **verified**

The T1091 hypothesis is not supported. The only file-creation events on non-C: drive letters in windows.sysmon are (a) 14 writes by C:\windows\system32\DFSRs.exe to F:\System Volume Information\DFSR\Config\*.XML.TMP on newyork.dmevals.local between 02:56:48Z and 03:26:49Z, which is normal DFS Replication staging on a fixed volume, and (b) one write of D:\pagefile.sys by C:\windows\System32\smss.exe on scranton.dmevals.local at 03:19:09Z, which is normal pagefile creation at boot. windows.other volume-health events (code 98) confirm C:, D: and \\?\Volume{d1b3f076-...} are \Device\HarddiskVolume* fixed disks, not removable media. No USB device, removable-volume or drive-letter insertion events were found in windows.other, and the Sysinternals Volumeid.exe files seen on scranton were written to C:\Users\pbeesly\Downloads, not to removable media. The Zeek dataset (2020-04-30) does not overlap the Windows window and contains no removable-media telemetry.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:56:48.208Z | newyork.dmevals.local | windows.sysmon | file.path | F:\System Volume Information\DFSR\Config\Volume_6936845B-3943-400C-B266-FE6A00502C0C.XML.TMP | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hwyqf3 | q-c47e14bcbe | ok |
| 2 | 2020-05-02 02:56:48.208Z | newyork.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\DFSRs.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hwyqf3 | q-b231f629b9 | ok |
| 3 | 2020-05-02 03:19:09.192Z | scranton.dmevals.local | windows.sysmon | file.path | D:\pagefile.sys | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7cxqOiA | q-c47e14bcbe | ok |
| 4 | 2020-05-02 03:19:09.192Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\System32\smss.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7cxqOiA | q-c47e14bcbe | ok |
| 5 | 2020-05-02 03:19:05.000Z | scranton.dmevals.local | windows.other | message | Volume D: (\Device\HarddiskVolume3) is healthy.  No action is needed. | .ds-logs-windows.other-default-2026.10.20-000001 / AaFZR_JfH5wFd7pNHuA7 | q-9335b641ac | ok |
| 6 | 2020-05-02 03:00:28.158Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Users\pbeesly\Downloads\SysinternalsSuite\Volumeid64.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hbcHo- | q-07cc99e24b | ok |

### F15 · benign / medium · T1210 · Benign SMB/DC and machine-account network logons (10.0.0.4, 445, NEWYORK$/SCRANTON$/NASHUA$/UTICA$)

Evidence status: **verified**

The bulk of port-445 traffic (66 connections overall, 26 to 10.0.0.4) was generated by process 'System' from all four hosts, and the 218 LogonType 3 events are dominated by machine accounts (NEWYORK$ 123, SCRANTON$ 37, NASHUA$ 25, UTICA$ 5) from loopback/link-local/DC addresses — normal domain authentication and SMB to the DC. The single RDP (3389) and 12 WinRM (5985) connections are not accompanied by exploitation artefacts; only the pbeesly WinRM session from SCRANTON to NASHUA is anomalous. Zeek (2020-04-30) does not overlap the Windows window and shows only 45 flows to 445 and 8 to 5985 with no exploitation indicators retrievable in this window.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:09:23.801Z | scranton.dmevals.local | windows.sysmon | destination.ip | 10.0.1.6 | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7c-4MbN | q-64cc0e0433 | ok |
| 2 | 2020-05-02 02:56:47.000Z | newyork.dmevals.local | windows.security | win.TargetUserName | NEWYORK$ | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7rxEjJI | q-a0c79eca9c | ok |

### F17 · benign / medium · T1534 · No internal spearphishing (mail-borne lure) observed; PowerShell 4104 URL/mail hits are benign module manifests

Evidence status: **verified**

The 10 PowerShell 4104 script blocks matching http/attachment/mail were reviewed: they are Microsoft DSC/xStorage module manifests, a PSSA suppression comment, a 7-Zip module manifest, and a PDQ-blog screen-capture function — no mail client, attachment, or internal phishing content. windows.other event.code 1/11 hits are Hyper-V NIC restarts, time-change and filter-unload messages, not lure-opened documents. No 4625 failed logons were observed (C086 zero hits). The zeek window (2020-04-30) does not overlap the Windows window (2020-05-02), so no mail/web delivery could be correlated; the internal host 192.168.0.4 served all 62 HTTP requests in the zeek window, but no phishing content was visible in the retrieved events.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:53.000Z | scranton.dmevals.local | windows.powershell | process.command_line | function Invoke-ScreenCapture # https://www.pdq.com/blog/capturing-screenshots-with-powershell-and-net/ {     Start-Job -Name "Screenshot" -ScriptBlock {       … | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qvSyuh | q-8dcf263055 | ok |
| 2 | 2020-05-02 03:01:30.000Z | newyork.dmevals.local | windows.powershell | user.name | SYSTEM | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qwT1sV | q-8dcf263055 | ok |
| 3 | 2020-05-02 03:02:46.000Z | scranton.dmevals.local | windows.other | message | Miniport NIC 'Microsoft Hyper-V Network Adapter' restarted | .ds-logs-windows.other-default-2026.10.20-000001 / AaFZR_JfH5wFd7pNHuBw | q-0485eeb629 | ok |

### F20 · benign / medium · T1550.003 · No pass-the-ticket indicators: Kerberos tickets requested normally, no pre-auth-0 logons or ticket-injection tooling

Evidence status: **verified**

Kerberos activity in the window is ordinary: 4769 service-ticket requests for pbeesly@DMEVALS.LOCAL from client 10.0.1.4 (scranton) to newyork.dmevals.local for krbtgt, NEWYORK$ and NASHUA$ services, each with a distinct Logon GUID and normal client ports — i.e. tickets being legitimately obtained, not replayed. The PreAuthType aggregation over Kerberos 4624 logons returned no buckets (no PreAuthType 0 / no-pre-auth logons), and the Rubeus/kirbi/asktgt script-block search returned zero hits. Network logons are dominated by machine accounts (NEWYORK$ 123, SCRANTON$ 37, NASHUA$ 25) plus pbeesly 20, which is normal domain traffic. No evidence of stolen or injected Kerberos tickets.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:09:23.000Z | newyork.dmevals.local | windows.security | message | A Kerberos service ticket was requested.    Account Information:  	Account Name:		pbeesly@DMEVALS.LOCAL  	Account Domain:		DMEVALS.LOCAL  	Logon GUID:		{b7617a6… | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7njzKBN | q-3ca792f6ba | ok |
| 2 | 2020-05-02 03:04:04.000Z | newyork.dmevals.local | windows.security | source.ip | ::ffff:10.0.1.4 | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7nq72Yx | q-3ca792f6ba | ok |

### F21 · benign / medium · T1563 · No remote service session hijacking observed; lateral movement used PsExec service execution instead

Evidence status: **verified**

Hunting for T1563 (Remote Service Session Hijacking) produced no hijack evidence. The only remote-interactive (LogonType 10) logons in the window are two 4624 events on scranton.dmevals.local at 2020-05-02T03:20:46Z for DMEVALS\pbeesly from 172.18.39.2 (LogonProcessName 'User32 ', WorkstationName SCRANTON, TargetLogonId 0x1305dc, Linked Logon ID 0x13069A). That session is a normal, freshly established RDP logon: TermService (svchost -k NetworkService -s TermService) spawned rdpclip.exe at 03:20:48Z in TerminalSessionId 2 with LogonId 0x13069A, followed by explorer.exe, LogonUI.exe, dwm.exe and fontdrvhost.exe — i.e. a new interactive desktop, not a takeover of an existing session. No tscon, mstsc, qwinsta or query session execution exists in sysmon process-creation events, and the 120 PowerShell 4104 'hits' for tscon/qwinsta/query session are false positives from built-in CimCmdlets module text (e.g. '[Alias('Session')] [CimSession[]] ${CimSession}') on newyork.dmevals.local, not attacker script. The real lateral movement in this window is PsExec-based (T1021.002), which is outside this technique family.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:20:46.000Z | scranton.dmevals.local | windows.security | win.LogonType | 10 | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7nKg4v2 | q-04039f0deb | ok |
| 2 | 2020-05-02 03:20:46.000Z | scranton.dmevals.local | windows.security | win.LogonProcessName | User32  | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7nKg4v2 | q-04039f0deb | ok |
| 3 | 2020-05-02 03:20:48.127Z | scranton.dmevals.local | windows.sysmon | process.command_line | rdpclip | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRfJfH5wFd7b_zvXB | q-2840f214ba | ok |
| 4 | 2020-05-02 03:20:48.127Z | scranton.dmevals.local | windows.sysmon | process.parent.command_line | C:\windows\System32\svchost.exe -k NetworkService -s TermService | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRfJfH5wFd7b_zvXB | q-2840f214ba | ok |
| 5 | 2020-05-02 03:01:33.000Z | newyork.dmevals.local | windows.powershell | win.ScriptBlockText | erSetName='ByDisk')]      [Alias('Session')]      [ValidateNotNullOrEmpty()]      [CimSession[]]      ${CimSession},        [Parameter(ParameterSetName='ByPhysi… | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qvTSui | q-ad74212516 | ok |

### F22 · benign / medium · T1563.002 · RDP session on scranton is a legitimate new interactive logon, not a hijacked session

Evidence status: **verified**

The single RDP-related network event is a sysmon event.code 3 on scranton.dmevals.local at 2020-05-02T03:20:21Z: svchost.exe (PID 1056, NT AUTHORITY\NETWORK SERVICE) receiving an inbound TCP connection from 172.18.39.2:60579 to 10.0.1.4:3389 (Initiated: false). It is immediately followed by the LogonType 10 4624 for pbeesly from 172.18.39.2 and by rdpclip.exe spawned from TermService in TerminalSessionId 2. There is no evidence of session takeover: no tscon.exe execution (C119 zero hits), no mstsc/ssh/winrs command lines (C114 zero hits), no Enter-PSSession/New-PSSession script blocks (C116 zero hits), and no second session being redirected to an existing one. The RDP session is the attacker's/user's own interactive foothold on scranton, from which the actual lateral movement to nashua.dmevals.local was performed with PsExec64.exe (cleartext -u dmevals\pbeesly -p ... \\NASHUA -i 2 C:\Windows\Temp\python.exe at 03:11:18Z, 03:12:25Z, 03:13:28Z, 03:14:42Z), creating PSEXESVC services and running python.exe on nashua — that is T1021.002, not RDP hijacking.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:20:21.001Z | scranton.dmevals.local | windows.sysmon | destination.port | 3389 | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7cdSewt | q-17c8ec6556 | ok |
| 2 | 2020-05-02 03:20:21.001Z | scranton.dmevals.local | windows.sysmon | win.Initiated | false | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7cdSewt | q-17c8ec6556 | ok |
| 3 | 2020-05-02 03:20:48.127Z | scranton.dmevals.local | windows.sysmon | win.TerminalSessionId | 2 | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRfJfH5wFd7b_zvXB | q-2840f214ba | ok |
| 4 | 2020-05-02 03:12:25.384Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\PsExec64.exe" -accepteula \\NASHUA -u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7h03AIc | q-60f48e6e74 | ok |
| 5 | 2020-05-02 03:11:40.213Z | nashua.dmevals.local | windows.sysmon | process.parent.executable | C:\Windows\PSEXESVC.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7c82OhP | q-418abcd71e | ok |

### F24 · benign / medium · T1570 · SYSVOL/IPC$ share access by machine accounts (NEWYORK$, SCRANTON$) — benign domain replication traffic

Evidence status: **verified**

The remaining 5140/5145 share hits are SYSVOL and IPC$ access by machine accounts: NEWYORK$ from fe80::e40c:95b6:b0a7:6429 and SCRANTON$ from 10.0.1.4 on newyork.dmevals.local, plus IPC$ sessions. These are read-oriented domain controller replication/Group Policy and SMB session setup patterns (SYSVOL share path \\??\F:\SYSVOL\sysvol), not tool staging. No file writes to ADMIN$ or other hosts were observed from these accounts, so they are assessed as normal domain behaviour rather than lateral tool transfer.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:56:47.000Z | newyork.dmevals.local | windows.security | win.ShareName | \\*\SYSVOL | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7rxEjIW | q-d67e250095 | ok |
| 2 | 2020-05-02 02:56:47.000Z | newyork.dmevals.local | windows.security | user.name | NEWYORK$ | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7rxEjIW | q-d67e250095 | ok |
| 3 | 2020-05-02 03:01:43.000Z | newyork.dmevals.local | windows.security | user.name | SCRANTON$ | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7ns-ApD | q-d67e250095 | ok |

## Pivot candidates

Processes the pivot reviewer had to assess (started by a script host or from outside the Windows directory, rare in the 15-minute windows around verified activity).

| Host | Executable | Starts | Parents | Assessment | Reason |
|---|---|---|---|---|---|
| nashua.dmevals.local | C:\Program Files\WindowsApps\Microsoft.SkypeApp_14.35.152.0_x64__kzf8qxf38zg5c\S… | 1 | C:\Program Files\WindowsApps\Microsoft.SkypeApp_14.35.152.0_x64__kzf8qxf38zg5c\S… | benign | Windows Store Skype app self-restarting; its only child is WerFault.exe (crash reporting). No relation to the PsExec/python chain. |
| nashua.dmevals.local | C:\Windows\Temp\python.exe | 5 | C:\Windows\PSEXESVC.exe, C:\Windows\Temp\python.exe | malicious | Dropped to C:\Windows\Temp and launched by C:\Windows\PSEXESVC.exe four times (03:11:40, 03:12:46, 03:13:49, 03:15:03) as pbeesly; beaconed to 192.168.0.4:8443 … |
| nashua.dmevals.local | C:\Windows\Temp\Rar.exe | 1 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | malicious | Written by C:\Windows\Temp\python.exe at 03:15:31 and executed by powershell.exe to create password-protected C:\Users\pbeesly\Desktop\working.zip; later wiped … |
| nashua.dmevals.local | C:\Windows\Temp\sdelete64.exe | 3 | C:\Windows\System32\cmd.exe | malicious | Written by C:\Windows\Temp\python.exe at 03:15:38 and run three times from cmd.exe to securely delete Rar.exe and working.zip — anti-forensic cleanup of the att… |
| nashua.dmevals.local | C:\WindowsAzure\Packages\CollectGuestLogs.exe | 1 | C:\WindowsAzure\Packages\WaAppAgent.exe | benign | Azure guest agent diagnostic collection (parent WaAppAgent.exe), same pattern on NEWYORK and UTICA; unrelated to the intrusion. |
| scranton.dmevals.local | C:\Packages\Plugins\Microsoft.Azure.NetworkWatcher.NetworkWatcherAgentWindows\1.… | 4 | C:\Windows\System32\cmd.exe, C:\Windows\System32\services.exe | benign | Azure Network Watcher extension started by services.exe/cmd.exe; standard cloud agent, no attacker linkage. |
| scranton.dmevals.local | C:\Packages\Plugins\Microsoft.Azure.Security.IaaSAntimalware\1.5.5.9\Antimalware… | 1 | C:\WindowsAzure\Packages\GuestAgent\WindowsAzureGuestAgent.exe | benign | Azure antimalware extension configuration launched by WindowsAzureGuestAgent.exe; expected platform activity. |
| scranton.dmevals.local | C:\Packages\Plugins\Microsoft.Compute.CustomScriptExtension\1.10.5\bin\CustomScr… | 1 | C:\Windows\System32\cmd.exe | benign | Azure Custom Script extension handler started by cmd.exe; standard VM extension, no evidence of attacker use. |
| scranton.dmevals.local | C:\Packages\Plugins\Microsoft.Compute.JsonADDomainExtension\1.3.2\bin\JsonADDoma… | 1 | C:\Windows\System32\cmd.exe | benign | Azure domain-join extension; expected provisioning activity. |
| scranton.dmevals.local | C:\Program Files (x86)\Google\Update\1.3.35.452\GoogleCrashHandler.exe | 2 | C:\Program Files (x86)\Google\Update\GoogleUpdate.exe | benign | Google Update crash handler child of GoogleUpdate.exe; routine software update activity. |
| scranton.dmevals.local | C:\Program Files (x86)\Google\Update\1.3.35.452\GoogleCrashHandler64.exe | 2 | C:\Program Files (x86)\Google\Update\GoogleUpdate.exe | benign | Google Update crash handler child of GoogleUpdate.exe; routine software update activity. |
| scranton.dmevals.local | C:\Program Files (x86)\Google\Update\GoogleUpdate.exe | 3 | C:\Program Files (x86)\Google\Update\GoogleUpdate.exe, C:\Windows\System32\servi… | benign | Google updater started by services.exe/svchost.exe; standard scheduled update. |
| scranton.dmevals.local | C:\Program Files\SysinternalsSuite\accessChk.exe | 1 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | suspicious | Sysinternals accessChk run by powershell.exe as pbeesly at 03:04:34 from a suite the attacker downloaded (SysinternalsSuite.zip) — permission enumeration suppor… |
| scranton.dmevals.local | C:\Program Files\SysinternalsSuite\PsExec64.exe | 4 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | malicious | Run four times by powershell.exe with cleartext credentials: -accepteula \\NASHUA -u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe — the la… |
| scranton.dmevals.local | C:\Program Files\SysinternalsSuite\sdelete64.exe | 3 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | malicious | Run by powershell.exe to securely delete the attacker's payload C:\programdata\victim\???cod.3aka3.scr, Draft.Zip and SysinternalsSuite.zip — anti-forensic clea… |
| scranton.dmevals.local | C:\Program Files\Windows Defender\MsMpEng.exe | 1 | C:\Windows\System32\services.exe | benign | Windows Defender service started by services.exe; normal security product. |
| scranton.dmevals.local | C:\Program Files\Windows Defender\NisSrv.exe | 2 | C:\Windows\System32\services.exe | benign | Windows Defender network inspection service; normal security product. |
| scranton.dmevals.local | C:\ProgramData\victim\â€®cod.3aka3.scr | 1 | C:\Windows\explorer.exe | malicious | Screensaver-named binary in C:\ProgramData\victim launched by explorer.exe with /S at 02:55:56, wrote C:\Users\pbeesly\Downloads\monkey.png and spawned cmd.exe/… |
| scranton.dmevals.local | C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe | 2 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | malicious | Invoked twice by powershell.exe compiling attacker source (qkbkqqbs.cmdline, 0piklvia.cmdline) into DLLs in the user Temp directory — in-memory/on-disk payload … |
| scranton.dmevals.local | C:\Windows\System32\hostui.exe | 1 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | suspicious | Rare binary started by powershell.exe as pbeesly at 03:21:27 with no arguments; not a normal user-launched process and follows the attacker's PowerShell activit… |
| scranton.dmevals.local | C:\Windows\System32\sdclt.exe | 3 | C:\Windows\System32\cmd.exe | suspicious | Three sdclt.exe executions from cmd.exe at 02:58:42-43 (UAC bypass/backup-related LOLBin) immediately before csc.exe compilation and Recent\Backup and Restore l… |
| scranton.dmevals.local | C:\WindowsAzure\Packages\GuestAgent\BfeToolWin8.exe | 1 | C:\WindowsAzure\Packages\GuestAgent\WindowsAzureGuestAgent.exe | benign | Azure guest agent firewall helper; standard platform component. |
| scranton.dmevals.local | C:\WindowsAzure\Packages\GuestAgent\FindVolume\FindVolume.exe | 1 | C:\WindowsAzure\Packages\GuestAgent\WindowsAzureGuestAgent.exe | benign | Azure guest agent volume discovery utility; standard platform component. |
| scranton.dmevals.local | C:\WindowsAzure\Packages\GuestAgent\WindowsAzureGuestAgent.exe | 1 | C:\Windows\System32\services.exe | benign | Azure guest agent service; standard platform component. |
| scranton.dmevals.local | C:\WindowsAzure\Packages\Telemetry\WindowsAzureTelemetryService.exe | 1 | C:\Windows\System32\services.exe | benign | Azure telemetry service; standard platform component. |
| scranton.dmevals.local | C:\WindowsAzure\Packages\WaAppAgent.exe | 1 | C:\Windows\System32\services.exe | benign | Azure VM agent; standard platform component. |
| scranton.dmevals.local | C:\WindowsAzure\SecAgent\WaSecAgentProv.exe | 2 | C:\WindowsAzure\Packages\WaAppAgent.exe | benign | Azure security agent provider; standard platform component. |
| scranton.dmevals.local | C:\WindowsAzure\WindowsAzureNetAgent_1.0.0.143\WindowsAzureNetAgent\Plugins\VFPl… | 1 | C:\WindowsAzure\WindowsAzureNetAgent_1.0.0.143\WindowsAzureNetAgent\WindowsAzure… | benign | Azure network agent plugin; standard platform component. |
| scranton.dmevals.local | C:\WindowsAzure\WindowsAzureNetAgent_1.0.0.143\WindowsAzureNetAgent\WindowsAzure… | 1 | C:\Windows\System32\services.exe | benign | Azure network agent service; standard platform component. |

## Technique conclusions

One line per technique in scope: status from the triage of its family; `not_observed` = checked, nothing found; `not_observable` = no dataset records it.

| Technique | Status | Reason |
|---|---|---|
| T1021 Remote Services | malicious | Remote service use from scranton.dmevals.local (10.0.1.4) by pbeesly against nashua.dmevals.local: WinRM Invoke-Command to NASHUA followed by four PsExec64 executions with cleartext credentials, PSEXESVC service installs… |
| T1021.001 Remote Desktop Protocol | suspicious | New: LogonType 2 interactive sessions for pbeesly on NASHUA at 03:11:40, 03:12:46, 03:13:49, 03:15:03, each paired with a PsExec network logon from 10.0.1.4 and PSEXESVC.exe/python.exe start. |
| T1021.002 SMB/Windows Admin Shares | suspicious | New: pbeesly LogonType 3 from 10.0.1.4 (SCRANTON) to NEWYORK at 03:04:04 followed by IPC$ share access, plus a further pbeesly network logon from 10.0.1.6 (NASHUA) at 03:14:20 — SMB access to the DC beyond the anchored N… |
| T1021.003 Distributed Component Object Model | not_observed | No DCOM artifacts: no LogonType 3 with svchost process name, no MMC20.Application/ShellWindows/ShellBrowserWindow script blocks; only a benign Invoke-CimMethod alias definition. |
| T1021.004 SSH | not_observed | No port 22 connections in sysmon or zeek, no sshd service installs, no ssh/plink script blocks. |
| T1021.005 VNC | not_observed | No port 5900 connections, no vnc/tvnserver binaries, services or script blocks. |
| T1021.006 Windows Remote Management | malicious | Invoke-Command -ComputerName NASHUA executed by pbeesly on SCRANTON with matching powershell.exe outbound TCP 5985 connections from 10.0.1.4 to 10.0.1.6, immediately preceding the PsExec movement to the same host. |
| T1072 Software Deployment Tools | malicious | Confirmed and extended: PsExec-deployed python.exe on NASHUA then deployed Rar.exe and sdelete64.exe into C:\Windows\Temp and executed them. |
| T1080 Taint Shared Content | not_observed | All share activity in the retrieved events is read-only or PsExec service staging, not tainting of shared content. 5145/5140 events touch only SYSVOL (read masks 0x100081/0x120089 on GPO files), IPC$ and ADMIN$; Zeek smb… |
| T1091 Replication Through Removable Media | not_observed | No removable-media activity exists in the data. All non-C: drive writes are fixed-disk operations: DFSRs.exe writing F:\System Volume Information\DFSR\Config\*.XML.TMP on newyork (14 events) and smss.exe creating D:\page… |
| T1210 Exploitation of Remote Services | suspicious | NEWYORK (DC) received pbeesly network logons and IPC$ access from both compromised hosts (10.0.1.4 and 10.0.1.6); no successful remote code execution observed there. |
| T1534 Internal Spearphishing | malicious | Internal spearphishing/lateral execution continued: PsExec with pbeesly's plaintext password launched python.exe on NASHUA four times, which then ran PowerShell, Rar and sdelete. |
| T1550 Use Alternate Authentication Material | malicious | Cleartext pbeesly credentials reused by PsExec64.exe from SCRANTON against NASHUA (four invocations with -u dmevals\pbeesly -p ...). |
| T1550.002 Pass the Hash | suspicious | One NTLM (NtLmSsp, NTLM V2) type-3 logon for pbeesly on scranton from 172.18.39.2, consistent with the PsExec alternate-credential move; no credential-dumping precursor or anomalous LSASS access, so pass-the-hash itself … |
| T1550.003 Pass the Ticket | not_observed | Kerberos 4769 requests are normal TGT/service-ticket acquisitions from 10.0.1.4; no PreAuthType 0 logons and zero Rubeus/kirbi/asktgt script blocks. |
| T1563 Remote Service Session Hijacking | not_observed | No session hijacking artifacts: no tscon/mstsc/qwinsta/query session process creations, no Enter-PSSession/New-PSSession script blocks. The 120 PowerShell 4104 matches were built-in CimCmdlets module text containing 'Ses… |
| T1563.002 RDP Hijacking | not_observed | The single inbound 3389 connection (scranton, 172.18.39.2 -> 10.0.1.4, Initiated false) corresponds to a legitimate new RDP logon for pbeesly (LogonType 10, User32, TerminalSessionId 2, rdpclip.exe child of TermService).… |
| T1570 Lateral Tool Transfer | malicious | New: Rar.exe and sdelete64.exe written into C:\Windows\Temp on NASHUA by the attacker's python.exe and executed for archiving and anti-forensic deletion; Sysinternals suite downloaded to SCRANTON. |

## Coverage

Cells: number of hits of the planned checks, `n/a` (reason in report.json), or GAP.

| Technique | windows.other | windows.powershell | windows.security | windows.sysmon | zeek |
|---|---|---|---|---|---|
| T1021 Remote Services | 10 hits | 4 hits | 750 hits | 1308 hits | 666 hits |
| T1021.001 Remote Desktop Protocol | 0 hits | 0 hits | 4 hits | 1 hits | 0 hits |
| T1021.002 SMB/Windows Admin Shares | 0 hits | 43 hits | 192 hits | 73 hits | 23 hits |
| T1021.003 Distributed Component Object Model | 3 hits | 0 hits | 1 hits | 940 hits | 123 hits |
| T1021.004 SSH | 0 hits | 0 hits | 218 hits | 447 hits | 0 hits |
| T1021.005 VNC | 0 hits | 0 hits | 218 hits | 0 hits | 0 hits |
| T1021.006 Windows Remote Management | 11 hits | 1 hits | 609 hits | 1 hits | 8 hits |
| T1072 Software Deployment Tools | 5 hits | 2 hits | 460 hits | 447 hits | 613 hits |
| T1080 Taint Shared Content | 29 hits | 1 hits | 284 hits | 3298 hits | 12 hits |
| T1091 Replication Through Removable Media | 8 hits | 0 hits | 460 hits | 0 hits | 2140 hits |
| T1210 Exploitation of Remote Services | 0 hits | 1 hits | 297 hits | 60850 hits | 53 hits |
| T1534 Internal Spearphishing | 7 hits | 10 hits | 524 hits | 447 hits | 62 hits |
| T1550 Use Alternate Authentication Material | 5 hits | 1 hits | 609 hits | 447 hits | n/a |
| T1550.002 Pass the Hash | 5 hits | 0 hits | 219 hits | 39415 hits | n/a |
| T1550.003 Pass the Ticket | 5 hits | 0 hits | 435 hits | 39301 hits | n/a |
| T1563 Remote Service Session Hijacking | n/a | 0 hits | 314 hits | 13 hits | n/a |
| T1563.002 RDP Hijacking | 5 hits | 120 hits | 4 hits | 1 hits | n/a |
| T1570 Lateral Tool Transfer | n/a | 1 hits | 205 hits | 1649 hits | n/a |

Cells: 90, gaps: 0.

## Queries

Every MCP tool call of this run (653), in order (source: mcp_audit.jsonl written by the MCP server).

| Query | Phase | Tool | Arguments | Hits / rows | Cited by |
|---|---|---|---|---|---|
| q-8bafad126e | scope | list_data_sources | {} | None |  |
| q-dd974cb134 | scope | get_registry | {} | None |  |
| q-22bbc86482 | scope | get_fields | {"dataset": "windows.other", "prefix": ""} | None |  |
| q-f7a681daf7 | scope | get_fields | {"dataset": "windows.powershell", "prefix": ""} | None |  |
| q-5927588f7f | scope | get_fields | {"dataset": "windows.security", "prefix": ""} | None |  |
| q-fa2554e443 | scope | get_fields | {"dataset": "windows.sysmon", "prefix": ""} | None |  |
| q-2922143b6f | scope | get_fields | {"dataset": "zeek", "prefix": ""} | None |  |
| q-94912660a4 | check C001 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 297 |  |
| q-1d33423623 | check C002 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4624 AND (win.LogonType:3 OR win.LogonType:10)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 220 |  |
| q-59de4e3d01 | check C003 | aggregate | {"dataset": "windows.security", "field": "win.IpAddress", "query": "event.code:4624 AND win.LogonType:3", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 218 |  |
| q-ac9203fe22 | check C004 | search | {"dataset": "windows.security", "query": "event.code:4648", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 15 | F01 |
| q-aefd72d6b6 | check C005 | aggregate | {"dataset": "windows.sysmon", "field": "destination.port", "query": "event.code:3", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1229 |  |
| q-5370e05846 | check C006 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:3 AND (destination.port:445 OR destination.port:3389 OR destination.port:5985 OR destination.port:5986 OR destination.port:22 OR destination.port:5900)", "time_from": null, "time… | 79 |  |
| q-c77c948eee | check C007 | search | {"dataset": "windows.sysmon", "query": "event.code:22 AND (win.QueryName:*Admin$* OR win.QueryName:*C$ OR win.QueryName:*IPC$ OR win.QueryName:*ADMIN$*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset… | 0 |  |
| q-15f73bfd33 | check C008 | aggregate | {"dataset": "windows.other", "field": "win.ServiceName", "query": "event.code:7045", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 5 |  |
| q-9276a6f139 | check C009 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 | F01 |
| q-ecb946390c | check C010 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Invoke-Command* OR win.ScriptBlockText:*New-PSSession* OR win.ScriptBlockText:*Enter-PSSession* OR win.ScriptBlockText:*Invoke-WmiMethod* OR win.ScriptBlockText:*Invoke-CimMe… | 4 | F04 |
| q-cf992ef430 | check C011 | aggregate | {"dataset": "zeek", "field": "destination.port", "query": "event.action:conn", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 613 |  |
| q-ab82db0de1 | check C012 | search | {"dataset": "zeek", "query": "event.action:conn AND (destination.port:445 OR destination.port:3389 OR destination.port:5985 OR destination.port:22 OR destination.port:5900)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.n… | 53 | F05 |
| q-9c0232970f | check C013 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4624 AND win.LogonType:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 2 |  |
| q-df22a5c1d0 | check C014 | aggregate | {"dataset": "windows.security", "field": "win.IpAddress", "query": "event.code:4624 AND win.LogonType:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 2 |  |
| q-471d03a44e | check C015 | search | {"dataset": "windows.security", "query": "event.code:4624 AND win.LogonType:10 AND win.AuthenticationPackageName:NTLM", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "proc… | 0 |  |
| q-e325d39874 | check C016 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:3 AND destination.port:3389", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1 |  |
| q-f3c51ad07a | check C017 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.executable:*mstsc* OR process.command_line:*mstsc*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "proc… | 0 |  |
| q-a394d14886 | check C018 | search | {"dataset": "windows.other", "query": "event.code:4778 OR event.code:4779", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "so… | 0 |  |
| q-381d0e74cf | check C019 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*mstsc* OR win.ScriptBlockText:*3389*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name",… | 0 |  |
| q-1c153ef808 | check C020 | search | {"dataset": "zeek", "query": "event.action:conn AND destination.port:3389", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "so… | 0 |  |
| q-dcc5a8a3cb | check C021 | aggregate | {"dataset": "windows.security", "field": "win.ShareName", "query": "event.code:5140", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 42 |  |
| q-f9bae6b3e1 | check C022 | aggregate | {"dataset": "windows.security", "field": "win.SubjectUserName", "query": "event.code:5140 AND (win.ShareName:*ADMIN$ OR win.ShareName:*C$ OR win.ShareName:*IPC$)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 29 |  |
| q-a6f37e0cc5 | check C023 | aggregate | {"dataset": "windows.security", "field": "win.IpAddress", "query": "event.code:5145", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 121 |  |
| q-ca563f5882 | check C024 | search | {"dataset": "windows.security", "query": "event.code:5145 AND (win.RelativeTargetName:*\\\\.exe OR win.RelativeTargetName:*\\\\.dll OR win.RelativeTargetName:*\\\\.bat OR win.RelativeTargetName:*\\\\.ps1)", "time_from": null, "time_to": null, "fields": ["@time… | 0 |  |
| q-e07ab2dfe4 | check C025 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:3 AND destination.port:445", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 66 |  |
| q-839fccd30f | check C026 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*\\\\\\\\* OR process.command_line:*ADMIN$* OR process.command_line:*IPC$*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.datas… | 7 |  |
| q-3c7be1ea70 | check C027 | search | {"dataset": "windows.other", "query": "event.code:7045 AND (win.ImagePath:*\\\\\\\\* OR win.ImagePath:*ADMIN$* OR win.ImagePath:*Temp*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", … | 0 |  |
| q-c1952cb2f9 | check C028 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Copy-Item*ADMIN$* OR win.ScriptBlockText:*net use* OR win.ScriptBlockText:*\\\\\\\\*ADMIN$*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "obse… | 43 |  |
| q-71f87f7749 | check C029 | aggregate | {"dataset": "zeek", "field": "zeek.filename", "query": "event.action:smb_files", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 12 |  |
| q-c98289a79e | check C030 | search | {"dataset": "zeek", "query": "event.action:smb_mapping", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 11 |  |
| q-f5f0c9a32d | check C031 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4624 AND win.LogonType:3 AND win.AuthenticationPackageName:NTLM", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1 |  |
| q-6dd0889f53 | check C032 | search | {"dataset": "windows.security", "query": "event.code:4624 AND win.LogonType:3 AND win.ProcessName:*svchost*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.execut… | 0 |  |
| q-dd592df7bd | check C033 | aggregate | {"dataset": "windows.sysmon", "field": "process.parent.executable", "query": "event.code:1 AND (process.parent.executable:*svchost* OR process.parent.executable:*mmc* OR process.parent.executable:*dllhost*)", "time_from": null, "time_to": null, "size": 50, "su… | 121 |  |
| q-439778c10d | check C034 | aggregate | {"dataset": "windows.sysmon", "field": "win.ImageLoaded", "query": "event.code:7 AND (win.ImageLoaded:*wbem* OR win.ImageLoaded:*combase* OR win.ImageLoaded:*ole32*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 753 |  |
| q-41b79b9160 | check C035 | search | {"dataset": "windows.sysmon", "query": "event.code:3 AND destination.port:135", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line",… | 66 |  |
| q-7581247a5b | check C036 | search | {"dataset": "windows.other", "query": "event.code:10016", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destina… | 3 |  |
| q-eca5a5d456 | check C037 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*MMC20.Application* OR win.ScriptBlockText:*ShellBrowserWindow* OR win.ScriptBlockText:*ShellWindows* OR win.ScriptBlockText:*CreateInstance*)", "time_from": null, "time_to": … | 0 |  |
| q-862da5e568 | check C038 | search | {"dataset": "zeek", "query": "event.action:dce_rpc", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destination.… | 123 |  |
| q-15ed0d93c3 | check C039 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:3 AND destination.port:22", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-4552fa2386 | check C040 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.executable:*ssh* OR process.command_line:*ssh *)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process… | 447 |  |
| q-b4fea8ebda | check C041 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4624 AND win.LogonType:3 AND win.AuthenticationPackageName:*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 218 |  |
| q-a662780a26 | check C042 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*ssh * OR win.ScriptBlockText:*New-PSSession* -HostName* OR win.ScriptBlockText:*plink*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.… | 0 |  |
| q-84deb77d55 | check C043 | search | {"dataset": "windows.other", "query": "event.code:7045 AND (win.ImagePath:*sshd* OR win.ServiceName:*ssh*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executa… | 0 |  |
| q-18022c2f60 | check C044 | search | {"dataset": "zeek", "query": "event.action:conn AND destination.port:22", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "sour… | 0 |  |
| q-3f5d2768b2 | check C045 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:3 AND destination.port:5900", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-d0ec56065b | check C046 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.executable:*vnc* OR process.command_line:*vnc*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.… | 0 |  |
| q-e87715c45a | check C047 | search | {"dataset": "windows.other", "query": "event.code:7045 AND (win.ImagePath:*vnc* OR win.ServiceName:*vnc* OR win.ServiceName:*tvnserver*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code",… | 0 |  |
| q-86fdf826d7 | check C048 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4624 AND win.LogonType:3", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 218 |  |
| q-42659d68e0 | check C049 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*vnc* OR win.ScriptBlockText:*5900*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "… | 0 |  |
| q-48f0613160 | check C050 | search | {"dataset": "zeek", "query": "event.action:conn AND destination.port:5900", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "so… | 0 |  |
| q-8d241a2e9b | check C051 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 297 |  |
| q-363f0ee712 | check C052 | aggregate | {"dataset": "windows.security", "field": "win.LogonProcessName", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 297 |  |
| q-6cbeef0102 | check C053 | search | {"dataset": "windows.security", "query": "event.code:4648", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 15 |  |
| q-d05a328d23 | check C054 | search | {"dataset": "windows.other", "query": "event.code:6", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destination… | 11 |  |
| q-31d2015a30 | check C055 | aggregate | {"dataset": "windows.sysmon", "field": "process.parent.executable", "query": "event.code:1 AND (process.executable:*wsmprovhost* OR process.parent.executable:*wsmprovhost*)", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 1 |  |
| q-52fdab0caf | check C056 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Enter-PSSession* OR win.ScriptBlockText:*New-PSSession* OR win.ScriptBlockText:*Invoke-Command*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "… | 1 |  |
| q-eac4374ff4 | check C057 | aggregate | {"dataset": "zeek", "field": "destination.port", "query": "event.action:conn AND (destination.port:5985 OR destination.port:5986)", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 8 |  |
| q-28fcacbd49 | check C058 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 460 |  |
| q-28781b879a | check C059 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*ccmsetup* OR process.command_line:*Intune* OR process.command_line:*SMS*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.d… | 0 |  |
| q-79877b0035 | check C060 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 | F07, F08 |
| q-a77d782ca2 | check C061 | aggregate | {"dataset": "windows.sysmon", "field": "process.parent.executable", "query": "event.code:1", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 447 |  |
| q-d96d898469 | check C062 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Invoke-Command* OR win.ScriptBlockText:*Start-Process*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.c… | 2 |  |
| q-daf2914c7d | check C063 | aggregate | {"dataset": "zeek", "field": "destination.port", "query": "event.action:conn", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 613 |  |
| q-1b9e207ca4 | check C064 | aggregate | {"dataset": "windows.security", "field": "win.ShareName", "query": "event.code:5145", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 121 |  |
| q-4502c1a1f3 | check C065 | search | {"dataset": "windows.security", "query": "event.code:5145 AND win.AccessMask:*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line"… | 121 | F09 |
| q-ac301145e1 | check C066 | aggregate | {"dataset": "windows.security", "field": "win.ShareName", "query": "event.code:5140", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 42 |  |
| q-316cb43840 | check C067 | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1649 |  |
| q-25c81b3109 | check C068 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*\\\\* OR file.path:*\\\\\\\\*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", … | 1649 | F09 |
| q-ac6eafecf1 | check C069 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Copy-Item* OR win.ScriptBlockText:*Out-File* OR win.ScriptBlockText:*Set-Content*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name"… | 1 |  |
| q-83ee184f24 | check C070 | aggregate | {"dataset": "zeek", "field": "zeek.filename", "query": "event.action:smb_files", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 12 |  |
| q-a80ab68064 | check C071 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.executable:*\\\\D:* OR process.executable:*\\\\E:* OR process.executable:*\\\\F:* OR process.executable:*\\\\G:* OR process.executable:*\\\\H:*)", "time_from": null, "time_to": null, "fields": [… | ERROR |  |
| q-5b19a35bac | check C071 (repaired) | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.executable:*\\\\D:* OR process.executable:*\\\\E:* OR process.executable:*\\\\F:* OR process.executable:*\\\\G:* OR process.executable:*\\\\H:*)", "time_from": null, "time_to": null, "fields": [… | ERROR |  |
| q-3ccbb56bf4 | check C072 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*\\\\D:* OR file.path:*\\\\E:* OR file.path:*\\\\F:* OR file.path:*\\\\G:* OR file.path:*\\\\H:*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", … | ERROR |  |
| q-b4b434e7ec | check C072 (repaired) | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*\\\\D\\:* OR file.path:*\\\\E\\:* OR file.path:*\\\\F\\:* OR file.path:*\\\\G\\:* OR file.path:*\\\\H\\:*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observ… | 0 |  |
| q-bccf94a6ca | check C073 | search | {"dataset": "windows.other", "query": "event.code:1006 OR event.code:2004 OR event.code:2006", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process… | 8 |  |
| q-ca9620d2e2 | check C074 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 460 |  |
| q-6a51d54621 | check C075 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*D:\\* OR win.ScriptBlockText:*E:\\* OR win.ScriptBlockText:*F:\\*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset… | ERROR |  |
| q-db85024f64 | check C075 (repaired) | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*D\\\\:* OR win.ScriptBlockText:*E\\\\:* OR win.ScriptBlockText:*F\\\\:*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.d… | ERROR |  |
| q-2fa99beaab | check C076 | aggregate | {"dataset": "zeek", "field": "event.action", "query": "*", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 2140 |  |
| q-487e45a942 | check C077 | aggregate | {"dataset": "windows.sysmon", "field": "destination.port", "query": "event.code:3", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1229 |  |
| q-1102877f24 | check C078 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:3 AND (destination.port:445 OR destination.port:3389 OR destination.port:5985 OR destination.port:5986)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 79 |  |
| q-b121edfaea | check C079 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-485192173f | check C080 | aggregate | {"dataset": "windows.sysmon", "field": "win.ImageLoaded", "query": "event.code:7", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 20259 |  |
| q-13f3b2a1fb | check C081 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 297 |  |
| q-64d44e6090 | check C082 | search | {"dataset": "windows.other", "query": "event.code:1000 OR event.code:1001", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "so… | 0 |  |
| q-1810667bb6 | check C083 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Invoke-Shellcode* OR win.ScriptBlockText:*DownloadString* OR win.ScriptBlockText:*IEX*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.… | 1 |  |
| q-9ed12ed9cc | check C084 | aggregate | {"dataset": "zeek", "field": "destination.port", "query": "event.action:conn AND (destination.port:445 OR destination.port:3389 OR destination.port:5985 OR destination.port:5986)", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 53 |  |
| q-2787bfe10b | check C085 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 297 |  |
| q-94a99efbc8 | check C086 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-4bcf97cf33 | check C087 | aggregate | {"dataset": "windows.security", "field": "win.PrivilegeList", "query": "event.code:4672", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 212 |  |
| q-2d13c1540d | check C088 | search | {"dataset": "windows.security", "query": "event.code:4648", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 15 |  |
| q-16704c0116 | check C089 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 447 |  |
| q-8dcf263055 | check C090 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*http* OR win.ScriptBlockText:*attachment* OR win.ScriptBlockText:*mail*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.d… | 10 | F17 |
| q-0485eeb629 | check C091 | search | {"dataset": "windows.other", "query": "event.code:1 OR event.code:11", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.… | 7 | F17 |
| q-69bba07916 | check C092 | aggregate | {"dataset": "zeek", "field": "url.domain", "query": "event.action:http", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 62 |  |
| q-7833a50bc4 | check C093 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 297 |  |
| q-ae957517ed | check C094 | aggregate | {"dataset": "windows.security", "field": "win.AuthenticationPackageName", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 297 |  |
| q-ae8cd475a2 | check C095 | search | {"dataset": "windows.security", "query": "event.code:4648", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 15 |  |
| q-4e9a1fcf1b | check C096 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 447 |  |
| q-e5c4fd8202 | check C097 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Invoke-Command* OR win.ScriptBlockText:*New-PSSession* OR win.ScriptBlockText:*Enter-PSSession*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "… | 1 | F18 |
| q-a392280f3a | check C098 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 | F18 |
| q-98be28e307 | check C099 | aggregate | {"dataset": "windows.security", "field": "win.LogonProcessName", "query": "event.code:4624 AND win.LogonType:3", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 218 |  |
| q-877e260b1a | check C100 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4624 AND win.AuthenticationPackageName:NTLM", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1 |  |
| q-5f83990d6d | check C101 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 39283 |  |
| q-ff5786c6b6 | check C102 | search | {"dataset": "windows.sysmon", "query": "event.code:3 AND (destination.port:445 OR destination.port:135)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable… | 132 |  |
| q-5749286bf4 | check C103 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*mimikatz* OR win.ScriptBlockText:*sekurlsa* OR win.ScriptBlockText:*Invoke-Mimikatz*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.na… | 0 |  |
| q-938cf68f34 | check C104 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-9fd7c4e769 | check C105 | aggregate | {"dataset": "windows.security", "field": "win.PreAuthType", "query": "event.code:4624 AND win.AuthenticationPackageName:Kerberos", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 217 |  |
| q-03e7497fb8 | check C106 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4624 AND win.LogonType:3", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 218 |  |
| q-4c97b6f1db | check C107 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 39283 |  |
| q-8950767205 | check C108 | search | {"dataset": "windows.sysmon", "query": "event.code:7 AND (win.ImageLoaded:*kerberos* OR win.ImageLoaded:*kdc*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.exe… | 18 |  |
| q-701041041f | check C109 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Rubeus* OR win.ScriptBlockText:*kirbi* OR win.ScriptBlockText:*asktgt*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.da… | 0 |  |
| q-fe4a0971ab | check C110 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-475e495bbd | check C111 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 297 |  |
| q-0fb7fc539c | check C112 | aggregate | {"dataset": "windows.security", "field": "win.IpAddress", "query": "event.code:4624 AND win.LogonType:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 2 |  |
| q-14a9d1c2b2 | check C113 | search | {"dataset": "windows.security", "query": "event.code:4648", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 15 |  |
| q-3a6380b3d9 | check C114 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*mstsc* OR process.command_line:*ssh* OR process.command_line:*winrs*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-ae21c33f08 | check C115 | search | {"dataset": "windows.sysmon", "query": "event.code:3 AND (destination.port:3389 OR destination.port:22 OR destination.port:5985)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.n… | 13 |  |
| q-60fcd54366 | check C116 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Enter-PSSession* OR win.ScriptBlockText:*New-PSSession*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.… | 0 |  |
| q-ffcc793d17 | check C117 | aggregate | {"dataset": "windows.security", "field": "win.IpAddress", "query": "event.code:4624 AND win.LogonType:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 2 |  |
| q-8f8bc5752a | check C118 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4624 AND win.LogonType:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 2 |  |
| q-11aa3778bd | check C119 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*tscon* OR process.command_line:*mstsc*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-ca33bcc6ad | check C120 | search | {"dataset": "windows.sysmon", "query": "event.code:3 AND destination.port:3389", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line"… | 1 |  |
| q-6f6c6ed64a | check C121 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-4447684e6e | check C122 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*tscon* OR win.ScriptBlockText:*query session* OR win.ScriptBlockText:*qwinsta*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "… | 120 |  |
| q-ef986b9841 | check C123 | aggregate | {"dataset": "windows.security", "field": "win.ShareName", "query": "event.code:5140", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 42 |  |
| q-e2e21301e6 | check C124 | aggregate | {"dataset": "windows.security", "field": "win.IpAddress", "query": "event.code:5140", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 42 |  |
| q-d67e250095 | check C125 | search | {"dataset": "windows.security", "query": "event.code:5145", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 121 | F24 |
| q-0fe75c8aa2 | check C126 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1649 |  |
| q-9b230d0643 | check C127 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*copy* OR process.command_line:*xcopy* OR process.command_line:*robocopy*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.datase… | 0 |  |
| q-78a48e82cb | check C128 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Copy-Item* OR win.ScriptBlockText:*Invoke-WebRequest* OR win.ScriptBlockText:*DownloadFile*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "obse… | 1 |  |
| q-25042c1e20 | check C129 | aggregate | {"dataset": "windows.other", "field": "win.ServiceName", "query": "event.code:7045", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 5 |  |
| q-dfe1900123 | check C130 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-edca269a82 | check C131 | aggregate | {"dataset": "windows.other", "field": "win.ImagePath", "query": "event.code:7045", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 5 |  |
| q-446f51e628 | check C132 | search | {"dataset": "windows.other", "query": "event.code:11", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinatio… | 4 |  |
| q-ef0fe9cfa5 | check C133 | aggregate | {"dataset": "windows.other", "field": "file.path", "query": "event.code:11", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 4 |  |
| q-24997502b8 | check C134 | search | {"dataset": "windows.other", "query": "event.code:1", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destination… | 3 |  |
| q-82b7d9b4af | check C135 | aggregate | {"dataset": "windows.other", "field": "process.executable", "query": "event.code:1", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 3 |  |
| q-dad3c51741 | triage T1021 step 1 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cxoQzx"} | None | F01 |
| q-eedf0bc97a | triage T1021 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND process.executable:*PsExec*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command… | 4 |  |
| q-deff16df7d | triage T1021 step 1 | search | {"dataset": "windows.security", "query": "event.code:4624 AND win.LogonType:10", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line"… | 2 |  |
| q-809481db0a | triage T1021 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:3 AND (destination.port:5985 OR destination.port:3389)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executab… | 13 |  |
| q-27922b6776 | triage T1021 step 2 | search | {"dataset": "windows.security", "query": "event.code:5140 OR event.code:5145", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "win.ShareName", "win.SubjectUserName", "win.IpAddress", "win.RelativeTargetName", "user.name… | 163 |  |
| q-e010f19792 | triage T1021 step 2 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nKg4v2"} | None | F03 |
| q-a95c00adfc | triage T1021 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:3 AND destination.port:5985", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line"… | 12 | F02, F06 |
| q-4e3249cc6c | triage T1021 step 3 | search | {"dataset": "windows.security", "query": "event.code:5140 AND win.ShareName:*ADMIN$", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_… | 9 | F01 |
| q-d834c4cc01 | triage T1021 step 3 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Invoke-Command* OR win.ScriptBlockText:*PSSession* OR win.ScriptBlockText:*PsExec* OR win.ScriptBlockText:*python*)", "time_from": null, "time_to": null, "fields": ["@timesta… | 5 | F01, F02 |
| q-da306f3cd9 | triage T1021 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cxoQzx"} | None |  |
| q-9858c70456 | triage T1021 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cxoQzx"} | None |  |
| q-595cc78b28 | triage T1021 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qrRFHq"} | None |  |
| q-2c1b96b027 | triage T1021 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuCk"} | None |  |
| q-0de476cc2b | triage T1021 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNvI"} | None |  |
| q-2510f0a0cb | triage T1021 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNur"} | None |  |
| q-d9c5ac2dc1 | triage T1021 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qrRbzS"} | None |  |
| q-c6c158acd1 | triage T1021 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c-4MbN"} | None |  |
| q-ab785dfec7 | triage T1021 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c-4MbP"} | None |  |
| q-952eb3e252 | triage T1021 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nKg4v2"} | None |  |
| q-fd172b755a | triage T1021 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nKg4v2"} | None |  |
| q-10e7d540a0 | triage T1021 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nKg4v2"} | None |  |
| q-c537c6f3c7 | triage T1021 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qwTlue"} | None |  |
| q-25037c752b | triage T1021 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_aFZ1"} | None |  |
| q-4902e7de68 | triage T1021 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c-4MbN"} | None |  |
| q-8d3838fe54 | triage T1072 step 1 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.executable:*PsExec* OR process.executable:*PSEXESVC* OR process.executable:*sdelete* OR process.executable:*python*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.nam… | 19 | F07 |
| q-10e292fc55 | triage T1072 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.parent.executable:*PSEXESVC* OR process.executable:*PsExec* OR process.executable:*PSEXESVC* OR process.parent.executable:*cod.3aka3*)", "time_from": null, "time_to": null, "fields": ["@timestam… | 16 | F07 |
| q-3d2aa0f369 | triage T1072 step 2 | search | {"dataset": "windows.sysmon", "query": "host.name:nashua.dmevals.local AND (process.parent.executable:*python* OR process.executable:*python* OR event.code:3 OR event.code:11)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.na… | 830 |  |
| q-c8c0123d26 | triage T1072 step 2 | search | {"dataset": "windows.security", "query": "event.code:4624 AND win.LogonType:3", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "win.TargetUserName", "win.LogonType", "win.IpAddress", "win.Workstation", "win.Authenticatio… | 218 |  |
| q-6c06613c3e | triage T1072 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE host.name == \"nashua.dmevals.local\" AND (process.parent.executable LIKE \"*python*\" OR process.executable LIKE \"*python*\" OR process.parent.executable LIKE \"*PSEXESVC*\") \| KEEP @… | 60 |  |
| q-846ac30166 | triage T1072 step 3 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4624\" AND win.LogonType == \"3\" AND win.TargetUserName LIKE \"*pbeesly*\" \| KEEP @timestamp, host.name, win.TargetUserName, win.IpAddress, win.Workstation, win.Authe… | 20 |  |
| q-5aa2e0cdfa | triage T1072 step 4 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7h03AJQ"} | None | F07 |
| q-849c3b3ee9 | triage T1072 step 4 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.executable:*javamtsup* OR process.parent.executable:*javamtsup* OR process.executable:*hostui* OR process.executable:*logman*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "hos… | 10 | F08 |
| q-b94a210fb4 | triage T1072 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cxoQzx"} | None |  |
| q-4376915466 | triage T1072 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c82Oiy"} | None |  |
| q-a559b1e79c | triage T1072 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c82OhP"} | None |  |
| q-cf1e6614b3 | triage T1072 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c82OhP"} | None |  |
| q-c174970bd1 | triage T1072 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuCk"} | None |  |
| q-391329c7a2 | triage T1072 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNv3"} | None |  |
| q-a97afb6470 | triage T1072 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7h03AJQ"} | None |  |
| q-0562923eec | triage T1072 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cfUP4A"} | None |  |
| q-f5daff3242 | triage T1072 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cxpAy5"} | None |  |
| q-d977ebf2a5 | triage T1072 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuDg"} | None |  |
| q-3033dfca0b | triage T1080 step 1 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == 5145 \| STATS cnt = COUNT(*) BY win.ShareName, win.AccessMask, win.RelativeTargetName, user.name, source.ip \| SORT cnt DESC \| LIMIT 50"} | ERROR |  |
| q-49167d2324 | triage T1080 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None | F09 |
| q-e8b20d98e8 | triage T1080 step 2 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"5145\" \| STATS cnt = COUNT(*) BY win.ShareName, win.AccessMask, win.RelativeTargetName, user.name, source.ip \| SORT cnt DESC \| LIMIT 50"} | 50 |  |
| q-360c8d5d98 | triage T1080 step 2 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"5140\" \| STATS cnt = COUNT(*) BY win.ShareName, win.ShareLocalPath, user.name, source.ip, host.name \| SORT cnt DESC \| LIMIT 50"} | 11 |  |
| q-b4d4b7c090 | triage T1080 step 3 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"5145\" AND win.ShareName LIKE \"*ADMIN$*\" AND win.RelativeTargetName LIKE \"*python*\" \| KEEP @timestamp, host.name, user.name, source.ip, win.ShareName, win.AccessMa… | 3 |  |
| q-8b4eafe162 | triage T1080 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*sysvol*\" OR TO_LOWER(file.path) LIKE \"*\\\\\\\\*\") \| KEEP @timestamp, host.name, user.name, process.executable, file.path \| LIM… | 40 |  |
| q-68d066ef8e | triage T1080 step 4 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"smb_files\" OR event.action == \"smb_mapping\" \| KEEP @timestamp, event.action, source.ip, destination.ip, zeek.filename, zeek.path, zeek.name, zeek.share_type, zeek.action, zee… | 23 |  |
| q-6ae591a0c9 | triage T1080 step 4 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"5145\" AND win.RelativeTargetName LIKE \"*PSEXESVC*\" \| KEEP @timestamp, host.name, user.name, source.ip, win.ShareName, win.AccessMask, win.RelativeTargetName \| LIMI… | 20 |  |
| q-2de443f9da | triage T1080 step 5 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"smb_files\" \| STATS cnt = COUNT(*) BY zeek.action, zeek.path \| SORT cnt DESC \| LIMIT 30"} | 1 |  |
| q-1fdfadec32 | triage T1080 step 5 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7ns-ApD"} | None | F09 |
| q-5c50d1b0d2 | triage T1080 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7ns-ApD"} | None |  |
| q-38aa60050e | triage T1080 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7ns-ApD"} | None |  |
| q-41b6ea77d3 | triage T1080 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7ns-ApD"} | None |  |
| q-a0de3a7546 | triage T1080 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7rxEjIW"} | None |  |
| q-6ad0bc45c0 | triage T1080 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7pNHuDg"} | ERROR |  |
| q-60df625212 | triage T1080 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuCk"} | None |  |
| q-1a81738021 | triage T1080 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None |  |
| q-84088601cf | triage T1080 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hx0G9q"} | None |  |
| q-da75090822 | triage T1080 step 7 | esql | {"query": "FROM logs-windows.other-default METADATA _id, _index \| WHERE event.code == \"7045\" \| KEEP @timestamp, host.name, user.name, win.ServiceName, win.ImagePath, _id, _index \| LIMIT 10"} | 5 | F09 |
| q-a871290f74 | triage T1091 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*\\\\D\\\\* OR file.path:*\\\\E\\\\* OR file.path:*\\\\F\\\\* OR file.path:*\\\\G\\\\* OR file.path:*\\\\H\\\\* OR file.path:*\\\\D: OR file.path:*\\\\E: OR file.path:*\\\\F:)", "time_from": … | ERROR |  |
| q-1979b33f11 | triage T1091 step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 11 AND (TO_LOWER(file.path) LIKE \"*\\\\\\\\?\\\\d:*\" OR TO_LOWER(file.path) LIKE \"*\\\\\\\\?\\\\e:*\" OR TO_LOWER(file.path) LIKE \"*\\\\\\\\?\\\\f:*\" OR TO_LOWER(file.… | ERROR |  |
| q-2dceb98f18 | triage T1091 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 11 AND (TO_LOWER(file.path) LIKE \"*d:*\" OR TO_LOWER(file.path) LIKE \"*e:*\" OR TO_LOWER(file.path) LIKE \"*f:*\" OR TO_LOWER(file.path) LIKE \"*g:*\" OR TO_LOWER(file.pa… | ERROR |  |
| q-ced297b3fc | triage T1091 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 1 AND (TO_LOWER(process.executable) LIKE \"*psexec*\" OR TO_LOWER(process.executable) LIKE \"*sdelete*\" OR TO_LOWER(process.executable) LIKE \"*\\\\\\\\temp\\\\\\\\*\" OR … | ERROR |  |
| q-c47e14bcbe | triage T1091 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*d:*\" OR TO_LOWER(file.path) LIKE \"*e:*\" OR TO_LOWER(file.path) LIKE \"*f:*\" OR TO_LOWER(file.path) LIKE \"*g:*\" OR TO_LOWER(fil… | 15 | F10 |
| q-762b97d6aa | triage T1091 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.executable) LIKE \"*psexec*\" OR TO_LOWER(process.executable) LIKE \"*sdelete*\" OR TO_LOWER(process.executable) LIKE \"*temp*\" OR TO_LOWER(pro… | 16 | F11 |
| q-b26b576b25 | triage T1091 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*\\\\\\\\?\\\\d:*\" OR TO_LOWER(file.path) LIKE \"*\\\\\\\\?\\\\e:*\" OR TO_LOWER(file.path) LIKE \"*\\\\\\\\?\\\\f:*\" OR TO_LOWER(f… | ERROR |  |
| q-de9a37aff5 | triage T1091 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*\\\\\\\\?\\\\d:*\" OR TO_LOWER(file.path) LIKE \"*\\\\\\\\?\\\\e:*\" OR TO_LOWER(file.path) LIKE \"*\\\\\\\\?\\\\f:*\" OR TO_LOWER(f… | ERROR |  |
| q-4f378835a0 | triage T1091 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*usb*\" OR TO_LOWER(file.path) LIKE \"*removable*\" OR TO_LOWER(file.path) LIKE \"*volume*\" OR TO_LOWER(file.path) LIKE \"*d:*\" OR … | 7 |  |
| q-07cc99e24b | triage T1091 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*usb*\" OR TO_LOWER(file.path) LIKE \"*removable*\" OR TO_LOWER(file.path) LIKE \"*volume*\" OR TO_LOWER(file.path) LIKE \"*d:*\" OR … | 19 | F10 |
| q-b231f629b9 | triage T1091 step 6 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hwyqf3"} | None | F10 |
| q-9335b641ac | triage T1091 step 6 | esql | {"query": "FROM logs-windows.other-default METADATA _id, _index \| WHERE TO_LOWER(message) LIKE \"*usb*\" OR TO_LOWER(message) LIKE \"*removable*\" OR TO_LOWER(message) LIKE \"*volume*\" OR TO_LOWER(win.DeviceName) LIKE \"*usb*\" OR TO_LOWER(win.DriveName) LIK… | 4 | F10 |
| q-5045a72084 | triage T1091 step 7 | esql | {"query": "FROM logs-windows.security METADATA _id, _index \| WHERE event.code == \"4688\" AND (TO_LOWER(process.executable) LIKE \"*psexec*\" OR TO_LOWER(process.executable) LIKE \"*psexesvc*\" OR TO_LOWER(process.executable) LIKE \"*\\\\\\\\temp\\\\\\\\*\") … | ERROR |  |
| q-76bfefa4ab | triage T1091 step 7 | esql | {"query": "FROM logs-windows.security METADATA _id, _index \| WHERE event.code == \"4624\" AND win.LogonType == \"3\" \| STATS c = COUNT(*) BY win.TargetUserName, source.ip, host.name"} | ERROR |  |
| q-f31bc56ccf | triage T1091 step 8 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.executable:*PsExec* OR process.executable:*PSEXESVC* OR process.executable:*\\\\Temp\\\\*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "process.… | 17 | F11 |
| q-df1fec87b4 | triage T1091 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hwyqf3"} | None |  |
| q-c37d66a4c8 | triage T1091 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hwyqf3"} | None |  |
| q-b5dfd93a16 | triage T1091 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cxqOiA"} | None |  |
| q-b748a1cf7f | triage T1091 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cxqOiA"} | None |  |
| q-270d2c49a9 | triage T1091 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuA7"} | None |  |
| q-439cdf3309 | triage T1091 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hbcHo-"} | None |  |
| q-b7866b65ae | triage T1091 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cxoQzx"} | None |  |
| q-6021cb938d | triage T1091 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cwoB6l"} | None |  |
| q-3e9145f23a | triage T1091 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c4xY6Y"} | None |  |
| q-fe355249b1 | triage T1091 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c1t6d3"} | None |  |
| q-f540a1456e | triage T1091 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNuP"} | None |  |
| q-6327629e6d | triage T1210 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7q0Y_4v"} | None | F14 |
| q-81420ee4a3 | triage T1210 step 1 | aggregate | {"dataset": "windows.sysmon", "field": "destination.ip", "query": "event.code:3 AND (destination.port:445 OR destination.port:3389 OR destination.port:5985 OR destination.port:5986)", "time_from": null, "time_to": null, "size": 50, "sub_field": "process.execut… | 79 |  |
| q-03494350d9 | triage T1210 step 1 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4624 AND win.LogonType:3", "time_from": null, "time_to": null, "size": 50, "sub_field": "source.ip"} | 218 |  |
| q-64cc0e0433 | triage T1210 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:3 AND destination.ip:10.0.1.6 AND process.executable:*powershell*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "process.executable", "process.command_line", "destina… | 4 | F12, F15 |
| q-4ffcea3e4d | triage T1210 step 2 | search | {"dataset": "windows.security", "query": "event.code:4624 AND win.LogonType:3 AND win.TargetUserName:pbeesly", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "win.TargetUserName", "win.LogonType", "win.IpAddress", "win.Workstation", … | 20 | F12 |
| q-ebede971ad | triage T1210 step 3 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND host.name:nashua.dmevals.local", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "process.executable", "process.command_line", "process.parent.executable", "process… | 61 |  |
| q-a0c79eca9c | triage T1210 step 3 | search | {"dataset": "windows.security", "query": "event.code:4624 AND win.LogonType:3 AND (win.TargetUserName:UTICA$ OR win.TargetUserName:NEWYORK$ OR win.TargetUserName:WEC$)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "win.TargetUserN… | 136 | F15 |
| q-4572768bb8 | triage T1210 step 4 | search | {"dataset": "windows.sysmon", "query": "host.name:nashua.dmevals.local AND (process.parent.executable:*wsmprovhost* OR process.executable:*wsmprovhost*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "event.code", "pro… | 491 | F12 |
| q-82b1acda84 | triage T1210 step 4 | aggregate | {"dataset": "windows.sysmon", "field": "host.name", "query": "event.code:3 AND destination.ip:10.0.0.4 AND destination.port:445", "time_from": null, "time_to": null, "size": 20, "sub_field": "process.executable"} | 26 |  |
| q-23a2622bc3 | triage T1210 step 5 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND host.name:nashua.dmevals.local AND process.parent.executable:*wsmprovhost*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "process.executable", "process.command_… | 0 |  |
| q-f8c4f2b0a6 | triage T1210 step 5 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND host.name:nashua.dmevals.local", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "win.ScriptBlockText"], "size": 20, "sort": "asc"} | 11 | F13 |
| q-8674d0aaf8 | triage T1210 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c-4MbN"} | None |  |
| q-6cddaf269d | triage T1210 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c-4MbN"} | None |  |
| q-a5afad21c0 | triage T1210 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c-4MbN"} | None |  |
| q-67369fb0fd | triage T1210 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c-4cYK"} | None |  |
| q-a9456e8993 | triage T1210 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niytuv"} | None |  |
| q-57d7b9d6bd | triage T1210 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niytuv"} | None |  |
| q-1fe9e2589a | triage T1210 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qrRC92"} | None |  |
| q-7ba9ca4e2a | triage T1210 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qrRC-J"} | None |  |
| q-9ec9659905 | triage T1210 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qqQm-i"} | None |  |
| q-d1a0283a9b | triage T1210 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qrRapX"} | None |  |
| q-58850358bb | triage T1210 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7q0Y_4v"} | None |  |
| q-56ba1bdcc7 | triage T1210 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7q0Y_4v"} | None |  |
| q-eac84f56d0 | triage T1210 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c-4MbN"} | None |  |
| q-19941c84cc | triage T1210 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7rxEjJI"} | None |  |
| q-48eefa2cf5 | triage T1534 step 1 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNur"} | None | F16 |
| q-518aedf546 | triage T1534 step 1 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nKg4v1"} | None |  |
| q-e0c4a8ce59 | triage T1534 step 1 | aggregate | {"dataset": "windows.sysmon", "field": "process.command_line", "query": "event.code:1 AND (process.executable:*PsExec* OR process.executable:*PSEXESVC* OR process.executable:*sdelete*)", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 14 |  |
| q-0133df2eff | triage T1534 step 1 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4624 AND win.LogonType:3", "time_from": null, "time_to": null, "size": 30, "sub_field": "host.name"} | 218 |  |
| q-cd1a654ba3 | triage T1534 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.executable:*PsExec* OR process.executable:*PSEXESVC* OR process.executable:*python.exe OR process.executable:*sdelete*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name"… | 19 | F16 |
| q-848f614b5e | triage T1534 step 2 | search | {"dataset": "windows.security", "query": "event.code:4624 AND win.TargetUserName:pbeesly", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "win.TargetUserName", "win.LogonType", "win.IpAddress", "win.Workstation", "win.LogonProcessNam… | 30 |  |
| q-17f7f4e966 | triage T1534 step 3 | search | {"dataset": "windows.sysmon", "query": "event.code:3 AND host.name:nashua.dmevals.local AND process.executable:*python*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "event.code", "process.executable", "destination.ip… | 348 | F16 |
| q-51417f146b | triage T1534 step 3 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "win.ServiceName", "win.ImagePath", "win.ServiceType", "win.ServiceStartType", "win.ServiceAccount", "message"], "size": 10, "sor… | 5 | F16 |
| q-7e8205d5e7 | triage T1534 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cxoQzx"} | None |  |
| q-9d63a6cef6 | triage T1534 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cxoQzx"} | None |  |
| q-122ab6ea30 | triage T1534 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuCk"} | None |  |
| q-9b34c8ec14 | triage T1534 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuCk"} | None |  |
| q-d30b29441a | triage T1534 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNur"} | None |  |
| q-85b5627e33 | triage T1534 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNur"} | None |  |
| q-90d3f8358d | triage T1534 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c82OhP"} | None |  |
| q-023675dd14 | triage T1534 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c82OhP"} | None |  |
| q-cfd9c2c67f | triage T1534 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c5ylrT"} | None |  |
| q-9a26c40d9b | triage T1534 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c5ylrT"} | None |  |
| q-a1172f000c | triage T1534 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hWVSlm"} | None |  |
| q-e3961167cc | triage T1534 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSyuh"} | None |  |
| q-9bf0e48d35 | triage T1534 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qwT1sV"} | None |  |
| q-a655feb4bc | triage T1534 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuBw"} | None |  |
| q-05e6c65792 | triage T1550 step 1 | search | {"dataset": "windows.security", "query": "event.code:4624 AND win.AuthenticationPackageName:NTLM", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "pro… | 1 | F19 |
| q-4edda752cc | triage T1550 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.executable:*PsExec* OR process.executable:*PSEXESVC* OR process.executable:*sdelete*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset"… | 14 | F18 |
| q-02ab91ba23 | triage T1550 step 2 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nQi3T7"} | None | F19 |
| q-ed9fcca54c | triage T1550 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 10 AND win.TargetImage LIKE \"*lsass*\" AND (win.GrantedAccess == \"0x1010\" OR win.GrantedAccess == \"0x1410\" OR win.GrantedAccess == \"0x1fffff\" OR win.GrantedAccess ==… | ERROR |  |
| q-cac125b806 | triage T1550 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND win.TargetImage LIKE \"*lsass*\" AND (win.GrantedAccess == \"0x1010\" OR win.GrantedAccess == \"0x1410\" OR win.GrantedAccess == \"0x1fffff\" OR win.GrantedAcces… | 4 |  |
| q-3ca792f6ba | triage T1550 step 3 | search | {"dataset": "windows.security", "query": "event.code:4768 OR event.code:4769 OR event.code:4770 OR event.code:4769", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process… | 42 | F20 |
| q-f31e6158f1 | triage T1550 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND win.TargetImage LIKE \"*lsass*\" AND win.GrantedAccess == \"0x1fffff\" \| KEEP @timestamp, host.name, process.executable, process.command_line, win.GrantedAccess… | 3 | F19 |
| q-49cc0800a8 | triage T1550 step 4 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4648\" \| KEEP @timestamp, host.name, user.name, process.executable, win.TargetServerName, win.TargetUserName, source.ip, _id, _index \| SORT @timestamp ASC"} | 15 | F18, F19 |
| q-5f2e64ee5d | triage T1550 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cxoQzx"} | None |  |
| q-0314f6f941 | triage T1550 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuCk"} | None |  |
| q-b4c937eb3b | triage T1550 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c82Oiy"} | None |  |
| q-d030538d70 | triage T1550 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niydsP"} | None |  |
| q-9df332a471 | triage T1550 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qrRbzS"} | None |  |
| q-cbae87ce01 | triage T1550 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cri_p-"} | None |  |
| q-252013a306 | triage T1550 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nQi3T7"} | None |  |
| q-9244640b93 | triage T1550 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nQi3T7"} | None |  |
| q-5bbdcb4c62 | triage T1550 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nQi3T7"} | None |  |
| q-8e08336d99 | triage T1550 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nKg4v1"} | None |  |
| q-9811ff3817 | triage T1550 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-3b5ac7b508 | triage T1550 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7njzKBN"} | None |  |
| q-7054a00c11 | triage T1550 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq72Yx"} | None |  |
| q-f1b68dadad | triage T1563 step 1 | search | {"dataset": "windows.security", "query": "event.code:4624 AND win.LogonType:10", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line"… | 2 |  |
| q-17c8ec6556 | triage T1563 step 1 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cdSewt"} | None | F22 |
| q-973cd90639 | triage T1563 step 1 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == 4104 AND (TO_LOWER(win.ScriptBlockText) LIKE \"*tscon*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*qwinsta*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*query session*\") … | ERROR |  |
| q-e74940243f | triage T1563 step 2 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*tscon*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*qwinsta*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*query session*… | 0 |  |
| q-04039f0deb | triage T1563 step 2 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nKg4v2"} | None | F21 |
| q-ad74212516 | triage T1563 step 3 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*tscon* OR win.ScriptBlockText:*query session* OR win.ScriptBlockText:*qwinsta*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "win.… | 120 | F21 |
| q-0accbce800 | triage T1563 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*tscon*\" OR TO_LOWER(process.command_line) LIKE \"*qwinsta*\" OR TO_LOWER(process.command_line) LIKE \"*query session*\" O… | 3 |  |
| q-2840f214ba | triage T1563 step 4 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRfJfH5wFd7b_zvXB"} | None | F21, F22 |
| q-06b357391c | triage T1563 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND host.name == \"scranton.dmevals.local\" AND @timestamp >= \"2020-05-02T03:18:00Z\" \| KEEP @timestamp, user.name, process.executable, process.command_line, proces… | 40 |  |
| q-60f48e6e74 | triage T1563 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND user.name == \"pbeesly\" AND (TO_LOWER(process.command_line) LIKE \"*invoke-expression*\" OR TO_LOWER(process.command_line) LIKE \"*hostui*\" OR TO_LOWER(process.… | 8 | F22 |
| q-5c2ca6d84b | triage T1563 step 5 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4624\" AND win.LogonType == \"3\" AND win.TargetUserName == \"pbeesly\" \| KEEP @timestamp, host.name, win.TargetUserName, win.IpAddress, win.WorkstationName, win.Logon… | 20 |  |
| q-418abcd71e | triage T1563 step 6 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND host.name == \"nashua.dmevals.local\" AND (TO_LOWER(process.executable) LIKE \"*python*\" OR TO_LOWER(process.executable) LIKE \"*psexesvc*\") \| KEEP @timestamp,… | 9 | F22 |
| q-f29316980d | triage T1563 step 6 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*hostui*\" OR TO_LOWER(file.path) LIKE \"*python*\") \| KEEP @timestamp, host.name, user.name, file.path, process.executable, _id, _i… | 12 |  |
| q-15cabd9d2b | triage T1563 step 7 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND host.name == \"scranton.dmevals.local\" AND (TO_LOWER(file.path) LIKE \"*hostui*\") \| KEEP @timestamp, file.path, process.executable, _id, _index \| LIMIT 20"} | 4 |  |
| q-949a8f0c2c | triage T1563 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nKg4v2"} | None |  |
| q-afba2922a6 | triage T1563 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nKg4v2"} | None |  |
| q-71e90ef013 | triage T1563 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRfJfH5wFd7b_zvXB"} | None |  |
| q-b9e853f837 | triage T1563 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRfJfH5wFd7b_zvXB"} | None |  |
| q-a24ad81f2f | triage T1563 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvTSui"} | None |  |
| q-11f392fd98 | triage T1563 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cdSewt"} | None |  |
| q-296ee67f40 | triage T1563 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cdSewt"} | None |  |
| q-ecbc90df2e | triage T1563 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRfJfH5wFd7b_zvXB"} | None |  |
| q-3d40696481 | triage T1563 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7h03AIc"} | None |  |
| q-2294cb8882 | triage T1563 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c82OhP"} | None |  |
| q-09e9733b73 | triage T1570 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND win.TargetFilename:*PSEXESVC*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.comm… | 8 | F23 |
| q-40a69af749 | triage T1570 step 1 | search | {"dataset": "windows.security", "query": "event.code:5140 AND win.ShareName:*ADMIN$", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_… | 9 |  |
| q-df4efb1457 | triage T1570 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None | F25 |
| q-2f8c340f19 | triage T1570 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.executable:*PSEXEC* OR process.parent.executable:*PSEXESVC* OR process.command_line:*PSEXESVC*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "even… | 8 |  |
| q-4c06eb98d3 | triage T1570 step 2 | search | {"dataset": "windows.security", "query": "event.code:5145 AND win.ShareName:*ADMIN$", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_… | 20 |  |
| q-cf7b110726 | triage T1570 step 3 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niytvL"} | None | F23 |
| q-133ecfed5d | triage T1570 step 3 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNu7"} | None | F23 |
| q-a74fa56090 | triage T1570 step 3 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND win.TargetFilename:*python.exe", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.com… | 1 | F23 |
| q-f416380fba | triage T1570 step 4 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c82Oiy"} | None | F23 |
| q-60c2ae5dcb | triage T1570 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 11 AND (TO_LOWER(win.TargetFilename) LIKE \"*psexesvc*\" OR TO_LOWER(win.TargetFilename) LIKE \"*\\\\\\\\temp\\\\\\\\*.exe\") \| KEEP @timestamp, host.name, win.TargetFilen… | ERROR |  |
| q-5922ed391a | triage T1570 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(win.TargetFilename) LIKE \"*psexesvc*\" OR TO_LOWER(win.TargetFilename) LIKE \"*\\\\\\\\temp\\\\\\\\*.exe\") \| KEEP @timestamp, host.name, win.TargetF… | 12 | F23 |
| q-caeb6674f0 | triage T1570 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNu7"} | None |  |
| q-8ddc2f8383 | triage T1570 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNu7"} | None |  |
| q-8ca060fade | triage T1570 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNu7"} | None |  |
| q-9567cfd66b | triage T1570 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niytvL"} | None |  |
| q-b543f08e7b | triage T1570 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7h03ALx"} | None |  |
| q-57a9b5e5df | triage T1570 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c82-ha"} | None |  |
| q-67a9f1544d | triage T1570 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c82Oiy"} | None |  |
| q-b99dba3157 | triage T1570 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c82Oiy"} | None |  |
| q-c8ca37ee88 | triage T1570 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c5yloe"} | None |  |
| q-316fa0c090 | triage T1570 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7culih9"} | None |  |
| q-c1122635e1 | triage T1570 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7rxEjIW"} | None |  |
| q-3f8ac110f8 | triage T1570 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7rxEjIW"} | None |  |
| q-e0dd33ebca | triage T1570 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7ns-ApD"} | None |  |
| q-9b500caa73 | triage T1570 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None |  |
| q-1dfb538a17 | triage T1570 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None |  |
| q-fc5c88b45e | triage T1570 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None |  |
| q-55f3adbee3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cxoQzx"} | None |  |
| q-c09628c2cb | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cxoQzx"} | None |  |
| q-c191e2e719 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qrRFHq"} | None |  |
| q-fee8bd8c5b | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuCk"} | None |  |
| q-9047317b01 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNvI"} | None |  |
| q-380fe9bc4e | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNur"} | None |  |
| q-b6d52d1283 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qrRbzS"} | None |  |
| q-2ee36d805b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c-4MbN"} | None |  |
| q-86fe61c47c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c-4MbP"} | None |  |
| q-09ec172d90 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nKg4v2"} | None |  |
| q-b2c5c6162b | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nKg4v2"} | None |  |
| q-9806d12800 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nKg4v2"} | None |  |
| q-1f4941463b | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qwTlue"} | None |  |
| q-518f464954 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_aFZ1"} | None |  |
| q-f77fddbdc0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c-4MbN"} | None |  |
| q-db8e7bf2f0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cxoQzx"} | None |  |
| q-9dc9b4c690 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c82Oiy"} | None |  |
| q-56a17b57b5 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c82OhP"} | None |  |
| q-402411600c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c82OhP"} | None |  |
| q-4069137590 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuCk"} | None |  |
| q-af3196e595 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNv3"} | None |  |
| q-7d1548d67b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7h03AJQ"} | None |  |
| q-19bc085db4 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cfUP4A"} | None |  |
| q-690d2cd75c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cxpAy5"} | None |  |
| q-e79f47ea8f | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuDg"} | None |  |
| q-c884d37d96 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7ns-ApD"} | None |  |
| q-00e1c5e3b7 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7ns-ApD"} | None |  |
| q-e8ce388981 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7ns-ApD"} | None |  |
| q-2877d59f2e | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7rxEjIW"} | None |  |
| q-78d52610ad | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuDg"} | None |  |
| q-ef10c6e714 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuCk"} | None |  |
| q-2dbafa978d | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None |  |
| q-86e1a033a6 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hx0G9q"} | None |  |
| q-ca5d001c0b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hwyqf3"} | None |  |
| q-913efc7908 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hwyqf3"} | None |  |
| q-39b861ae03 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cxqOiA"} | None |  |
| q-a54a68a819 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cxqOiA"} | None |  |
| q-2da58b31c6 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuA7"} | None |  |
| q-88aee43a39 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hbcHo-"} | None |  |
| q-05f5b9e1c4 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cxoQzx"} | None |  |
| q-2e04d2b1a1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cwoB6l"} | None |  |
| q-78f2dff056 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c4xY6Y"} | None |  |
| q-d1f2d9c422 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c1t6d3"} | None |  |
| q-4b762dd2d1 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNuP"} | None |  |
| q-de4e07012b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c-4MbN"} | None |  |
| q-5737ac41cf | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c-4MbN"} | None |  |
| q-967a5325a3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c-4MbN"} | None |  |
| q-74b630b5b1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c-4cYK"} | None |  |
| q-4fd7d6493d | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niytuv"} | None |  |
| q-def09af586 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niytuv"} | None |  |
| q-596dd7104b | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qrRC92"} | None |  |
| q-5e6eb953ad | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qrRC-J"} | None |  |
| q-7781715bd7 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qqQm-i"} | None |  |
| q-8a3e4804df | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qrRapX"} | None |  |
| q-ed84c5efd2 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7q0Y_4v"} | None |  |
| q-a278058b17 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7q0Y_4v"} | None |  |
| q-93c8f40db2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c-4MbN"} | None |  |
| q-1887bdce49 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7rxEjJI"} | None |  |
| q-ac3eacd0e1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cxoQzx"} | None |  |
| q-9d9130c7c0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cxoQzx"} | None |  |
| q-b3e9edc574 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuCk"} | None |  |
| q-4be13cf028 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuCk"} | None |  |
| q-459ce79f39 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNur"} | None |  |
| q-5589439077 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNur"} | None |  |
| q-49d655dbf8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c82OhP"} | None |  |
| q-1d462680d6 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c82OhP"} | None |  |
| q-feaf67e1bc | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c5ylrT"} | None |  |
| q-b0f33cd769 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c5ylrT"} | None |  |
| q-01324d7524 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hWVSlm"} | None |  |
| q-5d815efa44 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSyuh"} | None |  |
| q-e95211a9f0 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qwT1sV"} | None |  |
| q-70c7547d90 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuBw"} | None |  |
| q-9fc5f6f76d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cxoQzx"} | None |  |
| q-a03ea880b6 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuCk"} | None |  |
| q-b0c8580f48 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c82Oiy"} | None |  |
| q-2a289fd92c | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niydsP"} | None |  |
| q-eb6be09d70 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qrRbzS"} | None |  |
| q-ef7fc98072 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cri_p-"} | None |  |
| q-e036d338aa | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nQi3T7"} | None |  |
| q-e917e55d09 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nQi3T7"} | None |  |
| q-77402e17da | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nQi3T7"} | None |  |
| q-3121303abb | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nKg4v1"} | None |  |
| q-167171bbcd | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-ba5d7ba95d | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7njzKBN"} | None |  |
| q-b05c472933 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq72Yx"} | None |  |
| q-653be29dd2 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nKg4v2"} | None |  |
| q-aaa9a56b0c | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nKg4v2"} | None |  |
| q-58cc7546a6 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRfJfH5wFd7b_zvXB"} | None |  |
| q-72d576595f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRfJfH5wFd7b_zvXB"} | None |  |
| q-fef8e0b1d1 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvTSui"} | None |  |
| q-71078d4500 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cdSewt"} | None |  |
| q-1587c7408e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cdSewt"} | None |  |
| q-3c3f89b143 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRfJfH5wFd7b_zvXB"} | None |  |
| q-2895b8cad8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7h03AIc"} | None |  |
| q-4919de14f5 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c82OhP"} | None |  |
| q-c50071dcb9 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNu7"} | None |  |
| q-b00afdf4fd | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNu7"} | None |  |
| q-15ca734dee | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNu7"} | None |  |
| q-51ddb15c43 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niytvL"} | None |  |
| q-26b4b79a80 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7h03ALx"} | None |  |
| q-e727394d03 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c82-ha"} | None |  |
| q-7faaac2fbe | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c82Oiy"} | None |  |
| q-7b3caa205b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c82Oiy"} | None |  |
| q-8aa9822ba7 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c5yloe"} | None |  |
| q-a82fa4ba9f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7culih9"} | None |  |
| q-7e4c8d8339 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7rxEjIW"} | None |  |
| q-e5c010ad9a | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7rxEjIW"} | None |  |
| q-e55e5a7bfa | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7ns-ApD"} | None |  |
| q-be72881ded | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None |  |
| q-0febb2abf7 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None |  |
| q-c7b51da038 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None |  |
| q-5cc9298ff0 | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND host.name:\"nashua.dmevals.local\"", "time_from": "2020-05-02T02:54:23.881000+00:00", "time_to": "2020-05-02T03:32:41.290000+00:00", "size": 100, "sub_field": "process.pare… | 61 |  |
| q-b24914a52b | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11 AND host.name:\"nashua.dmevals.local\"", "time_from": "2020-05-02T02:54:23.881000+00:00", "time_to": "2020-05-02T03:32:41.290000+00:00", "size": 100, "sub_field": "process.executable"} | 249 |  |
| q-194caefb35 | pivot seed | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND host.name:\"nashua.dmevals.local\"", "time_from": "2020-05-02T02:54:23.881000+00:00", "time_to": "2020-05-02T03:32:41.290000+00:00", "size": 100, "sub_field": "process… | 63 |  |
| q-8a4a6e7cc6 | pivot seed | aggregate | {"dataset": "windows.powershell", "field": "event.code", "query": "host.name:\"nashua.dmevals.local\"", "time_from": "2020-05-02T02:54:23.881000+00:00", "time_to": "2020-05-02T03:32:41.290000+00:00", "size": 100, "sub_field": null} | 192 |  |
| q-9c49a99904 | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND host.name:\"scranton.dmevals.local\"", "time_from": "2020-05-02T02:43:45+00:00", "time_to": "2020-05-02T03:35:46+00:00", "size": 100, "sub_field": "process.parent.executabl… | 359 |  |
| q-78de4e86a8 | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11 AND host.name:\"scranton.dmevals.local\"", "time_from": "2020-05-02T02:43:45+00:00", "time_to": "2020-05-02T03:35:46+00:00", "size": 100, "sub_field": "process.executable"} | 1276 |  |
| q-46823c3c5a | pivot seed | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND host.name:\"scranton.dmevals.local\"", "time_from": "2020-05-02T02:43:45+00:00", "time_to": "2020-05-02T03:35:46+00:00", "size": 100, "sub_field": "process.parent.exec… | 370 |  |
| q-b65bd00372 | pivot seed | aggregate | {"dataset": "windows.powershell", "field": "event.code", "query": "host.name:\"scranton.dmevals.local\"", "time_from": "2020-05-02T02:43:45+00:00", "time_to": "2020-05-02T03:35:46+00:00", "size": 100, "sub_field": null} | 8602 |  |
| q-e8446e9aff | pivot step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (host.name LIKE \"*newyork*\" OR host.name LIKE \"*utica*\") \| KEEP @timestamp, host.name, user.name, process.executable, process.parent.executable, process.comm… | ERROR |  |
| q-3b9e093c52 | pivot step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND host.name LIKE \"*scranton*\" AND (process.executable LIKE \"*Sysinternals*\" OR process.executable LIKE \"*Temp*\" OR process.executable LIKE \"*ProgramData*\" O… | 15 | F29, F30, F31 |
| q-c48e289515 | pivot step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (host.name LIKE \"*newyork*\" OR host.name LIKE \"*utica*\") \| KEEP @timestamp, host.name, user.name, process.executable, process.parent.executable, process.comm… | 27 |  |
| q-4eff2ff9e3 | pivot step 2 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4624\" AND winlog.event_data.LogonType IN (\"3\",\"10\") \| STATS cnt = COUNT(*) BY host.name, winlog.event_data.LogonType, winlog.event_data.TargetUserName, source.ip … | ERROR |  |
| q-c74ad6410f | pivot step 3 | get_fields | {"dataset": "windows.security", "prefix": "winlog"} | None |  |
| q-74904b188f | pivot step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"3\" AND (host.name LIKE \"*nashua*\" OR host.name LIKE \"*scranton*\") \| STATS cnt = COUNT(*) BY host.name, destination.ip, destination.port, process.executable \| SORT … | 60 |  |
| q-a933097f80 | pivot step 4 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4624\" AND winlog.logon.type IN (\"3\",\"10\") \| STATS cnt = COUNT(*) BY host.name, winlog.logon.type, user.name, source.ip \| SORT cnt DESC \| LIMIT 100"} | 17 |  |
| q-747e6b9a58 | pivot step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND host.name LIKE \"*scranton*\" AND (file.path LIKE \"*Temp*\" OR file.path LIKE \"*ProgramData*\" OR file.path LIKE \"*Roaming*\" OR file.path LIKE \"*Downloads*\… | 100 | F29, F31 |
| q-9243e8a803 | pivot step 5 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4624\" AND user.name == \"pbeesly\" AND host.name LIKE \"*newyork*\" \| KEEP @timestamp, host.name, user.name, winlog.logon.type, source.ip, winlog.logon.id, _id, _inde… | 6 | F26 |
| q-ddb68d1dac | pivot step 5 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"5145\" AND host.name LIKE \"*newyork*\" \| STATS cnt = COUNT(*) BY share.name, file.path, user.name, source.ip \| SORT cnt DESC \| LIMIT 40"} | ERROR |  |
| q-5c9ae3dd54 | pivot step 6 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq72Yy"} | None | F26 |
| q-64fabd0b90 | pivot step 6 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nixQYA"} | None |  |
| q-87a8c72ff2 | pivot step 7 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"5140\",\"5145\") AND host.name LIKE \"*newyork*\" \| KEEP @timestamp, host.name, user.name, source.ip, winlog.event_data.ShareName, winlog.event_data.ShareLocalPath, w… | ERROR |  |
| q-22e0668436 | pivot step 7 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND host.name LIKE \"*newyork*\" AND (file.path LIKE \"*Temp*\" OR file.path LIKE \"*ProgramData*\" OR file.path LIKE \"*Users*\") \| KEEP @timestamp, host.name, use… | 10 |  |
| q-1b51c7928e | pivot step 8 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"5140\",\"5145\") AND host.name LIKE \"*newyork*\" \| KEEP @timestamp, host.name, user.name, source.ip, _id, _index \| SORT @timestamp ASC \| LIMIT 60"} | 60 |  |
| q-6ee120e3b4 | pivot step 8 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE host.name LIKE \"*newyork*\" AND event.code IN (\"4104\",\"4103\",\"800\") \| KEEP @timestamp, host.name, user.name, event.code, powershell.file.script_block_text, _id, _index \| SOR… | ERROR |  |
| q-db709d38d0 | pivot step 9 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq72Zu"} | None | F26 |
| q-5a19f09256 | pivot step 9 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7ns-Apn"} | None |  |
| q-10d5e8573f | pivot step 10 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"5140\" AND host.name LIKE \"*newyork*\" AND user.name == \"pbeesly\" \| KEEP @timestamp, host.name, user.name, source.ip, win.ShareName, win.RelativeTargetName, _id, _i… | 1 |  |
| q-e7e028beb3 | pivot step 10 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4688\" AND host.name LIKE \"*newyork*\" \| KEEP @timestamp, host.name, user.name, process.executable, process.parent.executable, process.command_line, _id, _index \| SO… | 18 |  |
| q-b30d31f62b | pivot step 11 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4624\" AND host.name LIKE \"*nashua*\" AND user.name == \"pbeesly\" \| KEEP @timestamp, host.name, user.name, winlog.logon.type, source.ip, winlog.logon.id, _id, _index… | 21 | F28 |
| q-33f98ea0c0 | pivot step 11 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND host.name LIKE \"*nashua*\" AND (process.executable LIKE \"*Temp*\" OR process.executable LIKE \"*Rar*\" OR process.executable LIKE \"*powershell*\" OR process.ex… | 17 | F27, F28 |
| q-58f80cb511 | pivot step 12 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND host.name LIKE \"*nashua*\" AND (file.path LIKE \"*working.zip*\" OR file.path LIKE \"*Temp*Rar*\" OR file.path LIKE \"*Temp*python*\" OR file.path LIKE \"*Temp*… | 7 | F27 |
| q-8731ad8caf | pivot step 12 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"3\" AND host.name LIKE \"*nashua*\" AND destination.port IN (445, 5985, 3389, 135) \| KEEP @timestamp, host.name, user.name, destination.ip, destination.port, process.exe… | 25 |  |
| q-bf8e20563d | pivot verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq72Yy"} | None |  |
| q-32298612ca | pivot verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq72Yy"} | None |  |
| q-7daa6ae502 | pivot verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq72Yy"} | None |  |
| q-9f8b05fe2f | pivot verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq72Zu"} | None |  |
| q-23fab45aae | pivot verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq72Zu"} | None |  |
| q-74b51c8762 | pivot verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nixQYA"} | None |  |
| q-18312d9342 | pivot verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nixQYA"} | None |  |
| q-a8e13630f7 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c5yloe"} | None |  |
| q-06179704c2 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7culih9"} | None |  |
| q-acbab3dec7 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c4xY6Y"} | None |  |
| q-1349f1dffb | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cri_p-"} | None |  |
| q-e73d02e0fc | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7crhzvV"} | None |  |
| q-14777a034f | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c1t6d3"} | None |  |
| q-fefc323ca8 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7culihF"} | None |  |
| q-debd81e550 | pivot verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNuT"} | None |  |
| q-2d82bf511a | pivot verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNuT"} | None |  |
| q-e6b9b41ffe | pivot verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNvH"} | None |  |
| q-be77d0a8ed | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c82Oiy"} | None |  |
| q-78e425abe2 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c82OhP"} | None |  |
| q-e2462aa5ba | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cxoQzx"} | None |  |
| q-a93324ad2f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cxoQzx"} | None |  |
| q-bcd31691be | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qrRFHq"} | None |  |
| q-ccd8f23abb | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuCk"} | None |  |
| q-284d758798 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNvI"} | None |  |
| q-46de1d73d9 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNur"} | None |  |
| q-a2567abd6b | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qrRbzS"} | None |  |
| q-35a55f8248 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c-4MbN"} | None |  |
| q-9e54c442b3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c-4MbP"} | None |  |
| q-ff7c4e07fc | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nKg4v2"} | None |  |
| q-cd64f52d4d | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nKg4v2"} | None |  |
| q-99eee20f7c | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nKg4v2"} | None |  |
| q-694a81beac | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qwTlue"} | None |  |
| q-86c26a7fc4 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_aFZ1"} | None |  |
| q-76a77898e6 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c-4MbN"} | None |  |
| q-d9363a80b8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cxoQzx"} | None |  |
| q-bfa6df506e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c82Oiy"} | None |  |
| q-d3fbcfc3a3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c82OhP"} | None |  |
| q-38320eb2b7 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c82OhP"} | None |  |
| q-82fa3c7894 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuCk"} | None |  |
| q-31df6ecd81 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNv3"} | None |  |
| q-9170d6b9e8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7h03AJQ"} | None |  |
| q-ac0d00eb11 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cfUP4A"} | None |  |
| q-35c937bf6b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cxpAy5"} | None |  |
| q-92d4b7bb75 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuDg"} | None |  |
| q-cf23b828f3 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7ns-ApD"} | None |  |
| q-479e80080b | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7ns-ApD"} | None |  |
| q-b724df7f54 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7ns-ApD"} | None |  |
| q-942fc7ba3f | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7rxEjIW"} | None |  |
| q-23d8d7545f | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuDg"} | None |  |
| q-8bbec522f5 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuCk"} | None |  |
| q-a4adcf81c1 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None |  |
| q-dae81b9b57 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hx0G9q"} | None |  |
| q-12e897be88 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hwyqf3"} | None |  |
| q-a8bbf7bf52 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hwyqf3"} | None |  |
| q-d10cc032d7 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cxqOiA"} | None |  |
| q-fb119d2752 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cxqOiA"} | None |  |
| q-cc01647eda | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuA7"} | None |  |
| q-563f287277 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hbcHo-"} | None |  |
| q-45b0f23d04 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cxoQzx"} | None |  |
| q-b2beed6af2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cwoB6l"} | None |  |
| q-ce92109ffc | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c4xY6Y"} | None |  |
| q-a92e23ef95 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c1t6d3"} | None |  |
| q-532ec041d3 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNuP"} | None |  |
| q-96ef9a030d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c-4MbN"} | None |  |
| q-774ed934f9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c-4MbN"} | None |  |
| q-38a8e1f818 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c-4MbN"} | None |  |
| q-465bb98e9d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c-4cYK"} | None |  |
| q-1bcdb282b7 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niytuv"} | None |  |
| q-43f678206d | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niytuv"} | None |  |
| q-66d22a2678 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qrRC92"} | None |  |
| q-b7e6597ba0 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qrRC-J"} | None |  |
| q-5fad3a8381 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qqQm-i"} | None |  |
| q-b70d6285df | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qrRapX"} | None |  |
| q-f26e03c30b | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7q0Y_4v"} | None |  |
| q-03353c615c | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7q0Y_4v"} | None |  |
| q-42f5799780 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c-4MbN"} | None |  |
| q-8748b1210f | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7rxEjJI"} | None |  |
| q-f877aa4485 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cxoQzx"} | None |  |
| q-b6fed3c551 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cxoQzx"} | None |  |
| q-1be2f1472b | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuCk"} | None |  |
| q-8d39a0cb53 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuCk"} | None |  |
| q-5e337f3bc0 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNur"} | None |  |
| q-7a8340ca53 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNur"} | None |  |
| q-1982049387 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c82OhP"} | None |  |
| q-f0fba6dec0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c82OhP"} | None |  |
| q-f14c2e2060 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c5ylrT"} | None |  |
| q-650633c745 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c5ylrT"} | None |  |
| q-761db0a1ca | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hWVSlm"} | None |  |
| q-7b510b7bf4 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSyuh"} | None |  |
| q-68d5b6b955 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qwT1sV"} | None |  |
| q-5d3d340217 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuBw"} | None |  |
| q-1143031c2d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cxoQzx"} | None |  |
| q-1e07d8441e | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuCk"} | None |  |
| q-8594b27375 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c82Oiy"} | None |  |
| q-1fa243763c | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niydsP"} | None |  |
| q-8de6f562d2 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qrRbzS"} | None |  |
| q-a6f318e984 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cri_p-"} | None |  |
| q-2e5cc048b4 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nQi3T7"} | None |  |
| q-140bf51e80 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nQi3T7"} | None |  |
| q-f4ca810e8d | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nQi3T7"} | None |  |
| q-baa8e05ce5 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nKg4v1"} | None |  |
| q-867860dcbd | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-597be1cb76 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7njzKBN"} | None |  |
| q-cc52e0debb | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq72Yx"} | None |  |
| q-0087cf7192 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nKg4v2"} | None |  |
| q-f404688549 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nKg4v2"} | None |  |
| q-900471cda1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRfJfH5wFd7b_zvXB"} | None |  |
| q-587d4c9214 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRfJfH5wFd7b_zvXB"} | None |  |
| q-7caff8d362 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvTSui"} | None |  |
| q-d9a67817f4 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cdSewt"} | None |  |
| q-10c5e311eb | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cdSewt"} | None |  |
| q-56f67dd45c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRfJfH5wFd7b_zvXB"} | None |  |
| q-9f5767a653 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7h03AIc"} | None |  |
| q-4099d49048 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c82OhP"} | None |  |
| q-ae623368f3 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNu7"} | None |  |
| q-1a916856f7 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNu7"} | None |  |
| q-87c397fab6 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNu7"} | None |  |
| q-270d96a34d | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niytvL"} | None |  |
| q-f0391ecc31 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7h03ALx"} | None |  |
| q-9ad3282623 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c82-ha"} | None |  |
| q-1feb8e9d19 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c82Oiy"} | None |  |
| q-c7d277efdd | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c82Oiy"} | None |  |
| q-290d37ffd3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c5yloe"} | None |  |
| q-35853c5e92 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7culih9"} | None |  |
| q-8ab3fc4710 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7rxEjIW"} | None |  |
| q-153f5bded3 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7rxEjIW"} | None |  |
| q-d8dd70be1f | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7ns-ApD"} | None |  |
| q-3c200ab354 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None |  |
| q-fbe54f4bcd | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None |  |
| q-0ed4b0c906 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None |  |
| q-099bc4a460 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq72Yy"} | None |  |
| q-e59e605ff6 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq72Yy"} | None |  |
| q-dae3a5c20f | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq72Yy"} | None |  |
| q-c9c7563c4c | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq72Zu"} | None |  |
| q-e38f4d294b | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq72Zu"} | None |  |
| q-cff78c13ca | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nixQYA"} | None |  |
| q-3f0ae42570 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nixQYA"} | None |  |
| q-f7455cc2f3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c5yloe"} | None |  |
| q-9e60c69735 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7culih9"} | None |  |
| q-c24b9d1413 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c4xY6Y"} | None |  |
| q-517b98f1c8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cri_p-"} | None |  |
| q-c2bfc9a44c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7crhzvV"} | None |  |
| q-fcdafb57a6 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c1t6d3"} | None |  |
| q-c079adcda7 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7culihF"} | None |  |
| q-864083f324 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNuT"} | None |  |
| q-e13b1aae99 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNvH"} | None |  |
| q-7996584ec7 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c82Oiy"} | None |  |
| q-2945610d71 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c82OhP"} | None |  |
| q-719497459a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hRQwNZ"} | None |  |
| q-4d7abfcf2d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hRQwNZ"} | None |  |
| q-0dbac4333e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hjk9tr"} | None |  |
| q-e0ddb6ec44 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cxoQzx"} | None |  |
| q-14a906704b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cxoQzx"} | None |  |
| q-bfaf0ca54b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7WVSlm"} | ERROR |  |
| q-3adc402c92 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hJHlRK"} | None |  |
| q-f42de7fb40 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7htvuyT"} | None |  |
| q-cefa3de710 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7huwtP3"} | None |  |
| q-5d1532d5d7 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7YE3lVE"} | None |  |
| q-726318f76e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hWVSlm"} | None |  |

## Verification

Evidence items cited: 140; confirmed against the stored events: 139; rejected: 1. Each item was re-fetched with get_event; it is confirmed only if the event exists, the cited field holds the cited value, and the cited query_id is a query of this run that returned that event.
Evidence sent back to the agents for correction during the run: 3 item(s) in 2 submission(s) (one correction round each; what still failed was rejected).

## Limitations

- Findings describe what the stored logs show; activity these sources did not log cannot be seen.
- Datasets with non-overlapping time windows (see Data examined) were analysed separately.
- Long field values are shortened in this report; full events are retrievable by _index/_id.
