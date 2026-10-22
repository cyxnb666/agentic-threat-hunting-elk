# Threat hunt report — 20261022-135215-converged-recheck-b

**Hypothesis:** An adversary who compromised Windows hosts in this network stole credentials from them (MITRE ATT&CK tactic: Credential Access).

**Verdict: Confirmed** — 8 in-scope incident(s) of verified malicious findings (confidence >= medium): I01 T1003.001 (F01, F09, F16, F19, F23, F31, F46, F53), I04 T1056.002 (F10), I05 T1552 (F27), I06 T1552.001 (F26, F57), I07 T1552.001 (F56), I08 T1552.001 (F58), I09 T1552.001 (F60), I10 T1552.004 (F25, F51, F54)

Verdict method: rules over verified evidence (Confirmed if >=1 in-scope incident of verified malicious findings (confidence >= medium); Inconclusive if only suspicious incidents or coverage gaps; Refuted if full coverage and no malicious/suspicious finding)

| Run | Value |
|---|---|
| Profile | converged (thinking=False, temperature=0.0) |
| Model | deepseek-flash |
| Started / finished (UTC) | 2026-10-22T05:52:15+00:00 / 2026-10-22T06:03:11+00:00 (655.7 s) |
| LLM calls / tokens | 149 / {'prompt': 4558276, 'completion': 141262} |
| MCP tool calls | 1203 (server tools: list_data_sources, get_fields, search, count, aggregate, timeline, esql, get_event, get_registry) |
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
| I01 | T1003.001 | yes | malicious/high | F01, F09, F16, F19, F23, F31, F46, F53 | Hidden PowerShell opens LSASS with full-access masks and injects a remote thread on scranton |
| I02 | T1003.001 | yes | suspicious/medium | F02, F20 | wsmprovhost.exe on nashua opens LSASS with 0x1F3FFF during pbeesly remote PowerShell session |
| I03 | T1003.002 | yes | suspicious/low | F62 | SAM hive opened with 0xf003f by lsass on scranton |
| I04 | T1056.002 | yes | malicious/medium | F10 | Invoke-ScreenCapture loop capturing the desktop every 300s on scranton |
| I05 | T1552 | yes | malicious/high | F27 | Credential-harvesting chain on scranton with pfx export, staging, and PsExec lateral use of pbeesly credentials |
| I06 | T1552.001 | yes | malicious/high | F26, F57 | Hardcoded plaintext credentials in attacker PowerShell scripts and staged archive |
| I07 | T1552.001 | yes | malicious/high | F56 | PsExec on scranton launches python.exe on nashua with plaintext pbeesly password |
| I08 | T1552.001 | yes | malicious/high | F58 | Password-protected archive staged on nashua with hardcoded RAR password |
| I09 | T1552.001 | yes | malicious/high | F60 | Credential-harvesting script on scranton collects password/login-named files into an archive |
| I10 | T1552.004 | yes | malicious/high | F25, F51, F54 | PowerShell Get-PrivateKeys exports LocalMachine certificates to password-protected .pfx files on scranton |
| I11 | T1555.003 | yes | suspicious/medium | F61 | accesschk.exe on scranton probes a 'passwordsDB' file in the Sysinternals folder |
| I12 | T1556 | yes | suspicious/medium | F35 | Credential-access intrusion on scranton/nashua without authentication-process modification |
| I13 | T1556.008 | yes | suspicious/low | F41 | No malicious network provider DLL; LSASS memory-write access is the credential-theft signal |
| I14 | out-of-scope:T1027 | no | malicious/high | F64 | Hidden PowerShell compiles .NET payloads with csc.exe from Temp response files on scranton |
| I15 | out-of-scope:T1071 | no | malicious/high | F59 | PsExec-delivered python.exe on nashua beacons to 192.168.0.4:8443 and spawns cmd/powershell |
| I16 | out-of-scope:T1204 | no | malicious/high | F63 | Screensaver-named loader in C:\ProgramData\victim opens LSA registry key and stages IEX payload on scranton |
| I17 | out-of-scope:T1547.001 | no | suspicious/medium | F65 | hostui.exe launched with -verb runas and hostui.lnk placed in StartUp for persistence on scranton |
| I18 | out-of-scope:T1548.002 | no | suspicious/low | F66 | sdclt.exe UAC-bypass-style launches from cmd.exe in C:\ProgramData\victim on scranton |

## Findings

### F01 · malicious / high · T1003.001 · PowerShell opens lsass.exe with full-access masks on scranton (pbeesly session)

Evidence status: **verified**

On scranton.dmevals.local, PowerShell.exe (PID 2976, entity {47ab858c-e1e4-5eac-b803-000000000400}) opened lsass.exe (PID 736) twice within 31 ms at 2020-05-02T03:05:16Z with GrantedAccess 0x1F3FFF and 0x1FFFFF — full-process-access masks consistent with LSASS memory dumping. The call trace ends in an UNKNOWN module after ntdll/KERNELBASE, i.e. code not backed by a known image. The same PowerShell session (user pbeesly) had just run a hands-on-keyboard toolkit from C:\Program Files\SysinternalsSuite (accesschk.exe, Get-PrivateKeys exporting a .pfx to C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx, Invoke-ScreenCapture, Keystroke-Check AV enumeration) and had earlier executed a hidden, bypass-mode PowerShell one-liner that decoded a bitmap (monkey.png) and IEX'd the result. Security 4663 confirms powershell.exe (PID 0xba0) accessing \Device\HarddiskVolume2\Windows\System32\lsass.exe as pbeesly at 23:05:16 local. No .dmp file was written to disk, so the dump was likely held in memory or exfiltrated in-session.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoMQUXF | q-0c4b89c94e | ok |
| 2 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoMQUXI | q-0c4b89c94e | ok |
| 3 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.CallTrace | C:\windows\SYSTEM32\ntdll.dll+9c584\|C:\windows\System32\KERNELBASE.dll+2732e\|UNKNOWN(000001996D252982) | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoMQUXF | q-6aec89f821 | ok |
| 4 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | win.ProcessName | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBy4FbI2 | q-878ccb5cec | ok |
| 5 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | win.SubjectUserName | pbeesly | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBy4FbI2 | q-878ccb5cec | ok |
| 6 | 2020-05-02 03:00:13.551Z | scranton.dmevals.local | windows.sysmon | process.parent.command_line | "PowerShell.exe" -noni -noexit -ep bypass -window hidden -c "sal a New-Object;Add-Type -AssemblyName 'System.Drawing'; $g=a System.Drawing.Bitmap('C:\Users\pbee… | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoZdz9r | q-200368d154 | ok |
| 7 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByRaLqc | q-1fde6ed3f0 | ok |
| 8 | 2020-05-02 03:04:57.460Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoMQkXH | q-ec9dad1d5a | ok |

### F10 · malicious / medium · T1056.002 · Invoke-ScreenCapture loop capturing the desktop every 300s on scranton (GUI input capture)

Evidence status: **verified**

On scranton.dmevals.local, PowerShell script-block logging (4104, user pbeesly, PID 3852, Path C:\Program Files\SysinternalsSuite\psversion.ps1) records a function Invoke-ScreenCapture that starts a background job looping forever, using System.Windows.Forms.SystemInformation::VirtualScreen and Graphics.CopyFromScreen to grab the full virtual screen and save it as a random .bmp in $env:USERPROFILE\Downloads every 300 seconds. This is GUI/screen capture of the user's session (which would include credential prompts and typed secrets), matching the same pbeesly activity window as the lsass injection.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:53.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-ScreenCapture # https://www.pdq.com/blog/capturing-screenshots-with-powershell-and-net/ {     Start-Job -Name "Screenshot" -ScriptBlock {       … | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByRabqD | q-268fc0290b | ok |
| 2 | 2020-05-02 03:05:53.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\psversion.ps1 | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByRabqD | q-268fc0290b | ok |
| 3 | 2020-05-02 03:05:59.000Z | scranton.dmevals.local | windows.powershell | process.command_line |           Write-Host "`nJobPID`n------`n$PID"         while($true){             $RandomFileName = [System.IO.Path]::GetRandomFileName();              $Filepath=… | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByRZ7r5 | q-9754abc782 | ok |

### F09 · malicious / high · T1056.004 · PowerShell (pbeesly) opens lsass with full-access masks and creates a remote thread in lsass on scranton

Evidence status: **verified**

On scranton.dmevals.local, a hidden, execution-policy-bypass PowerShell (PID 2976, GUID {47ab858c-e1e4-5eac-b803-000000000400}) was launched at 2020-05-02T02:58:44Z by control.exe /name Microsoft.BackupAndRestoreCenter as DMEVALS\pbeesly. Its command line decodes a bitmap (C:\Users\pbeesly\Downloads\monkey.png) pixel-by-pixel and IEX-executes the extracted ASCII payload. At 03:05:16Z the same process opened lsass.exe with GrantedAccess 0x1f3fff and 0x1fffff (PROCESS_ALL_ACCESS-class masks, CallTrace ending in UNKNOWN module) and created a remote thread in lsass (Sysmon 8, StartAddress 0x00000117610E0000, StartModule '-'), i.e. code injection into the credential-handling process consistent with credential API hooking. Security log corroborates: 4656 on \Device\HarddiskVolume2\Windows\System32\lsass.exe with AccessMask 0x1f3fff and 0x1fffff by powershell.exe as pbeesly, and 4663 with AccessMask 0x10. A second host, nashua.dmevals.local, shows wsmprovhost.exe (WinRM remote PowerShell, PID 7720) opening lsass with 0x1f3fff at 03:09:29Z after a type-3 logon as pbeesly, indicating the same technique was executed remotely on nashua.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | message | CreateRemoteThread detected:  RuleName: -  UtcTime: 2020-05-02 03:05:16.623  SourceProcessGuid: {47ab858c-e1e4-5eac-b803-000000000400}  SourceProcessId: 2976  S… | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoMQUXG | q-0e8331c4eb | ok |
| 2 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.StartAddress | 0x00000117610E0000 | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoMQUXG | q-0e8331c4eb | ok |
| 3 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoMQUXF | q-31c75be9de | ok |
| 4 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoMQUXI | q-31c75be9de | ok |
| 5 | 2020-05-02 02:58:44.325Z | scranton.dmevals.local | windows.sysmon | process.command_line | "PowerShell.exe" -noni -noexit -ep bypass -window hidden -c "sal a New-Object;Add-Type -AssemblyName 'System.Drawing'; $g=a System.Drawing.Bitmap('C:\Users\pbee… | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBorwtwa | q-40bdab2b52 | ok |
| 6 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | win.AccessMask | 0x1f3fff | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBy0A4ua | q-49cce6dce9 | ok |
| 7 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | win.AccessMask | 0x1fffff | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBy0A4uc | q-49cce6dce9 | ok |
| 8 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBn663fz | q-8c847efd90 | ok |
| 9 | 2020-05-02 03:09:29.000Z | nashua.dmevals.local | windows.security | win.ProcessName | C:\Windows\System32\wsmprovhost.exe | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBux8Gu0 | q-49cce6dce9 | ok |

### F19 · malicious / high · T1111 · Hidden PowerShell loader on scranton opened lsass.exe with PROCESS_ALL_ACCESS (0x1FFFFF) — credential/MFA material access

Evidence status: **verified**

On scranton.dmevals.local, user pbeesly, a hidden PowerShell process (PID 2976, entity {47ab858c-e1e4-5eac-b803-000000000400}) was started at 02:58:44Z by control.exe with the command line "PowerShell.exe" -noni -noexit -ep bypass -window hidden -c "sal a New-Object;Add-Type -AssemblyName 'System.Drawing'; $g=a System.Drawing.Bitmap('C:\Users\pbeesly\Downloads\monkey.png')...IEX([System.Text.Encoding]::ASCII.GetString($o[0..3932]))" — a steganographic image-decoding loader that IEX-executes the decoded payload (matching 4104 script block at 02:58:45Z). At 03:05:16Z that same PowerShell process opened lsass.exe (PID 736) twice with GrantedAccess 0x1F3FFF and 0x1FFFFF (PROCESS_ALL_ACCESS), with an UNKNOWN call trace outside lsass's own modules — the classic pattern for dumping LSASS to harvest credentials and authentication material (including MFA/token-related secrets). This is the only PowerShell-to-lsass access in the whole dataset; all other lsass access (289 events) is svchost.exe with 0x1000/0x1400, and the remaining high-mask accesses are legitimate system processes (wininit/csrss at boot, svchost via lsm.dll/sysmain.dll).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoMQUXI | q-cb0a015528 | ok |
| 2 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.TargetImage | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoMQUXI | q-0429e39fbe | ok |
| 3 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoMQUXF | q-cb0a015528 | ok |
| 4 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.CallTrace | C:\windows\SYSTEM32\ntdll.dll+9c584\|C:\windows\System32\KERNELBASE.dll+2732e\|UNKNOWN(000001996D252982) | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoMQUXF | q-d24a60e5d5 | ok |
| 5 | 2020-05-02 02:58:44.325Z | scranton.dmevals.local | windows.sysmon | process.command_line | "PowerShell.exe" -noni -noexit -ep bypass -window hidden -c "sal a New-Object;Add-Type -AssemblyName 'System.Drawing'; $g=a System.Drawing.Bitmap('C:\Users\pbee… | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBorwtwa | q-f19d6e5206 | ok |
| 6 | 2020-05-02 02:58:44.325Z | scranton.dmevals.local | windows.sysmon | process.parent.executable | C:\Windows\System32\control.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBorwtwa | q-f19d6e5206 | ok |
| 7 | 2020-05-02 02:58:45.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | sal a New-Object;Add-Type -AssemblyName 'System.Drawing'; $g=a System.Drawing.Bitmap('C:\Users\pbeesly\Downloads\monkey.png');$o=a Byte[] 4480;for($i=0; $i -le … | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByYf10Q | q-6d8504818f | ok |

### F23 · malicious / high · T1212 · PowerShell and WMI-hosted PowerShell opened lsass.exe with full access (0x1F3FFF / 0x1FFFFF) on SCRANTON and NASHUA

Evidence status: **verified**

On 2020-05-02 between 03:05:16 and 03:09:29 UTC, PowerShell.exe (PID 2976, user pbeesly) on scranton.dmevals.local opened C:\windows\system32\lsass.exe with GrantedAccess 0x1F3FFF and 0x1FFFFF, and wsmprovhost.exe (PID 7720) on nashua.dmevals.local opened lsass.exe with 0x1F3FFF. These are full-access masks typical of credential dumping (e.g. MiniDumpWriteDump / sekurlsa), and the call traces show the access originating from managed PowerShell code (System.ni.dll / Microsoft.PowerShell.Commands.Management.ni.dll) rather than a normal system component. The only other full-access (0x1fffff) lsass opens in the dataset are from csrss.exe and wininit.exe at 03:19:09, which are legitimate system processes. The lsass access occurred in the middle of a hands-on-keyboard intrusion by user pbeesly on scranton: obfuscated PowerShell launched from control.exe (02:58:44), Invoke-Discovery reconnaissance (03:04:03), Invoke-Exfil script block with hardcoded credentials and WebDAV exfil to \\192.168.0.4\webdav (03:08:02), sdelete64.exe wiping of files (03:02-03:03), and PsExec64.exe with plaintext password 'Fl0nk3rt0n!T0by' to \\NASHUA launching C:\Windows\Temp\python.exe (03:11:18, 03:12:25). The nashua lsass access at 03:09:29 follows network logons (4624 type 3) and 4672 special-privilege assignments for pbeesly on nashua at 03:09:23-03:09:29 and a wsmprovhost.exe -Embedding spawn, consistent with remote PowerShell/WinRM-driven credential access. No 4104 script block containing lsass/MiniDump/comsvcs text was captured, so the dumping code itself was not logged, but the access pattern is unambiguous.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoMQUXF | q-8fe99ba4d7 | ok |
| 2 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoMQUXF | q-8fe99ba4d7 | ok |
| 3 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoMQUXI | q-eaee04f321 | ok |
| 4 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.CallTrace | C:\windows\SYSTEM32\ntdll.dll+9c584\|C:\windows\System32\KERNELBASE.dll+2732e\|UNKNOWN(000001996D28200D) | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoMQUXI | q-eaee04f321 | ok |
| 5 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBn663fz | q-8fe99ba4d7 | ok |
| 6 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBn663fz | q-8fe99ba4d7 | ok |
| 7 | 2020-05-02 03:11:18.784Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\PsExec64.exe" -accepteula \\NASHUA -u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoz4z4i | q-57f15c5fcb | ok |
| 8 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\psversion.ps1 | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByPYrDh | q-7f45343856 | ok |
| 9 | 2020-05-02 03:09:23.000Z | nashua.dmevals.local | windows.security | process.command_line | C:\windows\system32\wsmprovhost.exe -Embedding | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBuv5SEZ | q-ff724b8103 | ok |

### F27 · malicious / high · T1552 · Credential-harvesting chain on scranton: pfx export, staging, and lateral use of pbeesly credentials via PsExec

Evidence status: **verified**

The unsecured-credentials activity is part of a broader intrusion by user pbeesly. On scranton.dmevals.local the Get-PrivateKeys export (03:04:56Z) and Invoke-Exfil staging (03:08:02Z) run from SysinternalsSuite paths, and a service 'Java(TM) Virtual Machine Support Service' pointing at C:\Windows\System32\javamtsup.exe was installed at 03:04:15Z. The same account then used PsExec: PSEXESVC service installs on nashua.dmevals.local at 03:11:39, 03:12:46, 03:13:49 and 03:15:03Z, each matched by a 4648 explicit-credential logon on nashua (process C:\Windows\PSEXESVC.exe, credentials of pbeesly) and a corresponding 4648 on scranton targeting server NASHUA from source.ip 10.0.1.6. This shows the harvested/held credentials being reused across hosts.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:15.000Z | scranton.dmevals.local | windows.other | process.executable | C:\Windows\System32\javamtsup.exe | .ds-logs-windows.other-default-2026.10.22-000001 / AaFiKJc9VXKkeBwdLx2Z | q-4e6af364e1 | ok |
| 2 | 2020-05-02 03:11:39.000Z | nashua.dmevals.local | windows.other | process.executable | %SystemRoot%\PSEXESVC.exe | .ds-logs-windows.other-default-2026.10.22-000001 / AaFiKJc9VXKkeBwdMB0i | q-4e6af364e1 | ok |
| 3 | 2020-05-02 03:11:40.000Z | nashua.dmevals.local | windows.security | process.executable | C:\Windows\PSEXESVC.exe | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBuu5GRH | q-a999f11f0d | ok |
| 4 | 2020-05-02 03:11:18.000Z | scranton.dmevals.local | windows.security | source.ip | 10.0.1.6 | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBunxq0T | q-a999f11f0d | ok |
| 5 | 2020-05-02 03:11:18.000Z | scranton.dmevals.local | windows.security | win.TargetServerName | NASHUA | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBunxq0T | q-a999f11f0d | ok |

### F26 · malicious / high · T1552.001 · Hardcoded plaintext credentials in attacker PowerShell scripts (pfx password, WebDAV account) and staged archive of harvested files

Evidence status: **verified**

Two attacker script blocks on scranton.dmevals.local embed plaintext credentials: Get-PrivateKeys uses ConvertTo-SecureString -String "saribas" -AsPlainText -Force as the .pfx password, and Invoke-Exfil (ScriptBlock ID b2b03a9c-43f0-4285-837d-f22d4600b2ae, Path C:\Program Files\SysinternalsSuite\psversion.ps1, 03:08:02Z) builds a PSCredential for user "cozy" with password "MyCozyPassw0rd!" to mount \\192.168.0.4\webdav. Invoke-Exfil also installs 7Zip4Powershell and compresses the entire Downloads directory (where the exported .pfx landed) into C:\Users\pbeesly\AppData\Roaming\OfficeSupplies.7z with password "lolol"; Sysmon shows that archive being created at 03:08:35Z by powershell.exe. The credentials-in-files element here is the attacker's own credential material embedded in scripts on disk, and the harvested credential files being collected for exfiltration.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByPYrDh | q-587074facd | ok |
| 2 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\psversion.ps1 | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByPYrDh | q-587074facd | ok |
| 3 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByRaLqc | q-9c2d214561 | ok |
| 4 | 2020-05-02 03:08:35.270Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Users\pbeesly\AppData\Roaming\OfficeSupplies.7z | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBo05T5k | q-59b205ef9f | ok |

### F56 · malicious / high · T1552.001 · PsExec on scranton launches C:\Windows\Temp\python.exe on nashua with plaintext pbeesly password on the command line

Evidence status: **verified**

On 2020-05-02 between 03:11:18 and 03:14:42, PowerShell (pbeesly) on scranton.dmevals.local ran C:\Program Files\SysinternalsSuite\PsExec64.exe four times with the cleartext domain credential '-u dmevals\pbeesly -p Fl0nk3rt0n!T0by' to start C:\Windows\Temp\python.exe on \\NASHUA. On nashua the resulting python.exe processes (03:11:40, 03:12:46, 03:13:49, 03:15:03) were children of C:\Windows\PSEXESVC.exe running as pbeesly. This is new relative to the anchors: the anchors covered the pfx export and the PsExec lateral use, but not the hardcoded password in the PsExec command line nor the python payload delivered to nashua.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:18.784Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\PsExec64.exe" -accepteula \\NASHUA -u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoz4z4i | q-01c368af06 | ok |
| 2 | 2020-05-02 03:11:40.213Z | nashua.dmevals.local | windows.sysmon | process.parent.executable | C:\Windows\PSEXESVC.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoz4j7h | q-71b0483a9e | ok |
| 3 | 2020-05-02 03:11:40.213Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoz4j7h | q-71b0483a9e | ok |

### F57 · malicious / high · T1552.001 · Hardcoded WebDAV credentials (cozy / MyCozyPassw0rd!) in Invoke-Exfil script on scranton

Evidence status: **verified**

A PowerShell script block on scranton.dmevals.local (pbeesly, 03:08:02) defines Invoke-Exfil, which compresses the user's Downloads with password 'lolol' into %APPDATA%\OfficeSupplies.7z and copies it to the WebDAV share \\192.168.0.4\webdav using the hardcoded account 'cozy' with password 'MyCozyPassw0rd!'. The script was stored as C:\Program Files\SysinternalsSuite\psversion.ps1. This is a new credential-in-script artifact beyond the anchors' generic 'hardcoded credentials' statement.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByPYrDh | q-c461c04d02 | ok |
| 2 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\psversion.ps1 | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByPYrDh | q-c461c04d02 | ok |
| 3 | 2020-05-02 03:08:35.270Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Users\pbeesly\AppData\Roaming\OfficeSupplies.7z | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBo05T5k | q-94543ab8bb | ok |

### F58 · malicious / high · T1552.001 · Password-protected archive staged on nashua with hardcoded RAR password fGzq5yKw

Evidence status: **verified**

On nashua.dmevals.local at 03:16:19, PowerShell (pbeesly) executed C:\Windows\Temp\Rar.exe with the hardcoded archive password '-hpfGzq5yKw' to create C:\Users\pbeesly\Desktop\working.zip from C:\Users\pbeesly\AppData\Roaming\working.zip. Rar.exe had been dropped into C:\Windows\Temp by the PsExec-delivered python.exe at 03:15:31, and sdelete64.exe was then used to wipe Rar.exe and both zip files (03:16:52-03:17:41). This staging/anti-forensics chain on nashua is new compared with the anchors.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:16:19.395Z | nashua.dmevals.local | windows.sysmon | process.command_line | "C:\Windows\Temp\Rar.exe" a -hpfGzq5yKw C:\Users\pbeesly\Desktop\working.zip C:\Users\pbeesly\AppData\Roaming\working.zip | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBow1qSj | q-71b0483a9e | ok |
| 2 | 2020-05-02 03:15:31.530Z | nashua.dmevals.local | windows.sysmon | file.path | C:\Windows\Temp\Rar.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoy3l6o | q-f84bd08d34 | ok |
| 3 | 2020-05-02 03:16:52.456Z | nashua.dmevals.local | windows.sysmon | process.command_line | .\sdelete64.exe  /accepteula "C:\Windows\Temp\Rar.exe" | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBnnmUud | q-71b0483a9e | ok |
| 4 | 2020-05-02 03:17:18.030Z | nashua.dmevals.local | windows.sysmon | process.command_line | .\sdelete64.exe  /accepteula "C:\Users\pbeesly\AppData\Roaming\working.zip"  | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBnttWk7 | q-71b0483a9e | ok |

### F59 · malicious / high · T1552.001 · PsExec-delivered python.exe on nashua beacons to 192.168.0.4:8443 and spawns cmd/powershell

Evidence status: **verified**

The C:\Windows\Temp\python.exe started on nashua.dmevals.local by PSEXESVC.exe (pbeesly) unpacked a PyInstaller bundle into C:\Users\pbeesly\AppData\Local\Temp\_MEI29522 and made 348 outbound connections to 192.168.0.4:8443 — the same host used as the WebDAV exfil destination in the scranton script. It then spawned cmd.exe (03:16:40) and powershell.exe (03:15:48) on nashua, which ran the Rar staging. This remote-control payload on nashua is new relative to the anchors.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:15:05.142Z | nashua.dmevals.local | windows.sysmon | destination.ip | 192.168.0.4 | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBnyzTy7 | q-04c27caedf | ok |
| 2 | 2020-05-02 03:15:04.135Z | nashua.dmevals.local | windows.sysmon | file.path | C:\Users\pbeesly\AppData\Local\Temp\_MEI29522 | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBow16Q8 | q-f84bd08d34 | ok |
| 3 | 2020-05-02 03:15:48.652Z | nashua.dmevals.local | windows.sysmon | process.parent.executable | C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBnyzDzk | q-71b0483a9e | ok |
| 4 | 2020-05-02 03:16:40.975Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\Windows\System32\cmd.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBnvv_3R | q-71b0483a9e | ok |

### F60 · malicious / high · T1552.001 · Credential-harvesting script on scranton collects files matching *pass*, *login*, *vpn*, *sifr* into an archive

Evidence status: **verified**

At 02:56:17 on scranton.dmevals.local, PowerShell (pbeesly) enumerated the user profile for *.doc, *.xls, *.pdf, *.zip, *.pst, *psw*, *pass*, *login*, *admin*, *sifr*, *sifer*, *vpn*, *.txt, *.lnk and compressed the results with Compress-Archive into %APPDATA% (Draft.Zip written at 02:56:18). This targeted collection of password/login-named files is a credential-harvesting step not described in the anchors.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:56:17.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | $env:APPDATA;$files=ChildItem -Path $env:USERPROFILE\ -Include *.doc,*.xps,*.xls,*.ppt,*.pps,*.wps,*.wpd,*.ods,*.odt,*.lwp,*.jtd,*.pdf,*.zip,*.rar,*.docx,*.url,… | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByXfnRy | q-dc66aba2a4 | ok |
| 2 | 2020-05-02 02:56:18.032Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Users\pbeesly\AppData\Roaming\Draft.Zip | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBouzukT | q-ceded19947 | ok |

### F63 · malicious / high · T1552.001 · Screensaver-named loader in C:\ProgramData\victim opens LSA registry key and stages the IEX payload on scranton

Evidence status: **verified**

At 02:55:56 on scranton.dmevals.local, explorer.exe launched C:\ProgramData\victim\â€®cod.3aka3.scr with /S as pbeesly. The binary immediately opened HKLM\SYSTEM\ControlSet001\Control\Lsa (02:55:56), spawned cmd.exe, and wrote C:\Users\pbeesly\Downloads\monkey.png (02:57:00) which the hidden PowerShell stager decoded and IEX'd. It was later wiped with sdelete64 at 03:02:04. This LSA-registry-touching loader is the entry point of the credential-theft chain and is new relative to the anchors.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:55:56.157Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\ProgramData\victim\â€®cod.3aka3.scr" /S | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBow1KRR | q-a347dbe744 | ok |
| 2 | 2020-05-02 02:55:56.157Z | scranton.dmevals.local | windows.sysmon | process.parent.executable | C:\Windows\explorer.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBow1KRR | q-a347dbe744 | ok |
| 3 | 2020-05-02 02:55:56.000Z | scranton.dmevals.local | windows.security | win.ObjectName | \REGISTRY\MACHINE\SYSTEM\ControlSet001\Control\Lsa | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBy3EfF1 | q-e6a33b0285 | ok |
| 4 | 2020-05-02 02:57:00.933Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Users\pbeesly\Downloads\monkey.png | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBouy-nD | q-ceded19947 | ok |

### F64 · malicious / high · T1552.001 · Hidden PowerShell compiles .NET payloads with csc.exe from Temp response files on scranton

Evidence status: **verified**

On scranton.dmevals.local, csc.exe was launched twice (02:58:45 and 03:08:03) by a hidden PowerShell (-noni -noexit -ep bypass -window hidden) that decodes a payload from monkey.png and IEX's it, compiling qkbkqqbs.dll and 0piklvia.dll from response files in %TEMP%. This in-memory .NET compilation supporting the credential-theft tooling is new relative to the anchors.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:58:45.297Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe" /noconfig /fullpaths @"C:\Users\pbeesly\AppData\Local\Temp\qkbkqqbs\qkbkqqbs.cmdline" | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBorwNwU | q-cbd90322c6 | ok |
| 2 | 2020-05-02 02:58:45.297Z | scranton.dmevals.local | windows.sysmon | process.parent.command_line | "PowerShell.exe" -noni -noexit -ep bypass -window hidden -c "sal a New-Object;Add-Type -AssemblyName 'System.Drawing'; $g=a System.Drawing.Bitmap('C:\Users\pbee… | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBorwNwU | q-cbd90322c6 | ok |
| 3 | 2020-05-02 03:15:04.197Z | nashua.dmevals.local | windows.sysmon | file.path | C:\Users\pbeesly\AppData\Local\Temp\_MEI29522\python.exe.manifest | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoy314I | q-f84bd08d34 | ok |

### F25 · malicious / high · T1552.004 · PowerShell Get-PrivateKeys exports all LocalMachine certificates to password-protected .pfx files in Downloads

Evidence status: **verified**

On scranton.dmevals.local at 2020-05-02T03:04:56Z, user pbeesly (SID S-1-5-21-1830255721-3727074217-2423397540-1107) executed a script block defining function Get-PrivateKeys (ScriptBlock ID 9d153741-75c3-4062-afe3-aeca0aee611b, Path C:\Program Files\SysinternalsSuite\readme.ps1). It enumerates cert:\LocalMachine recursively and calls Export-PfxCertificate for every certificate with a thumbprint, writing to $env:USERPROFILE\Downloads\<random>.pfx protected by the hardcoded password "saribas". One second later Sysmon recorded powershell.exe creating C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx, confirming the private-key export actually happened. This is textbook private-key harvesting for later credential/authentication abuse.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByRaLqc | q-9c2d214561 | ok |
| 2 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\readme.ps1 | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByRaLqc | q-9c2d214561 | ok |
| 3 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | user.name | pbeesly | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByRaLqc | q-9c2d214561 | ok |
| 4 | 2020-05-02 03:04:57.460Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoMQkXH | q-59b205ef9f | ok |
| 5 | 2020-05-02 03:04:57.460Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\WindowsPowerShell\v1.0\powershell.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoMQkXH | q-59b205ef9f | ok |

### F31 · malicious / high · T1555 · Full-access LSASS handle from PowerShell.exe on scranton (credential-dump style access)

Evidence status: **verified**

On scranton.dmevals.local, PowerShell.exe (PID 2976, running as SYSTEM, entity {47ab858c-e1e4-5eac-b803-000000000400}) opened lsass.exe (PID 736) with GrantedAccess 0x1F3FFF at 03:05:16.623Z and 0x1FFFFF at 03:05:16.654Z, with a CallTrace ending in UNKNOWN(000001996D252982)/UNKNOWN(000001996D28200D) — i.e. code outside any known module, the classic signature of an in-memory credential dumper. This is the only process in the whole dataset that requested PROCESS_ALL_ACCESS-style masks on lsass; the other 0x1fffff holders are wininit.exe/csrss.exe at 03:19:09 (system boot-time access). It occurs inside a confirmed intrusion chain on scranton: a malicious screen saver C:\ProgramData\victim\â€®cod.3aka3.scr launched by explorer.exe as pbeesly at 02:55:56, spawning cmd.exe and powershell.exe, followed by sdclt.exe UAC-bypass abuse, csc.exe compilation of an in-memory payload, Sysinternals download, sdelete64.exe anti-forensics, and a PowerShell exfil script (Invoke-Exfil) that archives and copies data to \\192.168.0.4\webdav. The same actor also ran Get-PrivateKeys, exporting all LocalMachine certificates to .pfx files. Credential theft from the host is therefore strongly supported.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoMQUXF | q-e2eb56940b | ok |
| 2 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoMQUXF | q-e2eb56940b | ok |
| 3 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.CallTrace | C:\windows\SYSTEM32\ntdll.dll+9c584\|C:\windows\System32\KERNELBASE.dll+2732e\|UNKNOWN(000001996D252982) | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoMQUXF | q-c18fa49215 | ok |
| 4 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoMQUXI | q-e2eb56940b | ok |
| 5 | 2020-05-02 02:55:56.157Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\ProgramData\victim\â€®cod.3aka3.scr | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBow1KRR | q-90c21448c2 | ok |
| 6 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByRaLqc | q-851d07f079 | ok |

### F51 · malicious / high · T1606.002 · Certificate private keys exported to password-protected .pfx files on SCRANTON (staging for token/certificate forgery)

Evidence status: **verified**

On scranton.dmevals.local, user pbeesly (PowerShell PID 3876, script path C:\Program Files\SysinternalsSuite\readme.ps1) defined and executed a Get-PrivateKeys function at 2020-05-02T03:04:56Z that enumerates every certificate in cert:\LocalMachine recursively and exports each one with its private key via Export-PfxCertificate to $env:USERPROFILE\Downloads\<random>.pfx, protected by the hardcoded password 'saribas'. One second later (03:04:57.460Z) Sysmon recorded the resulting file C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx created by powershell.exe. The exported keys were then bundled: Invoke-Exfil (03:08:02Z) 7-Zips the whole Downloads directory into $env:APPDATA\OfficeSupplies.7z with password 'lolol' and copies it to the WebDAV share \\192.168.0.4\webdav using credentials cozy/MyCozyPassw0rd!, after which Invoke-BeachCleanup (03:08:51Z) deletes *.pfx, *.bmp, *.png and OfficeSupplies.7z. Exported certificate private keys are exactly the material used to sign forged SAML tokens / mint forged web credentials, so this is credential-access staging for T1606.002. No AADInternals, ADFS, SAML or New-AADIntSAMLToken script blocks were observed in the PowerShell logs, so the actual token forging step is not visible in this window.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByRaLqc | q-1623f33a96 | ok |
| 2 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\readme.ps1 | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByRaLqc | q-1623f33a96 | ok |
| 3 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | user.name | pbeesly | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByRaLqc | q-1623f33a96 | ok |
| 4 | 2020-05-02 03:04:57.460Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoMQkXH | q-8ffc39c626 | ok |
| 5 | 2020-05-02 03:04:57.460Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\WindowsPowerShell\v1.0\powershell.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoMQkXH | q-8ffc39c626 | ok |
| 6 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByPYrDh | q-3e10606af0 | ok |
| 7 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByPYrDh | q-3e10606af0 | ok |
| 8 | 2020-05-02 03:08:51.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-BeachCleanup {     Write-Host "[*] Cleaning up"     Remove-Item -Path "$env:USERPROFILE\Downloads\*.pfx" -Force     Remove-Item -Path "$env:USER… | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByCVdnF | q-272f41c77c | ok |

### F54 · malicious / high · T1649 · PowerShell Get-PrivateKeys exports all LocalMachine certificates to password-protected .pfx files on SCRANTON

Evidence status: **verified**

On 2020-05-02 at 03:04:56 UTC (23:04:56 local) on scranton.dmevals.local, user pbeesly executed a PowerShell script block (4104, ScriptBlock ID 9d153741-75c3-4062-afe3-aeca0aee611b, Path C:\Program Files\SysinternalsSuite\readme.ps1) defining function Get-PrivateKeys. The script enumerates every certificate in cert:\LocalMachine recursively and calls Export-PfxCertificate for each one that has a Thumbprint, writing to $env:USERPROFILE\Downloads\<random>.pfx protected by the hardcoded password 'saribas'. One second later (03:04:57.460 UTC) Sysmon recorded powershell.exe (PID 3876) creating C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx, confirming the export actually ran and private keys were written to disk in exportable form. A companion script block at 03:08:51 (Invoke-BeachCleanup, Path C:\Program Files\SysinternalsSuite\psversion.ps1) deletes $env:USERPROFILE\Downloads\*.pfx along with *.bmp, *.png and %APPDATA%\OfficeSupplies.7z, i.e. anti-forensic cleanup of the stolen certificate bundles and staged data. This is textbook T1649 certificate theft: harvesting machine private keys for later authentication/forgery. The same actor then used PsExec64.exe from SCRANTON with cleartext credentials (dmevals\pbeesly) to run C:\Windows\Temp\python.exe on \\NASHUA at 03:11-03:14, consistent with using harvested material to move laterally.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByRaLqc | q-b2e54336ab | ok |
| 2 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\readme.ps1 | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByRaLqc | q-b2e54336ab | ok |
| 3 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | user.name | pbeesly | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByRaLqc | q-b2e54336ab | ok |
| 4 | 2020-05-02 03:04:57.460Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoMQkXH | q-5d2d917009 | ok |
| 5 | 2020-05-02 03:04:57.460Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\WindowsPowerShell\v1.0\powershell.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoMQkXH | q-5d2d917009 | ok |
| 6 | 2020-05-02 03:08:51.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-BeachCleanup {     Write-Host "[*] Cleaning up"     Remove-Item -Path "$env:USERPROFILE\Downloads\*.pfx" -Force     Remove-Item -Path "$env:USER… | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByCVdnF | q-fe96bb92ca | ok |
| 7 | 2020-05-02 03:11:18.784Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\PsExec64.exe" -accepteula \\NASHUA -u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoz4z4i | q-ee97073d9d | ok |

### F02 · suspicious / medium · T1003.001 · wsmprovhost.exe on nashua opens lsass with 0x1F3FFF during pbeesly remote PowerShell session

Evidence status: **verified**

On nashua.dmevals.local at 2020-05-02T03:09:29Z, wsmprovhost.exe (PID 7720) opened lsass.exe (PID 728) with GrantedAccess 0x1F3FFF. The call trace runs through System.ni.dll and Microsoft.PowerShell.Commands.Management.ni.dll, i.e. a PowerShell cmdlet (Get-Process -IncludeUserName) issued inside the WinRM host. This is the same pbeesly session that at 23:09:23 local ran 'Invoke-Command -ComputerName NASHUA -ScriptBlock { Get-Process -IncludeUserName ... }' from scranton, and 4688/4624 show wsmprovhost.exe and network logons (LogonType 3) for pbeesly on nashua at that time. The access mask is far broader than needed for a process listing, but the call trace is consistent with a legitimate .NET/PowerShell API path rather than injected code, so this is assessed as suspicious lateral credential-access reconnaissance rather than a confirmed dump.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBn663fz | q-0c4b89c94e | ok |
| 2 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBn663fz | q-0de9df3352 | ok |
| 3 | 2020-05-02 03:09:23.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | Invoke-Command -ComputerName NASHUA -ScriptBlock { Get-Process -IncludeUserName \| Select-Object UserName,SessionId \| Where-Object { $_.UserName -like "*\$env:… | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByEVwPJ | q-e0c80138ad | ok |
| 4 | 2020-05-02 03:09:23.000Z | nashua.dmevals.local | windows.security | process.command_line | C:\windows\system32\wsmprovhost.exe -Embedding | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBuv5SEZ | q-5c6287c0eb | ok |
| 5 | 2020-05-02 03:10:23.000Z | nashua.dmevals.local | windows.security | win.IpAddress | 10.0.1.4 | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBunxq2L | q-5c6287c0eb | ok |

### F62 · suspicious / low · T1003.002 · SAM hive opened with 0xf003f by lsass on scranton during the intrusion window

Evidence status: **verified**

On scranton.dmevals.local, lsass.exe (SCRANTON$) opened the SAM registry object with access mask 0xf003f at 03:19:21-03:19:22 and again at 03:20:46. This is consistent with local account hash access, but the requesting process is lsass itself under the machine account, so it may be legitimate system activity; it is reported as suspicious only because it coincides with the credential-dumping session.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:21.000Z | scranton.dmevals.local | windows.security | win.ObjectName | SAM | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBudp5HI | q-428954f97c | ok |
| 2 | 2020-05-02 03:19:21.000Z | scranton.dmevals.local | windows.security | win.AccessMask | 0xf003f | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBudp5HI | q-428954f97c | ok |
| 3 | 2020-05-02 03:20:46.000Z | scranton.dmevals.local | windows.security | win.ProcessName | C:\Windows\System32\lsass.exe | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBuiuXgG | q-428954f97c | ok |

### F16 · suspicious / medium · T1110.002 · LSASS memory read by PowerShell (0x1fffff) and registry LSA/SAM access — credential dumping, not offline cracking

Evidence status: **verified**

On scranton.dmevals.local at 2020-05-02T03:05:16Z, C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe (PID 2976, SYSTEM) opened lsass.exe (PID 736) with GrantedAccess 0x1f3fff and then 0x1fffff — full-access handles consistent with credential dumping; the call trace ends in UNKNOWN(000001996D28200D), i.e. unbacked code. This is the only non-system process in the whole window with such access (all other 289 svchost.exe accesses are 0x1000). Related: 4663 object-access events show pbeesly's tooling (PsExec64.exe, sdelete64.exe, logman.exe) touching \REGISTRY\MACHINE\SYSTEM\ControlSet001\Control\Lsa, and the SAM object appears 10 times in the 4663/4656 stack. However, no evidence of offline cracking was found: no reg save of hives (0 hits), no hashcat/john/Invoke-Mimikatz script blocks (0 hits), and the only hive-like file creations are benign Prefetch .pf entries for SECURITYHEALTH* binaries. The observed behaviour is dumping/collection, so T1110.002 (password cracking) itself is not observed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoMQUXI | q-b618d396bf | ok |
| 2 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.CallTrace | C:\windows\SYSTEM32\ntdll.dll+9c584\|C:\windows\System32\KERNELBASE.dll+2732e\|UNKNOWN(000001996D28200D) | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoMQUXI | q-b618d396bf | ok |
| 3 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoMQUXF | q-a1160a3df2 | ok |
| 4 | 2020-05-02 03:02:04.000Z | scranton.dmevals.local | windows.security | win.ObjectName | \REGISTRY\MACHINE\SYSTEM\ControlSet001\Control\Lsa | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBy1B5lE | q-e47895b6dd | ok |
| 5 | 2020-05-02 03:21:28.476Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Windows\Prefetch\SECURITYHEALTHSYSTRAY.EXE-41AD6DE1.pf | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBizx7sV | q-1820d76eaf | ok |

### F20 · suspicious / medium · T1111 · wsmprovhost.exe on nashua opened lsass.exe with 0x1F3FFF via PowerShell Management module

Evidence status: **verified**

On nashua.dmevals.local at 03:09:29Z, wsmprovhost.exe (PID 7720, WinRM/PSRemoting host, parent svchost.exe -k DcomLaunch -p) opened lsass.exe (PID 728) with GrantedAccess 0x1F3FFF. The call trace runs through Microsoft.PowerShell.Commands.Management.ni.dll, i.e. a PowerShell remoting session requested the handle. This coincides with pbeesly's PsExec-style lateral movement to nashua (PSEXESVC service installs and 4648 explicit-credential logons for pbeesly at 23:11–23:15 local) and with the malicious LSASS access on scranton, so it is consistent with remote credential harvesting over WinRM rather than routine administration; however no dump file or follow-on tooling was observed for this host, hence medium confidence.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBn663fz | q-cb0a015528 | ok |
| 2 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBn663fz | q-4322e8e879 | ok |
| 3 | 2020-05-02 03:09:23.885Z | nashua.dmevals.local | windows.sysmon | process.command_line | C:\windows\system32\wsmprovhost.exe -Embedding | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBo05D7L | q-7c2edc99fb | ok |
| 4 | 2020-05-02 03:11:40.000Z | nashua.dmevals.local | windows.security | process.executable | C:\Windows\PSEXESVC.exe | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBuu5GRH | q-1507fd9e9f | ok |

### F65 · suspicious / medium · T1552.001 · hostui.exe launched with -verb runas and hostui.lnk placed in StartUp for persistence on scranton

Evidence status: **verified**

On scranton.dmevals.local at 03:21:27, PowerShell (pbeesly) ran 'Start-Process C:\Windows\System32\hostui.exe -verb runas', elevating hostui.exe to High integrity, and at 03:04:23 a hostui.lnk was written to the all-users StartUp folder. This is attacker persistence/elevation supporting the credential-access session, not described in the anchors.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:21:27.276Z | scranton.dmevals.local | windows.sysmon | process.parent.command_line | powershell.exe  -c "Start-Process C:\Windows\System32\hostui.exe -verb runas" | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBi30hQJ | q-67b388b1da | ok |
| 2 | 2020-05-02 03:04:23.681Z | scranton.dmevals.local | windows.sysmon | file.path | C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\hostui.lnk | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoOSXoo | q-77bad2548c | ok |

### F66 · suspicious / low · T1552.001 · sdclt.exe UAC-bypass-style launches from cmd.exe in C:\ProgramData\victim on scranton

Evidence status: **verified**

On scranton.dmevals.local at 02:58:42-02:58:43, cmd.exe (pbeesly, current directory C:\ProgramData\victim\) launched sdclt.exe three times, followed by control.exe as a child of sdclt.exe. sdclt is a known UAC-bypass binary; no credential-store access resulted from it in the observed window.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:58:42.401Z | scranton.dmevals.local | windows.sysmon | process.command_line | C:\windows\system32\sdclt.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBosxOR1 | q-9e73a25bac | ok |
| 2 | 2020-05-02 02:58:42.401Z | scranton.dmevals.local | windows.sysmon | process.parent.executable | C:\Windows\System32\cmd.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBosxOR1 | q-9e73a25bac | ok |

### F61 · suspicious / medium · T1555.003 · accesschk.exe on scranton probes a 'passwordsDB' file in the Sysinternals folder

Evidence status: **verified**

At 03:04:35 on scranton.dmevals.local, C:\Program Files\SysinternalsSuite\accesschk.exe (child of PowerShell, pbeesly) wrote/created C:\Program Files\SysinternalsSuite\passwordsDB. The tool was run from the attacker-staged SysinternalsSuite directory and the artifact name indicates a password store being touched; no browser credential database access was observed in the window.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:35.069Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Program Files\SysinternalsSuite\passwordsDB | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoNRGHl | q-77bad2548c | ok |
| 2 | 2020-05-02 03:04:34.951Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\accesschk.exe" | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoNRGHW | q-01c368af06 | ok |

### F35 · suspicious / medium · T1556 · Credential-access intrusion on scranton/nashua with full-access lsass handles, but no authentication-process modification observed

Evidence status: **verified**

On 2020-05-02 between 02:56 and 03:21 UTC an operator using account pbeesly ran a steganographic PowerShell loader on scranton.dmevals.local (payload decoded from C:\Users\pbeesly\Downloads\monkey.png, parent control.exe), spawned hidden/encoded PowerShell, and used a UAC bypass (powershell.exe -c "Start-Process C:\Windows\System32\hostui.exe -verb runas" followed by powershell.exe -c "Get-ItemPropertyValue 'HKLM:\\SOFTWARE\Javasoft' 'value Supplement' \| Invoke-Expression"). On nashua.dmevals.local the same user ran C:\Windows\Temp\python.exe from PSEXESVC.exe, which spawned powershell.exe and cmd.exe. In this context PowerShell.exe on scranton opened lsass.exe with GrantedAccess 0x1FFFFF (full access) at 03:05:16 and wsmprovhost.exe on nashua opened lsass.exe with 0x1F3FFF at 03:09:29 — consistent with credential theft from lsass. However, no evidence of authentication-process modification was found: no 4657 changes to LSA/Security/SAM keys (only WMI Autologger and certificate/WSMAN keys), no registry writes to Notification Packages/WDigest/lsass paths, no 4739/5136 events, no password-filter DLL loads into lsass, and the only lsass image load was lsass.exe itself at boot. The 4648 machine-account logon (SCRANTON$ via taskhostw.exe) and 4662 SecretObject reads of Policy\Secrets\$MACHINE.ACC by LOCAL SERVICE are routine.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoMQUXI | q-aeb82104e7 | ok |
| 2 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBn663fz | q-fe0639e9fd | ok |
| 3 | 2020-05-02 02:58:44.325Z | scranton.dmevals.local | windows.sysmon | process.command_line | "PowerShell.exe" -noni -noexit -ep bypass -window hidden -c "sal a New-Object;Add-Type -AssemblyName 'System.Drawing'; $g=a System.Drawing.Bitmap('C:\Users\pbee… | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBorwtwa | q-2fe8d90d06 | ok |
| 4 | 2020-05-02 03:21:27.859Z | scranton.dmevals.local | windows.sysmon | process.command_line | powershell.exe -c "Get-ItemPropertyValue 'HKLM:\\SOFTWARE\Javasoft' 'value Supplement' \| Invoke-Expression" | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBizx7td | q-2fe8d90d06 | ok |
| 5 | 2020-05-02 03:11:40.213Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoz4j7h | q-0f3e8bb2b3 | ok |
| 6 | 2020-05-02 03:19:35.000Z | scranton.dmevals.local | windows.security | win.ProcessName | C:\Windows\System32\taskhostw.exe | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBuWmJMP | q-2717e5b199 | ok |

### F41 · suspicious / low · T1556.008 · No malicious network provider DLL; lsass memory-write access is the credential-theft signal

Evidence status: **verified**

The 30,212 process-access events with memory-write rights are dominated by svchost.exe (17,145), backgroundTaskHost.exe (5,296) and Explorer.EXE (750) — normal Windows behaviour. lsass.exe appears as a target 294 times, including the full-access opens by PowerShell.exe on scranton (0x1FFFFF) and wsmprovhost.exe on nashua (0x1F3FFF) during the pbeesly intrusion, which is consistent with credential dumping rather than a network-provider backdoor. No 4657 changes to NetworkProvider/Winlogon keys, no PowerShell referencing NetworkProvider, and loaded network-related images are all legitimate System32 DLLs (npmproxy.dll, mobilenetworking.dll, InputHost.dll).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoMQUXI | q-aeb82104e7 | ok |
| 2 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBn663fz | q-fe0639e9fd | ok |

### F46 · suspicious / medium · T1558 · PowerShell session on SCRANTON opened lsass with full-access rights (0x1F3FFF / 0x1FFFFF) during a hands-on-keyboard intrusion

Evidence status: **verified**

On scranton.dmevals.local at 2020-05-02T03:05:16, PowerShell.exe (PID 2976, running as SYSTEM per the event's AccountName) opened C:\windows\system32\lsass.exe twice within 31 ms with GrantedAccess 0x1F3FFF and 0x1FFFFF — masks that include PROCESS_VM_READ/PROCESS_VM_WRITE and are the classic signature of credential/ticket material harvesting from LSASS. The same PowerShell session (user pbeesly) was concurrently running attacker-style functions: Get-PrivateKeys (exporting cert private keys with a hardcoded password), Invoke-Persistence, Invoke-ScreenCapture, Invoke-BeachCleanup, and Invoke-SeaDukeStage -ComputerName NASHUA. No mimikatz/Rubeus/sekurlsa command line was found in Sysmon process creation (0 hits), and no 4768/4771/4770 Kerberos failures were observed, so the specific ticket-theft outcome is not proven — but the LSASS access is not explainable as normal system behaviour and is consistent with credential/ticket theft on a compromised host.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoMQUXI | q-20d1b13f4b | ok |
| 2 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoMQUXF | q-ed934a40c6 | ok |
| 3 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoMQUXI | q-20d1b13f4b | ok |
| 4 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByRaLqc | q-dc3e061ee9 | ok |
| 5 | 2020-05-02 03:04:23.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | Invoke-Persistence -PersistStep 2 | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByRarq9 | q-dc3e061ee9 | ok |
| 6 | 2020-05-02 03:10:22.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | Invoke-SeaDukeStage -ComputerName NASHUA | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByDV_QB | q-48a91ef4ea | ok |

### F53 · suspicious / medium · T1606 · Credential-access precursor activity: lsass handle access and PsExec lateral movement by pbeesly

Evidence status: **verified**

On scranton.dmevals.local, PowerShell.exe (PID 2976) opened lsass.exe (PID 736) with GrantedAccess 0x1F3FFF and 0x1FFFFF at 2020-05-02T03:05:16Z, immediately after the certificate-export script ran; the remaining high-access lsass events (wininit.exe/csrss.exe 0x1FFFFF at 03:19:09Z, svchost.exe 0x101001, 0x3000) are consistent with normal system processes. In the same session pbeesly performed explicit-credential logons (4648) from 10.0.1.6 against scranton.dmevals.local and, via C:\Windows\PSEXESVC.exe, against nashua.dmevals.local, where PSEXESVC services were installed four times between 03:11:39Z and 03:15:03Z. This is credential use/lateral movement rather than web-credential forging itself, so it is reported as suspicious context for the T1606 family rather than as forged-credential activity.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoMQUXI | q-bc9ad6c418 | ok |
| 2 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoMQUXF | q-bc9ad6c418 | ok |
| 3 | 2020-05-02 03:11:40.000Z | nashua.dmevals.local | windows.security | process.executable | C:\Windows\PSEXESVC.exe | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBuu5GRH | q-89c5439091 | ok |
| 4 | 2020-05-02 03:11:39.000Z | nashua.dmevals.local | windows.other | process.executable | %SystemRoot%\PSEXESVC.exe | .ds-logs-windows.other-default-2026.10.22-000001 / AaFiKJc9VXKkeBwdMB0i | q-04e60f7b60 | ok |

### F05 · benign / medium · T1003.002 · No SAM/SECURITY hive export observed

Evidence status: **verified**

Registry writes touching SAM/SECURITY keys were limited to HKLM\SECURITY\Cache\NL$1 (5), HKLM\SAM\SAM\Domains\Account\F (1) and a LogonUI SessionData value; file writes matching SAM/SECURITY/SYSTEM/*.hiv were only Prefetch files for SecurityHealth binaries. No reg save/export command lines, no 4663 access to SAM/SECURITY objects and no hive files written (checks C015-C021 zero hits). The HKLM\SECURITY\Cache\NL$1 writes are the OS updating the cached-credential store, not an extraction.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:59:42.544Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Users\pbeesly\Downloads\SysinternalsSuite.zip | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoglALi | q-ec9dad1d5a | ok |

### F06 · benign / medium · T1003.003 · No NTDS.dit / VSS shadow copy activity

Evidence status: **verified**

No process command lines referencing ntds, ntdsutil, vssadmin or diskshadow, no writes of ntds.dit, and no 7045 service installs with vss/ntds/shadow image paths were found (checks C022-C027 zero hits). The only .dmp files written were WER crash dumps (WER51F5.tmp.dmp, WER5437.tmp.dmp) under C:\ProgramData\Microsoft\Windows\WER\Temp, which are Windows Error Reporting artifacts, not credential dumps.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:27.395Z | nashua.dmevals.local | windows.sysmon | win.TargetFilename | C:\ProgramData\Microsoft\Windows\WER\Temp\WER51F5.tmp.dmp | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoLO1t- | q-ec9dad1d5a | ok |

### F03 · benign / medium · T1003.004 · LSA secret $MACHINE.ACC queried by LOCAL SERVICE on three hosts (benign service behaviour)

Evidence status: **verified**

Six 4662 events show NT AUTHORITY\LOCAL SERVICE querying the LSA secret object Policy\Secrets\$MACHINE.ACC (AccessMask 0x2, 'Query secret value') on nashua, scranton and utica between 23:02:59 and 23:20:36 local. This is the standard machine-account secret read performed by the local service stack, not an attacker dumping LSA secrets; no non-service account, no lsadump/secretsdump tooling and no SECURITY\Policy\Secrets file access was observed (checks C029-C034 had no hits).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:02:59.000Z | nashua.dmevals.local | windows.security | win.ObjectName | Policy\Secrets\$MACHINE.ACC | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBy1BJnq | q-d92d21a2ac | ok |
| 2 | 2020-05-02 03:02:59.000Z | nashua.dmevals.local | windows.security | win.SubjectUserName | LOCAL SERVICE | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBy1BJnq | q-d92d21a2ac | ok |
| 3 | 2020-05-02 03:20:03.000Z | nashua.dmevals.local | windows.security | win.AccessMask | 0x2 | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBufr2nf | q-d92d21a2ac | ok |

### F07 · benign / medium · T1003.005 · No cached domain credential extraction observed

Evidence status: **verified**

Command lines matching cache/dcc2/mscache/cachedump were only dxgiadaptercache.exe and svchost Dnscache; no 4663/4656/4670 access to SECURITY\Cache objects and no PowerShell script blocks referencing cachedump/dcc2/mscache (checks C036-C040 zero hits). The HKLM\SECURITY\Cache\NL$1 registry writes are normal OS maintenance of the cached logon store.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:00:13.557Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\Windows\System32\conhost.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoZdz8w | q-200368d154 | ok |

### F04 · benign / medium · T1003.006 · Single 4662 DS access by NEWYORK$ machine account — not DCSync

Evidence status: **verified**

One 4662 on newyork.dmevals.local at 2020-05-01T23:16:15 local shows the machine account NEWYORK$ (S-1-5-18, Logon ID 0x167EDA) performing 'Control Access' (AccessMask 0x100) on a DS object, with the Properties list containing {1131f6aa-9c07-11d1-f79f-00c04fc2dcd2} (DS-Replication-Get-Changes). It is a single event by the host's own computer account, not a user account, and does not include the DS-Replication-Get-Changes-All GUID {1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}; no drsuapi/lsadump/dcsync command lines were found (C043 zero hits). Consistent with normal AD-integrated host replication/DC interaction rather than a DCSync attack.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:16:15.000Z | newyork.dmevals.local | windows.security | win.SubjectUserName | NEWYORK$ | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBumw-cX | q-d92d21a2ac | ok |
| 2 | 2020-05-02 03:16:15.000Z | newyork.dmevals.local | windows.security | win.Properties | %%7688  		{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}  	{19195a5b-6da0-11d0-afd3-00c04fd930c9}   | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBumw-cX | q-d92d21a2ac | ok |
| 3 | 2020-05-02 03:16:15.000Z | newyork.dmevals.local | windows.security | win.AccessMask | 0x100 | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBumw-cX | q-3bed1ffea0 | ok |

### F08 · benign / high · T1040 · Azure Network Watcher agent ran netsh packet capture on scranton.dmevals.local (benign platform telemetry)

Evidence status: **verified**

On 2020-05-02 at 03:19:17Z on scranton.dmevals.local, SYSTEM launched C:\Windows\System32\netsh.exe 'trace start capture=yes traceFile="C:\windows\TEMP\E7116ECA-DFE6-43C7-8FA8-8D3AC5AA8726\B91E06C5-1C7C-4830-9A76-74FA211560A7.etl"'. The parent of every netsh invocation is the signed Microsoft Azure Network Watcher agent (C:\Packages\Plugins\Microsoft.Azure.NetworkWatcher.NetworkWatcherAgentWindows\1.4.1421.1\NetworkWatcherAgent\NetworkWatcherAgent.exe /service, Company 'Microsoft CoreXT', Description 'Networking-NetAnalytics release_14_nwa'). The capture lifecycle is complete and self-contained: trace start at 03:19:17, ETL written to C:\Windows\Temp\E7116ECA-...\B91E06C5-....etl at 03:19:23, trace stop at 03:19:24, and .etl.merged at 03:19:26. The same agent also spawned logman.exe trace sessions writing to C:\WindowsAzure\Logs\WaAppAgent.etl and RuntimeEvents.etl under WaAppAgent.exe. This is Azure Network Watcher packet-capture/NetAnalytics functionality, not adversary sniffing. No attacker-controlled capture tooling was found: zero hits for pktmon, dumpcap, tshark, wireshark, windump, rawcap, NetworkMiner or fiddler in Sysmon process creation or Security 4688; zero Sysmon image loads of pcap/npcap/winpcap/pktmon drivers; zero registry writes referencing pcap/npcap/WinPcap/pktmon; zero service installs of pcap/npcap/winpcap; zero PowerShell script blocks referencing pktmon/netsh/WinPcap/Get-NetAdapter. The zeek window (2020-04-30, non-overlapping with the Windows data) shows only ordinary service traffic (8443, 445, 53, 389, 88, 135, 80, 5985) with no capture-related or promiscuous-pattern indicators, and its only notices are SSL::Invalid_Server_Cert self-signed certificate events.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:17.154Z | scranton.dmevals.local | windows.sysmon | process.command_line | C:\windows\system32\netsh.exe trace start capture=yes traceFile="C:\windows\TEMP\E7116ECA-DFE6-43C7-8FA8-8D3AC5AA8726\B91E06C5-1C7C-4830-9A76-74FA211560A7.etl" | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBnvvDAD | q-f9ad8635b5 | ok |
| 2 | 2020-05-02 03:19:17.154Z | scranton.dmevals.local | windows.sysmon | process.parent.executable | C:\Packages\Plugins\Microsoft.Azure.NetworkWatcher.NetworkWatcherAgentWindows\1.4.1421.1\NetworkWatcherAgent\NetworkWatcherAgent.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBnvvDAD | q-f9ad8635b5 | ok |
| 3 | 2020-05-02 03:19:24.835Z | scranton.dmevals.local | windows.sysmon | process.command_line | C:\windows\system32\netsh.exe trace stop | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBnkjXIW | q-f9ad8635b5 | ok |
| 4 | 2020-05-02 03:19:13.877Z | scranton.dmevals.local | windows.sysmon | win.Description | Networking-NetAnalytics release_14_nwa (af53be328) Microsoft CoreXT | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBnaXZbG | q-10cc721beb | ok |
| 5 | 2020-05-02 03:19:13.877Z | scranton.dmevals.local | windows.sysmon | win.Company | Microsoft CoreXT | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBnaXZbG | q-10cc721beb | ok |
| 6 | 2020-05-02 03:19:23.900Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Windows\Temp\E7116ECA-DFE6-43C7-8FA8-8D3AC5AA8726\B91E06C5-1C7C-4830-9A76-74FA211560A7.etl | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBndb5l3 | q-d56b2e06c6 | ok |
| 7 | 2020-05-02 03:19:26.759Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Windows\Temp\E7116ECA-DFE6-43C7-8FA8-8D3AC5AA8726\B91E06C5-1C7C-4830-9A76-74FA211560A7.etl.merged | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBncbMoA | q-d56b2e06c6 | ok |
| 8 | 2020-05-02 03:19:29.878Z | scranton.dmevals.local | windows.sysmon | process.command_line | "logman.exe" create trace GAEvents -max 50 -f bincirc -o C:\WindowsAzure\Logs\WaAppAgent.etl -p "{3000b92b-ca8b-4269-90ea-c4185ee09e92}" | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBnooszM | q-f9ad8635b5 | ok |
| 9 | 2020-05-02 03:19:17.000Z | scranton.dmevals.local | windows.security | win.ParentProcessName | C:\Packages\Plugins\Microsoft.Azure.NetworkWatcher.NetworkWatcherAgentWindows\1.4.1421.1\NetworkWatcherAgent\NetworkWatcherAgent.exe | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBuYnMlG | q-788a253398 | ok |

### F13 · benign / medium · T1056 · Baseline lsass handle traffic from svchost/Defender/Azure agents is benign; the anomalous access is the PowerShell/wsmprovhost pair

Evidence status: **verified**

Of 326 lsass process-access events, 293 use GrantedAccess 0x1000 (query-only) from svchost.exe, and the 0x1400 accesses come from WindowsAzureTelemetryService.exe via CorperfmonExt.dll (perf counters). 4663 lsass object access comes from CollectGuestLogs.exe and MsMpEng.exe (Defender) as machine accounts, and the 0x101001 accesses at 03:18:34Z come from svchost.exe via lsm.dll (LSA session management). These are normal platform behaviour; the credential-capture signal is the 0x1f3fff/0x1fffff PowerShell and wsmprovhost access reported under T1056.004.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:18:34.438Z | scranton.dmevals.local | windows.sysmon | win.CallTrace | C:\windows\SYSTEM32\ntdll.dll+9def4\|c:\windows\system32\lsm.dll+1aa6e\|c:\windows\system32\lsm.dll+1a9c3\|c:\windows\system32\lsm.dll+65e1\|c:\windows\system32… | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBnrrZmZ | q-31c75be9de | ok |
| 2 | 2020-05-02 03:20:15.000Z | scranton.dmevals.local | windows.security | process.executable | C:\Program Files\Windows Defender\MsMpEng.exe | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBudppHE | q-49cce6dce9 | ok |

### F11 · benign / medium · T1056.001 · No keylogger artifacts: keyboard registry hits are OS keyboard-layout/device entries

Evidence status: **verified**

The 26 registry writes matching *Keyboard* are all standard Windows keyboard-layout and device-enumeration keys (HKU\.DEFAULT\Keyboard Layout\Preload, CTF\SortOrder\...\KeyboardLayout, HKLM\HARDWARE\DEVICEMAP\KeyboardClass, TERMINPUT_BUS device parameters). No SetWindowsHookEx/GetAsyncKeyState script blocks, no keylog service installs (7045), and no keyboard-object handle requests were found. No keylogging activity observed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:56:14.000Z | utica.dmevals.local | windows.sysmon | win.TargetImage | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBov0sHE | q-6ab47c8850 | ok |

### F12 · benign / medium · T1056.003 · No web-portal credential capture: PowerShell hits are archive staging, not login pages

Evidence status: **verified**

The two 4104 hits matching *login*/*Set-Content*/*Out-File* are a file-collection/Compress-Archive script (ChildItem over *.doc,*.xls,*pass*,*login*,*admin* then Compress-Archive to $env:APPDATA\Draft.Zip) on scranton and nashua by pbeesly — data staging, not a credential-capture web page. No writes to wwwroot/inetpub, no IIS/W3SVC service installs, and no HTTP POSTs in the zeek window. No web portal capture observed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:56:17.000Z | scranton.dmevals.local | windows.powershell | process.command_line | $env:APPDATA;$files=ChildItem -Path $env:USERPROFILE\ -Include *.doc,*.xps,*.xls,*.ppt,*.pps,*.wps,*.wpd,*.ods,*.odt,*.lwp,*.jtd,*.pdf,*.zip,*.rar,*.docx,*.url,… | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByXfnRy | q-5cd54ab513 | ok |

### F14 · benign / high · T1110 · No brute-force authentication activity; credential use was with a single known plaintext password

Evidence status: **verified**

Across windows.security (02:55–03:28Z) there are zero 4625 failed-logon, zero 4771 and zero 4740 lockout events; the only authentication-failure-family record is a single 4776 on newyork.dmevals.local at 2020-05-01T23:20:40-04:00 for pbeesly with Status 0x0 (successful validation). 4624 logons are 297 total, dominated by LogonType 3 machine accounts (NEWYORK$ 123, SCRANTON$ 37, NASHUA$ 25) and LogonType 5 service logons (SYSTEM 59), plus 15 LogonType 2 and 2 LogonType 10 for pbeesly. No repeated authentication attempts, no spray, no lockouts. The attacker activity present in this window (pbeesly on scranton.dmevals.local) used one already-known credential, not guessing.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:20:40.000Z | newyork.dmevals.local | windows.security | win.Status | 0x0 | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBuTlU_q | q-2fdaf3dd46 | ok |
| 2 | 2020-05-02 03:20:40.000Z | newyork.dmevals.local | windows.security | win.TargetUserName | pbeesly | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBuTlU_q | q-2fdaf3dd46 | ok |
| 3 | 2020-05-02 03:20:46.000Z | scranton.dmevals.local | windows.security | win.LogonType | 10 | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBudppFY | q-2fdaf3dd46 | ok |

### F15 · benign / high · T1110.001 · No password guessing; runas hit is a UAC elevation of hostui.exe, not a password attempt

Evidence status: **verified**

The only runas-related process creation is on scranton.dmevals.local at 2020-05-02T03:21:19Z by pbeesly: powershell.exe -c "Start-Process C:\Windows\System32\hostui.exe -verb runas", which is a UAC elevation request, not an interactive password guess. No 4625 events exist at all (0 hits for event.code:4625 in windows.security and windows.other), so there is no evidence of repeated wrong-password attempts. The PowerShell 4104 blocks matching PSCredential/ConvertTo-SecureString are the attacker's own tooling (Get-PrivateKeys using a hardcoded string "saribas" to export .pfx certificates, and Invoke-Exfil), i.e. use of a known secret rather than guessing.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:21:19.323Z | scranton.dmevals.local | windows.sysmon | process.command_line | powershell.exe  -c "Start-Process C:\Windows\System32\hostui.exe -verb runas" | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBi85SQC | q-3e366de3c3 | ok |
| 2 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByRaLqc | q-986f7d2501 | ok |

### F17 · benign / high · T1110.003 · No password spraying; single account pbeesly used across hosts with one password

Evidence status: **verified**

No 4625/4771 events exist in windows.security or windows.other (0 hits), so there is no pattern of one password tried against many accounts. The lateral activity uses a single account: pbeesly on scranton.dmevals.local ran PsExec64.exe against \\NASHUA with -u dmevals\pbeesly -p "Fl0nk3rt0n!T0by" four times (03:11:18, 03:12:25, 03:13:28, 03:14:42Z), and Invoke-Command -ComputerName NASHUA was used at 03:09:23Z. This is reuse of one already-obtained credential against one target, not spraying across many accounts.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:18.784Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\PsExec64.exe" -accepteula \\NASHUA -u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoz4z4i | q-1c343f5e0f | ok |
| 2 | 2020-05-02 03:09:23.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | Invoke-Command -ComputerName NASHUA -ScriptBlock { Get-Process -IncludeUserName \| Select-Object UserName,SessionId \| Where-Object { $_.UserName -like "*\$env:… | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByEVwPJ | q-986f7d2501 | ok |

### F18 · benign / high · T1110.004 · No credential stuffing; no user/password list processing observed

Evidence status: **verified**

No 4625 failures exist to indicate stuffing, and no process command line referencing a .txt user list was found (0 hits for event.code:1 with .txt and user). The only credential-bearing command lines are the four PsExec64 invocations with the single hardcoded password for dmevals\pbeesly, and the PowerShell 4104 blocks contain a hardcoded archive password ("lolol") and certificate password ("saribas") used for exfiltration/packaging, not for authenticating against accounts. No evidence of iterating stolen credential pairs.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:18.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | .\PsExec64.exe -accepteula \\NASHUA -u "dmevals\pbeesly" -p "Fl0nk3rt0n!T0by" -i 2 "C:\Windows\Temp\python.exe" | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByCVdVX | q-986f7d2501 | ok |
| 2 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByPYrDh | q-986f7d2501 | ok |

### F21 · benign / high · T1111 · Remaining high-mask lsass accesses are legitimate system processes (benign)

Evidence status: **verified**

The bulk of lsass process-access events are benign: 289 of 326 come from svchost.exe with GrantedAccess 0x1000/0x1400, and the other high-mask handles are opened by Windows system components at boot or by OS services — wininit.exe and csrss.exe with 0x1FFFFF/0x1000000 at 03:19:09Z on scranton (boot-time session setup, call traces inside wininit.exe/basesrv.DLL/CSRSRV.dll), svchost.exe with 0x101001 at 03:18:34Z via lsm.dll (Local Session Manager), and svchost.exe with 0x3000 at 03:19:59Z via sysmain.dll. AntimalwareConfig.exe and WindowsAzureTelemetryService.exe also read lsass with 0x1000/0x1400 as expected for security/telemetry agents. No registry modification of LSA settings (event 13 with registry.path *lsa*) was observed, and no MFA/credential-provider component was installed — the 7045 service installs are javamtsup.exe and PSEXESVC, not authentication packages.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:09.803Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\wininit.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBnaXZbs | q-cb0a015528 | ok |
| 2 | 2020-05-02 03:19:09.803Z | scranton.dmevals.local | windows.sysmon | win.CallTrace | C:\windows\SYSTEM32\ntdll.dll+9c584\|C:\windows\system32\basesrv.DLL+2fba\|C:\windows\SYSTEM32\CSRSRV.dll+5af4\|C:\windows\SYSTEM32\ntdll.dll+6cedf | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBnqqYet | q-cb0a015528 | ok |
| 3 | 2020-05-02 03:18:34.438Z | scranton.dmevals.local | windows.sysmon | win.CallTrace | C:\windows\SYSTEM32\ntdll.dll+9def4\|c:\windows\system32\lsm.dll+1aa6e\|c:\windows\system32\lsm.dll+1a9c3\|c:\windows\system32\lsm.dll+65e1\|c:\windows\system32… | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBnrrZmZ | q-cb0a015528 | ok |
| 4 | 2020-05-02 03:19:59.323Z | scranton.dmevals.local | windows.sysmon | win.CallTrace | C:\windows\SYSTEM32\ntdll.dll+9c584\|C:\windows\System32\KERNELBASE.dll+2732e\|c:\windows\system32\sysmain.dll+1e689\|c:\windows\system32\sysmain.dll+1e509\|c:\… | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBnTPq-O | q-cb0a015528 | ok |
| 5 | 2020-05-02 03:04:15.000Z | scranton.dmevals.local | windows.other | process.executable | C:\Windows\System32\javamtsup.exe | .ds-logs-windows.other-default-2026.10.22-000001 / AaFiKJc9VXKkeBwdLx2Z | q-3c915aebe5 | ok |

### F22 · benign / medium · T1187 · No forced-authentication (T1187) artifacts; WebDAV/SMB traffic is legitimate internal file transfer and GPO access

Evidence status: **verified**

Hunting for T1187 on 2020-04-30 (zeek) and 2020-05-02 (Windows) found no coercion artifacts. The WebDAV-style HTTP methods (OPTIONS/PROPFIND/PUT/LOCK/PROPPATCH/UNLOCK, 62 requests) all come from 10.0.1.4 to internal host 192.168.0.4 with user-agent Microsoft-WebDAV-MiniRedir/10.0.18362 and DavClnt, and are a normal WebDAV upload of /webdav/OfficeSupplies.7z (PUT 201/204, PROPFIND 207) — a client-side file transfer, not an attacker coercing a victim to authenticate. SMB 445/139 traffic in zeek is GPO/sysvol reads (\\NEWYORK.dmevals.local\sysvol, GptTmpl.inf, gpt.ini) and IPC$ mappings from 10.0.1.4/10.0.1.6 to 10.0.0.4; sysmon SMB connections are all process 'System' (SYSTEM) to internal 10.0.0.4, 10.0.1.6 and a link-local IPv6 address. No .lnk/.scf/.url/.library-ms/.searchconnector-ms trigger files were created (only three .lnk files, all Explorer Recent items plus a hostui.lnk StartUp persistence artifact from powershell.exe on scranton, which is persistence rather than forced auth). No 4104 script block referenced WebDAV/NTLM/445 coercion, and all 4624 type-3 logons observed were Kerberos, not NTLM. Note: separate malicious PowerShell activity (steganography from monkey.png, hidden encoded command, hostui.exe runas persistence, Invoke-BeachCleanup deleting .pfx/.bmp/.png/OfficeSupplies.7z) exists on scranton.dmevals.local but is not T1187.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-04-30 00:32:18.095Z | simplerockbuild.simplerock.lan | zeek | user_agent.original | DavClnt | .ds-logs-zeek-default-2026.10.22-000001 / AaFiKZc9VXKkeBwkgR9D | q-05b413e1fa | ok |
| 2 | 2020-04-30 00:32:21.918Z | simplerockbuild.simplerock.lan | zeek | url.original | /webdav/OfficeSupplies.7z | .ds-logs-zeek-default-2026.10.22-000001 / AaFiKZc9VXKkeBwkgh8V | q-a84ce99ff0 | ok |
| 3 | 2020-04-30 00:32:21.918Z | simplerockbuild.simplerock.lan | zeek | http.request.method | PUT | .ds-logs-zeek-default-2026.10.22-000001 / AaFiKZc9VXKkeBwkgh8V | q-a84ce99ff0 | ok |
| 4 | 2020-04-30 00:12:01.670Z | simplerockbuild.simplerock.lan | zeek | zeek.name | dmevals.local\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\Machine\Microsoft\Windows NT\SecEdit | .ds-logs-zeek-default-2026.10.22-000001 / AaFiKZc9VXKkeBwkgR8h | q-0773003ab2 | ok |
| 5 | 2020-05-02 03:01:43.033Z | scranton.dmevals.local | windows.sysmon | process.executable | System | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoSWKN8 | q-1fdca5fe97 | ok |
| 6 | 2020-05-02 03:04:23.681Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\hostui.lnk | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoOSXoo | q-83c72233ff | ok |
| 7 | 2020-05-02 03:01:42.000Z | newyork.dmevals.local | windows.security | win.AuthenticationPackageName | Kerberos | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBy8KXgk | q-b9f4bf0ea7 | ok |

### F24 · benign / high · T1539 · No browser cookie/session-store theft observed; hits are benign browser process access and unrelated PowerShell tradecraft

Evidence status: **verified**

Hunted all four Windows hosts (2020-05-02 02:55–03:28Z) for T1539. No event shows a non-browser process reading a browser cookie database or browser memory for session theft. (1) Sysmon file-create (event 2) stacking returned only OS/AppX artefacts (USOPrivate update store, ContentDeliveryManager creatives, Cortana caches, systemprofile AppData blobs) — no Cookies/Login Data/Web Data files. (2) A targeted ES\|QL search for file paths matching *cookies*/*login data*/*web data*/*cookies.sqlite* returned exactly one hit: svchost.exe creating C:\Windows\ServiceProfiles\LocalService\...\AC\INetCookies, a normal Windows service-profile artefact. (3) Process-access (event 10) to Edge/Chrome/Firefox images came only from Explorer.EXE, svchost.exe and ctfmon.exe with GrantedAccess 0x1000/0x1400/0x2000 (query-limited/read-small), i.e. normal shell/COM/UI automation, not full-access (0x1fffff/0x1410) reads typical of cookie stealers. (4) Security 4663/5145/4656 events referencing cookie stores: zero. (5) The 4104 script blocks matching *cookie*/*session*/*token*/*browser* were benign module manifests/localized strings on newyork (SYSTEM) plus pbeesly's CIM-session aliases and a Get-Process -IncludeUserName session enumeration on scranton/nashua — no cookie extraction code. (6) The suspicious pbeesly activity on scranton (Invoke-ScreenCapture, Invoke-Exfil with 7Zip4Powershell and a WebDAV copy to \\192.168.0.4\webdav) and the PyInstaller python.exe on nashua beaconing to 192.168.0.4:8443 are collection/exfiltration tradecraft, not web-session-cookie theft. Zeek data (2020-04-30) does not overlap the Windows window and its POST check returned zero hits, so no HTTP cookie exfil is observable.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:21:05.681Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Windows\ServiceProfiles\LocalService\AppData\Local\Packages\warp_jit_db4a1097-b484-4973-bbf2-a04208ecd4d4\AC\INetCookies | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBi-6ySm | q-f84a58df14 | ok |
| 2 | 2020-05-02 03:21:30.845Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x2000 | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBizxbvb | q-7ddbc99f22 | ok |
| 3 | 2020-05-02 03:21:28.351Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\svchost.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBizx7sR | q-7ddbc99f22 | ok |
| 4 | 2020-05-02 03:09:23.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | Invoke-Command -ComputerName NASHUA -ScriptBlock { Get-Process -IncludeUserName \| Select-Object UserName,SessionId \| Where-Object { $_.UserName -like "*\$env:… | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByEVwPJ | q-3cd882cedd | ok |
| 5 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByPYrDh | q-684b371e0d | ok |
| 6 | 2020-05-02 03:17:56.477Z | nashua.dmevals.local | windows.sysmon | destination.port | 8443 | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBnaX5as | q-5b4b175941 | ok |

### F28 · benign / medium · T1552.002 · Registry credential-key access not observed; only OS/winlogon housekeeping writes

Evidence status: **verified**

No reg.exe/reg query/reg save of SAM, SECURITY or LSA keys was found (C159 zero hits; C147 zero hits for reg save/ntdsutil/vssadmin). The 17 registry value-set events matching credential keywords are all routine: svchost.exe writing IdentityCRL ProviderPasswordLength/CharacterGroups policy values on nashua and scranton, winlogon.exe writing PUUActive/DP and PasswordExpiryNotification values for the pbeesly profile, and lsass.exe writing its own Lsa\LsaPid/LsaCfgFlagsDefault/ProductType values during a reboot at 03:19:09Z. No attacker process touched credential-bearing registry keys.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:09.834Z | scranton.dmevals.local | windows.sysmon | registry.path | HKLM\System\CurrentControlSet\Control\Lsa\LsaPid | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBnaXZbu | q-96f7eac6f7 | ok |
| 2 | 2020-05-02 03:05:28.255Z | nashua.dmevals.local | windows.sysmon | registry.path | HKU\.DEFAULT\Software\Microsoft\IdentityCRL\ProviderPasswordLength | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoKOGL_ | q-96f7eac6f7 | ok |
| 3 | 2020-05-02 03:21:20.841Z | scranton.dmevals.local | windows.sysmon | registry.path | HKU\S-1-5-21-1830255721-3727074217-2423397540-1107\Software\Microsoft\Windows\Winlogon\PasswordExpiryNotification\NotShownTime | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBi85CSh | q-96f7eac6f7 | ok |

### F29 · benign / medium · T1552.003 · No shell-history or PSReadLine harvesting observed

Evidence status: **verified**

Checks C163/C164/C165/C166 for ConsoleHost_history, PSReadLine and history.txt returned zero hits, and a broader ES\|QL sweep of Sysmon process creations for 'history' returned no matching command lines. The only PowerShell script blocks referencing credentials are the attacker's own Get-PrivateKeys/Invoke-Exfil functions, not reads of shell history files.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:06:14.652Z | newyork.dmevals.local | windows.sysmon | process.command_line | C:\windows\System32\dsregcmd.exe $(Arg0) $(Arg1) $(Arg2) | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoGKqgM | q-e604dea39d | ok |

### F30 · benign / medium · T1552.006 · SYSVOL/GPP file creation is normal Group Policy client refresh, not cpassword harvesting

Evidence status: **verified**

C171-C174 (Groups.xml, cpassword, gpprefdecrypt, SYSVOL in command lines) had zero hits. The 22 Sysmon file-create events under C:\Windows\System32\GroupPolicy\DataStore\0\sysvol\dmevals.local\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9} (gpt.ini, Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf) were all written by svchost.exe on scranton (03:01:43Z, 03:19:18Z) and nashua (03:10:40Z) — the standard Group Policy client caching its local DataStore, with no Groups.xml and no attacker process involved.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:01:43.091Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Windows\System32\GroupPolicy\DataStore\0\sysvol\dmevals.local\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.in… | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoTWpZy | q-f69a49b7ee | ok |
| 2 | 2020-05-02 03:10:40.324Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\svchost.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBn56HkU | q-f69a49b7ee | ok |

### F32 · benign / medium · T1555.003 · No browser credential-store access observed

Evidence status: **verified**

No evidence of browser credential theft. The only file-creation event matching browser store names in the whole window is a single svchost.exe write to C:\Windows\ServiceProfiles\LocalService\AppData\Local\Packages\warp_jit_db4a1097-...\AC\INetCookies on scranton at 03:21:05Z, which is a normal Windows service-profile cookie container, not a user browser profile. No process accessed chrome.exe/firefox.exe/msedge.exe memory, no 4663 object access on 'Login Data'/'logins.json'/'key4.db'/'Web Data', and no command line or script block referenced those files. The attacker's PowerShell collection script on scranton did enumerate files matching *pass*, *login*, *vpn* etc. for archiving, but that is file collection, not extraction of browser password stores.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:21:05.681Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Windows\ServiceProfiles\LocalService\AppData\Local\Packages\warp_jit_db4a1097-b484-4973-bbf2-a04208ecd4d4\AC\INetCookies | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBi-6ySm | q-a581369e20 | ok |
| 2 | 2020-05-02 03:21:05.681Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\System32\svchost.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBi-6ySm | q-a581369e20 | ok |

### F33 · benign / medium · T1555.004 · No Windows Credential Manager / vault access; LSASS access on nashua is PowerShell remoting

Evidence status: **verified**

No cmdkey, vaultcmd, credman or Credential Manager API usage was found in process creation, 4688, script blocks or registry events (checks C186/C188/C189 zero hits). The 0x1F3FFF lsass handle on nashua.dmevals.local at 03:09:29Z came from wsmprovhost.exe (PID 7720) with a CallTrace through System.ni.dll and Microsoft.PowerShell.Commands.Management.ni.dll — i.e. a PowerShell remoting session, not a credential dump; nashua also shows PSEXESVC.exe spawning C:\Windows\Temp\python.exe repeatedly (03:11–03:15) and Rar.exe archiving to working.zip, which is lateral movement/collection rather than Credential Manager theft. The scranton PowerShell→lsass full-access handle is reported under T1555. The only 'Credential' string in windows.other is a benign Credential Guard configuration message (event 14) on scranton.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBn663fz | q-e2eb56940b | ok |
| 2 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBn663fz | q-e2eb56940b | ok |
| 3 | 2020-05-02 03:11:40.213Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoz4j7h | q-3690c8852e | ok |
| 4 | 2020-05-02 03:19:09.000Z | scranton.dmevals.local | windows.other | message | Credential Guard configuration: 0x0, 0 | .ds-logs-windows.other-default-2026.10.22-000001 / AaFiKJc9VXKkeBwdMB1A | q-3892907d24 | ok |

### F34 · benign / high · T1555.005 · No password-manager store access observed

Evidence status: **verified**

All password-manager checks returned zero hits: no process creation, file creation (.kdbx/1password/keepass), process-memory access to KeePass/1Password/Bitwarden, 4688 command lines, script blocks or windows.other messages referencing password managers. The only password-like artefacts are the attacker's own hardcoded credentials in scripts (e.g. 'MyCozyPassw0rd!' in Invoke-Exfil and 'saribas' used as the .pfx export password), which are attacker tooling, not theft from a password manager.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByPYrDh | q-b512256bd5 | ok |

### F36 · benign / medium · T1556.001 · No domain-controller authentication tampering; lsass handle access is from PowerShell hosts, not DC auth patching

Evidence status: **verified**

Handle access to lsass.exe (326 events) is dominated by svchost.exe with GrantedAccess 0x1000 (286) plus AntimalwareConfig.exe and WindowsAzureTelemetryService.exe with 0x1400 — normal security-product/telemetry query access. The non-standard full-access opens (PowerShell.exe 0x1FFFFF/0x1F3FFF, wsmprovhost.exe 0x1F3FFF) are credential-theft style reads, not modification of DC authentication. Logon process names for 4624/4648 are standard (Kerberos 217, Advapi 76, User32 2, NtLmSsp 1); the single 4648 with a machine-account target is SCRANTON$ logging on to scranton$ from taskhostw.exe, a routine scheduled-task style self-logon. No cryptdll/ntds DLL loads into unexpected processes and no lsass/cryptdll messages in windows.other.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoMQUXF | q-d702859970 | ok |
| 2 | 2020-05-02 03:19:35.000Z | scranton.dmevals.local | windows.security | win.TargetServerName | scranton$ | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBuWmJMP | q-2717e5b199 | ok |

### F37 · benign / high · T1556.002 · No password-filter DLL registration or load into lsass

Evidence status: **verified**

The only file matching the password/filter pattern was C:\Program Files\SysinternalsSuite\passwordsDB, created by C:\Program Files\SysinternalsSuite\accesschk.exe on scranton at 03:04:35 — an admin tool output file, not a DLL. The remaining matches are Cortana filtertrie cache files under pbeesly's profile. No registry writes to Notification Packages/PasswordFilter/Lsa, no 4657 on those keys, no PowerShell referencing them, and the only lsass image load was lsass.exe itself.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:35.069Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Program Files\SysinternalsSuite\passwordsDB | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoNRGHl | q-93dd8be46e | ok |
| 2 | 2020-05-02 03:19:09.803Z | scranton.dmevals.local | windows.sysmon | win.ImageLoaded | C:\Windows\System32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBnZW8l5 | q-856240609f | ok |

### F38 · benign / high · T1556.005 · No reversible-encryption account control changes

Evidence status: **verified**

No 4739 events exist in windows.security, no process command lines reference Reversible/Set-ADAccountControl/Set-ADUser, and no windows.other messages mention reversible encryption. The single PowerShell 4104 hit for the reversible-encryption keywords was a false positive: a SYSTEM script block on newyork.dmevals.local containing generic TimeSpan validation code, not an AD account-control change.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:01:30.000Z | newyork.dmevals.local | windows.powershell | user.name | SYSTEM | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByUbwtm | q-8ee255138e | ok |

### F39 · benign / high · T1556.006 · No MFA/authentication-policy modification

Evidence status: **verified**

No 4739 events, no 5136 directory-service changes, and the only 4662 objects were SecretObject reads of Policy\Secrets\$MACHINE.ACC by LOCAL SERVICE (normal LSA secret access) plus one NEWYORK$ read. The two processes matching ADUser/AuthenticationPolicy command lines were the Azure JsonADDomainExtension.exe domain-join extension and cmd.exe. Newly installed services (7045) were Java(TM) Virtual Machine Support Service (javamtsup.exe) on scranton and repeated PSEXESVC installs on nashua by pbeesly — lateral-movement tooling, not an authentication bypass component.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:02:59.000Z | nashua.dmevals.local | windows.security | win.ObjectName | Policy\Secrets\$MACHINE.ACC | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBy1BJnq | q-4f7712ec3f | ok |
| 2 | 2020-05-02 03:11:39.000Z | nashua.dmevals.local | windows.other | process.executable | %SystemRoot%\PSEXESVC.exe | .ds-logs-windows.other-default-2026.10.22-000001 / AaFiKJc9VXKkeBwdMB0i | q-1d77c8876d | ok |

### F40 · benign / medium · T1556.007 · No hybrid-identity / federation or sync-service backdooring

Evidence status: **verified**

No 5136 directory modifications were recorded, and the 7045 service installations in the window are javamtsup.exe and PSEXESVC — no AAD Connect, federation or identity-sync service was installed or modified. The 20,259 image-load events are overwhelmingly standard System32 DLLs (ntdll, KernelBase, kernel32, rpcrt4, sechost); no anomalous DLL was loaded into an identity process.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:15.000Z | scranton.dmevals.local | windows.other | process.executable | C:\Windows\System32\javamtsup.exe | .ds-logs-windows.other-default-2026.10.22-000001 / AaFiKJc9VXKkeBwdLx2Z | q-e5c6923e0d | ok |

### F42 · benign / medium · T1557 · No adversary-in-the-middle activity observed; credential theft on hosts was done with PsExec + python.exe, not interception

Evidence status: **verified**

Across windows.sysmon/security/other/powershell (2020-05-02 02:55-03:28Z) and zeek (2020-04-30 00:06-00:45Z) no AiTM tooling, rogue relay endpoint or interception infrastructure was found. Outbound connections (1229 event.code 3) are dominated by internal hosts 192.168.0.4, 10.0.0.4, 10.0.1.4/5/6 and Microsoft/Office telemetry addresses; DNS queries (81 event.code 22) are ordinary AD/DC SRV lookups and Microsoft domains. The only new services are javamtsup (scranton) and PSEXESVC (nashua), i.e. lateral-movement tooling rather than interception. Zeek TLS SNI is uniformly 192.168.0.4 and Kerberos peers are all 10.0.0.4 (the DC), with no rogue KDC/relay peer.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:14.118Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\Windows\System32\javamtsup.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBnlkXpm | q-7feda4e3d2 | ok |
| 2 | 2020-05-02 03:11:39.934Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\Windows\PSEXESVC.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBn55Xmr | q-c2ca5fa14d | ok |

### F43 · benign / medium · T1557.001 · SMB traffic is normal DC/file-server access; no LLMNR/NBT-NS poisoning or SMB relay tooling

Evidence status: **verified**

All 66 SMB (445/139) connections in windows.sysmon come from process 'System' on newyork/scranton/nashua/utica toward 10.0.0.4 (DC), 10.0.1.6 and the link-local fe80::e40c:95b6:b0a7:6429 - consistent with normal domain authentication/file access, not a relay target. No 4657 change to EnableMulticast and no PowerShell script block referencing Responder/EnableMulticast (checks C243/C244 zero hits). The 4697 service installs are javamtsup (scranton, pbeesly) and PSEXESVC (nashua, pbeesly) plus a burst of per-user svchost services on scranton at 03:20:48 - lateral movement, not name-resolution poisoning. The single NTLM network logon (4624 type 3, NtLmSsp, pbeesly, source 172.18.39.2, workstation 10.0.1.4) on scranton at 03:20:41 is a direct NTLM authentication, not a relayed one.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:10:23.315Z | scranton.dmevals.local | windows.sysmon | destination.ip | 10.0.1.6 | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBn66XZS | q-d2b2ec6bb5 | ok |
| 2 | 2020-05-02 03:20:41.000Z | scranton.dmevals.local | windows.security | win.LogonProcessName | NtLmSsp  | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBufr2mI | q-a8d1d4011a | ok |
| 3 | 2020-05-02 03:11:39.000Z | nashua.dmevals.local | windows.security | win.ServiceName | PSEXESVC | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBuq1HQ4 | q-a762472d81 | ok |

### F44 · benign / medium · T1557.002 · No ARP cache poisoning indicators; traffic paths and DNS answers are consistent

Evidence status: **verified**

Outbound connection stacking shows no unexpected gateway or duplicate-IP pattern that would suggest ARP poisoning: destinations are the internal DC/file servers (10.0.0.4, 10.0.1.4/5/6, 192.168.0.4) plus Microsoft cloud ranges. DNS queries are normal AD SRV/DC discovery and Microsoft telemetry; zeek DNS responses are 25 NOERROR / 12 NXDOMAIN with no anomalous answers. Object-access stacking (10834 events) shows only routine registry/LSA/Winlogon reads and Defender definition files - no network-configuration tampering. No ARP-poisoning tooling was installed (only javamtsup and PSEXESVC services).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:01:43.033Z | scranton.dmevals.local | windows.sysmon | destination.ip | 10.0.0.4 | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoSWKN8 | q-d2b2ec6bb5 | ok |
| 2 | 2020-05-02 03:01:00.762Z | newyork.dmevals.local | windows.sysmon | destination.ip | fe80:0:0:0:e40c:95b6:b0a7:6429 | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoXbqXA | q-d2b2ec6bb5 | ok |

### F45 · benign / medium · T1557.003 · No DHCP spoofing: only local ipconfig queries, no rogue DHCP server or DHCP config changes

Evidence status: **verified**

The only DHCP-related process activity is 3 executions of C:\Windows\System32\ipconfig.exe (local interface inspection), with no DHCP server/service installation, no DHCP configuration events (1341/1342/1020/1063 zero hits), no PowerShell DHCP/rogue-server script blocks and no Zeek conn traffic to UDP 67/68. Logon process stacking for 4624 is Kerberos (217), Advapi (76), User32 (2) and one NtLmSsp - no evidence of credentials captured via a spoofed DHCP/rogue gateway.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:12:25.384Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\Program Files\SysinternalsSuite\PsExec64.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBn4413G | q-c2ca5fa14d | ok |

### F47 · benign / medium · T1558.001 · No golden-ticket indicators: krbtgt service tickets are ordinary AES256 TGT renewals for pbeesly/SCRANTON$

Evidence status: **verified**

The 4769 events on newyork.dmevals.local include 3 krbtgt service-ticket requests (1 for pbeesly@DMEVALS.LOCAL, 2 for SCRANTON$@DMEVALS.LOCAL), all with Ticket Encryption Type 0x12 (AES256-CTS-HMAC-SHA1-96), Ticket Options 0x60810010 and Failure Code 0x0 — normal TGT renewal/forwardable-ticket behaviour, not RC4 (0x17) or forged-ticket patterns. No 4768/4771/4770 anomalies, no krbtgt/golden/mimikatz/kirbi strings in PowerShell 4104 script blocks, and no mimikatz/Rubeus command lines in Sysmon. The high-privilege LSASS access on SCRANTON is reported under T1558 as suspicious, but nothing in the retrieved data shows a forged TGT being used.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:04.000Z | newyork.dmevals.local | windows.security | win.ServiceName | krbtgt | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBy4FbJD | q-6ad41a2e97 | ok |
| 2 | 2020-05-02 03:04:04.000Z | newyork.dmevals.local | windows.security | win.TicketEncryptionType | 0x12 | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBy4FbJD | q-6ad41a2e97 | ok |
| 3 | 2020-05-02 03:04:04.000Z | newyork.dmevals.local | windows.security | win.TicketOptions | 0x60810010 | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBy4FbJD | q-6ad41a2e97 | ok |

### F48 · benign / medium · T1558.002 · No silver-ticket indicators: all 4769 service tickets are AES256 for machine accounts, no forged service-ticket use

Evidence status: **verified**

All 28 4769 events in windows.security are AES256 (0x12) service-ticket requests for machine accounts (NEWYORK$ 11, NASHUA$ 10, SCRANTON$ 3, krbtgt 3, WEC$ 1) with Failure Code 0x0; none target a user account SPN and none show RC4 or anomalous encryption. 4672 special-privilege logons are dominated by machine accounts (NEWYORK$ 123, SYSTEM 54, pbeesly 17) with no unusual account receiving sensitive privileges. No silver/ticket/mimikatz/kirbi strings in PowerShell script blocks. The suspicious LSASS access on SCRANTON is captured under T1558; no evidence of forged service tickets was retrieved.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:04.000Z | newyork.dmevals.local | windows.security | win.ServiceName | NEWYORK$ | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBy8J3fS | q-9591b2ae25 | ok |
| 2 | 2020-05-02 03:09:23.000Z | newyork.dmevals.local | windows.security | win.ServiceName | NASHUA$ | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBuv5SEr | q-9591b2ae25 | ok |

### F49 · benign / medium · T1558.003 · No Kerberoasting: no RC4 TGS requests for user SPNs, no roasting tooling; 4648 events are PsExec-driven lateral movement by pbeesly

Evidence status: **verified**

Kerberoasting requires TGS requests for user-account SPNs, typically RC4 (0x17). All 28 4769 events are AES256 (0x12) and target only machine accounts (NEWYORK$, NASHUA$, SCRANTON$, WEC$, krbtgt) — no user SPN was requested. No kerberoast/SPN/Invoke-Kerberoast/GetUserSPNs strings in PowerShell 4104 blocks and no roasting tool command lines in Sysmon. The 15 4648 explicit-credential logons are pbeesly authenticating via C:\Windows\PSEXESVC.exe on nashua.dmevals.local (Target Server Name 'localhost') and from scranton.dmevals.local, plus routine DWM-1/UMFD-0/UMFD-1/UMFD-2/SCRANTON$ winlogon/wininit/taskhostw events — consistent with PsExec lateral movement, not credential roasting. Zeek kerberos records (separate 2020-04-30 window) show only pbeesly AS/TGS for krbtgt and cifs/host/ldap/HTTP services in AES256, with KDC_ERR_PREAUTH_REQUIRED on the initial AS-REQ (normal pre-auth).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:40.000Z | nashua.dmevals.local | windows.security | process.executable | C:\Windows\PSEXESVC.exe | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBuu5GRH | q-af5a860328 | ok |
| 2 | 2020-05-02 03:11:40.000Z | nashua.dmevals.local | windows.security | win.TargetServerName | localhost | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBuu5GRH | q-af5a860328 | ok |
| 3 | 2020-04-30 00:40:22.447Z | simplerockbuild.simplerock.lan | zeek | zeek.service | cifs/NASHUA | .ds-logs-zeek-default-2026.10.22-000001 / AaFiKZc9VXKkeBwkgR8n | q-4e00417a0b | ok |
| 4 | 2020-04-30 00:40:22.447Z | simplerockbuild.simplerock.lan | zeek | zeek.cipher | aes256-cts-hmac-sha1-96 | .ds-logs-zeek-default-2026.10.22-000001 / AaFiKZc9VXKkeBwkgR8n | q-4e00417a0b | ok |

### F50 · benign / medium · T1558.004 · No AS-REP roasting: no 4768 events, no GetNPUsers/Rubeus/asrep activity

Evidence status: **verified**

AS-REP roasting requires AS-REQ (4768) for accounts without pre-authentication. No 4768 events exist in windows.other or windows.security, no asrep/GetNPUsers/rubeus/preauth strings appear in PowerShell 4104 script blocks, and no matching command lines appear in Sysmon process creation (0 hits). The only AS-REQ activity is in the non-overlapping zeek window (2020-04-30) for pbeesly, where the initial AS-REQ returns KDC_ERR_PREAUTH_REQUIRED — i.e. pre-authentication is enforced, the opposite of a roastable account.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-04-30 00:40:22.445Z | simplerockbuild.simplerock.lan | zeek | zeek.request_type | AS | .ds-logs-zeek-default-2026.10.22-000001 / AaFiKZc9VXKkeBwkgR8m | q-4e00417a0b | ok |
| 2 | 2020-04-30 00:40:22.436Z | simplerockbuild.simplerock.lan | zeek | zeek.error_msg | KDC_ERR_PREAUTH_REQUIRED | .ds-logs-zeek-default-2026.10.22-000001 / AaFiKZc9VXKkeBwkgh9H | q-4e00417a0b | ok |

### F52 · benign / medium · T1606.001 · No browser cookie theft or forged-cookie replay observed

Evidence status: **verified**

The only cookie-related file event in the window is a single Sysmon file-create of C:\Windows\ServiceProfiles\LocalService\AppData\Local\Packages\warp_jit_db4a1097-b484-4973-bbf2-a04208ecd4d4\AC\INetCookies by svchost.exe on scranton.dmevals.local at 2020-05-02T03:21:05Z, which is normal LocalService package/AppContainer cookie-store activity, not access to a user browser cookie database. No PowerShell script block referencing cookies was found (zero hits), and the Zeek HTTP/TLS data (2020-04-30, non-overlapping window) shows only a single internal destination 192.168.0.4 with no external web identity service. Nothing indicates cookie theft or forged web cookies.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:21:05.681Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Windows\ServiceProfiles\LocalService\AppData\Local\Packages\warp_jit_db4a1097-b484-4973-bbf2-a04208ecd4d4\AC\INetCookies | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBi-6ySm | q-4777ce2b70 | ok |
| 2 | 2020-05-02 03:21:05.681Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\System32\svchost.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBi-6ySm | q-4777ce2b70 | ok |

### F55 · benign / low · T1649 · ROOT certificate store blob modified on NASHUA by Sysmon.exe (likely benign tooling artifact)

Evidence status: **verified**

On nashua.dmevals.local at 2020-05-02 03:16:19 UTC, security event 4657 shows the 'Blob' value of \REGISTRY\MACHINE\SOFTWARE\Microsoft\SystemCertificates\ROOT\Certificates\BE36A4562FB2EE05DBB3D32323ADF445084ED656 being modified by process C:\Windows\Sysmon.exe under NASHUA$ (SYSTEM, logon 0x3e7). This is the only certificate-store registry write in the dataset and it is a single event, not a pattern of rogue root CA installation; the writing image is the Sysmon binary path rather than a certificate utility, and the old/new values are not auditable for REG_BINARY. It does not show an attacker adding a forged trust anchor, so I treat it as a benign/ambiguous artifact rather than evidence of certificate forgery. The genuine T1649 activity in this window is the private-key export on SCRANTON.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:16:19.000Z | nashua.dmevals.local | windows.security | win.ObjectName | \REGISTRY\MACHINE\SOFTWARE\Microsoft\SystemCertificates\ROOT\Certificates\BE36A4562FB2EE05DBB3D32323ADF445084ED656 | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBuu4mRU | q-7d1d4a2c74 | ok |
| 2 | 2020-05-02 03:16:19.000Z | nashua.dmevals.local | windows.security | win.ProcessName | C:\Windows\Sysmon.exe | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBuu4mRU | q-7d1d4a2c74 | ok |
| 3 | 2020-05-02 03:16:19.000Z | nashua.dmevals.local | windows.security | win.SubjectUserName | NASHUA$ | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBuu4mRU | q-7d1d4a2c74 | ok |

## Pivot candidates

Processes the pivot reviewer had to assess (started by a script host or from outside the Windows directory, rare in the 15-minute windows around verified activity).

| Host | Executable | Starts | Parents | Assessment | Reason |
|---|---|---|---|---|---|
| nashua.dmevals.local | C:\Program Files\WindowsApps\Microsoft.SkypeApp_14.35.152.0_x64__kzf8qxf38zg5c\S… | 1 | C:\Program Files\WindowsApps\Microsoft.SkypeApp_14.35.152.0_x64__kzf8qxf38zg5c\S… | benign | Signed Store app self-restarting; only produced a WerFault crash report, no credential access. |
| nashua.dmevals.local | C:\Windows\Temp\python.exe | 5 | C:\Windows\PSEXESVC.exe, C:\Windows\Temp\python.exe | malicious | Delivered by PsExec64 from scranton with cleartext pbeesly password; PyInstaller payload unpacked to _MEI29522, made 348 connections to 192.168.0.4:8443 and spa… |
| nashua.dmevals.local | C:\Windows\Temp\Rar.exe | 1 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | malicious | Dropped into Temp by the python payload and run by PowerShell with hardcoded password -hpfGzq5yKw to build working.zip, then wiped with sdelete64. |
| nashua.dmevals.local | C:\Windows\Temp\sdelete64.exe | 3 | C:\Windows\System32\cmd.exe | malicious | Dropped by the python payload and used to securely delete Rar.exe and both working.zip archives (anti-forensics). |
| nashua.dmevals.local | C:\WindowsAzure\Packages\CollectGuestLogs.exe | 1 | C:\WindowsAzure\Packages\WaAppAgent.exe | benign | Azure guest agent log collection; its lsass handle 0x1410 is read-only and expected. |
| scranton.dmevals.local | C:\Packages\Plugins\Microsoft.Azure.NetworkWatcher.NetworkWatcherAgentWindows\1.… | 4 | C:\Windows\System32\cmd.exe, C:\Windows\System32\services.exe | benign | Azure Network Watcher plugin started by services.exe/cmd.exe, standard cloud agent. |
| scranton.dmevals.local | C:\Packages\Plugins\Microsoft.Azure.Security.IaaSAntimalware\1.5.5.9\Antimalware… | 1 | C:\WindowsAzure\Packages\GuestAgent\WindowsAzureGuestAgent.exe | benign | Azure antimalware configuration plugin launched by WindowsAzureGuestAgent. |
| scranton.dmevals.local | C:\Packages\Plugins\Microsoft.Compute.CustomScriptExtension\1.10.5\bin\CustomScr… | 1 | C:\Windows\System32\cmd.exe | benign | Azure VM custom script extension handler, standard provisioning component. |
| scranton.dmevals.local | C:\Packages\Plugins\Microsoft.Compute.JsonADDomainExtension\1.3.2\bin\JsonADDoma… | 1 | C:\Windows\System32\cmd.exe | benign | Azure AD domain-join extension, standard provisioning component. |
| scranton.dmevals.local | C:\Program Files (x86)\Google\Update\1.3.35.452\GoogleCrashHandler.exe | 2 | C:\Program Files (x86)\Google\Update\GoogleUpdate.exe | benign | Google Update crash handler child of GoogleUpdate.exe. |
| scranton.dmevals.local | C:\Program Files (x86)\Google\Update\1.3.35.452\GoogleCrashHandler64.exe | 2 | C:\Program Files (x86)\Google\Update\GoogleUpdate.exe | benign | Google Update crash handler child of GoogleUpdate.exe. |
| scranton.dmevals.local | C:\Program Files (x86)\Google\Update\GoogleUpdate.exe | 3 | C:\Program Files (x86)\Google\Update\GoogleUpdate.exe, C:\Windows\System32\servi… | benign | Standard Google updater started by services.exe/svchost. |
| scranton.dmevals.local | C:\Program Files\SysinternalsSuite\accessChk.exe | 1 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | suspicious | Run by PowerShell from the attacker-staged SysinternalsSuite and created a file named passwordsDB in that folder. |
| scranton.dmevals.local | C:\Program Files\SysinternalsSuite\PsExec64.exe | 4 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | malicious | Run four times by PowerShell with cleartext dmevals\pbeesly password to launch C:\Windows\Temp\python.exe on \\NASHUA. |
| scranton.dmevals.local | C:\Program Files\SysinternalsSuite\sdelete64.exe | 3 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | malicious | Used by PowerShell to wipe the dropped .scr, Draft.Zip and SysinternalsSuite.zip on scranton (anti-forensics). |
| scranton.dmevals.local | C:\Program Files\Windows Defender\MsMpEng.exe | 1 | C:\Windows\System32\services.exe | benign | Defender service; its 0x1fffff lsass handle is normal AV scanning behaviour. |
| scranton.dmevals.local | C:\Program Files\Windows Defender\NisSrv.exe | 2 | C:\Windows\System32\services.exe | benign | Defender network inspection service started by services.exe. |
| scranton.dmevals.local | C:\ProgramData\victim\â€®cod.3aka3.scr | 1 | C:\Windows\explorer.exe | malicious | Screensaver-named binary in ProgramData\victim launched from explorer with /S; opened HKLM\SYSTEM\ControlSet001\Control\Lsa, spawned cmd.exe and wrote monkey.pn… |
| scranton.dmevals.local | C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe | 2 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | malicious | Invoked by hidden PowerShell with @response files in Temp (qkbkqqbs, 0piklvia) to compile 0piklvia.dll/qkbkqqbs.dll — in-memory .NET payload compilation. |
| scranton.dmevals.local | C:\Windows\System32\hostui.exe | 1 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | suspicious | Started by PowerShell with -verb runas (UAC elevation) and a hostui.lnk was placed in the StartUp folder for persistence. |
| scranton.dmevals.local | C:\Windows\System32\sdclt.exe | 3 | C:\Windows\System32\cmd.exe | suspicious | Three sdclt.exe launches from cmd.exe followed by control.exe — sdclt is a known UAC-bypass binary; no credential access itself. |
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
| T1003 OS Credential Dumping | malicious | PowerShell on scranton opened lsass with 0x1F3FFF/0x1FFFFF from an unknown call-trace module during a hands-on-keyboard intrusion by pbeesly. |
| T1003.001 LSASS Memory | malicious | New instance beyond the anchors: wsmprovhost.exe (pbeesly) opened lsass.exe with 0x1f3fff on nashua at 03:09:29, immediately before the PsExec/python delivery. |
| T1003.002 Security Account Manager | suspicious | SAM opened with 0xf003f by lsass.exe on scranton at 03:19:21-03:20:46; requester is lsass under the machine account, so attribution to the attacker is uncertain. |
| T1003.003 NTDS | not_observed | No ntdsutil/vssadmin/diskshadow usage, no ntds.dit writes, no shadow-copy service installs. |
| T1003.004 LSA Secrets | benign | Only LOCAL SERVICE querying Policy\Secrets\$MACHINE.ACC (routine machine-account secret read); no lsadump/secretsdump tooling. |
| T1003.005 Cached Domain Credentials | not_observed | No cachedump/dcc2/mscache tooling or SECURITY\Cache object access; NL$1 writes are normal OS cache maintenance. |
| T1003.006 DCSync | benign | Single 4662 by NEWYORK$ machine account with DS-Replication-Get-Changes only (no Get-Changes-All), no drsuapi/dcsync tooling. |
| T1040 Network Sniffing | benign | The only packet-capture activity is netsh.exe 'trace start capture=yes' / 'trace stop' on scranton.dmevals.local, spawned exclusively by the signed Microsoft Azure Network Watcher agent (NetworkWatcherAgent.exe, Company … |
| T1056 Input Capture | malicious | lsass handle traffic is mostly benign baseline (svchost 0x1000, Defender, Azure agents), but the same window contains PowerShell/wsmprovhost full-access lsass access and a remote thread into lsass — input/credential capt… |
| T1056.001 Keylogging | not_observed | No keylogger artifacts: keyboard registry writes are OS keyboard-layout/device keys; no SetWindowsHookEx/GetAsyncKeyState scripts, keylog services, or keyboard object handles. |
| T1056.002 GUI Input Capture | malicious | Invoke-ScreenCapture script on scranton (pbeesly) loops CopyFromScreen every 300s saving desktop bitmaps to Downloads — GUI input capture. |
| T1056.003 Web Portal Capture | not_observed | No web content written to wwwroot/inetpub, no IIS/W3SVC service installs, no HTTP POSTs; the *login* PowerShell hit is file-collection/Compress-Archive staging. |
| T1056.004 Credential API Hooking | malicious | powershell.exe (PID 2976, pbeesly) opened lsass with 0x1f3fff/0x1fffff and created a remote thread in lsass on scranton; wsmprovhost.exe did the same 0x1f3fff access on nashua — credential API hooking/injection. |
| T1110 Brute Force | not_observed | Zero 4625/4771/4740 events in windows.security and windows.other; the only 4776 is a successful validation (Status 0x0) for pbeesly. No repeated authentication attempts anywhere in the window. |
| T1110.001 Password Guessing | not_observed | No failed logons at all; the single runas invocation on scranton is a UAC elevation of hostui.exe, and PowerShell credential usage relies on hardcoded known secrets, not guessing. |
| T1110.002 Password Cracking | suspicious | PowerShell.exe on scranton opened lsass.exe with 0x1f3fff/0x1fffff and unbacked call trace, and LSA/SAM registry keys were accessed by attacker tooling — credential dumping/collection is present, but no offline cracking … |
| T1110.003 Password Spraying | not_observed | No 4625/4771 spray pattern; a single account (pbeesly) with one password was used against NASHUA via PsExec and Invoke-Command. |
| T1110.004 Credential Stuffing | not_observed | No failed logons and no user/password list processing; only a single hardcoded credential pair appears in PsExec command lines. |
| T1111 Multi-Factor Authentication Interception | malicious | On scranton.dmevals.local a hidden, IEX-based PowerShell loader (PID 2976, launched by control.exe, decoding payload from monkey.png) opened lsass.exe with 0x1F3FFF and 0x1FFFFF (PROCESS_ALL_ACCESS) at 03:05:16Z, and on … |
| T1187 Forced Authentication | not_observed | No forced-authentication artifacts: WebDAV HTTP methods are a legitimate Microsoft-WebDAV-MiniRedir/DavClnt upload of /webdav/OfficeSupplies.7z from 10.0.1.4 to internal 192.168.0.4; SMB 445/139 is GPO/sysvol and IPC$ ac… |
| T1212 Exploitation for Credential Access | malicious | PowerShell.exe on scranton.dmevals.local and wsmprovhost.exe on nashua.dmevals.local opened lsass.exe with full-access masks 0x1F3FFF/0x1FFFFF from managed PowerShell call traces, embedded in a hands-on-keyboard intrusio… |
| T1539 Steal Web Session Cookie | not_observed | No access to browser cookie/session stores was found: the only *cookies* file path in Sysmon was a LocalService INetCookies artefact created by svchost.exe; process access to Edge/Chrome images came only from Explorer.EX… |
| T1552 Unsecured Credentials | malicious | Unsecured credentials harvested and staged: Draft.Zip of password/login-named files on scranton, working.zip on nashua, OfficeSupplies.7z exfiltrated to \\192.168.0.4\webdav. |
| T1552.001 Credentials In Files | malicious | Cleartext dmevals\pbeesly password in PsExec64 command line, hardcoded WebDAV credential cozy/MyCozyPassw0rd! in Invoke-Exfil, hardcoded RAR password fGzq5yKw on nashua, and a *pass*/*login*/*vpn* file-harvesting script … |
| T1552.002 Credentials in Registry | benign | No reg save/query of SAM/SECURITY/LSA; the 17 credential-keyword registry writes are svchost/winlogon/lsass housekeeping. |
| T1552.003 Shell History | not_observed | Zero hits for ConsoleHost_history, PSReadLine or history.txt across PowerShell, Sysmon and Security datasets. |
| T1552.004 Private Keys | malicious | Get-PrivateKeys exported LocalMachine certificates via Export-PfxCertificate; Sysmon confirms C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx created by powershell.exe. |
| T1552.006 Group Policy Preferences | benign | No Groups.xml/cpassword activity; SYSVOL DataStore writes are svchost.exe Group Policy client refresh on scranton and nashua. |
| T1555 Credentials from Password Stores | suspicious | Only the accesschk-created 'passwordsDB' artifact on scranton; no credential-store file reads were captured. |
| T1555.003 Credentials from Web Browsers | suspicious | accesschk.exe created C:\Program Files\SysinternalsSuite\passwordsDB on scranton; no browser Login Data/cookie store access was observed in the window. |
| T1555.004 Windows Credential Manager | not_observed | No cmdkey/vault/credman usage in process creation, 4688, script blocks or registry events; the nashua lsass 0x1F3FFF handle is a PowerShell remoting (wsmprovhost) session, and the scranton full-access lsass handle is rep… |
| T1555.005 Password Managers | not_observed | All password-manager checks (process creation, .kdbx/1password/keepass file creation, memory access, 4688, script blocks, windows.other) returned zero hits. |
| T1556 Modify Authentication Process | suspicious | A real intrusion by pbeesly (steganographic PowerShell from monkey.png, hidden/encoded PowerShell, hostui.exe UAC bypass, PSEXESVC+python.exe on nashua) coincides with full-access lsass handles (0x1FFFFF from PowerShell.… |
| T1556.001 Domain Controller Authentication | not_observed | Logon process names are standard, the only machine-account 4648 is a routine taskhostw.exe self-logon, and lsass handle access is dominated by svchost.exe 0x1000 plus AV/telemetry 0x1400; no DC authentication patching. |
| T1556.002 Password Filter DLL | not_observed | No Notification Packages/PasswordFilter registry writes or 4657 events; the only 'password' file was accesschk.exe output passwordsDB, and no password-filter DLL loaded into lsass. |
| T1556.005 Reversible Encryption | not_observed | No 4739 events, no Set-ADAccountControl/Set-ADUser or reversible-encryption command lines; the single 4104 keyword hit was generic TimeSpan validation code. |
| T1556.006 Multi-Factor Authentication | not_observed | No 4739 or 5136 events; 4662 activity is LOCAL SERVICE reading $MACHINE.ACC, and the only AD-related processes were the Azure domain-join extension and cmd.exe. |
| T1556.007 Hybrid Identity | not_observed | No 5136 directory changes and no identity-sync/federation service installed; 7045 services were javamtsup.exe and PSEXESVC only. |
| T1556.008 Network Provider DLL | not_observed | No NetworkProvider/Winlogon registry changes and only legitimate System32 network DLLs loaded; the lsass memory-write accesses are attributable to the credential-theft activity, not a network provider backdoor. |
| T1557 Adversary-in-the-Middle | not_observed | No AiTM/relay infrastructure, rogue TLS SNI or unusual Kerberos peer in windows.* or zeek; only PsExec/javamtsup lateral-movement tooling was found. |
| T1557.001 Name Resolution Poisoning and SMB Relay | not_observed | SMB 445/139 connections are System->DC/file servers (10.0.0.4, 10.0.1.6, link-local); no EnableMulticast change, no Responder/poisoning script blocks, no relayed NTLM logon. |
| T1557.002 ARP Cache Poisoning | not_observed | No unexpected gateway/duplicate-IP traffic pattern, no network-config tampering in object-access events, no ARP-poisoning tooling installed. |
| T1557.003 DHCP Spoofing | not_observed | Only local ipconfig.exe runs; no DHCP server/config events, no DHCP PowerShell, no UDP 67/68 traffic in zeek. |
| T1558 Steal or Forge Kerberos Tickets | suspicious | PowerShell.exe (PID 2976) on scranton.dmevals.local opened lsass.exe with 0x1F3FFF and 0x1FFFFF at 2020-05-02T03:05:16 during a hands-on-keyboard session running Get-PrivateKeys, Invoke-Persistence, Invoke-ScreenCapture … |
| T1558.001 Golden Ticket | not_observed | Only 3 krbtgt 4769 requests, all AES256 (0x12) with Failure Code 0x0 for pbeesly and SCRANTON$; no 4768/4771 anomalies, no golden-ticket tooling or script content. |
| T1558.002 Silver Ticket | not_observed | All 28 4769 service tickets are AES256 for machine accounts (NEWYORK$, NASHUA$, SCRANTON$, WEC$, krbtgt); no forged service-ticket use or silver-ticket tooling observed. |
| T1558.003 Kerberoasting | not_observed | No TGS requests for user-account SPNs and no RC4 tickets; 4648 events are pbeesly via PSEXESVC.exe (PsExec lateral movement), not roasting. |
| T1558.004 AS-REP Roasting | not_observed | No 4768 events in any Windows dataset and no asrep/GetNPUsers/Rubeus activity; zeek AS-REQs show KDC_ERR_PREAUTH_REQUIRED, i.e. pre-auth enforced. |
| T1606 Forge Web Credentials | suspicious | No forged web credential was directly observed, but the same pbeesly session on scranton.dmevals.local combined high-access lsass handle opens (0x1F3FFF/0x1FFFFF by PowerShell.exe) with explicit-credential logons and PsE… |
| T1606.001 Web Cookies | not_observed | Only a benign LocalService INetCookies file creation by svchost.exe; no cookie-referencing PowerShell script blocks and no external web destinations in Zeek. |
| T1606.002 SAML Tokens | malicious | Certificate private keys exported to a password-protected .pfx on scranton, enabling SAML/token forgery with the stolen key material. |
| T1621 Multi-Factor Authentication Request Generatio… | not_observed | 6 planned checks, all with zero hits |
| T1649 Steal or Forge Authentication Certificates | malicious | Get-PrivateKeys exported LocalMachine certificates to C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx with password 'saribas' on scranton at 03:04:57. |

## Coverage

Cells: number of hits of the planned checks, `n/a` (reason in report.json), or GAP.

| Technique | windows.other | windows.powershell | windows.security | windows.sysmon | zeek |
|---|---|---|---|---|---|
| T1003 OS Credential Dumping | 0 hits | 0 hits | 6 hits | 327 hits | n/a |
| T1003.001 LSASS Memory | n/a | 0 hits | 0 hits | 666 hits | n/a |
| T1003.002 Security Account Manager | n/a | 0 hits | 0 hits | 10 hits | n/a |
| T1003.003 NTDS | 0 hits | 0 hits | 0 hits | 0 hits | n/a |
| T1003.004 LSA Secrets | n/a | 0 hits | 0 hits | 529 hits | n/a |
| T1003.005 Cached Domain Credentials | n/a | 0 hits | 0 hits | 330 hits | n/a |
| T1003.006 DCSync | 0 hits | 0 hits | 7 hits | 0 hits | 123 hits |
| T1040 Network Sniffing | 0 hits | 0 hits | 2 hits | 9 hits | 613 hits |
| T1056 Input Capture | 0 hits | 0 hits | 19 hits | 652 hits | 613 hits |
| T1056.001 Keylogging | 0 hits | 0 hits | 0 hits | 352 hits | 613 hits |
| T1056.002 GUI Input Capture | 0 hits | 2 hits | 0 hits | 0 hits | 613 hits |
| T1056.003 Web Portal Capture | 0 hits | 2 hits | 0 hits | 0 hits | 0 hits |
| T1056.004 Credential API Hooking | 0 hits | 0 hits | 6 hits | 60196 hits | n/a |
| T1110 Brute Force | 2 hits | 3 hits | 1 hits | 31 hits | n/a |
| T1110.001 Password Guessing | 0 hits | 4 hits | 0 hits | 1 hits | n/a |
| T1110.002 Password Cracking | 1 hits | 0 hits | 15318 hits | 329 hits | n/a |
| T1110.003 Password Spraying | 0 hits | 0 hits | 15 hits | 30 hits | n/a |
| T1110.004 Credential Stuffing | 0 hits | 0 hits | 0 hits | 0 hits | n/a |
| T1111 Multi-Factor Authentication Interception | 5 hits | 3 hits | 312 hits | 39283 hits | GAP: n/a refused (time window … |
| T1187 Forced Authentication | 4 hits | 0 hits | 14140 hits | 1715 hits | 86 hits |
| T1212 Exploitation for Credential Access | 5 hits | 0 hits | 502 hits | 39609 hits | 2 hits |
| T1539 Steal Web Session Cookie | 4 hits | 13 hits | 460 hits | 39492 hits | 0 hits |
| T1552 Unsecured Credentials | 5 hits | 4 hits | 460 hits | 19190 hits | 12 hits |
| T1552.001 Credentials In Files | 4 hits | 1 hits | 15 hits | 2096 hits | 12 hits |
| T1552.002 Credentials in Registry | 11 hits | 3 hits | 0 hits | 17 hits | n/a |
| T1552.003 Shell History | n/a | 0 hits | 0 hits | 0 hits | n/a |
| T1552.004 Private Keys | n/a | 1 hits | 0 hits | 1 hits | n/a |
| T1552.006 Group Policy Preferences | n/a | 0 hits | 0 hits | 0 hits | n/a |
| T1555 Credentials from Password Stores | 0 hits | 3 hits | 6 hits | 653 hits | n/a |
| T1555.003 Credentials from Web Browsers | n/a | 0 hits | 0 hits | 162 hits | n/a |
| T1555.004 Windows Credential Manager | 2 hits | 3 hits | 0 hits | 326 hits | n/a |
| T1555.005 Password Managers | 0 hits | 0 hits | 0 hits | 0 hits | n/a |
| T1556 Modify Authentication Process | 0 hits | 0 hits | 0 hits | 549 hits | n/a |
| T1556.001 Domain Controller Authentication | 0 hits | 0 hits | 313 hits | 413 hits | n/a |
| T1556.002 Password Filter DLL | 5 hits | 0 hits | 0 hits | 8 hits | n/a |
| T1556.005 Reversible Encryption | 0 hits | 5495 hits | 0 hits | 0 hits | n/a |
| T1556.006 Multi-Factor Authentication | 5 hits | 1 hits | 7 hits | 2 hits | n/a |
| T1556.007 Hybrid Identity | 5 hits | 0 hits | 0 hits | 20259 hits | n/a |
| T1556.008 Network Provider DLL | 5 hits | 0 hits | 0 hits | 30786 hits | n/a |
| T1557 Adversary-in-the-Middle | 5 hits | 0 hits | 10977 hits | 1310 hits | 466 hits |
| T1557.001 Name Resolution Poisoning and SMB Relay | 5 hits | 0 hits | 23 hits | 147 hits | n/a |
| T1557.002 ARP Cache Poisoning | 5 hits | 0 hits | 10834 hits | 1310 hits | n/a |
| T1557.003 DHCP Spoofing | 0 hits | 0 hits | 297 hits | 3 hits | 0 hits |
| T1558 Steal or Forge Kerberos Tickets | 0 hits | 0 hits | 448 hits | 326 hits | 35 hits |
| T1558.001 Golden Ticket | 0 hits | 0 hits | 476 hits | 326 hits | 35 hits |
| T1558.002 Silver Ticket | 0 hits | 0 hits | 448 hits | 326 hits | 35 hits |
| T1558.003 Kerberoasting | 0 hits | 0 hits | 552 hits | 326 hits | 35 hits |
| T1558.004 AS-REP Roasting | 0 hits | 0 hits | 14 hits | 0 hits | 35 hits |
| T1606 Forge Web Credentials | 5 hits | 1 hits | 312 hits | 326 hits | 440 hits |
| T1606.001 Web Cookies | 0 hits | 0 hits | 297 hits | 1 hits | 440 hits |
| T1606.002 SAML Tokens | 5 hits | 2 hits | 312 hits | 1 hits | 440 hits |
| T1621 Multi-Factor Authentication Request Generatio… | 0 hits | 0 hits | 0 hits | 0 hits | n/a |
| T1649 Steal or Forge Authentication Certificates | 5 hits | 1 hits | 50 hits | 1 hits | n/a |

Cells: 265, gaps: 1.

## Queries

Every MCP tool call of this run (1203), in order (source: mcp_audit.jsonl written by the MCP server).

| Query | Phase | Tool | Arguments | Hits / rows | Cited by |
|---|---|---|---|---|---|
| q-658ec083cb | scope | list_data_sources | {} | None |  |
| q-a851cc3504 | scope | get_registry | {} | None |  |
| q-5f7ee8a02d | scope | get_fields | {"dataset": "windows.other", "prefix": ""} | None |  |
| q-a46a04cb16 | scope | get_fields | {"dataset": "windows.powershell", "prefix": ""} | None |  |
| q-4effd05d46 | scope | get_fields | {"dataset": "windows.security", "prefix": ""} | None |  |
| q-ad09bb2e7d | scope | get_fields | {"dataset": "windows.sysmon", "prefix": ""} | None |  |
| q-fe22e589ea | scope | get_fields | {"dataset": "zeek", "prefix": ""} | None |  |
| q-e30cc07034 | check C001 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*procdump* OR process.command_line:*comsvcs* OR process.command_line:*MiniDump* OR process.command_line:*mimikatz* OR process.command_line:*sekurlsa* … | 1 |  |
| q-351c912bc1 | check C002 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass.exe", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-915b36353b | check C003 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND (win.ObjectName:*lsass* OR win.ObjectName:*SAM* OR win.ObjectName:*SECURITY* OR win.ObjectName:*NTDS*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 6 |  |
| q-102737a0f0 | check C004 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND (process.command_line:*procdump* OR process.command_line:*comsvcs* OR process.command_line:*MiniDump* OR process.command_line:*mimikatz* OR process.command_line:*lsass… | 0 |  |
| q-ccc0cca6a8 | check C005 | aggregate | {"dataset": "windows.powershell", "field": "host.name", "query": "event.code:4104 AND (win.ScriptBlockText:*MiniDump* OR win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*mimikatz* OR win.ScriptBlockText:*sekurlsa* OR win.ScriptBlockText:*procdump*)", "time_… | 0 |  |
| q-ed5b5f623e | check C006 | aggregate | {"dataset": "windows.other", "field": "win.ServiceName", "query": "event.code:7045 AND (win.ImagePath:*lsass* OR win.ImagePath:*dump* OR win.ImagePath:*mimikatz* OR win.ImagePath:*procdump*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-a90cca1823 | check C007 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND win.TargetImage:*lsass.exe", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 326 |  |
| q-d0370c5e93 | check C008 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass.exe", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-d2ceb4d803 | check C009 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*lsass* OR process.command_line:*MiniDump* OR process.command_line:*comsvcs*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1 |  |
| q-ae754159bf | check C010 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND (win.TargetFilename:*.dmp OR win.TargetFilename:*lsass*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 2 |  |
| q-b46db84a05 | check C011 | aggregate | {"dataset": "windows.sysmon", "field": "registry.path", "query": "event.code:13 AND (registry.path:*lsass* OR registry.path:*WDigest* OR registry.path:*Credential*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 11 |  |
| q-339a3bb8fe | check C012 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4673 AND (win.ObjectName:*lsass* OR win.ObjectName:*LSA*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-462626632b | check C013 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND (process.command_line:*lsass* OR process.command_line:*MiniDump* OR process.command_line:*comsvcs*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null… | 0 |  |
| q-fee62494fd | check C014 | aggregate | {"dataset": "windows.powershell", "field": "host.name", "query": "event.code:4104 AND (win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*MiniDump* OR win.ScriptBlockText:*sekurlsa*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-38ca2b9b59 | check C015 | aggregate | {"dataset": "windows.sysmon", "field": "process.command_line", "query": "event.code:1 AND (process.command_line:*reg* AND (process.command_line:*save* OR process.command_line:*export*) AND (process.command_line:*SAM* OR process.command_line:*SECURITY* OR proce… | 0 |  |
| q-9fc4883b7d | check C016 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND (win.TargetFilename:*SAM* OR win.TargetFilename:*SECURITY* OR win.TargetFilename:*SYSTEM* OR win.TargetFilename:*.hiv)", "time_from": null, "time_to": null, "size": 50, "s… | 3 |  |
| q-127396bc3b | check C017 | aggregate | {"dataset": "windows.sysmon", "field": "registry.path", "query": "event.code:13 AND (registry.path:*SAM* OR registry.path:*SECURITY*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 7 |  |
| q-b3e5ef6564 | check C018 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:2 AND (win.TargetFilename:*SAM* OR win.TargetFilename:*SECURITY*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-65b32250ce | check C019 | aggregate | {"dataset": "windows.security", "field": "process.command_line", "query": "event.code:4688 AND (process.command_line:*reg* AND (process.command_line:*save* OR process.command_line:*export*))", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-cc7e0e2fef | check C020 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND (win.ObjectName:*SAM* OR win.ObjectName:*SECURITY*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-b9e45a3447 | check C021 | aggregate | {"dataset": "windows.powershell", "field": "host.name", "query": "event.code:4104 AND (win.ScriptBlockText:*reg* AND (win.ScriptBlockText:*save* OR win.ScriptBlockText:*export*) AND (win.ScriptBlockText:*SAM* OR win.ScriptBlockText:*SECURITY*))", "time_from": … | 0 |  |
| q-8b894accea | check C022 | aggregate | {"dataset": "windows.sysmon", "field": "process.command_line", "query": "event.code:1 AND (process.command_line:*ntds* OR process.command_line:*vssadmin* OR process.command_line:*ntdsutil* OR process.command_line:*diskshadow*)", "time_from": null, "time_to": n… | 0 |  |
| q-81d019ffef | check C023 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND (win.TargetFilename:*ntds* OR win.TargetFilename:*.dit)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-6e63f25144 | check C024 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:2 AND win.TargetFilename:*ntds*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-beda2b5b23 | check C025 | aggregate | {"dataset": "windows.security", "field": "process.command_line", "query": "event.code:4688 AND (process.command_line:*ntds* OR process.command_line:*vssadmin* OR process.command_line:*ntdsutil* OR process.command_line:*diskshadow*)", "time_from": null, "time_t… | 0 |  |
| q-7c1115c2e9 | check C026 | aggregate | {"dataset": "windows.other", "field": "win.ServiceName", "query": "event.code:7045 AND (win.ImagePath:*vss* OR win.ImagePath:*ntds* OR win.ImagePath:*shadow*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-6e2b8abcb0 | check C027 | aggregate | {"dataset": "windows.powershell", "field": "host.name", "query": "event.code:4104 AND (win.ScriptBlockText:*ntds* OR win.ScriptBlockText:*vssadmin* OR win.ScriptBlockText:*diskshadow*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-0ae83e7955 | check C028 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND (win.TargetImage:*lsass.exe OR win.TargetImage:*services.exe)", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 506 |  |
| q-061e44a816 | check C029 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*SECURITY* OR process.command_line:*Policy*Secrets* OR process.command_line:*lsadump* OR process.command_line:*secretsdump*)", "time_from": null, "tim… | 0 |  |
| q-76f6bf71ff | check C030 | aggregate | {"dataset": "windows.sysmon", "field": "win.ImageLoaded", "query": "event.code:7 AND (win.ImageLoaded:*lsass* OR win.ImageLoaded:*samlib* OR win.ImageLoaded:*vaultcli*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 23 |  |
| q-2393b3861e | check C031 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND (win.ObjectName:*SECURITY*Policy*Secrets* OR win.ObjectName:*LSA*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-c5e69cc723 | check C032 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4656 AND (win.ObjectName:*SECURITY* OR win.ObjectName:*LSA*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-167ed833be | check C033 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4670 AND (win.ObjectName:*SECURITY* OR win.ObjectName:*LSA*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-8922aca8b3 | check C034 | aggregate | {"dataset": "windows.powershell", "field": "host.name", "query": "event.code:4104 AND (win.ScriptBlockText:*lsadump* OR win.ScriptBlockText:*secretsdump* OR win.ScriptBlockText:*Policy*Secrets*)", "time_from": null, "time_to": null, "size": 50, "sub_field": nu… | 0 |  |
| q-db90aaf50f | check C035 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND win.TargetImage:*lsass.exe", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 326 |  |
| q-33c9b57955 | check C036 | aggregate | {"dataset": "windows.sysmon", "field": "process.command_line", "query": "event.code:1 AND (process.command_line:*cache* OR process.command_line:*dcc2* OR process.command_line:*mscache* OR process.command_line:*cachedump*)", "time_from": null, "time_to": null, … | 4 |  |
| q-3930c30bcd | check C037 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND (win.ObjectName:*SECURITY*Cache* OR win.ObjectName:*Cache*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-971e291e40 | check C038 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4656 AND win.ObjectName:*Cache*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-0beb0f6eeb | check C039 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4670 AND win.ObjectName:*Cache*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-62a50d57e9 | check C040 | aggregate | {"dataset": "windows.powershell", "field": "host.name", "query": "event.code:4104 AND (win.ScriptBlockText:*cachedump* OR win.ScriptBlockText:*dcc2* OR win.ScriptBlockText:*mscache*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-08e7ff4300 | check C041 | aggregate | {"dataset": "windows.security", "field": "win.Properties", "query": "event.code:4662", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 7 |  |
| q-60ff47602f | check C042 | aggregate | {"dataset": "windows.security", "field": "win.SubjectUserName", "query": "event.code:4662 AND win.Properties:*1131f6aa* OR event.code:4662 AND win.Properties:*1131f6ad*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-90cc353f71 | check C043 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*drsuapi* OR process.command_line:*lsadump* OR process.command_line:*dcsync*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-d7e1b148af | check C044 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*DCSync* OR win.ScriptBlockText:*Invoke-Mimikatz* OR win.ScriptBlockText:*lsadump* OR win.ScriptBlockText:*drsuapi*)", "time_from": null, "time_to": null, "fields": ["@timesta… | 0 |  |
| q-68cfee3078 | check C045 | search | {"dataset": "windows.other", "query": "event.code:7045 AND (win.ImagePath:*drsuapi* OR win.ImagePath:*dcsync* OR win.ServiceName:*dcsync*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code… | 0 |  |
| q-d749eb95e3 | check C046 | aggregate | {"dataset": "zeek", "field": "zeek.operation", "query": "event.action:dce_rpc", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 123 |  |
| q-2854a5db81 | check C047 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND (process.command_line:*pktmon* OR process.command_line:*netsh* OR process.command_line:*windump* OR process.command_line:*tcpdump* OR process.command_line:*rawcap*)", … | 2 |  |
| q-db205ef984 | check C048 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*pktmon* OR process.command_line:*windump* OR process.command_line:*tcpdump* OR process.command_line:*rawcap* OR process.command_line:*netsh trace*)",… | 9 |  |
| q-49e8d30e20 | check C049 | search | {"dataset": "windows.other", "query": "event.code:7045 AND (win.ImagePath:*pcap* OR win.ImagePath:*npcap* OR win.ImagePath:*winpcap* OR win.ServiceName:*npcap* OR win.ServiceName:*pcap*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name… | 0 |  |
| q-8e0580c77e | check C050 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*pktmon* OR win.ScriptBlockText:*netsh* OR win.ScriptBlockText:*WinPcap* OR win.ScriptBlockText:*Get-NetAdapter*)", "time_from": null, "time_to": null, "fields": ["@timestamp"… | 0 |  |
| q-4ec80d090c | check C051 | aggregate | {"dataset": "zeek", "field": "zeek.service", "query": "event.action:conn", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 613 |  |
| q-3ae80e67f7 | check C052 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass.exe", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-cca83a4652 | check C053 | aggregate | {"dataset": "windows.sysmon", "field": "win.SourceImage", "query": "event.code:10 AND win.TargetImage:*lsass.exe", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-c05d0b389c | check C054 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4656 AND (win.ObjectName:*lsass* OR win.ObjectName:*sam* OR win.ObjectName:*security*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 13 |  |
| q-9674a03eeb | check C055 | aggregate | {"dataset": "windows.security", "field": "win.ProcessName", "query": "event.code:4663 AND (win.ObjectName:*lsass* OR win.ObjectName:*sam*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 6 |  |
| q-94329e905a | check C056 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Get-Process*lsass* OR win.ScriptBlockText:*MiniDump* OR win.ScriptBlockText:*comsvcs* OR win.ScriptBlockText:*SetWindowsHookEx*)", "time_from": null, "time_to": null, "fields… | 0 |  |
| q-671f73e7e1 | check C057 | search | {"dataset": "windows.other", "query": "event.code:7045 AND (win.ImagePath:*hook* OR win.ImagePath:*keylog* OR win.ImagePath:*capture*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "… | 0 |  |
| q-d785dcabe9 | check C058 | aggregate | {"dataset": "zeek", "field": "destination.port", "query": "event.action:conn", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 613 |  |
| q-ae8f40fa10 | check C059 | aggregate | {"dataset": "windows.sysmon", "field": "registry.path", "query": "event.code:13 AND (registry.path:*Keyboard* OR registry.path:*keylog* OR registry.path:*SetWindowsHookEx*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 26 |  |
| q-f6d8dfbfbf | check C060 | aggregate | {"dataset": "windows.sysmon", "field": "win.SourceImage", "query": "event.code:10 AND win.TargetImage:*lsass.exe", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-6a01e09006 | check C061 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4656 AND (win.ObjectName:*keyboard* OR win.ObjectName:*keylog*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-80ad2388d0 | check C062 | search | {"dataset": "windows.other", "query": "event.code:7045 AND (win.ImagePath:*keylog* OR win.ImagePath:*hook* OR win.ServiceName:*keylog*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", … | 0 |  |
| q-0489ff6a70 | check C063 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*keylog* OR win.ScriptBlockText:*GetAsyncKeyState* OR win.ScriptBlockText:*SetWindowsHookEx* OR win.ScriptBlockText:*Register-ObjectEvent*)", "time_from": null, "time_to": nul… | 0 |  |
| q-67b8e399b6 | check C064 | aggregate | {"dataset": "zeek", "field": "destination.port", "query": "event.action:conn", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 613 |  |
| q-9754abc782 | check C065 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*CredentialPrompt* OR win.ScriptBlockText:*Get-Credential* OR win.ScriptBlockText:*PromptForCredential* OR win.ScriptBlockText:*Windows.Forms*)", "time_from": null, "time_to":… | 2 | F10 |
| q-c475be195a | check C066 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*Get-Credential* OR process.command_line:*PromptForCredential* OR process.command_line:*CredentialPrompt*)", "time_from": null, "time_to": null, "size… | 0 |  |
| q-ea28a43bb6 | check C067 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND (process.command_line:*Get-Credential* OR process.command_line:*PromptForCredential*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-4b28d45a40 | check C068 | search | {"dataset": "windows.other", "query": "event.code:7045 AND (win.ImagePath:*prompt* OR win.ImagePath:*credential*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.… | 0 |  |
| q-078c054d86 | check C069 | aggregate | {"dataset": "zeek", "field": "destination.port", "query": "event.action:conn", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 613 |  |
| q-0b031e3ebf | check C070 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND (win.TargetFilename:*login* OR win.TargetFilename:*portal* OR win.TargetFilename:*wwwroot*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-5cd54ab513 | check C071 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*wwwroot* OR win.ScriptBlockText:*login* OR win.ScriptBlockText:*Set-Content* OR win.ScriptBlockText:*Out-File*)", "time_from": null, "time_to": null, "fields": ["@timestamp",… | 2 | F12 |
| q-0ca467981f | check C072 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND (win.ObjectName:*wwwroot* OR win.ObjectName:*inetpub*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-5b7500e74a | check C073 | search | {"dataset": "windows.other", "query": "event.code:7045 AND (win.ImagePath:*iis* OR win.ImagePath:*w3wp* OR win.ServiceName:*W3SVC*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "use… | 0 |  |
| q-0acfac648b | check C074 | aggregate | {"dataset": "zeek", "field": "url.original", "query": "event.action:http AND (http.request.method:POST)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-92639f18ac | check C075 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-6ab47c8850 | check C076 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 326 | F11 |
| q-aba6bc1b20 | check C077 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-ba9015ebab | check C078 | aggregate | {"dataset": "windows.sysmon", "field": "win.ImageLoaded", "query": "event.code:7", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 20259 |  |
| q-d155400b92 | check C079 | search | {"dataset": "windows.sysmon", "query": "event.code:8 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_lin… | 2 |  |
| q-48e6279332 | check C080 | search | {"dataset": "windows.security", "query": "event.code:4663 AND win.ObjectName:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command… | 6 |  |
| q-800c0434d8 | check C081 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND win.ScriptBlockText:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.… | 0 |  |
| q-5edd629557 | check C082 | search | {"dataset": "windows.other", "query": "message:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 0 |  |
| q-24d3f509f5 | check C083 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-cbdc4c0333 | check C084 | aggregate | {"dataset": "windows.security", "field": "source.ip", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-f5eb3894a3 | check C085 | timeline | {"dataset": "windows.security", "query": "event.code:4625", "interval": "1m", "time_from": null, "time_to": null} | 0 |  |
| q-0d711fff23 | check C086 | search | {"dataset": "windows.security", "query": "event.code:4625 OR event.code:4776", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 1 |  |
| q-ed7c3fe19b | check C087 | search | {"dataset": "windows.other", "query": "message:*4625* OR message:*logon*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "sou… | 2 |  |
| q-7c6247f7e0 | check C088 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*password* OR win.ScriptBlockText:*Credential*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "us… | 3 |  |
| q-ff4db723fc | check C089 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*net* OR process.command_line:*user*)", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 31 |  |
| q-7158603398 | check C090 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-d812a34871 | check C091 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 0 |  |
| q-b547d0ba32 | check C092 | timeline | {"dataset": "windows.security", "query": "event.code:4625", "interval": "5m", "time_from": null, "time_to": null} | 0 |  |
| q-59e476d0b4 | check C093 | search | {"dataset": "windows.other", "query": "message:*4625*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinati… | 0 |  |
| q-7951674f64 | check C094 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*PSCredential* OR win.ScriptBlockText:*ConvertTo-SecureString*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "… | 4 |  |
| q-3e366de3c3 | check C095 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND process.command_line:*runas*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.comman… | 1 | F15 |
| q-b8eeccd5b8 | check C096 | search | {"dataset": "windows.security", "query": "event.code:4663 AND (win.ObjectName:*SAM* OR win.ObjectName:*SECURITY* OR win.ObjectName:*SYSTEM*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.co… | 4484 |  |
| q-5519d0d163 | check C097 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 OR event.code:4656", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 10834 |  |
| q-1c5c518dae | check C098 | search | {"dataset": "windows.security", "query": "event.code:4670 AND win.ObjectName:*SAM*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_l… | 0 |  |
| q-0dfafc858d | check C099 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*reg* AND process.command_line:*save*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "proc… | 0 |  |
| q-1820d76eaf | check C100 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*SAM* OR file.path:*ntds.dit* OR file.path:*SECURITY*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name",… | 3 | F16 |
| q-6cce5ecef3 | check C101 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 326 |  |
| q-ee9d93154f | check C102 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*hashcat* OR win.ScriptBlockText:*john* OR win.ScriptBlockText:*Invoke-Mimikatz*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", … | 0 |  |
| q-b188f20c80 | check C103 | search | {"dataset": "windows.other", "query": "message:*SAM* OR message:*ntds*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "sourc… | 1 |  |
| q-5464057c9d | check C104 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 200, "sub_field": null} | 0 |  |
| q-803917b088 | check C105 | aggregate | {"dataset": "windows.security", "field": "source.ip", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-486c2462a3 | check C106 | search | {"dataset": "windows.security", "query": "event.code:4648", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 15 |  |
| q-2d7cbb8bc2 | check C107 | timeline | {"dataset": "windows.security", "query": "event.code:4625", "interval": "1m", "time_from": null, "time_to": null} | 0 |  |
| q-09d3455ea1 | check C108 | search | {"dataset": "windows.other", "query": "message:*4771* OR message:*4625*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "sour… | 0 |  |
| q-88dff1cd73 | check C109 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*foreach* AND win.ScriptBlockText:*Credential*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "us… | 0 |  |
| q-9d559df5ea | check C110 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND process.command_line:*net*", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 30 |  |
| q-f440518018 | check C111 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 200, "sub_field": null} | 0 |  |
| q-88066435ef | check C112 | aggregate | {"dataset": "windows.security", "field": "source.ip", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-7f9e803d56 | check C113 | search | {"dataset": "windows.security", "query": "event.code:4625", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 0 |  |
| q-0a72ac2276 | check C114 | search | {"dataset": "windows.other", "query": "message:*4625*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinati… | 0 |  |
| q-3a5f96eb14 | check C115 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*user* AND win.ScriptBlockText:*pass*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name",… | 0 |  |
| q-da3d352f12 | check C116 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*.txt* AND process.command_line:*user*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "pro… | 0 |  |
| q-c65d345344 | check C117 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 297 |  |
| q-1507fd9e9f | check C118 | search | {"dataset": "windows.security", "query": "event.code:4648", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 15 | F20 |
| q-d9fbba0022 | check C119 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-5a10ae7510 | check C120 | search | {"dataset": "windows.sysmon", "query": "event.code:13 AND registry.path:*lsa*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line",… | 0 |  |
| q-dd3d16bd8d | check C121 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND win.ScriptBlockText:*Credential*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "pro… | 3 |  |
| q-3c915aebe5 | check C122 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 | F21 |
| q-1c5b6b1254 | check C123 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 OR event.code:4656 OR event.code:4670", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 10977 |  |
| q-aff9f45063 | check C124 | aggregate | {"dataset": "windows.security", "field": "destination.ip", "query": "event.code:5156", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 3163 |  |
| q-da8a54b613 | check C125 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1649 |  |
| q-b1ffbe97d8 | check C126 | aggregate | {"dataset": "windows.sysmon", "field": "destination.ip", "query": "event.code:3 AND (destination.port:445 OR destination.port:139)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 66 |  |
| q-e49b80fed1 | check C127 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*WebDAV* OR win.ScriptBlockText:*NTLM* OR win.ScriptBlockText:*445*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.datase… | 0 |  |
| q-ad11d58625 | check C128 | search | {"dataset": "windows.other", "query": "event.code:11", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinatio… | 4 |  |
| q-ce62e1a19d | check C129 | aggregate | {"dataset": "zeek", "field": "destination.port", "query": "event.action:conn AND (destination.port:445 OR destination.port:139)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 50 |  |
| q-014c380495 | check C130 | search | {"dataset": "zeek", "query": "event.action:http AND (http.request.method:PROPFIND OR http.request.method:OPTIONS OR http.request.method:MOVE)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.c… | 36 |  |
| q-054a6c7159 | check C131 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-a275dd9210 | check C132 | aggregate | {"dataset": "windows.sysmon", "field": "win.SourceImage", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-a37181940d | check C133 | search | {"dataset": "windows.security", "query": "event.code:4768 OR event.code:4769 OR event.code:4770", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "proc… | 42 |  |
| q-26da242da3 | check C134 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 460 |  |
| q-7951fc3c3a | check C135 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*MiniDump* OR win.ScriptBlockText:*comsvcs*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event… | 0 |  |
| q-d358b0b2d8 | check C136 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-04bd74273d | check C137 | search | {"dataset": "zeek", "query": "event.action:notice", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destination.i… | 2 |  |
| q-b729a440fb | check C138 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:2", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 209 |  |
| q-b6ea876041 | check C139 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-86e762c526 | check C140 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 460 |  |
| q-552a45dc36 | check C141 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Cookies* OR win.ScriptBlockText:*Login Data* OR win.ScriptBlockText:*sqlite*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "ev… | 13 |  |
| q-8c2e700445 | check C142 | search | {"dataset": "windows.other", "query": "event.code:11", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinatio… | 4 |  |
| q-0f92884168 | check C143 | search | {"dataset": "zeek", "query": "event.action:http AND http.request.method:POST", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 0 |  |
| q-199e2ee0b2 | check C144 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1649 |  |
| q-cd68379244 | check C145 | aggregate | {"dataset": "windows.sysmon", "field": "registry.path", "query": "event.code:13", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 17541 |  |
| q-a4f30c539c | check C146 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 460 |  |
| q-d471ffa69a | check C147 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*reg\\ save* OR process.command_line:*ntdsutil* OR process.command_line:*vssadmin*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name",… | 0 |  |
| q-7697d60112 | check C148 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*password* OR win.ScriptBlockText:*credential* OR win.ScriptBlockText:*ConvertTo-SecureString*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "ob… | 4 |  |
| q-4e6af364e1 | check C149 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 | F27 |
| q-a55d5657ef | check C150 | search | {"dataset": "zeek", "query": "event.action:smb_files", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinatio… | 12 |  |
| q-8d7056ba3f | check C151 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1649 |  |
| q-127ce656d6 | check C152 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 447 |  |
| q-bfd02212ba | check C153 | search | {"dataset": "windows.security", "query": "event.code:4648", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 15 |  |
| q-880cdb57b3 | check C154 | aggregate | {"dataset": "windows.security", "field": "process.command_line", "query": "event.code:4688 AND (process.command_line:*findstr* OR process.command_line:*password* OR process.command_line:*unattend*)", "time_from": null, "time_to": null, "size": 50, "sub_field":… | 0 |  |
| q-af04cf38ec | check C155 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Get-Content* OR win.ScriptBlockText:*Select-String* OR win.ScriptBlockText:*findstr*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.na… | 1 |  |
| q-4b5873a9ac | check C156 | search | {"dataset": "windows.other", "query": "event.code:11", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinatio… | 4 |  |
| q-27b7bad703 | check C157 | search | {"dataset": "zeek", "query": "event.action:smb_files", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinatio… | 12 |  |
| q-e2021ebac6 | check C158 | aggregate | {"dataset": "windows.sysmon", "field": "registry.path", "query": "event.code:13 AND (registry.path:*Password* OR registry.path:*password* OR registry.path:*Credential* OR registry.path:*credential* OR registry.path:*Secret* OR registry.path:*secret*)", "time_f… | 17 |  |
| q-3645bdd2ea | check C159 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*reg\\ query* OR process.command_line:*reg\\ save* OR process.command_line:*reg.exe* OR process.command_line:*HKLM*SAM* OR process.command_line:*SECURITY* OR process.command_line:*L… | 0 |  |
| q-fa459d0f89 | check C160 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*HKLM* OR win.ScriptBlockText:*SAM* OR win.ScriptBlockText:*SECURITY* OR win.ScriptBlockText:*LSA* OR win.ScriptBlockText:*Password*)", "time_from": null, "time_to": null, "fi… | 3 |  |
| q-e7cbb354b7 | check C161 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND (win.ObjectName:*SAM* OR win.ObjectName:*SECURITY* OR win.ObjectName:*LSA*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-d8f1d99e5a | check C162 | search | {"dataset": "windows.other", "query": "message:*SAM* OR message:*SECURITY* OR message:*LSA* OR message:*reg.exe*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.e… | 11 |  |
| q-9cbda45fc1 | check C163 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*ConsoleHost_history* OR win.ScriptBlockText:*history* OR win.ScriptBlockText:*Get-Content*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "obser… | 0 |  |
| q-55021acf2c | check C164 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*ConsoleHost_history* OR process.command_line:*history.txt* OR process.command_line:*PSReadLine*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observ… | 0 |  |
| q-d1a0411f79 | check C165 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*ConsoleHost_history* OR file.path:*PSReadLine*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "proc… | 0 |  |
| q-e7235a9d12 | check C166 | search | {"dataset": "windows.security", "query": "event.code:4663 AND (win.ObjectName:*ConsoleHost_history* OR win.ObjectName:*PSReadLine*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "use… | 0 |  |
| q-0d964cc842 | check C167 | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11 AND (file.path:*.pfx OR file.path:*.pem OR file.path:*.key OR file.path:*.p12 OR file.path:*.ppk OR file.path:*.pgp OR file.path:*.cer OR file.path:*.p7b OR file.path:*.asc)", "time_fr… | 1 |  |
| q-063f050648 | check C168 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*.pfx OR process.command_line:*.pem OR process.command_line:*.key OR process.command_line:*.p12 OR process.command_line:*.ppk)", "time_from": null, "time_to": null, "fields": ["@tim… | 0 |  |
| q-ee769adcaa | check C169 | aggregate | {"dataset": "windows.security", "field": "win.RelativeTargetName", "query": "event.code:5145 AND (win.RelativeTargetName:*.pfx OR win.RelativeTargetName:*.pem OR win.RelativeTargetName:*.key OR win.RelativeTargetName:*.p12 OR win.RelativeTargetName:*.ppk)", "t… | 0 |  |
| q-05fd3e528e | check C170 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*.pfx OR win.ScriptBlockText:*.pem OR win.ScriptBlockText:*.p12 OR win.ScriptBlockText:*.ppk OR win.ScriptBlockText:*Export-PfxCertificate*)", "time_from": null, "time_to": nu… | 1 |  |
| q-8a7288ab1d | check C171 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Groups.xml* OR win.ScriptBlockText:*gpprefdecrypt* OR win.ScriptBlockText:*cpassword* OR win.ScriptBlockText:*SYSVOL* OR win.ScriptBlockText:*AES*)", "time_from": null, "time… | 0 |  |
| q-44b1a01dec | check C172 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*Groups.xml* OR process.command_line:*SYSVOL* OR process.command_line:*gpprefdecrypt* OR process.command_line:*cpassword*)", "time_from": null, "time_to": null, "fields": ["@timesta… | 0 |  |
| q-7fcf095bbb | check C173 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*Groups.xml* OR file.path:*SYSVOL*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executabl… | 0 |  |
| q-c60a0048ad | check C174 | aggregate | {"dataset": "windows.security", "field": "win.RelativeTargetName", "query": "event.code:5145 AND (win.RelativeTargetName:*Groups.xml* OR win.RelativeTargetName:*SYSVOL* OR win.RelativeTargetName:*.xml)", "time_from": null, "time_to": null, "size": 50, "sub_fie… | 0 |  |
| q-b06a342a16 | check C175 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND (win.TargetImage:*lsass.exe OR win.TargetImage:*lsass*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-91d8f5bbca | check C176 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass.exe", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-9d4ffff3b2 | check C177 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*procdump* OR process.command_line:*comsvcs* OR process.command_line:*MiniDump* OR process.command_line:*mimikatz* OR process.command_line:*sekurlsa* OR process.command_line:*lsass*… | 1 |  |
| q-09a7a8f67b | check C178 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND (win.ObjectName:*lsass* OR win.ObjectName:*SAM* OR win.ObjectName:*SECURITY* OR win.ObjectName:*NTDS*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 6 |  |
| q-4377f46b31 | check C179 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*MiniDump* OR win.ScriptBlockText:*sekurlsa* OR win.ScriptBlockText:*Credential* OR win.ScriptBlockText:*vault*)", "time_from": null, "time_to":… | 3 |  |
| q-ba63a3e5e3 | check C180 | search | {"dataset": "windows.other", "query": "message:*lsass* OR message:*MiniDump* OR message:*procdump* OR message:*mimikatz*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "p… | 0 |  |
| q-dfee280852 | check C181 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND (win.TargetImage:*chrome.exe OR win.TargetImage:*firefox.exe OR win.TargetImage:*msedge.exe OR win.TargetImage:*iexplore.exe)", "time_from": null, "time_to": null, "size":… | 0 |  |
| q-d1a1f40bd8 | check C182 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*Login\\ Data* OR file.path:*logins.json* OR file.path:*key4.db* OR file.path:*Cookies* OR file.path:*Web Data*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "o… | 162 |  |
| q-669b7ee3f6 | check C183 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND (win.ObjectName:*Login Data* OR win.ObjectName:*logins.json* OR win.ObjectName:*key4.db* OR win.ObjectName:*Web Data*)", "time_from": null, "time_to": null, "size": 50, "s… | 0 |  |
| q-8dcd3519de | check C184 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*Login\\ Data* OR process.command_line:*logins.json* OR process.command_line:*key4.db* OR process.command_line:*sqlite*)", "time_from": null, "time_to": null, "fields": ["@timestamp… | 0 |  |
| q-7022338a31 | check C185 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Login Data* OR win.ScriptBlockText:*logins.json* OR win.ScriptBlockText:*key4.db* OR win.ScriptBlockText:*CryptUnprotectData*)", "time_from": null, "time_to": null, "fields":… | 0 |  |
| q-d315ec94b1 | check C186 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*vault* OR process.command_line:*credman* OR process.command_line:*Credential* OR process.command_line:*cmdkey*)", "time_from": null, "time_to": null,… | 0 |  |
| q-b63202ce9a | check C187 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 326 |  |
| q-3c9dc51148 | check C188 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:15 AND (win.TargetFilename:*Credentials* OR win.TargetFilename:*Vault*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-c03ebc15cf | check C189 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*vault* OR process.command_line:*cmdkey* OR process.command_line:*credman*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.… | 0 |  |
| q-38fd4ca69f | check C190 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Credential* OR win.ScriptBlockText:*vault* OR win.ScriptBlockText:*cmdkey* OR win.ScriptBlockText:*CredentialManager*)", "time_from": null, "time_to": null, "fields": ["@time… | 3 |  |
| q-3892907d24 | check C191 | search | {"dataset": "windows.other", "query": "message:*vault* OR message:*Credential* OR message:*cmdkey*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "p… | 2 | F33 |
| q-0d38d4ee7d | check C192 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*keepass* OR process.command_line:*1password* OR process.command_line:*bitwarden* OR process.command_line:*lastpass* OR process.command_line:*KeePass*… | 0 |  |
| q-90e3b6aa3a | check C193 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND (win.TargetFilename:*.kdbx OR win.TargetFilename:*1password* OR win.TargetFilename:*keepass*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-9873564514 | check C194 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND (win.TargetImage:*keepass* OR win.TargetImage:*1password* OR win.TargetImage:*bitwarden*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "e… | 0 |  |
| q-c96efe8867 | check C195 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*keepass* OR process.command_line:*1password* OR process.command_line:*bitwarden* OR process.command_line:*lastpass*)", "time_from": null, "time_to": null, "fields": ["@timesta… | 0 |  |
| q-9d9fd20052 | check C196 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*kdbx* OR win.ScriptBlockText:*keepass* OR win.ScriptBlockText:*1password* OR win.ScriptBlockText:*bitwarden*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "… | 0 |  |
| q-db04ca57a8 | check C197 | search | {"dataset": "windows.other", "query": "message:*keepass* OR message:*1password* OR message:*bitwarden* OR message:*kdbx*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "p… | 0 |  |
| q-6bafe0846e | check C198 | search | {"dataset": "windows.security", "query": "event.code:4657 AND (win.ObjectName:*lsass* OR win.ObjectName:*Security* OR win.ObjectName:*SAM*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.cod… | 0 |  |
| q-33e6e86fa1 | check C199 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10 AND (win.TargetImage:*lsass* OR win.TargetImage:*cryptdll* OR win.TargetImage:*sam* OR win.TargetImage:*winlogon*)", "time_from": null, "time_to": null, "size": 50, "sub_field": … | 470 |  |
| q-b836092261 | check C200 | aggregate | {"dataset": "windows.sysmon", "field": "win.ImageLoaded", "query": "event.code:7 AND (win.ImageLoaded:*lsass* OR win.ImageLoaded:*cryptdll* OR win.ImageLoaded:*sam* OR win.ImageLoaded:*msv1_0* OR win.ImageLoaded:*wdigest*)", "time_from": null, "time_to": null,… | 79 |  |
| q-9d5b1832ad | check C201 | search | {"dataset": "windows.sysmon", "query": "event.code:13 AND (registry.path:*lsass* OR registry.path:*Security\\\\Authentication* OR registry.path:*WDigest*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.datas… | 0 |  |
| q-a34cc9944e | check C202 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*WDigest* OR win.ScriptBlockText:*UseLogonCredential* OR win.ScriptBlockText:*cryptdll*)", "time_from": null, "time_to": null, "fields": ["@time… | 0 |  |
| q-77982902f3 | check C203 | search | {"dataset": "windows.other", "query": "message:*lsass* OR message:*cryptdll* OR message:*WDigest*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "pr… | 0 |  |
| q-948f245e82 | check C204 | aggregate | {"dataset": "windows.security", "field": "win.LogonProcessName", "query": "event.code:4624 OR event.code:4648", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 312 |  |
| q-8774d708b4 | check C205 | search | {"dataset": "windows.security", "query": "event.code:4648 AND win.TargetUserName:*$", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_… | 1 |  |
| q-b9e3a237e6 | check C206 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10 AND (win.TargetImage:*lsass* OR win.TargetImage:*cryptdll*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-8aad1225f2 | check C207 | aggregate | {"dataset": "windows.sysmon", "field": "win.ImageLoaded", "query": "event.code:7 AND (win.ImageLoaded:*cryptdll* OR win.ImageLoaded:*lsass* OR win.ImageLoaded:*ntds* OR win.ImageLoaded:*sam*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 87 |  |
| q-3563a3e749 | check C208 | search | {"dataset": "windows.other", "query": "message:*lsass* OR message:*cryptdll*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 0 |  |
| q-eadf25a263 | check C209 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*cryptdll* OR win.ScriptBlockText:*Skeleton* OR win.ScriptBlockText:*mimilib*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "h… | 0 |  |
| q-764f1b0a4b | check C210 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND (win.TargetFilename:*\\\\secrets\\\\* OR win.TargetFilename:*password* OR win.TargetFilename:*filter*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 7 |  |
| q-30cc006813 | check C211 | search | {"dataset": "windows.sysmon", "query": "event.code:13 AND (registry.path:*Notification Packages* OR registry.path:*PasswordFilter* OR registry.path:*Lsa*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.datas… | 0 |  |
| q-e2b27bab4a | check C212 | aggregate | {"dataset": "windows.sysmon", "field": "win.ImageLoaded", "query": "event.code:7 AND (win.ImageLoaded:*lsass* OR win.ImageLoaded:*password*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1 |  |
| q-fbdbfe90d8 | check C213 | search | {"dataset": "windows.security", "query": "event.code:4657 AND (win.ObjectName:*Notification Packages* OR win.ObjectName:*Lsa* OR win.ObjectName:*PasswordFilter*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "even… | 0 |  |
| q-49597be41e | check C214 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Notification Packages* OR win.ScriptBlockText:*PasswordFilter* OR win.ScriptBlockText:*Lsa*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "obse… | 0 |  |
| q-b6bcb0b983 | check C215 | search | {"dataset": "windows.other", "query": "message:*Notification Packages* OR message:*PasswordFilter*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "p… | 5 |  |
| q-8ee255138e | check C216 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*AllowReversiblePasswordEncryption* OR win.ScriptBlockText:*ReversibleEncryption* OR win.ScriptBlockText:*Set-ADAccountControl* OR win.ScriptBlockText:*Set-ADUser*)", "time_fr… | 1 | F38 |
| q-652d5b29f9 | check C217 | search | {"dataset": "windows.powershell", "query": "event.code:4103 OR event.code:4104 OR event.code:4105 OR event.code:4106", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "proce… | 5494 |  |
| q-94c532dffe | check C218 | search | {"dataset": "windows.security", "query": "event.code:4739", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 0 |  |
| q-72c2d6a74b | check C219 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*Reversible* OR process.command_line:*Set-ADAccountControl* OR process.command_line:*Set-ADUser* OR process.command_line:*dsmod*)", "time_from": null,… | 0 |  |
| q-fa9f169c45 | check C220 | search | {"dataset": "windows.other", "query": "message:*Reversible* OR message:*AllowReversiblePasswordEncryption*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executa… | 0 |  |
| q-0a19e863d7 | check C221 | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*set-aduser*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*set-adauthenticationpolicy*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*strongauthentication*\" OR TO_L… | ERROR |  |
| q-2b52339dfd | check C221 (repaired) | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*set-aduser*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*set-adauthenticationpolicy*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*strongauthenticati… | 1 |  |
| q-4dffe0cd63 | check C222 | count | {"dataset": "windows.security", "query": "event.code:4739", "time_from": null, "time_to": null} | 0 |  |
| q-5c37349827 | check C223 | aggregate | {"dataset": "windows.security", "field": "win.ObjectType", "query": "event.code:4662 OR event.code:5136", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 7 |  |
| q-098f70826f | check C224 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*ADUser* OR process.command_line:*AuthenticationPolicy* OR process.command_line:*ADDomain*)", "time_from": null, "time_to": null, "size": 20, "sub_fie… | 2 |  |
| q-1d77c8876d | check C225 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 | F39 |
| q-6d29c8bd8d | check C226 | aggregate | {"dataset": "windows.sysmon", "field": "win.ImageLoaded", "query": "event.code:7", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 20259 |  |
| q-caba3d33b6 | check C227 | count | {"dataset": "windows.security", "query": "event.code:5136", "time_from": null, "time_to": null} | 0 |  |
| q-7cc529c257 | check C228 | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*azuread*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*aadconnect*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*connect-msolservice*\" OR TO_LOWER(win.ScriptBlock… | ERROR |  |
| q-c90ebc40d5 | check C228 (repaired) | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*azuread*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*aadconnect*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*connect-msolservice*\" OR TO_LOWER(win.ScriptBlock… | ERROR |  |
| q-e5c6923e0d | check C229 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 | F40 |
| q-4e26f05e2f | check C230 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10 AND (win.GrantedAccess:*1040* OR win.GrantedAccess:*1000* OR win.GrantedAccess:*1410*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 30212 |  |
| q-c720cf487d | check C231 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND (win.TargetFilename:*network* OR win.TargetFilename:*np*.dll OR win.TargetFilename:*System32*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 425 |  |
| q-2c139948fe | check C232 | aggregate | {"dataset": "windows.sysmon", "field": "win.ImageLoaded", "query": "event.code:7 AND (win.ImageLoaded:*network* OR win.ImageLoaded:*np*.dll)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 149 |  |
| q-ce534123d0 | check C233 | count | {"dataset": "windows.security", "query": "event.code:4657 AND (win.ObjectName:*NetworkProvider* OR win.ObjectName:*Winlogon*)", "time_from": null, "time_to": null} | 0 |  |
| q-6953d02f83 | check C234 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-e94843323c | check C235 | aggregate | {"dataset": "windows.sysmon", "field": "destination.ip", "query": "event.code:3", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1229 |  |
| q-4a22ee3fbe | check C236 | aggregate | {"dataset": "windows.sysmon", "field": "dns.question.name", "query": "event.code:22", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 81 |  |
| q-4fc4510971 | check C237 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 OR event.code:4656 OR event.code:4670", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 10977 |  |
| q-a4614d9ae0 | check C238 | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*responder*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*inveigh*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*llmnr*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*a… | ERROR |  |
| q-12f291b01a | check C238 (repaired) | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*responder*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*inveigh*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*llmnr*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*a… | ERROR |  |
| q-88d79a15fd | check C239 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-73c3922e9a | check C240 | aggregate | {"dataset": "windows.sysmon", "field": "destination.ip", "query": "event.code:3 AND (destination.port:445 OR destination.port:139)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 66 |  |
| q-cc3763021c | check C241 | aggregate | {"dataset": "windows.sysmon", "field": "dns.question.name", "query": "event.code:22", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 81 |  |
| q-9be6abbcf5 | check C242 | count | {"dataset": "windows.security", "query": "event.code:4697", "time_from": null, "time_to": null} | 23 |  |
| q-ebffeca081 | check C243 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4657 AND win.ObjectName:*EnableMulticast*", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 0 |  |
| q-979c01ad7f | check C244 | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*enablemulticast*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*responder*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*inveigh*\" OR TO_LOWER(win.ScriptBlockText)… | ERROR |  |
| q-2ab85cdd84 | check C244 (repaired) | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*enablemulticast*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*responder*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*inveigh*\" OR TO_LOWER(win.Scr… | 0 |  |
| q-48562cf9a5 | check C245 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-a754970774 | check C246 | aggregate | {"dataset": "windows.sysmon", "field": "destination.ip", "query": "event.code:3", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1229 |  |
| q-7521ed00be | check C247 | aggregate | {"dataset": "windows.sysmon", "field": "dns.question.name", "query": "event.code:22", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 81 |  |
| q-082a4a4b61 | check C248 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 OR event.code:4656", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 10834 |  |
| q-0201e965ed | check C249 | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*arp*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*spoof*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*ettercap*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*cain*\… | ERROR |  |
| q-ed1ebe86fc | check C249 (repaired) | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*arp*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*spoof*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*ettercap*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*cain*\… | ERROR |  |
| q-955fa66de2 | check C250 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-ce5ec55816 | check C251 | search | {"dataset": "windows.other", "query": "event.code:(1341 OR 1342 OR 1020 OR 1063)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_lin… | 0 |  |
| q-acefdd3dbe | check C252 | aggregate | {"dataset": "windows.security", "field": "win.LogonProcessName", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 297 |  |
| q-beca3a7f73 | check C253 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*dhcp* OR process.command_line:*ipconfig*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 3 |  |
| q-cfeeaa0890 | check C254 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND win.ScriptBlockText:(*dhcp* OR *DhcpServer* OR *rogue*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "pr… | 0 |  |
| q-17820ba6d8 | check C255 | aggregate | {"dataset": "zeek", "field": "destination.port", "query": "event.action:conn AND (destination.port:67 OR destination.port:68)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-d918e5b07d | check C256 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4672", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 212 |  |
| q-dfa5025d99 | check C257 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4634", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 236 |  |
| q-c1023414a3 | check C258 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass.exe", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-fe0609966e | check C259 | search | {"dataset": "windows.other", "query": "event.code:(4769 OR 4768 OR 4771)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "sou… | 0 |  |
| q-2ec18dfc4a | check C260 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND win.ScriptBlockText:(*kerberos* OR *ticket* OR *kirbi* OR *mimikatz*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "u… | 0 |  |
| q-e1d9815bb0 | check C261 | aggregate | {"dataset": "zeek", "field": "zeek.request_type", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 35 |  |
| q-e893616e32 | check C262 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4672", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 212 |  |
| q-2a0a8f0d2b | check C263 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4634", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 236 |  |
| q-9591b2ae25 | check C264 | search | {"dataset": "windows.security", "query": "event.code:4769", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 28 | F48 |
| q-2a00cbf6b7 | check C265 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass.exe", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-48d38bf451 | check C266 | search | {"dataset": "windows.other", "query": "event.code:(4769 OR 4768)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip",… | 0 |  |
| q-24585cca26 | check C267 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND win.ScriptBlockText:(*krbtgt* OR *golden* OR *mimikatz* OR *kirbi*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "use… | 0 |  |
| q-94421d9127 | check C268 | aggregate | {"dataset": "zeek", "field": "zeek.request_type", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 35 |  |
| q-e463219424 | check C269 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4672", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 212 |  |
| q-199945a477 | check C270 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4634", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 236 |  |
| q-73c020eaca | check C271 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass.exe", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-1064695a3c | check C272 | search | {"dataset": "windows.other", "query": "event.code:4769", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 0 |  |
| q-49bda7010d | check C273 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND win.ScriptBlockText:(*silver* OR *ticket* OR *mimikatz* OR *kirbi*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "use… | 0 |  |
| q-7009e96039 | check C274 | aggregate | {"dataset": "zeek", "field": "zeek.request_type", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 35 |  |
| q-0687d91b1b | check C275 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 297 |  |
| q-26b124776d | check C276 | search | {"dataset": "windows.security", "query": "event.code:4648", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 15 |  |
| q-93dfa26d4a | check C277 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4672", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 212 |  |
| q-63e9b17328 | check C278 | search | {"dataset": "windows.security", "query": "event.code:4769", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 28 |  |
| q-92464915ee | check C279 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass.exe", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-4e88e9054c | check C280 | search | {"dataset": "windows.other", "query": "event.code:4769", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 0 |  |
| q-e5bc622fb3 | check C281 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND win.ScriptBlockText:(*kerberoast* OR *SPN* OR *Invoke-Kerberoast* OR *GetUserSPNs*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "e… | 0 |  |
| q-52ad340dfb | check C282 | aggregate | {"dataset": "zeek", "field": "zeek.request_type", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 35 |  |
| q-1c9879dc53 | check C283 | search | {"dataset": "windows.security", "query": "event.code:4768", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 14 |  |
| q-75a6f53259 | check C284 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*asrep* OR process.command_line:*GetNPUsers* OR process.command_line:*rubeus*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-a29c33c80b | check C285 | search | {"dataset": "windows.other", "query": "event.code:4768", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 0 |  |
| q-698c977ef7 | check C286 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND win.ScriptBlockText:(*asrep* OR *GetNPUsers* OR *rubeus* OR *preauth*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "… | 0 |  |
| q-87d02a791f | check C287 | aggregate | {"dataset": "zeek", "field": "zeek.request_type", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 35 |  |
| q-7ad7d0422a | check C288 | aggregate | {"dataset": "windows.security", "field": "win.LogonProcessName", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 297 |  |
| q-0efa1bd7f2 | check C289 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4648", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 15 |  |
| q-12b913b91d | check C290 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-4981e6b649 | check C291 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*AADInternals* OR win.ScriptBlockText:*SAML* OR win.ScriptBlockText:*token* OR win.ScriptBlockText:*cookie*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "ho… | 1 |  |
| q-04e60f7b60 | check C292 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 | F53 |
| q-0e3a8bb536 | check C293 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND (win.TargetFilename:*Cookies* OR win.TargetFilename:*cookie*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1 |  |
| q-33b908033a | check C294 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 297 |  |
| q-670a4820e2 | check C295 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*cookie* OR win.ScriptBlockText:*Cookie*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.nam… | 0 |  |
| q-f109316b0a | check C296 | search | {"dataset": "windows.other", "query": "event.code:11 AND (file.path:*Cookies* OR file.path:*cookie*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", … | 0 |  |
| q-0872bbfc9e | check C297 | aggregate | {"dataset": "windows.security", "field": "win.LogonProcessName", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 297 |  |
| q-8760522619 | check C298 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4648", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 15 |  |
| q-4b514e443c | check C299 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*SAML* OR win.ScriptBlockText:*saml* OR win.ScriptBlockText:*NotOnOrAfter* OR win.ScriptBlockText:*X509* OR win.ScriptBlockText:*certificate*)", "time_from": null, "time_to": … | 2 |  |
| q-412b455188 | check C300 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND (win.TargetFilename:*.pfx OR win.TargetFilename:*.p12 OR win.TargetFilename:*.cer)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1 |  |
| q-25fe91f57f | check C301 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-379dd61cc8 | check C302 | count | {"dataset": "windows.security", "query": "event.code:4625", "time_from": null, "time_to": null} | 0 |  |
| q-574f8d6365 | check C303 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-267f81f8e2 | check C304 | aggregate | {"dataset": "windows.security", "field": "source.ip", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-9a5a362a53 | check C305 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*MFA* OR win.ScriptBlockText:*mfa* OR win.ScriptBlockText:*2FA* OR win.ScriptBlockText:*Authenticator*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.na… | 0 |  |
| q-265624811a | check C306 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*MFA* OR process.command_line:*mfa*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-9435df7f43 | check C307 | search | {"dataset": "windows.other", "query": "event.code:4625", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 0 |  |
| q-36e5cbfd30 | check C308 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4657", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 36 |  |
| q-d2f03a3eb4 | check C309 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4768", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 14 |  |
| q-a98c2f9848 | check C310 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND (win.TargetFilename:*.pfx OR win.TargetFilename:*.p12 OR win.TargetFilename:*.cer OR win.TargetFilename:*.crt)", "time_from": null, "time_to": null, "size": 50, "sub_field… | 1 |  |
| q-e1e2dc1554 | check C311 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Export-PfxCertificate* OR win.ScriptBlockText:*Certify* OR win.ScriptBlockText:*CertRequest* OR win.ScriptBlockText:*certutil*)", "time_from": null, "time_to": null, "fields"… | 1 |  |
| q-5558c7b891 | check C312 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-52441bcae1 | check C313 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*NetworkProvider* OR win.ScriptBlockText:*System32* AND win.ScriptBlockText:*dll*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name",… | 0 |  |
| q-82a22f8c8d | check C314 | aggregate | {"dataset": "zeek", "field": "zeek.server_name", "query": "event.action:ssl", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 378 |  |
| q-61f1201ff3 | check C315 | aggregate | {"dataset": "zeek", "field": "zeek.rcode_name", "query": "event.action:dns", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 53 |  |
| q-342943ab32 | check C316 | aggregate | {"dataset": "zeek", "field": "zeek.id_resp_h", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 35 |  |
| q-555cac0b41 | check C317 | aggregate | {"dataset": "zeek", "field": "zeek.server_name", "query": "event.action:ssl", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 378 |  |
| q-75daa8bfc0 | check C318 | aggregate | {"dataset": "zeek", "field": "url.domain", "query": "event.action:http", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 62 |  |
| q-a6e8406253 | check C319 | aggregate | {"dataset": "zeek", "field": "url.domain", "query": "event.action:http", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 62 |  |
| q-670618a73f | check C320 | aggregate | {"dataset": "zeek", "field": "zeek.server_name", "query": "event.action:ssl", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 378 |  |
| q-89b50cd924 | check C321 | aggregate | {"dataset": "zeek", "field": "url.domain", "query": "event.action:http", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 62 |  |
| q-8949fba14a | check C322 | aggregate | {"dataset": "zeek", "field": "zeek.server_name", "query": "event.action:ssl", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 378 |  |
| q-0c4b89c94e | triage T1003 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass.exe AND (win.GrantedAccess:0x1fffff OR win.GrantedAccess:0x101001 OR win.GrantedAccess:0x1f3fff OR win.GrantedAccess:0x1000000 OR win.GrantedAccess:0x3000)", "time_from": null, "t… | 9 | F01, F02 |
| q-d92d21a2ac | triage T1003 step 1 | search | {"dataset": "windows.security", "query": "event.code:4662", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "win.SubjectUserName", "win.SubjectDomainName", "win.Properties", "win.ObjectName", "win.ObjectType", "win.AccessMask", "win.A… | 7 | F03, F04 |
| q-6aec89f821 | triage T1003 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None | F01 |
| q-b221e9c1d2 | triage T1003 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-17025da120 | triage T1003 step 2 | search | {"dataset": "windows.powershell", "query": "host.name:scranton.dmevals.local AND @timestamp:[2020-05-02T03:04:00.000Z TO 2020-05-02T03:07:00.000Z]", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "user.name", "process.c… | 415 |  |
| q-1fde6ed3f0 | triage T1003 step 3 | search | {"dataset": "windows.powershell", "query": "host.name:scranton.dmevals.local AND event.code:4104 AND @timestamp:[2020-05-02T03:04:30.000Z TO 2020-05-02T03:06:30.000Z]", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "us… | 18 | F01 |
| q-200368d154 | triage T1003 step 3 | search | {"dataset": "windows.sysmon", "query": "host.name:scranton.dmevals.local AND event.code:1 AND @timestamp:[2020-05-02T03:00:00.000Z TO 2020-05-02T03:10:00.000Z]", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "process.e… | 42 | F01, F07 |
| q-e0c80138ad | triage T1003 step 4 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*MiniDump* OR win.ScriptBlockText:*procdump* OR win.ScriptBlockText:*Get-Process* OR win.ScriptBlockText:*OpenProcess* OR win.ScriptBlockText:*D… | 5 | F02 |
| q-ec9dad1d5a | triage T1003 step 4 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (win.TargetFilename:*.dmp OR win.TargetFilename:*.zip OR win.TargetFilename:*.pfx OR win.TargetFilename:*.txt OR win.TargetFilename:*.bmp)", "time_from": null, "time_to": null, "fields": ["@timestamp", … | 27 | F01, F05, F06 |
| q-878ccb5cec | triage T1003 step 5 | search | {"dataset": "windows.security", "query": "event.code:4663 AND win.ObjectName:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "win.ObjectName", "win.ProcessName", "win.SubjectUserName", "win.AccessMask", "win.Ac… | 6 | F01 |
| q-5c6287c0eb | triage T1003 step 5 | search | {"dataset": "windows.security", "query": "host.name:nashua.dmevals.local AND (event.code:4688 OR event.code:4624) AND @timestamp:[2020-05-02T03:08:00.000Z TO 2020-05-02T03:11:00.000Z]", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", … | 14 | F02 |
| q-3bed1ffea0 | triage T1003 step 6 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBumw-cX"} | None | F04 |
| q-0de9df3352 | triage T1003 step 6 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None | F02 |
| q-8df820fb17 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None |  |
| q-d0f39c9786 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-41cb6196bc | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None |  |
| q-db1ea3a5f0 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy4FbI2"} | None |  |
| q-0e66b1c70f | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy4FbI2"} | None |  |
| q-5359369e6b | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoZdz9r"} | None |  |
| q-2a96d35174 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-6928f6e242 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQkXH"} | None |  |
| q-f220753407 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-2c5db281bb | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-528698097e | triage T1003 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByEVwPJ"} | None |  |
| q-8a6a27b288 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuv5SEZ"} | None |  |
| q-e2f6029c0b | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBunxq2L"} | None |  |
| q-65069c52e0 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy1BJnq"} | None |  |
| q-06230066c8 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy1BJnq"} | None |  |
| q-332f7f3808 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBufr2nf"} | None |  |
| q-99015e6c38 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBumw-cX"} | None |  |
| q-f1612fc05e | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBumw-cX"} | None |  |
| q-e3156f5969 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBumw-cX"} | None |  |
| q-2f5a79100a | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoglALi"} | None |  |
| q-1bc43948dc | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoLO1t-"} | None |  |
| q-d14b4749c2 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoZdz8w"} | None |  |
| q-f9ad8635b5 | triage T1040 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*pktmon* OR process.command_line:*windump* OR process.command_line:*tcpdump* OR process.command_line:*rawcap* OR process.command_line:*netsh trace*)", "time_from": null, "time_to": … | 9 | F08 |
| q-788a253398 | triage T1040 step 1 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*pktmon* OR process.command_line:*netsh* OR process.command_line:*windump* OR process.command_line:*tcpdump* OR process.command_line:*rawcap*)", "time_from": null, "time_to": n… | 2 | F08 |
| q-10cc721beb | triage T1040 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND process.executable:*NetworkWatcherAgent*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "process.executable", "process.command_line", "win.Signed", "win.Signatur… | 4 | F08 |
| q-8195970416 | triage T1040 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:7 AND (win.ImageLoaded:*pcap* OR win.ImageLoaded:*npcap* OR win.ImageLoaded:*winpcap* OR win.ImageLoaded:*pktmon*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "proc… | 0 |  |
| q-b4c544d054 | triage T1040 step 3 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*pktmon* OR process.command_line:*promiscuous* OR process.command_line:*WinPcap* OR process.command_line:*npcap* OR process.command_line:*\"monitor mode\"* OR process.command_line:*… | 0 |  |
| q-807f4ae352 | triage T1040 step 3 | search | {"dataset": "windows.sysmon", "query": "event.code:13 AND (win.TargetObject:*pcap* OR win.TargetObject:*npcap* OR win.TargetObject:*WinPcap* OR win.TargetObject:*pktmon*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", … | 0 |  |
| q-732f4ece09 | triage T1040 step 4 | search | {"dataset": "zeek", "query": "event.action:notice OR event.action:weird", "time_from": null, "time_to": null, "fields": ["@timestamp", "event.action", "zeek.note", "zeek.msg", "zeek.peer", "source.ip", "destination.ip", "zeek.analyzer"], "size": 20, "sort": "a… | 14 |  |
| q-74c44de08a | triage T1040 step 4 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*.etl OR win.TargetFilename:*.etl)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "process.executable", "file.path", "win.TargetFilename"], "size": 2… | 38 |  |
| q-d56b2e06c6 | triage T1040 step 5 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*E7116ECA* OR win.TargetFilename:*E7116ECA* OR file.path:*B91E06C5* OR win.TargetFilename:*B91E06C5*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "process.exec… | 4 | F08 |
| q-473fbca517 | triage T1040 step 5 | aggregate | {"dataset": "zeek", "field": "destination.port", "query": "event.action:conn", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 613 |  |
| q-8c5d853fab | triage T1040 step 6 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.executable:*wireshark* OR process.executable:*dumpcap* OR process.executable:*tshark* OR process.executable:*windump* OR process.executable:*rawcap* OR process.executable:*pktmon* OR process.exe… | 0 |  |
| q-9f4c79c705 | triage T1040 step 6 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*pktmon* OR process.command_line:*dumpcap* OR process.command_line:*tshark* OR process.command_line:*wireshark* OR process.command_line:*promiscuous*)", "time_from": null, "tim… | 0 |  |
| q-32d8224020 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnvvDAD"} | None |  |
| q-ade8af63b0 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnvvDAD"} | None |  |
| q-e1dddb21ac | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnkjXIW"} | None |  |
| q-e84d74a167 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnaXZbG"} | None |  |
| q-7474bc6c31 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnaXZbG"} | None |  |
| q-171521436c | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBndb5l3"} | None |  |
| q-3d9f882233 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBncbMoA"} | None |  |
| q-800a91489c | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnooszM"} | None |  |
| q-74f104c886 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuYnMlG"} | None |  |
| q-31c75be9de | triage T1056 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND (win.GrantedAccess:0x1fffff OR win.GrantedAccess:0x101001 OR win.GrantedAccess:0x1f3fff OR win.GrantedAccess:0x1000000 OR win.GrantedAccess:0x3000 OR win.GrantedAccess:0x1400… | 33 | F09, F13 |
| q-0e8331c4eb | triage T1056 step 1 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXG"} | None | F09 |
| q-6d1b84d39c | triage T1056 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.pid:2976 OR win.ProcessId:2976 OR process.command_line:*lsass* OR process.command_line:*MiniDump* OR process.command_line:*ScreenCapture* OR process.command_line:*GetAsyncKeyState*)", "time_from… | 2 |  |
| q-268fc0290b | triage T1056 step 2 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRabqD"} | None | F10 |
| q-40bdab2b52 | triage T1056 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBorwtwa"} | None | F09 |
| q-f21898151c | triage T1056 step 3 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*MiniDump* OR win.ScriptBlockText:*monkey* OR win.ScriptBlockText:*IEX* OR win.ScriptBlockText:*GetPixel*)", "time_from": null, "time_to": null,… | 1 |  |
| q-49cce6dce9 | triage T1056 step 4 | search | {"dataset": "windows.security", "query": "event.code:(4656 OR 4663 OR 4688) AND (win.ObjectName:*lsass* OR process.command_line:*monkey* OR process.command_line:*IEX* OR process.command_line:*lsass*)", "time_from": null, "time_to": null, "fields": ["@timestamp… | 20 | F09, F13 |
| q-8c847efd90 | triage T1056 step 4 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND win.SourceImage:*wsmprovhost*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "process.executable", "process.command_line", "process.parent.execut… | 1 | F09 |
| q-07240dd9fe | triage T1056 step 5 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-1f6b1e5a35 | triage T1056 step 5 | search | {"dataset": "windows.security", "query": "event.code:(4624 OR 4688) AND (win.TargetUserName:pbeesly OR win.SubjectUserName:pbeesly) AND host.name:nashua.dmevals.local", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "us… | 57 |  |
| q-892e2967de | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXG"} | None |  |
| q-d2e7e0918c | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXG"} | None |  |
| q-5a9f1d1e4f | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None |  |
| q-b159328329 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-af1a2a396f | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBorwtwa"} | None |  |
| q-7b2f56763c | triage T1056 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy0A4ua"} | None |  |
| q-16d7c7d317 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy0A4uc"} | None |  |
| q-0df89bb697 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-aa4df3b015 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBux8Gu0"} | None |  |
| q-27a4186200 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRabqD"} | None |  |
| q-ad289bd252 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRabqD"} | None |  |
| q-4f59ab9b9d | triage T1056 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRZ7r5"} | None |  |
| q-b1dee26b25 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBov0sHE"} | None |  |
| q-0be33fda74 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByXfnRy"} | None |  |
| q-0e8a65ab15 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnrrZmZ"} | None |  |
| q-c6e4f15856 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBudppHE"} | None |  |
| q-77fb8c72bc | triage T1110 step 1 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": "win.GrantedAccess"} | 326 |  |
| q-62a164b274 | triage T1110 step 1 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4663 AND (win.ObjectName:*Lsa* OR win.ObjectName:*SAM* OR win.ObjectName:*Winlogon*)", "time_from": null, "time_to": null, "size": 50, "sub_field": "win.ObjectName"} | 2311 |  |
| q-a1160a3df2 | triage T1110 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND (win.GrantedAccess:0x1fffff OR win.GrantedAccess:0x1f3fff OR process.executable:*wsmprovhost* OR process.executable:*wininit* OR process.executable:*csrss*)", "time_from": nu… | 6 | F16 |
| q-e47895b6dd | triage T1110 step 2 | search | {"dataset": "windows.security", "query": "event.code:4663 AND (process.executable:*PsExec64* OR process.executable:*PSEXESVC* OR process.executable:*sdelete64* OR process.executable:*logman* OR process.executable:*dsregcmd*)", "time_from": null, "time_to": nul… | 30 | F16 |
| q-b618d396bf | triage T1110 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None | F16 |
| q-f2f62cf7c5 | triage T1110 step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == 4104 AND host.name == \"scranton.dmevals.local\" AND @timestamp >= \"2020-05-02T03:00:00.000Z\" AND @timestamp <= \"2020-05-02T03:10:00.000Z\" \| KEEP @timestamp, host.… | ERROR |  |
| q-835d534fe5 | triage T1110 step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND host.name == \"scranton.dmevals.local\" AND @timestamp >= \"2020-05-02T03:00:00.000Z\" AND @timestamp <= \"2020-05-02T03:10:00.000Z\" \| KEEP @timestamp, h… | 20 |  |
| q-63efbf2712 | triage T1110 step 4 | count | {"dataset": "windows.security", "query": "event.code:4625 OR event.code:4771 OR event.code:4776 OR event.code:4740", "time_from": null, "time_to": null} | 1 |  |
| q-d1390983c3 | triage T1110 step 5 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 20, "sub_field": "win.TargetUserName"} | 297 |  |
| q-1c343f5e0f | triage T1110 step 5 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*Invoke-Command* OR process.command_line:*NASHUA* OR process.command_line:*PsExec* OR process.command_line:*sdelete*)", "time_from": null, "time_to": null, "fields": ["@timestamp", … | 10 | F17 |
| q-986f7d2501 | triage T1110 step 6 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Fl0nk3rt0n* OR win.ScriptBlockText:*Get-Credential* OR win.ScriptBlockText:*Invoke-Command* OR win.ScriptBlockText:*New-Object*System.Net* OR win.ScriptBlockText:*Password*)"… | 7 | F15, F17, F18 |
| q-2fdaf3dd46 | triage T1110 step 6 | search | {"dataset": "windows.security", "query": "event.code:4776 OR (event.code:4624 AND win.LogonType:10)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "win.TargetUserName", "win.LogonType", "win.IpAddress", "win.Workstatio… | 3 | F14 |
| q-348e95d91b | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuTlU_q"} | None |  |
| q-c50f2fad8a | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuTlU_q"} | None |  |
| q-8da855d2ee | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBudppFY"} | None |  |
| q-618e0b3ae9 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBi85SQC"} | None |  |
| q-696323fa1d | triage T1110 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-a892a7b98e | triage T1110 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-a7d6c582ae | triage T1110 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-180820edac | triage T1110 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None |  |
| q-868c66d97c | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy1B5lE"} | None |  |
| q-0d56a9e366 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBizx7sV"} | None |  |
| q-c68a21ee03 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoz4z4i"} | None |  |
| q-84a229783f | triage T1110 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByEVwPJ"} | None |  |
| q-5532f22146 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByCVdVX"} | None |  |
| q-565aa3ef8e | triage T1110 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByPYrDh"} | None |  |
| q-fa6da31bc1 | triage T1111 step 1 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND win.TargetImage:*lsass.exe", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-7c2b0222af | triage T1111 step 1 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass.exe", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-cb0a015528 | triage T1111 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass.exe AND (win.GrantedAccess:0x1fffff OR win.GrantedAccess:0x101001 OR win.GrantedAccess:0x1f3fff OR win.GrantedAccess:0x1000000 OR win.GrantedAccess:0x3000)", "time_from": null, "t… | 9 | F19, F20, F21 |
| q-4a077109b4 | triage T1111 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass.exe AND process.executable:*PowerShell.exe", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "process.executable", "process.command_line", "… | 2 |  |
| q-0429e39fbe | triage T1111 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None | F19 |
| q-d24a60e5d5 | triage T1111 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None | F19 |
| q-f19d6e5206 | triage T1111 step 4 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND process.pid:2976", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "process.executable", "process.command_line", "process.parent.executable", "process.parent.comman… | 1 | F19 |
| q-4322e8e879 | triage T1111 step 4 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None | F20 |
| q-adbd812d76 | triage T1111 step 5 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*MiniDump* OR win.ScriptBlockText:*Credential* OR win.ScriptBlockText:*token* OR win.ScriptBlockText:*AAD* OR win.ScriptBlockText:*MFA*)", "time… | 4 |  |
| q-7c2edc99fb | triage T1111 step 5 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND process.executable:*wsmprovhost.exe", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "process.executable", "process.command_line", "process.parent.executable", "pr… | 1 | F20 |
| q-6d8504818f | triage T1111 step 6 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND host.name:scranton.dmevals.local AND (win.ScriptBlockText:*monkey* OR win.ScriptBlockText:*GetPixel* OR win.ScriptBlockText:*IEX*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "h… | 1 | F19 |
| q-fdd14252a5 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-aae8209cdc | triage T1111 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-d0d7c02b3d | triage T1111 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None |  |
| q-0c15bad5da | triage T1111 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None |  |
| q-0a2eb600d8 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBorwtwa"} | None |  |
| q-939b66bc1d | triage T1111 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBorwtwa"} | None |  |
| q-b2b9a1383a | triage T1111 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByYf10Q"} | None |  |
| q-959270ffd9 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-5b5918daa2 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-04bba4d525 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBo05D7L"} | None |  |
| q-a6e98f133a | triage T1111 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuu5GRH"} | None |  |
| q-a863636599 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnaXZbs"} | None |  |
| q-618022223c | triage T1111 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnqqYet"} | None |  |
| q-514537e2eb | triage T1111 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnrrZmZ"} | None |  |
| q-c82c094fc3 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnTPq-O"} | None |  |
| q-df9a374dbc | triage T1111 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeBwdLx2Z"} | None |  |
| q-05b413e1fa | triage T1187 step 1 | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgR9D"} | None | F22 |
| q-90298829a3 | triage T1187 step 1 | aggregate | {"dataset": "zeek", "field": "http.request.method", "query": "event.action:http", "time_from": null, "time_to": null, "size": 30, "sub_field": "url.domain"} | 62 |  |
| q-8106068447 | triage T1187 step 1 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:3 AND (destination.port:445 OR destination.port:139)", "time_from": null, "time_to": null, "size": 30, "sub_field": "host.name"} | 66 |  |
| q-a84ce99ff0 | triage T1187 step 2 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"http\" AND http.request.method IN (\"PROPFIND\",\"OPTIONS\",\"PROPPATCH\",\"PUT\",\"LOCK\",\"UNLOCK\",\"HEAD\") \| KEEP @timestamp, source.ip, destination.ip, http.request.method… | 40 | F22 |
| q-3f2108a9f5 | triage T1187 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 3 AND (destination.port == 445 OR destination.port == 139) \| KEEP @timestamp, host.name, process.executable, destination.ip, destination.port, user.name, _id, _index \| SO… | ERROR |  |
| q-e397706e13 | triage T1187 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"3\" AND (destination.port == \"445\" OR destination.port == \"139\") \| KEEP @timestamp, host.name, process.executable, destination.ip, destination.port, user.name, _id, … | ERROR |  |
| q-0773003ab2 | triage T1187 step 3 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action IN (\"notice\",\"weird\",\"smb_files\",\"smb_mapping\") \| KEEP @timestamp, event.action, source.ip, destination.ip, destination.port, zeek.note, zeek.msg, zeek.name, zeek.path, zeek.… | 37 | F22 |
| q-1fdca5fe97 | triage T1187 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"3\" AND (destination.port == 445 OR destination.port == 139) \| KEEP @timestamp, host.name, process.executable, destination.ip, destination.port, user.name, _id, _index \… | 66 | F22 |
| q-83c72233ff | triage T1187 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(win.TargetFilename) LIKE \"*.lnk\" OR TO_LOWER(win.TargetFilename) LIKE \"*.scf\" OR TO_LOWER(win.TargetFilename) LIKE \"*.url\" OR TO_LOWER(win.Target… | 3 | F22 |
| q-a64a214b63 | triage T1187 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE (event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*webdav*\" OR TO_LOWER(process.command_line) LIKE \"*net use*\" OR TO_LOWER(process.command_line) LIKE \"*\\\\\\\\*\")) OR… | 40 |  |
| q-6e24011934 | triage T1187 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND process.executable LIKE \"*powershell*\" \| KEEP @timestamp, host.name, process.executable, process.command_line, process.parent.executable, user.name, _id, _inde… | 12 |  |
| q-b9f4bf0ea7 | triage T1187 step 6 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4624\" AND win.LogonType == \"3\" \| KEEP @timestamp, host.name, win.TargetUserName, win.AuthenticationPackageName, win.IpAddress, win.Workstation, win.LogonProcessName… | 60 | F22 |
| q-2286abd546 | triage T1187 step 6 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*webdav*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*ntlm*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*\\\\\\\\*\" OR T… | 20 |  |
| q-b3415d2c4b | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgR9D"} | None |  |
| q-e6cdbd8204 | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgh8V"} | None |  |
| q-01b202faf9 | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgh8V"} | None |  |
| q-f2a26a6503 | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgR8h"} | None |  |
| q-8cbbca8b23 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoSWKN8"} | None |  |
| q-be262e35a6 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoOSXoo"} | None |  |
| q-5c7d60acea | triage T1187 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy8KXgk"} | None |  |
| q-8fe99ba4d7 | triage T1212 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND (win.SourceImage:*PowerShell* OR win.SourceImage:*wsmprovhost* OR win.SourceImage:*wininit* OR win.SourceImage:*csrss* OR win.SourceImage:*services*)", "time_from": null, "ti… | 9 | F23 |
| q-8b2a126d78 | triage T1212 step 1 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 30, "sub_field": "win.SourceImage"} | 326 |  |
| q-d60dc61b13 | triage T1212 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None |  |
| q-5d70b4303c | triage T1212 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-7f45343856 | triage T1212 step 3 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*MiniDump* OR win.ScriptBlockText:*comsvcs* OR win.ScriptBlockText:*Credential* OR win.ScriptBlockText:*Invoke-Mimikatz* OR win.ScriptBlockText:… | 3 | F23 |
| q-861189748f | triage T1212 step 3 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*lsass* OR process.command_line:*MiniDump* OR process.command_line:*comsvcs* OR process.command_line:*procdump* OR process.command_line:*sekurlsa* OR process.command_line:*DumpCred*… | 1 |  |
| q-57f15c5fcb | triage T1212 step 4 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.executable:*powershell* OR process.executable:*python* OR process.executable:*PsExec* OR process.executable:*sdelete* OR process.executable:*PSEXESVC*)", "time_from": null, "time_to": null, "fie… | 31 | F23 |
| q-5b8f24ce33 | triage T1212 step 4 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByPYrDh"} | None |  |
| q-08485d9687 | triage T1212 step 5 | search | {"dataset": "windows.powershell", "query": "host.name:(scranton.dmevals.local OR nashua.dmevals.local) AND event.code:(4104 OR 4103 OR 800) AND @timestamp:[2020-05-02T03:04:00.000Z TO 2020-05-02T03:12:00.000Z]", "time_from": null, "time_to": null, "fields": ["… | 4062 |  |
| q-266ccd36a8 | triage T1212 step 6 | search | {"dataset": "windows.powershell", "query": "win.Message:(*lsass* OR *MiniDump* OR *comsvcs* OR *sekurlsa* OR *DumpCred* OR *Credential* OR *Get-Process*lsass*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "user.name… | 38 |  |
| q-ff724b8103 | triage T1212 step 7 | search | {"dataset": "windows.security", "query": "event.code:(4624 OR 4672 OR 4648 OR 4688) AND host.name:(nashua.dmevals.local OR scranton.dmevals.local) AND @timestamp:[2020-05-02T03:08:00.000Z TO 2020-05-02T03:14:00.000Z] AND (win.TargetUserName:pbeesly OR user.nam… | 51 | F23 |
| q-eaee04f321 | triage T1212 step 8 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None | F23 |
| q-4a20eaf77e | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None |  |
| q-6402516f27 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None |  |
| q-fa2b5dde88 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-2d9eea8726 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-0343c0e0d4 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-37c49ba126 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-b55eb296c2 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoz4z4i"} | None |  |
| q-540708ef7d | triage T1212 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByPYrDh"} | None |  |
| q-aa71bbcf3c | triage T1212 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuv5SEZ"} | None |  |
| q-684b371e0d | triage T1539 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByPYrDh"} | None | F24 |
| q-6e9fa8514c | triage T1539 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRarqU"} | None |  |
| q-f84a58df14 | triage T1539 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*cookies*\" OR TO_LOWER(file.path) LIKE \"*login data*\" OR TO_LOWER(file.path) LIKE \"*web data*\" OR TO_LOWER(file.path) LIKE \"*co… | 1 | F24 |
| q-7ddbc99f22 | triage T1539 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND (TO_LOWER(win.TargetImage) LIKE \"*chrome*\" OR TO_LOWER(win.TargetImage) LIKE \"*firefox*\" OR TO_LOWER(win.TargetImage) LIKE \"*iexplore*\" OR TO_LOWER(win.Tar… | 374 | F24 |
| q-94fb305ad9 | triage T1539 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND TO_LOWER(process.executable) LIKE \"*python*\" \| STATS cnt = COUNT(*) BY process.executable, win.TargetImage, win.GrantedAccess, host.name \| SORT cnt DESC \| L… | 3 |  |
| q-38dd34b5c7 | triage T1539 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE (event.code == \"11\" OR event.code == \"23\" OR event.code == \"1\") AND (TO_LOWER(file.path) LIKE \"*user data*\" OR TO_LOWER(file.path) LIKE \"*appdata*google*\" OR TO_LOWER(file.path… | 0 |  |
| q-a8353a6c02 | triage T1539 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE TO_LOWER(process.executable) LIKE \"*python*\" OR TO_LOWER(process.parent.executable) LIKE \"*python*\" \| KEEP @timestamp, host.name, user.name, event.code, process.executable, process.… | 40 |  |
| q-7c21faf5da | triage T1539 step 4 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE (event.code == \"4663\" OR event.code == \"5145\" OR event.code == \"4656\") AND (TO_LOWER(win.ObjectName) LIKE \"*cookies*\" OR TO_LOWER(win.ObjectName) LIKE \"*login data*\" OR TO_LO… | 0 |  |
| q-5b4b175941 | triage T1539 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"3\" AND TO_LOWER(process.executable) LIKE \"*python*\" \| KEEP @timestamp, host.name, user.name, process.executable, destination.ip, destination.port, network.transport, … | 20 | F24 |
| q-af4b29203a | triage T1539 step 5 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*cookie*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*session*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*token*\" OR T… | 3 |  |
| q-3cd882cedd | triage T1539 step 6 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND user.name == \"pbeesly\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*cookie*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*session*\" OR TO_LOWER(win.ScriptBlo… | 7 | F24 |
| q-80e54ff487 | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBi-6ySm"} | None |  |
| q-bf27ea7c74 | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBizxbvb"} | None |  |
| q-0b301e6a6b | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBizx7sR"} | None |  |
| q-2a502e3d52 | triage T1539 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByEVwPJ"} | None |  |
| q-7b4531d7e4 | triage T1539 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByPYrDh"} | None |  |
| q-79b651bb91 | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnaX5as"} | None |  |
| q-9c2d214561 | triage T1552 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None | F25, F26 |
| q-587074facd | triage T1552 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByPYrDh"} | None | F26 |
| q-e21cd0d4b2 | triage T1552 step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 11 AND (TO_LOWER(win.TargetFilename) LIKE \"*.pfx\" OR TO_LOWER(win.TargetFilename) LIKE \"*.p12\" OR TO_LOWER(win.TargetFilename) LIKE \"*.pem\" OR TO_LOWER(win.TargetFile… | ERROR |  |
| q-95c4292fb3 | triage T1552 step 1 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == 4104 AND (TO_LOWER(win.ScriptBlockText) LIKE \"*get-privatekeys*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*cert:\\\\localmachine*\" OR TO_LOWER(win.ScriptBlockText) LI… | ERROR |  |
| q-ab6f7987d5 | triage T1552 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 11 AND (TO_LOWER(win.TargetFilename) LIKE \"*.pfx\" OR TO_LOWER(win.TargetFilename) LIKE \"*.p12\" OR TO_LOWER(win.TargetFilename) LIKE \"*.pem\" OR TO_LOWER(win.TargetFile… | ERROR |  |
| q-deb7088f58 | triage T1552 step 2 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == 4104 AND (TO_LOWER(win.ScriptBlockText) LIKE \"*get-privatekeys*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*export-pfxcertificate*\" OR TO_LOWER(win.ScriptBlockText) LI… | ERROR |  |
| q-59b205ef9f | triage T1552 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(win.TargetFilename) LIKE \"*.pfx\" OR TO_LOWER(win.TargetFilename) LIKE \"*.p12\" OR TO_LOWER(win.TargetFilename) LIKE \"*.pem\" OR TO_LOWER(win.Target… | 4 | F25, F26 |
| q-f3fc6783bd | triage T1552 step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*get-privatekeys*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*export-pfxcertificate*\" OR TO_LOWER(win.ScriptBlockText… | 6 |  |
| q-e604dea39d | triage T1552 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*reg*\" OR TO_LOWER(process.command_line) LIKE \"*history*\" OR TO_LOWER(process.command_line) LIKE \"*groups.xml*\" OR TO_… | 8 | F29 |
| q-b3f4db22a3 | triage T1552 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"13\" AND (TO_LOWER(registry.path) LIKE \"*winlogon*\" OR TO_LOWER(registry.path) LIKE \"*lsa*\" OR TO_LOWER(registry.path) LIKE \"*defaultpassword*\" OR TO_LOWER(registry… | ERROR |  |
| q-ab8f0beac6 | triage T1552 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"13\" AND (TO_LOWER(registry.path) LIKE \"*winlogon*\" OR TO_LOWER(registry.path) LIKE \"*lsa*\" OR TO_LOWER(registry.path) LIKE \"*defaultpassword*\" OR TO_LOWER(registry… | ERROR |  |
| q-a999f11f0d | triage T1552 step 5 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4648\" \| KEEP @timestamp, host.name, user.name, process.executable, win.TargetServerName, win.TargetUserName, win.SubjectUserName, source.ip, _id, _index \| SORT @time… | 15 | F27 |
| q-96f7eac6f7 | triage T1552 step 6 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"13\" AND (TO_LOWER(registry.path) LIKE \"*winlogon*\" OR TO_LOWER(registry.path) LIKE \"*lsa*\" OR TO_LOWER(registry.path) LIKE \"*defaultpassword*\" OR TO_LOWER(registry… | 17 | F28 |
| q-f69a49b7ee | triage T1552 step 6 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(win.TargetFilename) LIKE \"*consolehost_history*\" OR TO_LOWER(win.TargetFilename) LIKE \"*groups.xml*\" OR TO_LOWER(win.TargetFilename) LIKE \"*sysvol… | 22 | F30 |
| q-ccb02ab568 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-699d0de42e | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-ae2c4d2d11 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-bd950fc791 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQkXH"} | None |  |
| q-801b12d9b7 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQkXH"} | None |  |
| q-4f3056f13d | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByPYrDh"} | None |  |
| q-3b6bd7f432 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByPYrDh"} | None |  |
| q-d2ddf93947 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-b6dff63032 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBo05T5k"} | None |  |
| q-059c6e9499 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeBwdLx2Z"} | None |  |
| q-c1b89aa228 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeBwdMB0i"} | None |  |
| q-4bb0f1b03b | triage T1552 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuu5GRH"} | None |  |
| q-8a0a5c0dc1 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBunxq0T"} | None |  |
| q-5c41e24388 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeBunxq0T"} | ERROR |  |
| q-8e5d938121 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnaXZbu"} | None |  |
| q-573702336e | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoKOGL_"} | None |  |
| q-3070340db6 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBi85CSh"} | None |  |
| q-0a646b0044 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoGKqgM"} | None |  |
| q-37601268f2 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoTWpZy"} | None |  |
| q-1e48aa07bf | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn56HkU"} | None |  |
| q-53d1cd17d4 | triage T1555 step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 10 AND win.TargetImage LIKE \"*lsass*\" AND win.GrantedAccess IN (\"0x1fffff\",\"0x101001\",\"0x1f3fff\",\"0x1000000\",\"0x3000\",\"0x1400\") \| KEEP @timestamp, host.name,… | ERROR |  |
| q-b512256bd5 | triage T1555 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByPYrDh"} | None | F34 |
| q-e2eb56940b | triage T1555 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND win.TargetImage LIKE \"*lsass*\" AND win.GrantedAccess != \"0x1000\" \| KEEP @timestamp, host.name, process.executable, process.command_line, win.GrantedAccess, … | 33 | F31, F33 |
| q-4bd10ba958 | triage T1555 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND win.TargetImage LIKE \"*lsass*\" AND process.executable LIKE \"*powershell*\" \| KEEP @timestamp, host.name, process.executable, process.command_line, win.Grante… | 2 |  |
| q-c18fa49215 | triage T1555 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None | F31 |
| q-c45c9e14f6 | triage T1555 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-9c92d52dfd | triage T1555 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-90c21448c2 | triage T1555 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND host.name == \"scranton.dmevals.local\" \| KEEP @timestamp, host.name, process.executable, process.command_line, process.parent.executable, user.name, _id, _index… | 359 | F31 |
| q-4c1027d422 | triage T1555 step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*lsass*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*minidump*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*sekurlsa*\" O… | 5 |  |
| q-2230b3b2b2 | triage T1555 step 5 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE host.name == \"scranton.dmevals.local\" AND event.code == \"4104\" \| KEEP @timestamp, user.name, win.Path, win.ScriptBlockId, win.ScriptBlockText, _id, _index \| SORT @timestamp ASC… | 146 |  |
| q-a581369e20 | triage T1555 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (file.path LIKE \"*Login Data*\" OR file.path LIKE \"*logins.json*\" OR file.path LIKE \"*key4.db*\" OR file.path LIKE \"*Cookies*\" OR file.path LIKE \"*Web Dat… | 1 | F32 |
| q-6ce35b5efa | triage T1555 step 6 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE host.name == \"scranton.dmevals.local\" AND event.code == \"4104\" AND @timestamp > \"2020-05-02T03:01:51.000Z\" \| KEEP @timestamp, user.name, win.ScriptBlockText, _id, _index \| SO… | 106 |  |
| q-3690c8852e | triage T1555 step 6 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE host.name == \"nashua.dmevals.local\" AND event.code == \"1\" \| KEEP @timestamp, process.executable, process.command_line, process.parent.executable, user.name, _id, _index \| SORT @tim… | 61 | F33 |
| q-851d07f079 | triage T1555 step 7 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None | F31 |
| q-f1e5a5a1b3 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None |  |
| q-4cead78849 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None |  |
| q-66998c2c4b | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None |  |
| q-6723adb779 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-df253a4b2e | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBow1KRR"} | None |  |
| q-c6703672b1 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-9995ee071a | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBi-6ySm"} | None |  |
| q-bc4cd50ab1 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBi-6ySm"} | None |  |
| q-aae4232060 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-1d06ee409c | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-d3a6b254cf | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoz4j7h"} | None |  |
| q-cbe4357f3b | triage T1555 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeBwdMB1A"} | None |  |
| q-8da590e747 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByPYrDh"} | None |  |
| q-4aef7ab8c6 | triage T1556 step 1 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 40, "sub_field": "win.GrantedAccess"} | 326 |  |
| q-93dd8be46e | triage T1556 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND win.TargetFilename:*passwordsDB*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.c… | 1 | F37 |
| q-d702859970 | triage T1556 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND (process.executable:*PowerShell* OR process.executable:*wsmprovhost* OR process.executable:*wininit* OR process.executable:*csrss*)", "time_from": null, "time_to": null, "fie… | 8 | F36 |
| q-856240609f | triage T1556 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:7 AND win.ImageLoaded:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_lin… | 1 | F37 |
| q-aeb82104e7 | triage T1556 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None | F35, F41 |
| q-fe0639e9fd | triage T1556 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None | F35, F41 |
| q-20d82af1c0 | triage T1556 step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == 4104 AND (TO_LOWER(win.ScriptBlockText) LIKE \"*lsass*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*minidump*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*procdump*\" OR TO… | ERROR |  |
| q-6fb3ecead0 | triage T1556 step 4 | aggregate | {"dataset": "windows.sysmon", "field": "process.command_line", "query": "event.code:1 AND (process.command_line:*lsass* OR process.command_line:*dump* OR process.command_line:*sekurlsa* OR process.command_line:*minidump*)", "time_from": null, "time_to": null, … | 1 |  |
| q-bc007eb6fe | triage T1556 step 5 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*lsass*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*minidump*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*procdump*\" O… | 0 |  |
| q-2fe8d90d06 | triage T1556 step 5 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND process.executable:*PowerShell*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "process.command_line", "process.parent.executable"], "size": 30, "sort": "asc"} | 12 | F35 |
| q-578e3b27cf | triage T1556 step 6 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4657", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 36 |  |
| q-d088f84693 | triage T1556 step 6 | aggregate | {"dataset": "windows.security", "field": "win.PrivilegeList", "query": "event.code:4673 OR event.code:4674", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 989 |  |
| q-2717e5b199 | triage T1556 step 7 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuWmJMP"} | None | F35, F36 |
| q-4f7712ec3f | triage T1556 step 7 | search | {"dataset": "windows.security", "query": "event.code:4662 OR event.code:5136", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "win.ObjectType", "win.ObjectName", "win.Properties", "win.AccessMask", "win.SubjectUserName"]… | 7 | F39 |
| q-0f3e8bb2b3 | triage T1556 step 8 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.executable:*python* OR process.parent.executable:*python*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "process.executable", "process.command_line", … | 11 | F35 |
| q-69478f2fc3 | triage T1556 step 8 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (win.TargetFilename:*.dmp OR win.TargetFilename:*lsass* OR win.TargetFilename:*Temp*.zip OR win.TargetFilename:*Draft*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "proce… | 3 |  |
| q-15f129c962 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-b83abbf3a2 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-402bc3e93d | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBorwtwa"} | None |  |
| q-e6e3af15c2 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBizx7td"} | None |  |
| q-27fb0822bc | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoz4j7h"} | None |  |
| q-0235b75433 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuWmJMP"} | None |  |
| q-9683152dc2 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None |  |
| q-c609dc2f64 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuWmJMP"} | None |  |
| q-9f157fdfd1 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoNRGHl"} | None |  |
| q-960f57aa85 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnZW8l5"} | None |  |
| q-37342c0577 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByUbwtm"} | None |  |
| q-bec2057dff | triage T1556 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy1BJnq"} | None |  |
| q-ff1bbf0df9 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeBwdMB0i"} | None |  |
| q-56cd920303 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeBwdLx2Z"} | None |  |
| q-0cbd606051 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-0d31d6fc84 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-478badadae | triage T1557 step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 3 AND (destination.port == 445 OR destination.port == 139) \| KEEP @timestamp, host.name, process.executable, destination.ip, destination.port, user.name, _id, _index \| SO… | ERROR |  |
| q-5a300a7593 | triage T1557 step 1 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == 4697 \| KEEP @timestamp, host.name, win.ServiceName, win.ServiceFileName, win.ServiceAccount, user.name, _id, _index \| SORT @timestamp ASC \| LIMIT 30"} | ERROR |  |
| q-f536ada267 | triage T1557 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"3\" AND (destination.port == \"445\" OR destination.port == \"139\") \| KEEP @timestamp, host.name, process.executable, destination.ip, destination.port, user.name, _id, … | ERROR |  |
| q-a762472d81 | triage T1557 step 2 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4697\" \| KEEP @timestamp, host.name, win.ServiceName, win.ServiceFileName, win.ServiceAccount, user.name, _id, _index \| SORT @timestamp ASC \| LIMIT 30"} | 23 | F43 |
| q-d2b2ec6bb5 | triage T1557 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"3\" AND (destination.port == 445 OR destination.port == 139) \| KEEP @timestamp, host.name, process.executable, destination.ip, destination.port, user.name, _id, _index \… | 66 | F43, F44 |
| q-c2ca5fa14d | triage T1557 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*psexec*\" OR TO_LOWER(process.executable) LIKE \"*psexesvc*\" OR TO_LOWER(process.command_line) LIKE \"*javamtsup*\" OR TO… | 9 | F42, F45 |
| q-6ed57d0161 | triage T1557 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (process.executable LIKE \"*python*\" OR process.parent.executable LIKE \"*python*\" OR process.executable LIKE \"*javamtsup*\" OR process.parent.executable LIKE … | 13 |  |
| q-7e03cf9a1b | triage T1557 step 4 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4624\" AND win.LogonProcessName LIKE \"*NtLmSsp*\" \| KEEP @timestamp, host.name, win.TargetUserName, win.LogonProcessName, win.LogonType, win.IpAddress, win.Workstatio… | 1 |  |
| q-dda326993b | triage T1557 step 5 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*invoke-mimikatz*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*sekurlsa*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*lsa… | 4 |  |
| q-e3c6ad89bf | triage T1557 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"3\" AND destination.ip == \"172.18.39.2\" \| KEEP @timestamp, host.name, process.executable, destination.ip, destination.port, user.name, _id, _index \| SORT @timestamp A… | 30 |  |
| q-a8d1d4011a | triage T1557 step 6 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBufr2mI"} | None | F43 |
| q-7feda4e3d2 | triage T1557 step 6 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnlkXpm"} | None | F42 |
| q-f16ddc0b51 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnlkXpm"} | None |  |
| q-8cce2c18dc | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn55Xmr"} | None |  |
| q-b39d4229e2 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn66XZS"} | None |  |
| q-af75ec4abd | triage T1557 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBufr2mI"} | None |  |
| q-0b55533ba4 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuq1HQ4"} | None |  |
| q-daac5edb19 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoSWKN8"} | None |  |
| q-501ffeb717 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoXbqXA"} | None |  |
| q-8fd043fc11 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn4413G"} | None |  |
| q-98e7864e0d | triage T1558 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass.exe AND (win.GrantedAccess:0x1fffff OR win.GrantedAccess:0x101001 OR win.GrantedAccess:0x1f3fff OR win.GrantedAccess:0x1000000 OR win.GrantedAccess:0x3000 OR win.GrantedAccess:0x1… | 33 |  |
| q-8d5f19f746 | triage T1558 step 1 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND win.TargetImage:*lsass.exe", "time_from": null, "time_to": null, "size": 30, "sub_field": "win.GrantedAccess"} | 326 |  |
| q-20d1b13f4b | triage T1558 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None | F46 |
| q-ed934a40c6 | triage T1558 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None | F46 |
| q-8822564560 | triage T1558 step 2 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*lsass*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*kerberos*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*ticket*\" OR … | 16 |  |
| q-48a91ef4ea | triage T1558 step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND host.name == \"scranton.dmevals.local\" AND @timestamp >= \"2020-05-02T03:03:00.000Z\" AND @timestamp <= \"2020-05-02T03:11:00.000Z\" \| KEEP @timestamp, u… | 20 | F46 |
| q-dc3e061ee9 | triage T1558 step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND host.name == \"scranton.dmevals.local\" AND @timestamp >= \"2020-05-02T03:03:30.000Z\" AND @timestamp <= \"2020-05-02T03:06:30.000Z\" \| KEEP @timestamp, u… | 20 | F46 |
| q-6ad41a2e97 | triage T1558 step 4 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy4FbJD"} | None | F47 |
| q-ecebfcd65e | triage T1558 step 5 | aggregate | {"dataset": "windows.security", "field": "win.ServiceName", "query": "event.code:4769", "time_from": null, "time_to": null, "size": 30, "sub_field": "win.TicketEncryptionType"} | 28 |  |
| q-af5a860328 | triage T1558 step 5 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuu5GRH"} | None | F49 |
| q-4e00417a0b | triage T1558 step 6 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"kerberos\" \| KEEP @timestamp, zeek.request_type, zeek.client, zeek.service, zeek.success, zeek.error_msg, zeek.cipher, zeek.forwardable, zeek.renewable, source.ip, destination.i… | 35 | F49, F50 |
| q-ba2fbe4a76 | triage T1558 step 6 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4672\" \| STATS c = COUNT(*) BY win.SubjectUserName, host.name \| SORT c DESC \| LIMIT 20"} | 12 |  |
| q-eab0fbc161 | triage T1558 step 7 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4769\" \| STATS c = COUNT(*) BY win.ServiceName, win.TargetUserName, win.TicketEncryptionType \| SORT c DESC \| LIMIT 30"} | 8 |  |
| q-afc2a9014a | triage T1558 step 7 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4624\" AND win.TargetUserName == \"pbeesly\" \| STATS c = COUNT(*) BY win.LogonType, win.AuthenticationPackageName, host.name \| SORT c DESC \| LIMIT 20"} | 5 |  |
| q-b08c6059cf | triage T1558 step 8 | count | {"dataset": "windows.security", "query": "event.code:(4768 OR 4771 OR 4770)", "time_from": null, "time_to": null} | 14 |  |
| q-82d8c62714 | triage T1558 step 8 | count | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*rubeus* OR process.command_line:*kerberoast* OR process.command_line:*asrep* OR process.command_line:*GetNPUsers* OR process.command_line:*mimikatz* OR process.command_line:*sekurl… | 0 |  |
| q-e8ec4a8fbe | triage T1558 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-01c5290bd8 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None |  |
| q-251fe00377 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-cb58ccce36 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-632887bc38 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRarq9"} | None |  |
| q-3fa96bf12b | triage T1558 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByDV_QB"} | None |  |
| q-fb6bd9dc20 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy4FbJD"} | None |  |
| q-0beb5e62ef | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy4FbJD"} | None |  |
| q-ab65e2aa37 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy4FbJD"} | None |  |
| q-b3914a8acc | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy8J3fS"} | None |  |
| q-7ee0d3bbb9 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuv5SEr"} | None |  |
| q-2592e19ac2 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuu5GRH"} | None |  |
| q-94bb87d706 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuu5GRH"} | None |  |
| q-66828789ed | triage T1558 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgR8n"} | None |  |
| q-76523f2047 | triage T1558 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgR8n"} | None |  |
| q-204e0f817e | triage T1558 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgR8m"} | None |  |
| q-1d4258952b | triage T1558 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgh9H"} | None |  |
| q-8ffc39c626 | triage T1606 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND win.TargetFilename:*.pfx", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_l… | 1 | F51 |
| q-bc9ad6c418 | triage T1606 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND (win.GrantedAccess:0x1fffff OR win.GrantedAccess:0x101001 OR win.GrantedAccess:0x1f3fff OR win.GrantedAccess:0x1000000 OR win.GrantedAccess:0x3000)", "time_from": null, "time… | 9 | F53 |
| q-d02b268b7b | triage T1606 step 2 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND host.name:scranton.dmevals.local AND @timestamp:[2020-05-02T03:00:00.000Z TO 2020-05-02T03:10:00.000Z]", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", … | 99 |  |
| q-a878259052 | triage T1606 step 2 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaboq"} | None |  |
| q-e2c4bb2194 | triage T1606 step 3 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND @timestamp:[2020-05-02T03:03:00.000Z TO 2020-05-02T03:07:00.000Z]", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.… | 43 |  |
| q-f0a62fdde7 | triage T1606 step 3 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*AADInternals* OR win.ScriptBlockText:*New-AADInt* OR win.ScriptBlockText:*Get-AADInt* OR win.ScriptBlockText:*Open-AADInt* OR win.ScriptBlockText:*pfx* OR win.ScriptBlockText… | 4 |  |
| q-1623f33a96 | triage T1606 step 4 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None | F51 |
| q-272f41c77c | triage T1606 step 4 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*ADFS* OR win.ScriptBlockText:*adfs* OR win.ScriptBlockText:*Golden* OR win.ScriptBlockText:*DKM* OR win.ScriptBlockText:*EncryptedPFX* OR win.ScriptBlockText:*Get-PrivateKeys… | 4 | F51 |
| q-3e10606af0 | triage T1606 step 5 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByPYrDh"} | None | F51 |
| q-76b9f4589e | triage T1606 step 5 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*AADInternals* OR win.ScriptBlockText:*New-AADIntSAMLToken* OR win.ScriptBlockText:*Get-AADIntAccessToken* OR win.ScriptBlockText:*ADFS* OR win.ScriptBlockText:*Saml* OR win.S… | 0 |  |
| q-4777ce2b70 | triage T1606 step 6 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND win.TargetFilename:*INetCookies*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.c… | 1 | F52 |
| q-89c5439091 | triage T1606 step 6 | search | {"dataset": "windows.security", "query": "event.code:4648 AND win.TargetUserName:pbeesly", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.com… | 9 | F53 |
| q-d2bc509d97 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-b5e43d4fbb | triage T1606 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-ed8346d7b5 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-34d22385b8 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQkXH"} | None |  |
| q-1f997153bb | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQkXH"} | None |  |
| q-d802b5a665 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByPYrDh"} | None |  |
| q-0cc994a696 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByPYrDh"} | None |  |
| q-f77deafd88 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByCVdnF"} | None |  |
| q-30ae622e06 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBi-6ySm"} | None |  |
| q-931924b571 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBi-6ySm"} | None |  |
| q-7e846dc5a6 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-e2060c8d56 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None |  |
| q-6dd6417a31 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuu5GRH"} | None |  |
| q-6324f147df | triage T1606 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeBwdMB0i"} | None |  |
| q-b2e54336ab | triage T1649 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None | F54 |
| q-9a2c8aa2d5 | triage T1649 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND win.TargetFilename:*pfx*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "win.TargetFilename", "process.executable", "process.command_line", "process.parent.exec… | 1 |  |
| q-364c43d209 | triage T1649 step 1 | search | {"dataset": "windows.security", "query": "event.code:4657 AND win.ObjectName:*SystemCertificates*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "win.ObjectName", "win.ObjectValueName", "win.OperationType", "win.NewVal… | 1 |  |
| q-5d2d917009 | triage T1649 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQkXH"} | None | F54 |
| q-7d1d4a2c74 | triage T1649 step 2 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuu4mRU"} | None | F55 |
| q-e9ff787581 | triage T1649 step 2 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*cert:\\\\* OR win.ScriptBlockText:*Certificate* OR win.ScriptBlockText:*pfx* OR win.ScriptBlockText:*PrivateKey*)", "time_from": null, "time_to": null, "fields": ["@timestamp… | ERROR |  |
| q-944a61b35a | triage T1649 step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == 4104 AND (TO_LOWER(win.ScriptBlockText) LIKE \"*export-pfxcertificate*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*certificate*\" OR TO_LOWER(win.ScriptBlockText) LIKE \… | ERROR |  |
| q-553a231646 | triage T1649 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 1 AND (TO_LOWER(process.command_line) LIKE \"*pfx*\" OR TO_LOWER(process.command_line) LIKE \"*cert*\" OR TO_LOWER(process.executable) LIKE \"*psexec*\" OR TO_LOWER(process… | ERROR |  |
| q-29f98965fc | triage T1649 step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*export-pfxcertificate*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*certificate*\" OR TO_LOWER(win.ScriptBlockText) LI… | 5 |  |
| q-ee97073d9d | triage T1649 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*pfx*\" OR TO_LOWER(process.command_line) LIKE \"*cert*\" OR TO_LOWER(process.executable) LIKE \"*psexec*\" OR TO_LOWER(pro… | 5 | F54 |
| q-ae4ffcabbe | triage T1649 step 5 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByOXiqV"} | None |  |
| q-fe96bb92ca | triage T1649 step 5 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByCVdnF"} | None | F54 |
| q-962a4b52c6 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-d5447584b9 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-fb14cf3bf3 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-c46a9811fa | triage T1649 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQkXH"} | None |  |
| q-8d9467b431 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQkXH"} | None |  |
| q-4c076c9d15 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByCVdnF"} | None |  |
| q-6bb4069f29 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoz4z4i"} | None |  |
| q-e60fbb4cc1 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuu4mRU"} | None |  |
| q-caf90e6eed | triage T1649 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuu4mRU"} | None |  |
| q-5ad0ed7c24 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuu4mRU"} | None |  |
| q-3e1f1d26b5 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None |  |
| q-155f6c30b5 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-df308fea95 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None |  |
| q-5ec8f765e1 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy4FbI2"} | None |  |
| q-9d5e3ce513 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy4FbI2"} | None |  |
| q-71bd81dc1b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoZdz9r"} | None |  |
| q-269cd82264 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-4b22f0505e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQkXH"} | None |  |
| q-ff0320de4b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-9df146e7ed | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-54f8262b1b | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByEVwPJ"} | None |  |
| q-70bfbc053a | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuv5SEZ"} | None |  |
| q-abd4640bf8 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBunxq2L"} | None |  |
| q-096b70df3f | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy1BJnq"} | None |  |
| q-c78a3cd357 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy1BJnq"} | None |  |
| q-9d41ae06eb | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBufr2nf"} | None |  |
| q-0ddccc56cb | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBumw-cX"} | None |  |
| q-a609f376f7 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBumw-cX"} | None |  |
| q-7eb19f7193 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBumw-cX"} | None |  |
| q-383515382b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoglALi"} | None |  |
| q-14c54447c2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoLO1t-"} | None |  |
| q-65477f8da4 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoZdz8w"} | None |  |
| q-db9a4b3faf | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnvvDAD"} | None |  |
| q-3341307346 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnvvDAD"} | None |  |
| q-d595c0c2d9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnkjXIW"} | None |  |
| q-a19c833b75 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnaXZbG"} | None |  |
| q-130565d495 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnaXZbG"} | None |  |
| q-9bcb37f426 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBndb5l3"} | None |  |
| q-05eca6daa3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBncbMoA"} | None |  |
| q-4bbb440c73 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnooszM"} | None |  |
| q-585637b826 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuYnMlG"} | None |  |
| q-6f1188c2c5 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXG"} | None |  |
| q-9c863386b9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXG"} | None |  |
| q-9c6c000bf6 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None |  |
| q-d1729fe974 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-56e8183d45 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBorwtwa"} | None |  |
| q-163f2e558e | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy0A4ua"} | None |  |
| q-3ef8aa7503 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy0A4uc"} | None |  |
| q-ec80d6e1dd | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-7ed01aac83 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBux8Gu0"} | None |  |
| q-a81b98daee | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRabqD"} | None |  |
| q-6aa8164e6c | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRabqD"} | None |  |
| q-8922bbfce6 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRZ7r5"} | None |  |
| q-e36e108ffc | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBov0sHE"} | None |  |
| q-647ab766bd | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByXfnRy"} | None |  |
| q-83b9226b20 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnrrZmZ"} | None |  |
| q-2e2eda8cc1 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBudppHE"} | None |  |
| q-ce3ae5ca94 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuTlU_q"} | None |  |
| q-5ee74f6b0c | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuTlU_q"} | None |  |
| q-938f621fdf | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBudppFY"} | None |  |
| q-2b11511b92 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBi85SQC"} | None |  |
| q-b3a889e213 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-c4fae99c4e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-c12baa00ec | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-42ac00e30b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None |  |
| q-57009c7692 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy1B5lE"} | None |  |
| q-e4ccf09930 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBizx7sV"} | None |  |
| q-b64f709439 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoz4z4i"} | None |  |
| q-6c6875af49 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByEVwPJ"} | None |  |
| q-0ab629fd45 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByCVdVX"} | None |  |
| q-4a72184fa8 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByPYrDh"} | None |  |
| q-8013fdaefa | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-68952a4768 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-1b9d02758b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None |  |
| q-f3f54f7aa9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None |  |
| q-a8580f30dc | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBorwtwa"} | None |  |
| q-4cfb6a01ea | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBorwtwa"} | None |  |
| q-3c4f70ba70 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByYf10Q"} | None |  |
| q-622f66f5a4 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-0be04a7bd2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-92b5455ce1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBo05D7L"} | None |  |
| q-c0419ec29c | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuu5GRH"} | None |  |
| q-0a4ec2f417 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnaXZbs"} | None |  |
| q-01e2090f1f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnqqYet"} | None |  |
| q-7cc783caaa | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnrrZmZ"} | None |  |
| q-1c0aaa063a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnTPq-O"} | None |  |
| q-8088943402 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeBwdLx2Z"} | None |  |
| q-6b2cf96053 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgR9D"} | None |  |
| q-bacbdc32fb | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgh8V"} | None |  |
| q-186f7f79d9 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgh8V"} | None |  |
| q-1b68444e34 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgR8h"} | None |  |
| q-5c90ce1b0b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoSWKN8"} | None |  |
| q-7740cd6f62 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoOSXoo"} | None |  |
| q-1f98cd171f | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy8KXgk"} | None |  |
| q-08cf1e42a7 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None |  |
| q-06c5cd2ae3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None |  |
| q-99c4e682b4 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-cdb9a1e1dc | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-5d33849d31 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-136d9fa303 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-0ef7c554d3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoz4z4i"} | None |  |
| q-b5b2b83913 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByPYrDh"} | None |  |
| q-29ae71bbdb | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuv5SEZ"} | None |  |
| q-bd3a046710 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBi-6ySm"} | None |  |
| q-561127403f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBizxbvb"} | None |  |
| q-c443a0f181 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBizx7sR"} | None |  |
| q-5421c7dafc | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByEVwPJ"} | None |  |
| q-f1fd0e4c56 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByPYrDh"} | None |  |
| q-8f866e7114 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnaX5as"} | None |  |
| q-0271cdf3c0 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-03f1fd6660 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-be1e5a74a9 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-69057da510 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQkXH"} | None |  |
| q-4be95ce62a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQkXH"} | None |  |
| q-4f30c8a076 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByPYrDh"} | None |  |
| q-9be8481516 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByPYrDh"} | None |  |
| q-ce1f7fdde3 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-16955cfa24 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBo05T5k"} | None |  |
| q-0e2072c085 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeBwdLx2Z"} | None |  |
| q-c345d9382a | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeBwdMB0i"} | None |  |
| q-7728b1205c | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuu5GRH"} | None |  |
| q-5e1e3516ff | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBunxq0T"} | None |  |
| q-9808a8c578 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBunxq0T"} | None |  |
| q-760255a441 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnaXZbu"} | None |  |
| q-23ac79be1f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoKOGL_"} | None |  |
| q-866bc4b62c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBi85CSh"} | None |  |
| q-5e8e0ef0ad | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoGKqgM"} | None |  |
| q-ec827ccf40 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoTWpZy"} | None |  |
| q-26c0276a30 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn56HkU"} | None |  |
| q-9e4ca1fcd3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None |  |
| q-a9aec2f6ad | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None |  |
| q-22ff624d8f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None |  |
| q-e8ace40206 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-5275e6d352 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBow1KRR"} | None |  |
| q-e7ebdf9ce4 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-8f8f6db4e1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBi-6ySm"} | None |  |
| q-ca4cd4d28f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBi-6ySm"} | None |  |
| q-ec466a461f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-85ec47fd95 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-f7153ff52c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoz4j7h"} | None |  |
| q-5eedeab232 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeBwdMB1A"} | None |  |
| q-fabce1aad6 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByPYrDh"} | None |  |
| q-af25225585 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-2941e79d3d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-727c8aa05a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBorwtwa"} | None |  |
| q-e4155848b8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBizx7td"} | None |  |
| q-a55f04d5c8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoz4j7h"} | None |  |
| q-f030df75cd | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuWmJMP"} | None |  |
| q-63dbe390d9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None |  |
| q-f4d87f1705 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuWmJMP"} | None |  |
| q-4ef0427265 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoNRGHl"} | None |  |
| q-16a459499a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnZW8l5"} | None |  |
| q-7ef2469872 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByUbwtm"} | None |  |
| q-2c57227bd9 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy1BJnq"} | None |  |
| q-f4d2b7d345 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeBwdMB0i"} | None |  |
| q-e1127d467e | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeBwdLx2Z"} | None |  |
| q-265edff92a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-5f1afd2fae | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-506d96eafd | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnlkXpm"} | None |  |
| q-1a0fc84c80 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn55Xmr"} | None |  |
| q-4c41a60b34 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn66XZS"} | None |  |
| q-189ed4a542 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBufr2mI"} | None |  |
| q-a5cd3229dc | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuq1HQ4"} | None |  |
| q-489dedb386 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoSWKN8"} | None |  |
| q-ad965dddb3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoXbqXA"} | None |  |
| q-031f443dd7 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn4413G"} | None |  |
| q-8374e25b0a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-a986e158bf | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None |  |
| q-1983e860fd | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-fc8e123422 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-2c3a0664d6 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRarq9"} | None |  |
| q-098ec313ae | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByDV_QB"} | None |  |
| q-cdad4fcefc | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy4FbJD"} | None |  |
| q-5e81244fe3 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy4FbJD"} | None |  |
| q-a5b9a97d38 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy4FbJD"} | None |  |
| q-ed2b4466cd | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy8J3fS"} | None |  |
| q-1ac4f514a2 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuv5SEr"} | None |  |
| q-713620ec05 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuu5GRH"} | None |  |
| q-7643a5194a | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuu5GRH"} | None |  |
| q-f95a460641 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgR8n"} | None |  |
| q-3fda1a41b2 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgR8n"} | None |  |
| q-6bd59634e5 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgR8m"} | None |  |
| q-d2ce7ab836 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgh9H"} | None |  |
| q-937a6a8532 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-081d502dcd | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-e5d23244fd | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-bc101ea49e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQkXH"} | None |  |
| q-c226f3c3d5 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQkXH"} | None |  |
| q-a7e9002109 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByPYrDh"} | None |  |
| q-f1e86e7c44 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByPYrDh"} | None |  |
| q-bbc03c80d2 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByCVdnF"} | None |  |
| q-42288e7e24 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBi-6ySm"} | None |  |
| q-86f5082b0b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBi-6ySm"} | None |  |
| q-da4562438b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-3e04dba096 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None |  |
| q-f0f3e02591 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuu5GRH"} | None |  |
| q-7495f8a668 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeBwdMB0i"} | None |  |
| q-564f8d4a05 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-0f4d11669f | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-f7151e8b23 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-364fdc7cba | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQkXH"} | None |  |
| q-2736b196c8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQkXH"} | None |  |
| q-910bc043b3 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByCVdnF"} | None |  |
| q-b471cf0230 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoz4z4i"} | None |  |
| q-41c405da82 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuu4mRU"} | None |  |
| q-d2c7d938c1 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuu4mRU"} | None |  |
| q-7d40abf701 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuu4mRU"} | None |  |
| q-356e9784bd | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND host.name:\"nashua.dmevals.local\"", "time_from": "2020-05-02T02:54:23+00:00", "time_to": "2020-05-02T03:26:40.213000+00:00", "size": 100, "sub_field": "process.parent.exec… | 61 |  |
| q-838a189091 | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11 AND host.name:\"nashua.dmevals.local\"", "time_from": "2020-05-02T02:54:23+00:00", "time_to": "2020-05-02T03:26:40.213000+00:00", "size": 100, "sub_field": "process.executable"} | 248 |  |
| q-f9fe325f55 | pivot seed | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND host.name:\"nashua.dmevals.local\"", "time_from": "2020-05-02T02:54:23+00:00", "time_to": "2020-05-02T03:26:40.213000+00:00", "size": 100, "sub_field": "process.parent… | 63 |  |
| q-fff5f64ab6 | pivot seed | aggregate | {"dataset": "windows.powershell", "field": "event.code", "query": "host.name:\"nashua.dmevals.local\"", "time_from": "2020-05-02T02:54:23+00:00", "time_to": "2020-05-02T03:26:40.213000+00:00", "size": 100, "sub_field": null} | 192 |  |
| q-9458388c2e | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND host.name:\"scranton.dmevals.local\"", "time_from": "2020-05-02T02:40:56.157000+00:00", "time_to": "2020-05-02T03:36:28.476000+00:00", "size": 100, "sub_field": "process.pa… | 359 |  |
| q-c80797e51b | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11 AND host.name:\"scranton.dmevals.local\"", "time_from": "2020-05-02T02:40:56.157000+00:00", "time_to": "2020-05-02T03:36:28.476000+00:00", "size": 100, "sub_field": "process.executable… | 1276 |  |
| q-2914e94048 | pivot seed | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND host.name:\"scranton.dmevals.local\"", "time_from": "2020-05-02T02:40:56.157000+00:00", "time_to": "2020-05-02T03:36:28.476000+00:00", "size": 100, "sub_field": "proce… | 370 |  |
| q-80b74e07c4 | pivot seed | aggregate | {"dataset": "windows.powershell", "field": "event.code", "query": "host.name:\"scranton.dmevals.local\"", "time_from": "2020-05-02T02:40:56.157000+00:00", "time_to": "2020-05-02T03:36:28.476000+00:00", "size": 100, "sub_field": null} | 8602 |  |
| q-71b0483a9e | pivot step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND host.name == \"nashua.dmevals.local\" AND (process.executable LIKE \"*python.exe\" OR process.executable LIKE \"*Rar.exe\" OR process.executable LIKE \"*sdelete64… | 13 | F56, F58, F59 |
| q-01c368af06 | pivot step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND host.name == \"scranton.dmevals.local\" AND (process.executable LIKE \"*cod.3aka3.scr\" OR process.executable LIKE \"*csc.exe\" OR process.executable LIKE \"*host… | 15 | F56, F61 |
| q-ea29b9e420 | pivot step 2 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE host.name == \"nashua.dmevals.local\" AND event.code IN (\"4104\",\"4103\",\"800\",\"600\") \| KEEP @timestamp, host.name, user.name, event.code, powershell.file.script_block_text, p… | ERROR |  |
| q-992d070078 | pivot step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND host.name == \"nashua.dmevals.local\" AND (file.path LIKE \"*pbeesly*\" OR file.path LIKE \"*Temp*\" OR file.path LIKE \"*working*\" OR file.path LIKE \"*.pfx\" … | 60 |  |
| q-66172bb2de | pivot step 3 | get_fields | {"dataset": "windows.powershell", "prefix": ""} | None |  |
| q-a8590e341b | pivot step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND host.name == \"nashua.dmevals.local\" AND (file.path LIKE \"*working.zip*\" OR file.path LIKE \"*Rar.exe*\" OR file.path LIKE \"*python.exe*\" OR file.path LIKE … | 6 |  |
| q-b88ec8ba85 | pivot step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE host.name == \"nashua.dmevals.local\" AND event.code IN (\"4104\",\"4103\",\"800\",\"600\") \| KEEP @timestamp, host.name, user.name, event.code, win.ScriptBlockText, win.Message, pr… | 40 |  |
| q-1ae902b70d | pivot step 5 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE host.name == \"nashua.dmevals.local\" AND event.code == \"4104\" AND @timestamp >= \"2020-05-02T03:16:00.000Z\" \| KEEP @timestamp, host.name, user.name, win.ScriptBlockText, _id, _i… | 6 |  |
| q-c192fdc9b6 | pivot step 5 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE host.name == \"nashua.dmevals.local\" AND event.code IN (\"4663\",\"4656\",\"4673\",\"4688\") AND (win.ObjectName LIKE \"*Crypto*\" OR win.ObjectName LIKE \"*SAM*\" OR win.ObjectName L… | 3 |  |
| q-04c27caedf | pivot step 6 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE host.name == \"nashua.dmevals.local\" AND event.code IN (\"3\",\"22\",\"17\",\"18\",\"2\") AND (process.executable LIKE \"*python.exe*\" OR process.executable LIKE \"*powershell.exe*\" O… | 40 | F59 |
| q-428954f97c | pivot step 6 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE host.name == \"scranton.dmevals.local\" AND event.code IN (\"4663\",\"4656\") AND (win.ObjectName LIKE \"*SAM*\" OR win.ObjectName LIKE \"*SECURITY*\" OR win.ObjectName LIKE \"*lsass*\… | 22 | F62 |
| q-f84bd08d34 | pivot step 7 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE host.name == \"nashua.dmevals.local\" AND process.executable LIKE \"*python.exe*\" AND event.code IN (\"11\",\"23\",\"12\",\"13\",\"15\") \| KEEP @timestamp, host.name, user.name, event.… | 40 | F58, F59, F64 |
| q-e6a33b0285 | pivot step 7 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE host.name == \"scranton.dmevals.local\" AND event.code IN (\"4663\",\"4656\") AND (win.ObjectName LIKE \"*SECURITY*\" OR win.ObjectName LIKE \"*SYSTEM*\" OR win.ObjectName LIKE \"*SAM*… | 40 | F63 |
| q-6d15cb97e7 | pivot step 8 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE host.name == \"scranton.dmevals.local\" AND event.code == \"4104\" AND (win.ScriptBlockText LIKE \"*pfx*\" OR win.ScriptBlockText LIKE \"*PrivateKey*\" OR win.ScriptBlockText LIKE \"… | 3 |  |
| q-ceded19947 | pivot step 8 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE host.name == \"scranton.dmevals.local\" AND event.code == \"11\" AND (file.path LIKE \"*.pfx\" OR file.path LIKE \"*.zip\" OR file.path LIKE \"*Login Data*\" OR file.path LIKE \"*.dmp\" … | 40 | F60, F63 |
| q-94543ab8bb | pivot step 9 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE host.name == \"scranton.dmevals.local\" AND event.code == \"11\" AND (file.path LIKE \"*.pfx\" OR file.path LIKE \"*Login Data*\" OR file.path LIKE \"*cookies*\" OR file.path LIKE \"*.7z… | 5 | F57 |
| q-4d4ffb6a5e | pivot step 9 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-dc66aba2a4 | pivot step 10 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE host.name == \"scranton.dmevals.local\" AND event.code == \"4104\" AND (win.ScriptBlockText LIKE \"*OfficeSupplies*\" OR win.ScriptBlockText LIKE \"*7z*\" OR win.ScriptBlockText LIKE… | 20 | F60 |
| q-77bad2548c | pivot step 10 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE host.name == \"scranton.dmevals.local\" AND event.code == \"11\" AND @timestamp >= \"2020-05-02T03:04:00.000Z\" AND @timestamp <= \"2020-05-02T03:12:00.000Z\" \| KEEP @timestamp, host.na… | 40 | F61, F65 |
| q-c461c04d02 | pivot step 11 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByPYrDh"} | None | F57 |
| q-b9bf8bfe07 | pivot step 11 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE host.name == \"nashua.dmevals.local\" AND event.code == \"3\" AND process.executable LIKE \"*python.exe*\" \| STATS cnt = COUNT(*) BY destination.ip, destination.port, destination.hostna… | ERROR |  |
| q-e75eddf855 | pivot step 12 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE host.name == \"nashua.dmevals.local\" AND event.code == \"3\" AND process.executable LIKE \"*python.exe*\" \| STATS cnt = COUNT(*) BY destination.ip, destination.port \| SORT cnt DESC"} | 1 |  |
| q-8054cef060 | pivot step 12 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE host.name == \"nashua.dmevals.local\" AND event.code IN (\"4663\",\"4656\") AND (win.ObjectName LIKE \"*Crypto*\" OR win.ObjectName LIKE \"*Protect*\" OR win.ObjectName LIKE \"*Vault*\… | 0 |  |
| q-e2a8b7783e | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoz4z4i"} | None |  |
| q-992f0126f1 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoz4j7h"} | None |  |
| q-fc3f3bd97f | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoz4j7h"} | None |  |
| q-a9fd90f3a6 | pivot verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByPYrDh"} | None |  |
| q-f21a585ec4 | pivot verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByPYrDh"} | None |  |
| q-17c08ac868 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBo05T5k"} | None |  |
| q-1cdefbe8d4 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBow1qSj"} | None |  |
| q-2837abfb64 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoy3l6o"} | None |  |
| q-bd916ff1b2 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnnmUud"} | None |  |
| q-4af9f1a25c | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnttWk7"} | None |  |
| q-4894d4c331 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnyzTy7"} | None |  |
| q-3753d67ab9 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBow16Q8"} | None |  |
| q-3ae34b0737 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnyzDzk"} | None |  |
| q-fef61ad459 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnvv_3R"} | None |  |
| q-dade3b661e | pivot verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByXfnRy"} | None |  |
| q-ec01c600cd | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBouzukT"} | None |  |
| q-f926fea84e | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoNRGHl"} | None |  |
| q-b1b3dd0992 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoNRGHW"} | None |  |
| q-501486e3c9 | pivot verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBudp5HI"} | None |  |
| q-899c250050 | pivot verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBudp5HI"} | None |  |
| q-24bd769a4c | pivot verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuiuXgG"} | None |  |
| q-a347dbe744 | pivot step 14 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBow1KRR"} | None | F63 |
| q-cbd90322c6 | pivot step 14 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBorwNwU"} | None | F64 |
| q-67b388b1da | pivot step 14 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBi30hQJ"} | None | F65 |
| q-9e73a25bac | pivot step 14 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBosxOR1"} | None | F66 |
| q-65693822ea | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None |  |
| q-084a438e7b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-4a138208fd | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None |  |
| q-e8e4f7bfef | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy4FbI2"} | None |  |
| q-fab3ea8ffd | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy4FbI2"} | None |  |
| q-239d17cf01 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoZdz9r"} | None |  |
| q-9d841726c0 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-7cb337a64d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQkXH"} | None |  |
| q-4279905f40 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-0611b70789 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-572df9ce02 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByEVwPJ"} | None |  |
| q-8e5b8f6efb | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuv5SEZ"} | None |  |
| q-fc18f445b1 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBunxq2L"} | None |  |
| q-b91b1a31bf | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy1BJnq"} | None |  |
| q-7089c1bee5 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy1BJnq"} | None |  |
| q-bb22ecf58a | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBufr2nf"} | None |  |
| q-6294cd5e24 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBumw-cX"} | None |  |
| q-52754b96e1 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBumw-cX"} | None |  |
| q-62b254cf90 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBumw-cX"} | None |  |
| q-88002e8788 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoglALi"} | None |  |
| q-bb8262c156 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoLO1t-"} | None |  |
| q-20b4e46583 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoZdz8w"} | None |  |
| q-8af5cbd97a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnvvDAD"} | None |  |
| q-9fe9279d65 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnvvDAD"} | None |  |
| q-2219935420 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnkjXIW"} | None |  |
| q-193ddfb6bd | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnaXZbG"} | None |  |
| q-a4cc7284df | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnaXZbG"} | None |  |
| q-0c78673ce2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBndb5l3"} | None |  |
| q-a6d0aaea21 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBncbMoA"} | None |  |
| q-833cd79d89 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnooszM"} | None |  |
| q-70c1dcb520 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuYnMlG"} | None |  |
| q-443a76f14c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXG"} | None |  |
| q-babe1a347e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXG"} | None |  |
| q-68519ec2b4 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None |  |
| q-2cb565aaab | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-ee9035f53c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBorwtwa"} | None |  |
| q-f8141c8e56 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy0A4ua"} | None |  |
| q-34280501fd | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy0A4uc"} | None |  |
| q-58b5d6a825 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-eb630672c8 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBux8Gu0"} | None |  |
| q-44497a4e24 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRabqD"} | None |  |
| q-7af0647ce7 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRabqD"} | None |  |
| q-8769a4223a | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRZ7r5"} | None |  |
| q-6e198c7ec1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBov0sHE"} | None |  |
| q-8364107e51 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByXfnRy"} | None |  |
| q-eefb7e4458 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnrrZmZ"} | None |  |
| q-18760f629e | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBudppHE"} | None |  |
| q-1ab873a252 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuTlU_q"} | None |  |
| q-7688f38ed1 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuTlU_q"} | None |  |
| q-9ea818dd10 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBudppFY"} | None |  |
| q-cc626bf11e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBi85SQC"} | None |  |
| q-79e8f11e69 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-db7d07087a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-4a7f1319ba | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-86206f64c8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None |  |
| q-a486c8eceb | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy1B5lE"} | None |  |
| q-35bf5aec0a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBizx7sV"} | None |  |
| q-57833b958f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoz4z4i"} | None |  |
| q-7c0e9fb84f | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByEVwPJ"} | None |  |
| q-479dd14241 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByCVdVX"} | None |  |
| q-a1ff44cf93 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByPYrDh"} | None |  |
| q-c6fab9e736 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-10e17a3053 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-8ec95d2c12 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None |  |
| q-5ade6377a9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None |  |
| q-9fb0cca824 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBorwtwa"} | None |  |
| q-d798d15108 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBorwtwa"} | None |  |
| q-b0f36df04b | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByYf10Q"} | None |  |
| q-54f528489d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-145ab7d0ff | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-4247147f1b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBo05D7L"} | None |  |
| q-bc8b8babfd | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuu5GRH"} | None |  |
| q-f9c4b382ef | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnaXZbs"} | None |  |
| q-a846c2e67f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnqqYet"} | None |  |
| q-5e99f8c804 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnrrZmZ"} | None |  |
| q-a36704b7b9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnTPq-O"} | None |  |
| q-bcc5acd6de | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeBwdLx2Z"} | None |  |
| q-6922e0c7be | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgR9D"} | None |  |
| q-14612146e9 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgh8V"} | None |  |
| q-57f18408ae | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgh8V"} | None |  |
| q-1762466597 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgR8h"} | None |  |
| q-32c46ddba3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoSWKN8"} | None |  |
| q-2a2f0f7bb6 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoOSXoo"} | None |  |
| q-6993551ce4 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy8KXgk"} | None |  |
| q-081465097d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None |  |
| q-4c26e02561 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None |  |
| q-05b4d2a4ea | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-c07f471fe0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-cc120930c7 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-9f65c33db8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-b04e213a5b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoz4z4i"} | None |  |
| q-4916302036 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByPYrDh"} | None |  |
| q-ec31b027db | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuv5SEZ"} | None |  |
| q-41d6135920 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBi-6ySm"} | None |  |
| q-71011feab9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBizxbvb"} | None |  |
| q-d1fae996a4 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBizx7sR"} | None |  |
| q-9be80187a6 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByEVwPJ"} | None |  |
| q-c8a6390aa6 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByPYrDh"} | None |  |
| q-81720680a5 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnaX5as"} | None |  |
| q-330633b670 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-44cbbe11bb | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-85bcb4596b | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-73d879fb26 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQkXH"} | None |  |
| q-b4da33b259 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQkXH"} | None |  |
| q-7cc9ac98f9 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByPYrDh"} | None |  |
| q-39b5b54fc0 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByPYrDh"} | None |  |
| q-399a6206ed | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-16d1357569 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBo05T5k"} | None |  |
| q-907a641f6c | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeBwdLx2Z"} | None |  |
| q-82380ecdfb | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeBwdMB0i"} | None |  |
| q-6682ff78b2 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuu5GRH"} | None |  |
| q-d401682e2f | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBunxq0T"} | None |  |
| q-978b41f3d6 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBunxq0T"} | None |  |
| q-199117c5d4 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnaXZbu"} | None |  |
| q-fd42814fb8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoKOGL_"} | None |  |
| q-b31a031c71 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBi85CSh"} | None |  |
| q-4ded7df96c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoGKqgM"} | None |  |
| q-e8c5eb87cd | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoTWpZy"} | None |  |
| q-2cd695a348 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn56HkU"} | None |  |
| q-cf80fd7509 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None |  |
| q-6f2809163d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None |  |
| q-12d237a86e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None |  |
| q-356988d55d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-cacbb2a374 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBow1KRR"} | None |  |
| q-fb5c5e4ca5 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-b7bf4beaac | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBi-6ySm"} | None |  |
| q-ac6e79eb15 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBi-6ySm"} | None |  |
| q-500f8bdb23 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-e2c50e2482 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-71b27994e2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoz4j7h"} | None |  |
| q-a4f8914484 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeBwdMB1A"} | None |  |
| q-8e2b66f76d | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByPYrDh"} | None |  |
| q-edf60a2a55 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-aff625ac4c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-176324100e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBorwtwa"} | None |  |
| q-8912092b4f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBizx7td"} | None |  |
| q-91c54d56aa | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoz4j7h"} | None |  |
| q-ba5f8be1a4 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuWmJMP"} | None |  |
| q-6a8d335955 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None |  |
| q-8af116ead3 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuWmJMP"} | None |  |
| q-91cc6b83c1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoNRGHl"} | None |  |
| q-c7c9077c3c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnZW8l5"} | None |  |
| q-2d1370e857 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByUbwtm"} | None |  |
| q-d3b0043533 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy1BJnq"} | None |  |
| q-7a5550a15f | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeBwdMB0i"} | None |  |
| q-199aac74dc | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeBwdLx2Z"} | None |  |
| q-debe132038 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-f9ad809ecb | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-d54d1fdfd9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnlkXpm"} | None |  |
| q-6df9e5a786 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn55Xmr"} | None |  |
| q-dd626dbce0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn66XZS"} | None |  |
| q-e2ae02a56d | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBufr2mI"} | None |  |
| q-0ad2f05fd7 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuq1HQ4"} | None |  |
| q-420ad8cf35 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoSWKN8"} | None |  |
| q-9409ddfda9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoXbqXA"} | None |  |
| q-25d4442979 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn4413G"} | None |  |
| q-896bb4efd9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-4aabebda0d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None |  |
| q-e948dc7bfc | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-f146c845e6 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-a1a46c6d0c | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRarq9"} | None |  |
| q-83aa89a4b3 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByDV_QB"} | None |  |
| q-fc25a9a9ce | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy4FbJD"} | None |  |
| q-4a1020c1c8 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy4FbJD"} | None |  |
| q-320bc3b3e4 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy4FbJD"} | None |  |
| q-142d317f4d | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy8J3fS"} | None |  |
| q-82855854a4 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuv5SEr"} | None |  |
| q-69e091a672 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuu5GRH"} | None |  |
| q-a9ceda3265 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuu5GRH"} | None |  |
| q-4efedaa598 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgR8n"} | None |  |
| q-37dcea4101 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgR8n"} | None |  |
| q-4a11afe354 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgR8m"} | None |  |
| q-a12ebe1012 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgh9H"} | None |  |
| q-937d23ecf5 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-c0a9e31d48 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-873aea5ebc | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-281ba76316 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQkXH"} | None |  |
| q-a26851edac | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQkXH"} | None |  |
| q-b06b072ef8 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByPYrDh"} | None |  |
| q-0c95086035 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByPYrDh"} | None |  |
| q-5ddd9f4fce | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByCVdnF"} | None |  |
| q-2f8b4c079e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBi-6ySm"} | None |  |
| q-c93c130720 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBi-6ySm"} | None |  |
| q-7e8607beab | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-45d0570576 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None |  |
| q-f5fd309e9c | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuu5GRH"} | None |  |
| q-606c11a432 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeBwdMB0i"} | None |  |
| q-f40190959f | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-895f2f90a6 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-d3d13aad55 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-6b5ba190aa | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQkXH"} | None |  |
| q-af75c3cb0b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQkXH"} | None |  |
| q-8fe2460244 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByCVdnF"} | None |  |
| q-535f996135 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoz4z4i"} | None |  |
| q-41e379a6a1 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuu4mRU"} | None |  |
| q-e413dc73aa | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuu4mRU"} | None |  |
| q-7aebd1bbea | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuu4mRU"} | None |  |
| q-e97d01c212 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoz4z4i"} | None |  |
| q-99e85b0886 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoz4j7h"} | None |  |
| q-9e9a1dbdf1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoz4j7h"} | None |  |
| q-eb200961a7 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByPYrDh"} | None |  |
| q-6a920e7997 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByPYrDh"} | None |  |
| q-a0d1d627a9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBo05T5k"} | None |  |
| q-87686d9dda | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBow1qSj"} | None |  |
| q-63d0120284 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoy3l6o"} | None |  |
| q-128eb6caf2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnnmUud"} | None |  |
| q-20eaf684f6 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnttWk7"} | None |  |
| q-9818293ae5 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnyzTy7"} | None |  |
| q-c326d5eb60 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBow16Q8"} | None |  |
| q-08f0b08f4c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnyzDzk"} | None |  |
| q-d8ff6da399 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnvv_3R"} | None |  |
| q-2696ffb53a | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByXfnRy"} | None |  |
| q-7f99cf0895 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBouzukT"} | None |  |
| q-f7ee65843f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoNRGHl"} | None |  |
| q-c1f32746ae | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoNRGHW"} | None |  |
| q-b77d5a261f | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBudp5HI"} | None |  |
| q-c42b6b1e69 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBudp5HI"} | None |  |
| q-a91087b6fd | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuiuXgG"} | None |  |
| q-0b12e500db | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBow1KRR"} | None |  |
| q-8425017f6f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBow1KRR"} | None |  |
| q-6603968d01 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy3EfF1"} | None |  |
| q-7ba33a6000 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBouy-nD"} | None |  |
| q-626b182fb5 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBorwNwU"} | None |  |
| q-50ea91ff6f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBorwNwU"} | None |  |
| q-fbacf86dfd | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoy314I"} | None |  |
| q-fc738ddf1d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBi30hQJ"} | None |  |
| q-ae1b7a9d18 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoOSXoo"} | None |  |
| q-f84d2953ed | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBosxOR1"} | None |  |
| q-45862eb937 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBosxOR1"} | None |  |

## Verification

Evidence items cited: 229; confirmed against the stored events: 229; rejected: 0. Each item was re-fetched with get_event; it is confirmed only if the event exists, the cited field holds the cited value, and the cited query_id is a query of this run that returned that event.
Evidence sent back to the agents for correction during the run: 7 item(s) in 6 submission(s) (one correction round each; what still failed was rejected).

## Limitations

- Findings describe what the stored logs show; activity these sources did not log cannot be seen.
- Datasets with non-overlapping time windows (see Data examined) were analysed separately.
- Long field values are shortened in this report; full events are retrievable by _index/_id.
