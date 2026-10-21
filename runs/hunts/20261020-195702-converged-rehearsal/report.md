# Threat hunt report — 20261020-195702-converged-rehearsal

**Hypothesis:** An adversary who compromised Windows hosts in this network stole credentials from them (MITRE ATT&CK tactic: Credential Access).

**Verdict: Confirmed** — 6 in-scope incident(s) of verified malicious findings (confidence >= medium): I01 T1003.001 (F01, F11, F32, F36, F47, F53), I03 T1056.001 (F60), I04 T1056.002 (F10), I05 T1552.001 (F27, F31, F58), I06 T1552.001 (F59), I08 T1649 (F26, F52, F55, F62)

Verdict method: rules over verified evidence (Confirmed if >=1 in-scope incident of verified malicious findings (confidence >= medium); Inconclusive if only suspicious incidents or coverage gaps; Refuted if full coverage and no malicious/suspicious finding)

| Run | Value |
|---|---|
| Profile | converged (thinking=False, temperature=0.0) |
| Model | deepseek-flash |
| Started / finished (UTC) | 2026-10-20T11:57:02+00:00 / 2026-10-20T12:07:11+00:00 (608.8 s) |
| LLM calls / tokens | 140 / {'prompt': 4065540, 'completion': 138926} |
| MCP tool calls | 1149 (server tools: list_data_sources, get_fields, search, count, aggregate, timeline, esql, get_event, get_registry) |
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
| I01 | T1003.001 | yes | malicious/high | F01, F11, F32, F36, F47, F53 | PowerShell steganography loader opens LSASS with full-access masks on scranton |
| I02 | T1003.001 | yes | suspicious/medium | F02, F12 | wsmprovhost.exe PowerShell remoting session opens LSASS with 0x1F3FFF on nashua |
| I03 | T1056.001 | yes | malicious/high | F60 | Get-Keystrokes keylogger job on scranton |
| I04 | T1056.002 | yes | malicious/high | F10 | PowerShell screen-capture (GUI input capture) on scranton |
| I05 | T1552.001 | yes | malicious/high | F27, F31, F58 | Cleartext credentials in files and command lines on scranton (Invoke-Exfil, PsExec64) |
| I06 | T1552.001 | yes | malicious/high | F59 | PowerShell on nashua collects credential-keyword files into working.zip |
| I07 | T1555.003 | yes | suspicious/medium | F61 | PowerShell credential harvesting and exfil staging (clipboard, archive, cleanup) on scranton |
| I08 | T1649 | yes | malicious/high | F26, F52, F55, F62 | Get-PrivateKeys certificate export to password-protected .pfx on scranton |
| I09 | out-of-scope:T1027.004 | no | malicious/high | F64 | csc.exe runtime compilation of attacker DLLs from PowerShell on scranton |
| I10 | out-of-scope:T1204 | no | malicious/high | F63 | Screensaver payload drops steganographic monkey.png on scranton |
| I11 | out-of-scope:T1548.002 | no | suspicious/medium | F65 | hostui.exe -verb runas elevation and registry-value Invoke-Expression on scranton |
| I12 | out-of-scope:T1548.002 | no | suspicious/medium | F66 | sdclt.exe UAC-bypass pattern with HKCU Folder shell open command on scranton |

## Findings

### F01 · malicious / high · T1003.001 · PowerShell (steganography/IEX loader) opened LSASS with full-access 0x1FFFFF on scranton

Evidence status: **verified**

On scranton.dmevals.local, PowerShell.exe PID 2976 — spawned at 02:58:44 by control.exe with a hidden-window, execution-policy-bypass command that decodes a bitmap (C:\Users\pbeesly\Downloads\monkey.png) and IEXes the extracted payload — opened a handle to lsass.exe (PID 736) at 03:05:16 with GrantedAccess 0x1F3FFF and then 0x1FFFFF, the classic LSASS read-memory mask used by credential dumpers. The call trace ends in UNKNOWN modules, not a signed Windows DLL. The same session had just deployed SysinternalsSuite, run discovery, and later ran keystroke/screenshot jobs, so this is attacker tooling, not administration. A security 4663 event at 03:05:16 records the same powershell.exe (user pbeesly) accessing \Device\HarddiskVolume2\Windows\System32\lsass.exe.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOtaokyU | q-9570601447 | ok |
| 2 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOtaokyU | q-9570601447 | ok |
| 3 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.CallTrace | C:\windows\SYSTEM32\ntdll.dll+9c584\|C:\windows\System32\KERNELBASE.dll+2732e\|UNKNOWN(000001996D28200D) | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOtaokyU | q-9570601447 | ok |
| 4 | 2020-05-02 02:58:44.325Z | scranton.dmevals.local | windows.sysmon | process.command_line | "PowerShell.exe" -noni -noexit -ep bypass -window hidden -c "sal a New-Object;Add-Type -AssemblyName 'System.Drawing'; $g=a System.Drawing.Bitmap('C:\Users\pbee… | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOx6IsLb | q-711ecd7dc9 | ok |
| 5 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | win.ObjectName | \Device\HarddiskVolume2\Windows\System32\lsass.exe | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZI2iSVpshTO39W64C | q-79cf3a74a2 | ok |
| 6 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOtaokyR | q-4e454ad9f7 | ok |

### F60 · malicious / high · T1056.001 · Get-Keystrokes keylogger job executed in PowerShell on SCRANTON

Evidence status: **verified**

On scranton.dmevals.local, pbeesly's PowerShell (running the attacker toolkit loaded from C:\Program Files\SysinternalsSuite\readme.ps1) invoked Get-Keystrokes at 03:06:59, slept 15 seconds, viewed the 'Keystrokes' job output at 03:07:36 and removed the job at 03:07:49. A Keystroke-Check function enumerating AV products was also defined/run at 03:06:47. This keyboard input capture is new compared with the anchors (which covered screen capture and LSASS access).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:06:59.000Z | scranton.dmevals.local | windows.powershell | powershell.script_block.text | Get-Keystrokes;Start-Sleep -Seconds 15;View-Job -JobName "Keystrokes" | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZJGiSVpshTO3P0J3p | q-a38568493c | ok |
| 2 | 2020-05-02 03:07:36.000Z | scranton.dmevals.local | windows.powershell | powershell.script_block.text | View-Job -JobName "Keystrokes" | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZJGiSVpshTO3NxokS | q-a38568493c | ok |
| 3 | 2020-05-02 03:06:47.000Z | scranton.dmevals.local | windows.powershell | powershell.script_block.text | Keystroke-Check | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZJGiSVpshTO3P0p1J | q-a38568493c | ok |

### F10 · malicious / high · T1056.002 · PowerShell screen-capture (GUI input capture) script executed on scranton.dmevals.local

Evidence status: **verified**

On 2020-05-02 03:05:53Z (host scranton.dmevals.local, user DMEVALS\pbeesly, PowerShell PID 3852) a script block defining 'function Invoke-ScreenCapture' was logged (4104). The function starts a background job named "Screenshot" that loops forever, using System.Windows.Forms/System.Drawing to grab the full virtual screen via CopyFromScreen and save it as a randomly named .bmp in $env:USERPROFILE\Downloads every 300 seconds. It was immediately invoked by a second script block 'Invoke-ScreenCapture;Start-Sleep -Seconds 3;View-Job -JobName "Screenshot"'. The defining script block's Path is C:\Program Files\SysinternalsSuite\psversion.ps1, i.e. attacker code appended to a legitimate Sysinternals script. Repeated screen capture of the interactive desktop is GUI input capture used to harvest on-screen credentials/activity.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:53.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-ScreenCapture # https://www.pdq.com/blog/capturing-screenshots-with-powershell-and-net/ {     Start-Job -Name "Screenshot" -ScriptBlock {       … | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZJGiSVpshTO3Pzp3U | q-d24986d215 | ok |
| 2 | 2020-05-02 03:05:53.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\psversion.ps1 | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZJGiSVpshTO3Pzp3U | q-d24986d215 | ok |
| 3 | 2020-05-02 03:05:53.000Z | scranton.dmevals.local | windows.powershell | user.name | pbeesly | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZJGiSVpshTO3Pzp3U | q-d24986d215 | ok |
| 4 | 2020-05-02 03:05:59.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText |           Write-Host "`nJobPID`n------`n$PID"         while($true){             $RandomFileName = [System.IO.Path]::GetRandomFileName();              $Filepath=… | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZJGiSVpshTO3Oy3md | q-6415ad8776 | ok |
| 5 | 2020-05-02 03:05:53.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | Invoke-ScreenCapture;Start-Sleep -Seconds 3;View-Job -JobName "Screenshot" | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZJGiSVpshTO3Pz52N | q-32147b6521 | ok |

### F11 · malicious / high · T1056.004 · PowerShell.exe opened lsass.exe with full access (0x1FFFFF / 0x1F3FFF) on scranton.dmevals.local

Evidence status: **verified**

Sysmon EventID 10 shows C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe (PID 2976) opening lsass.exe (PID 736) on scranton.dmevals.local at 2020-05-02 03:05:16Z with GrantedAccess 0x1FFFFF and, 31 ms earlier, 0x1F3FFF. Both masks include PROCESS_VM_READ/PROCESS_VM_WRITE and full handle rights, and the call trace ends in UNKNOWN modules rather than a signed system DLL — the classic signature of a script/tool reading and manipulating lsass memory (credential API hooking / in-memory credential theft). This is the only non-system process on the estate granted full access to lsass; all other lsass accessors are svchost.exe, Azure telemetry/antimalware perf-counter readers (0x1400), or OS init processes. It occurs ~37 seconds before the Invoke-ScreenCapture script block was logged on the same host, consistent with a single credential-access toolchain.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOtaokyU | q-53c91be657 | ok |
| 2 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOtaokyU | q-53c91be657 | ok |
| 3 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.CallTrace | C:\windows\SYSTEM32\ntdll.dll+9c584\|C:\windows\System32\KERNELBASE.dll+2732e\|UNKNOWN(000001996D28200D) | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOtaokyU | q-53c91be657 | ok |
| 4 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOtaokyR | q-115ba048c6 | ok |
| 5 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | host.name | scranton.dmevals.local | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOtaokyU | q-53c91be657 | ok |

### F23 · malicious / medium · T1212 · PowerShell (pbeesly) opened lsass.exe with full-access masks on scranton; wsmprovhost did the same on nashua

Evidence status: **NOT verified (12/13 evidence items)** — excluded from the verdict

On scranton.dmevals.local, the PowerShell.exe process (PID 2976, user pbeesly) launched at 02:58:44Z from control.exe with the hidden/encoded command line "PowerShell.exe" -noni -noexit -ep bypass -window hidden -c "sal a New-Object;Add-Type -AssemblyName 'System.Drawing'; ... IEX(...)" opened lsass.exe (PID 736) at 03:05:16Z with GrantedAccess 0x1f3fff and 0x1fffff (PROCESS_ALL_ACCESS), with an UNKNOWN call-trace frame. Windows security logged the same handle requests (4656, AccessMask 0x1f3fff and 0x1fffff, SubjectUserName pbeesly, ProcessName powershell.exe). At 03:09:29Z on nashua.dmevals.local, wsmprovhost.exe (PID 7720, remote PowerShell session) opened lsass.exe (PID 728) with 0x1f3fff, and security 4656 shows SubjectUserName pbeesly. In the same session pbeesly repeatedly opened \REGISTRY\MACHINE\SYSTEM\ControlSet001\Control\Lsa on nashua (4656/4663, 0x20019/0x1). The same pbeesly PowerShell session on scranton ran credential-adjacent collection: Get-PrivateKeys (exporting cert:\LocalMachine private keys to .pfx with password 'saribas'), Get-Clipboard, Invoke-Discovery, Invoke-Persistence, Invoke-ScreenCapture and Invoke-Exfil. No MiniDump/lsass dump file or dump-writing tool was observed (windows.other lsass/MiniDump query returned 0 hits; only lsass.exe itself matched a *dump* command-line search), so the full-access lsass handles are the strongest exploitation-for-credential-access signal rather than a confirmed dump. Other lsass access in the window is benign: svchost.exe (lsm.dll/sysmain.dll call traces, 0x1000/0x101001/0x3000), wininit.exe/csrss.exe at boot (0x1fffff/0x1000000), and CollectGuestLogs.exe/AntimalwareConfig.exe/WindowsAzureTelemetryService.exe (0x1410/0x1000).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOtaokyU | q-bfea890357 | ok |
| 2 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOtaokyR | q-bfea890357 | ok |
| 3 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOtaokyU | q-c8b2fb27cf | ok |
| 4 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.CallTrace | C:\windows\SYSTEM32\ntdll.dll+9c584\|C:\windows\System32\KERNELBASE.dll+2732e\|UNKNOWN(000001996D252982) | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOtaokyR | q-648ebfa44e | ok |
| 5 | 2020-05-02 02:58:44.325Z | scranton.dmevals.local | windows.sysmon | process.command_line | "PowerShell.exe" -noni -noexit -ep bypass -window hidden -c "sal a New-Object;Add-Type -AssemblyName 'System.Drawing'; $g=a System.Drawing.Bitmap('C:\Users\pbee… | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOx6IsLb | q-873732594d | ok |
| 6 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | win.AccessMask | 0x1fffff | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZI2iSVpshTO39W66U | q-141d5002cc | ok |
| 7 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | win.ProcessName | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZI2iSVpshTO39W65K | q-141d5002cc | ok |
| 8 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOtIR1Pn | q-136ed6d288 | ok |
| 9 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOtIR1Pn | q-bfea890357 | ok |
| 10 | 2020-05-02 03:09:29.000Z | nashua.dmevals.local | windows.security | win.SubjectUserName | pbeesly | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZI2iSVpshTO32Nwbs | q-141d5002cc | ok |
| 11 | 2020-05-02 03:11:40.000Z | nashua.dmevals.local | windows.security | win.ObjectName | \REGISTRY\MACHINE\SYSTEM\ControlSet001\Control\Lsa | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZI2iSVpshTO31NCqM | q-141d5002cc | ok |
| 12 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZJGiSVpshTO3P0p0s | q-95bb75b549 | FAILED: claimed value differs from the stored value |
| 13 | 2020-05-02 03:06:42.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | Get-Clipboard | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZJGiSVpshTO3P0J3m | q-6a7795c748 | ok |

### F31 · malicious / high · T1552 · Unsecured credentials: attacker tooling on SCRANTON harvested certificates and embedded plaintext credentials

Evidence status: **verified**

The T1552 family activity is concentrated on scranton.dmevals.local under user pbeesly between 2020-05-02T03:04Z and 03:21Z: a Get-PrivateKeys function exported every LocalMachine certificate to .pfx files in Downloads (one observed: coyn5igj.3io.pfx), an Invoke-Exfil function embedded the plaintext credential cozy/MyCozyPassw0rd! and archived Downloads to OfficeSupplies.7z, and PsExec64.exe was launched with a cleartext password for dmevals\pbeesly against \\NASHUA. Surrounding activity (sdelete64 wiping files, accesschk, WebDAV cookie setup to 192.168.0.4, python.exe pushed to NASHUA) confirms a hands-on-keyboard intrusion rather than administrative tooling.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZJGiSVpshTO3P0p0s | q-0d502830b6 | ok |
| 2 | 2020-05-02 03:04:57.460Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOtao0x- | q-0433c05b78 | ok |
| 3 | 2020-05-02 03:11:18.784Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\PsExec64.exe" -accepteula \\NASHUA -u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOtGQk7R | q-dec15c6479 | ok |
| 4 | 2020-05-02 03:08:50.846Z | scranton.dmevals.local | windows.sysmon | process.command_line | rundll32.exe C:\windows\system32\davclnt.dll,DavSetCookie 192.168.0.4 http://192.168.0.4/webdav | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOtISlSY | q-dec15c6479 | ok |

### F63 · malicious / high · T1552 · Screensaver-named payload in C:\ProgramData\victim dropped the steganographic image monkey.png on SCRANTON

Evidence status: **verified**

On scranton.dmevals.local, explorer.exe launched C:\ProgramData\victim\â€®cod.3aka3.scr with /S at 02:55:56; that process wrote C:\Users\pbeesly\Downloads\monkey.png at 02:57:00, the image later decoded by the PowerShell steganography/IEX loader. This is the initial payload delivery that precedes the anchored credential access.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:55:56.157Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\ProgramData\victim\â€®cod.3aka3.scr" /S | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOx-Nf0f | q-2f4bdb6be6 | ok |
| 2 | 2020-05-02 02:57:00.933Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Users\pbeesly\Downloads\monkey.png | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOx9LDOJ | q-3e007c1589 | ok |

### F64 · malicious / high · T1552 · csc.exe runtime compilation of attacker DLLs from PowerShell on SCRANTON

Evidence status: **verified**

On scranton.dmevals.local, PowerShell spawned csc.exe twice (02:58:45 and 03:08:03) with @response files in random Temp directories, producing qkbkqqbs.dll and 0piklvia.dll. This runtime compilation (Add-Type) is the mechanism by which the attacker's credential-access code was built and loaded in memory.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:58:45.297Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe" /noconfig /fullpaths @"C:\Users\pbeesly\AppData\Local\Temp\qkbkqqbs\qkbkqqbs.cmdline" | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOx5IMzm | q-2f4bdb6be6 | ok |
| 2 | 2020-05-02 02:58:45.292Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Users\pbeesly\AppData\Local\Temp\qkbkqqbs\qkbkqqbs.dll | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOx5IMzh | q-3e007c1589 | ok |

### F27 · malicious / medium · T1552.001 · Credential-bearing script blocks and cleartext credentials in files/command lines on SCRANTON

Evidence status: **verified**

The same pbeesly PowerShell session on scranton.dmevals.local staged credentials in files and command lines: the 'Invoke-Exfil' function (ScriptBlock ID b2b03a9c-43f0-4285-837d-f22d4600b2ae, path C:\Program Files\SysinternalsSuite\psversion.ps1) embeds the plaintext credential cozy / MyCozyPassw0rd! and compresses the user's Downloads directory into $env:APPDATA\OfficeSupplies.7z with password 'lolol'; Sysmon shows that archive being created by powershell.exe at 2020-05-02T03:08:35Z. The attacker also passed a cleartext password on the command line when running PsExec64.exe against \\NASHUA (-u dmevals\pbeesly -p Fl0nk3rt0n!T0by). No evidence of searching for credentials inside configuration/unattend files was found (the file-creation stacks were Cortana/WER/GroupPolicy noise), so this finding covers credentials exposed in scripts and command lines rather than file-content harvesting.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZJGiSVpshTO3AvzkC | q-9242f83730 | ok |
| 2 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\psversion.ps1 | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZJGiSVpshTO3AvzkC | q-9242f83730 | ok |
| 3 | 2020-05-02 03:08:35.270Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Users\pbeesly\AppData\Roaming\OfficeSupplies.7z | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOtIS1QC | q-4d423f4883 | ok |
| 4 | 2020-05-02 03:11:18.784Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\PsExec64.exe" -accepteula \\NASHUA -u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOtGQk7R | q-dec15c6479 | ok |

### F58 · malicious / high · T1552.001 · PsExec64 launched with cleartext domain credentials in command line to stage python.exe on NASHUA

Evidence status: **verified**

On scranton.dmevals.local, user pbeesly's PowerShell ran C:\Program Files\SysinternalsSuite\PsExec64.exe four times (03:11:18, 03:12:25, 03:13:28, 03:14:42) with the domain password in cleartext on the command line (-u dmevals\pbeesly -p Fl0nk3rt0n!T0by) to start C:\Windows\Temp\python.exe on \\NASHUA. This is new relative to the anchors (which covered LSASS access and certificate export): the credential is embedded in the process command line and was used for lateral movement. On nashua.dmevals.local the corresponding PSEXESVC.exe service and python.exe children appear at 03:11:39-03:15:03.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:18.784Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\PsExec64.exe" -accepteula \\NASHUA -u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOtGQk7R | q-2f4bdb6be6 | ok |
| 2 | 2020-05-02 03:11:18.000Z | scranton.dmevals.local | windows.powershell | powershell.script_block.text | .\PsExec64.exe -accepteula \\NASHUA -u "dmevals\pbeesly" -p "Fl0nk3rt0n!T0by" -i 2 "C:\Windows\Temp\python.exe" | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZJGiSVpshTO3IxM8t | q-335e87da80 | ok |
| 3 | 2020-05-02 03:11:40.213Z | nashua.dmevals.local | windows.sysmon | process.command_line | "C:\Windows\Temp\python.exe"  | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOyESnYY | q-6f7b836566 | ok |

### F59 · malicious / high · T1552.001 · PowerShell on NASHUA collected user files matching credential keywords (*pass*, *login*, *admin*, *vpn) into working.zip

Evidence status: **verified**

On nashua.dmevals.local, a PowerShell session spawned by the PsExec-delivered C:\Windows\Temp\python.exe (03:15:48) ran a recursive ChildItem over the user profile for *.doc/*.pdf/*.zip/*.pst plus *psw*, *pass*, *login*, *admin*, *sifr*, *sifer*, *vpn, *.txt, *.lnk and compressed the results with Compress-Archive into $env:APPDATA\working.zip (written 03:16:00). It then ran Rar.exe with a hardcoded password to copy the archive to the Desktop (03:16:19) and deleted Rar.exe and both archives with sdelete64. This credential-file harvesting on NASHUA is new compared with the anchors, which were limited to scranton/nashua LSASS access and scranton certificate export.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:15:59.000Z | nashua.dmevals.local | windows.powershell | powershell.script_block.text | $env:APPDATA;$files=ChildItem -Path $env:USERPROFILE\ -Include *.doc,*.xps,*.xls,*.ppt,*.pps,*.wps,*.wpd,*.ods,*.odt,*.lwp,*.jtd,*.pdf,*.zip,*.rar,*.docx,*.url,… | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZJGiSVpshTO3JxTei | q-d70840b65a | ok |
| 2 | 2020-05-02 03:16:00.353Z | nashua.dmevals.local | windows.sysmon | file.path | C:\Users\pbeesly\AppData\Roaming\working.zip | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOyGVFIa | q-fb6d95645f | ok |
| 3 | 2020-05-02 03:16:19.395Z | nashua.dmevals.local | windows.sysmon | process.command_line | "C:\Windows\Temp\Rar.exe" a -hpfGzq5yKw C:\Users\pbeesly\Desktop\working.zip C:\Users\pbeesly\AppData\Roaming\working.zip | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOyBQa1A | q-6f7b836566 | ok |

### F26 · malicious / high · T1552.004 · Get-PrivateKeys PowerShell function exported all LocalMachine certificates to password-protected .pfx files in Downloads

Evidence status: **verified**

On scranton.dmevals.local, in the context of user pbeesly (SID S-1-5-21-1830255721-3727074217-2423397540-1107), a PowerShell script block named 'Get-PrivateKeys' (ScriptBlock ID 9d153741-75c3-4062-afe3-aeca0aee611b, loaded from C:\Program Files\SysinternalsSuite\readme.ps1) enumerated cert:\LocalMachine recursively and called Export-PfxCertificate for every certificate with a thumbprint, writing each to $env:USERPROFILE\Downloads\<random>.pfx protected with the hardcoded password 'saribas'. Sysmon recorded the resulting file creation C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx by powershell.exe (PID 3876) at 2020-05-02T03:04:57Z, one second after the script block was logged. This is private-key/certificate harvesting for later authentication abuse, part of a broader hands-on-keyboard intrusion on SCRANTON (discovery, Invoke-Exfil to WebDAV 192.168.0.4, PsExec to NASHUA with cleartext credentials).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZJGiSVpshTO3P0p0s | q-0d502830b6 | ok |
| 2 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\readme.ps1 | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZJGiSVpshTO3P0p0s | q-0d502830b6 | ok |
| 3 | 2020-05-02 03:04:57.460Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOtao0x- | q-0433c05b78 | ok |
| 4 | 2020-05-02 03:04:57.460Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\WindowsPowerShell\v1.0\powershell.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOtao0x- | q-0433c05b78 | ok |

### F62 · malicious / high · T1552.004 · Attacker toolkit (readme.ps1) staged in C:\Program Files\SysinternalsSuite and executed via dot-sourcing on SCRANTON

Evidence status: **verified**

On scranton.dmevals.local, pbeesly's PowerShell downloaded/extracted SysinternalsSuite.zip, moved it to C:\Program Files\SysinternalsSuite, renamed readme.txt to readme.ps1 and dot-sourced it at 03:03:57, then ran Invoke-Discovery, Invoke-Persistence and Get-PrivateKeys from it. The Get-PrivateKeys script block records Path: C:\Program Files\SysinternalsSuite\readme.ps1, confirming the certificate-export function came from this attacker-staged script rather than an interactive one-liner. This staging detail is new relative to the anchors.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:03:57.000Z | scranton.dmevals.local | windows.powershell | powershell.script_block.text | . .\readme.ps1 | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZJGiSVpshTO3Pz52j | q-0165f1819d | ok |
| 2 | 2020-05-02 03:03:49.000Z | scranton.dmevals.local | windows.powershell | powershell.script_block.text | Move-Item .\readme.txt readme.ps1 | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZJGiSVpshTO3Pz51j | q-0165f1819d | ok |
| 3 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\readme.ps1 | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZJGiSVpshTO3P0p0s | q-0ebc915bf2 | ok |

### F36 · malicious / medium · T1556 · Credential access from lsass by attacker-controlled PowerShell on SCRANTON, but no authentication-process modification observed

Evidence status: **verified**

On scranton.dmevals.local at 2020-05-02T02:58:44Z a hidden, execution-policy-bypassing PowerShell (PID 2976, user DMEVALS\pbeesly, parent control.exe /name Microsoft.BackupAndRestoreCenter) was launched with a steganographic payload that decodes bytes from C:\Users\pbeesly\Downloads\monkey.png and IEX's them. At 03:05:16Z that same PID 2976 opened lsass.exe (PID 736) with GrantedAccess 0x1F3FFF and 0x1FFFFF (full access, call trace ending in UNKNOWN module) — classic credential-dump access. The same session ran Invoke-Discovery, Invoke-Persistence, Invoke-Exfil, Invoke-ScreenCapture and Invoke-SeaDukeStage, and moved laterally to NASHUA (wsmprovhost.exe PID 7720 also opened lsass with 0x1F3FFF; PSEXESVC.exe logons as pbeesly). However, no evidence of authentication-process modification was found: no 4657 writes to LSA/Notification Packages/Reversible-Encryption keys, no 4739/5136 policy changes, no rogue DLLs in System32, and the only LSA registry writes seen are lsass.exe's own ProductType/LsaCfgFlagsDefault values. The lsass access is credential theft (T1003.001 territory), not T1556.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:58:44.325Z | scranton.dmevals.local | windows.sysmon | process.command_line | "PowerShell.exe" -noni -noexit -ep bypass -window hidden -c "sal a New-Object;Add-Type -AssemblyName 'System.Drawing'; $g=a System.Drawing.Bitmap('C:\Users\pbee… | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOx6IsLb | q-532998cd0f | ok |
| 2 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOtaokyU | q-1f72657aef | ok |
| 3 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOtaokyU | q-1f72657aef | ok |
| 4 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOtIR1Pn | q-ad3c2559b7 | ok |
| 5 | 2020-05-02 03:04:23.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | Invoke-Persistence -PersistStep 2 | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZJGiSVpshTO3Pz51x | q-d8b8a36208 | ok |
| 6 | 2020-05-02 03:19:10.368Z | scranton.dmevals.local | windows.sysmon | registry.path | HKLM\System\CurrentControlSet\Control\Lsa\ProductType | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOs4A9go | q-fcd5baf246 | ok |

### F52 · malicious / high · T1606.002 · PowerShell Get-PrivateKeys exports all LocalMachine certificates (private keys) to .pfx with hardcoded password on scranton

Evidence status: **verified**

On scranton.dmevals.local, user pbeesly ran a PowerShell toolkit disguised as 'readme.ps1' (moved from readme.txt inside a downloaded SysinternalsSuite archive, then dot-sourced with '. .\readme.ps1'). At 2020-05-02T03:04:56Z the script block 'Get-PrivateKeys' was created: it enumerates cert:\LocalMachine recursively and calls Export-PfxCertificate for every certificate with a thumbprint, writing to $env:USERPROFILE\Downloads\<random>.pfx protected by the hardcoded password 'saribas'. One second later (03:04:57.460Z) Sysmon recorded the resulting file C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx created by powershell.exe (PID 3876). Exporting machine private keys is the prerequisite for forging signed tokens (e.g. SAML assertions) and is not normal user behaviour; the same session also ran Invoke-Discovery, Invoke-Persistence, accesschk.exe and sdelete64.exe against the dropped payload and archive. The same PowerShell session (PID 2976) also opened lsass.exe with GrantedAccess 0x1FFFFF at 03:05:16Z.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZJGiSVpshTO3P0p0s | q-37d8d998aa | ok |
| 2 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\readme.ps1 | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZJGiSVpshTO3P0p0s | q-525038a397 | ok |
| 3 | 2020-05-02 03:04:57.460Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOtao0x- | q-e657a67cce | ok |
| 4 | 2020-05-02 03:03:49.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | Move-Item .\readme.txt readme.ps1 | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZJGiSVpshTO3Pz51j | q-37d8d998aa | ok |
| 5 | 2020-05-02 03:03:57.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | . .\readme.ps1 | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZJGiSVpshTO3Pz52j | q-37d8d998aa | ok |

### F55 · malicious / high · T1649 · Get-PrivateKeys PowerShell function exported all LocalMachine certificates to password-protected .pfx files on SCRANTON

Evidence status: **verified**

On scranton.dmevals.local, in the context of user pbeesly, a script block named Get-PrivateKeys was defined and executed (2020-05-02T03:04:56Z). It enumerates cert:\LocalMachine recursively, and for every certificate with a thumbprint exports it with Export-PfxCertificate to "$env:USERPROFILE\Downloads\$RandomFileName.pfx" protected by the hardcoded password "saribas". The script was staged as C:\Program Files\SysinternalsSuite\readme.ps1 (preceded by 'Move-Item .\readme.txt readme.ps1' at 03:03:49Z and dot-sourced with '. .\readme.ps1' at 03:03:57Z), i.e. a text file renamed to a script and executed. One second later Sysmon recorded the resulting file creation C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx by powershell.exe (PID 3876), confirming the export actually succeeded. This is theft of authentication certificates/private keys for later use (e.g. certificate-based authentication / forging). The same host also shows a suspicious binary C:\ProgramData\victim\â€®cod.3aka3.scr making outbound connections to 192.168.0.5 shortly before, consistent with an initial-access/execution stage on the same host.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZJGiSVpshTO3P0p0s | q-0b3d9fcb55 | ok |
| 2 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\readme.ps1 | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZJGiSVpshTO3P0p0s | q-0b3d9fcb55 | ok |
| 3 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | user.name | pbeesly | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZJGiSVpshTO3P0p0s | q-0b3d9fcb55 | ok |
| 4 | 2020-05-02 03:03:49.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | Move-Item .\readme.txt readme.ps1 | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZJGiSVpshTO3Pz51j | q-1ae908b0f5 | ok |
| 5 | 2020-05-02 03:03:57.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | . .\readme.ps1 | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZJGiSVpshTO3Pz52j | q-1ae908b0f5 | ok |
| 6 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | Get-PrivateKeys | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZJGiSVpshTO3Pz51N | q-1ae908b0f5 | ok |
| 7 | 2020-05-02 03:04:57.460Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOtao0x- | q-6ff27f2197 | ok |
| 8 | 2020-05-02 03:04:57.460Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\WindowsPowerShell\v1.0\powershell.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOtao0x- | q-6ff27f2197 | ok |
| 9 | 2020-05-02 02:55:59.631Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\ProgramData\victim\â€®cod.3aka3.scr | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOx-NP1p | q-f713cff8f2 | ok |

### F02 · suspicious / medium · T1003.001 · wsmprovhost.exe (PowerShell remoting session) opened LSASS with 0x1F3FFF on nashua

Evidence status: **verified**

On nashua.dmevals.local, wsmprovhost.exe PID 7720 (started 03:09:23 as pbeesly via svchost -Embedding, i.e. a PowerShell remoting/WinRM session) opened lsass.exe (PID 728) at 03:09:29 with GrantedAccess 0x1F3FFF. The call trace runs through System.ni.dll and Microsoft.PowerShell.Commands.Management.ni.dll, i.e. the access came from a PowerShell cmdlet in the remote session; the only script block logged in that session at 03:09:28-29 is 'Get-Process -IncludeUserName \| Select-Object UserName,SessionId \| Where-Object { $_.UserName -like "*\$env:USERNAME" }'. That cmdlet normally needs only query access, so the 0x1F3FFF mask is anomalous, but no dump file or dumping tool was observed on nashua.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOtIR1Pn | q-3f68bd099c | ok |
| 2 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOtIR1Pn | q-3f68bd099c | ok |
| 3 | 2020-05-02 03:09:23.885Z | nashua.dmevals.local | windows.sysmon | process.command_line | C:\windows\system32\wsmprovhost.exe -Embedding | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOtISFPF | q-e740b77bbc | ok |
| 4 | 2020-05-02 03:09:28.000Z | nashua.dmevals.local | windows.powershell | win.ScriptBlockText |  Get-Process -IncludeUserName \| Select-Object UserName,SessionId \| Where-Object { $_.UserName -like "*\$env:USERNAME" } \| Sort-Object SessionId -Unique  | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZJGiSVpshTO3Iwxm0 | q-bcfc1bee58 | ok |

### F12 · suspicious / medium · T1056.004 · wsmprovhost.exe (PowerShell Remoting) opened lsass.exe with 0x1F3FFF on nashua.dmevals.local

Evidence status: **verified**

On nashua.dmevals.local at 2020-05-02 03:09:29Z, C:\windows\system32\wsmprovhost.exe (PID 7720, the PowerShell Remoting host) opened lsass.exe (PID 728) with GrantedAccess 0x1F3FFF. The call trace runs through System.ni.dll and Microsoft.PowerShell.Commands.Management.ni.dll, i.e. a PowerShell cmdlet issued over a remote WinRM session requested a full-rights handle to lsass. This is the only wsmprovhost.exe lsass access in the dataset and matches the same credential-access pattern seen on scranton, indicating the operator pivoted to nashua via PowerShell Remoting.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOtIR1Pn | q-0202b73f79 | ok |
| 2 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOtIR1Pn | q-0202b73f79 | ok |
| 3 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | host.name | nashua.dmevals.local | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOtIR1Pn | q-0202b73f79 | ok |

### F65 · suspicious / medium · T1552 · hostui.exe launched with -verb runas followed by registry-value Invoke-Expression on SCRANTON

Evidence status: **verified**

On scranton.dmevals.local at 03:21:26-03:21:28, PowerShell ran 'Start-Process C:\Windows\System32\hostui.exe -verb runas' and then executed a registry value via Invoke-Expression, followed by a reflective P/Invoke loader (function jzI using GetProcAddress). This is an elevation/execution step in the intrusion chain, not previously covered by the anchors.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:21:27.276Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Windows\System32\hostui.exe"  | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOoDOLr2 | q-2f4bdb6be6 | ok |
| 2 | 2020-05-02 03:21:28.000Z | scranton.dmevals.local | windows.powershell | powershell.script_block.text | Get-ItemPropertyValue 'HKLM:\\SOFTWARE\Javasoft' 'value Supplement' \| Invoke-Expression | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZJGiSVpshTO3Q03Gn | q-335e87da80 | ok |

### F66 · suspicious / medium · T1552 · sdclt.exe UAC-bypass pattern with HKCU Folder\shell\open\command DelegateExecute on SCRANTON

Evidence status: **verified**

On scranton.dmevals.local, cmd.exe launched sdclt.exe three times at 02:58:42-02:58:43 while PowerShell was creating HKCU\Software\Classes\Folder\shell\open\command with a DelegateExecute value (02:57:18-02:58:28) and then removed the key at 02:59:15. This matches the sdclt UAC-bypass pattern used to elevate the attacker's code.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:58:42.401Z | scranton.dmevals.local | windows.sysmon | process.command_line | C:\windows\system32\sdclt.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOx6JcI- | q-2f4bdb6be6 | ok |
| 2 | 2020-05-02 02:58:28.000Z | scranton.dmevals.local | windows.powershell | powershell.script_block.text | Set-ItemProperty -Path "HKCU:\Software\Classes\Folder\shell\open\command" -Name "DelegateExecute" -Force | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZJGiSVpshTO3V6Js6 | q-00f2232ea5 | ok |

### F32 · suspicious / medium · T1555 · PowerShell and PowerShell-remoting processes opened lsass with full read rights on scranton and nashua

Evidence status: **verified**

On scranton.dmevals.local, PowerShell.exe (pid 2976) opened lsass.exe (pid 736) with GrantedAccess 0x1FFFFF at 2020-05-02T03:05:16.654Z and a second handle with 0x1f3fff at 03:05:16.623Z; the call trace ends in an UNKNOWN module rather than a known Windows DLL. On nashua.dmevals.local, wsmprovhost.exe (pid 7720) opened lsass (pid 728) with 0x1f3fff at 03:09:29.430Z, but its call trace runs through System.ni.dll and Microsoft.PowerShell.Commands.Management.ni.dll, consistent with the Get-Process -IncludeUserName cmdlet logged at 23:09:28 rather than memory dumping. No procdump/comsvcs/MiniDump/sekurlsa command lines, no lsass dump files, and no 4663 object-access on lsass by these processes were observed. The scranton PowerShell handle remains unexplained and coincides with a compromised host (cmd.exe spawned from C:\ProgramData\victim\...cod.3aka3.scr and a hidden -ep bypass PowerShell loader), so it is treated as suspicious rather than confirmed dumping.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOtaokyU | q-396665d6af | ok |
| 2 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOtaokyU | q-396665d6af | ok |
| 3 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.CallTrace | C:\windows\SYSTEM32\ntdll.dll+9c584\|C:\windows\System32\KERNELBASE.dll+2732e\|UNKNOWN(000001996D28200D) | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOtaokyU | q-396665d6af | ok |
| 4 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOtIR1Pn | q-bd7e5eec19 | ok |
| 5 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOtIR1Pn | q-bd7e5eec19 | ok |
| 6 | 2020-05-02 03:09:28.000Z | nashua.dmevals.local | windows.powershell | win.ScriptBlockText |  Get-Process -IncludeUserName \| Select-Object UserName,SessionId \| Where-Object { $_.UserName -like "*\$env:USERNAME" } \| Sort-Object SessionId -Unique  | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZJGiSVpshTO3Iwxm0 | q-801302c490 | ok |
| 7 | 2020-05-02 02:56:14.000Z | scranton.dmevals.local | windows.security | process.parent.executable | C:\Windows\System32\cmd.exe | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZJGiSVpshTO0EgbIk | q-a04f436c94 | ok |

### F61 · suspicious / medium · T1555.003 · Get-Clipboard credential harvesting and Invoke-Exfil staging on SCRANTON

Evidence status: **verified**

On scranton.dmevals.local, pbeesly's PowerShell ran Get-Clipboard at 03:06:42 (harvesting clipboard contents, a common source of pasted passwords) and then Invoke-Exfil at 03:08:02, which loaded the 7-Zip PowerShell module (module manifest events at 03:08:34-03:08:35) and defined Invoke-BeachCleanup that deletes Downloads\*.pfx, *.bmp, *.png and $env:APPDATA\OfficeSupplies.7z - i.e. the collected certificate, screenshot and archive artifacts. The exfil staging of the harvested credentials is new relative to the anchors.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:06:42.000Z | scranton.dmevals.local | windows.powershell | powershell.script_block.text | Get-Clipboard | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZJGiSVpshTO3P0J3m | q-0165f1819d | ok |
| 2 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | powershell.script_block.text | Invoke-Exfil | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZJGiSVpshTO3NxogH | q-a38568493c | ok |
| 3 | 2020-05-02 03:08:51.000Z | scranton.dmevals.local | windows.powershell | powershell.script_block.text | function Invoke-BeachCleanup {     Write-Host "[*] Cleaning up"     Remove-Item -Path "$env:USERPROFILE\Downloads\*.pfx" -Force     Remove-Item -Path "$env:USER… | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZJGiSVpshTO3JxTeO | q-406c37e592 | ok |

### F47 · suspicious / medium · T1558 · PowerShell and WSMAN host processes opened lsass.exe with full-access masks on scranton and nashua (credential access, but no Kerberos ticket theft observed)

Evidence status: **verified**

On 2020-05-02 at 03:05:16, PowerShell.exe (PID 2976) on scranton.dmevals.local opened lsass.exe (PID 736) with GrantedAccess 0x1F3FFF and then 0x1FFFFF, with a call trace ending in an UNKNOWN module — consistent with in-memory credential access rather than a signed Windows component. At 03:09:29 on nashua.dmevals.local, wsmprovhost.exe (PID 7720, the WinRM host) opened lsass.exe with 0x1F3FFF, with a call trace through System.ni.dll / Microsoft.PowerShell.Commands.Management.ni.dll, i.e. a PowerShell remoting session touching lsass. The same scranton host shows a hands-on-keyboard PowerShell toolkit in script-block logging (Get-Keystrokes, Invoke-ScreenCapture, Get-Clipboard, AV-process discovery, Invoke-Exfil with 7Zip4Powershell and password 'lolol', and a base64/gzip hidden-window launcher), plus a dropped C:\ProgramData\victim\...scr writing C:\Users\pbeesly\Downloads\monkey.png. However, no Kerberos-specific ticket theft was observed: no 4768/4769 anomalies (all tickets AES 0x12, no RC4, no failures, only pbeesly and machine accounts), no ticket-dumping tooling in process command lines, and no Kerberos/ticket strings in script blocks. The lsass access is therefore assessed as credential dumping (T1003.001 territory) rather than T1558 ticket theft.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOtaokyR | q-d36336ab30 | ok |
| 2 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOtaokyU | q-0a8bd44da9 | ok |
| 3 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOtaokyR | q-d36336ab30 | ok |
| 4 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOtIR1Pn | q-3e56719bcf | ok |
| 5 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOtIR1Pn | q-3e56719bcf | ok |
| 6 | 2020-05-02 03:06:59.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | Get-Keystrokes;Start-Sleep -Seconds 15;View-Job -JobName "Keystrokes" | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZJGiSVpshTO3P0J3p | q-e8892b00f8 | ok |
| 7 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZJGiSVpshTO3AvzkC | q-326925f05e | ok |
| 8 | 2020-05-02 02:57:00.933Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Users\pbeesly\Downloads\monkey.png | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOx9LDOJ | q-b2df00dd0f | ok |

### F53 · suspicious / medium · T1606 · PowerShell toolkit on scranton opened lsass.exe with full access (0x1FFFFF) right after certificate export

Evidence status: **verified**

On scranton.dmevals.local, PowerShell.exe (PID 2976, the interactive session driven by pbeesly that ran the readme.ps1 toolkit) opened lsass.exe (PID 736) twice at 2020-05-02T03:05:16Z with GrantedAccess 0x1F3FFF and 0x1FFFFF, i.e. full process access including memory read, minutes after the Get-PrivateKeys certificate export. The other high-access lsass events in the window come from OS components (wininit.exe, csrss.exe, svchost.exe) and are consistent with normal system behaviour, but a user-launched PowerShell requesting 0x1FFFFF on lsass is not. No SAML/cookie-specific forging artefacts were observed, so this is reported as suspicious credential-access activity in the T1606 family rather than confirmed token forgery.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOtaokyU | q-f1fd5ada21 | ok |
| 2 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOtaokyU | q-f1fd5ada21 | ok |
| 3 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOtaokyR | q-9bb08c601e | ok |

### F03 · benign / high · T1003.001 · Routine svchost/Azure-agent LSASS handle accesses (0x1000/0x1400) are benign

Evidence status: **verified**

The bulk of the 326 lsass process-access events are svchost.exe (289), AntimalwareConfig.exe (15) and WindowsAzureTelemetryService.exe (13) with GrantedAccess 0x1000/0x1400, plus wininit.exe/csrss.exe 0x1FFFFF at 03:19:09 which coincides with a new lsass.exe process creation (PID 748) — i.e. normal process-start/telemetry behaviour. The only .dmp files written were WerFault.exe WER temp dumps (WER51F5.tmp.dmp, WER5437.tmp.dmp), not LSASS dumps. No comsvcs MiniDump, procdump or mimikatz command line was found.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:56:14.000Z | utica.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\svchost.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOx-M_2G | q-08d9791693 | ok |
| 2 | 2020-05-02 03:19:09.803Z | scranton.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\wininit.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOs4A9hl | q-cc9a9f63cc | ok |
| 3 | 2020-05-02 03:05:27.395Z | nashua.dmevals.local | windows.sysmon | win.TargetFilename | C:\ProgramData\Microsoft\Windows\WER\Temp\WER51F5.tmp.dmp | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOtYnKtJ | q-c4ecf00dc7 | ok |
| 4 | 2020-05-02 03:19:09.809Z | scranton.dmevals.local | windows.sysmon | process.command_line | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOs4A9hk | q-e292ae6a4f | ok |

### F04 · benign / medium · T1003.002 · No SAM hive dumping observed

Evidence status: **verified**

No 'reg save' of SAM/SYSTEM/SECURITY, no 4663 object access to SAM/SECURITY registry hives, and no PowerShell script block referencing reg save or hive export was found in any dataset. The only registry object-access targets were Lsa, Session Manager\Environment and Winlogon keys, which are normal system activity.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:03:00.000Z | scranton.dmevals.local | windows.security | win.ObjectName | Policy\Secrets\$MACHINE.ACC | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZI2iSVpshTO39Xq5t | q-eaa4ff7129 | ok |

### F05 · benign / medium · T1003.003 · No NTDS.dit / ntdsutil / vssadmin activity observed

Evidence status: **verified**

No process creation with ntdsutil, vssadmin or ntds.dit in the command line, no file creation of *.dit, and no 4663 access to ntds.dit in windows.sysmon or windows.security. The hosts are member workstations/servers, not domain controllers, so NTDS extraction is not applicable here.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:09.809Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\Windows\System32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOs4A9hk | q-e292ae6a4f | ok |

### F06 · benign / medium · T1003.004 · LSA Secrets reads are LOCAL SERVICE machine-account operations

Evidence status: **verified**

The only 4662 events on Policy\Secrets were 'Policy\Secrets\$MACHINE.ACC' with AccessMask 0x2 by LOCAL SERVICE on nashua, scranton, utica and nashua/utica again — routine machine-account secret access by the local service, not lsadump/secretsdump. No mimikatz/lsadump command line or SECURITY\Policy\Secrets registry access was found.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:02:59.000Z | nashua.dmevals.local | windows.security | win.ObjectName | Policy\Secrets\$MACHINE.ACC | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZI2iSVpshTO3-XnWS | q-eaa4ff7129 | ok |
| 2 | 2020-05-02 03:02:59.000Z | nashua.dmevals.local | windows.security | win.SubjectUserName | LOCAL SERVICE | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZI2iSVpshTO3-XnWS | q-eaa4ff7129 | ok |

### F07 · benign / medium · T1003.005 · No cached domain credential (DCC) access observed

Evidence status: **verified**

No 4663 object access to SECURITY\Cache and no PowerShell script block referencing cache/dcc/secretsdump was found. The only lsass-related object access recorded in windows.security was the powershell.exe handle on scranton (already covered under T1003.001) and routine CollectGuestLogs/MsMpEng accesses; nothing touched the LSA cached-credentials store.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | win.ObjectName | \Device\HarddiskVolume2\Windows\System32\lsass.exe | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZI2iSVpshTO39W64C | q-79cf3a74a2 | ok |

### F08 · benign / low · T1003.006 · Single 4662 directory-replication access on newyork is not DCSync

Evidence status: **verified**

One 4662 on newyork.dmevals.local at 03:16:15 shows subject NEWYORK$ with AccessMask 0x100 and replication GUIDs {1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}/{19195a5b-6da0-11d0-afd3-00c04fd930c9}. The subject is the machine account itself (not a user or attacker-controlled principal), there is no matching DRSUAPI network traffic in the overlapping window, and no DCSync/Invoke-Mimikatz/drsuapi script block was found, so this is assessed as benign machine-account directory access rather than a DCSync attack.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:16:15.000Z | newyork.dmevals.local | windows.security | win.SubjectUserName | NEWYORK$ | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZI2iSVpshTO3zLZNi | q-eaa4ff7129 | ok |
| 2 | 2020-05-02 03:16:15.000Z | newyork.dmevals.local | windows.security | win.Properties | %%7688  		{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}  	{19195a5b-6da0-11d0-afd3-00c04fd930c9}   | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZI2iSVpshTO3zLZNi | q-eaa4ff7129 | ok |

### F09 · benign / high · T1040 · netsh packet capture on scranton.dmevals.local is the Azure Network Watcher agent, not adversary sniffing

Evidence status: **verified**

The only packet-capture activity in the Windows window is two netsh.exe executions on scranton.dmevals.local at 2020-05-02T03:19:17Z and 03:19:24Z: 'netsh.exe trace start capture=yes traceFile="C:\windows\TEMP\E7116ECA-DFE6-43C7-8FA8-8D3AC5AA8726\B91E06C5-1C7C-4830-9A76-74FA211560A7.etl"' followed by 'netsh.exe trace stop'. Both were spawned by C:\Packages\Plugins\Microsoft.Azure.NetworkWatcher.NetworkWatcherAgentWindows\1.4.1421.1\NetworkWatcherAgent\NetworkWatcherAgent.exe /service and ran as NT AUTHORITY\SYSTEM (LogonId 0x3E7, IntegrityLevel System) with the genuine Microsoft-signed netsh.exe (OriginalFileName netsh.exe, Company Microsoft Corporation). This is the Azure Network Watcher platform agent performing its own diagnostic capture, so it is benign platform behaviour rather than an attacker sniffing credentials. No third-party capture tooling was observed anywhere: zero hits for pktmon/windump/tcpdump/rawcap/dumpcap/wireshark/tshark/npcap/winpcap/promiscuous in sysmon EID 1, security 4688 or PowerShell 4104, and zero sysmon EID 7 image loads matching pcap/npf/wpcap/Packet (no Npcap/WinPcap driver). The 5 EID 7045 service installs are a Java VM support service and four PSEXESVC installs by pbeesly on nashua.dmevals.local (PsExec lateral movement), none of which is a capture driver. The non-overlapping zeek window (2020-04-30) shows only ssl/dns/kerberos/dce_rpc/smb/http services with no capture-related traffic.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:17.154Z | scranton.dmevals.local | windows.sysmon | process.command_line | C:\windows\system32\netsh.exe trace start capture=yes traceFile="C:\windows\TEMP\E7116ECA-DFE6-43C7-8FA8-8D3AC5AA8726\B91E06C5-1C7C-4830-9A76-74FA211560A7.etl" | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOonrxo5 | q-58d84a1bd5 | ok |
| 2 | 2020-05-02 03:19:17.154Z | scranton.dmevals.local | windows.sysmon | process.parent.executable | C:\Packages\Plugins\Microsoft.Azure.NetworkWatcher.NetworkWatcherAgentWindows\1.4.1421.1\NetworkWatcherAgent\NetworkWatcherAgent.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOonrxo5 | q-e4deb8c865 | ok |
| 3 | 2020-05-02 03:19:17.154Z | scranton.dmevals.local | windows.sysmon | user.name | SYSTEM | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOonrxo5 | q-58d84a1bd5 | ok |
| 4 | 2020-05-02 03:19:24.835Z | scranton.dmevals.local | windows.sysmon | process.command_line | C:\windows\system32\netsh.exe trace stop | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOosxQHp | q-58d84a1bd5 | ok |
| 5 | 2020-05-02 03:19:17.000Z | scranton.dmevals.local | windows.security | process.command_line | C:\windows\system32\netsh.exe trace start capture=yes traceFile="C:\windows\TEMP\E7116ECA-DFE6-43C7-8FA8-8D3AC5AA8726\B91E06C5-1C7C-4830-9A76-74FA211560A7.etl" | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZJGiSVpshTO0HjD-1 | q-c133861175 | ok |
| 6 | 2020-05-02 03:11:39.000Z | nashua.dmevals.local | windows.other | win.ServiceName | PSEXESVC | .ds-logs-windows.other-default-2026.10.20-000001 / AaFZJGiSVpshTO1pngK- | q-5737e4a48f | ok |

### F14 · benign / medium · T1056.001 · No keylogger artifacts: no keyboard-hook script blocks, no keylogger service or driver installs

Evidence status: **verified**

Searches for GetAsyncKeyState/SetWindowsHookEx/keylog in PowerShell 4104 script blocks returned zero hits, and the only registry writes touching keyboard paths are default Windows keyboard-layout/device-enumeration entries (HKU\.DEFAULT\Keyboard Layout\Preload, TERMINPUT_BUS device parameters). The five 7045 service installs in windows.other are a Java VM support service (javamtsup.exe) on scranton and four PSEXESVC installs on nashua by pbeesly — PsExec remote execution, not a keyboard filter driver. No keylogging was observed; the input capture on this estate was screen-based (T1056.002).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:39.000Z | nashua.dmevals.local | windows.other | message | A service was installed in the system.    Service Name:  PSEXESVC  Service File Name:  %SystemRoot%\PSEXESVC.exe  Service Type:  user mode service  Service Star… | .ds-logs-windows.other-default-2026.10.20-000001 / AaFZJGiSVpshTO1pngK- | q-2287ded4f7 | ok |
| 2 | 2020-05-02 03:04:15.000Z | scranton.dmevals.local | windows.other | process.executable | C:\Windows\System32\javamtsup.exe | .ds-logs-windows.other-default-2026.10.20-000001 / AaFZJGiSVpshTO1pngIR | q-2287ded4f7 | ok |

### F15 · benign / medium · T1056.003 · No web portal capture: no login-portal files, no inetpub/wwwroot writes, no login URLs in HTTP logs

Evidence status: **verified**

No 4663 object access to wwwroot/inetpub/.aspx files, no file creations named login/portal/wwwroot, and no HTTP requests to login/auth/signin URLs in the zeek window. The only 'login' matches are PowerShell archive-staging script blocks that enumerate user files matching *login*, *pass*, *psw* etc. and Compress-Archive them (scranton 03:05:17Z, nashua 03:15:59Z) — that is file collection/staging, not web portal credential capture. No web-server component was installed by the 7045 service events.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:56:17.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | $env:APPDATA;$files=ChildItem -Path $env:USERPROFILE\ -Include *.doc,*.xps,*.xls,*.ppt,*.pps,*.wps,*.wpd,*.ods,*.odt,*.lwp,*.jtd,*.pdf,*.zip,*.rar,*.docx,*.url,… | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZJGiSVpshTO3V6Jtq | q-ac621f6181 | ok |

### F13 · benign / high · T1056.004 · Routine lsass handle access by OS/Azure agents (0x1000, 0x1400, 0x1FFFFF by wininit/csrss) is benign

Evidence status: **verified**

The bulk of the 326 lsass process-access events are benign: 289 from svchost.exe with GrantedAccess 0x1000 (query-only), 15 from the Azure IaaS antimalware AntimalwareConfig.exe and 13 from WindowsAzureTelemetryService.exe with 0x1400, all with call traces through CorperfmonExt.dll/perfts.dll (performance-counter enumeration). The 0x1FFFFF/0x1000000 handles at 03:19:09Z come from wininit.exe and csrss.exe during session initialization, and the 0x101001 handles from svchost.exe via lsm.dll (Local Session Manager). None of these represent attacker credential access.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:09.803Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\wininit.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOs4A9hl | q-115ba048c6 | ok |
| 2 | 2020-05-02 03:18:34.438Z | scranton.dmevals.local | windows.sysmon | win.CallTrace | C:\windows\SYSTEM32\ntdll.dll+9def4\|c:\windows\system32\lsm.dll+1aa6e\|c:\windows\system32\lsm.dll+1a9c3\|c:\windows\system32\lsm.dll+65e1\|c:\windows\system32… | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOs7DwuP | q-115ba048c6 | ok |
| 3 | 2020-05-02 03:19:59.323Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x3000 | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOoWdgoz | q-d3992c7fde | ok |

### F16 · benign / high · T1110 · No brute-force authentication activity; only successful single-account logons observed

Evidence status: **verified**

Across windows.security (2020-05-02 02:55-03:28Z) there are zero 4625 failed-logon events and zero 4771 Kerberos pre-auth failures. The only 4776 NTLM credential validation is a single SUCCESS (Error Code 0x0) for pbeesly from workstation 10.0.1.4 on newyork.dmevals.local at 23:20:40. 4624 logons are dominated by machine accounts (NEWYORK$ 123, SYSTEM 60, SCRANTON$ 37) and pbeesly (30), with no repetition pattern indicating guessing. The C084 hit (svchost.exe/netsh.exe/userinit.exe matching *net*/*user*/*password* in command lines) is normal Windows service and network-configuration command-line text, not authentication tooling.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:20:40.000Z | newyork.dmevals.local | windows.security | message | The computer attempted to validate the credentials for an account.    Authentication Package:	MICROSOFT_AUTHENTICATION_PACKAGE_V1_0  Logon Account:	pbeesly  Sou… | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZI2iSVpshTO3mCkhu | q-c6b6fe298a | ok |
| 2 | 2020-05-02 03:20:40.000Z | newyork.dmevals.local | windows.security | win.TargetUserName | pbeesly | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZI2iSVpshTO3mCkhu | q-c6b6fe298a | ok |

### F17 · benign / high · T1110.001 · No password-guessing attempts; no failed logons or net user/net use enumeration

Evidence status: **verified**

Checks C087-C091 returned no hits: no 4625 events at all in windows.security, and no 'net user'/'net use' process creations in windows.sysmon. The only PowerShell script blocks matching *password*/*Login* are module manifests and localized resource strings (e.g. MSFT_ScriptResourceStrings.psd1) on newyork.dmevals.local, not guessing logic. The single RDP session on scranton.dmevals.local (1149 authentication succeeded, 21 session logon succeeded for DMEVALS\pbeesly from 172.18.39.2) is a successful interactive logon, not repeated guessing.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:20:42.000Z | scranton.dmevals.local | windows.other | message | Remote Desktop Services: User authentication succeeded:    User: pbeesly  Domain: dmevals  Source Network Address: 172.18.39.2 | .ds-logs-windows.other-default-2026.10.20-000001 / AaFZJGiSVpshTO1pngJm | q-da16f4ab44 | ok |
| 2 | 2020-05-02 03:01:30.000Z | newyork.dmevals.local | windows.powershell | message | Creating Scriptblock text (1 of 1):  # Localized	09/15/2018 04:54 AM (GMT)	303:6.40.10614 	MSFT_ScriptResourceStrings.psd1  # Localized MSFT_ScriptResourceStrin… | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZJGiSVpshTO3Q199Y | q-cfc9178d4e | ok |

### F18 · benign / medium · T1110.002 · No offline-cracking artifacts (no hive/NTDS dumps); lsass access by PowerShell is credential theft, not cracking

Evidence status: **verified**

No evidence of password cracking: no reg save/ntds.dit/SAM dump command lines (C096 zero hits), no 4663 access to SAM/SECURITY/NTDS objects (C093 zero hits), and the only EventCode 11 files matching SAM/SECURITY are Prefetch files for SecurityHealthHost/Service/Systray. The 326 lsass process-access events (C098) are dominated by svchost.exe (289), Azure antimalware/telemetry (28) and a handful of system processes; only 4 come from PowerShell. Two of those are PowerShell (PID 3876, thread 5584) opening lsass with GrantedAccess 0x1000 on scranton.dmevals.local at 03:01:03Z, which is consistent with credential access (T1003) rather than brute force/cracking, and is out of scope for T1110. The 4670 permission-change events all have ObjectName '-' (no credential file).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:01:03.622Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1000 | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOtjz-FD | q-909fc0cc1e | ok |
| 2 | 2020-05-02 03:01:03.622Z | scranton.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\WindowsPowerShell\v1.0\powershell.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOtjz-FD | q-909fc0cc1e | ok |

### F19 · benign / high · T1110.003 · No password spraying; 4648 explicit-credential logons are local system pseudo-accounts

Evidence status: **verified**

No 4625 or 4771 events exist, so there is no spray pattern across accounts. The 15 4648 events (C104) break down as pbeesly 9 plus UMFD-0/1/2, DWM-1/2 and SCRANTON$ — the latter six are Font Driver Host / Window Manager / machine-account logons by S-1-5-18 on scranton.dmevals.local at 23:19-23:20, which is standard Windows session behaviour. The single runas hit (C105) is 'powershell.exe -c "Start-Process C:\Windows\System32\hostui.exe -verb runas"' by pbeesly on scranton.dmevals.local at 03:21:19Z — a local UAC elevation, not credential spraying. PowerShell script blocks matching Credential/Password are module manifests and resource strings.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:10.000Z | scranton.dmevals.local | windows.security | win.TargetUserName | UMFD-0 | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZJGiSVpshTO0KlA9b | q-abdc1b3498 | ok |
| 2 | 2020-05-02 03:21:19.323Z | scranton.dmevals.local | windows.sysmon | process.command_line | powershell.exe  -c "Start-Process C:\Windows\System32\hostui.exe -verb runas" | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOoXemmg | q-8c99a56f7f | ok |

### F20 · benign / high · T1110.004 · No credential stuffing; hardcoded credentials in PowerShell belong to exfiltration, not stuffing

Evidence status: **verified**

No 4625 failures and no authentication attempts against multiple accounts, so no stuffing. The two PowerShell script blocks matching password/credential (C112) are localized resource strings on newyork.dmevals.local. Separately, scranton.dmevals.local shows hardcoded credentials in attacker-style scripts run as pbeesly: Get-PrivateKeys exports all LocalMachine certificates to .pfx with password 'saribas' (23:04:56), and Invoke-Exfil builds a PSCredential for user 'cozy' to map \\192.168.0.4\webdav and copy a 7z archive (23:08:02). These are credential theft/exfiltration (T1552/T1048), not brute force, and are outside the T1110 family.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZJGiSVpshTO3P0p0s | q-400335d6fb | ok |
| 2 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZJGiSVpshTO3AvzkC | q-d5f93f4e36 | ok |

### F21 · benign / high · T1111 · No MFA/smart-card interception activity; credential-related hits are benign Windows components and unrelated lateral movement

Evidence status: **verified**

Across windows.sysmon, windows.security, windows.powershell and windows.other (2020-05-02 02:55–03:28Z) there is no evidence of MFA interception: no process was created with smart-card, credential-provider, VaultCmd, NgcCtnr or MFA-related command lines (0 hits in both sysmon event.code:1 and security 4688), and no smart-card service (SCardSvr) or credential-provider DLL was installed or modified. The 12 registry hits touching SmartCard/Credential paths are all routine: services.exe writing MuiCache entries for SCardSvr.dll and creating the built-in CredentialEnrollmentManagerUserSvc_13619b service on scranton, and lsass.exe writing its own boot-time LSA values (LsaPid, LsaCfgFlagsDefault, ProductType) plus DeviceGuard\Scenarios\CredentialGuard\Enabled=0 on scranton at 03:19:09Z — normal LSA initialization, not tampering. The single windows.other 'Credential Guard configuration: 0x0, 0' event (Wininit event 14, SYSTEM) is a boot-time status report. The 15 security 4648 explicit-credential events are pbeesly authenticating to NASHUA (10.0.1.6) and locally via C:\Windows\PSEXESVC.exe between 23:11 and 23:15 local, i.e. PsExec lateral movement (PSEXESVC service installed four times on nashua), not MFA token or OTP interception. The 4104 script block matching 'Credential' is an Invoke-Exfil function on scranton that hardcodes a 'cozy' account password for a WebDAV upload — credential use for exfiltration, not MFA interception. No MFA bypass, no smart-card/OTP capture, no authentication-package or SSP registration was observed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:09.865Z | scranton.dmevals.local | windows.sysmon | registry.path | HKLM\System\CurrentControlSet\Control\DeviceGuard\Scenarios\CredentialGuard\Enabled | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOs4A9hu | q-64416cddaf | ok |
| 2 | 2020-05-02 03:19:09.834Z | scranton.dmevals.local | windows.sysmon | registry.path | HKLM\System\CurrentControlSet\Control\Lsa\LsaPid | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOs4A9hp | q-64416cddaf | ok |
| 3 | 2020-05-02 03:19:49.376Z | scranton.dmevals.local | windows.sysmon | registry.path | HKU\.DEFAULT\Software\Classes\Local Settings\MuiCache\4\52C64B7E\@%SystemRoot%\System32\SCardSvr.dll,-1 | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOoWeAuy | q-7daf7e684f | ok |
| 4 | 2020-05-02 03:20:48.264Z | scranton.dmevals.local | windows.sysmon | registry.path | HKLM\System\CurrentControlSet\Services\CredentialEnrollmentManagerUserSvc_13619b\ImagePath | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOoRaEln | q-7daf7e684f | ok |
| 5 | 2020-05-02 03:19:09.000Z | scranton.dmevals.local | windows.other | message | Credential Guard configuration: 0x0, 0 | .ds-logs-windows.other-default-2026.10.20-000001 / AaFZJGiSVpshTO1pnQLs | q-5d97c12dbb | ok |
| 6 | 2020-05-02 03:11:40.000Z | nashua.dmevals.local | windows.security | win.ProcessName | C:\Windows\PSEXESVC.exe | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZI2iSVpshTO31NCqL | q-9ee6363fc5 | ok |
| 7 | 2020-05-02 03:11:18.000Z | scranton.dmevals.local | windows.security | win.TargetServerName | NASHUA | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZI2iSVpshTO31NSq9 | q-9ee6363fc5 | ok |
| 8 | 2020-05-02 03:11:39.000Z | nashua.dmevals.local | windows.other | win.ServiceName | PSEXESVC | .ds-logs-windows.other-default-2026.10.20-000001 / AaFZJGiSVpshTO1pngK- | q-b086f83fc1 | ok |
| 9 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZJGiSVpshTO3AvzkC | q-f296c2ca15 | ok |

### F22 · benign / medium · T1187 · No forced-authentication (T1187) activity observed; SMB/WebDAV hits are internal domain infrastructure and attacker-side exfil, not credential coercion

Evidence status: **verified**

Hunting for T1187 on 2020-05-02 02:55-03:28Z found no evidence of forced authentication. (1) The three .lnk creations (Sysmon 11) are not lure files: two are Explorer-generated Recent-items shortcuts for 'Backup and Restore (Windows 7)' and 'System and Security' on scranton (C:\windows\Explorer.EXE, 02:58:44), and the third is C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\hostui.lnk written at 03:04:23 by the PowerShell process {47ab858c-e23d-5eac-c603-000000000400} (pid 3876, user DMEVALS\pbeesly) — a persistence shortcut, not a credential-capture lure. (2) All outbound SMB (Sysmon 3, 66 events) is System process traffic to internal addresses only: 10.0.0.4 (26), fe80::e40c:95b6:b0a7:6429 (24, newyork only) and 10.0.1.6 (16) — no external/untrusted SMB server. (3) Security 5140/5145 share access is domain infrastructure: machine accounts (NEWYORK$, SCRANTON$, NASHUA$, UTICA$, WEC$) reading \\*\SYSVOL gpt.ini/GptTmpl.inf and \\*\IPC$ (samr), plus pbeesly writing Temp\python.exe to \\*\ADMIN$ on nashua from 10.0.1.4 (lateral movement, not forced auth). (4) The single NTLM mention is LsaSrv event 6038 on scranton at 03:20:41, a once-per-boot informational warning that NTLM is in use — not a coercion attempt. (5) The only WebDAV reference is in the attacker's own Invoke-Exfil script block (4104, scranton, 03:08:02), which maps \\192.168.0.4\webdav with hardcoded credentials 'cozy'/'MyCozyPassw0rd!' to copy out OfficeSupplies.7z — that is exfiltration over WebDAV using attacker-supplied creds, the opposite direction of T1187. Zeek (2020-04-30) does not overlap the Windows window; its 12 smb_files records are 10.0.1.4 and 10.0.1.6 to 10.0.0.4 (internal), and no HTTP PROPFIND/WebDAV/NTLM URLs were seen. Note: the host is clearly compromised by other means (obfuscated steganographic PowerShell loader reading monkey.png, StartUp persistence, archive/exfil), but T1187 itself is not present in the retrieved data.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:23.681Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\hostui.lnk | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOtcqWLx | q-52d59e6798 | ok |
| 2 | 2020-05-02 03:00:13.551Z | scranton.dmevals.local | windows.sysmon | win.ParentCommandLine | "PowerShell.exe" -noni -noexit -ep bypass -window hidden -c "sal a New-Object;Add-Type -AssemblyName 'System.Drawing'; $g=a System.Drawing.Bitmap('C:\Users\pbee… | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOtl2JQj | q-21aac0c570 | ok |
| 3 | 2020-05-02 03:10:23.315Z | scranton.dmevals.local | windows.sysmon | destination.ip | 10.0.1.6 | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOtHRU4M | q-f5a8b6a39d | ok |
| 4 | 2020-05-02 03:10:23.000Z | nashua.dmevals.local | windows.security | win.RelativeTargetName | Temp\python.exe | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZI2iSVpshTO31NyoH | q-deba999383 | ok |
| 5 | 2020-05-02 03:01:43.000Z | newyork.dmevals.local | windows.security | win.RelativeTargetName | dmevals.local\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\gpt.ini | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZI2iSVpshTO3_ZDTc | q-deba999383 | ok |
| 6 | 2020-05-02 03:20:41.000Z | scranton.dmevals.local | windows.other | event.code | 6038 | .ds-logs-windows.other-default-2026.10.20-000001 / AaFZJGiSVpshTO1pnQLy | q-7726a514c5 | ok |
| 7 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZJGiSVpshTO3AvzkC | q-07a9422c64 | ok |

### F24 · benign / high · T1212 · Routine lsass handle access by system services and Azure guest agents (benign)

Evidence status: **verified**

The bulk of lsass process-access events (326 total) come from expected sources: svchost.exe (289, call traces through lsm.dll and sysmain.dll, masks 0x1000/0x101001/0x3000), Microsoft.Azure.Security.IaaSAntimalware AntimalwareConfig.exe (15), WindowsAzureTelemetryService.exe (13), and boot-time wininit.exe/csrss.exe (0x1fffff/0x1000000 at 03:19:09Z). Security 4656 shows CollectGuestLogs.exe on newyork.dmevals.local opening lsass with 0x1410 as NEWYORK$. These are normal service/agent behaviour, not exploitation.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:18:34.438Z | scranton.dmevals.local | windows.sysmon | win.CallTrace | C:\windows\SYSTEM32\ntdll.dll+9def4\|c:\windows\system32\lsm.dll+1aa6e\|c:\windows\system32\lsm.dll+1a9c3\|c:\windows\system32\lsm.dll+65e1\|c:\windows\system32… | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOs7DwuP | q-bfea890357 | ok |
| 2 | 2020-05-02 03:19:59.323Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x3000 | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOoWdgoz | q-bfea890357 | ok |
| 3 | 2020-05-02 03:19:09.803Z | scranton.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\wininit.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOs4A9hl | q-bfea890357 | ok |
| 4 | 2020-05-02 03:03:38.000Z | newyork.dmevals.local | windows.security | win.ProcessName | C:\WindowsAzure\Packages\CollectGuestLogs.exe | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZI2iSVpshTO39XK6I | q-141d5002cc | ok |

### F25 · benign / high · T1539 · No browser cookie-store theft observed; only WebDAV DavSetCookie and Edge's own profile writes

Evidence status: **NOT verified (4/5 evidence items)** — excluded from the verdict

Across all four hosts (2020-05-02 02:55-03:28Z) there is no evidence of web session cookie theft. The 162 sysmon file-creation hits for *Cookies*/*Login Data*/*Web Data* collapse to a single genuine cookie-path event: svchost.exe creating C:\Windows\ServiceProfiles\LocalService\AppData\Local\Packages\warp_jit_db4a1097-...\AC\INetCookies on scranton.dmevals.local (a service-profile INetCookies container, not a browser cookie DB). No sysmon event code 2 (file change) or code 10 (process access) touched chrome/firefox/msedge/iexplore/brave/opera images, and no security 4663/4656 object access referenced a cookie, Login Data or Web Data file. The only 'cookie' command lines are rundll32.exe davclnt.dll,DavSetCookie 192.168.0.4 http://192.168.0.4/webdav run as pbeesly on scranton at 03:08:50 and 03:10:22-23 - WebDAV credential caching for the exfil share used by the Invoke-Exfil script block, not browser session theft. The 13 PowerShell 4104 hits for Cookies/Login Data/sqlite are Microsoft module manifests/localization data on newyork.dmevals.local plus the pbeesly screen-capture and Invoke-Exfil tooling on scranton; none read a browser cookie store. Edge profile writes on scranton are MicrosoftEdge.exe's own DataStore/Temp files. Related malicious activity on scranton (screen capture, 7-Zip staging of Downloads to \\192.168.0.4\webdav) is real but belongs to other techniques, not T1539.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:21:05.681Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Windows\ServiceProfiles\LocalService\AppData\Local\Packages\warp_jit_db4a1097-b484-4973-bbf2-a04208ecd4d4\AC\INetCookies | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOociZfQ | q-176afef4b5 | ok |
| 2 | 2020-05-02 03:10:23.154Z | scranton.dmevals.local | windows.sysmon | process.command_line | rundll32.exe C:\windows\system32\davclnt.dll,DavSetCookie 192.168.0.4 http://192.168.0.4/webdav | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOtHRU7U | q-1c18d576f5 | ok |
| 3 | 2020-05-02 03:08:50.963Z | scranton.dmevals.local | windows.sysmon | process.command_line | rundll32.exe C:\windows\system32\davclnt.dll,DavSetCookie 192.168.0.4 http://192.168.0.4/webdav | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOtISlRo | q-1c18d576f5 | ok |
| 4 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZJGiSVpshTO3AvzkC | q-6576f87b64 | ok |
| 5 | 2020-05-02 03:21:05.681Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Windows\ServiceProfiles\LocalService\AppData\Local\Packages\warp_jit_db4a1097-b484-4973-bbf2-a04208ecd4d4\AC\INetCookies | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOociZfQ | q-d79b786172 | FAILED: cited query did not return this event |

### F28 · benign / medium · T1552.002 · Registry credential-path hits are Windows service/identity noise; no hive or stored-credential harvesting observed

Evidence status: **verified**

All 17 Sysmon registry SetValue events matching Password/Credential/Secret paths are legitimate OS activity: svchost.exe writing HKU\.DEFAULT\Software\Microsoft\IdentityCRL\ProviderPasswordLength/CharacterGroups on nashua and scranton, lsass.exe setting DeviceGuard\Scenarios\CredentialGuard\Enabled to 0, services.exe creating the CredentialEnrollmentManagerUserSvc_13619b service keys, and winlogon.exe writing PasswordExpiryNotification values. The 4663 object-access stack on SAM/SECURITY/SYSTEM paths is dominated by \REGISTRY\MACHINE\SYSTEM\ControlSet001\Control\Session Manager\Environment (2968) and ...\Control\Lsa (1473), i.e. routine registry reads, with no reg save/reg query or hive-copy command lines found. The one registry-read script block (Get-ItemPropertyValue 'HKLM:\\SOFTWARE\Javasoft' 'value Supplement' \| Invoke-Expression) is a registry-stored-payload execution pattern rather than credential theft, and no credential value was retrieved.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:09.865Z | scranton.dmevals.local | windows.sysmon | registry.path | HKLM\System\CurrentControlSet\Control\DeviceGuard\Scenarios\CredentialGuard\Enabled | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOs4A9hu | q-37261658ed | ok |
| 2 | 2020-05-02 03:19:49.065Z | scranton.dmevals.local | windows.sysmon | registry.path | HKU\.DEFAULT\Software\Classes\Local Settings\MuiCache\4\52C64B7E\@%SystemRoot%\system32\CredentialEnrollmentManager.exe,-100 | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOokoC4V | q-37261658ed | ok |
| 3 | 2020-05-02 03:21:28.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | Get-ItemPropertyValue 'HKLM:\\SOFTWARE\Javasoft' 'value Supplement' \| Invoke-Expression | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZJGiSVpshTO3Q03Gn | q-7ec4edd397 | ok |

### F29 · benign / medium · T1552.003 · No shell-history access observed

Evidence status: **verified**

No Sysmon process-creation, file-creation, PowerShell 4104 or Security 4663 event referenced ConsoleHost_history, PSReadLine or Get-History. The only 'history' matches in windows.other are registry hive access-history maintenance messages (event code 16) for provisioning/Skype/Alarms settings.dat hives, which are normal Windows behaviour.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:02:47.000Z | scranton.dmevals.local | windows.other | message | The access history in hive \??\C:\ProgramData\Microsoft\Provisioning\Microsoft-Desktop-Provisioning-Sequence.dat was cleared updating 0 keys and creating 0 modi… | .ds-logs-windows.other-default-2026.10.20-000001 / AaFZJGiSVpshTO1pngKW | q-0813c384e2 | ok |

### F30 · benign / medium · T1552.006 · SYSVOL/Group Policy access is machine-account GPO refresh, not GPP password harvesting

Evidence status: **verified**

All SYSVOL reads (Security 5145 on \\*\SYSVOL) come from computer accounts NEWYORK$, SCRANTON$ and NASHUA$ reading gpt.ini, GptTmpl.inf and the {31B2F340-...} policy tree, matching the corresponding svchost.exe GroupPolicy\DataStore file creations on scranton and nashua — standard periodic Group Policy processing. No Groups.xml, cpassword, or user-driven SYSVOL access was observed, and no process command line referenced SYSVOL or Groups.xml.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:01:43.000Z | newyork.dmevals.local | windows.security | win.RelativeTargetName | dmevals.local\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\gpt.ini | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZI2iSVpshTO3_ZDTc | q-09ecca0b44 | ok |
| 2 | 2020-05-02 03:01:43.000Z | newyork.dmevals.local | windows.security | user.name | SCRANTON$ | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZI2iSVpshTO3_ZDTc | q-09ecca0b44 | ok |
| 3 | 2020-05-02 03:01:43.091Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Windows\System32\GroupPolicy\DataStore\0\sysvol\dmevals.local\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.in… | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOtfu-5W | q-4d423f4883 | ok |

### F33 · benign / medium · T1555.003 · No browser credential-store access observed; only a benign INetCookies write

Evidence status: **verified**

The only file-creation hit matching browser credential-store patterns was a single write of C:\Windows\ServiceProfiles\LocalService\AppData\Local\Packages\warp_jit_db4a1097-...\AC\INetCookies, a Windows platform cookie container rather than a browser Login Data / Local State / logins.json / key4.db store. No process command lines, 4663 object accesses, script blocks or other-channel messages referencing browser credential files were found. The credential-adjacent activity on these hosts (Invoke-Exfil archiving of Downloads, Rar.exe of $env:APPDATA) targets files for exfiltration, not browser password stores.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:27.395Z | nashua.dmevals.local | windows.sysmon | win.TargetFilename | C:\ProgramData\Microsoft\Windows\WER\Temp\WER51F5.tmp.dmp | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOtYnKtJ | q-766408abb2 | ok |

### F34 · benign / medium · T1555.004 · No Windows Credential Manager / Vault access; only a Credential Guard configuration status message

Evidence status: **verified**

The only Credential-related hit in windows.other was a Credential Guard configuration status line (event code 14) on scranton.dmevals.local, a routine platform status message rather than credential retrieval. No cmdkey/credman/vault command lines, no 4688 process creations, no registry writes to Vault/Credentials/CredMan/ProtectedStorage keys, and no file writes to Microsoft\Credentials or Vault paths were observed. The 4104 script blocks that matched 'Credential' were unrelated (a TimeSpan helper and an AD cmdlet help block).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:09.000Z | scranton.dmevals.local | windows.other | message | Credential Guard configuration: 0x0, 0 | .ds-logs-windows.other-default-2026.10.20-000001 / AaFZJGiSVpshTO1pnQLs | q-24d05c9446 | ok |

### F35 · benign / medium · T1555.005 · No password-manager artifacts (KeePass/1Password/Bitwarden) observed

Evidence status: **verified**

No process command lines, file writes (.kdbx, 1password, keepass), process-memory accesses to password-manager images, 4688 process creations, script blocks or other-channel messages referencing password managers were found on any host. The archive/collection activity seen (Compress-Archive of *.psw/*pass/*login/*vpn files on nashua, Rar.exe -hpfGzq5yKw of $env:APPDATA) is bulk file collection for exfiltration, not password-manager store theft.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:15:59.000Z | nashua.dmevals.local | windows.powershell | win.ScriptBlockText | $env:APPDATA;$files=ChildItem -Path $env:USERPROFILE\ -Include *.doc,*.xps,*.xls,*.ppt,*.pps,*.wps,*.wpd,*.ods,*.odt,*.lwp,*.jtd,*.pdf,*.zip,*.rar,*.docx,*.url,… | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZJGiSVpshTO3JxTei | q-801302c490 | ok |

### F37 · benign / medium · T1556.001 · No domain-controller authentication patching; lsass access was credential dumping, not Skeleton Key

Evidence status: **verified**

The 326 lsass handle events stack to expected sources (svchost.exe 289, Azure antimalware/telemetry, wininit/csrss/services at boot). The only anomalous ones are the attacker's PowerShell.exe (PID 2976, scranton, 0x1F3FFF/0x1FFFFF) and wsmprovhost.exe (PID 7720, nashua, 0x1F3FFF), which are credential-dump style accesses rather than patching of the DC authentication process. No lsass module loads other than cryptdll.dll/msv1_0.dll/wdigest.dll/lsass.exe were seen, and no 4657 LSA registry modifications occurred. Network logons (4624 type 3) are dominated by machine accounts (NEWYORK$ 123, SCRANTON$ 37, NASHUA$ 25) plus pbeesly 20, consistent with the observed lateral movement rather than a DC auth bypass.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOtaokyR | q-1f72657aef | ok |
| 2 | 2020-05-02 03:19:09.865Z | scranton.dmevals.local | windows.sysmon | registry.path | HKLM\System\CurrentControlSet\Control\Lsa\LsaCfgFlagsDefault | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOs4A9hr | q-fcd5baf246 | ok |

### F38 · benign / high · T1556.002 · No password filter DLL registered or dropped

Evidence status: **verified**

No 4657 registry change to LSA 'Notification Packages' or Control\Lsa was recorded in windows.security, no Sysmon 11 file creation of a DLL under System32, and no PowerShell script block or windows.other message referenced Notification Packages or PasswordFilter. The 19,432 Sysmon 7 image loads from System32 are ordinary Windows DLLs (ntdll, KernelBase, kernel32, rpcrt4, sechost ...).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:09.865Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOs4A9hr | q-fcd5baf246 | ok |

### F39 · benign / high · T1556.005 · No reversible-encryption / UserAccountControl tampering

Evidence status: **verified**

No 4739 (domain policy change) events, no 4657 writes to Reversible/UserAccountControl values, and no process command line or PowerShell script block referencing Reversible, Set-ADAccountControl or UserAccountControl in the 02:55–03:28Z window. The attacker's PowerShell activity (Invoke-Discovery/Persistence/Exfil/SeaDukeStage) did not touch account control flags.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:03.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | Invoke-Discovery | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZJGiSVpshTO3P0Z28 | q-d8b8a36208 | ok |

### F40 · benign / medium · T1556.006 · No MFA/authentication policy modification; Kerberos traffic is normal DC authentication

Evidence status: **verified**

No 4739 or 5136 events exist in windows.security or windows.other, so no authentication policy silo or MFA-related change was made. The 35 zeek kerberos records (2020-04-30, non-overlapping window) are ordinary client-to-DC authentication from 10.0.1.4 and 10.0.1.6 to 10.0.0.4 with no anomalous pre-auth characteristics visible.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-04-30 00:06:38.908Z | simplerockbuild.simplerock.lan | zeek | event.action | kerberos | .ds-logs-zeek-default-2026.10.20-000001 / AaFZJWiSVpshTO03669g | q-f82ff2fa5c | ok |

### F41 · benign / medium · T1556.007 · No hybrid identity / federation or directory-sync backdoor

Evidence status: **verified**

No 5136 directory-service change events were recorded, and the Sysmon 7 image-load stack contains only standard Windows DLLs — no ADFS, Azure AD Connect or cloud-sync binaries were loaded. The only cloud-related processes touching lsass are the legitimate Azure antimalware/telemetry agents and CollectGuestLogs.exe (0x1410 read access on utica/nashua).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:23:12.000Z | utica.dmevals.local | windows.security | win.ProcessName | C:\WindowsAzure\Packages\CollectGuestLogs.exe | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZI2iSVpshTOzc__0s | q-01874066e2 | ok |

### F42 · benign / medium · T1556.008 · No rogue network provider DLL; lsass access is credential dumping

Evidence status: **verified**

All 326 Sysmon 10 events target C:\windows\system32\lsass.exe, but no registry write to a NetworkProvider key, no NetworkProvider DLL image load, and no 4657 NetworkProvider change were found. Sysmon 11 file creations under System32 are GroupPolicy DataStore, DSC mof files, SRU logs and systemprofile temp files — no dropped provider DLL. The attacker's lsass handles (PowerShell.exe 0x1FFFFF on scranton, wsmprovhost.exe 0x1F3FFF on nashua) indicate memory read for credential theft rather than a registered network provider.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOtIR1Pn | q-ad3c2559b7 | ok |
| 2 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.TargetImage | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOtIR1Pn | q-ad3c2559b7 | ok |

### F43 · benign / medium · T1557 · No adversary-in-the-middle activity; observed credential-access-adjacent activity is PsExec lateral movement with plaintext credentials

Evidence status: **verified**

Hunting for AiTM on the Windows hosts (2020-05-02 02:55-03:28Z) and in the Zeek window (2020-04-30 00:06-00:45Z) produced no relay/interception evidence. Outbound connections from sysmon event.code 3 go to expected internal peers (192.168.0.4, 10.0.0.4, 10.0.1.4/5/6) and Microsoft/Azure endpoints. The only genuinely malicious activity found is a separate chain on scranton.dmevals.local: user pbeesly ran PsExec64.exe against \\NASHUA with a plaintext password (-u dmevals\pbeesly -p Fl0nk3rt0n!T0by) to launch C:\Windows\Temp\python.exe, which installed PSEXESVC on nashua.dmevals.local four times, and ran sdelete64.exe against files under C:\programdata\victim and the user profile. That is lateral movement/execution/anti-forensics (T1021.002/T1070.004), not AiTM, so it is reported here only as context and not attributed to T1557.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:18.784Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\PsExec64.exe" -accepteula \\NASHUA -u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOtGQk7R | q-daad1834b0 | ok |
| 2 | 2020-05-02 03:11:40.213Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOyESnYY | q-daad1834b0 | ok |
| 3 | 2020-05-02 03:02:04.324Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\sdelete64.exe" /accepteula C:\programdata\victim\???cod.3aka3.scr | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOtftxew | q-daad1834b0 | ok |

### F44 · benign / medium · T1557.001 · SMB/LLMNR/NBT-NS traffic is normal domain traffic; no name-resolution poisoning or SMB relay observed

Evidence status: **verified**

Connections to 445/137 exist (74 sysmon event.code 3 hits, 47 Zeek conn hits) but they are ordinary domain traffic: scranton.dmevals.local (10.0.1.4) and newyork.dmevals.local talking to 10.0.0.4 over 445, plus IPv6 link-local loopback 445 and NBT-NS broadcast to 10.0.0.255:137. Zeek DNS queries are routine (wpad.dmevals.local, wec.dmevals.local, _ldap._tcp SRV lookups, Microsoft telemetry). No DNSClient registry tampering was found (C232 zero hits). The single NTLM network logon (4624 type 3, NtLmSsp, NTLM) on scranton.dmevals.local came from 172.18.39.2 and was immediately followed by type 10 logons from the same address, i.e. a remote interactive session, not a relayed authentication. The 4697 service installs are PSEXESVC (from the PsExec chain above) and javamtsup, not relay tooling.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:01:43.033Z | scranton.dmevals.local | windows.sysmon | destination.ip | 10.0.0.4 | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOtfue5A | q-6dbff09784 | ok |
| 2 | 2020-05-02 03:03:13.822Z | newyork.dmevals.local | windows.sysmon | destination.port | 137 | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOtdr1W2 | q-6dbff09784 | ok |
| 3 | 2020-05-02 03:20:41.000Z | scranton.dmevals.local | windows.security | win.LogonProcessName | NtLmSsp  | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZJGiSVpshTO0NmmRM | q-fd233f92dc | ok |
| 4 | 2020-05-02 03:20:46.000Z | scranton.dmevals.local | windows.security | win.LogonType | 10 | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZJGiSVpshTO0Gh1d1 | q-87dcc66212 | ok |

### F45 · benign / medium · T1557.002 · No ARP cache poisoning: L2 address mapping is stable and one-to-one per host

Evidence status: **verified**

Zeek conn records show a stable L2 mapping with no duplicate or conflicting MACs: 10.0.1.6 always uses 00:0d:3a:13:e3:69 (430 conns), 10.0.1.4 always uses 00:0d:3a:4d:42:f2 (129 conns), and the responder 12:34:56:78:9a:bc is used consistently for the internal servers (10.0.0.4, 192.168.0.4/5) across DNS, SMB, Kerberos, LDAP, NTP and DCE-RPC. The 44 conns from fc:bd:67:e1:a9:c1 to 00:0d:3a:13:e3:69 are a single host-to-host pair, not a MAC claimed by two IPs. The ARP.EXE /a, ROUTE.EXE print and ipconfig /all executions on scranton.dmevals.local are read-only diagnostics spawned by the Azure Guest Agent, Telemetry Service and WaAppAgent, not ARP manipulation.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-04-30 00:06:39.824Z | bobs.bigwheel.local | zeek | zeek.orig_l2_addr | 00:0d:3a:13:e3:69 | .ds-logs-zeek-default-2026.10.20-000001 / AaFZJWiSVpshTO2e9qSA | q-60884afbd3 | ok |
| 2 | 2020-04-30 00:06:38.899Z | simplerockbuild.simplerock.lan | zeek | zeek.orig_l2_addr | 00:0d:3a:4d:42:f2 | .ds-logs-zeek-default-2026.10.20-000001 / AaFZJWiSVpshTO037K8i | q-60884afbd3 | ok |
| 3 | 2020-05-02 03:19:25.370Z | scranton.dmevals.local | windows.sysmon | process.command_line | "arp.exe" /a | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOo2-WWw | q-5415764006 | ok |
| 4 | 2020-05-02 03:19:25.370Z | scranton.dmevals.local | windows.sysmon | process.parent.executable | C:\WindowsAzure\Packages\GuestAgent\WindowsAzureGuestAgent.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOo2-WWw | q-5415764006 | ok |

### F46 · benign / medium · T1557.003 · No DHCP spoofing; network configuration changes are Azure Network Watcher packet capture

Evidence status: **verified**

No rogue DHCP server or DHCP-based redirection was found. The DHCP-related event codes queried in windows.other (1341/1342/1020/1063) returned zero hits, and no PowerShell script block referenced dhcp/netsh/DhcpServer. The only network-stack changes on scranton.dmevals.local are the Microsoft NDIS Capture service start type flipping demand->system->demand at 2020-05-01T23:19:22-23:19:26, immediately preceded by netsh.exe trace start capture=yes writing an .etl to C:\windows\TEMP and followed by netsh trace stop, all parented by the Azure NetworkWatcherAgent service. That is cloud packet-capture telemetry, not DHCP spoofing.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:22.000Z | scranton.dmevals.local | windows.other | message | The start type of the Microsoft NDIS Capture service was changed from demand start to system start. | .ds-logs-windows.other-default-2026.10.20-000001 / AaFZJGiSVpshTO1pngI8 | q-38492b4961 | ok |
| 2 | 2020-05-02 03:19:17.154Z | scranton.dmevals.local | windows.sysmon | process.command_line | C:\windows\system32\netsh.exe trace start capture=yes traceFile="C:\windows\TEMP\E7116ECA-DFE6-43C7-8FA8-8D3AC5AA8726\B91E06C5-1C7C-4830-9A76-74FA211560A7.etl" | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOonrxo5 | q-d1dc5d10e2 | ok |
| 3 | 2020-05-02 03:19:24.835Z | scranton.dmevals.local | windows.sysmon | process.command_line | C:\windows\system32\netsh.exe trace stop | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOosxQHp | q-d1dc5d10e2 | ok |

### F48 · benign / medium · T1558.001 · No golden-ticket indicators: no krbtgt dumping, no forged-TGT logon anomalies

Evidence status: **verified**

No evidence of golden ticket activity. Script-block logging contains no 'golden', 'krbtgt' or 'mimikatz' content (the only 4104 hits for 'credential' were benign Microsoft module resource strings on newyork.dmevals.local running as SYSTEM). No service installs referencing kdc (7045/7040) were found. Kerberos events on newyork.dmevals.local show only normal 4768/4769 issuance for pbeesly and machine accounts (SCRANTON$, NEWYORK$, NASHUA$, WEC$) with AES encryption type 0x12 and status 0x0; no anomalous privileged logons or unusual accounts appear in 4672/4634/4624 stacks. The lsass full-access reads on scranton are noted under T1558 but no krbtgt-specific theft or forged-ticket use was observed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:13.000Z | newyork.dmevals.local | windows.security | win.TargetUserName | SCRANTON$ | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZJGiSVpshTO0MlXTc | q-297ae1969b | ok |
| 2 | 2020-05-02 03:19:13.000Z | newyork.dmevals.local | windows.security | win.TicketEncryptionType | 0x12 | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZJGiSVpshTO0MlXTc | q-297ae1969b | ok |
| 3 | 2020-05-02 03:11:18.000Z | newyork.dmevals.local | windows.security | win.TargetUserName | pbeesly | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZI2iSVpshTO31NCrt | q-297ae1969b | ok |

### F49 · benign / medium · T1558.002 · No silver-ticket indicators: no service-account ticket abuse or service-ticket forgery evidence

Evidence status: **NOT verified (2/3 evidence items)** — excluded from the verdict

No silver ticket activity observed. Script blocks contain no 'silver', 'service ticket', 'TGS' or 'mimikatz' content, and no service installs referencing spool/mssql/http were found. The 4769 service tickets issued by newyork.dmevals.local are for machine accounts (NEWYORK$, NASHUA$, SCRANTON$, WEC$) and krbtgt, all AES 0x12 with status 0x0, requested by pbeesly or SCRANTON$ from 10.0.1.4/10.0.1.6 — normal service-ticket acquisition, not forged service tickets.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:09:23.000Z | newyork.dmevals.local | windows.security | win.ServiceName | NASHUA$ | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZI2iSVpshTO32OAbc | q-297ae1969b | ok |
| 2 | 2020-05-02 03:09:23.000Z | newyork.dmevals.local | windows.security | win.TicketEncryptionType | 0x12 | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZI2iSVpshTO32OAbc | q-297ae1969b | ok |
| 3 |  | None | None | win.ServiceName | SCRANTON$ | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZI2iSVpshTO0MlnQk | q-297ae1969b | FAILED: cited query did not return this event; event not found |

### F50 · benign / medium · T1558.003 · No Kerberoasting: no RC4 service-ticket requests, no SPN enumeration tooling

Evidence status: **verified**

No Kerberoasting indicators. Script-block logging has no 'Kerberoast', 'SPN', 'GetUserSPNs' or 'Rubeus' content, and no service installs referencing spn were found. All 4769 service-ticket events on newyork.dmevals.local use TicketEncryptionType 0x12 (AES256), not the RC4 0x17 typical of roasting, and target only machine accounts/krbtgt. Zeek kerberos logs (2020-04-30, non-overlapping window) show 14 AS and 11 TGS requests from 10.0.1.4 and 10.0.1.6 to 10.0.0.4 for client pbeesly/DMEVALS.LOCAL, with a single KDC_ERR_PREAUTH_REQUIRED followed by a successful AS exchange — normal interactive logon, not bulk ticket requests.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:04.000Z | newyork.dmevals.local | windows.security | win.TicketEncryptionType | 0x12 | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZI2iSVpshTO39XK4T | q-297ae1969b | ok |
| 2 | 2020-05-02 03:04:04.000Z | newyork.dmevals.local | windows.security | win.ServiceName | NEWYORK$ | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZI2iSVpshTO39XK4T | q-297ae1969b | ok |
| 3 | 2020-04-30 00:24:19.110Z | simplerockbuild.simplerock.lan | zeek | zeek.error_msg | KDC_ERR_PREAUTH_REQUIRED | .ds-logs-zeek-default-2026.10.20-000001 / AaFZJWiSVpshTO03669f | q-b88545452d | ok |
| 4 | 2020-04-30 00:24:19.119Z | simplerockbuild.simplerock.lan | zeek | zeek.client | pbeesly/DMEVALS.LOCAL | .ds-logs-zeek-default-2026.10.20-000001 / AaFZJWiSVpshTO036q-N | q-b88545452d | ok |

### F51 · benign / medium · T1558.004 · No AS-REP roasting: no preauth-disabled account abuse or GetNPUsers/Rubeus tooling

Evidence status: **verified**

No AS-REP roasting indicators. Script blocks contain no 'AS-REP', 'GetNPUsers', 'Rubeus' or 'asreproast' content, and no kdc-related service installs were found. All 4768 events on newyork.dmevals.local are for pbeesly and SCRANTON$ with PreAuthType 2 (pre-authentication enabled) and status 0x0, which is incompatible with AS-REP roasting. Zeek kerberos AS requests in the 2020-04-30 window are a single client (pbeesly) with one KDC_ERR_PREAUTH_REQUIRED followed by success — normal logon behaviour.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:18.000Z | newyork.dmevals.local | windows.security | win.PreAuthType | 2 | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZI2iSVpshTO31NCrt | q-297ae1969b | ok |
| 2 | 2020-05-02 03:11:18.000Z | newyork.dmevals.local | windows.security | win.Status | 0x0 | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZI2iSVpshTO31NCrt | q-297ae1969b | ok |
| 3 | 2020-04-30 00:24:19.110Z | simplerockbuild.simplerock.lan | zeek | zeek.request_type | AS | .ds-logs-zeek-default-2026.10.20-000001 / AaFZJWiSVpshTO03669f | q-b88545452d | ok |

### F54 · benign / medium · T1606.001 · No web-cookie forging or cookie-store access observed

Evidence status: **verified**

The only cookie-related file creation in the window is C:\Windows\ServiceProfiles\LocalService\AppData\Local\Packages\warp_jit_db4a1097-b484-4973-bbf2-a04208ecd4d4\AC\INetCookies, created by svchost.exe under the LocalService profile at 2020-05-02T03:21:05Z — a normal OS/AppContainer artefact. No PowerShell script block referenced cookies and no cookie-store access by user processes was found, so no web cookie theft or forgery is evidenced in the available telemetry.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:21:05.681Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Windows\ServiceProfiles\LocalService\AppData\Local\Packages\warp_jit_db4a1097-b484-4973-bbf2-a04208ecd4d4\AC\INetCookies | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOociZfQ | q-caac29a951 | ok |
| 2 | 2020-05-02 03:21:05.681Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\System32\svchost.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZI2iSVpshTOociZfQ | q-caac29a951 | ok |

### F56 · benign / medium · T1649 · Registry write to LocalMachine ROOT certificate store on NASHUA (single event, no certificate content change)

Evidence status: **verified**

One 4657 registry-modification event on nashua.dmevals.local (2020-05-01T23:16:19Z, subject NASHUA$) touched \REGISTRY\MACHINE\SOFTWARE\Microsoft\SystemCertificates\ROOT\Certificates\BE36A4562FB2EE05DBB3D32323ADF445084ED656, but the recorded operation is a value/permission-type change (OperationType %%1905, NewValue and OldValue both %%1800 — unchanged) performed by C:\Windows\Sysmon.exe, i.e. no certificate blob was added or replaced. All other 4657 hits in the window are WMI Autologger EventLog-Application GUID keys, unrelated to certificates. No certificate export, import, or forged-certificate use was observed on NASHUA, so this is not evidence of certificate theft/forgery.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:16:19.000Z | nashua.dmevals.local | windows.security | win.ObjectName | \REGISTRY\MACHINE\SOFTWARE\Microsoft\SystemCertificates\ROOT\Certificates\BE36A4562FB2EE05DBB3D32323ADF445084ED656 | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZI2iSVpshTO3zLJP8 | q-47e6baf6c0 | ok |
| 2 | 2020-05-02 03:16:19.000Z | nashua.dmevals.local | windows.security | win.ProcessName | C:\Windows\Sysmon.exe | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZI2iSVpshTO3zLJP8 | q-47e6baf6c0 | ok |
| 3 | 2020-05-02 03:16:19.000Z | nashua.dmevals.local | windows.security | win.NewValue | %%1800 | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZI2iSVpshTO3zLJP8 | q-47e6baf6c0 | ok |

### F57 · benign / medium · T1649 · Kerberos TGT requests for pbeesly and SCRANTON$ show no certificate-based (PKINIT) pre-authentication

Evidence status: **verified**

All 14 4768 events in the window are on newyork.dmevals.local: 9 for pbeesly and 5 for the machine account SCRANTON$, all with PreAuthType 2 (encrypted timestamp, i.e. password-based) and Status 0x0. None used PKINIT/certificate pre-authentication, so there is no observed use of a stolen or forged certificate for authentication in this dataset. (The pbeesly TGTs from 10.0.1.4/10.0.1.6 are consistent with normal logons and do not by themselves show certificate abuse.)

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:18.000Z | newyork.dmevals.local | windows.security | win.PreAuthType | 2 | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZI2iSVpshTO31NCrt | q-01501fcce5 | ok |
| 2 | 2020-05-02 03:19:13.000Z | newyork.dmevals.local | windows.security | win.TargetUserName | SCRANTON$ | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZJGiSVpshTO0MlXTa | q-01501fcce5 | ok |

## Pivot candidates

Processes the pivot reviewer had to assess (started by a script host or from outside the Windows directory, rare in the 15-minute windows around verified activity).

| Host | Executable | Starts | Parents | Assessment | Reason |
|---|---|---|---|---|---|
| nashua.dmevals.local | C:\Program Files\WindowsApps\Microsoft.SkypeApp_14.35.152.0_x64__kzf8qxf38zg5c\S… | 1 | C:\Program Files\WindowsApps\Microsoft.SkypeApp_14.35.152.0_x64__kzf8qxf38zg5c\S… | benign | Windows Store Skype app self-restarting; parent is itself and it produced a WerFault crash report, no credential access. |
| nashua.dmevals.local | C:\Windows\Temp\python.exe | 5 | C:\Windows\PSEXESVC.exe, C:\Windows\Temp\python.exe | malicious | PyInstaller-packed python.exe dropped to C:\Windows\Temp and started by PSEXESVC.exe (PsExec from scranton with cleartext dmevals\pbeesly password); it spawned … |
| nashua.dmevals.local | C:\Windows\Temp\Rar.exe | 1 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | malicious | Rar.exe dropped in C:\Windows\Temp and run by PowerShell with hardcoded password -hpfGzq5yKw to archive the harvested working.zip to the Desktop, then deleted w… |
| nashua.dmevals.local | C:\Windows\Temp\sdelete64.exe | 3 | C:\Windows\System32\cmd.exe | malicious | Anti-forensics: sdelete64.exe copied to C:\Windows\Temp and used by cmd.exe to securely delete Rar.exe and the harvested working.zip archives on nashua. |
| nashua.dmevals.local | C:\WindowsAzure\Packages\CollectGuestLogs.exe | 1 | C:\WindowsAzure\Packages\WaAppAgent.exe | benign | Azure guest agent diagnostic log collector started by WaAppAgent.exe; standard platform activity. |
| scranton.dmevals.local | C:\Packages\Plugins\Microsoft.Azure.NetworkWatcher.NetworkWatcherAgentWindows\1.… | 4 | C:\Windows\System32\cmd.exe, C:\Windows\System32\services.exe | benign | Azure Network Watcher agent plugin started by services.exe/cmd.exe; standard Azure VM extension. |
| scranton.dmevals.local | C:\Packages\Plugins\Microsoft.Azure.Security.IaaSAntimalware\1.5.5.9\Antimalware… | 1 | C:\WindowsAzure\Packages\GuestAgent\WindowsAzureGuestAgent.exe | benign | Azure IaaS Antimalware extension configuration binary started by WindowsAzureGuestAgent.exe. |
| scranton.dmevals.local | C:\Packages\Plugins\Microsoft.Compute.CustomScriptExtension\1.10.5\bin\CustomScr… | 1 | C:\Windows\System32\cmd.exe | benign | Azure Custom Script Extension handler; standard VM extension execution. |
| scranton.dmevals.local | C:\Packages\Plugins\Microsoft.Compute.JsonADDomainExtension\1.3.2\bin\JsonADDoma… | 1 | C:\Windows\System32\cmd.exe | benign | Azure AD domain-join extension handler; standard VM provisioning activity. |
| scranton.dmevals.local | C:\Program Files (x86)\Google\Update\1.3.35.452\GoogleCrashHandler.exe | 2 | C:\Program Files (x86)\Google\Update\GoogleUpdate.exe | benign | Google Update crash handler child of GoogleUpdate.exe; normal software update behavior. |
| scranton.dmevals.local | C:\Program Files (x86)\Google\Update\1.3.35.452\GoogleCrashHandler64.exe | 2 | C:\Program Files (x86)\Google\Update\GoogleUpdate.exe | benign | Google Update crash handler child of GoogleUpdate.exe; normal software update behavior. |
| scranton.dmevals.local | C:\Program Files (x86)\Google\Update\GoogleUpdate.exe | 3 | C:\Program Files (x86)\Google\Update\GoogleUpdate.exe, C:\Windows\System32\servi… | benign | Google Update service/updater started by services.exe/svchost.exe; normal. |
| scranton.dmevals.local | C:\Program Files\SysinternalsSuite\accessChk.exe | 1 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | suspicious | Sysinternals accesschk.exe run from the attacker-staged C:\Program Files\SysinternalsSuite by PowerShell right after the toolkit was dot-sourced; used for permi… |
| scranton.dmevals.local | C:\Program Files\SysinternalsSuite\PsExec64.exe | 4 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | malicious | PsExec64.exe invoked four times by PowerShell with the cleartext domain password (-u dmevals\pbeesly -p Fl0nk3rt0n!T0by) to launch C:\Windows\Temp\python.exe on… |
| scranton.dmevals.local | C:\Program Files\SysinternalsSuite\sdelete64.exe | 3 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | malicious | sdelete64.exe run by PowerShell to securely delete the dropped .scr payload, Draft.Zip and SysinternalsSuite.zip on scranton - anti-forensics. |
| scranton.dmevals.local | C:\Program Files\Windows Defender\MsMpEng.exe | 1 | C:\Windows\System32\services.exe | benign | Windows Defender antivirus service started by services.exe. |
| scranton.dmevals.local | C:\Program Files\Windows Defender\NisSrv.exe | 2 | C:\Windows\System32\services.exe | benign | Windows Defender network inspection service started by services.exe. |
| scranton.dmevals.local | C:\ProgramData\victim\â€®cod.3aka3.scr | 1 | C:\Windows\explorer.exe | malicious | Screensaver-named binary in C:\ProgramData\victim launched by explorer.exe with /S; it wrote C:\Users\pbeesly\Downloads\monkey.png (the steganographic payload i… |
| scranton.dmevals.local | C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe | 2 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | malicious | csc.exe invoked by PowerShell with @response files in random Temp dirs (qkbkqqbs, 0piklvia) producing qkbkqqbs.dll/0piklvia.dll - runtime compilation of attacke… |
| scranton.dmevals.local | C:\Windows\System32\hostui.exe | 1 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | suspicious | hostui.exe started by PowerShell with 'Start-Process ... -verb runas' at 03:21:26, immediately followed by 'Get-ItemPropertyValue HKLM:\\SOFTWARE\Javasoft ... \… |
| scranton.dmevals.local | C:\Windows\System32\sdclt.exe | 3 | C:\Windows\System32\cmd.exe | suspicious | sdclt.exe (Backup and Restore) launched three times by cmd.exe at 02:58:42-43 while the attacker was setting HKCU\Software\Classes\Folder\shell\open\command wit… |
| scranton.dmevals.local | C:\WindowsAzure\Packages\GuestAgent\BfeToolWin8.exe | 1 | C:\WindowsAzure\Packages\GuestAgent\WindowsAzureGuestAgent.exe | benign | Azure guest agent firewall configuration tool started by WindowsAzureGuestAgent.exe. |
| scranton.dmevals.local | C:\WindowsAzure\Packages\GuestAgent\FindVolume\FindVolume.exe | 1 | C:\WindowsAzure\Packages\GuestAgent\WindowsAzureGuestAgent.exe | benign | Azure guest agent volume discovery utility started by WindowsAzureGuestAgent.exe. |
| scranton.dmevals.local | C:\WindowsAzure\Packages\GuestAgent\WindowsAzureGuestAgent.exe | 1 | C:\Windows\System32\services.exe | benign | Azure Windows Guest Agent service started by services.exe. |
| scranton.dmevals.local | C:\WindowsAzure\Packages\Telemetry\WindowsAzureTelemetryService.exe | 1 | C:\Windows\System32\services.exe | benign | Azure telemetry service started by services.exe. |
| scranton.dmevals.local | C:\WindowsAzure\Packages\WaAppAgent.exe | 1 | C:\Windows\System32\services.exe | benign | Azure agent host process started by services.exe. |
| scranton.dmevals.local | C:\WindowsAzure\SecAgent\WaSecAgentProv.exe | 2 | C:\WindowsAzure\Packages\WaAppAgent.exe | benign | Azure security agent provider started by WaAppAgent.exe. |
| scranton.dmevals.local | C:\WindowsAzure\WindowsAzureNetAgent_1.0.0.143\WindowsAzureNetAgent\Plugins\VFPl… | 1 | C:\WindowsAzure\WindowsAzureNetAgent_1.0.0.143\WindowsAzureNetAgent\WindowsAzure… | benign | Azure network agent plugin child of WindowsAzureNetAgent.exe. |
| scranton.dmevals.local | C:\WindowsAzure\WindowsAzureNetAgent_1.0.0.143\WindowsAzureNetAgent\WindowsAzure… | 1 | C:\Windows\System32\services.exe | benign | Azure network agent service started by services.exe. |

## Technique conclusions

One line per technique in scope: status from the triage of its family; `not_observed` = checked, nothing found; `not_observable` = no dataset records it.

| Technique | Status | Reason |
|---|---|---|
| T1003 OS Credential Dumping | malicious | Credential-access tooling confirmed on scranton: hidden PowerShell stego/IEX loader (PID 2976, parent control.exe) opened lsass.exe with 0x1F3FFF/0x1FFFFF, alongside SysinternalsSuite deployment, discovery, keystroke/scr… |
| T1003.001 LSASS Memory | malicious | LSASS memory access with full-access masks: PowerShell.exe 0x1FFFFF on scranton (03:05:16) and wsmprovhost.exe 0x1F3FFF on nashua (03:09:29); remaining 300+ lsass accesses are svchost/Azure-agent 0x1000/0x1400 and proces… |
| T1003.002 Security Account Manager | not_observed | No reg save of SAM/SYSTEM/SECURITY, no 4663 access to SAM/SECURITY hives, no hive-export script blocks. |
| T1003.003 NTDS | not_observed | No ntdsutil/vssadmin/ntds.dit command lines, file writes or object access; hosts are not domain controllers. |
| T1003.004 LSA Secrets | benign | Only Policy\Secrets\$MACHINE.ACC 4662 reads by LOCAL SERVICE (machine account), no lsadump/secretsdump activity. |
| T1003.005 Cached Domain Credentials | not_observed | No SECURITY\Cache object access and no cache/dcc/secretsdump script blocks. |
| T1003.006 DCSync | benign | Single 4662 replication-GUID access on newyork by the machine account NEWYORK$ with no DRSUAPI traffic or DCSync tooling; assessed benign. |
| T1040 Network Sniffing | benign | The only packet-capture activity is netsh.exe 'trace start capture=yes' / 'trace stop' on scranton.dmevals.local, spawned by the Microsoft Azure Network Watcher agent (NetworkWatcherAgent.exe /service) as SYSTEM using th… |
| T1056 Input Capture | malicious | Input capture toolkit executed on scranton: Get-Keystrokes keylogger job and Invoke-ScreenCapture. |
| T1056.001 Keylogging | malicious | Get-Keystrokes job run at 03:06:59, output viewed at 03:07:36 and job removed at 03:07:49 on scranton. |
| T1056.002 GUI Input Capture | malicious | Invoke-ScreenCapture function (CopyFromScreen loop, 300s interval, .bmp to Downloads) defined in psversion.ps1 and invoked by pbeesly on scranton.dmevals.local. |
| T1056.003 Web Portal Capture | not_observed | No wwwroot/inetpub/.aspx access, no login-portal file creation, no login/auth/signin HTTP URLs; 'login' hits were file-archive staging scripts. |
| T1056.004 Credential API Hooking | malicious | PowerShell.exe (scranton) and wsmprovhost.exe (nashua) opened lsass.exe with 0x1FFFFF/0x1F3FFF and UNKNOWN call-trace frames; remaining lsass access is benign OS/Azure perf-counter reads. |
| T1110 Brute Force | not_observed | Zero 4625/4771 failures; the only 4776 is a successful validation (Error Code 0x0) for pbeesly. No repeated authentication attempts on any host. |
| T1110.001 Password Guessing | not_observed | No failed logons and no net user/net use enumeration; PowerShell password matches are module manifests/resource strings. |
| T1110.002 Password Cracking | not_observed | No hive/NTDS/SAM dump commands or file access; lsass access is dominated by svchost/Azure agents and the 2 PowerShell accesses indicate credential theft (T1003), not cracking. |
| T1110.003 Password Spraying | not_observed | No spray pattern; 4648 events are UMFD/DWM/machine-account logons and the single runas is a local UAC elevation by pbeesly. |
| T1110.004 Credential Stuffing | not_observed | No authentication attempts across multiple accounts; hardcoded credentials in scranton PowerShell scripts relate to certificate export and WebDAV exfiltration, not stuffing. |
| T1111 Multi-Factor Authentication Interception | not_observed | No MFA/smart-card interception artifacts: zero process creations with smart-card/credential-provider/MFA command lines in sysmon (event.code:1) and security (4688); no SCardSvr or credential-provider service/DLL installa… |
| T1187 Forced Authentication | not_observed | No forced-authentication artifacts in the retrieved data. The only .lnk files are Explorer Recent items and a StartUp persistence shortcut (hostui.lnk) written by the compromised PowerShell process; all 66 outbound SMB c… |
| T1212 Exploitation for Credential Access | suspicious | No exploit of a vulnerable service or memory-corruption payload was observed, but the compromised pbeesly PowerShell session (hidden, -ep bypass, launched from control.exe) opened lsass.exe with full-access masks 0x1f3ff… |
| T1539 Steal Web Session Cookie | not_observed | No access to or copying of browser cookie/credential stores: sysmon code 10 hits on browser images = 0, sysmon code 2 hits = 0, security 4663/4656 object names matching cookie/Login Data/Web Data = 0. The only cookie-rel… |
| T1552 Unsecured Credentials | malicious | Unsecured credentials harvested: cleartext domain password in PsExec command lines and credential-keyword file collection into working.zip on nashua. |
| T1552.001 Credentials In Files | malicious | Cleartext dmevals\pbeesly password on PsExec64 command lines and PowerShell script blocks; recursive collection of *pass*/*login*/*admin*/*vpn files into working.zip. |
| T1552.002 Credentials in Registry | benign | All credential-named registry writes are OS service/identity/winlogon activity; no hive dumping or stored-credential reads. |
| T1552.003 Shell History | not_observed | No ConsoleHost_history, PSReadLine or Get-History access in sysmon, powershell or security data. |
| T1552.004 Private Keys | malicious | Get-PrivateKeys exported LocalMachine certificates to .pfx with hardcoded password 'saribas' from the attacker-staged readme.ps1 in C:\Program Files\SysinternalsSuite. |
| T1552.006 Group Policy Preferences | benign | SYSVOL reads are machine-account GPO refresh (gpt.ini/GptTmpl.inf); no Groups.xml or cpassword access. |
| T1555 Credentials from Password Stores | suspicious | Get-Clipboard harvesting and Invoke-Exfil staging of collected credential artifacts on scranton; no direct credential-store file reads observed. |
| T1555.003 Credentials from Web Browsers | suspicious | Clipboard contents read via Get-Clipboard at 03:06:42 on scranton, a common source of pasted credentials; no browser credential database access observed. |
| T1555.004 Windows Credential Manager | not_observed | No cmdkey/credman/vault execution, no Vault/Credentials registry or file access; only a Credential Guard configuration status message. |
| T1555.005 Password Managers | not_observed | No KeePass/1Password/Bitwarden process, file, memory or script activity; observed archiving is bulk file collection for exfiltration. |
| T1556 Modify Authentication Process | suspicious | Attacker-controlled hidden PowerShell (PID 2976, pbeesly, scranton) opened lsass with 0x1FFFFF and wsmprovhost on nashua with 0x1F3FFF, but no authentication-process modification was observed — the access is credential d… |
| T1556.001 Domain Controller Authentication | not_observed | No LSA registry writes, no unexpected lsass module loads, no DC authentication patching; anomalous lsass handles are dump-style access. |
| T1556.002 Password Filter DLL | not_observed | No Notification Packages registry change, no DLL dropped to System32, no password-filter references in PowerShell or windows.other. |
| T1556.005 Reversible Encryption | not_observed | No 4739 events and no Reversible/UserAccountControl registry or command-line activity. |
| T1556.006 Multi-Factor Authentication | not_observed | No 4739/5136 authentication policy changes; zeek kerberos records show only routine client-to-DC authentication. |
| T1556.007 Hybrid Identity | not_observed | No 5136 directory changes and no ADFS/Azure AD Connect or cloud-sync binaries loaded. |
| T1556.008 Network Provider DLL | not_observed | No NetworkProvider registry writes, DLL loads or file drops; lsass handles reflect memory access, not a registered provider. |
| T1557 Adversary-in-the-Middle | not_observed | No interception/relay evidence in sysmon, security or Zeek data. Outbound connections go to expected internal peers and Microsoft/Azure endpoints. The malicious PsExec+sdelete chain found on scranton/nashua is lateral mo… |
| T1557.001 Name Resolution Poisoning and SMB Relay | not_observed | SMB 445 and NBT-NS 137 traffic is ordinary domain traffic to 10.0.0.4; DNS queries are routine; no DNSClient registry tampering (C232 zero hits); the only NTLM network logon (172.18.39.2) is followed by type 10 logons fr… |
| T1557.002 ARP Cache Poisoning | not_observed | Zeek L2 mapping is stable and one-to-one (10.0.1.6 -> 00:0d:3a:13:e3:69, 10.0.1.4 -> 00:0d:3a:4d:42:f2, responder 12:34:56:78:9a:bc consistent); no duplicate MAC for multiple IPs. arp.exe /a, route.exe print and ipconfig… |
| T1557.003 DHCP Spoofing | not_observed | DHCP-related event codes 1341/1342/1020/1063 returned zero hits and no PowerShell referenced dhcp/netsh. The NDIS Capture start-type changes on scranton are part of an Azure Network Watcher netsh trace packet capture, no… |
| T1558 Steal or Forge Kerberos Tickets | suspicious | PowerShell.exe on scranton (0x1F3FFF then 0x1FFFFF) and wsmprovhost.exe on nashua (0x1F3FFF) opened lsass.exe with full-access masks alongside a hands-on-keyboard PowerShell toolkit (keystroke logging, screen capture, ex… |
| T1558.001 Golden Ticket | not_observed | No krbtgt dumping, no 'golden'/'krbtgt'/'mimikatz' script blocks, no kdc service installs; 4768/4769 for pbeesly and machine accounts only, AES 0x12, status 0x0. |
| T1558.002 Silver Ticket | not_observed | No silver-ticket tooling or service-ticket forgery evidence; 4769 service tickets only for machine accounts/krbtgt with AES 0x12 and status 0x0. |
| T1558.003 Kerberoasting | not_observed | No Kerberoast/SPN/GetUserSPNs/Rubeus artifacts; all 4769 tickets use AES 0x12 (no RC4 0x17) and target only machine accounts; Zeek kerberos shows normal single-client AS/TGS flow. |
| T1558.004 AS-REP Roasting | not_observed | No AS-REP/GetNPUsers/Rubeus artifacts; all 4768 events have PreAuthType 2 with status 0x0, and Zeek AS requests are a normal pbeesly logon with one KDC_ERR_PREAUTH_REQUIRED. |
| T1606 Forge Web Credentials | suspicious | User-launched PowerShell (PID 2976) on scranton opened lsass.exe with 0x1F3FFF/0x1FFFFF at 03:05:16Z immediately after exporting machine certificates; other high-access lsass events are from OS processes (wininit, csrss,… |
| T1606.001 Web Cookies | not_observed | No cookie-store access or cookie-related script blocks; the single INetCookies file creation is a normal LocalService AppContainer artefact created by svchost.exe. |
| T1606.002 SAML Tokens | malicious | Get-PrivateKeys in readme.ps1 exported every cert:\LocalMachine certificate to a .pfx with hardcoded password 'saribas' on scranton, producing C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx — private-key theft enabling toke… |
| T1621 Multi-Factor Authentication Request Generatio… | not_observed | 5 planned checks, all with zero hits |
| T1649 Steal or Forge Authentication Certificates | malicious | On scranton.dmevals.local, user pbeesly executed a staged script (readme.txt renamed to readme.ps1 and dot-sourced) defining Get-PrivateKeys, which exported every cert:\LocalMachine certificate with Export-PfxCertificate… |

## Coverage

Cells: number of hits of the planned checks, `n/a` (reason in report.json), or GAP.

| Technique | windows.other | windows.powershell | windows.security | windows.sysmon | zeek |
|---|---|---|---|---|---|
| T1003 OS Credential Dumping | 5 hits | 0 hits | 5797 hits | 40056 hits | n/a |
| T1003.001 LSASS Memory | n/a | 0 hits | 940 hits | 981 hits | n/a |
| T1003.002 Security Account Manager | n/a | 0 hits | 0 hits | 10 hits | n/a |
| T1003.003 NTDS | 5 hits | 0 hits | 0 hits | 0 hits | n/a |
| T1003.004 LSA Secrets | n/a | 0 hits | 934 hits | 349 hits | n/a |
| T1003.005 Cached Domain Credentials | n/a | 0 hits | 934 hits | 6955 hits | n/a |
| T1003.006 DCSync | 5 hits | 0 hits | 14 hits | 1 hits | n/a |
| T1040 Network Sniffing | 5 hits | 0 hits | 2 hits | 0 hits | 2140 hits |
| T1056 Input Capture | 5 hits | 0 hits | 10977 hits | 652 hits | n/a |
| T1056.001 Keylogging | 5 hits | 0 hits | 10977 hits | 353 hits | n/a |
| T1056.002 GUI Input Capture | 5 hits | 2 hits | 3 hits | 3 hits | n/a |
| T1056.003 Web Portal Capture | 5 hits | 2 hits | 0 hits | 0 hits | 124 hits |
| T1056.004 Credential API Hooking | 0 hits | 0 hits | 6 hits | 60196 hits | n/a |
| T1110 Brute Force | 2 hits | 3 hits | 1 hits | 31 hits | n/a |
| T1110.001 Password Guessing | 2 hits | 0 hits | 0 hits | 0 hits | n/a |
| T1110.002 Password Cracking | 6 hits | 10 hits | 153 hits | 329 hits | n/a |
| T1110.003 Password Spraying | 4 hits | 4 hits | 15 hits | 1 hits | n/a |
| T1110.004 Credential Stuffing | 2 hits | 2 hits | 0 hits | 0 hits | n/a |
| T1111 Multi-Factor Authentication Interception | 2 hits | 3 hits | 327 hits | 39295 hits | n/a |
| T1187 Forced Authentication | 1 hits | 0 hits | 11140 hits | 69 hits | 62 hits |
| T1212 Exploitation for Credential Access | 0 hits | 22 hits | 502 hits | 652 hits | n/a |
| T1539 Steal Web Session Cookie | 3 hits | 13 hits | 460 hits | 162 hits | n/a |
| T1552 Unsecured Credentials | 2 hits | 2 hits | 460 hits | 89 hits | n/a |
| T1552.001 Credentials In Files | 0 hits | 1 hits | 312 hits | 72 hits | n/a |
| T1552.002 Credentials in Registry | 9 hits | 5 hits | 4484 hits | 17 hits | n/a |
| T1552.003 Shell History | 5 hits | 0 hits | 0 hits | 0 hits | n/a |
| T1552.004 Private Keys | 0 hits | 1 hits | 0 hits | 1 hits | n/a |
| T1552.006 Group Policy Preferences | 0 hits | 3 hits | 38 hits | 0 hits | n/a |
| T1555 Credentials from Password Stores | 0 hits | 3 hits | 6 hits | 652 hits | n/a |
| T1555.003 Credentials from Web Browsers | 0 hits | 0 hits | 0 hits | 1 hits | n/a |
| T1555.004 Windows Credential Manager | 2 hits | 3 hits | 0 hits | 0 hits | n/a |
| T1555.005 Password Managers | 0 hits | 0 hits | 0 hits | 0 hits | n/a |
| T1556 Modify Authentication Process | 0 hits | 0 hits | 0 hits | 691 hits | n/a |
| T1556.001 Domain Controller Authentication | 0 hits | 0 hits | 233 hits | 359 hits | n/a |
| T1556.002 Password Filter DLL | 0 hits | 0 hits | 0 hits | 19432 hits | n/a |
| T1556.005 Reversible Encryption | 0 hits | 0 hits | 0 hits | 0 hits | n/a |
| T1556.006 Multi-Factor Authentication | 0 hits | 0 hits | 0 hits | n/a | 35 hits |
| T1556.007 Hybrid Identity | n/a | 0 hits | 0 hits | 20259 hits | 35 hits |
| T1556.008 Network Provider DLL | n/a | n/a | 0 hits | 751 hits | 123 hits |
| T1557 Adversary-in-the-Middle | n/a | n/a | 10977 hits | 1310 hits | 613 hits |
| T1557.001 Name Resolution Poisoning and SMB Relay | n/a | n/a | 23 hits | 74 hits | 100 hits |
| T1557.002 ARP Cache Poisoning | n/a | n/a | n/a | 2458 hits | 1226 hits |
| T1557.003 DHCP Spoofing | 0 hits | 0 hits | 297 hits | 447 hits | n/a |
| T1558 Steal or Forge Kerberos Tickets | 0 hits | 0 hits | 448 hits | 652 hits | 84 hits |
| T1558.001 Golden Ticket | 0 hits | 0 hits | 448 hits | 326 hits | n/a |
| T1558.002 Silver Ticket | 0 hits | 0 hits | 448 hits | 326 hits | n/a |
| T1558.003 Kerberoasting | 0 hits | 0 hits | 509 hits | 326 hits | n/a |
| T1558.004 AS-REP Roasting | 0 hits | 0 hits | 509 hits | 447 hits | n/a |
| T1606 Forge Web Credentials | 9 hits | 1 hits | 297 hits | 326 hits | n/a |
| T1606.001 Web Cookies | 0 hits | 0 hits | 312 hits | 1 hits | n/a |
| T1606.002 SAML Tokens | 9 hits | 0 hits | 312 hits | 1 hits | n/a |
| T1621 Multi-Factor Authentication Request Generatio… | 0 hits | 0 hits | 0 hits | 0 hits | n/a |
| T1649 Steal or Forge Authentication Certificates | 0 hits | 1 hits | 50 hits | 1 hits | n/a |

Cells: 265, gaps: 0.

## Queries

Every MCP tool call of this run (1149), in order (source: mcp_audit.jsonl written by the MCP server).

| Query | Phase | Tool | Arguments | Hits / rows | Cited by |
|---|---|---|---|---|---|
| q-8850ce6026 | scope | list_data_sources | {} | None |  |
| q-413c422489 | scope | get_registry | {} | None |  |
| q-1feffcc0f6 | scope | get_fields | {"dataset": "windows.other", "prefix": ""} | None |  |
| q-640559e562 | scope | get_fields | {"dataset": "windows.powershell", "prefix": ""} | None |  |
| q-f0ce2d6e85 | scope | get_fields | {"dataset": "windows.security", "prefix": ""} | None |  |
| q-27ea52b8a0 | scope | get_fields | {"dataset": "windows.sysmon", "prefix": ""} | None |  |
| q-e012b914c3 | scope | get_fields | {"dataset": "zeek", "prefix": ""} | None |  |
| q-6078b15ccd | check C001 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 447 |  |
| q-86e2c2685e | check C002 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 39283 |  |
| q-c79601544a | check C003 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 326 |  |
| q-3b68ae1797 | check C004 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 460 |  |
| q-1d98e91ba4 | check C005 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 5337 |  |
| q-ae8a46b70c | check C006 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*MiniDump* OR win.ScriptBlockText:*procdump* OR win.ScriptBlockText:*mimikatz* OR win.ScriptBlockText:*ntds*)", "time_from": null, "time_to": nu… | 0 |  |
| q-f8b398c9a9 | check C007 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-08d9791693 | check C008 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass.exe", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command… | 326 | F03 |
| q-64f6fee24e | check C009 | aggregate | {"dataset": "windows.sysmon", "field": "win.SourceImage", "query": "event.code:10 AND win.TargetImage:*lsass.exe", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 326 |  |
| q-94664f3475 | check C010 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass.exe", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 326 |  |
| q-e292ae6a4f | check C011 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*comsvcs* OR process.command_line:*MiniDump* OR process.command_line:*procdump* OR process.command_line:*lsass*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host… | 1 | F03, F05 |
| q-c4ecf00dc7 | check C012 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (win.TargetFilename:*.dmp OR win.TargetFilename:*lsass*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process… | 2 | F03 |
| q-7827f00ac4 | check C013 | search | {"dataset": "windows.sysmon", "query": "event.code:13 AND (registry.path:*lsass* OR registry.path:*WDigest* OR registry.path:*UseLogonCredential*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "ev… | 0 |  |
| q-b3836b0825 | check C014 | aggregate | {"dataset": "windows.security", "field": "win.ProcessName", "query": "event.code:4673", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 934 |  |
| q-0325152b65 | check C015 | search | {"dataset": "windows.security", "query": "event.code:4663 AND win.ObjectName:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command… | 6 |  |
| q-036fa430ea | check C016 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*MiniDump* OR win.ScriptBlockText:*comsvcs*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event… | 0 |  |
| q-5b3391f435 | check C017 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*reg* AND process.command_line:*save* AND process.command_line:*SAM*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "… | 0 |  |
| q-21ba49e0b9 | check C018 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (win.TargetFilename:*SAM* OR win.TargetFilename:*SYSTEM* OR win.TargetFilename:*SECURITY*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "… | 3 |  |
| q-4dcdfd83a0 | check C019 | search | {"dataset": "windows.sysmon", "query": "event.code:2 AND (file.path:*SAM* OR file.path:*SYSTEM* OR file.path:*SECURITY*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "p… | 0 |  |
| q-5f4523aed8 | check C020 | search | {"dataset": "windows.sysmon", "query": "event.code:13 AND (registry.path:*SAM* OR registry.path:*SECURITY*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.execut… | 7 |  |
| q-69137c4be0 | check C021 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*reg* AND process.command_line:*save*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", … | 0 |  |
| q-943c20d75f | check C022 | search | {"dataset": "windows.security", "query": "event.code:4663 AND (win.ObjectName:*SAM* OR win.ObjectName:*SECURITY*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.… | 0 |  |
| q-bbdacf0bbe | check C023 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*reg save* OR win.ScriptBlockText:*SAM* OR win.ScriptBlockText:*hive*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.data… | 0 |  |
| q-58d0e55d84 | check C024 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*ntdsutil* OR process.command_line:*vssadmin* OR process.command_line:*ntds.dit*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event… | 0 |  |
| q-db0de522a7 | check C025 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (win.TargetFilename:*ntds.dit* OR win.TargetFilename:*.dit)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "proc… | 0 |  |
| q-97d18f8c69 | check C026 | search | {"dataset": "windows.sysmon", "query": "event.code:2 AND file.path:*ntds.dit*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line",… | 0 |  |
| q-4295cc6bf6 | check C027 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*ntdsutil* OR process.command_line:*vssadmin* OR process.command_line:*ntds.dit*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "… | 0 |  |
| q-4851611d77 | check C028 | search | {"dataset": "windows.security", "query": "event.code:4663 AND win.ObjectName:*ntds.dit*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.comm… | 0 |  |
| q-5087f64565 | check C029 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-334ebf5192 | check C030 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*ntds* OR win.ScriptBlockText:*vssadmin* OR win.ScriptBlockText:*shadow*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.d… | 0 |  |
| q-d0ea20ce72 | check C031 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass.exe", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command… | 326 |  |
| q-6e5fd2dac1 | check C032 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*secrets* OR process.command_line:*lsadump* OR process.command_line:*mimikatz*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.d… | 0 |  |
| q-2a0fb2f7a1 | check C033 | search | {"dataset": "windows.sysmon", "query": "event.code:7 AND (win.ImageLoaded:*lsass* OR win.ImageLoaded:*samlib* OR win.ImageLoaded:*vaultcli*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.co… | 23 |  |
| q-98287b6d4c | check C034 | search | {"dataset": "windows.sysmon", "query": "event.code:13 AND registry.path:*SECURITY*Policy*Secrets*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "pr… | 0 |  |
| q-d1d954d080 | check C035 | search | {"dataset": "windows.security", "query": "event.code:4663 AND win.ObjectName:*SECURITY*Policy*Secrets*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable"… | 0 |  |
| q-b0a0349bf6 | check C036 | aggregate | {"dataset": "windows.security", "field": "win.ProcessName", "query": "event.code:4673", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 934 |  |
| q-92226c2818 | check C037 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Secrets* OR win.ScriptBlockText:*lsadump* OR win.ScriptBlockText:*LSA*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.da… | 0 |  |
| q-a1b4ea2399 | check C038 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass.exe", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command… | 326 |  |
| q-7cc9ad6c7c | check C039 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*cache* OR process.command_line:*dcc* OR process.command_line:*mimikatz* OR process.command_line:*secretsdump*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.… | 4 |  |
| q-49f15724e8 | check C040 | search | {"dataset": "windows.sysmon", "query": "event.code:13 AND (registry.path:*Cache* OR registry.path:*SECURITY*Cache*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "proces… | 6625 |  |
| q-53e9d2a72f | check C041 | search | {"dataset": "windows.security", "query": "event.code:4663 AND (win.ObjectName:*SECURITY*Cache* OR win.ObjectName:*Cache*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "… | 0 |  |
| q-aa0ccbe61f | check C042 | aggregate | {"dataset": "windows.security", "field": "win.ProcessName", "query": "event.code:4673", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 934 |  |
| q-6197393619 | check C043 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*cache* OR win.ScriptBlockText:*dcc* OR win.ScriptBlockText:*secretsdump*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.… | 0 |  |
| q-4830ee09ef | check C044 | count | {"dataset": "windows.security", "query": "event.code:4662", "time_from": null, "time_to": null} | 7 |  |
| q-1181fabdd2 | check C045 | aggregate | {"dataset": "windows.security", "field": "win.Properties", "query": "event.code:4662", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 7 |  |
| q-7975c4b92c | check C046 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*drsuapi* OR process.command_line:*lsass* OR process.command_line:*ntds*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1 |  |
| q-f0350e8a2a | check C047 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*DCSync* OR win.ScriptBlockText:*Invoke-Mimikatz* OR win.ScriptBlockText:*drsuapi* OR win.ScriptBlockText:*lsadump*)", "time_from": null, "time_to": null, "fields": ["@timesta… | 0 |  |
| q-80b0c2a993 | check C048 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-02b64f7372 | check C049 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND (process.command_line:*pktmon* OR process.command_line:*netsh* OR process.command_line:*windump* OR process.command_line:*tcpdump* OR process.command_line:*rawcap*)", … | 2 |  |
| q-c567d1f548 | check C050 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*pktmon* OR process.command_line:*windump* OR process.command_line:*tcpdump* OR process.command_line:*rawcap* OR process.command_line:*netsh*wlan*)", … | 0 |  |
| q-b237775900 | check C051 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-af40c19d6a | check C052 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*pktmon* OR win.ScriptBlockText:*WinPcap* OR win.ScriptBlockText:*promiscuous* OR win.ScriptBlockText:*packet*)", "time_from": null, "time_to": null, "fields": ["@timestamp", … | 0 |  |
| q-6b6fa70c40 | check C053 | aggregate | {"dataset": "zeek", "field": "zeek.service", "query": "*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 2140 |  |
| q-ad5f251d77 | check C054 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass.exe", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-4e6c202617 | check C055 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND win.TargetImage:*lsass.exe", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-e88a4753d8 | check C056 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4656 OR event.code:4663 OR event.code:4670", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 10977 |  |
| q-585a9f716a | check C057 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*GetAsyncKeyState* OR win.ScriptBlockText:*SetWindowsHookEx* OR win.ScriptBlockText:*keylog*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "obse… | 0 |  |
| q-2287ded4f7 | check C058 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 | F14 |
| q-2e0ea4de91 | check C059 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND win.TargetImage:*lsass.exe", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-8bc054d46e | check C060 | aggregate | {"dataset": "windows.sysmon", "field": "registry.path", "query": "event.code:13 AND (registry.path:*Keyboard* OR registry.path:*keylog* OR registry.path:*CurrentVersion\\\\Run*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 27 |  |
| q-e7c7834804 | check C061 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4656 OR event.code:4663 OR event.code:4670", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 10977 |  |
| q-9fb72c6479 | check C062 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-039f738a33 | check C063 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*GetAsyncKeyState* OR win.ScriptBlockText:*SetWindowsHookEx* OR win.ScriptBlockText:*keylog*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "obse… | 0 |  |
| q-fbaf12fe8d | check C064 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*Credential* OR process.command_line:*prompt* OR process.command_line:*consent*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 3 |  |
| q-3f8dab3c7b | check C065 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*CredentialUI* OR win.ScriptBlockText:*Get-Credential* OR win.ScriptBlockText:*PromptForCredential* OR win.ScriptBlockText:*Windows.Forms*)", "time_from": null, "time_to": nul… | 2 |  |
| q-ce3a540db8 | check C066 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND (process.command_line:*Credential* OR process.command_line:*consent*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 3 |  |
| q-528eb6778b | check C067 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-0143998491 | check C068 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND (win.TargetFilename:*login* OR win.TargetFilename:*portal* OR win.TargetFilename:*wwwroot* OR win.TargetFilename:*.aspx OR win.TargetFilename:*.php)", "time_from": null, "… | 0 |  |
| q-48ba1c603d | check C069 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND (win.ObjectName:*wwwroot* OR win.ObjectName:*inetpub* OR win.ObjectName:*.aspx)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-ac621f6181 | check C070 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*wwwroot* OR win.ScriptBlockText:*inetpub* OR win.ScriptBlockText:*login*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.… | 2 | F15 |
| q-58805ad5d7 | check C071 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-0cf8be034a | check C072 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-8df0c4f93b | check C073 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-fd934a941c | check C074 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 326 |  |
| q-cde8949d6c | check C075 | aggregate | {"dataset": "windows.sysmon", "field": "win.ImageLoaded", "query": "event.code:7", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 20259 |  |
| q-31ec03869c | check C076 | search | {"dataset": "windows.sysmon", "query": "event.code:8 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_lin… | 2 |  |
| q-48ab0ff8c6 | check C077 | aggregate | {"dataset": "windows.security", "field": "win.TargetProcessName", "query": "event.code:4663 AND win.ObjectType:*Process*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 6 |  |
| q-61bcefe9f1 | check C078 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*MiniDump* OR win.ScriptBlockText:*comsvcs*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event… | 0 |  |
| q-e739364a70 | check C079 | search | {"dataset": "windows.other", "query": "message:*lsass* OR win.ImagePath:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line… | 0 |  |
| q-2031263afd | check C080 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-e9ee46e6d1 | check C081 | aggregate | {"dataset": "windows.security", "field": "source.ip", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-a7f2e0af08 | check C082 | timeline | {"dataset": "windows.security", "query": "event.code:4625", "interval": "1m", "time_from": null, "time_to": null} | 0 |  |
| q-3756701582 | check C083 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4776", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1 |  |
| q-7a308a29b5 | check C084 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*net* OR process.command_line:*user* OR process.command_line:*password*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 31 |  |
| q-e113006160 | check C085 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*password* OR win.ScriptBlockText:*Credential* OR win.ScriptBlockText:*Brute*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "ev… | 3 |  |
| q-b1ec63d21b | check C086 | search | {"dataset": "windows.other", "query": "message:*logon* OR message:*password*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 2 |  |
| q-f9dc5769c6 | check C087 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-e3be4151da | check C088 | timeline | {"dataset": "windows.security", "query": "event.code:4625", "interval": "1m", "time_from": null, "time_to": null} | 0 |  |
| q-1cc1c2d0a6 | check C089 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-ea764d22a9 | check C090 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*net\\ user* OR process.command_line:*net\\ use*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.n… | 0 |  |
| q-66cf6b990b | check C091 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*password* OR win.ScriptBlockText:*Login*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.na… | 0 |  |
| q-a088ac2cdd | check C092 | search | {"dataset": "windows.other", "query": "message:*password* OR message:*logon*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 2 |  |
| q-b424c70cb0 | check C093 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND (win.ObjectName:*SAM* OR win.ObjectName:*SECURITY* OR win.ObjectName:*NTDS*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-46e9a4ceca | check C094 | aggregate | {"dataset": "windows.security", "field": "win.TargetProcessName", "query": "event.code:4656 AND (win.ObjectName:*SAM* OR win.ObjectName:*SECURITY* OR win.ObjectName:*NTDS*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 10 |  |
| q-ee5cf59405 | check C095 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4670", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 143 |  |
| q-dd49466fbb | check C096 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*reg\\ save* OR process.command_line:*ntds* OR process.command_line:*sam*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-45377a162b | check C097 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND (win.TargetFilename:*SAM* OR win.TargetFilename:*SECURITY* OR win.TargetFilename:*ntds.dit*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 3 |  |
| q-17cef39f44 | check C098 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10 AND (win.TargetImage:*lsass* OR win.TargetImage:*SAM*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-28981b7081 | check C099 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*ntds* OR win.ScriptBlockText:*reg\\ save* OR win.ScriptBlockText:*hash*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.d… | 10 |  |
| q-1bc94f0cf5 | check C100 | search | {"dataset": "windows.other", "query": "message:*ntds* OR message:*SAM* OR message:*hive*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.com… | 6 |  |
| q-c684946cf1 | check C101 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-78908c4d0a | check C102 | aggregate | {"dataset": "windows.security", "field": "source.ip", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-bd06d747b9 | check C103 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4771", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-6f34dd24e9 | check C104 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4648", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 15 |  |
| q-8c99a56f7f | check C105 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*net\\ use* OR process.command_line:*runas*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name",… | 1 | F19 |
| q-ec1ecd8a58 | check C106 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Credential* OR win.ScriptBlockText:*Password*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "us… | 4 |  |
| q-da16f4ab44 | check C107 | search | {"dataset": "windows.other", "query": "message:*logon* OR message:*authentication*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_l… | 4 | F17 |
| q-3617c51b3d | check C108 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-64df0c2c15 | check C109 | aggregate | {"dataset": "windows.security", "field": "source.ip", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-18810681bd | check C110 | timeline | {"dataset": "windows.security", "query": "event.code:4625", "interval": "1m", "time_from": null, "time_to": null} | 0 |  |
| q-ba8497371b | check C111 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*password* OR process.command_line:*credential*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.na… | 0 |  |
| q-cfc9178d4e | check C112 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*password* OR win.ScriptBlockText:*credential*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "us… | 2 | F17 |
| q-2e2f514f49 | check C113 | search | {"dataset": "windows.other", "query": "message:*logon* OR message:*password*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 2 |  |
| q-e0deb82ed2 | check C114 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4624 OR event.code:4648", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 312 |  |
| q-18612de0c5 | check C115 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4648", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 15 |  |
| q-08b10221dd | check C116 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 39283 |  |
| q-7daf7e684f | check C117 | search | {"dataset": "windows.sysmon", "query": "event.code:13 AND (registry.path:*SmartCard* OR registry.path:*SCard* OR registry.path:*Credential*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.co… | 12 | F21 |
| q-ca6d11ff77 | check C118 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*SmartCard* OR win.ScriptBlockText:*Credential* OR win.ScriptBlockText:*MFA*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "eve… | 3 |  |
| q-fab0076e3c | check C119 | search | {"dataset": "windows.other", "query": "message:*SmartCard* OR message:*Credential*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_l… | 2 |  |
| q-fdce133582 | check C120 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 OR event.code:4656 OR event.code:4670", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 10977 |  |
| q-1194c934d0 | check C121 | aggregate | {"dataset": "windows.security", "field": "win.ShareName", "query": "event.code:5140 OR event.code:5145", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 163 |  |
| q-a243475759 | check C122 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (win.TargetFilename:*.lnk OR win.TargetFilename:*.scf OR win.TargetFilename:*.url OR win.TargetFilename:*.library-ms)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observe… | 3 |  |
| q-f9ff34a43c | check C123 | aggregate | {"dataset": "windows.sysmon", "field": "destination.ip", "query": "event.code:3 AND (destination.port:445 OR destination.port:139)", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 66 |  |
| q-96ccbdd494 | check C124 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*WebDAV* OR win.ScriptBlockText:*NTLM* OR win.ScriptBlockText:*\\\\\\\\)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.da… | 0 |  |
| q-ac04f4a360 | check C125 | search | {"dataset": "windows.other", "query": "message:*WebDAV* OR message:*NTLM*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "so… | 1 |  |
| q-c30a0c0f3b | check C126 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4768 OR event.code:4769 OR event.code:4770", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 42 |  |
| q-1c9b47ea5c | check C127 | aggregate | {"dataset": "windows.sysmon", "field": "win.SourceImage", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 326 |  |
| q-f6f3003c58 | check C128 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 326 |  |
| q-2e3476e80e | check C129 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 460 |  |
| q-018a9b6524 | check C130 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Invoke-* OR win.ScriptBlockText:*Reflection* OR win.ScriptBlockText:*Assembly*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "… | 22 |  |
| q-93b3a7944a | check C131 | search | {"dataset": "windows.other", "query": "message:*lsass* OR message:*MiniDump*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 0 |  |
| q-b6514fe66a | check C132 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (win.TargetFilename:*Cookies* OR win.TargetFilename:*Login Data* OR win.TargetFilename:*Web Data*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dat… | 162 |  |
| q-c4a55bb79a | check C133 | search | {"dataset": "windows.sysmon", "query": "event.code:2 AND (win.TargetFilename:*Cookies* OR win.TargetFilename:*Login Data*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", … | 0 |  |
| q-98acbf689a | check C134 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10 AND (win.TargetImage:*chrome* OR win.TargetImage:*firefox* OR win.TargetImage:*msedge* OR win.TargetImage:*iexplore*)", "time_from": null, "time_to": null, "size": 30, "sub_field… | 0 |  |
| q-68e470092e | check C135 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 460 |  |
| q-47b240967a | check C136 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Cookies* OR win.ScriptBlockText:*Login Data* OR win.ScriptBlockText:*sqlite*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "ev… | 13 |  |
| q-27640efd57 | check C137 | search | {"dataset": "windows.other", "query": "message:*Cookies* OR message:*Login Data*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_lin… | 3 |  |
| q-7be8b77e98 | check C138 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND (win.TargetFilename:*.txt OR win.TargetFilename:*.config OR win.TargetFilename:*.xml OR win.TargetFilename:*.ini OR win.TargetFilename:*.ps1)", "time_from": null, "time_to… | 72 |  |
| q-37261658ed | check C139 | search | {"dataset": "windows.sysmon", "query": "event.code:13 AND (registry.path:*Password* OR registry.path:*Credential* OR registry.path:*Unattend*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.… | 17 | F28 |
| q-5fa1b89d3f | check C140 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 460 |  |
| q-a97a0d138b | check C141 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*password* OR win.ScriptBlockText:*credential* OR win.ScriptBlockText:*Get-Content*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name… | 2 |  |
| q-36e6dc497d | check C142 | search | {"dataset": "windows.other", "query": "message:*password* OR message:*credential*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 2 |  |
| q-067f7f688d | check C143 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND (win.TargetFilename:*.txt OR win.TargetFilename:*.config OR win.TargetFilename:*.xml OR win.TargetFilename:*.ini OR win.TargetFilename:*.ps1 OR win.TargetFilename:*.bat)",… | 72 |  |
| q-1e14f63c6f | check C144 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*password* OR process.command_line:*credential* OR process.command_line:*.config)", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 0 |  |
| q-313ce74305 | check C145 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4624 OR event.code:4648", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 312 |  |
| q-dec630efcc | check C146 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Get-Content* OR win.ScriptBlockText:*Select-String* OR win.ScriptBlockText:*password*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.n… | 1 |  |
| q-5ad64e21c4 | check C147 | search | {"dataset": "windows.other", "query": "message:*.config OR message:*.txt", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "sou… | 0 |  |
| q-648792209d | check C148 | aggregate | {"dataset": "windows.sysmon", "field": "registry.path", "query": "event.code:13 AND (registry.path:*Password* OR registry.path:*Credential* OR registry.path:*Secret* OR registry.path:*DefaultPassword*)", "time_from": null, "time_to": null, "size": 50, "sub_fie… | 17 |  |
| q-a1bc38df50 | check C149 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*reg\\ query* OR process.command_line:*reg\\ save* OR process.command_line:*win32_credential* OR process.command_line:*vaultcmd*)", "time_from": null, "time_to": null, "fields": ["@… | 0 |  |
| q-063b963a08 | check C150 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Password* OR win.ScriptBlockText:*Credential* OR win.ScriptBlockText:*HKLM* OR win.ScriptBlockText:*Get-ItemProperty*)", "time_from": null, "time_to": null, "fields": ["@time… | 5 |  |
| q-89a590564b | check C151 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND (win.ObjectName:*SAM* OR win.ObjectName:*SECURITY* OR win.ObjectName:*SYSTEM*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 4484 |  |
| q-37389fe6d3 | check C152 | search | {"dataset": "windows.other", "query": "event.code:7045 OR event.code:7040", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "so… | 9 |  |
| q-2dc80c8bcb | check C153 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*history* OR win.ScriptBlockText:*ConsoleHost_history* OR win.ScriptBlockText:*Get-History* OR win.ScriptBlockText:*PSReadLine*)", "time_from": null, "time_to": null, "fields"… | 0 |  |
| q-d985678bda | check C154 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*ConsoleHost_history* OR process.command_line:*PSReadLine* OR process.command_line:*Get-History*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observ… | 0 |  |
| q-ca02aa5f9c | check C155 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*ConsoleHost_history* OR file.path:*PSReadLine*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "proc… | 0 |  |
| q-08b12f12b9 | check C156 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND (win.ObjectName:*ConsoleHost_history* OR win.ObjectName:*PSReadLine*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-0813c384e2 | check C157 | search | {"dataset": "windows.other", "query": "message:*history* OR message:*PSReadLine*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_lin… | 5 | F29 |
| q-70268b77fd | check C158 | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11 AND (file.path:*.pfx OR file.path:*.pem OR file.path:*.key OR file.path:*.p12 OR file.path:*.ppk OR file.path:*.cer OR file.path:*.p7b OR file.path:*.asc)", "time_from": null, "time_to… | 1 |  |
| q-c18ba6dc42 | check C159 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*.pfx OR process.command_line:*.pem OR process.command_line:*.p12 OR process.command_line:*certutil* OR process.command_line:*Export-PfxCertificate*)", "time_from": null, "time_to":… | 0 |  |
| q-25c724ff87 | check C160 | aggregate | {"dataset": "windows.security", "field": "win.RelativeTargetName", "query": "event.code:5145 AND (win.RelativeTargetName:*.pfx OR win.RelativeTargetName:*.pem OR win.RelativeTargetName:*.key OR win.RelativeTargetName:*.p12 OR win.RelativeTargetName:*.ppk)", "t… | 0 |  |
| q-5fca2dc3fe | check C161 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*.pfx OR win.ScriptBlockText:*.pem OR win.ScriptBlockText:*Export-PfxCertificate* OR win.ScriptBlockText:*Get-ChildItem*key*)", "time_from": null, "time_to": null, "fields": [… | 1 |  |
| q-33eee3d038 | check C162 | search | {"dataset": "windows.other", "query": "message:*.pfx OR message:*.pem OR message:*.p12", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.comma… | 0 |  |
| q-649d1e4831 | check C163 | aggregate | {"dataset": "windows.security", "field": "win.RelativeTargetName", "query": "event.code:5145 AND (win.RelativeTargetName:*Groups.xml OR win.RelativeTargetName:*SYSVOL* OR win.RelativeTargetName:*Policies*)", "time_from": null, "time_to": null, "size": 50, "sub… | 38 |  |
| q-591112b42c | check C164 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*Groups.xml OR process.command_line:*SYSVOL* OR process.command_line:*gpp* OR process.command_line:*cpassword*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.… | 0 |  |
| q-95dbcc9b6e | check C165 | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11 AND (file.path:*Groups.xml OR file.path:*SYSVOL*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-f0147bbe67 | check C166 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*cpassword* OR win.ScriptBlockText:*Groups.xml* OR win.ScriptBlockText:*AES* OR win.ScriptBlockText:*FromBase64String*)", "time_from": null, "time_to": null, "fields": ["@time… | 3 |  |
| q-ccf873efa2 | check C167 | search | {"dataset": "windows.other", "query": "message:*Groups.xml OR message:*cpassword* OR message:*SYSVOL*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable",… | 0 |  |
| q-6e49328991 | check C168 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10 AND win.TargetImage:*lsass.exe", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-2090271f1e | check C169 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass.exe", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-52a191cb1a | check C170 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*procdump* OR process.command_line:*comsvcs* OR process.command_line:*MiniDump* OR process.command_line:*sekurlsa* OR process.command_line:*mimikatz* OR process.command_line:*vaultc… | 0 |  |
| q-0ce3017fed | check C171 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND (win.ObjectName:*lsass* OR win.ObjectName:*SAM* OR win.ObjectName:*SECURITY* OR win.ObjectName:*NTDS.dit* OR win.ObjectName:*Credential*)", "time_from": null, "time_to": n… | 6 |  |
| q-41aca7678a | check C172 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4769 AND win.TicketEncryptionType:0x17", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-8d8f1f152d | check C173 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*MiniDump* OR win.ScriptBlockText:*Credential* OR win.ScriptBlockText:*Invoke-Mimikatz*)", "time_from": null, "time_to": null, "fields": ["@time… | 3 |  |
| q-a45935bb7b | check C174 | search | {"dataset": "windows.other", "query": "message:*lsass* OR message:*MiniDump* OR message:*NTDS*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "proce… | 0 |  |
| q-8d7d22db04 | check C175 | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11 AND (file.path:*Login\\ Data* OR file.path:*Local\\ State* OR file.path:*logins.json* OR file.path:*key4.db* OR file.path:*Cookies*)", "time_from": null, "time_to": null, "size": 50, "… | 1 |  |
| q-a4e60a9990 | check C176 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*Login\\ Data* OR process.command_line:*Local\\ State* OR process.command_line:*logins.json* OR process.command_line:*key4.db* OR process.command_line:*sqlite*)", "time_from": null,… | 0 |  |
| q-ee2a152729 | check C177 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND (win.ObjectName:*Login\\ Data* OR win.ObjectName:*Local\\ State* OR win.ObjectName:*logins.json* OR win.ObjectName:*key4.db*)", "time_from": null, "time_to": null, "size":… | 0 |  |
| q-61c2339f44 | check C178 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Login\\ Data* OR win.ScriptBlockText:*Local\\ State* OR win.ScriptBlockText:*logins.json* OR win.ScriptBlockText:*key4.db*)", "time_from": null, "time_to": null, "fields": ["… | 0 |  |
| q-3301fdd861 | check C179 | search | {"dataset": "windows.other", "query": "message:*Login\\ Data* OR message:*logins.json* OR message:*key4.db*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.execut… | 0 |  |
| q-60e0367a7e | check C180 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*vault* OR process.command_line:*credman* OR process.command_line:*cmdkey* OR process.command_line:*Credential*)", "time_from": null, "time_to": null,… | 0 |  |
| q-c3f81414cf | check C181 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetObject", "query": "event.code:10 AND win.TargetObject:*Vault*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-9cb9e6e66d | check C182 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND (win.TargetFilename:*Microsoft\\\\Credentials* OR win.TargetFilename:*Vault*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-2d8b9c64f7 | check C183 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND (process.command_line:*vault* OR process.command_line:*cmdkey* OR process.command_line:*credman*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-6863794517 | check C184 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Vault* OR win.ScriptBlockText:*Credential* OR win.ScriptBlockText:*cmdkey*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "even… | 3 |  |
| q-24d05c9446 | check C185 | search | {"dataset": "windows.other", "query": "message:*Vault* OR message:*Credential*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line"… | 2 | F34 |
| q-55f0a20f38 | check C186 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*keepass* OR process.command_line:*1password* OR process.command_line:*bitwarden* OR process.command_line:*lastpass* OR process.command_line:*KeePass*… | 0 |  |
| q-b247672949 | check C187 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND (win.TargetFilename:*.kdbx OR win.TargetFilename:*1password* OR win.TargetFilename:*keepass*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-f4bc523a47 | check C188 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10 AND (win.TargetImage:*keepass* OR win.TargetImage:*1password* OR win.TargetImage:*bitwarden*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-64c2101aee | check C189 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND (process.command_line:*keepass* OR process.command_line:*1password* OR process.command_line:*bitwarden*)", "time_from": null, "time_to": null, "size": 50, "sub_field":… | 0 |  |
| q-528a10591b | check C190 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*kdbx* OR win.ScriptBlockText:*keepass* OR win.ScriptBlockText:*1password*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event… | 0 |  |
| q-585c34ea60 | check C191 | search | {"dataset": "windows.other", "query": "message:*keepass* OR message:*1password* OR message:*kdbx*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "pr… | 0 |  |
| q-719d47af49 | check C192 | aggregate | {"dataset": "windows.sysmon", "field": "win.SourceImage", "query": "event.code:10 AND win.TargetImage:*lsass.exe", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 326 |  |
| q-679576d10a | check C193 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass.exe", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-384de0f48b | check C194 | aggregate | {"dataset": "windows.sysmon", "field": "win.ImageLoaded", "query": "event.code:7 AND (win.ImageLoaded:*lsass* OR win.ImageLoaded:*cryptdll* OR win.ImageLoaded:*wdigest* OR win.ImageLoaded:*msv1_0*)", "time_from": null, "time_to": null, "size": 50, "sub_field":… | 39 |  |
| q-15c7861327 | check C195 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4657 AND (win.ObjectName:*Security* OR win.ObjectName:*Lsa* OR win.ObjectName:*Authentication*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-74eb2d734c | check C196 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND (process.command_line:*lsass* OR process.command_line:*procdump* OR process.command_line:*comsvcs* OR process.command_line:*MiniDump*)", "time_from": null, "time_to": … | 0 |  |
| q-f4b0bdaf44 | check C197 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*MiniDump* OR win.ScriptBlockText:*comsvcs* OR win.ScriptBlockText:*mimikatz*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "h… | 0 |  |
| q-8669ce0f6c | check C198 | search | {"dataset": "windows.other", "query": "message:*lsass* OR message:*cryptdll*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 0 |  |
| q-d150b67288 | check C199 | aggregate | {"dataset": "windows.sysmon", "field": "win.SourceImage", "query": "event.code:10 AND win.TargetImage:*lsass.exe", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 326 |  |
| q-bd24ddee37 | check C200 | aggregate | {"dataset": "windows.sysmon", "field": "win.ImageLoaded", "query": "event.code:7 AND (win.ImageLoaded:*lsass* OR win.ImageLoaded:*cryptdll*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 33 |  |
| q-b1b6df815d | check C201 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4624 AND win.LogonType:3", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 218 |  |
| q-1ab42eb1ef | check C202 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4648", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 15 |  |
| q-0b6de8b28f | check C203 | search | {"dataset": "windows.other", "query": "message:*lsass* OR message:*cryptdll*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 0 |  |
| q-bf3df96546 | check C204 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*cryptdll* OR win.ScriptBlockText:*Skeleton*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "even… | 0 |  |
| q-76e21afdd1 | check C205 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND win.TargetFilename:*\\\\System32\\\\*.dll", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-272e4bfe8d | check C206 | aggregate | {"dataset": "windows.sysmon", "field": "win.ImageLoaded", "query": "event.code:7 AND win.ImageLoaded:*System32*", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 19432 |  |
| q-371c188755 | check C207 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4657 AND win.ObjectName:*Notification Packages*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-58dc5c988f | check C208 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4657 AND (win.ObjectName:*Lsa* OR win.ObjectName:*Control\\\\Lsa*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-7322b6c07d | check C209 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Notification*Packages* OR win.ScriptBlockText:*PasswordFilter*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", … | 0 |  |
| q-37c6760af7 | check C210 | search | {"dataset": "windows.other", "query": "message:*Notification*Packages* OR message:*PasswordFilter*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "p… | 0 |  |
| q-b6ff61176b | check C211 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4739", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-c9a1292d08 | check C212 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4657 AND (win.ObjectName:*Reversible* OR win.ObjectName:*UserAccountControl*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-59711c2524 | check C213 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*Reversible* OR process.command_line:*UserAccountControl* OR process.command_line:*Set-ADAccountControl*)", "time_from": null, "time_to": null, "size"… | 0 |  |
| q-4ed5ae9d38 | check C214 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Reversible* OR win.ScriptBlockText:*Set-ADAccountControl* OR win.ScriptBlockText:*UserAccountControl*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.na… | 0 |  |
| q-163b903f74 | check C215 | search | {"dataset": "windows.other", "query": "message:*Reversible* OR message:*UserAccountControl*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.… | 0 |  |
| q-92c4d2fabd | check C216 | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*set-aduser*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*set-adauthenticationpolicy*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*strongauthentication*\" OR TO_L… | ERROR |  |
| q-e89d2b2b2e | check C216 (repaired) | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*set-aduser*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*set-adauthenticationpolicy*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*strongauthentication*\" OR TO_L… | ERROR |  |
| q-7d09e9fc05 | check C217 | aggregate | {"dataset": "windows.security", "field": "event.code", "query": "event.code:4739", "time_from": null, "time_to": null, "size": 10, "sub_field": null} | 0 |  |
| q-85274427f6 | check C218 | search | {"dataset": "windows.other", "query": "event.code:4739 OR event.code:5136 OR message:*AuthenticationPolicy*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.execut… | 0 |  |
| q-498bda35bb | check C219 | aggregate | {"dataset": "windows.sysmon", "field": "win.ImageLoaded", "query": "event.code:7", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 20259 |  |
| q-61197afc8d | check C220 | search | {"dataset": "windows.security", "query": "event.code:5136", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 0 |  |
| q-dbc3fcfda4 | check C221 | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*azuread*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*aadconnect*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*adfs*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*c… | ERROR |  |
| q-1266bdc835 | check C221 (repaired) | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*azuread*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*aadconnect*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*adfs*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*c… | ERROR |  |
| q-af796fdd8b | check C222 | aggregate | {"dataset": "windows.sysmon", "field": "registry.path", "query": "event.code:13 AND registry.path:*NetworkProvider*", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-7ff540e7b1 | check C223 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 326 |  |
| q-b4c26c0ee0 | check C224 | aggregate | {"dataset": "windows.sysmon", "field": "win.ImageLoaded", "query": "event.code:7 AND win.ImageLoaded:*NetworkProvider*", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-c380f374c5 | check C225 | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11 AND (file.path:*System32* OR file.path:*network*)", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 425 |  |
| q-4e0c4c9224 | check C226 | search | {"dataset": "windows.security", "query": "event.code:4657 AND win.ObjectName:*NetworkProvider*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "proce… | 0 |  |
| q-392f46adce | check C227 | aggregate | {"dataset": "windows.sysmon", "field": "destination.ip", "query": "event.code:3", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 1229 |  |
| q-c2a601003e | check C228 | aggregate | {"dataset": "windows.sysmon", "field": "dns.question.name", "query": "event.code:22", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 81 |  |
| q-9e69ea552b | check C229 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 OR event.code:4670 OR event.code:4656", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 10977 |  |
| q-bc8ee5de9d | check C230 | aggregate | {"dataset": "zeek", "field": "destination.ip", "query": "event.action:conn", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 613 |  |
| q-63a48db746 | check C231 | aggregate | {"dataset": "windows.sysmon", "field": "destination.port", "query": "event.code:3 AND (destination.port:5355 OR destination.port:137 OR destination.port:445)", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 74 |  |
| q-4886a1a00e | check C232 | aggregate | {"dataset": "windows.sysmon", "field": "registry.path", "query": "event.code:13 AND registry.path:*DNSClient*", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-82ea143089 | check C233 | aggregate | {"dataset": "windows.security", "field": "win.ServiceName", "query": "event.code:4697", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 23 |  |
| q-9b7d011045 | check C234 | aggregate | {"dataset": "zeek", "field": "destination.port", "query": "event.action:conn AND (destination.port:5355 OR destination.port:137 OR destination.port:445)", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 47 |  |
| q-d5f8a748e9 | check C235 | aggregate | {"dataset": "zeek", "field": "dns.question.name", "query": "event.action:dns", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 53 |  |
| q-cb3bbff236 | check C236 | aggregate | {"dataset": "windows.sysmon", "field": "destination.ip", "query": "event.code:3", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 1229 |  |
| q-246290172b | check C237 | aggregate | {"dataset": "windows.sysmon", "field": "source.ip", "query": "event.code:3", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 1229 |  |
| q-ec4bad5017 | check C238 | aggregate | {"dataset": "zeek", "field": "zeek.orig_l2_addr", "query": "event.action:conn", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 613 |  |
| q-009aa0de04 | check C239 | aggregate | {"dataset": "zeek", "field": "zeek.resp_l2_addr", "query": "event.action:conn", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 613 |  |
| q-8dab853e70 | check C240 | search | {"dataset": "windows.other", "query": "event.code:(1341 OR 1342 OR 1020 OR 1063)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_lin… | 0 |  |
| q-e389782c1f | check C241 | aggregate | {"dataset": "windows.security", "field": "win.LogonProcessName", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 297 |  |
| q-f196693ad5 | check C242 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 447 |  |
| q-cb1efb4b14 | check C243 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND win.ScriptBlockText:(*dhcp* OR *DhcpServer* OR *netsh*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "pr… | 0 |  |
| q-0f3cae9051 | check C244 | aggregate | {"dataset": "windows.security", "field": "win.PrivilegeList", "query": "event.code:4672", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 212 |  |
| q-7ebfc14d9a | check C245 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4634", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 236 |  |
| q-1797469df1 | check C246 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-9f4c3a0c02 | check C247 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 326 |  |
| q-cf0962d9f9 | check C248 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND win.ScriptBlockText:(*kerberos* OR *ticket* OR *mimikatz* OR *Invoke-Kerberoast*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "eve… | 0 |  |
| q-9793fd2d40 | check C249 | search | {"dataset": "windows.other", "query": "event.code:(7045 OR 7040) AND (win.ServiceName:*kerb* OR win.ImagePath:*kerb*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "proc… | 0 |  |
| q-3ca7718467 | check C250 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4672", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 212 |  |
| q-c5eebb24cd | check C251 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4634", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 236 |  |
| q-3591447bd4 | check C252 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 326 |  |
| q-be36386a86 | check C253 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND win.ScriptBlockText:(*golden* OR *krbtgt* OR *mimikatz* OR *ticket*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "us… | 0 |  |
| q-ea8a80bbd0 | check C254 | search | {"dataset": "windows.other", "query": "event.code:(7045 OR 7040) AND (win.ServiceName:*kdc* OR win.ImagePath:*kdc*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "proces… | 0 |  |
| q-d7450fad00 | check C255 | aggregate | {"dataset": "windows.security", "field": "win.ServiceName", "query": "event.code:4672", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 212 |  |
| q-0588e62158 | check C256 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4634", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 236 |  |
| q-d775e8c598 | check C257 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-ac5a853804 | check C258 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND win.ScriptBlockText:(*silver* OR *service ticket* OR *TGS* OR *mimikatz*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code"… | 0 |  |
| q-693aea5ad3 | check C259 | search | {"dataset": "windows.other", "query": "event.code:(7045 OR 7040) AND (win.ServiceName:*spool* OR win.ServiceName:*mssql* OR win.ServiceName:*http*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "e… | 0 |  |
| q-4922387e1a | check C260 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 297 |  |
| q-25536956b5 | check C261 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4672", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 212 |  |
| q-913522f766 | check C262 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 326 |  |
| q-239c56fb66 | check C263 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND win.ScriptBlockText:(*Kerberoast* OR *SPN* OR *GetUserSPNs* OR *Rubeus*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code",… | 0 |  |
| q-18614d30b4 | check C264 | search | {"dataset": "windows.other", "query": "event.code:(7045 OR 7040) AND (win.ServiceName:*spn* OR win.ImagePath:*spn*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "proces… | 0 |  |
| q-aa746b7840 | check C265 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 297 |  |
| q-f4158a335c | check C266 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4672", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 212 |  |
| q-17339a75be | check C267 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 447 |  |
| q-2fff4c26cf | check C268 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND win.ScriptBlockText:(*AS-REP* OR *GetNPUsers* OR *Rubeus* OR *asreproast*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code… | 0 |  |
| q-fe06b3b337 | check C269 | search | {"dataset": "windows.other", "query": "event.code:(7045 OR 7040) AND (win.ServiceName:*kdc* OR win.ImagePath:*kdc*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "proces… | 0 |  |
| q-7252531eb3 | check C270 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-33832c2df2 | check C271 | aggregate | {"dataset": "windows.security", "field": "win.LogonProcessName", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 297 |  |
| q-109605020e | check C272 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*token* OR win.ScriptBlockText:*cookie* OR win.ScriptBlockText:*SAML* OR win.ScriptBlockText:*forge*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name… | 1 |  |
| q-25196b4ccd | check C273 | search | {"dataset": "windows.other", "query": "event.code:7045 OR event.code:7040", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "so… | 9 |  |
| q-7e18f4a815 | check C274 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND (win.TargetFilename:*cookie* OR win.TargetFilename:*Cookies*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1 |  |
| q-e4eaaa0d26 | check C275 | aggregate | {"dataset": "windows.security", "field": "win.LogonProcessName", "query": "event.code:4624 OR event.code:4648", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 312 |  |
| q-dffe7f3f9d | check C276 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*cookie* OR win.ScriptBlockText:*Cookie*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.nam… | 0 |  |
| q-6c162bc476 | check C277 | search | {"dataset": "windows.other", "query": "event.code:11 AND (file.path:*cookie* OR file.path:*Cookies*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", … | 0 |  |
| q-3476763acc | check C278 | aggregate | {"dataset": "windows.security", "field": "win.LogonProcessName", "query": "event.code:4624 OR event.code:4648", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 312 |  |
| q-f1918b1401 | check C279 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*SAML* OR win.ScriptBlockText:*saml* OR win.ScriptBlockText:*NotOnOrAfter*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event… | 0 |  |
| q-81957f42c6 | check C280 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND (win.TargetFilename:*saml* OR win.TargetFilename:*SAML* OR win.TargetFilename:*.pfx*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1 |  |
| q-5534d94171 | check C281 | search | {"dataset": "windows.other", "query": "event.code:7045 OR event.code:7040", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "so… | 9 |  |
| q-5603bccadc | check C282 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-0b40cd4e79 | check C283 | aggregate | {"dataset": "windows.security", "field": "source.ip", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-541aaaf5e7 | check C284 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*MFA* OR win.ScriptBlockText:*2FA* OR win.ScriptBlockText:*Authenticator*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.… | 0 |  |
| q-b5edf3354d | check C285 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*MFA* OR process.command_line:*2FA*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-ab819d6075 | check C286 | search | {"dataset": "windows.other", "query": "event.code:4625", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 0 |  |
| q-14e8a2e6df | check C287 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4657", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 36 |  |
| q-6d3fada925 | check C288 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4768", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 14 |  |
| q-4ecfea3a3b | check C289 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND (win.TargetFilename:*.pfx* OR win.TargetFilename:*.p12* OR win.TargetFilename:*.cer* OR win.TargetFilename:*.crt*)", "time_from": null, "time_to": null, "size": 50, "sub_f… | 1 |  |
| q-aa9d1bb05d | check C290 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Export-PfxCertificate* OR win.ScriptBlockText:*certutil* OR win.ScriptBlockText:*Certificates*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "o… | 1 |  |
| q-666be10653 | check C291 | search | {"dataset": "windows.other", "query": "event.code:4657", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 0 |  |
| q-e55291ff75 | check C292 | aggregate | {"dataset": "zeek", "field": "http.request.method", "query": "event.action:http", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 62 |  |
| q-eab09a61e5 | check C293 | search | {"dataset": "zeek", "query": "event.action:http AND (url.original:*login* OR url.original:*auth* OR url.original:*signin*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", … | 0 |  |
| q-57e256c4cf | check C294 | aggregate | {"dataset": "zeek", "field": "user_agent.original", "query": "event.action:http", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 62 |  |
| q-ac0bf2559f | check C295 | search | {"dataset": "zeek", "query": "event.action:http AND (url.original:*NTLM* OR url.original:*PROPFIND* OR url.original:*WebDAV*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name… | 0 |  |
| q-fa8d512a3c | check C296 | aggregate | {"dataset": "zeek", "field": "destination.port", "query": "event.action:conn AND (destination.port:139 OR destination.port:445)", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 50 |  |
| q-23efc0fb93 | check C297 | search | {"dataset": "zeek", "query": "event.action:smb_files", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinatio… | 12 |  |
| q-f82ff2fa5c | check C298 | search | {"dataset": "zeek", "query": "event.action:kerberos", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destination… | 35 | F40 |
| q-b8e8277a39 | check C299 | search | {"dataset": "zeek", "query": "event.action:kerberos", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destination… | 35 |  |
| q-08e3e6e769 | check C300 | search | {"dataset": "zeek", "query": "event.action:dce_rpc", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destination.… | 123 |  |
| q-db9873c0db | check C301 | aggregate | {"dataset": "zeek", "field": "zeek.request_type", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 35 |  |
| q-ad3d806c02 | check C302 | aggregate | {"dataset": "zeek", "field": "zeek.error_msg", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 35 |  |
| q-6c9e8db888 | check C303 | search | {"dataset": "zeek", "query": "event.action:kerberos AND zeek.request_type:AS", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 14 |  |
| q-08739ecdc2 | triage T1003 step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 10 AND win.TargetImage LIKE \"*lsass.exe\" AND win.SourceImage NOT LIKE \"*svchost.exe\" \| KEEP @timestamp, host.name, win.SourceImage, win.GrantedAccess, win.CallTrace, w… | ERROR |  |
| q-fc03442696 | triage T1003 step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 10 AND win.GrantedAccess IN (\"0x1fffff\",\"0x1010\",\"0x1410\",\"0x1f3fff\",\"0x101001\",\"0x1000000\") \| KEEP @timestamp, host.name, win.SourceImage, win.TargetImage, wi… | ERROR |  |
| q-cc9a9f63cc | triage T1003 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND win.TargetImage LIKE \"*lsass.exe\" AND win.SourceImage NOT LIKE \"*svchost.exe\" \| KEEP @timestamp, host.name, win.SourceImage, win.GrantedAccess, win.CallTrac… | 37 | F03 |
| q-4e454ad9f7 | triage T1003 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND win.GrantedAccess IN (\"0x1fffff\",\"0x1010\",\"0x1410\",\"0x1f3fff\",\"0x101001\",\"0x1000000\") \| KEEP @timestamp, host.name, win.SourceImage, win.TargetImage… | 500 | F01 |
| q-9570601447 | triage T1003 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtaokyU"} | None | F01 |
| q-3f68bd099c | triage T1003 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtIR1Pn"} | None | F02 |
| q-e740b77bbc | triage T1003 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (process.pid == 2976 OR process.parent.pid == 2976 OR process.executable LIKE \"*wsmprovhost*\" OR process.executable LIKE \"*powershell*\") \| KEEP @timestamp, h… | 15 | F02 |
| q-699efd697d | triage T1003 step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (win.ScriptBlockText LIKE \"*lsass*\" OR win.ScriptBlockText LIKE \"*MiniDump*\" OR win.ScriptBlockText LIKE \"*procdump*\" OR win.ScriptBlockText LIKE \"*… | 0 |  |
| q-711ecd7dc9 | triage T1003 step 5 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOx6IsLb"} | None | F01 |
| q-60f639ef27 | triage T1003 step 5 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND host.name == \"scranton.dmevals.local\" \| KEEP @timestamp, win.ScriptBlockText, _id, _index \| SORT @timestamp ASC"} | 146 |  |
| q-daa44985c8 | triage T1003 step 6 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND @timestamp > \"2020-05-02T03:01:51.000Z\" \| KEEP @timestamp, host.name, win.ScriptBlockText, _id, _index \| SORT @timestamp ASC"} | 252 |  |
| q-bcfc1bee58 | triage T1003 step 7 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND host.name == \"nashua.dmevals.local\" \| KEEP @timestamp, win.ScriptBlockText, _id, _index \| SORT @timestamp ASC"} | 11 | F02 |
| q-05de05de6b | triage T1003 step 7 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND host.name == \"scranton.dmevals.local\" AND @timestamp > \"2020-05-02T03:06:47.000Z\" \| KEEP @timestamp, win.ScriptBlockText, _id, _index \| SORT @timesta… | 63 |  |
| q-79cf3a74a2 | triage T1003 step 8 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4663\" AND win.ObjectName LIKE \"*lsass*\" \| KEEP @timestamp, host.name, win.ObjectName, win.ProcessName, win.SubjectUserName, win.AccessMask, win.AccessList, _id, _in… | 6 | F01, F07 |
| q-eaa4ff7129 | triage T1003 step 8 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4662\" OR (event.code == \"4663\" AND (win.ObjectName LIKE \"*SAM*\" OR win.ObjectName LIKE \"*SECURITY*\" OR win.ObjectName LIKE \"*NTDS*\" OR win.ObjectName LIKE \"*C… | 7 | F04, F06, F08 |
| q-9ec2cf2c9e | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtaokyU"} | None |  |
| q-cd14c83a23 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtaokyU"} | None |  |
| q-03b64229cd | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtaokyU"} | None |  |
| q-b41ca022d1 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOx6IsLb"} | None |  |
| q-9454b8baee | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO39W64C"} | None |  |
| q-d87bd10599 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtaokyR"} | None |  |
| q-603766e736 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtIR1Pn"} | None |  |
| q-84a469c5b8 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtIR1Pn"} | None |  |
| q-13a4eb1d47 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtISFPF"} | None |  |
| q-2ef0ff231d | triage T1003 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3Iwxm0"} | None |  |
| q-08c966430c | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOx-M_2G"} | None |  |
| q-b0bec32044 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOs4A9hl"} | None |  |
| q-631af90547 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtYnKtJ"} | None |  |
| q-84a8b7321c | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOs4A9hk"} | None |  |
| q-baa1c379d9 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO39Xq5t"} | None |  |
| q-3a02716532 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOs4A9hk"} | None |  |
| q-c7c8fb7b28 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO3-XnWS"} | None |  |
| q-b690311775 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO3-XnWS"} | None |  |
| q-863f095e22 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO0NmmRU"} | ERROR |  |
| q-592d502e83 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO3zLZNi"} | None |  |
| q-2fc18ababa | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO3zLZNi"} | None |  |
| q-c133861175 | triage T1040 step 1 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*pktmon* OR process.command_line:*netsh* OR process.command_line:*windump* OR process.command_line:*tcpdump* OR process.command_line:*rawcap*)", "time_from": null, "time_to": n… | 2 | F09 |
| q-1db14d8dc7 | triage T1040 step 1 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*netsh* OR process.command_line:*pktmon* OR process.command_line:*pcap* OR process.command_line:*capture*)", "time_from": null, "time_to": null, "size… | 2 |  |
| q-58d84a1bd5 | triage T1040 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*netsh* OR process.command_line:*pktmon* OR process.command_line:*pcap* OR process.command_line:*capture*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name"… | 2 | F09 |
| q-bac2c61dd0 | triage T1040 step 2 | aggregate | {"dataset": "windows.sysmon", "field": "win.ImageLoaded", "query": "event.code:7 AND (win.ImageLoaded:*pcap* OR win.ImageLoaded:*npf* OR win.ImageLoaded:*wpcap* OR win.ImageLoaded:*Packet*)", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 0 |  |
| q-1037b1ff5a | triage T1040 step 3 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:3 AND (win.Initiated:true OR win.Initiated:false) AND (process.executable:*dump* OR process.executable:*sniff* OR process.executable:*cap* OR process.executable:*wireshark* OR pr… | 0 |  |
| q-0a10a11291 | triage T1040 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*promiscuous*\" OR TO_LOWER(process.command_line) LIKE \"*raw socket*\" OR TO_LOWER(process.command_line) LIKE \"*wireshark… | 0 |  |
| q-e4deb8c865 | triage T1040 step 4 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOonrxo5"} | None | F09 |
| q-bac1c5ebb9 | triage T1040 step 4 | aggregate | {"dataset": "zeek", "field": "zeek.service", "query": "event.action:conn AND (zeek.service:*pcap* OR zeek.service:*sniff* OR zeek.service:*capture*)", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 0 |  |
| q-5737e4a48f | triage T1040 step 5 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "event.code", "process.executable", "win.ServiceName", "win.ImagePath", "message"], "size": 10, "sort": "asc"} | 5 | F09 |
| q-c6958787d2 | triage T1040 step 5 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4688\" AND (TO_LOWER(process.command_line) LIKE \"*promiscuous*\" OR TO_LOWER(process.command_line) LIKE \"*pktmon*\" OR TO_LOWER(process.command_line) LIKE \"*npcap*\"… | 0 |  |
| q-fdaf97e041 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOonrxo5"} | None |  |
| q-2b4c73d869 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOonrxo5"} | None |  |
| q-fa68acb0ca | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOonrxo5"} | None |  |
| q-604c034cbb | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOosxQHp"} | None |  |
| q-d9f9bade95 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO0HjD-1"} | None |  |
| q-d3012f7581 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO1pngK-"} | None |  |
| q-d24986d215 | triage T1056 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3Pzp3U"} | None | F10 |
| q-6415ad8776 | triage T1056 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3Oy3md"} | None | F10 |
| q-aaebf6a19a | triage T1056 step 1 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtjz-FD"} | None |  |
| q-613402ab83 | triage T1056 step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 10 AND win.TargetImage LIKE \"*lsass*\" AND win.GrantedAccess IN (\"0x1fffff\",\"0x101001\",\"0x1f3fff\",\"0x1000000\",\"0x3000\",\"0x1400\") \| KEEP @timestamp, host.name,… | ERROR |  |
| q-d3992c7fde | triage T1056 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND win.TargetImage LIKE \"*lsass*\" AND win.GrantedAccess IN (\"0x1fffff\",\"0x101001\",\"0x1f3fff\",\"0x1000000\",\"0x3000\",\"0x1400\") \| KEEP @timestamp, host.n… | 33 | F13 |
| q-3e46f36c8e | triage T1056 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (process.command_line LIKE \"*lsass*\" OR process.command_line LIKE \"*MiniDump*\" OR process.command_line LIKE \"*comsvcs*\" OR process.command_line LIKE \"*Scre… | 1 |  |
| q-115ba048c6 | triage T1056 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND win.TargetImage LIKE \"*lsass*\" AND win.GrantedAccess IN (\"0x1fffff\",\"0x101001\",\"0x1f3fff\",\"0x1000000\") \| KEEP @timestamp, host.name, process.executabl… | 8 | F11, F13 |
| q-d57e98d85e | triage T1056 step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (win.ScriptBlockText LIKE \"*lsass*\" OR win.ScriptBlockText LIKE \"*Invoke-ScreenCapture*\" OR win.ScriptBlockText LIKE \"*CopyFromScreen*\" OR win.Script… | 3 |  |
| q-53c91be657 | triage T1056 step 4 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtaokyU"} | None | F11 |
| q-0202b73f79 | triage T1056 step 4 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtIR1Pn"} | None | F12 |
| q-32147b6521 | triage T1056 step 4 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3Pz52N"} | None | F10 |
| q-04c2df0f3e | triage T1056 step 5 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4656\",\"4663\",\"4670\") AND (win.ObjectName LIKE \"*lsass*\" OR win.ObjectName == \"SAM\" OR win.ObjectName LIKE \"*ControlSet001\\\\\\\\Control\\\\\\\\Lsa*\") \| KE… | 30 |  |
| q-88c2e4e131 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3Pzp3U"} | None |  |
| q-d2d9f10ff3 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3Pzp3U"} | None |  |
| q-a5645412a4 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3Pzp3U"} | None |  |
| q-c00f7738d0 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3Oy3md"} | None |  |
| q-c6c82061b6 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3Pz52N"} | None |  |
| q-61e68795fa | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtaokyU"} | None |  |
| q-1a146b71aa | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtaokyU"} | None |  |
| q-37f37a880a | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtaokyU"} | None |  |
| q-d192613593 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtaokyR"} | None |  |
| q-b3b54a9c24 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtaokyU"} | None |  |
| q-ad73f4427a | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtIR1Pn"} | None |  |
| q-4ccf3ae9a0 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtIR1Pn"} | None |  |
| q-e90d15e85b | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtIR1Pn"} | None |  |
| q-39a18b70d9 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOs4A9hl"} | None |  |
| q-963b79141f | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOs7DwuP"} | None |  |
| q-01e31d497b | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOoWdgoz"} | None |  |
| q-3f102b8184 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO1pngK-"} | None |  |
| q-07df1caa5a | triage T1056 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO1pngIR"} | None |  |
| q-64505d33b7 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3V6Jtq"} | None |  |
| q-c6b6fe298a | triage T1110 step 1 | search | {"dataset": "windows.security", "query": "event.code:4776", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 1 | F16 |
| q-400335d6fb | triage T1110 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3P0p0s"} | None | F20 |
| q-f57dbb5723 | triage T1110 step 1 | aggregate | {"dataset": "windows.sysmon", "field": "win.SourceImage", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-909fc0cc1e | triage T1110 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND win.SourceImage:*powershell*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process… | 2 | F18 |
| q-d5f93f4e36 | triage T1110 step 2 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3AvzkC"} | None | F20 |
| q-ace3f72bfe | triage T1110 step 2 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 297 |  |
| q-a713d0211a | triage T1110 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtjz-FD"} | None |  |
| q-63df626992 | triage T1110 step 3 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4624 AND win.TargetUserName:pbeesly", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 30 |  |
| q-bf749b8e44 | triage T1110 step 3 | count | {"dataset": "windows.security", "query": "event.code:(4625 OR 4771 OR 4776 OR 4648) AND NOT win.TargetUserName:pbeesly", "time_from": null, "time_to": null} | 6 |  |
| q-abdc1b3498 | triage T1110 step 4 | search | {"dataset": "windows.security", "query": "event.code:(4625 OR 4771 OR 4776 OR 4648) AND NOT win.TargetUserName:pbeesly", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "win.TargetUserName", "win.LogonType", "source.ip",… | 6 | F19 |
| q-66e1c8e9ad | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO3mCkhu"} | None |  |
| q-c110cfd6d6 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO3mCkhu"} | None |  |
| q-7ff7bcb6ff | triage T1110 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO1pngJm"} | None |  |
| q-68fe03a34c | triage T1110 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3Q199Y"} | None |  |
| q-a8121daf65 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtjz-FD"} | None |  |
| q-b78ce238e8 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtjz-FD"} | None |  |
| q-de70b8ec5d | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO0KlA9b"} | None |  |
| q-ae25983f3d | triage T1110 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOoXemmg"} | None |  |
| q-1a632b4b34 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3P0p0s"} | None |  |
| q-ef48f1048b | triage T1110 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3AvzkC"} | None |  |
| q-f296c2ca15 | triage T1111 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3AvzkC"} | None | F21 |
| q-5d97c12dbb | triage T1111 step 1 | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO1pnQLs"} | None | F21 |
| q-9ee6363fc5 | triage T1111 step 1 | search | {"dataset": "windows.security", "query": "event.code:4648", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "win.TargetUserName", "win.TargetServerName", "win.ProcessName", "win.IpAddress", "win.LogonType"], "size": 20, "… | 15 | F21 |
| q-02d2a461b4 | triage T1111 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*SmartCard* OR process.command_line:*scardsvr* OR process.command_line:*Credential* OR process.command_line:*MFA* OR process.command_line:*NgcCtnr* OR process.command_line:*VaultCmd… | 0 |  |
| q-bf28149af7 | triage T1111 step 2 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*SmartCard* OR process.command_line:*Credential* OR process.command_line:*MFA* OR process.command_line:*scardsvr* OR process.command_line:*VaultCmd*)", "time_from": null, "time… | 0 |  |
| q-64416cddaf | triage T1111 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:13 AND (registry.path:*DeviceGuard* OR registry.path:*Lsa* OR registry.path:*WDigest* OR registry.path:*SecurityProviders*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "process.… | 4 | F21 |
| q-69e8850f07 | triage T1111 step 3 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.executable:*psexec* OR process.command_line:*psexec* OR process.executable:*PSEXESVC*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "process.executabl… | 4 |  |
| q-b086f83fc1 | triage T1111 step 3 | search | {"dataset": "windows.other", "query": "event.code:7045 OR event.code:7040 OR event.code:7036", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "win.ServiceName", "win.ImagePath", "win.ServiceStartType", "message"], "size": 30, "sort":… | 17 | F21 |
| q-f174d21543 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOs4A9hu"} | None |  |
| q-afb5cbda8e | triage T1111 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOs4A9hp"} | None |  |
| q-8c4648976f | triage T1111 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOoWeAuy"} | None |  |
| q-957d46967c | triage T1111 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOoRaEln"} | None |  |
| q-ffa5c29846 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO1pnQLs"} | None |  |
| q-50f3a0711e | triage T1111 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO31NCqL"} | None |  |
| q-cf496d89b2 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO31NSq9"} | None |  |
| q-9cc6feac25 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO1pngK-"} | None |  |
| q-a1885787b3 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3AvzkC"} | None |  |
| q-52d59e6798 | triage T1187 step 1 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtcqWLx"} | None | F22 |
| q-4a49dd952f | triage T1187 step 1 | aggregate | {"dataset": "windows.sysmon", "field": "destination.ip", "query": "event.code:3 AND (destination.port:445 OR destination.port:139)", "time_from": null, "time_to": null, "size": 20, "sub_field": "host.name"} | 66 |  |
| q-72404e9e66 | triage T1187 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE process.entity_id == \"{47ab858c-e23d-5eac-c603-000000000400}\" \| KEEP @timestamp, host.name, event.code, process.executable, process.command_line, process.parent.executable, process.pa… | 500 |  |
| q-d7797dea96 | triage T1187 step 2 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == 4104 AND (TO_LOWER(win.ScriptBlockText) LIKE \"*hostui*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*startup*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*lnk*\") \| KEEP @… | ERROR |  |
| q-21aac0c570 | triage T1187 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtl2JQj"} | None | F22 |
| q-07ed0fa421 | triage T1187 step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*hostui*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*startup*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*lnk*\" OR TO_… | 4 |  |
| q-f5a8b6a39d | triage T1187 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"3\" AND (destination.port == 445 OR destination.port == 139) \| KEEP @timestamp, host.name, user.name, process.executable, destination.ip, destination.port, win.SourceHos… | 66 | F22 |
| q-deba999383 | triage T1187 step 4 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"5140\" OR event.code == \"5145\" \| KEEP @timestamp, host.name, user.name, win.ShareName, win.SubjectUserName, win.IpAddress, win.RelativeTargetName, win.ObjectName, _i… | 60 | F22 |
| q-07a9422c64 | triage T1187 step 5 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3AvzkC"} | None | F22 |
| q-7726a514c5 | triage T1187 step 5 | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO1pnQLy"} | None | F22 |
| q-c65c5df6ed | triage T1187 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtcqWLx"} | None |  |
| q-8199c8530e | triage T1187 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtl2JQj"} | None |  |
| q-a6c4bb8f7b | triage T1187 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtHRU4M"} | None |  |
| q-ea60de2754 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO31NyoH"} | None |  |
| q-0999b98355 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO3_ZDTc"} | None |  |
| q-c89d69ff89 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO1pnQLy"} | None |  |
| q-98943d2af5 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3AvzkC"} | None |  |
| q-bfea890357 | triage T1212 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND (win.GrantedAccess:0x1fffff OR win.GrantedAccess:0x101001 OR win.GrantedAccess:0x1f3fff OR win.GrantedAccess:0x1000000 OR win.GrantedAccess:0x3000)", "time_from": null, "time… | 9 | F23, F24 |
| q-5f42b67656 | triage T1212 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND win.SourceImage:*PowerShell*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "win.SourceImage", "win.TargetImage", "win.GrantedAccess", "user.name… | 4 |  |
| q-c8b2fb27cf | triage T1212 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtaokyU"} | None | F23 |
| q-648ebfa44e | triage T1212 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtaokyR"} | None | F23 |
| q-d454fddfed | triage T1212 step 2 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*MiniDump* OR win.ScriptBlockText:*Dump* OR win.ScriptBlockText:*Credential* OR win.ScriptBlockText:*sekurlsa* OR win.ScriptBlockText:*OpenProce… | 3 |  |
| q-873732594d | triage T1212 step 3 | search | {"dataset": "windows.sysmon", "query": "process.pid:2976 OR win.ProcessId:2976 OR win.ParentProcessId:2976", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "process.pid", "process.executable", "process.command_line", "p… | 546 | F23 |
| q-95bb75b549 | triage T1212 step 3 | search | {"dataset": "windows.powershell", "query": "host.name:scranton.dmevals.local AND event.code:4104 AND @timestamp:[2020-05-02T03:04:00.000Z TO 2020-05-02T03:07:00.000Z]", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "us… | 35 | F23 |
| q-6a7795c748 | triage T1212 step 4 | search | {"dataset": "windows.powershell", "query": "host.name:scranton.dmevals.local AND event.code:4104 AND @timestamp:[2020-05-02T03:05:00.000Z TO 2020-05-02T03:07:00.000Z]", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "us… | 21 | F23 |
| q-a8af8d7ad3 | triage T1212 step 4 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*lsass* OR process.command_line:*dump* OR process.command_line:*procdump* OR process.command_line:*comsvcs* OR process.command_line:*MiniDump*)", "time_from": null, "time_to": null,… | 1 |  |
| q-141d5002cc | triage T1212 step 5 | search | {"dataset": "windows.security", "query": "(event.code:4663 OR event.code:4656) AND (win.ObjectName:*lsass* OR win.ObjectName:*SAM* OR win.ObjectName:*SECURITY* OR win.ProcessName:*lsass*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.nam… | 154 | F23, F24 |
| q-136ed6d288 | triage T1212 step 5 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtIR1Pn"} | None | F23 |
| q-bfec639b40 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtaokyU"} | None |  |
| q-59cc850252 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtaokyR"} | None |  |
| q-aecd3a08d9 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtaokyU"} | None |  |
| q-d768098ca6 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtaokyR"} | None |  |
| q-87dbab9f3e | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOx6IsLb"} | None |  |
| q-766a46668e | triage T1212 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO39W66U"} | None |  |
| q-4e77b9ad2a | triage T1212 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO39W65K"} | None |  |
| q-37acc6f99c | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtIR1Pn"} | None |  |
| q-1632d77a8d | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtIR1Pn"} | None |  |
| q-dcfad06330 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO32Nwbs"} | None |  |
| q-54db336f83 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO31NCqM"} | None |  |
| q-be96bf3df5 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3P0p0s"} | None |  |
| q-db3ff1548a | triage T1212 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3P0J3m"} | None |  |
| q-6f77b778fd | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOs7DwuP"} | None |  |
| q-14c62d1154 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOoWdgoz"} | None |  |
| q-00d4e5b90d | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOs4A9hl"} | None |  |
| q-4f75a07176 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO39XK6I"} | None |  |
| q-74c691f039 | triage T1539 step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 11 AND (win.TargetFilename LIKE \"*Cookies*\" OR win.TargetFilename LIKE \"*Login Data*\" OR win.TargetFilename LIKE \"*Web Data*\") \| STATS c = COUNT(*) BY process.execut… | ERROR |  |
| q-39b1855f33 | triage T1539 step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 11 AND (win.TargetFilename LIKE \"*Cookies*\" OR win.TargetFilename LIKE \"*Login Data*\" OR win.TargetFilename LIKE \"*Web Data*\") \| KEEP @timestamp, host.name, process.… | ERROR |  |
| q-c5c3ab4620 | triage T1539 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (win.TargetFilename LIKE \"*Cookies*\" OR win.TargetFilename LIKE \"*Login Data*\" OR win.TargetFilename LIKE \"*Web Data*\") \| STATS c = COUNT(*) BY process.ex… | 1 |  |
| q-176afef4b5 | triage T1539 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (win.TargetFilename LIKE \"*Cookies*\" OR win.TargetFilename LIKE \"*Login Data*\" OR win.TargetFilename LIKE \"*Web Data*\") \| KEEP @timestamp, host.name, proc… | 1 | F25 |
| q-ead8056c35 | triage T1539 step 3 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3P0Z25"} | None |  |
| q-6576f87b64 | triage T1539 step 3 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3AvzkC"} | None | F25 |
| q-4ab629207e | triage T1539 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE TO_LOWER(win.TargetFilename) LIKE \"*cookie*\" OR TO_LOWER(win.TargetFilename) LIKE \"*login data*\" OR TO_LOWER(win.TargetFilename) LIKE \"*web data*\" OR TO_LOWER(win.TargetFilename) L… | ERROR |  |
| q-1ec4e1a6c4 | triage T1539 step 4 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE TO_LOWER(win.ObjectName) LIKE \"*cookie*\" OR TO_LOWER(win.ObjectName) LIKE \"*login data*\" OR TO_LOWER(win.ObjectName) LIKE \"*web data*\" \| STATS c = COUNT(*) BY event.code, proces… | 0 |  |
| q-d79b786172 | triage T1539 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE TO_LOWER(win.TargetFilename) LIKE \"*cookie*\" OR TO_LOWER(win.TargetFilename) LIKE \"*login data*\" OR TO_LOWER(win.TargetFilename) LIKE \"*web data*\" \| STATS c = COUNT(*) BY event.co… | 1 | F25 |
| q-1c18d576f5 | triage T1539 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*cookie*\" OR TO_LOWER(process.command_line) LIKE \"*login data*\" OR TO_LOWER(process.command_line) LIKE \"*sqlite*\" OR T… | 5 | F25 |
| q-1974c2e653 | triage T1539 step 6 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND (TO_LOWER(win.TargetImage) LIKE \"*chrome*\" OR TO_LOWER(win.TargetImage) LIKE \"*firefox*\" OR TO_LOWER(win.TargetImage) LIKE \"*msedge*\" OR TO_LOWER(win.Targe… | 0 |  |
| q-2115f5d38c | triage T1539 step 6 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE TO_LOWER(win.TargetFilename) LIKE \"*appdata*\" AND (TO_LOWER(win.TargetFilename) LIKE \"*google*\" OR TO_LOWER(win.TargetFilename) LIKE \"*mozilla*\" OR TO_LOWER(win.TargetFilename) LIK… | ERROR |  |
| q-350f7f0155 | triage T1539 step 7 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE TO_LOWER(win.TargetFilename) LIKE \"*appdata*\" AND (TO_LOWER(win.TargetFilename) LIKE \"*google*\" OR TO_LOWER(win.TargetFilename) LIKE \"*mozilla*\" OR TO_LOWER(win.TargetFilename) LIK… | 6 |  |
| q-d34592447d | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOociZfQ"} | None |  |
| q-d75f73433e | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtHRU7U"} | None |  |
| q-3b55f0d71b | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtISlRo"} | None |  |
| q-1506707bd4 | triage T1539 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3AvzkC"} | None |  |
| q-b9f30d43ec | triage T1539 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3P0Z25"} | None |  |
| q-0d502830b6 | triage T1552 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3P0p0s"} | None | F26, F31 |
| q-7ec4edd397 | triage T1552 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3Q03Gn"} | None | F28 |
| q-9242f83730 | triage T1552 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3AvzkC"} | None | F27 |
| q-f9d4eb9096 | triage T1552 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3P0J33"} | None |  |
| q-d14971cc3b | triage T1552 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 11 AND (TO_LOWER(win.TargetFilename) LIKE \"*.pfx\" OR TO_LOWER(win.TargetFilename) LIKE \"*.pem\" OR TO_LOWER(win.TargetFilename) LIKE \"*.p12\" OR TO_LOWER(win.TargetFile… | ERROR |  |
| q-8dd45be390 | triage T1552 step 2 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == 5145 AND (TO_LOWER(win.RelativeTargetName) LIKE \"*groups.xml\" OR TO_LOWER(win.ShareName) LIKE \"*sysvol*\" OR TO_LOWER(win.RelativeTargetName) LIKE \"*.pfx\" OR TO_LOWE… | ERROR |  |
| q-4d423f4883 | triage T1552 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(win.TargetFilename) LIKE \"*.pfx\" OR TO_LOWER(win.TargetFilename) LIKE \"*.pem\" OR TO_LOWER(win.TargetFilename) LIKE \"*.p12\" OR TO_LOWER(win.Target… | 26 | F27, F30 |
| q-09ecca0b44 | triage T1552 step 3 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"5145\" AND (TO_LOWER(win.RelativeTargetName) LIKE \"*groups.xml\" OR TO_LOWER(win.ShareName) LIKE \"*sysvol*\" OR TO_LOWER(win.RelativeTargetName) LIKE \"*.pfx\" OR TO_… | 56 | F30 |
| q-f7e4d00395 | triage T1552 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*pfx*\" OR TO_LOWER(process.command_line) LIKE \"*cert*\" OR TO_LOWER(process.command_line) LIKE \"*unattend*\" OR TO_LOWER… | 1 |  |
| q-f90102ba8e | triage T1552 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND user.name == \"pbeesly\" \| KEEP @timestamp, host.name, user.name, process.executable, process.command_line, _id, _index \| SORT @timestamp"} | 141 |  |
| q-dec15c6479 | triage T1552 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND user.name == \"pbeesly\" AND @timestamp > \"2020-05-02T03:05:26Z\" \| KEEP @timestamp, host.name, user.name, process.executable, process.command_line, _id, _index… | 100 | F27, F31 |
| q-d97f1435ba | triage T1552 step 5 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4663\" AND (TO_LOWER(win.ObjectName) LIKE \"*.pfx\" OR TO_LOWER(win.ObjectName) LIKE \"*downloads*\" OR TO_LOWER(win.ObjectName) LIKE \"*office*\" OR TO_LOWER(win.Objec… | 0 |  |
| q-0433c05b78 | triage T1552 step 6 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtao0x-"} | None | F26, F31 |
| q-44a1e24629 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3P0p0s"} | None |  |
| q-7b1155063f | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3P0p0s"} | None |  |
| q-4cdd407658 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtao0x-"} | None |  |
| q-b21dcb3837 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtao0x-"} | None |  |
| q-e096a6be42 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3AvzkC"} | None |  |
| q-3bb3f4c4c8 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3AvzkC"} | None |  |
| q-5f71e221f3 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtIS1QC"} | None |  |
| q-1b4179a6b3 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtGQk7R"} | None |  |
| q-a2bdb99f1f | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOs4A9hu"} | None |  |
| q-4e3274d4e4 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOokoC4V"} | None |  |
| q-e4a65e0ecf | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3Q03Gn"} | None |  |
| q-6853f4d4b4 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO1pngKW"} | None |  |
| q-546f8192a4 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO3_ZDTc"} | None |  |
| q-f68dd12ad8 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO3_ZDTc"} | None |  |
| q-6e6f9d1009 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtfu-5W"} | None |  |
| q-db9119d314 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3P0p0s"} | None |  |
| q-b8e20c1b20 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtao0x-"} | None |  |
| q-5be88df35f | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtGQk7R"} | None |  |
| q-9b49c255dc | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtISlSY"} | None |  |
| q-6420d1d765 | triage T1555 step 1 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND win.TargetImage:*lsass.exe", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-834d147961 | triage T1555 step 1 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND win.TargetImage:*lsass.exe AND (win.GrantedAccess:0x1fffff OR win.GrantedAccess:0x101001 OR win.GrantedAccess:0x1f3fff OR win.GrantedAccess:0x1400 OR win.GrantedAccess:0x3… | 33 |  |
| q-6a315ee930 | triage T1555 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass.exe AND (process.executable:*PowerShell.exe OR process.executable:*wsmprovhost.exe OR process.executable:*wininit.exe OR process.executable:*csrss.exe)", "time_from": null, "time_… | 6 |  |
| q-df954b1102 | triage T1555 step 2 | search | {"dataset": "windows.security", "query": "event.code:4663 AND win.ObjectName:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "win.ObjectName", "win.ProcessName", "win.SubjectUserName", "win.AccessMask", "win.AccessList", "wi… | 6 |  |
| q-396665d6af | triage T1555 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtaokyU"} | None | F32 |
| q-addb29bf5d | triage T1555 step 3 | search | {"dataset": "windows.powershell", "query": "host.name:scranton.dmevals.local AND event.code:4104 AND (win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*MiniDump* OR win.ScriptBlockText:*Credential* OR win.ScriptBlockText:*Invoke-Mimikatz* OR win.ScriptBlockT… | 1 |  |
| q-df40b4d93a | triage T1555 step 4 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3AvzkC"} | None |  |
| q-4c111dd82b | triage T1555 step 4 | search | {"dataset": "windows.security", "query": "host.name:scranton.dmevals.local AND event.code:4688 AND (process.command_line:*lsass* OR process.command_line:*dump* OR process.command_line:*credential* OR process.command_line:*vault* OR process.command_line:*cmdkey… | 0 |  |
| q-e4e7365161 | triage T1555 step 5 | search | {"dataset": "windows.sysmon", "query": "host.name:scranton.dmevals.local AND event.code:1 AND (process.command_line:*lsass* OR process.command_line:*dump* OR process.command_line:*credential* OR process.command_line:*vault* OR process.command_line:*cmdkey* OR … | 1 |  |
| q-766408abb2 | triage T1555 step 5 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (win.TargetFilename:*lsass* OR win.TargetFilename:*Credentials* OR win.TargetFilename:*Vault* OR win.TargetFilename:*.dmp OR win.TargetFilename:*Login* OR win.TargetFilename:*logins.json* OR win.TargetF… | 2 | F33 |
| q-cfa376075b | triage T1555 step 6 | search | {"dataset": "windows.sysmon", "query": "event.code:13 AND (win.TargetObject:*Vault* OR win.TargetObject:*Credentials* OR win.TargetObject:*CredMan* OR win.TargetObject:*ProtectedStorage*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.nam… | 0 |  |
| q-05c51e55f8 | triage T1555 step 6 | search | {"dataset": "windows.sysmon", "query": "host.name:scranton.dmevals.local AND event.code:1 AND process.executable:*PowerShell.exe", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "process.executable", "process.command_li… | 0 |  |
| q-a04f436c94 | triage T1555 step 7 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.executable:*powershell.exe OR process.executable:*wsmprovhost.exe OR process.executable:*cmd.exe)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "… | 31 | F32 |
| q-bd7e5eec19 | triage T1555 step 7 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtIR1Pn"} | None | F32 |
| q-801302c490 | triage T1555 step 8 | search | {"dataset": "windows.powershell", "query": "host.name:nashua.dmevals.local AND event.code:4104", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "user.name", "win.ScriptBlockText", "win.Path"], "size": 40, "sort": "asc"} | 11 | F32, F35 |
| q-fac12b3679 | triage T1555 step 8 | search | {"dataset": "windows.sysmon", "query": "host.name:nashua.dmevals.local AND (event.code:11 OR event.code:1) AND (win.TargetFilename:*AppData* OR process.command_line:*AppData* OR process.command_line:*Credential* OR process.command_line:*vault* OR process.comma… | 127 |  |
| q-b688952727 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtaokyU"} | None |  |
| q-df908befe8 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtaokyU"} | None |  |
| q-ffcdf79a58 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtaokyU"} | None |  |
| q-6b82c65861 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtIR1Pn"} | None |  |
| q-deffeb1986 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtIR1Pn"} | None |  |
| q-905c464bbb | triage T1555 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3Iwxm0"} | None |  |
| q-00c3c6375f | triage T1555 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO32OQYa"} | ERROR |  |
| q-e913e5c556 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO0EgbIk"} | None |  |
| q-fe223ab2a2 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtYnKtJ"} | None |  |
| q-38f41df9d5 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO1pnQLs"} | None |  |
| q-21d6089238 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3JxTei"} | None |  |
| q-1f72657aef | triage T1556 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass.exe AND (win.GrantedAccess:0x1fffff OR win.GrantedAccess:0x101001 OR win.GrantedAccess:0x1f3fff OR win.GrantedAccess:0x1000000 OR win.GrantedAccess:0x3000)", "time_from": null, "t… | 9 | F36, F37 |
| q-ad3c2559b7 | triage T1556 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass.exe AND (win.SourceImage:*PowerShell* OR win.SourceImage:*wsmprovhost* OR win.SourceImage:*wininit* OR win.SourceImage:*csrss* OR win.SourceImage:*services.exe)", "time_from": nul… | 9 | F36, F42 |
| q-4f9ee2a0ad | triage T1556 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtaokyU"} | None |  |
| q-581993328d | triage T1556 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtIR1Pn"} | None |  |
| q-d8b8a36208 | triage T1556 step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*lsass*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*minidump*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*comsvcs*\" OR… | 16 | F36, F39 |
| q-fcd5baf246 | triage T1556 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"13\" AND (TO_LOWER(registry.path) LIKE \"*lsa*\" OR TO_LOWER(registry.path) LIKE \"*networkprovider*\" OR TO_LOWER(registry.path) LIKE \"*wdigest*\" OR TO_LOWER(registry.… | 30 | F36, F37, F38 |
| q-799dcfb71a | triage T1556 step 4 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3Pz51x"} | None |  |
| q-532998cd0f | triage T1556 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (process.pid == 2976 OR process.pid == 3876 OR process.pid == 7720 OR TO_LOWER(process.command_line) LIKE \"*lsass*\" OR TO_LOWER(process.command_line) LIKE \"*no… | 5 | F36 |
| q-01874066e2 | triage T1556 step 5 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE (event.code == \"4656\" OR event.code == \"4663\" OR event.code == \"4673\" OR event.code == \"4674\") AND (TO_LOWER(win.ObjectName) LIKE \"*lsass*\" OR TO_LOWER(win.ProcessName) LIKE … | 25 | F41 |
| q-b40cefef4d | triage T1556 step 5 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4657\" OR event.code == \"4739\" OR event.code == \"5136\" OR event.code == \"4907\" \| KEEP @timestamp, host.name, event.code, user.name, win.ObjectName, win.ObjectVal… | 25 |  |
| q-79747cfcd8 | triage T1556 step 6 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOx6IsLb"} | None |  |
| q-4e6339f563 | triage T1556 step 6 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4648\" OR (event.code == \"4624\" AND win.TargetUserName == \"pbeesly\") \| KEEP @timestamp, host.name, event.code, user.name, win.TargetUserName, win.LogonType, win.Lo… | 25 |  |
| q-9fc54d407f | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOx6IsLb"} | None |  |
| q-72c2d314d9 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtaokyU"} | None |  |
| q-7b5afc1194 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtaokyU"} | None |  |
| q-1e91031ec6 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtIR1Pn"} | None |  |
| q-66f49561c4 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3Pz51x"} | None |  |
| q-5e7bc99765 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOs4A9go"} | None |  |
| q-c96d3a6ee7 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtaokyR"} | None |  |
| q-c6cf24d327 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOs4A9hr"} | None |  |
| q-d69df70da4 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOs4A9hr"} | None |  |
| q-b68e8fc497 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3P0Z28"} | None |  |
| q-d2ac326514 | triage T1556 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZJWiSVpshTO03669g"} | None |  |
| q-bc9be16540 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOzc__0s"} | None |  |
| q-526e653c1a | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtIR1Pn"} | None |  |
| q-d1d1797eb7 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtIR1Pn"} | None |  |
| q-d1dc5d10e2 | triage T1557 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.executable:*ARP.EXE OR process.executable:*ROUTE.EXE OR process.executable:*ipconfig.exe OR process.executable:*netsh*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name"… | 11 | F46 |
| q-60884afbd3 | triage T1557 step 1 | search | {"dataset": "zeek", "query": "event.action:conn AND (zeek.orig_l2_addr:\"fc:bd:67:e1:a9:c1\" OR zeek.resp_l2_addr:\"12:34:56:78:9a:bc\")", "time_from": null, "time_to": null, "fields": ["@timestamp", "observer.name", "source.ip", "destination.ip", "destination… | 603 | F45 |
| q-72bb1828dd | triage T1557 step 2 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"conn\" \| STATS cnt = COUNT(*), srcs = COUNT_DISTINCT(source.ip), dsts = COUNT_DISTINCT(destination.ip) BY zeek.resp_l2_addr, zeek.orig_l2_addr \| SORT cnt DESC"} | 5 |  |
| q-1a8d4dd332 | triage T1557 step 2 | search | {"dataset": "zeek", "query": "event.action:conn AND destination.ip:192.168.0.5", "time_from": null, "time_to": null, "fields": ["@timestamp", "observer.name", "source.ip", "destination.ip", "destination.port", "zeek.orig_l2_addr", "zeek.resp_l2_addr", "zeek.se… | 3 |  |
| q-daad1834b0 | triage T1557 step 3 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.executable:*PsExec64.exe OR process.executable:*PSEXESVC.exe OR process.executable:*sdelete64.exe OR process.executable:*python.exe)", "time_from": null, "time_to": null, "fields": ["@timestamp"… | 19 | F43 |
| q-8afa932284 | triage T1557 step 3 | search | {"dataset": "windows.security", "query": "event.code:4697 AND (win.ServiceName:PSEXESVC OR win.ServiceName:javamtsup)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "win.ServiceName", "win.ServiceFileName", "win.Servic… | 5 |  |
| q-6dbff09784 | triage T1557 step 4 | search | {"dataset": "windows.sysmon", "query": "event.code:3 AND (destination.port:445 OR destination.port:137)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "process.executable", "destination.ip", "destination.port", "source… | 74 | F44 |
| q-fd233f92dc | triage T1557 step 4 | search | {"dataset": "windows.security", "query": "event.code:4624 AND (win.LogonProcessName:\"NtLmSsp \" OR win.LogonProcessName:\"User32 \")", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "win.LogonProcessName", "win.LogonTyp… | 3 | F44 |
| q-87dcc66212 | triage T1557 step 5 | search | {"dataset": "windows.security", "query": "win.IpAddress:172.18.39.2", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "event.code", "win.LogonType", "win.IpAddress", "win.Workstation", "win.TargetUserName", "win.ProcessNa… | 4 | F44 |
| q-38492b4961 | triage T1557 step 5 | search | {"dataset": "windows.other", "query": "event.code:(7045 OR 7040 OR 2004 OR 2006 OR 98 OR 55 OR 32)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "win.ServiceName", "win.ImagePath", "win.param1", "win.param2", "messag… | 24 | F46 |
| q-4c1ba677c5 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtGQk7R"} | None |  |
| q-cdabe8b6f8 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOyESnYY"} | None |  |
| q-0ad625e615 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtftxew"} | None |  |
| q-7630288c0c | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtfue5A"} | None |  |
| q-b613978ca7 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtdr1W2"} | None |  |
| q-5987a91fe4 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO0NmmRM"} | None |  |
| q-785c21e770 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO0Gh1d1"} | None |  |
| q-7bb66cacca | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZJWiSVpshTO2e9qSA"} | None |  |
| q-9c81b3c57c | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZJWiSVpshTO037K8i"} | None |  |
| q-b7674e3da8 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO2-WWw"} | ERROR |  |
| q-2a85cd2ffa | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO2-WWw"} | ERROR |  |
| q-7383270262 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO1pngI8"} | None |  |
| q-8bc29e4fa4 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOonrxo5"} | None |  |
| q-485672eeb6 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOosxQHp"} | None |  |
| q-166a5d1282 | triage T1557 step 7 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO2-WWw"} | ERROR |  |
| q-5415764006 | triage T1557 step 8 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND process.executable:*ARP.EXE", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "process.executable", "process.command_line", "process.parent.executable"], "size": 5, "sort": "asc… | 3 | F45 |
| q-ee7ed3fc38 | triage T1558 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND (win.GrantedAccess:0x1fffff OR win.GrantedAccess:0x1f3fff OR win.GrantedAccess:0x101001 OR win.GrantedAccess:0x1000000 OR win.GrantedAccess:0x3000 OR win.GrantedAccess:0x1400… | 33 |  |
| q-53194b4f7b | triage T1558 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND process.executable:*PowerShell*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "process.executable", "process.command_line", "win.GrantedAccess",… | 4 |  |
| q-d36336ab30 | triage T1558 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtaokyR"} | None | F47 |
| q-0a8bd44da9 | triage T1558 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtaokyU"} | None | F47 |
| q-3e56719bcf | triage T1558 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtIR1Pn"} | None | F47 |
| q-12cd90bd4c | triage T1558 step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*kerberos*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*ticket*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*lsass*\"… | 0 |  |
| q-b88545452d | triage T1558 step 3 | search | {"dataset": "zeek", "query": "event.action:kerberos", "time_from": null, "time_to": null, "fields": ["@timestamp", "source.ip", "destination.ip", "zeek.request_type", "zeek.client", "zeek.service", "zeek.error_msg", "zeek.success", "zeek.cipher", "zeek.forward… | 35 | F50, F51 |
| q-09837374c7 | triage T1558 step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" \| STATS c = COUNT(*) BY host.name, user.name \| SORT c DESC"} | 3 |  |
| q-e8892b00f8 | triage T1558 step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND host.name == \"scranton.dmevals.local\" \| KEEP @timestamp, user.name, win.ScriptBlockText, _id, _index \| LIMIT 25"} | 25 | F47 |
| q-326925f05e | triage T1558 step 5 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*invoke-mimikatz*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*sekurlsa*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"… | 5 | F47 |
| q-93d20e75be | triage T1558 step 5 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND host.name == \"newyork.dmevals.local\" \| KEEP @timestamp, user.name, win.ScriptBlockText, _id, _index \| LIMIT 20"} | 20 |  |
| q-767b4a0ecb | triage T1558 step 6 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4768\",\"4769\",\"4770\",\"4771\",\"4765\",\"4766\",\"4776\",\"4752\",\"4753\",\"4754\",\"4755\",\"4756\",\"4757\",\"4758\",\"4759\",\"4760\",\"4761\",\"4762\",\"4763\… | 3 |  |
| q-4ea23c5f62 | triage T1558 step 6 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4672\" \| STATS c = COUNT(*) BY host.name, win.SubjectUserName, win.SubjectDomainName \| SORT c DESC"} | 12 |  |
| q-16ffea9430 | triage T1558 step 7 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4768\",\"4769\",\"4776\") \| KEEP @timestamp, host.name, event.code, win.TargetUserName, win.ServiceName, win.TicketEncryptionType, win.TicketOptions, win.Status, win.… | 43 |  |
| q-8a3cd0b163 | triage T1558 step 8 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*mimikatz*\" OR TO_LOWER(process.command_line) LIKE \"*kerberos*\" OR TO_LOWER(process.command_line) LIKE \"*ticket*\" OR T… | 1 |  |
| q-b2df00dd0f | triage T1558 step 8 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND host.name == \"scranton.dmevals.local\" \| KEEP @timestamp, user.name, file.path, process.executable, _id, _index \| SORT @timestamp ASC \| LIMIT 40"} | 40 | F47 |
| q-ed9347d402 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtaokyR"} | None |  |
| q-1c9f75feb0 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtaokyU"} | None |  |
| q-786c40be23 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtaokyR"} | None |  |
| q-3a02014344 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtIR1Pn"} | None |  |
| q-8807f3823d | triage T1558 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtIR1Pn"} | None |  |
| q-8a5987196c | triage T1558 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3P0J3p"} | None |  |
| q-76a94da06e | triage T1558 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3AvzkC"} | None |  |
| q-a14e3c3035 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOx9LDOJ"} | None |  |
| q-72463f8fed | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO0MlXTc"} | ERROR |  |
| q-02fa1bbd22 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO0MlXTc"} | ERROR |  |
| q-7948e2e209 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO31NCrt"} | None |  |
| q-e70783f194 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO32OAbc"} | None |  |
| q-a4a2e4b4d6 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO32OAbc"} | None |  |
| q-6833da1f72 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO0MlnQk"} | ERROR |  |
| q-5823b3e0f6 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO39XK4T"} | None |  |
| q-26796faab1 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO39XK4T"} | None |  |
| q-94da37194d | triage T1558 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZJWiSVpshTO03669f"} | None |  |
| q-1d564fd2d4 | triage T1558 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZJWiSVpshTO036q-N"} | None |  |
| q-1a97f25547 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO31NCrt"} | None |  |
| q-41b89410be | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO31NCrt"} | None |  |
| q-4af86cf1d6 | triage T1558 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZJWiSVpshTO03669f"} | None |  |
| q-b18ec4cc87 | triage T1558 step 10 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO0MlXTc"} | ERROR |  |
| q-ed3db9c136 | triage T1558 step 10 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO0MlnQk"} | ERROR |  |
| q-297ae1969b | triage T1558 step 11 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4768\",\"4769\") \| KEEP @timestamp, host.name, event.code, win.TargetUserName, win.ServiceName, win.TicketEncryptionType, win.PreAuthType, win.Status, _id, _index \| … | 42 | F48, F49, F50, F51 |
| q-e657a67cce | triage T1606 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND win.TargetFilename:*pfx*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_l… | 1 | F52 |
| q-9bb08c601e | triage T1606 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND (win.GrantedAccess:0x1fffff OR win.GrantedAccess:0x101001 OR win.GrantedAccess:0x1f3fff OR win.GrantedAccess:0x1000000 OR win.GrantedAccess:0x3000)", "time_from": null, "time… | 9 | F53 |
| q-584a47d61d | triage T1606 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3Pz52r"} | None |  |
| q-6fe8ccc04c | triage T1606 step 2 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == 4104 \| KEEP @timestamp, host.name, user.name, win.Path, win.ScriptBlockId, _id, _index \| SORT @timestamp ASC \| LIMIT 100"} | ERROR |  |
| q-0e8afd3246 | triage T1606 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND host.name:scranton.dmevals.local AND process.pid:3876", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.ex… | 320 |  |
| q-a3ac380dff | triage T1606 step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" \| KEEP @timestamp, host.name, user.name, win.Path, win.ScriptBlockId, _id, _index \| SORT @timestamp ASC \| LIMIT 100"} | 100 |  |
| q-52433c0f7d | triage T1606 step 3 | search | {"dataset": "windows.sysmon", "query": "event.code:3 AND host.name:scranton.dmevals.local AND process.pid:3876", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.exe… | 0 |  |
| q-37d8d998aa | triage T1606 step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND @timestamp >= \"2020-05-02T03:02:00.000Z\" AND @timestamp <= \"2020-05-02T03:10:00.000Z\" \| KEEP @timestamp, host.name, user.name, win.Path, win.ScriptBlo… | 30 | F52 |
| q-9995958641 | triage T1606 step 4 | search | {"dataset": "windows.sysmon", "query": "event.code:3 AND host.name:scranton.dmevals.local", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.co… | 140 |  |
| q-525038a397 | triage T1606 step 5 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3P0p0s"} | None | F52 |
| q-f1fd5ada21 | triage T1606 step 5 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtaokyU"} | None | F53 |
| q-25c27d14ed | triage T1606 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3P0p0s"} | None |  |
| q-8b5695c34a | triage T1606 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3P0p0s"} | None |  |
| q-ca36e196c0 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtao0x-"} | None |  |
| q-b1ebe49e17 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3Pz51j"} | None |  |
| q-f5d0d99fa8 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3Pz52j"} | None |  |
| q-b01a77f09e | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtaokyU"} | None |  |
| q-a200e2d54c | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtaokyU"} | None |  |
| q-9d4748ed7f | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtaokyR"} | None |  |
| q-78805cb13a | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO3Pz52r"} | ERROR |  |
| q-caac29a951 | triage T1606 step 7 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND win.TargetFilename:*INetCookies*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.c… | 1 | F54 |
| q-0b3d9fcb55 | triage T1649 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3P0p0s"} | None | F55 |
| q-b13bb3b400 | triage T1649 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND win.TargetFilename:*pfx*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "process.executable", "process.command_line", "win.TargetFilename", "process.parent.exec… | 1 |  |
| q-47e6baf6c0 | triage T1649 step 1 | search | {"dataset": "windows.security", "query": "event.code:4657 AND win.ObjectName:*SystemCertificates*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "win.ObjectName", "win.OperationType", "win.NewValue", "win.OldValue", "w… | 1 | F56 |
| q-6ff27f2197 | triage T1649 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtao0x-"} | None | F55 |
| q-7002047647 | triage T1649 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*Export-PfxCertificate* OR process.command_line:*Get-PrivateKeys* OR process.command_line:*readme.ps1* OR process.command_line:*certutil* OR process.command_line:*pfx*)", "time_from… | 0 |  |
| q-1ae908b0f5 | triage T1649 step 2 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Get-PrivateKeys* OR win.ScriptBlockText:*Export-PfxCertificate* OR win.ScriptBlockText:*readme.ps1*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name… | 4 | F55 |
| q-f713cff8f2 | triage T1649 step 3 | search | {"dataset": "windows.sysmon", "query": "host.name:scranton.dmevals.local AND (win.TargetFilename:*readme* OR win.TargetFilename:*Downloads* OR win.DestinationHostname:* OR (event.code:22 AND win.QueryName:*))", "time_from": null, "time_to": null, "fields": ["@… | 516 | F55 |
| q-01501fcce5 | triage T1649 step 3 | search | {"dataset": "windows.security", "query": "event.code:4768", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "event.code", "win.TargetUserName", "win.IpAddress", "win.ServiceName", "win.PreAuthType", "win.Status"], "size":… | 14 | F57 |
| q-0a7554e9f4 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3P0p0s"} | None |  |
| q-10a2125f28 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3P0p0s"} | None |  |
| q-d43ae08b25 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3P0p0s"} | None |  |
| q-3c0d4362fd | triage T1649 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3Pz51j"} | None |  |
| q-2ff0cb45c6 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3Pz52j"} | None |  |
| q-7355a39390 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3Pz51N"} | None |  |
| q-4751853ffd | triage T1649 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtao0x-"} | None |  |
| q-f59f8e4542 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtao0x-"} | None |  |
| q-caa0a7dd4d | triage T1649 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOx-NP1p"} | None |  |
| q-059d8d8b37 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO3zLJP8"} | None |  |
| q-56ec8b0bfc | triage T1649 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO3zLJP8"} | None |  |
| q-04508c00ce | triage T1649 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO3zLJP8"} | None |  |
| q-200f276248 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO31NCrt"} | None |  |
| q-616d29d3a4 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO0MlXTa"} | None |  |
| q-a70bcd7ab0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtaokyU"} | None |  |
| q-a34a7d5bc4 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtaokyU"} | None |  |
| q-7d24140047 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtaokyU"} | None |  |
| q-68b32fcd72 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOx6IsLb"} | None |  |
| q-406ee30f1b | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO39W64C"} | None |  |
| q-f5a3073d82 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtaokyR"} | None |  |
| q-111f5479fb | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtIR1Pn"} | None |  |
| q-3fdb507f45 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtIR1Pn"} | None |  |
| q-8d973dc200 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtISFPF"} | None |  |
| q-6bd9bee65c | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3Iwxm0"} | None |  |
| q-81a39cf3ad | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOx-M_2G"} | None |  |
| q-6f8634541c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOs4A9hl"} | None |  |
| q-e4d870707d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtYnKtJ"} | None |  |
| q-5e4d86dd19 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOs4A9hk"} | None |  |
| q-d2a102b928 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO39Xq5t"} | None |  |
| q-e25fce5127 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOs4A9hk"} | None |  |
| q-b9b633c8de | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO3-XnWS"} | None |  |
| q-c6aeee7a56 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO3-XnWS"} | None |  |
| q-9fc379ac76 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO39W64C"} | None |  |
| q-2cbefd5b70 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO3zLZNi"} | None |  |
| q-ca1e9f60e9 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO3zLZNi"} | None |  |
| q-c0b12f01c5 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOonrxo5"} | None |  |
| q-a6d9592701 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOonrxo5"} | None |  |
| q-bf5bc0544e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOonrxo5"} | None |  |
| q-3adbb02e97 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOosxQHp"} | None |  |
| q-9d4b5fd1e2 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO0HjD-1"} | None |  |
| q-fe97b597d5 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO1pngK-"} | None |  |
| q-5c55975d31 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3Pzp3U"} | None |  |
| q-dacd3cb42c | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3Pzp3U"} | None |  |
| q-0d67c26117 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3Pzp3U"} | None |  |
| q-e6e9eccb8d | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3Oy3md"} | None |  |
| q-707914f5b5 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3Pz52N"} | None |  |
| q-b7a3d93d8b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtaokyU"} | None |  |
| q-886ef89144 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtaokyU"} | None |  |
| q-b47e7be859 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtaokyU"} | None |  |
| q-acf3aa6976 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtaokyR"} | None |  |
| q-589024c6ef | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtaokyU"} | None |  |
| q-7b8365722d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtIR1Pn"} | None |  |
| q-29f0ded4ee | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtIR1Pn"} | None |  |
| q-9570f72932 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtIR1Pn"} | None |  |
| q-fcb6bfb6b9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOs4A9hl"} | None |  |
| q-0cecefb4d4 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOs7DwuP"} | None |  |
| q-7bf94a091d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOoWdgoz"} | None |  |
| q-f2142e8b2e | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO1pngK-"} | None |  |
| q-f4c92082ce | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO1pngIR"} | None |  |
| q-4c6a60a979 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3V6Jtq"} | None |  |
| q-2c9181e2b0 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO3mCkhu"} | None |  |
| q-cd3008174a | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO3mCkhu"} | None |  |
| q-5631ebc624 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO1pngJm"} | None |  |
| q-2246c10956 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3Q199Y"} | None |  |
| q-5a6fd99428 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtjz-FD"} | None |  |
| q-9b1176d08c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtjz-FD"} | None |  |
| q-15019ef732 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO0KlA9b"} | None |  |
| q-439bf9bab7 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOoXemmg"} | None |  |
| q-60a7f48ae6 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3P0p0s"} | None |  |
| q-583a2d8472 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3AvzkC"} | None |  |
| q-b9f0da17e7 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOs4A9hu"} | None |  |
| q-94ba31d88e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOs4A9hp"} | None |  |
| q-2a90175bfa | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOoWeAuy"} | None |  |
| q-9f1e39e068 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOoRaEln"} | None |  |
| q-044fea1910 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO1pnQLs"} | None |  |
| q-5c09f75d17 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO31NCqL"} | None |  |
| q-566064c3c5 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO31NSq9"} | None |  |
| q-db9fcf24c3 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO1pngK-"} | None |  |
| q-5980ed118b | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3AvzkC"} | None |  |
| q-9981f158d5 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtcqWLx"} | None |  |
| q-ba78055cf5 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtl2JQj"} | None |  |
| q-2b1f6a904a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtHRU4M"} | None |  |
| q-fd95849fab | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO31NyoH"} | None |  |
| q-f667460cbf | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO3_ZDTc"} | None |  |
| q-04509d2c80 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO1pnQLy"} | None |  |
| q-80be0483ad | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3AvzkC"} | None |  |
| q-1d8a732726 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtaokyU"} | None |  |
| q-50b03e8186 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtaokyR"} | None |  |
| q-33d37b0eb0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtaokyU"} | None |  |
| q-b912199a1a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtaokyR"} | None |  |
| q-aeef97bfc3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOx6IsLb"} | None |  |
| q-2d76294b4e | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO39W66U"} | None |  |
| q-03c97577fd | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO39W65K"} | None |  |
| q-43a4889dbb | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtIR1Pn"} | None |  |
| q-f7dbe28794 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtIR1Pn"} | None |  |
| q-63e92c5142 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO32Nwbs"} | None |  |
| q-aaa138f613 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO31NCqM"} | None |  |
| q-1649bdab67 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3P0p0s"} | None |  |
| q-c7a67bb89c | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3P0J3m"} | None |  |
| q-6b9416d92f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOs7DwuP"} | None |  |
| q-eabcd7b2cb | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOoWdgoz"} | None |  |
| q-2e069285cb | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOs4A9hl"} | None |  |
| q-73db906341 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO39XK6I"} | None |  |
| q-023db52df3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOociZfQ"} | None |  |
| q-180f518c16 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtHRU7U"} | None |  |
| q-ede4b8a05a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtISlRo"} | None |  |
| q-a18d6b46c2 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3AvzkC"} | None |  |
| q-417c48990a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOociZfQ"} | None |  |
| q-44d0ceb859 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3P0p0s"} | None |  |
| q-9b61fbc630 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3P0p0s"} | None |  |
| q-7035887bdb | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtao0x-"} | None |  |
| q-a40dba93be | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtao0x-"} | None |  |
| q-3382b13a8a | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3AvzkC"} | None |  |
| q-52eefd1a62 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3AvzkC"} | None |  |
| q-b8d587ee50 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtIS1QC"} | None |  |
| q-82317c3878 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtGQk7R"} | None |  |
| q-67079e4400 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOs4A9hu"} | None |  |
| q-15e917375e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOokoC4V"} | None |  |
| q-161e69bdc4 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3Q03Gn"} | None |  |
| q-c916b548c9 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO1pngKW"} | None |  |
| q-075e051d10 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO3_ZDTc"} | None |  |
| q-e571da82af | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO3_ZDTc"} | None |  |
| q-c4f2fd4ee5 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtfu-5W"} | None |  |
| q-e96417d038 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3P0p0s"} | None |  |
| q-26ffe28c2c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtao0x-"} | None |  |
| q-5790444f90 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtGQk7R"} | None |  |
| q-5bcb19aba6 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtISlSY"} | None |  |
| q-d8a2d7c78b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtaokyU"} | None |  |
| q-fc51a09d27 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtaokyU"} | None |  |
| q-1095600a2b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtaokyU"} | None |  |
| q-1608e30da9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtIR1Pn"} | None |  |
| q-6dd5d04e2a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtIR1Pn"} | None |  |
| q-435bce5dcb | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3Iwxm0"} | None |  |
| q-d6f3c0ebfe | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO0EgbIk"} | None |  |
| q-7305892c25 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtYnKtJ"} | None |  |
| q-3b4bb97cf1 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO1pnQLs"} | None |  |
| q-c8d6431113 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3JxTei"} | None |  |
| q-fc1bb416d7 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOx6IsLb"} | None |  |
| q-6c1dffc994 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtaokyU"} | None |  |
| q-29a68d366e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtaokyU"} | None |  |
| q-1ed50b654c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtIR1Pn"} | None |  |
| q-b9c24a2fc2 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3Pz51x"} | None |  |
| q-eae533fc5e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOs4A9go"} | None |  |
| q-56a81b00da | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtaokyR"} | None |  |
| q-34283daa28 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOs4A9hr"} | None |  |
| q-47004ff901 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOs4A9hr"} | None |  |
| q-441b87a79a | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3P0Z28"} | None |  |
| q-32cf1fd14c | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZJWiSVpshTO03669g"} | None |  |
| q-e0d32a6b67 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOzc__0s"} | None |  |
| q-e30291f576 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtIR1Pn"} | None |  |
| q-7d176f64a6 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtIR1Pn"} | None |  |
| q-0c88a74491 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtGQk7R"} | None |  |
| q-450896a49e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOyESnYY"} | None |  |
| q-2f9c84f8ca | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtftxew"} | None |  |
| q-37700bc164 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtfue5A"} | None |  |
| q-fbdcdb5aba | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtdr1W2"} | None |  |
| q-d6bad3b9a3 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO0NmmRM"} | None |  |
| q-b2e4f056fe | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO0Gh1d1"} | None |  |
| q-07aea080a4 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZJWiSVpshTO2e9qSA"} | None |  |
| q-b1721f9100 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZJWiSVpshTO037K8i"} | None |  |
| q-729dd05137 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOo2-WWw"} | None |  |
| q-4c6466f76d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOo2-WWw"} | None |  |
| q-65c7aaf93e | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO1pngI8"} | None |  |
| q-a405ec1100 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOonrxo5"} | None |  |
| q-56e0de2edd | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOosxQHp"} | None |  |
| q-f0c23e11f5 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtaokyR"} | None |  |
| q-f8016121a1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtaokyU"} | None |  |
| q-62859d7dd1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtaokyR"} | None |  |
| q-2f57baa750 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtIR1Pn"} | None |  |
| q-7d758bda2a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtIR1Pn"} | None |  |
| q-bd87755c5b | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3P0J3p"} | None |  |
| q-7b24a3d983 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3AvzkC"} | None |  |
| q-450229c353 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOx9LDOJ"} | None |  |
| q-04ee681960 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO0MlXTc"} | None |  |
| q-2c42dd7bc7 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO0MlXTc"} | None |  |
| q-6c3c115f51 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO31NCrt"} | None |  |
| q-6d81720cef | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO32OAbc"} | None |  |
| q-190557d343 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO32OAbc"} | None |  |
| q-110daef5b5 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO0MlnQk"} | ERROR |  |
| q-7254f028d6 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO39XK4T"} | None |  |
| q-d542dbff21 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO39XK4T"} | None |  |
| q-cf6010584a | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZJWiSVpshTO03669f"} | None |  |
| q-25619a9981 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZJWiSVpshTO036q-N"} | None |  |
| q-03bb5cb9ae | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO31NCrt"} | None |  |
| q-631f738db6 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO31NCrt"} | None |  |
| q-e3c10d971d | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZJWiSVpshTO03669f"} | None |  |
| q-14dda0cd1f | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3P0p0s"} | None |  |
| q-75bf968b38 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3P0p0s"} | None |  |
| q-8494596b68 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtao0x-"} | None |  |
| q-11b546c6be | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3Pz51j"} | None |  |
| q-dd4cdb3d82 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3Pz52j"} | None |  |
| q-25298fb54d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtaokyU"} | None |  |
| q-5ec9f37f58 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtaokyU"} | None |  |
| q-c0ddead516 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtaokyR"} | None |  |
| q-7f81c8fcd8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOociZfQ"} | None |  |
| q-df9218a6ae | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOociZfQ"} | None |  |
| q-d0658a2309 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3P0p0s"} | None |  |
| q-a6ae513711 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3P0p0s"} | None |  |
| q-48e054cfd0 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3P0p0s"} | None |  |
| q-01d8c91095 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3Pz51j"} | None |  |
| q-3928c8b2fb | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3Pz52j"} | None |  |
| q-a4038ac4e8 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3Pz51N"} | None |  |
| q-543b10526d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtao0x-"} | None |  |
| q-8448e60b30 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtao0x-"} | None |  |
| q-e24f54c667 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOx-NP1p"} | None |  |
| q-bfd5918eee | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO3zLJP8"} | None |  |
| q-54a9e0bb60 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO3zLJP8"} | None |  |
| q-f84b17c0dd | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO3zLJP8"} | None |  |
| q-b462b11be6 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO31NCrt"} | None |  |
| q-cc7db21b5a | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO0MlXTa"} | None |  |
| q-c16f4c33b7 | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND host.name:\"nashua.dmevals.local\"", "time_from": "2020-05-02T02:54:23.885000+00:00", "time_to": "2020-05-02T03:24:29.430000+00:00", "size": 100, "sub_field": "process.pare… | 57 |  |
| q-f07f5dc9d0 | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11 AND host.name:\"nashua.dmevals.local\"", "time_from": "2020-05-02T02:54:23.885000+00:00", "time_to": "2020-05-02T03:24:29.430000+00:00", "size": 100, "sub_field": "process.executable"} | 242 |  |
| q-a2b8109f19 | pivot seed | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND host.name:\"nashua.dmevals.local\"", "time_from": "2020-05-02T02:54:23.885000+00:00", "time_to": "2020-05-02T03:24:29.430000+00:00", "size": 100, "sub_field": "process… | 59 |  |
| q-c8890e0d83 | pivot seed | aggregate | {"dataset": "windows.powershell", "field": "event.code", "query": "host.name:\"nashua.dmevals.local\"", "time_from": "2020-05-02T02:54:23.885000+00:00", "time_to": "2020-05-02T03:24:29.430000+00:00", "size": 100, "sub_field": null} | 192 |  |
| q-e266db1189 | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND host.name:\"scranton.dmevals.local\"", "time_from": "2020-05-02T02:40:59.631000+00:00", "time_to": "2020-05-02T03:34:10.368000+00:00", "size": 100, "sub_field": "process.pa… | 359 |  |
| q-a26021ab1c | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11 AND host.name:\"scranton.dmevals.local\"", "time_from": "2020-05-02T02:40:59.631000+00:00", "time_to": "2020-05-02T03:34:10.368000+00:00", "size": 100, "sub_field": "process.executable… | 1276 |  |
| q-e171eb7fbc | pivot seed | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND host.name:\"scranton.dmevals.local\"", "time_from": "2020-05-02T02:40:59.631000+00:00", "time_to": "2020-05-02T03:34:10.368000+00:00", "size": 100, "sub_field": "proce… | 370 |  |
| q-c6972fc272 | pivot seed | aggregate | {"dataset": "windows.powershell", "field": "event.code", "query": "host.name:\"scranton.dmevals.local\"", "time_from": "2020-05-02T02:40:59.631000+00:00", "time_to": "2020-05-02T03:34:10.368000+00:00", "size": 100, "sub_field": null} | 8602 |  |
| q-bfe17b6453 | pivot step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 1 AND host.name == \"scranton.dmevals.local\" AND (process.executable LIKE \"*SysinternalsSuite*\" OR process.executable LIKE \"*csc.exe\" OR process.executable LIKE \"*hos… | ERROR |  |
| q-f163044b71 | pivot step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 1 AND host.name == \"nashua.dmevals.local\" AND (process.executable LIKE \"*Temp*\" OR process.executable LIKE \"*PSEXESVC*\" OR process.executable LIKE \"*wsmprovhost*\" O… | ERROR |  |
| q-2f4bdb6be6 | pivot step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND host.name == \"scranton.dmevals.local\" AND (process.executable LIKE \"*SysinternalsSuite*\" OR process.executable LIKE \"*csc.exe\" OR process.executable LIKE \"… | 15 | F58, F63, F64, F65, F66 |
| q-6f7b836566 | pivot step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND host.name == \"nashua.dmevals.local\" AND (process.executable LIKE \"*Temp*\" OR process.executable LIKE \"*PSEXESVC*\" OR process.executable LIKE \"*wsmprovhost*… | 15 | F58, F59 |
| q-ef9d33a3d2 | pivot step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND host.name == \"nashua.dmevals.local\" \| KEEP @timestamp, host.name, user.name, powershell.file.script_block_text, _id, _index \| SORT @timestamp ASC"} | ERROR |  |
| q-3e007c1589 | pivot step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND host.name == \"scranton.dmevals.local\" AND (file.path LIKE \"*Temp*\" OR file.path LIKE \"*Downloads*\" OR file.path LIKE \"*Roaming*\" OR file.path LIKE \"*vic… | 476 | F63, F64 |
| q-cfbc366172 | pivot step 4 | get_fields | {"dataset": "windows.powershell", "prefix": ""} | None |  |
| q-b8f900ae25 | pivot step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND host.name == \"scranton.dmevals.local\" AND (file.path LIKE \"*.pfx\" OR file.path LIKE \"*Downloads*\" OR file.path LIKE \"*Desktop*\" OR file.path LIKE \"*work… | 318 |  |
| q-00165160e8 | pivot step 5 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND host.name == \"nashua.dmevals.local\" \| KEEP @timestamp, host.name, user.name, powershell.script_block.text, _id, _index \| SORT @timestamp ASC"} | 11 |  |
| q-00f2232ea5 | pivot step 5 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND host.name == \"scranton.dmevals.local\" \| KEEP @timestamp, host.name, user.name, powershell.script_block.text, _id, _index \| SORT @timestamp ASC"} | 146 | F66 |
| q-d70840b65a | pivot step 6 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3JxTei"} | None | F59 |
| q-bd060fa2e7 | pivot step 6 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (file.path LIKE \"*Login Data*\" OR file.path LIKE \"*logins.json*\" OR file.path LIKE \"*key3.db*\" OR file.path LIKE \"*key4.db*\" OR file.path LIKE \"*Cookies… | 4 |  |
| q-1b52d0b573 | pivot step 7 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND host.name == \"scranton.dmevals.local\" AND (file.path LIKE \"*Crypto*\" OR file.path LIKE \"*Protect*\" OR file.path LIKE \"*Credentials*\" OR file.path LIKE \"… | ERROR |  |
| q-0165f1819d | pivot step 7 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND host.name == \"scranton.dmevals.local\" AND @timestamp > \"2020-05-02T03:01:50Z\" \| KEEP @timestamp, user.name, powershell.script_block.text, _id, _index … | 108 | F61, F62 |
| q-0ebc915bf2 | pivot step 8 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3P0p0s"} | None | F62 |
| q-a38568493c | pivot step 8 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND host.name == \"scranton.dmevals.local\" AND @timestamp > \"2020-05-02T03:06:41Z\" \| KEEP @timestamp, user.name, powershell.script_block.text, _id, _index … | 69 | F60, F61 |
| q-ced8c2fdf0 | pivot step 9 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND host.name == \"scranton.dmevals.local\" AND (powershell.script_block.text LIKE \"*Invoke-Exfil*\" OR powershell.script_block.text LIKE \"*Get-Keystrokes*\"… | 6 |  |
| q-335e87da80 | pivot step 9 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND host.name == \"scranton.dmevals.local\" AND @timestamp > \"2020-05-02T03:08:51Z\" \| KEEP @timestamp, powershell.script_block.text, _id, _index \| SORT @ti… | 25 | F58, F65 |
| q-3b0aeabf86 | pivot step 10 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND host.name == \"scranton.dmevals.local\" AND (powershell.script_block.text LIKE \"*function Invoke-Exfil*\" OR powershell.script_block.text LIKE \"*function… | 0 |  |
| q-a83c9cdfa1 | pivot step 11 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND host.name == \"scranton.dmevals.local\" AND (powershell.script_block.text LIKE \"*Exfil*\" OR powershell.script_block.text LIKE \"*SeaDuke*\" OR powershell… | 8 |  |
| q-406c37e592 | pivot step 12 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND host.name == \"scranton.dmevals.local\" AND @timestamp >= \"2020-05-02T03:08:51Z\" AND @timestamp <= \"2020-05-02T03:09:05Z\" \| KEEP @timestamp, powershel… | 16 | F61 |
| q-fb6d95645f | pivot step 12 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND host.name == \"nashua.dmevals.local\" AND (file.path LIKE \"*working*\" OR file.path LIKE \"*OfficeSupplies*\" OR file.path LIKE \"*Downloads*\" OR file.path LIK… | 38 | F59 |
| q-b8c94d999d | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtGQk7R"} | None |  |
| q-aef3b02306 | pivot verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3IxM8t"} | None |  |
| q-70ebbf6a4c | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOyESnYY"} | None |  |
| q-dc1430c5dd | pivot verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3JxTei"} | None |  |
| q-eb5e36ac67 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOyGVFIa"} | None |  |
| q-c3130135d9 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOyBQa1A"} | None |  |
| q-972688ff44 | pivot verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3P0J3p"} | None |  |
| q-6009fda888 | pivot verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3NxokS"} | None |  |
| q-4aacefea2e | pivot verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3P0p1J"} | None |  |
| q-31abe17f7c | pivot verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3P0J3m"} | None |  |
| q-923f1a1d30 | pivot verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3NxogH"} | None |  |
| q-da54823a99 | pivot verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3JxTeO"} | None |  |
| q-6da5405717 | pivot verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3Pz52j"} | None |  |
| q-9a50bfdbfc | pivot verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3Pz51j"} | None |  |
| q-e7a6fe8555 | pivot verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3P0p0s"} | None |  |
| q-eabd0efbc5 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtaokyU"} | None |  |
| q-48c27ee41f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtaokyU"} | None |  |
| q-70029d196e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtaokyU"} | None |  |
| q-2f3a3a6aeb | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOx6IsLb"} | None |  |
| q-98d7deb71b | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO39W64C"} | None |  |
| q-ee0660fbd8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtaokyR"} | None |  |
| q-c319de132b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtIR1Pn"} | None |  |
| q-7e450f78c2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtIR1Pn"} | None |  |
| q-040b7a5001 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtISFPF"} | None |  |
| q-94af125677 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3Iwxm0"} | None |  |
| q-b690984e5a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOx-M_2G"} | None |  |
| q-7986c81b93 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOs4A9hl"} | None |  |
| q-163e7c90b1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtYnKtJ"} | None |  |
| q-308b3b96cd | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOs4A9hk"} | None |  |
| q-637027bc33 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO39Xq5t"} | None |  |
| q-944e55db13 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOs4A9hk"} | None |  |
| q-35215d0cf9 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO3-XnWS"} | None |  |
| q-401d510ebd | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO3-XnWS"} | None |  |
| q-7254e3c559 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO39W64C"} | None |  |
| q-369ce3f713 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO3zLZNi"} | None |  |
| q-ff845af973 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO3zLZNi"} | None |  |
| q-f7fe150ca6 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOonrxo5"} | None |  |
| q-ee468db71c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOonrxo5"} | None |  |
| q-be97a0d38f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOonrxo5"} | None |  |
| q-50cd73e56b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOosxQHp"} | None |  |
| q-9cda910284 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO0HjD-1"} | None |  |
| q-e507abc444 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO1pngK-"} | None |  |
| q-60e322fe32 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3Pzp3U"} | None |  |
| q-aa2b9b3909 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3Pzp3U"} | None |  |
| q-6828410dde | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3Pzp3U"} | None |  |
| q-1a9c5c5df9 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3Oy3md"} | None |  |
| q-55e23f6214 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3Pz52N"} | None |  |
| q-449bc08b52 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtaokyU"} | None |  |
| q-37640d861d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtaokyU"} | None |  |
| q-ef1da33ea4 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtaokyU"} | None |  |
| q-8c9742d91d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtaokyR"} | None |  |
| q-25e9c865bb | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtaokyU"} | None |  |
| q-69170f93b9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtIR1Pn"} | None |  |
| q-1fba3c3725 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtIR1Pn"} | None |  |
| q-281d4eff4b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtIR1Pn"} | None |  |
| q-00697f4b6e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOs4A9hl"} | None |  |
| q-c3926ec179 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOs7DwuP"} | None |  |
| q-1dbd0e6487 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOoWdgoz"} | None |  |
| q-81a0cfff5e | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO1pngK-"} | None |  |
| q-b8d6c6e1bd | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO1pngIR"} | None |  |
| q-d4c8be2ef3 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3V6Jtq"} | None |  |
| q-c247613726 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO3mCkhu"} | None |  |
| q-1635e12592 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO3mCkhu"} | None |  |
| q-01b6a41c51 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO1pngJm"} | None |  |
| q-f00fe637b1 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3Q199Y"} | None |  |
| q-bba63787fa | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtjz-FD"} | None |  |
| q-a9bc44fa6c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtjz-FD"} | None |  |
| q-386a1eefe5 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO0KlA9b"} | None |  |
| q-2002d7825a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOoXemmg"} | None |  |
| q-4eeb9e3114 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3P0p0s"} | None |  |
| q-bf071b0678 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3AvzkC"} | None |  |
| q-e21f72e981 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOs4A9hu"} | None |  |
| q-87b3a08625 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOs4A9hp"} | None |  |
| q-7c758e179d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOoWeAuy"} | None |  |
| q-56e6bc77f0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOoRaEln"} | None |  |
| q-2ce1d912ca | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO1pnQLs"} | None |  |
| q-73578ec760 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO31NCqL"} | None |  |
| q-f3d9f22de2 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO31NSq9"} | None |  |
| q-cf5399d640 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO1pngK-"} | None |  |
| q-edec2e4147 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3AvzkC"} | None |  |
| q-b6b315d189 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtcqWLx"} | None |  |
| q-1cdc47f50d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtl2JQj"} | None |  |
| q-da769b5fd6 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtHRU4M"} | None |  |
| q-6dc3e66853 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO31NyoH"} | None |  |
| q-3682337639 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO3_ZDTc"} | None |  |
| q-8a33b5a60c | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO1pnQLy"} | None |  |
| q-e1512e54e8 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3AvzkC"} | None |  |
| q-9da7ae4aed | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtaokyU"} | None |  |
| q-c5ffa5da6c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtaokyR"} | None |  |
| q-af0f56bc58 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtaokyU"} | None |  |
| q-a7a9b5fcab | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtaokyR"} | None |  |
| q-cea0c8aae8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOx6IsLb"} | None |  |
| q-b7d609d56f | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO39W66U"} | None |  |
| q-a105513557 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO39W65K"} | None |  |
| q-f08677ee70 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtIR1Pn"} | None |  |
| q-00944981e9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtIR1Pn"} | None |  |
| q-a613307ef1 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO32Nwbs"} | None |  |
| q-ca15fd772a | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO31NCqM"} | None |  |
| q-609394d243 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3P0p0s"} | None |  |
| q-83d76cac39 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3P0J3m"} | None |  |
| q-726d13359c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOs7DwuP"} | None |  |
| q-2059548fbe | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOoWdgoz"} | None |  |
| q-ea5121c246 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOs4A9hl"} | None |  |
| q-0e67f89b95 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO39XK6I"} | None |  |
| q-635438cd8b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOociZfQ"} | None |  |
| q-4e95291c89 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtHRU7U"} | None |  |
| q-a0c3188f7d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtISlRo"} | None |  |
| q-8b242d2216 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3AvzkC"} | None |  |
| q-3d0801ee07 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOociZfQ"} | None |  |
| q-570325ca02 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3P0p0s"} | None |  |
| q-4229f51133 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3P0p0s"} | None |  |
| q-5300be8eca | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtao0x-"} | None |  |
| q-d65da44666 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtao0x-"} | None |  |
| q-49dbfdc2a3 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3AvzkC"} | None |  |
| q-e871bff20f | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3AvzkC"} | None |  |
| q-af13651475 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtIS1QC"} | None |  |
| q-351bd94f0c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtGQk7R"} | None |  |
| q-c54ba053cd | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOs4A9hu"} | None |  |
| q-bbcf8e461e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOokoC4V"} | None |  |
| q-ba2de80da4 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3Q03Gn"} | None |  |
| q-000ca6beaf | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO1pngKW"} | None |  |
| q-6f31402184 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO3_ZDTc"} | None |  |
| q-9458cc383f | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO3_ZDTc"} | None |  |
| q-e14636237d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtfu-5W"} | None |  |
| q-b3907f68a3 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3P0p0s"} | None |  |
| q-3ce8c1e3bd | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtao0x-"} | None |  |
| q-6816cd1cb9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtGQk7R"} | None |  |
| q-2cfd5751e1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtISlSY"} | None |  |
| q-b28d88e8ea | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtaokyU"} | None |  |
| q-93276ba868 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtaokyU"} | None |  |
| q-cb5c8b9dd2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtaokyU"} | None |  |
| q-99ac94e275 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtIR1Pn"} | None |  |
| q-514f223b35 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtIR1Pn"} | None |  |
| q-54401b3abe | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3Iwxm0"} | None |  |
| q-766a7a5b31 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO0EgbIk"} | None |  |
| q-42a6fadc62 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtYnKtJ"} | None |  |
| q-fc27873f3d | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO1pnQLs"} | None |  |
| q-0441d36c68 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3JxTei"} | None |  |
| q-7bc1c0948b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOx6IsLb"} | None |  |
| q-914916b35b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtaokyU"} | None |  |
| q-296a6139cc | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtaokyU"} | None |  |
| q-a461e3cadd | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtIR1Pn"} | None |  |
| q-0c6540b7b5 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3Pz51x"} | None |  |
| q-150036be19 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOs4A9go"} | None |  |
| q-968521c2b2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtaokyR"} | None |  |
| q-2aac9a7a33 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOs4A9hr"} | None |  |
| q-87feac6dc9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOs4A9hr"} | None |  |
| q-6108cabafb | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3P0Z28"} | None |  |
| q-d8e7a677e0 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZJWiSVpshTO03669g"} | None |  |
| q-74f1187717 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOzc__0s"} | None |  |
| q-5cfeb4f2d3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtIR1Pn"} | None |  |
| q-c444fc4b75 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtIR1Pn"} | None |  |
| q-f067421520 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtGQk7R"} | None |  |
| q-89d8f9d6fc | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOyESnYY"} | None |  |
| q-3db933968b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtftxew"} | None |  |
| q-be29cf7d60 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtfue5A"} | None |  |
| q-5adff8e53b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtdr1W2"} | None |  |
| q-c159b5a04e | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO0NmmRM"} | None |  |
| q-8cbf11ade1 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO0Gh1d1"} | None |  |
| q-ffcdb92fba | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZJWiSVpshTO2e9qSA"} | None |  |
| q-af9b5583b5 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZJWiSVpshTO037K8i"} | None |  |
| q-1b93ffec4f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOo2-WWw"} | None |  |
| q-285552a806 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOo2-WWw"} | None |  |
| q-7bf7692db6 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO1pngI8"} | None |  |
| q-c4e570ac46 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOonrxo5"} | None |  |
| q-18166ced1e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOosxQHp"} | None |  |
| q-031fe5e8ec | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtaokyR"} | None |  |
| q-f3ce870193 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtaokyU"} | None |  |
| q-99ef650d92 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtaokyR"} | None |  |
| q-0eb6e8e7d3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtIR1Pn"} | None |  |
| q-72201fe605 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtIR1Pn"} | None |  |
| q-bc0f9e3b99 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3P0J3p"} | None |  |
| q-344f80cd5e | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3AvzkC"} | None |  |
| q-b4f1f5150d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOx9LDOJ"} | None |  |
| q-ef52bbf0d9 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO0MlXTc"} | None |  |
| q-981c5fb47e | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO0MlXTc"} | None |  |
| q-97fd83f738 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO31NCrt"} | None |  |
| q-7e6547ff05 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO32OAbc"} | None |  |
| q-abf2fdd0f3 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO32OAbc"} | None |  |
| q-f563590afe | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO0MlnQk"} | ERROR |  |
| q-215ef5d720 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO39XK4T"} | None |  |
| q-96f2c66fbb | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO39XK4T"} | None |  |
| q-c8d77af577 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZJWiSVpshTO03669f"} | None |  |
| q-4ec8346a8c | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZJWiSVpshTO036q-N"} | None |  |
| q-6fc410bfe0 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO31NCrt"} | None |  |
| q-d29e333336 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO31NCrt"} | None |  |
| q-a2a7aa34ac | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZJWiSVpshTO03669f"} | None |  |
| q-602ca5e92a | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3P0p0s"} | None |  |
| q-fb97968a7e | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3P0p0s"} | None |  |
| q-3cc5f5a6a4 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtao0x-"} | None |  |
| q-56416549f1 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3Pz51j"} | None |  |
| q-dce0a9b3cc | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3Pz52j"} | None |  |
| q-3a831f11d7 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtaokyU"} | None |  |
| q-cee4ff206e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtaokyU"} | None |  |
| q-d9e9d2966f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtaokyR"} | None |  |
| q-1b34bb8978 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOociZfQ"} | None |  |
| q-74a802fac2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOociZfQ"} | None |  |
| q-dc7cfb590e | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3P0p0s"} | None |  |
| q-eba8a97d69 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3P0p0s"} | None |  |
| q-9a21d30d66 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3P0p0s"} | None |  |
| q-dde235132d | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3Pz51j"} | None |  |
| q-1c7ef19667 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3Pz52j"} | None |  |
| q-a7da8036c9 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3Pz51N"} | None |  |
| q-b43aaccbec | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtao0x-"} | None |  |
| q-fdd96e2ae4 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtao0x-"} | None |  |
| q-16757d5521 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOx-NP1p"} | None |  |
| q-e3ee954b31 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO3zLJP8"} | None |  |
| q-7ece146658 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO3zLJP8"} | None |  |
| q-b20b020e2f | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO3zLJP8"} | None |  |
| q-68ff9eb956 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZI2iSVpshTO31NCrt"} | None |  |
| q-c6fcdd11fd | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO0MlXTa"} | None |  |
| q-1b4f23a12d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOtGQk7R"} | None |  |
| q-0b1440a33b | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3IxM8t"} | None |  |
| q-9db95f97ff | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOyESnYY"} | None |  |
| q-96731295fb | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3JxTei"} | None |  |
| q-94762c7067 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOyGVFIa"} | None |  |
| q-cc09303d2b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOyBQa1A"} | None |  |
| q-a247f5dfb6 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3P0J3p"} | None |  |
| q-9d2bc130c1 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3NxokS"} | None |  |
| q-dc4593522a | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3P0p1J"} | None |  |
| q-2f8cdbb6fd | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3P0J3m"} | None |  |
| q-f8adc6287f | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3NxogH"} | None |  |
| q-8de49cbfba | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3JxTeO"} | None |  |
| q-9870314129 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3Pz52j"} | None |  |
| q-8b0bef645e | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3Pz51j"} | None |  |
| q-635ea439b8 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3P0p0s"} | None |  |
| q-0c20009d22 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOx-Nf0f"} | None |  |
| q-46b30cef6c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOx9LDOJ"} | None |  |
| q-94321f6ed9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOx5IMzm"} | None |  |
| q-8b9389f6f0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOx5IMzh"} | None |  |
| q-5e30195dc1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOoDOLr2"} | None |  |
| q-3e1cfc0f7b | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3Q03Gn"} | None |  |
| q-4121bb6fed | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZI2iSVpshTOx6JcI-"} | None |  |
| q-b60e838a26 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZJGiSVpshTO3V6Js6"} | None |  |

## Verification

Evidence items cited: 219; confirmed against the stored events: 216; rejected: 3. Each item was re-fetched with get_event; it is confirmed only if the event exists, the cited field holds the cited value, and the cited query_id is a query of this run that returned that event.
Evidence sent back to the agents for correction during the run: 16 item(s) in 9 submission(s) (one correction round each; what still failed was rejected).

## Limitations

- Findings describe what the stored logs show; activity these sources did not log cannot be seen.
- Datasets with non-overlapping time windows (see Data examined) were analysed separately.
- Long field values are shortened in this report; full events are retrievable by _index/_id.
