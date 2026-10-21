# Threat hunt report — 20261017-124403-converged-round1-b

**Hypothesis:** An adversary who compromised Windows hosts in this network stole credentials from them (MITRE ATT&CK tactic: Credential Access).

**Verdict: Confirmed** — 14 in-scope incident(s) of verified malicious findings (confidence >= medium): I01 T1003 (F08, F67), I02 T1003.001 (F01, F12, F18, F31, F61, F66), I04 T1056.001 (F59), I05 T1056.002 (F13, F65), I07 T1187 (F22), I08 T1212 (F23), I09 T1552.001 (F27, F58, F68), I12 T1552.004 (F26, F63), I14 T1555.003 (F57), I15 T1556 (F42), I16 T1557 (F46), I18 T1557.002 (F43), I21 T1649 (F56), I22 T1649 (F64)

Verdict method: rules over verified evidence (Confirmed if >=1 in-scope incident of verified malicious findings (confidence >= medium); Inconclusive if only suspicious incidents or coverage gaps; Refuted if full coverage and no malicious/suspicious finding)

| Run | Value |
|---|---|
| Profile | converged (thinking=False, temperature=0.0) |
| Model | deepseek-flash |
| Started / finished (UTC) | 2026-10-17T04:44:03+00:00 / 2026-10-17T04:54:04+00:00 (600.5 s) |
| LLM calls / tokens | 146 / {'prompt': 4030000, 'completion': 137352} |
| MCP tool calls | 1316 (server tools: list_data_sources, get_fields, search, count, aggregate, timeline, esql, get_event, get_registry) |
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
| I01 | T1003 | yes | malicious/high | F08, F67 | Sysinternals/credential tooling staged and used on scranton |
| I02 | T1003.001 | yes | malicious/high | F01, F12, F18, F31, F61, F66 | PowerShell full-access LSASS handle and remote thread on scranton (pbeesly) |
| I03 | T1003.001 | yes | suspicious/medium | F02 | Remote PowerShell LSASS access on nashua via WinRM |
| I04 | T1056.001 | yes | malicious/high | F59 | Get-Keystrokes keylogger job run on scranton |
| I05 | T1056.002 | yes | malicious/high | F13, F65 | Invoke-ScreenCapture desktop capture on scranton |
| I06 | T1111 | yes | suspicious/medium | F21 | No MFA interception; credential theft was cert export plus LSASS access |
| I07 | T1187 | yes | malicious/high | F22 | WebDAV forced authentication from 10.0.1.4 to 192.168.0.4 |
| I08 | T1212 | yes | malicious/high | F23 | PowerShell full-access handles to LSASS and winlogon on scranton |
| I09 | T1552.001 | yes | malicious/high | F27, F58, F68 | Plaintext credentials in attacker tooling and passwordsDB on scranton |
| I10 | T1552.002 | yes | suspicious/low | F28 | Winlogon registry key queried by pbeesly's powershell.exe |
| I11 | T1552.002 | yes | suspicious/medium | F60 | Registry value piped to Invoke-Expression on scranton |
| I12 | T1552.004 | yes | malicious/high | F26, F63 | Get-PrivateKeys certificate private-key export on scranton |
| I13 | T1555 | yes | suspicious/low | F62 | Vault Latest.dat touched only by lsass.exe |
| I14 | T1555.003 | yes | malicious/high | F57 | Get-PrivateKeys exported all LocalMachine certs with private keys to .pfx on scranton |
| I15 | T1556 | yes | malicious/high | F42 | Adversary activity on scranton/nashua is credential theft and exfiltration, not authentication-process modification |
| I16 | T1557 | yes | malicious/medium | F46 | Adversary-in-the-middle position on the 10.0.1.0/24 segment evidenced by MAC/IP mismatch; Windows-side netsh/arp hits are benign Azure telem… |
| I17 | T1557.001 | yes | suspicious/low | F44 | NBT-NS/LLMNR name resolution for SCRANTON/NASHUA broadcast unanswered by any host; SMB auth traffic to 10.0.0.4/10.0.1.6 intercepted by the … |
| I18 | T1557.002 | yes | malicious/medium | F43 | Single non-vendor MAC 12:34:56:78:9a:bc answers for four distinct IPs on the 10.0.1.0/24 segment (ARP cache poisoning / AiTM position) |
| I19 | T1558 | yes | suspicious/medium | F47 | Compromised host scranton.dmevals.local: PowerShell opened LSASS with full access during a multi-stage intrusion, but no Kerberos ticket the… |
| I20 | T1606 | yes | suspicious/medium | F52 | No forged web credential activity; observed credential access is LSASS memory access and Credential Manager enumeration by pbeesly |
| I21 | T1649 | yes | malicious/high | F56 | Get-PrivateKeys PowerShell script exported all LocalMachine certificates with private keys to a password-protected .pfx on scranton.dmevals.… |
| I22 | T1649 | yes | malicious/high | F64 | Certificate private keys exported to .pfx on scranton |
| I23 | out-of-scope:T1071 | no | suspicious/medium | F11 | PsExec-delivered python.exe C2 client on nashua (not sniffing) |

## Findings

### F08 · malicious / high · T1003 · Credential-access tooling staged on scranton by pbeesly (Sysinternals suite, accesschk, sdelete) alongside LSASS access

Evidence status: **verified**

On scranton.dmevals.local the account pbeesly ran a hands-on-keyboard intrusion between 02:56 and 03:07 UTC: SysinternalsSuite.zip was expanded and moved to C:\Program Files\SysinternalsSuite, accesschk.exe was executed, Invoke-Discovery, Invoke-Persistence (steps 1 and 2) and Get-PrivateKeys were invoked, screenshots and clipboard were captured, and sdelete64.exe was used to wipe C:\programdata\victim\???cod.3aka3.scr, $env:APPDATA\Draft.Zip and the SysinternalsSuite.zip. The same session produced the full-access LSASS handle requests at 03:05:16. The 4673 events show the malicious C:\ProgramData\victim\...scr and PowerShell using SeProfileSingleProcessPrivilege/SeTcbPrivilege. This is attacker credential-access activity, not normal system behaviour.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:00:25.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | Expand-Archive -LiteralPath "$env:USERPROFILE\Downloads\SysinternalsSuite.zip" -DestinationPath "$env:USERPROFILE\Downloads\" | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMAWIxZm | q-fe0d76f87d | ok |
| 2 | 2020-05-02 03:02:04.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | .\sdelete64.exe /accepteula "C:\programdata\victim\???cod.3aka3.scr" | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMAQDVrD | q-158ef807ee | ok |
| 3 | 2020-05-02 03:04:15.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | Invoke-Persistence -PersistStep 1 | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMAQDVp0 | q-158ef807ee | ok |
| 4 | 2020-05-02 02:55:56.000Z | scranton.dmevals.local | windows.security | process.executable | C:\ProgramData\victim\â€®cod.3aka3.scr | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL9Typob | q-5fd8b39104 | ok |
| 5 | 2020-05-02 03:04:34.951Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\Program Files\SysinternalsSuite\accessChk.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63C9mZ | q-e6686a994e | ok |

### F67 · malicious / high · T1003 · Credential-access tooling staged on scranton

Evidence status: **verified**

SysinternalsSuite staged and used (accesschk, sdelete64, PsExec64) by pbeesly's PowerShell.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:34.951Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\accesschk.exe" | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63C9mZ | q-9e4f3772eb | ok |

### F01 · malicious / high · T1003.001 · PowerShell.exe on scranton opened lsass.exe with full-access masks (0x1F3FFF / 0x1FFFFF) under user pbeesly

Evidence status: **verified**

On 2020-05-02 at 03:05:16 UTC, PowerShell.exe (PID 2976) on scranton.dmevals.local opened lsass.exe (PID 736) twice within 31 ms with GrantedAccess 0x1F3FFF and 0x1FFFFF — PROCESS_ALL_ACCESS-style rights used for LSASS memory dumping, not the benign 0x1000/0x1400 query rights that dominate the 326 lsass access events. The security log independently records the same handle requests (4656, AccessMask 0x1fffff and 0x1f3fff, SubjectUserName pbeesly) plus a 4663 read (AccessMask 0x10) on \Device\HarddiskVolume2\Windows\System32\lsass.exe. This occurred in the middle of a hands-on-keyboard intrusion by pbeesly on scranton: SysinternalsSuite was unzipped and moved to C:\Program Files\SysinternalsSuite, accesschk.exe was run, Invoke-Discovery / Invoke-Persistence / Get-PrivateKeys were executed, and sdelete64 was used to wipe files. No .dmp file was written to disk in the window, so the dump may have been held in memory or the write was not captured.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63CNnH | q-80adfe1b1f | ok |
| 2 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63CAlf | q-80adfe1b1f | ok |
| 3 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.TargetImage | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63CNnH | q-74381dff60 | ok |
| 4 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | win.AccessMask | 0x1fffff | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL9MpvMw | q-1acfd30602 | ok |
| 5 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | win.SubjectUserName | pbeesly | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL9Qtr32 | q-1acfd30602 | ok |
| 6 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | win.ObjectName | \Device\HarddiskVolume2\Windows\System32\lsass.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL9Qt70r | q-1acfd30602 | ok |
| 7 | 2020-05-02 03:04:34.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | &amp; "C:\Program Files\SysinternalsSuite\accesschk.exe" | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMAQDVp3 | q-158ef807ee | ok |
| 8 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | Get-PrivateKeys | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMAQC1ns | q-158ef807ee | ok |

### F61 · malicious / medium · T1003.001 · Extra LSASS read by pbeesly's powershell.exe on scranton

Evidence status: **verified**

4656/4663 on lsass.exe by powershell.exe as pbeesly at 03:05:16Z; later LSASS/SAM handles are lsass/MsMpEng/CollectGuestLogs under SCRANTON$.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | win.ProcessName | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL9Qt70r | q-59711b7717 | ok |
| 2 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | event.code | 4656 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL9MpvMw | q-59711b7717 | ok |

### F59 · malicious / high · T1056.001 · Get-Keystrokes keylogger job run on scranton

Evidence status: **verified**

pbeesly's PowerShell started, viewed and removed a Keystrokes job at 03:06:59-03:07:49Z after AV enumeration.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:06:59.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | Get-Keystrokes;Start-Sleep -Seconds 15;View-Job -JobName "Keystrokes" | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMAQDFlH | q-5c9377b55e | ok |
| 2 | 2020-05-02 03:06:47.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Keystroke-Check {     Get-Process \| Where-Object { $_.ProcessName -Eq "avp" -or $_.ProcessName -Eq "acs" -or $_.ProcessName -Eq "outpost" -or $_.Proce… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMAQC1lL | q-9ad9ea5b5f | ok |

### F13 · malicious / medium · T1056.002 · Invoke-ScreenCapture PowerShell function repeatedly captured the desktop on scranton.dmevals.local

Evidence status: **verified**

On scranton.dmevals.local, PowerShell script block b91c2ae7-3a03-49df-8d2a-4c42fc79df56 (EventID 4104, user pbeesly, path C:\Program Files\SysinternalsSuite\psversion.ps1, 2020-05-02T03:05:53Z) defines function Invoke-ScreenCapture, which starts a background job looping forever, uses System.Windows.Forms/System.Drawing CopyFromScreen to grab the full virtual screen and saves each capture as a random-named .bmp in $env:USERPROFILE\Downloads every 300 seconds. A second script block (0365cb7f-22ef-47e4-ad96-230ddc962939, 03:05:59Z) contains the same System.Windows.Forms/System.Drawing screen-capture body. This is GUI input/screen capture of the user's desktop, collected into the same Downloads folder that the Invoke-Exfil function later archives and uploads to \\192.168.0.4\webdav. No fake credential prompt was observed: the only credential/consent command-line hits were three legitimate consent.exe process creations.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:53.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-ScreenCapture # https://www.pdq.com/blog/capturing-screenshots-with-powershell-and-net/ {     Start-Job -Name "Screenshot" -ScriptBlock {       … | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMAQC1kD | q-34a5f9e721 | ok |
| 2 | 2020-05-02 03:05:53.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\psversion.ps1 | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMAQC1kD | q-34a5f9e721 | ok |
| 3 | 2020-05-02 03:05:53.000Z | scranton.dmevals.local | windows.powershell | user.name | pbeesly | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMAQC1kD | q-34a5f9e721 | ok |
| 4 | 2020-05-02 03:05:59.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockId | 0365cb7f-22ef-47e4-ad96-230ddc962939 | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMAQC1lG | q-21b7b0d026 | ok |

### F65 · malicious / high · T1056.002 · Invoke-ScreenCapture job on scranton

Evidence status: **verified**

Screenshot job started at 03:05:53Z and removed at 03:07:54Z by pbeesly's PowerShell.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:53.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | Invoke-ScreenCapture;Start-Sleep -Seconds 3;View-Job -JobName "Screenshot" | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMAQC1mC | q-c3d74b0f04 | ok |

### F12 · malicious / high · T1056.004 · PowerShell opened a full-access handle to lsass.exe and created a remote thread in it on scranton.dmevals.local

Evidence status: **verified**

On 2020-05-02 at 03:05:16.623Z on scranton.dmevals.local, PowerShell.exe (PID 2976, process GUID {47ab858c-e1e4-5eac-b803-000000000400}) opened lsass.exe (PID 736) with GrantedAccess 0x1F3FFF and a CallTrace ending in UNKNOWN(000001996D252982) — i.e. code not backed by a known module. In the same second a second handle with GrantedAccess 0x1fffff was taken, and Sysmon EventID 8 recorded a CreateRemoteThread from that same PowerShell PID into lsass.exe (NewThreadId 912, StartAddress 0x00000117610E0000, StartModule '-', StartFunction '-'). Full-access process handles plus an unbacked remote thread in lsass is the classic credential-API-hooking / in-memory credential theft pattern. This PowerShell activity sits in the same session as the attacker tooling on the host: user pbeesly's script blocks in C:\Program Files\SysinternalsSuite\psversion.ps1 include Invoke-ScreenCapture (03:05:53) and Invoke-Exfil, which compresses the Downloads folder with password 'lolol' and copies it to \\192.168.0.4\webdav using hardcoded credentials (03:08:02). By contrast, the other lsass handles in the dataset are benign: svchost.exe via lsm.dll (0x101001), wininit/csrss (0x1fffff, basesrv/CSRSRV), WindowsAzureTelemetryService.exe and AntimalwareConfig.exe via CorperfmonExt.dll (0x1400), and a csrss.exe CreateRemoteThread into lsass whose StartFunction is CtrlRoutine in KERNELBASE.dll (console control, benign).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63CNnH | q-7a35883950 | ok |
| 2 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.CallTrace | C:\windows\SYSTEM32\ntdll.dll+9c584\|C:\windows\System32\KERNELBASE.dll+2732e\|UNKNOWN(000001996D252982) | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63CNnH | q-7a35883950 | ok |
| 3 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.StartModule | - | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63CNnI | q-20a7055954 | ok |
| 4 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.SourceImage | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63CNnI | q-20a7055954 | ok |
| 5 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.TargetImage | C:\Windows\System32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63CNnI | q-20a7055954 | ok |
| 6 | 2020-05-02 03:18:34.813Z | scranton.dmevals.local | windows.sysmon | win.StartFunction | CtrlRoutine | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2PTHqc | q-2de84ed164 | ok |
| 7 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\psversion.ps1 | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JL8F_6E7 | q-5479a9d4b9 | ok |

### F66 · malicious / medium · T1056.004 · LSASS handle and remote thread on scranton

Evidence status: **verified**

Anchored LSASS handle/remote-thread activity; no new instances beyond the anchor.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | win.ObjectName | \Device\HarddiskVolume2\Windows\System32\lsass.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL9Qt70r | q-59711b7717 | ok |

### F18 · malicious / high · T1110.002 · Credential dumping on scranton: hidden-window PowerShell stager opened lsass with full access (0x1FFFFF)

Evidence status: **verified**

On scranton.dmevals.local, PID 2976 was created at 2020-05-02T02:58:44Z as powershell.exe running with -noni -noexit -ep bypass -window hidden and an encoded command that decodes a System.Drawing bitmap from C:\Users\pbeesly\Downloads\monkey.png and IEXes the extracted bytes (steganographic loader), under user pbeesly. At 2020-05-02T03:05:16.623Z and 03:05:16.654Z that same process (SourceProcessId 2976, SourceImage C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe) opened a handle to C:\windows\system32\lsass.exe (TargetProcessId 736) with GrantedAccess 0x1F3FFF and then 0x1FFFFF — full-access PROCESS_ALL_ACCESS, the access pattern used to read lsass memory and extract credentials/hashes for offline cracking. This is the only PowerShell-to-lsass access in the dataset with such access rights; the other 322 lsass accesses are svchost.exe/Azure telemetry agents with 0x1000/0x1400. In the same session pbeesly also ran Get-PrivateKeys (exporting all LocalMachine certificates to .pfx with password 'saribas') and Invoke-Exfil (7-Zip of the Downloads folder to %APPDATA%\OfficeSupplies.7z), and made repeated 4648 explicit-credential logons to nashua.dmevals.local via C:\Windows\PSEXESVC.exe. The 4656 handle requests on SAM/SECURITY/ntds.dit objects were all issued by lsass.exe itself (10 events), i.e. normal, and the 3 file-creation hits for *SECURITY* were only Prefetch files for SecurityHealthHost/Service/Systray — no hive or ntds.dit copy was observed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63CAlf | q-59aaf14d2e | ok |
| 2 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.TargetImage | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63CAlf | q-59aaf14d2e | ok |
| 3 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63CAlf | q-59aaf14d2e | ok |
| 4 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63CNnH | q-ebfb62ae4b | ok |
| 5 | 2020-05-02 02:58:44.325Z | scranton.dmevals.local | windows.sysmon | process.command_line | "PowerShell.exe" -noni -noexit -ep bypass -window hidden -c "sal a New-Object;Add-Type -AssemblyName 'System.Drawing'; $g=a System.Drawing.Bitmap('C:\Users\pbee… | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL7ViMbT | q-dfcb5da3fc | ok |
| 6 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\readme.ps1 | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMAQC1mz | q-80759f4c6b | ok |

### F22 · malicious / high · T1187 · WebDAV forced authentication from 10.0.1.4 to 192.168.0.4 after SMB fallback (DavClnt / Microsoft-WebDAV-MiniRedir)

Evidence status: **verified**

In the Zeek window (2020-04-30 00:32:14–00:35:25Z), host 10.0.1.4 attempted SMB to 192.168.0.4 on TCP 445 and 139 ten times, all rejected (conn_state REJ, 0 bytes). It then immediately switched to HTTP on port 80 to the same host, where the client identified itself as 'DavClnt' (OPTIONS /, 403) and then 'Microsoft-WebDAV-MiniRedir/10.0.18362' for 61 requests. The WebDAV session shows the classic forced-authentication handshake: repeated PROPFIND to /webdav and /webdav/ answered with 401 challenges followed by 207 Multi-Status, then PROPFIND/PUT/LOCK/PROPPATCH/UNLOCK against a lure file '/webdav/OfficeSupplies.7z' (PUT 201/204, LOCK 200, PROPPATCH 207, UNLOCK 204). The 401-then-success pattern on each method is the server soliciting NTLM credentials from the Windows WebClient service, i.e. the victim host being coerced into authenticating to an attacker-controlled WebDAV server. All 62 HTTP requests in the dataset went to 192.168.0.4 and 61 of 62 used the WebDAV MiniRedir user agent, so this is not normal browsing traffic. The Windows-side SMB connections in the 2020-05-02 window are unrelated: all 66 Sysmon event.code 3 records on 445/139 come from process.executable 'System' (SYSTEM) to internal hosts 10.0.0.4 and a link-local IPv6 address, consistent with normal domain controller traffic. No .scf/.url/.library-ms lure files were created; the only .lnk creations were Explorer writing Recent shortcuts for pbeesly and a powershell.exe-created hostui.lnk in the StartUp folder on scranton.dmevals.local, which is persistence rather than forced authentication.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-04-30 00:32:14.891Z | simplerockbuild.simplerock.lan | zeek | zeek.conn_state | REJ | .ds-logs-zeek-default-2026.10.17-000001 / AaFIKqWOc7y0JMDGKA0a | q-123afbd815 | ok |
| 2 | 2020-04-30 00:32:14.891Z | simplerockbuild.simplerock.lan | zeek | destination.port | 445 | .ds-logs-zeek-default-2026.10.17-000001 / AaFIKqWOc7y0JMDGKA0a | q-123afbd815 | ok |
| 3 | 2020-04-30 00:32:18.094Z | simplerockbuild.simplerock.lan | zeek | destination.port | 80 | .ds-logs-zeek-default-2026.10.17-000001 / AaFIKqWOc7y0JMDGKA0F | q-123afbd815 | ok |
| 4 | 2020-04-30 00:32:18.095Z | simplerockbuild.simplerock.lan | zeek | user_agent.original | DavClnt | .ds-logs-zeek-default-2026.10.17-000001 / AaFIKqWOc7y0JMDGKA5C | q-b910d9f8af | ok |
| 5 | 2020-04-30 00:32:18.095Z | simplerockbuild.simplerock.lan | zeek | http.request.method | OPTIONS | .ds-logs-zeek-default-2026.10.17-000001 / AaFIKqWOc7y0JMDGKA5C | q-b910d9f8af | ok |
| 6 | 2020-04-30 00:32:21.533Z | simplerockbuild.simplerock.lan | zeek | user_agent.original | Microsoft-WebDAV-MiniRedir/10.0.18362 | .ds-logs-zeek-default-2026.10.17-000001 / AaFIKqWOc7y0JMDGKA5H | q-3651ac9dc9 | ok |
| 7 | 2020-04-30 00:32:21.533Z | simplerockbuild.simplerock.lan | zeek | http.response.status_code | 401 | .ds-logs-zeek-default-2026.10.17-000001 / AaFIKqWOc7y0JMDGKA5H | q-3651ac9dc9 | ok |
| 8 | 2020-04-30 00:32:21.538Z | simplerockbuild.simplerock.lan | zeek | http.response.status_code | 207 | .ds-logs-zeek-default-2026.10.17-000001 / AaFIKqWOc7y0JMDGKA5D | q-3651ac9dc9 | ok |
| 9 | 2020-04-30 00:32:21.895Z | simplerockbuild.simplerock.lan | zeek | url.original | /webdav/OfficeSupplies.7z | .ds-logs-zeek-default-2026.10.17-000001 / AaFIKqWOc7y0JMDGKA5I | q-3651ac9dc9 | ok |
| 10 | 2020-04-30 00:32:21.918Z | simplerockbuild.simplerock.lan | zeek | http.request.method | PUT | .ds-logs-zeek-default-2026.10.17-000001 / AaFIKqWOc7y0JMDGJw2G | q-993b01730d | ok |
| 11 | 2020-04-30 00:32:21.918Z | simplerockbuild.simplerock.lan | zeek | http.response.status_code | 201 | .ds-logs-zeek-default-2026.10.17-000001 / AaFIKqWOc7y0JMDGJw2G | q-993b01730d | ok |
| 12 | 2020-04-30 00:32:21.923Z | simplerockbuild.simplerock.lan | zeek | http.request.method | LOCK | .ds-logs-zeek-default-2026.10.17-000001 / AaFIKqWOc7y0JMDGKA5L | q-993b01730d | ok |
| 13 | 2020-04-30 00:32:21.944Z | simplerockbuild.simplerock.lan | zeek | http.request.method | UNLOCK | .ds-logs-zeek-default-2026.10.17-000001 / AaFIKqWOc7y0JMDGKA09 | q-993b01730d | ok |
| 14 | 2020-05-02 03:01:43.033Z | scranton.dmevals.local | windows.sysmon | process.executable | System | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL69HyZX | q-53a5728dd4 | ok |
| 15 | 2020-05-02 03:04:23.681Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\hostui.lnk | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL64D_f9 | q-1f9b0f229e | ok |

### F23 · malicious / high · T1212 · PowerShell on SCRANTON opened LSASS and winlogon with full-access masks (0x1FFFFF/0x1F3FFF) during a pbeesly intrusion chain

Evidence status: **verified**

On scranton.dmevals.local the user pbeesly ran a hands-on-keyboard PowerShell intrusion: a malicious screen-saver C:\ProgramData\victim\cod.3aka3.scr launched from explorer.exe spawned cmd.exe/powershell.exe, followed by Invoke-Discovery, Invoke-Persistence, Invoke-ScreenCapture, Invoke-Exfil (7-Zip archive with password 'lolol'), sdelete64.exe wiping artifacts, and Invoke-SeaDukeStage -ComputerName NASHUA. At 2020-05-02T03:05:16 PowerShell.exe (PID 2976) opened lsass.exe with GrantedAccess 0x1f3fff and then 0x1fffff, and in the same second opened winlogon.exe, LogonUI.exe, dwm.exe and multiple svchost.exe with 0x1fffff — a full-access credential-theft pattern (LSASS + interactive logon session memory) with an UNKNOWN call-trace module, not a signed security product. This is the credential-access step of the intrusion, immediately preceding lateral movement to NASHUA (wsmprovhost.exe on nashua opened lsass.exe with 0x1f3fff at 03:09:29 after pbeesly's Kerberos logon and SeDebugPrivilege 4672 events).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63CAlf | q-de5fe238e6 | ok |
| 2 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63CAlf | q-a58de6d9b1 | ok |
| 3 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.CallTrace | C:\windows\SYSTEM32\ntdll.dll+9c584\|C:\windows\System32\KERNELBASE.dll+2732e\|UNKNOWN(000001996D28200D) | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63CAlf | q-a58de6d9b1 | ok |
| 4 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.TargetImage | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63CNnH | q-6e4947cbf4 | ok |
| 5 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.TargetImage | C:\windows\system32\winlogon.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63CNnJ | q-6e4947cbf4 | ok |
| 6 | 2020-05-02 03:05:16.920Z | scranton.dmevals.local | windows.sysmon | win.TargetImage | C:\windows\system32\LogonUI.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63CAlm | q-6e4947cbf4 | ok |
| 7 | 2020-05-02 02:55:56.157Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\ProgramData\victim\â€®cod.3aka3.scr | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL7am0gN | q-591e0e85c1 | ok |
| 8 | 2020-05-02 03:10:22.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | Invoke-SeaDukeStage -ComputerName NASHUA | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMAOBExi | q-98bd6c2af2 | ok |
| 9 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2kp9uH | q-502efe9fc7 | ok |
| 10 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2kp9uH | q-502efe9fc7 | ok |

### F68 · malicious / high · T1552 · Unsecured credentials in attacker scripts and files

Evidence status: **verified**

Plaintext passwords in PowerShell tooling and passwordsDB file on scranton.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JL8F_6E7 | q-dd2ff714df | ok |

### F27 · malicious / medium · T1552.001 · Hardcoded plaintext credentials in PowerShell tooling and a passwordsDB file created by accesschk on scranton

Evidence status: **verified**

The same pbeesly PowerShell toolset on scranton.dmevals.local contains plaintext credentials embedded in script files: Get-PrivateKeys uses ConvertTo-SecureString -String "saribas" -AsPlainText, and Invoke-Exfil (script block b2b03a9c-43f0-4285-837d-f22d4600b2ae, loaded from C:\Program Files\SysinternalsSuite\psversion.ps1, 2020-05-02T03:08:02Z) builds a PSCredential for user "cozy" from the plaintext password "MyCozyPassw0rd!" and uses it to map \\192.168.0.4\webdav. Separately, at 03:04:34Z accesschk.exe was launched by pbeesly from C:\Program Files\SysinternalsSuite and at 03:04:35Z created the file C:\Program Files\SysinternalsSuite\passwordsDB — a credential-dump artifact name in a tool directory. The nuget.config creation at 03:08:31Z is a benign side effect of Install-Module 7Zip4Powershell. The 4648 explicit-credential logons for pbeesly (scranton -> NASHUA, and PSEXESVC on nashua) show the account being used with explicit credentials across hosts, consistent with harvested-credential reuse.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JL8F_6E7 | q-ee2771e7b9 | ok |
| 2 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\psversion.ps1 | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JL8F_6E7 | q-ee2771e7b9 | ok |
| 3 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMAQC1mz | q-8611178647 | ok |
| 4 | 2020-05-02 03:04:35.069Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Program Files\SysinternalsSuite\passwordsDB | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63C9mM | q-33af71c7ec | ok |
| 5 | 2020-05-02 03:04:34.951Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\accesschk.exe" | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63C9mZ | q-ae10894f5b | ok |
| 6 | 2020-05-02 03:11:40.000Z | nashua.dmevals.local | windows.security | win.ProcessName | C:\Windows\PSEXESVC.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL9OrXFR | q-350e6d4fdb | ok |

### F58 · malicious / high · T1552.001 · accesschk wrote passwordsDB; tooling holds plaintext credentials

Evidence status: **verified**

accesschk.exe created passwordsDB on scranton and scripts embed saribas, Fl0nk3rt0n!T0by and MyCozyPassw0rd!.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:35.069Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Program Files\SysinternalsSuite\passwordsDB | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63C9mM | q-aba201af42 | ok |
| 2 | 2020-05-02 03:11:18.784Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\PsExec64.exe" -accepteula \\NASHUA -u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2ioON3 | q-9e4f3772eb | ok |

### F26 · malicious / high · T1552.004 · Get-PrivateKeys PowerShell function exported all LocalMachine certificates to .pfx files on scranton

Evidence status: **verified**

On scranton.dmevals.local, user pbeesly (SID ...-1107) ran a PowerShell script block named Get-PrivateKeys at 2020-05-02T03:04:56Z (record 10494, script block 9d153741-75c3-4062-afe3-aeca0aee611b, loaded from C:\Program Files\SysinternalsSuite\readme.ps1). The function enumerates cert:\LocalMachine recursively and calls Export-PfxCertificate for every certificate with a thumbprint, writing each to $env:USERPROFILE\Downloads\<random>.pfx protected by the hardcoded plaintext password "saribas". One second later Sysmon recorded powershell.exe (PID 3876) creating C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx, confirming the export actually executed. This is deliberate private-key/certificate harvesting for later credential use, part of a broader offensive toolset on the same host (Invoke-Discovery, Invoke-Exfil).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMAQC1mz | q-8611178647 | ok |
| 2 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\readme.ps1 | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMAQC1mz | q-8611178647 | ok |
| 3 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | user.name | pbeesly | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMAQC1mz | q-8611178647 | ok |
| 4 | 2020-05-02 03:04:57.460Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63CdmD | q-33af71c7ec | ok |
| 5 | 2020-05-02 03:04:57.460Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\WindowsPowerShell\v1.0\powershell.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63CdmD | q-33af71c7ec | ok |

### F63 · malicious / high · T1552.004 · Certificate private keys exported to .pfx on scranton

Evidence status: **verified**

Get-PrivateKeys executed and the .pfx landed in Downloads.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | Get-PrivateKeys | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMAQC1ns | q-c3d74b0f04 | ok |

### F57 · malicious / high · T1555.003 · Get-PrivateKeys exported all LocalMachine certs with private keys to .pfx on scranton

Evidence status: **verified**

pbeesly's powershell.exe ran Get-PrivateKeys from SysinternalsSuite\readme.ps1 at 03:04:56Z and wrote coyn5igj.3io.pfx to Downloads.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMAQC1mz | q-a551aac8a5 | ok |
| 2 | 2020-05-02 03:04:57.460Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63CdmD | q-aba201af42 | ok |

### F42 · malicious / high · T1556 · Adversary activity on scranton/nashua is credential theft and exfiltration, not authentication-process modification

Evidence status: **verified**

On scranton.dmevals.local, user pbeesly, a hidden PowerShell (PID 2976, launched by control.exe /name Microsoft.BackupAndRestoreCenter at 02:58:44) decoded a steganographic payload from C:\Users\pbeesly\Downloads\monkey.png and IEX'd it; the same session later opened lsass.exe with GrantedAccess 0x1FFFFF (03:05:16) and ran Invoke-Exfil (script block b2b03a9c, 03:08:02) which 7-Zips the Downloads folder with password 'lolol' and copies it to \\192.168.0.4\webdav using hardcoded credentials. At 03:09:23 pbeesly ran Invoke-Command against NASHUA, spawning wsmprovhost.exe (PID 7720) which accessed nashua's lsass with 0x1F3FFF at 03:09:29. This is credential access/exfiltration (T1003/T1048), not T1556 — no authentication process, password filter, MFA, hybrid identity or network provider configuration was modified.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:58:44.325Z | scranton.dmevals.local | windows.sysmon | process.command_line | "PowerShell.exe" -noni -noexit -ep bypass -window hidden -c "sal a New-Object;Add-Type -AssemblyName 'System.Drawing'; $g=a System.Drawing.Bitmap('C:\Users\pbee… | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL7ViMbT | q-027a69ba28 | ok |
| 2 | 2020-05-02 02:58:44.325Z | scranton.dmevals.local | windows.sysmon | process.parent.executable | C:\Windows\System32\control.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL7ViMbT | q-027a69ba28 | ok |
| 3 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JL8F_6E7 | q-d1aa24ced5 | ok |
| 4 | 2020-05-02 03:09:23.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | Invoke-Command -ComputerName NASHUA -ScriptBlock { Get-Process -IncludeUserName \| Select-Object UserName,SessionId \| Where-Object { $_.UserName -like "*\$env:… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMAOAxHj | q-70f497d366 | ok |
| 5 | 2020-05-02 03:09:23.885Z | nashua.dmevals.local | windows.sysmon | process.command_line | C:\windows\system32\wsmprovhost.exe -Embedding | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2kqds5 | q-d72d7d841a | ok |

### F46 · malicious / medium · T1557 · Adversary-in-the-middle position on the 10.0.1.0/24 segment evidenced by MAC/IP mismatch; Windows-side netsh/arp hits are benign Azure telemetry

Evidence status: **verified**

The zeek capture shows an on-path device: MAC 12:34:56:78:9a:bc is the responder for 10.0.0.4 (66 flows from 10.0.1.4, 54 from 10.0.1.6), 10.0.1.6 (44 flows from 10.0.1.4), 192.168.0.4 (376 flows from 10.0.1.6, 16 from 10.0.1.4) and 192.168.0.5 (3 flows), while the genuine hosts use 00:0d:3a:13:e3:69 and 00:0d:3a:4d:42:f2. The intercepted traffic is SMB/gssapi/kerberos, i.e. credential-bearing authentication, matching the credential-access hypothesis. On the Windows side the only arp/netsh/ipconfig executions (scranton.dmevals.local, 2020-05-02 03:19-03:20) are children of Azure guest-agent and Network Watcher binaries and are benign; the poisoning host is not among the monitored Windows hosts.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-04-30 00:40:22.431Z | simplerockbuild.simplerock.lan | zeek | zeek.resp_l2_addr | 12:34:56:78:9a:bc | .ds-logs-zeek-default-2026.10.17-000001 / AaFIKqWOc7y0JMDGKA6t | q-ddbb0471a4 | ok |
| 2 | 2020-04-30 00:40:22.431Z | simplerockbuild.simplerock.lan | zeek | zeek.orig_l2_addr | 00:0d:3a:4d:42:f2 | .ds-logs-zeek-default-2026.10.17-000001 / AaFIKqWOc7y0JMDGKA6t | q-ddbb0471a4 | ok |
| 3 | 2020-04-30 00:36:40.048Z | bobs.bigwheel.local | zeek | zeek.orig_l2_addr | 00:0d:3a:13:e3:69 | .ds-logs-zeek-default-2026.10.17-000001 / AaFIK6WOc7y0JMA_NKaA | q-31a3605606 | ok |
| 4 | 2020-04-30 00:36:40.048Z | bobs.bigwheel.local | zeek | zeek.resp_l2_addr | 12:34:56:78:9a:bc | .ds-logs-zeek-default-2026.10.17-000001 / AaFIK6WOc7y0JMA_NKaA | q-31a3605606 | ok |
| 5 | 2020-04-30 00:32:17.069Z | simplerockbuild.simplerock.lan | zeek | zeek.resp_l2_addr | 12:34:56:78:9a:bc | .ds-logs-zeek-default-2026.10.17-000001 / AaFIKqWOc7y0JMDGKA0H | q-31a3605606 | ok |
| 6 | 2020-05-02 03:19:25.370Z | scranton.dmevals.local | windows.sysmon | process.parent.executable | C:\WindowsAzure\Packages\GuestAgent\WindowsAzureGuestAgent.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2IKpDz | q-53c7fb79bc | ok |

### F43 · malicious / medium · T1557.002 · Single non-vendor MAC 12:34:56:78:9a:bc answers for four distinct IPs on the 10.0.1.0/24 segment (ARP cache poisoning / AiTM position)

Evidence status: **verified**

In the zeek capture (2020-04-30 00:06-00:45, observer simplerockbuild.simplerock.lan) every connection from 10.0.1.4 and 10.0.1.6 to 10.0.0.4, 10.0.1.6, 192.168.0.4 and 192.168.0.5 is answered by the same layer-2 address 12:34:56:78:9a:bc, while the legitimate hosts use vendor MACs 00:0d:3a:13:e3:69 and 00:0d:3a:4d:42:f2. One MAC claiming four different IPs is the signature of ARP cache poisoning placing the attacker on-path. The flows are SMB (445) with gssapi/krb service and RSTO state, i.e. authentication traffic being intercepted. No arpspoof/responder tooling was seen on the Windows hosts (windows.sysmon arp/netsh hits are Azure guest-agent telemetry), so the poisoning host itself is not visible in the Windows datasets.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-04-30 00:40:22.431Z | simplerockbuild.simplerock.lan | zeek | zeek.resp_l2_addr | 12:34:56:78:9a:bc | .ds-logs-zeek-default-2026.10.17-000001 / AaFIKqWOc7y0JMDGKA6t | q-ddbb0471a4 | ok |
| 2 | 2020-04-30 00:40:22.431Z | simplerockbuild.simplerock.lan | zeek | zeek.id_resp_h | 10.0.1.6 | .ds-logs-zeek-default-2026.10.17-000001 / AaFIKqWOc7y0JMDGKA6t | q-ddbb0471a4 | ok |
| 3 | 2020-04-30 00:40:22.431Z | simplerockbuild.simplerock.lan | zeek | zeek.service | gssapi | .ds-logs-zeek-default-2026.10.17-000001 / AaFIKqWOc7y0JMDGKA6t | q-ddbb0471a4 | ok |
| 4 | 2020-04-30 00:36:40.048Z | bobs.bigwheel.local | zeek | zeek.resp_l2_addr | 12:34:56:78:9a:bc | .ds-logs-zeek-default-2026.10.17-000001 / AaFIK6WOc7y0JMA_NKaA | q-31a3605606 | ok |
| 5 | 2020-04-30 00:36:40.048Z | bobs.bigwheel.local | zeek | destination.ip | 10.0.0.4 | .ds-logs-zeek-default-2026.10.17-000001 / AaFIK6WOc7y0JMA_NKaA | q-31a3605606 | ok |
| 6 | 2020-04-30 00:32:17.069Z | simplerockbuild.simplerock.lan | zeek | destination.ip | 192.168.0.4 | .ds-logs-zeek-default-2026.10.17-000001 / AaFIKqWOc7y0JMDGKA0H | q-31a3605606 | ok |
| 7 | 2020-04-30 00:32:17.069Z | simplerockbuild.simplerock.lan | zeek | zeek.resp_l2_addr | 12:34:56:78:9a:bc | .ds-logs-zeek-default-2026.10.17-000001 / AaFIKqWOc7y0JMDGKA0H | q-31a3605606 | ok |

### F56 · malicious / high · T1649 · Get-PrivateKeys PowerShell script exported all LocalMachine certificates with private keys to a password-protected .pfx on scranton.dmevals.local

Evidence status: **verified**

On scranton.dmevals.local, user pbeesly executed a malicious screen saver C:\ProgramData\victim\...cod.3aka3.scr (launched by explorer.exe at 02:55:56Z) which spawned cmd.exe and powershell.exe. The chain used sdclt.exe -> control.exe (UAC bypass) to run a hidden, -ep bypass PowerShell that decoded a payload from C:\Users\pbeesly\Downloads\monkey.png via System.Drawing and IEX'd it, then downloaded/extracted SysinternalsSuite.zip. At 03:04:56Z a PowerShell 4104 scriptblock (ScriptBlock ID 9d153741-75c3-4062-afe3-aeca0aee611b, Path C:\Program Files\SysinternalsSuite\readme.ps1) defined function Get-PrivateKeys: it enumerates cert:\LocalMachine recursively and calls Export-PfxCertificate for every certificate with a thumbprint into $env:USERPROFILE\Downloads\<random>.pfx, protected by the hardcoded password 'saribas'. Sysmon shows the resulting file C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx created at 03:04:57Z by powershell.exe, with matching registry reads of the MY and Remote Desktop certificate stores (HKLM\SOFTWARE\Microsoft\SystemCertificates\MY\Certificates\48B5E43D09D080DF8863152FD22ED7C43443D499\Blob) at the same second, and the .pfx deleted by powershell.exe at 03:08:51Z (SHA256 F33BEEBFBFF89C1A8E51AD688CDDB1A972EDD5444380B93292929987D9618577). This is theft of authentication certificates/private keys for later use. The 4657 change to HKLM\SOFTWARE\Microsoft\SystemCertificates\ROOT\Certificates\BE36A4562FB2EE05DBB3D32323ADF445084ED656\Blob on nashua.dmevals.local was performed by C:\Windows\Sysmon.exe under NASHUA$ (SYSTEM logon 0x3e7) and the other 4657 hits are wevtutil/WMI Autologger EventLog-Application value changes — routine, not certificate tampering. Zeek x509/kerberos records (2020-04-30) do not overlap the Windows window and show only two ordinary TLS certificate subjects with no PKINIT evidence.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMAQC1mz | q-b43f698d87 | ok |
| 2 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\readme.ps1 | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMAQC1mz | q-b43f698d87 | ok |
| 3 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | user.name | pbeesly | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMAQC1mz | q-b43f698d87 | ok |
| 4 | 2020-05-02 03:04:57.460Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63CdmD | q-923df2280e | ok |
| 5 | 2020-05-02 03:04:57.460Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\WindowsPowerShell\v1.0\powershell.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63CdmD | q-923df2280e | ok |
| 6 | 2020-05-02 03:04:57.272Z | scranton.dmevals.local | windows.sysmon | win.TargetObject | HKLM\SOFTWARE\Microsoft\SystemCertificates\Remote Desktop\Certificates\615B93C2D2B647D1670500B3338EAAEC83BA5646\Blob | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63CtkV | q-c45e4ee926 | ok |
| 7 | 2020-05-02 03:04:57.428Z | scranton.dmevals.local | windows.sysmon | win.TargetObject | HKLM\SOFTWARE\Microsoft\SystemCertificates\MY\Certificates\48B5E43D09D080DF8863152FD22ED7C43443D499\Blob | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63CdmN | q-c45e4ee926 | ok |
| 8 | 2020-05-02 03:08:51.489Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2kqttt | q-71463a3dc6 | ok |
| 9 | 2020-05-02 03:08:51.489Z | scranton.dmevals.local | windows.sysmon | win.Hashes | SHA1=A6E731EA51C8809C6FE57DEF73ACD54228E953D7,MD5=8E41F755A152A2C139A922D9626B44C4,SHA256=F33BEEBFBFF89C1A8E51AD688CDDB1A972EDD5444380B93292929987D9618577,IMPHA… | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2kqttt | q-71463a3dc6 | ok |
| 10 | 2020-05-02 02:55:56.157Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\ProgramData\victim\â€®cod.3aka3.scr" /S | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL7am0gN | q-9909123faf | ok |
| 11 | 2020-05-02 02:58:43.212Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Windows\System32\control.exe"  /name Microsoft.BackupAndRestoreCenter | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL7VicZa | q-9909123faf | ok |
| 12 | 2020-05-02 03:16:19.000Z | nashua.dmevals.local | windows.security | win.ObjectName | \REGISTRY\MACHINE\SOFTWARE\Microsoft\SystemCertificates\ROOT\Certificates\BE36A4562FB2EE05DBB3D32323ADF445084ED656 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL9FgwRA | q-360aaf5dfd | ok |
| 13 | 2020-05-02 03:16:19.000Z | nashua.dmevals.local | windows.security | process.executable | C:\Windows\Sysmon.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL9FgwRA | q-360aaf5dfd | ok |

### F64 · malicious / high · T1649 · Certificate private keys exported to .pfx on scranton

Evidence status: **verified**

Same Get-PrivateKeys export of LocalMachine certs to a password-protected .pfx.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\readme.ps1 | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMAQC1mz | q-a551aac8a5 | ok |

### F02 · suspicious / medium · T1003.001 · wsmprovhost.exe on nashua opened lsass.exe with 0x1F3FFF during a remote PowerShell session as pbeesly

Evidence status: **verified**

On nashua.dmevals.local at 03:09:29 UTC, wsmprovhost.exe (PID 7720, the WinRM/remote PowerShell host) opened lsass.exe (PID 728) with GrantedAccess 0x1F3FFF; the call trace runs through System.ni.dll and Microsoft.PowerShell.Commands.Management.ni.dll, i.e. the access was made from PowerShell code. The security log shows the matching 4656 handle request with AccessMask 0x1f3fff and SubjectUserName pbeesly. The script block executed one second earlier was 'Get-Process -IncludeUserName \| Select-Object UserName,SessionId \| Where-Object { $_.UserName -like "*\$env:USERNAME" } \| Sort-Object SessionId -Unique', which is a session/user enumeration rather than a dump routine, and no dump file or dump command line was observed. The access mask is nonetheless dump-capable and the same account was dumping LSASS on scranton minutes earlier, so this is treated as suspicious rather than confirmed dumping.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2kp9uH | q-80adfe1b1f | ok |
| 2 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2kp9uH | q-80adfe1b1f | ok |
| 3 | 2020-05-02 03:09:29.000Z | nashua.dmevals.local | windows.security | win.AccessMask | 0x1f3fff | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL9VzibT | q-1acfd30602 | ok |
| 4 | 2020-05-02 03:09:28.000Z | nashua.dmevals.local | windows.powershell | win.ScriptBlockText |  Get-Process -IncludeUserName \| Select-Object UserName,SessionId \| Where-Object { $_.UserName -like "*\$env:USERNAME" } \| Sort-Object SessionId -Unique  | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMAMA2AH | q-075bcb78ef | ok |

### F11 · suspicious / medium · T1040 · Attacker tooling on nashua.dmevals.local is a PsExec-delivered python.exe C2 client, not a sniffer

Evidence status: **verified**

While hunting for sniffing tools I found the actual intrusion tooling, which is outbound C2 rather than packet capture: on nashua.dmevals.local, user pbeesly, C:\Windows\Temp\python.exe was launched repeatedly (03:11:40Z, 03:12:46Z, 03:13:49Z, 03:15:03Z) with parent C:\Windows\PSEXESVC.exe, and then made 348 outbound connections, all to 192.168.0.4:8443 from 10.0.1.6 (e.g. source port 60048 at 03:15:05Z). On scranton.dmevals.local the same user pbeesly ran a hidden, execution-policy-bypassing PowerShell command that decodes a bitmap (monkey.png) into shellcode and IEXs it. These are credential-access/C2-adjacent behaviours, but neither process performs promiscuous-mode capture or writes packet captures, so they do not constitute T1040 network sniffing.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:40.213Z | nashua.dmevals.local | windows.sysmon | process.parent.executable | C:\Windows\PSEXESVC.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2in-NH | q-2d0845d976 | ok |
| 2 | 2020-05-02 03:15:05.142Z | nashua.dmevals.local | windows.sysmon | destination.port | 8443 | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2bgjeM | q-2d0845d976 | ok |
| 3 | 2020-05-02 02:58:44.325Z | scranton.dmevals.local | windows.sysmon | process.command_line | "PowerShell.exe" -noni -noexit -ep bypass -window hidden -c "sal a New-Object;Add-Type -AssemblyName 'System.Drawing'; $g=a System.Drawing.Bitmap('C:\Users\pbee… | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL7ViMbT | q-8bca7e86c8 | ok |

### F21 · suspicious / medium · T1111 · No MFA/smart-card interception artifacts; credential theft on scranton was certificate private-key export plus LSASS access

Evidence status: **verified**

On scranton.dmevals.local, user pbeesly's PowerShell session (spawned 02:56:14 from cmd.exe, itself spawned by C:\ProgramData\victim\...cod.3aka3.scr) ran a credential-access chain: at 03:04:56 it defined and invoked Get-PrivateKeys, which enumerates cert:\LocalMachine and exports certificates to .pfx files in the user's Downloads folder using the hardcoded password 'saribas'; at 03:05:16 the same PowerShell process (PID 2976) opened lsass.exe (PID 736) with GrantedAccess 0x1f3fff and 0x1fffff (full access, consistent with credential dumping). This is credential/certificate theft, but nothing in the retrieved data shows interception of MFA: no smart-card registry changes (C130 zero hits), no smart-card/MFA provider events, and the only 'Credential' string in windows.other is a routine 'Credential Guard configuration: 0x0, 0' message on scranton at 03:19:09. The 4648 explicit-credential logons are pbeesly authenticating to NASHUA via PSEXESVC.exe (03:11-03:15) and machine-account/DWM/UMFD logons on scranton during a reboot at 03:19-03:20 — lateral movement and normal system behaviour, not MFA interception. The wsmprovhost.exe LSASS access on nashua at 03:09:29 (0x1f3fff) has a PowerShell/System.ni.dll call trace consistent with PowerShell remoting enumeration rather than a dump tool. T1111 itself is therefore not observed; the underlying credential-access activity is real and malicious in context.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMAQC1mz | q-da703d2999 | ok |
| 2 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | Get-PrivateKeys | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMAQC1ns | q-da703d2999 | ok |
| 3 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63CNnH | q-acd1e8eca2 | ok |
| 4 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63CAlf | q-acd1e8eca2 | ok |
| 5 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63CAlf | q-acd1e8eca2 | ok |
| 6 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2kp9uH | q-acd1e8eca2 | ok |
| 7 | 2020-05-02 03:11:40.000Z | nashua.dmevals.local | windows.security | win.ProcessName | C:\Windows\PSEXESVC.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL9OrXFR | q-d3b3e6fc0a | ok |
| 8 | 2020-05-02 03:19:09.000Z | scranton.dmevals.local | windows.other | message | Credential Guard configuration: 0x0, 0 | .ds-logs-windows.other-default-2026.10.17-000001 / AaFIKaWOc7y0JL-w3yMh | q-b2ca916fb1 | ok |

### F28 · suspicious / low · T1552.002 · Winlogon registry key queried by pbeesly's powershell.exe alongside mostly routine system reads

Evidence status: **verified**

838 object-access events (4663) target \REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon, all with AccessMask 0x1 (query value). The bulk of callers are ordinary system components (WmiPrvSE.exe 416, svchost.exe 223, wsmprovhost.exe 21, consent.exe, lsass.exe, LogonUI.exe, winlogon.exe, Defender, gpupdate), which is routine. However 77 of these reads come from powershell.exe, and the earliest ones at 2020-05-01T22:56:14Z on scranton.dmevals.local are attributed to user pbeesly — the same account running the Get-PrivateKeys/Invoke-Exfil toolset minutes later. A value-only query of the Winlogon key is a known precursor to reading AutoAdminLogon/DefaultPassword, so this is worth noting, but no reg query/reg save command line was observed (C168 zero hits) and no credential value was read, so it is not confirmed credential theft.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:56:14.000Z | scranton.dmevals.local | windows.security | win.ObjectName | \REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL9TyZrV | q-dc51cb6867 | ok |
| 2 | 2020-05-02 02:56:14.000Z | scranton.dmevals.local | windows.security | win.AccessMask | 0x1 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL9TyZrV | q-dc51cb6867 | ok |
| 3 | 2020-05-02 02:56:14.000Z | scranton.dmevals.local | windows.security | process.executable | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL9TyZrV | q-dc51cb6867 | ok |
| 4 | 2020-05-02 02:56:14.000Z | scranton.dmevals.local | windows.security | user.name | pbeesly | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL9TyZrV | q-dc51cb6867 | ok |

### F60 · suspicious / medium · T1552.002 · Registry value piped to Invoke-Expression on scranton

Evidence status: **verified**

After hostui.exe -verb runas, PowerShell read HKLM Javasoft 'value Supplement' and executed it, then a hidden base64 loader.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:21:28.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | Get-ItemPropertyValue 'HKLM:\\SOFTWARE\Javasoft' 'value Supplement' \| Invoke-Expression | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMAWJWsz | q-d2dc243e8d | ok |
| 2 | 2020-05-02 03:21:26.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | Start-Process C:\Windows\System32\hostui.exe -verb runas | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMAVH79h | q-d2dc243e8d | ok |

### F31 · suspicious / medium · T1555 · Full-access LSASS handle requests by pbeesly's PowerShell on scranton, but no credential-store extraction artifacts

Evidence status: **verified**

On 2020-05-02 at 03:05:16 UTC, PowerShell.exe (PID 2976) running as pbeesly on scranton.dmevals.local opened lsass.exe with GrantedAccess 0x1f3fff and 0x1fffff (call trace ntdll.dll+9c584\|KERNELBASE.dll+2732e\|UNKNOWN), and Windows security auditing recorded the matching 4656 handle requests (AccessMask 0x1fffff / 0x1f3fff) plus a 4663 read (0x10) on \Device\HarddiskVolume2\Windows\System32\lsass.exe. This is the access pattern of a memory-dump credential theft tool, and it occurred in the same session where pbeesly ran an obfuscated IEX loader from monkey.png, Invoke-Exfil (7-Zip staging to \\192.168.0.4\webdav) and a HKCU Folder\shell\open persistence key. However, no dump file was created (only WerFault WER*.tmp.dmp files exist), no procdump/comsvcs/MiniDump/sekurlsa command line was seen, and no SAM/SECURITY/NTDS or browser/vault/password-manager store was read. The remaining lsass access is benign: svchost.exe 0x1000 (289 events), Azure AntimalwareConfig.exe and WindowsAzureTelemetryService.exe 0x1400, and wininit/csrss 0x1fffff at 03:19:09 which coincides with a fresh lsass.exe start (wininit parent) i.e. a reboot. The nashua wsmprovhost 0x1f3fff access at 03:09:29 is explained by pbeesly's remote 'Get-Process -IncludeUserName' query. No evidence of actual credential-store harvesting was found.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63CAlf | q-bd4b487d37 | ok |
| 2 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63CAlf | q-bd4b487d37 | ok |
| 3 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.CallTrace | C:\windows\SYSTEM32\ntdll.dll+9c584\|C:\windows\System32\KERNELBASE.dll+2732e\|UNKNOWN(000001996D28200D) | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63CAlf | q-bd4b487d37 | ok |
| 4 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | win.AccessMask | 0x1fffff | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL9MpvMw | q-855a126cf0 | ok |
| 5 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | win.SubjectUserName | pbeesly | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL9MpvMw | q-855a126cf0 | ok |
| 6 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2kp9uH | q-77c2315acc | ok |
| 7 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2kp9uH | q-77c2315acc | ok |
| 8 | 2020-05-02 03:09:28.000Z | nashua.dmevals.local | windows.powershell | win.ScriptBlockText |  Get-Process -IncludeUserName \| Select-Object UserName,SessionId \| Where-Object { $_.UserName -like "*\$env:USERNAME" } \| Sort-Object SessionId -Unique  | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMAMA2AH | q-c3abe936f3 | ok |
| 9 | 2020-05-02 03:05:27.395Z | nashua.dmevals.local | windows.sysmon | file.path | C:\ProgramData\Microsoft\Windows\WER\Temp\WER51F5.tmp.dmp | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL62AkVX | q-58b724d8f4 | ok |

### F62 · suspicious / low · T1555 · Vault Latest.dat touched only by lsass.exe

Evidence status: **verified**

Sysmon 23 on Vault Latest.dat written by lsass.exe itself; no attacker credential-store extraction.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:22:35.895Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Users\pbeesly\AppData\Local\Microsoft\Vault\UserProfileRoaming\Latest.dat | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL17C4EF | q-6725f9dda8 | ok |

### F44 · suspicious / low · T1557.001 · NBT-NS/LLMNR name resolution for SCRANTON/NASHUA broadcast unanswered by any host; SMB auth traffic to 10.0.0.4/10.0.1.6 intercepted by the rogue MAC

Evidence status: **verified**

Six name-resolution queries on ports 5355/137 were issued from 10.0.1.4 (name SCRANTON, 3x) and 10.0.1.6 (name NASHUA, 3x) to the broadcast address 10.0.1.255; the only responder recorded is the broadcast address itself, so no poisoning responder is directly observed in the DNS log. However the SMB (445) sessions from those same hosts to 10.0.0.4 and 10.0.1.6 carry gssapi/krb authentication and are answered by the non-vendor MAC 12:34:56:78:9a:bc, consistent with name-resolution poisoning followed by SMB relay. No DNSClient registry tampering (Sysmon 13) and no arpspoof/responder script blocks were found, so the relay itself is inferred rather than directly logged.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-04-30 00:35:03.399Z | simplerockbuild.simplerock.lan | zeek | dns.question.name | SCRANTON | .ds-logs-zeek-default-2026.10.17-000001 / AaFIKqWOc7y0JMDGJw29 | q-1672aaecc1 | ok |
| 2 | 2020-04-30 00:35:03.399Z | simplerockbuild.simplerock.lan | zeek | destination.port | 137 | .ds-logs-zeek-default-2026.10.17-000001 / AaFIKqWOc7y0JMDGJw29 | q-1672aaecc1 | ok |
| 3 | 2020-04-30 00:34:53.248Z | bobs.bigwheel.local | zeek | dns.question.name | NASHUA | .ds-logs-zeek-default-2026.10.17-000001 / AaFIK6WOc7y0JMA_NabS | q-1672aaecc1 | ok |
| 4 | 2020-04-30 00:34:53.248Z | bobs.bigwheel.local | zeek | source.ip | 10.0.1.6 | .ds-logs-zeek-default-2026.10.17-000001 / AaFIK6WOc7y0JMA_NabS | q-1672aaecc1 | ok |
| 5 | 2020-04-30 00:36:38.970Z | simplerockbuild.simplerock.lan | zeek | zeek.service | krb,smb,gssapi | .ds-logs-zeek-default-2026.10.17-000001 / AaFIKqWOc7y0JMDGJw3s | q-31a3605606 | ok |
| 6 | 2020-04-30 00:36:38.970Z | simplerockbuild.simplerock.lan | zeek | zeek.resp_l2_addr | 12:34:56:78:9a:bc | .ds-logs-zeek-default-2026.10.17-000001 / AaFIKqWOc7y0JMDGJw3s | q-31a3605606 | ok |

### F47 · suspicious / medium · T1558 · Compromised host scranton.dmevals.local: PowerShell opened LSASS with full access during a multi-stage intrusion, but no Kerberos ticket theft/forgery artifacts were observed

Evidence status: **verified**

On scranton.dmevals.local, user pbeesly executed a malicious .scr (C:\ProgramData\victim\...cod.3aka3.scr) from explorer.exe at 02:55:56Z, which spawned cmd.exe and powershell.exe. PowerShell ran a steganographic loader (decoding C:\Users\pbeesly\Downloads\monkey.png via System.Drawing and IEX), compiled code with csc.exe, and later ran sdelete64.exe against the payload for anti-forensics. During this session, PowerShell.exe (PID 2976) opened handles to lsass.exe with GrantedAccess 0x1f3fff and 0x1fffff at 03:05:16Z — full-process access consistent with credential dumping. However, no Kerberos-specific ticket manipulation was observed: all 4768 AS-REQ events carry PreAuthType 2, all 4769 TGS tickets are AES256 (0x12) with no RC4 downgrade, and no krbtgt/service-ticket forgery or ticket-file artifacts appear. The LSASS access is a credential-access precursor to T1558 but the ticket-theft step itself is not evidenced.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63CAlf | q-62e58ef87a | ok |
| 2 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63CNnH | q-faef0dca02 | ok |
| 3 | 2020-05-02 02:55:56.157Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\ProgramData\victim\â€®cod.3aka3.scr | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL7am0gN | q-6eb9b96f53 | ok |
| 4 | 2020-05-02 02:58:45.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | sal a New-Object;Add-Type -AssemblyName 'System.Drawing'; $g=a System.Drawing.Bitmap('C:\Users\pbeesly\Downloads\monkey.png');$o=a Byte[] 4480;for($i=0; $i -le … | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMAWIhac | q-0e7e634ac8 | ok |
| 5 | 2020-05-02 03:02:04.324Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\sdelete64.exe" /accepteula C:\programdata\victim\???cod.3aka3.scr | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL69HSbI | q-6eb9b96f53 | ok |

### F52 · suspicious / medium · T1606 · No forged web credential activity; observed credential access is LSASS memory access and Credential Manager enumeration by pbeesly

Evidence status: **verified**

On 2020-05-02 between 03:05 and 03:20 UTC the account pbeesly performed credential-access activity on scranton.dmevals.local and nashua.dmevals.local. At 03:05:16 PowerShell.exe (PID 2976) on scranton opened lsass.exe (PID 736) with GrantedAccess 0x1F3FFF and 0x1FFFFF (full-access masks consistent with memory dumping), and at 03:09:29 wsmprovhost.exe (PID 7720) on nashua opened lsass.exe (PID 728) with 0x1F3FFF. At 03:05:28-03:05:32 Security event 5379 shows Credential Manager credentials being enumerated by pbeesly on nashua and scranton (WindowsLive token/cert and MicrosoftAccount targets). The same actor then used PsExec64.exe from scranton with the cleartext password '-p Fl0nk3rt0n!T0by' to run C:\Windows\Temp\python.exe on \\NASHUA, and ran rundll32.exe davclnt.dll,DavSetCookie against http://192.168.0.4/webdav, plus a PowerShell Invoke-Exfil function that 7-zips data and copies it to a WebDAV share. This is credential theft and lateral movement, but no evidence of forged web credentials (no SAML token or web cookie forging) was found: no ADFS/SAML artifacts, no cookie-store file access, and the only cookie-related activity is legitimate WebDAV DavSetCookie client behaviour. The 4648 explicit-credential events are the PsExec logons to NASHUA and normal Windows service logons (DWM/UMFD/SCRANTON$).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63CNnH | q-08a8fae6b4 | ok |
| 2 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63CAlf | q-8f2b7d68b4 | ok |
| 3 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2kp9uH | q-cc7e746338 | ok |
| 4 | 2020-05-02 03:05:28.000Z | nashua.dmevals.local | windows.security | win.TargetName | WindowsLive:(token):name=02tkygcqupblzpan;serviceuri=* | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL9Jl2tp | q-75b25819e1 | ok |
| 5 | 2020-05-02 03:11:18.784Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\PsExec64.exe" -accepteula \\NASHUA -u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2ioON3 | q-5b2bceb06d | ok |
| 6 | 2020-05-02 03:08:50.846Z | scranton.dmevals.local | windows.sysmon | process.command_line | rundll32.exe C:\windows\system32\davclnt.dll,DavSetCookie 192.168.0.4 http://192.168.0.4/webdav | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2lq7xd | q-5b2bceb06d | ok |
| 7 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\psversion.ps1 | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JL8F_6E7 | q-cbaee2ec24 | ok |

### F03 · benign / medium · T1003.002 · lsass.exe wrote HKLM\SAM\SAM\Domains\Account\F on scranton — normal SAM account update, not hive extraction

Evidence status: **verified**

The only registry write touching SAM\SAM in the dataset is a Sysmon event 13 at 03:19:10 UTC on scranton.dmevals.local where lsass.exe (PID 748) set HKLM\SAM\SAM\Domains\Account\F to 'Binary Data'. This is the SAM account record being updated by the LSA itself, not a reg save / esentutl / hive-copy operation: no process creation referenced reg save, esentutl or SAM (C019 zero hits), no SAM/SECURITY/SYSTEM hive file was created (C020 only matched Prefetch .pf files), and no 4663 object access on SAM/SECURITY was recorded (C024 zero hits). The 16962 event on scranton is the standard 'Remote calls to the SAM database are being restricted' policy message.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:10.368Z | scranton.dmevals.local | windows.sysmon | registry.path | HKLM\SAM\SAM\Domains\Account\F | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2ORrtI | q-e759fd8965 | ok |
| 2 | 2020-05-02 03:19:10.368Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2ORrtI | q-e759fd8965 | ok |
| 3 | 2020-05-02 03:19:10.000Z | scranton.dmevals.local | windows.other | message | Remote calls to the SAM database are being restricted using the default security descriptor: O:SYG:SYD:(A;;RC;;;BA).  For more information please see http://go.… | .ds-logs-windows.other-default-2026.10.17-000001 / AaFIKaWOc7y0JL-w3yM8 | q-dbc1c6d079 | ok |

### F04 · benign / high · T1003.003 · No NTDS.dit / shadow-copy activity observed

Evidence status: **verified**

No process creation referenced ntdsutil, vssadmin or diskshadow (C028 zero hits), no file named ntds/.dit was created (C029, C030 zero hits), no 4663 object access on ntds (C032 zero hits), no matching service/other-channel messages (C033) and no PowerShell script block referencing ntds/vssadmin/diskshadow (C034). The 12 zeek smb_files records returned no file names (C035), so no NTDS.dit transfer is visible on the wire either. Nothing in the retrieved data supports NTDS extraction.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-04-30 00:12:00.967Z | simplerockbuild.simplerock.lan | zeek | event.action | dce_rpc | .ds-logs-zeek-default-2026.10.17-000001 / AaFIKqWOc7y0JMDGKA6p | q-30cc0902c4 | ok |

### F05 · benign / medium · T1003.004 · No LSA secrets dumping observed; lsass image loads are Microsoft-signed system DLLs

Evidence status: **verified**

No process creation referenced SECURITY, secrets, lsadump or reg save (C036 zero hits), no 4663 object access on SECURITY\Policy\Secrets (C039 zero hits), no 4688 or 4104 referencing lsadump/secrets (C041, C042 zero hits). The 23 image-load events for lsass/samlib/vaultcli are samlib.dll ('SAM Library DLL', Microsoft Corporation) loaded into svchost.exe and powershell.exe, which is normal for SAM/LSA API use. The 4673 sensitive-privilege events involving lsass are all generated by lsass.exe itself (103 events, C014).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:04.501Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL66EEHK | q-b8a2cf8330 | ok |
| 2 | 2020-05-02 02:55:56.000Z | scranton.dmevals.local | windows.security | win.PrivilegeList | SeProfileSingleProcessPrivilege | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL9Typob | q-5fd8b39104 | ok |

### F06 · benign / medium · T1003.005 · No cached domain credential dumping observed

Evidence status: **verified**

No 4663 object access on Cache/SECURITY objects (C048 zero hits) and no other-channel message referencing cachedump/mscash/Cache (C051 zero hits). The only credential-adjacent collection seen on scranton was Get-PrivateKeys exporting certificates to .pfx files under the user's Downloads folder, which is certificate theft rather than cached domain credential extraction.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMAQC1mz | q-158ef807ee | ok |

### F07 · benign / medium · T1003.006 · DRSUAPI binds in zeek are DRSBind/DRSCrackNames/DRSUnbind only — no DCSync replication

Evidence status: **verified**

The zeek window (2020-04-30, which does not overlap the Windows logs) contains 9 drsuapi DCE-RPC records: DRSBind, DRSCrackNames and DRSUnbind from 10.0.1.4 and 10.0.1.6 to 10.0.0.4 (port 49667). No DRSGetNCChanges — the operation that actually replicates directory secrets in a DCSync — appears in the 123 dce_rpc operations (C018), and no process creation or script block referenced drsuapi/lsadump/dcsync (C056, C057, C058 zero hits). Name-cracking binds are consistent with normal domain name resolution, not credential replication.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-04-30 00:12:00.967Z | simplerockbuild.simplerock.lan | zeek | zeek.operation | DRSBind | .ds-logs-zeek-default-2026.10.17-000001 / AaFIKqWOc7y0JMDGKA6p | q-30cc0902c4 | ok |
| 2 | 2020-04-30 00:12:00.968Z | simplerockbuild.simplerock.lan | zeek | zeek.operation | DRSCrackNames | .ds-logs-zeek-default-2026.10.17-000001 / AaFIKqWOc7y0JMDGJw3L | q-30cc0902c4 | ok |
| 3 | 2020-04-30 00:12:00.969Z | simplerockbuild.simplerock.lan | zeek | zeek.operation | DRSUnbind | .ds-logs-zeek-default-2026.10.17-000001 / AaFIKqWOc7y0JMDGJw3G | q-30cc0902c4 | ok |

### F09 · benign / high · T1040 · netsh packet capture on scranton.dmevals.local is the Azure Network Watcher agent, not adversary sniffing

Evidence status: **verified**

The single hit for packet-capture command lines (check C060) is on scranton.dmevals.local at 2020-05-01T23:19:17-04:00 (2020-05-02T03:19:17Z): netsh.exe 'trace start capture=yes traceFile="C:\windows\TEMP\E7116ECA-...\B91E06C5-....etl"'. The 4688 event shows the creator subject is SCRANTON$ (S-1-5-18, logon 0x3e7) and the creator process is C:\Packages\Plugins\Microsoft.Azure.NetworkWatcher.NetworkWatcherAgentWindows\1.4.1421.1\NetworkWatcherAgent\NetworkWatcherAgent.exe — the Azure platform's network diagnostics extension. Sysmon corroborates the same netsh capture start (SYSTEM) and a matching 'netsh.exe trace stop' 7 seconds later, plus the resulting .etl file write. This is a short, self-terminating platform capture, not a sustained promiscuous-mode sniffer. No pktmon/windump/tcpdump usage, no pcap/npcap/winpcap service installs (C062 zero hits), and no PowerShell pktmon/promisc/Get-NetAdapter activity (C063 zero hits).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:17.000Z | scranton.dmevals.local | windows.security | process.command_line | C:\windows\system32\netsh.exe trace start capture=yes traceFile="C:\windows\TEMP\E7116ECA-DFE6-43C7-8FA8-8D3AC5AA8726\B91E06C5-1C7C-4830-9A76-74FA211560A7.etl" | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL9AdJ6k | q-7b72e66a62 | ok |
| 2 | 2020-05-02 03:19:17.000Z | scranton.dmevals.local | windows.security | process.parent.executable | C:\Packages\Plugins\Microsoft.Azure.NetworkWatcher.NetworkWatcherAgentWindows\1.4.1421.1\NetworkWatcherAgent\NetworkWatcherAgent.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL9AdJ6k | q-c4641cf1dc | ok |
| 3 | 2020-05-02 03:19:24.835Z | scranton.dmevals.local | windows.sysmon | process.command_line | C:\windows\system32\netsh.exe trace stop | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2IK5Hc | q-8bca7e86c8 | ok |
| 4 | 2020-05-02 03:19:23.900Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Windows\Temp\E7116ECA-DFE6-43C7-8FA8-8D3AC5AA8726\B91E06C5-1C7C-4830-9A76-74FA211560A7.etl | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2JMYSh | q-61d1646c15 | ok |

### F10 · benign / medium · T1040 · No credential-bearing cleartext protocols observed in the NSM window; zeek HTTP is WebDAV file transfer

Evidence status: **verified**

In the zeek window (2020-04-30T00:06:38Z..00:45:00Z) the 613 conn records are dominated by ssl (378), dns (39), krb_tcp (25), dce_rpc (20) and gssapi/smb combinations; there is no ftp, telnet or ftp-data service at all, so no cleartext credential exchange was captured that a sniffer could have harvested. The 62 http records are all Microsoft-WebDAV-MiniRedir/DavClnt traffic from 10.0.1.4 to 192.168.0.4:80 performing PROPFIND/PUT/LOCK on /webdav/OfficeSupplies.7z and /webdav/python.exe — WebDAV upload/download, not authentication traffic. The only zeek notices are SSL::Invalid_Server_Cert (self-signed certificate) for 10.0.1.6->192.168.0.4:8443 and 10.0.1.4->192.168.0.5:443, and the weird/dpd records are SMB (445) and high-port anomalies. Nothing in this window indicates a host in promiscuous mode or a passive sniffer.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-04-30 00:32:22.010Z | simplerockbuild.simplerock.lan | zeek | url.original | /webdav/OfficeSupplies.7z | .ds-logs-zeek-default-2026.10.17-000001 / AaFIKqWOc7y0JMDGKA04 | q-9d9254ba0b | ok |
| 2 | 2020-04-30 00:35:25.658Z | simplerockbuild.simplerock.lan | zeek | url.original | /webdav/python.exe | .ds-logs-zeek-default-2026.10.17-000001 / AaFIKqWOc7y0JMDGKA01 | q-9d9254ba0b | ok |
| 3 | 2020-04-30 00:40:44.740Z | bobs.bigwheel.local | zeek | zeek.note | SSL::Invalid_Server_Cert | .ds-logs-zeek-default-2026.10.17-000001 / AaFIK6WOc7y0JMA_NaZf | q-64203742f1 | ok |

### F14 · benign / medium · T1056.001 · No keylogging activity found

Evidence status: **verified**

No keylogger indicators were observed in any dataset. Searches for GetAsyncKeyState, SetWindowsHookEx and 'keylog' in PowerShell script blocks, Sysmon process command lines and windows.other messages returned zero hits, as did handle/access queries for keyboard objects in windows.security. The only keyboard-related registry writes (Sysmon EventID 13) are Windows keyboard-layout and TERMINPUT_BUS device-enumeration keys under HKU\.DEFAULT and HKLM\System\CurrentControlSet\Enum, which are normal OS behaviour. The lsass access described under T1056.004 is a credential-memory path, not keystroke capture.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.TargetImage | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63CNnH | q-7a35883950 | ok |

### F15 · benign / medium · T1056.003 · No web portal / web-shell credential capture found

Evidence status: **verified**

No evidence of web portal capture. Searches for IIS/appcmd/wwwroot command lines, 4663 access to wwwroot/inetpub, PowerShell WebAdministration/wwwroot/inetpub script blocks and windows.other messages mentioning wwwroot/inetpub all returned zero hits. The only file creations matching login/logon/portal names are Sysinternals tools (Autologon.exe, logonsessions.exe) downloaded by pbeesly plus Windows netlogon.ftl and the Netlogon operational event log. Zeek HTTP traffic in its separate (non-overlapping) window went only to url.domain 192.168.0.4, with no login/logon/signin URLs.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JL8F_6E7 | q-5479a9d4b9 | ok |

### F16 · benign / high · T1110 · No brute-force activity: zero failed-logon events; the only credential-validation record is a success

Evidence status: **verified**

Across windows.security (2020-05-02T02:55:25Z..03:28:09Z) there are no 4625 (failed logon) events at all, and the only credential-validation record in the whole window is a single 4776 on newyork.dmevals.local at 2020-05-01T23:20:40-04:00 for account pbeesly from workstation 10.0.1.4 with Error Code 0x0 / Status 0x0 (AUDIT_SUCCESS). A count of 4625 OR 4771 OR 4776 returned exactly 1 event. There is no repetition of authentication attempts against any account, so the T1110 family hypothesis is not supported by the authentication telemetry. The credential theft that did occur on this network (see T1110.002 finding) was memory/handle based, not password-guessing based.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:20:40.000Z | newyork.dmevals.local | windows.security | win.Status | 0x0 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL8xSa_z | q-43cc2735cc | ok |
| 2 | 2020-05-02 03:20:40.000Z | newyork.dmevals.local | windows.security | event.code | 4776 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL8xSa_z | q-43cc2735cc | ok |
| 3 | 2020-05-02 03:20:40.000Z | newyork.dmevals.local | windows.security | win.EventType | AUDIT_SUCCESS | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL8xSa_z | q-43cc2735cc | ok |

### F17 · benign / high · T1110.001 · No password guessing: no 4625 failures and no guessing script in PowerShell script blocks

Evidence status: **verified**

No 4625 events exist in windows.security, so there is no sequence of failed logons against any account that would indicate password guessing. The four 4104 script blocks matching *Password*/*Login*/*Credential* on scranton and newyork are not guessing code: one is a Get-PrivateKeys function that exports machine certificates to .pfx files using a hardcoded password string, one is an Invoke-Exfil function that 7-Zip-compresses the Downloads folder with a password, and two are benign module/help text (a TimeSpan helper and AD cmdlet help). None of them iterates candidate passwords against an account.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMAQC1mz | q-d8a307566e | ok |
| 2 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JL8F_6E7 | q-d8a307566e | ok |

### F19 · benign / medium · T1110.003 · No password spraying: 4648 explicit-credential logons are single-account admin/PSEXEC use, not many-accounts-one-password

Evidence status: **verified**

All 15 4648 events use the same account, pbeesly: 9 on scranton.dmevals.local and nashua.dmevals.local (5 and 4) plus 6 machine/service accounts (DWM-1, DWM-2, UMFD-0/1/2, SCRANTON$) generated by winlogon.exe, wininit.exe and taskhostw.exe at 23:19-23:20, which is normal Windows desktop/session behaviour. The pbeesly 4648s on nashua come from C:\Windows\PSEXESVC.exe (PsExec service) and on scranton from svchost.exe with source.ip 10.0.1.6 / 172.18.39.2. Spraying requires one password tried against many distinct accounts; here only one user account is ever presented, so this is lateral movement with already-obtained credentials rather than spraying. Note this activity is still attacker-driven (see T1110.002) but does not match T1110.003.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:40.000Z | nashua.dmevals.local | windows.security | process.executable | C:\Windows\PSEXESVC.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL9OrXFR | q-0bfdff0eb2 | ok |
| 2 | 2020-05-02 03:11:40.000Z | nashua.dmevals.local | windows.security | win.TargetUserName | pbeesly | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL9OrXFR | q-0bfdff0eb2 | ok |
| 3 | 2020-05-02 03:19:10.000Z | scranton.dmevals.local | windows.security | process.executable | C:\Windows\System32\winlogon.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL88ahmW | q-0bfdff0eb2 | ok |

### F20 · benign / high · T1110.004 · No credential stuffing: no failed authentications and no stuffing script observed

Evidence status: **verified**

Credential stuffing requires many authentication attempts using lists of stolen credentials, which would surface as repeated 4625/4771 failures. windows.security contains zero 4625 events and only one 4776 (a success for pbeesly from 10.0.1.4 on newyork). The four 4104 script blocks matching *Credential*/*Password*/*Login* contain no credential-list iteration: they are a certificate-export function, a 7-Zip exfiltration function, and two benign helper/help texts. No stuffing tooling or authentication loop was found.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JL8F_6E7 | q-fd3c9cd92c | ok |
| 2 | 2020-05-02 03:20:40.000Z | newyork.dmevals.local | windows.security | win.EventType | AUDIT_SUCCESS | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL8xSa_z | q-43cc2735cc | ok |

### F24 · benign / high · T1212 · Routine LSASS handle activity by svchost.exe, Azure antimalware/telemetry and OS processes is benign

Evidence status: **verified**

The bulk of the 326 LSASS process-access events are low-privilege handles: svchost.exe with 0x1000 (216 on scranton, 30 on newyork, 28 on nashua, 12 on utica), AntimalwareConfig.exe and WindowsAzureTelemetryService.exe with 0x1400, and OS-internal accesses by wininit.exe/csrss.exe/svchost.exe at 03:18-03:19 on scranton (0x1fffff/0x1000000/0x3000/0x101001) consistent with normal service and session management. No credential-dumping command lines (procdump/comsvcs/MiniDump) were found in process creation, no lsass/MiniDump strings in PowerShell script blocks or windows.other messages, and the Kerberos events (4768/4769 for pbeesly and SCRANTON$) are ordinary ticket requests accompanying the logons. The only anomalous LSASS access is the PowerShell/wsmprovhost full-access pattern reported separately.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:18:34.438Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x101001 | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2QULdY | q-de5fe238e6 | ok |
| 2 | 2020-05-02 03:19:09.803Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1000000 | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2ORrt4 | q-de5fe238e6 | ok |
| 3 | 2020-05-02 03:19:59.323Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x3000 | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JLx1ssmj | q-de5fe238e6 | ok |
| 4 | 2020-05-02 03:19:09.809Z | scranton.dmevals.local | windows.sysmon | process.command_line | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2ORrtq | q-30ff1295fb | ok |

### F25 · benign / high · T1539 · No web session cookie theft observed; browser cookie/credential stores never accessed

Evidence status: **verified**

Hunted T1539 across windows.sysmon, windows.security, windows.powershell and windows.other for the 2020-05-02 02:55-03:28Z window on scranton/newyork/nashua/utica.dmevals.local. No browser cookie or credential store was read or copied. (1) Sysmon event 10 (process access) shows zero events where win.TargetImage matches chrome/firefox/msedge/iexplore/brave/opera, so no process opened a browser with cookie-read access. (2) Sysmon event 11 file creations matching cookies/login data/user data/mozilla/profiles returned a single hit, svchost.exe writing C:\Windows\ServiceProfiles\LocalService\AppData\Local\Packages\warp_jit_db4a1097-...\AC\INetCookies - an OS package container path, not a browser profile. The 162-hit C149 result was a wildcard false positive: the buckets are lastalive0.dat/lastalive1.dat and GroupPolicy DataStore paths written by svchost.exe. (3) Security 4663 object-access events on cookies/login data/user data/mozilla paths: zero. (4) The 4 C148 4688 hits are all C:\Windows\System32\SearchProtocolHost.exe (parent SearchIndexer.exe) whose command line merely contains the literal string "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT; MS Search 4.0 Robot)" - the Windows Search indexer user-agent, not browser access. (5) The 5157 C152 PowerShell hits are 4103 command-invocation noise (Set-StrictMode, Test-Path, Resolve-Path on Desktop/Favorites .lnk files) plus 4104 module manifests (xStorage, Microsoft Corporation manifests) and a BitLocker resource string; the only 4104 script of interest is Invoke-Exfil on scranton.dmevals.local by pbeesly at 2020-05-01T23:08:02-04:00, which compresses only $env:USERPROFILE\Downloads into $env:APPDATA\OfficeSupplies.7z and copies it to \\192.168.0.4\webdav - it does not touch Cookies or Login Data. Corroborating file activity shows OfficeSupplies.7z created by powershell.exe at 03:08:35Z and a .7z staged in TfsStore\Tfs_DAV at 03:08:51Z, with no browser-profile file among them. The credential-access activity present in t…

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:21:05.681Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Windows\ServiceProfiles\LocalService\AppData\Local\Packages\warp_jit_db4a1097-b484-4973-bbf2-a04208ecd4d4\AC\INetCookies | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JLx56e_Q | q-a539e917dc | ok |
| 2 | 2020-05-02 03:21:05.681Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\System32\svchost.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JLx56e_Q | q-a539e917dc | ok |
| 3 | 2020-05-02 02:57:01.000Z | scranton.dmevals.local | windows.security | process.command_line | "C:\windows\system32\SearchProtocolHost.exe" Global\UsGthrFltPipeMssGthrPipe6_ Global\UsGthrCtrlFltPipeMssGthrPipe6 1 -2147483646 "Software\Microsoft\Windows Se… | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL9Txpr2 | q-6bc6669cd7 | ok |
| 4 | 2020-05-02 02:55:28.893Z | nashua.dmevals.local | windows.sysmon | win.TargetFilename | C:\Windows\ServiceState\EventLog\Data\lastalive1.dat | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL7anEhE | q-297bbc9e98 | ok |
| 5 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JL8F_6E7 | q-b683a436e6 | ok |
| 6 | 2020-05-02 03:08:35.270Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Users\pbeesly\AppData\Roaming\OfficeSupplies.7z | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2lq7zj | q-0374ef7355 | ok |

### F29 · benign / medium · T1552.003 · No shell history / PSReadLine access observed

Evidence status: **verified**

All four shell-history checks returned zero hits: no PowerShell script block or Sysmon process command line referencing ConsoleHost_history or PSReadLine, no file creation of ConsoleHost_history, and no 4663 object access to those paths. The only PowerShell content in the window was the offensive toolset script blocks, none of which touch shell history. No evidence of shell-history credential theft.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:56:15.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockId | 0943f7fe-e808-492e-b955-ca275c8ca2b5 | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMAWIhZ8 | q-9452af117f | ok |

### F30 · benign / medium · T1552.006 · No Group Policy Preferences cpassword harvesting observed; only routine gpt.ini policy refresh

Evidence status: **verified**

All five GPP checks returned zero hits: no script block or process command line referencing Groups.xml, cpassword, gpprefdecrypt or SYSVOL, no 5145 relative target for Groups.xml/SYSVOL, no Sysmon file creation of Groups.xml/SYSVOL, and no other-channel message mentioning them. The only Group Policy file activity is gpt.ini written by svchost.exe into the local GroupPolicy DataStore on scranton and nashua — normal policy refresh, not GPP credential extraction. No evidence of cpassword harvesting.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:01:43.107Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Windows\System32\GroupPolicy\DataStore\0\sysvol\dmevals.local\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\gpt.ini | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL6-IQQH | q-f2586a93f1 | ok |
| 2 | 2020-05-02 03:01:43.107Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\svchost.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL6-IQQH | q-f2586a93f1 | ok |

### F32 · benign / high · T1555.003 · No browser credential-store access observed

Evidence status: **verified**

No process command line, script block, file creation or object-access event referenced Chrome/Edge/Firefox credential stores (Login Data, Local State, logins.json, key4.db, Cookies). The only file-creation hit in that pattern was a ContentDeliveryManager INetCookies file written by backgroundTaskHost.exe under the LocalService service profile, which is normal Windows behaviour. The single MicrosoftEdgeSH.exe process on scranton (SCODEF/CREDAT arguments) is the standard Edge renderer helper, not a credential-store read.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:59:16.896Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\backgroundTaskHost.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL7Ufx6G | q-6f560f2f39 | ok |
| 2 | 2020-05-02 03:21:06.803Z | scranton.dmevals.local | windows.sysmon | process.command_line | C:\windows\system32\MicrosoftEdgeSH.exe SCODEF:6208 CREDAT:9730 APH:1000000000000004 JITHOST /prefetch:2 | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JLx56_hv | q-7429ca704b | ok |

### F33 · benign / high · T1555.004 · No Windows Credential Manager / Vault access; SAM handle requests are lsass itself

Evidence status: **verified**

No cmdkey, vault, credman or DPAPI command line or script block was found, and no registry (event 15) access to Vault\Credentials keys. The 4656 handle requests on the SAM object (AccessMask 0xf003f) at 23:19:21-23:19:22 on scranton were made by lsass.exe itself as SCRANTON$ during the post-reboot service start, and the lsass-on-lsass 0x1478 requests are likewise lsass's own internal access. The only 'Credential' string in windows.other is a Credential Guard configuration status message (event 14) on scranton, which is informational.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:21.000Z | scranton.dmevals.local | windows.security | win.ObjectName | SAM | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL81V4Qj | q-855a126cf0 | ok |
| 2 | 2020-05-02 03:19:21.000Z | scranton.dmevals.local | windows.security | process.executable | C:\Windows\System32\lsass.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL81V4Qj | q-855a126cf0 | ok |
| 3 | 2020-05-02 03:19:09.000Z | scranton.dmevals.local | windows.other | message | Credential Guard configuration: 0x0, 0 | .ds-logs-windows.other-default-2026.10.17-000001 / AaFIKaWOc7y0JL-w3yMh | q-149a3ccd5a | ok |

### F34 · benign / high · T1555.005 · No password-manager access observed

Evidence status: **verified**

No KeePass, 1Password or Bitwarden process execution, file creation (.kdbx/.kdb), process-memory access, script block or message was observed on any host in the window. The only password-related script content was pbeesly's Invoke-Exfil, which hardcodes a credential ('cozy' / 'MyCozyPassw0rd!') to map a WebDAV share for exfiltration rather than reading a password manager store.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JL8F_6E7 | q-9664be84ff | ok |

### F35 · benign / medium · T1556 · No authentication-process tampering; LSASS access hits are benign system/AV/telemetry readers plus one credential-dumping PowerShell

Evidence status: **verified**

The 326 LSASS process-access (Sysmon 10) hits stack into benign patterns: 293 are GrantedAccess 0x1000 from svchost.exe (286), plus AntimalwareConfig.exe, WindowsAzureTelemetryService.exe, services.exe and powershell.exe; 24 are 0x1400 from the Azure antimalware/telemetry agents; 0x101001 from svchost.exe; and 0x1FFFFF/0x1000000 from wininit.exe/csrss.exe at lsass start-up on scranton at 03:19:09. The only non-system full-access readers are PowerShell.exe (PID 2976, scranton, 03:05:16, 0x1F3FFF/0x1FFFFF) and wsmprovhost.exe (PID 7720, nashua, 03:09:29, 0x1F3FFF) — these are credential dumping (T1003), not modification of the authentication process. No registry writes to LSA/Notification Packages/NetworkProvider were found; the only Lsa key writes are lsass.exe's own start-up values (LsaPid, ProductType, LsaCfgFlagsDefault) on scranton at 03:19:09. The windows.other 'lsass/cryptdll' hits were unrelated registry-hive access-history messages.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:10.368Z | scranton.dmevals.local | windows.sysmon | registry.path | HKLM\System\CurrentControlSet\Control\Lsa\ProductType | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2ORrtJ | q-06db048358 | ok |
| 2 | 2020-05-02 03:19:09.834Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2ORrt6 | q-06db048358 | ok |
| 3 | 2020-05-02 03:19:09.809Z | scranton.dmevals.local | windows.sysmon | process.command_line | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2ORrtq | q-d72d7d841a | ok |

### F36 · benign / medium · T1556.001 · No skeleton-key style patching of DC authentication; LSASS full-access handles came from PowerShell/WinRM credential dumping

Evidence status: **verified**

No evidence of authentication-process patching on the domain controllers. The 4624 type-3 logons are machine accounts (NEWYORK$ 123, SCRANTON$ 37, NASHUA$ 25, UTICA$ 5, WEC$ 8) plus pbeesly (20) — no anomalous/backdoor account. The 4648 explicit-credential logons are pbeesly via PSEXESVC.exe on nashua and normal DWM-/UMFD-/machine-account logons on scranton. The only high-privilege LSASS handles are from PowerShell.exe PID 2976 on scranton (0x1FFFFF, 03:05:16) and wsmprovhost.exe PID 7720 on nashua (0x1F3FFF, 03:09:29, call trace through System.ni.dll / Microsoft.PowerShell.Commands.Management.ni.dll), i.e. remote PowerShell credential theft rather than DC authentication modification. No cryptdll/lsass image-load anomalies beyond the standard cryptdll.dll (32) and lsass.exe (1) loads.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63CAlf | q-3818a59ff7 | ok |
| 2 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2kp9uH | q-fe787fec23 | ok |
| 3 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2kp9uH | q-fe787fec23 | ok |

### F37 · benign / high · T1556.002 · No password-filter DLL registration or LSA Notification Packages modification

Evidence status: **verified**

No password filter DLL was dropped or registered. The only 'password'-named file creation is C:\Program Files\SysinternalsSuite\passwordsDB written by accesschk.exe on scranton at 03:04:35 (a Sysinternals tool output file, not a DLL in a LSA path); the remaining file hits are Cortana filtertrie intermediate files. No 4657 registry change to Notification Packages/Lsa, no 4104 script block referencing Notification Packages, and no image load of a non-Microsoft filter DLL into lsass.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:35.069Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Program Files\SysinternalsSuite\passwordsDB | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63C9mM | q-0fa7b0a44f | ok |
| 2 | 2020-05-02 03:04:35.069Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\Program Files\SysinternalsSuite\accesschk.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63C9mM | q-0fa7b0a44f | ok |

### F38 · benign / high · T1556.005 · No reversible-encryption / Set-ADUser password-flag changes observed

Evidence status: **verified**

All checks for reversible encryption (Set-ADUser, Set-ADAccountControl, dsmod, 4739 policy changes, 'Reversible' strings in PowerShell payloads, process command lines and windows.other messages) returned zero hits. The only AD-related PowerShell script blocks on newyork are the stock ActiveDirectory module resource strings (MSFT_ScriptResourceStrings.psd1, Get-CommonADParameters), not account-flag changes.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:01:30.000Z | newyork.dmevals.local | windows.powershell | win.ScriptBlockText | # Localized	09/15/2018 04:54 AM (GMT)	303:6.40.10614 	MSFT_ScriptResourceStrings.psd1  # Localized MSFT_ScriptResourceStrings.psd1    ConvertFrom-StringData @' … | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMASEsNZ | q-70f497d366 | ok |

### F39 · benign / high · T1556.006 · No MFA / authentication-policy modification observed

Evidence status: **verified**

No 4739 (domain policy change) events exist in windows.security, no Set-ADAuthenticationPolicy/Set-ADUser command lines in Sysmon process creation, and no 4739/5136/4662 events in windows.other. Nothing indicates tampering with multi-factor authentication configuration.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:10.368Z | scranton.dmevals.local | windows.sysmon | registry.path | HKLM\System\CurrentControlSet\Control\Lsa\ProductType | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2ORrtJ | q-06db048358 | ok |

### F40 · benign / high · T1556.007 · No hybrid-identity / Azure AD Connect tampering observed

Evidence status: **verified**

No PowerShell script blocks referencing AzureAD, Connect-MsolService or similar hybrid-identity cmdlets were found, and no 5136/4739 directory-service change events exist in windows.other. The Azure-related binaries seen in Sysmon are the standard IaaSAntimalware and WindowsAzureTelemetryService agents reading lsass with 0x1000/0x1400 access.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:42.009Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\WindowsAzure\Packages\Telemetry\WindowsAzureTelemetryService.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JLx0p9yU | q-e4f05b47c5 | ok |

### F41 · benign / high · T1556.008 · No Network Provider DLL registration observed

Evidence status: **verified**

No Sysmon registry-set (event 13) events touch a NetworkProvider key, and no related script blocks or service installs were found. The registry writes seen are LogonUI/Winlogon UI state and lsass start-up values only.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:20:46.756Z | scranton.dmevals.local | windows.sysmon | registry.path | HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\SessionData\2\LastLoggedOnProvider | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JLx4yj34 | q-06db048358 | ok |

### F45 · benign / medium · T1557.003 · No DHCP spoofing observed; no DHCP server events, no port 67/68 traffic, no DHCP configuration changes

Evidence status: **verified**

No DHCP-related activity was found in any dataset. The windows.other System channel contains no DHCP server/client event codes (1341/1342/1020/1063) in its 216 events, zeek has no connections on UDP 67/68, and no PowerShell DHCP-server cmdlets or rogue-DHCP script blocks were seen. The only network-configuration commands on Windows hosts were ipconfig /all, arp /a and netsh trace start/stop on scranton.dmevals.local, all spawned by Azure guest-agent/Network Watcher/Telemetry binaries (WindowsAzureGuestAgent.exe, WaAppAgent.exe, WindowsAzureTelemetryService.exe, NetworkWatcherAgent.exe) as SYSTEM - routine Azure VM telemetry, not DHCP manipulation.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:57.992Z | scranton.dmevals.local | windows.sysmon | process.command_line | "ipconfig.exe" /all | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JLx1s9Ic | q-53c7fb79bc | ok |
| 2 | 2020-05-02 03:19:57.992Z | scranton.dmevals.local | windows.sysmon | process.parent.executable | C:\WindowsAzure\Packages\WaAppAgent.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JLx1s9Ic | q-53c7fb79bc | ok |
| 3 | 2020-05-02 03:19:17.154Z | scranton.dmevals.local | windows.sysmon | process.command_line | C:\windows\system32\netsh.exe trace start capture=yes traceFile="C:\windows\TEMP\E7116ECA-DFE6-43C7-8FA8-8D3AC5AA8726\B91E06C5-1C7C-4830-9A76-74FA211560A7.etl" | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2LOurf | q-53c7fb79bc | ok |
| 4 | 2020-05-02 03:19:17.154Z | scranton.dmevals.local | windows.sysmon | process.parent.executable | C:\Packages\Plugins\Microsoft.Azure.NetworkWatcher.NetworkWatcherAgentWindows\1.4.1421.1\NetworkWatcherAgent\NetworkWatcherAgent.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2LOurf | q-53c7fb79bc | ok |
| 5 | 2020-05-02 03:19:25.000Z | scranton.dmevals.local | windows.security | process.command_line | "arp.exe" /a | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL8_cVAi | q-4989ff099a | ok |
| 6 | 2020-05-02 03:19:25.000Z | scranton.dmevals.local | windows.security | process.parent.executable | C:\WindowsAzure\Packages\GuestAgent\WindowsAzureGuestAgent.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL8_cVAi | q-4989ff099a | ok |

### F48 · benign / medium · T1558.001 · No golden-ticket indicators: all TGT/TGS requests are AES256 with pre-auth, no anomalous krbtgt ticket use

Evidence status: **verified**

Across the windows.security window (newyork.dmevals.local as DC), 14 event 4768 TGT requests all show PreAuthType 2 and TicketEncryptionType 0x12 (AES256), and all 28 event 4769 TGS requests are also 0x12 with Status 0x0. The krbtgt service tickets requested (by pbeesly and by SCRANTON$) are normal TGT-renewal patterns, not forged tickets. The only LSASS full-access reads were by PowerShell on scranton (see T1558 finding) — a prerequisite for krbtgt theft, but no forged-TGT authentication, no RC4/0x17 downgrade, and no Kerberos error events (only KDC_ERR_PREAUTH_REQUIRED in Zeek, which is normal pre-auth negotiation) were observed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:13.000Z | newyork.dmevals.local | windows.security | win.ServiceName | krbtgt | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL8-bHCF | q-d9affff9ac | ok |
| 2 | 2020-05-02 03:04:04.000Z | newyork.dmevals.local | windows.security | win.TicketEncryptionType | 0x12 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL9MpvNN | q-d9affff9ac | ok |
| 3 | 2020-05-02 03:20:45.000Z | newyork.dmevals.local | windows.security | win.PreAuthType | 2 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL8zTpG- | q-54e8f93f2c | ok |
| 4 | 2020-04-30 00:24:19.110Z | simplerockbuild.simplerock.lan | zeek | zeek.error_msg | KDC_ERR_PREAUTH_REQUIRED | .ds-logs-zeek-default-2026.10.17-000001 / AaFIKqWOc7y0JMDGJw1f | q-e42435a880 | ok |

### F49 · benign / medium · T1558.002 · No silver-ticket indicators: service tickets are AES256 for host accounts only, no forged service-ticket use

Evidence status: **verified**

The 28 event 4769 TGS requests on newyork.dmevals.local target only machine accounts (NEWYORK$, NASHUA$, SCRANTON$, WEC$) and krbtgt, all with TicketEncryptionType 0x12 (AES256) and Status 0x0. There is no RC4 (0x17) downgrade, no unusual SPN targeting, and no service-account ticket anomalies that would indicate a forged silver ticket. Zeek kerberos records (separate 2020-04-30 window) likewise show only AES256 cifs/host/ldap/HTTP TGS requests by pbeesly, all successful.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:14.000Z | newyork.dmevals.local | windows.security | win.ServiceName | WEC$ | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL9Cfa6G | q-d9affff9ac | ok |
| 2 | 2020-05-02 03:09:23.000Z | newyork.dmevals.local | windows.security | win.TicketEncryptionType | 0x12 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL9OrnEj | q-d9affff9ac | ok |
| 3 | 2020-04-30 00:24:19.122Z | simplerockbuild.simplerock.lan | zeek | zeek.service | cifs/NEWYORK | .ds-logs-zeek-default-2026.10.17-000001 / AaFIKqWOc7y0JMDGJw1d | q-e42435a880 | ok |

### F50 · benign / medium · T1558.003 · No Kerberoasting: no RC4 TGS requests and no bulk SPN enumeration by any account

Evidence status: **verified**

Kerberoasting requires RC4-encrypted TGS requests (0x17) and/or many distinct SPNs requested by one account. In this window all 28 TGS requests are AES256 (0x12), requested by pbeesly and SCRANTON$ for a small set of machine accounts, and no PowerShell script blocks or process command lines referencing SPN enumeration, GetUserSPNs, Invoke-Kerberoast or Rubeus were found. The Zeek kerberos log (2020-04-30) shows only routine AES256 TGS requests for cifs/host/ldap/HTTP services.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:18.000Z | newyork.dmevals.local | windows.security | win.TicketEncryptionType | 0x12 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL9LnloS | q-d9affff9ac | ok |
| 2 | 2020-05-02 03:12:25.000Z | newyork.dmevals.local | windows.security | win.ServiceName | NASHUA$ | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL9LnVrY | q-d9affff9ac | ok |
| 3 | 2020-04-30 00:33:14.816Z | simplerockbuild.simplerock.lan | zeek | zeek.service | ldap/NEWYORK.dmevals.local | .ds-logs-zeek-default-2026.10.17-000001 / AaFIKqWOc7y0JMDGKA0i | q-e42435a880 | ok |

### F51 · benign / medium · T1558.004 · No AS-REP roasting: every TGT request used pre-authentication

Evidence status: **verified**

AS-REP roasting requires TGT requests for accounts without Kerberos pre-authentication. All 14 event 4768 records on newyork.dmevals.local show PreAuthType 2 (pre-auth enabled) with Status 0x0, for pbeesly and SCRANTON$. The Zeek kerberos log shows the expected KDC_ERR_PREAUTH_REQUIRED followed by a successful AES256 AS exchange for pbeesly — normal pre-auth negotiation, not roasting. No asreproast/GetNPUsers/Rubeus command lines or script blocks were found.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:18.000Z | newyork.dmevals.local | windows.security | win.PreAuthType | 2 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL9OrXFP | q-54e8f93f2c | ok |
| 2 | 2020-05-02 03:19:13.000Z | newyork.dmevals.local | windows.security | win.TargetUserName | SCRANTON$ | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL8-bHB- | q-54e8f93f2c | ok |
| 3 | 2020-04-30 00:24:19.119Z | simplerockbuild.simplerock.lan | zeek | zeek.cipher | aes256-cts-hmac-sha1-96 | .ds-logs-zeek-default-2026.10.17-000001 / AaFIKqWOc7y0JMDGJw1g | q-e42435a880 | ok |

### F53 · benign / medium · T1606.001 · No web cookie forging; only legitimate WebDAV DavSetCookie client calls

Evidence status: **verified**

The only cookie-related activity in the window is rundll32.exe invoking davclnt.dll,DavSetCookie for 192.168.0.4 http://192.168.0.4/webdav on scranton.dmevals.local at 03:08:50, 03:10:22 and 03:10:23, which is the standard WebDAV client mechanism used by the Invoke-Exfil script to mount the remote share. No browser cookie store was read or written: the single cookie-named file-creation event is C:\Windows\ServiceProfiles\LocalService\AppData\Local\Packages\warp_jit_db4a1097-b484-4973-bbf2-a04208ecd4d4\AC\INetCookies, a system service profile artifact, and the PowerShell cookie search returned zero hits. No evidence of forged web cookies.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:08:50.846Z | scranton.dmevals.local | windows.sysmon | process.command_line | rundll32.exe C:\windows\system32\davclnt.dll,DavSetCookie 192.168.0.4 http://192.168.0.4/webdav | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2lq7xd | q-5b2bceb06d | ok |
| 2 | 2020-05-02 03:10:22.994Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\Windows\System32\rundll32.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2jpdJE | q-5b2bceb06d | ok |

### F54 · benign / medium · T1606.002 · No SAML token forging observed; logon packages are Kerberos/Negotiate only

Evidence status: **verified**

Across 297 successful 4624 logons in windows.security the authentication packages are Kerberos (217), Negotiate (78), NTLM (1) and one unset value, with logon processes Kerberos, Advapi, User32, NtLmSsp and one unset - no SAML, ADFS or token-based authentication package appears. A search of windows.security for SAML/ADFS/token object and service names returned only Credential Manager 5379 events for WindowsLive token/cert and MicrosoftAccount targets, which are stored-credential reads, not forged SAML assertions. No SAML token forging was observed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:28.000Z | nashua.dmevals.local | windows.security | win.TargetName | WindowsLive:(token):name=02tkygcqupblzpan;serviceuri=* | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL9Jl2tp | q-75b25819e1 | ok |
| 2 | 2020-05-02 03:11:18.000Z | scranton.dmevals.local | windows.security | win.TargetServerName | NASHUA | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL9OrXFV | q-42ad8ed90a | ok |

### F55 · benign / high · T1621 · WebDAV 401 challenge/response burst from 10.0.1.4 to 192.168.0.4 is Windows WebDAV-MiniRedir, not MFA request generation

Evidence status: **verified**

The only T1621-relevant hits were 62 zeek HTTP events, all between 10.0.1.4 and 192.168.0.4:80 (single destination, single source). The 31 HTTP 401 responses flagged by the stacking check are the normal WebDAV authentication handshake: every request is issued by user agent 'Microsoft-WebDAV-MiniRedir/10.0.18362' and each 401 is immediately followed by a successful retry on the same URI (e.g. OPTIONS /webdav 401 -> 301, PROPFIND /webdav/ 401 -> 207, PUT /webdav/OfficeSupplies.7z 401 -> 201, LOCK 401 -> 200, HEAD 401 -> 200, PROPPATCH 401 -> 207, UNLOCK 401 -> 204). The session ends with a successful PUT of /webdav/OfficeSupplies.7z (201 Created) and a LOCK/UNLOCK cycle, i.e. a file copy to a WebDAV share, not repeated authentication challenges to an identity provider. No MFA/identity-provider infrastructure is present anywhere in the data: all 53 DNS queries resolve only internal AD names (newyork/nashua/scranton.dmevals.local, wec.dmevals.local, _ldap._tcp...) and Microsoft/Windows Update/azureedge endpoints, and all 378 TLS records have client server_name 192.168.0.4 (no okta/duo/azure-mfa style endpoint). On the Windows side there is no MFA activity either: zero 4625 failed logons, zero PowerShell script blocks referencing MFA/2FA/Authenticator, and the only two script-block matches for 'azure' are the benign Microsoft xActiveDirectory DSC module manifest (C:\Program Files\WindowsPowerShell\Modules\xActiveDirectory\xActiveDirectory.psd1) loaded by SYSTEM on newyork.dmevals.local. 4624 logons are ordinary (218 network Kerberos, 61 service, 15 interactive, 2 remote-interactive). No evidence of MFA fatigue/push bombing or MFA request generation.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-04-30 00:32:21.422Z | simplerockbuild.simplerock.lan | zeek | user_agent.original | Microsoft-WebDAV-MiniRedir/10.0.18362 | .ds-logs-zeek-default-2026.10.17-000001 / AaFIKqWOc7y0JMDGJw17 | q-d2b18966f3 | ok |
| 2 | 2020-04-30 00:32:21.422Z | simplerockbuild.simplerock.lan | zeek | http.response.status_code | 401 | .ds-logs-zeek-default-2026.10.17-000001 / AaFIKqWOc7y0JMDGJw17 | q-d2b18966f3 | ok |
| 3 | 2020-04-30 00:32:21.446Z | simplerockbuild.simplerock.lan | zeek | http.response.status_code | 200 | .ds-logs-zeek-default-2026.10.17-000001 / AaFIKqWOc7y0JMDGJw2B | q-d2b18966f3 | ok |
| 4 | 2020-04-30 00:32:21.918Z | simplerockbuild.simplerock.lan | zeek | zeek.uri | /webdav/OfficeSupplies.7z | .ds-logs-zeek-default-2026.10.17-000001 / AaFIKqWOc7y0JMDGJw2G | q-09d604ab66 | ok |
| 5 | 2020-04-30 00:32:21.918Z | simplerockbuild.simplerock.lan | zeek | zeek.status_code | 201 | .ds-logs-zeek-default-2026.10.17-000001 / AaFIKqWOc7y0JMDGJw2G | q-09d604ab66 | ok |
| 6 | 2020-04-30 00:32:18.095Z | simplerockbuild.simplerock.lan | zeek | destination.ip | 192.168.0.4 | .ds-logs-zeek-default-2026.10.17-000001 / AaFIKqWOc7y0JMDGKA5C | q-d2b18966f3 | ok |
| 7 | 2020-04-30 00:06:38.899Z | simplerockbuild.simplerock.lan | zeek | dns.question.name | newyork.dmevals.local | .ds-logs-zeek-default-2026.10.17-000001 / AaFIKqWOc7y0JMDGJw2z | q-8040de7a7c | ok |
| 8 | 2020-05-02 03:16:32.000Z | newyork.dmevals.local | windows.powershell | win.Path | C:\Program Files\WindowsPowerShell\Modules\xActiveDirectory\xActiveDirectory.psd1 | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMAVHr_u | q-7ca5924081 | ok |

## Pivot candidates

Processes the pivot reviewer had to assess (started by a script host or from outside the Windows directory, rare in the 15-minute windows around verified activity).

| Host | Executable | Starts | Parents | Assessment | Reason |
|---|---|---|---|---|---|
| nashua.dmevals.local | C:\Program Files\WindowsApps\Microsoft.SkypeApp_14.35.152.0_x64__kzf8qxf38zg5c\S… | 1 | C:\Program Files\WindowsApps\Microsoft.SkypeApp_14.35.152.0_x64__kzf8qxf38zg5c\S… | benign | Store Skype app self-restart. |
| nashua.dmevals.local | C:\Windows\Temp\python.exe | 5 | C:\Windows\PSEXESVC.exe, C:\Windows\Temp\python.exe | malicious | PsExec-delivered C2 client on nashua. |
| nashua.dmevals.local | C:\Windows\Temp\Rar.exe | 1 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | malicious | Rar.exe from Temp by pbeesly's PowerShell created password-protected working.zip archives. |
| nashua.dmevals.local | C:\Windows\Temp\sdelete64.exe | 3 | C:\Windows\System32\cmd.exe | malicious | Wiped Rar.exe and staged working.zip on nashua. |
| nashua.dmevals.local | C:\WindowsAzure\Packages\CollectGuestLogs.exe | 1 | C:\WindowsAzure\Packages\WaAppAgent.exe | benign | Azure guest log collection. |
| scranton.dmevals.local | C:\Packages\Plugins\Microsoft.Azure.NetworkWatcher.NetworkWatcherAgentWindows\1.… | 4 | C:\Windows\System32\cmd.exe, C:\Windows\System32\services.exe | benign | Azure Network Watcher extension. |
| scranton.dmevals.local | C:\Packages\Plugins\Microsoft.Azure.Security.IaaSAntimalware\1.5.5.9\Antimalware… | 1 | C:\WindowsAzure\Packages\GuestAgent\WindowsAzureGuestAgent.exe | benign | Azure antimalware config helper. |
| scranton.dmevals.local | C:\Packages\Plugins\Microsoft.Compute.CustomScriptExtension\1.10.5\bin\CustomScr… | 1 | C:\Windows\System32\cmd.exe | benign | Azure VM extension handler. |
| scranton.dmevals.local | C:\Packages\Plugins\Microsoft.Compute.JsonADDomainExtension\1.3.2\bin\JsonADDoma… | 1 | C:\Windows\System32\cmd.exe | benign | Azure domain-join extension. |
| scranton.dmevals.local | C:\Program Files (x86)\Google\Update\1.3.35.452\GoogleCrashHandler.exe | 2 | C:\Program Files (x86)\Google\Update\GoogleUpdate.exe | benign | Google updater crash handler. |
| scranton.dmevals.local | C:\Program Files (x86)\Google\Update\1.3.35.452\GoogleCrashHandler64.exe | 2 | C:\Program Files (x86)\Google\Update\GoogleUpdate.exe | benign | Google updater crash handler. |
| scranton.dmevals.local | C:\Program Files (x86)\Google\Update\GoogleUpdate.exe | 3 | C:\Program Files (x86)\Google\Update\GoogleUpdate.exe, C:\Windows\System32\servi… | benign | Google updater service. |
| scranton.dmevals.local | C:\Program Files\SysinternalsSuite\accessChk.exe | 1 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | malicious | Attacker-staged tool that wrote passwordsDB. |
| scranton.dmevals.local | C:\Program Files\SysinternalsSuite\PsExec64.exe | 4 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | malicious | Lateral movement to NASHUA with plaintext credentials. |
| scranton.dmevals.local | C:\Program Files\SysinternalsSuite\sdelete64.exe | 3 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | malicious | Anti-forensic deletion of dropped .scr, Draft.Zip and SysinternalsSuite.zip on scranton. |
| scranton.dmevals.local | C:\Program Files\Windows Defender\MsMpEng.exe | 1 | C:\Windows\System32\services.exe | benign | Defender service; LSASS handle is normal scanning. |
| scranton.dmevals.local | C:\Program Files\Windows Defender\NisSrv.exe | 2 | C:\Windows\System32\services.exe | benign | Defender network inspection service. |
| scranton.dmevals.local | C:\ProgramData\victim\â€®cod.3aka3.scr | 1 | C:\Windows\explorer.exe | malicious | Screensaver-named payload launched by explorer.exe that wrote monkey.png used by the IEX stego loader. |
| scranton.dmevals.local | C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe | 2 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | malicious | Compiled in-memory payload DLLs qkbkqqbs.dll and 0piklvia.dll from PowerShell. |
| scranton.dmevals.local | C:\Windows\System32\hostui.exe | 1 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | malicious | Started via -verb runas as elevation proxy before registry Invoke-Expression loader. |
| scranton.dmevals.local | C:\Windows\System32\sdclt.exe | 3 | C:\Windows\System32\cmd.exe | suspicious | Three cmd.exe-launched sdclt runs just before the csc.exe payload compile; known UAC-bypass proxy. |
| scranton.dmevals.local | C:\WindowsAzure\Packages\GuestAgent\BfeToolWin8.exe | 1 | C:\WindowsAzure\Packages\GuestAgent\WindowsAzureGuestAgent.exe | benign | Azure firewall helper. |
| scranton.dmevals.local | C:\WindowsAzure\Packages\GuestAgent\FindVolume\FindVolume.exe | 1 | C:\WindowsAzure\Packages\GuestAgent\WindowsAzureGuestAgent.exe | benign | Azure volume discovery helper. |
| scranton.dmevals.local | C:\WindowsAzure\Packages\GuestAgent\WindowsAzureGuestAgent.exe | 1 | C:\Windows\System32\services.exe | benign | Azure guest agent service. |
| scranton.dmevals.local | C:\WindowsAzure\Packages\Telemetry\WindowsAzureTelemetryService.exe | 1 | C:\Windows\System32\services.exe | benign | Azure telemetry service. |
| scranton.dmevals.local | C:\WindowsAzure\Packages\WaAppAgent.exe | 1 | C:\Windows\System32\services.exe | benign | Azure agent host. |
| scranton.dmevals.local | C:\WindowsAzure\SecAgent\WaSecAgentProv.exe | 2 | C:\WindowsAzure\Packages\WaAppAgent.exe | benign | Azure security agent provider. |
| scranton.dmevals.local | C:\WindowsAzure\WindowsAzureNetAgent_1.0.0.143\WindowsAzureNetAgent\Plugins\VFPl… | 1 | C:\WindowsAzure\WindowsAzureNetAgent_1.0.0.143\WindowsAzureNetAgent\WindowsAzure… | benign | Azure network agent plugin. |
| scranton.dmevals.local | C:\WindowsAzure\WindowsAzureNetAgent_1.0.0.143\WindowsAzureNetAgent\WindowsAzure… | 1 | C:\Windows\System32\services.exe | benign | Azure network agent service. |

## Technique conclusions

One line per technique in scope: status from the triage of its family; `not_observed` = checked, nothing found; `not_observable` = no dataset records it.

| Technique | Status | Reason |
|---|---|---|
| T1003 OS Credential Dumping | malicious | Sysinternals credential tooling staged and used. |
| T1003.001 LSASS Memory | malicious | Extra LSASS read by pbeesly's powershell.exe. |
| T1003.002 Security Account Manager | benign | Only SAM\SAM write is lsass.exe updating HKLM\SAM\SAM\Domains\Account\F; no reg save/esentutl/hive copies, no SAM/SECURITY object access. |
| T1003.003 NTDS | not_observed | No ntdsutil/vssadmin/diskshadow process, no ntds/.dit file creation, no NTDS object access, no SMB file names. |
| T1003.004 LSA Secrets | not_observed | No lsadump/secrets/reg save command lines or script blocks, no SECURITY\Policy\Secrets object access; samlib.dll loads are Microsoft-signed system DLLs. |
| T1003.005 Cached Domain Credentials | not_observed | No 4663 access on Cache/SECURITY objects and no cachedump/mscash references in any channel. |
| T1003.006 DCSync | benign | Zeek drsuapi traffic is only DRSBind/DRSCrackNames/DRSUnbind from 10.0.1.4 and 10.0.1.6 to 10.0.0.4; no DRSGetNCChanges and no dcsync/lsadump tooling in Windows logs. |
| T1040 Network Sniffing | benign | The only packet-capture activity is the Azure Network Watcher agent (NetworkWatcherAgent.exe -> netsh.exe trace start capture=yes, SYSTEM on scranton.dmevals.local, stopped 7s later). No pktmon/windump/tcpdump, no pcap/n… |
| T1056 Input Capture | malicious | Input capture tooling (screen capture) and full-access lsass handle with an unbacked remote thread were executed by PowerShell on scranton.dmevals.local in the same session as exfiltration scripts. |
| T1056.001 Keylogging | malicious | Get-Keystrokes job executed on scranton. |
| T1056.002 GUI Input Capture | malicious | Screen capture job ran on scranton. |
| T1056.003 Web Portal Capture | not_observed | Zero hits for IIS/wwwroot/inetpub command lines, file access, PowerShell WebAdministration scripts or login/logon/signin HTTP URLs. |
| T1056.004 Credential API Hooking | malicious | Anchored LSASS handle/remote thread; no new instances. |
| T1110 Brute Force | not_observed | Zero 4625 failed logons in windows.security; the only credential-validation event is a single successful 4776 (Status 0x0) for pbeesly on newyork. No repeated authentication attempts. |
| T1110.001 Password Guessing | not_observed | No failed-logon sequences and no password-guessing code; the matching 4104 blocks are certificate export, 7-Zip exfiltration and benign helper/help text. |
| T1110.002 Password Cracking | malicious | On scranton.dmevals.local, hidden-window encoded PowerShell (PID 2976, user pbeesly) opened lsass.exe with GrantedAccess 0x1F3FFF and 0x1FFFFF at 2020-05-02T03:05:16Z — full-access credential dumping for offline cracking… |
| T1110.003 Password Spraying | not_observed | All 4648 explicit-credential logons use the single account pbeesly (plus machine/service accounts from winlogon/wininit/taskhostw); no one-password-many-accounts pattern. |
| T1110.004 Credential Stuffing | not_observed | No failed authentications and no credential-list iteration in script blocks; stuffing would require repeated 4625/4771 which are absent. |
| T1111 Multi-Factor Authentication Interception | not_observed | No MFA/smart-card interception evidence: zero smart-card registry modifications (C130), no smart-card or MFA provider events in windows.other (only a routine 'Credential Guard configuration: 0x0, 0' message), and no Powe… |
| T1187 Forced Authentication | malicious | Zeek shows 10.0.1.4 failing SMB to 192.168.0.4 on 445/139 (all REJ) and then falling back to HTTP port 80 using DavClnt and Microsoft-WebDAV-MiniRedir/10.0.18362, with repeated 401 challenges followed by 207/201/200/204 … |
| T1212 Exploitation for Credential Access | malicious | On scranton.dmevals.local, PowerShell.exe (PID 2976) in the pbeesly intrusion chain opened lsass.exe with 0x1f3fff then 0x1fffff and winlogon.exe/LogonUI.exe/dwm.exe with 0x1fffff at 03:05:16, with an UNKNOWN call-trace … |
| T1539 Steal Web Session Cookie | not_observed | No access to browser cookie/credential stores: zero Sysmon 10 process-access events targeting chrome/firefox/msedge/iexplore/brave/opera, zero Security 4663 object accesses on cookies/login data/user data/mozilla paths, … |
| T1552 Unsecured Credentials | malicious | Plaintext credentials in scripts and files. |
| T1552.001 Credentials In Files | malicious | passwordsDB file and plaintext credentials in tooling. |
| T1552.002 Credentials in Registry | suspicious | Registry value piped to Invoke-Expression. |
| T1552.003 Shell History | not_observed | All four ConsoleHost_history/PSReadLine checks returned zero hits. |
| T1552.004 Private Keys | malicious | Get-PrivateKeys executed. |
| T1552.006 Group Policy Preferences | not_observed | All five Groups.xml/cpassword/SYSVOL checks returned zero hits; only routine svchost gpt.ini policy refresh seen. |
| T1555 Credentials from Password Stores | suspicious | Vault file touched only by lsass.exe. |
| T1555.003 Credentials from Web Browsers | malicious | Cert private keys exported to .pfx on scranton. |
| T1555.004 Windows Credential Manager | not_observed | No cmdkey/vault/credman/DPAPI activity; SAM and lsass handle requests came from lsass.exe itself during normal service start, and the only Credential string was a Credential Guard status message. |
| T1555.005 Password Managers | not_observed | No KeePass/1Password/Bitwarden process, .kdbx file, memory access or script reference anywhere in the datasets. |
| T1556 Modify Authentication Process | not_observed | LSASS access hits are benign system/AV/telemetry readers (0x1000/0x1400) plus lsass start-up handles; the only full-access readers are the actor's PowerShell/WinRM credential dumping. No authentication-process modificati… |
| T1556.001 Domain Controller Authentication | not_observed | No skeleton-key style patching on DCs; 4624/4648 logons show only machine accounts and pbeesly via PSEXESVC. High-privilege lsass handles came from PowerShell (scranton) and wsmprovhost (nashua) credential theft. |
| T1556.002 Password Filter DLL | not_observed | No password-filter DLL dropped or registered; only Sysinternals accesschk.exe writing passwordsDB. No 4657 Notification Packages/Lsa changes, no filter DLL loaded into lsass. |
| T1556.005 Reversible Encryption | not_observed | All reversible-encryption checks (Set-ADUser, Set-ADAccountControl, dsmod, 4739, 'Reversible' strings) returned zero hits. |
| T1556.006 Multi-Factor Authentication | not_observed | No 4739 policy-change events, no Set-ADAuthenticationPolicy command lines, no 5136/4662 directory changes. |
| T1556.007 Hybrid Identity | not_observed | No AzureAD/Connect-MsolService script blocks and no directory-service change events; Azure binaries seen are standard antimalware/telemetry agents. |
| T1556.008 Network Provider DLL | not_observed | No registry writes to any NetworkProvider key and no related DLL registration or service install. |
| T1557 Adversary-in-the-Middle | malicious | Zeek conn log shows non-vendor MAC 12:34:56:78:9a:bc answering for four distinct IPs (10.0.0.4, 10.0.1.6, 192.168.0.4, 192.168.0.5) while genuine hosts use 00:0d:3a:* MACs - an on-path device intercepting SMB/gssapi/kerb… |
| T1557.001 Name Resolution Poisoning and SMB Relay | suspicious | NBT-NS/LLMNR queries for SCRANTON/NASHUA from 10.0.1.4 and 10.0.1.6 with no legitimate responder, and SMB auth sessions to 10.0.0.4/10.0.1.6 answered by the rogue MAC; relay inferred, no responder tooling or DNSClient ta… |
| T1557.002 ARP Cache Poisoning | malicious | Single MAC 12:34:56:78:9a:bc bound to four different IPs in the zeek capture is the signature of ARP cache poisoning; the poisoning host itself is not among the monitored Windows hosts. |
| T1557.003 DHCP Spoofing | not_observed | No DHCP server/client events (1341/1342/1020/1063), no UDP 67/68 traffic in zeek, no DHCP PowerShell cmdlets; the only ipconfig/netsh/arp executions are Azure guest-agent and Network Watcher telemetry on scranton. |
| T1558 Steal or Forge Kerberos Tickets | suspicious | Host scranton.dmevals.local is clearly compromised (malicious .scr -> cmd -> PowerShell steganographic IEX loader -> csc.exe compile -> sdelete64 anti-forensics) and PowerShell opened lsass.exe with 0x1f3fff/0x1fffff acc… |
| T1558.001 Golden Ticket | not_observed | All 4768/4769 events are AES256 (0x12) with pre-auth and Status 0x0; krbtgt tickets requested are normal renewals. No forged-TGT authentication, RC4 downgrade, or Kerberos error events beyond normal KDC_ERR_PREAUTH_REQUI… |
| T1558.002 Silver Ticket | not_observed | TGS requests target only machine accounts (NEWYORK$, NASHUA$, SCRANTON$, WEC$) and krbtgt, all AES256 with success; no RC4 downgrade or anomalous service-ticket use. |
| T1558.003 Kerberoasting | not_observed | No RC4 (0x17) TGS requests, no bulk/distinct SPN enumeration, and no Kerberoast tooling in PowerShell script blocks or process command lines. |
| T1558.004 AS-REP Roasting | not_observed | All 14 event 4768 TGT requests show PreAuthType 2 (pre-auth enabled); Zeek shows normal KDC_ERR_PREAUTH_REQUIRED then AES256 success. No AS-REP roasting tooling observed. |
| T1606 Forge Web Credentials | not_observed | No forged web credential artifacts were found. The credential-access activity present (LSASS access with 0x1F3FFF/0x1FFFFF by PowerShell on scranton and wsmprovhost on nashua, Credential Manager 5379 enumeration by pbees… |
| T1606.001 Web Cookies | not_observed | Only legitimate WebDAV client cookie handling (rundll32 davclnt.dll,DavSetCookie to 192.168.0.4/webdav) and a system INetCookies file creation; no browser cookie store access or cookie forgery, and the PowerShell cookie … |
| T1606.002 SAML Tokens | not_observed | 4624 authentication packages are only Kerberos, Negotiate and NTLM; no SAML/ADFS token issuance or use appears in windows.security, and the only token-named objects are WindowsLive Credential Manager entries read via 537… |
| T1621 Multi-Factor Authentication Request Generatio… | benign | The 62 HTTP events (31 x 401) are a single Windows WebDAV-MiniRedir session from 10.0.1.4 to 192.168.0.4 where each 401 is followed by a successful authenticated retry and a final PUT 201 of /webdav/OfficeSupplies.7z. No… |
| T1649 Steal or Forge Authentication Certificates | malicious | Certificate private keys exported to .pfx. |

## Coverage

Cells: number of hits of the planned checks, `n/a` (reason in report.json), or GAP.

| Technique | windows.other | windows.powershell | windows.security | windows.sysmon | zeek |
|---|---|---|---|---|---|
| T1003 OS Credential Dumping | 0 hits | 0 hits | 6 hits | 773 hits | 135 hits |
| T1003.001 LSASS Memory | 0 hits | 0 hits | 116 hits | 655 hits | 123 hits |
| T1003.002 Security Account Manager | 1 hits | 9 hits | 6 hits | 4 hits | 12 hits |
| T1003.003 NTDS | 0 hits | 0 hits | 0 hits | 0 hits | 12 hits |
| T1003.004 LSA Secrets | 11 hits | 0 hits | 103 hits | 349 hits | 12 hits |
| T1003.005 Cached Domain Credentials | 0 hits | 4 hits | 4 hits | 6956 hits | 12 hits |
| T1003.006 DCSync | 0 hits | 0 hits | 21 hits | 0 hits | 123 hits |
| T1040 Network Sniffing | 0 hits | 0 hits | 1 hits | 0 hits | 613 hits |
| T1056 Input Capture | 0 hits | 0 hits | 162 hits | 652 hits | 613 hits |
| T1056.001 Keylogging | 0 hits | 0 hits | 0 hits | 352 hits | 613 hits |
| T1056.002 GUI Input Capture | 0 hits | 5496 hits | 3 hits | 3 hits | 62 hits |
| T1056.003 Web Portal Capture | 0 hits | 0 hits | 0 hits | 8 hits | 0 hits |
| T1056.004 Credential API Hooking | n/a | 0 hits | 19 hits | 60196 hits | n/a |
| T1110 Brute Force | n/a | 4 hits | 1 hits | 0 hits | n/a |
| T1110.001 Password Guessing | n/a | 4 hits | 0 hits | n/a | n/a |
| T1110.002 Password Cracking | n/a | 0 hits | 153 hits | 329 hits | n/a |
| T1110.003 Password Spraying | n/a | 4 hits | 15 hits | n/a | n/a |
| T1110.004 Credential Stuffing | n/a | 4 hits | 0 hits | n/a | n/a |
| T1111 Multi-Factor Authentication Interception | 2 hits | 3 hits | 312 hits | 326 hits | n/a |
| T1187 Forced Authentication | 0 hits | 0 hits | 11140 hits | 69 hits | 86 hits |
| T1212 Exploitation for Credential Access | 0 hits | 0 hits | 42 hits | 327 hits | 35 hits |
| T1539 Steal Web Session Cookie | 3 hits | 5157 hits | 4 hits | 162 hits | n/a |
| T1552 Unsecured Credentials | 2 hits | 4 hits | 0 hits | 19 hits | 0 hits |
| T1552.001 Credentials In Files | 0 hits | 1 hits | 178 hits | 72 hits | 448 hits |
| T1552.002 Credentials in Registry | 2 hits | 4 hits | 838 hits | 20 hits | n/a |
| T1552.003 Shell History | n/a | 0 hits | 0 hits | 0 hits | n/a |
| T1552.004 Private Keys | 0 hits | 1 hits | 0 hits | 1 hits | n/a |
| T1552.006 Group Policy Preferences | 0 hits | 0 hits | 0 hits | 0 hits | n/a |
| T1555 Credentials from Password Stores | 0 hits | 3 hits | 29 hits | 652 hits | n/a |
| T1555.003 Credentials from Web Browsers | 0 hits | 0 hits | 0 hits | 1 hits | n/a |
| T1555.004 Windows Credential Manager | 2 hits | 3 hits | 0 hits | 326 hits | n/a |
| T1555.005 Password Managers | 0 hits | 0 hits | 0 hits | 0 hits | n/a |
| T1556 Modify Authentication Process | 4 hits | 0 hits | 0 hits | 418 hits | n/a |
| T1556.001 Domain Controller Authentication | 0 hits | 0 hits | 233 hits | 359 hits | n/a |
| T1556.002 Password Filter DLL | 5 hits | 0 hits | 2 hits | 8 hits | n/a |
| T1556.005 Reversible Encryption | 0 hits | 1 hits | 0 hits | 0 hits | n/a |
| T1556.006 Multi-Factor Authentication | 0 hits | 0 hits | 7 hits | 0 hits | n/a |
| T1556.007 Hybrid Identity | 0 hits | 0 hits | 594 hits | 3 hits | n/a |
| T1556.008 Network Provider DLL | 1 hits | 0 hits | 36 hits | 20183 hits | n/a |
| T1557 Adversary-in-the-Middle | 0 hits | 0 hits | 10977 hits | 1310 hits | 613 hits |
| T1557.001 Name Resolution Poisoning and SMB Relay | 5 hits | 0 hits | 23 hits | 0 hits | 57 hits |
| T1557.002 ARP Cache Poisoning | 3 hits | 0 hits | 5 hits | 1315 hits | 613 hits |
| T1557.003 DHCP Spoofing | 216 hits | 0 hits | 297 hits | 5 hits | 0 hits |
| T1558 Steal or Forge Kerberos Tickets | 1 hits | 0 hits | 509 hits | 652 hits | 35 hits |
| T1558.001 Golden Ticket | 1 hits | 0 hits | 268 hits | 326 hits | 35 hits |
| T1558.002 Silver Ticket | 97 hits | 0 hits | 268 hits | 326 hits | 35 hits |
| T1558.003 Kerberoasting | 1 hits | 0 hits | 580 hits | 326 hits | 35 hits |
| T1558.004 AS-REP Roasting | 1 hits | 0 hits | 28 hits | 0 hits | 35 hits |
| T1606 Forge Web Credentials | 0 hits | 3 hits | 609 hits | 652 hits | 2237 hits |
| T1606.001 Web Cookies | n/a | 0 hits | 312 hits | 163 hits | 124 hits |
| T1606.002 SAML Tokens | n/a | 1 hits | 312 hits | 1 hits | 124 hits |
| T1621 Multi-Factor Authentication Request Generatio… | n/a | 0 hits | 0 hits | n/a | 124 hits |
| T1649 Steal or Forge Authentication Certificates | n/a | 1 hits | 86 hits | 1 hits | 791 hits |

Cells: 265, gaps: 0.

## Queries

Every MCP tool call of this run (1316), in order (source: mcp_audit.jsonl written by the MCP server).

| Query | Phase | Tool | Arguments | Hits / rows | Cited by |
|---|---|---|---|---|---|
| q-6f4f613034 | scope | list_data_sources | {} | None |  |
| q-1ec6516430 | scope | get_registry | {} | None |  |
| q-a5e1d4b1a5 | scope | get_fields | {"dataset": "windows.other", "prefix": ""} | None |  |
| q-d0dc6693c4 | scope | get_fields | {"dataset": "windows.powershell", "prefix": ""} | None |  |
| q-07ef999565 | scope | get_fields | {"dataset": "windows.security", "prefix": ""} | None |  |
| q-c4018b1246 | scope | get_fields | {"dataset": "windows.sysmon", "prefix": ""} | None |  |
| q-b5dba4acd1 | scope | get_fields | {"dataset": "zeek", "prefix": ""} | None |  |
| q-9fd7938cab | check C001 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 447 |  |
| q-0d887a8876 | check C002 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 326 |  |
| q-554a2aaa0c | check C003 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*lsass* OR process.command_line:*procdump* OR process.command_line:*MiniDump* OR process.command_line:*mimikatz* OR process.command_line:*ntdsutil* OR process.command_line:*\"reg sa… | 0 |  |
| q-8a9c10fb81 | check C004 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND (win.ObjectName:*lsass* OR win.ObjectName:*SAM* OR win.ObjectName:*SECURITY* OR win.ObjectName:*NTDS*)", "time_from": null, "time_to": null, "size": 100, "sub_field": null… | 6 |  |
| q-925788d39d | check C005 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND (process.command_line:*lsass* OR process.command_line:*procdump* OR process.command_line:*MiniDump* OR process.command_line:*ntdsutil* OR process.command_line:*mimikat… | 0 |  |
| q-7863f8cce2 | check C006 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*MiniDump* OR win.ScriptBlockText:*mimikatz* OR win.ScriptBlockText:*Invoke-Mimikatz* OR win.ScriptBlockText:*sekurlsa* OR win.ScriptBlockText:*… | 0 |  |
| q-a694f412d0 | check C007 | search | {"dataset": "windows.other", "query": "message:*lsass* OR message:*procdump* OR message:*MiniDump* OR message:*mimikatz* OR message:*ntdsutil*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.… | 0 |  |
| q-6d173d9b73 | check C008 | aggregate | {"dataset": "zeek", "field": "zeek.service", "query": "event.action:dce_rpc OR event.action:smb_files", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 135 |  |
| q-9b51b4bbfd | check C009 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 326 |  |
| q-29a5e5caba | check C010 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 326 |  |
| q-4e9bf6333c | check C011 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*comsvcs* OR process.command_line:*MiniDump* OR process.command_line:*procdump* OR process.command_line:*lsass*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host… | 1 |  |
| q-edb33dcc73 | check C012 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (win.TargetFilename:*.dmp OR win.TargetFilename:*lsass*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process… | 2 |  |
| q-ece163895f | check C013 | search | {"dataset": "windows.sysmon", "query": "event.code:13 AND (registry.path:*lsass* OR registry.path:*WDigest* OR registry.path:*UseLogonCredential*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "ev… | 0 |  |
| q-9de095a35b | check C014 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4673 AND (win.ObjectName:*lsass* OR win.ProcessName:*lsass*)", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 103 |  |
| q-fe159c8084 | check C015 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4656 AND win.ObjectName:*lsass*", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 13 |  |
| q-ac9c852c32 | check C016 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*MiniDump* OR win.ScriptBlockText:*sekurlsa* OR win.ScriptBlockText:*Invoke-Mimikatz*)", "time_from": null, "time_to": null, "fields": ["@timest… | 0 |  |
| q-d1c8f94df4 | check C017 | search | {"dataset": "windows.other", "query": "message:*lsass* OR message:*MiniDump* OR message:*procdump*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "p… | 0 |  |
| q-286486cff2 | check C018 | aggregate | {"dataset": "zeek", "field": "zeek.operation", "query": "event.action:dce_rpc", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 123 |  |
| q-751459c0db | check C019 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*reg\\ save* OR process.command_line:*reg.exe* OR process.command_line:*SAM* OR process.command_line:*esentutl*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host… | 0 |  |
| q-79ed574b16 | check C020 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (win.TargetFilename:*SAM* OR win.TargetFilename:*SECURITY* OR win.TargetFilename:*SYSTEM* OR win.TargetFilename:*.hiv*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "obser… | 3 |  |
| q-ab8384df92 | check C021 | search | {"dataset": "windows.sysmon", "query": "event.code:2 AND (win.TargetFilename:*SAM* OR win.TargetFilename:*SECURITY*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "proce… | 0 |  |
| q-d46ad4fdbc | check C022 | search | {"dataset": "windows.sysmon", "query": "event.code:13 AND (registry.path:*SAM\\\\SAM* OR registry.path:*SECURITY\\\\Policy*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name"… | 1 |  |
| q-a11ac4967a | check C023 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND (process.command_line:*reg* OR process.command_line:*esentutl* OR process.command_line:*SAM*)", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 6 |  |
| q-7f0bef8b37 | check C024 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND (win.ObjectName:*SAM* OR win.ObjectName:*SECURITY*)", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-58b82ac8c9 | check C025 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*reg\\ save* OR win.ScriptBlockText:*SAM* OR win.ScriptBlockText:*esentutl* OR win.ScriptBlockText:*hive*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host… | 9 |  |
| q-dbc1c6d079 | check C026 | search | {"dataset": "windows.other", "query": "message:*reg\\ save* OR message:*SAM* OR message:*esentutl*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "p… | 1 | F03 |
| q-afc6db8dc1 | check C027 | aggregate | {"dataset": "zeek", "field": "zeek.filename", "query": "event.action:smb_files", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 12 |  |
| q-1bbdb8e0c4 | check C028 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*ntdsutil* OR process.command_line:*ntds* OR process.command_line:*vssadmin* OR process.command_line:*diskshadow*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "ho… | 0 |  |
| q-44c54725d6 | check C029 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (win.TargetFilename:*ntds* OR win.TargetFilename:*.dit*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process… | 0 |  |
| q-0eca17a4cd | check C030 | search | {"dataset": "windows.sysmon", "query": "event.code:2 AND win.TargetFilename:*ntds*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_l… | 0 |  |
| q-f10282a7ca | check C031 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND (process.command_line:*ntdsutil* OR process.command_line:*vssadmin* OR process.command_line:*diskshadow* OR process.command_line:*ntds*)", "time_from": null, "time_to"… | 0 |  |
| q-65808b1dc6 | check C032 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND win.ObjectName:*ntds*", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-12ae6cd465 | check C033 | search | {"dataset": "windows.other", "query": "message:*ntdsutil* OR message:*vssadmin* OR message:*diskshadow* OR message:*shadow*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name",… | 0 |  |
| q-abc64f7521 | check C034 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*ntds* OR win.ScriptBlockText:*vssadmin* OR win.ScriptBlockText:*diskshadow* OR win.ScriptBlockText:*shadow*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "h… | 0 |  |
| q-1b129137e9 | check C035 | aggregate | {"dataset": "zeek", "field": "zeek.filename", "query": "event.action:smb_files", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 12 |  |
| q-737a14b5a5 | check C036 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*SECURITY* OR process.command_line:*secrets* OR process.command_line:*lsadump* OR process.command_line:*reg\\ save*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "… | 0 |  |
| q-fa6ca23f37 | check C037 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 326 |  |
| q-b8a2cf8330 | check C038 | search | {"dataset": "windows.sysmon", "query": "event.code:7 AND (win.ImageLoaded:*lsass* OR win.ImageLoaded:*samlib* OR win.ImageLoaded:*vaultcli*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.co… | 23 | F05 |
| q-fb25b9dcae | check C039 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND (win.ObjectName:*SECURITY* OR win.ObjectName:*Policy\\\\Secrets*)", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-cfe34fcb73 | check C040 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4673 AND (win.ObjectName:*SECURITY* OR win.ProcessName:*lsass*)", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 103 |  |
| q-8d798b1f55 | check C041 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND (process.command_line:*SECURITY* OR process.command_line:*lsadump* OR process.command_line:*secrets*)", "time_from": null, "time_to": null, "size": 100, "sub_field": n… | 0 |  |
| q-8ae778b506 | check C042 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*lsadump* OR win.ScriptBlockText:*SECURITY* OR win.ScriptBlockText:*secrets* OR win.ScriptBlockText:*LsaSecret*)", "time_from": null, "time_to": null, "fields": ["@timestamp",… | 0 |  |
| q-4b9e61a609 | check C043 | search | {"dataset": "windows.other", "query": "message:*lsadump* OR message:*SECURITY* OR message:*secrets*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "… | 11 |  |
| q-2d24de57e8 | check C044 | aggregate | {"dataset": "zeek", "field": "zeek.filename", "query": "event.action:smb_files", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 12 |  |
| q-1ae89d53c4 | check C045 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*cache* OR process.command_line:*cachedump* OR process.command_line:*mscash* OR process.command_line:*lsass*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.na… | 5 |  |
| q-54f9cb2388 | check C046 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 326 |  |
| q-4d0c1aee90 | check C047 | search | {"dataset": "windows.sysmon", "query": "event.code:13 AND (registry.path:*Cache* OR registry.path:*NL$* OR registry.path:*SECURITY\\\\Cache*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.c… | 6625 |  |
| q-3925c1f263 | check C048 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND (win.ObjectName:*Cache* OR win.ObjectName:*SECURITY*)", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-087ad08e80 | check C049 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND (process.command_line:*cache* OR process.command_line:*cachedump* OR process.command_line:*mscash*)", "time_from": null, "time_to": null, "size": 100, "sub_field": nul… | 4 |  |
| q-63bf129073 | check C050 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*cachedump* OR win.ScriptBlockText:*mscash* OR win.ScriptBlockText:*Cache*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event… | 4 |  |
| q-5a86b08cf0 | check C051 | search | {"dataset": "windows.other", "query": "message:*cachedump* OR message:*mscash* OR message:*Cache*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "pr… | 0 |  |
| q-e1518db026 | check C052 | aggregate | {"dataset": "zeek", "field": "zeek.filename", "query": "event.action:smb_files", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 12 |  |
| q-af981cbb56 | check C053 | count | {"dataset": "windows.security", "query": "event.code:4662", "time_from": null, "time_to": null} | 7 |  |
| q-a5744a2302 | check C054 | aggregate | {"dataset": "windows.security", "field": "win.Properties", "query": "event.code:4662", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 7 |  |
| q-718247d3b7 | check C055 | aggregate | {"dataset": "windows.security", "field": "win.SubjectUserName", "query": "event.code:4662", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 7 |  |
| q-61521cb179 | check C056 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*drsuapi* OR process.command_line:*lsadump* OR process.command_line:*dcsync*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-3a60c48980 | check C057 | search | {"dataset": "windows.powershell", "query": "win.ScriptBlockText:*dcsync* OR win.ScriptBlockText:*Invoke-Mimikatz* OR win.ScriptBlockText:*lsadump*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "ev… | 0 |  |
| q-eee4aef683 | check C058 | search | {"dataset": "windows.other", "query": "message:*drsuapi* OR message:*dcsync*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 0 |  |
| q-e64cb625a8 | check C059 | aggregate | {"dataset": "zeek", "field": "zeek.endpoint", "query": "event.action:dce_rpc", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 123 |  |
| q-bd8c7a61b6 | check C060 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND (process.command_line:*promisc* OR process.command_line:*pktmon* OR process.command_line:*windump* OR process.command_line:*tcpdump* OR process.command_line:*netsh*cap… | 1 |  |
| q-8cc5b3209f | check C061 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*pktmon* OR process.command_line:*windump* OR process.command_line:*tcpdump* OR process.command_line:*RawCap* OR process.command_line:*promisc*)", "ti… | 0 |  |
| q-42bb8cb072 | check C062 | search | {"dataset": "windows.other", "query": "event.code:7045 AND (message:*pcap* OR message:*npcap* OR message:*winpcap* OR message:*promisc*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code",… | 0 |  |
| q-0bcb6194c6 | check C063 | search | {"dataset": "windows.powershell", "query": "win.ScriptBlockText:*pktmon* OR win.ScriptBlockText:*promisc* OR win.ScriptBlockText:*Get-NetAdapter*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "eve… | 0 |  |
| q-1697f2dd7b | check C064 | aggregate | {"dataset": "zeek", "field": "zeek.service", "query": "event.action:conn", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 613 |  |
| q-d9616025b3 | check C065 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass.exe", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-3a2b967c17 | check C066 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND win.TargetImage:*lsass.exe", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-2e8300ce1f | check C067 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4656 AND (win.ObjectName:*lsass* OR win.ObjectName:*credential*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 13 |  |
| q-2c47f875db | check C068 | aggregate | {"dataset": "windows.security", "field": "win.AccessMask", "query": "event.code:4663 AND win.ObjectName:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 6 |  |
| q-ef01d9f8b2 | check C069 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4670", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 143 |  |
| q-2977b52693 | check C070 | search | {"dataset": "windows.powershell", "query": "win.ScriptBlockText:*GetAsyncKeyState* OR win.ScriptBlockText:*SetWindowsHookEx* OR win.ScriptBlockText:*keylog*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dat… | 0 |  |
| q-b8555f7923 | check C071 | search | {"dataset": "windows.other", "query": "message:*keylog* OR message:*GetAsyncKeyState*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.comman… | 0 |  |
| q-3acc666fa0 | check C072 | aggregate | {"dataset": "zeek", "field": "zeek.service", "query": "event.action:conn", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 613 |  |
| q-4e100b747a | check C073 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*keylog* OR process.command_line:*GetAsyncKeyState* OR process.command_line:*SetWindowsHookEx*)", "time_from": null, "time_to": null, "size": 50, "sub… | 0 |  |
| q-3b64ed147e | check C074 | aggregate | {"dataset": "windows.sysmon", "field": "registry.path", "query": "event.code:13 AND (registry.path:*Keyboard* OR registry.path:*keylog*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 26 |  |
| q-2a4acc9d16 | check C075 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass.exe", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-e0897a09be | check C076 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4656 AND (win.ObjectName:*keyboard* OR win.ObjectName:*keylog*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-820acd79c3 | check C077 | aggregate | {"dataset": "windows.security", "field": "win.AccessMask", "query": "event.code:4663 AND win.ObjectName:*keyboard*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-0ba5a07a37 | check C078 | search | {"dataset": "windows.other", "query": "event.code:7045 AND (message:*keylog* OR message:*hook*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "proc… | 0 |  |
| q-8173702e9c | check C079 | search | {"dataset": "windows.powershell", "query": "win.ScriptBlockText:*GetAsyncKeyState* OR win.ScriptBlockText:*SetWindowsHookEx* OR win.ScriptBlockText:*keylog*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dat… | 0 |  |
| q-dcf9b64e96 | check C080 | aggregate | {"dataset": "zeek", "field": "zeek.service", "query": "event.action:conn", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 613 |  |
| q-49dce98858 | check C081 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*Credential* OR process.command_line:*prompt* OR process.command_line:*consent*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 3 |  |
| q-8aa0b85bc3 | check C082 | search | {"dataset": "windows.powershell", "query": "win.ScriptBlockText:*CredentialUIBroker* OR win.ScriptBlockText:*Windows.Forms* OR win.ScriptBlockText:*Get-Credential*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "ev… | 2 |  |
| q-81364533bb | check C083 | count | {"dataset": "windows.powershell", "query": "event.code:4103 OR event.code:4104 OR event.code:4105 OR event.code:4106", "time_from": null, "time_to": null} | 5494 |  |
| q-c4c9177c27 | check C084 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND (process.command_line:*Credential* OR process.command_line:*consent*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 3 |  |
| q-a7161398e4 | check C085 | search | {"dataset": "windows.other", "query": "message:*CredentialUIBroker* OR message:*consent*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.com… | 0 |  |
| q-d3440d1e49 | check C086 | aggregate | {"dataset": "zeek", "field": "url.domain", "query": "event.action:http", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 62 |  |
| q-90c15e88d0 | check C087 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND (win.TargetFilename:*login* OR win.TargetFilename:*logon* OR win.TargetFilename:*portal*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 8 |  |
| q-470224455b | check C088 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*iis* OR process.command_line:*appcmd* OR process.command_line:*wwwroot*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-3115adf997 | check C089 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND (win.ObjectName:*wwwroot* OR win.ObjectName:*inetpub*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-6b8949013d | check C090 | search | {"dataset": "windows.powershell", "query": "win.ScriptBlockText:*wwwroot* OR win.ScriptBlockText:*inetpub* OR win.ScriptBlockText:*WebAdministration*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", … | 0 |  |
| q-908d1d507d | check C091 | search | {"dataset": "windows.other", "query": "message:*wwwroot* OR message:*inetpub*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line",… | 0 |  |
| q-50473ba7b9 | check C092 | aggregate | {"dataset": "zeek", "field": "url.original", "query": "event.action:http AND (url.original:*login* OR url.original:*logon* OR url.original:*signin*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-c467f23cef | check C093 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-f9c8eac4fb | check C094 | aggregate | {"dataset": "windows.sysmon", "field": "win.SourceImage", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-b462c3d2b4 | check C095 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-09fcf84aa3 | check C096 | aggregate | {"dataset": "windows.sysmon", "field": "win.ImageLoaded", "query": "event.code:7", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 20259 |  |
| q-a53bbe9fce | check C097 | search | {"dataset": "windows.sysmon", "query": "event.code:8 AND (win.TargetImage:*lsass* OR win.SourceImage:*lsass*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.exec… | 2 |  |
| q-f46f056fa3 | check C098 | aggregate | {"dataset": "windows.security", "field": "win.TargetProcessName", "query": "event.code:4663 AND win.ObjectType:*Process*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 6 |  |
| q-e6bd36cf6a | check C099 | aggregate | {"dataset": "windows.security", "field": "win.ProcessName", "query": "event.code:4656 AND win.ObjectType:*Process*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 13 |  |
| q-cc0c2a338d | check C100 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*MiniDump* OR win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*comsvcs* OR win.ScriptBlockText:*VirtualProtect* OR win.ScriptBlockText:*SetWindowsHookEx*)", "time_from": nu… | 0 |  |
| q-0bbd294265 | check C101 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-fd9c6fe39a | check C102 | aggregate | {"dataset": "windows.security", "field": "source.ip", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-361cab8b72 | check C103 | timeline | {"dataset": "windows.security", "query": "event.code:4625", "interval": "1m", "time_from": null, "time_to": null} | 0 |  |
| q-940d546141 | check C104 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4776", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1 |  |
| q-8aa3bf219c | check C105 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*net*user* OR process.command_line:*net*group* OR process.command_line:*password*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null… | 0 |  |
| q-bd94ac2377 | check C106 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*BruteForce* OR win.ScriptBlockText:*Password* OR win.ScriptBlockText:*Credential*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name"… | 4 |  |
| q-312d9e5ecf | check C107 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-e12752a0b4 | check C108 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-897fa221b8 | check C109 | timeline | {"dataset": "windows.security", "query": "event.code:4625", "interval": "1m", "time_from": null, "time_to": null} | 0 |  |
| q-d8a307566e | check C110 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Password* OR win.ScriptBlockText:*Login* OR win.ScriptBlockText:*Credential*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "ev… | 4 | F17 |
| q-7408ea5ae5 | check C111 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*hashcat* OR process.command_line:*john* OR process.command_line:*secretsdump* OR process.command_line:*mimikatz*)", "time_from": null, "time_to": nul… | 0 |  |
| q-a82f056b59 | check C112 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND (win.TargetFilename:*ntds.dit* OR win.TargetFilename:*SAM* OR win.TargetFilename:*SECURITY*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 3 |  |
| q-b12a57a1af | check C113 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-cb74477b22 | check C114 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND (win.ObjectName:*SAM* OR win.ObjectName:*SECURITY* OR win.ObjectName:*ntds.dit*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-aad8156e6f | check C115 | aggregate | {"dataset": "windows.security", "field": "win.ProcessName", "query": "event.code:4656 AND (win.ObjectName:*SAM* OR win.ObjectName:*SECURITY* OR win.ObjectName:*ntds.dit*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 10 |  |
| q-a1bb222123 | check C116 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4670", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 143 |  |
| q-13a02e35a2 | check C117 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*hashcat* OR win.ScriptBlockText:*ntds* OR win.ScriptBlockText:*Invoke-Mimikatz* OR win.ScriptBlockText:*DumpCreds*)", "time_from": null, "time_to": null, "fields": ["@timesta… | 0 |  |
| q-7909eaf466 | check C118 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-108d4e9893 | check C119 | aggregate | {"dataset": "windows.security", "field": "source.ip", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-38897be160 | check C120 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4648", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 15 |  |
| q-d68dfcba7d | check C121 | timeline | {"dataset": "windows.security", "query": "event.code:4625", "interval": "1m", "time_from": null, "time_to": null} | 0 |  |
| q-71ac596b46 | check C122 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Spray* OR win.ScriptBlockText:*Password* OR win.ScriptBlockText:*Credential*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "ev… | 4 |  |
| q-a90bf4c95b | check C123 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-acf7c470c5 | check C124 | aggregate | {"dataset": "windows.security", "field": "source.ip", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-7dcab73a2a | check C125 | timeline | {"dataset": "windows.security", "query": "event.code:4625", "interval": "1m", "time_from": null, "time_to": null} | 0 |  |
| q-fd3c9cd92c | check C126 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Credential* OR win.ScriptBlockText:*Password* OR win.ScriptBlockText:*Login*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "ev… | 4 | F20 |
| q-ce6132fbda | check C127 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 297 |  |
| q-94ca7740d1 | check C128 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4648", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 15 |  |
| q-62ad8ceafd | check C129 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 326 |  |
| q-75ab078e0f | check C130 | search | {"dataset": "windows.sysmon", "query": "event.code:13 AND registry.path:*SmartCard*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_… | 0 |  |
| q-4c25761d35 | check C131 | search | {"dataset": "windows.powershell", "query": "win.ScriptBlockText:*SmartCard* OR win.ScriptBlockText:*MFA* OR win.ScriptBlockText:*Credential*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.co… | 3 |  |
| q-b2ca916fb1 | check C132 | search | {"dataset": "windows.other", "query": "message:*SmartCard* OR message:*Credential*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_l… | 2 | F21 |
| q-bccbe8b663 | check C133 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 OR event.code:4656 OR event.code:4670", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 10977 |  |
| q-9d9e9de892 | check C134 | aggregate | {"dataset": "windows.security", "field": "win.ShareName", "query": "event.code:5140 OR event.code:5145", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 163 |  |
| q-0400c7476f | check C135 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND (win.TargetFilename:*.scf OR win.TargetFilename:*.lnk OR win.TargetFilename:*.url OR win.TargetFilename:*.library-ms)", "time_from": null, "time_to": null, "size": 30, "su… | 3 |  |
| q-54a48a7b29 | check C136 | aggregate | {"dataset": "windows.sysmon", "field": "destination.ip", "query": "event.code:3 AND (destination.port:445 OR destination.port:139)", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 66 |  |
| q-92cab27baf | check C137 | search | {"dataset": "windows.powershell", "query": "win.ScriptBlockText:*WebDAV* OR win.ScriptBlockText:*NTLM* OR win.ScriptBlockText:*PROPFIND*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code",… | 0 |  |
| q-4ae7757c4c | check C138 | search | {"dataset": "windows.other", "query": "message:*WebClient* OR message:*WebDAV*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line"… | 0 |  |
| q-5acfc76bd9 | check C139 | aggregate | {"dataset": "zeek", "field": "destination.port", "query": "event.action:conn AND (destination.port:445 OR destination.port:139)", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 50 |  |
| q-13924bf549 | check C140 | search | {"dataset": "zeek", "query": "event.action:http AND (http.request.method:PROPFIND OR http.request.method:OPTIONS OR http.request.method:MOVE)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.c… | 36 |  |
| q-d0d1047cec | check C141 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4768 OR event.code:4769 OR event.code:4770", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 42 |  |
| q-65fda05867 | check C142 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 326 |  |
| q-3909ae83f3 | check C143 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*lsass* OR process.command_line:*dump*)", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 1 |  |
| q-44aa953fd6 | check C144 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND (process.command_line:*lsass* OR process.command_line:*dump*)", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 0 |  |
| q-4cf2025e71 | check C145 | search | {"dataset": "windows.powershell", "query": "win.ScriptBlockText:*MiniDump* OR win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*Invoke-Mimikatz*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "ev… | 0 |  |
| q-d04d003783 | check C146 | search | {"dataset": "windows.other", "query": "message:*lsass* OR message:*MiniDump*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 0 |  |
| q-b6242b82aa | check C147 | aggregate | {"dataset": "zeek", "field": "event.action", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 35 |  |
| q-3e2d525fa8 | check C148 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND (process.command_line:*Cookies* OR process.command_line:*Login Data* OR process.command_line:*chrome* OR process.command_line:*firefox*)", "time_from": null, "time_to"… | 4 |  |
| q-bd13622268 | check C149 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND (win.TargetFilename:*Cookies* OR win.TargetFilename:*Login Data*)", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 162 |  |
| q-3597679479 | check C150 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND (win.TargetImage:*chrome* OR win.TargetImage:*firefox* OR win.TargetImage:*iexplore* OR win.TargetImage:*msedge*)", "time_from": null, "time_to": null, "size": 20, "sub_fie… | 0 |  |
| q-c20656f5ab | check C151 | search | {"dataset": "windows.sysmon", "query": "event.code:2 AND (file.path:*Cookies* OR file.path:*Login Data*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executabl… | 0 |  |
| q-a68c63e2e2 | check C152 | search | {"dataset": "windows.powershell", "query": "win.ScriptBlockText:*Cookies* OR win.ScriptBlockText:*Login Data* OR win.ScriptBlockText:*sqlite*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.c… | 5157 |  |
| q-aad3ad5e9e | check C153 | search | {"dataset": "windows.other", "query": "message:*Cookies* OR message:*Login Data*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_lin… | 3 |  |
| q-f7fd07e5e8 | check C154 | aggregate | {"dataset": "windows.security", "field": "process.command_line", "query": "event.code:4688 AND (process.command_line:*password* OR process.command_line:*credential* OR process.command_line:*unattend* OR process.command_line:*vault*)", "time_from": null, "time_… | 0 |  |
| q-d7f3f8c2a8 | check C155 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND (win.TargetFilename:*unattend* OR win.TargetFilename:*password* OR win.TargetFilename:*.config OR win.TargetFilename:*credential*)", "time_from": null, "time_to": null, "s… | 2 |  |
| q-0d6addd61d | check C156 | aggregate | {"dataset": "windows.sysmon", "field": "registry.path", "query": "event.code:13 AND (registry.path:*Password* OR registry.path:*Credential* OR registry.path:*Vault*)", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 17 |  |
| q-21159d5e30 | check C157 | search | {"dataset": "windows.powershell", "query": "win.ScriptBlockText:*password* OR win.ScriptBlockText:*credential* OR win.ScriptBlockText:*ConvertTo-SecureString*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.d… | 4 |  |
| q-906b0add1a | check C158 | search | {"dataset": "windows.other", "query": "message:*password* OR message:*credential*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 2 |  |
| q-8175930b1d | check C159 | search | {"dataset": "zeek", "query": "event.action:http AND (url.original:*password* OR url.original:*credential* OR url.original:*.config)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "use… | 0 |  |
| q-9825fd5ded | check C160 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*findstr* OR process.command_line:*Select-String* OR process.command_line:*type* OR process.command_line:*grep*)", "time_from": null, "time_to": null,… | 1 |  |
| q-388b3960f5 | check C161 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND (win.TargetFilename:*.txt OR win.TargetFilename:*.xml OR win.TargetFilename:*.ini OR win.TargetFilename:*.ps1)", "time_from": null, "time_to": null, "size": 30, "sub_field… | 71 |  |
| q-61151cedb6 | check C162 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4648", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 15 |  |
| q-604f3c4157 | check C163 | aggregate | {"dataset": "windows.security", "field": "win.ShareName", "query": "event.code:5140 OR event.code:5145", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 163 |  |
| q-3e3e43e565 | check C164 | search | {"dataset": "windows.powershell", "query": "win.ScriptBlockText:*Get-Content* OR win.ScriptBlockText:*Select-String* OR win.ScriptBlockText:*password*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset",… | 1 |  |
| q-9bdf498f46 | check C165 | search | {"dataset": "windows.other", "query": "message:*.config OR message:*.txt OR message:*password*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "proce… | 0 |  |
| q-286f2ed29d | check C166 | aggregate | {"dataset": "zeek", "field": "file.mime_type", "query": "event.action:files", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 448 |  |
| q-04b7873a3d | check C167 | aggregate | {"dataset": "windows.sysmon", "field": "registry.path", "query": "event.code:13 AND (registry.path:*Password* OR registry.path:*Credential* OR registry.path:*Login* OR registry.path:*Secret*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 20 |  |
| q-15bb1a2c0f | check C168 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*reg\\ query* OR process.command_line:*reg\\ save* OR process.command_line:*CurrentVersion\\\\Winlogon* OR process.command_line:*Vault*)", "time_from": null, "time_to": null, "field… | 0 |  |
| q-786a3a5b09 | check C169 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Password* OR win.ScriptBlockText:*Credential* OR win.ScriptBlockText:*Winlogon* OR win.ScriptBlockText:*reg\\ query*)", "time_from": null, "time_to": null, "fields": ["@times… | 4 |  |
| q-0fedd6d0b3 | check C170 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND (win.ObjectName:*Winlogon* OR win.ObjectName:*Vault* OR win.ObjectName:*Credential*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 838 |  |
| q-afc00a19cb | check C171 | search | {"dataset": "windows.other", "query": "message:*Password* OR message:*Credential*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 2 |  |
| q-d506f85dc7 | check C172 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*ConsoleHost_history* OR win.ScriptBlockText:*history* OR win.ScriptBlockText:*PSReadLine*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observ… | 0 |  |
| q-1c0051d317 | check C173 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*ConsoleHost_history* OR process.command_line:*PSReadLine* OR process.command_line:*history.txt*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observ… | 0 |  |
| q-8a485a7e49 | check C174 | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11 AND (file.path:*ConsoleHost_history* OR file.path:*PSReadLine*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-0b8c273ed4 | check C175 | search | {"dataset": "windows.security", "query": "event.code:4663 AND (win.ObjectName:*ConsoleHost_history* OR win.ObjectName:*PSReadLine*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "use… | 0 |  |
| q-dfe5edcd24 | check C176 | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11 AND (file.path:*.pfx OR file.path:*.pem OR file.path:*.key OR file.path:*.p12 OR file.path:*.ppk OR file.path:*.cer OR file.path:*.asc OR file.path:*.gpg)", "time_from": null, "time_to… | 1 |  |
| q-a62cc39f53 | check C177 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*.pfx OR process.command_line:*.pem OR process.command_line:*.p12 OR process.command_line:*.ppk OR process.command_line:*certutil*)", "time_from": null, "time_to": null, "fields": [… | 0 |  |
| q-29abe26f04 | check C178 | aggregate | {"dataset": "windows.security", "field": "win.RelativeTargetName", "query": "event.code:5145 AND (win.RelativeTargetName:*.pfx OR win.RelativeTargetName:*.pem OR win.RelativeTargetName:*.key OR win.RelativeTargetName:*.p12)", "time_from": null, "time_to": null… | 0 |  |
| q-42234d9065 | check C179 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*.pfx OR win.ScriptBlockText:*.pem OR win.ScriptBlockText:*.p12 OR win.ScriptBlockText:*Export-PfxCertificate*)", "time_from": null, "time_to": null, "fields": ["@timestamp", … | 1 |  |
| q-26d5661ce3 | check C180 | search | {"dataset": "windows.other", "query": "message:*.pfx OR message:*.pem OR message:*.p12", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.comma… | 0 |  |
| q-45eb74df9a | check C181 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Groups.xml OR win.ScriptBlockText:*cpassword OR win.ScriptBlockText:*gpprefdecrypt* OR win.ScriptBlockText:*SYSVOL*)", "time_from": null, "time_to": null, "fields": ["@timest… | 0 |  |
| q-33828d9754 | check C182 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*Groups.xml* OR process.command_line:*cpassword* OR process.command_line:*SYSVOL* OR process.command_line:*gpprefdecrypt*)", "time_from": null, "time_to": null, "fields": ["@timesta… | 0 |  |
| q-6082c38b87 | check C183 | aggregate | {"dataset": "windows.security", "field": "win.RelativeTargetName", "query": "event.code:5145 AND (win.RelativeTargetName:*Groups.xml* OR win.RelativeTargetName:*SYSVOL* OR win.RelativeTargetName:*.xml)", "time_from": null, "time_to": null, "size": 50, "sub_fie… | 0 |  |
| q-792ba31f52 | check C184 | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11 AND (file.path:*Groups.xml* OR file.path:*SYSVOL*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-52a73d372e | check C185 | search | {"dataset": "windows.other", "query": "message:*SYSVOL* OR message:*Groups.xml* OR message:*cpassword*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable"… | 0 |  |
| q-ae42d8b4ba | check C186 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND (win.TargetImage:*lsass.exe OR win.TargetImage:*lsass*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-e185aee02f | check C187 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND (win.TargetImage:*lsass.exe OR win.TargetImage:*lsass*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-2de6257111 | check C188 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*procdump* OR process.command_line:*comsvcs* OR process.command_line:*MiniDump* OR process.command_line:*sekurlsa* OR process.command_line:*mimikatz*)", "time_from": null, "time_to"… | 0 |  |
| q-704642ad37 | check C189 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND (win.ObjectName:*lsass* OR win.ObjectName:*SAM* OR win.ObjectName:*SECURITY* OR win.ObjectName:*NTDS.dit* OR win.ObjectName:*Credential*)", "time_from": null, "time_to": n… | 6 |  |
| q-d553a1f23a | check C190 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4656 AND (win.ObjectName:*lsass* OR win.ObjectName:*SAM* OR win.ObjectName:*SECURITY* OR win.ObjectName:*NTDS.dit*)", "time_from": null, "time_to": null, "size": 50, "sub_field… | 23 |  |
| q-a7fec9eb72 | check C191 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*MiniDump* OR win.ScriptBlockText:*sekurlsa* OR win.ScriptBlockText:*Credential*)", "time_from": null, "time_to": null, "fields": ["@timestamp",… | 3 |  |
| q-16864654e0 | check C192 | search | {"dataset": "windows.other", "query": "message:*lsass* OR message:*MiniDump* OR message:*NTDS.dit*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "p… | 0 |  |
| q-bf2dc3ad0d | check C193 | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11 AND (file.path:*Login\\ Data* OR file.path:*Local\\ State* OR file.path:*logins.json* OR file.path:*key4.db* OR file.path:*Cookies*)", "time_from": null, "time_to": null, "size": 50, "… | 1 |  |
| q-42c17b0d39 | check C194 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*Login\\ Data* OR process.command_line:*Local\\ State* OR process.command_line:*logins.json* OR process.command_line:*key4.db*)", "time_from": null, "time_to": null, "fields": ["@ti… | 0 |  |
| q-c8b2988c8d | check C195 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND (win.ObjectName:*Login\\ Data* OR win.ObjectName:*Local\\ State* OR win.ObjectName:*logins.json* OR win.ObjectName:*key4.db*)", "time_from": null, "time_to": null, "size":… | 0 |  |
| q-1bfadb96e0 | check C196 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND (win.TargetImage:*chrome.exe OR win.TargetImage:*firefox.exe OR win.TargetImage:*msedge.exe OR win.TargetImage:*iexplore.exe)", "time_from": null, "time_to": null, "size":… | 0 |  |
| q-6d06b0dda4 | check C197 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Login\\ Data* OR win.ScriptBlockText:*Local\\ State* OR win.ScriptBlockText:*logins.json* OR win.ScriptBlockText:*key4.db*)", "time_from": null, "time_to": null, "fields": ["… | 0 |  |
| q-c4df2bbbf4 | check C198 | search | {"dataset": "windows.other", "query": "message:*Login\\ Data* OR message:*logins.json* OR message:*key4.db*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.execut… | 0 |  |
| q-875ef430ee | check C199 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*vault* OR process.command_line:*credman* OR process.command_line:*cmdkey* OR process.command_line:*Credential* OR process.command_line:*dpapi*)", "ti… | 0 |  |
| q-12eb395e27 | check C200 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 326 |  |
| q-af8686ded8 | check C201 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetObject", "query": "event.code:15 AND (win.TargetObject:*Vault* OR win.TargetObject:*Credentials*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-3c0b967622 | check C202 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND (process.command_line:*vault* OR process.command_line:*cmdkey* OR process.command_line:*credman* OR process.command_line:*dpapi*)", "time_from": null, "time_to": null,… | 0 |  |
| q-af4adbce65 | check C203 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Vault* OR win.ScriptBlockText:*Credential* OR win.ScriptBlockText:*cmdkey* OR win.ScriptBlockText:*DPAPI*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "hos… | 3 |  |
| q-149a3ccd5a | check C204 | search | {"dataset": "windows.other", "query": "message:*Vault* OR message:*Credential* OR win.HiveName:*SECURITY*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executab… | 2 | F33 |
| q-bc1805e129 | check C205 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*keepass* OR process.command_line:*1password* OR process.command_line:*bitwarden* OR process.command_line:*lastpass* OR process.command_line:*password… | 0 |  |
| q-82f6976350 | check C206 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND (win.TargetFilename:*.kdbx OR win.TargetFilename:*.kdb OR win.TargetFilename:*1password* OR win.TargetFilename:*keepass*)", "time_from": null, "time_to": null, "size": 50,… | 0 |  |
| q-5deaa51a52 | check C207 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND (win.TargetImage:*keepass* OR win.TargetImage:*1password* OR win.TargetImage:*bitwarden*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "e… | 0 |  |
| q-598d654650 | check C208 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND (process.command_line:*keepass* OR process.command_line:*1password* OR process.command_line:*bitwarden* OR process.command_line:*password*)", "time_from": null, "time_… | 0 |  |
| q-5ff11c7875 | check C209 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*kdbx* OR win.ScriptBlockText:*keepass* OR win.ScriptBlockText:*1password* OR win.ScriptBlockText:*password*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "h… | 0 |  |
| q-19025c67e7 | check C210 | search | {"dataset": "windows.other", "query": "message:*keepass* OR message:*1password* OR message:*password*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable",… | 0 |  |
| q-20d5f304ec | check C211 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 326 |  |
| q-12ecaf021c | check C212 | aggregate | {"dataset": "windows.sysmon", "field": "win.ImageLoaded", "query": "event.code:7 AND (win.ImageLoaded:*lsass* OR win.ImageLoaded:*cryptdll* OR win.ImageLoaded:*sam* OR win.ImageLoaded:*wdigest* OR win.ImageLoaded:*kerberos*)", "time_from": null, "time_to": nul… | 92 |  |
| q-8ecbdeede4 | check C213 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4657 AND (win.ObjectName:*Security* OR win.ObjectName:*SAM* OR win.ObjectName:*Lsa* OR win.ObjectName:*Notification*)", "time_from": null, "time_to": null, "size": 50, "sub_field":… | 0 |  |
| q-8775962ee4 | check C214 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND (process.command_line:*lsass* OR process.command_line:*mimikatz* OR process.command_line:*procdump* OR process.command_line:*comsvcs* OR process.command_line:*MiniDump… | 0 |  |
| q-9cca893e4d | check C215 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*MiniDump* OR win.ScriptBlockText:*comsvcs* OR win.ScriptBlockText:*mimikatz* OR win.ScriptBlockText:*sekurlsa*)", "time_from": null, "time_to":… | 0 |  |
| q-9480785527 | check C216 | search | {"dataset": "windows.other", "query": "message:*lsass* OR message:*cryptdll* OR message:*Notification Packages*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.ex… | 4 |  |
| q-d0cecb2270 | check C217 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 326 |  |
| q-f5428b8fc6 | check C218 | aggregate | {"dataset": "windows.sysmon", "field": "win.ImageLoaded", "query": "event.code:7 AND (win.ImageLoaded:*lsass* OR win.ImageLoaded:*cryptdll*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 33 |  |
| q-4bb9650a09 | check C219 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4624 AND win.LogonType:3", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 218 |  |
| q-3849cd6218 | check C220 | search | {"dataset": "windows.security", "query": "event.code:4648", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 15 |  |
| q-2735691732 | check C221 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*skeleton* OR win.ScriptBlockText:*mimikatz* OR win.ScriptBlockText:*cryptdll*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "… | 0 |  |
| q-559e277c4f | check C222 | search | {"dataset": "windows.other", "query": "message:*lsass* OR message:*cryptdll*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 0 |  |
| q-a3ef8059ac | check C223 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND (win.TargetFilename:*lsa* OR win.TargetFilename:*password* OR win.TargetFilename:*filter*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 7 |  |
| q-b93e37e401 | check C224 | aggregate | {"dataset": "windows.sysmon", "field": "win.ImageLoaded", "query": "event.code:7 AND (win.ImageLoaded:*lsass* OR win.ImageLoaded:*password* OR win.ImageLoaded:*filter*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1 |  |
| q-3acf216233 | check C225 | aggregate | {"dataset": "windows.security", "field": "win.ObjectValueName", "query": "event.code:4657 AND (win.ObjectName:*Notification Packages* OR win.ObjectName:*Lsa*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-2ffb2201ff | check C226 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND (process.command_line:*Notification* OR process.command_line:*reg add* OR process.command_line:*password*)", "time_from": null, "time_to": null, "size": 50, "sub_field… | 2 |  |
| q-d529e2b386 | check C227 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Notification Packages* OR win.ScriptBlockText:*password* OR win.ScriptBlockText:*Lsa*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.n… | 0 |  |
| q-1a2f04e4b2 | check C228 | search | {"dataset": "windows.other", "query": "message:*Notification Packages* OR message:*password filter* OR message:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "pro… | 5 |  |
| q-42f6da1ef3 | check C229 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*ReversibleEncryption* OR win.ScriptBlockText:*AllowReversiblePasswordEncryption* OR win.ScriptBlockText:*Set-ADAccountControl* OR win.ScriptBlockText:*Set-ADUser*)", "time_fr… | 1 |  |
| q-446943f0ed | check C230 | search | {"dataset": "windows.powershell", "query": "event.code:4103 AND (win.Payload:*Reversible* OR win.Payload:*Set-ADUser* OR win.Payload:*Set-ADAccountControl*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dat… | 0 |  |
| q-b0bae5d9ef | check C231 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*Reversible* OR process.command_line:*Set-ADUser* OR process.command_line:*Set-ADAccountControl* OR process.command_line:*dsmod*)", "time_from": null,… | 0 |  |
| q-89dabf988b | check C232 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND (process.command_line:*Reversible* OR process.command_line:*Set-ADUser* OR process.command_line:*dsmod* OR process.command_line:*Set-ADAccountControl*)", "time_from": … | 0 |  |
| q-ab72e55a1c | check C233 | search | {"dataset": "windows.other", "query": "message:*Reversible* OR message:*password* OR message:*4739*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "… | 0 |  |
| q-aba1f856e7 | check C234 | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*set-aduser*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*set-adaccount*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*set-adauthenticationpolicy*\" OR TO_LOWER(wi… | ERROR |  |
| q-8f286f3dd3 | check C234 (repaired) | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*set-aduser*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*set-adaccount*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*set-adauthenticationpolicy*\" OR TO_LOWER(wi… | ERROR |  |
| q-ae1a8f1a17 | check C235 | count | {"dataset": "windows.security", "query": "event.code:4739", "time_from": null, "time_to": null} | 0 |  |
| q-974c226d02 | check C236 | aggregate | {"dataset": "windows.security", "field": "win.ObjectType", "query": "event.code:4662 OR event.code:5136", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 7 |  |
| q-135e11e8eb | check C237 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*Set-ADUser* OR process.command_line:*Set-ADAuthenticationPolicy* OR process.command_line:*dsacls* OR process.command_line:*adsi*)", "time_from": null… | 0 |  |
| q-c0de6fdb4e | check C238 | search | {"dataset": "windows.other", "query": "event.code:4739 OR event.code:5136 OR event.code:4662", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process… | 0 |  |
| q-de3a9b880c | check C239 | aggregate | {"dataset": "windows.security", "field": "win.LogonProcessName", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 297 |  |
| q-43fd1e39ab | check C240 | aggregate | {"dataset": "windows.security", "field": "win.AuthenticationPackageName", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 297 |  |
| q-22974eaba8 | check C241 | aggregate | {"dataset": "windows.sysmon", "field": "win.ImageLoaded", "query": "event.code:7 AND (win.ImageLoaded:*Azure* OR win.ImageLoaded:*AAD* OR win.ImageLoaded:*CloudAP* OR win.ImageLoaded:*Identity*)", "time_from": null, "time_to": null, "size": 50, "sub_field": nu… | 3 |  |
| q-8607ee0ece | check C242 | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*azuread*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*connect-msolservice*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*aadinternals*\" OR TO_LOWER(win.ScriptBlo… | ERROR |  |
| q-7cff15427a | check C242 (repaired) | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*azuread*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*connect-msolservice*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*aadinternals*\" OR TO_LOWER(… | 0 |  |
| q-d609d23d98 | check C243 | search | {"dataset": "windows.other", "query": "event.code:5136 OR event.code:4739", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "so… | 0 |  |
| q-cddf957397 | check C244 | aggregate | {"dataset": "windows.sysmon", "field": "registry.path", "query": "event.code:13 AND registry.path:*NetworkProvider*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-39a57e4249 | check C245 | aggregate | {"dataset": "windows.sysmon", "field": "win.ImageLoaded", "query": "event.code:7 AND (win.ImageLoaded:*\\\\System32\\\\* OR win.ImageLoaded:*Network*)", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 19432 |  |
| q-36aed1814c | check C246 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND (win.TargetFilename:*\\\\System32\\\\* OR win.TargetFilename:*NetworkProvider*)", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 425 |  |
| q-3f6b856c05 | check C247 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass.exe", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-49bfa38960 | check C248 | count | {"dataset": "windows.security", "query": "event.code:4657", "time_from": null, "time_to": null} | 36 |  |
| q-fa368919b3 | check C249 | search | {"dataset": "windows.other", "query": "event.code:4657 OR event.code:13", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "sour… | 1 |  |
| q-fe5e09d740 | check C250 | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*networkprovider*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*hklm*network*\" \| KEEP @timestamp, host.name, user.name, win.ScriptBlockId, _id, _index"} | ERROR |  |
| q-1b826950be | check C250 (repaired) | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*networkprovider*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*hklm*network*\" \| KEEP @timestamp, host.name, user.name, win.ScriptBlockId, _id, _index"} | ERROR |  |
| q-2c8727166d | check C251 | aggregate | {"dataset": "windows.sysmon", "field": "win.DestinationHostname", "query": "event.code:22", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 81 |  |
| q-cbe73086b6 | check C252 | aggregate | {"dataset": "windows.sysmon", "field": "destination.ip", "query": "event.code:3", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 1229 |  |
| q-be30a71e23 | check C253 | aggregate | {"dataset": "windows.security", "field": "win.ObjectType", "query": "event.code:4663 OR event.code:4670 OR event.code:4656", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 10977 |  |
| q-036e725a7f | check C254 | search | {"dataset": "windows.other", "query": "event.code:4663 OR event.code:4670 OR event.code:4656", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process… | 0 |  |
| q-b42e7fa47b | check C255 | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*arpspoof*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*responder*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*ettercap*\" OR TO_LOWER(win.ScriptBlockText) LIKE … | ERROR |  |
| q-2060e80d13 | check C255 (repaired) | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*arpspoof*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*responder*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*ettercap*\" OR TO_LOWER(win.ScriptBlo… | 0 |  |
| q-ec1b8624bf | check C256 | aggregate | {"dataset": "zeek", "field": "zeek.conn_state", "query": "event.action:conn", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 613 |  |
| q-7f00c9b9c7 | check C257 | aggregate | {"dataset": "zeek", "field": "zeek.id_resp_h", "query": "event.action:dns AND (destination.port:5355 OR destination.port:137)", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 6 |  |
| q-4d0b7a784d | check C258 | aggregate | {"dataset": "zeek", "field": "zeek.id_orig_h", "query": "event.action:dns AND (destination.port:5355 OR destination.port:137)", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 6 |  |
| q-1ea0ef912b | check C259 | aggregate | {"dataset": "zeek", "field": "zeek.service", "query": "event.action:conn AND destination.port:445", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 45 |  |
| q-18c271c8bd | check C260 | aggregate | {"dataset": "windows.sysmon", "field": "registry.path", "query": "event.code:13 AND registry.path:*DNSClient*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-eef6c9841c | check C261 | count | {"dataset": "windows.security", "query": "event.code:4697", "time_from": null, "time_to": null} | 23 |  |
| q-9d39722be3 | check C262 | search | {"dataset": "windows.other", "query": "event.code:4697 OR event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "so… | 5 |  |
| q-6424dbee08 | check C263 | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*enablemulticast*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*llmnr*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*nbt-ns*\" OR TO_LOWER(win.ScriptBlockText) LIKE… | ERROR |  |
| q-e6d8f2bd0d | check C263 (repaired) | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*enablemulticast*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*llmnr*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*nbt-ns*\" OR TO_LOWER(win.ScriptBlockText) LIKE… | ERROR |  |
| q-52013e5a62 | check C264 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*arp* OR process.command_line:*netsh* OR process.command_line:*spoof*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 5 |  |
| q-bd218fd072 | check C265 | aggregate | {"dataset": "windows.sysmon", "field": "destination.ip", "query": "event.code:3", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 1229 |  |
| q-98c881aa0c | check C266 | aggregate | {"dataset": "windows.sysmon", "field": "win.DestinationHostname", "query": "event.code:22", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 81 |  |
| q-f648582dc2 | check C267 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*arp* OR process.command_line:*netsh*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", … | 5 |  |
| q-992a84cb4e | check C268 | search | {"dataset": "windows.other", "query": "event.code:4688 OR event.code:1", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "sourc… | 3 |  |
| q-49728ef468 | check C269 | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*arp*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*netsh interface*\" \| KEEP @timestamp, host.name, user.name, win.ScriptBlockId, _id, _index"} | ERROR |  |
| q-2a0dc88cb8 | check C269 (repaired) | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*arp*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*netsh interface*\" \| KEEP @timestamp, host.name, user.name, win.ScriptBlockId, _id, _index"} | ERROR |  |
| q-aa01f0931e | check C270 | aggregate | {"dataset": "zeek", "field": "zeek.orig_l2_addr", "query": "event.action:conn", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 613 |  |
| q-686c30e185 | check C271 | search | {"dataset": "windows.other", "query": "event.code:(1341 OR 1342 OR 1020 OR 1063)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_lin… | 0 |  |
| q-ef39a0d80c | check C272 | aggregate | {"dataset": "windows.other", "field": "event.code", "query": "*", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 216 |  |
| q-26356e6d4b | check C273 | aggregate | {"dataset": "windows.security", "field": "win.LogonProcessName", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 297 |  |
| q-bcb86aaf2d | check C274 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*dhcp* OR process.command_line:*ipconfig* OR process.command_line:*netsh*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 5 |  |
| q-316bd92a6d | check C275 | search | {"dataset": "windows.powershell", "query": "win.ScriptBlockText:(*DhcpServer* OR *Add-DhcpServerv4OptionValue* OR *rogue* OR *dhcp*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "us… | 0 |  |
| q-a3e2df9e98 | check C276 | aggregate | {"dataset": "zeek", "field": "destination.port", "query": "event.action:conn AND (source.port:67 OR source.port:68 OR destination.port:67 OR destination.port:68)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-a59b46b1ef | check C277 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4672", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 212 |  |
| q-6ca7835248 | check C278 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 297 |  |
| q-9109001a16 | check C279 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-5250069182 | check C280 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 326 |  |
| q-313fd67476 | check C281 | search | {"dataset": "windows.powershell", "query": "win.ScriptBlockText:(*kerberos* OR *ticket* OR *kirbi* OR *Rubeus* OR *Mimikatz* OR *sekurlsa*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.cod… | 0 |  |
| q-d12ebd7b7c | check C282 | search | {"dataset": "windows.other", "query": "message:(*Kerberos* OR *ticket*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "sour… | 1 |  |
| q-9a82f47360 | check C283 | aggregate | {"dataset": "zeek", "field": "zeek.error_msg", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 35 |  |
| q-ae1197fbd0 | check C284 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4672", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 212 |  |
| q-e5723d97d9 | check C285 | aggregate | {"dataset": "windows.security", "field": "win.TicketEncryptionType", "query": "event.code:4769", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 28 |  |
| q-56a4863dc1 | check C286 | search | {"dataset": "windows.security", "query": "event.code:4769", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 28 |  |
| q-a8f6f222d8 | check C287 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 326 |  |
| q-dff8906838 | check C288 | search | {"dataset": "windows.powershell", "query": "win.ScriptBlockText:(*krbtgt* OR *golden* OR *mimikatz* OR *lsadump* OR *dcsync*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name… | 0 |  |
| q-3943534be0 | check C289 | search | {"dataset": "windows.other", "query": "message:(*krbtgt* OR *Kerberos* OR *ticket*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_… | 1 |  |
| q-5792c0ec59 | check C290 | aggregate | {"dataset": "zeek", "field": "zeek.error_msg", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 35 |  |
| q-6a1dd78015 | check C291 | aggregate | {"dataset": "windows.security", "field": "win.ServiceName", "query": "event.code:4769", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 28 |  |
| q-6557940d3f | check C292 | aggregate | {"dataset": "windows.security", "field": "win.TicketEncryptionType", "query": "event.code:4769", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 28 |  |
| q-932a1a8f30 | check C293 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4672", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 212 |  |
| q-8b3021a8f7 | check C294 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 326 |  |
| q-22d2c85adf | check C295 | search | {"dataset": "windows.powershell", "query": "win.ScriptBlockText:(*silver* OR *kerberos* OR *ticket* OR *kirbi* OR *Rubeus*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name",… | 0 |  |
| q-bcf0e11c7c | check C296 | search | {"dataset": "windows.other", "query": "message:(*Kerberos* OR *ticket* OR *service*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command… | 97 |  |
| q-f2d328d223 | check C297 | aggregate | {"dataset": "zeek", "field": "zeek.error_msg", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 35 |  |
| q-a08ca22d08 | check C298 | aggregate | {"dataset": "windows.security", "field": "win.ServiceName", "query": "event.code:4769", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 28 |  |
| q-2bceaeebb2 | check C299 | aggregate | {"dataset": "windows.security", "field": "win.TicketEncryptionType", "query": "event.code:4769", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 28 |  |
| q-402b65e947 | check C300 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4624 OR event.code:4648", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 312 |  |
| q-69ce59be8a | check C301 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4672", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 212 |  |
| q-6baf4608c1 | check C302 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 326 |  |
| q-5a38a1f568 | check C303 | search | {"dataset": "windows.powershell", "query": "win.ScriptBlockText:(*SPN* OR *kerberoast* OR *GetUserSPNs* OR *Invoke-Kerberoast* OR *Rubeus*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.cod… | 0 |  |
| q-8d766fbb7e | check C304 | search | {"dataset": "windows.other", "query": "message:(*Kerberos* OR *SPN* OR *ticket*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_lin… | 1 |  |
| q-3bae01461e | check C305 | aggregate | {"dataset": "zeek", "field": "zeek.error_msg", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 35 |  |
| q-da108e43f5 | check C306 | search | {"dataset": "windows.security", "query": "event.code:4768", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 14 |  |
| q-ccc51fb187 | check C307 | aggregate | {"dataset": "windows.security", "field": "win.PreAuthType", "query": "event.code:4768", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 14 |  |
| q-08734cc179 | check C308 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*asreproast* OR process.command_line:*GetNPUsers* OR process.command_line:*rubeus*)", "time_from": null, "time_to": null, "size": 50, "sub_field": nul… | 0 |  |
| q-b6945c318c | check C309 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*kerberos* OR process.command_line:*spn* OR process.command_line:*ldap*)", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-407701c602 | check C310 | search | {"dataset": "windows.powershell", "query": "win.ScriptBlockText:(*asreproast* OR *GetNPUsers* OR *DONT_REQ_PREAUTH* OR *preauth*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.… | 0 |  |
| q-0eb7618b0c | check C311 | search | {"dataset": "windows.other", "query": "message:(*Kerberos* OR *preauth* OR *pre-authentication*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "pro… | 1 |  |
| q-68beef62d3 | check C312 | aggregate | {"dataset": "zeek", "field": "zeek.error_msg", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 35 |  |
| q-5dc99947a6 | check C313 | aggregate | {"dataset": "windows.security", "field": "win.LogonProcessName", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 297 |  |
| q-cf7ad95116 | check C314 | aggregate | {"dataset": "windows.security", "field": "win.AuthenticationPackageName", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 297 |  |
| q-7b7c51a666 | check C315 | search | {"dataset": "windows.security", "query": "event.code:4648", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 15 |  |
| q-284ad92fb4 | check C316 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-7f211d2953 | check C317 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-84a43e1e75 | check C318 | search | {"dataset": "windows.powershell", "query": "win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*MiniDump* OR win.ScriptBlockText:*sekurlsa* OR win.ScriptBlockText:*Credential*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observe… | 3 |  |
| q-7e7dc7808a | check C319 | search | {"dataset": "windows.other", "query": "message:*lsass* OR message:*MiniDump* OR message:*procdump*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "p… | 0 |  |
| q-da4db297d3 | check C320 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND (win.TargetFilename:*Cookie* OR win.TargetFilename:*cookie*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1 |  |
| q-a0cade7597 | check C321 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (win.TargetFilename:*Cookies* OR win.TargetFilename:*Login Data*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name",… | 162 |  |
| q-1576644ec5 | check C322 | aggregate | {"dataset": "windows.security", "field": "win.LogonProcessName", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 297 |  |
| q-cd19e71fef | check C323 | search | {"dataset": "windows.security", "query": "event.code:4648", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 15 |  |
| q-d746a40b1c | check C324 | search | {"dataset": "windows.powershell", "query": "win.ScriptBlockText:*cookie* OR win.ScriptBlockText:*Cookie*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executabl… | 0 |  |
| q-b2ff275329 | check C325 | aggregate | {"dataset": "windows.security", "field": "win.AuthenticationPackageName", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 297 |  |
| q-563da23f10 | check C326 | search | {"dataset": "windows.security", "query": "event.code:4648", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 15 |  |
| q-f1b8db2c74 | check C327 | search | {"dataset": "windows.powershell", "query": "win.ScriptBlockText:*SAML* OR win.ScriptBlockText:*saml* OR win.ScriptBlockText:*token*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "use… | 1 |  |
| q-a79beeb1a8 | check C328 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND (win.TargetFilename:*.pfx OR win.TargetFilename:*.p12 OR win.TargetFilename:*.cer)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1 |  |
| q-97a651074d | check C329 | count | {"dataset": "windows.security", "query": "event.code:4625", "time_from": null, "time_to": null} | 0 |  |
| q-972be9e0a9 | check C330 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-6f32f5c042 | check C331 | aggregate | {"dataset": "windows.security", "field": "source.ip", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-ea07da0b40 | check C332 | search | {"dataset": "windows.powershell", "query": "win.ScriptBlockText:*MFA* OR win.ScriptBlockText:*2FA* OR win.ScriptBlockText:*Authenticator*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code"… | 0 |  |
| q-c753282c28 | check C333 | search | {"dataset": "windows.security", "query": "event.code:4657", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 36 |  |
| q-ba109f5e62 | check C334 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4657", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 36 |  |
| q-7a30441c74 | check C335 | search | {"dataset": "windows.security", "query": "event.code:4768", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 14 |  |
| q-a4ab9c6644 | check C336 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND (win.TargetFilename:*.pfx OR win.TargetFilename:*.p12 OR win.TargetFilename:*.cer OR win.TargetFilename:*.crt)", "time_from": null, "time_to": null, "size": 50, "sub_field… | 1 |  |
| q-1deae82203 | check C337 | search | {"dataset": "windows.powershell", "query": "win.ScriptBlockText:*Cert* OR win.ScriptBlockText:*certutil* OR win.ScriptBlockText:*Export-PfxCertificate*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset"… | 1 |  |
| q-aafd7f672b | check C338 | aggregate | {"dataset": "zeek", "field": "event.action", "query": "*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 2140 |  |
| q-c8ca2ab472 | check C339 | search | {"dataset": "zeek", "query": "event.action:kerberos", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destination… | 35 |  |
| q-484bff57fb | check C340 | search | {"dataset": "zeek", "query": "event.action:http", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destination.ip"… | 62 |  |
| q-76cec491dc | check C341 | search | {"dataset": "zeek", "query": "event.action:http", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destination.ip"… | 62 |  |
| q-c751507a58 | check C342 | aggregate | {"dataset": "zeek", "field": "url.domain", "query": "event.action:http", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 62 |  |
| q-2608005072 | check C343 | search | {"dataset": "zeek", "query": "event.action:http", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destination.ip"… | 62 |  |
| q-82d5ddc656 | check C344 | aggregate | {"dataset": "zeek", "field": "http.request.method", "query": "event.action:http", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 62 |  |
| q-6ec6d6f3ff | check C345 | search | {"dataset": "zeek", "query": "event.action:http", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destination.ip"… | 62 |  |
| q-9ca611124c | check C346 | aggregate | {"dataset": "zeek", "field": "http.response.status_code", "query": "event.action:http", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 62 |  |
| q-29d3e4621c | check C347 | search | {"dataset": "zeek", "query": "event.action:x509", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destination.ip"… | 378 |  |
| q-d491f3aa8b | check C348 | aggregate | {"dataset": "zeek", "field": "zeek.certificate_subject", "query": "event.action:x509", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 378 |  |
| q-6b3e73f5cc | check C349 | search | {"dataset": "zeek", "query": "event.action:kerberos", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destination… | 35 |  |
| q-80adfe1b1f | triage T1003 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND NOT win.GrantedAccess:(0x1000 OR 0x1400)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "process.executable", "process.command_line", "win.Grante… | 9 | F01, F02 |
| q-398b5ad432 | triage T1003 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND process.executable:*powershell*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "process.executable", "process.command_line", "win.GrantedAccess",… | 2 |  |
| q-74381dff60 | triage T1003 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None | F01 |
| q-7389c97319 | triage T1003 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-26ff47ee37 | triage T1003 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-7852327797 | triage T1003 step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == 4104 AND @timestamp >= \"2020-05-02T03:00:00.000Z\" AND @timestamp <= \"2020-05-02T03:12:00.000Z\" \| KEEP @timestamp, host.name, user.name, win.ScriptBlockText, _id, _… | ERROR |  |
| q-e6686a994e | triage T1003 step 3 | search | {"dataset": "windows.sysmon", "query": "host.name:scranton.dmevals.local AND @timestamp:[2020-05-02T03:04:30.000Z TO 2020-05-02T03:06:30.000Z] AND event.code:(1 OR 11 OR 10 OR 7)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "even… | 1837 | F08 |
| q-fe0d76f87d | triage T1003 step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND @timestamp >= \"2020-05-02T03:00:00.000Z\" AND @timestamp <= \"2020-05-02T03:12:00.000Z\" \| KEEP @timestamp, host.name, user.name, win.ScriptBlockText, _i… | 226 | F08 |
| q-158ef807ee | triage T1003 step 5 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND @timestamp >= \"2020-05-02T03:02:00.000Z\" AND @timestamp <= \"2020-05-02T03:12:00.000Z\" AND host.name IN (\"scranton.dmevals.local\", \"nashua.dmevals.lo… | 90 | F01, F06, F08 |
| q-075bcb78ef | triage T1003 step 6 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND @timestamp >= \"2020-05-02T03:06:00.000Z\" AND @timestamp <= \"2020-05-02T03:21:00.000Z\" AND host.name == \"nashua.dmevals.local\" \| KEEP @timestamp, hos… | 11 | F02 |
| q-1acfd30602 | triage T1003 step 6 | search | {"dataset": "windows.security", "query": "event.code:(4656 OR 4663) AND win.ObjectName:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "process.executable", "win.ObjectName", "win.AccessMask", "win.ProcessName"… | 19 | F01, F02 |
| q-5fd8b39104 | triage T1003 step 7 | search | {"dataset": "windows.security", "query": "event.code:4673 AND NOT process.executable:*lsass.exe", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "process.executable", "win.ObjectName", "win.PrivilegeList", "win.SubjectU… | 831 | F05, F08 |
| q-30cc0902c4 | triage T1003 step 7 | search | {"dataset": "zeek", "query": "event.action:dce_rpc AND zeek.operation:DRS*", "time_from": null, "time_to": null, "fields": ["@timestamp", "event.action", "zeek.operation", "source.ip", "destination.ip", "zeek.id_orig_h", "zeek.id_resp_h", "zeek.status", "zeek.… | 9 | F04, F07 |
| q-3ff3f8360d | triage T1003 step 8 | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA6p"} | None |  |
| q-e759fd8965 | triage T1003 step 8 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2ORrtI"} | None | F03 |
| q-e40cc96a97 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None |  |
| q-cb10c2035b | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-ab6de8c350 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None |  |
| q-ec107f3db5 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9MpvMw"} | None |  |
| q-d48f9da70a | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9Qtr32"} | None |  |
| q-d667ddb0f3 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9Qt70r"} | None |  |
| q-cfddb27637 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQDVp3"} | None |  |
| q-49906375f1 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1ns"} | None |  |
| q-90f9986654 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-6b412fe4a0 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-421fa4e8b1 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9VzibT"} | None |  |
| q-8df9a0dc53 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAMA2AH"} | None |  |
| q-6faa233086 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2ORrtI"} | None |  |
| q-ae2f91bec2 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2ORrtI"} | None |  |
| q-a9e7238dc4 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL-w3yM8"} | None |  |
| q-1e154f4ab2 | triage T1003 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA6p"} | None |  |
| q-8a17ea3582 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL66EEHK"} | None |  |
| q-9197a003b0 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9Typob"} | None |  |
| q-52b74bd604 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-293c8d3226 | triage T1003 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA6p"} | None |  |
| q-8a5bd4f635 | triage T1003 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGJw3L"} | None |  |
| q-758d8024d6 | triage T1003 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGJw3G"} | None |  |
| q-50bc954d2e | triage T1003 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAWIxZm"} | None |  |
| q-3dca9c9768 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQDVrD"} | None |  |
| q-fcf9123752 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQDVp0"} | None |  |
| q-fe047b3051 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9Typob"} | None |  |
| q-cf3e24110e | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63C9mZ"} | None |  |
| q-7b72e66a62 | triage T1040 step 1 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*promisc* OR process.command_line:*pktmon* OR process.command_line:*windump* OR process.command_line:*tcpdump* OR process.command_line:*netsh*cap*)", "time_from": null, "time_t… | 1 | F09 |
| q-467f582382 | triage T1040 step 1 | aggregate | {"dataset": "zeek", "field": "zeek.service", "query": "event.action:http", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 62 |  |
| q-c4641cf1dc | triage T1040 step 2 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9AdJ6k"} | None | F09 |
| q-9d9254ba0b | triage T1040 step 2 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"http\" \| KEEP @timestamp, source.ip, destination.ip, destination.port, url.original, http.request.method, user_agent.original, _id, _index \| LIMIT 30"} | 30 | F10 |
| q-64203742f1 | triage T1040 step 3 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action IN (\"notice\", \"weird\", \"dpd\") OR zeek.service IN (\"ftp\", \"telnet\", \"ftp-data\") \| KEEP @timestamp, event.action, zeek.service, zeek.note, zeek.msg, source.ip, destination.… | 26 | F10 |
| q-5320e2090e | triage T1040 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"3\" \| STATS c = COUNT(*) BY process.executable, destination.port \| SORT c ASC \| LIMIT 40"} | 40 |  |
| q-b0dee9c873 | triage T1040 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"3\" \| STATS c = COUNT(*) BY process.executable \| SORT c ASC \| LIMIT 40"} | 17 |  |
| q-dfdd5cbdff | triage T1040 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" \| STATS c = COUNT(*) BY process.executable \| SORT c ASC \| LIMIT 40"} | 40 |  |
| q-2d0845d976 | triage T1040 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE process.executable LIKE \"*Temp*python.exe\" AND event.code IN (\"1\",\"3\") \| KEEP @timestamp, event.code, host.name, user.name, process.executable, process.command_line, process.paren… | 25 | F11 |
| q-05d39e8672 | triage T1040 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE process.executable LIKE \"*Temp*python.exe\" AND event.code == \"3\" \| STATS c = COUNT(*) BY destination.ip, destination.port, host.name \| SORT c DESC \| LIMIT 30"} | 1 |  |
| q-61d1646c15 | triage T1040 step 6 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*.pcap*\" OR TO_LOWER(file.path) LIKE \"*.etl\" OR TO_LOWER(file.path) LIKE \"*.cap\") \| KEEP @timestamp, host.name, user.name, proc… | 20 | F09 |
| q-8bca7e86c8 | triage T1040 step 6 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*promisc*\" OR TO_LOWER(process.command_line) LIKE \"*pktmon*\" OR TO_LOWER(process.command_line) LIKE \"*windump*\" OR TO_… | 3 | F09, F11 |
| q-f32319c471 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9AdJ6k"} | None |  |
| q-4d5149b7f2 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9AdJ6k"} | None |  |
| q-2e09fdf539 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2IK5Hc"} | None |  |
| q-3f1c6f3dce | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2JMYSh"} | None |  |
| q-04ea095e8b | triage T1040 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA04"} | None |  |
| q-68da7cffd3 | triage T1040 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA01"} | None |  |
| q-0f6faf688d | triage T1040 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIK6WOc7y0JMA_NaZf"} | None |  |
| q-764c5194ea | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2in-NH"} | None |  |
| q-637b1e1bfe | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2bgjeM"} | None |  |
| q-750afdd18f | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7ViMbT"} | None |  |
| q-20a7055954 | triage T1056 step 1 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnI"} | None | F12 |
| q-34a5f9e721 | triage T1056 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1kD"} | None | F13 |
| q-2de84ed164 | triage T1056 step 1 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2PTHqc"} | None | F12 |
| q-c036fee5af | triage T1056 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass.exe AND process.executable:*powershell*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "process.executable", "process.command_line", "win.SourceImage"… | 2 |  |
| q-11e90d4b46 | triage T1056 step 2 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == 4104 AND (win.ScriptBlockText LIKE \"*lsass*\" OR win.ScriptBlockText LIKE \"*MiniDump*\" OR win.ScriptBlockText LIKE \"*comsvcs*\" OR win.ScriptBlockText LIKE \"*Virtu… | ERROR |  |
| q-21b7b0d026 | triage T1056 step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (win.ScriptBlockText LIKE \"*lsass*\" OR win.ScriptBlockText LIKE \"*MiniDump*\" OR win.ScriptBlockText LIKE \"*comsvcs*\" OR win.ScriptBlockText LIKE \"*V… | 5 | F13 |
| q-5bd2fc9c82 | triage T1056 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7BNbI-"} | None |  |
| q-7a35883950 | triage T1056 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND win.TargetImage LIKE \"*lsass.exe\" AND win.GrantedAccess IN (\"0x1fffff\",\"0x101001\",\"0x1f3fff\",\"0x1000000\",\"0x3000\",\"0x1400\") \| KEEP @timestamp, hos… | 33 | F12, F14 |
| q-aa7f3dbf15 | triage T1056 step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE user.name == \"pbeesly\" AND event.code == \"4104\" \| KEEP @timestamp, host.name, win.Path, win.ScriptBlockId, _id, _index \| SORT @timestamp"} | 157 |  |
| q-b2b45f0a97 | triage T1056 step 5 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None |  |
| q-5479a9d4b9 | triage T1056 step 5 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None | F12, F15 |
| q-3d7df77e1f | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None |  |
| q-469c8effcf | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None |  |
| q-595f669cfe | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnI"} | None |  |
| q-b67328c2f5 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnI"} | None |  |
| q-d44e9af74c | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnI"} | None |  |
| q-612ed53a00 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2PTHqc"} | None |  |
| q-9c47ef30eb | triage T1056 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None |  |
| q-eb58b4d7e6 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1kD"} | None |  |
| q-50189b5020 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1kD"} | None |  |
| q-7cd6027eb6 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1kD"} | None |  |
| q-f95b19a2d1 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1lG"} | None |  |
| q-e3dad00707 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None |  |
| q-eb9eec7ee1 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None |  |
| q-d574fbcd7b | triage T1110 step 1 | search | {"dataset": "windows.security", "query": "event.code:4776", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 1 |  |
| q-771721a8ac | triage T1110 step 1 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 30, "sub_field": "win.GrantedAccess"} | 326 |  |
| q-76cc3986c0 | triage T1110 step 1 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4648", "time_from": null, "time_to": null, "size": 20, "sub_field": "host.name"} | 15 |  |
| q-ebfb62ae4b | triage T1110 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND process.executable:*PowerShell*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "proc… | 4 | F18 |
| q-0bfdff0eb2 | triage T1110 step 2 | search | {"dataset": "windows.security", "query": "event.code:4648", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 15 | F19 |
| q-59aaf14d2e | triage T1110 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None | F18 |
| q-80759f4c6b | triage T1110 step 3 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None | F18 |
| q-dfcb5da3fc | triage T1110 step 4 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND process.pid:2976", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "so… | 1 | F18 |
| q-b30a97c1b2 | triage T1110 step 4 | count | {"dataset": "windows.security", "query": "event.code:4625 OR event.code:4771 OR event.code:4776", "time_from": null, "time_to": null} | 1 |  |
| q-43cc2735cc | triage T1110 step 5 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL8xSa_z"} | None | F16, F20 |
| q-f55aa94aeb | triage T1110 step 5 | aggregate | {"dataset": "windows.security", "field": "win.Status", "query": "event.code:4624 OR event.code:4625", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 297 |  |
| q-40defb7c4e | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL8xSa_z"} | None |  |
| q-b6e43c77fe | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL8xSa_z"} | None |  |
| q-3509697a9d | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL8xSa_z"} | None |  |
| q-38c861bf70 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-3664a108f7 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None |  |
| q-198beb1453 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-7c07dea588 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-2b2b70548e | triage T1110 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-e67aa23c62 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None |  |
| q-735f71c77e | triage T1110 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7ViMbT"} | None |  |
| q-54e9791f91 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-324e6b8b6a | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9OrXFR"} | None |  |
| q-f05fad0db7 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9OrXFR"} | None |  |
| q-2f91956baf | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL88ahmW"} | None |  |
| q-ddbe10979c | triage T1110 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None |  |
| q-3b30a28edc | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL8xSa_z"} | None |  |
| q-8652bdc63f | triage T1111 step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 10 AND win.TargetImage LIKE \"*lsass*\" AND win.GrantedAccess IN (\"0x1fffff\",\"0x101001\",\"0x1f3fff\",\"0x1000000\",\"0x3000\",\"0x1400\") \| KEEP @timestamp, host.name,… | ERROR |  |
| q-dc96471518 | triage T1111 step 1 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == 4648 \| KEEP @timestamp, host.name, win.TargetUserName, win.SubjectUserName, win.ProcessName, win.IpAddress, win.TargetServerName, _id, _index \| SORT @timestamp ASC"} | ERROR |  |
| q-acd1e8eca2 | triage T1111 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND win.TargetImage LIKE \"*lsass*\" AND win.GrantedAccess IN (\"0x1fffff\",\"0x101001\",\"0x1f3fff\",\"0x1000000\",\"0x3000\",\"0x1400\") \| KEEP @timestamp, host.n… | 33 | F21 |
| q-d3b3e6fc0a | triage T1111 step 2 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4648\" \| KEEP @timestamp, host.name, win.TargetUserName, win.SubjectUserName, win.ProcessName, win.IpAddress, win.TargetServerName, _id, _index \| SORT @timestamp ASC"… | 15 | F21 |
| q-c8e8ad7e6e | triage T1111 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-d964fcb2e8 | triage T1111 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None |  |
| q-401f4bf9b6 | triage T1111 step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (win.ScriptBlockText LIKE \"*lsass*\" OR win.ScriptBlockText LIKE \"*MiniDump*\" OR win.ScriptBlockText LIKE \"*sekurlsa*\" OR win.ScriptBlockText LIKE \"*… | 4 |  |
| q-0028918220 | triage T1111 step 4 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mm"} | None |  |
| q-bfce5e4a16 | triage T1111 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND host.name == \"scranton.dmevals.local\" \| KEEP @timestamp, host.name, user.name, process.executable, process.command_line, process.parent.executable, process.par… | 359 |  |
| q-caede9243e | triage T1111 step 5 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE host.name == \"scranton.dmevals.local\" AND event.code == \"4104\" \| KEEP @timestamp, user.name, win.Path, win.ScriptBlockId, win.ScriptBlockText, _id, _index \| SORT @timestamp ASC… | 146 |  |
| q-edc3d84c9a | triage T1111 step 5 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-da703d2999 | triage T1111 step 6 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE host.name == \"scranton.dmevals.local\" AND event.code == \"4104\" AND @timestamp >= \"2020-05-02T03:01:51.000Z\" \| KEEP @timestamp, user.name, win.ScriptBlockId, win.ScriptBlockTex… | 108 | F21 |
| q-d254432ea3 | triage T1111 step 6 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4624\" AND win.LogonType IN (\"2\",\"10\",\"0\") \| KEEP @timestamp, host.name, win.LogonType, win.TargetUserName, win.IpAddress, win.Workstation, win.LogonProcessName,… | 18 |  |
| q-3f67e27cc4 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-efc4aa9643 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1ns"} | None |  |
| q-ed4bd7cf00 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None |  |
| q-dc36f2e662 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-ec66da60f1 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-c346247f74 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-b9498dcdcb | triage T1111 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9OrXFR"} | None |  |
| q-fea4085a9d | triage T1111 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL-w3yMh"} | None |  |
| q-b910d9f8af | triage T1187 step 1 | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA5C"} | None | F22 |
| q-289cd05c39 | triage T1187 step 1 | aggregate | {"dataset": "zeek", "field": "http.request.method", "query": "event.action:http", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 62 |  |
| q-cabcf104fb | triage T1187 step 1 | aggregate | {"dataset": "zeek", "field": "destination.ip", "query": "event.action:conn AND (destination.port:445 OR destination.port:139)", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 50 |  |
| q-1c696d08f8 | triage T1187 step 1 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:3 AND (destination.port:445 OR destination.port:139)", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 66 |  |
| q-3651ac9dc9 | triage T1187 step 2 | search | {"dataset": "zeek", "query": "event.action:http AND http.request.method:PROPFIND", "time_from": null, "time_to": null, "fields": ["@timestamp", "source.ip", "destination.ip", "destination.port", "http.request.method", "url.original", "user_agent.original", "ht… | 26 | F22 |
| q-ec60017ea5 | triage T1187 step 2 | aggregate | {"dataset": "zeek", "field": "user_agent.original", "query": "event.action:http", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 62 |  |
| q-093186bfe7 | triage T1187 step 2 | aggregate | {"dataset": "zeek", "field": "destination.ip", "query": "event.action:http", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 62 |  |
| q-993b01730d | triage T1187 step 3 | search | {"dataset": "zeek", "query": "event.action:http AND (http.request.method:PUT OR http.request.method:LOCK OR http.request.method:PROPPATCH OR http.request.method:UNLOCK)", "time_from": null, "time_to": null, "fields": ["@timestamp", "source.ip", "destination.ip… | 20 | F22 |
| q-c33ffdd327 | triage T1187 step 3 | search | {"dataset": "zeek", "query": "event.action:conn AND (destination.port:445 OR destination.port:139)", "time_from": null, "time_to": null, "fields": ["@timestamp", "source.ip", "destination.ip", "destination.port", "zeek.conn_state", "zeek.duration", "zeek.orig_… | 50 |  |
| q-123afbd815 | triage T1187 step 4 | search | {"dataset": "zeek", "query": "event.action:conn AND source.ip:10.0.1.4 AND destination.ip:192.168.0.4", "time_from": null, "time_to": null, "fields": ["@timestamp", "source.ip", "destination.ip", "destination.port", "zeek.conn_state", "network.transport"], "si… | 16 | F22 |
| q-a19502acfc | triage T1187 step 4 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (win.TargetFilename:*.scf OR win.TargetFilename:*.lnk OR win.TargetFilename:*.url OR win.TargetFilename:*.library-ms)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.na… | 3 |  |
| q-1f9b0f229e | triage T1187 step 5 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL64D_f9"} | None | F22 |
| q-53a5728dd4 | triage T1187 step 5 | search | {"dataset": "windows.sysmon", "query": "event.code:3 AND (destination.port:445 OR destination.port:139)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "process.executable", "destination.ip", "destination.port", "win.In… | 66 | F22 |
| q-389dbb9d94 | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA0a"} | None |  |
| q-351f428f5c | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA0a"} | None |  |
| q-fcb0619950 | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA0F"} | None |  |
| q-ed4d15d4fb | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA5C"} | None |  |
| q-f3bd9f07ac | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA5C"} | None |  |
| q-3737001023 | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA5H"} | None |  |
| q-a15f301125 | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA5H"} | None |  |
| q-7083b5c73c | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA5D"} | None |  |
| q-d5654cc150 | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA5I"} | None |  |
| q-599e5e1f3e | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGJw2G"} | None |  |
| q-e85512e30e | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGJw2G"} | None |  |
| q-06bd00ff0d | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA5L"} | None |  |
| q-077de5f660 | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA09"} | None |  |
| q-5925c2c5fa | triage T1187 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL69HyZX"} | None |  |
| q-6a8cd79928 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL64D_f9"} | None |  |
| q-0c98eb8d72 | triage T1212 step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 10 AND TO_LOWER(win.TargetImage) LIKE \"*lsass*\" AND win.GrantedAccess IN (\"0x1fffff\",\"0x101001\",\"0x1f3fff\",\"0x1000000\",\"0x3000\") \| KEEP @timestamp, host.name, … | ERROR |  |
| q-6faa9608a7 | triage T1212 step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 10 AND TO_LOWER(win.TargetImage) LIKE \"*lsass*\" \| STATS c = COUNT(*) BY process.executable, host.name, win.GrantedAccess \| SORT c DESC"} | ERROR |  |
| q-de5fe238e6 | triage T1212 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND TO_LOWER(win.TargetImage) LIKE \"*lsass*\" AND win.GrantedAccess IN (\"0x1fffff\",\"0x101001\",\"0x1f3fff\",\"0x1000000\",\"0x3000\") \| KEEP @timestamp, host.na… | 9 | F23, F24 |
| q-7d8c7c8403 | triage T1212 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND TO_LOWER(win.TargetImage) LIKE \"*lsass*\" \| STATS c = COUNT(*) BY process.executable, host.name, win.GrantedAccess \| SORT c DESC"} | 18 |  |
| q-a58de6d9b1 | triage T1212 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None | F23 |
| q-502efe9fc7 | triage T1212 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None | F23 |
| q-600a56ccaf | triage T1212 step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*lsass*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*minidump*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*credential*\"… | 20 |  |
| q-30ff1295fb | triage T1212 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*lsass*\" OR TO_LOWER(process.command_line) LIKE \"*dump*\" OR TO_LOWER(process.command_line) LIKE \"*procdump*\" OR TO_LOW… | 1 | F24 |
| q-98bd6c2af2 | triage T1212 step 5 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAOBExi"} | None | F23 |
| q-591e0e85c1 | triage T1212 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND host.name == \"scranton.dmevals.local\" AND user.name == \"pbeesly\" \| KEEP @timestamp, process.executable, process.command_line, process.parent.executable, _id,… | 106 | F23 |
| q-1499dc47c1 | triage T1212 step 6 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4624\",\"4672\",\"4648\",\"4768\",\"4769\",\"4776\") AND (win.TargetUserName LIKE \"*pbeesly*\" OR win.SubjectUserName LIKE \"*pbeesly*\") \| KEEP @timestamp, host.nam… | 83 |  |
| q-6e4947cbf4 | triage T1212 step 6 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND host.name == \"scranton.dmevals.local\" AND process.executable LIKE \"*PowerShell.exe\" \| KEEP @timestamp, process.executable, win.TargetImage, win.GrantedAcces… | 141 | F23 |
| q-51d7895337 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-826299765d | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-5b25912b18 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-17d5721733 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None |  |
| q-9735655446 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnJ"} | None |  |
| q-6d9a26b57d | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlm"} | None |  |
| q-01699b6494 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7am0gN"} | None |  |
| q-ff765c820c | triage T1212 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAOBExi"} | None |  |
| q-6db19f3179 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-3c20d058d1 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-eeb4ba0495 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2QULdY"} | None |  |
| q-d52f4049aa | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2ORrt4"} | None |  |
| q-a88ba3ca13 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JLx1ssmj"} | None |  |
| q-7efd2cb9d9 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2ORrtq"} | None |  |
| q-aa0ec9230f | triage T1539 step 1 | aggregate | {"dataset": "windows.powershell", "field": "win.ScriptBlockId", "query": "win.ScriptBlockText:*Cookies* OR win.ScriptBlockText:*Login Data* OR win.ScriptBlockText:*sqlite*", "time_from": null, "time_to": null, "size": 15, "sub_field": null} | 5157 |  |
| q-8ce7b33ef4 | triage T1539 step 1 | aggregate | {"dataset": "windows.powershell", "field": "host.name", "query": "win.ScriptBlockText:*Cookies* OR win.ScriptBlockText:*Login Data* OR win.ScriptBlockText:*sqlite*", "time_from": null, "time_to": null, "size": 15, "sub_field": null} | 5157 |  |
| q-fbe17d245d | triage T1539 step 2 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Cookies* OR win.ScriptBlockText:*Login Data* OR win.ScriptBlockText:*sqlite*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "win.Sc… | 13 |  |
| q-297bbc9e98 | triage T1539 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (win.TargetFilename:*Cookies* OR win.TargetFilename:*Login Data*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "process.executable", "win.TargetFilename"], "s… | 162 | F25 |
| q-b683a436e6 | triage T1539 step 3 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None | F25 |
| q-b8cf5feaf9 | triage T1539 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 11 AND (TO_LOWER(win.TargetFilename) LIKE \"*cookies*\" OR TO_LOWER(win.TargetFilename) LIKE \"*login data*\" OR TO_LOWER(win.TargetFilename) LIKE \"*\\\\\\\\user data\\\\\… | ERROR |  |
| q-a539e917dc | triage T1539 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(win.TargetFilename) LIKE \"*cookies*\" OR TO_LOWER(win.TargetFilename) LIKE \"*login data*\" OR TO_LOWER(win.TargetFilename) LIKE \"*user data*\" OR TO… | 1 | F25 |
| q-9fe1fd42fa | triage T1539 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND (TO_LOWER(win.TargetImage) LIKE \"*chrome*\" OR TO_LOWER(win.TargetImage) LIKE \"*firefox*\" OR TO_LOWER(win.TargetImage) LIKE \"*msedge*\" OR TO_LOWER(win.Targe… | 0 |  |
| q-6bc6669cd7 | triage T1539 step 5 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*Cookies* OR process.command_line:*Login Data* OR process.command_line:*chrome* OR process.command_line:*firefox*)", "time_from": null, "time_to": null, "fields": ["@timestamp"… | 4 | F25 |
| q-e5bb6dd2e8 | triage T1539 step 5 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4663\" AND (TO_LOWER(win.ObjectName) LIKE \"*cookies*\" OR TO_LOWER(win.ObjectName) LIKE \"*login data*\" OR TO_LOWER(win.ObjectName) LIKE \"*user data*\" OR TO_LOWER(w… | 0 |  |
| q-764933f603 | triage T1539 step 6 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*cookies*\" OR TO_LOWER(process.command_line) LIKE \"*login data*\" OR TO_LOWER(process.command_line) LIKE \"*user data*\" … | 1 |  |
| q-0374ef7355 | triage T1539 step 6 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(win.TargetFilename) LIKE \"*officesupplies*\" OR TO_LOWER(win.TargetFilename) LIKE \"*.7z\" OR TO_LOWER(win.TargetFilename) LIKE \"*\\\\\\\\appdata\\\\… | 16 | F25 |
| q-db657b7f22 | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JLx56e_Q"} | None |  |
| q-9e624becdc | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JLx56e_Q"} | None |  |
| q-f1ad87ddd8 | triage T1539 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9Txpr2"} | None |  |
| q-055e7ed9b9 | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7anEhE"} | None |  |
| q-8c5baa6894 | triage T1539 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None |  |
| q-f507f479a0 | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2lq7zj"} | None |  |
| q-8611178647 | triage T1552 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None | F26, F27 |
| q-33af71c7ec | triage T1552 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*.pfx OR win.TargetFilename:*passwordsDB OR win.TargetFilename:*nuget.config)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "ev… | 3 | F26, F27 |
| q-b28272bdfe | triage T1552 step 2 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == 4104 AND host.name == \"scranton.dmevals.local\" \| KEEP @timestamp, user.name, win.ScriptBlockId, win.Path, _id, _index \| SORT @timestamp ASC"} | ERROR |  |
| q-5946fbd7a5 | triage T1552 step 2 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4663 AND win.ObjectName:*Winlogon*", "time_from": null, "time_to": null, "size": 20, "sub_field": "win.AccessMask"} | 838 |  |
| q-9452af117f | triage T1552 step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND host.name == \"scranton.dmevals.local\" \| KEEP @timestamp, user.name, win.ScriptBlockId, win.Path, _id, _index \| SORT @timestamp ASC"} | 146 | F29 |
| q-087fd10288 | triage T1552 step 3 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND process.executable:*accesschk*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.comm… | 0 |  |
| q-ee2771e7b9 | triage T1552 step 4 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None | F27 |
| q-ae10894f5b | triage T1552 step 4 | search | {"dataset": "windows.sysmon", "query": "process.executable:*accesschk* OR process.command_line:*accesschk*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executa… | 2 | F27 |
| q-350e6d4fdb | triage T1552 step 5 | search | {"dataset": "windows.security", "query": "event.code:4648 AND win.TargetUserName:pbeesly", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "win.TargetUserName", "win.SubjectUserName", "win.ProcessName", "win.IpAddress", "win.TargetSer… | 9 | F27 |
| q-acfe2162e8 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-2f20714cee | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-e5ee398eab | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-d8ab0c3f92 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CdmD"} | None |  |
| q-5c3b3c2732 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CdmD"} | None |  |
| q-40168534cf | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None |  |
| q-1f3b6293f5 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None |  |
| q-c0dbf90fb2 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-0b39e1c05a | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63C9mM"} | None |  |
| q-c174c7c0a8 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63C9mZ"} | None |  |
| q-0588a5c3f6 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9OrXFR"} | None |  |
| q-833a306e3a | triage T1552 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9OrXFV"} | None |  |
| q-883ded84a1 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63C9mM"} | None |  |
| q-98d4b09932 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAWIhZ8"} | None |  |
| q-14b6f51315 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63C9mM"} | None |  |
| q-dc51cb6867 | triage T1552 step 7 | search | {"dataset": "windows.security", "query": "event.code:4663 AND win.ObjectName:*Winlogon*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "win.ObjectName", "win.AccessMask", "process.executable", "user.name"], "size": 3, "sort": "asc"… | 838 | F28 |
| q-f2586a93f1 | triage T1552 step 7 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND win.TargetFilename:*gpt.ini", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "win.TargetFilename", "process.executable"], "size": 3, "sort": "asc"} | 3 | F30 |
| q-dff1da1659 | triage T1555 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND (process.executable:*powershell* OR process.executable:*wsmprovhost* OR process.executable:*wininit* OR process.executable:*csrss* OR process.executable:*services*)", "time_f… | 7 |  |
| q-9664be84ff | triage T1555 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None | F34 |
| q-77c2315acc | triage T1555 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None | F31 |
| q-855a126cf0 | triage T1555 step 2 | search | {"dataset": "windows.security", "query": "event.code:(4656 OR 4663) AND (win.ObjectName:*lsass* OR win.ObjectName:*SAM* OR win.ObjectName:*SECURITY* OR win.ObjectName:*NTDS.dit*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "even… | 29 | F31, F33 |
| q-8a515c13b7 | triage T1555 step 3 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*lsass* OR process.command_line:*dump* OR process.command_line:*Out-Minidump* OR process.command_line:*Get-Process* OR process.command_line:*Invoke-Mimikatz* OR process.command_line… | 1 |  |
| q-58b724d8f4 | triage T1555 step 3 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*.dmp OR file.path:*lsass* OR file.path:*minidump* OR file.path:*credential* OR file.path:*vault*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "p… | 2 | F31 |
| q-c3abe936f3 | triage T1555 step 4 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*MiniDump* OR win.ScriptBlockText:*sekurlsa* OR win.ScriptBlockText:*Credential* OR win.ScriptBlockText:*Get-Process* OR win.ScriptBlockText:*Du… | 6 | F31 |
| q-52048a649c | triage T1555 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 1 AND (TO_LOWER(process.command_line) LIKE \"*lsass*\" OR TO_LOWER(process.command_line) LIKE \"*dump*\" OR TO_LOWER(process.command_line) LIKE \"*vault*\" OR TO_LOWER(proc… | ERROR |  |
| q-7429ca704b | triage T1555 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*lsass*\" OR TO_LOWER(process.command_line) LIKE \"*dump*\" OR TO_LOWER(process.command_line) LIKE \"*vault*\" OR TO_LOWER(… | 2 | F32 |
| q-bcc6d5b6c4 | triage T1555 step 5 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND user.name:pbeesly", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "user.name", "process.command_line", "win.ScriptBlockText"], "size": 30, "sort": "asc"} | 157 |  |
| q-a34d3b02fc | triage T1555 step 6 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND win.GrantedAccess:(0x1fffff OR 0x1f3fff OR 0x101001 OR 0x1400 OR 0x3000)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "process.ex… | 32 |  |
| q-6f560f2f39 | triage T1555 step 6 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*AppData* AND (file.path:*Login* OR file.path:*Cookies* OR file.path:*Web Data* OR file.path:*Local*State* OR file.path:*key4.db* OR file.path:*logins.json*))", "time_from": null, "time_to": … | 103 | F32 |
| q-bd4b487d37 | triage T1555 step 7 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None | F31 |
| q-8252910f2a | triage T1555 step 7 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND process.executable:*PowerShell* AND user.name:pbeesly", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "process.executable", "process.command_line", "process.pare… | 12 |  |
| q-4b39392e0f | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-05f479efbf | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-18963b7875 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-919217101b | triage T1555 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9MpvMw"} | None |  |
| q-2913fc7333 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9MpvMw"} | None |  |
| q-7b5a4fffa7 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-508394481a | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-7e8824a473 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAMA2AH"} | None |  |
| q-bc5038f36d | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL62AkVX"} | None |  |
| q-94ff68a5c5 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7Ufx6G"} | None |  |
| q-1806794073 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JLx56_hv"} | None |  |
| q-2e3203a129 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL81V4Qj"} | None |  |
| q-bd87a3b4ac | triage T1555 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL81V4Qj"} | None |  |
| q-989401e4b0 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL-w3yMh"} | None |  |
| q-bb59858cee | triage T1555 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None |  |
| q-abd524f907 | triage T1556 step 1 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": "process.executable"} | 326 |  |
| q-e4f05b47c5 | triage T1556 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND NOT win.GrantedAccess:0x1000", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process… | 33 | F40 |
| q-3818a59ff7 | triage T1556 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None | F36 |
| q-fe787fec23 | triage T1556 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None | F36 |
| q-70f497d366 | triage T1556 step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*lsass*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*minidump*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*comsvcs*\" OR… | 6 | F38, F42 |
| q-d72d7d841a | triage T1556 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (process.pid == 2976 OR process.pid == 7720 OR TO_LOWER(process.command_line) LIKE \"*lsass*\" OR TO_LOWER(process.command_line) LIKE \"*minidump*\" OR TO_LOWER(p… | 3 | F35, F42 |
| q-027a69ba28 | triage T1556 step 4 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7ViMbT"} | None | F42 |
| q-d1aa24ced5 | triage T1556 step 4 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None | F42 |
| q-06db048358 | triage T1556 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"13\" AND (TO_LOWER(registry.path) LIKE \"*lsa*\" OR TO_LOWER(registry.path) LIKE \"*networkprovider*\" OR TO_LOWER(registry.path) LIKE \"*notification packages*\" OR TO_L… | 40 | F35, F39, F41 |
| q-0fa7b0a44f | triage T1556 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND TO_LOWER(win.TargetFilename) LIKE \"*passwordsdb*\" \| KEEP @timestamp, host.name, user.name, process.executable, win.TargetFilename, _id, _index"} | 1 | F37 |
| q-4be8863b48 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2ORrtJ"} | None |  |
| q-4df3a130f3 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2ORrt6"} | None |  |
| q-659620341c | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2ORrtq"} | None |  |
| q-eadcc2e32a | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-5ec24668d2 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-cb22d1303a | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-d857e973b7 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63C9mM"} | None |  |
| q-e944ef48cc | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63C9mM"} | None |  |
| q-402389ba9e | triage T1556 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMASEsNZ"} | None |  |
| q-149a388ed7 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2ORrtJ"} | None |  |
| q-a6b23a963d | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JLx0p9yU"} | None |  |
| q-4f2c1da480 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JLx4yj34"} | None |  |
| q-be916770f7 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7ViMbT"} | None |  |
| q-c82c3b7cd2 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7ViMbT"} | None |  |
| q-87293f181d | triage T1556 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None |  |
| q-cc8c7fbfcb | triage T1556 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAOAxHj"} | None |  |
| q-e8974cb12c | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kqds5"} | None |  |
| q-314e70fa47 | triage T1557 step 1 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9AdJ6k"} | None |  |
| q-4989ff099a | triage T1557 step 1 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL8_cVAi"} | None | F45 |
| q-1672aaecc1 | triage T1557 step 1 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"dns\" AND (destination.port == 5355 OR destination.port == 137) \| KEEP @timestamp, source.ip, destination.ip, dns.question.name, zeek.id_orig_h, zeek.id_resp_h, zeek.rcode_name,… | 6 | F44 |
| q-c24a23f066 | triage T1557 step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 1 AND (process.command_line LIKE \"*ipconfig*\" OR process.command_line LIKE \"*netsh*\") \| KEEP @timestamp, host.name, user.name, process.executable, process.command_line… | ERROR |  |
| q-53c7fb79bc | triage T1557 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (process.command_line LIKE \"*ipconfig*\" OR process.command_line LIKE \"*netsh*\" OR process.command_line LIKE \"*arp*\") \| KEEP @timestamp, host.name, user.nam… | 8 | F45, F46 |
| q-31a3605606 | triage T1557 step 2 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"conn\" AND destination.port == 445 \| KEEP @timestamp, source.ip, destination.ip, zeek.service, zeek.conn_state, zeek.orig_l2_addr, zeek.resp_l2_addr, _id, _index"} | 45 | F43, F44, F46 |
| q-871678daac | triage T1557 step 3 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"notice\" OR event.action == \"weird\" \| KEEP @timestamp, event.action, zeek.note, zeek.msg, source.ip, destination.ip, zeek.orig_l2_addr, zeek.resp_l2_addr, _id, _index"} | 14 |  |
| q-48eb6429ab | triage T1557 step 3 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"conn\" \| STATS cnt = COUNT(*) BY source.ip, zeek.orig_l2_addr, destination.ip, zeek.resp_l2_addr \| SORT cnt DESC \| LIMIT 40"} | 9 |  |
| q-ddbb0471a4 | triage T1557 step 4 | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA6t"} | None | F43, F46 |
| q-83bea6dc22 | triage T1557 step 4 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4624\" AND win.LogonProcessName RLIKE \".*NtLmSsp.*\" \| KEEP @timestamp, host.name, user.name, win.TargetUserName, win.LogonProcessName, win.LogonType, source.ip, win.… | 1 |  |
| q-4f4d9debab | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA6t"} | None |  |
| q-1ab4da157e | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA6t"} | None |  |
| q-01d6420550 | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA6t"} | None |  |
| q-0e84394b57 | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIK6WOc7y0JMA_NKaA"} | None |  |
| q-b2cbb1c722 | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIK6WOc7y0JMA_NKaA"} | None |  |
| q-bd66aec20a | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA0H"} | None |  |
| q-08d11a626c | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA0H"} | None |  |
| q-73aacd625c | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGJw29"} | None |  |
| q-2b273ba052 | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGJw29"} | None |  |
| q-16a8970123 | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIK6WOc7y0JMA_NabS"} | None |  |
| q-2084ad53f0 | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIK6WOc7y0JMA_NabS"} | None |  |
| q-82e616001a | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGJw3s"} | None |  |
| q-094f7fb821 | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGJw3s"} | None |  |
| q-999515393d | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JLx1s9Ic"} | None |  |
| q-bb2e69471f | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JLx1s9Ic"} | None |  |
| q-70c34132a0 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2LOurf"} | None |  |
| q-379ea04ad6 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2LOurf"} | None |  |
| q-8a2fa185e7 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL8_cVAi"} | None |  |
| q-74c1fd0de3 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL8_cVAi"} | None |  |
| q-84affd6011 | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA6t"} | None |  |
| q-27fda95be7 | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA6t"} | None |  |
| q-c85dd40740 | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIK6WOc7y0JMA_NKaA"} | None |  |
| q-c8c5883bcc | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIK6WOc7y0JMA_NKaA"} | None |  |
| q-6c233e112f | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA0H"} | None |  |
| q-8507f8db9a | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2IKpDz"} | None |  |
| q-62e58ef87a | triage T1558 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND process.executable:*PowerShell*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "process.executable", "process.command_line", "win.GrantedAccess",… | 4 | F47 |
| q-9f1e95bab9 | triage T1558 step 1 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == 4768 \| KEEP @timestamp, host.name, user.name, win.TargetUserName, win.PreAuthType, win.TicketEncryptionType, win.IpAddress, win.Status, _id, _index"} | ERROR |  |
| q-0e79a304c0 | triage T1558 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-54e8f93f2c | triage T1558 step 2 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4768\" \| KEEP @timestamp, host.name, user.name, win.TargetUserName, win.PreAuthType, win.TicketEncryptionType, win.IpAddress, win.Status, _id, _index"} | 14 | F48, F51 |
| q-ecc2b761e3 | triage T1558 step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE host.name == \"scranton.dmevals.local\" AND @timestamp >= \"2020-05-02T03:00:00.000Z\" AND @timestamp <= \"2020-05-02T03:10:00.000Z\" \| KEEP @timestamp, event.code, user.name, proce… | 500 |  |
| q-6eb9b96f53 | triage T1558 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND host.name == \"scranton.dmevals.local\" \| KEEP @timestamp, process.executable, process.command_line, process.parent.executable, user.name, _id, _index \| SORT @t… | 359 | F47 |
| q-0e7e634ac8 | triage T1558 step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND host.name == \"scranton.dmevals.local\" \| KEEP @timestamp, user.name, win.ScriptBlockText, _id, _index \| SORT @timestamp ASC"} | 146 | F47 |
| q-a3da2a533c | triage T1558 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND process.executable LIKE \"*powershell*\" AND host.name == \"scranton.dmevals.local\" \| KEEP @timestamp, process.command_line, process.parent.executable, _id, _in… | 11 |  |
| q-e42435a880 | triage T1558 step 5 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"kerberos\" \| KEEP @timestamp, zeek.id_orig_h, zeek.id_resp_h, zeek.request_type, zeek.client, zeek.service, zeek.success, zeek.error_msg, zeek.cipher, _id, _index \| SORT @times… | 35 | F48, F49, F50, F51 |
| q-d9affff9ac | triage T1558 step 5 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4769\" \| KEEP @timestamp, host.name, user.name, win.ServiceName, win.TicketEncryptionType, win.TicketOptions, win.Status, win.IpAddress, _id, _index \| SORT @timestamp… | 28 | F48, F49, F50 |
| q-faef0dca02 | triage T1558 step 6 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None | F47 |
| q-1f711321fc | triage T1558 step 6 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL17AQxS"} | None |  |
| q-596ba43a7c | triage T1558 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-0f07d8ae26 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None |  |
| q-4c4e3993b7 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7am0gN"} | None |  |
| q-69c90f57df | triage T1558 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAWIhac"} | None |  |
| q-e7b7fa3af0 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL69HSbI"} | None |  |
| q-ceae135cbb | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL8-bHCF"} | None |  |
| q-daa36e4f27 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9MpvNN"} | None |  |
| q-98d45c8170 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL8zTpG-"} | None |  |
| q-65257578e1 | triage T1558 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGJw1f"} | None |  |
| q-a4a0f0bc3b | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9Cfa6G"} | None |  |
| q-1bdc8acaf7 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9OrnEj"} | None |  |
| q-9fe102462d | triage T1558 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGJw1d"} | None |  |
| q-6beb9243f8 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9LnloS"} | None |  |
| q-c3155007db | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9LnVrY"} | None |  |
| q-c8ff9c427d | triage T1558 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA0i"} | None |  |
| q-b69288b71f | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9OrXFP"} | None |  |
| q-a37c2bdf82 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL8-bHB-"} | None |  |
| q-8cb8888a89 | triage T1558 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGJw1g"} | None |  |
| q-92ab2b982e | triage T1606 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND (win.GrantedAccess:0x1fffff OR win.GrantedAccess:0x101001 OR win.GrantedAccess:0x1f3fff OR win.GrantedAccess:0x1000000 OR win.GrantedAccess:0x3000)", "time_from": null, "time… | 9 |  |
| q-cbaee2ec24 | triage T1606 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None | F52 |
| q-8f2b7d68b4 | triage T1606 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None | F52 |
| q-cc7e746338 | triage T1606 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None | F52 |
| q-177419f814 | triage T1606 step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == 4104 AND (TO_LOWER(win.ScriptBlockText) LIKE \"*lsass*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*minidump*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*sekurlsa*\" OR TO… | ERROR |  |
| q-50cc17f6fa | triage T1606 step 3 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 447 |  |
| q-d95799453f | triage T1606 step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*lsass*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*minidump*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*sekurlsa*\" O… | 3 |  |
| q-5b2bceb06d | triage T1606 step 4 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.executable:*python* OR process.executable:*PsExec* OR process.executable:*sdelete* OR process.executable:*rundll32* OR process.executable:*logman*)", "time_from": null, "time_to": null, "fields"… | 29 | F52, F53 |
| q-e00566e0c0 | triage T1606 step 5 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMANA6lp"} | None |  |
| q-de886dc201 | triage T1606 step 5 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4648\",\"4624\",\"4672\",\"5145\",\"5140\") AND (TO_LOWER(win.TargetServerName) LIKE \"*192.168*\" OR TO_LOWER(win.ShareName) LIKE \"*webdav*\" OR TO_LOWER(win.ObjectN… | 0 |  |
| q-42ad8ed90a | triage T1606 step 6 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4648\" \| KEEP @timestamp, host.name, user.name, win.TargetServerName, win.TargetUserName, win.ProcessName, win.IpAddress, _id, _index \| SORT @timestamp ASC"} | 15 | F54 |
| q-1884f8fb02 | triage T1606 step 6 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE TO_LOWER(win.ObjectName) LIKE \"*cookie*\" OR TO_LOWER(win.ObjectName) LIKE \"*saml*\" OR TO_LOWER(win.ObjectName) LIKE \"*token*\" OR TO_LOWER(win.TargetName) LIKE \"*cookie*\" OR TO_… | 6 |  |
| q-75b25819e1 | triage T1606 step 7 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9Jl2tp"} | None | F52, F54 |
| q-c942ed54d0 | triage T1606 step 7 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"5379\" OR event.code == \"5380\" OR event.code == \"5381\" OR event.code == \"5382\" \| KEEP @timestamp, host.name, event.code, user.name, win.TargetName, win.ProcessNa… | 26 |  |
| q-08a8fae6b4 | triage T1606 step 8 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None | F52 |
| q-43296e4e51 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None |  |
| q-607c92e893 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-d0e3d6ded2 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-c0a26a8772 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9Jl2tp"} | None |  |
| q-f69f9aca0d | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2ioON3"} | None |  |
| q-f99fefa4cc | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2lq7xd"} | None |  |
| q-9a33dea90f | triage T1606 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None |  |
| q-927cbd72a1 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2lq7xd"} | None |  |
| q-3601a75bbf | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2jpdJE"} | None |  |
| q-16fdc13e34 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9Jl2tp"} | None |  |
| q-1c2548e366 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9OrXFV"} | None |  |
| q-d2b18966f3 | triage T1621 step 1 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"http\" \| KEEP @timestamp, source.ip, destination.ip, destination.port, url.domain, url.original, http.request.method, http.response.status_code, user_agent.original, zeek.uri, z… | 62 | F55 |
| q-d6b322f597 | triage T1621 step 1 | aggregate | {"dataset": "zeek", "field": "destination.ip", "query": "event.action:http", "time_from": null, "time_to": null, "size": 30, "sub_field": "http.response.status_code"} | 62 |  |
| q-8040de7a7c | triage T1621 step 2 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"dns\" \| KEEP @timestamp, source.ip, destination.ip, dns.question.name, dns.response_code, zeek.query, zeek.answers, _id, _index \| SORT @timestamp ASC \| LIMIT 60"} | 53 | F55 |
| q-e177b8a1e9 | triage T1621 step 2 | aggregate | {"dataset": "zeek", "field": "tls.client.server_name", "query": "event.action:ssl", "time_from": null, "time_to": null, "size": 40, "sub_field": null} | 378 |  |
| q-8a9f4ee80f | triage T1621 step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*mfa*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*2fa*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*authenticator*\" OR TO_LOWER(win.ScriptBlockText… | 2 |  |
| q-735ad5266a | triage T1621 step 3 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 20, "sub_field": "win.AuthenticationPackageName"} | 297 |  |
| q-7ca5924081 | triage T1621 step 4 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAVHr_u"} | None | F55 |
| q-b310ae04b0 | triage T1621 step 4 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"files\" OR event.action == \"smb_files\" \| KEEP @timestamp, source.ip, destination.ip, file.path, file.mime_type, zeek.filename, zeek.mime_type, zeek.source, zeek.analyzers, _id… | 40 |  |
| q-12563ae3a9 | triage T1621 step 5 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4688\" \| STATS c = COUNT(*) BY process.executable, host.name \| SORT c DESC \| LIMIT 40"} | 40 |  |
| q-9eb90c6523 | triage T1621 step 5 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"notice\" OR event.action == \"weird\" OR event.action == \"pe\" \| KEEP @timestamp, event.action, source.ip, destination.ip, zeek.note, zeek.msg, zeek.name, file.mime_type, zeek.… | 15 |  |
| q-09d604ab66 | triage T1621 step 6 | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGJw2G"} | None | F55 |
| q-acc0d79f77 | triage T1621 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGJw17"} | None |  |
| q-f84f68e858 | triage T1621 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGJw17"} | None |  |
| q-82a77face2 | triage T1621 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGJw2B"} | None |  |
| q-d2f78d64a2 | triage T1621 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGJw2G"} | None |  |
| q-ee6d65b28c | triage T1621 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGJw2G"} | None |  |
| q-12e7a1ab3c | triage T1621 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA5C"} | None |  |
| q-fdfcd2ea66 | triage T1621 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGJw2z"} | None |  |
| q-2e28d8530e | triage T1621 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAVHr_u"} | None |  |
| q-b43f698d87 | triage T1649 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None | F56 |
| q-923df2280e | triage T1649 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND win.TargetFilename:*pfx*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "win.TargetFilename", "process.executable", "process.command_line", "win.Image", "win.Ha… | 1 | F56 |
| q-360aaf5dfd | triage T1649 step 1 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9FgwRA"} | None | F56 |
| q-702269f1a9 | triage T1649 step 2 | search | {"dataset": "windows.sysmon", "query": "host.name:scranton.dmevals.local AND (process.command_line:*readme.ps1* OR process.command_line:*Export-Pfx* OR process.command_line:*certutil* OR process.command_line:*Get-PrivateKeys* OR win.TargetFilename:*Downloads*)… | 317 |  |
| q-9909123faf | triage T1649 step 2 | search | {"dataset": "windows.sysmon", "query": "user.name:pbeesly AND event.code:1", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "event.code", "process.executable", "process.command_line", "process.parent.executable", "win.Ta… | 141 | F56 |
| q-584e7924fe | triage T1649 step 3 | search | {"dataset": "windows.sysmon", "query": "process.command_line:*readme.ps1* OR process.command_line:*Get-PrivateKeys* OR win.TargetFilename:*pfx* OR win.TargetFilename:*SysinternalsSuite*readme*", "time_from": null, "time_to": null, "fields": ["@timestamp", "hos… | 4 |  |
| q-c45e4ee926 | triage T1649 step 3 | search | {"dataset": "windows.sysmon", "query": "event.code:13 AND (registry.path:*SystemCertificates* OR registry.path:*Cryptography* OR registry.path:*Certificate*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "event.code",… | 25 | F56 |
| q-71463a3dc6 | triage T1649 step 4 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kqttt"} | None | F56 |
| q-7e484de190 | triage T1649 step 4 | search | {"dataset": "windows.sysmon", "query": "host.name:scranton.dmevals.local AND event.code:3 AND @timestamp:[2020-05-02T03:04:00.000Z TO 2020-05-02T03:28:00.000Z]", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "event.code… | 114 |  |
| q-74fd8cf951 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-d7faae0295 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-bb4c28a619 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-cd7e6e6809 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CdmD"} | None |  |
| q-cd031ad452 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CdmD"} | None |  |
| q-c5250ba732 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CtkV"} | None |  |
| q-90e87e44fe | triage T1649 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CdmN"} | None |  |
| q-cc7c8ff773 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kqttt"} | None |  |
| q-9a2c339c3b | triage T1649 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kqttt"} | None |  |
| q-05257ff30d | triage T1649 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7am0gN"} | None |  |
| q-b7f02bc7a9 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7ViMbT"} | None |  |
| q-460639bb6e | triage T1649 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7VicZa"} | None |  |
| q-e7d9bdcfef | triage T1649 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9FgwRA"} | None |  |
| q-6aa3bf727a | triage T1649 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9FgwRA"} | None |  |
| q-10caf2e294 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None |  |
| q-1634626f9b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-f6c0f9fffa | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None |  |
| q-1f6f390623 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9MpvMw"} | None |  |
| q-ca9f55af00 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9Qtr32"} | None |  |
| q-39beec0d1d | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9Qt70r"} | None |  |
| q-58371b58f0 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQDVp3"} | None |  |
| q-f13cd1681c | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1ns"} | None |  |
| q-b7c8775d42 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-7a8f104e1d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-98133846e9 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9VzibT"} | None |  |
| q-d2fcb708ea | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAMA2AH"} | None |  |
| q-1da4a8a7c0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2ORrtI"} | None |  |
| q-13efae2031 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2ORrtI"} | None |  |
| q-ac79a41be0 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL-w3yM8"} | None |  |
| q-315ae63766 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA6p"} | None |  |
| q-e9a73aa19d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL66EEHK"} | None |  |
| q-1edb65b503 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9Typob"} | None |  |
| q-ebaa7cb480 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-1cb4a65d51 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA6p"} | None |  |
| q-0fec99e951 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGJw3L"} | None |  |
| q-f50c8e3ce9 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGJw3G"} | None |  |
| q-2c29d7241c | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAWIxZm"} | None |  |
| q-56198780bd | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQDVrD"} | None |  |
| q-91c1e358d3 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQDVp0"} | None |  |
| q-196bc83a43 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9Typob"} | None |  |
| q-57e4656e52 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63C9mZ"} | None |  |
| q-c931071522 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9AdJ6k"} | None |  |
| q-44b57cbc21 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9AdJ6k"} | None |  |
| q-03cc1c9f6c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2IK5Hc"} | None |  |
| q-878cf0d22c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2JMYSh"} | None |  |
| q-e20132d596 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA04"} | None |  |
| q-9ccacc24a9 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA01"} | None |  |
| q-0be138e9eb | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIK6WOc7y0JMA_NaZf"} | None |  |
| q-a86cbe84c5 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2in-NH"} | None |  |
| q-6eaa1f1cab | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2bgjeM"} | None |  |
| q-4dbd8ad0d8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7ViMbT"} | None |  |
| q-1729f00ecf | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None |  |
| q-12434f254c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None |  |
| q-0e0cb5e4f0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnI"} | None |  |
| q-0d95ee848d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnI"} | None |  |
| q-886f8c75b2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnI"} | None |  |
| q-49d54a899d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2PTHqc"} | None |  |
| q-6e01ae2a8b | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None |  |
| q-a93326e163 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1kD"} | None |  |
| q-26293a7580 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1kD"} | None |  |
| q-97b2870ba8 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1kD"} | None |  |
| q-31bbd26e8b | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1lG"} | None |  |
| q-782fcbc7ab | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None |  |
| q-f4807c0ab3 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None |  |
| q-5c3c02d2c7 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL8xSa_z"} | None |  |
| q-2a95f20acf | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL8xSa_z"} | None |  |
| q-d3fa8c9b1a | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL8xSa_z"} | None |  |
| q-917a7fb6af | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-212d3249e2 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None |  |
| q-44d49816be | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-c596a70164 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-3b4246025e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-0e1b8beaa1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None |  |
| q-aff54ce83d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7ViMbT"} | None |  |
| q-80287985d8 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-5308416ee9 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9OrXFR"} | None |  |
| q-bef45a01e0 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9OrXFR"} | None |  |
| q-28c50f2469 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL88ahmW"} | None |  |
| q-c4643d81c4 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None |  |
| q-6304534071 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL8xSa_z"} | None |  |
| q-2597465e8b | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-5deaaf12ad | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1ns"} | None |  |
| q-3271680e66 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None |  |
| q-1fbb58ed3f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-bc0f8bb0ab | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-0f4fd7d44c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-6ec3d3b939 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9OrXFR"} | None |  |
| q-0bc94654f1 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL-w3yMh"} | None |  |
| q-3c84a9a128 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA0a"} | None |  |
| q-78c8852568 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA0a"} | None |  |
| q-efca94b6d7 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA0F"} | None |  |
| q-3eb6e87140 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA5C"} | None |  |
| q-57fdd894c9 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA5C"} | None |  |
| q-5bbd992a76 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA5H"} | None |  |
| q-8a502b489f | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA5H"} | None |  |
| q-c8413f3722 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA5D"} | None |  |
| q-a20af2bbad | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA5I"} | None |  |
| q-71d45a8233 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGJw2G"} | None |  |
| q-dab9e43b66 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGJw2G"} | None |  |
| q-04777cc2e7 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA5L"} | None |  |
| q-2f9c2c4797 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA09"} | None |  |
| q-8d8e690d96 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL69HyZX"} | None |  |
| q-4d2de5821b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL64D_f9"} | None |  |
| q-d43727f989 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-a16d7f17e4 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-3e4446a716 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-0bde2b102c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None |  |
| q-537584c1ab | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnJ"} | None |  |
| q-83de41db9c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlm"} | None |  |
| q-2c613a07d8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7am0gN"} | None |  |
| q-cdd46480e0 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAOBExi"} | None |  |
| q-07228c1aac | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-0f6a7b03d1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-d6559409d1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2QULdY"} | None |  |
| q-2f373bd550 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2ORrt4"} | None |  |
| q-ea86b0bee8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JLx1ssmj"} | None |  |
| q-ba22b8c6f4 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2ORrtq"} | None |  |
| q-5fa4084092 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JLx56e_Q"} | None |  |
| q-2c945494cf | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JLx56e_Q"} | None |  |
| q-ffc1470b09 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9Txpr2"} | None |  |
| q-985cbe8316 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7anEhE"} | None |  |
| q-8ec1f3fc61 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None |  |
| q-a6ba7c8547 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2lq7zj"} | None |  |
| q-0704387deb | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-97f2fd4da0 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-895653f2b3 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-fee5eb223b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CdmD"} | None |  |
| q-3543dfd0a3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CdmD"} | None |  |
| q-cd967965e7 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None |  |
| q-7923d71fb3 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None |  |
| q-5c93f8003f | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-559a527213 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63C9mM"} | None |  |
| q-113a7090c7 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63C9mZ"} | None |  |
| q-291b85cd90 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9OrXFR"} | None |  |
| q-4baf610b75 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9TyZrV"} | None |  |
| q-aeffe5f0f4 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9TyZrV"} | None |  |
| q-147b6b9401 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9TyZrV"} | None |  |
| q-287ee36193 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9TyZrV"} | None |  |
| q-5d4b2d1cc0 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAWIhZ8"} | None |  |
| q-7e6d2cf420 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL6-IQQH"} | None |  |
| q-e40a124fe9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL6-IQQH"} | None |  |
| q-f32932ba77 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-e3b58053d7 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-61f95c2cac | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-f67d396a01 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9MpvMw"} | None |  |
| q-cbbc28ba7a | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9MpvMw"} | None |  |
| q-30aa8bde24 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-d143921cd9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-28e5c1f923 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAMA2AH"} | None |  |
| q-c0f36f34a5 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL62AkVX"} | None |  |
| q-be15fd568c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7Ufx6G"} | None |  |
| q-33508ea0da | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JLx56_hv"} | None |  |
| q-4f16b6e251 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL81V4Qj"} | None |  |
| q-ccbd147bb5 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL81V4Qj"} | None |  |
| q-20d121a46f | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL-w3yMh"} | None |  |
| q-74f6331832 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None |  |
| q-cfcafead4c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2ORrtJ"} | None |  |
| q-35af26405f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2ORrt6"} | None |  |
| q-de606b1c86 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2ORrtq"} | None |  |
| q-b9d8977a09 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-51b4477d65 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-0542808262 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-6cf5033b68 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63C9mM"} | None |  |
| q-07acb85f42 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63C9mM"} | None |  |
| q-55ff4e1ef2 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMASEsNZ"} | None |  |
| q-198f215074 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2ORrtJ"} | None |  |
| q-fdb48d4aa2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JLx0p9yU"} | None |  |
| q-48b859a7bf | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JLx4yj34"} | None |  |
| q-fbbb160502 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7ViMbT"} | None |  |
| q-c0993be5c1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7ViMbT"} | None |  |
| q-20c90077f4 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None |  |
| q-20443ed075 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAOAxHj"} | None |  |
| q-83408bd809 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kqds5"} | None |  |
| q-7c90fe0453 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA6t"} | None |  |
| q-9a56887c81 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA6t"} | None |  |
| q-97df7020d1 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA6t"} | None |  |
| q-761d10279d | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIK6WOc7y0JMA_NKaA"} | None |  |
| q-41643571f3 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIK6WOc7y0JMA_NKaA"} | None |  |
| q-cd501f29fb | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA0H"} | None |  |
| q-e905538435 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA0H"} | None |  |
| q-417c7f3b6e | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGJw29"} | None |  |
| q-0ab652519b | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGJw29"} | None |  |
| q-85bef21762 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIK6WOc7y0JMA_NabS"} | None |  |
| q-0f526099f9 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIK6WOc7y0JMA_NabS"} | None |  |
| q-bf16fe1498 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGJw3s"} | None |  |
| q-fccdbabb4d | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGJw3s"} | None |  |
| q-b4c1ff9d94 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JLx1s9Ic"} | None |  |
| q-5268996ec8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JLx1s9Ic"} | None |  |
| q-e5da6473f8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2LOurf"} | None |  |
| q-94ca180126 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2LOurf"} | None |  |
| q-f272d3a094 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL8_cVAi"} | None |  |
| q-823aeb539c | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL8_cVAi"} | None |  |
| q-941b69228a | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA6t"} | None |  |
| q-ac48102ece | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA6t"} | None |  |
| q-1abe885316 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIK6WOc7y0JMA_NKaA"} | None |  |
| q-75df665604 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIK6WOc7y0JMA_NKaA"} | None |  |
| q-8aee891baa | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA0H"} | None |  |
| q-962d77ead1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2IKpDz"} | None |  |
| q-98a650ccef | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-79356b6bd8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None |  |
| q-8e4ff3bdbb | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7am0gN"} | None |  |
| q-9618432612 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAWIhac"} | None |  |
| q-578b5c54ef | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL69HSbI"} | None |  |
| q-d8dfb22280 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL8-bHCF"} | None |  |
| q-392691d6fd | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9MpvNN"} | None |  |
| q-47dc55a7fd | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL8zTpG-"} | None |  |
| q-917e267711 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGJw1f"} | None |  |
| q-a5766ca474 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9Cfa6G"} | None |  |
| q-596affc8ba | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9OrnEj"} | None |  |
| q-0342f42218 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGJw1d"} | None |  |
| q-a0f9f21e83 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9LnloS"} | None |  |
| q-8698b3eb15 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9LnVrY"} | None |  |
| q-1b699de322 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA0i"} | None |  |
| q-2ea8c4b3de | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9OrXFP"} | None |  |
| q-ac6a6f7693 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL8-bHB-"} | None |  |
| q-1f39920dd9 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGJw1g"} | None |  |
| q-efe56dde36 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None |  |
| q-210672255c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-9665d4f6f8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-9d5d91095d | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9Jl2tp"} | None |  |
| q-40922e2df4 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2ioON3"} | None |  |
| q-03878e735d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2lq7xd"} | None |  |
| q-fa224b1c4c | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None |  |
| q-13e056e695 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2lq7xd"} | None |  |
| q-912ace1141 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2jpdJE"} | None |  |
| q-4171b003bc | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9Jl2tp"} | None |  |
| q-26fd5ddcb3 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9OrXFV"} | None |  |
| q-536982a893 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGJw17"} | None |  |
| q-d0f68fe9c6 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGJw17"} | None |  |
| q-d2fa1295d8 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGJw2B"} | None |  |
| q-db82bafd9f | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGJw2G"} | None |  |
| q-e1b7edac92 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGJw2G"} | None |  |
| q-01029e0759 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA5C"} | None |  |
| q-187bddf9ae | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGJw2z"} | None |  |
| q-96a9b4f8d0 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAVHr_u"} | None |  |
| q-e9543f6fbc | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-e8692093aa | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-4449c7bb2e | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-d16ff2c177 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CdmD"} | None |  |
| q-e5caa43d7c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CdmD"} | None |  |
| q-285855550f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CtkV"} | None |  |
| q-fc5c6f5cd4 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CdmN"} | None |  |
| q-777ea376da | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kqttt"} | None |  |
| q-912b2a3697 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kqttt"} | None |  |
| q-b83c4eb46e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7am0gN"} | None |  |
| q-5a13db63a8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7VicZa"} | None |  |
| q-1296aad734 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9FgwRA"} | None |  |
| q-81cdad4ca0 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9FgwRA"} | None |  |
| q-9c29d54f73 | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND host.name:\"nashua.dmevals.local\"", "time_from": "2020-05-02T02:50:27.395000+00:00", "time_to": "2020-05-02T03:31:19+00:00", "size": 100, "sub_field": "process.parent.exec… | 61 |  |
| q-d1974ee501 | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11 AND host.name:\"nashua.dmevals.local\"", "time_from": "2020-05-02T02:50:27.395000+00:00", "time_to": "2020-05-02T03:31:19+00:00", "size": 100, "sub_field": "process.executable"} | 249 |  |
| q-8839901877 | pivot seed | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND host.name:\"nashua.dmevals.local\"", "time_from": "2020-05-02T02:50:27.395000+00:00", "time_to": "2020-05-02T03:31:19+00:00", "size": 100, "sub_field": "process.parent… | 63 |  |
| q-5558fb78de | pivot seed | aggregate | {"dataset": "windows.powershell", "field": "event.code", "query": "host.name:\"nashua.dmevals.local\"", "time_from": "2020-05-02T02:50:27.395000+00:00", "time_to": "2020-05-02T03:31:19+00:00", "size": 100, "sub_field": null} | 192 |  |
| q-0090663b8b | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND host.name:\"scranton.dmevals.local\"", "time_from": "2020-05-02T02:40:56+00:00", "time_to": "2020-05-02T03:34:25.370000+00:00", "size": 100, "sub_field": "process.parent.ex… | 359 |  |
| q-35da54aee8 | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11 AND host.name:\"scranton.dmevals.local\"", "time_from": "2020-05-02T02:40:56+00:00", "time_to": "2020-05-02T03:34:25.370000+00:00", "size": 100, "sub_field": "process.executable"} | 1276 |  |
| q-3044b0c498 | pivot seed | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND host.name:\"scranton.dmevals.local\"", "time_from": "2020-05-02T02:40:56+00:00", "time_to": "2020-05-02T03:34:25.370000+00:00", "size": 100, "sub_field": "process.pare… | 370 |  |
| q-f65a456d23 | pivot seed | aggregate | {"dataset": "windows.powershell", "field": "event.code", "query": "host.name:\"scranton.dmevals.local\"", "time_from": "2020-05-02T02:40:56+00:00", "time_to": "2020-05-02T03:34:25.370000+00:00", "size": 100, "sub_field": null} | 8602 |  |
| q-812f78f007 | pivot step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 1 AND host.name == \"scranton.dmevals.local\" AND (process.executable LIKE \"*SysinternalsSuite*\" OR process.executable LIKE \"*victim*\" OR process.executable LIKE \"*csc… | ERROR |  |
| q-e2b0ec2a35 | pivot step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 1 AND host.name == \"nashua.dmevals.local\" AND (process.executable LIKE \"*Temp*\" OR process.executable LIKE \"*SkypeApp*\") \| KEEP @timestamp, _id, _index, process.exec… | ERROR |  |
| q-9e4f3772eb | pivot step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND host.name == \"scranton.dmevals.local\" AND (process.executable LIKE \"*SysinternalsSuite*\" OR process.executable LIKE \"*victim*\" OR process.executable LIKE \"… | 15 | F58, F67 |
| q-973857cd9d | pivot step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND host.name == \"nashua.dmevals.local\" AND (process.executable LIKE \"*Temp*\" OR process.executable LIKE \"*SkypeApp*\") \| KEEP @timestamp, _id, _index, process.… | 9 |  |
| q-0aa6238c25 | pivot step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND host.name == \"scranton.dmevals.local\" AND (file.path LIKE \"*victim*\" OR file.path LIKE \"*.pfx\" OR file.path LIKE \"*password*\" OR file.path LIKE \"*Draft*… | 462 |  |
| q-7906f86dde | pivot step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND host.name == \"scranton.dmevals.local\" \| KEEP @timestamp, _id, _index, powershell.file.script_block_text, user.name \| SORT @timestamp ASC"} | ERROR |  |
| q-0733f7e54f | pivot step 4 | get_fields | {"dataset": "windows.powershell", "prefix": ""} | None |  |
| q-aba201af42 | pivot step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND host.name == \"scranton.dmevals.local\" AND (file.path LIKE \"*.pfx\" OR file.path LIKE \"*password*\" OR file.path LIKE \"*victim*\" OR file.path LIKE \"*Draft*… | 4 | F57, F58 |
| q-f3d72789f2 | pivot step 5 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND host.name == \"scranton.dmevals.local\" \| KEEP @timestamp, _id, _index, win.ScriptBlockText \| SORT @timestamp ASC"} | 146 |  |
| q-c3d74b0f04 | pivot step 6 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND host.name == \"scranton.dmevals.local\" AND @timestamp > \"2020-05-02T03:01:51.000Z\" \| KEEP @timestamp, _id, _index, win.ScriptBlockText \| SORT @timesta… | 106 | F63, F65 |
| q-5c9377b55e | pivot step 7 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND host.name == \"scranton.dmevals.local\" AND @timestamp > \"2020-05-02T03:06:47.000Z\" \| KEEP @timestamp, _id, _index, win.ScriptBlockText \| SORT @timesta… | 63 | F59 |
| q-d2dc243e8d | pivot step 8 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND host.name == \"scranton.dmevals.local\" AND @timestamp > \"2020-05-02T03:09:04.000Z\" \| KEEP @timestamp, _id, _index, win.ScriptBlockText \| SORT @timesta… | 23 | F60 |
| q-a551aac8a5 | pivot step 9 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None | F57, F64 |
| q-dd2ff714df | pivot step 9 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None | F68 |
| q-9ad9ea5b5f | pivot step 10 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1lL"} | None | F59 |
| q-85c4f13067 | pivot step 10 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND host.name == \"nashua.dmevals.local\" \| KEEP @timestamp, _id, _index, win.ScriptBlockText \| SORT @timestamp ASC"} | 11 |  |
| q-239ed30fc7 | pivot step 11 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE host.name == \"scranton.dmevals.local\" AND (file.path LIKE \"*Microsoft\\\\Credentials*\" OR file.path LIKE \"*Microsoft\\\\Protect*\" OR file.path LIKE \"*Vault*\" OR file.path LIKE \"… | ERROR |  |
| q-82fcae542b | pivot step 11 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE host.name == \"scranton.dmevals.local\" AND event.code IN (\"4663\",\"4656\",\"4673\",\"4674\") AND (win.ObjectName LIKE \"*lsass*\" OR win.ObjectName LIKE \"*SAM*\" OR win.ObjectName … | ERROR |  |
| q-6725f9dda8 | pivot step 12 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE host.name == \"scranton.dmevals.local\" AND (file.path LIKE \"*Credentials*\" OR file.path LIKE \"*Protect*\" OR file.path LIKE \"*Vault*\" OR file.path LIKE \"*SAM*\" OR file.path LIKE … | 20 | F62 |
| q-59711b7717 | pivot step 12 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE host.name == \"scranton.dmevals.local\" AND event.code IN (\"4663\",\"4656\",\"4673\",\"4674\") AND (win.ObjectName LIKE \"*lsass*\" OR win.ObjectName LIKE \"*SAM*\" OR win.ObjectName … | 22 | F61, F66 |
| q-5ea3d94ee9 | pivot verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-061df7297e | pivot verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-3be7f67333 | pivot verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1ns"} | None |  |
| q-16eb299646 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CdmD"} | None |  |
| q-d959c182a9 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63C9mM"} | None |  |
| q-9dd907ec24 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63C9mZ"} | None |  |
| q-ceabca0cbb | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2ioON3"} | None |  |
| q-4a303e5ed6 | pivot verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None |  |
| q-a9271c95b0 | pivot verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQDFlH"} | None |  |
| q-aeb2e661ec | pivot verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1lL"} | None |  |
| q-b6cab19223 | pivot verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL_--77z"} | None |  |
| q-21065b30ce | pivot verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAWJWsz"} | None |  |
| q-1bd27e8116 | pivot verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAVH79h"} | None |  |
| q-b11dfadd2c | pivot verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAWJGOH"} | None |  |
| q-ba61d6928f | pivot verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9Qt70r"} | None |  |
| q-144ec8c78f | pivot verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9Qt70r"} | None |  |
| q-d642ae8873 | pivot verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9MpvMw"} | None |  |
| q-4f7eed7c89 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL17C4EF"} | None |  |
| q-cce6a12215 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None |  |
| q-0722485b31 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-e48520b13b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None |  |
| q-6b6ebbab7a | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9MpvMw"} | None |  |
| q-a49dfd2b42 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9Qtr32"} | None |  |
| q-55b572f35f | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9Qt70r"} | None |  |
| q-a4d56ee54f | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQDVp3"} | None |  |
| q-b31aad6755 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1ns"} | None |  |
| q-12e67b2245 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-2b955624a0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-4fe119760f | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9VzibT"} | None |  |
| q-21428216b7 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAMA2AH"} | None |  |
| q-f3e7ee7615 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2ORrtI"} | None |  |
| q-dfc3f6fe0a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2ORrtI"} | None |  |
| q-6d4ba5b01b | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL-w3yM8"} | None |  |
| q-a22f36ea59 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA6p"} | None |  |
| q-64b85851a3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL66EEHK"} | None |  |
| q-77be392778 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9Typob"} | None |  |
| q-9f88cf052f | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-153d6e669e | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA6p"} | None |  |
| q-ded53ee68e | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGJw3L"} | None |  |
| q-d3dc251508 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGJw3G"} | None |  |
| q-c6eb47b50e | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAWIxZm"} | None |  |
| q-05c9555134 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQDVrD"} | None |  |
| q-0a4991a5e8 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQDVp0"} | None |  |
| q-96403bb647 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9Typob"} | None |  |
| q-cce2c5bff1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63C9mZ"} | None |  |
| q-1000fece4a | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9AdJ6k"} | None |  |
| q-007ca784ca | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9AdJ6k"} | None |  |
| q-2afcedc03b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2IK5Hc"} | None |  |
| q-5f7606916a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2JMYSh"} | None |  |
| q-8683baf4da | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA04"} | None |  |
| q-ee469e579e | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA01"} | None |  |
| q-85ea87fcd6 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIK6WOc7y0JMA_NaZf"} | None |  |
| q-a114bc4025 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2in-NH"} | None |  |
| q-ff776e4038 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2bgjeM"} | None |  |
| q-cb88c756a3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7ViMbT"} | None |  |
| q-2361f439db | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None |  |
| q-63af3ee357 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None |  |
| q-46970055ff | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnI"} | None |  |
| q-97e6b0bb7b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnI"} | None |  |
| q-802d9de045 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnI"} | None |  |
| q-f6f7c353eb | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2PTHqc"} | None |  |
| q-e466e8a2a7 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None |  |
| q-8946ecaf21 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1kD"} | None |  |
| q-337fa7eae8 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1kD"} | None |  |
| q-81ecfb47e2 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1kD"} | None |  |
| q-f218581c1f | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1lG"} | None |  |
| q-28e10cfb99 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None |  |
| q-0082e19421 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None |  |
| q-2c371ef145 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL8xSa_z"} | None |  |
| q-c82c415ef0 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL8xSa_z"} | None |  |
| q-dca988ad89 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL8xSa_z"} | None |  |
| q-44549aa43c | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-27e03ee971 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None |  |
| q-f7ecc74b15 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-530507eb10 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-488d268bbf | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-f1da1a6157 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None |  |
| q-38f0bd4e14 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7ViMbT"} | None |  |
| q-35cbcf9d38 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-676b5a2499 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9OrXFR"} | None |  |
| q-5d249d4fde | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9OrXFR"} | None |  |
| q-c50621d446 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL88ahmW"} | None |  |
| q-df24e6b2f3 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None |  |
| q-6e19a10167 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL8xSa_z"} | None |  |
| q-b3166cd3e4 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-5f15edaadf | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1ns"} | None |  |
| q-05e5f7c8cc | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None |  |
| q-5edccf3d1a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-034f8545c2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-f0cb99a6d8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-8c53e5554e | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9OrXFR"} | None |  |
| q-7d8b09bd53 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL-w3yMh"} | None |  |
| q-aa030209f6 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA0a"} | None |  |
| q-f7967296e9 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA0a"} | None |  |
| q-fd3bbe0ceb | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA0F"} | None |  |
| q-7112e83372 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA5C"} | None |  |
| q-1a3363c6b6 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA5C"} | None |  |
| q-43cfa73235 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA5H"} | None |  |
| q-88f01ad841 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA5H"} | None |  |
| q-2a50327276 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA5D"} | None |  |
| q-05a28b6300 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA5I"} | None |  |
| q-a22e0bfcb1 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGJw2G"} | None |  |
| q-8f5d7e7e33 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGJw2G"} | None |  |
| q-9a1df4162a | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA5L"} | None |  |
| q-078e6a1125 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA09"} | None |  |
| q-f09861f7a9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL69HyZX"} | None |  |
| q-2ccd02710f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL64D_f9"} | None |  |
| q-51e1e4e829 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-a95a98c67f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-cb6a627f99 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-08dd3a9213 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None |  |
| q-bacb006a81 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnJ"} | None |  |
| q-18c0442b2f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlm"} | None |  |
| q-72145e2a54 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7am0gN"} | None |  |
| q-bd784a772f | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAOBExi"} | None |  |
| q-bf6682ff9d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-eed6905d5b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-568acaa22e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2QULdY"} | None |  |
| q-f0db2952fc | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2ORrt4"} | None |  |
| q-47da1efa74 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JLx1ssmj"} | None |  |
| q-70fcc13aee | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2ORrtq"} | None |  |
| q-3168d870aa | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JLx56e_Q"} | None |  |
| q-7b33b05393 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JLx56e_Q"} | None |  |
| q-951f470519 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9Txpr2"} | None |  |
| q-3fe3aa8e6e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7anEhE"} | None |  |
| q-894322c90f | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None |  |
| q-1529e2fd56 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2lq7zj"} | None |  |
| q-6776b67668 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-e0025a06f0 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-a6ba9d9aed | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-725e71fc07 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CdmD"} | None |  |
| q-8cde4a78eb | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CdmD"} | None |  |
| q-8fcc87e23d | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None |  |
| q-d747f12ffc | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None |  |
| q-6c47713a03 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-cacb8f7ff0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63C9mM"} | None |  |
| q-8a952a8b05 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63C9mZ"} | None |  |
| q-311c6022aa | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9OrXFR"} | None |  |
| q-5257267e74 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9TyZrV"} | None |  |
| q-48cb6e6465 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9TyZrV"} | None |  |
| q-61a94601de | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9TyZrV"} | None |  |
| q-522607efb1 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9TyZrV"} | None |  |
| q-b4acea4a64 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAWIhZ8"} | None |  |
| q-8570be5675 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL6-IQQH"} | None |  |
| q-fa950a1018 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL6-IQQH"} | None |  |
| q-dcfb608525 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-c7d659897d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-f8f26fdeb9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-8070c5dcac | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9MpvMw"} | None |  |
| q-8410960660 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9MpvMw"} | None |  |
| q-fd9838b770 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-c332fc3988 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-34b0af3026 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAMA2AH"} | None |  |
| q-bef5ae0f1a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL62AkVX"} | None |  |
| q-6ad46f77e3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7Ufx6G"} | None |  |
| q-675bed8858 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JLx56_hv"} | None |  |
| q-c3268d5ef6 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL81V4Qj"} | None |  |
| q-f4f7c2b91e | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL81V4Qj"} | None |  |
| q-aea840d27b | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL-w3yMh"} | None |  |
| q-e2a6439093 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None |  |
| q-7145d98d3d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2ORrtJ"} | None |  |
| q-243ec04d10 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2ORrt6"} | None |  |
| q-df331fe213 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2ORrtq"} | None |  |
| q-a073fc0526 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-4550ab6f26 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-1c5c6de172 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-70308c08e5 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63C9mM"} | None |  |
| q-7cccb2681b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63C9mM"} | None |  |
| q-72309c054a | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMASEsNZ"} | None |  |
| q-c0e619ae7c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2ORrtJ"} | None |  |
| q-27ac2be428 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JLx0p9yU"} | None |  |
| q-df63617382 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JLx4yj34"} | None |  |
| q-f239f1864e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7ViMbT"} | None |  |
| q-cb0cb09061 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7ViMbT"} | None |  |
| q-7ceddc23ae | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None |  |
| q-c3996ef0c2 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAOAxHj"} | None |  |
| q-ab4f02c983 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kqds5"} | None |  |
| q-0aa4199efc | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA6t"} | None |  |
| q-a9bd11c413 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA6t"} | None |  |
| q-cbc42662a4 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA6t"} | None |  |
| q-cb4b0f7bf5 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIK6WOc7y0JMA_NKaA"} | None |  |
| q-9696f36f98 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIK6WOc7y0JMA_NKaA"} | None |  |
| q-752f1d19d6 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA0H"} | None |  |
| q-f1c5696b22 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA0H"} | None |  |
| q-38b068e3ca | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGJw29"} | None |  |
| q-e767ac0a53 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGJw29"} | None |  |
| q-839e4c2486 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIK6WOc7y0JMA_NabS"} | None |  |
| q-96bba66527 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIK6WOc7y0JMA_NabS"} | None |  |
| q-a2f0c60d0d | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGJw3s"} | None |  |
| q-9c9cd76193 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGJw3s"} | None |  |
| q-504225406b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JLx1s9Ic"} | None |  |
| q-067356883f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JLx1s9Ic"} | None |  |
| q-4fd7fd99f9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2LOurf"} | None |  |
| q-d4eff21f79 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2LOurf"} | None |  |
| q-448bfa5eab | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL8_cVAi"} | None |  |
| q-fdf5051c4f | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL8_cVAi"} | None |  |
| q-9472b58999 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA6t"} | None |  |
| q-8ade395068 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA6t"} | None |  |
| q-1f15f3275c | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIK6WOc7y0JMA_NKaA"} | None |  |
| q-0a0a9c0c5c | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIK6WOc7y0JMA_NKaA"} | None |  |
| q-8675c15441 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA0H"} | None |  |
| q-d67dae3a00 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2IKpDz"} | None |  |
| q-4b94ca4f68 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-063e571b39 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None |  |
| q-60e6ce4234 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7am0gN"} | None |  |
| q-ce5e775659 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAWIhac"} | None |  |
| q-fe5cf45b1f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL69HSbI"} | None |  |
| q-fd08e1cdcb | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL8-bHCF"} | None |  |
| q-07ee9e520a | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9MpvNN"} | None |  |
| q-0d131041fb | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL8zTpG-"} | None |  |
| q-f9168e4bd1 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGJw1f"} | None |  |
| q-10a8e3cefe | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9Cfa6G"} | None |  |
| q-1ad5d10d95 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9OrnEj"} | None |  |
| q-a1d5561983 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGJw1d"} | None |  |
| q-a6cdb431af | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9LnloS"} | None |  |
| q-0d22ca2520 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9LnVrY"} | None |  |
| q-ee4e4bd009 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA0i"} | None |  |
| q-f9e3e2811e | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9OrXFP"} | None |  |
| q-d25dea6b95 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL8-bHB-"} | None |  |
| q-fd20854ae3 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGJw1g"} | None |  |
| q-730e05e655 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None |  |
| q-2dd597f60d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-bdc2d176fd | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-30e2164702 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9Jl2tp"} | None |  |
| q-9e007f26a9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2ioON3"} | None |  |
| q-4f0c225837 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2lq7xd"} | None |  |
| q-127c533168 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None |  |
| q-f8faefec9e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2lq7xd"} | None |  |
| q-b8215abcb1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2jpdJE"} | None |  |
| q-b6f16adb2b | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9Jl2tp"} | None |  |
| q-1264562daa | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9OrXFV"} | None |  |
| q-ce4ee5dd29 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGJw17"} | None |  |
| q-b668b9e088 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGJw17"} | None |  |
| q-93c77a378f | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGJw2B"} | None |  |
| q-0d7338fb44 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGJw2G"} | None |  |
| q-0b398570f6 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGJw2G"} | None |  |
| q-2bd68eeb0c | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA5C"} | None |  |
| q-15e47f5bfa | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGJw2z"} | None |  |
| q-6e3edae3ce | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAVHr_u"} | None |  |
| q-7edffa5109 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-a0320c495a | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-142ff3aa52 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-f6cfcf37ff | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CdmD"} | None |  |
| q-c1f2ee2c9b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CdmD"} | None |  |
| q-dded133a3a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CtkV"} | None |  |
| q-bdc485e7e1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CdmN"} | None |  |
| q-90f3d8f8ba | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kqttt"} | None |  |
| q-4ffc7c071d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kqttt"} | None |  |
| q-88664116db | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7am0gN"} | None |  |
| q-bf71928bb1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7VicZa"} | None |  |
| q-7995858c7f | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9FgwRA"} | None |  |
| q-73f633c323 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9FgwRA"} | None |  |
| q-86304c22a7 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-c57f570778 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CdmD"} | None |  |
| q-6f4ac6df4f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63C9mM"} | None |  |
| q-3beb2c09ec | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2ioON3"} | None |  |
| q-6df75d3f87 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQDFlH"} | None |  |
| q-8128ec3f3f | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1lL"} | None |  |
| q-f928c6c7dc | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAWJWsz"} | None |  |
| q-09be0daf5e | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAVH79h"} | None |  |
| q-a10c4fc2fd | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9Qt70r"} | None |  |
| q-e795782fbf | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9MpvMw"} | None |  |
| q-2ff528b755 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL17C4EF"} | None |  |
| q-9cf74f8ad5 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1ns"} | None |  |
| q-fd325bb840 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-8dcb030ae0 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mC"} | None |  |
| q-c3188276d8 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9Qt70r"} | None |  |
| q-21eb7572c1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63C9mZ"} | None |  |
| q-20b54dc06a | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None |  |

## Verification

Evidence items cited: 251; confirmed against the stored events: 251; rejected: 0. Each item was re-fetched with get_event; it is confirmed only if the event exists, the cited field holds the cited value, and the cited query_id is a query of this run that returned that event.
Evidence sent back to the agents for correction during the run: 6 item(s) in 4 submission(s) (one correction round each; what still failed was rejected).

## Limitations

- Findings describe what the stored logs show; activity these sources did not log cannot be seen.
- Datasets with non-overlapping time windows (see Data examined) were analysed separately.
- Long field values are shortened in this report; full events are retrievable by _index/_id.
