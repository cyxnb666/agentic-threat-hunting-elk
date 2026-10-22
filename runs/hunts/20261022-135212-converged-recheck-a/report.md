# Threat hunt report — 20261022-135212-converged-recheck-a

**Hypothesis:** An adversary who compromised Windows hosts in this network stole credentials from them (MITRE ATT&CK tactic: Credential Access).

**Verdict: Confirmed** — 5 in-scope incident(s) of verified malicious findings (confidence >= medium): I01 T1003.001 (F01, F09, F12, F18, F19, F28, F31), I03 T1056.002 (F06), I04 T1187 (F16, F57), I06 T1552.001 (F23, F54, F56), I07 T1649 (F22, F51)

Verdict method: rules over verified evidence (Confirmed if >=1 in-scope incident of verified malicious findings (confidence >= medium); Inconclusive if only suspicious incidents or coverage gaps; Refuted if full coverage and no malicious/suspicious finding)

| Run | Value |
|---|---|
| Profile | converged (thinking=False, temperature=0.0) |
| Model | deepseek-flash |
| Started / finished (UTC) | 2026-10-22T05:52:12+00:00 / 2026-10-22T06:03:01+00:00 (649.4 s) |
| LLM calls / tokens | 150 / {'prompt': 4722126, 'completion': 134347} |
| MCP tool calls | 1214 (server tools: list_data_sources, get_fields, search, count, aggregate, timeline, esql, get_event, get_registry) |
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
| I01 | T1003.001 | yes | malicious/high | F01, F09, F12, F18, F19, F28, F31 | LSASS memory access with full-access rights by hidden PowerShell on SCRANTON (and via WinRM on NASHUA) |
| I02 | T1003.002 | yes | suspicious/medium | F55 | SAM server full-access handle requests on SCRANTON |
| I03 | T1056.002 | yes | malicious/high | F06 | Screen-capture loop writing BMPs to Downloads on SCRANTON |
| I04 | T1187 | yes | malicious/medium | F16, F57 | Forced-authentication artifacts: Folder handler hijack and StartUp hostui.lnk on SCRANTON |
| I05 | T1552 | yes | suspicious/low | F24 | accesschk.exe writing passwordsDB in SysinternalsSuite on SCRANTON |
| I06 | T1552.001 | yes | malicious/high | F23, F54, F56 | Credential-bearing file harvesting, archiving, and plaintext-password lateral use (SCRANTON to NASHUA) |
| I07 | T1649 | yes | malicious/high | F22, F51 | Get-PrivateKeys export of LocalMachine certificate private keys to .pfx on SCRANTON |
| I08 | T1649 | yes | suspicious/low | F52 | Root certificate store Blob modification on NASHUA by Sysmon.exe |
| I09 | out-of-scope:T1070 | no | malicious/medium | F02 | Credential-access tooling staging and anti-forensic cleanup on SCRANTON and NASHUA |

## Findings

### F02 · malicious / medium · T1003 · Credential-access tooling staged on scranton (fake .scr in C:\ProgramData\victim, sdelete64 anti-forensics) alongside the LSASS access

Evidence status: **verified**

On scranton.dmevals.local, user pbeesly executed C:\ProgramData\victim\…cod.3aka3.scr (launched by explorer.exe with /S) at 02:55:56, then enumerated the folder with 'gci C:\programdata\victim\' and deleted the file with Sysinternals sdelete64.exe at 03:02:04; further sdelete64 runs wiped Draft.Zip and SysinternalsSuite.zip. On nashua.dmevals.local the same pattern continued with C:\Windows\Temp\sdelete64.exe deleting Rar.exe and working.zip. This staging/cleanup activity brackets the LSASS memory access at 03:05:16 and shows deliberate artifact removal, consistent with a credential-theft operation. No SAM/SECURITY hive export, ntds.dit copy, or DCSync command line was observed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:55:56.157Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\ProgramData\victim\â€®cod.3aka3.scr" /S | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBow1KRR | q-37563fc203 | ok |
| 2 | 2020-05-02 03:02:04.324Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\sdelete64.exe" /accepteula C:\programdata\victim\???cod.3aka3.scr | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoSVqPo | q-37563fc203 | ok |
| 3 | 2020-05-02 03:01:51.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | gci C:\programdata\victim\ | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByRaboC | q-e3acce2504 | ok |
| 4 | 2020-05-02 03:16:52.000Z | nashua.dmevals.local | windows.security | process.command_line | .\sdelete64.exe  /accepteula "C:\Windows\Temp\Rar.exe" | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBukwKVF | q-4dc4d34b31 | ok |

### F01 · malicious / high · T1003.001 · PowerShell (pbeesly, high integrity) opened lsass.exe with full access and read its process memory on scranton.dmevals.local

Evidence status: **verified**

On scranton.dmevals.local at 2020-05-02T03:05:16, a PowerShell.exe process (PID 2976, user DMEVALS\pbeesly, LogonId 0x372E81) opened a handle to lsass.exe (PID 736) with GrantedAccess 0x1F3FFF and 0x1FFFFF (PROCESS_ALL_ACCESS) and then performed a 0x10 'Read from process memory' access on \Device\HarddiskVolume2\Windows\System32\lsass.exe (handle 0xcb4). This is the classic LSASS memory-dump access pattern. It is part of a broader intrusion on the same host: the same PowerShell session was launched from a hidden, execution-policy-bypass PowerShell that decoded a payload from C:\Users\pbeesly\Downloads\monkey.png, and the host also ran C:\ProgramData\victim\…cod.3aka3.scr and Sysinternals sdelete64.exe to wipe artifacts. A second, similar 0x1F3FFF lsass access came from wsmprovhost.exe (PowerShell Remoting) on nashua.dmevals.local at 03:09:29 under pbeesly, indicating the same tooling was used remotely. Benign lsass accessors in the same window (svchost.exe 0x1000, WindowsAzureTelemetryService.exe/AntimalwareConfig.exe 0x1400, CollectGuestLogs.exe 0x1410) are Azure guest-agent telemetry and were excluded.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoMQUXI | q-27bb341b1e | ok |
| 2 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoMQUXF | q-844adb9ad8 | ok |
| 3 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | win.ObjectName | \Device\HarddiskVolume2\Windows\System32\lsass.exe | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBy4FbI2 | q-bde202437f | ok |
| 4 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | win.AccessMask | 0x10 | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBy4FbI2 | q-bde202437f | ok |
| 5 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBn663fz | q-6e8791fb1e | ok |
| 6 | 2020-05-02 03:05:24.771Z | scranton.dmevals.local | windows.sysmon | win.ParentCommandLine | "PowerShell.exe" -noni -noexit -ep bypass -window hidden -c "sal a New-Object;Add-Type -AssemblyName 'System.Drawing'; $g=a System.Drawing.Bitmap('C:\Users\pbee… | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoMQUUD | q-18af10a154 | ok |

### F05 · malicious / high · T1056 · PowerShell opens full-access handles to lsass.exe on scranton (credential theft via process access)

Evidence status: **NOT verified (5/6 evidence items)** — excluded from the verdict

On scranton.dmevals.local, PowerShell.exe (PID 2976, running as SYSTEM, entity {47ab858c-e1e4-5eac-b803-000000000400}) requested lsass.exe (PID 736) with GrantedAccess 0x1F3FFF at 03:05:16.623Z and 0x1FFFFF at 03:05:16.654Z. Both call traces end in UNKNOWN(...) frames rather than a signed Windows DLL path, the classic signature of an in-memory credential-dumping routine rather than legitimate lsass access. This is the only non-system process in the dataset that requested full lsass access; all other lsass accessors were svchost.exe, wininit.exe, csrss.exe, services.exe, Defender and Azure agents. It sits inside a broader intrusion chain on scranton by user pbeesly: a hidden, encoded PowerShell launched from control.exe (02:58:44Z) that decodes a payload from C:\Users\pbeesly\Downloads\monkey.png, download of SysinternalsSuite.zip (02:59:42Z), and a later hidden encoded PowerShell spawned from a registry-stored 'Javasoft' value via hostui.exe runas (03:21:28Z).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoMQUXI | q-0444bba3ef | ok |
| 2 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.CallTrace | C:\windows\SYSTEM32\ntdll.dll+9c584\|C:\windows\System32\KERNELBASE.dll+2732e\|UNKNOWN(000001996D28200D) | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoMQUXI | q-0444bba3ef | ok |
| 3 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoMQUXF | q-c7604c3837 | ok |
| 4 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.TargetImage | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoMQUXF | q-c7604c3837 | ok |
| 5 | 2020-05-02 03:05:24.771Z | scranton.dmevals.local | windows.sysmon | win.ParentCommandLine | "PowerShell.exe" -noni -noexit -ep bypass -window hidden -c "sal a New-Object;Add-Type -AssemblyName 'System.Drawing'; $g=a System.Drawing.Bitmap('C:\Users\pbee… | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoMQUUD | q-b2bf4e2929 | ok |
| 6 |  | None | None | process.command_line | powershell.exe  -c "Start-Process C:\Windows\System32\hostui.exe -verb runas" | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBi85SQC | q-13422ff22a | FAILED: cited query did not return this event; event not found |

### F06 · malicious / high · T1056.001 · PowerShell screen-capture loop (Invoke-ScreenCapture) writing BMPs to Downloads on scranton

Evidence status: **verified**

On scranton.dmevals.local, user pbeesly, PowerShell script blocks implementing 'function Invoke-ScreenCapture' were logged (4104, ScriptBlock ID b91c2ae7-3a03-49df-8d2a-4c42fc79df56, path C:\Program Files\SysinternalsSuite\psversion.ps1, plus a second block 0365cb7f-22ef-47e4-ad96-230ddc962939). The code starts a background job that loops forever, uses System.Windows.Forms.SystemInformation::VirtualScreen and Graphics.CopyFromScreen to grab the full desktop, saves it to $env:USERPROFILE\Downloads\<random>.bmp and sleeps 300 seconds. This is repeated visual input capture of the user's session (screenshots of whatever is on screen, including credential prompts). It is corroborated by a file-creation event for C:\Users\pbeesly\Downloads\gwq4xdwv.s5g.bmp written by powershell.exe at 03:06:00Z. No GetAsyncKeyState/SetWindowsHookEx keylogger API was found in script blocks, so the capture is screen-based rather than keystroke-based.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:53.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-ScreenCapture # https://www.pdq.com/blog/capturing-screenshots-with-powershell-and-net/ {     Start-Job -Name "Screenshot" -ScriptBlock {       … | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByRabqD | q-406307317f | ok |
| 2 | 2020-05-02 03:05:53.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\psversion.ps1 | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByRabqD | q-406307317f | ok |
| 3 | 2020-05-02 03:05:59.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText |           Write-Host "`nJobPID`n------`n$PID"         while($true){             $RandomFileName = [System.IO.Path]::GetRandomFileName();              $Filepath=… | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByRZ7r5 | q-e488a87b0f | ok |
| 4 | 2020-05-02 03:06:00.421Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Users\pbeesly\Downloads\gwq4xdwv.s5g.bmp | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoHL6FX | q-22fa19a764 | ok |

### F09 · malicious / medium · T1056.004 · lsass access from PowerShell with UNKNOWN call trace (API-hooking-style credential access) on scranton and nashua

Evidence status: **verified**

Two hosts show non-standard processes opening lsass.exe with near-full access: on scranton.dmevals.local PowerShell.exe (PID 2976, SYSTEM) used 0x1F3FFF and 0x1FFFFF with call traces ending in UNKNOWN(000001996D252982)/UNKNOWN(000001996D28200D) — memory not backed by a known module, consistent with a manually mapped/reflective payload calling credential APIs; on nashua.dmevals.local wsmprovhost.exe (PID 7720, SYSTEM, i.e. a remote PowerShell/WinRM session) opened lsass with 0x1F3FFF, its trace running through PowerShell management native images into UNKNOWN(00007FFA...) frames. No MiniDump script block and no lsass service/image-path events were found, so the dump mechanism itself is not directly visible; the assessment rests on the access masks and anomalous call traces. All other lsass accessors (svchost.exe 289, AntimalwareConfig.exe 15, WindowsAzureTelemetryService.exe 13, wininit/csrss/services) are legitimate system/agent behaviour.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.CallTrace | C:\windows\SYSTEM32\ntdll.dll+9c584\|C:\windows\System32\KERNELBASE.dll+2732e\|UNKNOWN(000001996D252982) | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoMQUXF | q-c7604c3837 | ok |
| 2 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoMQUXI | q-0444bba3ef | ok |
| 3 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBn663fz | q-41e1e1d263 | ok |
| 4 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBn663fz | q-41e1e1d263 | ok |

### F12 · malicious / high · T1110.002 · LSASS memory accessed with full rights by hidden PowerShell (credential theft, not offline cracking)

Evidence status: **verified**

On scranton.dmevals.local, PID 2976 (powershell.exe, user DMEVALS\pbeesly, High integrity) was spawned by control.exe '/name Microsoft.BackupAndRestoreCenter' (sdclt UAC-bypass chain) with '-noni -noexit -ep bypass -window hidden' and a System.Drawing bitmap-decoded IEX stager; its 4104 script block then defines VirtualAlloc/CreateThread and a large shellcode byte array. At 03:05:16Z that same PID opened lsass.exe with GrantedAccess 0x1f3fff and 0x1fffff (PROCESS_ALL_ACCESS) with an UNKNOWN call trace — classic in-memory credential dumping. The 10 SAM 4656 handle events are all lsass.exe itself (SCRANTON$, AccessMask 0xf003f) and are benign; no reg save/NTDS.dit/Mimikatz script text was found. No offline cracking tooling was observed, so the cracking sub-technique itself is not evidenced — the theft precursor is.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoMQUXI | q-17f077b209 | ok |
| 2 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoMQUXF | q-17f077b209 | ok |
| 3 | 2020-05-02 02:58:44.325Z | scranton.dmevals.local | windows.sysmon | process.command_line | "PowerShell.exe" -noni -noexit -ep bypass -window hidden -c "sal a New-Object;Add-Type -AssemblyName 'System.Drawing'; $g=a System.Drawing.Bitmap('C:\Users\pbee… | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBorwtwa | q-d73f99347f | ok |
| 4 | 2020-05-02 02:58:45.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | $cFIrwwpZzGzU = @"  [DllImport("kernel32.dll")]  public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);… | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByYfl1_ | q-66f48b3738 | ok |
| 5 | 2020-05-02 03:19:21.000Z | scranton.dmevals.local | windows.security | process.executable | C:\Windows\System32\lsass.exe | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBudp5HI | q-3a7e0d47a3 | ok |

### F16 · malicious / medium · T1187 · Forced-authentication artifacts (Folder\shell\open\command hijack + StartUp hostui.lnk) planted by PowerShell on scranton.dmevals.local

Evidence status: **verified**

On scranton.dmevals.local, user pbeesly ran an interactive PowerShell session (PID 3876/6868) that at 02:57:18 created HKCU\Software\Classes\Folder\shell\open\command and at 02:58:18 set its (Default) value to a hidden, execution-policy-bypassing PowerShell one-liner that decodes a payload from C:\Users\pbeesly\Downloads\monkey.png and IEXes it, plus a DelegateExecute value at 02:58:30. This is the classic T1187 'Folder' handler hijack: any user or process that opens a folder triggers the attacker command, which can be used to force authentication/credential capture. At 03:04:23 the same PowerShell wrote C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\hostui.lnk (Invoke-Persistence -PersistStep 2), a shortcut in the all-users StartUp folder that executes on logon. The session also ran credential-access style functions (Get-PrivateKeys exporting certs to .pfx, Get-Clipboard, keystroke/AV checks) and anti-forensics (sdelete64). The hijack keys were removed at 02:59:15 (Remove-Item HKCU:\Software\Classes\Folder* -Recurse -Force), but the StartUp shortcut remained. Supporting context: a single NTLM network logon (4624 type 3, NtLmSsp, pbeesly, from 172.18.39.2) on scranton at 03:20:41 and LsaSrv event 6038 reporting NTLM use on the same host at 03:20:41. No WebDAV/searchConnector artifacts or attacker-controlled SMB server were observed; the forced-auth mechanism here is the local shell-handler/shortcut hijack rather than a remote UNC/WebDAV path.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:58:18.576Z | scranton.dmevals.local | windows.sysmon | win.Details | powershell.exe -noni -noexit -ep bypass -window hidden -c "sal a New-Object;Add-Type -AssemblyName 'System.Drawing'; $g=a System.Drawing.Bitmap('C:\Users\pbeesl… | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBosxeSr | q-a07f0b02a1 | ok |
| 2 | 2020-05-02 02:58:18.576Z | scranton.dmevals.local | windows.sysmon | registry.path | HKU\S-1-5-21-1830255721-3727074217-2423397540-1107_Classes\Folder\shell\open\command\(Default) | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBosxeSr | q-a07f0b02a1 | ok |
| 3 | 2020-05-02 03:04:23.681Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\hostui.lnk | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoOSXoo | q-23dc754f83 | ok |
| 4 | 2020-05-02 03:04:23.681Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\WindowsPowerShell\v1.0\powershell.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoOSXoo | q-23dc754f83 | ok |
| 5 | 2020-05-02 03:04:15.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | Invoke-Persistence -PersistStep 1 | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByRaboN | q-9c976dcd3c | ok |
| 6 | 2020-05-02 03:04:23.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | Invoke-Persistence -PersistStep 2 | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByRarq9 | q-0baaa9fdd8 | ok |
| 7 | 2020-05-02 02:58:07.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | Set-ItemProperty -Path "HKCU:\Software\Classes\Folder\shell\open\command" -Name "(Default)" | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByYf107 | q-7f119c6028 | ok |
| 8 | 2020-05-02 02:59:15.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | Remove-Item -Path HKCU:\Software\Classes\Folder* -Recurse -Force | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByYfl2t | q-7f119c6028 | ok |
| 9 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByRaLqc | q-0baaa9fdd8 | ok |
| 10 | 2020-05-02 03:20:41.000Z | scranton.dmevals.local | windows.security | win.AuthenticationPackageName | NTLM | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBufr2mI | q-f319480d1f | ok |
| 11 | 2020-05-02 03:20:41.000Z | scranton.dmevals.local | windows.other | event.code | 6038 | .ds-logs-windows.other-default-2026.10.22-000001 / AaFiKJc9VXKkeBwdMB0m | q-eb10e5ff08 | ok |

### F57 · malicious / medium · T1187 · hostui.exe launched by PowerShell on SCRANTON (binary abused by the anchored StartUp hostui.lnk)

Evidence status: **verified**

On scranton.dmevals.local, powershell.exe (pbeesly) launched C:\Windows\System32\hostui.exe at 03:21:27Z. hostui.exe is the binary referenced by the already-anchored StartUp hostui.lnk forced-authentication artifact, and a process-access event shows hostui.exe opening C:\windows\Explorer.EXE with 0x1400. Execution of this abused system binary by the attacker's PowerShell is new relative to the anchors.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:21:27.276Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Windows\System32\hostui.exe"  | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBi30hQJ | q-2d40d7195e | ok |
| 2 | 2020-05-02 02:55:56.136Z | scranton.dmevals.local | windows.sysmon | win.SourceImage | C:\Windows\System32\smartscreen.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBow1KRZ | q-989d5f64d9 | ok |

### F18 · malicious / high · T1212 · Hidden PowerShell stager (control.exe parent) opened lsass.exe with full access on SCRANTON — credential dumping via process access

Evidence status: **verified**

On scranton.dmevals.local at 2020-05-02T02:58:44Z, control.exe ("/name Microsoft.BackupAndRestoreCenter") spawned powershell.exe PID 2976 running as DMEVALS\pbeesly at High integrity with the flags -noni -noexit -ep bypass -window hidden, decoding a payload from a bitmap (C:\Users\pbeesly\Downloads\monkey.png) and IEX-ing it. At 03:05:16Z that same PowerShell process (PID 2976, entity {47ab858c-e1e4-5eac-b803-000000000400}) opened lsass.exe (PID 736) twice with GrantedAccess 0x1F3FFF and 0x1FFFFF — full-access handles consistent with in-memory credential dumping (MiniDumpWriteDump-style read of LSASS). The CallTrace shows ntdll/KERNELBASE plus an UNKNOWN module, i.e. code not backed by a known on-disk DLL. This is the strongest T1212 signal in the dataset: an adversary-controlled PowerShell session exploiting its high-integrity token to read LSASS memory. The same session later ran Invoke-Exfil (7-Zip of Downloads to \\192.168.0.4\webdav with hardcoded creds cozy/MyCozyPassw0rd!) and Invoke-SeaDukeStage -ComputerName NASHUA, and pbeesly Kerberos TGT/TGS requests (4768/4769, RC4 0x12) were issued from 10.0.1.4 to the DC newyork.dmevals.local, consistent with use of harvested credentials.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoMQUXI | q-f051f2f350 | ok |
| 2 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoMQUXI | q-f051f2f350 | ok |
| 3 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoMQUXF | q-f051f2f350 | ok |
| 4 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.CallTrace | C:\windows\SYSTEM32\ntdll.dll+9c584\|C:\windows\System32\KERNELBASE.dll+2732e\|UNKNOWN(000001996D252982) | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoMQUXF | q-01c2e5bc86 | ok |
| 5 | 2020-05-02 02:58:44.325Z | scranton.dmevals.local | windows.sysmon | process.command_line | "PowerShell.exe" -noni -noexit -ep bypass -window hidden -c "sal a New-Object;Add-Type -AssemblyName 'System.Drawing'; $g=a System.Drawing.Bitmap('C:\Users\pbee… | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBorwtwa | q-a0db64da50 | ok |
| 6 | 2020-05-02 02:58:44.325Z | scranton.dmevals.local | windows.sysmon | process.parent.executable | C:\Windows\System32\control.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBorwtwa | q-a0db64da50 | ok |
| 7 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByPYrDh | q-b8821fe065 | ok |
| 8 | 2020-05-02 03:20:45.000Z | newyork.dmevals.local | windows.security | win.TargetUserName | pbeesly | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBuTlU_I | q-327e38cc8b | ok |

### F23 · malicious / high · T1552.001 · Credential-bearing file collection and plaintext password use from scranton to nashua

Evidence status: **verified**

The same pbeesly PowerShell session on scranton.dmevals.local (02:56-03:15 UTC on 2020-05-02) staged credential-bearing files: at 02:56:17 it enumerated the user profile for *psw*, *pass*, *login*, *admin*, *sifr*, *sifer*, *vpn* files and compressed them with Compress-Archive; at 03:08:02 Invoke-Exfil compressed the whole Downloads directory (which contained the harvested .pfx) into $env:APPDATA\OfficeSupplies.7z with password "lolol" and copied it to a WebDAV share using hardcoded credentials cozy/MyCozyPassw0rd!. The harvested credentials were then used: PsExec64.exe was launched four times (03:11:18, 03:12:25, 03:13:28, 03:14:42) with the cleartext password -p Fl0nk3rt0n!T0by for dmevals\pbeesly against \\NASHUA, and each time C:\Windows\Temp\python.exe spawned on nashua.dmevals.local under PSEXESVC.exe. The nuget.config file created at 03:08:31 is a side effect of the Install-Module 7Zip4Powershell call inside Invoke-Exfil, not credential theft.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByPYrDh | q-9b3e36e9fb | ok |
| 2 | 2020-05-02 03:11:18.784Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\PsExec64.exe" -accepteula \\NASHUA -u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoz4z4i | q-019ae56e5e | ok |
| 3 | 2020-05-02 03:11:40.213Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoz4j7h | q-019ae56e5e | ok |
| 4 | 2020-05-02 03:11:40.213Z | nashua.dmevals.local | windows.sysmon | process.parent.executable | C:\Windows\PSEXESVC.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoz4j7h | q-019ae56e5e | ok |
| 5 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\psversion.ps1 | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByPYrDh | q-9b3e36e9fb | ok |
| 6 | 2020-05-02 03:08:31.192Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Users\pbeesly\AppData\Roaming\NuGet\nuget.config | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBn78FjI | q-f6ac99eeb2 | ok |

### F54 · malicious / high · T1552.001 · PowerShell on NASHUA harvested credential-named files from the user profile and archived them into working.zip

Evidence status: **verified**

On nashua.dmevals.local, in the pbeesly session (PowerShell PID 4876, script block 4adf51bc-704e-4481-8e1f-d7af5cc7acaa at 2020-05-02T03:15:59Z), a script enumerated the whole user profile for credential-bearing file types (*psw*, *pass*, *login*, *admin*, *sifr*, *sifer*, *vpn, *.pst, *.ost, *.txt, *.lnk, *.zip, *.rar) and compressed the results into %APPDATA%\working.zip. Seconds later the operator cd'd to C:\Windows\Temp and ran Rar.exe with a password (-hpfGzq5yKw) to produce C:\Users\pbeesly\Desktop\working.zip from the APPDATA archive, then wiped Rar.exe and both zips with sdelete64. This is credential-file collection and staging on the second host, distinct from the scranton anchors.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:15:59.000Z | nashua.dmevals.local | windows.powershell | win.ScriptBlockText | $env:APPDATA;$files=ChildItem -Path $env:USERPROFILE\ -Include *.doc,*.xps,*.xls,*.ppt,*.pps,*.wps,*.wpd,*.ods,*.odt,*.lwp,*.jtd,*.pdf,*.zip,*.rar,*.docx,*.url,… | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByDVjze | q-0520247262 | ok |
| 2 | 2020-05-02 03:16:19.000Z | nashua.dmevals.local | windows.powershell | win.ScriptBlockText | .\Rar.exe a -hpfGzq5yKw "$env:USERPROFILE\Desktop\working.zip" "$env:APPDATA\working.zip" | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByCVMj0 | q-a078ecb4e6 | ok |
| 3 | 2020-05-02 03:16:19.395Z | nashua.dmevals.local | windows.sysmon | process.command_line | "C:\Windows\Temp\Rar.exe" a -hpfGzq5yKw C:\Users\pbeesly\Desktop\working.zip C:\Users\pbeesly\AppData\Roaming\working.zip | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBow1qSj | q-2d40d7195e | ok |
| 4 | 2020-05-02 03:16:52.456Z | nashua.dmevals.local | windows.sysmon | process.command_line | .\sdelete64.exe  /accepteula "C:\Windows\Temp\Rar.exe" | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBnnmUud | q-2d40d7195e | ok |

### F56 · malicious / high · T1552.001 · Plaintext domain password used with PsExec64 to reach NASHUA, accesschk run, and sdelete64 wiping the tooling on SCRANTON

Evidence status: **verified**

On scranton.dmevals.local, powershell.exe (pbeesly) downloaded SysinternalsSuite.zip at 02:59:42Z, extracted it, and ran accessChk.exe at 03:04:34Z, then PsExec64.exe four times (03:11:18Z, 03:12:25Z, 03:13:28Z, 03:14:42Z) with the plaintext domain password Fl0nk3rt0n!T0by to launch C:\Windows\Temp\python.exe on NASHUA, and sdelete64.exe three times (03:02:04Z, 03:03:14Z, 03:03:33Z) to wipe the fake .scr, Draft.Zip and the SysinternalsSuite archive. The plaintext credential use and the tooling cleanup are new relative to the anchors.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:18.784Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\PsExec64.exe" -accepteula \\NASHUA -u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoz4z4i | q-2d40d7195e | ok |
| 2 | 2020-05-02 03:04:34.951Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\accesschk.exe" | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoNRGHW | q-2d40d7195e | ok |
| 3 | 2020-05-02 03:02:04.324Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\sdelete64.exe" /accepteula C:\programdata\victim\???cod.3aka3.scr | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoSVqPo | q-2d40d7195e | ok |

### F22 · malicious / high · T1552.004 · Get-PrivateKeys exports all LocalMachine certificates to .pfx files on scranton

Evidence status: **verified**

On 2020-05-02 at 03:04:56 UTC, in a PowerShell session running as DMEVALS\pbeesly on scranton.dmevals.local, the attacker loaded a script file (readme.txt renamed to readme.ps1 in C:\Program Files\SysinternalsSuite) and executed the function Get-PrivateKeys. The function enumerates cert:\LocalMachine recursively and calls Export-PfxCertificate for every certificate with a thumbprint, writing each to $env:USERPROFILE\Downloads\<random>.pfx protected by the hardcoded password "saribas". One second later Sysmon recorded the resulting file C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx created by powershell.exe. The same session later defined Invoke-BeachCleanup which deletes $env:USERPROFILE\Downloads\*.pfx, confirming deliberate private-key harvesting followed by anti-forensic cleanup.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByRaLqc | q-3a2db39970 | ok |
| 2 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\readme.ps1 | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByRaLqc | q-3a2db39970 | ok |
| 3 | 2020-05-02 03:04:57.460Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoMQkXH | q-f8e629725a | ok |
| 4 | 2020-05-02 03:04:57.460Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\WindowsPowerShell\v1.0\powershell.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoMQkXH | q-f8e629725a | ok |
| 5 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | user.name | pbeesly | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByRaLqc | q-3a2db39970 | ok |

### F28 · malicious / high · T1555 · Interactive PowerShell session on SCRANTON opened LSASS with full-access rights (0x1FFFFF / 0x1F3FFF) during a hands-on-keyboard intrusion

Evidence status: **verified**

On scranton.dmevals.local, user pbeesly ran an interactive PowerShell session (PID 2976) that, at 2020-05-02T03:05:16Z, opened lsass.exe (PID 736) twice with GrantedAccess 0x1F3FFF and 0x1FFFFF — PROCESS_ALL_ACCESS-class masks consistent with in-memory credential theft. The same access is corroborated by Security 4663 object-access on \Device\HarddiskVolume2\Windows\System32\lsass.exe by C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe under pbeesly at 23:05:16 local. This occurred inside a broader intrusion chain on the same host: registry Folder\shell\open\command hijack, shellcode loader via Add-Type/VirtualAlloc, a PNG-steganography IEX payload, SysinternalsSuite staging, Invoke-Discovery, Invoke-Persistence, Get-PrivateKeys (certificate export), sdelete64 anti-forensics, and Invoke-Exfil to a WebDAV share at \\192.168.0.4\webdav. A second high-privilege LSASS access (0x1F3FFF) came from wsmprovhost.exe (PID 7720) on nashua.dmevals.local at 03:09:29Z, immediately after pbeesly ran 'Get-Process -IncludeUserName' there, indicating remote PowerShell credential access on a second host. The remaining LSASS accesses (svchost 0x1000/0x1400/0x101001/0x3000, wininit/csrss 0x1fffff, CollectGuestLogs, MsMpEng) are normal system/AV behaviour.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoMQUXI | q-4e24274fdf | ok |
| 2 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoMQUXI | q-4e24274fdf | ok |
| 3 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoMQUXF | q-3493f157d5 | ok |
| 4 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBn663fz | q-194675c2fd | ok |
| 5 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | win.ProcessName | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBy4FbI2 | q-2d4abd583a | ok |
| 6 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | win.SubjectUserName | pbeesly | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBy4FbI2 | q-2d4abd583a | ok |
| 7 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByRaLqc | q-2684c9afe5 | ok |
| 8 | 2020-05-02 03:09:28.000Z | nashua.dmevals.local | windows.powershell | win.ScriptBlockText |  Get-Process -IncludeUserName \| Select-Object UserName,SessionId \| Where-Object { $_.UserName -like "*\$env:USERNAME" } \| Sort-Object SessionId -Unique  | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByCVtlI | q-f67b5d1176 | ok |

### F51 · malicious / high · T1649 · PowerShell Get-PrivateKeys exported all LocalMachine certificate private keys to password-protected .pfx on SCRANTON, then deleted them

Evidence status: **verified**

On scranton.dmevals.local, in the context of user pbeesly (S-1-5-21-1830255721-3727074217-2423397540-1107), a PowerShell script block named Get-PrivateKeys was created at 2020-05-01T23:04:56-04:00 (script block 9d153741-75c3-4062-afe3-aeca0aee611b, recorded with Path C:\Program Files\SysinternalsSuite\readme.ps1). The function enumerates cert:\LocalMachine recursively and calls Export-PfxCertificate for every certificate with a thumbprint, writing to $env:USERPROFILE\Downloads\<random>.pfx protected by the hardcoded password "saribas". One second later (23:04:57) Sysmon recorded powershell.exe (PID 3876) creating C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx, confirming the export actually executed. At 23:08:51 a second script block, Invoke-BeachCleanup (Path C:\Program Files\SysinternalsSuite\psversion.ps1), was created that removes $env:USERPROFILE\Downloads\*.pfx, *.bmp, *.png and $env:APPDATA\OfficeSupplies.7z, and Sysmon event 23 shows the same pfx file being deleted at 23:08:51.489 — i.e. the stolen certificate bundle was staged and then wiped for anti-forensics. This is certificate/private-key theft (T1649) on a host where the same user also ran a suspicious .scr from C:\ProgramData\victim, sdclt.exe, and a hidden -ep bypass PowerShell stager. No PKINIT (PreAuthType 2 only) or forged-certificate use was observed in the 4768 events, so the theft is confirmed but downstream certificate-based authentication abuse is not.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByRaLqc | q-3fcd20b8e2 | ok |
| 2 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\readme.ps1 | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByRaLqc | q-3fcd20b8e2 | ok |
| 3 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | user.name | pbeesly | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByRaLqc | q-3fcd20b8e2 | ok |
| 4 | 2020-05-02 03:04:57.460Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoMQkXH | q-823aa968c1 | ok |
| 5 | 2020-05-02 03:04:57.460Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\WindowsPowerShell\v1.0\powershell.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoMQkXH | q-823aa968c1 | ok |
| 6 | 2020-05-02 03:08:51.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-BeachCleanup {     Write-Host "[*] Cleaning up"     Remove-Item -Path "$env:USERPROFILE\Downloads\*.pfx" -Force     Remove-Item -Path "$env:USER… | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByCVdnF | q-51a1832531 | ok |
| 7 | 2020-05-02 03:08:51.489Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBn77ViM | q-477f5b261a | ok |
| 8 | 2020-05-02 03:08:51.489Z | scranton.dmevals.local | windows.sysmon | event.code | 23 | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBn77ViM | q-477f5b261a | ok |

### F55 · suspicious / medium · T1003.002 · Full-access handle to the SAM server (SAM_SERVER, 0xF003F) requested on SCRANTON during the intrusion

Evidence status: **verified**

On scranton.dmevals.local, ten 4656 events between 03:19:21Z and 03:20:46Z record handles requested on the Security Account Manager object 'SAM' (ObjectType SAM_SERVER) with AccessMask 0xf003f (DELETE, READ_CONTROL, WRITE_DAC, WRITE_OWNER, ConnectToServer, ShutdownServer, InitializeServer, CreateDomain, EnumerateDomains, LookupDomain). The requesting process is lsass.exe under SYSTEM (logon 0x3e7), which is the normal broker for SAM access, so this is not by itself proof of dumping; however it coincides with the LSASS memory access and sdelete anti-forensics already anchored on this host and is the SAM-hive access pattern that accompanies credential dumping. No SAM/SECURITY hive file copy or save was observed in the retrieved events.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:21.000Z | scranton.dmevals.local | windows.security | win.AccessMask | 0xf003f | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBudp5HI | q-c2b284e3b2 | ok |
| 2 | 2020-05-02 03:19:21.000Z | scranton.dmevals.local | windows.security | win.ObjectName | SAM | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBudp5HI | q-c2b284e3b2 | ok |
| 3 | 2020-05-02 03:19:21.000Z | scranton.dmevals.local | windows.security | win.ObjectType | SAM_SERVER | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBudp5HI | q-c2b284e3b2 | ok |
| 4 | 2020-05-02 03:19:21.000Z | scranton.dmevals.local | windows.security | @timestamp | 2020-05-01T23:19:21.000-04:00 | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBudp5HI | q-c2b284e3b2 | ok |

### F07 · suspicious / low · T1056.002 · consent.exe UAC prompt executions on the compromised hosts

Evidence status: **NOT verified (0/2 evidence items)** — excluded from the verdict

Three process-creation events for C:\Windows\System32\consent.exe were returned by both the Sysmon (event.code 1) and Security (4688) stacks, i.e. UAC elevation prompts were displayed. On scranton this fits the intrusion chain: pbeesly ran 'powershell.exe -c "Start-Process C:\Windows\System32\hostui.exe -verb runas"' from cmd.exe /c hostui.bat at 03:21:19Z, which would raise a consent prompt, and hostui.exe then spawned a hidden encoded PowerShell that read and Invoke-Expression'd a value from HKLM:\SOFTWARE\Javasoft. However, I did not retrieve the individual consent.exe events, so I cannot attribute each prompt to a specific parent process or confirm a fake/credential-harvesting prompt; consent.exe is also the legitimate Windows UAC broker. Treated as suspicious-but-unconfirmed GUI prompt activity rather than a confirmed fake credential dialog.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 |  | None | None | process.command_line | powershell.exe  -c "Start-Process C:\Windows\System32\hostui.exe -verb runas" | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBi85SQC | q-13422ff22a | FAILED: cited query did not return this event; event not found |
| 2 |  | None | None | process.command_line | powershell.exe -c "Get-ItemPropertyValue 'HKLM:\\SOFTWARE\Javasoft' 'value Supplement' \| Invoke-Expression" | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBizx7td | q-13422ff22a | FAILED: cited query did not return this event; event not found |

### F19 · suspicious / medium · T1212 · wsmprovhost.exe (PowerShell remoting) opened lsass.exe with 0x1F3FFF on NASHUA during pbeesly remote session

Evidence status: **verified**

On nashua.dmevals.local at 2020-05-02T03:09:29Z, wsmprovhost.exe PID 7720 (the WinRM/PowerShell remoting host) opened lsass.exe PID 728 with GrantedAccess 0x1F3FFF. The CallTrace is dominated by System.ni.dll and Microsoft.PowerShell.Commands.Management.ni.dll frames, i.e. the access came from a PowerShell cmdlet running inside the remoting session rather than from a native dumper. This coincides with pbeesly's remote PowerShell activity from SCRANTON (Invoke-Command -ComputerName NASHUA at 03:09:23Z and Invoke-SeaDukeStage -ComputerName NASHUA at 03:10:22Z), so it is part of the same intrusion chain and is a plausible attempt to read LSASS credentials on the second host; however the call stack is consistent with a legitimate PowerShell management cmdlet, so I rate it suspicious rather than confirmed dumping.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBn663fz | q-f051f2f350 | ok |
| 2 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBn663fz | q-f051f2f350 | ok |
| 3 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.CallTrace | C:\windows\SYSTEM32\ntdll.dll+9c584\|C:\windows\System32\KERNELBASE.dll+2732e\|C:\windows\assembly\NativeImages_v4.0.30319_64\System\9803982d7bc887e2745bff18a43… | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBn663fz | q-40c1bdb09d | ok |
| 4 | 2020-05-02 03:10:22.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | Invoke-SeaDukeStage -ComputerName NASHUA | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByDV_QB | q-6732c9cb62 | ok |

### F24 · suspicious / low · T1552 · accesschk.exe writing passwordsDB in SysinternalsSuite directory

Evidence status: **verified**

At 03:04:35 UTC on scranton.dmevals.local, accesschk.exe (launched by pbeesly's PowerShell at 03:04:34) created the file C:\Program Files\SysinternalsSuite\passwordsDB. This occurred inside the same malicious session that harvested certificates and exfiltrated data, but the file name matches the SysinternalsSuite archive contents and no content of the file was observed, so it cannot be confirmed as a credential store. The other T1552 hits (Credential Guard config event, CredentialEnrollmentManagerUserSvc registry writes, Winlogon PasswordExpiryNotification values, MSFT_ScriptResourceStrings.psd1 script blocks) are normal Windows behaviour.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:35.069Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Program Files\SysinternalsSuite\passwordsDB | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoNRGHl | q-897925fc91 | ok |
| 2 | 2020-05-02 03:04:35.069Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\Program Files\SysinternalsSuite\accesschk.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoNRGHl | q-897925fc91 | ok |
| 3 | 2020-05-02 03:04:34.951Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\accesschk.exe" | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoNRGHW | q-ea7d2db17a | ok |

### F31 · suspicious / medium · T1556 · PowerShell.exe opened lsass.exe with full-access masks (0x1F3FFF / 0x1FFFFF) on scranton.dmevals.local

Evidence status: **verified**

On 2020-05-02 at 03:05:16, PowerShell.exe (PID 2976, entity {47ab858c-e1e4-5eac-b803-000000000400}) on scranton.dmevals.local opened lsass.exe (PID 736) twice with GrantedAccess 0x1F3FFF and 0x1FFFFF; the call trace ends in an UNKNOWN module frame (UNKNOWN(000001996D252982) / UNKNOWN(000001996D28200D)) rather than a known Windows DLL, consistent with in-memory code touching the authentication process. This is the same PowerShell session (user pbeesly) that minutes later ran Get-Keystrokes and Invoke-Exfil, so the lsass handle belongs to the same hands-on-keyboard intrusion. No evidence of persistent authentication-process modification (no password filter / Notification Packages / Security Packages registry writes, no lsass DLL loads other than lsass.exe itself, no 4657/4739/5136 events) was found, so this is treated as suspicious credential-access behaviour rather than confirmed T1556 tampering.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoMQUXI | q-26390e67bb | ok |
| 2 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.CallTrace | C:\windows\SYSTEM32\ntdll.dll+9c584\|C:\windows\System32\KERNELBASE.dll+2732e\|UNKNOWN(000001996D28200D) | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoMQUXI | q-26390e67bb | ok |
| 3 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoMQUXF | q-810f342ae3 | ok |
| 4 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoMQUXF | q-810f342ae3 | ok |

### F52 · suspicious / low · T1649 · Root certificate store Blob modified on NASHUA by Sysmon.exe (single event, no corroborating theft)

Evidence status: **verified**

On nashua.dmevals.local at 2020-05-01T23:16:19-04:00, security event 4657 recorded the modification of the 'Blob' value under \REGISTRY\MACHINE\SOFTWARE\Microsoft\SystemCertificates\ROOT\Certificates\BE36A4562FB2EE05DBB3D32323ADF445084ED656 by the machine account NASHUA$ (S-1-5-18, logon 0x3E7) with process C:\Windows\Sysmon.exe. This is the only certificate-store registry write in the dataset (all other 4657 events are WMI Autologger/EventLog-Application value changes by wevtutil.exe). A root-store certificate blob change could indicate a rogue CA certificate being installed for certificate forgery, but the writing process is Sysmon.exe running as SYSTEM, the old/new values are not auditable (REG_BINARY), and no matching certificate file, export script, or PKINIT logon was seen on nashua. Treated as suspicious but unconfirmed; it may be a benign certificate-store update.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:16:19.000Z | nashua.dmevals.local | windows.security | win.ObjectName | \REGISTRY\MACHINE\SOFTWARE\Microsoft\SystemCertificates\ROOT\Certificates\BE36A4562FB2EE05DBB3D32323ADF445084ED656 | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBuu4mRU | q-d2d27e32a2 | ok |
| 2 | 2020-05-02 03:16:19.000Z | nashua.dmevals.local | windows.security | process.executable | C:\Windows\Sysmon.exe | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBuu4mRU | q-68936a0c57 | ok |
| 3 | 2020-05-02 03:16:19.000Z | nashua.dmevals.local | windows.security | user.name | NASHUA$ | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBuu4mRU | q-68936a0c57 | ok |

### F03 · benign / medium · T1003.006 · Single 4662 DS 'Control Access' event on newyork.dmevals.local by the machine account NEWYORK$ — not a DCSync

Evidence status: **verified**

One 4662 Directory Service Access event was recorded on newyork.dmevals.local at 03:16:15 by subject NEWYORK$ (S-1-5-18, logon 0x167EDA) with AccessMask 0x100 and Properties 'Control Access' on object type {19195a5b-6da0-11d0-afd3-00c04fd930c9}. It does not carry the replication GUIDs {1131f6aa-9c07-11d1-f79f-00c04fc2dcd2} (DS-Replication-Get-Changes) or {1131f6ad-9c07-11d1-f79f-00c04fc2dcd2} (DS-Replication-Get-Changes-All) as the granted access, and there is no accompanying 4624/4672 or drsuapi/lsadump command line. No DCSync-style replication request was observed in any dataset.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:16:15.000Z | newyork.dmevals.local | windows.security | win.AccessMask | 0x100 | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBumw-cX | q-c448c20793 | ok |
| 2 | 2020-05-02 03:16:15.000Z | newyork.dmevals.local | windows.security | win.SubjectUserName | NEWYORK$ | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBumw-cX | q-c448c20793 | ok |

### F04 · benign / high · T1040 · netsh trace packet capture on scranton.dmevals.local spawned by Azure Network Watcher Agent (benign platform telemetry)

Evidence status: **verified**

The only packet-capture activity in the Windows telemetry is on scranton.dmevals.local: at 2020-05-02T03:19:17Z netsh.exe was launched with 'trace start capture=yes traceFile="C:\windows\TEMP\E7116ECA-DFE6-43C7-8FA8-8D3AC5AA8726\B91E06C5-1C7C-4830-9A76-74FA211560A7.etl"' and at 03:19:24Z with 'trace stop'. Both were created by C:\Packages\Plugins\Microsoft.Azure.NetworkWatcher.NetworkWatcherAgentWindows\1.4.1421.1\NetworkWatcherAgent\NetworkWatcherAgent.exe running as SYSTEM (creator account SCRANTON$, logon 0x3e7), i.e. the Azure Network Watcher guest agent performing a short (~7 second) diagnostic capture into the agent's own TEMP ETL file. The same agent was also seen starting as a service from services.exe and being (re)installed/started via cmd.exe ('Install /service /autoStart', 'Start /service /autoStart'), and the Azure guest agent WaAppAgent.exe was concurrently cycling its own ETW sessions with logman.exe (GAEvents, RTEvents, WindowsAzure-GuestAgent-Diagnostic). No packet-capture driver (pktmon/npcap/winpcap) was loaded (0 sysmon image-load hits), no tcpdump/windump/rawcap/dumpcap usage was found in sysmon or PowerShell script blocks, and no attacker-controlled capture tooling appears. The 7045 service installations (javamtsup.exe on scranton, PSEXESVC on nashua under user pbeesly) are not packet-capture services and are unrelated to sniffing. Zeek (2020-04-30 window, non-overlapping) shows only routine conn/ssl/dns/kerberos/smb traffic with two SSL::Invalid_Server_Cert notices and generic 'weird' events — no sniffing-related notices. Conclusion: T1040 is not evidenced as attacker activity; the capture is sanctioned Azure platform monitoring.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:17.000Z | scranton.dmevals.local | windows.security | process.command_line | C:\windows\system32\netsh.exe trace start capture=yes traceFile="C:\windows\TEMP\E7116ECA-DFE6-43C7-8FA8-8D3AC5AA8726\B91E06C5-1C7C-4830-9A76-74FA211560A7.etl" | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBuYnMlG | q-9a8a8eb2a5 | ok |
| 2 | 2020-05-02 03:19:17.000Z | scranton.dmevals.local | windows.security | process.parent.executable | C:\Packages\Plugins\Microsoft.Azure.NetworkWatcher.NetworkWatcherAgentWindows\1.4.1421.1\NetworkWatcherAgent\NetworkWatcherAgent.exe | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBuYnMlG | q-9a8a8eb2a5 | ok |
| 3 | 2020-05-02 03:19:24.000Z | scranton.dmevals.local | windows.security | process.command_line | C:\windows\system32\netsh.exe trace stop | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBuWmJOo | q-9a8a8eb2a5 | ok |
| 4 | 2020-05-02 03:19:17.154Z | scranton.dmevals.local | windows.sysmon | process.command_line | C:\windows\system32\netsh.exe trace start capture=yes traceFile="C:\windows\TEMP\E7116ECA-DFE6-43C7-8FA8-8D3AC5AA8726\B91E06C5-1C7C-4830-9A76-74FA211560A7.etl" | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBnvvDAD | q-f6049575f1 | ok |
| 5 | 2020-05-02 03:19:17.154Z | scranton.dmevals.local | windows.sysmon | user.name | SYSTEM | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBnvvDAD | q-f6049575f1 | ok |
| 6 | 2020-05-02 03:20:41.941Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Packages\Plugins\Microsoft.Azure.NetworkWatcher.NetworkWatcherAgentWindows\1.4.1421.1\NetworkWatcherAgent\NetworkWatcherAgent.exe"  Install /service /autoSt… | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBnDAQqo | q-18b28342f2 | ok |
| 7 | 2020-05-02 03:18:38.942Z | scranton.dmevals.local | windows.sysmon | process.command_line | "logman.exe" stop GAEvents | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBnfd0sF | q-f6049575f1 | ok |
| 8 | 2020-05-02 03:19:41.076Z | scranton.dmevals.local | windows.sysmon | process.command_line | "logman.exe" create trace RTEvents -max 50 -f bincirc -o C:\WindowsAzure\Logs\RuntimeEvents.etl -pf C:\WindowsAzure\Packages\GuestAgent\ProviderGuids.txt | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBnFCvgF | q-f6049575f1 | ok |
| 9 | 2020-04-30 00:15:18.392Z | simplerockbuild.simplerock.lan | zeek | zeek.note | SSL::Invalid_Server_Cert | .ds-logs-zeek-default-2026.10.22-000001 / AaFiKZc9VXKkeBwkgR8i | q-066024d66f | ok |

### F08 · benign / medium · T1056.003 · No web-portal capture observed; only archive-staging of files matching *login*/*pass*

Evidence status: **verified**

No inetpub/aspx file creation, no 4663 access on inetpub objects, and no HTTP POST in the zeek window (which does not overlap the Windows telemetry anyway). The only hits were two 4104 script blocks on scranton and nashua (user pbeesly) that enumerate user-profile files with -Include patterns such as *psw*, *pass*, *login*, *admin* and Compress-Archive them to $env:APPDATA\Draft.Zip — this is file collection/staging for exfiltration, not web-portal credential capture. No evidence of a cloned or injected login page.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:56:17.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | $env:APPDATA;$files=ChildItem -Path $env:USERPROFILE\ -Include *.doc,*.xps,*.xls,*.ppt,*.pps,*.wps,*.wpd,*.ods,*.odt,*.lwp,*.jtd,*.pdf,*.zip,*.rar,*.docx,*.url,… | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByXfnRy | q-de6bf68423 | ok |

### F10 · benign / high · T1110 · No brute-force authentication activity; credential theft on scranton.dmevals.local instead

Evidence status: **verified**

Across the whole 2020-05-02 window there are zero failed-logon events (event.code:4625 count = 0) in windows.security, and no logon-failure text in windows.other. The only explicit-credential logons (4648, 15 total) are 9 for pbeesly (5 on scranton.dmevals.local, 4 on nashua.dmevals.local via C:\Windows\PSEXESVC.exe) plus 6 machine/desktop accounts (DWM-1/2, UMFD-0/1/2, SCRANTON$) from winlogon.exe/wininit.exe/taskhostw.exe, which are normal Windows behaviour. The 30 sysmon hits for 'net'/'password' command lines are svchost.exe (28) and netsh.exe (2), i.e. no brute-force tooling. The credential access on this host was theft (LSASS access by a hidden PowerShell), not password guessing/spraying/stuffing.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:40.000Z | nashua.dmevals.local | windows.security | process.executable | C:\Windows\PSEXESVC.exe | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBuu5GRH | q-6c1484888e | ok |
| 2 | 2020-05-02 03:19:10.000Z | scranton.dmevals.local | windows.security | process.executable | C:\Windows\System32\winlogon.exe | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBupz0Op | q-6c1484888e | ok |

### F11 · benign / high · T1110.001 · No password guessing observed

Evidence status: **verified**

No 4625 failures exist at all (count 0), so there is no repeated guessing against any account. The two PowerShell 4104 hits for 'Login'/'Password' are not guessing loops: on scranton.dmevals.local pbeesly ran a Get-PrivateKeys function that exports certificates with a hardcoded password 'saribas', and an Invoke-Exfil function that 7-Zips the Downloads folder with password 'lolol' — credential/collection and exfil staging, not authentication attempts. The 447 sysmon hits for 'runas'/'net use' resolve to ordinary processes (conhost.exe, cmd.exe, powershell.exe, SearchProtocolHost.exe, sdclt.exe, control.exe, dllhost.exe) with no password arguments.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByRaLqc | q-0b2b1d00be | ok |
| 2 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByPYrDh | q-0b2b1d00be | ok |

### F13 · benign / high · T1110.003 · No password spraying; single-account reuse of pbeesly credentials for lateral movement

Evidence status: **verified**

Spraying requires many distinct accounts failing from one source; there are zero 4625 events and the 4648 target accounts are only pbeesly (9) plus machine/desktop accounts. The pbeesly 4648s are one account reused: 5 on scranton.dmevals.local (source.ip 10.0.1.6, svchost.exe) and 4 on nashua.dmevals.local through C:\Windows\PSEXESVC.exe, i.e. PsExec lateral movement with the harvested credential rather than a spray. No 'foreach'+Credential script block and no net use/Invoke-Command process creation were found.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:12:46.000Z | nashua.dmevals.local | windows.security | process.executable | C:\Windows\PSEXESVC.exe | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBuu42Tt | q-a8ed39e970 | ok |
| 2 | 2020-05-02 03:11:18.000Z | scranton.dmevals.local | windows.security | source.ip | 10.0.1.6 | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBunxq0T | q-a8ed39e970 | ok |

### F14 · benign / high · T1110.004 · No credential stuffing observed

Evidence status: **verified**

No failed authentications exist (4625 count 0) and no script block combines username/password lists for replay against services. The only password-bearing scripts are pbeesly's Get-PrivateKeys (cert export with password 'saribas') and Invoke-Exfil (7-Zip archive password 'lolol'), which are collection/exfiltration, not stuffing. The 30 sysmon 'password'/'credential' command-line hits are svchost.exe and netsh.exe.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByPYrDh | q-cf56c3d08d | ok |

### F15 · benign / medium · T1111 · No MFA/smartcard interception; lsass access and 4648 logons are credential theft/exfil

Evidence status: **verified**

No smartcard/MFA tooling or interception artifacts; lsass access by pbeesly's PowerShell and 4648 logons to NASHUA are credential theft/reuse and exfiltration, not MFA interception.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoMQUXI | q-332a6b5ac1 | ok |
| 2 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.CallTrace | C:\windows\SYSTEM32\ntdll.dll+9c584\|C:\windows\System32\KERNELBASE.dll+2732e\|UNKNOWN(000001996D28200D) | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoMQUXI | q-63360ebb74 | ok |
| 3 | 2020-05-02 03:11:40.000Z | nashua.dmevals.local | windows.security | process.executable | C:\Windows\PSEXESVC.exe | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBuu5GRH | q-2ced3d70da | ok |

### F17 · benign / medium · T1187 · SMB/445 and WebDAV-method traffic in the zeek window is benign infrastructure activity

Evidence status: **verified**

The zeek dataset (2020-04-30, non-overlapping with the Windows windows) shows 50 conn records to SMB ports (45 to 445, 5 to 139) and 36 HTTP records with PROPFIND/MOVE/OPTIONS methods, all between 10.0.1.4 and 192.168.0.4 observed by simplerockbuild.simplerock.lan. These are internal file-share/WebDAV-style operations between two internal hosts with no evidence of an attacker-controlled listener or credential capture, and they cannot be correlated in time with the Windows forced-authentication artifacts. Likewise, the 168 security 5156 events to 445/139 and the sysmon network connections to 445 are System-process SMB traffic to internal addresses (10.0.0.4, 10.0.1.6, link-local fe80::e40c:95b6:b0a7:6429) consistent with domain GPO/SYSVOL and ADMIN$ access, not outbound forced authentication to an external host.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-04-30 00:32:18.095Z | simplerockbuild.simplerock.lan | zeek | destination.ip | 192.168.0.4 | .ds-logs-zeek-default-2026.10.22-000001 / AaFiKZc9VXKkeBwkgR9D | q-26ed8d3a05 | ok |
| 2 | 2020-04-30 00:32:18.095Z | simplerockbuild.simplerock.lan | zeek | source.ip | 10.0.1.4 | .ds-logs-zeek-default-2026.10.22-000001 / AaFiKZc9VXKkeBwkgR9D | q-26ed8d3a05 | ok |
| 3 | 2020-05-02 03:01:43.033Z | scranton.dmevals.local | windows.sysmon | destination.ip | 10.0.0.4 | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoSWKN8 | q-a3dfbfa403 | ok |
| 4 | 2020-05-02 03:10:23.000Z | nashua.dmevals.local | windows.security | win.ShareName | \\*\ADMIN$ | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBuv5CHV | q-800a8bd9e2 | ok |

### F20 · benign / high · T1212 · Remaining lsass handle requests are Windows system processes (wininit/csrss/svchost) — benign

Evidence status: **verified**

The other high-GrantedAccess lsass accesses in the stack are all on scranton.dmevals.local at 03:18:34–03:19:59Z and come from C:\windows\system32\wininit.exe (0x1fffff, 0x1000000), csrss.exe (0x1fffff) and svchost.exe (0x101001, 0x3000) — the standard Windows boot/session-manager and service-host handles taken when lsass is (re)started; lsass.exe itself was created at 03:19:09Z by wininit.exe as SYSTEM. The bulk of the 326 lsass access events (293 with 0x1000, 24 with 0x1400) are likewise routine query-limited handles. No dump tooling (procdump/comsvcs/MiniDump) appears in any process command line, and no PowerShell script block references lsass/MiniDump/comsvcs/procdump (C134 zero hits). The Zeek notices/weirds (C136) are from a separate 2020-04-30 window and show only generic weird/notice records with no credential-related content.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:09.803Z | scranton.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\csrss.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBnqqYet | q-f051f2f350 | ok |
| 2 | 2020-05-02 03:19:59.323Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x3000 | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBnTPq-O | q-f051f2f350 | ok |
| 3 | 2020-05-02 03:19:09.809Z | scranton.dmevals.local | windows.sysmon | process.command_line | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBnaXZbr | q-b5af7faff2 | ok |

### F21 · benign / medium · T1539 · No web session cookie theft observed; browser cookie-store hits are Windows Search indexing and normal Edge startup

Evidence status: **verified**

All T1539-relevant hits were reviewed and none show theft of browser session cookies. The 4 process-creation hits matching *cookie*/*Login Data* in windows.security are C:\Windows\System32\SearchProtocolHost.exe spawned by SearchIndexer.exe on scranton.dmevals.local (22:57-23:04) and nashua.dmevals.local (23:16) with the standard Windows Search command line ("Software\Microsoft\Windows Search" ... "DownLevelDaemon") - normal indexer behaviour, not cookie access. The 162 sysmon file-creation hits matching *Cookies*/*Login Data*/*Web Data* are dominated by C:\Windows\ServiceState\EventLog\Data\lastalive0.dat / lastalive1.dat (133 events) and GroupPolicy DataStore files, i.e. substring matches on unrelated paths. The only genuine browser-profile file activity is MicrosoftEdge.exe (user pbeesly) on scranton at 03:21:05-03:21:06 creating its own DataStore\_TempTestAccess.txt, Recovery\Active\RecoveryStore.{5E6C474D-...}.dat and AC\Temp\~DF*.TMP files, alongside MicrosoftEdgeSH.exe/MicrosoftEdgeCP.exe process creations - a normal Edge launch. No non-browser process was seen touching an Edge/Chrome/Firefox cookie or Login Data store, no 4663 object-access events on cookie paths, and no sysmon event.code 10 handle to a browser image (C139 zero hits). The PowerShell 4104 hits for *cookie*/*sqlite*/*credential*/*password* are Microsoft DSC/xActiveDirectory module manifests and localized-string blocks on newyork.dmevals.local (SYSTEM), plus the attacker toolkit scripts on scranton (pbeesly) which export certificates (Get-PrivateKeys), capture screenshots and exfiltrate via WebDAV - credential-adjacent activity, but none of them read browser cookie databases. Zeek HTTP hits are two GET requests from 10.0.1.4 to 192.168.0.4 on 2020-04-30 (non-overlapping window) with no cookie content retrievable.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:57:01.000Z | scranton.dmevals.local | windows.security | process.command_line | "C:\windows\system32\SearchProtocolHost.exe" Global\UsGthrFltPipeMssGthrPipe6_ Global\UsGthrCtrlFltPipeMssGthrPipe6 1 -2147483646 "Software\Microsoft\Windows Se… | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBy3DhyQ | q-f5b5a1df52 | ok |
| 2 | 2020-05-02 03:16:20.000Z | nashua.dmevals.local | windows.security | process.parent.executable | C:\Windows\System32\SearchIndexer.exe | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBuw76B1 | q-f5b5a1df52 | ok |
| 3 | 2020-05-02 03:21:05.198Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Users\pbeesly\AppData\Local\Packages\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\AC\MicrosoftEdge\User\Default\DataStore\_TempTestAccess.txt | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBi1zvyC | q-74377e70bf | ok |
| 4 | 2020-05-02 03:21:05.914Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Users\pbeesly\AppData\Local\Packages\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\AC\MicrosoftEdge\User\Default\Recovery\Active\RecoveryStore.{5E6C474D-D0E6-4BC1-A0… | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBi1zfyN | q-74377e70bf | ok |
| 5 | 2020-05-02 03:21:01.765Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Windows\SystemApps\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\MicrosoftEdge.exe" -ServerName:MicrosoftEdge.AppXdnhjhccw3zf0j06tkg3jtqr00qdm0khc.mca | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBnJGZ0U | q-a67d2de158 | ok |
| 6 | 2020-05-02 03:21:05.681Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Windows\ServiceProfiles\LocalService\AppData\Local\Packages\warp_jit_db4a1097-b484-4973-bbf2-a04208ecd4d4\AC\INetCookies | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBi-6ySm | q-27eadcdcf4 | ok |
| 7 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByRaLqc | q-3e5dda5c81 | ok |
| 8 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByPYrDh | q-ff22a330fd | ok |

### F25 · benign / medium · T1552.002 · No registry credential harvesting observed

Evidence status: **verified**

The 17 registry SetValue events matching Password/Credential/Secret are all OS-generated: IdentityCRL ProviderPasswordLength/CharacterGroups, DeviceGuard CredentialGuard Enabled, CredentialEnrollmentManagerUserSvc_13619b service values and Winlogon PasswordExpiryNotification values. No reg query/reg save of SAM/SECURITY was seen and no 4663 access to SAM/SECURITY/Password objects was returned. The only registry activity by the attacker was HKCU\Software\Classes\Folder\shell\open\command manipulation (persistence), not credential access.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:58:07.000Z | scranton.dmevals.local | windows.powershell | process.command_line | Set-ItemProperty -Path "HKCU:\Software\Classes\Folder\shell\open\command" -Name "(Default)" | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByYf107 | q-c1730246ed | ok |

### F26 · benign / medium · T1552.003 · No shell history access observed

Evidence status: **verified**

No process command line, file creation or script block referenced ConsoleHost_history, Get-History or PSReadline in the windows.sysmon and windows.powershell datasets for this window. The attacker operated interactively in PowerShell but did not read shell history files.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:03.000Z | scranton.dmevals.local | windows.powershell | process.command_line | function Invoke-Discovery {     $DiscoveryInfo =@()     $CurrentDir = Get-Location      $DiscoveryInfo += [PSCustomObject]@{                 CurrentDirectory = … | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByRaboE | q-fdb634945b | ok |

### F27 · benign / medium · T1552.006 · No Group Policy Preferences credential access observed

Evidence status: **verified**

No script block, process command line or 5145 share access referenced Groups.xml, cpassword, SYSVOL or gpp. The only GPO-related file activity was the OS writing C:\Windows\System32\GroupPolicy\DataStore\0\sysvol\dmevals.local\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\gpt.ini, which is normal Group Policy processing.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\readme.ps1 | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByRaLqc | q-3a2db39970 | ok |

### F29 · benign / medium · T1555.003 · No browser credential-store access observed; only a benign LocalService INetCookies file creation

Evidence status: **verified**

The only hit for browser credential-store paths was a single Sysmon file-create of C:\Windows\ServiceProfiles\LocalService\AppData\Local\Packages\warp_jit_db4a1097-b484-4973-bbf2-a04208ecd4d4\AC\INetCookies on scranton.dmevals.local by svchost.exe (Windows.WARP.JITService context), which is normal Windows service-profile cookie handling, not theft of Chrome/Edge/Firefox Login Data, logins.json or Local State. No process-creation, 4663 object-access or PowerShell script-block events referencing browser credential files were found. Note the intruder did run a broad file-collection script matching *pass*, *login*, *psw* patterns on scranton and nashua, but that is file staging/collection, not browser credential-store extraction.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:21:05.681Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Windows\ServiceProfiles\LocalService\AppData\Local\Packages\warp_jit_db4a1097-b484-4973-bbf2-a04208ecd4d4\AC\INetCookies | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBi-6ySm | q-7c01717bbc | ok |
| 2 | 2020-05-02 03:21:05.681Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\System32\svchost.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBi-6ySm | q-7c01717bbc | ok |

### F30 · benign / medium · T1555.004 · No Windows Credential Manager / vault access observed; LSASS access is attributed to T1555 credential dumping instead

Evidence status: **verified**

No cmdkey, vaultcmd, credman or Get-StoredCredential execution, no Sysmon registry/file events on \Microsoft\Protect or Vault directories, and no 4688 process creation referencing vault or credman were found on any host. The two windows.other hits were a Credential Guard configuration status message (event code 14, 'Credential Guard configuration: 0x0, 0') and an unrelated DNS PTR registration failure on scranton.dmevals.local. The PowerShell 4104 hits for 'Credential' were a PSCredential object built for the WebDAV exfil drive and unrelated module help text, not Credential Manager enumeration. The high-privilege LSASS handles reported under T1555 are the credential-theft activity, not Credential Manager access.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:09.000Z | scranton.dmevals.local | windows.other | message | Credential Guard configuration: 0x0, 0 | .ds-logs-windows.other-default-2026.10.22-000001 / AaFiKJc9VXKkeBwdMB1A | q-00820b3e33 | ok |
| 2 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByPYrDh | q-eba5708948 | ok |

### F32 · benign / high · T1556.001 · lsass.exe access on scranton from wininit/csrss/services and svchost (lsm.dll) is normal system behaviour

Evidence status: **verified**

The rare lsass access masks on scranton.dmevals.local at 03:18-03:19 come from Windows' own components: wininit.exe (0x1FFFFF and 0x1000000, call trace inside wininit.exe), csrss.exe (0x1FFFFF, basesrv.DLL/CSRSRV.dll), services.exe (0x1000, RPCRT4.dll) and svchost.exe (0x101001, call trace entirely in lsm.dll) — the standard boot/logon/shutdown and LSM notification paths, coinciding with a user logoff/logon cycle (Winlogon 7002/7001 events). The 0x1400 accesses are from the Azure telemetry service via CorperfmonExt.dll (performance counters). No non-standard process or unsigned module touched lsass, and no DC authentication modification (no 4657 on LSA objects, no 4739, no 5136) was observed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:18:34.438Z | scranton.dmevals.local | windows.sysmon | win.CallTrace | C:\windows\SYSTEM32\ntdll.dll+9def4\|c:\windows\system32\lsm.dll+1aa6e\|c:\windows\system32\lsm.dll+1a9c3\|c:\windows\system32\lsm.dll+65e1\|c:\windows\system32… | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBnrrZmZ | q-039d28021c | ok |
| 2 | 2020-05-02 03:19:09.803Z | scranton.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\wininit.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBnaXZbs | q-039d28021c | ok |
| 3 | 2020-05-02 03:19:09.803Z | scranton.dmevals.local | windows.sysmon | win.CallTrace | C:\windows\SYSTEM32\ntdll.dll+9c584\|C:\windows\system32\basesrv.DLL+2fba\|C:\windows\SYSTEM32\CSRSRV.dll+5af4\|C:\windows\SYSTEM32\ntdll.dll+6cedf | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBnqqYet | q-039d28021c | ok |
| 4 | 2020-05-02 03:19:13.337Z | scranton.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\services.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBnlknoR | q-c7a32415de | ok |

### F33 · benign / high · T1556.002 · No password filter DLL activity; cryptdll/samlib/samcli loads are standard Microsoft DLLs

Evidence status: **verified**

The 33 image-load hits for lsass/cryptdll/PasswordFilter are all Microsoft-signed system DLLs (cryptdll.dll 'Cryptography Manager', samlib.dll 'SAM Library DLL', samcli.dll 'Security Accounts Manager Client DLL') loaded by ordinary processes such as SearchProtocolHost.exe, SearchFilterHost.exe, WmiPrvSE.exe, svchost.exe, dsregcmd.exe and powershell.exe on scranton, newyork and nashua. The only lsass.exe image-load record is lsass.exe itself. No registry write to the LSA 'Notification Packages' value, no 4657 on Notification Packages/Password objects, and no PasswordFilter DLL file creation were observed, so there is no evidence of a password filter being registered.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:01:36.915Z | newyork.dmevals.local | windows.sysmon | win.ImageLoaded | C:\Windows\System32\cryptdll.dll | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoTW5Zx | q-9f1a8d9fd5 | ok |
| 2 | 2020-05-02 03:04:04.220Z | scranton.dmevals.local | windows.sysmon | win.ImageLoaded | C:\Windows\System32\samcli.dll | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoOSno9 | q-9f1a8d9fd5 | ok |
| 3 | 2020-05-02 03:01:42.638Z | scranton.dmevals.local | windows.sysmon | win.ImageLoaded | C:\Windows\System32\cryptdll.dll | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoTW5b_ | q-9f1a8d9fd5 | ok |

### F34 · benign / high · T1556.005 · Reversible-encryption hit is a benign xActiveDirectory DSC module script on newyork

Evidence status: **verified**

The single 4104 script block matching Set-ADUser/Set-ADAccountControl on newyork.dmevals.local (2020-05-02T03:01:30Z, SYSTEM, PID 5344) is the Microsoft xActiveDirectory DSC helper file C:\Program Files\WindowsPowerShell\Modules\xActiveDirectory\DscResources\MSFT_xADCommon\MSFT_xADCommon.ps1 — the match comes from cmdlet help text ('Get-ADUser, Set-ADUser and Remove-ADUser cmdlets take an Identity parameter'), not from any account-control change. No 4739 policy-change events, no Set-ADAccountControl/Reversible command lines and no reversible-encryption messages were found.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:01:30.000Z | newyork.dmevals.local | windows.powershell | win.Path | C:\Program Files\WindowsPowerShell\Modules\xActiveDirectory\DscResources\MSFT_xADCommon\MSFT_xADCommon.ps1 | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByUbwtm | q-0dd098f7b5 | ok |
| 2 | 2020-05-02 03:01:30.000Z | newyork.dmevals.local | windows.powershell | host.name | newyork.dmevals.local | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByUbwtm | q-0dd098f7b5 | ok |

### F35 · benign / medium · T1556.006 · No MFA modification observed

Evidence status: **verified**

No events indicating MFA/authentication-policy modification were retrieved: the 4739 (domain policy change) query returned zero hits in windows.security, and no MFA-related configuration changes appeared in the other datasets. The credential theft in this incident (Get-Keystrokes by pbeesly) does not involve MFA tampering.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:01:30.000Z | newyork.dmevals.local | windows.powershell | event.code | 4104 | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByUbwtm | q-0dd098f7b5 | ok |

### F36 · benign / medium · T1556.007 · No hybrid identity / directory-sync modification observed

Evidence status: **verified**

The 5136 (directory service object modification) query returned zero hits, and the only hybrid-identity-adjacent activity is dsregcmd.exe on newyork.dmevals.local loading the standard cryptdll.dll at 03:06:14 — normal Azure AD registration tooling, not a federation/Seamless SSO or PTA agent change.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:06:14.783Z | newyork.dmevals.local | windows.sysmon | process.executable | C:\Windows\System32\dsregcmd.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoGKaib | q-9f1a8d9fd5 | ok |

### F37 · benign / medium · T1556.008 · No network provider DLL registration observed

Evidence status: **verified**

No 4657 registry-modification events referencing NetworkProvider, Winlogon or Credential objects were found, and the registry writes retrieved under Winlogon/Lsa keys are routine system values (LsaPid, ProductType, LsaCfgFlagsDefault, WinStationsDisabled, PasswordExpiryNotification) written by lsass.exe, winlogon.exe, wininit.exe and svchost.exe. No third-party network provider DLL was registered.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:09.834Z | scranton.dmevals.local | windows.sysmon | registry.path | HKLM\System\CurrentControlSet\Control\Lsa\LsaPid | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBnaXZbu | q-ca3926364e | ok |
| 2 | 2020-05-02 03:19:09.834Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBnaXZbu | q-ca3926364e | ok |

### F38 · benign / medium · T1557 · No adversary-in-the-middle positioning observed; NTLM network logon to SCRANTON is a single lateral-movement artifact, not relay

Evidence status: **verified**

Across the 2020-05-02 02:55-03:28Z Windows window there is no evidence of traffic interception/relay infrastructure. The only NTLM network logon in windows.security is a single type-3 logon for pbeesly on scranton.dmevals.local at 2020-05-01T23:20:41-04:00 (NtLmSsp, NTLM V2, Workstation Name 10.0.1.4, Source Network Address 172.18.39.2) - one event, not a relay pattern, and it coincides with the pbeesly PSEXESVC service installs on nashua (23:11-23:15) and the javamtsup service on scranton (23:04), i.e. ordinary PsExec-style remote administration by a known account. The 23 event.code:4697 service installs are either those pbeesly installs or per-user svchost services created by SCRANTON$ at 23:20:48 (OneSyncSvc_13619b, cbdhsvc_13619b, etc.), all standard Windows behaviour. In the non-overlapping zeek window (2020-04-30 00:06-00:45Z) all SMB traffic is normal Kerberos/GSSAPI SMB to the DC 10.0.0.4 and between 10.0.1.4/10.0.1.6; the only oddity is 10.0.1.4 repeatedly hitting 192.168.0.4:445/139 with REJ (unreachable, no session established), which is a failed connection attempt, not a successful relay.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:20:41.000Z | scranton.dmevals.local | windows.security | win.LogonProcessName | NtLmSsp  | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBufr2mI | q-0a1475eea7 | ok |
| 2 | 2020-05-02 03:20:41.000Z | scranton.dmevals.local | windows.security | win.WorkstationName | 10.0.1.4 | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBufr2mI | q-0a1475eea7 | ok |
| 3 | 2020-05-02 03:20:41.000Z | scranton.dmevals.local | windows.security | win.IpAddress | 172.18.39.2 | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBufr2mI | q-0a1475eea7 | ok |
| 4 | 2020-05-02 03:11:39.000Z | nashua.dmevals.local | windows.security | win.ServiceName | PSEXESVC | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBuq1HQ4 | q-2df7b457e0 | ok |
| 5 | 2020-05-02 03:20:48.000Z | scranton.dmevals.local | windows.security | win.ServiceName | CredentialEnrollmentManagerUserSvc_13619b | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBufrmli | q-2df7b457e0 | ok |
| 6 | 2020-04-30 00:32:14.891Z | simplerockbuild.simplerock.lan | zeek | zeek.conn_state | REJ | .ds-logs-zeek-default-2026.10.22-000001 / AaFiKZc9VXKkeBwkgR_2 | q-8fb7b53b05 | ok |
| 7 | 2020-04-30 00:32:14.891Z | simplerockbuild.simplerock.lan | zeek | destination.ip | 192.168.0.4 | .ds-logs-zeek-default-2026.10.22-000001 / AaFiKZc9VXKkeBwkgR_2 | q-8fb7b53b05 | ok |

### F39 · benign / medium · T1557.001 · No LLMNR/NBT-NS/mDNS poisoning or SMB relay; only a single failed NetBIOS name lookup

Evidence status: **verified**

Name-resolution poisoning and SMB relay are not supported by the data. In zeek the only LLMNR/NBT-NS/mDNS-class traffic is two UDP/137 datagrams from 10.0.1.6 and 10.0.1.4 to the broadcast address 10.0.1.255 (NASHUA NetBIOS name queries at 00:34:51 and 00:35:01Z) with conn_state S0 - no responder answered, and no host was seen answering name queries for others. All DNS answers in the zeek window come from the legitimate DC resolver 10.0.0.4 (e.g. newyork.dmevals.local -> 10.0.0.4, nashua.dmevals.local -> 10.0.1.6, wec.dmevals.local -> 10.0.1.10); the only NXDOMAINs are routine wpad.dmevals.local lookups and site-specific _ldap._tcp SRV queries. SMB sessions are Kerberos/GSSAPI-authenticated to 10.0.0.4 and between 10.0.1.4/10.0.1.6, with no anonymous/relayed authentication. On the Windows side, no PowerShell script block mentions Responder/Inveigh/LLMNR/NBT-NS (zero hits) and no registry change to EnableMulticast was recorded; the 23 service installs are pbeesly's PSEXESVC/javamtsup and per-user svchost services, none of which is name-resolution or relay tooling.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-04-30 00:34:51.731Z | bobs.bigwheel.local | zeek | dns.question.name | NASHUA | .ds-logs-zeek-default-2026.10.22-000001 / AaFiKZc9VXKkeByOjhn8 | q-783f436ec9 | ok |
| 2 | 2020-04-30 00:34:51.731Z | bobs.bigwheel.local | zeek | destination.ip | 10.0.1.255 | .ds-logs-zeek-default-2026.10.22-000001 / AaFiKZc9VXKkeByOjhn8 | q-783f436ec9 | ok |
| 3 | 2020-04-30 00:33:26.294Z | simplerockbuild.simplerock.lan | zeek | zeek.answers | ["10.0.1.6"] | .ds-logs-zeek-default-2026.10.22-000001 / AaFiKZc9VXKkeBwkgR-S | q-783f436ec9 | ok |
| 4 | 2020-04-30 00:33:26.294Z | simplerockbuild.simplerock.lan | zeek | dns.question.name | nashua.dmevals.local | .ds-logs-zeek-default-2026.10.22-000001 / AaFiKZc9VXKkeBwkgR-S | q-783f436ec9 | ok |
| 5 | 2020-04-30 00:07:59.132Z | simplerockbuild.simplerock.lan | zeek | dns.response_code | NXDOMAIN | .ds-logs-zeek-default-2026.10.22-000001 / AaFiKZc9VXKkeBwkgR-J | q-783f436ec9 | ok |
| 6 | 2020-04-30 00:06:38.903Z | simplerockbuild.simplerock.lan | zeek | zeek.service | krb,smb,gssapi | .ds-logs-zeek-default-2026.10.22-000001 / AaFiKZc9VXKkeBwkgh8D | q-8fb7b53b05 | ok |

### F40 · benign / medium · T1557.002 · No ARP cache poisoning indicators; network-config commands are Azure guest-agent telemetry

Evidence status: **verified**

No evidence of ARP poisoning or MITM positioning. The only processes touching network configuration in windows.sysmon are ipconfig.exe /all and ROUTE.EXE print on scranton.dmevals.local at 2020-05-02 03:19:24-03:20:00Z, all spawned by Azure guest/telemetry agents (C:\WindowsAzure\Packages\GuestAgent\WindowsAzureGuestAgent.exe, Telemetry\WindowsAzureTelemetryService.exe, WaAppAgent.exe) as SYSTEM - read-only inventory commands, not ARP manipulation. No PowerShell script block referencing arp/netsh/route was found (zero hits). In zeek, connection sources are only the two internal hosts 10.0.1.4 and 10.0.1.6, with no host mediating traffic between many peers; the 192.168.0.4:445/139 attempts from 10.0.1.4 were rejected (REJ) and never established, so no interception path exists in the captured traffic.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:57.992Z | scranton.dmevals.local | windows.sysmon | process.command_line | "ipconfig.exe" /all | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBnEBpF6 | q-9de32fd136 | ok |
| 2 | 2020-05-02 03:19:57.992Z | scranton.dmevals.local | windows.sysmon | process.parent.executable | C:\WindowsAzure\Packages\WaAppAgent.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBnEBpF6 | q-9de32fd136 | ok |
| 3 | 2020-05-02 03:19:33.689Z | scranton.dmevals.local | windows.sysmon | process.command_line | "route.exe" print | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBnHC1-C | q-9de32fd136 | ok |
| 4 | 2020-05-02 03:19:33.689Z | scranton.dmevals.local | windows.sysmon | process.parent.executable | C:\WindowsAzure\Packages\Telemetry\WindowsAzureTelemetryService.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBnHC1-C | q-9de32fd136 | ok |
| 5 | 2020-04-30 00:32:15.443Z | simplerockbuild.simplerock.lan | zeek | zeek.conn_state | REJ | .ds-logs-zeek-default-2026.10.22-000001 / AaFiKZc9VXKkeBwkgh-e | q-8fb7b53b05 | ok |

### F41 · benign / medium · T1557.003 · No DHCP spoofing or rogue DHCP server activity observed

Evidence status: **verified**

DHCP spoofing is not observed. No DHCP server/lease events (1341/1342/1020/1063) exist in windows.other, and no PowerShell script block references dhcp/DhcpServer (zero hits). The only DHCP/network-configuration commands are the Azure guest-agent ipconfig/route invocations on scranton described above. In zeek, all DNS resolution is directed at the legitimate DC 10.0.0.4 and no host is seen handing out configuration or acting as a rogue DHCP/name server; the single NTLM network logon (pbeesly, type 3, from 10.0.1.4/172.18.39.2 to scranton) is consistent with the concurrent PsExec administration, not with credential capture via a spoofed DHCP/name-resolution path.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:29.539Z | scranton.dmevals.local | windows.sysmon | process.command_line | "ipconfig.exe" /all | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBncaspm | q-9de32fd136 | ok |
| 2 | 2020-05-02 03:19:29.539Z | scranton.dmevals.local | windows.sysmon | process.parent.executable | C:\WindowsAzure\Packages\Telemetry\WindowsAzureTelemetryService.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBncaspm | q-9de32fd136 | ok |
| 3 | 2020-04-30 00:06:38.899Z | simplerockbuild.simplerock.lan | zeek | destination.ip | 10.0.0.4 | .ds-logs-zeek-default-2026.10.22-000001 / AaFiKZc9VXKkeBwkgR-a | q-783f436ec9 | ok |
| 4 | 2020-05-02 03:20:41.000Z | scranton.dmevals.local | windows.security | win.AuthenticationPackageName | NTLM | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBufr2mI | q-0a1475eea7 | ok |

### F42 · benign / medium · T1558 · No Kerberos ticket theft/forgery observed; lsass handle events are benign tooling, but host is compromised by a separate shellcode loader

Evidence status: **verified**

Across windows.sysmon (2020-05-02 02:55-03:28Z) 326 process-access events target lsass.exe. The 0x1000/0x1400 grants (293+24) come from svchost.exe, AntimalwareConfig.exe and WindowsAzureTelemetryService.exe (AV/telemetry). The only full-access grants are 5 events: powershell.exe on scranton.dmevals.local at 03:01:03 (0x1000) and 03:05:16 (0x1f3fff and 0x1fffff), and wsmprovhost.exe on nashua.dmevals.local at 03:09:29 (0x1f3fff). Reading the full events shows the 03:05:16 PowerShell access has CallTrace ntdll.dll+KERNELBASE.dll+UNKNOWN and the wsmprovhost access has a CallTrace entirely through System.ni.dll / Microsoft.PowerShell.Commands.Management.ni.dll managed frames - i.e. PowerShell/.NET managed code, not a credential-dumping tool. No 4104 script block in windows.powershell mentions kerberos, ticket, krbtgt, golden, silver, SPN, ASREP or mimikatz (0 hits). The 4104 blocks that do exist on scranton are a reflective shellcode loader (GetProcAddress/GetModuleHandle + base64 PE), which is code execution, not ticket theft. Zeek kerberos (2020-04-30, non-overlapping window) shows only 35 events: 14 AS and 11 TGS requests, all from pbeesly, with 7 KDC_ERR_PREAUTH_REQUIRED that are immediately followed by successful AS-REP - normal preauthentication, not roasting. No ticket-forging or ticket-theft evidence for T1558 as a family.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoMQUXI | q-04426dd94b | ok |
| 2 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.CallTrace | C:\windows\SYSTEM32\ntdll.dll+9c584\|C:\windows\System32\KERNELBASE.dll+2732e\|UNKNOWN(000001996D28200D) | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoMQUXI | q-04426dd94b | ok |
| 3 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBn663fz | q-07620e0662 | ok |
| 4 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBn663fz | q-07620e0662 | ok |
| 5 | 2020-04-30 00:24:19.110Z | simplerockbuild.simplerock.lan | zeek | zeek.error_msg | KDC_ERR_PREAUTH_REQUIRED | .ds-logs-zeek-default-2026.10.22-000001 / AaFiKZc9VXKkeBwkgh9J | q-a46d3c5dd8 | ok |
| 6 | 2020-04-30 00:24:19.119Z | simplerockbuild.simplerock.lan | zeek | zeek.request_type | AS | .ds-logs-zeek-default-2026.10.22-000001 / AaFiKZc9VXKkeBwkgh9K | q-a46d3c5dd8 | ok |

### F43 · benign / medium · T1558.001 · No golden ticket indicators: no krbtgt access, no forged-TGT anomalies

Evidence status: **verified**

Golden-ticket prerequisites (KRBTGT hash extraction from lsass or a forged TGT) are not present. No 4104 script block references krbtgt or golden (0 hits). The only lsass full-access events are the PowerShell/wsmprovhost managed-code accesses described above, whose call traces run through .NET managed assemblies rather than a dumping tool. Zeek kerberos shows krbtgt/DMEVALS.LOCAL service requests only as the normal AS-REP/TGS-renewal pair from pbeesly (e.g. AS at 00:24:19.110 with KDC_ERR_PREAUTH_REQUIRED followed 9ms later by a successful AS-REP, then a TGS to krbtgt/DMEVALS.LOCAL at 00:24:19.124). 4672 privileged logons are all the machine account NEWYORK$ with its standard privilege set, and 4634 logoffs are 227 type-3 / 9 type-2 - no anomalous forged-session pattern.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-04-30 00:24:19.124Z | simplerockbuild.simplerock.lan | zeek | zeek.service | krbtgt/DMEVALS.LOCAL | .ds-logs-zeek-default-2026.10.22-000001 / AaFiKZc9VXKkeBwkgR8w | q-a46d3c5dd8 | ok |
| 2 | 2020-04-30 00:24:19.119Z | simplerockbuild.simplerock.lan | zeek | zeek.success | True | .ds-logs-zeek-default-2026.10.22-000001 / AaFiKZc9VXKkeBwkgh9K | q-a46d3c5dd8 | ok |
| 3 | 2020-05-02 02:55:54.000Z | newyork.dmevals.local | windows.security | win.SubjectUserName | NEWYORK$ | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBy3EfF3 | q-2229601f58 | ok |

### F44 · benign / medium · T1558.002 · No silver ticket indicators; TGS requests are ordinary service access by pbeesly

Evidence status: **verified**

Zeek kerberos shows 11 TGS requests, all from client pbeesly/DMEVALS.LOCAL, to cifs/NASHUA (4), host/nashua.dmevals.local (3), cifs/NEWYORK (1), HTTP/NASHUA (1), ldap/NEWYORK.dmevals.local (1) and krbtgt/DMEVALS.LOCAL (1). These are single, spaced-out service-ticket requests (00:24 to 00:40) consistent with normal SMB/LDAP/HTTP access, not a burst of service-ticket acquisition. No 4104 script block mentions silver or 'service ticket' (0 hits), and no lsass access by a service-account-harvesting tool was found. The 4672 privileged logons are only the NEWYORK$ machine account.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-04-30 00:35:25.646Z | simplerockbuild.simplerock.lan | zeek | zeek.service | cifs/NASHUA | .ds-logs-zeek-default-2026.10.22-000001 / AaFiKZc9VXKkeBwkgR8s | q-a46d3c5dd8 | ok |
| 2 | 2020-04-30 00:33:14.816Z | simplerockbuild.simplerock.lan | zeek | zeek.service | ldap/NEWYORK.dmevals.local | .ds-logs-zeek-default-2026.10.22-000001 / AaFiKZc9VXKkeBwkgh8P | q-a46d3c5dd8 | ok |
| 3 | 2020-04-30 00:33:26.292Z | simplerockbuild.simplerock.lan | zeek | zeek.client | pbeesly/DMEVALS.LOCAL | .ds-logs-zeek-default-2026.10.22-000001 / AaFiKZc9VXKkeBwkgh8Q | q-a46d3c5dd8 | ok |

### F45 · benign / medium · T1558.003 · No Kerberoasting: no SPN enumeration or RC4 TGS burst; pbeesly activity is compromised-host lateral movement

Evidence status: **verified**

Kerberoasting requires a burst of TGS requests for many SPNs, typically with RC4 encryption. Zeek shows only 11 TGS requests total, all from pbeesly/DMEVALS.LOCAL, spread over 16 minutes and targeting only 5 distinct services - not a roasting pattern. No 4104 script block contains SPN or Kerberoast (0 hits). Note however that pbeesly is the account running attacker tooling on scranton.dmevals.local (cod.3aka3.scr -> cmd -> powershell -> csc.exe) and making Kerberos type-3 network logons to newyork.dmevals.local from 10.0.1.4 (03:04:04, 03:09:04, 03:20:46) and to nashua.dmevals.local - that is lateral movement with a valid ticket, not ticket harvesting.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-04-30 00:24:19.122Z | simplerockbuild.simplerock.lan | zeek | zeek.service | cifs/NEWYORK | .ds-logs-zeek-default-2026.10.22-000001 / AaFiKZc9VXKkeBwkgR8v | q-a46d3c5dd8 | ok |
| 2 | 2020-05-02 03:04:04.000Z | newyork.dmevals.local | windows.security | win.LogonType | 3 | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBy4FbJE | q-d08351c526 | ok |
| 3 | 2020-05-02 03:04:04.000Z | newyork.dmevals.local | windows.security | win.IpAddress | 10.0.1.4 | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBy4FbJE | q-d08351c526 | ok |

### F46 · benign / medium · T1558.004 · No AS-REP roasting: all AS-REQs are preauthenticated and succeed

Evidence status: **verified**

AS-REP roasting requires AS-REQ for accounts with preauthentication disabled, returning an encrypted AS-REP without a prior KDC_ERR_PREAUTH_REQUIRED. In zeek, all 7 AS-REQ events carrying an error show KDC_ERR_PREAUTH_REQUIRED (pbeesly/dmevals and pbeesly/DMEVALS.LOCAL), and each is followed within milliseconds by a successful AS-REP - the normal preauthenticated flow. No 4104 script block mentions ASREP, GetNPUsers or preauth (0 hits), and no sysmon process command line contains asrep/GetNPUsers (0 hits).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-04-30 00:36:17.846Z | simplerockbuild.simplerock.lan | zeek | zeek.error_msg | KDC_ERR_PREAUTH_REQUIRED | .ds-logs-zeek-default-2026.10.22-000001 / AaFiKZc9VXKkeBwkgR8t | q-a46d3c5dd8 | ok |
| 2 | 2020-04-30 00:36:17.855Z | simplerockbuild.simplerock.lan | zeek | zeek.success | True | .ds-logs-zeek-default-2026.10.22-000001 / AaFiKZc9VXKkeBwkgR8u | q-a46d3c5dd8 | ok |
| 3 | 2020-04-30 00:36:38.961Z | bobs.bigwheel.local | zeek | zeek.client | pbeesly/dmevals | .ds-logs-zeek-default-2026.10.22-000001 / AaFiKZc9VXKkeByNi0EJ | q-a46d3c5dd8 | ok |

### F47 · benign / high · T1606 · No forged web credential activity; explicit-credential logons are PsExec remote administration

Evidence status: **verified**

Across windows.security, windows.sysmon, windows.powershell and windows.other (2020-05-02 02:55-03:28Z) there is no evidence of forged web credentials. The 15 event 4648 explicit-credential logons are a repeating administrative pattern: user pbeesly on scranton.dmevals.local (source 10.0.1.6) targeting server NASHUA, matched on nashua.dmevals.local by C:\Windows\PSEXESVC.exe logons for pbeesly to localhost, plus routine DWM-1/UMFD-0/UMFD-1/UMFD-2/SCRANTON$ winlogon/wininit/taskhostw self-logon events. 4624 logons use only Kerberos (217), Negotiate (78) and NTLM (1) with no anomalous authentication package. The single PowerShell 4104 hit matching 'token' is the SysinternalsSuite readme.ps1 script (win.Path C:\Program Files\SysinternalsSuite\readme.ps1) that enumerates SE_GROUP_* access-token attribute constants via Get-AttributesMask - token-attribute documentation, not credential forging. Rare process-access rights (0x1fffff, 0x1f3fff, 0x101541) belong to csrss.exe, services.exe, svchost.exe and wsmprovhost.exe against normal OS targets (svchost, conhost, wmiprvse, RuntimeBroker, taskhostw), i.e. standard OS/management behaviour.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:18.000Z | scranton.dmevals.local | windows.security | win.TargetServerName | NASHUA | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBunxq0T | q-583cf065e5 | ok |
| 2 | 2020-05-02 03:11:40.000Z | nashua.dmevals.local | windows.security | process.executable | C:\Windows\PSEXESVC.exe | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBuu5GRH | q-583cf065e5 | ok |
| 3 | 2020-05-02 03:20:46.000Z | scranton.dmevals.local | windows.security | win.TargetServerName | localhost | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBudppFX | q-ebc4b173be | ok |
| 4 | 2020-05-02 03:04:04.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\readme.ps1 | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByRaboq | q-d382914fbf | ok |
| 5 | 2020-05-02 03:04:04.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-AttributesMask($AttributesMask) {     &lt;#         SE_GROUP_MANDATORY          0x00000001  The group is mandatory.         SE_GROUP_ENABLED_BY_DEF… | .ds-logs-windows.powershell-default-2026.10.22-000001 / AaFiKJc9VXKkeByRaboq | q-d382914fbf | ok |

### F48 · benign / high · T1606.001 · Cookie-related artifacts are WebDAV DavSetCookie and a Windows INetCookies cache file, not forged browser cookies

Evidence status: **verified**

The only cookie-related events are (1) six 4688 process creations on scranton.dmevals.local by user pbeesly running 'rundll32.exe C:\windows\system32\davclnt.dll,DavSetCookie 192.168.0.4 http://192.168.0.4/webdav' between 03:08:50 and 03:10:23Z - the WebDAV client setting an authentication cookie for a WebDAV share, a normal Windows WebDAV access pattern; and (2) one Sysmon event 11 on scranton.dmevals.local at 03:21:05Z where C:\windows\System32\svchost.exe (SYSTEM) created C:\Windows\ServiceProfiles\LocalService\AppData\Local\Packages\warp_jit_db4a1097-b484-4973-bbf2-a04208ecd4d4\AC\INetCookies, a per-package WinINet cookie cache file. No browser cookie store (Cookies/Login Data/Local State) was created or accessed, and no PowerShell script block referenced cookies (C288 zero hits). Nothing indicates cookie theft or forgery.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:10:23.000Z | scranton.dmevals.local | windows.security | process.command_line | rundll32.exe C:\windows\system32\davclnt.dll,DavSetCookie 192.168.0.4 http://192.168.0.4/webdav | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBunxq22 | q-0a9955d83a | ok |
| 2 | 2020-05-02 03:10:23.000Z | scranton.dmevals.local | windows.security | user.name | pbeesly | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBunxq22 | q-0a9955d83a | ok |
| 3 | 2020-05-02 03:21:05.681Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Windows\ServiceProfiles\LocalService\AppData\Local\Packages\warp_jit_db4a1097-b484-4973-bbf2-a04208ecd4d4\AC\INetCookies | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBi-6ySm | q-bec431539b | ok |
| 4 | 2020-05-02 03:21:05.681Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\System32\svchost.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBi-6ySm | q-bec431539b | ok |

### F49 · benign / high · T1606.002 · No SAML token forging indicators; no ADFS/SAML artifacts or token-signing references

Evidence status: **verified**

No SAML/ADFS activity was observed. Searches for SAML/ADFS/NotOnOrAfter/token-signing in PowerShell script blocks (C292) and in windows.other messages (C293) returned zero hits, and no file creations matched saml/adfs names. 4624 logons on all four hosts use only Kerberos, Negotiate and NTLM authentication packages with no rare or forged-token package. The only external identity-related DNS lookups were login.live.com resolved by svchost.exe on scranton and nashua at 03:05:31-32Z, which is normal Windows consumer-account/telemetry behaviour, not SAML token issuance or forgery.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:31.948Z | scranton.dmevals.local | windows.sysmon | dns.question.name | login.live.com | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoJM2Xy | q-a5f37f4497 | ok |
| 2 | 2020-05-02 03:05:31.948Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\Windows\System32\svchost.exe | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJ5c9VXKkeBoJM2Xy | q-a5f37f4497 | ok |

### F50 · benign / high · T1621 · No MFA request generation observed; dsregcmd hits are routine Azure AD device registration

Evidence status: **verified**

The only T1621-relevant hits were 5 process creations of C:\Windows\System32\dsregcmd.exe on nashua.dmevals.local, scranton.dmevals.local and newyork.dmevals.local between 2020-05-02T03:06:14Z and 03:25:30Z. The full event for the nashua instance (03:25:30.859Z) shows the genuine Microsoft-signed binary (Company 'Microsoft Corporation', Description 'DSREG commandline tool', SHA256 4921B19D3C43CC0CF9921CC37AC0ADF10CEDF20C61AA52F7FC8BA6E717168635) launched as NT AUTHORITY\SYSTEM from svchost.exe -k netsvcs -p -s Schedule (Task Scheduler) with the standard placeholder command line 'C:\windows\System32\dsregcmd.exe $(Arg0) $(Arg1) $(Arg2)'. This is normal Azure AD/device-registration maintenance, not adversary-driven MFA prompt generation. No MFA/2FA/authenticator content was found in any PowerShell 4104 script block, no MFA-related messages in windows.other, no 4625 failures, and no command line referencing MFA, Connect-MsolService, login.microsoftonline or any identity provider. DNS/network activity to Microsoft endpoints was limited to routine telemetry (v10/v20.events.data.microsoft.com, watson.telemetry.microsoft.com, store-images.s-microsoft.com, checkappexec.microsoft.com, go.microsoft.com) from svchost.exe, WerFault.exe, BackgroundTransferHost.exe, smartscreen.exe and powershell.exe; no okta/duo/login endpoints were contacted. Separately, the same window contains clearly malicious pbeesly activity on nashua.dmevals.local (PSEXESVC-spawned C:\Windows\Temp\python.exe making hundreds of connections to 192.168.0.4:8443, plus sdelete64.exe wiping archives), but that is credential use/lateral movement, not MFA request generation.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:25:30.859Z | nashua.dmevals.local | windows.sysmon | process.command_line | C:\windows\System32\dsregcmd.exe $(Arg0) $(Arg1) $(Arg2) | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBi30BSA | q-fde6253da5 | ok |
| 2 | 2020-05-02 03:25:30.859Z | nashua.dmevals.local | windows.sysmon | process.parent.command_line | C:\windows\system32\svchost.exe -k netsvcs -p -s Schedule | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBi30BSA | q-fde6253da5 | ok |
| 3 | 2020-05-02 03:25:30.859Z | nashua.dmevals.local | windows.sysmon | win.Hashes | SHA1=D5C4637678805DAE0DC1054994682A8F09B41A4D,MD5=D92CE4EF92E2A72C5A151F3A6AC008C8,SHA256=4921B19D3C43CC0CF9921CC37AC0ADF10CEDF20C61AA52F7FC8BA6E717168635,IMPHA… | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBi30BSA | q-fde6253da5 | ok |
| 4 | 2020-05-02 03:25:30.859Z | nashua.dmevals.local | windows.sysmon | win.Company | Microsoft Corporation | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBi30BSA | q-fde6253da5 | ok |
| 5 | 2020-05-02 03:25:30.859Z | nashua.dmevals.local | windows.sysmon | user.name | SYSTEM | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBi30BSA | q-fde6253da5 | ok |
| 6 | 2020-05-02 03:25:35.000Z | nashua.dmevals.local | windows.sysmon | win.QueryName | v10.events.data.microsoft.com | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBi30BRX | q-4e6763d367 | ok |
| 7 | 2020-05-02 03:17:56.477Z | nashua.dmevals.local | windows.sysmon | destination.ip | 192.168.0.4 | .ds-logs-windows.sysmon-default-2026.10.22-000001 / AaFiJpc9VXKkeBnaX5as | q-d45ab94b54 | ok |

### F53 · benign / medium · T1649 · Kerberos TGT requests show only password pre-authentication (PreAuthType 2), no PKINIT certificate logons

Evidence status: **verified**

All 14 Kerberos TGT requests (event 4768) in the window, on newyork.dmevals.local, carry win.PreAuthType = 2 (password pre-authentication) — 9 for pbeesly from 10.0.1.4/10.0.1.6 and 5 for the SCRANTON$ machine account from 10.0.1.4. No PKINIT (PreAuthType 16) or certificate-based authentication was observed, so there is no evidence in this dataset that a stolen or forged certificate was used to obtain tickets. The remaining 4657 registry writes are WMI Autologger/EventLog-Application value changes by wevtutil.exe on scranton, unrelated to certificate stores.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:18.000Z | newyork.dmevals.local | windows.security | win.PreAuthType | 2 | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBuy-fsg | q-79a0372e66 | ok |
| 2 | 2020-05-02 03:19:13.000Z | newyork.dmevals.local | windows.security | win.TargetUserName | SCRANTON$ | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBus3Fam | q-79a0372e66 | ok |
| 3 | 2020-05-02 03:19:16.000Z | scranton.dmevals.local | windows.security | win.ObjectName | \REGISTRY\MACHINE\SYSTEM\ControlSet001\Control\WMI\Autologger\EventLog-Application\{498a78f0-d57b-488d-9666-b0e7f5473cd9} | .ds-logs-windows.security-default-2026.10.22-000001 / AaFiJ5c9VXKkeBuhtIn4 | q-e1ff22e2b6 | ok |

## Pivot candidates

Processes the pivot reviewer had to assess (started by a script host or from outside the Windows directory, rare in the 15-minute windows around verified activity).

| Host | Executable | Starts | Parents | Assessment | Reason |
|---|---|---|---|---|---|
| nashua.dmevals.local | C:\Program Files\WindowsApps\Microsoft.SkypeApp_14.35.152.0_x64__kzf8qxf38zg5c\S… | 1 | C:\Program Files\WindowsApps\Microsoft.SkypeApp_14.35.152.0_x64__kzf8qxf38zg5c\S… | benign | Store Skype app relaunching itself; no credential-store access, no files written, unrelated to the intrusion tooling. |
| nashua.dmevals.local | C:\Windows\Temp\python.exe | 5 | C:\Windows\PSEXESVC.exe, C:\Windows\Temp\python.exe | malicious | Five starts on nashua, four parented by C:\Windows\PSEXESVC.exe, i.e. pushed remotely by PsExec64.exe from scranton with the plaintext password Fl0nk3rt0n!T0by;… |
| nashua.dmevals.local | C:\Windows\Temp\Rar.exe | 1 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | malicious | Started by powershell.exe on nashua to password-protect (-hpfGzq5yKw) the archive of credential-named files collected from the user profile into Desktop\working… |
| nashua.dmevals.local | C:\Windows\Temp\sdelete64.exe | 3 | C:\Windows\System32\cmd.exe | malicious | Three runs on nashua under cmd.exe wiping C:\Windows\Temp\Rar.exe and both working.zip archives — anti-forensics covering the credential-file staging. |
| nashua.dmevals.local | C:\WindowsAzure\Packages\CollectGuestLogs.exe | 1 | C:\WindowsAzure\Packages\WaAppAgent.exe | benign | Azure guest agent diagnostic collection launched by WaAppAgent.exe; standard platform behaviour, no credential access. |
| newyork.dmevals.local | C:\Windows\System32\conhost.exe | 1 | C:\Windows\System32\dsregcmd.exe | benign | Console host for dsregcmd.exe on newyork; normal Windows component. |
| scranton.dmevals.local | C:\Packages\Plugins\Microsoft.Azure.NetworkWatcher.NetworkWatcherAgentWindows\1.… | 4 | C:\Windows\System32\cmd.exe, C:\Windows\System32\services.exe | benign | Azure Network Watcher extension binary started by services.exe/cmd.exe; platform monitoring, no credential activity. |
| scranton.dmevals.local | C:\Packages\Plugins\Microsoft.Azure.Security.IaaSAntimalware\1.5.5.9\Antimalware… | 1 | C:\WindowsAzure\Packages\GuestAgent\WindowsAzureGuestAgent.exe | benign | Azure antimalware extension configuration started by WindowsAzureGuestAgent.exe; expected platform component. |
| scranton.dmevals.local | C:\Packages\Plugins\Microsoft.Compute.CustomScriptExtension\1.10.5\bin\CustomScr… | 1 | C:\Windows\System32\cmd.exe | benign | Azure custom-script extension handler; standard guest-agent child, no credential access observed. |
| scranton.dmevals.local | C:\Packages\Plugins\Microsoft.Compute.JsonADDomainExtension\1.3.2\bin\JsonADDoma… | 1 | C:\Windows\System32\cmd.exe | benign | Azure domain-join extension handler; expected platform component. |
| scranton.dmevals.local | C:\Program Files (x86)\Google\Update\1.3.35.452\GoogleCrashHandler.exe | 2 | C:\Program Files (x86)\Google\Update\GoogleUpdate.exe | benign | Google Update crash handler child of GoogleUpdate.exe; routine updater activity. |
| scranton.dmevals.local | C:\Program Files (x86)\Google\Update\1.3.35.452\GoogleCrashHandler64.exe | 2 | C:\Program Files (x86)\Google\Update\GoogleUpdate.exe | benign | Google Update crash handler child of GoogleUpdate.exe; routine updater activity. |
| scranton.dmevals.local | C:\Program Files (x86)\Google\Update\GoogleUpdate.exe | 3 | C:\Program Files (x86)\Google\Update\GoogleUpdate.exe, C:\Windows\System32\servi… | benign | Google updater started by services.exe/svchost.exe; routine software update. |
| scranton.dmevals.local | C:\Program Files\SysinternalsSuite\accessChk.exe | 1 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | malicious | Run by powershell.exe on scranton at 03:04:34Z from a SysinternalsSuite downloaded minutes earlier; accesschk is used to enumerate permissions on credential-bea… |
| scranton.dmevals.local | C:\Program Files\SysinternalsSuite\PsExec64.exe | 4 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | malicious | Four runs from powershell.exe on scranton using explicit domain credentials (\\NASHUA -u dmevals\pbeesly -p Fl0nk3rt0n!T0by) to launch C:\Windows\Temp\python.ex… |
| scranton.dmevals.local | C:\Program Files\SysinternalsSuite\sdelete64.exe | 3 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | malicious | Three runs from powershell.exe on scranton wiping the fake .scr, Draft.Zip and SysinternalsSuite.zip — anti-forensics over the credential-access tooling. |
| scranton.dmevals.local | C:\Program Files\Windows Defender\MsMpEng.exe | 1 | C:\Windows\System32\services.exe | benign | Defender service binary started by services.exe; normal AV component. |
| scranton.dmevals.local | C:\Program Files\Windows Defender\NisSrv.exe | 2 | C:\Windows\System32\services.exe | benign | Defender network inspection service; normal AV component. |
| scranton.dmevals.local | C:\ProgramData\victim\â€®cod.3aka3.scr | 1 | C:\Windows\explorer.exe | malicious | Fake screen-saver in C:\ProgramData\victim launched by explorer.exe with /S; it opened cmd.exe and conhost.exe with 0x1fffff and spawned the PowerShell chain th… |
| scranton.dmevals.local | C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe | 2 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | malicious | Invoked twice by powershell.exe with @response files in C:\Users\pbeesly\AppData\Local\Temp\qkbkqqbs and 0piklvia, compiling qkbkqqbs.dll and 0piklvia.dll in te… |
| scranton.dmevals.local | C:\Windows\System32\hostui.exe | 1 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | malicious | Started by powershell.exe on scranton at 03:21:27Z; hostui.exe is the binary abused by the anchored StartUp hostui.lnk forced-authentication artifact, and it in… |
| scranton.dmevals.local | C:\Windows\System32\sdclt.exe | 3 | C:\Windows\System32\cmd.exe | suspicious | Three sdclt.exe launches from cmd.exe at 02:58:42Z, immediately followed by sdclt spawning control.exe with 0x1fffff and then the csc.exe compile — sdclt is a k… |
| scranton.dmevals.local | C:\WindowsAzure\Packages\GuestAgent\BfeToolWin8.exe | 1 | C:\WindowsAzure\Packages\GuestAgent\WindowsAzureGuestAgent.exe | benign | Azure guest agent firewall tool; platform component. |
| scranton.dmevals.local | C:\WindowsAzure\Packages\GuestAgent\FindVolume\FindVolume.exe | 1 | C:\WindowsAzure\Packages\GuestAgent\WindowsAzureGuestAgent.exe | benign | Azure guest agent volume discovery helper; platform component. |
| scranton.dmevals.local | C:\WindowsAzure\Packages\GuestAgent\WindowsAzureGuestAgent.exe | 1 | C:\Windows\System32\services.exe | benign | Azure guest agent service; platform component. |
| scranton.dmevals.local | C:\WindowsAzure\Packages\Telemetry\WindowsAzureTelemetryService.exe | 1 | C:\Windows\System32\services.exe | benign | Azure telemetry service; platform component. |
| scranton.dmevals.local | C:\WindowsAzure\Packages\WaAppAgent.exe | 1 | C:\Windows\System32\services.exe | benign | Azure agent host service; platform component. |
| scranton.dmevals.local | C:\WindowsAzure\SecAgent\WaSecAgentProv.exe | 2 | C:\WindowsAzure\Packages\WaAppAgent.exe | benign | Azure security agent provider; platform component. |
| scranton.dmevals.local | C:\WindowsAzure\WindowsAzureNetAgent_1.0.0.143\WindowsAzureNetAgent\Plugins\VFPl… | 1 | C:\WindowsAzure\WindowsAzureNetAgent_1.0.0.143\WindowsAzureNetAgent\WindowsAzure… | benign | Azure network agent plugin; platform component. |
| scranton.dmevals.local | C:\WindowsAzure\WindowsAzureNetAgent_1.0.0.143\WindowsAzureNetAgent\WindowsAzure… | 1 | C:\Windows\System32\services.exe | benign | Azure network agent service; platform component. |

## Technique conclusions

One line per technique in scope: status from the triage of its family; `not_observed` = checked, nothing found; `not_observable` = no dataset records it.

| Technique | Status | Reason |
|---|---|---|
| T1003 OS Credential Dumping | malicious | Credential-theft staging and anti-forensic cleanup on scranton/nashua (C:\ProgramData\victim\…cod.3aka3.scr, sdelete64 wiping of the payload and archives) surrounding the LSASS memory access. |
| T1003.001 LSASS Memory | malicious | PowerShell.exe (pbeesly, high integrity) opened lsass.exe with 0x1F3FFF/0x1FFFFF and read process memory (0x10) on scranton at 03:05:16; wsmprovhost.exe did the same with 0x1F3FFF on nashua at 03:09:29. |
| T1003.002 Security Account Manager | suspicious | Ten 4656 SAM_SERVER handle requests with AccessMask 0xf003f on scranton between 03:19:21Z and 03:20:46Z, concurrent with the anchored LSASS access and sdelete anti-forensics; requester is lsass.exe as SYSTEM, so no hive … |
| T1003.003 NTDS | not_observed | No ntdsutil/vssadmin/diskshadow/ntds.dit activity in process creation, file creation or PowerShell script blocks. |
| T1003.004 LSA Secrets | not_observed | No access to SECURITY\Policy\Secrets registry keys, no lsadump/secrets command lines and no SECURITY object access events. |
| T1003.005 Cached Domain Credentials | not_observed | No cached-credential (SECURITY hive / Cache) object access or lsadump cache commands were observed. |
| T1003.006 DCSync | benign | Only one 4662 DS Control Access event by machine account NEWYORK$ with mask 0x100; no DS-Replication-Get-Changes access, no drsuapi/DCSync tooling. |
| T1040 Network Sniffing | benign | Only packet-capture activity observed is netsh.exe 'trace start capture=yes' / 'trace stop' on scranton.dmevals.local, spawned as SYSTEM by the signed Azure Network Watcher Agent (NetworkWatcherAgent.exe) alongside Azure… |
| T1056 Input Capture | malicious | PowerShell.exe (PID 2976, SYSTEM) on scranton opened lsass.exe with 0x1F3FFF and 0x1FFFFF and UNKNOWN call-trace frames at 03:05:16Z, inside a broader hidden-PowerShell intrusion chain by pbeesly. |
| T1056.001 Keylogging | malicious | Invoke-ScreenCapture script block on scranton loops CopyFromScreen every 300s and saves BMPs to the user's Downloads; a .bmp file creation by powershell.exe corroborates execution. Screen-based capture, no keylogger APIs… |
| T1056.002 GUI Input Capture | suspicious | Three consent.exe UAC prompt creations exist and scranton shows a 'Start-Process hostui.exe -verb runas' elevation, but individual consent events were not retrieved, so a fake credential prompt is unconfirmed. |
| T1056.003 Web Portal Capture | not_observed | No inetpub/aspx file writes, no 4663 inetpub access, no HTTP POST; the only related hits were archive staging of *login*/*pass* files, which is collection not web-portal capture. |
| T1056.004 Credential API Hooking | malicious | lsass handles with near-full access from PowerShell on scranton (UNKNOWN call trace) and from wsmprovhost.exe on nashua (0x1F3FFF, UNKNOWN frames) indicate credential-API abuse; no MiniDump script block was logged. |
| T1110 Brute Force | not_observed | Zero 4625 failed logons in windows.security; the 15 4648 events are pbeesly's own explicit-credential logons plus normal winlogon/wininit/taskhostw machine-account logons. No brute-force tooling in process command lines. |
| T1110.001 Password Guessing | not_observed | No failed authentication attempts at all (4625 count 0); PowerShell 'Password' hits are certificate export and 7-Zip archive passwords, not guessing loops. |
| T1110.002 Password Cracking | suspicious | No offline cracking tooling or NTDS/SAM hive dumps were seen, but on scranton.dmevals.local hidden PowerShell PID 2976 (spawned by control.exe, shellcode stager) opened lsass.exe with 0x1f3fff and 0x1fffff — the credenti… |
| T1110.003 Password Spraying | not_observed | No 4625 failures and no multi-account authentication from a single source; pbeesly's 4648s are one account reused via PSEXESVC.exe on nashua.dmevals.local (lateral movement), not a spray. |
| T1110.004 Credential Stuffing | not_observed | No failed logons and no username/password list replay scripts; password strings found in script blocks belong to cert export and archive compression. |
| T1111 Multi-Factor Authentication Interception | not_observed | No smartcard/MFA tooling or interception artifacts; lsass access and 4648 logons are credential theft/reuse and exfiltration. |
| T1187 Forced Authentication | malicious | On scranton.dmevals.local, PowerShell (user pbeesly) hijacked HKCU\Software\Classes\Folder\shell\open\command with a hidden -ep bypass PowerShell payload and dropped hostui.lnk into the all-users StartUp folder via Invok… |
| T1212 Exploitation for Credential Access | malicious | On scranton.dmevals.local a hidden, execution-policy-bypassing PowerShell (PID 2976, child of control.exe, running as DMEVALS\pbeesly at High integrity) opened lsass.exe with GrantedAccess 0x1F3FFF and 0x1FFFFF at 03:05:… |
| T1539 Steal Web Session Cookie | not_observed | No event shows a browser cookie/session store being read or copied by a non-browser process. Cookie-related hits resolve to Windows Search indexing (SearchProtocolHost.exe under SearchIndexer.exe), substring matches on l… |
| T1552 Unsecured Credentials | suspicious | accesschk.exe created C:\Program Files\SysinternalsSuite\passwordsDB inside the malicious pbeesly session; content unverified, other hits are OS noise. |
| T1552.001 Credentials In Files | malicious | PowerShell on nashua enumerated the user profile for *pass*/*psw*/*login*/*vpn*/*.pst/*.txt/*.lnk files and compressed them to working.zip, then Rar.exe password-protected the archive and sdelete64 wiped it; on scranton … |
| T1552.002 Credentials in Registry | not_observed | Only OS-generated registry writes to Credential/Password paths; no reg query/save or SAM/SECURITY access. |
| T1552.003 Shell History | not_observed | No ConsoleHost_history, Get-History or PSReadline references in sysmon or PowerShell logs. |
| T1552.004 Private Keys | malicious | Get-PrivateKeys exported LocalMachine certificates to .pfx with hardcoded password saribas; coyn5igj.3io.pfx created on scranton. |
| T1552.006 Group Policy Preferences | not_observed | No Groups.xml/cpassword/SYSVOL/gpp references; only normal gpt.ini Group Policy processing. |
| T1555 Credentials from Password Stores | malicious | pbeesly's interactive PowerShell (PID 2976) on scranton.dmevals.local opened lsass.exe with 0x1F3FFF and 0x1FFFFF at 03:05:16Z, corroborated by Security 4663, inside a full intrusion chain (registry hijack, shellcode loa… |
| T1555.003 Credentials from Web Browsers | benign | Only a benign LocalService INetCookies file creation by svchost.exe; no Login Data, logins.json or Local State access by any process, and no browser credential-store references in process creation, 4663 or PowerShell log… |
| T1555.004 Windows Credential Manager | benign | No cmdkey/vault/credman execution, no registry or file events on Vault/Microsoft\Protect; the only 'Credential' hits were a Credential Guard status message and a PSCredential object used for the WebDAV exfil drive. |
| T1555.005 Password Managers | not_observed | All password-manager checks (process creation, process access, file creation, 4688, 4104, windows.other) returned zero hits across all four hosts. |
| T1556 Modify Authentication Process | suspicious | PowerShell.exe (PID 2976) on scranton opened lsass.exe with 0x1F3FFF/0x1FFFFF and an UNKNOWN call-trace frame at 03:05:16, in the same pbeesly session that ran Get-Keystrokes and Invoke-Exfil; no persistent authenticatio… |
| T1556.001 Domain Controller Authentication | benign | All lsass accesses on scranton trace to Windows components (wininit, csrss, services, svchost/lsm.dll, Azure telemetry via CorperfmonExt.dll); no 4657/4739/5136 authentication changes. |
| T1556.002 Password Filter DLL | benign | Only Microsoft cryptdll/samlib/samcli DLL loads by normal processes; no Notification Packages registry write, no PasswordFilter DLL, no 4657 on LSA objects. |
| T1556.005 Reversible Encryption | benign | The single Set-ADUser script-block hit is the Microsoft xActiveDirectory DSC module help text on newyork; no 4739 events or reversible-encryption commands. |
| T1556.006 Multi-Factor Authentication | not_observed | No MFA/authentication-policy modification events (4739 query returned zero hits). |
| T1556.007 Hybrid Identity | not_observed | No 5136 directory-object modifications; only routine dsregcmd.exe activity on newyork. |
| T1556.008 Network Provider DLL | not_observed | No 4657 events for NetworkProvider/Winlogon/Credential objects; retrieved Winlogon/Lsa registry writes are routine system values. |
| T1557 Adversary-in-the-Middle | benign | No interception/relay infrastructure: single NTLM type-3 logon for pbeesly on scranton tied to concurrent PsExec service installs; all 4697 service installs are pbeesly PSEXESVC/javamtsup or per-user svchost services; ze… |
| T1557.001 Name Resolution Poisoning and SMB Relay | benign | Only two unanswered NetBIOS name queries to 10.0.1.255 (S0); all DNS answers come from the legitimate DC 10.0.0.4; no Responder/Inveigh/LLMNR script blocks or EnableMulticast registry changes; SMB sessions are Kerberos/G… |
| T1557.002 ARP Cache Poisoning | benign | No ARP manipulation: ipconfig/route executions on scranton are read-only commands spawned by Azure guest/telemetry agents; no arp/netsh PowerShell; no host mediating traffic between many peers in zeek. |
| T1557.003 DHCP Spoofing | benign | No DHCP server/lease events (1341/1342/1020/1063) and no dhcp-related PowerShell; DNS/DHCP resolution stays with the legitimate DC 10.0.0.4. |
| T1558 Steal or Forge Kerberos Tickets | not_observed | 326 lsass process-access events are dominated by svchost.exe/AntimalwareConfig.exe/WindowsAzureTelemetryService.exe with 0x1000/0x1400; the 5 full-access grants (powershell.exe on scranton, wsmprovhost.exe on nashua) hav… |
| T1558.001 Golden Ticket | not_observed | No krbtgt/golden references in PowerShell (0 hits), no KRBTGT hash extraction from lsass, and krbtgt/DMEVALS.LOCAL TGS requests are the normal renewal pair following a successful preauthenticated AS-REP. 4672 privileged … |
| T1558.002 Silver Ticket | not_observed | Only 11 TGS requests, all from pbeesly/DMEVALS.LOCAL, to 5 distinct services spread over 16 minutes - ordinary SMB/LDAP/HTTP access. No silver/service-ticket strings in PowerShell and no service-account hash harvesting f… |
| T1558.003 Kerberoasting | not_observed | No SPN/Kerberoast strings in any 4104 script block (0 hits) and no burst of TGS requests for many SPNs. pbeesly's Kerberos type-3 logons to newyork/nashua from 10.0.1.4 reflect lateral movement from the compromised scran… |
| T1558.004 AS-REP Roasting | not_observed | All 7 AS-REQ events with errors are KDC_ERR_PREAUTH_REQUIRED, each followed within milliseconds by a successful AS-REP - normal preauthentication. No ASREP/GetNPUsers/preauth strings in PowerShell or sysmon command lines… |
| T1606 Forge Web Credentials | not_observed | No forged web credential activity. 4648 explicit-credential logons are PsExec administration (scranton pbeesly -> NASHUA, PSEXESVC.exe) plus routine winlogon/wininit/taskhostw self-logon events; 4624 logons use only Kerb… |
| T1606.001 Web Cookies | not_observed | Only cookie artifacts are WebDAV DavSetCookie rundll32 invocations by pbeesly against http://192.168.0.4/webdav and a svchost-created INetCookies cache file under a LocalService package profile. No browser cookie store a… |
| T1606.002 SAML Tokens | not_observed | Zero hits for SAML/ADFS/NotOnOrAfter/token-signing in PowerShell script blocks and windows.other messages; no SAML/ADFS file artifacts; authentication packages limited to Kerberos/Negotiate/NTLM. Only identity DNS was lo… |
| T1621 Multi-Factor Authentication Request Generatio… | not_observed | No MFA/2FA request generation activity in any dataset. The only related hits were 5 legitimate Microsoft-signed dsregcmd.exe executions by NT AUTHORITY\SYSTEM from svchost.exe (Task Scheduler) for Azure AD device registr… |
| T1649 Steal or Forge Authentication Certificates | malicious | On scranton.dmevals.local, user pbeesly ran a PowerShell Get-PrivateKeys function that enumerated cert:\LocalMachine and exported every certificate with Export-PfxCertificate to a password-protected .pfx ("saribas"); Sys… |

## Context (outside the hypothesis)

Activity reported under techniques outside the hypothesis' scope. Not verified, not part of the verdict.

- T1074 · malicious/high · Password-protected RAR archive of collected credential files created and then wiped with sdelete64 on NASHUA (pivot)
- T1074 · malicious/high · Password-protected RAR archive of collected credential files created and then wiped with sdelete64 on NASHUA (pivot)
- T1027 · malicious/medium · PowerShell-driven csc.exe compilation of DLL payloads in the user Temp directory on SCRANTON (pivot)
- T1218 · suspicious/low · sdclt.exe launched from cmd.exe and spawning control.exe with full access before the payload compile on SCRANTON (pivot)

## Coverage

Cells: number of hits of the planned checks, `n/a` (reason in report.json), or GAP.

| Technique | windows.other | windows.powershell | windows.security | windows.sysmon | zeek |
|---|---|---|---|---|---|
| T1003 OS Credential Dumping | 5 hits | 0 hits | 5797 hits | 40056 hits | n/a |
| T1003.001 LSASS Memory | 5 hits | 0 hits | 116 hits | 656 hits | n/a |
| T1003.002 Security Account Manager | n/a | 0 hits | 6 hits | 10 hits | n/a |
| T1003.003 NTDS | 5 hits | 0 hits | 0 hits | 0 hits | n/a |
| T1003.004 LSA Secrets | n/a | 0 hits | 0 hits | 513 hits | n/a |
| T1003.005 Cached Domain Credentials | n/a | 0 hits | 0 hits | 6955 hits | n/a |
| T1003.006 DCSync | 5 hits | 0 hits | 15 hits | 0 hits | n/a |
| T1040 Network Sniffing | 5 hits | 0 hits | 2 hits | 0 hits | 2140 hits |
| T1056 Input Capture | 5 hits | 0 hits | 19 hits | 652 hits | n/a |
| T1056.001 Keylogging | 5 hits | 0 hits | 19 hits | 353 hits | n/a |
| T1056.002 GUI Input Capture | 5 hits | 15 hits | 3 hits | 3 hits | n/a |
| T1056.003 Web Portal Capture | 5 hits | 2 hits | 0 hits | 0 hits | 62 hits |
| T1056.004 Credential API Hooking | 0 hits | 0 hits | 6 hits | 655 hits | n/a |
| T1110 Brute Force | 0 hits | 4 hits | 15 hits | 30 hits | n/a |
| T1110.001 Password Guessing | 0 hits | 2 hits | 0 hits | 447 hits | n/a |
| T1110.002 Password Cracking | 1 hits | 0 hits | 10 hits | 326 hits | n/a |
| T1110.003 Password Spraying | 2 hits | 0 hits | 15 hits | 0 hits | n/a |
| T1110.004 Credential Stuffing | 2 hits | 0 hits | 218 hits | 0 hits | n/a |
| T1111 Multi-Factor Authentication Interception | 2 hits | 3 hits | 312 hits | 338 hits | n/a |
| T1187 Forced Authentication | 1 hits | 2 hits | 11145 hits | 3 hits | 86 hits |
| T1212 Exploitation for Credential Access | 0 hits | 0 hits | 42 hits | 327 hits | 14 hits |
| T1539 Steal Web Session Cookie | 3 hits | 13 hits | 4 hits | 162 hits | 2 hits |
| T1552 Unsecured Credentials | 2 hits | 2 hits | 0 hits | 19 hits | 0 hits |
| T1552.001 Credentials In Files | 0 hits | 1 hits | 15 hits | 73 hits | 2 hits |
| T1552.002 Credentials in Registry | n/a | 12 hits | 0 hits | 17 hits | n/a |
| T1552.003 Shell History | n/a | 0 hits | n/a | 0 hits | n/a |
| T1552.004 Private Keys | n/a | n/a | 0 hits | 1 hits | n/a |
| T1552.006 Group Policy Preferences | n/a | 0 hits | 0 hits | 0 hits | n/a |
| T1555 Credentials from Password Stores | n/a | 3 hits | 6 hits | 652 hits | n/a |
| T1555.003 Credentials from Web Browsers | n/a | 0 hits | 0 hits | 1 hits | n/a |
| T1555.004 Windows Credential Manager | 2 hits | 3 hits | 0 hits | 652 hits | n/a |
| T1555.005 Password Managers | 0 hits | 0 hits | 0 hits | 0 hits | n/a |
| T1556 Modify Authentication Process | 0 hits | 0 hits | 0 hits | 731 hits | n/a |
| T1556.001 Domain Controller Authentication | 0 hits | 0 hits | 530 hits | 359 hits | n/a |
| T1556.002 Password Filter DLL | 5 hits | 0 hits | 0 hits | 34 hits | n/a |
| T1556.005 Reversible Encryption | 0 hits | 5495 hits | 0 hits | 0 hits | n/a |
| T1556.006 Multi-Factor Authentication | 9 hits | 1 hits | 0 hits | 2 hits | n/a |
| T1556.007 Hybrid Identity | 17 hits | 1 hits | 0 hits | 2 hits | n/a |
| T1556.008 Network Provider DLL | 9 hits | 3 hits | 0 hits | 20183 hits | n/a |
| T1557 Adversary-in-the-Middle | 9 hits | 0 hits | 10977 hits | 1310 hits | 50 hits |
| T1557.001 Name Resolution Poisoning and SMB Relay | 9 hits | 0 hits | 23 hits | 0 hits | 52 hits |
| T1557.002 ARP Cache Poisoning | 9 hits | 0 hits | 10977 hits | 1310 hits | 613 hits |
| T1557.003 DHCP Spoofing | 0 hits | 0 hits | 297 hits | 6 hits | n/a |
| T1558 Steal or Forge Kerberos Tickets | 5 hits | 0 hits | 448 hits | 652 hits | 70 hits |
| T1558.001 Golden Ticket | 5 hits | 0 hits | 448 hits | 326 hits | 42 hits |
| T1558.002 Silver Ticket | 5 hits | 0 hits | 448 hits | 326 hits | 70 hits |
| T1558.003 Kerberoasting | 5 hits | 0 hits | 509 hits | 326 hits | 22 hits |
| T1558.004 AS-REP Roasting | 5 hits | 0 hits | 297 hits | 0 hits | 21 hits |
| T1606 Forge Web Credentials | 0 hits | 1 hits | 609 hits | 39283 hits | n/a |
| T1606.001 Web Cookies | 0 hits | 0 hits | 15 hits | 2 hits | n/a |
| T1606.002 SAML Tokens | 0 hits | 0 hits | 312 hits | 39283 hits | n/a |
| T1621 Multi-Factor Authentication Request Generatio… | 0 hits | 0 hits | 0 hits | 447 hits | n/a |
| T1649 Steal or Forge Authentication Certificates | 0 hits | 1 hits | 100 hits | 1 hits | n/a |

Cells: 265, gaps: 0.

## Queries

Every MCP tool call of this run (1214), in order (source: mcp_audit.jsonl written by the MCP server).

| Query | Phase | Tool | Arguments | Hits / rows | Cited by |
|---|---|---|---|---|---|
| q-8bd432f4e1 | scope | list_data_sources | {} | None |  |
| q-bf6f13d5de | scope | get_registry | {} | None |  |
| q-65deb2722e | scope | get_fields | {"dataset": "windows.other", "prefix": ""} | None |  |
| q-faf885a4d1 | scope | get_fields | {"dataset": "windows.powershell", "prefix": ""} | None |  |
| q-15a81c501e | scope | get_fields | {"dataset": "windows.security", "prefix": ""} | None |  |
| q-935866b71a | scope | get_fields | {"dataset": "windows.sysmon", "prefix": ""} | None |  |
| q-3dff23d3ac | scope | get_fields | {"dataset": "zeek", "prefix": ""} | None |  |
| q-5d338d7333 | check C001 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 447 |  |
| q-4f81034167 | check C002 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 39283 |  |
| q-aa71d96470 | check C003 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 326 |  |
| q-c2ea54887c | check C004 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 5337 |  |
| q-b5500b091a | check C005 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 460 |  |
| q-7747ce849d | check C006 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*MiniDump* OR win.ScriptBlockText:*comsvcs* OR win.ScriptBlockText:*mimikatz* OR win.ScriptBlockText:*sekurlsa*)", "time_from": null, "time_to":… | 0 |  |
| q-598abf081e | check C007 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-ba356c0e21 | check C008 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass.exe*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.comman… | 326 |  |
| q-5fe475108c | check C009 | aggregate | {"dataset": "windows.sysmon", "field": "win.SourceImage", "query": "event.code:10 AND win.TargetImage:*lsass.exe*", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 326 |  |
| q-e66ff6288d | check C010 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*lsass* OR process.command_line:*MiniDump* OR process.command_line:*comsvcs* OR process.command_line:*procdump*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host… | 1 |  |
| q-37687e863a | check C011 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (win.TargetFilename:*.dmp OR win.TargetFilename:*lsass*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process… | 2 |  |
| q-93ab98a99b | check C012 | search | {"dataset": "windows.sysmon", "query": "event.code:7 AND win.ImageLoaded:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_lin… | 1 |  |
| q-19ca81c179 | check C013 | search | {"dataset": "windows.security", "query": "event.code:4673 AND (win.ProcessName:*lsass* OR win.ObjectName:*lsass*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.… | 103 |  |
| q-0e45e81634 | check C014 | search | {"dataset": "windows.security", "query": "event.code:4656 AND win.ObjectName:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command… | 13 |  |
| q-b386788a42 | check C015 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*MiniDump* OR win.ScriptBlockText:*sekurlsa*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "even… | 0 |  |
| q-ad6e4037e1 | check C016 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-1b7d350a26 | check C017 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*reg\\ save* OR process.command_line:*reg\\ export* OR process.command_line:*SAM* OR process.command_line:*SECURITY*)", "time_from": null, "time_to": null, "fields": ["@timestamp", … | 0 |  |
| q-ba217b4068 | check C018 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (win.TargetFilename:*SAM* OR win.TargetFilename:*SECURITY* OR win.TargetFilename:*SYSTEM* OR win.TargetFilename:*.hiv*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "obser… | 3 |  |
| q-3319fd4240 | check C019 | search | {"dataset": "windows.sysmon", "query": "event.code:2 AND (win.TargetFilename:*SAM* OR win.TargetFilename:*SECURITY*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "proce… | 0 |  |
| q-1eca508498 | check C020 | aggregate | {"dataset": "windows.sysmon", "field": "registry.path", "query": "event.code:13 AND (registry.path:*SAM* OR registry.path:*SECURITY*)", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 7 |  |
| q-b5af41997d | check C021 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND (process.command_line:*reg* OR process.command_line:*SAM* OR process.command_line:*SECURITY*)", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 6 |  |
| q-dbcd22094c | check C022 | search | {"dataset": "windows.security", "query": "event.code:4663 AND (win.ObjectName:*SAM* OR win.ObjectName:*SECURITY*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.… | 0 |  |
| q-2f79fd48e2 | check C023 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*reg\\ save* OR win.ScriptBlockText:*SAM* OR win.ScriptBlockText:*SECURITY*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "even… | 0 |  |
| q-772d7835b9 | check C024 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*ntds* OR process.command_line:*vssadmin* OR process.command_line:*ntdsutil* OR process.command_line:*diskshadow*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "ho… | 0 |  |
| q-e30adeba06 | check C025 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (win.TargetFilename:*ntds.dit* OR win.TargetFilename:*.dit*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "pro… | 0 |  |
| q-22e70b5cfa | check C026 | search | {"dataset": "windows.sysmon", "query": "event.code:2 AND win.TargetFilename:*ntds.dit*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.comma… | 0 |  |
| q-6209bc6e7e | check C027 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND (process.command_line:*ntds* OR process.command_line:*vssadmin* OR process.command_line:*diskshadow*)", "time_from": null, "time_to": null, "size": 100, "sub_field": n… | 0 |  |
| q-c19592836f | check C028 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-47e24edc68 | check C029 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*ntds* OR win.ScriptBlockText:*vssadmin* OR win.ScriptBlockText:*diskshadow*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "eve… | 0 |  |
| q-3d397220cb | check C030 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND (win.TargetImage:*lsass.exe* OR win.TargetImage:*services.exe*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "… | 506 |  |
| q-244569bc1a | check C031 | aggregate | {"dataset": "windows.sysmon", "field": "registry.path", "query": "event.code:13 AND registry.path:*SECURITY*Policy*Secrets*", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-e2e873d0b1 | check C032 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*secrets* OR process.command_line:*lsadump* OR process.command_line:*reg\\ save*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event… | 0 |  |
| q-785f93fbda | check C033 | search | {"dataset": "windows.sysmon", "query": "event.code:7 AND (win.ImageLoaded:*lsass* OR win.ImageLoaded:*vault*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.exec… | 7 |  |
| q-b5fce8d34a | check C034 | search | {"dataset": "windows.security", "query": "event.code:4663 AND win.ObjectName:*SECURITY*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.comm… | 0 |  |
| q-4aacd1c0ce | check C035 | search | {"dataset": "windows.security", "query": "event.code:4656 AND win.ObjectName:*SECURITY*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.comm… | 0 |  |
| q-b8f08bae05 | check C036 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*lsadump* OR win.ScriptBlockText:*Secrets* OR win.ScriptBlockText:*lsass*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.… | 0 |  |
| q-ea6b47e66e | check C037 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass.exe*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.comman… | 326 |  |
| q-03f85c9b8f | check C038 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*cache* OR process.command_line:*dcc* OR process.command_line:*lsadump* OR process.command_line:*mimikatz*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name… | 4 |  |
| q-4308a3cfdc | check C039 | aggregate | {"dataset": "windows.sysmon", "field": "registry.path", "query": "event.code:13 AND (registry.path:*Cache* OR registry.path:*SECURITY*)", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 6625 |  |
| q-a9c50046be | check C040 | search | {"dataset": "windows.security", "query": "event.code:4663 AND (win.ObjectName:*SECURITY* OR win.ObjectName:*Cache*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "proces… | 0 |  |
| q-042ccc5425 | check C041 | search | {"dataset": "windows.security", "query": "event.code:4656 AND (win.ObjectName:*SECURITY* OR win.ObjectName:*Cache*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "proces… | 0 |  |
| q-3277814284 | check C042 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*lsadump* OR win.ScriptBlockText:*cache* OR win.ScriptBlockText:*lsass*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.da… | 0 |  |
| q-c0f0b0308c | check C043 | count | {"dataset": "windows.security", "query": "event.code:4662", "time_from": null, "time_to": null} | 7 |  |
| q-0e15f12e97 | check C044 | aggregate | {"dataset": "windows.security", "field": "win.Properties", "query": "event.code:4662", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 7 |  |
| q-5c90914272 | check C045 | search | {"dataset": "windows.security", "query": "event.code:4662 AND win.Properties:*1131f6aa*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.comm… | 1 |  |
| q-c5f42484a1 | check C046 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*drsuapi* OR process.command_line:*lsadump* OR process.command_line:*dcsync*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-a04197c006 | check C047 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*DCSync* OR win.ScriptBlockText:*lsadump* OR win.ScriptBlockText:*Invoke-Mimikatz* OR win.ScriptBlockText:*DRSUAPI*)", "time_from": null, "time_to": null, "fields": ["@timesta… | 0 |  |
| q-16563785ca | check C048 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-80f55832ce | check C049 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND (process.command_line:*pktmon* OR process.command_line:*netsh* OR process.command_line:*windump* OR process.command_line:*tcpdump* OR process.command_line:*rawcap*)", … | 2 |  |
| q-7bb76b470f | check C050 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*pktmon* OR process.command_line:*windump* OR process.command_line:*tcpdump* OR process.command_line:*rawcap* OR process.command_line:*netsh\\ capture… | 0 |  |
| q-110f970ed2 | check C051 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND process.command_line:*pktmon*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.comma… | 0 |  |
| q-0f7fbc0001 | check C052 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-1f72e428e5 | check C053 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*pktmon* OR win.ScriptBlockText:*NetEventSession* OR win.ScriptBlockText:*netsh* OR win.ScriptBlockText:*capture*)", "time_from": null, "time_to": null, "fields": ["@timestamp… | 0 |  |
| q-833d8b3533 | check C054 | aggregate | {"dataset": "zeek", "field": "event.action", "query": "*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 2140 |  |
| q-e4aa5665b6 | check C055 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass.exe", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-c881e9e23c | check C056 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND win.TargetImage:*lsass.exe", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-9a3b2a5047 | check C057 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4656 AND win.ObjectName:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 13 |  |
| q-be17e7e19d | check C058 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4663 AND win.ObjectName:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 6 |  |
| q-61f4554208 | check C059 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*GetAsyncKeyState* OR win.ScriptBlockText:*SetWindowsHookEx* OR win.ScriptBlockText:*keylog*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "obse… | 0 |  |
| q-1e17a1a768 | check C060 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-c76813d474 | check C061 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND win.TargetImage:*lsass.exe", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-3a00936c53 | check C062 | search | {"dataset": "windows.sysmon", "query": "event.code:13 AND (registry.path:*Keyboard* OR registry.path:*keylog* OR registry.path:*CurrentVersion\\\\Run*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset"… | 27 |  |
| q-12f7f8e8e8 | check C063 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4656 AND (win.ObjectName:*lsass* OR win.ObjectName:*Keyboard*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 13 |  |
| q-36542fbc9e | check C064 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4663 AND (win.ObjectName:*lsass* OR win.ObjectName:*Keyboard*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 6 |  |
| q-9245f2ae0e | check C065 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-97e3781996 | check C066 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*GetAsyncKeyState* OR win.ScriptBlockText:*SetWindowsHookEx* OR win.ScriptBlockText:*keylog*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "obse… | 0 |  |
| q-7fdb7a04b5 | check C067 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*Credential* OR process.command_line:*prompt* OR process.command_line:*consent*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 3 |  |
| q-bb4268eb68 | check C068 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*CredentialUI* OR win.ScriptBlockText:*Get-Credential* OR win.ScriptBlockText:*Windows.Forms* OR win.ScriptBlockText:*ShowDialog*)", "time_from": null, "time_to": null, "field… | 2 |  |
| q-a811d12f80 | check C069 | search | {"dataset": "windows.powershell", "query": "event.code:4103 AND (win.Payload:*Credential* OR win.Payload:*ShowDialog*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "pro… | 13 |  |
| q-79ddb0c2ed | check C070 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND (process.command_line:*Credential* OR process.command_line:*consent*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 3 |  |
| q-f96eb36c37 | check C071 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-443726b934 | check C072 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND (win.TargetFilename:*\\\\inetpub\\\\* OR win.TargetFilename:*.aspx OR win.TargetFilename:*.asp OR win.TargetFilename:*.php)", "time_from": null, "time_to": null, "size": 5… | 0 |  |
| q-860b2b0dee | check C073 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND win.TargetFilename:*\\\\inetpub\\\\*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "proce… | 0 |  |
| q-267a724636 | check C074 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*inetpub* OR win.ScriptBlockText:*login* OR win.ScriptBlockText:*password*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event… | 2 |  |
| q-8a5a342f81 | check C075 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND win.ObjectName:*inetpub*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-a8b1721c61 | check C076 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-f05f2c4020 | check C077 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-972753764b | check C078 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-e53b7afdde | check C079 | search | {"dataset": "windows.sysmon", "query": "event.code:8 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_lin… | 2 |  |
| q-31c11f7607 | check C080 | search | {"dataset": "windows.sysmon", "query": "event.code:7 AND win.ImageLoaded:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_lin… | 1 |  |
| q-14325f1bea | check C081 | search | {"dataset": "windows.security", "query": "event.code:4663 AND win.ObjectName:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command… | 6 |  |
| q-4146829bad | check C082 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND win.ScriptBlockText:*MiniDump*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "proce… | 0 |  |
| q-c4e1e202a1 | check C083 | search | {"dataset": "windows.other", "query": "message:*lsass* OR win.ImagePath:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line… | 0 |  |
| q-d153ef16ed | check C084 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-48e18a483e | check C085 | aggregate | {"dataset": "windows.security", "field": "source.ip", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-29d59a32a5 | check C086 | timeline | {"dataset": "windows.security", "query": "event.code:4625", "interval": "1m", "time_from": null, "time_to": null} | 0 |  |
| q-6c1484888e | check C087 | search | {"dataset": "windows.security", "query": "event.code:4648", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 15 | F10 |
| q-9b125fa3cb | check C088 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*net* OR process.command_line:*password*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 30 |  |
| q-cf56c3d08d | check C089 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Password* OR win.ScriptBlockText:*Credential*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "us… | 4 | F14 |
| q-7af4fe3bc5 | check C090 | search | {"dataset": "windows.other", "query": "message:*logon* AND message:*fail*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "so… | 0 |  |
| q-35c88db5d6 | check C091 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-f10192ad4d | check C092 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 0 |  |
| q-e16831f20c | check C093 | timeline | {"dataset": "windows.security", "query": "event.code:4625", "interval": "1m", "time_from": null, "time_to": null} | 0 |  |
| q-0b2b1d00be | check C094 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Login* OR win.ScriptBlockText:*Password*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.na… | 2 | F11 |
| q-21c30d2716 | check C095 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*runas* OR process.command_line:*net\\\\ use*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name… | 447 |  |
| q-afcbe88dc8 | check C096 | search | {"dataset": "windows.other", "query": "message:*password*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 0 |  |
| q-a302ac25d1 | check C097 | search | {"dataset": "windows.security", "query": "event.code:4663 AND (win.ObjectName:*SAM* OR win.ObjectName:*SECURITY* OR win.ObjectName:*NTDS*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code… | 0 |  |
| q-2fe73ed15d | check C098 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4656 AND (win.ObjectName:*SAM* OR win.ObjectName:*NTDS*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 10 |  |
| q-d403d3c926 | check C099 | search | {"dataset": "windows.security", "query": "event.code:4670 AND (win.ObjectName:*SAM* OR win.ObjectName:*SECURITY*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.… | 0 |  |
| q-940d026e20 | check C100 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*sam* OR process.command_line:*ntds* OR process.command_line:*reg save*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-59e8420f79 | check C101 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (win.TargetFilename:*SAM* OR win.TargetFilename:*NTDS.dit* OR win.TargetFilename:*.hive*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "e… | 0 |  |
| q-8c17874a17 | check C102 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-92889fe9bd | check C103 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*ntds* OR win.ScriptBlockText:*Invoke-Mimikatz* OR win.ScriptBlockText:*DumpCreds*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name"… | 0 |  |
| q-dd29bb359b | check C104 | search | {"dataset": "windows.other", "query": "message:*ntds* OR message:*SAM*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "sourc… | 1 |  |
| q-b7ee4a5c8f | check C105 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-27b67e3f01 | check C106 | aggregate | {"dataset": "windows.security", "field": "source.ip", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-a8ed39e970 | check C107 | search | {"dataset": "windows.security", "query": "event.code:4648", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 15 | F13 |
| q-31c93bca8f | check C108 | timeline | {"dataset": "windows.security", "query": "event.code:4625", "interval": "5m", "time_from": null, "time_to": null} | 0 |  |
| q-d5d48b1df5 | check C109 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*foreach* AND win.ScriptBlockText:*Credential*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "us… | 0 |  |
| q-47b3233b5e | check C110 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*net\\\\ use* OR process.command_line:*Invoke-Command*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "… | 0 |  |
| q-7237ce5ad6 | check C111 | search | {"dataset": "windows.other", "query": "message:*logon*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 2 |  |
| q-54700d614a | check C112 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-fecd5a8e3f | check C113 | aggregate | {"dataset": "windows.security", "field": "source.ip", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-83703aab71 | check C114 | search | {"dataset": "windows.security", "query": "event.code:4624 AND win.LogonType:3", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line",… | 218 |  |
| q-2259ed5f11 | check C115 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*username* AND win.ScriptBlockText:*password*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "use… | 0 |  |
| q-fb4bb977b2 | check C116 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*password* OR process.command_line:*credential*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.na… | 0 |  |
| q-0eded7e082 | check C117 | search | {"dataset": "windows.other", "query": "message:*fail*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinati… | 2 |  |
| q-b99aef6bc6 | check C118 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 297 |  |
| q-82d8ef19a4 | check C119 | search | {"dataset": "windows.security", "query": "event.code:4648", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 15 |  |
| q-efef7df839 | check C120 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 326 |  |
| q-e6554ab8ac | check C121 | aggregate | {"dataset": "windows.sysmon", "field": "registry.path", "query": "event.code:13 AND (registry.path:*SmartCard* OR registry.path:*SCard* OR registry.path:*Credential*)", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 12 |  |
| q-e0f93a8221 | check C122 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*SmartCard* OR win.ScriptBlockText:*SCard* OR win.ScriptBlockText:*Credential*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "e… | 3 |  |
| q-853d729d81 | check C123 | search | {"dataset": "windows.other", "query": "message:*SmartCard* OR message:*SCard* OR message:*Credential*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable",… | 2 |  |
| q-78c5607cb2 | check C124 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 OR event.code:4656 OR event.code:4670", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 10977 |  |
| q-1487b650c4 | check C125 | aggregate | {"dataset": "windows.security", "field": "destination.port", "query": "event.code:5156 AND (destination.port:139 OR destination.port:445)", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 168 |  |
| q-935d3da9fb | check C126 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND (win.TargetFilename:*.lnk OR win.TargetFilename:*.url OR win.TargetFilename:*.library-ms OR win.TargetFilename:*.searchConnector-ms)", "time_from": null, "time_to": null, … | 3 |  |
| q-c1da028e45 | check C127 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*WebDAV* OR win.ScriptBlockText:*NTLM* OR win.ScriptBlockText:*lnk* OR win.ScriptBlockText:*searchConnector*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "h… | 2 |  |
| q-b75032fff4 | check C128 | search | {"dataset": "windows.other", "query": "message:*WebDAV* OR message:*NTLM* OR message:*searchConnector*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable"… | 1 |  |
| q-8e7fa7b029 | check C129 | aggregate | {"dataset": "zeek", "field": "destination.port", "query": "event.action:conn AND (destination.port:139 OR destination.port:445)", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 50 |  |
| q-26ed8d3a05 | check C130 | search | {"dataset": "zeek", "query": "event.action:http AND (http.request.method:PROPFIND OR http.request.method:MOVE OR http.request.method:OPTIONS)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.c… | 36 | F17 |
| q-c4e86557a6 | check C131 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4768 OR event.code:4769 OR event.code:4770", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 42 |  |
| q-6406fc132a | check C132 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 326 |  |
| q-9957886d4b | check C133 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*lsass* OR process.command_line:*dump* OR process.command_line:*procdump* OR process.command_line:*comsvcs*)", "time_from": null, "time_to": null, "si… | 1 |  |
| q-8e3a550d54 | check C134 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*MiniDump* OR win.ScriptBlockText:*comsvcs* OR win.ScriptBlockText:*procdump*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "h… | 0 |  |
| q-6fe94e5dcd | check C135 | search | {"dataset": "windows.other", "query": "message:*lsass* OR message:*MiniDump* OR message:*procdump*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "p… | 0 |  |
| q-2e19b01c8a | check C136 | search | {"dataset": "zeek", "query": "event.action:notice OR event.action:weird", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "sour… | 14 |  |
| q-46ca807de0 | check C137 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND (process.command_line:*cookie* OR process.command_line:*Cookies* OR process.command_line:*Login Data*)", "time_from": null, "time_to": null, "size": 30, "sub_field": n… | 4 |  |
| q-de7570bd71 | check C138 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND (win.TargetFilename:*Cookies* OR win.TargetFilename:*Login Data* OR win.TargetFilename:*Web Data*)", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 162 |  |
| q-e8f766a3e7 | check C139 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND (win.TargetImage:*chrome* OR win.TargetImage:*firefox* OR win.TargetImage:*msedge* OR win.TargetImage:*iexplore*)", "time_from": null, "time_to": null, "size": 20, "sub_fie… | 0 |  |
| q-04ef083075 | check C140 | search | {"dataset": "windows.sysmon", "query": "event.code:2 AND (file.path:*Cookies* OR file.path:*Login Data*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executabl… | 0 |  |
| q-d9ff619b5a | check C141 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Cookies* OR win.ScriptBlockText:*Login Data* OR win.ScriptBlockText:*sqlite*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "ev… | 13 |  |
| q-bea088470b | check C142 | search | {"dataset": "windows.other", "query": "message:*Cookies* OR message:*Login Data*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_lin… | 3 |  |
| q-2a936746ed | check C143 | search | {"dataset": "zeek", "query": "event.action:http AND (url.original:*cookie* OR http.request.method:GET)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable"… | 2 |  |
| q-51b7815268 | check C144 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND (process.command_line:*password* OR process.command_line:*credential* OR process.command_line:*vault* OR process.command_line:*unattend*)", "time_from": null, "time_to… | 0 |  |
| q-58d23f6fc2 | check C145 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND (win.TargetFilename:*unattend* OR win.TargetFilename:*web.config* OR win.TargetFilename:*.config OR win.TargetFilename:*passwords* OR win.TargetFilename:*.kdbx)", "time_fr… | 2 |  |
| q-91399af879 | check C146 | aggregate | {"dataset": "windows.sysmon", "field": "registry.path", "query": "event.code:13 AND (registry.path:*Password* OR registry.path:*Credential* OR registry.path:*Vault*)", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 17 |  |
| q-8db9af5ab5 | check C147 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*password* OR win.ScriptBlockText:*credential* OR win.ScriptBlockText:*vault* OR win.ScriptBlockText:*unattend*)", "time_from": null, "time_to": null, "fields": ["@timestamp",… | 2 |  |
| q-23cc2bef47 | check C148 | search | {"dataset": "windows.other", "query": "message:*password* OR message:*credential* OR message:*vault*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", … | 2 |  |
| q-8824193c59 | check C149 | search | {"dataset": "zeek", "query": "event.action:smb_files AND (file.path:*password* OR file.path:*.config OR file.path:*.txt)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "p… | 0 |  |
| q-6bb62087b0 | check C150 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND (win.ObjectName:*.txt OR win.ObjectName:*.config OR win.ObjectName:*.xml OR win.ObjectName:*.ini)", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 0 |  |
| q-59f30025c5 | check C151 | search | {"dataset": "windows.security", "query": "event.code:4648", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 15 |  |
| q-272a42d8de | check C152 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*findstr* OR process.command_line:*Select-String* OR process.command_line:*type* OR process.command_line:*Get-Content*)", "time_from": null, "time_to"… | 1 |  |
| q-e9952accef | check C153 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND (win.TargetFilename:*.txt OR win.TargetFilename:*.config OR win.TargetFilename:*.xml OR win.TargetFilename:*.ini OR win.TargetFilename:*.ps1)", "time_from": null, "time_to… | 72 |  |
| q-fdb634945b | check C154 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Get-Content* OR win.ScriptBlockText:*Select-String* OR win.ScriptBlockText:*findstr*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.na… | 1 | F26 |
| q-82ba4a6fdb | check C155 | search | {"dataset": "windows.other", "query": "message:*.config OR message:*.txt OR message:*.ini", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.co… | 0 |  |
| q-48f948275c | check C156 | search | {"dataset": "zeek", "query": "event.action:smb_files AND (file.path:*.txt OR file.path:*.config OR file.path:*.ini OR file.path:*.xml)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "… | 2 |  |
| q-9913981c7c | check C157 | aggregate | {"dataset": "windows.sysmon", "field": "registry.path", "query": "event.code:13 AND (registry.path:*Password* OR registry.path:*password* OR registry.path:*Credential* OR registry.path:*credential* OR registry.path:*Secret* OR registry.path:*secret*)", "time_f… | 17 |  |
| q-1c5595acf1 | check C158 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*reg\\ query* OR process.command_line:*reg\\ save* OR process.command_line:*reg.exe*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "e… | 0 |  |
| q-c1730246ed | check C159 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Password* OR win.ScriptBlockText:*Credential* OR win.ScriptBlockText:*HKLM* OR win.ScriptBlockText:*HKCU*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "hos… | 12 | F25 |
| q-f0d4ce9c68 | check C160 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND (win.ObjectName:*SAM* OR win.ObjectName:*SECURITY* OR win.ObjectName:*Password*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-705a5495b5 | check C161 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Get-History* OR win.ScriptBlockText:*ConsoleHost_history* OR win.ScriptBlockText:*history*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "obser… | 0 |  |
| q-0f147d8050 | check C162 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*ConsoleHost_history* OR process.command_line:*Get-History* OR process.command_line:*PSReadline*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observ… | 0 |  |
| q-0cb37ab997 | check C163 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*ConsoleHost_history* OR file.path:*history*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process… | 0 |  |
| q-3eeab60d20 | check C164 | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11 AND (file.path:*.pfx OR file.path:*.pem OR file.path:*.key OR file.path:*.p12 OR file.path:*.ppk OR file.path:*.cer OR file.path:*.asc)", "time_from": null, "time_to": null, "size": 50… | 1 |  |
| q-b60c6bddf8 | check C165 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*.pfx OR process.command_line:*.pem OR process.command_line:*.key OR process.command_line:*.p12)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observe… | 0 |  |
| q-becd385c21 | check C166 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:5145 AND (win.ObjectName:*.pfx OR win.ObjectName:*.pem OR win.ObjectName:*.key OR win.ObjectName:*.p12 OR win.ObjectName:*.cer)", "time_from": null, "time_to": null, "size": 50, "s… | 0 |  |
| q-9e16927610 | check C167 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*cpassword* OR win.ScriptBlockText:*Groups.xml* OR win.ScriptBlockText:*gpp* OR win.ScriptBlockText:*AES*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host… | 0 |  |
| q-0e9299839f | check C168 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*Groups.xml* OR process.command_line:*cpassword* OR process.command_line:*SYSVOL* OR process.command_line:*gpp*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host… | 0 |  |
| q-9ce3d65bba | check C169 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:5145 AND (win.ObjectName:*Groups.xml* OR win.ObjectName:*SYSVOL* OR win.ObjectName:*Policies*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-e112927bd6 | check C170 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND (win.TargetImage:*lsass.exe OR win.TargetImage:*LSASS*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-053102e207 | check C171 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass.exe", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-63ea41c024 | check C172 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*comsvcs* OR process.command_line:*MiniDump* OR process.command_line:*procdump* OR process.command_line:*sekurlsa* OR process.command_line:*mimikatz*)", "time_from": null, "time_to"… | 0 |  |
| q-5b3de6cacd | check C173 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND (win.ObjectName:*lsass* OR win.ObjectName:*SAM* OR win.ObjectName:*SECURITY* OR win.ObjectName:*NTDS*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 6 |  |
| q-2cb4db7354 | check C174 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND (process.command_line:*lsass* OR process.command_line:*dump* OR process.command_line:*mimikatz*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-0495ab46b9 | check C175 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*MiniDump* OR win.ScriptBlockText:*sekurlsa* OR win.ScriptBlockText:*Credential*)", "time_from": null, "time_to": null, "fields": ["@timestamp",… | 3 |  |
| q-2b98209b33 | check C176 | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11 AND (file.path:*Login\\ Data* OR file.path:*logins.json* OR file.path:*Cookies* OR file.path:*Local\\ State*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1 |  |
| q-9765c3c77a | check C177 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*Login\\ Data* OR process.command_line:*logins.json* OR process.command_line:*Local\\ State* OR process.command_line:*Cookies*)", "time_from": null, "time_to": null, "fields": ["@ti… | 0 |  |
| q-cc81bc8921 | check C178 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND (win.ObjectName:*Login\\ Data* OR win.ObjectName:*logins.json* OR win.ObjectName:*Local\\ State*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-28bfedee6b | check C179 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Login\\ Data* OR win.ScriptBlockText:*logins.json* OR win.ScriptBlockText:*Local\\ State* OR win.ScriptBlockText:*sqlite*)", "time_from": null, "time_to": null, "fields": ["@… | 0 |  |
| q-b575d8d2b5 | check C180 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*vault* OR process.command_line:*credman* OR process.command_line:*Credential* OR process.command_line:*cmdkey*)", "time_from": null, "time_to": null,… | 0 |  |
| q-f7619bbe64 | check C181 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND (win.TargetImage:*lsass* OR win.TargetImage:*vault* OR win.TargetImage:*Credential*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.… | 326 |  |
| q-86d65f71af | check C182 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-f83e2ce144 | check C183 | search | {"dataset": "windows.sysmon", "query": "event.code:15 AND (win.TargetFilename:*vault* OR win.TargetFilename:*Credentials* OR win.TargetFilename:*Microsoft\\\\Protect*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name",… | 0 |  |
| q-bdbb808721 | check C184 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*cmdkey* OR process.command_line:*vault* OR process.command_line:*credman*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.… | 0 |  |
| q-411ed4be28 | check C185 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Credential* OR win.ScriptBlockText:*vault* OR win.ScriptBlockText:*cmdkey* OR win.ScriptBlockText:*Get-StoredCredential*)", "time_from": null, "time_to": null, "fields": ["@t… | 3 |  |
| q-00820b3e33 | check C186 | search | {"dataset": "windows.other", "query": "message:*vault* OR message:*Credential* OR message:*cmdkey*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "p… | 2 | F30 |
| q-a9ac2c278b | check C187 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*keepass* OR process.command_line:*1password* OR process.command_line:*bitwarden* OR process.command_line:*lastpass* OR process.command_line:*KeePass*… | 0 |  |
| q-bcd04a7bab | check C188 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND (win.TargetImage:*keepass* OR win.TargetImage:*1password* OR win.TargetImage:*bitwarden* OR win.TargetImage:*lastpass*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "obser… | 0 |  |
| q-fae37f2187 | check C189 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (win.TargetFilename:*.kdbx OR win.TargetFilename:*1password* OR win.TargetFilename:*bitwarden*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.datase… | 0 |  |
| q-07c80d9105 | check C190 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*keepass* OR process.command_line:*1password* OR process.command_line:*bitwarden* OR process.command_line:*lastpass*)", "time_from": null, "time_to": null, "fields": ["@timesta… | 0 |  |
| q-69e1177356 | check C191 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*kdbx* OR win.ScriptBlockText:*keepass* OR win.ScriptBlockText:*1password* OR win.ScriptBlockText:*bitwarden*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "… | 0 |  |
| q-8bd3a5fca0 | check C192 | search | {"dataset": "windows.other", "query": "message:*keepass* OR message:*1password* OR message:*bitwarden* OR message:*lastpass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name"… | 0 |  |
| q-d18bb3f43d | check C193 | aggregate | {"dataset": "windows.sysmon", "field": "win.SourceImage", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 326 |  |
| q-028f84ba72 | check C194 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-9f1a8d9fd5 | check C195 | search | {"dataset": "windows.sysmon", "query": "event.code:7 AND (win.ImageLoaded:*lsass* OR win.ImageLoaded:*cryptdll* OR win.ImageLoaded:*sam* OR win.ImageLoaded:*wdigest* OR win.ImageLoaded:*msv1_0*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "h… | 79 | F33, F36 |
| q-74e9060d4f | check C196 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (win.TargetFilename:*\\\\config\\\\SAM OR win.TargetFilename:*\\\\config\\\\SECURITY OR win.TargetFilename:*\\\\config\\\\SYSTEM OR win.TargetFilename:*ntds.dit*)", "time_from": null, "time_to": null, "… | 0 |  |
| q-7ee0770c6f | check C197 | search | {"dataset": "windows.security", "query": "event.code:4657 AND (win.ObjectName:*lsass* OR win.ObjectName:*cryptdll* OR win.ObjectName:*Notification Packages* OR win.ObjectName:*Security Packages*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "… | 0 |  |
| q-dc41e654d7 | check C198 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*lsass* OR process.command_line:*MiniDump* OR process.command_line:*comsvcs* OR process.command_line:*procdump* OR process.command_line:*mimikatz*)", "time_from": null, "time_t… | 0 |  |
| q-c952ca7015 | check C199 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*MiniDump* OR win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*comsvcs* OR win.ScriptBlockText:*Invoke-Mimikatz* OR win.ScriptBlockText:*sekurlsa*)", "time_from": null, "ti… | 0 |  |
| q-6613e8cf5f | check C200 | search | {"dataset": "windows.other", "query": "message:*lsass* OR message:*MiniDump* OR message:*cryptdll*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "p… | 0 |  |
| q-86fe67e332 | check C201 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4624 OR event.code:4648", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 312 |  |
| q-5024f158ea | check C202 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4624 AND win.LogonType:3", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 218 |  |
| q-eaba10714c | check C203 | aggregate | {"dataset": "windows.sysmon", "field": "win.SourceImage", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 326 |  |
| q-e33d88682f | check C204 | search | {"dataset": "windows.sysmon", "query": "event.code:7 AND (win.ImageLoaded:*lsass* OR win.ImageLoaded:*cryptdll*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.e… | 33 |  |
| q-78b23568c0 | check C205 | search | {"dataset": "windows.other", "query": "message:*lsass* OR message:*cryptdll*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 0 |  |
| q-74e32835dd | check C206 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*cryptdll* OR win.ScriptBlockText:*Skeleton* OR win.ScriptBlockText:*mimilib*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "h… | 0 |  |
| q-147c48c3b6 | check C207 | search | {"dataset": "windows.security", "query": "event.code:4657 AND (win.ObjectName:*Notification Packages* OR win.ObjectName:*Password* OR win.ObjectName:*lsass*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.da… | 0 |  |
| q-9664bd557d | check C208 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (win.TargetFilename:*\\\\System32\\\\*.dll OR win.TargetFilename:*PasswordFilter* OR win.TargetFilename:*\\\\secrets\\\\)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "obs… | 0 |  |
| q-1a01724ae8 | check C209 | search | {"dataset": "windows.sysmon", "query": "event.code:7 AND (win.ImageLoaded:*lsass* OR win.ImageLoaded:*PasswordFilter* OR win.ImageLoaded:*cryptdll*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "… | 33 |  |
| q-8b155d97a8 | check C210 | aggregate | {"dataset": "windows.sysmon", "field": "win.ImageLoaded", "query": "event.code:7 AND win.ImageLoaded:*lsass*", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 1 |  |
| q-c50731a68d | check C211 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Notification Packages* OR win.ScriptBlockText:*PasswordFilter* OR win.ScriptBlockText:*lsass*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "ob… | 0 |  |
| q-eee753527d | check C212 | search | {"dataset": "windows.other", "query": "message:*Notification Packages* OR message:*PasswordFilter* OR message:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "proc… | 5 |  |
| q-b3b49a589d | check C213 | search | {"dataset": "windows.security", "query": "event.code:4739", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 0 |  |
| q-8a027d8657 | check C214 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*AllowReversiblePasswordEncryption* OR win.ScriptBlockText:*ReversibleEncryption* OR win.ScriptBlockText:*Set-ADAccountControl* OR win.ScriptBlockText:*Set-ADUser*)", "time_fr… | 1 |  |
| q-87f81cd693 | check C215 | search | {"dataset": "windows.powershell", "query": "event.code:4103 OR event.code:4104 OR event.code:4105 OR event.code:4106", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "proce… | 5494 |  |
| q-5e7e9ec56a | check C216 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*Reversible* OR process.command_line:*Set-ADAccountControl* OR process.command_line:*dsmod* OR process.command_line:*adsutil*)", "time_from": null, "t… | 0 |  |
| q-93503f6fc6 | check C217 | search | {"dataset": "windows.other", "query": "message:*Reversible* OR message:*AllowReversiblePasswordEncryption*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executa… | 0 |  |
| q-2f94ddaeb9 | check C218 | count | {"dataset": "windows.security", "query": "event.code:4739", "time_from": null, "time_to": null} | 0 |  |
| q-9a8d1d6518 | check C219 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Set-ADUser* OR win.ScriptBlockText:*Set-ADAuthenticationPolicy* OR win.ScriptBlockText:*AuthenticationPolicy*)", "time_from": null, "time_to": null, "fields": ["@timestamp", … | 1 |  |
| q-302425039b | check C220 | search | {"dataset": "windows.other", "query": "event.code:7045 OR event.code:7040", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "so… | 9 |  |
| q-c260ee620e | check C221 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*ADUser* OR process.command_line:*AuthenticationPolicy* OR process.command_line:*ADDomain*)", "time_from": null, "time_to": null, "size": 50, "sub_fie… | 2 |  |
| q-0ec581f445 | check C222 | count | {"dataset": "windows.security", "query": "event.code:5136", "time_from": null, "time_to": null} | 0 |  |
| q-b55c61e19a | check C223 | aggregate | {"dataset": "windows.sysmon", "field": "win.ImageLoaded", "query": "event.code:7 AND (win.ImageLoaded:*AAD* OR win.ImageLoaded:*Azure* OR win.ImageLoaded:*ADFS* OR win.ImageLoaded:*Identity*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 2 |  |
| q-de6a51001e | check C224 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*AADConnect* OR win.ScriptBlockText:*AzureAD* OR win.ScriptBlockText:*ADFS* OR win.ScriptBlockText:*Set-ADUser*)", "time_from": null, "time_to": null, "fields": ["@timestamp",… | 1 |  |
| q-988a2593ae | check C225 | search | {"dataset": "windows.other", "query": "event.code:7045 OR event.code:7040 OR event.code:7036", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process… | 17 |  |
| q-e8567eabda | check C226 | search | {"dataset": "windows.security", "query": "event.code:4657 AND (win.ObjectName:*NetworkProvider* OR win.ObjectName:*Winlogon* OR win.ObjectName:*Credential*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dat… | 0 |  |
| q-b7a545de61 | check C227 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND (win.TargetFilename:*System32* OR win.TargetFilename:*NetworkProvider*)", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 425 |  |
| q-9847a698c9 | check C228 | aggregate | {"dataset": "windows.sysmon", "field": "win.ImageLoaded", "query": "event.code:7 AND (win.ImageLoaded:*System32* OR win.ImageLoaded:*network*)", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 19432 |  |
| q-bb7b1c83d8 | check C229 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass.exe", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-2eafffd336 | check C230 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*NetworkProvider* OR win.ScriptBlockText:*Winlogon* OR win.ScriptBlockText:*Credential*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.… | 3 |  |
| q-8affc43f03 | check C231 | search | {"dataset": "windows.other", "query": "event.code:7045 OR event.code:7040", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "so… | 9 |  |
| q-0082572875 | check C232 | aggregate | {"dataset": "windows.sysmon", "field": "destination.ip", "query": "event.code:3", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 1229 |  |
| q-594b19f177 | check C233 | aggregate | {"dataset": "windows.sysmon", "field": "dns.question.name", "query": "event.code:22", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 81 |  |
| q-4c816412ef | check C234 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 OR event.code:4670 OR event.code:4656", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 10977 |  |
| q-c0700bfa54 | check C235 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Responder* OR win.ScriptBlockText:*Inveigh* OR win.ScriptBlockText:*LLMNR* OR win.ScriptBlockText:*NBT-NS*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "ho… | 0 |  |
| q-f344db4ba5 | check C236 | search | {"dataset": "windows.other", "query": "event.code:7045 OR event.code:7040", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "so… | 9 |  |
| q-f2bbe35c08 | check C237 | aggregate | {"dataset": "zeek", "field": "destination.port", "query": "event.action:conn AND (destination.port:445 OR destination.port:139)", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 50 |  |
| q-bba00fff26 | check C238 | aggregate | {"dataset": "zeek", "field": "destination.port", "query": "event.action:conn AND (destination.port:5355 OR destination.port:137 OR destination.port:5353)", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 2 |  |
| q-deaac753a8 | check C239 | aggregate | {"dataset": "zeek", "field": "source.ip", "query": "event.action:conn AND (destination.port:445 OR destination.port:139)", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 50 |  |
| q-112af84304 | check C240 | count | {"dataset": "windows.security", "query": "event.code:4697", "time_from": null, "time_to": null} | 23 |  |
| q-954b4e9d41 | check C241 | search | {"dataset": "windows.sysmon", "query": "event.code:13 AND registry.path:*EnableMulticast*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.co… | 0 |  |
| q-91bc74db9b | check C242 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*EnableMulticast* OR win.ScriptBlockText:*LLMNR* OR win.ScriptBlockText:*Inveigh* OR win.ScriptBlockText:*Responder*)", "time_from": null, "time_to": null, "fields": ["@timest… | 0 |  |
| q-4d80e48542 | check C243 | search | {"dataset": "windows.other", "query": "event.code:7045 OR event.code:7040", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "so… | 9 |  |
| q-380e25b7ed | check C244 | aggregate | {"dataset": "windows.sysmon", "field": "destination.ip", "query": "event.code:3", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 1229 |  |
| q-7277806339 | check C245 | aggregate | {"dataset": "windows.sysmon", "field": "dns.question.name", "query": "event.code:22", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 81 |  |
| q-d9d2df0dfb | check C246 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 OR event.code:4670 OR event.code:4656", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 10977 |  |
| q-0eeaf49f2d | check C247 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*arp* OR win.ScriptBlockText:*Arp* OR win.ScriptBlockText:*netsh* OR win.ScriptBlockText:*route*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "… | 0 |  |
| q-c0fe67d511 | check C248 | search | {"dataset": "windows.other", "query": "event.code:7045 OR event.code:7040", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "so… | 9 |  |
| q-77e8b49118 | check C249 | aggregate | {"dataset": "zeek", "field": "source.ip", "query": "event.action:conn", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 613 |  |
| q-24f2b88e97 | check C250 | aggregate | {"dataset": "windows.other", "field": "event.code", "query": "event.code:(1341 OR 1342 OR 1020 OR 1063)", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 0 |  |
| q-7b6f8edd04 | check C251 | aggregate | {"dataset": "windows.security", "field": "win.LogonProcessName", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 297 |  |
| q-252448c0d2 | check C252 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*dhcp* OR process.command_line:*ipconfig* OR process.command_line:*route*)", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 6 |  |
| q-0dbcfcea63 | check C253 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*dhcp* OR win.ScriptBlockText:*DhcpServer*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.n… | 0 |  |
| q-bbeb86c380 | check C254 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4672", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 212 |  |
| q-1bd4cc2889 | check C255 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4634", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 236 |  |
| q-610696056d | check C256 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass.exe", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 326 |  |
| q-9d007418bc | check C257 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND win.TargetImage:*lsass.exe", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-d61a9dbeab | check C258 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*kerberos* OR win.ScriptBlockText:*Kerberos* OR win.ScriptBlockText:*ticket* OR win.ScriptBlockText:*Ticket*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "h… | 0 |  |
| q-f9bb8bdd96 | check C259 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-0e7b65cec2 | check C260 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4672", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 212 |  |
| q-d04751ce47 | check C261 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4634", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 236 |  |
| q-d3aca82ec2 | check C262 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND win.TargetImage:*lsass.exe", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-92dc50b5f6 | check C263 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*krbtgt* OR win.ScriptBlockText:*golden* OR win.ScriptBlockText:*Golden*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.d… | 0 |  |
| q-e20ced6343 | check C264 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-49da12cc57 | check C265 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4672", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 212 |  |
| q-6269ec70d7 | check C266 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4634", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 236 |  |
| q-ced0d5b561 | check C267 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND win.TargetImage:*lsass.exe", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-880e2d9902 | check C268 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*silver* OR win.ScriptBlockText:*Silver* OR win.ScriptBlockText:*service ticket*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", … | 0 |  |
| q-09b3cf1637 | check C269 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-48060f0b9d | check C270 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 297 |  |
| q-b946218f23 | check C271 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4672", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 212 |  |
| q-8534274261 | check C272 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND win.TargetImage:*lsass.exe", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-9eb1f055eb | check C273 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*SPN* OR win.ScriptBlockText:*spn* OR win.ScriptBlockText:*Kerberoast* OR win.ScriptBlockText:*kerberoast*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "hos… | 0 |  |
| q-21d7750ee6 | check C274 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-25788a3a50 | check C275 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*asrep* OR process.command_line:*ASREP* OR process.command_line:*GetNPUsers* OR process.command_line:*preauth*)", "time_from": null, "time_to": null, … | 0 |  |
| q-b46f34c4a5 | check C276 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*ASREP* OR win.ScriptBlockText:*asrep* OR win.ScriptBlockText:*GetNPUsers* OR win.ScriptBlockText:*preauth*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "ho… | 0 |  |
| q-0ef61171c9 | check C277 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 297 |  |
| q-0e1789ba8b | check C278 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-e282010a6e | check C279 | aggregate | {"dataset": "windows.security", "field": "win.LogonProcessName", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 297 |  |
| q-275bf6b0db | check C280 | aggregate | {"dataset": "windows.security", "field": "win.AuthenticationPackageName", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 297 |  |
| q-d2284e09e3 | check C281 | search | {"dataset": "windows.security", "query": "event.code:4648", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 15 |  |
| q-7b398eb697 | check C282 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-ec004a60c6 | check C283 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*cookie* OR win.ScriptBlockText:*token* OR win.ScriptBlockText:*SAML*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.data… | 1 |  |
| q-450d26ff4e | check C284 | search | {"dataset": "windows.other", "query": "message:*token* OR message:*cookie* OR message:*SAML*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process… | 0 |  |
| q-6a5bad34ad | check C285 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND (win.TargetFilename:*Cookies* OR win.TargetFilename:*cookie*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1 |  |
| q-540196b907 | check C286 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND win.TargetFilename:*Cookies*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.comma… | 1 |  |
| q-dc7bd9c4ce | check C287 | search | {"dataset": "windows.security", "query": "event.code:4648", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 15 |  |
| q-59b75db2b1 | check C288 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Cookies* OR win.ScriptBlockText:*cookie*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.na… | 0 |  |
| q-07dae7d0db | check C289 | search | {"dataset": "windows.other", "query": "message:*cookie*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destina… | 0 |  |
| q-20e00467c7 | check C290 | aggregate | {"dataset": "windows.security", "field": "win.AuthenticationPackageName", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 297 |  |
| q-fd411226ef | check C291 | search | {"dataset": "windows.security", "query": "event.code:4648", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 15 |  |
| q-63f2092884 | check C292 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*SAML* OR win.ScriptBlockText:*NotOnOrAfter* OR win.ScriptBlockText:*token-signing*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name… | 0 |  |
| q-7ee976b9ad | check C293 | search | {"dataset": "windows.other", "query": "message:*SAML* OR message:*ADFS*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "sour… | 0 |  |
| q-10a9520e01 | check C294 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-e16e2832a7 | check C295 | count | {"dataset": "windows.security", "query": "event.code:4625", "time_from": null, "time_to": null} | 0 |  |
| q-c0964a57fc | check C296 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-f7f514895f | check C297 | aggregate | {"dataset": "windows.security", "field": "source.ip", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-01edc1d9f9 | check C298 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*MFA* OR win.ScriptBlockText:*2FA* OR win.ScriptBlockText:*Authenticator*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.… | 0 |  |
| q-1b0976f8df | check C299 | search | {"dataset": "windows.other", "query": "message:*MFA* OR message:*multi-factor*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line"… | 0 |  |
| q-d830be6be5 | check C300 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 447 |  |
| q-e1ff22e2b6 | check C301 | search | {"dataset": "windows.security", "query": "event.code:4657", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 36 | F53 |
| q-af277a3b01 | check C302 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4657", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 36 |  |
| q-0ce1b96b98 | check C303 | search | {"dataset": "windows.security", "query": "event.code:4768", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 14 |  |
| q-8b57271179 | check C304 | aggregate | {"dataset": "windows.security", "field": "win.PreAuthType", "query": "event.code:4768", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 14 |  |
| q-4765b0c5b6 | check C305 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND (win.TargetFilename:*.pfx OR win.TargetFilename:*.p12 OR win.TargetFilename:*.cer OR win.TargetFilename:*.pvk)", "time_from": null, "time_to": null, "size": 50, "sub_field… | 1 |  |
| q-91e6676386 | check C306 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Export-PfxCertificate* OR win.ScriptBlockText:*Cert:\\* OR win.ScriptBlockText:*certutil*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observ… | ERROR |  |
| q-89178ea3b2 | check C306 (repaired) | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Export-PfxCertificate* OR win.ScriptBlockText:*certutil*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event… | 1 |  |
| q-d98715dacc | check C307 | search | {"dataset": "windows.other", "query": "message:*certificate* OR message:*Cert*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line"… | 0 |  |
| q-a44bd8bb27 | check C308 | aggregate | {"dataset": "zeek", "field": "url.original", "query": "event.action:http", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 62 |  |
| q-21dd99c4f1 | check C309 | aggregate | {"dataset": "zeek", "field": "http.request.method", "query": "event.action:http AND http.request.method:POST", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 0 |  |
| q-71eb2ffa47 | check C310 | aggregate | {"dataset": "zeek", "field": "zeek.request_type", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 35 |  |
| q-2649a18353 | check C311 | aggregate | {"dataset": "zeek", "field": "zeek.error_msg", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 35 |  |
| q-cd40d3e6ff | check C312 | aggregate | {"dataset": "zeek", "field": "zeek.client", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 35 |  |
| q-7b5b33c13e | check C313 | search | {"dataset": "zeek", "query": "event.action:kerberos AND zeek.error_msg:*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "sou… | 7 |  |
| q-2b58f29bf2 | check C314 | aggregate | {"dataset": "zeek", "field": "zeek.service", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 35 |  |
| q-7a5c743172 | check C315 | aggregate | {"dataset": "zeek", "field": "zeek.success", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 10, "sub_field": null} | 35 |  |
| q-899fb2da30 | check C316 | aggregate | {"dataset": "zeek", "field": "zeek.request_type", "query": "event.action:kerberos AND zeek.request_type:TGS", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 11 |  |
| q-7c287a91fd | check C317 | aggregate | {"dataset": "zeek", "field": "zeek.client", "query": "event.action:kerberos AND zeek.request_type:TGS", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 11 |  |
| q-54a8664618 | check C318 | aggregate | {"dataset": "zeek", "field": "zeek.client", "query": "event.action:kerberos AND zeek.request_type:AS", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 14 |  |
| q-edd36ad645 | check C319 | search | {"dataset": "zeek", "query": "event.action:kerberos AND zeek.request_type:AS AND zeek.error_msg:*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "pr… | 7 |  |
| q-8158a0e3e7 | triage T1003 step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 10 AND win.TargetImage LIKE \"*lsass*\" AND win.SourceImage NOT LIKE \"*svchost.exe\" \| KEEP @timestamp, host.name, win.SourceImage, win.GrantedAccess, win.CallTrace, _id,… | ERROR |  |
| q-7fde94804e | triage T1003 step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 10 AND win.GrantedAccess IN (\"0x1410\",\"0x1010\",\"0x1fffff\",\"0x101541\",\"0x101441\",\"0x121440\",\"0x101068\",\"0x1000000\",\"0x2200\",\"0x14c0\") \| KEEP @timestamp,… | ERROR |  |
| q-87a6f4c9e9 | triage T1003 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND win.TargetImage LIKE \"*lsass*\" AND win.SourceImage NOT LIKE \"*svchost.exe\" \| KEEP @timestamp, host.name, win.SourceImage, win.GrantedAccess, win.CallTrace, … | 37 |  |
| q-3f4ad56079 | triage T1003 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND win.GrantedAccess IN (\"0x1410\",\"0x1010\",\"0x1fffff\",\"0x101541\",\"0x101441\",\"0x121440\",\"0x101068\",\"0x1000000\",\"0x2200\",\"0x14c0\") \| KEEP @timest… | 500 |  |
| q-27bb341b1e | triage T1003 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None | F01 |
| q-844adb9ad8 | triage T1003 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None | F01 |
| q-6e8791fb1e | triage T1003 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None | F01 |
| q-37563fc203 | triage T1003 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (process.command_line LIKE \"*victim*\" OR process.command_line LIKE \"*lsass*\" OR process.command_line LIKE \"*MiniDump*\" OR process.command_line LIKE \"*sekur… | 3 | F02 |
| q-e3acce2504 | triage T1003 step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (win.ScriptBlockText LIKE \"*lsass*\" OR win.ScriptBlockText LIKE \"*MiniDump*\" OR win.ScriptBlockText LIKE \"*sekurlsa*\" OR win.ScriptBlockText LIKE \"*… | 4 | F02 |
| q-0669676e8b | triage T1003 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND process.executable LIKE \"*powershell.exe\" \| KEEP @timestamp, host.name, user.name, process.command_line, process.parent.executable, _id, _index \| SORT @timest… | 12 |  |
| q-4dc4d34b31 | triage T1003 step 5 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4688\" AND (process.command_line LIKE \"*victim*\" OR process.command_line LIKE \"*sdelete*\" OR process.command_line LIKE \"*lsass*\" OR process.command_line LIKE \"*d… | 7 | F02 |
| q-defba21486 | triage T1003 step 6 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBjA9g2o"} | None |  |
| q-18af10a154 | triage T1003 step 6 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUUD"} | None | F01 |
| q-2e0045b306 | triage T1003 step 6 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4662\",\"4663\",\"4656\",\"5145\") AND (win.ObjectName LIKE \"*SAM*\" OR win.ObjectName LIKE \"*SECURITY*\" OR win.ObjectName LIKE \"*ntds*\" OR win.ObjectName LIKE \"… | 107 |  |
| q-c448c20793 | triage T1003 step 7 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBumw-cX"} | None | F03 |
| q-bde202437f | triage T1003 step 7 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy4FbI2"} | None | F01 |
| q-b9e5f69219 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-50e1b5284a | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None |  |
| q-17bcd11275 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy4FbI2"} | None |  |
| q-dfadc06be3 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy4FbI2"} | None |  |
| q-3e48a0871a | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-55eaaeae78 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUUD"} | None |  |
| q-d062856a33 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBow1KRR"} | None |  |
| q-bc6ad13038 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoSVqPo"} | None |  |
| q-ff64ea81f8 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaboC"} | None |  |
| q-c8a202f5a0 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBukwKVF"} | None |  |
| q-cd1101bf11 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBumw-cX"} | None |  |
| q-c3c6fbebe7 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBumw-cX"} | None |  |
| q-9a8a8eb2a5 | triage T1040 step 1 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*pktmon* OR process.command_line:*netsh* OR process.command_line:*windump* OR process.command_line:*tcpdump* OR process.command_line:*rawcap*)", "time_from": null, "time_to": n… | 2 | F04 |
| q-c907879454 | triage T1040 step 1 | aggregate | {"dataset": "windows.security", "field": "process.command_line", "query": "event.code:4688 AND process.executable:\"C:\\\\Windows\\\\System32\\\\netsh.exe\"", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 2 |  |
| q-926db27fb8 | triage T1040 step 2 | search | {"dataset": "windows.sysmon", "query": "process.executable:*NetworkWatcherAgent* OR process.command_line:*NetworkWatcher* OR process.command_line:*netsh*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "process.executab… | 75 |  |
| q-2013dba57e | triage T1040 step 2 | aggregate | {"dataset": "windows.sysmon", "field": "win.ImageLoaded", "query": "event.code:7 AND (win.ImageLoaded:*pktmon* OR win.ImageLoaded:*npcap* OR win.ImageLoaded:*winpcap* OR win.ImageLoaded:*pcap*)", "time_from": null, "time_to": null, "size": 30, "sub_field": nul… | 0 |  |
| q-18b28342f2 | triage T1040 step 3 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND process.executable:*NetworkWatcherAgent*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "process.executable", "process.command_line", "process.parent.executable"… | 4 | F04 |
| q-7a352c000d | triage T1040 step 3 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*capture* OR process.command_line:*sniff* OR process.command_line:*dumpcap* OR process.command_line:*pcap* OR process.command_line:*trace*)", "time_fr… | 4 |  |
| q-f6049575f1 | triage T1040 step 4 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.executable:*logman.exe OR process.executable:*netsh.exe)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "process.executable", "process.command_line", "p… | 9 | F04 |
| q-b880e6965a | triage T1040 step 4 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.executable:*PSEXESVC* OR process.command_line:*PSEXESVC* OR process.executable:*psexec*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "process.executa… | 4 |  |
| q-331e0d6806 | triage T1040 step 5 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuYnMlG"} | None |  |
| q-066024d66f | triage T1040 step 5 | search | {"dataset": "zeek", "query": "event.action:notice OR event.action:weird", "time_from": null, "time_to": null, "fields": ["@timestamp", "event.action", "zeek.note", "zeek.msg", "source.ip", "destination.ip", "observer.name"], "size": 20, "sort": "asc"} | 14 | F04 |
| q-76b1678f21 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuYnMlG"} | None |  |
| q-c473f2c506 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuYnMlG"} | None |  |
| q-764bdf9e1e | triage T1040 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuWmJOo"} | None |  |
| q-fe55189a50 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnvvDAD"} | None |  |
| q-38ec5a37f1 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnvvDAD"} | None |  |
| q-c5530fe6f6 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnDAQqo"} | None |  |
| q-33bde248e9 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnfd0sF"} | None |  |
| q-bc05842d05 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnFCvgF"} | None |  |
| q-29d80b7f55 | triage T1040 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgR8i"} | None |  |
| q-406307317f | triage T1056 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRabqD"} | None | F06 |
| q-e488a87b0f | triage T1056 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRZ7r5"} | None | F06 |
| q-2fbfed2490 | triage T1056 step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 10 AND win.TargetImage LIKE \"*lsass.exe\" AND process.executable LIKE \"*powershell*\" \| KEEP @timestamp, host.name, process.executable, process.command_line, win.Granted… | ERROR |  |
| q-d8a13bf112 | triage T1056 step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 10 AND win.TargetImage LIKE \"*lsass.exe\" AND win.GrantedAccess IN (\"0x1fffff\",\"0x101001\",\"0x1f3fff\",\"0x1000000\",\"0x3000\") \| KEEP @timestamp, host.name, process… | ERROR |  |
| q-e94fd09b44 | triage T1056 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND win.TargetImage LIKE \"*lsass.exe\" AND (process.executable LIKE \"*powershell*\" OR process.executable LIKE \"*wsmprovhost*\" OR process.executable LIKE \"*wini… | 7 |  |
| q-d35f1e88cf | triage T1056 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND win.TargetImage LIKE \"*lsass.exe\" AND win.GrantedAccess IN (\"0x1fffff\",\"0x101001\",\"0x1f3fff\",\"0x1000000\",\"0x3000\") \| KEEP @timestamp, host.name, pro… | 9 |  |
| q-0444bba3ef | triage T1056 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None | F05, F09 |
| q-c7604c3837 | triage T1056 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None | F05, F09 |
| q-13422ff22a | triage T1056 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND host.name == \"scranton.dmevals.local\" AND process.executable LIKE \"*powershell*\" \| KEEP @timestamp, host.name, user.name, process.executable, process.command… | 11 | F05, F07 |
| q-22fa19a764 | triage T1056 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND host.name == \"scranton.dmevals.local\" AND (win.TargetFilename LIKE \"*.bmp\" OR win.TargetFilename LIKE \"*.dmp\" OR win.TargetFilename LIKE \"*Downloads*\") \… | 315 | F06 |
| q-8f75b7cac5 | triage T1056 step 4 | esql | {"query": "FROM logs-windows.security METADATA _id, _index \| WHERE event.code == \"4688\" AND process.executable LIKE \"*consent.exe\" \| KEEP @timestamp, host.name, user.name, process.executable, process.command_line, process.parent.executable, win.TargetUse… | ERROR |  |
| q-41e1e1d263 | triage T1056 step 4 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None | F09 |
| q-6386ea1bfe | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-75f003e059 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-6f0404bc30 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None |  |
| q-e5a20a1500 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None |  |
| q-c9602896ca | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUUD"} | None |  |
| q-5ff0c5969e | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBjA9g2o"} | ERROR |  |
| q-b1dd0ccf0b | triage T1056 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRabqD"} | None |  |
| q-c9949219a8 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRabqD"} | None |  |
| q-f6dcd92478 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRZ7r5"} | None |  |
| q-c14a20f16d | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoHL6FX"} | None |  |
| q-491b92ff71 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBi85SQC"} | None |  |
| q-72daca781c | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBizx7td"} | None |  |
| q-90a6e0087b | triage T1056 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByXfnRy"} | None |  |
| q-1cae70e878 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None |  |
| q-a7b2c6ffe4 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-8841eda17c | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-d9ee5a2681 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-b2bf4e2929 | triage T1056 step 6 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUUD"} | None | F05 |
| q-de6bf68423 | triage T1056 step 6 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByXfnRy"} | None | F08 |
| q-4000b2659d | triage T1110 step 1 | count | {"dataset": "windows.security", "query": "event.code:4625", "time_from": null, "time_to": null} | 0 |  |
| q-921d63b3b4 | triage T1110 step 1 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4648", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 15 |  |
| q-b881598c4a | triage T1110 step 1 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass* AND process.executable:*PowerShell*", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 4 |  |
| q-a947973d8b | triage T1110 step 1 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4656 AND win.ObjectName:*SAM*", "time_from": null, "time_to": null, "size": 20, "sub_field": "process.executable"} | 10 |  |
| q-17f077b209 | triage T1110 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND process.executable:*PowerShell*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "process.executable", "process.command_line", "win.Ta… | 4 | F12 |
| q-3a7e0d47a3 | triage T1110 step 2 | search | {"dataset": "windows.security", "query": "event.code:4656 AND win.ObjectName:SAM", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "process.executable", "win.ObjectName", "win.AccessMask", "win.AccessList", "win.ProcessNa… | 10 | F12 |
| q-d54293b491 | triage T1110 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-0288bb37d3 | triage T1110 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None |  |
| q-848203910e | triage T1110 step 3 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*MiniDump* OR win.ScriptBlockText:*Dump* OR win.ScriptBlockText:*Amsi* OR win.ScriptBlockText:*Invoke-Mimikatz*)", "time_from": null, "time_to":… | 0 |  |
| q-6d74fc9f63 | triage T1110 step 4 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND host.name:scranton.dmevals.local AND @timestamp:[2020-05-02T03:00:00.000Z TO 2020-05-02T03:10:00.000Z]", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "win… | 99 |  |
| q-d73f99347f | triage T1110 step 4 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND process.pid:2976", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "process.executable", "process.command_line", "process.parent.executable", "process.pid"], "size"… | 1 | F12 |
| q-9a3592765d | triage T1110 step 5 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBorwtwa"} | None |  |
| q-66f48b3738 | triage T1110 step 5 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND process.pid:2976", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "win.ScriptBlockText", "process.pid"], "size": 20, "sort": "asc"} | 3 | F12 |
| q-a3150ac366 | triage T1110 step 6 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByYfl1_"} | None |  |
| q-90c11ada4f | triage T1110 step 7 | aggregate | {"dataset": "windows.security", "field": "host.name", "query": "event.code:4648 AND win.TargetUserName:pbeesly", "time_from": null, "time_to": null, "size": 20, "sub_field": "process.executable"} | 9 |  |
| q-f581c18f04 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuu5GRH"} | None |  |
| q-b8397a8240 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBupz0Op"} | None |  |
| q-f21f79b1e2 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-f0b9bcdd16 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByPYrDh"} | None |  |
| q-4cb7180fe6 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-d6e63b91ee | triage T1110 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None |  |
| q-be92a7f698 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBorwtwa"} | None |  |
| q-9e1a2a9816 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByYfl1_"} | None |  |
| q-787904012a | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBudp5HI"} | None |  |
| q-757de98fa8 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuu42Tt"} | None |  |
| q-81144033c5 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBunxq0T"} | None |  |
| q-a29f5ee576 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByPYrDh"} | None |  |
| q-332a6b5ac1 | triage T1111 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND (win.GrantedAccess:0x1fffff OR win.GrantedAccess:0x101001 OR win.GrantedAccess:0x1f3fff OR win.GrantedAccess:0x1000000 OR win.GrantedAccess:0x3000)", "time_from": null, "time… | 9 | F15 |
| q-c39536906e | triage T1111 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByPYrDh"} | None |  |
| q-fc002778d1 | triage T1111 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND win.SourceImage:*PowerShell*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "process.executable", "process.command_line", "process.parent.executa… | 4 |  |
| q-2ced3d70da | triage T1111 step 2 | search | {"dataset": "windows.security", "query": "event.code:4648 AND user.name:pbeesly", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "process.executable", "win.TargetServerName", "win.TargetUserName", "win.SubjectUserName", … | 9 | F15 |
| q-63360ebb74 | triage T1111 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None | F15 |
| q-d8d315f158 | triage T1111 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*lsass*\" OR TO_LOWER(process.command_line) LIKE \"*scard*\" OR TO_LOWER(process.command_line) LIKE \"*smartcard*\" OR TO_L… | 2 |  |
| q-47fd76838d | triage T1111 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND process.pid == \"2976\" \| KEEP @timestamp, host.name, user.name, process.executable, process.command_line, process.parent.executable, process.parent.command_line… | ERROR |  |
| q-3bc55beafb | triage T1111 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.executable) LIKE \"*scard*\" OR TO_LOWER(process.executable) LIKE \"*credential*\" OR TO_LOWER(process.executable) LIKE \"*mfa*\" OR TO_LOWER(pr… | 0 |  |
| q-029f4e272a | triage T1111 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND process.pid == 2976 \| KEEP @timestamp, host.name, user.name, process.executable, process.command_line, process.parent.executable, process.parent.command_line, _i… | 1 |  |
| q-1848cd9dba | triage T1111 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND host.name == \"scranton.dmevals.local\" AND @timestamp >= \"2020-05-02T03:04:00.000Z\" AND @timestamp <= \"2020-05-02T03:06:30.000Z\" \| KEEP @timestamp, user.nam… | 17 |  |
| q-7db3edeb7a | triage T1111 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-a072ff26a6 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-da358c4602 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None |  |
| q-eb264066b8 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBorwtwa"} | None |  |
| q-6311b2ff84 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoNRGHW"} | None |  |
| q-a8790f0566 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByPYrDh"} | None |  |
| q-b0357f6723 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBunxq0T"} | None |  |
| q-f8a0cbf1be | triage T1111 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuu5GRH"} | None |  |
| q-ce1c756e4f | triage T1111 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeBwdMB1A"} | None |  |
| q-1df360d02a | triage T1187 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (win.TargetFilename:*.lnk OR win.TargetFilename:*.url OR win.TargetFilename:*.library-ms OR win.TargetFilename:*.searchConnector-ms)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.… | 3 |  |
| q-eb10e5ff08 | triage T1187 step 1 | get_event | {"index": ".ds-logs-windows.other-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeBwdMB0m"} | None | F16 |
| q-23dc754f83 | triage T1187 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoOSXoo"} | None | F16 |
| q-cab8f5a2f7 | triage T1187 step 2 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == 4104 AND host.name == \"scranton.dmevals.local\" \| KEEP @timestamp, host.name, user.name, win.ScriptBlockId, win.ScriptBlockText, _id, _index \| SORT @timestamp ASC \|… | ERROR |  |
| q-7f119c6028 | triage T1187 step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND host.name == \"scranton.dmevals.local\" \| KEEP @timestamp, host.name, user.name, win.ScriptBlockId, win.ScriptBlockText, _id, _index \| SORT @timestamp AS… | 60 | F16 |
| q-0baaa9fdd8 | triage T1187 step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND host.name == \"scranton.dmevals.local\" AND @timestamp > \"2020-05-02T03:01:51.000Z\" \| KEEP @timestamp, host.name, user.name, win.ScriptBlockText, _id, _… | 60 | F16 |
| q-dae21f5f28 | triage T1187 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"13\" AND TO_LOWER(registry.path) LIKE \"*classes\\\\folder*\" \| KEEP @timestamp, host.name, user.name, registry.path, registry.data.strings, process.executable, _id, _in… | ERROR |  |
| q-dd26a7f37b | triage T1187 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"13\" AND TO_LOWER(registry.path) LIKE \"*folder*\" \| KEEP @timestamp, host.name, user.name, registry.path, registry.data.strings, process.executable, _id, _index \| SORT… | 25 |  |
| q-a3dfbfa403 | triage T1187 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"3\" AND (destination.port == 445 OR destination.port == 139) \| KEEP @timestamp, host.name, user.name, process.executable, destination.ip, destination.port, _id, _index \… | 60 | F17 |
| q-17eb45703e | triage T1187 step 6 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4624\" AND win.LogonType == \"3\" \| STATS c = COUNT(*) BY win.AuthenticationPackageName, win.TargetUserName, host.name \| SORT c DESC \| LIMIT 30"} | 10 |  |
| q-800a8bd9e2 | triage T1187 step 6 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"5145\" \| KEEP @timestamp, host.name, win.SubjectUserName, win.ShareName, win.RelativeTargetName, win.IpAddress, _id, _index \| SORT @timestamp ASC \| LIMIT 40"} | 40 | F17 |
| q-f319480d1f | triage T1187 step 7 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4624\" AND win.AuthenticationPackageName == \"NTLM\" \| KEEP @timestamp, host.name, win.TargetUserName, win.LogonType, win.IpAddress, win.Workstation, win.ProcessName, … | 1 | F16 |
| q-9c976dcd3c | triage T1187 step 7 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaboN"} | None | F16 |
| q-a07f0b02a1 | triage T1187 step 8 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBosxeSr"} | None | F16 |
| q-6576a977ee | triage T1187 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBosxeSr"} | None |  |
| q-dc5301cc67 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBosxeSr"} | None |  |
| q-215a5b8699 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoOSXoo"} | None |  |
| q-8fafcc7838 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoOSXoo"} | None |  |
| q-197da08712 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaboN"} | None |  |
| q-3ddbf3fa2a | triage T1187 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRarq9"} | None |  |
| q-0e806262b2 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByYf107"} | None |  |
| q-bea4e68db3 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByYfl2t"} | None |  |
| q-1014d05f1d | triage T1187 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-9321d51ca4 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBufr2mI"} | None |  |
| q-3adc2ec84d | triage T1187 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeBwdMB0m"} | None |  |
| q-65d76eaebd | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgR9D"} | None |  |
| q-de2c49e35d | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgR9D"} | None |  |
| q-ebd0d61328 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoSWKN8"} | None |  |
| q-cbe2324e2c | triage T1187 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuv5CHV"} | None |  |
| q-765dff5fae | triage T1212 step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 10 AND win.TargetImage LIKE \"*lsass*\" AND win.GrantedAccess IN (\"0x1fffff\",\"0x101001\",\"0x1f3fff\",\"0x1000000\",\"0x3000\") \| KEEP @timestamp, host.name, process.ex… | ERROR |  |
| q-98b33c6c5d | triage T1212 step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 1 AND (process.command_line LIKE \"*lsass*\" OR process.command_line LIKE \"*dump*\" OR process.command_line LIKE \"*procdump*\" OR process.command_line LIKE \"*comsvcs*\")… | ERROR |  |
| q-f051f2f350 | triage T1212 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND win.TargetImage LIKE \"*lsass*\" AND win.GrantedAccess IN (\"0x1fffff\",\"0x101001\",\"0x1f3fff\",\"0x1000000\",\"0x3000\") \| KEEP @timestamp, host.name, proces… | 9 | F18, F19, F20 |
| q-b5af7faff2 | triage T1212 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (process.command_line LIKE \"*lsass*\" OR process.command_line LIKE \"*dump*\" OR process.command_line LIKE \"*procdump*\" OR process.command_line LIKE \"*comsvcs… | 1 | F20 |
| q-c4351a3578 | triage T1212 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-01c2e5bc86 | triage T1212 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None | F18 |
| q-6732c9cb62 | triage T1212 step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE @timestamp >= \"2020-05-02T03:00:00.000Z\" AND @timestamp <= \"2020-05-02T03:12:00.000Z\" AND host.name == \"scranton.dmevals.local\" AND event.code IN (\"4104\",\"4103\",\"4100\",\"… | 40 | F19 |
| q-a0db64da50 | triage T1212 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND host.name == \"scranton.dmevals.local\" AND process.pid == 2976 \| KEEP @timestamp, host.name, process.executable, process.command_line, process.parent.executable… | 1 | F18 |
| q-b8821fe065 | triage T1212 step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (win.ScriptBlockText LIKE \"*lsass*\" OR win.ScriptBlockText LIKE \"*MiniDump*\" OR win.ScriptBlockText LIKE \"*comsvcs*\" OR win.ScriptBlockText LIKE \"*p… | 3 | F18 |
| q-f116e3c428 | triage T1212 step 5 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBorwtwa"} | None |  |
| q-08c45ece1a | triage T1212 step 5 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByPYrDh"} | None |  |
| q-40c1bdb09d | triage T1212 step 6 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None | F19 |
| q-327e38cc8b | triage T1212 step 6 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4768\",\"4769\",\"4770\") \| KEEP @timestamp, host.name, event.code, win.TargetUserName, win.IpAddress, win.Status, win.TicketEncryptionType, _id, _index \| LIMIT 45"} | 42 | F18 |
| q-0da5d24198 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-3b9ffde1de | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-41ee52f5b8 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None |  |
| q-e2cee64d02 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None |  |
| q-472ad91387 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBorwtwa"} | None |  |
| q-b9ff7b1e85 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBorwtwa"} | None |  |
| q-947cc89338 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByPYrDh"} | None |  |
| q-8256d31b42 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuTlU_I"} | None |  |
| q-b84efa1533 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-91e5e1ce3e | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-d97f22356e | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-f71258efb9 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByDV_QB"} | None |  |
| q-501d0c0f26 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnqqYet"} | None |  |
| q-fc9a490d7d | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnTPq-O"} | None |  |
| q-c652cf51c8 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnaXZbr"} | None |  |
| q-0c83b21cdb | triage T1539 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRarqU"} | None |  |
| q-ff22a330fd | triage T1539 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByPYrDh"} | None | F21 |
| q-f5b5a1df52 | triage T1539 step 1 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*cookie* OR process.command_line:*Cookies* OR process.command_line:*Login Data*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "proce… | 4 | F21 |
| q-27eadcdcf4 | triage T1539 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(win.TargetFilename) LIKE \"*cookies*\" OR TO_LOWER(win.TargetFilename) LIKE \"*login data*\" OR TO_LOWER(win.TargetFilename) LIKE \"*web data*\" OR TO_… | 1 | F21 |
| q-a67d2de158 | triage T1539 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*cookies*\" OR TO_LOWER(process.command_line) LIKE \"*login data*\" OR TO_LOWER(process.command_line) LIKE \"*local state*\… | 3 | F21 |
| q-b04d6a9e2f | triage T1539 step 3 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4663\" AND (TO_LOWER(win.ObjectName) LIKE \"*cookies*\" OR TO_LOWER(win.ObjectName) LIKE \"*login data*\" OR TO_LOWER(win.ObjectName) LIKE \"*web data*\" OR TO_LOWER(wi… | 0 |  |
| q-74377e70bf | triage T1539 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND TO_LOWER(win.TargetFilename) LIKE \"*microsoftedge*\" \| KEEP @timestamp, host.name, user.name, process.executable, win.TargetFilename, _id, _index \| SORT @time… | 4 | F21 |
| q-b5835d3f83 | triage T1539 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE (event.code == \"11\" OR event.code == \"2\" OR event.code == \"15\" OR event.code == \"23\") AND (TO_LOWER(win.TargetFilename) LIKE \"*appdata*packages*\" OR TO_LOWER(win.TargetFilename… | 350 |  |
| q-592dbfd714 | triage T1539 step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*cookie*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*login data*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*sqlite*\" … | 6 |  |
| q-3e5dda5c81 | triage T1539 step 5 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None | F21 |
| q-0caca610d0 | triage T1539 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy3DhyQ"} | None |  |
| q-600c9e7cf1 | triage T1539 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuw76B1"} | None |  |
| q-88d0c762e2 | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBi1zvyC"} | None |  |
| q-b96758f707 | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBi1zfyN"} | None |  |
| q-e1e02eb83c | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnJGZ0U"} | None |  |
| q-4b3313fb63 | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBi-6ySm"} | None |  |
| q-ff2865e567 | triage T1539 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-286d7d3bea | triage T1539 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByPYrDh"} | None |  |
| q-3a2db39970 | triage T1552 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None | F22, F27 |
| q-f8e629725a | triage T1552 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND file.path:*.pfx", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "file.path", "process.executable", "process.command_line", "process.parent.executable"], "size": … | 1 | F22 |
| q-897925fc91 | triage T1552 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*passwordsDB* OR file.path:*nuget.config*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "file.path", "process.executable", "process.command_line", … | 2 | F24 |
| q-5acb4d3e47 | triage T1552 step 2 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == 4104 AND user.name == \"pbeesly\" \| KEEP @timestamp, host.name, user.name, win.ScriptBlockId, win.Path, win.ScriptBlockText \| SORT @timestamp ASC \| LIMIT 60"} | ERROR |  |
| q-2a803dc5b1 | triage T1552 step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND user.name == \"pbeesly\" \| KEEP @timestamp, host.name, user.name, win.ScriptBlockId, win.Path, win.ScriptBlockText \| SORT @timestamp ASC \| LIMIT 60"} | 60 |  |
| q-a03156a1d1 | triage T1552 step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND user.name == \"pbeesly\" AND @timestamp > \"2020-05-02T03:01:51.000Z\" \| KEEP @timestamp, host.name, user.name, win.ScriptBlockId, win.ScriptBlockText \| … | 60 |  |
| q-ea7d2db17a | triage T1552 step 4 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*accesschk* OR process.command_line:*passwordsDB* OR process.command_line:*SysinternalsSuite*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name… | 8 | F24 |
| q-7732423bd3 | triage T1552 step 5 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND user.name == \"pbeesly\" AND @timestamp > \"2020-05-02T03:06:47.000Z\" \| KEEP @timestamp, host.name, user.name, win.ScriptBlockId, win.ScriptBlockText \| … | 60 |  |
| q-019ae56e5e | triage T1552 step 5 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*Fl0nk3rt0n* OR process.command_line:*python.exe*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "process.executable", "process.command_li… | 9 | F23 |
| q-9b3e36e9fb | triage T1552 step 6 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByPYrDh"} | None | F23 |
| q-f6ac99eeb2 | triage T1552 step 6 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn78FjI"} | None | F23 |
| q-45d13a9a23 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-cc9a2d876a | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-95acb408a1 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQkXH"} | None |  |
| q-f5f2858c27 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQkXH"} | None |  |
| q-a3ced169dc | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-6b70743c01 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByPYrDh"} | None |  |
| q-e65d4fc180 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoz4z4i"} | None |  |
| q-47365a4362 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoz4j7h"} | None |  |
| q-a0fb6058d9 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoz4j7h"} | None |  |
| q-ab0a05a574 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByPYrDh"} | None |  |
| q-fb63be11b6 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn78FjI"} | None |  |
| q-13f6c687d9 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoNRGHl"} | None |  |
| q-e5753ead1c | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoNRGHl"} | None |  |
| q-4d689e979e | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoNRGHW"} | None |  |
| q-02533bdb11 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByYf107"} | None |  |
| q-e32e1d039b | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaboE"} | None |  |
| q-0e149d6dbe | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-e709763896 | triage T1555 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND NOT win.GrantedAccess:(0x1000 OR 0x1400)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "process.executable", "process.command_line", "win.Grante… | 9 |  |
| q-eba5708948 | triage T1555 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByPYrDh"} | None | F30 |
| q-4e24274fdf | triage T1555 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None | F28 |
| q-194675c2fd | triage T1555 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None | F28 |
| q-7057c75dcf | triage T1555 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 1 AND host.name == \"scranton.dmevals.local\" AND (process.pid == 2976 OR process.pid == 3876 OR process.pid == 3852) \| KEEP @timestamp, host.name, process.pid, process.ex… | ERROR |  |
| q-2d4abd583a | triage T1555 step 3 | search | {"dataset": "windows.security", "query": "event.code:4663 AND win.ObjectName:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "win.ObjectName", "win.ProcessName", "win.SubjectUserName", "win.AccessMask", "win.AccessList", "wi… | 6 | F28 |
| q-ecf2deafcf | triage T1555 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND host.name == \"scranton.dmevals.local\" \| KEEP @timestamp, host.name, process.pid, process.executable, process.command_line, process.parent.executable, user.name… | 359 |  |
| q-143f7a3709 | triage T1555 step 5 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND host.name == \"scranton.dmevals.local\" \| KEEP @timestamp, host.name, user.name, win.ScriptBlockId, win.Path, win.ScriptBlockText, _id, _index \| SORT @ti… | 146 |  |
| q-2684c9afe5 | triage T1555 step 6 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND @timestamp > \"2020-05-02T03:01:51.000Z\" \| KEEP @timestamp, host.name, user.name, win.ScriptBlockText, _id, _index \| SORT @timestamp ASC"} | 252 | F28 |
| q-f67b5d1176 | triage T1555 step 7 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND host.name == \"nashua.dmevals.local\" \| KEEP @timestamp, host.name, user.name, win.ScriptBlockText, _id, _index \| SORT @timestamp ASC"} | 11 | F28 |
| q-7c01717bbc | triage T1555 step 7 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*login data*\" OR TO_LOWER(file.path) LIKE \"*logins.json*\" OR TO_LOWER(file.path) LIKE \"*local state*\" OR TO_LOWER(file.path) LIK… | 1 | F29 |
| q-3493f157d5 | triage T1555 step 8 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None | F28 |
| q-286ececb54 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-b3416d90cf | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-ed20a40ca5 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None |  |
| q-2c7e143d64 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-3595e034ca | triage T1555 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy4FbI2"} | None |  |
| q-f9e4828b02 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy4FbI2"} | None |  |
| q-834c384c16 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-1691d84cba | triage T1555 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByCVtlI"} | None |  |
| q-e6fcc2d906 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBi-6ySm"} | None |  |
| q-f1d3746246 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBi-6ySm"} | None |  |
| q-404a893c85 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeBwdMB1A"} | None |  |
| q-fe95a4c6d5 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByPYrDh"} | None |  |
| q-039d28021c | triage T1556 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND (win.GrantedAccess:0x1fffff OR win.GrantedAccess:0x101001 OR win.GrantedAccess:0x1f3fff OR win.GrantedAccess:0x1000000 OR win.GrantedAccess:0x3000 OR win.GrantedAccess:0x1400… | 33 | F32 |
| q-c7a32415de | triage T1556 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND (win.SourceImage:*PowerShell* OR win.SourceImage:*wsmprovhost* OR win.SourceImage:*wininit* OR win.SourceImage:*csrss* OR win.SourceImage:*services.exe)", "time_from": null, … | 9 | F32 |
| q-26390e67bb | triage T1556 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None | F31 |
| q-5c428721b9 | triage T1556 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-c69ecae6dd | triage T1556 step 2 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == 4104 AND @timestamp >= \"2020-05-02T03:04:00.000Z\" AND @timestamp <= \"2020-05-02T03:10:00.000Z\" \| KEEP @timestamp, host.name, user.name, win.ScriptBlockId, win.Scri… | ERROR |  |
| q-7c9061e52f | triage T1556 step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND @timestamp >= \"2020-05-02T03:03:00.000Z\" AND @timestamp <= \"2020-05-02T03:11:00.000Z\" \| KEEP @timestamp, host.name, user.name, win.ScriptBlockId, win.… | 40 |  |
| q-b4bb2ea613 | triage T1556 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (process.command_line LIKE \"*lsass*\" OR process.command_line LIKE \"*MiniDump*\" OR process.command_line LIKE \"*comsvcs*\" OR process.command_line LIKE \"*proc… | 1 |  |
| q-810f342ae3 | triage T1556 step 4 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None | F31 |
| q-0a3e87bd88 | triage T1556 step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (win.ScriptBlockText LIKE \"*Invoke-Exfil*\" OR win.ScriptBlockText LIKE \"*Keystrokes*\" OR win.ScriptBlockText LIKE \"*credential*\" OR win.ScriptBlockTe… | 10 |  |
| q-8e51b30ee4 | triage T1556 step 5 | get_event | {"index": ".ds-logs-windows.other-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeBwdLx3H"} | None |  |
| q-62cae0b176 | triage T1556 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"13\" AND (registry.path LIKE \"*Notification Packages*\" OR registry.path LIKE \"*Security Packages*\" OR registry.path LIKE \"*Winlogon*\" OR registry.path LIKE \"*Netwo… | 12 |  |
| q-f6b880b4ac | triage T1556 step 6 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE win.ScriptBlockId == \"b2b03a9c-43f0-4285-837d-f22d4600b2ae\" \| KEEP @timestamp, host.name, user.name, win.ScriptBlockId, win.ScriptBlockText \| LIMIT 5"} | 1 |  |
| q-0dd098f7b5 | triage T1556 step 7 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByUbwtm"} | None | F34, F35 |
| q-ffdec59575 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-1b8e94160e | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-3938371ee2 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None |  |
| q-af049fd8e7 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None |  |
| q-6b0849815e | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnrrZmZ"} | None |  |
| q-7bcd0b023a | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnaXZbs"} | None |  |
| q-deb9c1ea06 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnqqYet"} | None |  |
| q-9485506b77 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnlknoR"} | None |  |
| q-c16fbf0c84 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoTW5Zx"} | None |  |
| q-b5b61c06dc | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoOSno9"} | None |  |
| q-bb0cf7a941 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoTW5b_"} | None |  |
| q-5a622d3b95 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByUbwtm"} | None |  |
| q-5c29e47deb | triage T1556 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByUbwtm"} | None |  |
| q-47f040a760 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByUbwtm"} | None |  |
| q-872b38f8f8 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoGKaib"} | None |  |
| q-51b2b49df0 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnlknoR"} | None |  |
| q-55c90c586e | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnlknoR"} | None |  |
| q-ca3926364e | triage T1556 step 9 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"13\" AND registry.path LIKE \"*Lsa*\" \| KEEP @timestamp, host.name, _id, _index, registry.path, registry.data.strings, process.executable \| LIMIT 10"} | 3 | F37 |
| q-8fb7b53b05 | triage T1557 step 1 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"conn\" AND (destination.port == 445 OR destination.port == 139 OR destination.port == 137 OR destination.port == 5355) \| KEEP @timestamp, event.action, source.ip, source.port, d… | 52 | F38, F39, F40 |
| q-dc07aa5011 | triage T1557 step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 1 AND (process.command_line LIKE \"*dhcp*\" OR process.command_line LIKE \"*ipconfig*\" OR process.command_line LIKE \"*route*\") \| KEEP @timestamp, host.name, user.name, … | ERROR |  |
| q-9de32fd136 | triage T1557 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (process.command_line LIKE \"*dhcp*\" OR process.command_line LIKE \"*ipconfig*\" OR process.command_line LIKE \"*route*\") \| KEEP @timestamp, host.name, user.na… | 6 | F40, F41 |
| q-783f436ec9 | triage T1557 step 2 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"dns\" \| KEEP @timestamp, source.ip, destination.ip, dns.question.name, dns.response_code, zeek.answers, zeek.qtype_name, _id, _index \| SORT @timestamp ASC"} | 53 | F39, F41 |
| q-c489beb033 | triage T1557 step 3 | esql | {"query": "FROM logs-windows.security METADATA _id, _index \| WHERE event.code == \"4624\" AND win.LogonProcessName RLIKE \".*NtLmSsp.*\" \| KEEP @timestamp, host.name, user.name, win.TargetUserName, win.LogonType, win.LogonProcessName, win.IpAddress, win.Work… | ERROR |  |
| q-6f17de713e | triage T1557 step 3 | esql | {"query": "FROM logs-windows.security METADATA _id, _index \| WHERE event.code == \"4697\" \| KEEP @timestamp, host.name, user.name, win.ServiceName, win.ServiceFileName, win.ServiceAccount, win.ServiceStartType, _id, _index"} | ERROR |  |
| q-2ddc9180aa | triage T1557 step 4 | search | {"dataset": "windows.security", "query": "event.code:4624 AND win.LogonProcessName:NtLmSsp", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.c… | 0 |  |
| q-2df7b457e0 | triage T1557 step 4 | search | {"dataset": "windows.security", "query": "event.code:4697", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 23 | F38 |
| q-307906f94c | triage T1557 step 5 | search | {"dataset": "windows.security", "query": "event.code:4624 AND win.LogonProcessName:*NtLm*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.co… | 1 |  |
| q-3e72d2f4a7 | triage T1557 step 5 | search | {"dataset": "windows.security", "query": "event.code:5145 AND win.ShareName:*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line",… | 121 |  |
| q-0a1475eea7 | triage T1557 step 6 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBufr2mI"} | None | F38, F41 |
| q-6fc3cdfb62 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBufr2mI"} | None |  |
| q-375e421f50 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBufr2mI"} | None |  |
| q-76d9b1500c | triage T1557 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBufr2mI"} | None |  |
| q-102f6e9694 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuq1HQ4"} | None |  |
| q-cb074045d8 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBufrmli"} | None |  |
| q-769675f875 | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgR_2"} | None |  |
| q-73ced28f8a | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgR_2"} | None |  |
| q-bdd36d7237 | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeByOjhn8"} | None |  |
| q-d28d01eec9 | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeByOjhn8"} | None |  |
| q-a43212b1d9 | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgR-S"} | None |  |
| q-f70d7bdc3a | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgR-S"} | None |  |
| q-d1c561d3e5 | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgR-J"} | None |  |
| q-9e8f0d2fae | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgh8D"} | None |  |
| q-c678b3a33e | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnEBpF6"} | None |  |
| q-4006e6537b | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnEBpF6"} | None |  |
| q-bdc97d6150 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnHC1-C"} | None |  |
| q-1f1fc687d8 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnHC1-C"} | None |  |
| q-c171c77dff | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgh-e"} | None |  |
| q-7516500a08 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBncaspm"} | None |  |
| q-97f351b72a | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBncaspm"} | None |  |
| q-e28f300c82 | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgR-a"} | None |  |
| q-2c2225490f | triage T1557 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBufr2mI"} | None |  |
| q-2ca967a37d | triage T1558 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass.exe AND (process.executable:*powershell.exe OR process.executable:*PowerShell.exe OR process.executable:*wsmprovhost.exe)", "time_from": null, "time_to": null, "fields": ["@timest… | 5 |  |
| q-a46d3c5dd8 | triage T1558 step 1 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"kerberos\" \| KEEP @timestamp, observer.name, source.ip, destination.ip, zeek.request_type, zeek.client, zeek.service, zeek.error_msg, zeek.success, zeek.forwardable, zeek.renewa… | 35 | F42, F43, F44, F45, F46 |
| q-04426dd94b | triage T1558 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None | F42 |
| q-07620e0662 | triage T1558 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None | F42 |
| q-129a42f9ff | triage T1558 step 2 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*lsass*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*mimikatz*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*sekurlsa*… | 0 |  |
| q-53eb625f5b | triage T1558 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" \| KEEP @timestamp, host.name, user.name, process.executable, process.command_line, process.parent.executable, _id, _index \| SORT @timestamp"} | 447 |  |
| q-d5bacf242e | triage T1558 step 3 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4624\" AND win.TargetUserName == \"pbeesly\" \| KEEP @timestamp, host.name, win.TargetUserName, win.LogonType, win.IpAddress, win.Workstation, win.LogonProcessName, win… | 30 |  |
| q-92cbf0f7fb | triage T1558 step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" \| KEEP @timestamp, host.name, user.name, win.ScriptBlockId, win.ScriptBlockText, _id, _index \| SORT @timestamp DESC \| LIMIT 25"} | 25 |  |
| q-2229601f58 | triage T1558 step 4 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4672\" OR event.code == \"4673\" \| KEEP @timestamp, host.name, event.code, win.SubjectUserName, win.PrivilegeList, win.ProcessName, win.Service, _id, _index \| SORT @t… | 40 | F43 |
| q-f65d09dec3 | triage T1558 step 5 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByKWlPk"} | None |  |
| q-f02aa99463 | triage T1558 step 5 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByKWlCc"} | None |  |
| q-d08351c526 | triage T1558 step 6 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy4FbJE"} | None | F45 |
| q-d5ab7ca78c | triage T1558 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-7904e8ce02 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-d712225e5a | triage T1558 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-4a3eb935e7 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-894b2cf5f2 | triage T1558 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgh9J"} | None |  |
| q-e8d84a1304 | triage T1558 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgh9K"} | None |  |
| q-0c8c0938e1 | triage T1558 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgR8w"} | None |  |
| q-ff10a4c968 | triage T1558 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgh9K"} | None |  |
| q-d039fc5c6b | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy3EfF3"} | None |  |
| q-30f950867d | triage T1558 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgR8s"} | None |  |
| q-7caa3ca278 | triage T1558 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgh8P"} | None |  |
| q-46c8d5d04e | triage T1558 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgh8Q"} | None |  |
| q-5a6382afac | triage T1558 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgR8v"} | None |  |
| q-5f95944388 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy4FbJE"} | None |  |
| q-4a3386c857 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy4FbJE"} | None |  |
| q-a802ca21a9 | triage T1558 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgR8t"} | None |  |
| q-3fe32c1975 | triage T1558 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgR8u"} | None |  |
| q-31edcb3a7a | triage T1558 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeByNi0EJ"} | None |  |
| q-d382914fbf | triage T1606 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaboq"} | None | F47 |
| q-bec431539b | triage T1606 step 1 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBi-6ySm"} | None | F48 |
| q-ebc4b173be | triage T1606 step 1 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBudppFX"} | None | F47 |
| q-397bff2299 | triage T1606 step 2 | aggregate | {"dataset": "windows.powershell", "field": "win.Path", "query": "event.code:4104", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 414 |  |
| q-9fc333c9bc | triage T1606 step 2 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 30, "sub_field": "win.LogonType"} | 297 |  |
| q-451db7af47 | triage T1606 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 10 AND win.GrantedAccess IN (\"0x1fffff\",\"0x1f3fff\",\"0x121440\",\"0x101541\",\"0x101441\",\"0x103800\",\"0x103801\",\"0x1014c0\",\"0x1000000\",\"0x101068\",\"0x2200\",\… | ERROR |  |
| q-9fe2cde208 | triage T1606 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 22 AND (TO_LOWER(dns.question.name) LIKE \"*adfs*\" OR TO_LOWER(dns.question.name) LIKE \"*sts*\" OR TO_LOWER(dns.question.name) LIKE \"*login*\" OR TO_LOWER(dns.question.n… | ERROR |  |
| q-bc731a25b8 | triage T1606 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND win.GrantedAccess IN (\"0x1fffff\",\"0x1f3fff\",\"0x121440\",\"0x101541\",\"0x101441\",\"0x103800\",\"0x103801\",\"0x1014c0\",\"0x1000000\",\"0x101068\",\"0x2200… | 40 |  |
| q-a5f37f4497 | triage T1606 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"22\" AND (TO_LOWER(dns.question.name) LIKE \"*adfs*\" OR TO_LOWER(dns.question.name) LIKE \"*sts*\" OR TO_LOWER(dns.question.name) LIKE \"*login*\" OR TO_LOWER(dns.questi… | 2 | F49 |
| q-583cf065e5 | triage T1606 step 5 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4648\" \| KEEP @timestamp, host.name, user.name, process.executable, win.TargetServerName, win.TargetUserName, source.ip, _id, _index \| SORT @timestamp ASC \| LIMIT 20… | 15 | F47 |
| q-4bbdb3e270 | triage T1606 step 5 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4624\" AND win.TargetUserName == \"pbeesly\" \| STATS c = COUNT(*) BY host.name, win.LogonType, win.IpAddress, win.AuthenticationPackageName \| SORT c DESC \| LIMIT 20"… | 7 |  |
| q-4a64e13650 | triage T1606 step 6 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(win.TargetFilename) LIKE \"*login data*\" OR TO_LOWER(win.TargetFilename) LIKE \"*cookies*\" OR TO_LOWER(win.TargetFilename) LIKE \"*webcache*\" OR TO_… | 1 |  |
| q-0a9955d83a | triage T1606 step 6 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4688\" AND (TO_LOWER(process.command_line) LIKE \"*cookie*\" OR TO_LOWER(process.command_line) LIKE \"*saml*\" OR TO_LOWER(process.command_line) LIKE \"*adfs*\" OR TO_L… | 6 | F48 |
| q-4454632886 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBunxq0T"} | None |  |
| q-88e16352a1 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuu5GRH"} | None |  |
| q-7718f1e295 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBudppFX"} | None |  |
| q-c8e4272bf0 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaboq"} | None |  |
| q-4ffa68cb39 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaboq"} | None |  |
| q-1c5ea76462 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBunxq22"} | None |  |
| q-67045710fd | triage T1606 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBunxq22"} | None |  |
| q-b78692d5e1 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBi-6ySm"} | None |  |
| q-d59c8cb1b4 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBi-6ySm"} | None |  |
| q-879c5e6159 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoJM2Xy"} | None |  |
| q-bf465ebce8 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoJM2Xy"} | None |  |
| q-3551eae845 | triage T1621 step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*mfa*\" OR TO_LOWER(process.command_line) LIKE \"*2fa*\" OR TO_LOWER(process.command_line) LIKE \"*authenticator*\" OR TO_L… | 29 |  |
| q-4a3ba1c9a6 | triage T1621 step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (process.executable LIKE \"*dsregcmd*\" OR process.executable LIKE \"*PsExec64*\" OR process.executable LIKE \"*sdelete64*\" OR process.executable LIKE \"*python.… | 24 |  |
| q-49f3c46e6e | triage T1621 step 2 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*mfa*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*2fa*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*authenticator*\" OR … | 0 |  |
| q-7f4654aff0 | triage T1621 step 2 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4688\" AND (TO_LOWER(process.command_line) LIKE \"*mfa*\" OR TO_LOWER(process.command_line) LIKE \"*2fa*\" OR TO_LOWER(process.command_line) LIKE \"*authenticator*\" OR… | 5 |  |
| q-945e9914a6 | triage T1621 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"3\" AND (TO_LOWER(destination.ip) LIKE \"*login*\" OR TO_LOWER(win.DestinationHostname) LIKE \"*microsoft*\" OR TO_LOWER(win.DestinationHostname) LIKE \"*azure*\" OR TO_L… | ERROR |  |
| q-61bff02178 | triage T1621 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"3\" AND process.executable LIKE \"*python.exe*\" \| KEEP @timestamp, host.name, user.name, process.executable, win.DestinationHostname, destination.ip, destination.port, … | 348 |  |
| q-62118bd77e | triage T1621 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"22\" OR event.code == \"3\" \| WHERE TO_LOWER(win.QueryName) LIKE \"*microsoft*\" OR TO_LOWER(win.QueryName) LIKE \"*okta*\" OR TO_LOWER(win.QueryName) LIKE \"*duo*\" OR … | 14 |  |
| q-16ff9a2ccc | triage T1621 step 4 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4624\" AND win.LogonType == \"10\" \| KEEP @timestamp, host.name, user.name, win.TargetUserName, source.ip, win.LogonType, win.LogonProcessName, _id, _index"} | 2 |  |
| q-fde6253da5 | triage T1621 step 5 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBi30BSA"} | None | F50 |
| q-22188b4f82 | triage T1621 step 5 | esql | {"query": "FROM logs-windows.other-default METADATA _id, _index \| WHERE TO_LOWER(message) LIKE \"*mfa*\" OR TO_LOWER(message) LIKE \"*multi-factor*\" OR TO_LOWER(message) LIKE \"*authenticator*\" OR TO_LOWER(message) LIKE \"*two-factor*\" OR TO_LOWER(message)… | 0 |  |
| q-3a4e204e4a | triage T1621 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBi30BSA"} | None |  |
| q-3740e03882 | triage T1621 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBi30BSA"} | None |  |
| q-ddcc5cafda | triage T1621 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBi30BSA"} | None |  |
| q-3b83c1e22d | triage T1621 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBi30BSA"} | None |  |
| q-bf45250718 | triage T1621 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBi30BSA"} | None |  |
| q-6c2825efe4 | triage T1621 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBi30BRX"} | None |  |
| q-b82a383803 | triage T1621 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBoz3z5O"} | ERROR |  |
| q-2dbbf95d41 | triage T1621 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnaX5as"} | None |  |
| q-5edc95ccda | triage T1621 step 7 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBoz3z5O"} | ERROR |  |
| q-d45ab94b54 | triage T1621 step 8 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnaX5as"} | None | F50 |
| q-4e6763d367 | triage T1621 step 8 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBi30BRX"} | None | F50 |
| q-3fcd20b8e2 | triage T1649 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None | F51 |
| q-cde81f5295 | triage T1649 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND win.TargetFilename:*pfx*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "process.executable", "process.command_line", "win.TargetFilename", "win.Image"], "size"… | 1 |  |
| q-d2d27e32a2 | triage T1649 step 1 | search | {"dataset": "windows.security", "query": "event.code:4657 AND win.ObjectName:*SystemCertificates*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "process.executable", "win.ObjectName", "win.ObjectValueName", "win.Opera… | 1 | F52 |
| q-68936a0c57 | triage T1649 step 2 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuu4mRU"} | None | F52 |
| q-1337c4e449 | triage T1649 step 2 | search | {"dataset": "windows.sysmon", "query": "user.name:pbeesly AND (event.code:1 OR event.code:11 OR event.code:13)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "event.code", "process.executable", "process.command_line", … | 141 |  |
| q-8426ce5828 | triage T1649 step 2 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*cert* OR win.ScriptBlockText:*Cert* OR win.ScriptBlockText:*pfx* OR win.ScriptBlockText:*PrivateKey*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.nam… | 5 |  |
| q-823aa968c1 | triage T1649 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQkXH"} | None | F51 |
| q-79a0372e66 | triage T1649 step 3 | search | {"dataset": "windows.security", "query": "event.code:4768 AND win.PreAuthType:*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "event.code", "win.TargetUserName", "win.LogonType", "win.AuthenticationPackageName", "win.… | 14 | F53 |
| q-5400cf58bf | triage T1649 step 3 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (win.TargetFilename:*Downloads* OR win.TargetFilename:*OfficeSupplies*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "event.code", "process.executable", "proc… | 315 |  |
| q-51a1832531 | triage T1649 step 4 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByCVdnF"} | None | F51 |
| q-477f5b261a | triage T1649 step 4 | search | {"dataset": "windows.sysmon", "query": "event.code:23 AND win.TargetFilename:*pfx*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "event.code", "process.executable", "process.command_line", "win.TargetFilename", "win.T… | 1 | F51 |
| q-c24a77e0eb | triage T1649 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-d719533793 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-84de22bb91 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-0eddff200d | triage T1649 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQkXH"} | None |  |
| q-02864638c7 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQkXH"} | None |  |
| q-676d07668e | triage T1649 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByCVdnF"} | None |  |
| q-fb5567670c | triage T1649 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn77ViM"} | None |  |
| q-693fa5b638 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn77ViM"} | None |  |
| q-9b9a2b73ae | triage T1649 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuu4mRU"} | None |  |
| q-391350b9e8 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuu4mRU"} | None |  |
| q-d980c88485 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuu4mRU"} | None |  |
| q-a9934ea5e0 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuy-fsg"} | None |  |
| q-1a3c094fd3 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBus3Fam"} | None |  |
| q-e52b30d3cd | triage T1649 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuhtIn4"} | None |  |
| q-c9f327a213 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-a7c595a793 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None |  |
| q-623ab71ff2 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy4FbI2"} | None |  |
| q-b2a3a24f62 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy4FbI2"} | None |  |
| q-f58191f431 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-7a224c4987 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUUD"} | None |  |
| q-a9db57ab02 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBow1KRR"} | None |  |
| q-fceba9b800 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoSVqPo"} | None |  |
| q-aa8c04cdd4 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaboC"} | None |  |
| q-b4440ea4bd | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBukwKVF"} | None |  |
| q-43578c0e79 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBumw-cX"} | None |  |
| q-21786f2420 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBumw-cX"} | None |  |
| q-82badc5321 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuYnMlG"} | None |  |
| q-da5e641de8 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuYnMlG"} | None |  |
| q-c1a3b703b4 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuWmJOo"} | None |  |
| q-632e3d1308 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnvvDAD"} | None |  |
| q-609749cc19 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnvvDAD"} | None |  |
| q-1ea3f4f317 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnDAQqo"} | None |  |
| q-d8a3d85135 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnfd0sF"} | None |  |
| q-9e7e40443f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnFCvgF"} | None |  |
| q-4a98fbb00b | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgR8i"} | None |  |
| q-053590be55 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-9ee2c6d945 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-621bfb166c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None |  |
| q-3dd0a198e0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None |  |
| q-30f3c01848 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUUD"} | None |  |
| q-e6d55c952c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBi85SQC"} | ERROR |  |
| q-c734f27dce | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRabqD"} | None |  |
| q-c6c43c473d | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRabqD"} | None |  |
| q-6db8f8d122 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRZ7r5"} | None |  |
| q-9d093c58c2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoHL6FX"} | None |  |
| q-a16787ffa6 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBi85SQC"} | ERROR |  |
| q-3050b6d0ca | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBizx7td"} | ERROR |  |
| q-9f43acdeaa | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByXfnRy"} | None |  |
| q-ab7cc56671 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None |  |
| q-f673d0d638 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-b8aa2ccce7 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-786a830dde | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-d6269aaa31 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuu5GRH"} | None |  |
| q-e1214ec8e8 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBupz0Op"} | None |  |
| q-b0eb031d75 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-775e9e9d71 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByPYrDh"} | None |  |
| q-1147b7ecd4 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-da1dc5d1b9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None |  |
| q-234655695d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBorwtwa"} | None |  |
| q-ee4eaf5f19 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByYfl1_"} | None |  |
| q-4b39024948 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBudp5HI"} | None |  |
| q-7870b6cb32 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuu42Tt"} | None |  |
| q-e228f236c6 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBunxq0T"} | None |  |
| q-747116932b | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByPYrDh"} | None |  |
| q-4fa764bd0f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-12cd93fe4f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-f07e62bb8b | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuu5GRH"} | None |  |
| q-41f28e1591 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBosxeSr"} | None |  |
| q-4dc857b5c5 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBosxeSr"} | None |  |
| q-807273d6d3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoOSXoo"} | None |  |
| q-bc636531a5 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoOSXoo"} | None |  |
| q-e3cbfa7947 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaboN"} | None |  |
| q-c3656c5cfb | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRarq9"} | None |  |
| q-1b957fe18f | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByYf107"} | None |  |
| q-c00e532a5c | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByYfl2t"} | None |  |
| q-c59ace9954 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-aa5828748a | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBufr2mI"} | None |  |
| q-1a8f5f80d2 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeBwdMB0m"} | None |  |
| q-8f9f0a581f | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgR9D"} | None |  |
| q-b2e5119ab2 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgR9D"} | None |  |
| q-d8e4af8466 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoSWKN8"} | None |  |
| q-729428def6 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuv5CHV"} | None |  |
| q-0f5c21018b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-ea91728a3f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-49c4dc167d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None |  |
| q-5380bc5390 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None |  |
| q-9be1772ba8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBorwtwa"} | None |  |
| q-de8a528f44 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBorwtwa"} | None |  |
| q-1d8c479b01 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByPYrDh"} | None |  |
| q-ad71715104 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuTlU_I"} | None |  |
| q-b664546710 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-6b22bc17ab | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-89ba55cde2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-169a77c934 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByDV_QB"} | None |  |
| q-78cced7d71 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnqqYet"} | None |  |
| q-6158168397 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnTPq-O"} | None |  |
| q-ef0c5f6ca0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnaXZbr"} | None |  |
| q-930af653fe | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy3DhyQ"} | None |  |
| q-05f3bb9170 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuw76B1"} | None |  |
| q-5e40a7bd15 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBi1zvyC"} | None |  |
| q-2962803cd3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBi1zfyN"} | None |  |
| q-8fe7f811b7 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnJGZ0U"} | None |  |
| q-7e6837a582 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBi-6ySm"} | None |  |
| q-64f63998de | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-4888bb9ac3 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByPYrDh"} | None |  |
| q-108d6470c7 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-f430590b30 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-2af27fb8fd | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQkXH"} | None |  |
| q-19299068ac | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQkXH"} | None |  |
| q-16eb7251cf | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-9ffa930faa | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByPYrDh"} | None |  |
| q-15f50a6297 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoz4z4i"} | None |  |
| q-408d0f79ec | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoz4j7h"} | None |  |
| q-25b4eec410 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoz4j7h"} | None |  |
| q-bc6f810223 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByPYrDh"} | None |  |
| q-92a5d5b2d5 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn78FjI"} | None |  |
| q-4523e30470 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoNRGHl"} | None |  |
| q-f635f55f8a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoNRGHl"} | None |  |
| q-7829735274 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoNRGHW"} | None |  |
| q-dcaffb4d98 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByYf107"} | None |  |
| q-6cad959c6a | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaboE"} | None |  |
| q-95fc48307f | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-9d6417468b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-ad99839e73 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-304afc5309 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None |  |
| q-e48acf258f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-b0a0dbe5e2 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy4FbI2"} | None |  |
| q-a887572127 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy4FbI2"} | None |  |
| q-e11fdb299e | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-889e7a012e | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByCVtlI"} | None |  |
| q-cfee2d5e0c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBi-6ySm"} | None |  |
| q-e716aa26c4 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBi-6ySm"} | None |  |
| q-fb44e0c6b1 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeBwdMB1A"} | None |  |
| q-7a9af0c199 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByPYrDh"} | None |  |
| q-cd55c057be | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-3bc95f7f1c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-f7cd8df7b8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None |  |
| q-ba808decf8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None |  |
| q-448cb2340d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnrrZmZ"} | None |  |
| q-9b4fcd8d10 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnaXZbs"} | None |  |
| q-350c374324 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnqqYet"} | None |  |
| q-d0eedcb593 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnlknoR"} | None |  |
| q-09d73bb6e4 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoTW5Zx"} | None |  |
| q-1b8d2aecbc | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoOSno9"} | None |  |
| q-2bff78c0cd | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoTW5b_"} | None |  |
| q-0b5a5022a9 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByUbwtm"} | None |  |
| q-f319a1cfa5 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByUbwtm"} | None |  |
| q-3323f8e861 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByUbwtm"} | None |  |
| q-31a172f2a4 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoGKaib"} | None |  |
| q-c81f186f41 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnaXZbu"} | None |  |
| q-e48c9b2eea | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnaXZbu"} | None |  |
| q-8d041d262d | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBufr2mI"} | None |  |
| q-5d21c22c75 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBufr2mI"} | None |  |
| q-1b6eb15d9e | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBufr2mI"} | None |  |
| q-7a2d9e6d8d | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuq1HQ4"} | None |  |
| q-6249aad37d | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBufrmli"} | None |  |
| q-5253f98c45 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgR_2"} | None |  |
| q-b03e689069 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgR_2"} | None |  |
| q-809e12bc10 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeByOjhn8"} | None |  |
| q-c10360e073 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeByOjhn8"} | None |  |
| q-7e39441892 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgR-S"} | None |  |
| q-ec85a282e6 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgR-S"} | None |  |
| q-c8d3a0313d | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgR-J"} | None |  |
| q-6a2ed1e334 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgh8D"} | None |  |
| q-9255bde34b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnEBpF6"} | None |  |
| q-a5744c6952 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnEBpF6"} | None |  |
| q-e28c820949 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnHC1-C"} | None |  |
| q-f46795f150 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnHC1-C"} | None |  |
| q-6fcd383413 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgh-e"} | None |  |
| q-6c364ce5dc | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBncaspm"} | None |  |
| q-609efb7485 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBncaspm"} | None |  |
| q-428d634506 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgR-a"} | None |  |
| q-918deeb437 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBufr2mI"} | None |  |
| q-d33552706a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-cc8a8b02bb | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-095c40f6ba | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-3f6e71ec52 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-7076c688df | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgh9J"} | None |  |
| q-99bd31ccad | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgh9K"} | None |  |
| q-c2117885c1 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgR8w"} | None |  |
| q-9f0e44ac74 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgh9K"} | None |  |
| q-1424ac1c43 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy3EfF3"} | None |  |
| q-5ab1f82e8f | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgR8s"} | None |  |
| q-f7f37d8c41 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgh8P"} | None |  |
| q-83491a36c9 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgh8Q"} | None |  |
| q-3093b0365c | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgR8v"} | None |  |
| q-1178ccbbeb | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy4FbJE"} | None |  |
| q-6c116121e8 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy4FbJE"} | None |  |
| q-04b455139c | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgR8t"} | None |  |
| q-0528085fc8 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgR8u"} | None |  |
| q-ff17d5d358 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeByNi0EJ"} | None |  |
| q-ed3aa493a2 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBunxq0T"} | None |  |
| q-1986d72fc2 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuu5GRH"} | None |  |
| q-ede2a5c9d2 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBudppFX"} | None |  |
| q-82c0c470f4 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaboq"} | None |  |
| q-1153c77a55 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaboq"} | None |  |
| q-8f2d15ffc4 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBunxq22"} | None |  |
| q-eab7d69874 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBunxq22"} | None |  |
| q-50e23eb87f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBi-6ySm"} | None |  |
| q-692f851aea | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBi-6ySm"} | None |  |
| q-4a3aa67868 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoJM2Xy"} | None |  |
| q-8c6826a934 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoJM2Xy"} | None |  |
| q-e02f880bff | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBi30BSA"} | None |  |
| q-7ff1ef3201 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBi30BSA"} | None |  |
| q-3162e39c73 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBi30BSA"} | None |  |
| q-ec7cdc340d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBi30BSA"} | None |  |
| q-442e62869a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBi30BSA"} | None |  |
| q-aec8a9e773 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBi30BRX"} | None |  |
| q-ec789d3b56 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnaX5as"} | None |  |
| q-903b4ce32d | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-4e5ebc576e | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-51386ab3ca | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-586bf2a04e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQkXH"} | None |  |
| q-ee205c6a60 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQkXH"} | None |  |
| q-3f68941754 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByCVdnF"} | None |  |
| q-0476d69afb | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn77ViM"} | None |  |
| q-789b298359 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn77ViM"} | None |  |
| q-d267bb9865 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuu4mRU"} | None |  |
| q-96f40b4ab3 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuu4mRU"} | None |  |
| q-bf1a181157 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuu4mRU"} | None |  |
| q-8ef6e4872d | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuy-fsg"} | None |  |
| q-0113981255 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBus3Fam"} | None |  |
| q-12ebbe32ba | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuhtIn4"} | None |  |
| q-c4f2e6f8f1 | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND host.name:\"nashua.dmevals.local\"", "time_from": "2020-05-02T02:54:28+00:00", "time_to": "2020-05-02T03:31:52+00:00", "size": 100, "sub_field": "process.parent.executable"… | 61 |  |
| q-3eff8e63f7 | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11 AND host.name:\"nashua.dmevals.local\"", "time_from": "2020-05-02T02:54:28+00:00", "time_to": "2020-05-02T03:31:52+00:00", "size": 100, "sub_field": "process.executable"} | 249 |  |
| q-6319ad4fa8 | pivot seed | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND host.name:\"nashua.dmevals.local\"", "time_from": "2020-05-02T02:54:28+00:00", "time_to": "2020-05-02T03:31:52+00:00", "size": 100, "sub_field": "process.parent.execut… | 63 |  |
| q-ff0fc33420 | pivot seed | aggregate | {"dataset": "windows.powershell", "field": "event.code", "query": "host.name:\"nashua.dmevals.local\"", "time_from": "2020-05-02T02:54:28+00:00", "time_to": "2020-05-02T03:31:52+00:00", "size": 100, "sub_field": null} | 192 |  |
| q-2933c03504 | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND host.name:\"newyork.dmevals.local\"", "time_from": "2020-05-02T03:05:45+00:00", "time_to": "2020-05-02T03:35:45+00:00", "size": 100, "sub_field": "process.parent.executable… | 7 |  |
| q-7888a1c472 | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11 AND host.name:\"newyork.dmevals.local\"", "time_from": "2020-05-02T03:05:45+00:00", "time_to": "2020-05-02T03:35:45+00:00", "size": 100, "sub_field": "process.executable"} | 50 |  |
| q-e4850bb132 | pivot seed | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND host.name:\"newyork.dmevals.local\"", "time_from": "2020-05-02T03:05:45+00:00", "time_to": "2020-05-02T03:35:45+00:00", "size": 100, "sub_field": "process.parent.execu… | 7 |  |
| q-e592a9fd99 | pivot seed | aggregate | {"dataset": "windows.powershell", "field": "event.code", "query": "host.name:\"newyork.dmevals.local\"", "time_from": "2020-05-02T03:05:45+00:00", "time_to": "2020-05-02T03:35:45+00:00", "size": 100, "sub_field": null} | 975 |  |
| q-e7c47b396e | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND host.name:\"scranton.dmevals.local\"", "time_from": "2020-05-02T02:40:56.157000+00:00", "time_to": "2020-05-02T03:35:41+00:00", "size": 100, "sub_field": "process.parent.ex… | 359 |  |
| q-8893f536d7 | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11 AND host.name:\"scranton.dmevals.local\"", "time_from": "2020-05-02T02:40:56.157000+00:00", "time_to": "2020-05-02T03:35:41+00:00", "size": 100, "sub_field": "process.executable"} | 1276 |  |
| q-697e5b7f2f | pivot seed | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND host.name:\"scranton.dmevals.local\"", "time_from": "2020-05-02T02:40:56.157000+00:00", "time_to": "2020-05-02T03:35:41+00:00", "size": 100, "sub_field": "process.pare… | 370 |  |
| q-1a424ae456 | pivot seed | aggregate | {"dataset": "windows.powershell", "field": "event.code", "query": "host.name:\"scranton.dmevals.local\"", "time_from": "2020-05-02T02:40:56.157000+00:00", "time_to": "2020-05-02T03:35:41+00:00", "size": 100, "sub_field": null} | 8602 |  |
| q-b74d6a0772 | pivot step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 1 AND (process.executable LIKE \"*SysinternalsSuite*\" OR process.executable LIKE \"*\\\\\\\\Temp\\\\\\\\*\" OR process.executable LIKE \"*victim*\" OR process.executable L… | ERROR |  |
| q-39b6ad83e3 | pivot step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 11 AND (file.path LIKE \"*victim*\" OR file.path LIKE \"*Sysinternals*\" OR file.path LIKE \"*passwords*\" OR file.path LIKE \"*.pfx\" OR file.path LIKE \"*.scr\" OR file.p… | ERROR |  |
| q-2d40d7195e | pivot step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (process.executable LIKE \"*SysinternalsSuite*\" OR process.executable LIKE \"*\\\\\\\\Temp\\\\\\\\*\" OR process.executable LIKE \"*victim*\" OR process.executab… | 24 | F54, F56, F57 |
| q-51479bc687 | pivot step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (file.path LIKE \"*victim*\" OR file.path LIKE \"*Sysinternals*\" OR file.path LIKE \"*passwords*\" OR file.path LIKE \"*.pfx\" OR file.path LIKE \"*.scr\" OR fi… | 500 |  |
| q-ba6def6722 | pivot step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND host.name == \"nashua.dmevals.local\" \| KEEP @timestamp, host.name, user.name, powershell.script_block_text, _id, _index \| SORT @timestamp ASC"} | ERROR |  |
| q-7022bb7b56 | pivot step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND host.name == \"nashua.dmevals.local\" AND (file.path LIKE \"*pbeesly*\" OR file.path LIKE \"*Temp*\" OR file.path LIKE \"*ProgramData*\") \| KEEP @timestamp, pro… | 145 |  |
| q-15421eeeab | pivot step 4 | get_fields | {"dataset": "windows.powershell", "prefix": ""} | None |  |
| q-9d8a078a3c | pivot step 4 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4663\",\"5145\",\"4656\") AND (file.path LIKE \"*SAM*\" OR file.path LIKE \"*SECURITY*\" OR file.path LIKE \"*SYSTEM*\" OR file.path LIKE \"*NTDS*\" OR file.path LIKE … | ERROR |  |
| q-a078ecb4e6 | pivot step 5 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND host.name == \"nashua.dmevals.local\" \| KEEP @timestamp, user.name, win.ScriptBlockText, _id, _index \| SORT @timestamp ASC"} | 11 | F54 |
| q-65b96cd87b | pivot step 5 | get_fields | {"dataset": "windows.security", "prefix": "win"} | None |  |
| q-0520247262 | pivot step 6 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByDVjze"} | None | F54 |
| q-2113ca37a5 | pivot step 6 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4663\",\"5145\",\"4656\") AND (win.ObjectName LIKE \"*SAM*\" OR win.ObjectName LIKE \"*SECURITY*\" OR win.ObjectName LIKE \"*NTDS*\" OR win.ObjectName LIKE \"*pass*\" … | 10 |  |
| q-c2b284e3b2 | pivot step 7 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBudp5HI"} | None | F55 |
| q-163ab64104 | pivot step 7 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code IN (\"12\",\"13\",\"14\") AND (registry.path LIKE \"*SECURITY*Policy*Secrets*\" OR registry.path LIKE \"*Vault*\" OR registry.path LIKE \"*CredMan*\" OR registry.path LIKE \"*… | ERROR |  |
| q-d926c74bb0 | pivot step 8 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code IN (\"12\",\"13\",\"14\") AND (registry.path LIKE \"*Policy*Secrets*\" OR registry.path LIKE \"*Vault*\" OR registry.path LIKE \"*CredMan*\" OR registry.path LIKE \"*Control*L… | 65 |  |
| q-5223d2ab8f | pivot step 8 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND (target.process.executable LIKE \"*lsass*\" OR target.process.executable LIKE \"*winlogon*\" OR target.process.executable LIKE \"*vaultsvc*\" OR target.process.e… | ERROR |  |
| q-4d3fba9f8f | pivot step 9 | get_fields | {"dataset": "windows.sysmon", "prefix": "win"} | None |  |
| q-e1abb93210 | pivot step 10 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND (win.TargetImage LIKE \"*lsass*\" OR win.TargetImage LIKE \"*winlogon*\" OR win.TargetImage LIKE \"*vaultsvc*\" OR win.TargetImage LIKE \"*svchost*\" OR win.Targ… | 500 |  |
| q-0f58d71ffd | pivot step 11 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" \| STATS cnt = COUNT(*) BY win.SourceImage, win.TargetImage, win.GrantedAccess \| SORT cnt ASC \| LIMIT 40"} | 40 |  |
| q-989d5f64d9 | pivot step 12 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND (win.SourceImage LIKE \"*powershell*\" OR win.SourceImage LIKE \"*wsmprovhost*\" OR win.SourceImage LIKE \"*python*\" OR win.SourceImage LIKE \"*Rar*\" OR win.So… | 455 | F57 |
| q-d9b3859937 | pivot verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByDVjze"} | None |  |
| q-da95189f5b | pivot verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByCVMj0"} | None |  |
| q-5cd519ada7 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBow1qSj"} | None |  |
| q-ba349c4f10 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnnmUud"} | None |  |
| q-1d301289b2 | pivot verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBudp5HI"} | None |  |
| q-38967e5d37 | pivot verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBudp5HI"} | None |  |
| q-8535afe96a | pivot verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBudp5HI"} | None |  |
| q-78e9aea3ec | pivot verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBudp5HI"} | None |  |
| q-9103dabe2e | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoinp4Y"} | None |  |
| q-ff5da3c0e7 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-f6f7e8e8db | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None |  |
| q-49608e83a5 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy4FbI2"} | None |  |
| q-97d95f9c06 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy4FbI2"} | None |  |
| q-0a9e2bd527 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-ba0cae5d67 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUUD"} | None |  |
| q-89f3582c63 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBow1KRR"} | None |  |
| q-2f42da8968 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoSVqPo"} | None |  |
| q-3a2e7108bb | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaboC"} | None |  |
| q-545ade74dd | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBukwKVF"} | None |  |
| q-34178db356 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBumw-cX"} | None |  |
| q-b6e4be257b | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBumw-cX"} | None |  |
| q-3865894e80 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuYnMlG"} | None |  |
| q-f2eee846bf | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuYnMlG"} | None |  |
| q-2b20b51879 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuWmJOo"} | None |  |
| q-c0ea05ce48 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnvvDAD"} | None |  |
| q-b38c9c0308 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnvvDAD"} | None |  |
| q-5419f8699c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnDAQqo"} | None |  |
| q-a796b21095 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnfd0sF"} | None |  |
| q-8632de328a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnFCvgF"} | None |  |
| q-4c9ecef7eb | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgR8i"} | None |  |
| q-ebe57c67ca | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-7e60c675db | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-00636ea987 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None |  |
| q-28afa61a53 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None |  |
| q-02c5915b51 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUUD"} | None |  |
| q-2fd908432a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBi85SQC"} | ERROR |  |
| q-01a65ddc29 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRabqD"} | None |  |
| q-d6a034aebe | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRabqD"} | None |  |
| q-1c0e40ce2f | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRZ7r5"} | None |  |
| q-8ae4b7a381 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoHL6FX"} | None |  |
| q-042764bd5f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBi85SQC"} | ERROR |  |
| q-b83dc030a5 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBizx7td"} | ERROR |  |
| q-9e635123b2 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByXfnRy"} | None |  |
| q-78331eb6e2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None |  |
| q-7497d4963a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-8399a46dc4 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-b1c2329415 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-db7126e152 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuu5GRH"} | None |  |
| q-a5d67a0296 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBupz0Op"} | None |  |
| q-82569887c8 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-611355405d | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByPYrDh"} | None |  |
| q-e603907343 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-d5a54193fb | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None |  |
| q-894d4c1110 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBorwtwa"} | None |  |
| q-6d6f51d200 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByYfl1_"} | None |  |
| q-d4ce250391 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBudp5HI"} | None |  |
| q-47119baca7 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuu42Tt"} | None |  |
| q-b9c1a4cad3 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBunxq0T"} | None |  |
| q-0cd0707ffb | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByPYrDh"} | None |  |
| q-800d883565 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-72c681e64b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-6d0818c6a5 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuu5GRH"} | None |  |
| q-6c2457c7ef | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBosxeSr"} | None |  |
| q-491201a926 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBosxeSr"} | None |  |
| q-978faf3cb1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoOSXoo"} | None |  |
| q-da75f996b8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoOSXoo"} | None |  |
| q-629cff3670 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaboN"} | None |  |
| q-503fabe950 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRarq9"} | None |  |
| q-6dfb4d8f6d | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByYf107"} | None |  |
| q-bb2ccd60ea | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByYfl2t"} | None |  |
| q-f9345f5f04 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-65ffd86fd5 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBufr2mI"} | None |  |
| q-e4dc6b3d5d | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeBwdMB0m"} | None |  |
| q-ea83fd661a | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgR9D"} | None |  |
| q-542c30aea1 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgR9D"} | None |  |
| q-9fb35e2071 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoSWKN8"} | None |  |
| q-a5320dce00 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuv5CHV"} | None |  |
| q-2117fd0f78 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-76ff868b02 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-518dc44668 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None |  |
| q-836cdd13f4 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None |  |
| q-17ce1e4a04 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBorwtwa"} | None |  |
| q-e310e541a0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBorwtwa"} | None |  |
| q-f20ab04188 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByPYrDh"} | None |  |
| q-2c11d12991 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuTlU_I"} | None |  |
| q-a76dba8102 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-f48c27c64f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-4f0a38bc3c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-4474e462e3 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByDV_QB"} | None |  |
| q-f767f13482 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnqqYet"} | None |  |
| q-086627b9a2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnTPq-O"} | None |  |
| q-02ffbdd300 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnaXZbr"} | None |  |
| q-451844ba75 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy3DhyQ"} | None |  |
| q-a3deadfd49 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuw76B1"} | None |  |
| q-e50724d44c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBi1zvyC"} | None |  |
| q-cb4b17d809 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBi1zfyN"} | None |  |
| q-b30be7e272 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnJGZ0U"} | None |  |
| q-06677df9b8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBi-6ySm"} | None |  |
| q-32ad3ced8d | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-6c1d9348da | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByPYrDh"} | None |  |
| q-0669b7f328 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-380ec26a8b | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-aa48c9452a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQkXH"} | None |  |
| q-ce2e5c978b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQkXH"} | None |  |
| q-05380f4707 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-bdd68e63e2 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByPYrDh"} | None |  |
| q-431a9954b7 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoz4z4i"} | None |  |
| q-2e42355a5b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoz4j7h"} | None |  |
| q-5b73672de8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoz4j7h"} | None |  |
| q-de394c789a | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByPYrDh"} | None |  |
| q-f1580915fe | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn78FjI"} | None |  |
| q-eb459c2ef7 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoNRGHl"} | None |  |
| q-588e394f3f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoNRGHl"} | None |  |
| q-575c149ad1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoNRGHW"} | None |  |
| q-f77a768112 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByYf107"} | None |  |
| q-9bed44a402 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaboE"} | None |  |
| q-39f84b9435 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-707922f26a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-a8ac661106 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-96663663c5 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None |  |
| q-08c2bfb841 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-b8ae6d94ea | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy4FbI2"} | None |  |
| q-3af612c275 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy4FbI2"} | None |  |
| q-3dba583ae8 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-ab22de0ddc | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByCVtlI"} | None |  |
| q-8073e73454 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBi-6ySm"} | None |  |
| q-2dfc731c01 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBi-6ySm"} | None |  |
| q-3a74b4f3ed | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeBwdMB1A"} | None |  |
| q-d7decb88db | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByPYrDh"} | None |  |
| q-5ed6cabbeb | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-186fcaf8a0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-2f0319f6f5 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None |  |
| q-6b3490654a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXF"} | None |  |
| q-70c346bc1f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnrrZmZ"} | None |  |
| q-604ed148f1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnaXZbs"} | None |  |
| q-e013024c77 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnqqYet"} | None |  |
| q-2d65c5d7a7 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnlknoR"} | None |  |
| q-8889929f48 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoTW5Zx"} | None |  |
| q-5dbfc40527 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoOSno9"} | None |  |
| q-c91467cb89 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoTW5b_"} | None |  |
| q-49336ef549 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByUbwtm"} | None |  |
| q-a125a3e50d | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByUbwtm"} | None |  |
| q-5e191e8140 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByUbwtm"} | None |  |
| q-a8026912bf | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoGKaib"} | None |  |
| q-89bf6a3dee | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnaXZbu"} | None |  |
| q-20daee7460 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnaXZbu"} | None |  |
| q-003ba7758b | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBufr2mI"} | None |  |
| q-9898b28edc | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBufr2mI"} | None |  |
| q-cbcdc7eae4 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBufr2mI"} | None |  |
| q-05703782c4 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuq1HQ4"} | None |  |
| q-b2b164b9ac | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBufrmli"} | None |  |
| q-dcd045e3bd | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgR_2"} | None |  |
| q-a77e9ed1f1 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgR_2"} | None |  |
| q-d2cfed1636 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeByOjhn8"} | None |  |
| q-3af7ed1c30 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeByOjhn8"} | None |  |
| q-914edd2630 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgR-S"} | None |  |
| q-06cbe54faf | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgR-S"} | None |  |
| q-2571750586 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgR-J"} | None |  |
| q-68c2234008 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgh8D"} | None |  |
| q-eb82640564 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnEBpF6"} | None |  |
| q-ae95c38d5a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnEBpF6"} | None |  |
| q-57866370be | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnHC1-C"} | None |  |
| q-573f1e3e89 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnHC1-C"} | None |  |
| q-de60906c48 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgh-e"} | None |  |
| q-d347615393 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBncaspm"} | None |  |
| q-9956aba448 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBncaspm"} | None |  |
| q-998dbd9c83 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgR-a"} | None |  |
| q-45e95dedd6 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBufr2mI"} | None |  |
| q-16758e61d4 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-5a7c294df5 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQUXI"} | None |  |
| q-85195bb4e8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-fb8159ef68 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn663fz"} | None |  |
| q-ebedb59413 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgh9J"} | None |  |
| q-712f09d545 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgh9K"} | None |  |
| q-9430886fce | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgR8w"} | None |  |
| q-0ce9219e9f | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgh9K"} | None |  |
| q-05736911fc | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy3EfF3"} | None |  |
| q-86c6ce1e52 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgR8s"} | None |  |
| q-bb84f6ffed | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgh8P"} | None |  |
| q-9f671850f9 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgh8Q"} | None |  |
| q-54fc515d87 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgR8v"} | None |  |
| q-2534a01417 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy4FbJE"} | None |  |
| q-d7b535c5ce | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBy4FbJE"} | None |  |
| q-d60f4d11bb | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgR8t"} | None |  |
| q-3f0abdf726 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeBwkgR8u"} | None |  |
| q-19afd8d7ea | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.22-000001", "id": "AaFiKZc9VXKkeByNi0EJ"} | None |  |
| q-d277c1f16d | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBunxq0T"} | None |  |
| q-506812783d | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuu5GRH"} | None |  |
| q-565df63680 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBudppFX"} | None |  |
| q-42bf6f91d9 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaboq"} | None |  |
| q-fd3578b1c2 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaboq"} | None |  |
| q-b01c6db78f | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBunxq22"} | None |  |
| q-c92c427555 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBunxq22"} | None |  |
| q-5dd1e9b9b4 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBi-6ySm"} | None |  |
| q-691616024a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBi-6ySm"} | None |  |
| q-9968af8861 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoJM2Xy"} | None |  |
| q-4a41240f7b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoJM2Xy"} | None |  |
| q-47ee4f307d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBi30BSA"} | None |  |
| q-267a664199 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBi30BSA"} | None |  |
| q-dd4dfed303 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBi30BSA"} | None |  |
| q-46cbdfe8c6 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBi30BSA"} | None |  |
| q-6a0679be9e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBi30BSA"} | None |  |
| q-6ce1e4aa02 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBi30BRX"} | None |  |
| q-ec03cae35e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnaX5as"} | None |  |
| q-3c39fcc493 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-5b5b0f4a3e | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-3e2e5ff52f | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByRaLqc"} | None |  |
| q-716a931b70 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQkXH"} | None |  |
| q-581c247c12 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoMQkXH"} | None |  |
| q-9e4c7b48b0 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByCVdnF"} | None |  |
| q-76852bc62c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn77ViM"} | None |  |
| q-2da696353d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBn77ViM"} | None |  |
| q-159e49c6b4 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuu4mRU"} | None |  |
| q-209dc622d5 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuu4mRU"} | None |  |
| q-0b2421c306 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuu4mRU"} | None |  |
| q-861d2d0264 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuy-fsg"} | None |  |
| q-2b602c63ab | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBus3Fam"} | None |  |
| q-1d930a5fe3 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBuhtIn4"} | None |  |
| q-624ae3f18e | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByDVjze"} | None |  |
| q-0a66616771 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.22-000001", "id": "AaFiKJc9VXKkeByCVMj0"} | None |  |
| q-f1ecad41f6 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBow1qSj"} | None |  |
| q-84dee1e962 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBnnmUud"} | None |  |
| q-ff41979a28 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBudp5HI"} | None |  |
| q-9aa2edff2a | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBudp5HI"} | None |  |
| q-c21868a632 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBudp5HI"} | None |  |
| q-88864fa2dc | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBudp5HI"} | None |  |
| q-d785a5ae30 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoz4z4i"} | None |  |
| q-7ceaa849f5 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoNRGHW"} | None |  |
| q-3aa5902064 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBoSVqPo"} | None |  |
| q-a088b38a1f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJpc9VXKkeBi30hQJ"} | None |  |
| q-b445ae12ae | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.22-000001", "id": "AaFiJ5c9VXKkeBow1KRZ"} | None |  |

## Verification

Evidence items cited: 222; confirmed against the stored events: 219; rejected: 3. Each item was re-fetched with get_event; it is confirmed only if the event exists, the cited field holds the cited value, and the cited query_id is a query of this run that returned that event.
Evidence sent back to the agents for correction during the run: 11 item(s) in 7 submission(s) (one correction round each; what still failed was rejected).

## Limitations

- Findings describe what the stored logs show; activity these sources did not log cannot be seen.
- Datasets with non-overlapping time windows (see Data examined) were analysed separately.
- Long field values are shortened in this report; full events are retrievable by _index/_id.
