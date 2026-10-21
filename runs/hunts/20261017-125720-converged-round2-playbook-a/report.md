# Threat hunt report — 20261017-125720-converged-round2-playbook-a

**Hypothesis:** An adversary who compromised Windows hosts in this network stole credentials from them (MITRE ATT&CK tactic: Credential Access).

**Verdict: Confirmed** — 8 in-scope incident(s) of verified malicious findings (confidence >= medium): I01 T1003.001 (F01, F10, F20, F30, F34, F58), I05 T1056.001 (F09), I06 T1187 (F18), I07 T1552 (F02, F61), I08 T1552 (F60), I09 T1552.001 (F24, F56), I11 T1552.001 (F59), I12 T1552.004 (F25, F50, F54, F57)

Verdict method: rules over verified evidence (Confirmed if >=1 in-scope incident of verified malicious findings (confidence >= medium); Inconclusive if only suspicious incidents or coverage gaps; Refuted if full coverage and no malicious/suspicious finding)

| Run | Value |
|---|---|
| Profile | converged (thinking=False, temperature=0.0) |
| Model | deepseek-flash |
| Started / finished (UTC) | 2026-10-17T04:57:20+00:00 / 2026-10-17T05:05:46+00:00 (505.9 s) |
| LLM calls / tokens | 158 / {'prompt': 5131837, 'completion': 104249} |
| MCP tool calls | 1352 (server tools: list_data_sources, get_fields, search, count, aggregate, timeline, esql, get_event, get_registry) |
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
| I01 | T1003.001 | yes | malicious/high | F01, F10, F20, F30, F34, F58 | LSASS memory access with full-access masks by PowerShell on scranton |
| I02 | T1003.001 | yes | suspicious/low | F21 | PowerShell LSASS full-access open during hands-on-keyboard intrusion (T1212 framing) |
| I03 | T1003.001 | yes | suspicious/medium | F45 | No Kerberos ticket theft/forgery; LSASS handle access by PowerShell on scranton |
| I04 | T1003.001 | yes | suspicious/medium | F52 | No SAML token forgery; LSASS access by PowerShell/wsmprovhost |
| I05 | T1056.001 | yes | malicious/high | F09 | Keystroke-Check AV-evasion function and remote keylogger deployment to nashua |
| I06 | T1187 | yes | malicious/high | F18 | WebDAV/UNC forced-authentication exfil path from scranton to 192.168.0.4 |
| I07 | T1552 | yes | malicious/high | F02, F61 | Credential-access tooling staged on scranton (Sysinternals, keylogger, exfil scripts) |
| I08 | T1552 | yes | malicious/high | F60 | Attacker tooling staged in C:\Windows\Temp on nashua |
| I09 | T1552.001 | yes | malicious/high | F24, F56 | Credential-named file harvesting and archiving on scranton and nashua |
| I10 | T1552.001 | yes | suspicious/medium | F26 | accesschk.exe creating passwordsDB in SysinternalsSuite directory |
| I11 | T1552.001 | yes | malicious/high | F59 | Cleartext pbeesly password on PsExec64 command lines to NASHUA |
| I12 | T1552.004 | yes | malicious/high | F25, F50, F54, F57 | Get-PrivateKeys certificate private-key export to .pfx on scranton |
| I13 | out-of-scope:T1021.002 | no | suspicious/medium | F15 | No password spraying; valid pbeesly credentials reused via PsExec64 to NASHUA |
| I14 | out-of-scope:T1021.002 | no | malicious/high | F41 | Credential-theft campaign on scranton with lateral SMB/PsExec movement to nashua |
| I15 | out-of-scope:T1027.004 | no | malicious/medium | F63 | csc.exe compiling attacker .NET payloads from PowerShell response files |
| I16 | out-of-scope:T1059.001 | no | suspicious/medium | F17 | No MFA interception; PowerShell Remoting logon-session enumeration on nashua |
| I17 | out-of-scope:T1218.002 | no | malicious/medium | F62 | Screen-saver payload in C:\ProgramData\victim launched on scranton |
| I18 | out-of-scope:T1218.011 | no | suspicious/low | F65 | sdclt.exe execution proxy before payload compilation |
| I19 | out-of-scope:T1548.002 | no | suspicious/medium | F64 | hostui.exe elevation attempt and registry-stored encoded PowerShell stager |

## Findings

### F02 · malicious / medium · T1003 · Credential-access tooling staged on scranton: Sysinternals suite, keystroke logger, archive/exfil scripts

Evidence status: **verified**

In the same pbeesly session on scranton.dmevals.local the attacker expanded SysinternalsSuite.zip into the user's Downloads (03:00:25Z), ran a keystroke-capture function (Get-Keystrokes / Keystroke-Check with AV-process checks at 03:06:47Z), and defined Invoke-Exfil which 7-Zips the Downloads folder with password 'lolol' and copies it to a WebDAV share at \\192.168.0.4\webdav using hardcoded credentials (cozy / MyCozyPassw0rd!). On nashua.dmevals.local the same user enumerated processes with Get-Process -IncludeUserName and archived documents/password-named files with Compress-Archive and Rar.exe. This is credential/secret collection and staging around the LSASS access, though no standalone dumping utility (mimikatz/procdump/comsvcs) command line was observed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JL8F_6E7 | q-8175bd1e6c | ok |
| 2 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\psversion.ps1 | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JL8F_6E7 | q-3eab162185 | ok |
| 3 | 2020-05-02 03:00:25.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | Expand-Archive -LiteralPath "$env:USERPROFILE\Downloads\SysinternalsSuite.zip" -DestinationPath "$env:USERPROFILE\Downloads\" | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMAWIxZm | q-8370c17773 | ok |
| 4 | 2020-05-02 03:06:59.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | Get-Keystrokes;Start-Sleep -Seconds 15;View-Job -JobName "Keystrokes" | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMAQDFlH | q-8370c17773 | ok |
| 5 | 2020-05-02 03:15:59.000Z | nashua.dmevals.local | windows.powershell | win.ScriptBlockText | $env:APPDATA;$files=ChildItem -Path $env:USERPROFILE\ -Include *.doc,*.xps,*.xls,*.ppt,*.pps,*.wps,*.wpd,*.ods,*.odt,*.lwp,*.jtd,*.pdf,*.zip,*.rar,*.docx,*.url,… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMANA6l9 | q-2134dd860f | ok |

### F01 · malicious / high · T1003.001 · PowerShell process opened LSASS with full-access masks (0x1F3FFF / 0x1FFFFF) on scranton

Evidence status: **verified**

On scranton.dmevals.local, the PowerShell.exe process (PID 2976, entity {47ab858c-e1e4-5eac-b803-000000000400}) opened lsass.exe (PID 736) twice within 31 ms at 2020-05-02T03:05:16.623Z and 03:05:16.654Z with GrantedAccess 0x1f3fff and 0x1fffff — PROCESS_ALL_ACCESS-class masks that include memory read, the classic signature of LSASS memory credential dumping. The call trace ends in UNKNOWN modules (ntdll.dll+9c584\|KERNELBASE.dll+2732e\|UNKNOWN(...)), i.e. code not backed by a known on-disk module. This same PID 2976 was created at 02:58:44.325Z by control.exe with a hidden, execution-policy-bypass command that decoded a payload from the pixels of C:\Users\pbeesly\Downloads\monkey.png and IEX'd it (steganography loader), and the same PID 2976 then ran a VirtualAlloc/CreateThread shellcode loader script block. All other LSASS opens in the dataset are svchost.exe with 0x1000/0x1400 (benign), so these two are the only memory-read-class accesses.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63CNnH | q-373202e423 | ok |
| 2 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63CNnH | q-373202e423 | ok |
| 3 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.CallTrace | C:\windows\SYSTEM32\ntdll.dll+9c584\|C:\windows\System32\KERNELBASE.dll+2732e\|UNKNOWN(000001996D252982) | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63CNnH | q-e8e4921e2b | ok |
| 4 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63CAlf | q-373202e423 | ok |
| 5 | 2020-05-02 02:58:44.325Z | scranton.dmevals.local | windows.sysmon | process.command_line | "PowerShell.exe" -noni -noexit -ep bypass -window hidden -c "sal a New-Object;Add-Type -AssemblyName 'System.Drawing'; $g=a System.Drawing.Bitmap('C:\Users\pbee… | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL7ViMbT | q-0910761de9 | ok |
| 6 | 2020-05-02 02:58:45.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | $cFIrwwpZzGzU = @"  [DllImport("kernel32.dll")]  public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMAWIxa2 | q-12d93ed668 | ok |

### F09 · malicious / high · T1056.001 · Keystroke-Check AV-evasion function staged in psversion.ps1 on scranton, followed by remote keylogger deployment to nashua

Evidence status: **verified**

On 2020-05-02 at 03:06:47Z user pbeesly on scranton.dmevals.local created a PowerShell scriptblock defining 'function Keystroke-Check' that enumerates running processes to detect AV products (avp, outpost, kav, AvastSvc, nod32, MsMpEng, ekrn, savservice ...), stored in C:\Program Files\SysinternalsSuite\psversion.ps1. At 03:11-03:15Z the same user launched PsExec64.exe from scranton against \\NASHUA with cleartext credentials (-u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2) to run C:\Windows\Temp\python.exe; on nashua that python.exe (PyInstaller bundle extracted to C:\Users\pbeesly\AppData\Local\Temp\_MEI29522, including pywintypes27.dll/win32pipe.pyd) was spawned by PSEXESVC.exe, dropped Rar.exe and sdelete64.exe into C:\Windows\Temp, and opened cmd.exe and powershell.exe with GrantedAccess 0x1fffff (PROCESS_ALL_ACCESS). This is a keylogger/input-capture toolchain with anti-AV checks and staging/cleanup utilities.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:06:47.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Keystroke-Check {     Get-Process \| Where-Object { $_.ProcessName -Eq "avp" -or $_.ProcessName -Eq "acs" -or $_.ProcessName -Eq "outpost" -or $_.Proce… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMAQC1lL | q-cb34a3afb1 | ok |
| 2 | 2020-05-02 03:06:47.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\psversion.ps1 | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMAQC1lL | q-7e105d8b54 | ok |
| 3 | 2020-05-02 03:11:18.784Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\PsExec64.exe" -accepteula \\NASHUA -u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2ioON3 | q-9679637c95 | ok |
| 4 | 2020-05-02 03:11:40.213Z | nashua.dmevals.local | windows.sysmon | process.parent.executable | C:\Windows\PSEXESVC.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2in-NH | q-9679637c95 | ok |
| 5 | 2020-05-02 03:15:48.656Z | nashua.dmevals.local | windows.sysmon | win.TargetImage | C:\windows\System32\WindowsPowerShell\v1.0\powershell.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2bgTcg | q-a7bfecf533 | ok |
| 6 | 2020-05-02 03:15:48.656Z | nashua.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2bgTcg | q-a7bfecf533 | ok |
| 7 | 2020-05-02 03:15:31.530Z | nashua.dmevals.local | windows.sysmon | file.path | C:\Windows\Temp\Rar.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2bgTei | q-bfb4843222 | ok |
| 8 | 2020-05-02 03:15:04.213Z | nashua.dmevals.local | windows.sysmon | file.path | C:\Users\pbeesly\AppData\Local\Temp\_MEI29522\pywintypes27.dll | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2bgjf5 | q-bfb4843222 | ok |

### F10 · malicious / medium · T1056.004 · PowerShell and wsmprovhost opened LSASS with full access (0x1f3fff / 0x1fffff) on scranton and nashua

Evidence status: **verified**

Sysmon event 10 shows C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe (PID 2976, scranton) requesting GrantedAccess 0x1f3fff and 0x1fffff on lsass.exe at 03:05:16Z, and wsmprovhost.exe (PID 7720, nashua) requesting 0x1f3fff on lsass.exe at 03:09:29Z with a call trace through System.ni.dll / Microsoft.PowerShell.Commands.Management.ni.dll (i.e. a PowerShell cmdlet, not a native API). These are the only non-system processes in the dataset with all-access LSASS handles; the remaining LSASS opens are svchost 0x1000, Azure telemetry/antimalware 0x1400 and OS boot processes (wininit/csrss). The all-access LSASS handles coincide with the pbeesly intrusion chain (Keystroke-Check script, PsExec to nashua, python.exe payload), consistent with credential/API-hooking style access to LSASS memory.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63CNnH | q-a5b6261104 | ok |
| 2 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63CNnH | q-6c55db3682 | ok |
| 3 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63CAlf | q-a5b6261104 | ok |
| 4 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2kp9uH | q-2f8ece4fc3 | ok |
| 5 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2kp9uH | q-a5b6261104 | ok |

### F18 · malicious / high · T1187 · WebDAV/UNC forced-authentication path used by pbeesly PowerShell exfil tooling on SCRANTON (10.0.1.4) toward 192.168.0.4

Evidence status: **verified**

On scranton.dmevals.local, user DMEVALS\pbeesly ran a PowerShell toolkit (loaded from C:\Program Files\SysinternalsSuite\psversion.ps1) that defines Invoke-Exfil. The scriptblock maps a network drive to the UNC path \\192.168.0.4\webdav with explicit credentials (cozy / MyCozyPassw0rd!) via New-PSDrive and copies $env:APPDATA\OfficeSupplies.7z to it. Sysmon shows powershell.exe (PID 3852, DMEVALS\pbeesly) initiating TCP/80 to 192.168.0.4 at 2020-05-02T03:08:47Z, followed by svchost.exe (LOCAL SERVICE) connections to 192.168.0.4:80 at 03:08:50Z and 03:10:23Z — the WebClient/WebDAV redirector behaviour that turns a UNC path into HTTP. In the Zeek window (2020-04-30, non-overlapping) the same host 10.0.1.4 is seen probing 192.168.0.4: SMB 445/139 rejected (REJ) at 00:32:14–00:32:18Z, then WebDAV HTTP with user agent Microsoft-WebDAV-MiniRedir/10.0.18362 and DavClnt issuing OPTIONS/PROPFIND to /webdav, /webdav/OfficeSupplies.7z and /webdav/python.exe (00:32:18–00:32:21Z and 00:35:25Z). This is the forced-authentication/WebDAV coercion pattern (SMB blocked, fallback to WebDAV over HTTP) used to push credentials to an attacker-controlled listener. The same host also set HKCU Folder\shell\open\command to a hidden PowerShell one-liner and later ran Invoke-SeaDukeStage against NASHUA, so the activity is clearly attacker-driven, not administrative.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JL8F_6E7 | q-03dcca92b4 | ok |
| 2 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JL8F_6E7 | q-03dcca92b4 | ok |
| 3 | 2020-05-02 03:08:47.769Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2lq7yE | q-ac65e5f3f3 | ok |
| 4 | 2020-05-02 03:08:47.769Z | scranton.dmevals.local | windows.sysmon | destination.ip | 192.168.0.4 | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2lq7yE | q-ac65e5f3f3 | ok |
| 5 | 2020-05-02 03:08:50.904Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\Windows\System32\svchost.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2kqttk | q-5e28e8b9be | ok |
| 6 | 2020-04-30 00:32:18.095Z | simplerockbuild.simplerock.lan | zeek | user_agent.original | DavClnt | .ds-logs-zeek-default-2026.10.17-000001 / AaFIKqWOc7y0JMDGKA5C | q-1c022781f1 | ok |
| 7 | 2020-04-30 00:32:21.422Z | simplerockbuild.simplerock.lan | zeek | user_agent.original | Microsoft-WebDAV-MiniRedir/10.0.18362 | .ds-logs-zeek-default-2026.10.17-000001 / AaFIKqWOc7y0JMDGJw17 | q-57f692007d | ok |
| 8 | 2020-04-30 00:32:21.895Z | simplerockbuild.simplerock.lan | zeek | url.original | /webdav/OfficeSupplies.7z | .ds-logs-zeek-default-2026.10.17-000001 / AaFIKqWOc7y0JMDGKA5I | q-57f692007d | ok |
| 9 | 2020-04-30 00:32:14.891Z | simplerockbuild.simplerock.lan | zeek | zeek.conn_state | REJ | .ds-logs-zeek-default-2026.10.17-000001 / AaFIKqWOc7y0JMDGKA0a | q-efeca6a34f | ok |
| 10 | 2020-05-02 02:58:18.576Z | scranton.dmevals.local | windows.sysmon | registry.path | HKU\S-1-5-21-1830255721-3727074217-2423397540-1107_Classes\Folder\shell\open\command\(Default) | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL7WjMdm | q-647e458781 | ok |

### F20 · malicious / high · T1212 · PowerShell on scranton.dmevals.local opened lsass.exe with full-access masks (0x1F3FFF / 0x1FFFFF) during a hands-on-keyboard intrusion by user pbeesly

Evidence status: **verified**

On scranton.dmevals.local, PowerShell.exe (PID 2976, running as SYSTEM per the Sysmon event's AccountName) opened the lsass.exe process (PID 736) twice within 31 ms at 2020-05-02T03:05:16Z with GrantedAccess 0x1F3FFF and 0x1FFFFF — PROCESS_ALL_ACCESS-class rights that permit reading credential material from LSASS. The call trace is ntdll.dll+KERNELBASE.dll followed by an UNKNOWN module, i.e. not a normal Windows component. This is not isolated: the same host/user pbeesly shows a full intrusion chain in the same window — registry Folder\shell\open\command persistence (02:57), a bitmap-steganography loader that decodes a PNG into shellcode and IEXs it (02:58:45), SysinternalsSuite.zip expansion (03:00), an 'Invoke-Exfil' script block that 7-Zips the Downloads folder with password 'lolol' and copies it to \\192.168.0.4\webdav using hardcoded credentials (03:08), and a hidden base64-encoded powershell -nop -w hidden -e launch (03:21:28). The lsass access is therefore part of malicious post-exploitation, consistent with exploitation/abuse of the credential store rather than any legitimate tooling. Note: the 0x1FFFFF accesses by wininit.exe/csrss.exe at 03:19:09 coincide with a SYSTEM logon type 0 (boot) and are normal boot-time behaviour; the svchost 0x101001/0x3000 accesses are likewise service-manager activity. Only the PowerShell-sourced accesses are attributed as malicious.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63CAlf | q-208bc5e55e | ok |
| 2 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63CAlf | q-208bc5e55e | ok |
| 3 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.TargetImage | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63CAlf | q-208bc5e55e | ok |
| 4 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.CallTrace | C:\windows\SYSTEM32\ntdll.dll+9c584\|C:\windows\System32\KERNELBASE.dll+2732e\|UNKNOWN(000001996D28200D) | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63CAlf | q-208bc5e55e | ok |
| 5 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63CNnH | q-f8237ba8d3 | ok |
| 6 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | host.name | scranton.dmevals.local | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63CNnH | q-f8237ba8d3 | ok |
| 7 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JL8F_6E7 | q-a3378e96ae | ok |
| 8 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | user.name | pbeesly | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JL8F_6E7 | q-a3378e96ae | ok |
| 9 | 2020-05-02 02:58:45.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | sal a New-Object;Add-Type -AssemblyName 'System.Drawing'; $g=a System.Drawing.Bitmap('C:\Users\pbeesly\Downloads\monkey.png');$o=a Byte[] 4480;for($i=0; $i -le … | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMAWIhac | q-3460dd1d72 | ok |
| 10 | 2020-05-02 03:21:28.949Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\windows\System32\WindowsPowerShell\v1.0\powershell.exe" -nop -w hidden -e aQBmACgAWwBJAG4AdABQAHQAcgBdADoAOgBTAGkAegBlACAALQBlAHEAIAA0ACkAewAkAGIAPQAkAGUAbg… | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL17AQxS | q-9dc88c122b | ok |

### F24 · malicious / high · T1552 · Adversary staged and archived credential-named files from pbeesly's profile on scranton and nashua

Evidence status: **verified**

On scranton.dmevals.local at 2020-05-02T02:56:17Z, in a PowerShell session running as DMEVALS\pbeesly (PID 5944) that was spawned from cmd.exe, which itself was spawned by C:\ProgramData\victim\â€®cod.3aka3.scr, the attacker enumerated the user profile for files matching *psw*, *pass*, *login*, *admin*, *sifr*, *sifer*, *vpn and archived them to C:\Users\pbeesly\AppData\Roaming\Draft.Zip (created 02:56:18Z). The identical credential-targeting archive script ran on nashua.dmevals.local at 03:15:59Z, producing C:\Users\pbeesly\AppData\Roaming\working.zip (03:16:00Z), which was then packed with password-protected Rar.exe into C:\Users\pbeesly\Desktop\working.zip (03:16:19Z). Both archives were later wiped with sdelete64.exe. This is deliberate collection of unsecured credential material, not normal user behaviour.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:56:17.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | $env:APPDATA;$files=ChildItem -Path $env:USERPROFILE\ -Include *.doc,*.xps,*.xls,*.ppt,*.pps,*.wps,*.wpd,*.ods,*.odt,*.lwp,*.jtd,*.pdf,*.zip,*.rar,*.docx,*.url,… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMAWIxak | q-5552bcef81 | ok |
| 2 | 2020-05-02 02:56:18.032Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Users\pbeesly\AppData\Roaming\Draft.Zip | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL7YlLDM | q-f0976a4634 | ok |
| 3 | 2020-05-02 03:15:59.000Z | nashua.dmevals.local | windows.powershell | win.ScriptBlockText | $env:APPDATA;$files=ChildItem -Path $env:USERPROFILE\ -Include *.doc,*.xps,*.xls,*.ppt,*.pps,*.wps,*.wpd,*.ods,*.odt,*.lwp,*.jtd,*.pdf,*.zip,*.rar,*.docx,*.url,… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMANA6l9 | q-e4469457da | ok |
| 4 | 2020-05-02 03:16:19.462Z | nashua.dmevals.local | windows.sysmon | win.TargetFilename | C:\Users\pbeesly\Desktop\working.zip | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2ZequJ | q-e9e2f404a4 | ok |
| 5 | 2020-05-02 03:16:19.395Z | nashua.dmevals.local | windows.sysmon | process.command_line | "C:\Windows\Temp\Rar.exe" a -hpfGzq5yKw C:\Users\pbeesly\Desktop\working.zip C:\Users\pbeesly\AppData\Roaming\working.zip | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2Ze6tB | q-5c821681c4 | ok |
| 6 | 2020-05-02 02:55:56.157Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\ProgramData\victim\â€®cod.3aka3.scr | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL7am0gN | q-76eb6e4449 | ok |

### F60 · malicious / high · T1552 · Attacker tooling staged in C:\Windows\Temp on nashua (python.exe, Rar.exe, sdelete64.exe)

Evidence status: **verified**

C:\Windows\Temp\python.exe was started four times by PSEXESVC under pbeesly and spawned the harvesting PowerShell, Rar.exe and cmd.exe/sdelete64.exe cleanup.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:40.213Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2in-NH | q-96e856fb73 | ok |
| 2 | 2020-05-02 03:15:48.652Z | nashua.dmevals.local | windows.sysmon | process.parent.executable | C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2bgTcf | q-96e856fb73 | ok |

### F61 · malicious / high · T1552 · Sysinternals toolset run from staged directory on scranton (accesschk, PsExec64, sdelete64)

Evidence status: **verified**

pbeesly PowerShell ran accessChk.exe, PsExec64.exe and sdelete64.exe from C:\Program Files\SysinternalsSuite during the credential-access run on scranton.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:34.951Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\Program Files\SysinternalsSuite\accessChk.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63C9mZ | q-3449d8f1dc | ok |
| 2 | 2020-05-02 03:02:04.324Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\sdelete64.exe" /accepteula C:\programdata\victim\???cod.3aka3.scr | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL69HSbI | q-3449d8f1dc | ok |

### F62 · malicious / medium · T1552 · Suspicious screen-saver payload in C:\ProgramData\victim launched by explorer on scranton

Evidence status: **verified**

C:\ProgramData\victim\â€®cod.3aka3.scr ran with /S under pbeesly from explorer.exe, wrote Downloads\monkey.png, and a hidden PowerShell IEX stager decoded it and compiled qkbkqqbs.dll via csc.exe.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:55:56.157Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\ProgramData\victim\â€®cod.3aka3.scr" /S | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL7am0gN | q-5815b682ca | ok |
| 2 | 2020-05-02 02:57:00.933Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Users\pbeesly\Downloads\monkey.png | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL7YkrCD | q-e1cc213116 | ok |

### F63 · malicious / medium · T1552 · csc.exe compiled attacker .NET payloads from PowerShell response files on scranton

Evidence status: **verified**

pbeesly PowerShell invoked csc.exe with @response files in AppData\Local\Temp\qkbkqqbs and \0piklvia, producing qkbkqqbs.dll and 0piklvia.dll.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:08:03.260Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe" /noconfig /fullpaths @"C:\Users\pbeesly\AppData\Local\Temp\0piklvia\0piklvia.cmdline" | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2v5uV8 | q-731a07b697 | ok |
| 2 | 2020-05-02 02:58:45.292Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Users\pbeesly\AppData\Local\Temp\qkbkqqbs\qkbkqqbs.dll | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL7VhsbV | q-e1cc213116 | ok |

### F56 · malicious / high · T1552.001 · Credential-named file harvesting and password-protected archiving on nashua

Evidence status: **verified**

pbeesly PowerShell on nashua (child of PsExec-delivered C:\Windows\Temp\python.exe) enumerated *pass*/*psw*/*login*/*admin*/*vpn/*.pst files and archived them to working.zip; Rar.exe then made a password-protected copy and sdelete64 wiped it.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:15:59.000Z | nashua.dmevals.local | windows.powershell | win.ScriptBlockText | $env:APPDATA;$files=ChildItem -Path $env:USERPROFILE\ -Include *.doc,*.xps,*.xls,*.ppt,*.pps,*.wps,*.wpd,*.ods,*.odt,*.lwp,*.jtd,*.pdf,*.zip,*.rar,*.docx,*.url,… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMANA6l9 | q-9d302e2890 | ok |
| 2 | 2020-05-02 03:16:19.395Z | nashua.dmevals.local | windows.sysmon | process.command_line | "C:\Windows\Temp\Rar.exe" a -hpfGzq5yKw C:\Users\pbeesly\Desktop\working.zip C:\Users\pbeesly\AppData\Roaming\working.zip | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2Ze6tB | q-96e856fb73 | ok |
| 3 | 2020-05-02 03:17:18.030Z | nashua.dmevals.local | windows.sysmon | process.command_line | .\sdelete64.exe  /accepteula "C:\Users\pbeesly\AppData\Roaming\working.zip"  | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2VYgwB | q-96e856fb73 | ok |

### F59 · malicious / high · T1552.001 · Cleartext pbeesly password on PsExec64 command lines to NASHUA

Evidence status: **verified**

Four PsExec64 launches from pbeesly PowerShell on scranton carried -u dmevals\pbeesly -p Fl0nk3rt0n!T0by to \\NASHUA running C:\Windows\Temp\python.exe, installing PSEXESVC on nashua.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:18.784Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\PsExec64.exe" -accepteula \\NASHUA -u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2ioON3 | q-3449d8f1dc | ok |
| 2 | 2020-05-02 03:11:39.000Z | nashua.dmevals.local | windows.other | win.ServiceName | PSEXESVC | .ds-logs-windows.other-default-2026.10.17-000001 / AaFIKaWOc7y0JL-w3iOg | q-ca4d5cc7f4 | ok |

### F25 · malicious / high · T1552.004 · Get-PrivateKeys exported every LocalMachine certificate with private key to a password-protected .pfx on scranton

Evidence status: **verified**

On scranton.dmevals.local at 2020-05-02T03:04:56Z the attacker dot-sourced C:\Program Files\SysinternalsSuite\readme.ps1 (renamed from readme.txt at 03:03:49Z) and invoked Get-PrivateKeys. The function enumerates cert:\LocalMachine recursively and calls Export-PfxCertificate for every certificate with a thumbprint, writing to $env:USERPROFILE\Downloads\<random>.pfx protected with the hardcoded password "saribas". The export succeeded: Sysmon recorded creation of C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx at 03:04:57Z, and the file was deleted by powershell.exe at 03:08:51Z after collection. This is direct private-key theft.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMAQC1mz | q-7a82a4ea22 | ok |
| 2 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | Get-PrivateKeys | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMAQC1ns | q-ad2b9e32ad | ok |
| 3 | 2020-05-02 03:04:57.460Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63CdmD | q-f0976a4634 | ok |
| 4 | 2020-05-02 03:08:51.489Z | scranton.dmevals.local | windows.sysmon | message | File Delete:  RuleName: -  UtcTime: 2020-05-02 03:08:51.489  ProcessGuid: {47ab858c-e374-5eac-d803-000000000400}  ProcessId: 3852  User: DMEVALS\pbeesly  Image:… | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2kqttt | q-b8c57dd3ab | ok |
| 5 | 2020-05-02 03:03:49.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | Move-Item .\readme.txt readme.ps1 | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMAQDFnY | q-ad2b9e32ad | ok |

### F57 · malicious / high · T1552.004 · Get-PrivateKeys exported LocalMachine private keys to .pfx, then Invoke-Exfil 7-Zipped Downloads to WebDAV

Evidence status: **verified**

On scranton pbeesly ran Get-PrivateKeys (from SysinternalsSuite\readme.ps1) exporting every cert:\LocalMachine cert to Downloads\<random>.pfx with password 'saribas'; Invoke-Exfil then 7-Zipped Downloads to OfficeSupplies.7z and copied it to \\192.168.0.4\webdav, and BeachCleanup deleted the .pfx files.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMAQC1mz | q-326bac229c | ok |
| 2 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JL8F_6E7 | q-7344b068cc | ok |
| 3 | 2020-05-02 03:08:51.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-BeachCleanup {     Write-Host "[*] Cleaning up"     Remove-Item -Path "$env:USERPROFILE\Downloads\*.pfx" -Force     Remove-Item -Path "$env:USER… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMANA6lp | q-648c110b78 | ok |

### F30 · malicious / medium · T1555 · Compromised host scranton: PowerShell session opened LSASS with full-access (0x1FFFFF) handle during credential-harvesting toolset run

Evidence status: **verified**

On scranton.dmevals.local the user pbeesly was already fully compromised: a malicious screen saver C:\ProgramData\victim\cod.3aka3.scr spawned cmd.exe/powershell.exe, sdclt.exe was used for a UAC bypass, and a PowerShell session (PID 2976) ran a credential/collection toolset (Get-PrivateKeys exporting cert private keys to .pfx, Get-Keystrokes, Get-Clipboard, Invoke-Discovery, Invoke-Persistence, Invoke-Exfil). At 2020-05-02T03:05:16.654Z that same PowerShell.exe opened lsass.exe with GrantedAccess 0x1fffff (PROCESS_ALL_ACCESS) with a call trace ending in an UNKNOWN module — the classic pattern of an in-memory credential dumper reading LSASS secrets. A second handle at 03:05:16.623Z used 0x1f3fff. No sekurlsa/lsadump/mimikatz strings or dump files were observed, so the specific password-store module is not proven, but the access right is not explainable by normal PowerShell behaviour. Related: wsmprovhost.exe (PowerShell remoting) on nashua.dmevals.local opened lsass with 0x1f3fff at 03:09:29.430Z under the same pbeesly intrusion.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63CAlf | q-74ec2f3f94 | ok |
| 2 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63CAlf | q-74ec2f3f94 | ok |
| 3 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.CallTrace | C:\windows\SYSTEM32\ntdll.dll+9c584\|C:\windows\System32\KERNELBASE.dll+2732e\|UNKNOWN(000001996D28200D) | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63CAlf | q-74ec2f3f94 | ok |
| 4 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63CNnH | q-a3e6782aa6 | ok |
| 5 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2kp9uH | q-e4bf5a17be | ok |
| 6 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2kp9uH | q-e4bf5a17be | ok |
| 7 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMAQC1mz | q-05efeaa27d | ok |
| 8 | 2020-05-02 03:04:57.460Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63CdmD | q-be4b564417 | ok |
| 9 | 2020-05-02 02:55:56.157Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\ProgramData\victim\â€®cod.3aka3.scr | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL7am0gN | q-899ebf7b15 | ok |

### F41 · malicious / high · T1557 · Credential-theft campaign on scranton.dmevals.local (pbeesly) with lateral SMB/PsExec movement to nashua — no AiTM positioning observed

Evidence status: **verified**

On 2020-05-02 between 02:58 and 03:19 UTC the account DMEVALS\pbeesly on scranton.dmevals.local ran a full credential-access and exfiltration toolchain: a steganographic PowerShell loader reading C:\Users\pbeesly\Downloads\monkey.png, download/expansion of SysinternalsSuite, sdelete64 wiping of the downloaded zip, accesschk, a Get-PrivateKeys function that exports LocalMachine certificates to .pfx files, screen capture, and an Invoke-Exfil function compressing the Downloads directory into %APPDATA%\OfficeSupplies.7z with password 'lolol'. The actor then installed a masquerading LocalSystem service 'javamtsup' (C:\Windows\System32\javamtsup.exe, SHA256 8BE07818317849B36C2097E799DA9719471BA1D4DD9C60A97E31CA7CEDC6E992) which services.exe launched at 03:19:14, and used PsExec64 with the cleartext password 'Fl0nk3rt0n!T0by' against \\NASHUA, writing C:\Windows\Temp\python.exe via ADMIN$ (5145 at 03:10:23 from 10.0.1.4) and creating PSEXESVC services on nashua. This is credential theft and lateral movement, but the retrieved telemetry shows no adversary-in-the-middle positioning: no rogue name-resolution, no relay listener, no ARP/DHCP manipulation. The SMB traffic observed is ordinary domain-member to domain-controller authentication (10.0.1.4/10.0.1.6 -> 10.0.0.4 NEWYORK on 445/389/88) plus the attacker's own PsExec SMB sessions.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMAQC1mz | q-399a1eca45 | ok |
| 2 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JL8F_6E7 | q-399a1eca45 | ok |
| 3 | 2020-05-02 03:11:18.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | .\PsExec64.exe -accepteula \\NASHUA -u "dmevals\pbeesly" -p "Fl0nk3rt0n!T0by" -i 2 "C:\Windows\Temp\python.exe" | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMAOBvlP | q-399a1eca45 | ok |
| 4 | 2020-05-02 03:04:15.000Z | scranton.dmevals.local | windows.security | win.ServiceFileName | C:\Windows\System32\javamtsup.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL9Qtr33 | q-af6ffffedf | ok |
| 5 | 2020-05-02 03:19:14.118Z | scranton.dmevals.local | windows.sysmon | win.Hashes | SHA1=FF57080E5B19C3DCF62A00EA4037330F78B228CB,MD5=1B94BED747B7539280C9762C9C1B27EB,SHA256=8BE07818317849B36C2097E799DA9719471BA1D4DD9C60A97E31CA7CEDC6E992,IMPHA… | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2MP8kN | q-702359d6c6 | ok |
| 6 | 2020-05-02 03:10:23.000Z | nashua.dmevals.local | windows.security | win.RelativeTargetName | Temp\python.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL9LnlqG | q-5a7910490e | ok |

### F50 · malicious / high · T1606 · Machine certificate private keys exported to password-protected .pfx on scranton.dmevals.local (credential material for token/cookie forgery)

Evidence status: **verified**

On scranton.dmevals.local, in a PowerShell session running as DMEVALS\pbeesly (script path C:\Program Files\SysinternalsSuite\readme.ps1), the attacker defined and ran a function Get-PrivateKeys at 2020-05-02T03:04:56Z that enumerates every certificate in cert:\LocalMachine and exports each one, with its private key, to $env:USERPROFILE\Downloads\<random>.pfx protected by the hardcoded password 'saribas'. Sysmon file-create confirms the export at 2020-05-02T03:04:57Z: powershell.exe wrote C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx. This is the credential-material acquisition step that precedes web-credential forgery (T1606): a stolen CA/token-signing certificate plus private key is exactly what is needed to mint SAML tokens or forge authentication cookies. The same session then ran Invoke-Discovery, Invoke-Persistence (steps 1 and 2), Invoke-ScreenCapture, and Invoke-Exfil, which 7-Zipped the Downloads directory (containing the .pfx) to %APPDATA%\OfficeSupplies.7z (created 2020-05-02T03:08:35Z) and copied it to the WebDAV share \\192.168.0.4\webdav using hardcoded credentials cozy/MyCozyPassw0rd!, then ran Invoke-BeachCleanup to delete *.pfx, *.bmp, *.png and OfficeSupplies.7z. The theft of private keys and their exfiltration is attacker activity, not normal system behaviour.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMAQC1mz | q-4ae2bcfec5 | ok |
| 2 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\readme.ps1 | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMAQC1mz | q-dc4bc09706 | ok |
| 3 | 2020-05-02 03:04:57.460Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63CdmD | q-c87b4dbf3a | ok |
| 4 | 2020-05-02 03:08:35.270Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Users\pbeesly\AppData\Roaming\OfficeSupplies.7z | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2lq7zj | q-c87b4dbf3a | ok |
| 5 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JL8F_6E7 | q-369fd862ae | ok |
| 6 | 2020-05-02 03:08:51.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-BeachCleanup {     Write-Host "[*] Cleaning up"     Remove-Item -Path "$env:USERPROFILE\Downloads\*.pfx" -Force     Remove-Item -Path "$env:USER… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMANA6lp | q-4ae2bcfec5 | ok |

### F54 · malicious / high · T1649 · Private-key certificate export (Get-PrivateKeys / Export-PfxCertificate) on scranton.dmevals.local

Evidence status: **verified**

On 2020-05-02 between 03:03 and 03:08 UTC, in the context of user DMEVALS\pbeesly on scranton.dmevals.local, an interactive PowerShell session (PID 3876) renamed a dropped file readme.txt to readme.ps1, dot-sourced it, and then executed a function Get-PrivateKeys that enumerates every certificate in cert:\LocalMachine recursively and exports each one with its private key to $env:USERPROFILE\Downloads\<random>.pfx protected by the hardcoded password "saribas" (Export-PfxCertificate). Sysmon recorded the resulting file C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx created by that same powershell.exe PID 3876 at 03:04:57, and the same PowerShell process wrote the certificate store blobs HKLM\SOFTWARE\Microsoft\SystemCertificates\MY\Certificates\48B5E43D09D080DF8863152FD22ED7C43443D499\Blob and ...\Remote Desktop\Certificates\615B93C2D2B647D1670500B3338EAAEC83BA5646\Blob at 03:04:57. The exported .pfx was later deleted at 03:08:51 by another powershell.exe (PID 3852) under pbeesly, consistent with staging/cleanup after theft. The same session also ran screen-capture and clipboard-collection functions, indicating a broader hands-on-keyboard intrusion. This is theft of authentication certificates/private keys (T1649), not normal system behaviour.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMAQC1mz | q-040de0dacf | ok |
| 2 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMAQC1mz | q-040de0dacf | ok |
| 3 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\readme.ps1 | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMAQC1mz | q-040de0dacf | ok |
| 4 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | process.command_line | Get-PrivateKeys | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMAQC1ns | q-2cecb221e6 | ok |
| 5 | 2020-05-02 03:03:49.000Z | scranton.dmevals.local | windows.powershell | process.command_line | Move-Item .\readme.txt readme.ps1 | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMAQDFnY | q-2cecb221e6 | ok |
| 6 | 2020-05-02 03:03:57.000Z | scranton.dmevals.local | windows.powershell | process.command_line | . .\readme.ps1 | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMAQDVoX | q-2cecb221e6 | ok |
| 7 | 2020-05-02 03:04:57.460Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63CdmD | q-d61576a668 | ok |
| 8 | 2020-05-02 03:04:57.428Z | scranton.dmevals.local | windows.sysmon | registry.path | HKLM\SOFTWARE\Microsoft\SystemCertificates\MY\Certificates\48B5E43D09D080DF8863152FD22ED7C43443D499\Blob | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63CdmN | q-2e0c2964be | ok |
| 9 | 2020-05-02 03:04:57.272Z | scranton.dmevals.local | windows.sysmon | registry.path | HKLM\SOFTWARE\Microsoft\SystemCertificates\Remote Desktop\Certificates\615B93C2D2B647D1670500B3338EAAEC83BA5646\Blob | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63CtkV | q-2e0c2964be | ok |
| 10 | 2020-05-02 03:08:51.489Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2kqttt | q-5409c15ada | ok |

### F58 · suspicious / medium · T1003.001 · Audited LSASS handle open by pbeesly PowerShell on scranton

Evidence status: **verified**

4663 audit record shows pbeesly's powershell.exe opening \Device\HarddiskVolume2\Windows\System32\lsass.exe with AccessMask 0x10 at 03:05:16Z on scranton, between the key export and exfil steps.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | win.ObjectName | \Device\HarddiskVolume2\Windows\System32\lsass.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL9Qt70r | q-bdbe477010 | ok |
| 2 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | win.AccessMask | 0x10 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL9Qt70r | q-bdbe477010 | ok |

### F15 · suspicious / medium · T1110.003 · No password spraying; instead valid pbeesly credentials were reused via PsExec64 to NASHUA

Evidence status: **verified**

No spraying indicators exist: zero 4625 events, no user-list command lines (only userinit.exe), and no password/credential script blocks in PowerShell. What is present is credential reuse with a single known-good account: on scranton.dmevals.local, C:\Program Files\SysinternalsSuite\PsExec64.exe was run 4 times as "-accepteula \\NASHUA -u dmevals\pbeesly -p <plaintext password> -i 2 C:\Windows\Temp\python.exe", producing PSEXESVC service installs (7045) and 4648 explicit-credential logons on nashua.dmevals.local at 23:11:40, 23:12:46, 23:13:49 and 23:15:03 (-04:00). This is lateral movement using a valid credential, not brute force, so it is reported as suspicious context rather than a T1110.003 hit.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:58:44.325Z | scranton.dmevals.local | windows.sysmon | process.parent.executable | C:\Windows\System32\control.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL7ViMbT | q-a0bc4028a6 | ok |
| 2 | 2020-05-02 03:11:40.000Z | nashua.dmevals.local | windows.security | process.executable | C:\Windows\PSEXESVC.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL9OrXFR | q-fb64f3923d | ok |
| 3 | 2020-05-02 03:11:39.000Z | nashua.dmevals.local | windows.other | message | A service was installed in the system.    Service Name:  PSEXESVC  Service File Name:  %SystemRoot%\PSEXESVC.exe  Service Type:  user mode service  Service Star… | .ds-logs-windows.other-default-2026.10.17-000001 / AaFIKaWOc7y0JL-w3iOg | q-551782b308 | ok |
| 4 | 2020-05-02 03:20:46.000Z | scranton.dmevals.local | windows.security | source.ip | 172.18.39.2 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL8vSVsk | q-fb64f3923d | ok |

### F17 · suspicious / medium · T1111 · No MFA/smart-card interception artifacts; LSASS access on nashua is PowerShell Remoting logon-session enumeration by compromised account pbeesly

Evidence status: **verified**

Hunting for T1111 (MFA Interception) found no MFA-provider, smart-card, token-interception or credential-provider tampering artifacts. The only credential-adjacent activity is attacker credential ACCESS, not interception: on nashua.dmevals.local the account pbeesly obtained a network logon (4624 type 3) at 23:09:23 and spawned wsmprovhost.exe -Embedding (PowerShell Remoting) at 23:09:23; at 23:09:29 that wsmprovhost.exe (PID 7720) opened lsass.exe (PID 728) with GrantedAccess 0x1f3fff, and the 4104 script block logged one second earlier is 'Get-Process -IncludeUserName \| Select-Object UserName,SessionId ...' — i.e. PowerShell enumerating logon sessions, which requires opening LSASS. pbeesly also authenticated to nashua via C:\Windows\PSEXESVC.exe (4648 explicit-credential logons at 23:11:40, 23:12:46, 23:13:49, 23:15:03) and later ran collection/archiving commands (Compress-Archive over *.doc/*.pst/*pass*/*vpn files, .\Rar.exe a -hpfGzq5yKw) and an Invoke-Exfil function on scranton. The remaining hits are benign: 4648 events from winlogon/wininit/taskhostw for DWM-1/UMFD-0/UMFD-1/UMFD-2/SCRANTON$ are normal Windows logon plumbing; the CredentialGuard registry value set (HKLM\System\CurrentControlSet\Control\DeviceGuard\Scenarios\CredentialGuard\Enabled = 0x00000000 by lsass.exe) and the CredentialEnrollmentManagerUserSvc service keys written by services.exe are standard OS behaviour; the 4624 type-10 logons are pbeesly RDP from 172.18.39.2 with Negotiate/User32 (no smart-card or MFA package). No evidence of MFA interception was observed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2kp9uH | q-bdcb63c894 | ok |
| 2 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2kp9uH | q-bdcb63c894 | ok |
| 3 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.TargetImage | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2kp9uH | q-bdcb63c894 | ok |
| 4 | 2020-05-02 03:09:28.000Z | nashua.dmevals.local | windows.powershell | win.ScriptBlockText |  Get-Process -IncludeUserName \| Select-Object UserName,SessionId \| Where-Object { $_.UserName -like "*\$env:USERNAME" } \| Sort-Object SessionId -Unique  | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMAMA2AH | q-f9d5d2e6ff | ok |
| 5 | 2020-05-02 03:09:23.000Z | nashua.dmevals.local | windows.security | process.command_line | C:\windows\system32\wsmprovhost.exe -Embedding | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL9VzyYa | q-1f5cb8c92b | ok |
| 6 | 2020-05-02 03:09:23.000Z | nashua.dmevals.local | windows.security | win.LogonType | 3 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL9OrnEx | q-1f5cb8c92b | ok |
| 7 | 2020-05-02 03:11:40.000Z | nashua.dmevals.local | windows.security | process.executable | C:\Windows\PSEXESVC.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL9OrXFR | q-4c742553e3 | ok |
| 8 | 2020-05-02 03:15:59.000Z | nashua.dmevals.local | windows.powershell | win.ScriptBlockText | $env:APPDATA;$files=ChildItem -Path $env:USERPROFILE\ -Include *.doc,*.xps,*.xls,*.ppt,*.pps,*.wps,*.wpd,*.ods,*.odt,*.lwp,*.jtd,*.pdf,*.zip,*.rar,*.docx,*.url,… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMANA6l9 | q-f9d5d2e6ff | ok |
| 9 | 2020-05-02 03:19:09.865Z | scranton.dmevals.local | windows.sysmon | win.Details | DWORD (0x00000000) | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2ORrtv | q-b53a31a080 | ok |
| 10 | 2020-05-02 03:19:09.865Z | scranton.dmevals.local | windows.sysmon | win.TargetObject | HKLM\System\CurrentControlSet\Control\DeviceGuard\Scenarios\CredentialGuard\Enabled | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2ORrtv | q-b53a31a080 | ok |
| 11 | 2020-05-02 03:20:46.000Z | scranton.dmevals.local | windows.security | win.AuthenticationPackageName | Negotiate | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL8vSVsl | q-f0aff72e4c | ok |

### F21 · suspicious / low · T1212 · wsmprovhost.exe (PowerShell remoting) on nashua.dmevals.local opened lsass.exe with 0x1F3FFF — PowerShell/.NET call trace, no credential-dump payload observed

Evidence status: **verified**

On nashua.dmevals.local at 2020-05-02T03:09:29Z, wsmprovhost.exe (PID 7720, the PowerShell remoting host, spawned at 03:09:23 by svchost.exe -Embedding under user pbeesly) opened lsass.exe (PID 728) with GrantedAccess 0x1F3FFF. Unlike the scranton case, the call trace is entirely managed PowerShell/.NET: System.ni.dll and Microsoft.PowerShell.Commands.Management.ni.dll frames followed by UNKNOWN addresses, which is the signature of a PowerShell cmdlet (e.g. Get-Process/Get-CimInstance style process enumeration) rather than an injected credential dumper. No script block, command line or file artefact on nashua references lsass, dump, sekurlsa or credentials, and the only other PowerShell on the host is a bare 'powershell.exe' spawned by C:\Windows\Temp\python.exe at 03:15:48. The same user pbeesly is however the actor behind the confirmed malicious chain on scranton, so this remote-PowerShell LSASS handle is worth follow-up but is not itself proof of credential theft.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2kp9uH | q-a56ab7799f | ok |
| 2 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2kp9uH | q-a56ab7799f | ok |
| 3 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.CallTrace | C:\windows\SYSTEM32\ntdll.dll+9c584\|C:\windows\System32\KERNELBASE.dll+2732e\|C:\windows\assembly\NativeImages_v4.0.30319_64\System\9803982d7bc887e2745bff18a43… | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2kp9uH | q-a56ab7799f | ok |
| 4 | 2020-05-02 03:09:23.885Z | nashua.dmevals.local | windows.sysmon | process.command_line | C:\windows\system32\wsmprovhost.exe -Embedding | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2kqds5 | q-df161ece09 | ok |
| 5 | 2020-05-02 03:15:48.652Z | nashua.dmevals.local | windows.sysmon | process.parent.executable | C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2bgTcf | q-df161ece09 | ok |

### F64 · suspicious / medium · T1552 · hostui.exe elevation attempt followed by registry-stored encoded PowerShell stager on scranton

Evidence status: **verified**

PowerShell ran 'Start-Process C:\Windows\System32\hostui.exe -verb runas' at 03:21:27Z, then read HKLM:\SOFTWARE\Javasoft 'value Supplement' into Invoke-Expression and launched a hidden -nop -w hidden encoded child PowerShell.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:21:27.276Z | scranton.dmevals.local | windows.sysmon | process.parent.command_line | powershell.exe  -c "Start-Process C:\Windows\System32\hostui.exe -verb runas" | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JLx6_ejg | q-3449d8f1dc | ok |
| 2 | 2020-05-02 03:21:28.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | Get-ItemPropertyValue 'HKLM:\\SOFTWARE\Javasoft' 'value Supplement' \| Invoke-Expression | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMAWJWsz | q-485bae6812 | ok |

### F65 · suspicious / low · T1552 · sdclt.exe execution proxy runs before payload compilation on scranton

Evidence status: **verified**

Three sdclt.exe launches from cmd.exe under pbeesly at 02:58:42Z immediately preceded the csc.exe compilation of qkbkqqbs.dll; no credential access observed from it.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:58:42.401Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\Windows\System32\sdclt.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL7Wi8c6 | q-3449d8f1dc | ok |

### F26 · suspicious / medium · T1552.001 · accesschk.exe run from PowerShell created a 'passwordsDB' file in the SysinternalsSuite directory

Evidence status: **verified**

On scranton.dmevals.local at 2020-05-02T03:04:34Z, DMEVALS\pbeesly launched C:\Program Files\SysinternalsSuite\accesschk.exe with no arguments from the attacker's PowerShell session (parent powershell.exe PID 3876, the same process that later ran Get-PrivateKeys). One second later Sysmon recorded accesschk.exe creating C:\Program Files\SysinternalsSuite\passwordsDB, and the process exited at 03:04:54Z. The file name and the surrounding credential-collection chain indicate the tool was used to probe for credential-bearing files/objects; the content of passwordsDB was not observed in the telemetry.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:34.951Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\accesschk.exe" | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63C9mZ | q-bf7d61d1a8 | ok |
| 2 | 2020-05-02 03:04:35.069Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Program Files\SysinternalsSuite\passwordsDB | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63C9mM | q-68712bd624 | ok |
| 3 | 2020-05-02 03:04:34.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | &amp; "C:\Program Files\SysinternalsSuite\accesschk.exe" | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMAQDVp3 | q-ad2b9e32ad | ok |

### F34 · suspicious / medium · T1556 · SYSTEM-context PowerShell/WinRM processes opened LSASS with full access on scranton and nashua during an APT29-style intrusion

Evidence status: **verified**

On 2020-05-02 the sysmon LSASS-access stack (326 events) is dominated by svchost.exe (289, GrantedAccess 0x1000) plus Azure antimalware/telemetry agents (0x1400). The rare outliers are PowerShell.exe (PID 2976) on scranton.dmevals.local at 03:05:16 requesting 0x1F3FFF and 0x1FFFFF on lsass.exe (PID 736), and wsmprovhost.exe (PID 7720) on nashua.dmevals.local at 03:09:29 requesting 0x1F3FFF on lsass.exe (PID 728), both running as SYSTEM. These full-access handles are the prerequisite for reading/patching the authentication process. They occur inside a hands-on-keyboard intrusion on scranton: SysinternalsSuite was downloaded/expanded to C:\Program Files\SysinternalsSuite, readme.txt renamed to readme.ps1 and dot-sourced, then Invoke-Discovery, Invoke-Persistence -PersistStep 1/2, Get-PrivateKeys, Get-Keystrokes and Get-Clipboard were executed. No evidence of an actual LSASS patch, password filter, or authentication DLL replacement was found, so this is suspicious credential-access staging rather than confirmed authentication-process modification.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63CAlf | q-844016c830 | ok |
| 2 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63CAlf | q-844016c830 | ok |
| 3 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2kp9uH | q-844016c830 | ok |
| 4 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2kp9uH | q-844016c830 | ok |
| 5 | 2020-05-02 03:04:15.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | Invoke-Persistence -PersistStep 1 | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMAQDVp0 | q-e95a48cb36 | ok |
| 6 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | Get-PrivateKeys | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMAQC1ns | q-d30216fe06 | ok |
| 7 | 2020-05-02 03:06:59.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | Get-Keystrokes;Start-Sleep -Seconds 15;View-Job -JobName "Keystrokes" | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMAQDFlH | q-d30216fe06 | ok |

### F45 · suspicious / medium · T1558 · No Kerberos ticket theft/forgery observed; credential access on scranton was LSASS handle access by PowerShell during a hands-on-keyboard intrusion

Evidence status: **verified**

Across windows.security, windows.sysmon, windows.powershell and zeek there is no evidence of ticket theft or forgery: no 4768/4769 anomalies beyond normal AES256 (0x12) TGS/AS traffic, no RC4 downgrade, no krbtgt-targeted abuse, and no ticket-related PowerShell. The only credential-access-shaped activity is on scranton.dmevals.local, where the user pbeesly's PowerShell (PID 2976) opened lsass.exe with GrantedAccess 0x1f3fff and 0x1fffff at 2020-05-02T03:05:16Z, immediately after the same session ran Invoke-Discovery, Invoke-Persistence, accesschk.exe and Get-PrivateKeys (certificate export). This is consistent with a credential-dumping attempt inside an active intrusion, but no Kerberos ticket manipulation followed it.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63CAlf | q-645a33e294 | ok |
| 2 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63CNnH | q-39b9a9432b | ok |
| 3 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | Get-PrivateKeys | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMAQC1ns | q-9f533c46f4 | ok |
| 4 | 2020-05-02 03:04:03.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | Invoke-Discovery | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMAQDFmw | q-9f533c46f4 | ok |

### F52 · suspicious / medium · T1606.002 · No SAML token forgery observed; LSASS access by PowerShell/wsmprovhost is credential dumping, not token minting

Evidence status: **verified**

No SAML/ADFS/token artifacts exist in the data: zero PowerShell script blocks mentioning SAML, NotOnOrAfter or Assertion, zero Sysmon process creations with saml/token/cert in the command line, and zero Zeek HTTP requests to saml/adfs/token URLs. What is present is credential-material theft that could feed token forgery: on scranton.dmevals.local PowerShell.exe (PID 2976) opened lsass.exe (PID 736) at 2020-05-02T03:05:16Z with GrantedAccess 0x1f3fff and 0x1fffff (full-access masks typical of credential dumping), and on nashua.dmevals.local wsmprovhost.exe opened lsass.exe with 0x1f3fff at 2020-05-02T03:09:29Z, consistent with the attacker's Invoke-Command -ComputerName NASHUA lateral movement. The remaining LSASS access masks (0x1000, 0x1400 by WindowsAzureTelemetryService.exe, 0x101001 by svchost/lsm.dll, 0x1fffff by wininit/csrss) are normal Windows behaviour. The stolen private keys (.pfx) are the plausible precursor to SAML token forging, but no forged token was actually observed in these datasets.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63CNnH | q-803bffbb9d | ok |
| 2 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63CAlf | q-9baf1fff69 | ok |
| 3 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2kp9uH | q-a9c5df84ad | ok |
| 4 | 2020-05-02 03:09:23.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | Invoke-Command -ComputerName NASHUA -ScriptBlock { Get-Process -IncludeUserName \| Select-Object UserName,SessionId \| Where-Object { $_.UserName -like "*\$env:… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMAOAxHj | q-27b0e7dcec | ok |

### F03 · benign / high · T1003.002 · SAM object accesses are lsass.exe's own machine-account operations (benign)

Evidence status: **verified**

All 21 SAM_SERVER / SAM_DOMAIN / SAM_ALIAS handle requests in windows.security on scranton.dmevals.local are made by process C:\Windows\System32\lsass.exe running as the machine account SCRANTON$ (S-1-5-18, logon 0x3E7) between 23:19 and 23:20 local time. No non-lsass process opened SAM objects, no reg save / hive-copy command line was found, and the only file-create hits matching SAM/SECURITY/SYSTEM were Prefetch .pf files written by svchost.exe. This is normal local SAM maintenance, not credential dumping.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:21.000Z | scranton.dmevals.local | windows.security | win.ObjectType | SAM_SERVER | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL81V4Qj | q-8ec4d03a83 | ok |
| 2 | 2020-05-02 03:19:21.000Z | scranton.dmevals.local | windows.security | process.executable | C:\Windows\System32\lsass.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL81V4Qj | q-8ec4d03a83 | ok |
| 3 | 2020-05-02 03:19:21.000Z | scranton.dmevals.local | windows.security | user.name | SCRANTON$ | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL81V4Qj | q-8ec4d03a83 | ok |
| 4 | 2020-05-02 03:21:28.476Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Windows\Prefetch\SECURITYHEALTHSYSTRAY.EXE-41AD6DE1.pf | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL17AAad | q-3b99ebb47b | ok |

### F05 · benign / medium · T1003.003 · No NTDS / volume-shadow credential dumping observed

Evidence status: **verified**

No hits for ntds.dit file creation, ntdsutil/vssadmin/diskshadow command lines, or shadow-copy related messages in sysmon, security, powershell or windows.other. The only .dmp files created were WER crash dumps by WerFault.exe (WER51F5.tmp.dmp on nashua, WER5437.tmp.dmp on scranton), which are unrelated to credential extraction.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:27.395Z | nashua.dmevals.local | windows.sysmon | win.TargetFilename | C:\ProgramData\Microsoft\Windows\WER\Temp\WER51F5.tmp.dmp | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL62AkVX | q-16c3439f63 | ok |
| 2 | 2020-05-02 03:05:27.395Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\WerFault.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL62AkVX | q-16c3439f63 | ok |

### F06 · benign / medium · T1003.004 · No LSA Secrets access observed

Evidence status: **verified**

No handle/object-access events on SECURITY Policy Secrets objects, no lsadump/secrets command lines, and no PowerShell script blocks referencing LSA secrets were returned. The only SECURITY-hive activity is lsass.exe's own NL$1 cache writes.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:12:46.768Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2hm-XC | q-4e0692c73d | ok |

### F04 · benign / medium · T1003.005 · HKLM\SECURITY\Cache\NL$1 writes by lsass.exe are normal cached-credential updates (benign)

Evidence status: **verified**

The registry SetValue events on HKLM\SECURITY\Cache\NL$1 on nashua.dmevals.local (03:11:40Z, 03:12:46Z, 03:13:49Z, 03:15:03Z) and on scranton.dmevals.local are all written by C:\windows\system32\lsass.exe (PID 728 on nashua), i.e. the OS itself updating the cached domain credential entry. No non-lsass process read or wrote the SECURITY\Cache keys, and no mscache/DCC2 extraction command line or script block was found.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:40.144Z | nashua.dmevals.local | windows.sysmon | registry.path | HKLM\SECURITY\Cache\NL$1 | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2in-Mz | q-4e0692c73d | ok |
| 2 | 2020-05-02 03:11:40.144Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2in-Mz | q-4e0692c73d | ok |

### F07 · benign / medium · T1003.006 · No DCSync / DRSUAPI replication observed

Evidence status: **verified**

No process command lines or PowerShell script blocks referencing drsuapi, dcsync or lsadump were found in sysmon or powershell. The hosts in scope are member servers (scranton, nashua, newyork, utica) and no directory-replication credential theft was observed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:09.809Z | scranton.dmevals.local | windows.sysmon | process.command_line | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2ORrtq | q-d727513426 | ok |

### F08 · benign / medium · T1040 · No network sniffing observed; PyInstaller python.exe on NASHUA is C2/scanning, not packet capture

Evidence status: **verified**

The T1040 hypothesis is not supported by the telemetry. Across windows.security (460 4688 events), windows.sysmon (447 process-create events) and windows.powershell (414 4104 script blocks) there is no tcpdump/windump/wireshark/rawcap execution, no pcap/sniff/promiscuous command line, no Npcap/WinPcap driver load (event 6), and no capture-driver service installation. The 7045 service installs are PSEXESVC (from PsExec) and a Java support service, not capture drivers. The two high-volume 'network tool' candidates are benign infrastructure: NetworkWatcherAgent.exe (Microsoft Azure Network Watcher plugin, registry/file activity on nashua, scranton, utica) and logman.exe ("logman.exe" stop GAEvents, parent C:\WindowsAzure\Packages\WaAppAgent.exe — Azure guest agent telemetry). The genuinely malicious-looking activity in this window is on nashua.dmevals.local: a PyInstaller-packed C:\Windows\Temp\python.exe dropped at 03:10:23Z and launched four times via PsExec64 from scranton (03:11:40, 03:12:46, 03:13:49, 03:15:03Z) using cleartext credentials dmevals\pbeesly, preceded by PowerShell 'Invoke-SeaDukeStage -ComputerName NASHUA'. That binary extracts _MEI29522 with _socket.pyd/_ssl.pyd and opens hundreds of rapid outbound TCP connections from 10.0.1.6 to 192.168.0.4:8443 — this is C2/scanning behaviour, not passive sniffing, so it does not satisfy T1040. The zeek window (2020-04-30) does not overlap the Windows window and shows no ICMP conn records; its top destination 192.168.0.4 is ordinary traffic. Note: the python.exe activity is malicious in nature but belongs to other techniques (execution/lateral movement/C2), not network sniffing.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:06:30.688Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\Packages\Plugins\Microsoft.Azure.NetworkWatcher.NetworkWatcherAgentWindows\1.4.1421.1\NetworkWatcherAgent\NetworkWatcherAgent.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2x7o-G | q-fd4ad9b0f4 | ok |
| 2 | 2020-05-02 03:18:38.942Z | scranton.dmevals.local | windows.sysmon | process.command_line | "logman.exe" stop GAEvents | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2PS3oM | q-2a3edfb3be | ok |
| 3 | 2020-05-02 03:18:38.942Z | scranton.dmevals.local | windows.sysmon | process.parent.executable | C:\WindowsAzure\Packages\WaAppAgent.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2PS3oM | q-2a3edfb3be | ok |
| 4 | 2020-05-02 03:11:39.000Z | nashua.dmevals.local | windows.other | message | A service was installed in the system.    Service Name:  PSEXESVC  Service File Name:  %SystemRoot%\PSEXESVC.exe  Service Type:  user mode service  Service Star… | .ds-logs-windows.other-default-2026.10.17-000001 / AaFIKaWOc7y0JL-w3iOg | q-27b4d5bbf3 | ok |
| 5 | 2020-05-02 03:10:23.626Z | nashua.dmevals.local | windows.sysmon | win.TargetFilename | C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2jo9KZ | q-6614477890 | ok |
| 6 | 2020-05-02 03:15:04.150Z | nashua.dmevals.local | windows.sysmon | win.TargetFilename | C:\Users\pbeesly\AppData\Local\Temp\_MEI29522\_socket.pyd | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2bgzcO | q-2e8fdc4377 | ok |
| 7 | 2020-05-02 03:15:05.142Z | nashua.dmevals.local | windows.sysmon | win.DestinationPort | 8443 | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2bgjeM | q-91b4922ba8 | ok |
| 8 | 2020-05-02 03:11:18.000Z | scranton.dmevals.local | windows.security | process.command_line | "C:\Program Files\SysinternalsSuite\PsExec64.exe" -accepteula \\NASHUA -u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL9Uyl9o | q-4b21de6e18 | ok |
| 9 | 2020-05-02 03:10:22.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | Invoke-SeaDukeStage -ComputerName NASHUA | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMAOBExi | q-0df82486bc | ok |

### F11 · benign / medium · T1056 · LSASS handle requests and SAM object access are dominated by OS/Azure components (benign baseline)

Evidence status: **verified**

The bulk of LSASS-related telemetry is normal: 326 Sysmon process-access events to lsass.exe are mostly svchost.exe with GrantedAccess 0x1000 (216 on scranton, 30 newyork, 28 nashua, 12 utica), plus Azure TelemetryService.exe and IaaSAntimalware AntimalwareConfig.exe with 0x1400, and boot-time wininit/csrss all-access opens at 03:19:09Z. Security 4656 handle requests to lsass/SAM come from lsass.exe itself (SCRANTON$), MsMpEng.exe, CollectGuestLogs.exe and wsmprovhost.exe. The 10,750 'Key' object accesses are registry key auditing, not credential capture. These are baseline system behaviour; the anomalous subset is reported under T1056.001/T1056.004.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:09.803Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\wininit.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2ORrtr | q-a5b6261104 | ok |
| 2 | 2020-05-02 03:19:42.009Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\WindowsAzure\Packages\Telemetry\WindowsAzureTelemetryService.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JLx0p9yU | q-a5b6261104 | ok |
| 3 | 2020-05-02 03:19:21.000Z | scranton.dmevals.local | windows.security | process.executable | C:\Windows\System32\lsass.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL81V4Qj | q-d9d54526d4 | ok |
| 4 | 2020-05-02 03:20:15.000Z | scranton.dmevals.local | windows.security | process.executable | C:\Program Files\Windows Defender\MsMpEng.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL8-b3Gh | q-d9d54526d4 | ok |

### F12 · benign / high · T1110 · No brute-force authentication activity observed; only successful logons and one successful credential validation

Evidence status: **verified**

Across windows.security (2020-05-02T02:55:25Z..03:28:09Z) there are zero 4625 failed-logon events, zero 4740 lockouts and zero 4771 failures; the only authentication-validation event is a single 4776 on newyork.dmevals.local at 2020-05-01T23:20:40-04:00 for pbeesly with Error Code 0x0 (success). All 297 4624 logons are successful (NEWYORK$ 123, SYSTEM 60, SCRANTON$ 37, pbeesly 30, NASHUA$ 25, WEC$ 8, UTICA$ 5, machine/service accounts). The windows.other hits for 'logon'/'failed' were unrelated (7001 CEIP notification, 8013 PTR registration failure, 46 crash-dump init). No authentication-failure or lockout pattern exists in the window, so no brute-force attempt is evidenced.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:20:40.000Z | newyork.dmevals.local | windows.security | message | The computer attempted to validate the credentials for an account.    Authentication Package:	MICROSOFT_AUTHENTICATION_PACKAGE_V1_0  Logon Account:	pbeesly  Sou… | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL8xSa_z | q-239dc60d65 | ok |
| 2 | 2020-05-02 03:20:40.000Z | newyork.dmevals.local | windows.security | event.code | 4776 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL8xSa_z | q-239dc60d65 | ok |
| 3 | 2020-05-02 03:18:54.000Z | scranton.dmevals.local | windows.other | message | Crash dump initialization failed! | .ds-logs-windows.other-default-2026.10.17-000001 / AaFIKaWOc7y0JL-w3yMf | q-b8b5d4df82 | ok |

### F13 · benign / high · T1110.001 · No password-guessing pattern: no failed logons, no password-bearing command lines

Evidence status: **verified**

No 4625 events exist in windows.security, so there is no repeated guessing against any account. The sysmon command-line searches for 'password' returned nothing, and the only 'net'/'login' command-line hits were 28 svchost.exe and 2 netsh.exe (system services). The single 4776 on newyork at 2020-05-01T23:20:40-04:00 for pbeesly succeeded (0x0) from workstation 10.0.1.4, consistent with a normal domain credential validation rather than guessing. Note: the plaintext password seen in the PsExec64 command line (see T1110.003 finding) is a reused valid credential, not a guessed one.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:20:40.000Z | newyork.dmevals.local | windows.security | win.TargetUserName | pbeesly | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL8xSa_z | q-239dc60d65 | ok |
| 2 | 2020-05-02 02:58:44.325Z | scranton.dmevals.local | windows.sysmon | process.command_line | "PowerShell.exe" -noni -noexit -ep bypass -window hidden -c "sal a New-Object;Add-Type -AssemblyName 'System.Drawing'; $g=a System.Drawing.Bitmap('C:\Users\pbee… | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL7ViMbT | q-a0bc4028a6 | ok |

### F14 · benign / medium · T1110.002 · LSASS handle opens are AV/telemetry and OS processes; no hive dumping or cracking artifacts

Evidence status: **verified**

326 Sysmon event 10 accesses to C:\windows\system32\lsass.exe were stacked by source process: svchost.exe 289 (GrantedAccess 0x1000, i.e. query-limited), AntimalwareConfig.exe 15, WindowsAzureTelemetryService.exe 13, PowerShell.exe 2, powershell.exe 2, wininit.exe 2, csrss.exe 1, services.exe 1, wsmprovhost.exe 1. The full-access opens (0x1fffff / 0x1f3fff) are: PowerShell.exe pid 2976 on scranton at 2020-05-02T03:05:16.623Z and .654Z (this is the pbeesly-run obfuscated IEX loader, parent control.exe — suspicious in itself but no dump file was produced), wsmprovhost.exe on nashua at 03:09:29Z (PowerShell remoting, System.ni.dll call trace), and wininit.exe/csrss.exe on scranton at 03:19:09Z (boot-time OS processes). No 4663/4656 access to the SAM or SECURITY hive was found (C112 zero hits), no hash/crack command lines (C113 zero), no ConvertTo-SecureString/hash script blocks (C116 zero), and the only .txt/.pot file creations were Cortana/Edge/WER/SysinternalsSuite artifacts — no wordlists or potfiles. The 16962 SAM-restriction message on scranton is a default security-descriptor notice.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63CAlf | q-4b83b04371 | ok |
| 2 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63CNnH | q-3450500c2e | ok |
| 3 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2kp9uH | q-7d6c9afa2f | ok |
| 4 | 2020-05-02 03:19:10.000Z | scranton.dmevals.local | windows.other | message | Remote calls to the SAM database are being restricted using the default security descriptor: O:SYG:SYD:(A;;RC;;;BA).  For more information please see http://go.… | .ds-logs-windows.other-default-2026.10.17-000001 / AaFIKaWOc7y0JL-w3yM8 | q-973cdf91ea | ok |

### F16 · benign / high · T1110.004 · No credential-stuffing activity; no failed authentications against multiple accounts

Evidence status: **verified**

Credential stuffing requires many failed authentications across accounts from a common source. In windows.security there are no 4625 events at all, no 4740 lockouts, and the only 4776 validation succeeded (pbeesly, 0x0). The 4648 explicit-credential events are either the pbeesly/PSEXESVC pair on nashua, the pbeesly RDP session on scranton from 172.18.39.2 (windows.other event 21, session logon succeeded), or OS accounts (DWM-1/2, UMFD-0/1/2, SCRANTON$). No credential-list tooling or password-bearing command lines were found in sysmon or PowerShell.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:20:48.000Z | scranton.dmevals.local | windows.other | message | Remote Desktop Services: Session logon succeeded:    User: DMEVALS\pbeesly  Session ID: 2  Source Network Address: 172.18.39.2 | .ds-logs-windows.other-default-2026.10.17-000001 / AaFIKaWOc7y0JL-w3yNa | q-bbad469eeb | ok |
| 2 | 2020-05-02 03:19:10.000Z | scranton.dmevals.local | windows.security | user.name | DWM-1 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL88ahmW | q-fb64f3923d | ok |
| 3 | 2020-05-02 03:20:40.000Z | newyork.dmevals.local | windows.security | win.TargetUserName | pbeesly | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL8xSa_z | q-239dc60d65 | ok |

### F19 · benign / high · T1187 · Routine domain SYSVOL/IPC$ SMB access and localhost SMB loopback — benign background

Evidence status: **verified**

The bulk of the T1187 check hits are normal domain behaviour: 5140/5145 share-access events on newyork.dmevals.local are machine-account SYSVOL policy reads (NEWYORK$, SCRANTON$, NASHUA$, UTICA$, WEC$) and pbeesly IPC$ samr access, and Sysmon event 3 SMB connections are either loopback (fe80:0:0:0:e40c:95b6:b0a7:6429 to itself on port 445) or workstation-to-DC 10.0.0.4:445 group-policy traffic. Zeek SMB records show the same pattern (\\NEWYORK.dmevals.local\sysvol gpt.ini / GptTmpl.inf reads). No .lnk/.scf/.url coercion files were found in the Sysmon file-creation stack, and no PowerShell scriptblock referenced 445/WebDAV/NTLM in the C141 check. These are not forced-authentication indicators.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:56:47.000Z | newyork.dmevals.local | windows.security | win.ShareName | \\*\SYSVOL | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL9Tx5o2 | q-8f354e34da | ok |
| 2 | 2020-05-02 03:04:04.000Z | newyork.dmevals.local | windows.security | win.RelativeTargetName | samr | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL9Kl3_9 | q-8f354e34da | ok |
| 3 | 2020-05-02 02:56:48.006Z | newyork.dmevals.local | windows.sysmon | destination.ip | fe80:0:0:0:e40c:95b6:b0a7:6429 | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL7Yk7Al | q-24eb0d9322 | ok |
| 4 | 2020-04-30 00:12:01.673Z | simplerockbuild.simplerock.lan | zeek | zeek.name | dmevals.local\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf | .ds-logs-zeek-default-2026.10.17-000001 / AaFIKqWOc7y0JMDGJw1T | q-5a45fe6e8d | ok |

### F22 · benign / medium · T1212 · Kerberos 4768/4769 volume and remaining LSASS handle events are routine Windows behaviour

Evidence status: **verified**

The 42 Kerberos events (28x 4769, 14x 4768) are ordinary ticket requests: on newyork.dmevals.local user pbeesly@DMEVALS.LOCAL requests service tickets for krbtgt, NEWYORK$ and NASHUA$ from 10.0.1.4/10.0.1.6, and SCRANTON$ requests NEWYORK$/krbtgt — normal machine and user logon traffic with no RC4 downgrade, no 4770 and no anomalous encryption evidence retrieved. Likewise the bulk of the 326 Sysmon process-access events targeting lsass.exe are svchost.exe with GrantedAccess 0x1000 (289 events) plus AntimalwareConfig.exe (15) and WindowsAzureTelemetryService.exe (13), i.e. security/telemetry products querying limited information; the 0x1FFFFF accesses by wininit.exe and csrss.exe at 03:19:09 coincide with a SYSTEM logon type 0 (boot) and are normal boot-time handle duplication. The zeek notices/weirds (14 events, 2020-04-30) are in a non-overlapping window and contain no exploit or credential-access indicators. No exploit code, CVE reference or 'exploit' string was found in windows.other or in PowerShell 4104 script blocks.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:04.000Z | newyork.dmevals.local | windows.security | message | A Kerberos service ticket was requested.    Account Information:  	Account Name:		pbeesly@DMEVALS.LOCAL  	Account Domain:		DMEVALS.LOCAL  	Logon GUID:		{b4946ef… | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL9MpvNN | q-3804207965 | ok |
| 2 | 2020-05-02 03:04:04.000Z | newyork.dmevals.local | windows.security | user.name | pbeesly@DMEVALS.LOCAL | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL9MpvNN | q-3804207965 | ok |
| 3 | 2020-05-02 02:55:23.551Z | utica.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1000 | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL7anEhk | q-83aa13224c | ok |
| 4 | 2020-05-02 03:19:09.803Z | scranton.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\wininit.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2ORrtr | q-e1dc15878f | ok |
| 5 | 2020-05-02 03:19:09.000Z | scranton.dmevals.local | windows.security | win.LogonType | 0 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL88axkf | q-8259fb2493 | ok |

### F23 · benign / medium · T1539 · No web session cookie theft observed; cookie-related hits are Windows WebDAV/DavSetCookie and LocalService INetCookies artefacts of the exfil chain

Evidence status: **verified**

Hunting for T1539 on 2020-05-02 02:55-03:28Z found no evidence of browser session-cookie theft. The only cookie-named file creation in the whole sysmon window is C:\Windows\ServiceProfiles\LocalService\AppData\Local\Packages\warp_jit_db4a1097-b484-4973-bbf2-a04208ecd4d4\AC\INetCookies, created by C:\windows\System32\svchost.exe (SYSTEM) on scranton.dmevals.local at 03:21:05Z - a LocalService package cache path, not a user browser cookie store. The five 4688 hits for 'cookie' are all rundll32.exe C:\windows\system32\davclnt.dll,DavSetCookie 192.168.0.4 http://192.168.0.4/webdav on scranton.dmevals.local (user pbeesly, parent svchost.exe) at 23:08:50 and 23:10:22-23:10:23 local time; DavSetCookie is the WebDAV client setting a WebDAV auth cookie for the mapped \\192.168.0.4\webdav share, which matches the attacker's Invoke-Exfil script block (New-PSDrive to \\192.168.0.4\webdav, Copy-Item OfficeSupplies.7z) - it is WebDAV credential/cookie handling for exfiltration, not theft of browser session cookies. Zeek HTTP to 192.168.0.4 (2020-04-30, non-overlapping window) shows only DavClnt / Microsoft-WebDAV-MiniRedir OPTIONS and PROPFIND requests for /webdav and /webdav/OfficeSupplies.7z, consistent with the same WebDAV upload. Sysmon 10 process-access to Edge processes is dominated by Explorer.EXE and svchost.exe (normal Edge broker/IPC); the only PowerShell-sourced accesses (6 events, scranton, 03:01:03Z) are GrantedAccess 0x1000 (PROCESS_QUERY_LIMITED_INFORMATION) with a managed System.ni.dll call trace, i.e. .NET process enumeration, not memory reads for cookie extraction. No access to Chrome/Firefox/IE cookie databases, no Login Data/WebCache/Local Storage file access, and no cookie-related PowerShell script blocks or windows.other messages were found. The host is clearly compromised (Invoke-Exfil, PsExec, sdelete, WebDAV exfil), but the credential-access activity in this window is not web session cookie theft.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:21:05.681Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Windows\ServiceProfiles\LocalService\AppData\Local\Packages\warp_jit_db4a1097-b484-4973-bbf2-a04208ecd4d4\AC\INetCookies | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JLx56e_Q | q-9cc88ec15a | ok |
| 2 | 2020-05-02 03:21:05.681Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\System32\svchost.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JLx56e_Q | q-908e2c7971 | ok |
| 3 | 2020-05-02 03:08:50.000Z | scranton.dmevals.local | windows.security | process.command_line | rundll32.exe C:\windows\system32\davclnt.dll,DavSetCookie 192.168.0.4 http://192.168.0.4/webdav | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL9IkK9d | q-ac27aa157d | ok |
| 4 | 2020-05-02 03:08:50.000Z | scranton.dmevals.local | windows.security | win.ParentProcessName | C:\Windows\System32\svchost.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL9IkK9d | q-ac27aa157d | ok |
| 5 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JL8F_6E7 | q-e578d4b7e7 | ok |
| 6 | 2020-05-02 03:01:03.622Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1000 | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL7BNbJC | q-6c777619c7 | ok |
| 7 | 2020-05-02 03:01:03.622Z | scranton.dmevals.local | windows.sysmon | win.TargetImage | C:\Windows\SystemApps\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\MicrosoftEdge.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL7BNbJC | q-6c777619c7 | ok |
| 8 | 2020-04-30 00:32:21.895Z | simplerockbuild.simplerock.lan | zeek | zeek.uri | /webdav/OfficeSupplies.7z | .ds-logs-zeek-default-2026.10.17-000001 / AaFIKqWOc7y0JMDGKA5I | q-8845f91150 | ok |
| 9 | 2020-04-30 00:32:21.895Z | simplerockbuild.simplerock.lan | zeek | user_agent.original | Microsoft-WebDAV-MiniRedir/10.0.18362 | .ds-logs-zeek-default-2026.10.17-000001 / AaFIKqWOc7y0JMDGKA5I | q-8845f91150 | ok |

### F27 · benign / high · T1552.002 · Registry Password/Credential value sets are Windows service and identity plumbing, not credential harvesting

Evidence status: **verified**

The 17 Sysmon 13 hits on registry paths containing Password/Credential are all written by legitimate system binaries: svchost.exe writing HKU\.DEFAULT\Software\Microsoft\IdentityCRL\ProviderPasswordLength/ProviderPasswordCharacterGroups on nashua and scranton, lsass.exe setting DeviceGuard\Scenarios\CredentialGuard\Enabled to 0 on scranton, services.exe creating the CredentialEnrollmentManagerUserSvc_13619b service keys, and winlogon.exe writing the PasswordExpiryNotification NotShownTime value. No adversary process wrote credential-bearing registry values.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:28.255Z | nashua.dmevals.local | windows.sysmon | message | Registry value set:  RuleName: -  EventType: SetValue  UtcTime: 2020-05-02 03:05:28.255  ProcessGuid: {5aa8ec29-e378-5eac-6103-000000000400}  ProcessId: 8736  I… | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL21_2XV | q-450c1e829f | ok |
| 2 | 2020-05-02 03:19:09.865Z | scranton.dmevals.local | windows.sysmon | message | Registry value set:  RuleName: -  EventType: SetValue  UtcTime: 2020-05-02 03:19:09.865  ProcessGuid: {47ab858c-e6ad-5eac-0c00-000000000500}  ProcessId: 748  Im… | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2ORrtv | q-450c1e829f | ok |
| 3 | 2020-05-02 03:20:48.264Z | scranton.dmevals.local | windows.sysmon | message | Registry value set:  RuleName: -  EventType: SetValue  UtcTime: 2020-05-02 03:20:48.264  ProcessGuid: {47ab858c-e6ad-5eac-0b00-000000000500}  ProcessId: 736  Im… | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JLx4z3lk | q-450c1e829f | ok |

### F28 · benign / medium · T1552.003 · No shell history access observed

Evidence status: **verified**

No process creation or file-access event referencing ConsoleHost_history.txt or other shell history files was returned in any dataset. The attacker's PowerShell activity was captured through script-block logging rather than history-file reads.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:01:51.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | gci C:\programdata\victim\ | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMAQDVq3 | q-ad2b9e32ad | ok |

### F29 · benign / medium · T1552.006 · No Group Policy Preferences credential extraction observed

Evidence status: **verified**

No process command line or file-access event referenced Groups.xml, sysvol, or cpassword in the Windows datasets. The only GroupPolicy-related file activity was routine GptTmpl.inf/gpt.ini writes under the local GroupPolicy DataStore, and gpupdate.exe /target:computer was run by NETWORK SERVICE, which is normal policy refresh behaviour.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:01:42.046Z | scranton.dmevals.local | windows.sysmon | process.command_line | gpupdate.exe /target:computer | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL6-JcMt | q-76eb6e4449 | ok |

### F32 · benign / medium · T1555.003 · No browser credential-store access (Login Data / logins.json / browser process handles) on any host

Evidence status: **verified**

Checks C209-C214 (Sysmon process/file/process-access, Security object access, PowerShell script blocks, other channels) for browser credential files and browser process handles returned zero hits across scranton, nashua, newyork and utica. The intruder's collection on scranton targeted documents, certificates, keystrokes, clipboard and screenshots rather than browser password databases; no evidence of web-browser credential theft in this window.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:56:17.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | $env:APPDATA;$files=ChildItem -Path $env:USERPROFILE\ -Include *.doc,*.xps,*.xls,*.ppt,*.pps,*.wps,*.wpd,*.ods,*.odt,*.lwp,*.jtd,*.pdf,*.zip,*.rar,*.docx,*.url,… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFIKqWOc7y0JMAWIxak | q-36ecd61fef | ok |

### F31 · benign / medium · T1555.004 · LSASS handle access on all four hosts is dominated by Windows/Azure platform binaries — no Credential Manager (vault/cmdkey) theft observed

Evidence status: **verified**

Stacking the 326 Sysmon event-10 LSASS accesses shows 293 with 0x1000 and 24 with 0x1400, produced by svchost.exe, services.exe, csrss.exe, wininit.exe, wsmprovhost.exe, dsregcmd.exe, RuntimeBroker.exe, ShellExperienceHost.exe, sppsvc.exe, wmiprvse.exe, MsMpEng.exe, WindowsAzureTelemetryService.exe, AntimalwareConfig.exe and CollectGuestLogs.exe — normal Windows/Azure guest-agent behaviour. Security 4663/4656 object-access on lsass.exe likewise comes from CollectGuestLogs.exe (0x1410/0x10) and MsMpEng.exe. The only non-platform LSASS access is the pbeesly PowerShell/wsmprovhost activity reported under T1555. No cmdkey, vaultcmd, DPAPI Protect folder or Credential Manager file access was found (checks C217-C220 returned nothing beyond a benign 'Credential Guard configuration: 0x0, 0' event on scranton).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:42.009Z | scranton.dmevals.local | windows.sysmon | win.SourceImage | C:\WindowsAzure\Packages\Telemetry\WindowsAzureTelemetryService.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JLx0p9yU | q-a3e6782aa6 | ok |
| 2 | 2020-05-02 03:19:09.803Z | scranton.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\wininit.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2ORrtr | q-a3e6782aa6 | ok |
| 3 | 2020-05-02 03:18:34.438Z | scranton.dmevals.local | windows.sysmon | win.CallTrace | C:\windows\SYSTEM32\ntdll.dll+9def4\|c:\windows\system32\lsm.dll+1aa6e\|c:\windows\system32\lsm.dll+1a9c3\|c:\windows\system32\lsm.dll+65e1\|c:\windows\system32… | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2QULdY | q-a3e6782aa6 | ok |
| 4 | 2020-05-02 03:22:38.000Z | nashua.dmevals.local | windows.security | win.ProcessName | C:\WindowsAzure\Packages\CollectGuestLogs.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL8nPsh9 | q-813d8b560c | ok |
| 5 | 2020-05-02 03:19:09.000Z | scranton.dmevals.local | windows.other | message | Credential Guard configuration: 0x0, 0 | .ds-logs-windows.other-default-2026.10.17-000001 / AaFIKaWOc7y0JL-w3yMh | q-df5f4b5775 | ok |

### F33 · benign / medium · T1555.005 · No password-manager artefacts (KeePass/1Password/Bitwarden/LastPass/kdbx) observed

Evidence status: **verified**

Checks C221-C226 for password-manager executables, files, process handles, command lines, script blocks and other-channel messages returned zero hits on all four hosts. The only credential-adjacent collection seen was certificate private-key export (Get-PrivateKeys writing .pfx files) and keystroke/clipboard capture by pbeesly on scranton, which is not password-manager store access.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:57.460Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL63CdmD | q-be4b564417 | ok |

### F35 · benign / medium · T1556.001 · Network logons are machine-account and PSEXESVC activity; no DC authentication backdoor observed

Evidence status: **verified**

The 218 type-3 logons are almost entirely the NEWYORK$ machine account authenticating from ::1, fe80::e40c:95b6:b0a7:6429 and 10.0.0.4, i.e. normal local/loopback machine-account traffic. The 15 explicit-credential (4648) events show user pbeesly using explicit credentials from 10.0.1.6 on scranton and via C:\Windows\PSEXESVC.exe on nashua, plus a DWM-1/winlogon.exe entry — consistent with PsExec administration, not with a Skeleton Key or injected false credentials on a domain controller. No 4657 registry change to LSA/SAM and no 4688 command line referencing lsass/cryptdll/msv1_0 were found.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:56:47.000Z | newyork.dmevals.local | windows.security | source.ip | 10.0.0.4 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL9Tx5qJ | q-742e730435 | ok |
| 2 | 2020-05-02 03:11:40.000Z | nashua.dmevals.local | windows.security | process.executable | C:\Windows\PSEXESVC.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL9OrXFR | q-548554c447 | ok |
| 3 | 2020-05-02 03:11:40.000Z | nashua.dmevals.local | windows.security | user.name | pbeesly | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL9OrXFR | q-548554c447 | ok |

### F36 · benign / medium · T1556.002 · No password filter DLL installation or Notification Packages registry change

Evidence status: **verified**

Checks for password-filter indicators returned nothing: no 4657 change to Notification Packages/Password/lsass registry values, no 4688 command line containing Notification or PasswordFilter, no PowerShell script block referencing Notification/PasswordFilter/lsass, and no sysmon file-create of a DLL into System32. The only image loads into authentication DLLs are Microsoft-signed system DLLs (cryptdll.dll, samcli.dll, samlib.dll, msv1_0.dll, samsrv.dll) loaded by svchost.exe, lsass.exe, WmiPrvSE.exe, SearchIndexer.exe, LogonUI.exe and VSSVC.exe, plus one apisampling.dll load by svchost.exe on scranton at 03:21:27 (Microsoft 'API Sampling', 10.0.18362.1).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:21:27.354Z | scranton.dmevals.local | windows.sysmon | win.ImageLoaded | C:\Windows\System32\apisampling.dll | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JLx6_vHT | q-8d3d02d5f5 | ok |
| 2 | 2020-05-02 03:21:27.354Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\Windows\System32\svchost.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JLx6_vHT | q-8d3d02d5f5 | ok |

### F37 · benign / medium · T1556.005 · No reversible-encryption or AD user-attribute modification observed

Evidence status: **verified**

No 4739 (domain policy change), no 4688/sysmon process creation with Set-ADUser, dsmod or Reversible in the command line, and no PowerShell script block or windows.other message referencing AllowReversiblePasswordEncryption/ReversibleEncryption. The only account-related activity in the window is the pbeesly explicit-credential use described above.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:18.000Z | scranton.dmevals.local | windows.security | user.name | pbeesly | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL9OrXFV | q-548554c447 | ok |

### F38 · benign / medium · T1556.006 · No MFA/authentication policy registry or directory changes

Evidence status: **verified**

No 4739 policy-change events, no 5136 directory-object modifications, and no Set-ADUser/Set-ADAccountControl style command lines in sysmon or PowerShell. The registry writes seen on scranton between 03:04 and 03:10 are unrelated Windows notification/tile data and W32Time SecureTimeLimits values written by lsass.exe, not authentication-policy changes.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:41.209Z | scranton.dmevals.local | windows.sysmon | registry.path | HKLM\System\CurrentControlSet\Services\W32Time\SecureTimeLimits\RunTime\SecureTimeTickCount | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL20-Wda | q-8cf87fce27 | ok |

### F39 · benign / medium · T1556.007 · No hybrid-identity (Azure AD / AD FS / Seamless SSO) tampering observed

Evidence status: **verified**

No 5136 directory changes and no PowerShell script blocks referencing Connect-MsolService, Connect-AzureAD or similar hybrid-identity cmdlets. dsregcmd.exe on newyork.dmevals.local at 03:06:14 only loaded cryptdll.dll, which is normal for device-registration queries; no configuration change followed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:06:14.783Z | newyork.dmevals.local | windows.sysmon | process.executable | C:\Windows\System32\dsregcmd.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2x8I9e | q-f2a17d5dd8 | ok |

### F40 · benign / medium · T1556.008 · No Network Provider DLL registration or credential-provider modification

Evidence status: **verified**

No 4657 registry change to NetworkProvider or credential-provider keys and no PowerShell script block referencing NetworkProvider or New-ItemProperty. The LSA registry key (\REGISTRY\MACHINE\SYSTEM\ControlSet001\Control\Lsa) appears only in 4656 handle-open events with AccessMask 0x1 by pbeesly's cmd.exe/powershell.exe/conhost.exe on scranton and by LOCAL SERVICE svchost.exe on nashua — read-only key opens, not value writes.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:55:56.000Z | scranton.dmevals.local | windows.security | win.ObjectName | \REGISTRY\MACHINE\SYSTEM\ControlSet001\Control\Lsa | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL9TypoR | q-1103e1a2c5 | ok |
| 2 | 2020-05-02 02:55:56.000Z | scranton.dmevals.local | windows.security | win.AccessMask | 0x1 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL9TypoR | q-1103e1a2c5 | ok |

### F42 · benign / medium · T1557.001 · No name-resolution poisoning or SMB relay observed; SMB/Kerberos traffic is normal domain-member to DC authentication

Evidence status: **verified**

The SMB and name-resolution telemetry shows only expected domain behaviour. Zeek SMB sessions are between internal members (10.0.1.4 scranton, 10.0.1.6 nashua) and the domain controller 10.0.0.4 (NEWYORK) on 445/389/88, mapping \\NEWYORK.dmevals.local\IPC$ and \sysvol, with Kerberos/GSSAPI authentication — consistent with GPO/SYSVOL access and machine-account logons (4624 type 3 as SCRANTON$/NASHUA$/UTICA$/WEC$). Sysmon DNS queries (81 events) contain only normal names (wpad, _ldap._tcp SRV lookups, microsoft/akamai/azure endpoints) with no LLMNR/NBT-NS-style single-label lookups answered by an unexpected host. No 4657 DNS client registry tampering, no Responder/LLMNR/NBT-NS script content, and no SMB relay listener was found. The 4697 service installs are the attacker's own javamtsup/PSEXESVC services (covered under T1557), not relay infrastructure. The one unusual SMB pattern — 10.0.1.4 -> 10.0.1.6:445 at 00:35:26 with source MAC fc:bd:67:e1:a9:c1 — is the attacker's PsExec SMB session to nashua, not a relay.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-04-30 00:12:01.658Z | simplerockbuild.simplerock.lan | zeek | zeek.path | \\NEWYORK.dmevals.local\sysvol | .ds-logs-zeek-default-2026.10.17-000001 / AaFIKqWOc7y0JMDGKA0r | q-82e44b67f3 | ok |
| 2 | 2020-04-30 00:35:26.036Z | bobs.bigwheel.local | zeek | zeek.orig_l2_addr | fc:bd:67:e1:a9:c1 | .ds-logs-zeek-default-2026.10.17-000001 / AaFIK6WOc7y0JMA-MvX6 | q-6be11efc9b | ok |
| 3 | 2020-05-02 03:01:42.000Z | newyork.dmevals.local | windows.security | win.TargetUserName | SCRANTON$ | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL9Kmn8b | q-cb2253b53a | ok |

### F43 · benign / medium · T1557.002 · No ARP cache poisoning indicators; MAC-to-IP mappings are stable and consistent

Evidence status: **verified**

Zeek L2 address stacking over 613 conn records shows three source MACs (00:0d:3a:13:e3:69, 00:0d:3a:4d:42:f2, fc:bd:67:e1:a9:c1) and responder MACs 12:34:56:78:9a:bc (the gateway/DC side) plus broadcast ff:ff:ff:ff:ff:ff for NetBIOS 138 broadcasts. Each host MAC maps to a single consistent IP (10.0.1.4, 10.0.1.6) with no MAC claiming multiple IPs and no duplicate/gratuitous mappings that would indicate ARP spoofing. The 138/137 traffic is ordinary NetBIOS name-service broadcast from System. No PowerShell content referencing arp or netsh interface manipulation was found. The only external-looking flows (10.0.1.4 -> 192.168.0.5:1234 and :443) are the attacker's own C2/beacon traffic from the compromised host, not traffic redirected by ARP poisoning.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-04-30 00:08:02.361Z | simplerockbuild.simplerock.lan | zeek | destination.ip | 192.168.0.5 | .ds-logs-zeek-default-2026.10.17-000001 / AaFIKqWOc7y0JMDGKA0K | q-6be11efc9b | ok |
| 2 | 2020-04-30 00:08:43.385Z | bobs.bigwheel.local | zeek | zeek.resp_l2_addr | ff:ff:ff:ff:ff:ff | .ds-logs-zeek-default-2026.10.17-000001 / AaFIK6WOc7y0JMA_NKaC | q-3c6a72b69e | ok |
| 3 | 2020-05-02 02:56:32.208Z | nashua.dmevals.local | windows.sysmon | destination.port | 138 | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL7YlLAM | q-ec81aa420c | ok |

### F44 · benign / medium · T1557.003 · No DHCP spoofing activity; no DHCP events or DHCP traffic in any dataset

Evidence status: **verified**

No DHCP-related evidence exists in the collected windows. The System channel (windows.other, 216 events) contains no DHCP client/server event codes (1341/1342/1020/1063 returned zero hits), no PowerShell script block references Dhcp, and Sysmon network connections show no DHCP ports 67/68 — the destination-port stack is dominated by 8443, 389, 88, 53, 135, 445, 443 with no 67/68 entries. Zeek contains no dhcp log type (only conn, files, ssl, x509, dce_rpc, http, dns, kerberos, dpd, smb_files, weird, smb_mapping, notice, pe). The 5156 inbound-filter check also returned nothing. DHCP spoofing is therefore not observable in this telemetry and no indicator of it was found.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:04.000Z | scranton.dmevals.local | windows.other | message | The miniport 'Microsoft Hyper-V Network Adapter' was successfully initialized | .ds-logs-windows.other-default-2026.10.17-000001 / AaFIKaWOc7y0JL-w3yNV | q-e7f2dc0eaa | ok |
| 2 | 2020-05-02 02:56:38.280Z | scranton.dmevals.local | windows.sysmon | destination.port | 138 | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL7Yk7C5 | q-ec81aa420c | ok |

### F46 · benign / medium · T1558.001 · Golden ticket: no forged-TGT indicators; krbtgt service-ticket requests are normal AES256 TGS renewals

Evidence status: **verified**

All 28 event 4769 records on newyork.dmevals.local use Ticket Encryption Type 0x12 (AES256) with Failure Code 0x0 and Ticket Options 0x60810010/0x40810000 — no RC4 (0x17/0x18) downgrade, no anomalous encryption, no 4672 logons by unexpected principals (the 4672 events are the machine account NEWYORK$ with its standard privilege set). The krbtgt service requests by pbeesly@DMEVALS.LOCAL (03:04:04Z) and SCRANTON$@DMEVALS.LOCAL (03:19:13Z) are ordinary TGS requests for the krbtgt SPN, not forged TGT use. No golden-ticket tooling or krbtgt references appear in PowerShell script blocks.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:13.000Z | newyork.dmevals.local | windows.security | win.TicketEncryptionType | 0x12 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL8-bHCF | q-e1c7bee85d | ok |
| 2 | 2020-05-02 03:04:04.000Z | newyork.dmevals.local | windows.security | win.ServiceName | krbtgt | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL9MpvNN | q-525adead7f | ok |
| 3 | 2020-05-02 02:55:54.000Z | newyork.dmevals.local | windows.security | win.SubjectUserName | NEWYORK$ | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL9TypoZ | q-9d35e753c2 | ok |

### F47 · benign / medium · T1558.002 · Silver ticket: no service-ticket forgery indicators; TGS requests are routine host/SPN access

Evidence status: **verified**

The 4769 service tickets on newyork.dmevals.local target machine accounts (NEWYORK$, NASHUA$, SCRANTON$, WEC$) and krbtgt, all AES256 (0x12) with success status 0x0, issued to pbeesly@DMEVALS.LOCAL and SCRANTON$@DMEVALS.LOCAL from 10.0.1.4/10.0.1.6. Zeek kerberos records (2020-04-30 window) show only AS/TGS requests by pbeesly for krbtgt, cifs/NEWYORK, cifs/NASHUA, ldap/NEWYORK and host/nashua with aes256-cts-hmac-sha1-96 and no failures other than normal KDC_ERR_PREAUTH_REQUIRED. No silver-ticket tooling or SPN-targeted script blocks were found.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:09:23.000Z | newyork.dmevals.local | windows.security | win.ServiceName | NASHUA$ | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL9OrnEj | q-faccfa1147 | ok |
| 2 | 2020-04-30 00:24:19.122Z | simplerockbuild.simplerock.lan | zeek | zeek.service | cifs/NEWYORK | .ds-logs-zeek-default-2026.10.17-000001 / AaFIKqWOc7y0JMDGJw1d | q-5ebab1f540 | ok |
| 3 | 2020-04-30 00:24:19.119Z | simplerockbuild.simplerock.lan | zeek | zeek.cipher | aes256-cts-hmac-sha1-96 | .ds-logs-zeek-default-2026.10.17-000001 / AaFIKqWOc7y0JMDGJw1g | q-5ebab1f540 | ok |

### F48 · benign / medium · T1558.003 · Kerberoasting: no RC4 service-ticket requests or roasting tooling observed

Evidence status: **verified**

No 4769 ticket used RC4 (all 28 are 0x12/AES256), which is the hallmark of Kerberoasting, and no PowerShell script block referenced Kerberoast/Invoke-Kerberoast/Rubeus. The zeek kerberos log shows only AES256 TGS requests for cifs/host/ldap SPNs by pbeesly, consistent with normal file-share and host access.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:10:23.000Z | newyork.dmevals.local | windows.security | win.TicketEncryptionType | 0x12 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL9LnlqF | q-faccfa1147 | ok |
| 2 | 2020-04-30 00:36:38.972Z | bobs.bigwheel.local | zeek | zeek.service | host/nashua.dmevals.local | .ds-logs-zeek-default-2026.10.17-000001 / AaFIK6WOc7y0JMA_NaZg | q-5ebab1f540 | ok |

### F49 · benign / medium · T1558.004 · AS-REP roasting: no pre-auth-disabled account enumeration; AS exchanges are normal

Evidence status: **verified**

Zeek kerberos AS exchanges from 10.0.1.4 and 10.0.1.6 to the KDC 10.0.0.4 are all for pbeesly/dmevals requesting krbtgt, each preceded by a normal KDC_ERR_PREAUTH_REQUIRED and followed by a successful AES256 AS-REP — i.e. pre-authentication is enforced, so no AS-REP roasting. No GetNPUsers/AS-REP/DontRequirePreAuth strings appear in PowerShell script blocks.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-04-30 00:24:19.110Z | simplerockbuild.simplerock.lan | zeek | zeek.error_msg | KDC_ERR_PREAUTH_REQUIRED | .ds-logs-zeek-default-2026.10.17-000001 / AaFIKqWOc7y0JMDGJw1f | q-5ebab1f540 | ok |
| 2 | 2020-04-30 00:24:19.119Z | simplerockbuild.simplerock.lan | zeek | zeek.request_type | AS | .ds-logs-zeek-default-2026.10.17-000001 / AaFIKqWOc7y0JMDGJw1g | q-5ebab1f540 | ok |

### F51 · benign / medium · T1606.001 · No forged web cookies observed; only benign INetCookies file creation and ordinary HTTP traffic

Evidence status: **verified**

The only cookie-related file event in the whole window is a single Sysmon file-create on scranton.dmevals.local at 2020-05-02T03:21:05Z by C:\windows\System32\svchost.exe writing C:\Windows\ServiceProfiles\LocalService\AppData\Local\Packages\warp_jit_db4a1097-b484-4973-bbf2-a04208ecd4d4\AC\INetCookies - a LocalService package cookie store created by the normal Windows service host, not by the attacker's PowerShell session. No PowerShell script block in windows.powershell references cookie, Set-Cookie or session handling (zero hits), and the Zeek window (2020-04-30, non-overlapping with the Windows telemetry) contains only 62 ordinary HTTP records from 10.0.1.4 to 192.168.0.4 with no cookie-forgery indicators. The attacker's credential theft on scranton targeted certificate private keys, not browser cookies, so cookie forgery is not evidenced.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:21:05.681Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Windows\ServiceProfiles\LocalService\AppData\Local\Packages\warp_jit_db4a1097-b484-4973-bbf2-a04208ecd4d4\AC\INetCookies | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JLx56e_Q | q-fe004626f2 | ok |
| 2 | 2020-05-02 03:21:05.681Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\System32\svchost.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JLx56e_Q | q-fe004626f2 | ok |

### F53 · benign / high · T1621 · No MFA request generation observed; C355 hits are routine WMI provider events

Evidence status: **verified**

The only T1621 check with hits (C355, windows.other, 85 events) matched WMI-Activity events 5857/5858, not authentication failures. Event 5858 (49 events, 48 on newyork.dmevals.local) are IWbemServices::DeleteInstance calls against Root\Rsop\Computer RSOP_ExtensionStatus.extensionGuid entries by NT AUTHORITY\SYSTEM with ResultCode 0x80041002 (object not found) — normal Group Policy/RSoP WMI cleanup. Event 5857 (36 events across newyork, scranton, nashua, utica) are WMI provider start records (dsccore, CIMWin32, deploymentprovider, dnsclientcim, StorageWMI) with result code 0x0, hosted in wmiprvse.exe. Neither is an MFA push/OTP request. No 4625 failed-logon events exist in windows.security, no MFA/2FA/authenticator/push/duo/okta strings appear in any of the 414 PowerShell 4104 script blocks, and no such strings appear in Sysmon process command lines (the only 'azure' matches were legitimate Azure guest-agent binaries such as WindowsAzureGuestAgent.exe, WaSecAgentProv.exe and NetworkWatcherAgent.exe). dsregcmd.exe on nashua.dmevals.local contacted only the local domain controller 10.0.0.4 on 389/135/49667, with no cloud identity-provider traffic. Zeek HTTP had no login/auth/mfa URLs. Separately noted but unrelated to T1621: C:\Windows\Temp\python.exe (SHA256 43782EC4337D8F3DDB7EA0C451B3BC4F212F84C8D5571BD0A842001C859A02AE) was launched as user pbeesly on nashua.dmevals.local via C:\windows\PSEXESVC.exe and made 348 TCP connections to 192.168.0.4:8443 — this is lateral-movement/credential tooling, not MFA fatigue.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:56:47.000Z | newyork.dmevals.local | windows.other | message | Id = {C11E1664-7828-4AD0-B23A-0FCEF0EA26C0}; ClientMachine = NEWYORK; User = NT AUTHORITY\SYSTEM; ClientProcessId = 1588; Component = Unknown; Operation = Start… | .ds-logs-windows.other-default-2026.10.17-000001 / AaFIKaWOc7y0JL-w3yMK | q-42b94729d8 | ok |
| 2 | 2020-05-02 03:01:28.000Z | newyork.dmevals.local | windows.other | message | dsccore provider started with result code 0x0. HostProcess = wmiprvse.exe; ProcessID = 5344; ProviderPath = %systemroot%\system32\DscCore.dll | .ds-logs-windows.other-default-2026.10.17-000001 / AaFIKaWOc7y0JL-w3iO6 | q-d2ded0d129 | ok |
| 3 | 2020-05-02 03:01:30.000Z | newyork.dmevals.local | windows.other | message | CIMWin32 provider started with result code 0x0. HostProcess = wmiprvse.exe; ProcessID = 4292; ProviderPath = %systemroot%\system32\wbem\cimwin32.dll | .ds-logs-windows.other-default-2026.10.17-000001 / AaFIKaWOc7y0JL-w3iOa | q-d2ded0d129 | ok |
| 4 | 2020-05-02 03:25:31.315Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\Windows\System32\dsregcmd.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL18GdOb | q-18ca0ea40f | ok |
| 5 | 2020-05-02 03:15:03.954Z | nashua.dmevals.local | windows.sysmon | process.parent.executable | C:\Windows\PSEXESVC.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2bgzd1 | q-4a01ea1b6b | ok |
| 6 | 2020-05-02 03:15:05.142Z | nashua.dmevals.local | windows.sysmon | destination.port | 8443 | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2bgjeM | q-32e31791c6 | ok |

### F55 · benign / medium · T1649 · Routine certificate-store writes by lsass/svchost/taskhostw and Kerberos TGT requests are benign

Evidence status: **verified**

The remaining T1649 hits are normal Windows certificate-store maintenance and normal Kerberos logons. On nashua.dmevals.local, lsass.exe (PID 728) wrote AuthRoot\Certificates\A8985D3A65E5E5C4B2D7D66D40C6DD2FB19C5436\Blob at 02:59:37 and svchost.exe wrote AuthRoot\Certificates\AFE5D244A8D1194230FF479FE2F897BBCD7A8CB4\Blob at 03:16:19 (root certificate auto-update); svchost.exe on nashua and scranton wrote Windows Live ID Token Issuer certificate blobs at 03:05; smss.exe wrote the WOW6432Node SystemCertificates SymbolicLinkValue on scranton at 03:19; taskhostw.exe wrote per-user ACRS PhysicalStores values for SID ...-1107 on scranton at 03:20. The single 4657 on nashua (ROOT\Certificates\BE36A4562FB2EE05DBB3D32323ADF445084ED656, subject NASHUA$, process C:\Windows\Sysmon.exe) is a machine-account store update, not attacker tooling. The 14 Kerberos 4768 TGT requests on newyork.dmevals.local are for pbeesly (9) and the machine account SCRANTON$ (5) from internal addresses 10.0.1.4/10.0.1.6 — ordinary interactive and machine logons, with no certificate-based (PKINIT) or forged-ticket indicators. The Zeek x509 subjects (rempel.group.net 376, conn.sons.info 2) are from a non-overlapping 2020-04-30 window and show no relation to the Windows hosts.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:59:37.453Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL7LXG4H | q-2e0c2964be | ok |
| 2 | 2020-05-02 03:16:19.447Z | nashua.dmevals.local | windows.sysmon | registry.path | HKLM\SOFTWARE\Microsoft\SystemCertificates\AuthRoot\Certificates\AFE5D244A8D1194230FF479FE2F897BBCD7A8CB4\Blob | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2ZequA | q-2e0c2964be | ok |
| 3 | 2020-05-02 03:19:09.192Z | scranton.dmevals.local | windows.sysmon | registry.path | HKLM\SOFTWARE\WOW6432Node\Microsoft\SystemCertificates\SymbolicLinkValue | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JL2OR7uU | q-2e0c2964be | ok |
| 4 | 2020-05-02 03:20:49.745Z | scranton.dmevals.local | windows.sysmon | registry.path | HKU\S-1-5-21-1830255721-3727074217-2423397540-1107\Software\Microsoft\SystemCertificates\ACRS\PhysicalStores\.LocalMachine\OpenStoreProvider | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFIKKWOc7y0JLx41usR | q-2e0c2964be | ok |
| 5 | 2020-05-02 03:16:19.000Z | nashua.dmevals.local | windows.security | win.ObjectName | \REGISTRY\MACHINE\SOFTWARE\Microsoft\SystemCertificates\ROOT\Certificates\BE36A4562FB2EE05DBB3D32323ADF445084ED656 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL9FgwRA | q-e68335b7dd | ok |
| 6 | 2020-05-02 03:11:18.000Z | newyork.dmevals.local | windows.security | win.TargetUserName | pbeesly | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL9OrXFP | q-cbcaa91aa9 | ok |
| 7 | 2020-05-02 03:19:13.000Z | newyork.dmevals.local | windows.security | win.TargetUserName | SCRANTON$ | .ds-logs-windows.security-default-2026.10.17-000001 / AaFIKaWOc7y0JL8-bHB- | q-cbcaa91aa9 | ok |

## Pivot candidates

Processes the pivot reviewer had to assess (started by a script host or from outside the Windows directory, rare in the 15-minute windows around verified activity).

| Host | Executable | Starts | Parents | Assessment | Reason |
|---|---|---|---|---|---|
| nashua.dmevals.local | C:\Program Files\WindowsApps\Microsoft.SkypeApp_14.35.152.0_x64__kzf8qxf38zg5c\S… | 1 | C:\Program Files\WindowsApps\Microsoft.SkypeApp_14.35.152.0_x64__kzf8qxf38zg5c\S… | benign | Store Skype app self-restart; routine. |
| nashua.dmevals.local | C:\Windows\Temp\python.exe | 5 | C:\Windows\PSEXESVC.exe, C:\Windows\Temp\python.exe | malicious | PsExec-delivered payload that spawned the credential-file harvester, Rar.exe and sdelete64.exe. |
| nashua.dmevals.local | C:\Windows\Temp\Rar.exe | 1 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | malicious | Password-protected archiving of harvested credential files, then wiped. |
| nashua.dmevals.local | C:\Windows\Temp\sdelete64.exe | 3 | C:\Windows\System32\cmd.exe | malicious | Anti-forensic deletion of Rar.exe and both working.zip copies. |
| nashua.dmevals.local | C:\WindowsAzure\Packages\CollectGuestLogs.exe | 1 | C:\WindowsAzure\Packages\WaAppAgent.exe | benign | Azure guest log collection; its lsass 0x10 access is standard. |
| scranton.dmevals.local | C:\Packages\Plugins\Microsoft.Azure.NetworkWatcher.NetworkWatcherAgentWindows\1.… | 4 | C:\Windows\System32\cmd.exe, C:\Windows\System32\services.exe | benign | Azure Network Watcher extension. |
| scranton.dmevals.local | C:\Packages\Plugins\Microsoft.Azure.Security.IaaSAntimalware\1.5.5.9\Antimalware… | 1 | C:\WindowsAzure\Packages\GuestAgent\WindowsAzureGuestAgent.exe | benign | Azure antimalware config helper. |
| scranton.dmevals.local | C:\Packages\Plugins\Microsoft.Compute.CustomScriptExtension\1.10.5\bin\CustomScr… | 1 | C:\Windows\System32\cmd.exe | benign | Azure VM extension handler. |
| scranton.dmevals.local | C:\Packages\Plugins\Microsoft.Compute.JsonADDomainExtension\1.3.2\bin\JsonADDoma… | 1 | C:\Windows\System32\cmd.exe | benign | Azure domain-join extension. |
| scranton.dmevals.local | C:\Program Files (x86)\Google\Update\1.3.35.452\GoogleCrashHandler.exe | 2 | C:\Program Files (x86)\Google\Update\GoogleUpdate.exe | benign | Google updater crash handler. |
| scranton.dmevals.local | C:\Program Files (x86)\Google\Update\1.3.35.452\GoogleCrashHandler64.exe | 2 | C:\Program Files (x86)\Google\Update\GoogleUpdate.exe | benign | Google updater crash handler. |
| scranton.dmevals.local | C:\Program Files (x86)\Google\Update\GoogleUpdate.exe | 3 | C:\Program Files (x86)\Google\Update\GoogleUpdate.exe, C:\Windows\System32\servi… | benign | Google updater service. |
| scranton.dmevals.local | C:\Program Files\SysinternalsSuite\accessChk.exe | 1 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | malicious | Run by pbeesly PowerShell from attacker-staged SysinternalsSuite during credential access. |
| scranton.dmevals.local | C:\Program Files\SysinternalsSuite\PsExec64.exe | 4 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | malicious | Lateral movement to NASHUA with cleartext pbeesly credentials running python.exe. |
| scranton.dmevals.local | C:\Program Files\SysinternalsSuite\sdelete64.exe | 3 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | malicious | Wiped the staged screen-saver, Draft.Zip and SysinternalsSuite.zip. |
| scranton.dmevals.local | C:\Program Files\Windows Defender\MsMpEng.exe | 1 | C:\Windows\System32\services.exe | benign | Defender service; lsass 0x10 access is normal scanning. |
| scranton.dmevals.local | C:\Program Files\Windows Defender\NisSrv.exe | 2 | C:\Windows\System32\services.exe | benign | Defender network inspection service. |
| scranton.dmevals.local | C:\ProgramData\victim\â€®cod.3aka3.scr | 1 | C:\Windows\explorer.exe | malicious | Oddly named screen saver in C:\ProgramData\victim launched by explorer; wrote monkey.png decoded by a hidden IEX stager. |
| scranton.dmevals.local | C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe | 2 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | malicious | Compiled qkbkqqbs.dll and 0piklvia.dll from PowerShell response files in Temp. |
| scranton.dmevals.local | C:\Windows\System32\hostui.exe | 1 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | suspicious | Started with -verb runas by PowerShell, followed by registry-stored encoded stager execution. |
| scranton.dmevals.local | C:\Windows\System32\sdclt.exe | 3 | C:\Windows\System32\cmd.exe | suspicious | Three launches from cmd.exe just before payload compilation; known execution proxy, no credential access seen. |
| scranton.dmevals.local | C:\WindowsAzure\Packages\GuestAgent\BfeToolWin8.exe | 1 | C:\WindowsAzure\Packages\GuestAgent\WindowsAzureGuestAgent.exe | benign | Azure guest agent firewall tool. |
| scranton.dmevals.local | C:\WindowsAzure\Packages\GuestAgent\FindVolume\FindVolume.exe | 1 | C:\WindowsAzure\Packages\GuestAgent\WindowsAzureGuestAgent.exe | benign | Azure guest agent volume helper. |
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
| T1003 OS Credential Dumping | suspicious | Credential-access toolset executed on both hosts; no dump file observed. |
| T1003.001 LSASS Memory | suspicious | Audited powershell.exe LSASS handle open (0x10) on scranton. |
| T1003.002 Security Account Manager | benign | All SAM_SERVER/SAM_DOMAIN/SAM_ALIAS handle requests are by lsass.exe as SCRANTON$; no reg save or hive copies; SAM/SECURITY file hits were Prefetch .pf files. |
| T1003.003 NTDS | not_observed | No ntds.dit access, ntdsutil/vssadmin/diskshadow command lines or shadow-copy activity; only WerFault crash dumps. |
| T1003.004 LSA Secrets | not_observed | No SECURITY Policy Secrets object access, lsadump or secrets-related command lines/script blocks. |
| T1003.005 Cached Domain Credentials | benign | HKLM\SECURITY\Cache\NL$1 writes are performed by lsass.exe itself (normal cached-credential updates); no mscache/DCC2 extraction. |
| T1003.006 DCSync | not_observed | No drsuapi/dcsync/lsadump references in process command lines or PowerShell script blocks. |
| T1040 Network Sniffing | not_observed | No sniffing artifacts in any dataset: zero hits for tcpdump/windump/wireshark/rawcap execution, pcap/sniff/promiscuous command lines, Npcap/WinPcap driver loads (sysmon event 6), or capture-driver service installs (7045 … |
| T1056 Input Capture | suspicious | Input-capture tooling present (Keystroke-Check script, python.exe payload via PsExec) and anomalous all-access LSASS handles from PowerShell/wsmprovhost; baseline LSASS/SAM access otherwise benign. |
| T1056.001 Keylogging | malicious | Keystroke-Check AV-evasion function in psversion.ps1 on scranton and remote deployment of C:\Windows\Temp\python.exe (PyInstaller, pywintypes/win32pipe) to nashua via PsExec with cleartext credentials, opening cmd/powers… |
| T1056.002 GUI Input Capture | not_observed | No 4104 script blocks or 4688 command lines referencing Credential/Prompt/Read-Host were found (checks C076/C080 returned zero hits). |
| T1056.003 Web Portal Capture | not_observed | No file writes to wwwroot/inetpub/login, no w3wp/iis process activity, no 4663 access to web content, and no HTTP POST or login/portal URLs in zeek (checks C084/C086/C087/C089/C091 zero hits). |
| T1056.004 Credential API Hooking | suspicious | PowerShell.exe (0x1f3fff, 0x1fffff) and wsmprovhost.exe (0x1f3fff) opened lsass.exe with full access via PowerShell cmdlet call traces on scranton/nashua; no explicit hooking DLL evidence, so suspicious rather than confi… |
| T1110 Brute Force | not_observed | Zero 4625/4740/4771 events in windows.security; the only 4776 (newyork, pbeesly) returned Error Code 0x0. No authentication-failure or lockout pattern exists. |
| T1110.001 Password Guessing | not_observed | No failed logons and no password-bearing command lines; the single credential validation succeeded, consistent with normal domain logon. |
| T1110.002 Password Cracking | not_observed | LSASS accesses are dominated by svchost.exe (0x1000) and AV/Azure telemetry agents; full-access opens came from the pbeesly PowerShell loader, wsmprovhost and boot-time wininit/csrss. No SAM/SECURITY hive reads, no hash/… |
| T1110.003 Password Spraying | not_observed | No spray pattern (no 4625s, no user-list command lines). The observed authentication activity is reuse of one valid credential (pbeesly) via PsExec64 to NASHUA, which is lateral movement rather than spraying. |
| T1110.004 Credential Stuffing | not_observed | No failed authentications across accounts from any source; 4648 events map to the pbeesly/PSEXESVC pair, the pbeesly RDP session from 172.18.39.2, and OS accounts. |
| T1111 Multi-Factor Authentication Interception | not_observed | No MFA-interception artifacts in any dataset: no smart-card/MFA credential-provider tampering, no 4104 script referencing Credential/MFA (C135 zero hits), no MFA proxy or token-theft tooling. The credential-related hits … |
| T1187 Forced Authentication | malicious | On scranton.dmevals.local, DMEVALS\pbeesly PowerShell tooling (Invoke-Exfil in psversion.ps1) mapped \\192.168.0.4\webdav with explicit credentials via New-PSDrive; Sysmon shows powershell.exe and svchost.exe (WebClient)… |
| T1212 Exploitation for Credential Access | malicious | On scranton.dmevals.local, PowerShell.exe (PID 2976) opened lsass.exe with GrantedAccess 0x1F3FFF and 0x1FFFFF at 2020-05-02T03:05:16Z with an ntdll/KERNELBASE/UNKNOWN call trace, inside a confirmed pbeesly intrusion cha… |
| T1539 Steal Web Session Cookie | not_observed | No browser session-cookie theft found. The only cookie-named file creation is a LocalService package INetCookies file created by svchost.exe on scranton (03:21:05Z), and the only 'cookie' command lines are rundll32 davcl… |
| T1552 Unsecured Credentials | malicious | Credential-named collection and password-protected archiving on nashua. |
| T1552.001 Credentials In Files | malicious | Credential-named file harvesting on nashua and cleartext password on PsExec64 command lines. |
| T1552.002 Credentials in Registry | benign | All registry Password/Credential value sets came from svchost.exe, lsass.exe, services.exe and winlogon.exe performing normal identity/service/credential-guard plumbing. |
| T1552.003 Shell History | not_observed | No ConsoleHost_history.txt or other shell-history file access appeared in sysmon or security telemetry. |
| T1552.004 Private Keys | malicious | LocalMachine private keys exported to .pfx and exfiltrated via WebDAV. |
| T1552.006 Group Policy Preferences | not_observed | No Groups.xml, cpassword or sysvol credential access; only routine GptTmpl.inf/gpt.ini writes and a NETWORK SERVICE gpupdate.exe /target:computer. |
| T1555 Credentials from Password Stores | suspicious | Certificate-store private keys exported; no browser/vault access seen. |
| T1555.003 Credentials from Web Browsers | not_observed | All browser credential-store checks (C209-C214) returned zero hits; collection on scranton targeted documents, certificates, keystrokes and clipboard instead. |
| T1555.004 Windows Credential Manager | benign | LSASS handle access is dominated by Windows/Azure platform binaries (svchost, wininit, csrss, MsMpEng, CollectGuestLogs, WindowsAzureTelemetryService, AntimalwareConfig); no cmdkey/vaultcmd/DPAPI Credential Manager acces… |
| T1555.005 Password Managers | not_observed | Checks C221-C226 for KeePass/1Password/Bitwarden/LastPass/kdbx artefacts returned zero hits on all hosts. |
| T1556 Modify Authentication Process | suspicious | SYSTEM-context PowerShell.exe (scranton, 03:05:16, 0x1F3FFF/0x1FFFFF) and wsmprovhost.exe (nashua, 03:09:29, 0x1F3FFF) opened full-access handles to lsass.exe during an APT29-style hands-on-keyboard intrusion (Sysinterna… |
| T1556.001 Domain Controller Authentication | not_observed | Type-3 logons are machine-account/loopback traffic; 4648 events are pbeesly via PSEXESVC.exe and winlogon. No Skeleton Key/injected-credential indicators, no LSA/SAM registry writes. |
| T1556.002 Password Filter DLL | not_observed | No Notification Packages/PasswordFilter registry change, no password-filter DLL file creation in System32, no matching command lines or script blocks. |
| T1556.005 Reversible Encryption | not_observed | No 4739, no Set-ADUser/dsmod/Reversible command lines, no reversible-encryption references in PowerShell or windows.other. |
| T1556.006 Multi-Factor Authentication | not_observed | No 4739/5136 authentication-policy or directory changes; registry writes in the window are notification/tile and W32Time values. |
| T1556.007 Hybrid Identity | not_observed | No 5136 changes and no Connect-MsolService/Connect-AzureAD script blocks; dsregcmd.exe only loaded cryptdll.dll. |
| T1556.008 Network Provider DLL | not_observed | No NetworkProvider/credential-provider registry writes; LSA key appears only in read-only 4656 handle opens (AccessMask 0x1). |
| T1557 Adversary-in-the-Middle | not_observed | No adversary-in-the-middle positioning found. The malicious activity on scranton.dmevals.local (pbeesly) is credential theft (certificate .pfx export, screen capture, 7z exfiltration) plus PsExec lateral movement to nash… |
| T1557.001 Name Resolution Poisoning and SMB Relay | not_observed | SMB/Kerberos flows are normal member-to-DC authentication (10.0.1.4/10.0.1.6 -> 10.0.0.4 on 445/389/88, IPC$/sysvol mappings); DNS queries are ordinary with no LLMNR/NBT-NS poisoning, no DNS client registry tampering (46… |
| T1557.002 ARP Cache Poisoning | not_observed | Zeek L2 stacking shows stable one-to-one MAC/IP mappings (00:0d:3a:13:e3:69, 00:0d:3a:4d:42:f2, fc:bd:67:e1:a9:c1) with no MAC claiming multiple IPs and no gratuitous/duplicate mappings; no arp/netsh manipulation in Powe… |
| T1557.003 DHCP Spoofing | not_observable | No DHCP telemetry exists: no DHCP event codes in windows.other, no dhcp log type in Zeek, no ports 67/68 in Sysmon network connections, and no Dhcp references in PowerShell script blocks. |
| T1558 Steal or Forge Kerberos Tickets | suspicious | No ticket theft/forgery, but PowerShell (pbeesly, PID 2976) on scranton.dmevals.local opened lsass.exe with 0x1f3fff/0x1fffff at 03:05:16Z right after discovery/persistence/certificate-export commands — credential access… |
| T1558.001 Golden Ticket | benign | All 4769 tickets are AES256 (0x12) with success status; krbtgt SPN requests are ordinary TGS; 4672 logons only by machine account NEWYORK$; no golden-ticket tooling in PowerShell. |
| T1558.002 Silver Ticket | benign | Service tickets target normal machine accounts/SPNs with AES256 and success; zeek shows routine cifs/host/ldap TGS requests; no silver-ticket tooling. |
| T1558.003 Kerberoasting | benign | No RC4 (0x17/0x18) service-ticket requests and no Kerberoast/Rubeus script blocks; all TGS use aes256-cts-hmac-sha1-96. |
| T1558.004 AS-REP Roasting | benign | AS exchanges show KDC_ERR_PREAUTH_REQUIRED followed by successful AES256 AS-REP for pbeesly, i.e. pre-auth enforced; no AS-REP roasting tooling observed. |
| T1606 Forge Web Credentials | suspicious | Private-key material collected and exfiltrated; no forged token observed. |
| T1606.001 Web Cookies | not_observed | No forged or tampered web cookies. The single cookie-store file event is a benign svchost.exe creation of a LocalService INetCookies file on scranton; no PowerShell cookie/session handling and no cookie-bearing forged re… |
| T1606.002 SAML Tokens | suspicious | No SAML/ADFS/token artifacts were observed (zero hits for SAML, NotOnOrAfter, Assertion, saml/adfs/token URLs). However, the attacker stole certificate private keys and performed full-access LSASS reads (PowerShell 0x1f3… |
| T1621 Multi-Factor Authentication Request Generatio… | not_observed | No MFA/2FA/authenticator/push/duo/okta activity in any dataset. The 85 C355 hits in windows.other are WMI-Activity 5857/5858 provider-start and RSoP DeleteInstance records (ResultCode 0x80041002 / 0x0) by SYSTEM and NETW… |
| T1649 Steal or Forge Authentication Certificates | malicious | Export-PfxCertificate loop over cert:\LocalMachine then archive and exfil. |

## Coverage

Cells: number of hits of the planned checks, `n/a` (reason in report.json), or GAP.

| Technique | windows.other | windows.powershell | windows.security | windows.sysmon | zeek |
|---|---|---|---|---|---|
| T1003 OS Credential Dumping | 0 hits | 0 hits | 11437 hits | 39730 hits | n/a |
| T1003.001 LSASS Memory | 0 hits | 0 hits | 947 hits | 981 hits | n/a |
| T1003.002 Security Account Manager | 0 hits | 2 hits | 16 hits | 10 hits | n/a |
| T1003.003 NTDS | 0 hits | 0 hits | 0 hits | 0 hits | n/a |
| T1003.004 LSA Secrets | 0 hits | 0 hits | 0 hits | 327 hits | n/a |
| T1003.005 Cached Domain Credentials | 0 hits | 0 hits | 0 hits | 330 hits | n/a |
| T1003.006 DCSync | 90 hits | 0 hits | 21 hits | 0 hits | 9 hits |
| T1040 Network Sniffing | 5 hits | 0 hits | 460 hits | 0 hits | 0 hits |
| T1056 Input Capture | 90 hits | 0 hits | 21834 hits | 39609 hits | 0 hits |
| T1056.001 Keylogging | 5 hits | 0 hits | 10990 hits | 39779 hits | 0 hits |
| T1056.002 GUI Input Capture | 5 hits | 414 hits | 460 hits | 450 hits | 0 hits |
| T1056.003 Web Portal Capture | 5 hits | 0 hits | 5337 hits | 1649 hits | 0 hits |
| T1056.004 Credential API Hooking | 0 hits | 0 hits | 13 hits | 59963 hits | n/a |
| T1110 Brute Force | 2 hits | 0 hits | 0 hits | 30 hits | n/a |
| T1110.001 Password Guessing | 2 hits | 0 hits | 0 hits | 0 hits | n/a |
| T1110.002 Password Cracking | 1 hits | 0 hits | 10977 hits | 346 hits | n/a |
| T1110.003 Password Spraying | 7 hits | 0 hits | 15 hits | 1 hits | n/a |
| T1110.004 Credential Stuffing | 4 hits | 0 hits | 0 hits | 0 hits | n/a |
| T1111 Multi-Factor Authentication Interception | 2 hits | 0 hits | 312 hits | 39294 hits | n/a |
| T1187 Forced Authentication | 0 hits | 0 hits | 11140 hits | 1715 hits | 86 hits |
| T1212 Exploitation for Credential Access | 0 hits | 0 hits | 70 hits | 78566 hits | 14 hits |
| T1539 Steal Web Session Cookie | 0 hits | 0 hits | 465 hits | 40933 hits | 2 hits |
| T1552 Unsecured Credentials | 0 hits | 0 hits | 460 hits | 19208 hits | 12 hits |
| T1552.001 Credentials In Files | 0 hits | 0 hits | 312 hits | 2148 hits | 12 hits |
| T1552.002 Credentials in Registry | 3 hits | 1 hits | 1000 hits | 17606 hits | n/a |
| T1552.003 Shell History | 5 hits | 1 hits | 0 hits | 15 hits | n/a |
| T1552.004 Private Keys | 0 hits | 2 hits | 0 hits | 1 hits | n/a |
| T1552.006 Group Policy Preferences | 0 hits | 32 hits | 56 hits | 22 hits | n/a |
| T1555 Credentials from Password Stores | 2 hits | 5 hits | 19 hits | 1326 hits | n/a |
| T1555.003 Credentials from Web Browsers | 0 hits | 0 hits | 0 hits | 0 hits | n/a |
| T1555.004 Windows Credential Manager | 2 hits | 0 hits | 0 hits | 652 hits | n/a |
| T1555.005 Password Managers | 0 hits | 0 hits | 0 hits | 0 hits | n/a |
| T1556 Modify Authentication Process | 0 hits | 0 hits | 0 hits | 729 hits | n/a |
| T1556.001 Domain Controller Authentication | 0 hits | 0 hits | 545 hits | 359 hits | n/a |
| T1556.002 Password Filter DLL | 10 hits | 0 hits | 0 hits | 33 hits | n/a |
| T1556.005 Reversible Encryption | 0 hits | 0 hits | 0 hits | 0 hits | n/a |
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
| T1606 Forge Web Credentials | 90 hits | 0 hits | 312 hits | 326 hits | 475 hits |
| T1606.001 Web Cookies | 9 hits | 0 hits | 312 hits | 1 hits | 62 hits |
| T1606.002 SAML Tokens | 90 hits | 0 hits | 312 hits | 0 hits | 0 hits |
| T1621 Multi-Factor Authentication Request Generatio… | 85 hits | 0 hits | 0 hits | 0 hits | 0 hits |
| T1649 Steal or Forge Authentication Certificates | 90 hits | 0 hits | 50 hits | 1133 hits | 378 hits |

Cells: 265, gaps: 0.

## Queries

Every MCP tool call of this run (1352), in order (source: mcp_audit.jsonl written by the MCP server).

| Query | Phase | Tool | Arguments | Hits / rows | Cited by |
|---|---|---|---|---|---|
| q-c68cc0b92e | scope | list_data_sources | {} | None |  |
| q-04ca125cce | scope | get_registry | {} | None |  |
| q-a4657a0514 | scope | get_fields | {"dataset": "windows.other", "prefix": ""} | None |  |
| q-dec83807f5 | scope | get_fields | {"dataset": "windows.powershell", "prefix": ""} | None |  |
| q-1bebe3b172 | scope | get_fields | {"dataset": "windows.security", "prefix": ""} | None |  |
| q-ceb0292ca7 | scope | get_fields | {"dataset": "windows.sysmon", "prefix": ""} | None |  |
| q-b994f14f0a | scope | get_fields | {"dataset": "zeek", "prefix": ""} | None |  |
| q-a863d7a70b | check C001 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 447 |  |
| q-92c86541fb | check C002 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-8f147dd7f2 | check C003 | aggregate | {"dataset": "windows.security", "field": "win.ObjectType", "query": "event.code:(4656 OR 4663 OR 4670)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 10977 |  |
| q-da6420d8e8 | check C004 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 460 |  |
| q-8f9a7496a6 | check C005 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*lsass* OR powershell.script_block_text:*mimikatz* OR powershell.script_block_text:*sekurlsa* OR powershell.script_block_text:*DumpCreds*)", "time_from": null, "time_… | 0 |  |
| q-e42e393780 | check C006 | search | {"dataset": "windows.other", "query": "message:(*lsass* OR *mimikatz* OR *sekurlsa* OR *procdump*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "p… | 0 |  |
| q-45e10b6144 | check C007 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-d388a7ce2e | check C008 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 326 |  |
| q-d4738c667a | check C009 | aggregate | {"dataset": "windows.sysmon", "field": "win.SourceImage", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-16c3439f63 | check C010 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*lsass* OR file.path:*.dmp)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "pro… | 2 | F05 |
| q-5264df7bed | check C011 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*lsass* OR process.command_line:*comsvcs* OR process.command_line:*MiniDump*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dat… | 1 |  |
| q-922b036a8e | check C012 | search | {"dataset": "windows.sysmon", "query": "event.code:(13 OR 14) AND registry.path:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.comm… | 0 |  |
| q-14dcca2931 | check C013 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4673", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 934 |  |
| q-9ed608c716 | check C014 | search | {"dataset": "windows.security", "query": "event.code:4656 AND win.ObjectName:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command… | 13 |  |
| q-3774a2bea0 | check C015 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*lsass* OR powershell.script_block_text:*MiniDump* OR powershell.script_block_text:*Invoke-Mimikatz*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "… | 0 |  |
| q-df8256533f | check C016 | search | {"dataset": "windows.other", "query": "message:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 0 |  |
| q-3b99ebb47b | check C017 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*SAM* OR file.path:*SECURITY* OR file.path:*SYSTEM*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "… | 3 | F03 |
| q-4e0692c73d | check C018 | search | {"dataset": "windows.sysmon", "query": "event.code:(13 OR 14) AND (registry.path:*SAM* OR registry.path:*SECURITY*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "proces… | 7 | F04, F06 |
| q-b969f2f2db | check C019 | search | {"dataset": "windows.sysmon", "query": "event.code:2 AND (process.command_line:*SAM* OR process.command_line:*reg*save*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "p… | 0 |  |
| q-5c0e32d088 | check C020 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*reg save* OR process.command_line:*save*hklm* OR process.command_line:*SAM*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dat… | 0 |  |
| q-7bde125c0d | check C021 | aggregate | {"dataset": "windows.security", "field": "process.command_line", "query": "event.code:4688 AND (process.command_line:*reg* OR process.command_line:*save*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 6 |  |
| q-f6c6ab89a7 | check C022 | search | {"dataset": "windows.security", "query": "event.code:(4656 OR 4663) AND (win.ObjectName:*SAM* OR win.ObjectName:*SECURITY*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name",… | 10 |  |
| q-31d1adf663 | check C023 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*SAM* OR powershell.script_block_text:*reg save* OR powershell.script_block_text:*hive*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "… | 2 |  |
| q-c02e8a1778 | check C024 | search | {"dataset": "windows.other", "query": "message:(*SAM* OR *SECURITY hive* OR *reg save*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.comm… | 0 |  |
| q-34b7917a86 | check C025 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*ntds* OR file.path:*NTDS*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "pro… | 0 |  |
| q-a32b77d0a2 | check C026 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*ntds* OR process.command_line:*vssadmin* OR process.command_line:*ntdsutil* OR process.command_line:*diskshadow*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "ho… | 0 |  |
| q-7cdfbd170c | check C027 | search | {"dataset": "windows.sysmon", "query": "event.code:2 AND file.path:*ntds*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "so… | 0 |  |
| q-1171ecccd7 | check C028 | aggregate | {"dataset": "windows.security", "field": "process.command_line", "query": "event.code:4688 AND (process.command_line:*ntds* OR process.command_line:*vssadmin* OR process.command_line:*diskshadow*)", "time_from": null, "time_to": null, "size": 50, "sub_field": … | 0 |  |
| q-23f347f9d5 | check C029 | search | {"dataset": "windows.other", "query": "message:(*shadow* OR *VSS* OR *ntds*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 0 |  |
| q-104e7a3809 | check C030 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*ntds* OR powershell.script_block_text:*diskshadow* OR powershell.script_block_text:*vssadmin*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.n… | 0 |  |
| q-d5b415cb53 | check C031 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 326 |  |
| q-0e9bc6e770 | check C032 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*secrets* OR process.command_line:*lsadump* OR process.command_line:*reg save*HKLM\\\\SECURITY*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observe… | 0 |  |
| q-d2600d62e0 | check C033 | search | {"dataset": "windows.sysmon", "query": "event.code:7 AND win.ImageLoaded:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_lin… | 1 |  |
| q-d3907048fc | check C034 | search | {"dataset": "windows.security", "query": "event.code:(4656 OR 4663 OR 4670) AND win.ObjectName:*SECURITY*Policy*Secrets*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "p… | 0 |  |
| q-0dc9fd8c6d | check C035 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:(4656 OR 4663 OR 4670) AND win.ObjectName:*Secrets*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-a601fa6936 | check C036 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*Secrets* OR powershell.script_block_text:*lsadump* OR powershell.script_block_text:*LSA*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name",… | 0 |  |
| q-9dabfaa52e | check C037 | search | {"dataset": "windows.other", "query": "message:(*Secrets* OR *LSA* OR *lsadump*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_lin… | 0 |  |
| q-e115415449 | check C038 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 326 |  |
| q-432f11d415 | check C039 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*cache* OR process.command_line:*DCC2* OR process.command_line:*mscache* OR process.command_line:*cachedump*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.na… | 4 |  |
| q-da4013815c | check C040 | search | {"dataset": "windows.security", "query": "event.code:(4656 OR 4663 OR 4670) AND (win.ObjectName:*Cache* OR win.ObjectName:*SECURITY*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "u… | 0 |  |
| q-76fae2487b | check C041 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:(4656 OR 4663 OR 4670) AND win.ObjectName:*Cache*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-70b47ba49b | check C042 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*cache* OR powershell.script_block_text:*DCC2* OR powershell.script_block_text:*mscache*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", … | 0 |  |
| q-c75a09e7ae | check C043 | search | {"dataset": "windows.other", "query": "message:(*cached*credential* OR *mscache* OR *DCC2*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.… | 0 |  |
| q-6dc5c4915d | check C044 | count | {"dataset": "windows.security", "query": "event.code:4662", "time_from": null, "time_to": null} | 7 |  |
| q-a487a2b6b3 | check C045 | aggregate | {"dataset": "windows.security", "field": "win.AccessMask", "query": "event.code:4662", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 7 |  |
| q-bb6ce5127e | check C046 | aggregate | {"dataset": "windows.security", "field": "win.SubjectUserName", "query": "event.code:4662", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 7 |  |
| q-371c212516 | check C047 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*drsuapi* OR process.command_line:*lsadump* OR process.command_line:*dcsync*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dat… | 0 |  |
| q-351117b42b | check C048 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*DCSync* OR powershell.script_block_text:*lsadump* OR powershell.script_block_text:*drsuapi*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.nam… | 0 |  |
| q-490283a873 | check C049 | search | {"dataset": "windows.other", "query": "event.code:7045 OR event.code:5858 OR event.code:5857", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process… | 90 |  |
| q-b79ea19dad | check C050 | search | {"dataset": "zeek", "query": "event.action:dce_rpc AND (zeek.operation:*DRSUAPI* OR zeek.endpoint:*drsuapi* OR zeek.named_pipe:*drsuapi*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code"… | 9 |  |
| q-78b646319a | check C051 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 460 |  |
| q-cd143cc03a | check C052 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*pcap* OR process.command_line:*sniff* OR process.command_line:*promisc*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.da… | 0 |  |
| q-27b4d5bbf3 | check C053 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 | F08 |
| q-35e76bc963 | check C054 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.executable:*tcpdump* OR process.executable:*windump* OR process.executable:*wireshark* OR process.executable:*rawcap* OR process.executable:*npcap*)", "time_from": null, "time_to": null, "fields… | 0 |  |
| q-89f8c1db54 | check C055 | search | {"dataset": "windows.sysmon", "query": "event.code:6 AND (win.Image:*npcap* OR win.Image:*pcap* OR win.Image:*winpcap*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "pr… | 0 |  |
| q-cfc9033acb | check C056 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*pcap* OR powershell.script_block_text:*sniff* OR powershell.script_block_text:*promiscuous*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.nam… | 0 |  |
| q-7f57220426 | check C057 | search | {"dataset": "zeek", "query": "event.action:conn AND network.transport:icmp", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "s… | 0 |  |
| q-6ed162749a | check C058 | aggregate | {"dataset": "windows.security", "field": "win.ObjectType", "query": "event.code:4656 OR event.code:4663 OR event.code:4670", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 10977 |  |
| q-b1a6fd502e | check C059 | aggregate | {"dataset": "windows.security", "field": "win.AccessMask", "query": "event.code:4656 OR event.code:4663", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 10834 |  |
| q-d9d54526d4 | check C060 | search | {"dataset": "windows.security", "query": "event.code:4656 AND (win.ObjectName:*lsass* OR win.ObjectName:*credential* OR win.ObjectName:*SAM*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.c… | 23 | F11 |
| q-066c18fec0 | check C061 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-7eef0942c1 | check C062 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-b8955ba5a2 | check C063 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND (win.GrantedAccess:0x1010 OR win.GrantedAccess:0x1410 OR win.GrantedAccess:0x1438 OR win.GrantedAccess:0x143a)", "time_from": null, "time_to": null, "fields": ["@timestamp", … | 0 |  |
| q-7707474bbd | check C064 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*Get-Credential* OR powershell.script_block_text:*CredentialManager* OR powershell.script_block_text:*keylog*)", "time_from": null, "time_to": null, "fields": ["@time… | 0 |  |
| q-d354f5caea | check C065 | search | {"dataset": "windows.other", "query": "event.code:7045 OR event.code:5858 OR event.code:5857", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process… | 90 |  |
| q-5486308c5b | check C066 | search | {"dataset": "zeek", "query": "event.action:http AND http.request.method:POST", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 0 |  |
| q-01fd199cd1 | check C067 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-156431ac4e | check C068 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND (win.TargetImage:*lsass* OR win.TargetImage:*winlogon* OR win.TargetImage:*explorer*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event… | 470 |  |
| q-7a74ecf610 | check C069 | search | {"dataset": "windows.sysmon", "query": "event.code:13 AND (registry.path:*Keyboard* OR registry.path:*keylog* OR registry.path:*Scancode*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code… | 26 |  |
| q-62760a32f4 | check C070 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*keylog* OR process.command_line:*GetAsyncKeyState* OR process.command_line:*SetWindowsHookEx*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer… | 0 |  |
| q-fa1e9f53eb | check C071 | aggregate | {"dataset": "windows.security", "field": "win.ObjectType", "query": "event.code:4656 OR event.code:4663 OR event.code:4670", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 10977 |  |
| q-b919dad149 | check C072 | search | {"dataset": "windows.security", "query": "event.code:4656 AND (win.ObjectName:*lsass* OR win.ObjectName:*winlogon*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "proces… | 13 |  |
| q-03440c3a72 | check C073 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-4377780d04 | check C074 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*keylog* OR powershell.script_block_text:*GetAsyncKeyState* OR powershell.script_block_text:*SetWindowsHookEx*)", "time_from": null, "time_to": null, "fields": ["@tim… | 0 |  |
| q-2a1bc47435 | check C075 | search | {"dataset": "zeek", "query": "event.action:http AND http.request.method:POST", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 0 |  |
| q-15161ad3e9 | check C076 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*Credential* OR powershell.script_block_text:*Prompt* OR powershell.script_block_text:*Read-Host*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "hos… | 0 |  |
| q-2aad468088 | check C077 | aggregate | {"dataset": "windows.powershell", "field": "win.ScriptBlockId", "query": "event.code:4104", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 414 |  |
| q-0cdd4888d3 | check C078 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*Credential* OR process.command_line:*prompt* OR process.command_line:*consent*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.… | 3 |  |
| q-842ef8d8ff | check C079 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 447 |  |
| q-32b7252b0c | check C080 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*Credential* OR process.command_line:*prompt*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user… | 0 |  |
| q-445bcc7c40 | check C081 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 460 |  |
| q-fa135ea245 | check C082 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-6700bcab50 | check C083 | search | {"dataset": "zeek", "query": "event.action:http AND http.request.method:POST", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 0 |  |
| q-b839e56c08 | check C084 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*login* OR file.path:*portal* OR file.path:*wwwroot* OR file.path:*inetpub*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "eve… | 0 |  |
| q-69da4a23b7 | check C085 | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 1649 |  |
| q-f09a476522 | check C086 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*iis* OR process.command_line:*w3wp* OR process.command_line:*wwwroot*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset",… | 0 |  |
| q-a5fd3039cf | check C087 | search | {"dataset": "windows.security", "query": "event.code:4663 AND (win.ObjectName:*wwwroot* OR win.ObjectName:*inetpub* OR win.ObjectName:*login*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.… | 0 |  |
| q-b56fe87371 | check C088 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 5337 |  |
| q-b5d6268b2f | check C089 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*wwwroot* OR powershell.script_block_text:*login* OR powershell.script_block_text:*credential*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.n… | 0 |  |
| q-ba71189c75 | check C090 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-09bf170758 | check C091 | search | {"dataset": "zeek", "query": "event.action:http AND (url.original:*login* OR url.original:*portal*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "… | 0 |  |
| q-e6f00ed4ed | check C092 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-d33a0d20b7 | check C093 | aggregate | {"dataset": "windows.sysmon", "field": "win.SourceImage", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-d0d9d6fd17 | check C094 | aggregate | {"dataset": "windows.sysmon", "field": "win.ImageLoaded", "query": "event.code:7", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 20259 |  |
| q-66ac1236c4 | check C095 | search | {"dataset": "windows.sysmon", "query": "event.code:8", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinatio… | 95 |  |
| q-b9905c75a4 | check C096 | aggregate | {"dataset": "windows.security", "field": "win.CallerProcessName", "query": "event.code:4656 AND win.ObjectType:*Process*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 13 |  |
| q-05099e833e | check C097 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:*hook* OR powershell.script_block_text:*SetWindowsHookEx* OR powershell.script_block_text:*MiniDump*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.… | 0 |  |
| q-727bf08ced | check C098 | search | {"dataset": "windows.other", "query": "message:*hook* OR message:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "sou… | 0 |  |
| q-5edc75a3aa | check C099 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-52aaa9af58 | check C100 | aggregate | {"dataset": "windows.security", "field": "source.ip", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-5e5a4852ee | check C101 | timeline | {"dataset": "windows.security", "query": "event.code:4625", "interval": "1m", "time_from": null, "time_to": null} | 0 |  |
| q-bbad469eeb | check C102 | search | {"dataset": "windows.other", "query": "message:*logon* OR message:*password*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 2 | F16 |
| q-7466867387 | check C103 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:*Credential* OR powershell.script_block_text:*Password*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.n… | 0 |  |
| q-4e8926d8ad | check C104 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*net* OR process.command_line:*login*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 30 |  |
| q-917257eecb | check C105 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-70ba0fe315 | check C106 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 0 |  |
| q-2ad859a3cb | check C107 | timeline | {"dataset": "windows.security", "query": "event.code:4625", "interval": "1m", "time_from": null, "time_to": null} | 0 |  |
| q-b8b5d4df82 | check C108 | search | {"dataset": "windows.other", "query": "message:*4625* OR message:*failed*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "so… | 2 | F12 |
| q-c254c473d3 | check C109 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:*Password* OR powershell.script_block_text:*Credential*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.n… | 0 |  |
| q-cb7867cf08 | check C110 | aggregate | {"dataset": "windows.sysmon", "field": "process.command_line", "query": "event.code:1 AND process.command_line:*password*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-00fbf1f797 | check C111 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 OR event.code:4656 OR event.code:4670", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 10977 |  |
| q-c124a12003 | check C112 | aggregate | {"dataset": "windows.security", "field": "win.ProcessName", "query": "event.code:4663 AND (win.ObjectName:*SAM* OR win.ObjectName:*SECURITY*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-be97f2a600 | check C113 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*hash* OR process.command_line:*crack*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-3e2be4bdd1 | check C114 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND (win.TargetFilename:*.txt OR win.TargetFilename:*.pot)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 20 |  |
| q-089f7fa1f2 | check C115 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10 AND (win.TargetImage:*lsass* OR win.TargetImage:*SAM*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-14970947b0 | check C116 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:*hash* OR powershell.script_block_text:*ConvertTo-SecureString*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code",… | 0 |  |
| q-973cdf91ea | check C117 | search | {"dataset": "windows.other", "query": "message:*SAM* OR message:*hash*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "sourc… | 1 | F14 |
| q-fb5da766b5 | check C118 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-126abd1ae9 | check C119 | aggregate | {"dataset": "windows.security", "field": "source.ip", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-fb64f3923d | check C120 | search | {"dataset": "windows.security", "query": "event.code:4648", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 15 | F15, F16 |
| q-85e25e5488 | check C121 | timeline | {"dataset": "windows.security", "query": "event.code:4625", "interval": "1m", "time_from": null, "time_to": null} | 0 |  |
| q-551782b308 | check C122 | search | {"dataset": "windows.other", "query": "message:*logon* OR message:*account*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "… | 7 | F15 |
| q-290f97c28a | check C123 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:*Password* OR powershell.script_block_text:*Credential*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.n… | 0 |  |
| q-6a7dc9daa8 | check C124 | aggregate | {"dataset": "windows.sysmon", "field": "process.command_line", "query": "event.code:1 AND process.command_line:*user*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1 |  |
| q-df81b3f831 | check C125 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-f230347420 | check C126 | aggregate | {"dataset": "windows.security", "field": "source.ip", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-8e2a280306 | check C127 | timeline | {"dataset": "windows.security", "query": "event.code:4625", "interval": "1m", "time_from": null, "time_to": null} | 0 |  |
| q-5925578263 | check C128 | search | {"dataset": "windows.other", "query": "message:*logon* OR message:*credential*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line"… | 4 |  |
| q-6ddcfb4762 | check C129 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:*Credential* OR powershell.script_block_text:*Password*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.n… | 0 |  |
| q-b281419d70 | check C130 | aggregate | {"dataset": "windows.sysmon", "field": "process.command_line", "query": "event.code:1 AND process.command_line:*password*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-a73d9f52d5 | check C131 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 297 |  |
| q-4c742553e3 | check C132 | search | {"dataset": "windows.security", "query": "event.code:4648", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 15 | F17 |
| q-7912e6a102 | check C133 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-b53a31a080 | check C134 | search | {"dataset": "windows.sysmon", "query": "event.code:13 AND registry.path:*Credential*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command… | 11 | F17 |
| q-b1baf99326 | check C135 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND powershell.script_block_text:*Credential*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executab… | 0 |  |
| q-eeb612a8cd | check C136 | search | {"dataset": "windows.other", "query": "message:*Credential*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "des… | 2 |  |
| q-8c07d88828 | check C137 | aggregate | {"dataset": "windows.security", "field": "win.ObjectType", "query": "event.code:4656 OR event.code:4663 OR event.code:4670", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 10977 |  |
| q-77e4bd4f3c | check C138 | search | {"dataset": "windows.security", "query": "event.code:5140 OR event.code:5145", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 163 |  |
| q-e088f10928 | check C139 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1649 |  |
| q-59d102f8cd | check C140 | search | {"dataset": "windows.sysmon", "query": "event.code:3 AND (destination.port:445 OR destination.port:139)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable… | 66 |  |
| q-ce8d226699 | check C141 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*445* OR powershell.script_block_text:*WebDAV* OR powershell.script_block_text:*NTLM*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "ob… | 0 |  |
| q-07d8ce144a | check C142 | search | {"dataset": "windows.other", "query": "message:*445* OR message:*WebDAV*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "sou… | 0 |  |
| q-249ab8a8a5 | check C143 | aggregate | {"dataset": "zeek", "field": "destination.port", "query": "event.action:conn AND (destination.port:445 OR destination.port:139)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 50 |  |
| q-8153331a6e | check C144 | search | {"dataset": "zeek", "query": "event.action:http AND (http.request.method:PROPFIND OR http.request.method:MOVE OR http.request.method:OPTIONS)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.c… | 36 |  |
| q-80c7177357 | check C145 | aggregate | {"dataset": "windows.security", "field": "event.code", "query": "event.code:4768 OR event.code:4769 OR event.code:4770", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 42 |  |
| q-3804207965 | check C146 | search | {"dataset": "windows.security", "query": "event.code:4769", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 28 | F22 |
| q-7f6a762ba0 | check C147 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-83aa13224c | check C148 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.GrantedAccess:*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line",… | 39283 | F22 |
| q-fd7503c14b | check C149 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*Invoke-* OR powershell.script_block_text:*Exploit*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "ev… | 0 |  |
| q-1307cdd14d | check C150 | search | {"dataset": "windows.other", "query": "message:*exploit*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destin… | 0 |  |
| q-bc03c7adf1 | check C151 | search | {"dataset": "zeek", "query": "event.action:notice OR event.action:weird", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "sour… | 14 |  |
| q-360b6aa6e3 | check C152 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 460 |  |
| q-94679a4010 | check C153 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*cookie* OR process.command_line:*Cookie*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.nam… | 5 |  |
| q-2433f65fdd | check C154 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1649 |  |
| q-9cc88ec15a | check C155 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (win.TargetFilename:*Cookies* OR win.TargetFilename:*cookie*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "pr… | 1 | F23 |
| q-91f26a8f6f | check C156 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-6d1f8e9474 | check C157 | search | {"dataset": "windows.sysmon", "query": "event.code:2 AND (win.TargetFilename:*Cookies* OR win.TargetFilename:*cookie*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "pro… | 0 |  |
| q-bdee508514 | check C158 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*cookie* OR powershell.script_block_text:*Cookie*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "even… | 0 |  |
| q-0bdb5aca25 | check C159 | search | {"dataset": "windows.other", "query": "message:*cookie*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destina… | 0 |  |
| q-32a29b4305 | check C160 | search | {"dataset": "zeek", "query": "event.action:http AND http.request.method:GET", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "… | 2 |  |
| q-9ccd5f729d | check C161 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 460 |  |
| q-b36b5835be | check C162 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*password* OR process.command_line:*credential* OR process.command_line:*unattend*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name",… | 0 |  |
| q-98b5ea1816 | check C163 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1649 |  |
| q-8fc8afe0fb | check C164 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (win.TargetFilename:*unattend* OR win.TargetFilename:*password* OR win.TargetFilename:*credential*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.da… | 1 |  |
| q-9fe223727c | check C165 | aggregate | {"dataset": "windows.sysmon", "field": "registry.path", "query": "event.code:13 OR event.code:14", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 17541 |  |
| q-450c1e829f | check C166 | search | {"dataset": "windows.sysmon", "query": "event.code:13 AND (registry.path:*Password* OR registry.path:*Credential*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process… | 17 | F27 |
| q-f7d95a087a | check C167 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*password* OR powershell.script_block_text:*credential*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset",… | 0 |  |
| q-34c4674509 | check C168 | search | {"dataset": "windows.other", "query": "message:*password*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 0 |  |
| q-68f40f70f8 | check C169 | search | {"dataset": "zeek", "query": "event.action:smb_files", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinatio… | 12 |  |
| q-999d77ac36 | check C170 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 297 |  |
| q-49d4412096 | check C171 | search | {"dataset": "windows.security", "query": "event.code:4648", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 15 |  |
| q-3f75cae062 | check C172 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 447 |  |
| q-5bb07f4968 | check C173 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*password* OR process.command_line:*credential* OR process.command_line:*config*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event… | 8 |  |
| q-5032afa60b | check C174 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1649 |  |
| q-2189b4cd23 | check C175 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (win.TargetFilename:*.config OR win.TargetFilename:*.xml OR win.TargetFilename:*.txt)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event… | 44 |  |
| q-bca2517d0e | check C176 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*Get-Content* OR powershell.script_block_text:*Select-String*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dat… | 0 |  |
| q-bf5b263019 | check C177 | search | {"dataset": "windows.other", "query": "message:*password*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 0 |  |
| q-8155101cc7 | check C178 | search | {"dataset": "zeek", "query": "event.action:smb_files", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinatio… | 12 |  |
| q-ab1371a261 | check C179 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"13\" AND (TO_LOWER(registry.path) LIKE \"*\\\\sam\\\\*\" OR TO_LOWER(registry.path) LIKE \"*\\\\security\\\\*\" OR TO_LOWER(registry.path) LIKE \"*password*\" OR TO_LOWER… | ERROR |  |
| q-fcb80d1917 | check C179 (repaired) | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"13\" AND (TO_LOWER(registry.path) LIKE \"*\\\\\\\\sam\\\\\\\\*\" OR TO_LOWER(registry.path) LIKE \"*\\\\\\\\security\\\\\\\\*\" OR TO_LOWER(registry.path) LIKE \"*passwor… | 60 |  |
| q-32d39b7d2b | check C180 | aggregate | {"dataset": "windows.sysmon", "field": "registry.path", "query": "event.code:13", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 17541 |  |
| q-6395b48db5 | check C181 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*reg query*\" OR TO_LOWER(process.command_line) LIKE \"*reg save*\" OR TO_LOWER(process.command_line) LIKE \"*\\\\sam*\" OR… | ERROR |  |
| q-6e1024e167 | check C181 (repaired) | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*reg query*\" OR TO_LOWER(process.command_line) LIKE \"*reg save*\" OR TO_LOWER(process.command_line) LIKE \"*sam*\" OR TO_… | 5 |  |
| q-876df3b0db | check C182 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4663\",\"4656\",\"4670\",\"4658\") AND (TO_LOWER(win.ObjectName) LIKE \"*\\\\sam*\" OR TO_LOWER(win.ObjectName) LIKE \"*\\\\security*\" OR TO_LOWER(win.ObjectName) LIK… | ERROR |  |
| q-5b1ce9ba1a | check C182 (repaired) | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4663\",\"4656\",\"4670\",\"4658\") AND (TO_LOWER(win.ObjectName) LIKE \"*sam*\" OR TO_LOWER(win.ObjectName) LIKE \"*security*\" OR TO_LOWER(win.ObjectName) LIKE \"*lsa… | 500 |  |
| q-6f8f36fe5e | check C183 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code IN (\"4103\",\"4104\") AND (TO_LOWER(COALESCE(powershell.script_block_text, win.ScriptBlockText, \"\")) LIKE \"*reg query*\" OR TO_LOWER(COALESCE(powershell.script_block_t… | ERROR |  |
| q-e5f4af78de | check C183 (repaired) | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code IN (\"4103\",\"4104\") AND (TO_LOWER(COALESCE(win.ScriptBlockText, \"\")) LIKE \"*reg query*\" OR TO_LOWER(COALESCE(win.ScriptBlockText, \"\")) LIKE \"*reg save*\" OR TO_L… | 1 |  |
| q-e5f80a2123 | check C184 | esql | {"query": "FROM logs-windows.other-default METADATA _id, _index \| WHERE TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*\\\\sam*\" OR TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*\\\\security*\" OR TO_LOWER(COALESCE(message, win.Message, \"\"… | ERROR |  |
| q-8b9e335f7c | check C184 (repaired) | esql | {"query": "FROM logs-windows.other-default METADATA _id, _index \| WHERE TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*\\\\\\\\sam*\" OR TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*\\\\\\\\security*\" OR TO_LOWER(COALESCE(message, win.Messa… | 3 |  |
| q-1898a1b8e6 | check C185 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code IN (\"4103\",\"4104\") AND (TO_LOWER(COALESCE(powershell.script_block_text, win.ScriptBlockText, \"\")) LIKE \"*history*\" OR TO_LOWER(COALESCE(powershell.script_block_tex… | ERROR |  |
| q-bee5341651 | check C185 (repaired) | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code IN (\"4103\",\"4104\") AND (TO_LOWER(COALESCE(win.ScriptBlockText, \"\")) LIKE \"*history*\" OR TO_LOWER(COALESCE(win.ScriptBlockText, \"\")) LIKE \"*consolehost_history*\… | 1 |  |
| q-f0b6e2f1d3 | check C186 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*consolehost_history*\" OR TO_LOWER(process.command_line) LIKE \"*psreadline*\" OR TO_LOWER(process.command_line) LIKE \"*h… | 0 |  |
| q-795f4a39e7 | check C187 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*consolehost_history*\" OR TO_LOWER(file.path) LIKE \"*psreadline*\" OR TO_LOWER(file.path) LIKE \"*\\\\history*\" OR TO_LOWER(file.p… | ERROR |  |
| q-8eb039700d | check C187 (repaired) | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*consolehost_history*\" OR TO_LOWER(file.path) LIKE \"*psreadline*\" OR TO_LOWER(file.path) LIKE \"*history*\" OR TO_LOWER(file.path)… | 15 |  |
| q-7168274209 | check C188 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4663\",\"4656\",\"4658\") AND (TO_LOWER(win.ObjectName) LIKE \"*consolehost_history*\" OR TO_LOWER(win.ObjectName) LIKE \"*psreadline*\" OR TO_LOWER(win.ObjectName) LI… | 0 |  |
| q-02d273b767 | check C189 | esql | {"query": "FROM logs-windows.other-default METADATA _id, _index \| WHERE TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*history*\" OR TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*psreadline*\" \| KEEP @timestamp, host.name, event.code, messag… | 5 |  |
| q-7edaaa04b2 | check C190 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*.key\" OR TO_LOWER(file.path) LIKE \"*.pgp\" OR TO_LOWER(file.path) LIKE \"*.gpg\" OR TO_LOWER(file.path) LIKE \"*.ppk\" OR TO_LOWER… | 1 |  |
| q-c961fcb7fb | check C191 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*.pem*\" OR TO_LOWER(process.command_line) LIKE \"*.pfx*\" OR TO_LOWER(process.command_line) LIKE \"*.p12*\" OR TO_LOWER(pr… | 0 |  |
| q-d6fde792da | check C192 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"5145\" AND (TO_LOWER(win.RelativeTargetName) LIKE \"*.key\" OR TO_LOWER(win.RelativeTargetName) LIKE \"*.pem\" OR TO_LOWER(win.RelativeTargetName) LIKE \"*.pfx\" OR TO_… | 0 |  |
| q-c2d545d050 | check C193 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4663\",\"4656\",\"4658\") AND (TO_LOWER(win.ObjectName) LIKE \"*.key\" OR TO_LOWER(win.ObjectName) LIKE \"*.pem\" OR TO_LOWER(win.ObjectName) LIKE \"*.pfx\" OR TO_LOWE… | 0 |  |
| q-15f9420d64 | check C194 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code IN (\"4103\",\"4104\") AND (TO_LOWER(COALESCE(powershell.script_block_text, win.ScriptBlockText, \"\")) LIKE \"*.pem*\" OR TO_LOWER(COALESCE(powershell.script_block_text, … | ERROR |  |
| q-eaa09f1daf | check C194 (repaired) | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code IN (\"4103\",\"4104\") AND (TO_LOWER(COALESCE(win.ScriptBlockText, \"\")) LIKE \"*.pem*\" OR TO_LOWER(COALESCE(win.ScriptBlockText, \"\")) LIKE \"*.pfx*\" OR TO_LOWER(COAL… | 2 |  |
| q-9f51c52728 | check C195 | esql | {"query": "FROM logs-windows.other-default METADATA _id, _index \| WHERE TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*.pem*\" OR TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*.pfx*\" OR TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*… | 0 |  |
| q-525ac99ce7 | check C196 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code IN (\"4103\",\"4104\") AND (TO_LOWER(COALESCE(powershell.script_block_text, win.ScriptBlockText, \"\")) LIKE \"*groups.xml*\" OR TO_LOWER(COALESCE(powershell.script_block_… | ERROR |  |
| q-f2be55596b | check C196 (repaired) | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code IN (\"4103\",\"4104\") AND (TO_LOWER(COALESCE(win.ScriptBlockText, \"\")) LIKE \"*groups.xml*\" OR TO_LOWER(COALESCE(win.ScriptBlockText, \"\")) LIKE \"*sysvol*\" OR TO_LO… | 32 |  |
| q-74cf3b24e4 | check C197 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*sysvol*\" OR TO_LOWER(process.command_line) LIKE \"*groups.xml*\" OR TO_LOWER(process.command_line) LIKE \"*cpassword*\" O… | 0 |  |
| q-0e484f7dfc | check C198 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*groups.xml*\" OR TO_LOWER(file.path) LIKE \"*sysvol*\" OR TO_LOWER(file.path) LIKE \"*gpprefdecrypt*\" OR TO_LOWER(file.path) LIKE \… | 22 |  |
| q-56372fe0e1 | check C199 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"5145\" AND (TO_LOWER(win.RelativeTargetName) LIKE \"*groups.xml*\" OR TO_LOWER(win.ShareName) LIKE \"*sysvol*\" OR TO_LOWER(win.ShareName) LIKE \"*netlogon*\") \| KEEP … | 56 |  |
| q-6de41248ef | check C200 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4663\",\"4656\",\"4658\") AND (TO_LOWER(win.ObjectName) LIKE \"*groups.xml*\" OR TO_LOWER(win.ObjectName) LIKE \"*sysvol*\" OR TO_LOWER(win.ObjectName) LIKE \"*gpp*\")… | 0 |  |
| q-6b3fb99266 | check C201 | esql | {"query": "FROM logs-windows.other-default METADATA _id, _index \| WHERE TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*sysvol*\" OR TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*groups.xml*\" OR TO_LOWER(COALESCE(message, win.Message, \"\")) … | 0 |  |
| q-6973d5e2b7 | check C202 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND (TO_LOWER(win.TargetImage) LIKE \"*lsass.exe\" OR TO_LOWER(win.SourceImage) LIKE \"*lsass.exe\") \| KEEP @timestamp, host.name, user.name, win.SourceImage, win.T… | 500 |  |
| q-52e39a04da | check C203 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass.exe", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-0c668ddf2b | check C204 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*sekurlsa*\" OR TO_LOWER(process.command_line) LIKE \"*lsadump*\" OR TO_LOWER(process.command_line) LIKE \"*mimikatz*\" OR … | 0 |  |
| q-7e16a52e7c | check C205 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4663\",\"4656\",\"4670\",\"4658\") AND (TO_LOWER(win.ObjectName) LIKE \"*\\\\protect\\\\*\" OR TO_LOWER(win.ObjectName) LIKE \"*credential*\" OR TO_LOWER(win.ObjectNam… | ERROR |  |
| q-813d8b560c | check C205 (repaired) | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4663\",\"4656\",\"4670\",\"4658\") AND (TO_LOWER(win.ObjectName) LIKE \"*protect*\" OR TO_LOWER(win.ObjectName) LIKE \"*credential*\" OR TO_LOWER(win.ObjectName) LIKE … | 19 | F31 |
| q-ed838228d3 | check C206 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4688\" AND (TO_LOWER(process.command_line) LIKE \"*sekurlsa*\" OR TO_LOWER(process.command_line) LIKE \"*lsadump*\" OR TO_LOWER(process.command_line) LIKE \"*mimikatz*\… | 0 |  |
| q-a545cf6f56 | check C207 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code IN (\"4103\",\"4104\") AND (TO_LOWER(COALESCE(powershell.script_block_text, win.ScriptBlockText, \"\")) LIKE \"*sekurlsa*\" OR TO_LOWER(COALESCE(powershell.script_block_te… | ERROR |  |
| q-e6f6805127 | check C207 (repaired) | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code IN (\"4103\",\"4104\") AND (TO_LOWER(COALESCE(win.ScriptBlockText, \"\")) LIKE \"*sekurlsa*\" OR TO_LOWER(COALESCE(win.ScriptBlockText, \"\")) LIKE \"*lsadump*\" OR TO_LOW… | 5 |  |
| q-2aa36630bb | check C208 | esql | {"query": "FROM logs-windows.other-default METADATA _id, _index \| WHERE TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*lsass*\" OR TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*credential*\" OR TO_LOWER(COALESCE(message, win.Message, \"\")) L… | 2 |  |
| q-b047249812 | check C209 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*login data*\" OR TO_LOWER(process.command_line) LIKE \"*\\\\google\\\\chrome\\\\user data*\" OR TO_LOWER(process.command_l… | ERROR |  |
| q-b3340ef3ae | check C209 (repaired) | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*login data*\" OR TO_LOWER(process.command_line) LIKE \"*google*chrome*user data*\" OR TO_LOWER(process.command_line) LIKE … | 0 |  |
| q-777bee63ee | check C210 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*login data*\" OR TO_LOWER(file.path) LIKE \"*logins.json*\" OR TO_LOWER(file.path) LIKE \"*key3.db*\" OR TO_LOWER(file.path) LIKE \"… | ERROR |  |
| q-998dfb0631 | check C210 (repaired) | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*login data*\" OR TO_LOWER(file.path) LIKE \"*logins.json*\" OR TO_LOWER(file.path) LIKE \"*key3.db*\" OR TO_LOWER(file.path) LIKE \"… | 0 |  |
| q-642e683c4b | check C211 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND (TO_LOWER(win.TargetImage) LIKE \"*chrome.exe\" OR TO_LOWER(win.TargetImage) LIKE \"*firefox.exe\" OR TO_LOWER(win.TargetImage) LIKE \"*msedge.exe\" OR TO_LOWER(… | 0 |  |
| q-df25a3140f | check C212 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4663\",\"4656\",\"4658\") AND (TO_LOWER(win.ObjectName) LIKE \"*login data*\" OR TO_LOWER(win.ObjectName) LIKE \"*logins.json*\" OR TO_LOWER(win.ObjectName) LIKE \"*ke… | ERROR |  |
| q-281efbc8fa | check C212 (repaired) | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4663\",\"4656\",\"4658\") AND (TO_LOWER(win.ObjectName) LIKE \"*login data*\" OR TO_LOWER(win.ObjectName) LIKE \"*logins.json*\" OR TO_LOWER(win.ObjectName) LIKE \"*ke… | 0 |  |
| q-9a092c088f | check C213 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code IN (\"4103\",\"4104\") AND (TO_LOWER(COALESCE(powershell.script_block_text, win.ScriptBlockText, \"\")) LIKE \"*login data*\" OR TO_LOWER(COALESCE(powershell.script_block_… | ERROR |  |
| q-75e8857b9c | check C213 (repaired) | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code IN (\"4103\",\"4104\") AND (TO_LOWER(COALESCE(win.ScriptBlockText, \"\")) LIKE \"*login data*\" OR TO_LOWER(COALESCE(win.ScriptBlockText, \"\")) LIKE \"*logins.json*\" OR … | 0 |  |
| q-c68e2776ba | check C214 | esql | {"query": "FROM logs-windows.other-default METADATA _id, _index \| WHERE TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*login data*\" OR TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*logins.json*\" OR TO_LOWER(COALESCE(message, win.Message, \"… | 0 |  |
| q-1936f144dd | check C215 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 326 |  |
| q-ddc81cfaec | check C216 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-54f0f4db07 | check C217 | search | {"dataset": "windows.sysmon", "query": "event.code:15 AND file.path:*Credentials*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 0 |  |
| q-239177a8b2 | check C218 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*vault* OR process.command_line:*Credential* OR process.command_line:*cmdkey*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "eve… | 0 |  |
| q-14fb016763 | check C219 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*Credential* OR powershell.script_block_text:*vault* OR powershell.script_block_text:*cmdkey*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.na… | 0 |  |
| q-df5f4b5775 | check C220 | search | {"dataset": "windows.other", "query": "message:*Credential* OR message:*vault*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line"… | 2 | F31 |
| q-e97e927851 | check C221 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.executable:*keepass* OR process.executable:*1password* OR process.executable:*bitwarden* OR process.executable:*lastpass* OR process.executable:*dashlane*)", "time_from": null, "time_to": null, … | 0 |  |
| q-abbb2afcb9 | check C222 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*keepass* OR file.path:*1password* OR file.path:*bitwarden* OR file.path:*lastpass*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.datase… | 0 |  |
| q-3cdcac0e40 | check C223 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND (win.TargetImage:*keepass* OR win.TargetImage:*1password* OR win.TargetImage:*bitwarden*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "e… | 0 |  |
| q-5e67d0b10d | check C224 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*keepass* OR process.command_line:*1password* OR process.command_line:*bitwarden* OR process.command_line:*kdbx*)", "time_from": null, "time_to": null, "fields": ["@timestamp",… | 0 |  |
| q-5360302b64 | check C225 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*keepass* OR powershell.script_block_text:*kdbx* OR powershell.script_block_text:*1password* OR powershell.script_block_text:*bitwarden*)", "time_from": null, "time_t… | 0 |  |
| q-212652ef7e | check C226 | search | {"dataset": "windows.other", "query": "message:*keepass* OR message:*1password* OR message:*bitwarden* OR message:*kdbx*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "p… | 0 |  |
| q-65569858a3 | check C227 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 326 |  |
| q-760c45230b | check C228 | aggregate | {"dataset": "windows.sysmon", "field": "win.SourceImage", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-f2a17d5dd8 | check C229 | search | {"dataset": "windows.sysmon", "query": "event.code:7 AND (win.ImageLoaded:*lsass* OR win.ImageLoaded:*cryptdll* OR win.ImageLoaded:*sam* OR win.ImageLoaded:*msv1_0*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "… | 77 | F39 |
| q-370329837b | check C230 | search | {"dataset": "windows.security", "query": "event.code:4657 AND (win.ObjectName:*lsass* OR win.ObjectName:*cryptdll* OR win.ObjectName:*msv1_0* OR win.ObjectName:*sam*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", … | 0 |  |
| q-bb28fac055 | check C231 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*lsass* OR process.command_line:*cryptdll* OR process.command_line:*msv1_0*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event… | 0 |  |
| q-4b40b9f86f | check C232 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*lsass* OR powershell.script_block_text:*cryptdll* OR powershell.script_block_text:*msv1_0* OR powershell.script_block_text:*SecurityPackages*)", "time_from": null, "… | 0 |  |
| q-ed69cda737 | check C233 | search | {"dataset": "windows.other", "query": "message:*lsass* OR message:*cryptdll* OR message:*msv1_0*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "pro… | 0 |  |
| q-742e730435 | check C234 | search | {"dataset": "windows.security", "query": "event.code:4624 AND win.LogonType:3", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line",… | 218 | F35 |
| q-548554c447 | check C235 | search | {"dataset": "windows.security", "query": "event.code:4648", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 15 | F35, F37 |
| q-7171e02b20 | check C236 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4624 OR event.code:4648", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 312 |  |
| q-894ef58e13 | check C237 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 326 |  |
| q-7b73350058 | check C238 | search | {"dataset": "windows.sysmon", "query": "event.code:7 AND (win.ImageLoaded:*lsass* OR win.ImageLoaded:*cryptdll*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.e… | 33 |  |
| q-f0cb64b0fc | check C239 | search | {"dataset": "windows.other", "query": "message:*lsass* OR message:*cryptdll*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 0 |  |
| q-98eddca4fe | check C240 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*lsass* OR powershell.script_block_text:*cryptdll* OR powershell.script_block_text:*Skeleton* OR powershell.script_block_text:*DCShadow*)", "time_from": null, "time_t… | 0 |  |
| q-9bc15014ff | check C241 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*System32* AND (file.path:*.dll))", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable"… | 0 |  |
| q-4f7bb48f46 | check C242 | search | {"dataset": "windows.sysmon", "query": "event.code:7 AND (win.ImageLoaded:*lsass* OR win.ImageLoaded:*cryptdll*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.e… | 33 |  |
| q-6c74a56365 | check C243 | search | {"dataset": "windows.security", "query": "event.code:4657 AND (win.ObjectName:*Notification\\ Packages* OR win.ObjectName:*Password* OR win.ObjectName:*lsass*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.… | 0 |  |
| q-74937a2d62 | check C244 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*Notification* OR process.command_line:*PasswordFilter*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.co… | 0 |  |
| q-1914ee33c2 | check C245 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*Notification* OR powershell.script_block_text:*PasswordFilter* OR powershell.script_block_text:*lsass*)", "time_from": null, "time_to": null, "fields": ["@timestamp"… | 0 |  |
| q-cc2e55da1f | check C246 | search | {"dataset": "windows.other", "query": "message:*Notification* OR message:*PasswordFilter* OR message:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.execu… | 10 |  |
| q-93ad82a1a9 | check C247 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*AllowReversiblePasswordEncryption* OR powershell.script_block_text:*ReversibleEncryption* OR powershell.script_block_text:*Set-ADUser*)", "time_from": null, "time_to… | 0 |  |
| q-d83ed35c89 | check C248 | search | {"dataset": "windows.powershell", "query": "event.code:4103 AND (message:*AllowReversiblePasswordEncryption* OR message:*ReversibleEncryption*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event… | 0 |  |
| q-4eec6c0780 | check C249 | search | {"dataset": "windows.security", "query": "event.code:4739", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 0 |  |
| q-ee2b0a8cb7 | check C250 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*Reversible* OR process.command_line:*Set-ADUser* OR process.command_line:*dsmod*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", … | 0 |  |
| q-d099341df5 | check C251 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*Reversible* OR process.command_line:*Set-ADUser* OR process.command_line:*dsmod*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "even… | 0 |  |
| q-e8666de2a6 | check C252 | search | {"dataset": "windows.other", "query": "message:*Reversible* OR message:*AllowReversiblePasswordEncryption*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executa… | 0 |  |
| q-dcd2c3aeeb | check C253 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(powershell.script_block_text) LIKE \"*set-aduser*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*set-adauthenticationpolicy*\" OR TO_LOWER(powershell.script_block_text)… | ERROR |  |
| q-671e61bdd7 | check C253 (repaired) | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*set-aduser*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*set-adauthenticationpolicy*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*strongauthenticati… | 1 |  |
| q-7ef76c4b6f | check C254 | count | {"dataset": "windows.security", "query": "event.code:4739", "time_from": null, "time_to": null} | 0 |  |
| q-5232977204 | check C255 | aggregate | {"dataset": "windows.security", "field": "win.ObjectType", "query": "event.code:5136 OR event.code:4739", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-119bcd0d0c | check C256 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*set-aduser*\" OR TO_LOWER(process.command_line) LIKE \"*set-adauthenticationpolicy*\" OR TO_LOWER(process.command_line) LI… | 0 |  |
| q-7d8f6449b7 | check C257 | search | {"dataset": "windows.other", "query": "event.code:4739 OR event.code:5136 OR event.code:4738", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process… | 0 |  |
| q-a5e4032d9b | check C258 | aggregate | {"dataset": "windows.security", "field": "win.LogonProcessName", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 297 |  |
| q-1898bccd8f | check C259 | aggregate | {"dataset": "windows.security", "field": "win.AuthenticationPackageName", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 297 |  |
| q-ec237f6138 | check C260 | count | {"dataset": "windows.security", "query": "event.code:5136", "time_from": null, "time_to": null} | 0 |  |
| q-e5688d4485 | check C261 | aggregate | {"dataset": "windows.sysmon", "field": "win.ImageLoaded", "query": "event.code:7", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 20259 |  |
| q-a0c97d068a | check C262 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(powershell.script_block_text) LIKE \"*connect-msolservice*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*connect-azuread*\" OR TO_LOWER(powershell.script_block_text) L… | ERROR |  |
| q-3f551f2913 | check C262 (repaired) | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*connect-msolservice*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*connect-azuread*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*new-azuread*\" OR TO… | 0 |  |
| q-12a6942efb | check C263 | search | {"dataset": "windows.other", "query": "event.code:5136 OR event.code:4739 OR event.code:4738", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process… | 0 |  |
| q-863674aee1 | check C264 | count | {"dataset": "windows.security", "query": "event.code:4657", "time_from": null, "time_to": null} | 36 |  |
| q-526629cba3 | check C265 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4657\" AND (TO_LOWER(win.ObjectName) LIKE \"*networkprovider*\" OR TO_LOWER(win.ObjectName) LIKE \"*credential*\" OR TO_LOWER(win.ObjectName) LIKE \"*winlogon*\") \| KE… | 0 |  |
| q-39a7e5f13c | check C266 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*networkprovider*\" OR TO_LOWER(file.path) LIKE \"*system32*credential*\" OR TO_LOWER(file.path) LIKE \"*winlogon*\") \| KEEP @timest… | 1 |  |
| q-12b79b8aac | check C267 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 39283 |  |
| q-e25fe067b6 | check C268 | aggregate | {"dataset": "windows.sysmon", "field": "win.ImageLoaded", "query": "event.code:7", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 20259 |  |
| q-7e3e7a8104 | check C269 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(powershell.script_block_text) LIKE \"*networkprovider*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*new-itemproperty*\" OR TO_LOWER(powershell.script_block_text) LIKE… | ERROR |  |
| q-b38d008603 | check C269 (repaired) | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*networkprovider*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*new-itemproperty*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*reg add*\" \| KEEP @tim… | 0 |  |
| q-ad4ae386c0 | check C270 | search | {"dataset": "windows.other", "query": "event.code:4657 OR event.code:11 OR event.code:7", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.comm… | 4 |  |
| q-7a86123115 | check C271 | aggregate | {"dataset": "windows.security", "field": "win.ObjectType", "query": "event.code:4663 OR event.code:4670 OR event.code:4656", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 10977 |  |
| q-5672314ac3 | check C272 | aggregate | {"dataset": "windows.security", "field": "win.ProcessName", "query": "event.code:4663 OR event.code:4670 OR event.code:4656", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 10977 |  |
| q-9df683fcb3 | check C273 | aggregate | {"dataset": "windows.sysmon", "field": "win.DestinationHostname", "query": "event.code:3", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 1229 |  |
| q-1fee1235a1 | check C274 | aggregate | {"dataset": "windows.sysmon", "field": "win.QueryName", "query": "event.code:22", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 81 |  |
| q-6aa1242da1 | check C275 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(powershell.script_block_text) LIKE \"*responder*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*mitm*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*arpspoof*\" OR… | ERROR |  |
| q-f1dcb4db95 | check C275 (repaired) | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*responder*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*mitm*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*arpspoof*\" OR TO_LOWER(win.ScriptBlockTe… | 0 |  |
| q-e7f2dc0eaa | check C276 | search | {"dataset": "windows.other", "query": "event.code:4663 OR event.code:4670 OR event.code:4656 OR event.code:3 OR event.code:22", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name… | 2 | F44 |
| q-16124ac1d4 | check C277 | aggregate | {"dataset": "zeek", "field": "zeek.conn_state", "query": "event.action:conn", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 613 |  |
| q-db633d0b8a | check C278 | aggregate | {"dataset": "zeek", "field": "zeek.service", "query": "event.action:conn", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 613 |  |
| q-001557f90a | check C279 | count | {"dataset": "windows.security", "query": "event.code:4697", "time_from": null, "time_to": null} | 23 |  |
| q-fdf62113e3 | check C280 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4657\" AND TO_LOWER(win.ObjectName) LIKE \"*dnsclient*\" \| KEEP @timestamp, host.name, user.name, win.ObjectName, win.NewValue, _id, _index"} | 0 |  |
| q-d1d8426aa2 | check C281 | aggregate | {"dataset": "windows.sysmon", "field": "win.DestinationHostname", "query": "event.code:3", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 1229 |  |
| q-3dd67bed55 | check C282 | aggregate | {"dataset": "windows.sysmon", "field": "win.QueryName", "query": "event.code:22", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 81 |  |
| q-f7112c105f | check C283 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(powershell.script_block_text) LIKE \"*llmnr*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*nbt-ns*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*responder*\" OR … | ERROR |  |
| q-2d74d239d2 | check C283 (repaired) | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*llmnr*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*nbt-ns*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*responder*\" OR TO_LOWER(win.ScriptBlockTex… | 0 |  |
| q-bcaae5a0b4 | check C284 | search | {"dataset": "windows.other", "query": "event.code:4697 OR event.code:4657 OR event.code:3 OR event.code:22", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executa… | 2 |  |
| q-cff79eb336 | check C285 | aggregate | {"dataset": "zeek", "field": "zeek.id_resp_h", "query": "event.action:conn AND zeek.service:smb", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-09b166384a | check C286 | aggregate | {"dataset": "zeek", "field": "zeek.query", "query": "event.action:dns", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 53 |  |
| q-5711de4c9d | check C287 | aggregate | {"dataset": "windows.sysmon", "field": "win.DestinationHostname", "query": "event.code:3", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 1229 |  |
| q-0635a2d3bc | check C288 | aggregate | {"dataset": "windows.sysmon", "field": "win.QueryName", "query": "event.code:22", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 81 |  |
| q-25241450c2 | check C289 | aggregate | {"dataset": "windows.security", "field": "win.ProcessName", "query": "event.code:4663 OR event.code:4670 OR event.code:4656", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 10977 |  |
| q-9d776906a8 | check C290 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(powershell.script_block_text) LIKE \"*arp*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*netsh interface*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*get-netne… | ERROR |  |
| q-35db61186b | check C290 (repaired) | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*arp*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*netsh interface*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*get-netneighbor*\" OR TO_LOWER(win.S… | 0 |  |
| q-53709e7e20 | check C291 | search | {"dataset": "windows.other", "query": "event.code:3 OR event.code:22 OR event.code:4663 OR event.code:4670", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executa… | 2 |  |
| q-23fa6113ab | check C292 | aggregate | {"dataset": "zeek", "field": "zeek.orig_l2_addr", "query": "event.action:conn", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 613 |  |
| q-2b9f702d2c | check C293 | aggregate | {"dataset": "zeek", "field": "zeek.resp_l2_addr", "query": "event.action:conn", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 613 |  |
| q-daec16291d | check C294 | search | {"dataset": "windows.other", "query": "event.code:(1341 OR 1342 OR 1020 OR 1063)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_lin… | 0 |  |
| q-e03669bd83 | check C295 | aggregate | {"dataset": "windows.other", "field": "event.code", "query": "*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 216 |  |
| q-2c0f5aaea5 | check C296 | search | {"dataset": "windows.security", "query": "event.code:5156 AND win.Direction:Inbound", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_… | 0 |  |
| q-344e3e4245 | check C297 | aggregate | {"dataset": "windows.sysmon", "field": "destination.port", "query": "event.code:3", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1229 |  |
| q-993e4a3830 | check C298 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:(*Dhcp* OR *dhcp*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.… | 0 |  |
| q-cc903d6406 | check C299 | aggregate | {"dataset": "zeek", "field": "event.action", "query": "*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 2140 |  |
| q-9fa29d6779 | check C300 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4672", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 212 |  |
| q-c43a2818ac | check C301 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 297 |  |
| q-d0ccc65cb3 | check C302 | search | {"dataset": "windows.security", "query": "event.code:4634", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 236 |  |
| q-647295ea07 | check C303 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-f3918182f0 | check C304 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-6442e2d1c0 | check C305 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:(*kerberos* OR *Kerberos* OR *ticket* OR *Ticket*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name",… | 0 |  |
| q-004c276782 | check C306 | search | {"dataset": "windows.other", "query": "event.code:(7045 OR 7040)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip",… | 9 |  |
| q-33d00d2598 | check C307 | aggregate | {"dataset": "zeek", "field": "zeek.request_type", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 35 |  |
| q-8a2b85e7ad | check C308 | search | {"dataset": "windows.security", "query": "event.code:4769", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 28 |  |
| q-584f075065 | check C309 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4672", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 212 |  |
| q-4648440042 | check C310 | aggregate | {"dataset": "windows.security", "field": "win.TicketEncryptionType", "query": "event.code:4769", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 28 |  |
| q-710d819500 | check C311 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-14e4508955 | check C312 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:(*golden* OR *Golden* OR *krbtgt* OR *KRBTGT*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "pr… | 0 |  |
| q-94b91910a0 | check C313 | aggregate | {"dataset": "windows.other", "field": "event.code", "query": "*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 216 |  |
| q-f52fc1f43a | check C314 | aggregate | {"dataset": "zeek", "field": "zeek.request_type", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 35 |  |
| q-7686697e9c | check C315 | search | {"dataset": "windows.security", "query": "event.code:4769", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 28 |  |
| q-9fe61b2abe | check C316 | aggregate | {"dataset": "windows.security", "field": "win.ServiceName", "query": "event.code:4769", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 28 |  |
| q-b9acb98223 | check C317 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4672", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 212 |  |
| q-00c9ecc0d3 | check C318 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-03bcf225ae | check C319 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:(*silver* OR *Silver* OR *service ticket* OR *SPN*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name"… | 0 |  |
| q-9cbf798055 | check C320 | search | {"dataset": "windows.other", "query": "event.code:(7045 OR 7040)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip",… | 9 |  |
| q-dc1e57d30e | check C321 | aggregate | {"dataset": "zeek", "field": "zeek.request_type", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 35 |  |
| q-e73e0807fa | check C322 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4769", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 28 |  |
| q-fdf2927463 | check C323 | aggregate | {"dataset": "windows.security", "field": "win.TicketEncryptionType", "query": "event.code:4769", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 28 |  |
| q-1fb85c19af | check C324 | search | {"dataset": "windows.security", "query": "event.code:4648", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 15 |  |
| q-689a059600 | check C325 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 297 |  |
| q-67e8de3149 | check C326 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-9bb4a15808 | check C327 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:(*Kerberoast* OR *kerberoast* OR *Invoke-Kerberoast* OR *Rubeus*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code… | 0 |  |
| q-2b8b8a9309 | check C328 | aggregate | {"dataset": "windows.other", "field": "event.code", "query": "*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 216 |  |
| q-c7b07109b9 | check C329 | aggregate | {"dataset": "zeek", "field": "zeek.request_type", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 35 |  |
| q-de54086e89 | check C330 | search | {"dataset": "windows.security", "query": "event.code:4768", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 14 |  |
| q-d2d6d99ace | check C331 | aggregate | {"dataset": "windows.security", "field": "win.PreAuthType", "query": "event.code:4768", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 14 |  |
| q-90cc9a9d7a | check C332 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4768", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 14 |  |
| q-c6a5ef9c61 | check C333 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 447 |  |
| q-c8a4c1d1fe | check C334 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:(*AS-REP* OR *asrep* OR *GetNPUsers* OR *DontRequirePreAuth*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "… | 0 |  |
| q-9f68d20005 | check C335 | aggregate | {"dataset": "windows.other", "field": "event.code", "query": "*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 216 |  |
| q-eada4f3d8d | check C336 | aggregate | {"dataset": "zeek", "field": "zeek.request_type", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 35 |  |
| q-a4d1749e8d | check C337 | aggregate | {"dataset": "windows.security", "field": "win.LogonProcessName", "query": "event.code:4624 OR event.code:4648", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 312 |  |
| q-0f36a365b5 | check C338 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-c4e9d36489 | check C339 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*cookie* OR powershell.script_block_text:*token* OR powershell.script_block_text:*SAML*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "… | 0 |  |
| q-5e6cac26c6 | check C340 | search | {"dataset": "windows.other", "query": "event.code:7045 OR event.code:5857 OR event.code:5858", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process… | 90 |  |
| q-f7eb9e0752 | check C341 | aggregate | {"dataset": "zeek", "field": "event.action", "query": "event.action:http OR event.action:ssl OR event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 475 |  |
| q-64ad11d9b6 | check C342 | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11 AND (file.path:*cookie* OR file.path:*Cookies*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1 |  |
| q-f1f19e6313 | check C343 | aggregate | {"dataset": "windows.security", "field": "win.LogonProcessName", "query": "event.code:4624 OR event.code:4648", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 312 |  |
| q-2741f91ef4 | check C344 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*cookie* OR powershell.script_block_text:*Set-Cookie* OR powershell.script_block_text:*session*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.… | 0 |  |
| q-715dd1ab7b | check C345 | search | {"dataset": "windows.other", "query": "event.code:11 OR event.code:16", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source… | 9 |  |
| q-73f0513e68 | check C346 | search | {"dataset": "zeek", "query": "event.action:http AND http.request.method:*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "so… | 62 |  |
| q-d733f9ec27 | check C347 | aggregate | {"dataset": "windows.security", "field": "win.LogonProcessName", "query": "event.code:4624 OR event.code:4648", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 312 |  |
| q-5a82d70fa9 | check C348 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*SAML* OR powershell.script_block_text:*NotOnOrAfter* OR powershell.script_block_text:*Assertion*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "hos… | 0 |  |
| q-dc58ad66a8 | check C349 | search | {"dataset": "windows.other", "query": "event.code:7045 OR event.code:5857 OR event.code:5858", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process… | 90 |  |
| q-82e59b57cb | check C350 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*saml* OR process.command_line:*token* OR process.command_line:*cert*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-4fa576c71b | check C351 | search | {"dataset": "zeek", "query": "event.action:http AND (url.original:*saml* OR url.original:*adfs* OR url.original:*token*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "p… | 0 |  |
| q-4565ddb3e0 | check C352 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-61507c6af5 | check C353 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-35589d3c09 | check C354 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*MFA* OR powershell.script_block_text:*2FA* OR powershell.script_block_text:*Authenticator*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name… | 0 |  |
| q-42b94729d8 | check C355 | search | {"dataset": "windows.other", "query": "event.code:4625 OR event.code:5857 OR event.code:5858", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process… | 85 | F53 |
| q-1aec2df308 | check C356 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*login* OR process.command_line:*auth* OR process.command_line:*mfa*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-3627c0b94e | check C357 | search | {"dataset": "zeek", "query": "event.action:http AND (url.original:*login* OR url.original:*auth* OR url.original:*mfa*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "pr… | 0 |  |
| q-68f46eed9f | check C358 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4657", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 36 |  |
| q-a186fc6932 | check C359 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4768", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 14 |  |
| q-ef7528118e | check C360 | aggregate | {"dataset": "windows.sysmon", "field": "registry.path", "query": "event.code:13 AND (registry.path:*Certificate* OR registry.path:*Crypto* OR registry.path:*Keys*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1133 |  |
| q-b088e36e57 | check C361 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*Certificate* OR powershell.script_block_text:*Export-PfxCertificate* OR powershell.script_block_text:*New-SelfSignedCertificate*)", "time_from": null, "time_to": nul… | 0 |  |
| q-d89734f6a7 | check C362 | search | {"dataset": "windows.other", "query": "event.code:7045 OR event.code:5857 OR event.code:5858", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process… | 90 |  |
| q-75da85b2be | check C363 | aggregate | {"dataset": "zeek", "field": "zeek.certificate_subject", "query": "event.action:x509", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 378 |  |
| q-373202e423 | triage T1003 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND NOT win.GrantedAccess:(0x1000 OR 0x1400)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "process.executable", "win.SourceImage", "win.GrantedAcce… | 9 | F01 |
| q-8ec4d03a83 | triage T1003 step 1 | search | {"dataset": "windows.security", "query": "event.code:(4656 OR 4663 OR 4670) AND win.ObjectType:(SAM_DOMAIN OR SAM_SERVER OR SAM_ALIAS)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "user.name", "process.executable", … | 21 | F03 |
| q-e8e4921e2b | triage T1003 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None | F01 |
| q-39b173a9ab | triage T1003 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-5a393cb728 | triage T1003 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-54f8adfb49 | triage T1003 step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code IN (4104, 4103, 800) AND (@timestamp >= \"2020-05-02T03:04:00.000Z\" AND @timestamp <= \"2020-05-02T03:11:00.000Z\") \| WHERE TO_LOWER(COALESCE(win.ScriptBlockText, \"\"))… | ERROR |  |
| q-9e3c29f0df | triage T1003 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 1 AND (TO_LOWER(process.command_line) LIKE \"*lsass*\" OR TO_LOWER(process.command_line) LIKE \"*minidump*\" OR TO_LOWER(process.command_line) LIKE \"*comsvcs*\" OR TO_LOWE… | ERROR |  |
| q-8175bd1e6c | triage T1003 step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code IN (\"4104\", \"4103\", \"800\") AND @timestamp >= \"2020-05-02T03:03:00.000Z\" AND @timestamp <= \"2020-05-02T03:12:00.000Z\" \| WHERE TO_LOWER(COALESCE(win.ScriptBlockTe… | 1 | F02 |
| q-d727513426 | triage T1003 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*lsass*\" OR TO_LOWER(process.command_line) LIKE \"*minidump*\" OR TO_LOWER(process.command_line) LIKE \"*comsvcs*\" OR TO_… | 1 | F07 |
| q-3eab162185 | triage T1003 step 5 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None | F02 |
| q-a5b1cbc905 | triage T1003 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND process.executable LIKE \"*PowerShell*\" \| KEEP @timestamp, host.name, user.name, process.executable, process.command_line, process.parent.executable, process.pi… | 12 |  |
| q-0910761de9 | triage T1003 step 6 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7ViMbT"} | None | F01 |
| q-2134dd860f | triage T1003 step 6 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND host.name == \"nashua.dmevals.local\" \| KEEP @timestamp, host.name, user.name, win.ScriptBlockId, win.Path, win.ScriptBlockText, _id, _index \| LIMIT 20"} | 11 | F02 |
| q-8370c17773 | triage T1003 step 7 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND host.name == \"scranton.dmevals.local\" AND @timestamp >= \"2020-05-02T02:58:00.000Z\" AND @timestamp <= \"2020-05-02T03:08:00.000Z\" \| KEEP @timestamp, u… | 25 | F02 |
| q-12d93ed668 | triage T1003 step 8 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAWIxa2"} | None | F01 |
| q-e6ebe48eb8 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None |  |
| q-e0066fe33d | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None |  |
| q-70f4413cf6 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None |  |
| q-cb89023cb7 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-cada122f32 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7ViMbT"} | None |  |
| q-e9141d8b87 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAWIxa2"} | None |  |
| q-7b44d14bd0 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None |  |
| q-60b2240e62 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None |  |
| q-c47e65d33e | triage T1003 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAWIxZm"} | None |  |
| q-8ade0445c4 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQDFlH"} | None |  |
| q-471c998d8b | triage T1003 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMANA6l9"} | None |  |
| q-485a90bb7c | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL81V4Qj"} | None |  |
| q-8d57f219ac | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL81V4Qj"} | None |  |
| q-183203dc87 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL81V4Qj"} | None |  |
| q-ffc11f33ed | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL17AAad"} | None |  |
| q-dcb13c39d0 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2in-Mz"} | None |  |
| q-c1d5242f73 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2in-Mz"} | None |  |
| q-330b5362a3 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL62AkVX"} | None |  |
| q-dc17683481 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL62AkVX"} | None |  |
| q-6aa8594a53 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2hm-XC"} | None |  |
| q-30766d65fe | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2ORrtq"} | None |  |
| q-4b21de6e18 | triage T1040 step 1 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.executable:*NetworkWatcher* OR process.executable:*python.exe OR process.executable:*PsExec64.exe OR process.executable:*sdelete64.exe OR process.executable:*logman.exe OR process.executabl… | 32 | F08 |
| q-0b81065ede | triage T1040 step 1 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 447 |  |
| q-75d44b87e1 | triage T1040 step 2 | search | {"dataset": "windows.sysmon", "query": "process.executable:*python.exe OR process.parent.executable:*python.exe OR win.SourceImage:*python.exe OR win.TargetImage:*python.exe OR win.Image:*python.exe", "time_from": null, "time_to": null, "fields": ["@timestamp"… | 697 |  |
| q-fd4ad9b0f4 | triage T1040 step 2 | search | {"dataset": "windows.sysmon", "query": "process.executable:*logman.exe OR process.executable:*NetworkWatcherAgent.exe OR win.SourceImage:*logman.exe OR win.SourceImage:*NetworkWatcherAgent.exe", "time_from": null, "time_to": null, "fields": ["@timestamp", "hos… | 322 | F08 |
| q-91b4922ba8 | triage T1040 step 3 | search | {"dataset": "windows.sysmon", "query": "event.code:3 AND (process.executable:*python.exe OR process.executable:*logman.exe OR process.executable:*PsExec64.exe OR process.executable:*PSEXESVC.exe)", "time_from": null, "time_to": null, "fields": ["@timestamp", "… | 353 | F08 |
| q-2a3edfb3be | triage T1040 step 3 | search | {"dataset": "windows.sysmon", "query": "process.executable:*logman.exe OR process.parent.executable:*logman.exe", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "process.executable", "process.command_line", "process.par… | 257 | F08 |
| q-561a88d570 | triage T1040 step 4 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*python* OR win.ScriptBlockText:*NASHUA* OR win.ScriptBlockText:*PsExec* OR win.ScriptBlockText:*8443* OR win.ScriptBlockText:*192.168.0.4*)", "time_from": null, "time_to": nu… | 7 |  |
| q-6614477890 | triage T1040 step 4 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND win.TargetFilename:*python*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "process.executable", "process.command_line", "win.TargetFilename", "win.Image", "wi… | 3 | F08 |
| q-0df82486bc | triage T1040 step 5 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAOBExi"} | None | F08 |
| q-2e8fdc4377 | triage T1040 step 5 | search | {"dataset": "windows.sysmon", "query": "process.executable:*python.exe AND (event.code:11 OR event.code:22 OR event.code:13 OR event.code:12)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "process.executable", "proce… | 29 | F08 |
| q-3e19676e3b | triage T1040 step 6 | aggregate | {"dataset": "zeek", "field": "destination.ip", "query": "event.action:conn", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 613 |  |
| q-7df3ac13e4 | triage T1040 step 6 | search | {"dataset": "windows.sysmon", "query": "event.code:3 AND win.DestinationIp:192.168.0.4", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "process.executable", "win.DestinationIp", "win.DestinationPort", "win.SourceIp", "… | 356 |  |
| q-c7d67d5e21 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2x7o-G"} | None |  |
| q-d1109acbfd | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2PS3oM"} | None |  |
| q-d83e664897 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2PS3oM"} | None |  |
| q-1c287a4e30 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL-w3iOg"} | None |  |
| q-e95eac09ca | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2jo9KZ"} | None |  |
| q-71e84c4933 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2bgzcO"} | None |  |
| q-e1c9914731 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2bgjeM"} | None |  |
| q-1997194181 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9Uyl9o"} | None |  |
| q-a05f511a55 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAOBExi"} | None |  |
| q-f1c479e8b4 | triage T1056 step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 10 AND win.TargetImage LIKE \"*lsass*\" AND win.GrantedAccess IN (\"0x1fffff\",\"0x101001\",\"0x1f3fff\",\"0x1000000\",\"0x3000\",\"0x1400\") \| KEEP @timestamp, host.name,… | ERROR |  |
| q-4846b1d5ee | triage T1056 step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 10 AND process.executable LIKE \"*python*\" \| STATS c = COUNT(*) BY process.executable, win.TargetImage, win.GrantedAccess, host.name \| SORT c DESC"} | ERROR |  |
| q-a5b6261104 | triage T1056 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND win.TargetImage LIKE \"*lsass*\" AND win.GrantedAccess IN (\"0x1fffff\",\"0x101001\",\"0x1f3fff\",\"0x1000000\",\"0x3000\",\"0x1400\") \| KEEP @timestamp, host.n… | 33 | F10, F11 |
| q-a6a4966366 | triage T1056 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND process.executable LIKE \"*python*\" \| STATS c = COUNT(*) BY process.executable, win.TargetImage, win.GrantedAccess, host.name \| SORT c DESC"} | 3 |  |
| q-6c55db3682 | triage T1056 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None | F10 |
| q-2f8ece4fc3 | triage T1056 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None | F10 |
| q-9679637c95 | triage T1056 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (process.executable LIKE \"*python*\" OR process.command_line LIKE \"*python*\" OR process.command_line LIKE \"*lsass*\" OR process.command_line LIKE \"*MiniDump*… | 10 | F09 |
| q-cb34a3afb1 | triage T1056 step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (win.ScriptBlockText LIKE \"*lsass*\" OR win.ScriptBlockText LIKE \"*MiniDump*\" OR win.ScriptBlockText LIKE \"*procdump*\" OR win.ScriptBlockText LIKE \"*… | 6 | F09 |
| q-7e105d8b54 | triage T1056 step 5 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1lL"} | None | F09 |
| q-a7bfecf533 | triage T1056 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND process.executable LIKE \"*python*\" \| KEEP @timestamp, host.name, process.executable, win.TargetImage, win.GrantedAccess, win.CallTrace, _id, _index"} | 3 | F09 |
| q-bfb4843222 | triage T1056 step 6 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND host.name == \"nashua.dmevals.local\" AND (file.path LIKE \"*Temp*\" OR file.path LIKE \"*python*\" OR file.path LIKE \"*.py*\") \| KEEP @timestamp, host.name, u… | 36 | F09 |
| q-f4ca1b7c43 | triage T1056 step 6 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND win.TargetImage LIKE \"*lsass*\" \| STATS c = COUNT(*) BY process.executable, win.GrantedAccess, host.name \| SORT c DESC"} | 18 |  |
| q-978e3be250 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1lL"} | None |  |
| q-830bc6dd1d | triage T1056 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1lL"} | None |  |
| q-de6b45ce73 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2ioON3"} | None |  |
| q-bfb96b5ceb | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2in-NH"} | None |  |
| q-c0f1ee6301 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2bgTcg"} | None |  |
| q-30a7662e3b | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2bgTcg"} | None |  |
| q-9caaad708a | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2bgTei"} | None |  |
| q-0e2de7e840 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2bgjf5"} | None |  |
| q-95d38c6398 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None |  |
| q-dcb1e2e210 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None |  |
| q-436abd67b9 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-f432fccc18 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-0d49c08172 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-2ee4bb4c93 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2ORrtr"} | None |  |
| q-27b438ec06 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JLx0p9yU"} | None |  |
| q-1f80f66f24 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL81V4Qj"} | None |  |
| q-ab8aaa44b0 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL8-b3Gh"} | None |  |
| q-c33840de7c | triage T1110 step 1 | count | {"dataset": "windows.security", "query": "event.code:4625 OR event.code:4771 OR event.code:4776 OR event.code:4740", "time_from": null, "time_to": null} | 1 |  |
| q-852cabcdd1 | triage T1110 step 1 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 30, "sub_field": "win.GrantedAccess"} | 326 |  |
| q-9fb3764540 | triage T1110 step 1 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 30, "sub_field": "win.LogonType"} | 297 |  |
| q-239dc60d65 | triage T1110 step 2 | search | {"dataset": "windows.security", "query": "event.code:4625 OR event.code:4771 OR event.code:4776 OR event.code:4740", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "win.TargetUserName", "source.ip", "message"], "size": … | 1 | F12, F13, F16 |
| q-7d6c9afa2f | triage T1110 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND (win.GrantedAccess:0x1fffff OR win.GrantedAccess:0x1f3fff)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "process.executable", "process.command_… | 5 | F14 |
| q-4b83b04371 | triage T1110 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None | F14 |
| q-3450500c2e | triage T1110 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None | F14 |
| q-aee0452174 | triage T1110 step 3 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*MiniDump* OR win.ScriptBlockText:*Dump* OR win.ScriptBlockText:*Get-Process*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "h… | 3 |  |
| q-bed38cc3ce | triage T1110 step 4 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND process.pid:2976", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "process.executable", "process.command_line", "process.parent.executable", "process.parent.command_line", "use… | 1 |  |
| q-d872a58da6 | triage T1110 step 4 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND user.name:pbeesly", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "user.name", "win.ScriptBlockText"], "size": 40, "sort": "asc"} | 157 |  |
| q-a0bc4028a6 | triage T1110 step 5 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7ViMbT"} | None | F13, F15 |
| q-7e4e0a6bf8 | triage T1110 step 5 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*mimikatz* OR process.command_line:*sekurlsa* OR process.command_line:*procdump* OR process.command_line:*lsass* OR process.command_line:*Invoke-Mimikatz* OR process.command_line:*c… | 1 |  |
| q-660617828c | triage T1110 step 6 | search | {"dataset": "windows.sysmon", "query": "host.name:scranton.dmevals.local AND (event.code:11 OR event.code:22 OR event.code:3) AND (win.TargetFilename:*monkey* OR win.TargetFilename:*.zip OR win.TargetFilename:*.png OR win.TargetFilename:*.dmp OR win.TargetFile… | 4 |  |
| q-9475ca61de | triage T1110 step 6 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*psexec* OR process.command_line:*net use* OR process.command_line:*net.exe* OR process.command_line:*wmic*)", "time_from": null, "time_to": null, "si… | 447 |  |
| q-07b6d90597 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL8xSa_z"} | None |  |
| q-4bd0224d53 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL8xSa_z"} | None |  |
| q-7b1a0f0be4 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL-w3yMf"} | None |  |
| q-ab03b4aaf3 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL8xSa_z"} | None |  |
| q-3f3120c74b | triage T1110 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7ViMbT"} | None |  |
| q-536a7b7920 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-83c43045af | triage T1110 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None |  |
| q-dee3240732 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-69f8d97041 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL-w3yM8"} | None |  |
| q-edfaa33b5a | triage T1110 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7ViMbT"} | None |  |
| q-3c0a6dfbef | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9OrXFR"} | None |  |
| q-0fa0120c30 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL-w3iOg"} | None |  |
| q-7ec584485e | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL8vSVsk"} | None |  |
| q-6b9340f5a6 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL-w3yNa"} | None |  |
| q-e572b59775 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL88ahmW"} | None |  |
| q-0e72bd6df0 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL8xSa_z"} | None |  |
| q-43e37629cf | triage T1111 step 1 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4648", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 15 |  |
| q-c049c61777 | triage T1111 step 1 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND win.TargetImage:*lsass.exe", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 326 |  |
| q-ef6437c589 | triage T1111 step 1 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4624 AND win.LogonType:10", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 2 |  |
| q-54eedce477 | triage T1111 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass.exe AND (process.executable:*powershell.exe OR process.executable:*wsmprovhost.exe OR process.executable:*wininit.exe OR process.executable:*csrss.exe OR process.executable:*servi… | 7 |  |
| q-f0aff72e4c | triage T1111 step 2 | search | {"dataset": "windows.security", "query": "event.code:4624 AND win.LogonType:10", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "win.TargetUserName", "win.LogonType", "win.IpAddress", "win.Workstation", "win.AuthenticationPackageName… | 2 | F17 |
| q-bdcb63c894 | triage T1111 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None | F17 |
| q-db863d96e8 | triage T1111 step 3 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*LogonSession* OR win.ScriptBlockText:*Token* OR win.ScriptBlockText:*Invoke-Mimikatz* OR win.ScriptBlockText:*sekurlsa* OR win.ScriptBlockText:… | 3 |  |
| q-f9d5d2e6ff | triage T1111 step 4 | search | {"dataset": "windows.powershell", "query": "host.name:nashua.dmevals.local AND event.code:4104", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "user.name", "process.command_line", "win.Path", "win.ScriptBlockText"], "s… | 11 | F17 |
| q-1f5cb8c92b | triage T1111 step 4 | search | {"dataset": "windows.security", "query": "host.name:nashua.dmevals.local AND (event.code:4688 OR event.code:7045 OR event.code:4624) AND (user.name:pbeesly OR win.TargetUserName:pbeesly OR process.executable:*PSEXESVC* OR process.command_line:*pbeesly*)", "tim… | 53 | F17 |
| q-ce7e7bd490 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-132e7818b3 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-4eb1eacca2 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-9cd4c0a47c | triage T1111 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAMA2AH"} | None |  |
| q-c46a703df9 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9VzyYa"} | None |  |
| q-6118597e52 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9OrnEx"} | None |  |
| q-869be81ce7 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9OrXFR"} | None |  |
| q-8fd4e32c82 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMANA6l9"} | None |  |
| q-e926810c35 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2ORrtv"} | None |  |
| q-b97740dec6 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2ORrtv"} | None |  |
| q-fcfeb6b446 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL8vSVsl"} | None |  |
| q-1c022781f1 | triage T1187 step 1 | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA5C"} | None | F18 |
| q-57f692007d | triage T1187 step 1 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"http\" AND (http.request.method == \"PROPFIND\" OR http.request.method == \"MOVE\" OR http.request.method == \"OPTIONS\") \| KEEP @timestamp, source.ip, destination.ip, destinati… | 36 | F18 |
| q-efeca6a34f | triage T1187 step 2 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"conn\" AND (destination.port == 445 OR destination.port == 139) \| KEEP @timestamp, source.ip, source.port, destination.ip, destination.port, network.bytes, zeek.conn_state, zeek… | 50 | F18 |
| q-5a45fe6e8d | triage T1187 step 2 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"notice\" OR event.action == \"smb_files\" OR event.action == \"smb_mapping\" \| KEEP @timestamp, event.action, source.ip, destination.ip, zeek.name, zeek.note, zeek.msg, zeek.pat… | 25 | F19 |
| q-c4fff60d59 | triage T1187 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 3 AND (destination.ip LIKE \"192.168.0.*\" OR destination.port == 445 OR destination.port == 139 OR destination.port == 80) \| KEEP @timestamp, host.name, user.name, proces… | ERROR |  |
| q-ea4097cad1 | triage T1187 step 3 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == 5145 OR event.code == 5140 \| KEEP @timestamp, host.name, event.code, user.name, source.ip, win.ShareName, win.ShareLocalPath, win.RelativeTargetName, win.IpAddress, _id,… | ERROR |  |
| q-24eb0d9322 | triage T1187 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"3\" AND (TO_STRING(destination.ip) LIKE \"192.168.0.*\" OR destination.port == 445 OR destination.port == 139 OR destination.port == 80) \| KEEP @timestamp, host.name, us… | 428 | F19 |
| q-8f354e34da | triage T1187 step 4 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"5145\" OR event.code == \"5140\" \| KEEP @timestamp, host.name, event.code, user.name, source.ip, win.ShareName, win.ShareLocalPath, win.RelativeTargetName, win.IpAddre… | 163 | F19 |
| q-ac65e5f3f3 | triage T1187 step 5 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2lq7yE"} | None | F18 |
| q-5e28e8b9be | triage T1187 step 5 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kqttk"} | None | F18 |
| q-649595e5e3 | triage T1187 step 5 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*192.168.0.4*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*webdav*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*\\\\\\\\*… | 82 |  |
| q-b212260a69 | triage T1187 step 6 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE @timestamp >= \"2020-05-02T03:03:50Z\" AND @timestamp <= \"2020-05-02T03:12:00Z\" AND host.name == \"scranton.dmevals.local\" \| KEEP @timestamp, event.code, user.name, win.ScriptBlo… | 500 |  |
| q-647e458781 | triage T1187 step 6 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"13\" AND TO_LOWER(registry.path) LIKE \"*folder*shell*\" \| KEEP @timestamp, host.name, user.name, process.executable, registry.path, registry.data.strings, _id, _index \… | 5 | F18 |
| q-19c6c8c7aa | triage T1187 step 7 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND host.name == \"scranton.dmevals.local\" AND @timestamp >= \"2020-05-02T03:05:00Z\" AND @timestamp <= \"2020-05-02T03:12:00Z\" \| KEEP @timestamp, user.name… | 64 |  |
| q-6522fabfdd | triage T1187 step 7 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND host.name == \"scranton.dmevals.local\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*invoke-*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*function *\") \| KEE… | 19 |  |
| q-03dcca92b4 | triage T1187 step 8 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None | F18 |
| q-4b390eb6f3 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None |  |
| q-c79ef17944 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None |  |
| q-4e24ff5345 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2lq7yE"} | None |  |
| q-a6e839d189 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2lq7yE"} | None |  |
| q-6ae41cffdd | triage T1187 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kqttk"} | None |  |
| q-be013391ab | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA5C"} | None |  |
| q-6342e20437 | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGJw17"} | None |  |
| q-ec03bdb2c1 | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA5I"} | None |  |
| q-59a2252fc4 | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA0a"} | None |  |
| q-a8e5e1f0fd | triage T1187 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7WjMdm"} | None |  |
| q-99c6f4ae6f | triage T1187 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9Tx5o2"} | None |  |
| q-ed63e034b9 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9Kl3_9"} | None |  |
| q-b377da8792 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7Yk7Al"} | None |  |
| q-7adfdbf09d | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGJw1T"} | None |  |
| q-513d2a3cfe | triage T1212 step 1 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND win.TargetImage:*lsass.exe", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-9ca042662b | triage T1212 step 1 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass.exe", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-e1dc15878f | triage T1212 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass.exe AND (win.GrantedAccess:0x1fffff OR win.GrantedAccess:0x101001 OR win.GrantedAccess:0x1f3fff OR win.GrantedAccess:0x1000000 OR win.GrantedAccess:0x3000)", "time_from": null, "t… | 9 | F22 |
| q-e789e30b37 | triage T1212 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass.exe AND (process.executable:*powershell.exe OR process.executable:*wsmprovhost.exe)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "e… | 3 |  |
| q-208bc5e55e | triage T1212 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None | F20 |
| q-a56ab7799f | triage T1212 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None | F21 |
| q-f8237ba8d3 | triage T1212 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None | F20 |
| q-c361b7a855 | triage T1212 step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*lsass*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*minidump*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*sekurlsa*\" O… | 5 |  |
| q-dfa556a3d9 | triage T1212 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*lsass*\" OR TO_LOWER(process.command_line) LIKE \"*dump*\" OR TO_LOWER(process.command_line) LIKE \"*sekurlsa*\" OR TO_LOW… | 1 |  |
| q-a3378e96ae | triage T1212 step 5 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None | F20 |
| q-3460dd1d72 | triage T1212 step 5 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE host.name == \"scranton.dmevals.local\" AND event.code == \"4104\" \| KEEP @timestamp, user.name, win.ScriptBlockId, win.ScriptBlockText, _id, _index \| LIMIT 30"} | 30 | F20 |
| q-9dc88c122b | triage T1212 step 6 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND host.name == \"scranton.dmevals.local\" \| KEEP @timestamp, user.name, process.executable, process.command_line, process.parent.executable, process.pid, _id, _ind… | 40 | F20 |
| q-8259fb2493 | triage T1212 step 6 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4624\" AND host.name == \"scranton.dmevals.local\" \| KEEP @timestamp, user.name, win.LogonType, win.IpAddress, win.ProcessName, win.TargetUserName, _id, _index \| LIMI… | 40 | F22 |
| q-df161ece09 | triage T1212 step 7 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND host.name == \"nashua.dmevals.local\" AND (process.executable LIKE \"*wsmprovhost*\" OR process.executable LIKE \"*powershell*\") \| KEEP @timestamp, user.name, p… | 2 | F21 |
| q-789f32868c | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-0db25ff21f | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-deafb31d74 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-a0662ab1ac | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-252b55c8d7 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None |  |
| q-c0738b313c | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None |  |
| q-85d2bb383c | triage T1212 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None |  |
| q-e9244d9602 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None |  |
| q-6506027d50 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAWIhac"} | None |  |
| q-db675d6392 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL17AQxS"} | None |  |
| q-9f06804141 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-a352c24d93 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-7bf6202f4a | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-a33dd039ee | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kqds5"} | None |  |
| q-4ca0abc6b5 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2bgTcf"} | None |  |
| q-85e918eebb | triage T1212 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9MpvNN"} | None |  |
| q-4b64f9395b | triage T1212 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9MpvNN"} | None |  |
| q-617a9e73b7 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7anEhk"} | None |  |
| q-5bf0b7c6e0 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2ORrtr"} | None |  |
| q-2064545c48 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL88axkf"} | None |  |
| q-ac27aa157d | triage T1539 step 1 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9IkK9d"} | None | F23 |
| q-908e2c7971 | triage T1539 step 1 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JLx56e_Q"} | None | F23 |
| q-abacfa0d32 | triage T1539 step 1 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND (win.TargetImage:*MicrosoftEdge* OR win.TargetImage:*chrome* OR win.TargetImage:*firefox* OR win.TargetImage:*iexplore*)", "time_from": null, "time_to": null, "size": 30, … | 374 |  |
| q-edb5450db5 | triage T1539 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (win.TargetFilename:*INetCookies* OR win.TargetFilename:*Cookies* OR win.TargetFilename:*Login\\\\ Data* OR win.TargetFilename:*WebCache*)", "time_from": null, "time_to": null, "fields": ["@timestamp", … | 163 |  |
| q-b1499c1041 | triage T1539 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 11 AND (TO_LOWER(win.TargetFilename) LIKE \"*cookies*\" OR TO_LOWER(win.TargetFilename) LIKE \"*login data*\" OR TO_LOWER(win.TargetFilename) LIKE \"*webcache*\" OR TO_LOWE… | ERROR |  |
| q-dc1edf4840 | triage T1539 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 10 AND (TO_LOWER(win.TargetImage) LIKE \"*microsoftedge*\" OR TO_LOWER(win.TargetImage) LIKE \"*chrome*\" OR TO_LOWER(win.TargetImage) LIKE \"*firefox*\" OR TO_LOWER(win.Ta… | ERROR |  |
| q-22389818c1 | triage T1539 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(win.TargetFilename) LIKE \"*cookies*\" OR TO_LOWER(win.TargetFilename) LIKE \"*login data*\" OR TO_LOWER(win.TargetFilename) LIKE \"*webcache*\" OR TO_… | 1 |  |
| q-dac7f0018b | triage T1539 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND (TO_LOWER(win.TargetImage) LIKE \"*microsoftedge*\" OR TO_LOWER(win.TargetImage) LIKE \"*chrome*\" OR TO_LOWER(win.TargetImage) LIKE \"*firefox*\" OR TO_LOWER(wi… | 35 |  |
| q-5e830f9dc8 | triage T1539 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND process.executable LIKE \"*powershell*\" AND (TO_LOWER(win.TargetImage) LIKE \"*edge*\") \| KEEP @timestamp, host.name, user.name, process.executable, win.Target… | 6 |  |
| q-8845f91150 | triage T1539 step 4 | search | {"dataset": "zeek", "query": "event.action:http", "time_from": null, "time_to": null, "fields": ["@timestamp", "source.ip", "destination.ip", "url.original", "http.request.method", "user_agent.original", "zeek.uri", "zeek.user_agent", "zeek.host"], "size": 20,… | 62 | F23 |
| q-6c777619c7 | triage T1539 step 5 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7BNbJC"} | None | F23 |
| q-d86000d41b | triage T1539 step 5 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*edge*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*webdav*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*davclnt*\" OR TO… | 37 |  |
| q-e578d4b7e7 | triage T1539 step 6 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None | F23 |
| q-f43418013a | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JLx56e_Q"} | None |  |
| q-19c1e063a0 | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JLx56e_Q"} | None |  |
| q-a07dd475f1 | triage T1539 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9IkK9d"} | None |  |
| q-13618aee69 | triage T1539 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9IkK9d"} | None |  |
| q-d682698da5 | triage T1539 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None |  |
| q-efdc7a0b30 | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7BNbJC"} | None |  |
| q-0d887472cd | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7BNbJC"} | None |  |
| q-99ab94515e | triage T1539 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA5I"} | None |  |
| q-d725810be5 | triage T1539 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA5I"} | None |  |
| q-68712bd624 | triage T1552 step 1 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63C9mM"} | None | F26 |
| q-69122acbd4 | triage T1552 step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE TO_LOWER(process.executable) LIKE \"*accesschk*\" OR TO_LOWER(process.command_line) LIKE \"*accesschk*\" OR TO_LOWER(win.TargetFilename) LIKE \"*passwordsdb*\" \| KEEP @timestamp, host.n… | 22 |  |
| q-bf7d61d1a8 | triage T1552 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63C9mZ"} | None | F26 |
| q-76eb6e4449 | triage T1552 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND host.name == \"scranton.dmevals.local\" \| KEEP @timestamp, process.executable, process.command_line, process.parent.executable, user.name, _id, _index \| SORT @t… | 359 | F24, F29 |
| q-4770861799 | triage T1552 step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND host.name == \"scranton.dmevals.local\" \| KEEP @timestamp, win.ScriptBlockId, win.ScriptBlockText, _id, _index \| SORT @timestamp"} | 146 |  |
| q-5a4ebcdebf | triage T1552 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND host.name == \"scranton.dmevals.local\" AND @timestamp >= \"2020-05-02T03:03:00Z\" AND @timestamp <= \"2020-05-02T03:06:00Z\" \| KEEP @timestamp, process.executab… | 17 |  |
| q-5552bcef81 | triage T1552 step 4 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAWIxak"} | None | F24 |
| q-ad2b9e32ad | triage T1552 step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND host.name == \"scranton.dmevals.local\" AND @timestamp >= \"2020-05-02T03:01:50Z\" \| KEEP @timestamp, win.ScriptBlockText, _id, _index \| SORT @timestamp"… | 108 | F25, F26, F28 |
| q-7a82a4ea22 | triage T1552 step 5 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None | F25 |
| q-f0976a4634 | triage T1552 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE (TO_LOWER(win.TargetFilename) LIKE \"*.pfx\" OR TO_LOWER(win.TargetFilename) LIKE \"*.pem\" OR TO_LOWER(win.TargetFilename) LIKE \"*.key\" OR TO_LOWER(win.TargetFilename) LIKE \"*draft.z… | 4 | F24, F25 |
| q-b8c57dd3ab | triage T1552 step 6 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kqttt"} | None | F25 |
| q-ca44142fcd | triage T1552 step 6 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND host.name != \"scranton.dmevals.local\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*pfx*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*pass*\" OR TO_LOWER(win.… | 27 |  |
| q-e4469457da | triage T1552 step 7 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND host.name == \"nashua.dmevals.local\" AND win.ScriptBlockText != \"prompt\" \| KEEP @timestamp, win.ScriptBlockText, _id, _index \| SORT @timestamp"} | 7 | F24 |
| q-e9e2f404a4 | triage T1552 step 7 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE host.name == \"nashua.dmevals.local\" AND (event.code == \"11\" OR event.code == \"23\") AND (TO_LOWER(win.TargetFilename) LIKE \"*draft*\" OR TO_LOWER(win.TargetFilename) LIKE \"*.pfx\"… | 3 | F24 |
| q-6e1426182a | triage T1552 step 8 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4663\",\"4656\",\"4658\",\"5145\") AND (TO_LOWER(win.ObjectName) LIKE \"*passwordsdb*\" OR TO_LOWER(win.ObjectName) LIKE \"*.pfx\" OR TO_LOWER(win.ObjectName) LIKE \"*… | 0 |  |
| q-5c821681c4 | triage T1552 step 8 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND host.name == \"nashua.dmevals.local\" AND (TO_LOWER(process.executable) LIKE \"*rar*\" OR TO_LOWER(process.executable) LIKE \"*sdelete*\" OR TO_LOWER(process.exec… | 4 | F24 |
| q-2fdaa85598 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAWIxak"} | None |  |
| q-afd952345f | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7YlLDM"} | None |  |
| q-d0fa3e4842 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMANA6l9"} | None |  |
| q-28a7db2d2f | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2ZequJ"} | None |  |
| q-1e6132ec9d | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2Ze6tB"} | None |  |
| q-8e83744387 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7am0gN"} | None |  |
| q-7834580da2 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-7e1cebf16c | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1ns"} | None |  |
| q-49cedfbc67 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CdmD"} | None |  |
| q-4823eea4a2 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kqttt"} | None |  |
| q-169a3f0fe5 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQDFnY"} | None |  |
| q-5d6e739617 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63C9mZ"} | None |  |
| q-d90c4c5168 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63C9mM"} | None |  |
| q-7394d73794 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQDVp3"} | None |  |
| q-ea13b6468c | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL21_2XV"} | None |  |
| q-90d6b5fcb0 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2ORrtv"} | None |  |
| q-e5a782f529 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JLx4z3lk"} | None |  |
| q-bf9af037b6 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQDVq3"} | None |  |
| q-3591129bd1 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL6-JcMt"} | None |  |
| q-a3e6782aa6 | triage T1555 step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND win.TargetImage LIKE \"*lsass*\" AND win.GrantedAccess IN (\"0x1fffff\",\"0x101001\",\"0x1f3fff\",\"0x1000000\",\"0x3000\",\"0x1400\") \| KEEP @timestamp, host.n… | 33 | F30, F31 |
| q-feaa98bc2f | triage T1555 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None |  |
| q-5d1cecadf2 | triage T1555 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*lsass*\" OR TO_LOWER(process.command_line) LIKE \"*credential*\" OR TO_LOWER(process.command_line) LIKE \"*vault*\" OR TO_… | 1 |  |
| q-899ebf7b15 | triage T1555 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND user.name == \"pbeesly\" \| KEEP @timestamp, host.name, user.name, process.executable, process.command_line, process.parent.executable, _id, _index \| SORT @times… | 141 | F30 |
| q-36ecd61fef | triage T1555 step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND user.name == \"pbeesly\" \| KEEP @timestamp, host.name, user.name, win.Path, win.ScriptBlockText, _id, _index \| SORT @timestamp ASC"} | 157 | F32 |
| q-66d472af1f | triage T1555 step 3 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4688\" AND user.name == \"pbeesly\" \| KEEP @timestamp, host.name, user.name, process.executable, process.command_line, win.ParentProcessName, _id, _index \| SORT @time… | 88 |  |
| q-05efeaa27d | triage T1555 step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND user.name == \"pbeesly\" AND @timestamp > \"2020-05-02T03:01:51.000Z\" \| KEEP @timestamp, host.name, user.name, win.ScriptBlockText, _id, _index \| SORT @… | 117 | F30 |
| q-e4bf5a17be | triage T1555 step 4 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None | F30 |
| q-20cae43b2c | triage T1555 step 5 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND user.name == \"pbeesly\" AND @timestamp > \"2020-05-02T03:06:47.000Z\" \| KEEP @timestamp, host.name, user.name, win.ScriptBlockText, _id, _index \| SORT @… | 74 |  |
| q-be4b564417 | triage T1555 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*\\\\\\\\appdata\\\\\\\\roaming\\\\\\\\microsoft\\\\\\\\credentials*\" OR TO_LOWER(file.path) LIKE \"*\\\\\\\\appdata\\\\\\\\local\\\… | 1 | F30, F33 |
| q-74ec2f3f94 | triage T1555 step 6 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None | F30 |
| q-ba00518dd3 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-0638c95c66 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-e20700bd8a | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-d8c92ba728 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None |  |
| q-53cda98964 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-c1d7707767 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-c62e763bc0 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-9898cb0b1c | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CdmD"} | None |  |
| q-db01e69eac | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7am0gN"} | None |  |
| q-160acfad99 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JLx0p9yU"} | None |  |
| q-88c627c040 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2ORrtr"} | None |  |
| q-1b760558ac | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2QULdY"} | None |  |
| q-947adf010d | triage T1555 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL8nPsh9"} | None |  |
| q-3f4adb5ddc | triage T1555 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL-w3yMh"} | None |  |
| q-70d466b94c | triage T1555 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAWIxak"} | None |  |
| q-6aed08b970 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CdmD"} | None |  |
| q-46f5edddba | triage T1556 step 1 | aggregate | {"dataset": "windows.sysmon", "field": "win.SourceImage", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": "win.GrantedAccess"} | 326 |  |
| q-9d40f6e31b | triage T1556 step 1 | aggregate | {"dataset": "windows.sysmon", "field": "win.ImageLoaded", "query": "event.code:7 AND (win.ImageLoaded:*lsass* OR win.ImageLoaded:*cryptdll* OR win.ImageLoaded:*sam* OR win.ImageLoaded:*msv1_0*)", "time_from": null, "time_to": null, "size": 50, "sub_field": "pr… | 77 |  |
| q-844016c830 | triage T1556 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND (win.GrantedAccess:0x1fffff OR win.GrantedAccess:0x1f3fff OR win.GrantedAccess:0x101001 OR win.GrantedAccess:0x3000 OR win.GrantedAccess:0x1000000)", "time_from": null, "time… | 9 | F34 |
| q-8d3d02d5f5 | triage T1556 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:7 AND win.ImageLoaded:*apisampling*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.comma… | 1 | F36 |
| q-dd1bc84264 | triage T1556 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-10c43bfa31 | triage T1556 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-8ed03278f9 | triage T1556 step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND @timestamp >= \"2020-05-02T03:00:00.000Z\" AND @timestamp <= \"2020-05-02T03:12:00.000Z\" \| KEEP @timestamp, host.name, win.ScriptBlockId, win.ScriptBlock… | 40 |  |
| q-d30216fe06 | triage T1556 step 5 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND @timestamp >= \"2020-05-02T03:03:30.000Z\" AND @timestamp <= \"2020-05-02T03:10:30.000Z\" AND (host.name == \"scranton.dmevals.local\" OR host.name == \"na… | 60 | F34 |
| q-e95a48cb36 | triage T1556 step 6 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND win.ScriptBlockText IS NOT NULL AND (TO_LOWER(win.ScriptBlockText) LIKE \"*persiststep*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*notification packages*\"… | 2 | F34 |
| q-8cf87fce27 | triage T1556 step 7 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code IN (\"13\",\"11\",\"1\") AND @timestamp >= \"2020-05-02T03:04:00.000Z\" AND @timestamp <= \"2020-05-02T03:10:00.000Z\" AND host.name == \"scranton.dmevals.local\" AND (TO_LOWE… | 15 | F38 |
| q-1103e1a2c5 | triage T1556 step 8 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4673\",\"4674\",\"4703\",\"4670\",\"5447\",\"4945\",\"4690\",\"4656\") AND (TO_LOWER(win.ObjectName) LIKE \"*lsa*\" OR TO_LOWER(win.ObjectName) LIKE \"*sam*\" OR TO_LO… | 40 | F40 |
| q-1b04bbe53b | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-0fe182548b | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-1528fb8e9f | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-072ea94bed | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-4b4bb010da | triage T1556 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQDVp0"} | None |  |
| q-56f74805d8 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1ns"} | None |  |
| q-58af6674e5 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQDFlH"} | None |  |
| q-70842772b4 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9Tx5qJ"} | None |  |
| q-bcee294e7f | triage T1556 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9OrXFR"} | None |  |
| q-db87884b1c | triage T1556 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9OrXFR"} | None |  |
| q-aa67802028 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JLx6_vHT"} | None |  |
| q-e0bf311a63 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JLx6_vHT"} | None |  |
| q-0d3f9d690d | triage T1556 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9OrXFV"} | None |  |
| q-46dca386bd | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL20-Wda"} | None |  |
| q-22575081c3 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2x8I9e"} | None |  |
| q-03aeb16d1e | triage T1556 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9TypoR"} | None |  |
| q-b5621b875d | triage T1556 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9TypoR"} | None |  |
| q-3c6a72b69e | triage T1557 step 1 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"conn\" AND (zeek.orig_l2_addr == \"fc:bd:67:e1:a9:c1\" OR zeek.resp_l2_addr == \"12:34:56:78:9a:bc\" OR zeek.resp_l2_addr == \"ff:ff:ff:ff:ff:ff\") \| KEEP @timestamp, source.ip,… | 60 | F43 |
| q-1fcc6bebca | triage T1557 step 1 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4697\" \| KEEP @timestamp, host.name, user.name, win.ServiceName, win.ServiceFileName, win.ServiceAccount, _id, _index \| SORT @timestamp ASC \| LIMIT 30"} | 23 |  |
| q-6cb95996ba | triage T1557 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE (TO_LOWER(process.executable) LIKE \"*javamtsup*\" OR TO_LOWER(file.path) LIKE \"*javamtsup*\" OR TO_LOWER(process.command_line) LIKE \"*javamtsup*\") \| KEEP @timestamp, host.name, even… | 14 |  |
| q-5a7910490e | triage T1557 step 2 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"5145\" OR event.code == \"5140\" \| KEEP @timestamp, host.name, user.name, win.ShareName, win.ShareLocalPath, win.RelativeTargetName, win.IpAddress, win.SubjectUserName… | 40 | F41 |
| q-ec81aa420c | triage T1557 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"3\" AND (destination.port == 445 OR destination.port == 138 OR destination.port == 137 OR destination.port == 1234) \| KEEP @timestamp, host.name, user.name, process.exec… | 50 | F43, F44 |
| q-399a1eca45 | triage T1557 step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*sysinternals*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*download*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*invoke… | 16 | F41 |
| q-af6ffffedf | triage T1557 step 4 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9Qtr33"} | None | F41 |
| q-cb2253b53a | triage T1557 step 4 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4624\" AND win.LogonType IN (\"3\",\"9\",\"8\") \| KEEP @timestamp, host.name, win.LogonType, win.TargetUserName, win.IpAddress, win.AuthenticationPackageName, win.Logo… | 40 | F42 |
| q-6be11efc9b | triage T1557 step 5 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"conn\" AND (destination.ip == \"192.168.0.5\" OR zeek.service LIKE \"*smb*\") \| KEEP @timestamp, source.ip, destination.ip, destination.port, zeek.service, zeek.conn_state, zeek… | 19 | F42, F43 |
| q-82e44b67f3 | triage T1557 step 5 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"notice\" OR event.action == \"weird\" OR event.action == \"smb_mapping\" \| KEEP @timestamp, event.action, source.ip, destination.ip, zeek.name, zeek.msg, zeek.note, zeek.share_t… | 25 | F42 |
| q-702359d6c6 | triage T1557 step 6 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2MP8kN"} | None | F41 |
| q-bedebeb0d5 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-37dd59f3a4 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None |  |
| q-b94d677ff3 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAOBvlP"} | None |  |
| q-6fad3cdb56 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9Qtr33"} | None |  |
| q-c94e378b97 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2MP8kN"} | None |  |
| q-156149d544 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9LnlqG"} | None |  |
| q-8410954db5 | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA0r"} | None |  |
| q-2f34447c8d | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIK6WOc7y0JMA-MvX6"} | None |  |
| q-74a31014bf | triage T1557 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9Kmn8b"} | None |  |
| q-bfefd385b7 | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA0K"} | None |  |
| q-a9944a7cd5 | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIK6WOc7y0JMA_NKaC"} | None |  |
| q-43de6ba104 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7YlLAM"} | None |  |
| q-aa0cc4afdd | triage T1557 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL-w3yNV"} | None |  |
| q-d0e0eaf9ab | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7Yk7C5"} | None |  |
| q-39b9a9432b | triage T1558 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND (win.GrantedAccess:0x1fffff OR win.GrantedAccess:0x101001 OR win.GrantedAccess:0x1f3fff OR win.GrantedAccess:0x1000000 OR win.GrantedAccess:0x3000 OR win.GrantedAccess:0x1400… | 33 | F45 |
| q-53225cdd29 | triage T1558 step 1 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == 4769 \| KEEP @timestamp, host.name, user.name, source.ip, win.ServiceName, win.TicketEncryptionType, win.TicketOptions, win.Status, _id, _index \| SORT @timestamp ASC"} | ERROR |  |
| q-645a33e294 | triage T1558 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None | F45 |
| q-faccfa1147 | triage T1558 step 2 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4769\" \| KEEP @timestamp, host.name, user.name, source.ip, win.ServiceName, win.TicketEncryptionType, win.TicketOptions, win.Status, _id, _index \| SORT @timestamp ASC… | 28 | F47, F48 |
| q-7ea19f803f | triage T1558 step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND host.name == \"scranton.dmevals.local\" \| KEEP @timestamp, host.name, user.name, win.ScriptBlockId, win.ScriptBlockText, _id, _index \| SORT @timestamp AS… | 40 |  |
| q-5ebab1f540 | triage T1558 step 3 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"kerberos\" \| KEEP @timestamp, source.ip, destination.ip, zeek.request_type, zeek.client, zeek.service, zeek.success, zeek.error_msg, zeek.cipher, _id, _index \| SORT @timestamp … | 35 | F47, F48, F49 |
| q-9f533c46f4 | triage T1558 step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND host.name == \"scranton.dmevals.local\" AND @timestamp >= \"2020-05-02T03:01:50Z\" AND @timestamp <= \"2020-05-02T03:10:00Z\" \| KEEP @timestamp, user.name… | 87 | F45 |
| q-a49bc07ffe | triage T1558 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND host.name == \"scranton.dmevals.local\" \| KEEP @timestamp, user.name, process.executable, process.command_line, process.parent.executable, _id, _index \| SORT @t… | 359 |  |
| q-b97df7aca4 | triage T1558 step 5 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND host.name == \"scranton.dmevals.local\" AND @timestamp >= \"2020-05-02T03:06:00Z\" \| KEEP @timestamp, user.name, win.ScriptBlockText, _id, _index \| SORT … | 60 |  |
| q-654499fb8c | triage T1558 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND host.name == \"scranton.dmevals.local\" AND @timestamp >= \"2020-05-02T03:04:00Z\" AND @timestamp <= \"2020-05-02T03:08:00Z\" \| KEEP @timestamp, user.name, proce… | 19 |  |
| q-9d35e753c2 | triage T1558 step 6 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4672\" \| KEEP @timestamp, host.name, user.name, win.SubjectUserName, win.PrivilegeList, _id, _index \| SORT @timestamp ASC \| LIMIT 30"} | 30 | F46 |
| q-e65ce1ed24 | triage T1558 step 6 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4624\" AND win.LogonType IN (\"10\",\"2\",\"0\") \| KEEP @timestamp, host.name, user.name, win.LogonType, win.AuthenticationPackageName, source.ip, win.IpAddress, _id, … | 18 |  |
| q-e1c7bee85d | triage T1558 step 7 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL8-bHCF"} | None | F46 |
| q-525adead7f | triage T1558 step 7 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9MpvNN"} | None | F46 |
| q-e4cb8339a0 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-c6b0da4f41 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None |  |
| q-d1e5db68b1 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1ns"} | None |  |
| q-bf347c3b99 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQDFmw"} | None |  |
| q-bc3f207cb0 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL8-bHCF"} | None |  |
| q-1b130c580d | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9MpvNN"} | None |  |
| q-0e4ba2c314 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9TypoZ"} | None |  |
| q-9aa0a3ba00 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9OrnEj"} | None |  |
| q-a4d52ab462 | triage T1558 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGJw1d"} | None |  |
| q-10d812f62f | triage T1558 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGJw1g"} | None |  |
| q-e56a572952 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9LnlqF"} | None |  |
| q-c94c494ed8 | triage T1558 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIK6WOc7y0JMA_NaZg"} | None |  |
| q-377b76a53a | triage T1558 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGJw1f"} | None |  |
| q-749e72db04 | triage T1558 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGJw1g"} | None |  |
| q-a04fd07448 | triage T1606 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND (win.GrantedAccess:0x1fffff OR win.GrantedAccess:0x101001 OR win.GrantedAccess:0x1f3fff OR win.GrantedAccess:0x1000000 OR win.GrantedAccess:0x3000 OR win.GrantedAccess:0x1400… | 33 |  |
| q-fe004626f2 | triage T1606 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*cookie* OR file.path:*Cookies*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "process.executable", "process.command_line", "file.path", "win.Targe… | 1 | F51 |
| q-803bffbb9d | triage T1606 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None | F52 |
| q-9baf1fff69 | triage T1606 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None | F52 |
| q-27b0e7dcec | triage T1606 step 2 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*Aes* OR win.ScriptBlockText:*FromBase64* OR win.ScriptBlockText:*Invoke* OR win.ScriptBlockText:*Credential* OR win.ScriptBlockText:*MiniDump* … | 22 | F52 |
| q-4ae2bcfec5 | triage T1606 step 3 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*pfx* OR win.ScriptBlockText:*PFX* OR win.ScriptBlockText:*Certificate* OR win.ScriptBlockText:*AADInternals* OR win.ScriptBlockText:*AAD* OR win.ScriptBlockText:*Open-AADInt*… | 2 | F50 |
| q-c87b4dbf3a | triage T1606 step 3 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*.pfx OR file.path:*.p12 OR file.path:*.7z OR file.path:*OfficeSupplies*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "event.code", "process.execu… | 4 | F50 |
| q-dc4bc09706 | triage T1606 step 4 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None | F50 |
| q-a9c5df84ad | triage T1606 step 4 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND win.SourceImage:*wsmprovhost*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "event.code", "process.executable", "process.command_li… | 1 | F52 |
| q-a771305bde | triage T1606 step 5 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND win.ScriptBlockText:*cozy*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "event.code", "win.ScriptBlockText", "win.Path"], "size": 10, "sort": "asc"} | 1 |  |
| q-8d4b54464a | triage T1606 step 5 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND host.name:scranton.dmevals.local AND (process.command_line:*Get-PrivateKeys* OR process.command_line:*readme.ps1* OR process.command_line:*psversion.ps1* OR process.command_line:*Export-Pfx*)", "time_fro… | 0 |  |
| q-369fd862ae | triage T1606 step 6 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None | F50 |
| q-47fd86265d | triage T1606 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-9ba34c584e | triage T1606 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-6bdc9519f6 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CdmD"} | None |  |
| q-81bad119a0 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2lq7zj"} | None |  |
| q-2d68f6ecac | triage T1606 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None |  |
| q-454b5a0d97 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMANA6lp"} | None |  |
| q-6bbdc76454 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JLx56e_Q"} | None |  |
| q-8706ceed38 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JLx56e_Q"} | None |  |
| q-340182ac97 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None |  |
| q-a758bfcb9f | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-f39af0b296 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-f2a2b471f1 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAOAxHj"} | None |  |
| q-4cb22be879 | triage T1621 step 1 | aggregate | {"dataset": "windows.other", "field": "event.code", "query": "event.code:4625 OR event.code:5857 OR event.code:5858", "time_from": null, "time_to": null, "size": 20, "sub_field": "host.name"} | 85 |  |
| q-0710962066 | triage T1621 step 1 | esql | {"query": "FROM logs-windows.other-default METADATA _id, _index \| WHERE event.code == 5857 OR event.code == 5858 \| STATS c = COUNT(*) BY host.name, user.name, event.code \| SORT c DESC"} | ERROR |  |
| q-ab179356a5 | triage T1621 step 2 | esql | {"query": "FROM logs-windows.other-default METADATA _id, _index \| WHERE event.code == \"5857\" OR event.code == \"5858\" \| STATS c = COUNT(*) BY host.name, user.name, event.code \| SORT c DESC"} | 11 |  |
| q-d2ded0d129 | triage T1621 step 2 | search | {"dataset": "windows.other", "query": "event.code:5857", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "user.name", "message", "win.Operation", "win.ClientMachine"], "size": 5, "sort": "asc"} | 36 | F53 |
| q-40c350c22b | triage T1621 step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*mfa*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*2fa*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*authenticator*\"… | 0 |  |
| q-6d582f70a6 | triage T1621 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" \| WHERE TO_LOWER(process.command_line) LIKE \"*mfa*\" OR TO_LOWER(process.command_line) LIKE \"*2fa*\" OR TO_LOWER(process.command_line) LIKE \"*authenticator*\" OR … | 20 |  |
| q-3b4585e7a7 | triage T1621 step 4 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4624\" \| STATS c = COUNT(*) BY win.LogonType, win.AuthenticationPackageName, win.TargetUserName \| SORT c DESC \| LIMIT 30"} | 18 |  |
| q-79f9da8b17 | triage T1621 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"3\" \| STATS c = COUNT(*) BY destination.port, process.executable \| SORT c DESC \| LIMIT 30"} | 30 |  |
| q-25f4d3d43b | triage T1621 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"3\" AND process.executable == \"C:\\\\Windows\\\\Temp\\\\python.exe\" \| STATS c = COUNT(*) BY host.name, destination.ip, destination.port, user.name \| SORT c DESC \| LI… | 1 |  |
| q-18ca0ea40f | triage T1621 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE process.executable LIKE \"*dsregcmd*\" OR process.command_line LIKE \"*dsregcmd*\" \| KEEP @timestamp, host.name, user.name, event.code, process.executable, process.command_line, destina… | 20 | F53 |
| q-4a01ea1b6b | triage T1621 step 6 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE process.executable == \"C:\\\\Windows\\\\Temp\\\\python.exe\" AND event.code == \"1\" \| KEEP @timestamp, host.name, user.name, process.executable, process.command_line, process.parent.e… | 5 | F53 |
| q-32e31791c6 | triage T1621 step 6 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"3\" AND process.executable == \"C:\\\\Windows\\\\Temp\\\\python.exe\" \| KEEP @timestamp, host.name, user.name, destination.ip, destination.port, network.transport, _id, … | 5 | F53 |
| q-e50c9b280f | triage T1621 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL-w3yMK"} | None |  |
| q-ec0af1fa55 | triage T1621 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL-w3iO6"} | None |  |
| q-ad6661d525 | triage T1621 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL-w3iOa"} | None |  |
| q-ed44da69d6 | triage T1621 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL18GdOb"} | None |  |
| q-1ce960ab10 | triage T1621 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2bgzd1"} | None |  |
| q-290c2687f6 | triage T1621 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2bgjeM"} | None |  |
| q-829d12fe3a | triage T1649 step 1 | search | {"dataset": "windows.security", "query": "event.code:4657 AND win.ObjectName:*SystemCertificates*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "pr… | 1 |  |
| q-cbcaa91aa9 | triage T1649 step 1 | search | {"dataset": "windows.security", "query": "event.code:4768", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 14 | F55 |
| q-2e0c2964be | triage T1649 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:13 AND registry.path:*SystemCertificates*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process… | 19 | F54, F55 |
| q-b807e92bd1 | triage T1649 step 2 | search | {"dataset": "windows.sysmon", "query": "process.pid:3876 AND host.name:scranton.dmevals.local", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "proces… | 1999 |  |
| q-bd5b062f07 | triage T1649 step 2 | search | {"dataset": "windows.powershell", "query": "host.name:scranton.dmevals.local AND (win.ScriptBlockText:*Cert* OR win.ScriptBlockText:*cert* OR process.command_line:*Cert* OR process.command_line:*cert*)", "time_from": null, "time_to": null, "fields": ["@timesta… | 3 |  |
| q-040de0dacf | triage T1649 step 3 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None | F54 |
| q-cd541d792f | triage T1649 step 3 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND file.path:*Downloads*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line… | 314 |  |
| q-d61576a668 | triage T1649 step 4 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND file.path:*.pfx", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "so… | 1 | F54 |
| q-2cecb221e6 | triage T1649 step 4 | search | {"dataset": "windows.powershell", "query": "win.ScriptBlockText:*Get-PrivateKeys* OR win.ScriptBlockText:*Export-PfxCertificate* OR win.ScriptBlockText:*readme.ps1*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "e… | 4 | F54 |
| q-e68335b7dd | triage T1649 step 5 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9FgwRA"} | None | F55 |
| q-5409c15ada | triage T1649 step 5 | search | {"dataset": "windows.sysmon", "query": "file.path:*coyn5igj* OR process.command_line:*coyn5igj* OR process.command_line:*pfx*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name… | 2 | F54 |
| q-ef2fda040a | triage T1649 step 6 | search | {"dataset": "windows.powershell", "query": "host.name:scranton.dmevals.local AND @timestamp:[2020-05-02T03:05:00.000Z TO 2020-05-02T03:12:00.000Z] AND event.code:4104", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", … | 64 |  |
| q-f003f681fa | triage T1649 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-209cc37e4f | triage T1649 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-fd18205489 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-e511950940 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1ns"} | None |  |
| q-c8d5bb4fd2 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQDFnY"} | None |  |
| q-c6ea57825b | triage T1649 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQDVoX"} | None |  |
| q-ef69035a96 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CdmD"} | None |  |
| q-508368f453 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CdmN"} | None |  |
| q-8bb9458031 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CtkV"} | None |  |
| q-1633749a95 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kqttt"} | None |  |
| q-1b12051879 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7LXG4H"} | None |  |
| q-2b6f1d6d8f | triage T1649 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2ZequA"} | None |  |
| q-175702499b | triage T1649 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2OR7uU"} | None |  |
| q-3fd9bf50be | triage T1649 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JLx41usR"} | None |  |
| q-18f57e1c14 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9FgwRA"} | None |  |
| q-068f90c1b1 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9OrXFP"} | None |  |
| q-ae2b2951b8 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL8-bHB-"} | None |  |
| q-9adccb76a0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None |  |
| q-c2c0d83bc0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None |  |
| q-4a76bacd11 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None |  |
| q-d6f683f17b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-8dadd6b292 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7ViMbT"} | None |  |
| q-dec8008a2b | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAWIxa2"} | None |  |
| q-d2175e7416 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None |  |
| q-52c1baa004 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None |  |
| q-ba1ff19337 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAWIxZm"} | None |  |
| q-6e59ba8f74 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQDFlH"} | None |  |
| q-f2c520b5e0 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMANA6l9"} | None |  |
| q-ec824447ab | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL81V4Qj"} | None |  |
| q-4989e95ab1 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL81V4Qj"} | None |  |
| q-471f7acbea | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL81V4Qj"} | None |  |
| q-0f8fbc8471 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL17AAad"} | None |  |
| q-af557ec4b6 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2in-Mz"} | None |  |
| q-558319f662 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2in-Mz"} | None |  |
| q-6254d66f57 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL62AkVX"} | None |  |
| q-15c958ebfd | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL62AkVX"} | None |  |
| q-6fa37013b0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2hm-XC"} | None |  |
| q-ccf3a4eecc | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2ORrtq"} | None |  |
| q-f3bd63999f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2x7o-G"} | None |  |
| q-7ac079dfbb | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2PS3oM"} | None |  |
| q-ea58101161 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2PS3oM"} | None |  |
| q-84000888ed | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL-w3iOg"} | None |  |
| q-7d78fcf9b5 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2jo9KZ"} | None |  |
| q-74f1923013 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2bgzcO"} | None |  |
| q-e148e8ae6c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2bgjeM"} | None |  |
| q-5bb68dc3f8 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9Uyl9o"} | None |  |
| q-554f7aaec7 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAOBExi"} | None |  |
| q-317a90df8c | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1lL"} | None |  |
| q-e33a521517 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1lL"} | None |  |
| q-7c4f566a4a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2ioON3"} | None |  |
| q-03f92d5685 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2in-NH"} | None |  |
| q-7c5eab557b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2bgTcg"} | None |  |
| q-7684c8fcf6 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2bgTcg"} | None |  |
| q-fe29eac116 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2bgTei"} | None |  |
| q-57c50259fa | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2bgjf5"} | None |  |
| q-22471b0017 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None |  |
| q-b0c0bc6d8e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None |  |
| q-2594d2b96c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-1c976dd579 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-c37192dd0d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-5a8fe1b703 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2ORrtr"} | None |  |
| q-1bf3523b9d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JLx0p9yU"} | None |  |
| q-93d2200239 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL81V4Qj"} | None |  |
| q-438095d1e2 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL8-b3Gh"} | None |  |
| q-724cd35990 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL8xSa_z"} | None |  |
| q-190d291a9d | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL8xSa_z"} | None |  |
| q-f186d571ec | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL-w3yMf"} | None |  |
| q-3156b72132 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL8xSa_z"} | None |  |
| q-0bfd41d96d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7ViMbT"} | None |  |
| q-9dfed36248 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-7885611de9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None |  |
| q-708241a0c2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-696aa01acd | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL-w3yM8"} | None |  |
| q-64d77c3e2c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7ViMbT"} | None |  |
| q-86f309e885 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9OrXFR"} | None |  |
| q-5302d066fe | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL-w3iOg"} | None |  |
| q-aa8dc562b7 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL8vSVsk"} | None |  |
| q-41f50e94f6 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL-w3yNa"} | None |  |
| q-4496332129 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL88ahmW"} | None |  |
| q-bb770c4006 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL8xSa_z"} | None |  |
| q-f3d65c28cb | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-24729be437 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-375d28fdee | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-fc85a7358f | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAMA2AH"} | None |  |
| q-fe80910866 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9VzyYa"} | None |  |
| q-8bb99d65fd | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9OrnEx"} | None |  |
| q-e929d1ec2c | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9OrXFR"} | None |  |
| q-92c32bc30f | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMANA6l9"} | None |  |
| q-fff64104c9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2ORrtv"} | None |  |
| q-3459ce821f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2ORrtv"} | None |  |
| q-9dafb0ea8f | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL8vSVsl"} | None |  |
| q-64d44256be | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None |  |
| q-a78c98b2b6 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None |  |
| q-2c61082c63 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2lq7yE"} | None |  |
| q-8d65eef0d8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2lq7yE"} | None |  |
| q-d69b7a1c8e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kqttk"} | None |  |
| q-55d8345b11 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA5C"} | None |  |
| q-fb0f97cd84 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGJw17"} | None |  |
| q-eb55297166 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA5I"} | None |  |
| q-f7fd06bd94 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA0a"} | None |  |
| q-996e6a4a75 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7WjMdm"} | None |  |
| q-d6a9921a2d | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9Tx5o2"} | None |  |
| q-fe328d1fd2 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9Kl3_9"} | None |  |
| q-3c8722b296 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7Yk7Al"} | None |  |
| q-16eb48f666 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGJw1T"} | None |  |
| q-8732596427 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-a8b41e0759 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-07160f293f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-2b3b8e79ea | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-0477772bba | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None |  |
| q-54f7445ecc | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None |  |
| q-df334ef121 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None |  |
| q-204322648d | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None |  |
| q-167d122ea9 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAWIhac"} | None |  |
| q-138ab532f2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL17AQxS"} | None |  |
| q-1256e4a9de | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-f12fcfe749 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-a891b5f6fa | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-a6437a2116 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kqds5"} | None |  |
| q-615c8bfe06 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2bgTcf"} | None |  |
| q-13553f1808 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9MpvNN"} | None |  |
| q-1055f9df08 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9MpvNN"} | None |  |
| q-3433d34112 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7anEhk"} | None |  |
| q-06f9b9ee20 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2ORrtr"} | None |  |
| q-af16daee41 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL88axkf"} | None |  |
| q-48ef78426e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JLx56e_Q"} | None |  |
| q-7a3db3d695 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JLx56e_Q"} | None |  |
| q-36f02312cc | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9IkK9d"} | None |  |
| q-171f4f56ba | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9IkK9d"} | None |  |
| q-2db1cd4f12 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None |  |
| q-834ff4cd6c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7BNbJC"} | None |  |
| q-ad5f75c171 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7BNbJC"} | None |  |
| q-c088111541 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA5I"} | None |  |
| q-60999fcba3 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA5I"} | None |  |
| q-97b1763245 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAWIxak"} | None |  |
| q-518672abd3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7YlLDM"} | None |  |
| q-7e7fd354e8 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMANA6l9"} | None |  |
| q-e189d4f0f7 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2ZequJ"} | None |  |
| q-2cdff3bd88 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2Ze6tB"} | None |  |
| q-38ce80d5a4 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7am0gN"} | None |  |
| q-5fe7e848cf | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-f4498962cc | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1ns"} | None |  |
| q-e05e9e882e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CdmD"} | None |  |
| q-a3b2998eca | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kqttt"} | None |  |
| q-2a9ed0b91f | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQDFnY"} | None |  |
| q-d037fa07e1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63C9mZ"} | None |  |
| q-78f43ec0ce | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63C9mM"} | None |  |
| q-3436abc62c | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQDVp3"} | None |  |
| q-552fbdb882 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL21_2XV"} | None |  |
| q-1d5a55d2a3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2ORrtv"} | None |  |
| q-000eaeab43 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JLx4z3lk"} | None |  |
| q-57d316e539 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQDVq3"} | None |  |
| q-b10e3c2c29 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL6-JcMt"} | None |  |
| q-bdfff16cb0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-6a0d25054d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-9232e535c7 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-24bc60230c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None |  |
| q-abd0311e01 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-025ce91581 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-a34667b860 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-176ab28c8c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CdmD"} | None |  |
| q-5c3ef6c129 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7am0gN"} | None |  |
| q-5eb096f473 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JLx0p9yU"} | None |  |
| q-997e0e59c8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2ORrtr"} | None |  |
| q-d73a6aa6c6 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2QULdY"} | None |  |
| q-1059697cc6 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL8nPsh9"} | None |  |
| q-3655d0ac6a | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL-w3yMh"} | None |  |
| q-adaba17456 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAWIxak"} | None |  |
| q-5d4691c54e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CdmD"} | None |  |
| q-7b08d54bfc | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-cdfcf55720 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-0489d66f22 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-a57c07a320 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-fce3282470 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQDVp0"} | None |  |
| q-98e4c18e22 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1ns"} | None |  |
| q-306ff6bc98 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQDFlH"} | None |  |
| q-6cb3d88b6a | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9Tx5qJ"} | None |  |
| q-27abfb86ce | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9OrXFR"} | None |  |
| q-6ae16f93cd | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9OrXFR"} | None |  |
| q-cbebe04900 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JLx6_vHT"} | None |  |
| q-e9a1c6295e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JLx6_vHT"} | None |  |
| q-92e243edab | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9OrXFV"} | None |  |
| q-da05394257 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL20-Wda"} | None |  |
| q-33d2f885fa | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2x8I9e"} | None |  |
| q-3dba5b1c50 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9TypoR"} | None |  |
| q-bd59f75fbb | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9TypoR"} | None |  |
| q-9708122fef | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-d96aba474a | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None |  |
| q-4e657123c7 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAOBvlP"} | None |  |
| q-96a59b6e3a | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9Qtr33"} | None |  |
| q-cdf6f116cf | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2MP8kN"} | None |  |
| q-658a38cc15 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9LnlqG"} | None |  |
| q-4e15416d80 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA0r"} | None |  |
| q-04c6ac31fd | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIK6WOc7y0JMA-MvX6"} | None |  |
| q-79b8cada4a | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9Kmn8b"} | None |  |
| q-c4778ac4b3 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA0K"} | None |  |
| q-04cd72cab5 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIK6WOc7y0JMA_NKaC"} | None |  |
| q-9d389f0c38 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7YlLAM"} | None |  |
| q-417f80df45 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL-w3yNV"} | None |  |
| q-3148b0993e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7Yk7C5"} | None |  |
| q-c071e629f7 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-5f99a08627 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None |  |
| q-4cfeedc7f4 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1ns"} | None |  |
| q-76496811fe | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQDFmw"} | None |  |
| q-b94608ee67 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL8-bHCF"} | None |  |
| q-54b6994723 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9MpvNN"} | None |  |
| q-3fe23d9c61 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9TypoZ"} | None |  |
| q-c09d375be1 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9OrnEj"} | None |  |
| q-e02fa2e498 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGJw1d"} | None |  |
| q-7187927a6e | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGJw1g"} | None |  |
| q-b8d5d653d7 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9LnlqF"} | None |  |
| q-378b025d62 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIK6WOc7y0JMA_NaZg"} | None |  |
| q-f53a29e655 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGJw1f"} | None |  |
| q-0fb73d820d | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGJw1g"} | None |  |
| q-53ebf6ffb4 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-fc28656edf | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-05b89956a9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CdmD"} | None |  |
| q-5bafb090cb | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2lq7zj"} | None |  |
| q-5047fdc00e | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None |  |
| q-d613dd6524 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMANA6lp"} | None |  |
| q-774737e51e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JLx56e_Q"} | None |  |
| q-42f284dc9d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JLx56e_Q"} | None |  |
| q-4fdbd9ff92 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None |  |
| q-1958f27251 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-b26b2bce14 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-753f5704c9 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAOAxHj"} | None |  |
| q-4f13acd88f | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL-w3yMK"} | None |  |
| q-503552ff8d | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL-w3iO6"} | None |  |
| q-9fe0a75d28 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL-w3iOa"} | None |  |
| q-e5621e3c98 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL18GdOb"} | None |  |
| q-743db5499d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2bgzd1"} | None |  |
| q-9a74c8fbf5 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2bgjeM"} | None |  |
| q-9e4eabba31 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-445da0ad1e | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-4ab5104e34 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-58b89e08c5 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1ns"} | None |  |
| q-a5b89dcf2d | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQDFnY"} | None |  |
| q-9d3b85251e | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQDVoX"} | None |  |
| q-6dfae47c95 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CdmD"} | None |  |
| q-6f029ff5e0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CdmN"} | None |  |
| q-1d2c5eb18a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CtkV"} | None |  |
| q-1e0e7ac590 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kqttt"} | None |  |
| q-a22ea2ec70 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7LXG4H"} | None |  |
| q-0d9ea1c241 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2ZequA"} | None |  |
| q-2c56e3bacc | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2OR7uU"} | None |  |
| q-c684cb0597 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JLx41usR"} | None |  |
| q-a20bfa418b | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9FgwRA"} | None |  |
| q-27d8dccfa2 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9OrXFP"} | None |  |
| q-c24fa7e6aa | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL8-bHB-"} | None |  |
| q-5f2287dbb7 | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND host.name:\"nashua.dmevals.local\"", "time_from": "2020-05-02T02:54:23+00:00", "time_to": "2020-05-02T03:31:19.462000+00:00", "size": 100, "sub_field": "process.parent.exec… | 61 |  |
| q-1227ccb0c9 | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11 AND host.name:\"nashua.dmevals.local\"", "time_from": "2020-05-02T02:54:23+00:00", "time_to": "2020-05-02T03:31:19.462000+00:00", "size": 100, "sub_field": "process.executable"} | 249 |  |
| q-a0a162d6ed | pivot seed | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND host.name:\"nashua.dmevals.local\"", "time_from": "2020-05-02T02:54:23+00:00", "time_to": "2020-05-02T03:31:19.462000+00:00", "size": 100, "sub_field": "process.parent… | 63 |  |
| q-e297de0b25 | pivot seed | aggregate | {"dataset": "windows.powershell", "field": "event.code", "query": "host.name:\"nashua.dmevals.local\"", "time_from": "2020-05-02T02:54:23+00:00", "time_to": "2020-05-02T03:31:19.462000+00:00", "size": 100, "sub_field": null} | 192 |  |
| q-2499eb2f03 | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND host.name:\"scranton.dmevals.local\"", "time_from": "2020-05-02T02:40:56.157000+00:00", "time_to": "2020-05-02T03:36:28.949000+00:00", "size": 100, "sub_field": "process.pa… | 359 |  |
| q-3314316524 | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11 AND host.name:\"scranton.dmevals.local\"", "time_from": "2020-05-02T02:40:56.157000+00:00", "time_to": "2020-05-02T03:36:28.949000+00:00", "size": 100, "sub_field": "process.executable… | 1276 |  |
| q-fb7a7e98d8 | pivot seed | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND host.name:\"scranton.dmevals.local\"", "time_from": "2020-05-02T02:40:56.157000+00:00", "time_to": "2020-05-02T03:36:28.949000+00:00", "size": 100, "sub_field": "proce… | 370 |  |
| q-bac53f0e58 | pivot seed | aggregate | {"dataset": "windows.powershell", "field": "event.code", "query": "host.name:\"scranton.dmevals.local\"", "time_from": "2020-05-02T02:40:56.157000+00:00", "time_to": "2020-05-02T03:36:28.949000+00:00", "size": 100, "sub_field": null} | 8602 |  |
| q-54123fa50d | pivot step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 1 AND host.name == \"nashua.dmevals.local\" AND (process.executable LIKE \"*python.exe\" OR process.executable LIKE \"*Rar.exe\" OR process.executable LIKE \"*sdelete64.exe… | ERROR |  |
| q-5a88f3906f | pivot step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 1 AND host.name == \"scranton.dmevals.local\" AND (process.executable LIKE \"*csc.exe\" OR process.executable LIKE \"*hostui.exe\" OR process.executable LIKE \"*sdclt.exe\"… | ERROR |  |
| q-96e856fb73 | pivot step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND host.name == \"nashua.dmevals.local\" AND (process.executable LIKE \"*python.exe\" OR process.executable LIKE \"*Rar.exe\" OR process.executable LIKE \"*sdelete64… | 13 | F56, F60 |
| q-3449d8f1dc | pivot step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND host.name == \"scranton.dmevals.local\" AND (process.executable LIKE \"*csc.exe\" OR process.executable LIKE \"*hostui.exe\" OR process.executable LIKE \"*sdclt.e… | 15 | F59, F61, F64, F65 |
| q-4054821706 | pivot step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE host.name == \"nashua.dmevals.local\" AND event.code == \"4104\" \| KEEP @timestamp, host.name, user.name, powershell.file.script_block_text, _id, _index \| SORT @timestamp"} | ERROR |  |
| q-b2f4a78ef9 | pivot step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND host.name == \"nashua.dmevals.local\" AND (file.path LIKE \"*pbeesly*\" OR file.path LIKE \"*Temp*\" OR file.path LIKE \"*working*\" OR file.path LIKE \"*passw*\… | 138 |  |
| q-160f6fe509 | pivot step 4 | get_fields | {"dataset": "windows.powershell", "prefix": ""} | None |  |
| q-e1cc213116 | pivot step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND host.name == \"scranton.dmevals.local\" AND (file.path LIKE \"*passw*\" OR file.path LIKE \"*.pfx\" OR file.path LIKE \"*.zip\" OR file.path LIKE \"*cred*\" OR f… | 456 | F62, F63 |
| q-7221d5d070 | pivot step 5 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE host.name == \"nashua.dmevals.local\" AND event.code == \"4104\" \| KEEP @timestamp, host.name, user.name, win.ScriptBlockText, _id, _index \| SORT @timestamp"} | 11 |  |
| q-9d302e2890 | pivot step 6 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMANA6l9"} | None | F56 |
| q-648c110b78 | pivot step 6 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE host.name == \"scranton.dmevals.local\" AND event.code == \"4104\" AND (win.ScriptBlockText LIKE \"*pass*\" OR win.ScriptBlockText LIKE \"*cred*\" OR win.ScriptBlockText LIKE \"*lsas… | 7 | F57 |
| q-19d88b5bac | pivot step 7 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4663\" AND (win.ObjectName LIKE \"*lsass*\" OR win.ObjectName LIKE \"*SAM*\" OR win.ObjectName LIKE \"*SECURITY*\" OR win.ObjectName LIKE \"*vault*\" OR win.ObjectName … | ERROR |  |
| q-6faa3463a9 | pivot step 7 | esql | {"query": "FROM logs-windows.other-default METADATA _id, _index \| WHERE event.code == \"7045\" OR event.code == \"4697\" \| KEEP @timestamp, host.name, user.name, win.ServiceName, win.ImagePath, win.ServiceFileName, message, _id, _index \| SORT @timestamp"} | ERROR |  |
| q-bdbe477010 | pivot step 8 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4663\" AND (win.ObjectName LIKE \"*lsass*\" OR win.ObjectName LIKE \"*SAM*\" OR win.ObjectName LIKE \"*SECURITY*\" OR win.ObjectName LIKE \"*vault*\" OR win.ObjectName … | 6 | F58 |
| q-ca4d5cc7f4 | pivot step 8 | esql | {"query": "FROM logs-windows.other-default METADATA _id, _index \| WHERE event.code == \"7045\" \| KEEP @timestamp, host.name, user.name, win.ServiceName, win.ImagePath, message, _id, _index \| SORT @timestamp"} | 5 | F59 |
| q-326bac229c | pivot step 9 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None | F57 |
| q-7618c961e6 | pivot step 9 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND host.name == \"scranton.dmevals.local\" AND (file.path LIKE \"*.pfx\" OR file.path LIKE \"*OfficeSupplies*\" OR file.path LIKE \"*passwordsDB*\" OR file.path LIK… | 317 |  |
| q-485bae6812 | pivot step 10 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE host.name == \"scranton.dmevals.local\" AND event.code == \"4104\" AND (win.ScriptBlockText LIKE \"*OfficeSupplies*\" OR win.ScriptBlockText LIKE \"*BeachCleanup*\" OR win.ScriptBloc… | 19 | F64 |
| q-7344b068cc | pivot step 11 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None | F57 |
| q-b5d3188970 | pivot step 11 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAOBExi"} | None |  |
| q-22fe48dc0d | pivot verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMANA6l9"} | None |  |
| q-22bfec453f | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2Ze6tB"} | None |  |
| q-2b939fab09 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2VYgwB"} | None |  |
| q-b9effbe550 | pivot verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-2473349ae1 | pivot verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None |  |
| q-a4268d1f7e | pivot verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMANA6lp"} | None |  |
| q-fe43b9a8ce | pivot verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9Qt70r"} | None |  |
| q-cb9a8f4a4f | pivot verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9Qt70r"} | None |  |
| q-5f6e73a67c | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2ioON3"} | None |  |
| q-5ba2d6af3f | pivot verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL-w3iOg"} | None |  |
| q-5815b682ca | pivot step 13 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7am0gN"} | None | F62 |
| q-731a07b697 | pivot step 13 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2v5uV8"} | None | F63 |
| q-b6fc837b99 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None |  |
| q-e6dfd5a81c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None |  |
| q-1bf3414fa9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None |  |
| q-da399bcefc | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-823b6bef7d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7ViMbT"} | None |  |
| q-2043f377f6 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAWIxa2"} | None |  |
| q-d362442657 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None |  |
| q-8df4ffa685 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None |  |
| q-c71a41b446 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAWIxZm"} | None |  |
| q-34ddba2a18 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQDFlH"} | None |  |
| q-b3e8e8b103 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMANA6l9"} | None |  |
| q-b440d16dc7 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL81V4Qj"} | None |  |
| q-5d58a5c092 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL81V4Qj"} | None |  |
| q-ddc31e8836 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL81V4Qj"} | None |  |
| q-e5e314b43b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL17AAad"} | None |  |
| q-35547e2835 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2in-Mz"} | None |  |
| q-3d9e98b863 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2in-Mz"} | None |  |
| q-6daddda483 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL62AkVX"} | None |  |
| q-1025995a9c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL62AkVX"} | None |  |
| q-3f09fe19c4 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2hm-XC"} | None |  |
| q-7d978d686d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2ORrtq"} | None |  |
| q-4a8f6217ea | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2x7o-G"} | None |  |
| q-ce0ea53276 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2PS3oM"} | None |  |
| q-5fa63f384d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2PS3oM"} | None |  |
| q-f363a43f8d | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL-w3iOg"} | None |  |
| q-c6d7c37bc2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2jo9KZ"} | None |  |
| q-f72ba13bd5 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2bgzcO"} | None |  |
| q-77ef1958f1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2bgjeM"} | None |  |
| q-fe4cabafd0 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9Uyl9o"} | None |  |
| q-a44ada650b | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAOBExi"} | None |  |
| q-dbab3e142d | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1lL"} | None |  |
| q-8af2eb0400 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1lL"} | None |  |
| q-c2f76e1b06 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2ioON3"} | None |  |
| q-223bf95fce | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2in-NH"} | None |  |
| q-80796a2fda | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2bgTcg"} | None |  |
| q-e6915fa746 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2bgTcg"} | None |  |
| q-2f7baf72ba | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2bgTei"} | None |  |
| q-ce6b7f2217 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2bgjf5"} | None |  |
| q-c84a4ab558 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None |  |
| q-86c6dad145 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None |  |
| q-2a3173ab13 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-89e5f7b6b4 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-0c97cf2d7c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-ee3c6b8e8b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2ORrtr"} | None |  |
| q-3ec9c24159 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JLx0p9yU"} | None |  |
| q-89e5b07e43 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL81V4Qj"} | None |  |
| q-d1133bdfc2 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL8-b3Gh"} | None |  |
| q-be29852ee5 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL8xSa_z"} | None |  |
| q-66ad65e3d7 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL8xSa_z"} | None |  |
| q-ebbf1b1e10 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL-w3yMf"} | None |  |
| q-8dc58819f4 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL8xSa_z"} | None |  |
| q-61b8385124 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7ViMbT"} | None |  |
| q-faece2f439 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-c6ed9c5a35 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None |  |
| q-e3ae589cf3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-185a47b800 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL-w3yM8"} | None |  |
| q-7c3dd3b9d4 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7ViMbT"} | None |  |
| q-d3143d7825 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9OrXFR"} | None |  |
| q-5124fb64fc | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL-w3iOg"} | None |  |
| q-763068c87b | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL8vSVsk"} | None |  |
| q-e31164a306 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL-w3yNa"} | None |  |
| q-e34ff6f70f | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL88ahmW"} | None |  |
| q-fe377f9161 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL8xSa_z"} | None |  |
| q-114d93adf6 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-0a058a3632 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-72dad305fa | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-3a22c6c4a3 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAMA2AH"} | None |  |
| q-118c58491f | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9VzyYa"} | None |  |
| q-b3db7bf8db | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9OrnEx"} | None |  |
| q-fc167b9b3e | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9OrXFR"} | None |  |
| q-568adb9937 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMANA6l9"} | None |  |
| q-1284608ee6 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2ORrtv"} | None |  |
| q-eb08349116 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2ORrtv"} | None |  |
| q-836026c798 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL8vSVsl"} | None |  |
| q-6251298f0d | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None |  |
| q-3831147df2 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None |  |
| q-96ad73e420 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2lq7yE"} | None |  |
| q-ce05ef0ca4 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2lq7yE"} | None |  |
| q-f3aa4f7e1f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kqttk"} | None |  |
| q-eef6c6e147 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA5C"} | None |  |
| q-cc7c8d3e6b | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGJw17"} | None |  |
| q-99dd785a41 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA5I"} | None |  |
| q-f33baa5c85 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA0a"} | None |  |
| q-0db04c0aee | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7WjMdm"} | None |  |
| q-e17a47c5a8 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9Tx5o2"} | None |  |
| q-7dffd7324b | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9Kl3_9"} | None |  |
| q-e7fb64ab93 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7Yk7Al"} | None |  |
| q-9690dac43e | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGJw1T"} | None |  |
| q-e935227a7d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-d14493b97f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-2a6d911cca | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-8ddf55806a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-296e20ca48 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None |  |
| q-9532978d20 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None |  |
| q-be1f47aa35 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None |  |
| q-4a416bc756 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None |  |
| q-47f2f63fc0 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAWIhac"} | None |  |
| q-3aa3a40ccf | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL17AQxS"} | None |  |
| q-c0ad3ce2ad | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-8636b19fbc | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-79b505204b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-0fe3710ac5 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kqds5"} | None |  |
| q-07c7499428 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2bgTcf"} | None |  |
| q-1f929ea59e | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9MpvNN"} | None |  |
| q-e1520f79db | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9MpvNN"} | None |  |
| q-313c7b339b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7anEhk"} | None |  |
| q-8e53fb2737 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2ORrtr"} | None |  |
| q-3e8a8b12cd | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL88axkf"} | None |  |
| q-72794d5dd4 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JLx56e_Q"} | None |  |
| q-a5db126918 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JLx56e_Q"} | None |  |
| q-deed428094 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9IkK9d"} | None |  |
| q-5d0e73baf3 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9IkK9d"} | None |  |
| q-3e6baa5aaf | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None |  |
| q-b94b948080 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7BNbJC"} | None |  |
| q-ab01fdf3bd | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7BNbJC"} | None |  |
| q-34a843e29b | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA5I"} | None |  |
| q-e668e38fef | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA5I"} | None |  |
| q-371586a2ae | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAWIxak"} | None |  |
| q-d9eb0cd062 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7YlLDM"} | None |  |
| q-a4cb6d6c33 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMANA6l9"} | None |  |
| q-355223dbbe | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2ZequJ"} | None |  |
| q-3a002175c3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2Ze6tB"} | None |  |
| q-20e58165ef | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7am0gN"} | None |  |
| q-dddbba4a13 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-c0043858b9 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1ns"} | None |  |
| q-d48ef81614 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CdmD"} | None |  |
| q-b3f44d4e36 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kqttt"} | None |  |
| q-564547fed6 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQDFnY"} | None |  |
| q-de3792e676 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63C9mZ"} | None |  |
| q-ff50e97266 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63C9mM"} | None |  |
| q-e43db156c9 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQDVp3"} | None |  |
| q-3886653399 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL21_2XV"} | None |  |
| q-2358248a51 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2ORrtv"} | None |  |
| q-b89dc29977 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JLx4z3lk"} | None |  |
| q-61a85bab30 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQDVq3"} | None |  |
| q-4a608e479a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL6-JcMt"} | None |  |
| q-3c0b2a4dd1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-9d6d8ee958 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-d47904ade9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-9f9f85770b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None |  |
| q-5f2761efb1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-cd6928a37b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-3febdd85fe | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-9994ec4e6c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CdmD"} | None |  |
| q-6c1e82439c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7am0gN"} | None |  |
| q-342f0685c4 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JLx0p9yU"} | None |  |
| q-e8ee939840 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2ORrtr"} | None |  |
| q-2e4f9d3cf0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2QULdY"} | None |  |
| q-ba2ffb09c6 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL8nPsh9"} | None |  |
| q-71a47db36b | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL-w3yMh"} | None |  |
| q-90f357a3cf | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAWIxak"} | None |  |
| q-56d2af652f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CdmD"} | None |  |
| q-3b2ca50ced | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-2d649e8a9c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-a059fe68d2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-c7ccc9ced9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-e6630d8216 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQDVp0"} | None |  |
| q-40d140eb3a | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1ns"} | None |  |
| q-f84aa17813 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQDFlH"} | None |  |
| q-9ae1d66071 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9Tx5qJ"} | None |  |
| q-71fb93be1f | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9OrXFR"} | None |  |
| q-d70442825e | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9OrXFR"} | None |  |
| q-5d15ac3bf4 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JLx6_vHT"} | None |  |
| q-c81c48c037 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JLx6_vHT"} | None |  |
| q-28da597413 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9OrXFV"} | None |  |
| q-0022634949 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL20-Wda"} | None |  |
| q-f3f17b8035 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2x8I9e"} | None |  |
| q-c41914c73e | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9TypoR"} | None |  |
| q-5984e61f29 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9TypoR"} | None |  |
| q-1f5c1a24b4 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-783991b80e | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None |  |
| q-93554fd989 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAOBvlP"} | None |  |
| q-6a13256019 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9Qtr33"} | None |  |
| q-b93d05d5b3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2MP8kN"} | None |  |
| q-ccb3a541a9 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9LnlqG"} | None |  |
| q-207519102b | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA0r"} | None |  |
| q-b0d06b74f2 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIK6WOc7y0JMA-MvX6"} | None |  |
| q-8f599f60b2 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9Kmn8b"} | None |  |
| q-d2726d7ead | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGKA0K"} | None |  |
| q-a83f26c83c | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIK6WOc7y0JMA_NKaC"} | None |  |
| q-251f6de7fe | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7YlLAM"} | None |  |
| q-3bbf9d8090 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL-w3yNV"} | None |  |
| q-b884c46afd | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7Yk7C5"} | None |  |
| q-36a52f6543 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-2e55af7910 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None |  |
| q-fd70f0a1d6 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1ns"} | None |  |
| q-620393280e | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQDFmw"} | None |  |
| q-6d8c07b447 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL8-bHCF"} | None |  |
| q-2b6b118ae2 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9MpvNN"} | None |  |
| q-6ac94aced5 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9TypoZ"} | None |  |
| q-0d6264ede8 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9OrnEj"} | None |  |
| q-880dde580b | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGJw1d"} | None |  |
| q-eda1309464 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGJw1g"} | None |  |
| q-fa9b630734 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9LnlqF"} | None |  |
| q-abde8df0c5 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIK6WOc7y0JMA_NaZg"} | None |  |
| q-04d14f4b86 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGJw1f"} | None |  |
| q-d130e55179 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMDGJw1g"} | None |  |
| q-9b149eb235 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-636fc516d7 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-bd93f1966e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CdmD"} | None |  |
| q-daaecf4314 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2lq7zj"} | None |  |
| q-283ad43a66 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None |  |
| q-75921d0bdc | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMANA6lp"} | None |  |
| q-4c5e9c14f4 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JLx56e_Q"} | None |  |
| q-d01af1e34b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JLx56e_Q"} | None |  |
| q-68495f9da9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CNnH"} | None |  |
| q-9dffd1ad5e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CAlf"} | None |  |
| q-078c456891 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kp9uH"} | None |  |
| q-f9207b2346 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAOAxHj"} | None |  |
| q-2b009539e4 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL-w3yMK"} | None |  |
| q-91d1c58747 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL-w3iO6"} | None |  |
| q-2a7ce9510a | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL-w3iOa"} | None |  |
| q-104e556d1f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL18GdOb"} | None |  |
| q-04722deb4c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2bgzd1"} | None |  |
| q-0eb29bba42 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2bgjeM"} | None |  |
| q-cdcd3ddd73 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-8f1bfc1506 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-0942de9abb | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-e987130983 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1ns"} | None |  |
| q-c3ae7a801f | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQDFnY"} | None |  |
| q-64a8e09738 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQDVoX"} | None |  |
| q-4410830738 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CdmD"} | None |  |
| q-890ef89316 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CdmN"} | None |  |
| q-1410173550 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63CtkV"} | None |  |
| q-9efa6153d3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2kqttt"} | None |  |
| q-6ad047ae76 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7LXG4H"} | None |  |
| q-f0553022fb | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2ZequA"} | None |  |
| q-1d935948af | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2OR7uU"} | None |  |
| q-4e5d42164a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JLx41usR"} | None |  |
| q-ae282b3fd7 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9FgwRA"} | None |  |
| q-b3f026202e | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9OrXFP"} | None |  |
| q-950754f897 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL8-bHB-"} | None |  |
| q-1d506399c8 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMANA6l9"} | None |  |
| q-ee37e0115a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2Ze6tB"} | None |  |
| q-d45dfaccc7 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2VYgwB"} | None |  |
| q-9e42db4426 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAQC1mz"} | None |  |
| q-3021939b3e | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JL8F_6E7"} | None |  |
| q-e3a7f9f2cd | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMANA6lp"} | None |  |
| q-5999d7fafc | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9Qt70r"} | None |  |
| q-87943bc47c | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL9Qt70r"} | None |  |
| q-a83e45927b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2ioON3"} | None |  |
| q-e1de768fa1 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFIKaWOc7y0JL-w3iOg"} | None |  |
| q-2e75539d5c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2in-NH"} | None |  |
| q-453d4aeb5f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2bgTcf"} | None |  |
| q-b2a5fd3c01 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL63C9mZ"} | None |  |
| q-ef0661ceab | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL69HSbI"} | None |  |
| q-9e5047dacd | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7am0gN"} | None |  |
| q-db05e0c70b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7YkrCD"} | None |  |
| q-db003a99c0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL2v5uV8"} | None |  |
| q-5da8b73fb3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7VhsbV"} | None |  |
| q-465ef02d16 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JLx6_ejg"} | None |  |
| q-da50abeecd | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFIKqWOc7y0JMAWJWsz"} | None |  |
| q-e6e4d24914 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFIKKWOc7y0JL7Wi8c6"} | None |  |

## Verification

Evidence items cited: 253; confirmed against the stored events: 253; rejected: 0. Each item was re-fetched with get_event; it is confirmed only if the event exists, the cited field holds the cited value, and the cited query_id is a query of this run that returned that event.
Evidence sent back to the agents for correction during the run: 1 item(s) in 1 submission(s) (one correction round each; what still failed was rejected).

## Limitations

- Findings describe what the stored logs show; activity these sources did not log cannot be seen.
- Datasets with non-overlapping time windows (see Data examined) were analysed separately.
- Long field values are shortened in this report; full events are retrievable by _index/_id.
