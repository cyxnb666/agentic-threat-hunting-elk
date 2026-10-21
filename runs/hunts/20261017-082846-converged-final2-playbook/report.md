# Threat hunt report — 20261017-082846-converged-final2-playbook

**Hypothesis:** An adversary who compromised Windows hosts in this network stole credentials from them (MITRE ATT&CK tactic: Credential Access).

**Verdict: Confirmed** — 7 in-scope incident(s) of verified malicious findings (confidence >= medium): I01 T1003.001 (F01, F08, F16, F26, F27, F39, F43, F49), I03 T1056.001 (F62), I04 T1056.004 (F09), I05 T1552 (F04, F35), I06 T1552.001 (F34, F60), I07 T1552.004 (F33, F58, F61), I08 T1555.004 (F40)

Verdict method: rules over verified evidence (Confirmed if >=1 in-scope incident of verified malicious findings (confidence >= medium); Inconclusive if only suspicious incidents or coverage gaps; Refuted if full coverage and no malicious/suspicious finding)

| Run | Value |
|---|---|
| Profile | converged (thinking=False, temperature=0.0) |
| Model | deepseek-flash |
| Started / finished (UTC) | 2026-10-17T00:28:46+00:00 / 2026-10-17T00:36:50+00:00 (484.0 s) |
| LLM calls / tokens | 126 / {'prompt': 3257650, 'completion': 80156} |
| MCP tool calls | 1155 (server tools: list_data_sources, get_fields, search, count, aggregate, timeline, esql, get_event, get_registry) |
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
| I01 | T1003.001 | yes | malicious/high | F01, F08, F16, F26, F27, F39, F43, F49 | PowerShell and WinRM host processes opened LSASS with full memory-read access on scranton and nashua |
| I02 | T1003.005 | yes | suspicious/medium | F02 | LSASS wrote cached domain credential entry HKLM\SECURITY\Cache\NL$1 on nashua |
| I03 | T1056.001 | yes | malicious/high | F62 | Keystroke logging (Get-Keystrokes) and clipboard capture on scranton |
| I04 | T1056.004 | yes | malicious/high | F09 | Obfuscated PowerShell resolving native APIs via GetProcAddress/UnsafeNativeMethods on scranton |
| I05 | T1552 | yes | malicious/high | F04, F35 | Credential-harvesting and exfiltration toolkit staged in SysinternalsSuite on scranton |
| I06 | T1552.001 | yes | malicious/high | F34, F60 | Hardcoded credentials in PowerShell scripts and PsExec command line on scranton |
| I07 | T1552.004 | yes | malicious/high | F33, F58, F61 | Get-PrivateKeys exports all LocalMachine certificates to password-protected .pfx files on scranton |
| I08 | T1555.004 | yes | malicious/medium | F40 | LSASS full-access handles consistent with Windows Credential Manager / DPAPI secret harvesting |
| I09 | T1558.003 | yes | suspicious/medium | F50 | Kerberos TGS requests for krbtgt and host SPNs by pbeesly (RC4) |
| I10 | out-of-scope:T1021 | no | suspicious/medium | F07 | PsExec with cleartext password and sdelete on scranton/nashua (not network sniffing) |

## Findings

### F04 · malicious / high · T1003 · Adversary credential-access tooling on scranton (pbeesly) — exfil staging script and LSASS access

Evidence status: **verified**

The pbeesly account on scranton.dmevals.local ran a PowerShell script block 'Invoke-Exfil' (ScriptBlock ID b2b03a9c-43f0-4285-837d-f22d4600b2ae, Path C:\Program Files\SysinternalsSuite\psversion.ps1) that compresses user files with a password and copies them to a WebDAV share at \\192.168.0.4\webdav using hardcoded credentials (cozy / MyCozyPassw0rd!). The same account's PowerShell activity includes file-collection targeting *pass*, *login*, *admin*, *vpn* files. Combined with the LSASS full-access opens by PowerShell on the same host, this is consistent with an adversary performing credential access and collection.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\psversion.ps1 | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZCgBha | q-41f9033a6d | ok |
| 2 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | user.name | pbeesly | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZCgBha | q-41f9033a6d | ok |
| 3 | 2020-05-02 02:56:17.000Z | scranton.dmevals.local | windows.powershell | process.command_line | $env:APPDATA;$files=ChildItem -Path $env:USERPROFILE\ -Include *.doc,*.xps,*.xls,*.ppt,*.pps,*.wps,*.wpd,*.ods,*.odt,*.lwp,*.jtd,*.pdf,*.zip,*.rar,*.docx,*.url,… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZWqdCw | q-2f36b17452 | ok |

### F01 · malicious / high · T1003.001 · PowerShell and PowerShell Remoting processes opened LSASS with full memory-read access on scranton and nashua

Evidence status: **verified**

On scranton.dmevals.local, PowerShell.exe (PID 2976) opened lsass.exe (PID 736) with GrantedAccess 0x1F3FFF at 2020-05-02T03:05:16.623Z and 0x1FFFFF at 03:05:16.654Z — full access masks that include 'Read from process memory', the classic LSASS-dump signature. On nashua.dmevals.local, wsmprovhost.exe (PID 7720, the PowerShell Remoting host) opened lsass.exe (PID 728) with GrantedAccess 0x1F3FFF at 03:09:29.430Z, and its CallTrace shows the PowerShell Commands.Management native image, indicating a PowerShell-based tool performing the access. Windows Security 4656 on scranton shows the pbeesly account via powershell.exe requesting AccessMask 0x1F3FFF on \Device\HarddiskVolume2\Windows\System32\lsass.exe. This is consistent with an adversary dumping LSASS memory for credential theft.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTka0Gj | q-8db819feb0 | ok |
| 2 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTka0Gj | q-8db819feb0 | ok |
| 3 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTka0Gm | q-f00904a76a | ok |
| 4 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHNH1uOFchItUHCTY0 | q-900138bbba | ok |
| 5 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHNH1uOFchItUHCTY0 | q-900138bbba | ok |
| 6 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | win.AccessMask | 0x1f3fff | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItaDOKA_ | q-0dcca098ce | ok |
| 7 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | win.SubjectUserName | pbeesly | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItaDOKA_ | q-0dcca098ce | ok |

### F62 · malicious / high · T1056.001 · Keystroke logging (Get-Keystrokes) and clipboard capture on scranton

Evidence status: **verified**

On scranton.dmevals.local, user pbeesly ran Get-Keystrokes (PowerSploit/Empire keylogger that logs keys, time and active window) as a background job, and separately ran Get-Clipboard to capture clipboard contents. These are input-capture credential-theft actions not covered by the anchors.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:06:59.000Z | scranton.dmevals.local | windows.powershell | message | Creating Scriptblock text (1 of 1):  Get-Keystrokes;Start-Sleep -Seconds 15;View-Job -JobName "Keystrokes"    ScriptBlock ID: 7c8ce66d-dd1a-4a72-8e88-42dd7ff48c… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZRk1C1 | q-f88e5e7844 | ok |
| 2 | 2020-05-02 03:06:42.000Z | scranton.dmevals.local | windows.powershell | message | Creating Scriptblock text (1 of 1):  Get-Clipboard    ScriptBlock ID: df281a21-c9e5-4e45-bd4b-a0d36c3232a6  Path:  | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZRk1Cy | q-f88e5e7844 | ok |

### F08 · malicious / high · T1056.004 · PowerShell opens LSASS with full-access rights (0x1fffff / 0x1f3fff) on scranton

Evidence status: **verified**

On scranton.dmevals.local, PowerShell.exe (PID 3876, user pbeesly) opened lsass.exe with GrantedAccess 0x1fffff and 0x1f3fff at 2020-05-02T03:05:16Z — full process access including read/write memory and duplicate-handle rights, the classic signature of credential API hooking / LSASS memory access. The matching Security 4656 event shows pbeesly's powershell requesting AccessMask 0x1F3FFF on \Device\HarddiskVolume2\Windows\System32\lsass.exe. This is not the benign 0x1000 query-information access seen from svchost.exe.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:01:03.622Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1000 | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTtmJQ5 | q-d234a6e259 | ok |
| 2 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | win.AccessMask | 0x1f3fff | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItaDOKA_ | q-479ce50d19 | ok |
| 3 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | win.ObjectName | \Device\HarddiskVolume2\Windows\System32\lsass.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItaDOKA_ | q-479ce50d19 | ok |
| 4 | 2020-05-02 03:01:03.622Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\WindowsPowerShell\v1.0\powershell.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTtmJQ5 | q-d234a6e259 | ok |

### F09 · malicious / high · T1056.004 · Obfuscated PowerShell using GetProcAddress / UnsafeNativeMethods on scranton

Evidence status: **verified**

At 2020-05-02T03:21:29Z on scranton.dmevals.local, user pbeesly executed an obfuscated PowerShell script block (function 'jzI' with random parameter names) that resolves Microsoft.Win32.UnsafeNativeMethods and calls GetProcAddress via reflection — a technique used to dynamically resolve and invoke native APIs (e.g. for hooking/credential access) while evading static detection. The same session also ran a gzip+base64 encoded scriptblock launched via a hidden powershell process, and 'Start-Process C:\Windows\System32\hostui.exe -verb runas' for elevation.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:21:29.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function jzI {  	Param ($yKR, $cq)		  	$vvA = ([AppDomain]::CurrentDomain.GetAssemblies() \| Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZRkUVV | q-01364892a7 | ok |
| 2 | 2020-05-02 03:21:29.000Z | scranton.dmevals.local | windows.powershell | user.name | pbeesly | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZRkUVV | q-01364892a7 | ok |
| 3 | 2020-05-02 03:21:29.000Z | scranton.dmevals.local | windows.powershell | host.name | scranton.dmevals.local | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZRkUVV | q-01364892a7 | ok |

### F16 · malicious / high · T1110.002 · LSASS memory accessed with PROCESS_ALL_ACCESS by steganographic PowerShell payload on scranton

Evidence status: **verified**

On scranton.dmevals.local, powershell.exe (PID 2976, user DMEVALS\pbeesly, IntegrityLevel High) was launched by control.exe with '-noni -noexit -ep bypass -window hidden' and executed a steganographic payload that decodes bytes from C:\Users\pbeesly\Downloads\monkey.png and IEX's them. The same process (SourceProcessId 2976) then opened lsass.exe (PID 736) with GrantedAccess 0x1FFFFF (PROCESS_ALL_ACCESS) and 0x1f3fff at 03:05:16Z — the classic signature of in-memory credential dumping (e.g. MiniDumpWriteDump) to obtain password hashes for offline cracking. A separate 4104 script block on scranton defines Invoke-Exfil, which compresses the user's Downloads with a password and copies the archive to a WebDAV share at \\192.168.0.4\webdav using hardcoded credentials (cozy / MyCozyPassw0rd!). This is attacker credential-access tooling, not brute force.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTka0Gm | q-8bf4561309 | ok |
| 2 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.TargetImage | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTka0Gm | q-8bf4561309 | ok |
| 3 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTka0Gm | q-8bf4561309 | ok |
| 4 | 2020-05-02 02:58:44.325Z | scranton.dmevals.local | windows.sysmon | process.command_line | "PowerShell.exe" -noni -noexit -ep bypass -window hidden -c "sal a New-Object;Add-Type -AssemblyName 'System.Drawing'; $g=a System.Drawing.Bitmap('C:\Users\pbee… | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHNH1uOFchItQB61zZ | q-2353556a8d | ok |
| 5 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZCgBha | q-37db517e2c | ok |

### F23 · malicious / high · T1187 · WebDAV forced-authentication (NTLM leak) from scranton to attacker host 192.168.0.4

Evidence status: **NOT verified (7/8 evidence items)** — excluded from the verdict

On 2020-04-30 between 00:32:14 and 00:32:21 UTC, host 10.0.1.4 (scranton) attempted SMB to 192.168.0.4 on ports 445 and 139; every attempt was rejected (conn_state REJ, 0 bytes), showing the target does not run SMB. The client then fell back to WebDAV over HTTP port 80: a DavClnt OPTIONS to '/' returned 403, followed by Microsoft-WebDAV-MiniRedir/10.0.18362 OPTIONS and PROPFIND requests to /webdav, /webdav/ and /webdav/OfficeSupplies.7z. The first PROPFIND request carried an AUTHORIZATION header (client_header_names includes AUTHORIZATION) and the server answered 401 Unauthorized on the OfficeSupplies.7z path, i.e. the victim's credentials were transmitted to the attacker-controlled WebDAV listener. This is the classic forced-authentication chain (SCF/URL file or UNC path pointing at a WebDAV share) used to capture NTLM hashes. The activity is confined to the zeek window (2020-04-30) which does not overlap the Windows host logs (2020-05-02).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-04-30 00:32:18.095Z | simplerockbuild.simplerock.lan | zeek | user_agent.original | DavClnt | .ds-logs-zeek-default-2026.10.17-000001 / AaFHNX1uOFchItbgrYjF | q-c900f577e7 | ok |
| 2 | 2020-04-30 00:32:18.095Z | simplerockbuild.simplerock.lan | zeek | http.request.method | OPTIONS | .ds-logs-zeek-default-2026.10.17-000001 / AaFHNX1uOFchItbgrYjF | q-c900f577e7 | ok |
| 3 | 2020-04-30 00:32:21.535Z | simplerockbuild.simplerock.lan | zeek | zeek.client_header_names | ["CONNECTION", "USER-AGENT", "DEPTH", "TRANSLATE", "CONTENT-LENGTH", "HOST", "AUTHORIZATION"] | .ds-logs-zeek-default-2026.10.17-000001 / AaFHNX1uOFchItbgrYjN | q-6de615b455 | FAILED: claimed value differs from the stored value |
| 4 | 2020-04-30 00:32:21.535Z | simplerockbuild.simplerock.lan | zeek | user_agent.original | Microsoft-WebDAV-MiniRedir/10.0.18362 | .ds-logs-zeek-default-2026.10.17-000001 / AaFHNX1uOFchItbgrYjN | q-6de615b455 | ok |
| 5 | 2020-04-30 00:32:21.895Z | simplerockbuild.simplerock.lan | zeek | url.original | /webdav/OfficeSupplies.7z | .ds-logs-zeek-default-2026.10.17-000001 / AaFHNX1uOFchItbgrYgN | q-9cd66f00c2 | ok |
| 6 | 2020-04-30 00:32:21.895Z | simplerockbuild.simplerock.lan | zeek | http.response.status_code | 401 | .ds-logs-zeek-default-2026.10.17-000001 / AaFHNX1uOFchItbgrYgN | q-9cd66f00c2 | ok |
| 7 | 2020-04-30 00:32:14.891Z | simplerockbuild.simplerock.lan | zeek | zeek.conn_state | REJ | .ds-logs-zeek-default-2026.10.17-000001 / AaFHNX1uOFchItbgrYih | q-bb807a7b0c | ok |
| 8 | 2020-04-30 00:32:14.891Z | simplerockbuild.simplerock.lan | zeek | destination.port | 445 | .ds-logs-zeek-default-2026.10.17-000001 / AaFHNX1uOFchItbgrYih | q-bb807a7b0c | ok |

### F26 · malicious / high · T1212 · LSASS memory accessed with PROCESS_ALL_ACCESS by PowerShell on scranton.dmevals.local

Evidence status: **verified**

On 2020-05-02 at 03:05:16, PowerShell.exe (PID 2976, user pbeesly) opened lsass.exe (PID 736) with GrantedAccess 0x1FFFFF (PROCESS_ALL_ACCESS) and 0x1F3FFF on scranton.dmevals.local. This is the canonical signature of in-memory credential dumping (e.g. MiniDumpWriteDump / reflective loader). It coincides with a PowerShell script block that builds a reflective shellcode loader (GetProcAddress/GetModuleHandle/ReflectedDelegate + base64 shellcode), and with keystroke-logging, screen-capture and clipboard-theft activity on the same host — consistent with an adversary exploiting/abusing the host to steal credentials.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTka0Gm | q-bf1330a018 | ok |
| 2 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.TargetImage | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTka0Gm | q-bf1330a018 | ok |
| 3 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTka0Gm | q-bf1330a018 | ok |
| 4 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTka0Gj | q-bf1330a018 | ok |
| 5 | 2020-05-02 03:21:29.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function jzI {  	Param ($yKR, $cq)		  	$vvA = ([AppDomain]::CurrentDomain.GetAssemblies() \| Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZRkUVV | q-d531e089c4 | ok |
| 6 | 2020-05-02 03:06:59.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | Get-Keystrokes;Start-Sleep -Seconds 15;View-Job -JobName "Keystrokes" | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZRk1C1 | q-d531e089c4 | ok |

### F27 · malicious / high · T1212 · WinRM host process (wsmprovhost.exe) accessed LSASS with 0x1F3FFF on nashua.dmevals.local

Evidence status: **verified**

On 2020-05-02 at 03:09:29, wsmprovhost.exe (PID 7720, the WinRM remote-shell host, user pbeesly) opened lsass.exe (PID 728) with GrantedAccess 0x1F3FFF on nashua.dmevals.local. The call trace shows PowerShell command-management assemblies, i.e. a remote PowerShell session reading LSASS memory. Immediately after, the same session enumerated processes with usernames and collected/archived credential-related files (pass/login/admin/vpn patterns) into working.zip — consistent with credential access via a remotely-driven exploitation/abuse of the host.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHNH1uOFchItUHCTY0 | q-bf1330a018 | ok |
| 2 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHNH1uOFchItUHCTY0 | q-bf1330a018 | ok |
| 3 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.TargetImage | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHNH1uOFchItUHCTY0 | q-bf1330a018 | ok |
| 4 | 2020-05-02 03:15:59.000Z | nashua.dmevals.local | windows.powershell | win.ScriptBlockText | $env:APPDATA;$files=ChildItem -Path $env:USERPROFILE\ -Include *.doc,*.xps,*.xls,*.ppt,*.pps,*.wps,*.wpd,*.ods,*.odt,*.lwp,*.jtd,*.pdf,*.zip,*.rar,*.docx,*.url,… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZLhp5i | q-e668a2090c | ok |

### F35 · malicious / high · T1552 · Credential-harvesting toolkit (keystrokes, clipboard, screenshots) staged in SysinternalsSuite

Evidence status: **verified**

On scranton.dmevals.local, user pbeesly ran a multi-function PowerShell toolkit from C:\Program Files\SysinternalsSuite\psversion.ps1 that includes Get-Keystrokes, Get-Clipboard, Invoke-ScreenCapture and Invoke-Exfil (compresses Downloads to OfficeSupplies.7z and copies it to a WebDAV share \\192.168.0.4\webdav). This is credential collection from the host, consistent with the T1552 family.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:06:59.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | Get-Keystrokes;Start-Sleep -Seconds 15;View-Job -JobName "Keystrokes" | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZRk1C1 | q-06c46e63fe | ok |
| 2 | 2020-05-02 03:06:42.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | Get-Clipboard | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZRk1Cy | q-06c46e63fe | ok |
| 3 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZCgBha | q-fd932dd1e8 | ok |

### F34 · malicious / high · T1552.001 · Hardcoded credentials in PowerShell scripts and PsExec command line

Evidence status: **verified**

On scranton.dmevals.local, user pbeesly executed PsExec64.exe four times passing the plaintext password of dmevals\pbeesly on the command line (-p Fl0nk3rt0n!T0by) to run C:\Windows\Temp\python.exe on \\NASHUA. The same host's PowerShell scripts also embed plaintext credentials (Invoke-Exfil uses $Password = "MyCozyPassw0rd!" and a 7-Zip archive password "lolol"). These are credentials-in-files/command-line exposures used to move laterally.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:18.784Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\PsExec64.exe" -accepteula \\NASHUA -u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTVGglR | q-088e5cdd58 | ok |
| 2 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZCgBha | q-fd932dd1e8 | ok |
| 3 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\psversion.ps1 | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZCgBha | q-fd932dd1e8 | ok |

### F60 · malicious / high · T1552.001 · Hardcoded credentials in PowerShell exfil script and PsExec command line on scranton/nashua

Evidence status: **verified**

On scranton.dmevals.local, user pbeesly ran a PowerShell exfil function (Invoke-Exfil, from C:\Program Files\SysinternalsSuite\psversion.ps1) that embeds a hardcoded credential ($UserName = "cozy", $Password = "MyCozyPassw0rd!") to map a WebDAV share at \\192.168.0.4\webdav and copy the staged archive. Separately, PsExec64.exe was launched four times from PowerShell with a cleartext password (-u dmevals\pbeesly -p Fl0nk3rt0n!T0by) to run C:\Windows\Temp\python.exe on \\NASHUA. These are new credential-in-script/command-line artifacts beyond the anchors.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZCgBha | q-f226502a28 | ok |
| 2 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZCgBha | q-f226502a28 | ok |
| 3 | 2020-05-02 03:11:18.784Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\PsExec64.exe" -accepteula \\NASHUA -u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTVGglR | q-ef36a07188 | ok |

### F33 · malicious / high · T1552.004 · PowerShell Get-PrivateKeys exports all LocalMachine certificates to .pfx files

Evidence status: **verified**

On scranton.dmevals.local, user pbeesly ran a PowerShell script (loaded from C:\Program Files\SysinternalsSuite\readme.ps1 / psversion.ps1) defining Get-PrivateKeys, which enumerates cert:\LocalMachine recursively and exports every certificate with a thumbprint to a randomly-named .pfx in the user's Downloads folder, protected by the hardcoded password "saribas". This is direct private-key/certificate theft (T1552.004).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZSl2ML | q-77c941ede1 | ok |
| 2 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\readme.ps1 | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZSl2ML | q-77c941ede1 | ok |
| 3 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | Get-PrivateKeys | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZRlVDe | q-06c46e63fe | ok |

### F61 · malicious / high · T1552.004 · Get-PrivateKeys exports LocalMachine certificates to .pfx on scranton

Evidence status: **verified**

On scranton.dmevals.local, user pbeesly invoked Get-PrivateKeys, a function that enumerates cert:\LocalMachine recursively and exports each certificate with a private key to a randomly named .pfx file under the user profile, protected by the hardcoded password "saribas". A resulting file C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx was created by powershell.exe. This is new file-level evidence of the certificate/private-key theft beyond the anchor.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZSl2ML | q-f88e5e7844 | ok |
| 2 | 2020-05-02 03:04:57.460Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTkbEF9 | q-5e2dde62da | ok |

### F39 · malicious / high · T1555 · PowerShell and WinRM host processes opened LSASS with full-access rights (credential dumping)

Evidence status: **verified**

On 2020-05-02, user pbeesly's PowerShell.exe on scranton.dmevals.local (03:05:16) and wsmprovhost.exe on nashua.dmevals.local (03:09:29) opened lsass.exe with GrantedAccess 0x1fffff (PROCESS_ALL_ACCESS) and 0x1f3fff — the access masks used to read LSASS memory and harvest credentials. The same activity is corroborated by Windows Security object-access auditing (4663/4656) on the lsass.exe object with AccessMask 0x1fffff/0x1f3fff by the same processes/users. This is not the routine 0x1000/0x1400 query access seen from svchost/services; it is deliberate full-access to the credential store.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTka0Gm | q-3123768ab3 | ok |
| 2 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTka0Gm | q-3123768ab3 | ok |
| 3 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHNH1uOFchItUHCTY0 | q-3123768ab3 | ok |
| 4 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHNH1uOFchItUHCTY0 | q-3123768ab3 | ok |
| 5 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | win.AccessMask | 0x1fffff | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItaDOKB- | q-0d92c22d74 | ok |
| 6 | 2020-05-02 03:09:29.000Z | nashua.dmevals.local | windows.security | win.ProcessName | C:\Windows\System32\wsmprovhost.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItZ8FLV1 | q-0d92c22d74 | ok |

### F40 · malicious / medium · T1555.004 · LSASS full-access handles consistent with Windows Credential Manager / DPAPI secret harvesting

Evidence status: **verified**

The 0x1fffff/0x1f3fff handles to lsass.exe opened by pbeesly's PowerShell.exe (scranton, 03:05:16) and wsmprovhost.exe (nashua, 03:09:29) give read access to LSASS memory where Windows Credential Manager / DPAPI master-key material resides. The same user pbeesly also ran a PowerShell script (Get-PrivateKeys) exporting certificate private keys, showing a credential-harvesting campaign. No legitimate Credential Manager cmdlet (cmdkey/vaultcmd) activity was observed, but the LSASS access is the credential-store access path.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | win.AccessMask | 0x1f3fff | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItaDOKA_ | q-0d92c22d74 | ok |
| 2 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | win.ProcessName | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItaDOKA_ | q-0d92c22d74 | ok |
| 3 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | user.name | pbeesly | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItaDOKA_ | q-0d92c22d74 | ok |
| 4 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZSl2ML | q-a056e6e882 | ok |

### F43 · malicious / high · T1556 · LSASS accessed with full access rights by PowerShell on scranton (credential theft, not auth-process modification)

Evidence status: **verified**

On scranton.dmevals.local, PowerShell.exe (PID 2976) opened lsass.exe (PID 736) with GrantedAccess 0x1FFFFF (PROCESS_ALL_ACCESS) and 0x1F3FFF at 2020-05-02T03:05:16, the classic handle rights used to read credential material from LSASS. The same host/user (pbeesly) ran a steganographic PowerShell loader (monkey.png), a Get-PrivateKeys certificate-export function, and an Invoke-Exfil function. This is credential access via LSASS memory access (T1003.001), not modification of the authentication process itself; no password filter, DC auth backdoor, reversible-encryption, MFA, hybrid-identity or network-provider-DLL artifacts were observed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTka0Gm | q-19de71daec | ok |
| 2 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTka0Gm | q-19de71daec | ok |
| 3 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTka0Gj | q-8683b7cefa | ok |
| 4 | 2020-05-02 02:58:44.325Z | scranton.dmevals.local | windows.sysmon | process.command_line | "PowerShell.exe" -noni -noexit -ep bypass -window hidden -c "sal a New-Object;Add-Type -AssemblyName 'System.Drawing'; $g=a System.Drawing.Bitmap('C:\Users\pbee… | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHNH1uOFchItQB61zZ | q-a74c6e9d47 | ok |

### F49 · malicious / high · T1558 · LSASS memory access by PowerShell and WinRM host on scranton/nashua (credential theft precursor)

Evidence status: **verified**

On scranton.dmevals.local, PowerShell.exe (PID 2976, SYSTEM) opened lsass.exe with GrantedAccess 0x1FFFFF (PROCESS_ALL_ACCESS) and 0x1F3FFF at 2020-05-02T03:05:16, the access mask used by credential-dumping tooling to read LSASS secrets. On nashua.dmevals.local, wsmprovhost.exe (PID 7720, the WinRM remote-PowerShell host) opened lsass.exe with 0x1F3FFF at 03:09:29. The scranton host concurrently ran heavily obfuscated PowerShell (VirtualAlloc/CreateThread shellcode loader, IEX of a payload decoded from a bitmap, and staging of files matching *pass*/*login*/*admin* into an archive), consistent with an adversary harvesting credentials from compromised hosts.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTka0Gm | q-1b4fb686e2 | ok |
| 2 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.TargetImage | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTka0Gm | q-1b4fb686e2 | ok |
| 3 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTka0Gj | q-bd68b78e17 | ok |
| 4 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHNH1uOFchItUHCTY0 | q-46852bbfdf | ok |
| 5 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHNH1uOFchItUHCTY0 | q-46852bbfdf | ok |
| 6 | 2020-05-02 02:58:45.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | $cFIrwwpZzGzU = @"  [DllImport("kernel32.dll")]  public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZWqNA3 | q-28f685f0bf | ok |
| 7 | 2020-05-02 02:58:45.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | sal a New-Object;Add-Type -AssemblyName 'System.Drawing'; $g=a System.Drawing.Bitmap('C:\Users\pbeesly\Downloads\monkey.png');$o=a Byte[] 4480;for($i=0; $i -le … | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZWqNDf | q-28f685f0bf | ok |
| 8 | 2020-05-02 02:56:17.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | $env:APPDATA;$files=ChildItem -Path $env:USERPROFILE\ -Include *.doc,*.xps,*.xls,*.ppt,*.pps,*.wps,*.wpd,*.ods,*.odt,*.lwp,*.jtd,*.pdf,*.zip,*.rar,*.docx,*.url,… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZWqdCw | q-28f685f0bf | ok |

### F58 · malicious / high · T1649 · PowerShell Get-PrivateKeys exports all LocalMachine certificates to password-protected .pfx files on scranton

Evidence status: **verified**

On scranton.dmevals.local, user pbeesly executed a PowerShell script block (Event 4104, ScriptBlock ID 9d153741-75c3-4062-afe3-aeca0aee611b) defining a function Get-PrivateKeys that recursively enumerates cert:\LocalMachine, and for every certificate with a Thumbprint exports it via Export-PfxCertificate to a randomly-named .pfx file under $env:USERPROFILE\Downloads, protected by the hardcoded plaintext password "saribas", suppressing errors. The script was masqueraded as C:\Program Files\SysinternalsSuite\readme.ps1. Sysmon confirms the resulting file C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx was created (Event 11) at 03:04:57 and then deleted (Event 23) at 03:08:51 by the same powershell.exe process, consistent with staging and cleanup of stolen private keys/certificates for later use in authentication (Steal or Forge Authentication Certificates).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZSl2ML | q-959a0e7658 | ok |
| 2 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZSl2ML | q-959a0e7658 | ok |
| 3 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\readme.ps1 | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZSl2ML | q-959a0e7658 | ok |
| 4 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | user.name | pbeesly | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZSl2ML | q-959a0e7658 | ok |
| 5 | 2020-05-02 03:04:57.460Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTkbEF9 | q-e98d22506c | ok |
| 6 | 2020-05-02 03:08:51.489Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTWIbqw | q-39115298c8 | ok |
| 7 | 2020-05-02 03:08:51.489Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\WindowsPowerShell\v1.0\powershell.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTWIbqw | q-39115298c8 | ok |

### F02 · suspicious / medium · T1003.005 · LSASS wrote cached domain credential entry HKLM\SECURITY\Cache\NL$1 on nashua

Evidence status: **verified**

On nashua.dmevals.local, lsass.exe (PID 728) set the registry value HKLM\SECURITY\Cache\NL$1 (Details: Binary Data) repeatedly between 2020-05-02T03:11:40Z and 03:15:03Z. The SECURITY\Cache\NL$ keys hold cached domain credentials (DCC/DCC2 hashes). While lsass legitimately updates this key on interactive logon, the repeated writes clustered in the same window as the LSASS memory access on the same host are consistent with cached-credential manipulation/access activity.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:40.144Z | nashua.dmevals.local | windows.sysmon | win.TargetObject | HKLM\SECURITY\Cache\NL$1 | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTVGQnT | q-a4e5153170 | ok |
| 2 | 2020-05-02 03:11:40.144Z | nashua.dmevals.local | windows.sysmon | win.Image | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTVGQnT | q-a4e5153170 | ok |

### F07 · suspicious / medium · T1040 · Adjacent credential-access activity (PsExec with cleartext password, sdelete) is not network sniffing

Evidence status: **verified**

While hunting T1040 I observed unrelated but notable activity on scranton.dmevals.local: user pbeesly ran PsExec64.exe from SysinternalsSuite against \\NASHUA passing the cleartext password Fl0nk3rt0n!T0by, spawning C:\Windows\Temp\python.exe on nashua via PSEXESVC (repeated ~4x), and ran sdelete64.exe to wipe files including C:\programdata\victim\???cod.3aka3.scr. This is credential/lateral-movement activity, not packet sniffing, so it does not satisfy T1040; recorded here for context only.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:18.784Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\PsExec64.exe" -accepteula \\NASHUA -u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTVGglR | q-d455125961 | ok |
| 2 | 2020-05-02 03:11:40.213Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTVGQmt | q-d455125961 | ok |
| 3 | 2020-05-02 03:02:04.324Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\sdelete64.exe" /accepteula C:\programdata\victim\???cod.3aka3.scr | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTpgCep | q-d455125961 | ok |

### F50 · suspicious / medium · T1558.003 · Kerberos TGS requests for krbtgt and host SPNs by pbeesly (RC4)

Evidence status: **verified**

On newyork.dmevals.local the account pbeesly@DMEVALS.LOCAL requested Kerberos service tickets (event 4769) for the krbtgt service (Service ID S-1-5-21-1830255721-3727074217-2423397540-502) at 2020-05-02T03:04:04 and repeatedly for host SPNs NEWYORK$/NASHUA$ between 03:04 and 03:15, all with TicketEncryptionType 0x12 (RC4). The SCRANTON$ machine account also requested krbtgt TGS at 03:19:13/03:19:15. RC4 TGS requests for krbtgt are consistent with Kerberoasting-style ticket requests, though krbtgt TGS requests also occur in normal DC replication traffic, so this is suspicious rather than confirmed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:04.000Z | newyork.dmevals.local | windows.security | win.ServiceName | krbtgt | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItaDOKC- | q-9785d858da | ok |
| 2 | 2020-05-02 03:04:04.000Z | newyork.dmevals.local | windows.security | win.TicketEncryptionType | 0x12 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItaDOKC- | q-9785d858da | ok |
| 3 | 2020-05-02 03:04:04.000Z | newyork.dmevals.local | windows.security | user.name | pbeesly@DMEVALS.LOCAL | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItaDOKC- | q-9785d858da | ok |
| 4 | 2020-05-02 03:19:13.000Z | newyork.dmevals.local | windows.security | win.ServiceName | krbtgt | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItV3-aXQ | q-9785d858da | ok |
| 5 | 2020-05-02 03:19:13.000Z | newyork.dmevals.local | windows.security | user.name | SCRANTON$@DMEVALS.LOCAL | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItV3-aXQ | q-9785d858da | ok |

### F03 · benign / medium · T1003.002 · SAM object handle requests on scranton were made by lsass itself (benign system behaviour)

Evidence status: **verified**

Windows Security 4656 events on scranton.dmevals.local show handle requests to Security Account Manager objects (SAM_SERVER 'SAM', SAM_DOMAIN 'SCRANTON', SAM_ALIAS 'DOMAINS\Builtin\Aliases\00000221'). In every case the requesting process is C:\Windows\System32\lsass.exe running as the machine account (SCRANTON$, S-1-5-18), which is normal LSA/SAM operation, not an external tool reading the SAM hive. No reg save / hive-copy activity against SAM was observed (checks C019/C020/C024 returned zero hits).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:21.000Z | scranton.dmevals.local | windows.security | win.ObjectType | SAM_DOMAIN | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItVr3bsA | q-576d799731 | ok |
| 2 | 2020-05-02 03:19:21.000Z | scranton.dmevals.local | windows.security | process.executable | C:\Windows\System32\lsass.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItVr3bsA | q-576d799731 | ok |
| 3 | 2020-05-02 03:19:11.000Z | scranton.dmevals.local | windows.security | win.ObjectType | SAM_ALIAS | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItVz9KVt | q-576d799731 | ok |

### F05 · benign / high · T1040 · Azure Network Watcher agent performs netsh packet capture on scranton.dmevals.local

Evidence status: **verified**

The only packet-capture activity in the window is the legitimate Microsoft Azure Network Watcher agent. On scranton.dmevals.local, NetworkWatcherAgent.exe (running as SYSTEM, parent services.exe) launched netsh.exe to start a capture to an .etl file under C:\windows\TEMP, then stopped it ~7s later. The same agent also ran Install/Test/Start /service /autoStart and logman trace create/start/stop for Azure guest-agent ETW sessions. This is standard Azure VM network diagnostics, not adversary sniffing.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:17.154Z | scranton.dmevals.local | windows.sysmon | process.command_line | C:\windows\system32\netsh.exe trace start capture=yes traceFile="C:\windows\TEMP\E7116ECA-DFE6-43C7-8FA8-8D3AC5AA8726\B91E06C5-1C7C-4830-9A76-74FA211560A7.etl" | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItPM8kte | q-e9f87677cc | ok |
| 2 | 2020-05-02 03:19:17.154Z | scranton.dmevals.local | windows.sysmon | process.parent.executable | C:\Packages\Plugins\Microsoft.Azure.NetworkWatcher.NetworkWatcherAgentWindows\1.4.1421.1\NetworkWatcherAgent\NetworkWatcherAgent.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItPM8kte | q-e9f87677cc | ok |
| 3 | 2020-05-02 03:19:24.835Z | scranton.dmevals.local | windows.sysmon | process.command_line | C:\windows\system32\netsh.exe trace stop | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItPE0PdZ | q-e9f87677cc | ok |
| 4 | 2020-05-02 03:19:13.000Z | scranton.dmevals.local | windows.security | process.command_line | "C:\Packages\Plugins\Microsoft.Azure.NetworkWatcher.NetworkWatcherAgentWindows\1.4.1421.1\NetworkWatcherAgent\NetworkWatcherAgent.exe" /service | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItVz8aWs | q-9c26071d83 | ok |
| 5 | 2020-05-02 03:18:38.000Z | scranton.dmevals.local | windows.security | process.command_line | "logman.exe" stop GAEvents | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItV19xlz | q-9c26071d83 | ok |

### F06 · benign / high · T1040 · No sniffing tools or capture drivers found on any host

Evidence status: **verified**

Searches for classic sniffing tooling came back empty: no tcpdump/windump/wireshark/rawcap process creation in sysmon event 1, no pcap/npcap/winpcap/ndis/netmon driver image loads in sysmon event 6, no pcap/sniff/promiscuous command lines in security 4688 or PowerShell 4104, and no ICMP conn records in zeek. The 7045 service installations observed (Java(TM) Virtual Machine Support Service / javamtsup.exe on scranton, PSEXESVC on nashua) are not capture drivers. No evidence of network sniffing by an adversary.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:17.154Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\Windows\System32\netsh.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItPM8kte | q-e9f87677cc | ok |
| 2 | 2020-05-02 03:04:15.000Z | scranton.dmevals.local | windows.other | process.executable | C:\Windows\System32\javamtsup.exe | .ds-logs-windows.other-default-2026.10.17-000001 / AaFHNH1uOFchItbrX8TL | q-bfa947c90c | ok |

### F10 · benign / high · T1056 · Benign LSASS handle access by system processes (svchost, Defender, Azure agents)

Evidence status: **verified**

The bulk of LSASS process-access events are benign: svchost.exe opened lsass.exe 286 times with GrantedAccess 0x1000 (PROCESS_QUERY_LIMITED_INFORMATION), and Azure agents (AntimalwareConfig.exe, WindowsAzureTelemetryService.exe) used 0x1400. Security 4656 events show lsass.exe itself and MsMpEng.exe (Windows Defender) requesting handles to lsass.exe, and CollectGuestLogs.exe — all normal system/AV behaviour, not credential theft.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:56:14.000Z | utica.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1000 | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHNH1uOFchItQE_JuD | q-cdd65203ec | ok |
| 2 | 2020-05-02 03:20:15.000Z | scranton.dmevals.local | windows.security | process.executable | C:\Program Files\Windows Defender\MsMpEng.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItVq1T69 | q-f179c315fe | ok |
| 3 | 2020-05-02 03:22:38.000Z | nashua.dmevals.local | windows.security | process.executable | C:\WindowsAzure\Packages\CollectGuestLogs.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItViw21R | q-66afdad619 | ok |

### F11 · benign / medium · T1056.001 · No keylogging artifacts observed

Evidence status: **verified**

No Sysmon process-creation or PowerShell script-block events contained keylogger indicators (keylog, GetAsyncKeyState, SetWindowsHookEx) — the corresponding checks returned zero hits. The only process-access targets were standard system processes; no evidence of keystroke interception was found.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:01:03.622Z | scranton.dmevals.local | windows.sysmon | win.TargetImage | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTtmJQ5 | q-d234a6e259 | ok |

### F12 · benign / medium · T1056.002 · No GUI input capture / credential prompt abuse observed

Evidence status: **verified**

Checks for credential-prompt abuse (Credential/prompt/Read-Host in script blocks and process command lines) returned no hits. The only 'prompt' string seen was a bare PowerShell token in pbeesly's session, not a credential-prompt capture. No GUI input capture activity identified.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:21:29.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function jzI {  	Param ($yKR, $cq)		  	$vvA = ([AppDomain]::CurrentDomain.GetAssemblies() \| Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZRkUVV | q-01364892a7 | ok |

### F13 · benign / medium · T1056.003 · No web portal capture observed

Evidence status: **verified**

Checks for web-portal credential capture (IIS/wwwroot/inetpub file writes, w3wp/iis process creation, login/portal URLs in Zeek HTTP) returned zero hits across sysmon, security, powershell and zeek datasets. No evidence of web portal capture.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:01:03.622Z | scranton.dmevals.local | windows.sysmon | event.code | 10 | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTtmJQ5 | q-d234a6e259 | ok |

### F14 · benign / high · T1110 · No brute-force authentication activity; credential theft occurred via LSASS access instead

Evidence status: **verified**

Across windows.security (41002 events, 02:55-03:28Z), windows.other, windows.powershell and windows.sysmon there are zero failed-logon events (event.code 4625) and no lockout or spray tooling. The only authentication-related hits are benign: a Remote Desktop session logon succeeded for DMEVALS\pbeesly on scranton (event.code 21), a Customer Experience Improvement Program logon notification (7001), and normal explicit-credential logons (4648) from winlogon/wininit/taskhostw and PSEXESVC. No brute-force pattern (repeated failures, many usernames, many source IPs) exists in the data.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:20:48.000Z | scranton.dmevals.local | windows.other | message | Remote Desktop Services: Session logon succeeded:    User: DMEVALS\pbeesly  Session ID: 2  Source Network Address: 172.18.39.2 | .ds-logs-windows.other-default-2026.10.17-000001 / AaFHNH1uOFchItbrX8RS | q-c6f553a6fb | ok |
| 2 | 2020-05-02 03:20:46.000Z | scranton.dmevals.local | windows.other | message | User Logon Notification for Customer Experience Improvement Program | .ds-logs-windows.other-default-2026.10.17-000001 / AaFHNH1uOFchItbrX8Re | q-c6f553a6fb | ok |

### F15 · benign / high · T1110.001 · No password-guessing failures observed

Evidence status: **verified**

The 4625 (failed logon) checks C105/C106/C107 returned zero hits, and the windows.other message searches for 'failed'/'4625' returned only unrelated system messages (a crash-dump initialization failure and a DNS PTR registration failure). No repeated authentication failures against any account were found, so password guessing is not observed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:18:54.000Z | scranton.dmevals.local | windows.other | message | Crash dump initialization failed! | .ds-logs-windows.other-default-2026.10.17-000001 / AaFHNH1uOFchItbrX8RY | q-9cf9a2004e | ok |
| 2 | 2020-05-02 03:19:20.000Z | scranton.dmevals.local | windows.other | message | The system failed to register pointer (PTR) resource records (RRs) for network adapter  with settings:               Adapter Name : {3F54D943-1568-43BC-9FDA-67D… | .ds-logs-windows.other-default-2026.10.17-000001 / AaFHNH1uOFchItbrX8Rb | q-9cf9a2004e | ok |

### F17 · benign / high · T1110.003 · No password-spraying pattern observed

Evidence status: **verified**

No 4625 failures exist to indicate spraying, and the 4648 explicit-credential logons are all legitimate: repeated PSEXESVC.exe logons on nashua using pbeesly credentials (remote admin), and winlogon/wininit/taskhostw machine-account logons on scranton. The only command line referencing 'user' is userinit.exe. No single-source, many-account authentication attempts were found.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:40.000Z | nashua.dmevals.local | windows.security | process.executable | C:\Windows\PSEXESVC.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItZ7Ev8p | q-51f29a89fb | ok |
| 2 | 2020-05-02 02:58:44.325Z | scranton.dmevals.local | windows.sysmon | process.parent.executable | C:\Windows\System32\control.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHNH1uOFchItQB61zZ | q-c1fb1f406a | ok |

### F18 · benign / high · T1110.004 · No credential-stuffing activity observed

Evidence status: **verified**

No failed logons (4625) and no credential-list-driven authentication attempts were found. The credential-related windows.other messages are benign system events (Credential Guard configuration 0x0, a SAM remote-call security descriptor notice, and the RDP logon success). The credential material seen in the environment (hardcoded cozy/MyCozyPassw0rd! in the Invoke-Exfil script) is used for outbound WebDAV exfiltration, not for stuffing against accounts.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:09.000Z | scranton.dmevals.local | windows.other | message | Credential Guard configuration: 0x0, 0 | .ds-logs-windows.other-default-2026.10.17-000001 / AaFHNH1uOFchItbrX8R_ | q-42a52b7871 | ok |
| 2 | 2020-05-02 03:19:10.000Z | scranton.dmevals.local | windows.other | message | Remote calls to the SAM database are being restricted using the default security descriptor: O:SYG:SYD:(A;;RC;;;BA).  For more information please see http://go.… | .ds-logs-windows.other-default-2026.10.17-000001 / AaFHNH1uOFchItbrX8S- | q-9e72ec7b1f | ok |

### F19 · benign / high · T1111 · Explicit-credential logons (4648) for pbeesly via PsExec — lateral movement, not MFA interception

Evidence status: **verified**

On 2020-05-01/02, 15 event.code 4648 'logon using explicit credentials' events occurred. 9 used the account pbeesly, executed by C:\Windows\PSEXESVC.exe on nashua.dmevals.local and C:\Windows\System32\svchost.exe on scranton.dmevals.local, targeting localhost. These are PsExec-style remote execution artifacts (PSEXESVC service installs, event.code 7045, appear on nashua at the same times), i.e. lateral movement/remote admin, not interception of MFA tokens. No smart-card, PKINIT, or MFA-provider fields are present.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:40.000Z | nashua.dmevals.local | windows.security | process.executable | C:\Windows\PSEXESVC.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItZ7Ev8p | q-5598ca396b | ok |
| 2 | 2020-05-02 03:11:40.000Z | nashua.dmevals.local | windows.security | win.TargetUserName | pbeesly | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItZ7Ev8p | q-5598ca396b | ok |
| 3 | 2020-05-02 03:20:46.000Z | scranton.dmevals.local | windows.security | process.executable | C:\Windows\System32\svchost.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItVn01NG | q-79dc2eff0b | ok |
| 4 | 2020-05-02 03:11:39.000Z | nashua.dmevals.local | windows.other | win.ServiceName | PSEXESVC | .ds-logs-windows.other-default-2026.10.17-000001 / AaFHNH1uOFchItbrYMQT | q-1269cb8771 | ok |

### F20 · benign / high · T1111 · RDP logons (LogonType 10) for pbeesly use Negotiate, no smart-card/MFA provider

Evidence status: **verified**

The only LogonType 10 (RemoteInteractive) successful logons are two events on scranton.dmevals.local for user pbeesly from 172.18.39.2, authenticated with AuthenticationPackageName 'Negotiate' and LogonProcessName 'User32'. There is no Kerberos PKINIT, smart-card, or MFA/credential-provider indication, so these are ordinary RDP sessions rather than intercepted MFA authentication.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:20:46.000Z | scranton.dmevals.local | windows.security | win.LogonType | 10 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItVn0lP2 | q-c25d79f2d9 | ok |
| 2 | 2020-05-02 03:20:46.000Z | scranton.dmevals.local | windows.security | win.AuthenticationPackageName | Negotiate | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItVn0lP2 | q-c25d79f2d9 | ok |
| 3 | 2020-05-02 03:20:46.000Z | scranton.dmevals.local | windows.security | win.IpAddress | 172.18.39.2 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItVn0lP2 | q-c25d79f2d9 | ok |

### F21 · benign / high · T1111 · Credential-related registry writes are built-in Windows components (Credential Guard disabled, CredentialEnrollmentManager service)

Evidence status: **verified**

The 11 Sysmon event.code 13 registry writes matching 'Credential' are all legitimate Windows internals: lsass.exe setting HKLM\System\CurrentControlSet\Control\DeviceGuard\Scenarios\CredentialGuard\Enabled to DWORD (0x00000000) (Credential Guard is disabled — a defensive-posture observation, not interception), and services.exe registering the built-in CredentialEnrollmentManagerUserSvc service (ImagePath C:\windows\system32\CredentialEnrollmentManager.exe) plus MuiCache entries. No attacker-controlled credential-provider DLL or vault tampering is present.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:09.865Z | scranton.dmevals.local | windows.sysmon | registry.path | HKLM\System\CurrentControlSet\Control\DeviceGuard\Scenarios\CredentialGuard\Enabled | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItO9rO3Z | q-3314cb4844 | ok |
| 2 | 2020-05-02 03:19:09.865Z | scranton.dmevals.local | windows.sysmon | registry.data.strings | DWORD (0x00000000) | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItO9rO3Z | q-3314cb4844 | ok |
| 3 | 2020-05-02 03:20:48.264Z | scranton.dmevals.local | windows.sysmon | registry.data.strings | C:\windows\system32\CredentialEnrollmentManager.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItOxeHN4 | q-3314cb4844 | ok |

### F22 · benign / high · T1111 · No smart-card, MFA, token, vault or credential-provider artifacts observed

Evidence status: **verified**

Targeted hunts for MFA-interception indicators returned nothing: no Sysmon process-creation (event.code 1) with smartcard/scard/MFA/token in the command line, no file-creation (event.code 11) touching Credential/smartcard/scard paths, no vaultcmd/CredentialEnrollmentManager process execution, and no PowerShell script-block (4104) referencing Credential. The only 'Credential' text in windows.other is a benign 'Credential Guard configuration: 0x0, 0' message. There is no evidence of MFA token interception on any host.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:09.000Z | scranton.dmevals.local | windows.other | message | Credential Guard configuration: 0x0, 0 | .ds-logs-windows.other-default-2026.10.17-000001 / AaFHNH1uOFchItbrX8R_ | q-69c6dc0a6b | ok |

### F24 · benign / high · T1187 · Inbound SMB share access (SYSVOL/IPC$/ADMIN$) is normal domain machine-account traffic

Evidence status: **verified**

The 163 share-access events (5140/5145) on newyork.dmevals.local are SYSVOL, IPC$ and ADMIN$ accesses by domain computer accounts (NEWYORK$, SCRANTON$, NASHUA$, UTICA$, WEC$) and by user pbeesly, sourced from the internal 10.0.1.x range and link-local IPv6. These are routine domain logon-script, GPO and admin-share operations, not forced authentication: the accounts are the machines' own computer accounts and the shares are the standard AD shares. No attacker-controlled listener or credential-capture pattern is present in this dataset.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:56:47.000Z | newyork.dmevals.local | windows.security | win.ShareName | \\*\SYSVOL | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItaKWxp4 | q-471eba9bd2 | ok |
| 2 | 2020-05-02 02:56:47.000Z | newyork.dmevals.local | windows.security | user.name | NEWYORK$ | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItaKWxp4 | q-471eba9bd2 | ok |
| 3 | 2020-05-02 03:01:43.000Z | newyork.dmevals.local | windows.security | user.name | SCRANTON$ | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItaFQQtn | q-471eba9bd2 | ok |
| 4 | 2020-05-02 03:01:43.000Z | newyork.dmevals.local | windows.security | source.ip | 10.0.1.4 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItaFQQtn | q-471eba9bd2 | ok |

### F25 · benign / medium · T1187 · Outbound SMB (445/139) from workstations is internal domain traffic, not attacker listeners

Evidence status: **verified**

Sysmon event 3 shows 66 outbound SMB connections, all from the System process (PID 4) on the domain hosts, with destinations 10.0.0.4 (newyork, the DC) and 10.0.1.6, plus link-local IPv6 self-connections. Zeek conn records for 445/139 are dominated by 10.0.1.4 to 10.0.1.6 and 10.0.0.4. These are normal domain controller / SYSVOL replication and machine-account authentication flows within the internal network, not connections to an external or attacker-controlled SMB listener. The only anomalous SMB destination (192.168.0.4) was rejected and is captured in the malicious WebDAV finding above.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:01:43.033Z | scranton.dmevals.local | windows.sysmon | destination.ip | 10.0.0.4 | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTqgghU | q-7a2ab56bce | ok |
| 2 | 2020-05-02 03:01:43.033Z | scranton.dmevals.local | windows.sysmon | process.executable | System | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTqgghU | q-7a2ab56bce | ok |
| 3 | 2020-05-02 03:05:32.965Z | nashua.dmevals.local | windows.sysmon | source.ip | 10.0.1.6 | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHNH1uOFchItUKHd9O | q-7a2ab56bce | ok |

### F28 · benign / medium · T1212 · Kerberos service-ticket requests (4769/4768) are normal domain activity

Evidence status: **verified**

The 42 Kerberos events (28x 4769, 14x 4768) on newyork.dmevals.local are routine service-ticket requests for machine accounts (NEWYORK$, NASHUA$, SCRANTON$) and user pbeesly@DMEVALS.LOCAL from internal addresses 10.0.1.4/10.0.1.6. No anomalous encryption downgrade, no RC4/kerberoasting pattern, no unusual service names — consistent with normal domain authentication, not exploitation for credential access.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:04.000Z | newyork.dmevals.local | windows.security | message | A Kerberos service ticket was requested.    Account Information:  	Account Name:		pbeesly@DMEVALS.LOCAL  	Account Domain:		DMEVALS.LOCAL  	Logon GUID:		{b4946ef… | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItaDOKC- | q-7d51845cf6 | ok |
| 2 | 2020-05-02 03:19:13.000Z | newyork.dmevals.local | windows.security | message | A Kerberos service ticket was requested.    Account Information:  	Account Name:		SCRANTON$@DMEVALS.LOCAL  	Account Domain:		DMEVALS.LOCAL  	Logon GUID:		{4b3ec… | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItV3-aVk | q-7d51845cf6 | ok |

### F29 · benign / medium · T1212 · Zeek weird/notice records are protocol anomalies, not exploitation

Evidence status: **verified**

The 14 Zeek notice/weird records on 2020-04-30 are generic network anomalies: ip_hdr_len_zero, truncated_IP, unknown_dce_rpc_auth_type (addl 68) between 10.0.1.4/10.0.1.6 and 10.0.0.4, and self-signed SSL certificate validation failures. These are common malformed-packet/self-signed-cert artifacts with no exploit payload, no CVE signature and no credential-access content. They also fall in a time window (2020-04-30) that does not overlap the Windows credential-access activity (2020-05-02).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-04-30 00:14:21.969Z | simplerockbuild.simplerock.lan | zeek | message | {"@stream":"weird","@system":"simplerockbuild.simplerock.lan","@proc":"zeek","ts":1588205661.969959,"uid":"C3HnI71C1OMdjvWltf","id_orig_h":"10.0.1.4","id_orig_p… | .ds-logs-zeek-default-2026.10.17-000001 / AaFHNX1uOFchItbgrYiq | q-bfa05ccfb0 | ok |
| 2 | 2020-04-30 00:15:18.392Z | simplerockbuild.simplerock.lan | zeek | message | SSL certificate validation failed with (self signed certificate) | .ds-logs-zeek-default-2026.10.17-000001 / AaFHNX1uOFchItbgrIjg | q-bfa05ccfb0 | ok |

### F30 · benign / high · T1539 · WebDAV DavSetCookie activity on scranton.dmevals.local is a WebDAV client cookie, not browser session cookie theft

Evidence status: **verified**

Five 4688 process-creation events on scranton.dmevals.local (2020-05-01 23:08:50 and 23:10:22-23) show rundll32.exe invoking davclnt.dll,DavSetCookie against 192.168.0.4 http://192.168.0.4/webdav, spawned by svchost.exe under user pbeesly. DavSetCookie is the WebDAV redirector's own cookie mechanism for a WebDAV mount, not theft of a browser/web-application session cookie. The same command line also appears in Sysmon event.code 1. No browser cookie store was touched.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:08:50.000Z | scranton.dmevals.local | windows.security | process.command_line | rundll32.exe C:\windows\system32\davclnt.dll,DavSetCookie 192.168.0.4 http://192.168.0.4/webdav | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItZ8Frba | q-42b47bb637 | ok |
| 2 | 2020-05-02 03:08:50.000Z | scranton.dmevals.local | windows.security | process.parent.executable | C:\Windows\System32\svchost.exe | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItZ8Frba | q-42b47bb637 | ok |
| 3 | 2020-05-02 03:10:23.154Z | scranton.dmevals.local | windows.sysmon | process.command_line | rundll32.exe C:\windows\system32\davclnt.dll,DavSetCookie 192.168.0.4 http://192.168.0.4/webdav | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTVHe6C | q-6fc011558f | ok |

### F31 · benign / high · T1539 · INetCookies file creation by svchost.exe is a Windows service-profile artifact, not cookie theft

Evidence status: **verified**

The only Sysmon file-creation event matching *cookie* is svchost.exe (PID 7200, SYSTEM) creating C:\Windows\ServiceProfiles\LocalService\AppData\Local\Packages\warp_jit_db4a1097-...\AC\INetCookies on scranton.dmevals.local at 2020-05-02 03:21:05. This is a Windows WARP JIT service package artifact under the LocalService profile, not a browser cookie database (no Chrome/Edge/Firefox Cookies, Login Data or Web Data files were created or accessed anywhere in the dataset).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:21:05.681Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Windows\ServiceProfiles\LocalService\AppData\Local\Packages\warp_jit_db4a1097-b484-4973-bbf2-a04208ecd4d4\AC\INetCookies | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItOVAUl3 | q-6a4da6b762 | ok |
| 2 | 2020-05-02 03:21:05.681Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\System32\svchost.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItOVAUl3 | q-6a4da6b762 | ok |

### F32 · benign / medium · T1539 · Zeek HTTP GET /webdav/python.exe reflects WebDAV payload retrieval, not session-cookie use

Evidence status: **verified**

The two Zeek HTTP GET hits (2020-04-30 00:35:25, observer simplerockbuild.simplerock.lan, 10.0.1.4 -> 192.168.0.4:80) are Microsoft-WebDAV-MiniRedir requests for /webdav/python.exe returning 401 Unauthorized. They carry no Cookie header and represent WebDAV file retrieval (consistent with the python.exe dropped to C:\Windows\Temp on nashua.dmevals.local), not web session cookie theft. Zeek's window does not overlap the Windows host logs.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-04-30 00:35:25.656Z | simplerockbuild.simplerock.lan | zeek | url.original | /webdav/python.exe | .ds-logs-zeek-default-2026.10.17-000001 / AaFHNX1uOFchItbgrog- | q-b3b9e9644a | ok |
| 2 | 2020-04-30 00:35:25.656Z | simplerockbuild.simplerock.lan | zeek | user_agent.original | Microsoft-WebDAV-MiniRedir/10.0.18362 | .ds-logs-zeek-default-2026.10.17-000001 / AaFHNX1uOFchItbgrog- | q-b3b9e9644a | ok |
| 3 | 2020-04-30 00:35:25.656Z | simplerockbuild.simplerock.lan | zeek | http.response.status_code | 401 | .ds-logs-zeek-default-2026.10.17-000001 / AaFHNX1uOFchItbgrog- | q-b3b9e9644a | ok |

### F37 · benign / medium · T1552.002 · Registry Password/Credential value sets are OS-internal, not credential theft

Evidence status: **verified**

The 17 Sysmon registry value-set events matching Password/Credential were written by legitimate system processes (svchost.exe writing IdentityCRL ProviderPasswordLength, lsass.exe writing DeviceGuard CredentialGuard Enabled, services.exe registering CredentialEnrollmentManagerUserSvc, winlogon.exe writing PasswordExpiryNotification). No attacker-controlled process wrote credential material to the registry.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:28.255Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\svchost.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItThYt63 | q-9e80e56cb7 | ok |
| 2 | 2020-05-02 03:19:09.865Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItO9rO3Z | q-9e80e56cb7 | ok |

### F36 · benign / high · T1552.006 · GPO/SecEdit GptTmpl.inf access is normal Group Policy processing

Evidence status: **verified**

Sysmon file-create events for GptTmpl.inf under C:\Windows\System32\GroupPolicy\DataStore\...\SecEdit on scranton and nashua were generated by C:\windows\system32\svchost.exe (the Group Policy service), and the Zeek SMB reads of \\NEWYORK.dmevals.local\sysvol\...\SecEdit\GptTmpl.inf came from domain machines (10.0.1.4, 10.0.1.6) retrieving policy. No Groups.xml/cpassword access was observed. This is routine GPO application, not GPP credential theft.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:01:43.091Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\svchost.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItTqhAkt | q-b2ca0e1fd8 | ok |
| 2 | 2020-04-30 00:12:01.673Z | simplerockbuild.simplerock.lan | zeek | zeek.name | dmevals.local\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf | .ds-logs-zeek-default-2026.10.17-000001 / AaFHNX1uOFchItbgrYiv | q-1d343f305c | ok |

### F41 · benign / medium · T1555.003 · No browser credential-store access observed

Evidence status: **verified**

Checks for browser credential files (Login Data, logins.json, cookies) in Sysmon file/process events, Security object access, PowerShell script blocks and the other channel all returned zero hits. No evidence of web-browser credential theft in this window.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:21:05.057Z | scranton.dmevals.local | windows.sysmon | win.TargetImage | C:\Windows\SystemApps\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\MicrosoftEdge.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItOVAkmV | q-f96d7a8c3f | ok |

### F42 · benign / medium · T1555.005 · No password-manager access observed

Evidence status: **NOT verified (0/1 evidence items)** — excluded from the verdict

Checks for KeePass/1Password/Bitwarden/LastPass executables, files, process access, command lines and messages all returned zero hits. No password-manager credential theft in this window.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 |  | None | None | win.TargetImage | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItQE_JuD | q-26366cbc8c | FAILED: cited query did not return this event; event not found |

### F44 · benign / medium · T1556.001 · Network logons on newyork are machine-account (NEWYORK$) activity, not a DC authentication backdoor

Evidence status: **verified**

The 218 LogonType 3 (network) 4624 events are dominated by the machine account NEWYORK$ (123) and other host accounts (SCRANTON$, NASHUA$, UTICA$, WEC$) logging on to newyork.dmevals.local, with source IPs of ::1, fe80:: and 10.0.0.4 — normal machine-account/service network authentication. The only interactive user account seen is pbeesly (13 on nashua, 6 on newyork, 1 on scranton), consistent with lateral movement using stolen credentials rather than a modified DC authentication process. No evidence of a DC authentication backdoor (no Skeleton Key / DSRM / authentication-package tampering) was found.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:55:54.000Z | newyork.dmevals.local | windows.security | user.name | NEWYORK$ | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItaKXhpQ | q-4c7ad0a06f | ok |
| 2 | 2020-05-02 02:55:54.000Z | newyork.dmevals.local | windows.security | source.ip | ::1 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItaKXhpQ | q-4c7ad0a06f | ok |
| 3 | 2020-05-02 02:55:54.000Z | newyork.dmevals.local | windows.security | win.LogonType | 3 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItaKXhpQ | q-4c7ad0a06f | ok |

### F45 · benign / high · T1557 · No adversary-in-the-middle activity observed across Windows and Zeek telemetry

Evidence status: **verified**

Hunting the T1557 family across windows.security, windows.sysmon, windows.other, windows.powershell and zeek found no AiTM positioning. Object-access events (4663/4670/4656) are dominated by routine processes (powershell.exe, svchost.exe, WmiPrvSE.exe, services.exe) touching registry Keys and Tokens. Sysmon network connections (event.code 3) all have DestinationHostname '-' and go to internal DC/host IPs on standard ports (445, 389, 88, 53, 135). No rogue hosts, no relay destinations, no name-resolution anomalies.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:59.799Z | scranton.dmevals.local | windows.sysmon | destination.port | 445 | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItOrW_3E | q-9bbd9924a8 | ok |
| 2 | 2020-05-02 03:19:59.799Z | scranton.dmevals.local | windows.sysmon | destination.ip | 10.0.0.4 | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItOrW_3E | q-9bbd9924a8 | ok |
| 3 | 2020-05-02 03:19:59.799Z | scranton.dmevals.local | windows.sysmon | process.executable | System | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItOrW_3E | q-9bbd9924a8 | ok |

### F46 · benign / high · T1557.001 · No name-resolution poisoning or SMB relay; SMB/Kerberos flows are legitimate domain authentication

Evidence status: **verified**

Zeek shows SMB (445) and Kerberos flows between internal hosts (10.0.1.4, 10.0.1.6) and the DC (10.0.0.4), authenticating as pbeesly/DMEVALS.LOCAL with normal TGS requests for cifs/NASHUA, cifs/NEWYORK, host/nashua.dmevals.local and ldap/NEWYORK.dmevals.local, plus sysvol GPO reads. Sysmon DNS queries (event.code 22) are all benign (Microsoft telemetry, domain DC lookups, wpad, localhost). No LLMNR/NBT-NS poisoning, no rogue SMB responder, no relay. The 4697 service installs are normal Windows user services plus PSEXESVC/javamtsup (execution/lateral-movement artifacts, not AiTM).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-04-30 00:37:53.342Z | simplerockbuild.simplerock.lan | zeek | zeek.client | pbeesly/DMEVALS.LOCAL | .ds-logs-zeek-default-2026.10.17-000001 / AaFHNX1uOFchItbgrYiy | q-f26622abd1 | ok |
| 2 | 2020-04-30 00:37:53.342Z | simplerockbuild.simplerock.lan | zeek | zeek.service | cifs/NASHUA | .ds-logs-zeek-default-2026.10.17-000001 / AaFHNX1uOFchItbgrYiy | q-f26622abd1 | ok |
| 3 | 2020-05-02 03:19:31.333Z | scranton.dmevals.local | windows.sysmon | win.QueryName | wpad | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItOmQp3C | q-f7d74566a1 | ok |
| 4 | 2020-05-02 03:15:03.000Z | nashua.dmevals.local | windows.security | win.ServiceName | PSEXESVC | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItZ7DT5G | q-582ceeeee2 | ok |

### F47 · benign / high · T1557.002 · No ARP cache poisoning; MAC-to-IP mappings are consistent with the dataset's synthetic addressing

Evidence status: **verified**

Zeek conn records show three source MACs (00:0d:3a:13:e3:69, 00:0d:3a:4d:42:f2, fc:bd:67:e1:a9:c1) each mapping to a single source IP (10.0.1.6, 10.0.1.4, 10.0.1.4 respectively). The responder MAC 12:34:56:78:9a:bc is a well-known synthetic placeholder that answers for the DC/responder IPs (10.0.0.4, 192.168.0.4, 192.168.0.5) and 10.0.1.6 — a dataset artifact, not a single MAC claiming multiple victim IPs. No gratuitous ARP, no duplicate MAC-to-IP conflict indicating poisoning.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-04-30 00:36:38.970Z | simplerockbuild.simplerock.lan | zeek | zeek.resp_l2_addr | 12:34:56:78:9a:bc | .ds-logs-zeek-default-2026.10.17-000001 / AaFHNX1uOFchItbgroge | q-2d33b4ea2a | ok |
| 2 | 2020-04-30 00:36:38.970Z | simplerockbuild.simplerock.lan | zeek | zeek.orig_l2_addr | 00:0d:3a:4d:42:f2 | .ds-logs-zeek-default-2026.10.17-000001 / AaFHNX1uOFchItbgroge | q-2d33b4ea2a | ok |
| 3 | 2020-04-30 00:36:38.970Z | simplerockbuild.simplerock.lan | zeek | destination.ip | 10.0.0.4 | .ds-logs-zeek-default-2026.10.17-000001 / AaFHNX1uOFchItbgroge | q-2d33b4ea2a | ok |

### F48 · benign / high · T1557.003 · No DHCP spoofing; no DHCP events or DHCP traffic present in any dataset

Evidence status: **verified**

No DHCP-related Windows event codes (1341/1342/1020/1063) exist in windows.other, and no DHCP log type exists in the Zeek capture (only conn/files/ssl/x509/dce_rpc/http/dns/kerberos/dpd/smb_files/weird/smb_mapping/notice/pe). Sysmon network connections (event.code 3) show no traffic to DHCP ports 67/68; destination ports are standard service ports (8443, 389, 88, 53, 135, 445, 443). No rogue DHCP server activity is observable.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-04-30 00:36:38.970Z | simplerockbuild.simplerock.lan | zeek | event.action | conn | .ds-logs-zeek-default-2026.10.17-000001 / AaFHNX1uOFchItbgroge | q-2d33b4ea2a | ok |
| 2 | 2020-05-02 03:19:59.799Z | scranton.dmevals.local | windows.sysmon | destination.port | 445 | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItOrW_3E | q-9bbd9924a8 | ok |

### F51 · benign / medium · T1558.001 · No golden-ticket forging evidence observed

Evidence status: **verified**

All 28 Kerberos service-ticket requests (event 4769) on newyork.dmevals.local used TicketEncryptionType 0x12 (RC4) with normal TicketOptions (0x40810000/0x60810010); no anomalous encryption downgrade, no forged-ticket indicators, and no krbtgt hash theft followed by forged TGT use were observed. The krbtgt TGS requests are attributable to normal Kerberos/DC replication behaviour. No golden-ticket activity could be confirmed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:04.000Z | newyork.dmevals.local | windows.security | win.TicketEncryptionType | 0x12 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItaDOaA_ | q-9785d858da | ok |
| 2 | 2020-05-02 03:04:04.000Z | newyork.dmevals.local | windows.security | win.TicketOptions | 0x40810000 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItaDOaA_ | q-9785d858da | ok |

### F52 · benign / medium · T1558.002 · No silver-ticket forging evidence observed

Evidence status: **verified**

The 4769 service-ticket requests observed on newyork.dmevals.local are all KDC-issued tickets for legitimate host SPNs (NEWYORK$, NASHUA$, SCRANTON$, WEC$) with standard ticket options and RC4 encryption; no service tickets issued without KDC validation or other silver-ticket indicators were found. No silver-ticket activity could be confirmed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:09:23.000Z | newyork.dmevals.local | windows.security | win.ServiceName | NASHUA$ | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItZ8FbW6 | q-9785d858da | ok |
| 2 | 2020-05-02 03:09:23.000Z | newyork.dmevals.local | windows.security | win.TicketOptions | 0x40810000 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItZ8FbW6 | q-9785d858da | ok |

### F53 · benign / medium · T1558.004 · No AS-REP roasting evidence observed

Evidence status: **verified**

No AS-REP roasting indicators were found: no PowerShell script blocks referencing AS-REP/GetNPUsers/DontRequirePreAuth (check C334 returned zero hits), and no anomalous Kerberos AS request patterns were observed in the available data. No AS-REP roasting activity could be confirmed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:56:15.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | prompt | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZWqdCz | q-28f685f0bf | ok |

### F54 · benign / medium · T1606 · No forged web credential activity; hits are LSASS access, WMI/RSOP noise and WebDAV file transfer

Evidence status: **verified**

The T1606 check hits do not show any forging of web credentials. The windows.security logon-process stacking (312 events, q-60c287f89b) shows only normal Kerberos/Advapi/User32/NtLmSsp logon processes. The windows.other 5857/5858 hits (q-a16b4e80c0) are routine WMI RSOP_ExtensionStatus DeleteInstance operations by NT AUTHORITY\SYSTEM on newyork.dmevals.local. The zeek http/ssl/kerberos hits (q-3658c152ef) are WebDAV file transfers between 10.0.1.4 and 192.168.0.4 (OfficeSupplies.7z), not web authentication. The LSASS process-access hits (q-9904cadde9) are credential-dumping-adjacent (T1003) rather than web-credential forgery.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:56:47.000Z | newyork.dmevals.local | windows.other | message | Id = {C11E1664-7828-4AD0-B23A-0FCEF0EA26C0}; ClientMachine = NEWYORK; User = NT AUTHORITY\SYSTEM; ClientProcessId = 1588; Component = Unknown; Operation = Start… | .ds-logs-windows.other-default-2026.10.17-000001 / AaFHNH1uOFchItbrX8Rl | q-a16b4e80c0 | ok |
| 2 | 2020-04-30 00:32:22.010Z | simplerockbuild.simplerock.lan | zeek | url.original | /webdav/OfficeSupplies.7z | .ds-logs-zeek-default-2026.10.17-000001 / AaFHNX1uOFchItbgrYi9 | q-81138d1df9 | ok |

### F55 · benign / high · T1606.001 · No forged web cookies; only a benign INetCookies file creation by svchost

Evidence status: **verified**

The only cookie-related file event in the whole window is a single Sysmon file-create of C:\Windows\ServiceProfiles\LocalService\AppData\Local\Packages\warp_jit_db4a1097-b484-4973-bbf2-a04208ecd4d4\AC\INetCookies on scranton.dmevals.local, created by C:\windows\System32\svchost.exe (q-356e4f54d6 / q-d357b4f041). This is a normal Windows service-profile cookie store path, not browser cookie theft or forgery. No PowerShell script blocks referencing cookies/Set-Cookie/session were found (C344 zero hits), and the zeek HTTP traffic contains no cookie-bearing authentication requests.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:21:05.681Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Windows\ServiceProfiles\LocalService\AppData\Local\Packages\warp_jit_db4a1097-b484-4973-bbf2-a04208ecd4d4\AC\INetCookies | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItOVAUl3 | q-d357b4f041 | ok |
| 2 | 2020-05-02 03:21:05.681Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\System32\svchost.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItOVAUl3 | q-d357b4f041 | ok |

### F56 · benign / high · T1606.002 · No SAML token forgery; no SAML/ADFS/token artifacts in any dataset

Evidence status: **verified**

No SAML token forging activity was observed. PowerShell script-block searches for SAML/NotOnOrAfter/Assertion returned zero hits (C348), Sysmon process-command-line searches for saml/token/cert returned zero hits (C350), and zeek HTTP searches for saml/adfs/token URLs returned zero hits (C351). The windows.other 7045/5857/5858 hits (q-97ba48eaa3) are the same routine WMI RSOP DeleteInstance operations by SYSTEM on newyork.dmevals.local, unrelated to token minting. The only notable PowerShell activity is an obfuscated reflective shellcode loader on scranton.dmevals.local (user pbeesly), which is code-execution tradecraft (T1055/T1620), not SAML token forgery.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:21:29.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function jzI {  	Param ($yKR, $cq)		  	$vvA = ([AppDomain]::CurrentDomain.GetAssemblies() \| Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[… | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZRkUVV | q-6ff3bc8b90 | ok |
| 2 | 2020-05-02 02:56:47.000Z | newyork.dmevals.local | windows.other | message | Id = {C11E1664-7828-4AD0-B23A-0FCEF0EA26C0}; ClientMachine = NEWYORK; User = NT AUTHORITY\SYSTEM; ClientProcessId = 1588; Component = Unknown; Operation = Start… | .ds-logs-windows.other-default-2026.10.17-000001 / AaFHNH1uOFchItbrX8Rl | q-97ba48eaa3 | ok |

### F57 · benign / high · T1621 · No MFA request generation activity observed; windows.other 5857/5858 hits are benign WMI/RSOP GPO activity

Evidence status: **verified**

The T1621 hypothesis (adversary generating repeated MFA push/notification requests to fatigue a user) is not supported by any retrieved event. The windows.other hits that triggered the check are WMI event 5858 records on newyork.dmevals.local, all executed by NT AUTHORITY\SYSTEM (ClientProcessId 1588) performing IWbemServices::DeleteInstance against Root\Rsop\Computer RSOP_ExtensionStatus objects — routine Group Policy Resultant Set of Policy processing, not authentication or MFA activity. No PowerShell script block (4104) contained MFA/2FA/authenticator/OTP/push-notification/phone content, no sysmon process creation had MFA/auth/login command lines, and no HTTP request to a login/auth/MFA URL appeared in zeek. Only a single failed logon (4625) exists in the whole window, so there is no flood of authentication attempts characteristic of MFA fatigue.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:56:47.000Z | newyork.dmevals.local | windows.other | message | Id = {C11E1664-7828-4AD0-B23A-0FCEF0EA26C0}; ClientMachine = NEWYORK; User = NT AUTHORITY\SYSTEM; ClientProcessId = 1588; Component = Unknown; Operation = Start… | .ds-logs-windows.other-default-2026.10.17-000001 / AaFHNH1uOFchItbrX8Rl | q-3119c99bb6 | ok |
| 2 | 2020-05-02 02:56:47.000Z | newyork.dmevals.local | windows.other | user.name | SYSTEM | .ds-logs-windows.other-default-2026.10.17-000001 / AaFHNH1uOFchItbrX8Rl | q-3119c99bb6 | ok |
| 3 | 2020-05-02 02:56:47.000Z | newyork.dmevals.local | windows.other | event.code | 5858 | .ds-logs-windows.other-default-2026.10.17-000001 / AaFHNH1uOFchItbrX8Rl | q-3119c99bb6 | ok |

### F59 · benign / high · T1649 · Routine certificate store registry writes and Kerberos TGT requests (benign)

Evidence status: **verified**

The certificate-related registry writes flagged by the checks are normal Windows certificate store maintenance: Sysmon Event 13 writes to HKLM\SOFTWARE\Microsoft\SystemCertificates\...\Blob by lsass.exe, svchost.exe, taskhostw.exe and powershell.exe (AuthRoot, MY, Windows Live ID Token Issuer, Remote Desktop stores), and a single Security 4657 modification of the ROOT\Certificates\BE36A456... key by NASHUA$ via C:\Windows\Sysmon.exe. The 4657 WMI Autologger entries under ControlSet001\Control\WMI\Autologger are unrelated to certificates. The 14 Kerberos 4768 TGT requests (pbeesly, SCRANTON$) on newyork.dmevals.local are ordinary domain logons with standard RC4 ticket options 0x40810010 and status 0x0. The Zeek x509 subjects (rempel.group.net, conn.sons.info) are from a non-overlapping window and show no forged authentication certificates.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:59:37.453Z | nashua.dmevals.local | windows.sysmon | registry.path | HKLM\SOFTWARE\Microsoft\SystemCertificates\AuthRoot\Certificates\A8985D3A65E5E5C4B2D7D66D40C6DD2FB19C5436\Blob | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItT2v6oH | q-91d6aa662f | ok |
| 2 | 2020-05-02 02:59:37.453Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.17-000001 / AaFHM31uOFchItT2v6oH | q-91d6aa662f | ok |
| 3 | 2020-05-02 03:16:19.000Z | nashua.dmevals.local | windows.security | win.ObjectName | \REGISTRY\MACHINE\SOFTWARE\Microsoft\SystemCertificates\ROOT\Certificates\BE36A4562FB2EE05DBB3D32323ADF445084ED656 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItZ6CoZN | q-fed6de7260 | ok |
| 4 | 2020-05-02 03:11:18.000Z | newyork.dmevals.local | windows.security | win.TargetUserName | pbeesly | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItZ7Ef_w | q-1fbb5e0942 | ok |
| 5 | 2020-05-02 03:11:18.000Z | newyork.dmevals.local | windows.security | win.Status | 0x0 | .ds-logs-windows.security-default-2026.10.17-000001 / AaFHNH1uOFchItZ7Ef_w | q-1fbb5e0942 | ok |

### F38 · not_observed / medium · T1552.003 · No shell-history credential access observed

Evidence status: **verified**

No events referencing consolehost_history or PowerShell history files were found in windows.sysmon or windows.security. Although the attacker used an interactive PowerShell session on scranton, no evidence of reading shell history for credentials was retrieved.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | Get-PrivateKeys | .ds-logs-windows.powershell-default-2026.10.17-000001 / AaFHNX1uOFchItZRlVDe | q-06c46e63fe | ok |

## Pivot candidates

Processes the pivot reviewer had to assess (started by a script host or from outside the Windows directory, rare in the 15-minute windows around verified activity).

| Host | Executable | Starts | Parents | Assessment | Reason |
|---|---|---|---|---|---|
| nashua.dmevals.local | C:\Program Files\WindowsApps\Microsoft.SkypeApp_14.35.152.0_x64__kzf8qxf38zg5c\S… | 1 | C:\Program Files\WindowsApps\Microsoft.SkypeApp_14.35.152.0_x64__kzf8qxf38zg5c\S… | benign | Legitimate Microsoft Store Skype app; self-parented restart, no credential-access behavior. |
| nashua.dmevals.local | C:\Windows\Temp\python.exe | 5 | C:\Windows\PSEXESVC.exe, C:\Windows\Temp\python.exe | malicious | PyInstaller-bundled python.exe dropped to C:\Windows\Temp and executed via PsExec from scranton as pbeesly; it dropped Rar.exe and staged working.zip for exfil.… |
| nashua.dmevals.local | C:\Windows\Temp\Rar.exe | 1 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | malicious | Rar.exe dropped by the python.exe payload into C:\Windows\Temp and used to create a password-protected archive of user files (working.zip) for exfiltration. |
| nashua.dmevals.local | C:\Windows\Temp\sdelete64.exe | 3 | C:\Windows\System32\cmd.exe | malicious | Sysinternals sdelete run from C:\Windows\Temp by cmd.exe to securely delete the Rar.exe tool and staged working.zip archives (anti-forensics). |
| nashua.dmevals.local | C:\WindowsAzure\Packages\CollectGuestLogs.exe | 1 | C:\WindowsAzure\Packages\WaAppAgent.exe | benign | Standard Azure guest agent diagnostic log collector, parented by WaAppAgent.exe. |
| newyork.dmevals.local | C:\Windows\System32\conhost.exe | 3 | C:\WindowsAzure\Packages\CollectGuestLogs.exe, C:\Windows\System32\cmd.exe, C:\W… | benign | Normal console host spawned by cmd/dsregcmd/CollectGuestLogs; no credential activity. |
| scranton.dmevals.local | C:\Packages\Plugins\Microsoft.Azure.NetworkWatcher.NetworkWatcherAgentWindows\1.… | 4 | C:\Windows\System32\cmd.exe, C:\Windows\System32\services.exe | benign | Azure Network Watcher agent, standard Azure VM extension. |
| scranton.dmevals.local | C:\Packages\Plugins\Microsoft.Azure.Security.IaaSAntimalware\1.5.5.9\Antimalware… | 1 | C:\WindowsAzure\Packages\GuestAgent\WindowsAzureGuestAgent.exe | benign | Azure IaaS Antimalware extension config binary, parented by WindowsAzureGuestAgent. |
| scranton.dmevals.local | C:\Packages\Plugins\Microsoft.Compute.CustomScriptExtension\1.10.5\bin\CustomScr… | 1 | C:\Windows\System32\cmd.exe | benign | Azure Custom Script Extension handler, standard Azure VM extension. |
| scranton.dmevals.local | C:\Packages\Plugins\Microsoft.Compute.JsonADDomainExtension\1.3.2\bin\JsonADDoma… | 1 | C:\Windows\System32\cmd.exe | benign | Azure AD domain-join extension, standard Azure VM extension. |
| scranton.dmevals.local | C:\Program Files (x86)\Google\Update\1.3.35.452\GoogleCrashHandler.exe | 2 | C:\Program Files (x86)\Google\Update\GoogleUpdate.exe | benign | Google Update crash handler, legitimate updater component. |
| scranton.dmevals.local | C:\Program Files (x86)\Google\Update\1.3.35.452\GoogleCrashHandler64.exe | 2 | C:\Program Files (x86)\Google\Update\GoogleUpdate.exe | benign | Google Update crash handler (64-bit), legitimate updater component. |
| scranton.dmevals.local | C:\Program Files (x86)\Google\Update\GoogleUpdate.exe | 3 | C:\Program Files (x86)\Google\Update\GoogleUpdate.exe, C:\Windows\System32\servi… | benign | Google Update service, legitimate updater. |
| scranton.dmevals.local | C:\Program Files\SysinternalsSuite\accessChk.exe | 1 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | suspicious | Sysinternals accesschk run from PowerShell by pbeesly during the intrusion window, consistent with reconnaissance of permissions; part of the attacker's Sysinte… |
| scranton.dmevals.local | C:\Program Files\SysinternalsSuite\PsExec64.exe | 4 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | malicious | PsExec64 launched from PowerShell with a cleartext password (-u dmevals\pbeesly -p Fl0nk3rt0n!T0by) to run python.exe on \\NASHUA; lateral movement and credenti… |
| scranton.dmevals.local | C:\Program Files\SysinternalsSuite\sdelete64.exe | 3 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | malicious | Sysinternals sdelete run from PowerShell to securely delete staged archives and downloaded tooling (anti-forensics). |
| scranton.dmevals.local | C:\Program Files\Windows Defender\MsMpEng.exe | 1 | C:\Windows\System32\services.exe | benign | Windows Defender antimalware service, legitimate. |
| scranton.dmevals.local | C:\Program Files\Windows Defender\NisSrv.exe | 2 | C:\Windows\System32\services.exe | benign | Windows Defender network inspection service, legitimate. |
| scranton.dmevals.local | C:\ProgramData\victim\â€®cod.3aka3.scr | 1 | C:\Windows\explorer.exe | malicious | Suspicious .scr executable in C:\ProgramData\victim with a mangled name, launched by explorer.exe as pbeesly, making outbound TCP to 192.168.0.5:1234 and writin… |
| scranton.dmevals.local | C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe | 2 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | suspicious | C# compiler invoked by PowerShell with @response files in AppData\Local\Temp (qkbkqqbs.cmdline, 0piklvia.cmdline), consistent with in-memory/on-the-fly compilat… |
| scranton.dmevals.local | C:\Windows\System32\hostui.exe | 1 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | suspicious | hostui.exe launched by PowerShell as pbeesly; not a normal interactive-launch pattern and part of the attacker's tooling chain on scranton. |
| scranton.dmevals.local | C:\Windows\System32\sdclt.exe | 3 | C:\Windows\System32\cmd.exe | suspicious | sdclt.exe (Backup and Restore) spawned three times by cmd.exe as pbeesly; commonly abused for UAC bypass / execution, unusual here. |
| scranton.dmevals.local | C:\WindowsAzure\Packages\GuestAgent\BfeToolWin8.exe | 1 | C:\WindowsAzure\Packages\GuestAgent\WindowsAzureGuestAgent.exe | benign | Azure guest agent firewall helper, standard Azure component. |
| scranton.dmevals.local | C:\WindowsAzure\Packages\GuestAgent\FindVolume\FindVolume.exe | 1 | C:\WindowsAzure\Packages\GuestAgent\WindowsAzureGuestAgent.exe | benign | Azure guest agent volume discovery helper, standard Azure component. |
| scranton.dmevals.local | C:\WindowsAzure\Packages\GuestAgent\WindowsAzureGuestAgent.exe | 1 | C:\Windows\System32\services.exe | benign | Azure guest agent service, legitimate. |
| scranton.dmevals.local | C:\WindowsAzure\Packages\Telemetry\WindowsAzureTelemetryService.exe | 1 | C:\Windows\System32\services.exe | benign | Azure telemetry service, legitimate. |
| scranton.dmevals.local | C:\WindowsAzure\Packages\WaAppAgent.exe | 1 | C:\Windows\System32\services.exe | benign | Azure Windows Azure agent, legitimate. |
| scranton.dmevals.local | C:\WindowsAzure\SecAgent\WaSecAgentProv.exe | 2 | C:\WindowsAzure\Packages\WaAppAgent.exe | benign | Azure security agent provider, legitimate. |
| scranton.dmevals.local | C:\WindowsAzure\WindowsAzureNetAgent_1.0.0.143\WindowsAzureNetAgent\Plugins\VFPl… | 1 | C:\WindowsAzure\WindowsAzureNetAgent_1.0.0.143\WindowsAzureNetAgent\WindowsAzure… | benign | Azure network agent plugin, legitimate. |
| scranton.dmevals.local | C:\WindowsAzure\WindowsAzureNetAgent_1.0.0.143\WindowsAzureNetAgent\WindowsAzure… | 1 | C:\Windows\System32\services.exe | benign | Azure network agent service, legitimate. |

## Technique conclusions

One line per technique in scope: status from the triage of its family; `not_observed` = checked, nothing found; `not_observable` = no dataset records it.

| Technique | Status | Reason |
|---|---|---|
| T1003 OS Credential Dumping | malicious | Credential-access tooling on scranton (Get-PrivateKeys, Get-Keystrokes, Invoke-ScreenCapture, Invoke-Exfil) plus LSASS access. |
| T1003.001 LSASS Memory | malicious | LSASS opened with full-access rights (0x1f3fff/0x1fffff) by PowerShell on scranton and wsmprovhost on nashua; consistent with LSASS memory credential dumping. |
| T1003.002 Security Account Manager | benign | SAM_SERVER/SAM_DOMAIN/SAM_ALIAS handle requests on scranton were all made by lsass.exe itself as the machine account; no reg save or hive-copy of SAM observed. |
| T1003.003 NTDS | not_observed | No NTDS.dit file creation, ntdsutil/vssadmin/diskshadow command lines, or shadow-copy activity found (checks C025-C030 zero hits). |
| T1003.004 LSA Secrets | not_observed | No LSA Secrets / SECURITY Policy Secrets object access or lsadump/reg save HKLM\SECURITY command lines found (checks C032-C037 zero hits). |
| T1003.005 Cached Domain Credentials | malicious | lsass.exe wrote HKLM\SECURITY\Cache\NL$1 on nashua (4x) and scranton (1x), cached domain credential entry. |
| T1003.006 DCSync | not_observed | No DCSync/drsuapi/lsadump command lines or PowerShell script blocks found (checks C047/C048 zero hits). |
| T1040 Network Sniffing | benign | The only packet-capture activity is the legitimate Microsoft Azure Network Watcher agent (NetworkWatcherAgent.exe -> netsh trace start/stop capture=yes to an .etl file, plus logman ETW sessions) on scranton.dmevals.local… |
| T1056 Input Capture | suspicious | LSASS handle requests observed; most are benign system/AV access (0x1000), but PowerShell full-access opens on scranton are suspicious. |
| T1056.001 Keylogging | malicious | Get-Keystrokes keylogger and Get-Clipboard capture run by pbeesly on scranton. |
| T1056.002 GUI Input Capture | not_observed | No credential-prompt / GUI input capture artifacts found. |
| T1056.003 Web Portal Capture | not_observed | No IIS/wwwroot/login-portal capture activity in any dataset. |
| T1056.004 Credential API Hooking | malicious | PowerShell opened LSASS with 0x1f3fff/0x1fffff on scranton; obfuscated PowerShell with GetProcAddress/UnsafeNativeMethods per anchors. |
| T1110 Brute Force | not_observed | No failed-logon (4625) events, lockouts, or brute-force patterns in any dataset; only benign RDP/CEIP logon notifications and normal 4648 explicit-credential logons. |
| T1110.001 Password Guessing | not_observed | Zero 4625 failures and no repeated authentication attempts against any account; 'failed' message hits were unrelated system errors. |
| T1110.002 Password Cracking | malicious | LSASS accessed with PROCESS_ALL_ACCESS (0x1fffff) by PowerShell on scranton. |
| T1110.003 Password Spraying | not_observed | No 4625 failures and no single-source many-account authentication pattern; 4648 logons are legitimate PSEXESVC and machine-account logons. |
| T1110.004 Credential Stuffing | not_observed | No failed logons or credential-list-driven authentication attempts; credential material found is used for outbound WebDAV exfiltration, not stuffing. |
| T1111 Multi-Factor Authentication Interception | not_observed | No MFA-interception artifacts exist in the data. The credential-flavored hits are benign: 4648 explicit-credential logons for pbeesly via PSEXESVC.exe/svchost.exe (PsExec lateral movement), LogonType 10 RDP logons using … |
| T1187 Forced Authentication | malicious | Zeek HTTP logs show host 10.0.1.4 (scranton) using DavClnt and Microsoft-WebDAV-MiniRedir/10.0.18362 to reach 192.168.0.4 over WebDAV after SMB 445/139 attempts were rejected (REJ); the first PROPFIND carried an AUTHORIZ… |
| T1212 Exploitation for Credential Access | malicious | LSASS accessed with full access by PowerShell on scranton and wsmprovhost on nashua. |
| T1539 Steal Web Session Cookie | benign | All T1539 hits have benign explanations: the 'cookie' command-line matches are WebDAV DavSetCookie (davclnt.dll) invocations by rundll32.exe on scranton.dmevals.local, and the only *cookie* file creation is an INetCookie… |
| T1552 Unsecured Credentials | malicious | Credential-harvesting toolkit (keystrokes, clipboard, screenshots) staged in SysinternalsSuite on scranton. |
| T1552.001 Credentials In Files | malicious | Hardcoded credentials in Invoke-Exfil script (cozy/MyCozyPassw0rd!) and PsExec command line (Fl0nk3rt0n!T0by). |
| T1552.002 Credentials in Registry | benign | Registry Password/Credential value sets were written by legitimate system processes (svchost, lsass, services, winlogon). |
| T1552.003 Shell History | not_observed | No consolehost_history or shell-history access events found in sysmon/security. |
| T1552.004 Private Keys | malicious | Get-PrivateKeys exported LocalMachine certificates to .pfx (coyn5igj.3io.pfx) on scranton. |
| T1552.006 Group Policy Preferences | benign | GptTmpl.inf/SecEdit access was routine Group Policy processing by svchost.exe and domain machines; no Groups.xml/cpassword access. |
| T1555 Credentials from Password Stores | malicious | PowerShell and WinRM host processes opened LSASS with full-access rights (credential dumping). |
| T1555.003 Credentials from Web Browsers | not_observed | All browser-credential checks (Login Data, logins.json, cookies) returned zero hits across sysmon, security, powershell and other datasets. |
| T1555.004 Windows Credential Manager | malicious | LSASS full-access handles consistent with Windows Credential Manager / DPAPI secret harvesting. |
| T1555.005 Password Managers | not_observed | All password-manager checks (KeePass/1Password/Bitwarden/LastPass) returned zero hits across all datasets. |
| T1556 Modify Authentication Process | malicious | LSASS accessed with full access rights by PowerShell on scranton (credential theft). |
| T1556.001 Domain Controller Authentication | not_observed | Network logons are machine-account (NEWYORK$ etc.) activity; no DC authentication backdoor (Skeleton Key/DSRM/auth-package tampering) observed. |
| T1556.002 Password Filter DLL | not_observed | No password filter DLL registration or load artifacts in any dataset. |
| T1556.005 Reversible Encryption | not_observed | No reversible-encryption indicators (4739, Set-ADUser/dsmod, AllowReversiblePasswordEncryption) found. |
| T1556.006 Multi-Factor Authentication | not_observed | No MFA configuration modification events (4739/5136) found. |
| T1556.007 Hybrid Identity | not_observed | No hybrid identity / federation modification events (5136, Connect-MsolService/Connect-AzureAD) found. |
| T1556.008 Network Provider DLL | not_observed | No network provider DLL registration or modification artifacts found. |
| T1557 Adversary-in-the-Middle | not_observed | No AiTM positioning: object-access events are routine process/registry activity, Sysmon network connections all go to internal DC/host IPs on standard ports with no rogue destinations. |
| T1557.001 Name Resolution Poisoning and SMB Relay | not_observed | SMB/Kerberos flows are legitimate pbeesly domain authentication to the DC; DNS queries are benign; no LLMNR/NBT-NS poisoning, no rogue SMB responder, no relay. |
| T1557.002 ARP Cache Poisoning | not_observed | Each source MAC maps to a single source IP; the responder MAC 12:34:56:78:9a:bc is a synthetic dataset placeholder for the DC, not a MAC claiming multiple victim IPs. No gratuitous ARP. |
| T1557.003 DHCP Spoofing | not_observed | No DHCP event codes in windows.other, no DHCP log type in Zeek, and no Sysmon traffic to ports 67/68. |
| T1558 Steal or Forge Kerberos Tickets | malicious | LSASS memory access by PowerShell and WinRM host on scranton/nashua (credential theft precursor). |
| T1558.001 Golden Ticket | not_observed | All 4769 tickets used RC4 0x12 with normal ticket options; no forged-TGT or krbtgt-hash-theft-then-forge indicators found. |
| T1558.002 Silver Ticket | not_observed | Service tickets observed are KDC-issued for legitimate host SPNs with standard options; no silver-ticket indicators. |
| T1558.003 Kerberoasting | malicious | Kerberos TGS requests for krbtgt and host SPNs by pbeesly (RC4) per anchors. |
| T1558.004 AS-REP Roasting | not_observed | No AS-REP roasting tooling or anomalous AS request patterns observed; PowerShell checks for AS-REP/GetNPUsers returned zero hits. |
| T1606 Forge Web Credentials | not_observed | No forged web credential artifacts. Logon-process stacking shows only normal Kerberos/Advapi/User32/NtLmSsp; windows.other 5857/5858 hits are routine WMI RSOP DeleteInstance by SYSTEM; zeek http/ssl/kerberos hits are Web… |
| T1606.001 Web Cookies | not_observed | Only cookie-related event is a benign INetCookies file creation by svchost.exe in a Windows service profile on scranton.dmevals.local. No PowerShell cookie/Set-Cookie/session script blocks (C344 zero hits) and no cookie-… |
| T1606.002 SAML Tokens | not_observed | Zero hits for SAML/NotOnOrAfter/Assertion in PowerShell (C348), saml/token/cert in Sysmon command lines (C350), and saml/adfs/token URLs in zeek HTTP (C351). No token-minting tooling or federated-service authentication o… |
| T1621 Multi-Factor Authentication Request Generatio… | not_observed | No MFA request generation activity in any dataset. The windows.other 5857/5858 hits are benign WMI/RSOP Group Policy processing by NT AUTHORITY\SYSTEM on newyork.dmevals.local. Searches for MFA/2FA/authenticator/OTP/push… |
| T1649 Steal or Forge Authentication Certificates | malicious | Get-PrivateKeys exported LocalMachine certificates to password-protected .pfx files on scranton. |

## Context (outside the hypothesis)

Activity reported under techniques outside the hypothesis' scope. Not verified, not part of the verdict.

- T1113 · malicious/high · Screen capture (Invoke-ScreenCapture) writing .bmp files on scranton (pivot)
- T1074.001 · malicious/high · Local collection and staging: Rar archive of user files on nashua, 7z staging on scranton (pivot)
- T1070.004 · malicious/high · Anti-forensic deletion of staged archives and tools with sdelete on scranton and nashua (pivot)
- T1105 · malicious/high · Ingress of tooling: SysinternalsSuite.zip download and python.exe/Rar.exe dropped on nashua (pivot)

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

Every MCP tool call of this run (1155), in order (source: mcp_audit.jsonl written by the MCP server).

| Query | Phase | Tool | Arguments | Hits / rows | Cited by |
|---|---|---|---|---|---|
| q-35987462c5 | scope | list_data_sources | {} | None |  |
| q-88c2f45938 | scope | get_registry | {} | None |  |
| q-5ec7399971 | scope | get_fields | {"dataset": "windows.other", "prefix": ""} | None |  |
| q-992ef25c9e | scope | get_fields | {"dataset": "windows.powershell", "prefix": ""} | None |  |
| q-86b362aa49 | scope | get_fields | {"dataset": "windows.security", "prefix": ""} | None |  |
| q-951cf12302 | scope | get_fields | {"dataset": "windows.sysmon", "prefix": ""} | None |  |
| q-e31935a76e | scope | get_fields | {"dataset": "zeek", "prefix": ""} | None |  |
| q-95519670e5 | check C001 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 447 |  |
| q-6dcd43d2b7 | check C002 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-78c3870159 | check C003 | aggregate | {"dataset": "windows.security", "field": "win.ObjectType", "query": "event.code:(4656 OR 4663 OR 4670)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 10977 |  |
| q-939896376b | check C004 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 460 |  |
| q-a837566925 | check C005 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*lsass* OR powershell.script_block_text:*mimikatz* OR powershell.script_block_text:*sekurlsa* OR powershell.script_block_text:*DumpCreds*)", "time_from": null, "time_… | 0 |  |
| q-31d570fee7 | check C006 | search | {"dataset": "windows.other", "query": "message:(*lsass* OR *mimikatz* OR *sekurlsa* OR *procdump*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "p… | 0 |  |
| q-ba50f09f5a | check C007 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-a58f173089 | check C008 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 326 |  |
| q-a62cf203df | check C009 | aggregate | {"dataset": "windows.sysmon", "field": "win.SourceImage", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-fbc4053e49 | check C010 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*lsass* OR file.path:*.dmp)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "pro… | 2 |  |
| q-f5db67c0d0 | check C011 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*lsass* OR process.command_line:*comsvcs* OR process.command_line:*MiniDump*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dat… | 1 |  |
| q-31053655d2 | check C012 | search | {"dataset": "windows.sysmon", "query": "event.code:(13 OR 14) AND registry.path:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.comm… | 0 |  |
| q-2d9e8dda61 | check C013 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4673", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 934 |  |
| q-850a4d4852 | check C014 | search | {"dataset": "windows.security", "query": "event.code:4656 AND win.ObjectName:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command… | 13 |  |
| q-ce05ec3dcc | check C015 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*lsass* OR powershell.script_block_text:*MiniDump* OR powershell.script_block_text:*Invoke-Mimikatz*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "… | 0 |  |
| q-f12a821602 | check C016 | search | {"dataset": "windows.other", "query": "message:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 0 |  |
| q-677ae7cddb | check C017 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*SAM* OR file.path:*SECURITY* OR file.path:*SYSTEM*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "… | 3 |  |
| q-8a8b4b094b | check C018 | search | {"dataset": "windows.sysmon", "query": "event.code:(13 OR 14) AND (registry.path:*SAM* OR registry.path:*SECURITY*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "proces… | 7 |  |
| q-6b29f79891 | check C019 | search | {"dataset": "windows.sysmon", "query": "event.code:2 AND (process.command_line:*SAM* OR process.command_line:*reg*save*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "p… | 0 |  |
| q-60822131c0 | check C020 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*reg save* OR process.command_line:*save*hklm* OR process.command_line:*SAM*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dat… | 0 |  |
| q-686b824872 | check C021 | aggregate | {"dataset": "windows.security", "field": "process.command_line", "query": "event.code:4688 AND (process.command_line:*reg* OR process.command_line:*save*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 6 |  |
| q-17a54289ae | check C022 | search | {"dataset": "windows.security", "query": "event.code:(4656 OR 4663) AND (win.ObjectName:*SAM* OR win.ObjectName:*SECURITY*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name",… | 10 |  |
| q-66fb110def | check C023 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*SAM* OR powershell.script_block_text:*reg save* OR powershell.script_block_text:*hive*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "… | 2 |  |
| q-4f00c4cb8a | check C024 | search | {"dataset": "windows.other", "query": "message:(*SAM* OR *SECURITY hive* OR *reg save*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.comm… | 0 |  |
| q-eefd461bf5 | check C025 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*ntds* OR file.path:*NTDS*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "pro… | 0 |  |
| q-953836ee59 | check C026 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*ntds* OR process.command_line:*vssadmin* OR process.command_line:*ntdsutil* OR process.command_line:*diskshadow*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "ho… | 0 |  |
| q-988d9379b5 | check C027 | search | {"dataset": "windows.sysmon", "query": "event.code:2 AND file.path:*ntds*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "so… | 0 |  |
| q-dd5419ed79 | check C028 | aggregate | {"dataset": "windows.security", "field": "process.command_line", "query": "event.code:4688 AND (process.command_line:*ntds* OR process.command_line:*vssadmin* OR process.command_line:*diskshadow*)", "time_from": null, "time_to": null, "size": 50, "sub_field": … | 0 |  |
| q-6326672310 | check C029 | search | {"dataset": "windows.other", "query": "message:(*shadow* OR *VSS* OR *ntds*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 0 |  |
| q-885edc716b | check C030 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*ntds* OR powershell.script_block_text:*diskshadow* OR powershell.script_block_text:*vssadmin*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.n… | 0 |  |
| q-043fd7d945 | check C031 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 326 |  |
| q-622e629f35 | check C032 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*secrets* OR process.command_line:*lsadump* OR process.command_line:*reg save*HKLM\\\\SECURITY*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observe… | 0 |  |
| q-6c9e9c5039 | check C033 | search | {"dataset": "windows.sysmon", "query": "event.code:7 AND win.ImageLoaded:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_lin… | 1 |  |
| q-d781e3eaf9 | check C034 | search | {"dataset": "windows.security", "query": "event.code:(4656 OR 4663 OR 4670) AND win.ObjectName:*SECURITY*Policy*Secrets*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "p… | 0 |  |
| q-1d5a1a5be0 | check C035 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:(4656 OR 4663 OR 4670) AND win.ObjectName:*Secrets*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-803dc94bbf | check C036 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*Secrets* OR powershell.script_block_text:*lsadump* OR powershell.script_block_text:*LSA*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name",… | 0 |  |
| q-efeccd49a4 | check C037 | search | {"dataset": "windows.other", "query": "message:(*Secrets* OR *LSA* OR *lsadump*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_lin… | 0 |  |
| q-69e5e15779 | check C038 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 326 |  |
| q-d7f1a67dae | check C039 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*cache* OR process.command_line:*DCC2* OR process.command_line:*mscache* OR process.command_line:*cachedump*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.na… | 4 |  |
| q-6ecfcd3821 | check C040 | search | {"dataset": "windows.security", "query": "event.code:(4656 OR 4663 OR 4670) AND (win.ObjectName:*Cache* OR win.ObjectName:*SECURITY*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "u… | 0 |  |
| q-18542fa652 | check C041 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:(4656 OR 4663 OR 4670) AND win.ObjectName:*Cache*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-b9c021b7e3 | check C042 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*cache* OR powershell.script_block_text:*DCC2* OR powershell.script_block_text:*mscache*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", … | 0 |  |
| q-cb58290b2d | check C043 | search | {"dataset": "windows.other", "query": "message:(*cached*credential* OR *mscache* OR *DCC2*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.… | 0 |  |
| q-d45ff6d663 | check C044 | count | {"dataset": "windows.security", "query": "event.code:4662", "time_from": null, "time_to": null} | 7 |  |
| q-6cc2dbeb29 | check C045 | aggregate | {"dataset": "windows.security", "field": "win.AccessMask", "query": "event.code:4662", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 7 |  |
| q-44b482c8d5 | check C046 | aggregate | {"dataset": "windows.security", "field": "win.SubjectUserName", "query": "event.code:4662", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 7 |  |
| q-e4385a596d | check C047 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*drsuapi* OR process.command_line:*lsadump* OR process.command_line:*dcsync*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dat… | 0 |  |
| q-78cdce5f09 | check C048 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*DCSync* OR powershell.script_block_text:*lsadump* OR powershell.script_block_text:*drsuapi*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.nam… | 0 |  |
| q-a4d3a38872 | check C049 | search | {"dataset": "windows.other", "query": "event.code:7045 OR event.code:5858 OR event.code:5857", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process… | 90 |  |
| q-d46425c4e0 | check C050 | search | {"dataset": "zeek", "query": "event.action:dce_rpc AND (zeek.operation:*DRSUAPI* OR zeek.endpoint:*drsuapi* OR zeek.named_pipe:*drsuapi*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code"… | 9 |  |
| q-9963d377c6 | check C051 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 460 |  |
| q-f372826c8f | check C052 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*pcap* OR process.command_line:*sniff* OR process.command_line:*promisc*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.da… | 0 |  |
| q-5d3500b1b7 | check C053 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-72165da2f4 | check C054 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.executable:*tcpdump* OR process.executable:*windump* OR process.executable:*wireshark* OR process.executable:*rawcap* OR process.executable:*npcap*)", "time_from": null, "time_to": null, "fields… | 0 |  |
| q-0a36f77702 | check C055 | search | {"dataset": "windows.sysmon", "query": "event.code:6 AND (win.Image:*npcap* OR win.Image:*pcap* OR win.Image:*winpcap*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "pr… | 0 |  |
| q-6cf5a5cb77 | check C056 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*pcap* OR powershell.script_block_text:*sniff* OR powershell.script_block_text:*promiscuous*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.nam… | 0 |  |
| q-8fd783c8e4 | check C057 | search | {"dataset": "zeek", "query": "event.action:conn AND network.transport:icmp", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "s… | 0 |  |
| q-7b9beb7bac | check C058 | aggregate | {"dataset": "windows.security", "field": "win.ObjectType", "query": "event.code:4656 OR event.code:4663 OR event.code:4670", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 10977 |  |
| q-1a313b4af2 | check C059 | aggregate | {"dataset": "windows.security", "field": "win.AccessMask", "query": "event.code:4656 OR event.code:4663", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 10834 |  |
| q-f179c315fe | check C060 | search | {"dataset": "windows.security", "query": "event.code:4656 AND (win.ObjectName:*lsass* OR win.ObjectName:*credential* OR win.ObjectName:*SAM*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.c… | 23 | F10 |
| q-9105cae2b1 | check C061 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-5ecc0036af | check C062 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-9bd3c6f906 | check C063 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND (win.GrantedAccess:0x1010 OR win.GrantedAccess:0x1410 OR win.GrantedAccess:0x1438 OR win.GrantedAccess:0x143a)", "time_from": null, "time_to": null, "fields": ["@timestamp", … | 0 |  |
| q-073c59cca3 | check C064 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*Get-Credential* OR powershell.script_block_text:*CredentialManager* OR powershell.script_block_text:*keylog*)", "time_from": null, "time_to": null, "fields": ["@time… | 0 |  |
| q-5c3f719407 | check C065 | search | {"dataset": "windows.other", "query": "event.code:7045 OR event.code:5858 OR event.code:5857", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process… | 90 |  |
| q-2b8a7b326c | check C066 | search | {"dataset": "zeek", "query": "event.action:http AND http.request.method:POST", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 0 |  |
| q-0eb2a48421 | check C067 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-cdd65203ec | check C068 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND (win.TargetImage:*lsass* OR win.TargetImage:*winlogon* OR win.TargetImage:*explorer*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event… | 470 | F10 |
| q-61c9df8175 | check C069 | search | {"dataset": "windows.sysmon", "query": "event.code:13 AND (registry.path:*Keyboard* OR registry.path:*keylog* OR registry.path:*Scancode*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code… | 26 |  |
| q-4fc595bbcb | check C070 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*keylog* OR process.command_line:*GetAsyncKeyState* OR process.command_line:*SetWindowsHookEx*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer… | 0 |  |
| q-3fe83a3cc6 | check C071 | aggregate | {"dataset": "windows.security", "field": "win.ObjectType", "query": "event.code:4656 OR event.code:4663 OR event.code:4670", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 10977 |  |
| q-dc24ccd7f1 | check C072 | search | {"dataset": "windows.security", "query": "event.code:4656 AND (win.ObjectName:*lsass* OR win.ObjectName:*winlogon*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "proces… | 13 |  |
| q-689a5bee18 | check C073 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-e52b04b61f | check C074 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*keylog* OR powershell.script_block_text:*GetAsyncKeyState* OR powershell.script_block_text:*SetWindowsHookEx*)", "time_from": null, "time_to": null, "fields": ["@tim… | 0 |  |
| q-7d19203e77 | check C075 | search | {"dataset": "zeek", "query": "event.action:http AND http.request.method:POST", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 0 |  |
| q-e46c94a919 | check C076 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*Credential* OR powershell.script_block_text:*Prompt* OR powershell.script_block_text:*Read-Host*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "hos… | 0 |  |
| q-8958a8f2a8 | check C077 | aggregate | {"dataset": "windows.powershell", "field": "win.ScriptBlockId", "query": "event.code:4104", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 414 |  |
| q-b9db70915d | check C078 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*Credential* OR process.command_line:*prompt* OR process.command_line:*consent*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.… | 3 |  |
| q-1c384214d1 | check C079 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 447 |  |
| q-55caa615d5 | check C080 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*Credential* OR process.command_line:*prompt*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user… | 0 |  |
| q-b1f65ce487 | check C081 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 460 |  |
| q-992fa39f56 | check C082 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-83c2748a83 | check C083 | search | {"dataset": "zeek", "query": "event.action:http AND http.request.method:POST", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 0 |  |
| q-276d36be1f | check C084 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*login* OR file.path:*portal* OR file.path:*wwwroot* OR file.path:*inetpub*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "eve… | 0 |  |
| q-318200f112 | check C085 | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 1649 |  |
| q-6619638166 | check C086 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*iis* OR process.command_line:*w3wp* OR process.command_line:*wwwroot*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset",… | 0 |  |
| q-ae4c00da65 | check C087 | search | {"dataset": "windows.security", "query": "event.code:4663 AND (win.ObjectName:*wwwroot* OR win.ObjectName:*inetpub* OR win.ObjectName:*login*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.… | 0 |  |
| q-807b1f4746 | check C088 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 5337 |  |
| q-981ee02b5b | check C089 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*wwwroot* OR powershell.script_block_text:*login* OR powershell.script_block_text:*credential*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.n… | 0 |  |
| q-cbb04736e8 | check C090 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-cc1606a2d1 | check C091 | search | {"dataset": "zeek", "query": "event.action:http AND (url.original:*login* OR url.original:*portal*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "… | 0 |  |
| q-b65925a134 | check C092 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-d404cfc08a | check C093 | aggregate | {"dataset": "windows.sysmon", "field": "win.SourceImage", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-4d25f3f18a | check C094 | aggregate | {"dataset": "windows.sysmon", "field": "win.ImageLoaded", "query": "event.code:7", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 20259 |  |
| q-461c5504db | check C095 | search | {"dataset": "windows.sysmon", "query": "event.code:8", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinatio… | 95 |  |
| q-0a5c655168 | check C096 | aggregate | {"dataset": "windows.security", "field": "win.CallerProcessName", "query": "event.code:4656 AND win.ObjectType:*Process*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 13 |  |
| q-b8489d5789 | check C097 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:*hook* OR powershell.script_block_text:*SetWindowsHookEx* OR powershell.script_block_text:*MiniDump*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.… | 0 |  |
| q-82c6a1f1a6 | check C098 | search | {"dataset": "windows.other", "query": "message:*hook* OR message:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "sou… | 0 |  |
| q-4997740e8d | check C099 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-5d9a58ad5f | check C100 | aggregate | {"dataset": "windows.security", "field": "source.ip", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-c9e1ec976d | check C101 | timeline | {"dataset": "windows.security", "query": "event.code:4625", "interval": "1m", "time_from": null, "time_to": null} | 0 |  |
| q-c6f553a6fb | check C102 | search | {"dataset": "windows.other", "query": "message:*logon* OR message:*password*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 2 | F14 |
| q-2e44e109ce | check C103 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:*Credential* OR powershell.script_block_text:*Password*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.n… | 0 |  |
| q-cded8413a0 | check C104 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*net* OR process.command_line:*login*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 30 |  |
| q-86744a1690 | check C105 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-3210c8e894 | check C106 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 0 |  |
| q-02579bd869 | check C107 | timeline | {"dataset": "windows.security", "query": "event.code:4625", "interval": "1m", "time_from": null, "time_to": null} | 0 |  |
| q-9cf9a2004e | check C108 | search | {"dataset": "windows.other", "query": "message:*4625* OR message:*failed*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "so… | 2 | F15 |
| q-55feac366d | check C109 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:*Password* OR powershell.script_block_text:*Credential*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.n… | 0 |  |
| q-d714362817 | check C110 | aggregate | {"dataset": "windows.sysmon", "field": "process.command_line", "query": "event.code:1 AND process.command_line:*password*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-216c3057d7 | check C111 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 OR event.code:4656 OR event.code:4670", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 10977 |  |
| q-ab62b1f395 | check C112 | aggregate | {"dataset": "windows.security", "field": "win.ProcessName", "query": "event.code:4663 AND (win.ObjectName:*SAM* OR win.ObjectName:*SECURITY*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-c94587ea94 | check C113 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*hash* OR process.command_line:*crack*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-4d60d26e56 | check C114 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND (win.TargetFilename:*.txt OR win.TargetFilename:*.pot)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 20 |  |
| q-fdddaca381 | check C115 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10 AND (win.TargetImage:*lsass* OR win.TargetImage:*SAM*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-ef66afce11 | check C116 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:*hash* OR powershell.script_block_text:*ConvertTo-SecureString*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code",… | 0 |  |
| q-9e72ec7b1f | check C117 | search | {"dataset": "windows.other", "query": "message:*SAM* OR message:*hash*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "sourc… | 1 | F18 |
| q-e43127a287 | check C118 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-08b2e1c80f | check C119 | aggregate | {"dataset": "windows.security", "field": "source.ip", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-51f29a89fb | check C120 | search | {"dataset": "windows.security", "query": "event.code:4648", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 15 | F17 |
| q-50b00b5f77 | check C121 | timeline | {"dataset": "windows.security", "query": "event.code:4625", "interval": "1m", "time_from": null, "time_to": null} | 0 |  |
| q-7b4ba607d1 | check C122 | search | {"dataset": "windows.other", "query": "message:*logon* OR message:*account*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "… | 7 |  |
| q-33ea8452e7 | check C123 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:*Password* OR powershell.script_block_text:*Credential*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.n… | 0 |  |
| q-68a54b1ff1 | check C124 | aggregate | {"dataset": "windows.sysmon", "field": "process.command_line", "query": "event.code:1 AND process.command_line:*user*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1 |  |
| q-b7429d28ac | check C125 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-eb478826ac | check C126 | aggregate | {"dataset": "windows.security", "field": "source.ip", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-f3728c2232 | check C127 | timeline | {"dataset": "windows.security", "query": "event.code:4625", "interval": "1m", "time_from": null, "time_to": null} | 0 |  |
| q-42a52b7871 | check C128 | search | {"dataset": "windows.other", "query": "message:*logon* OR message:*credential*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line"… | 4 | F18 |
| q-78214bc5b5 | check C129 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:*Credential* OR powershell.script_block_text:*Password*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.n… | 0 |  |
| q-25d4d52ce1 | check C130 | aggregate | {"dataset": "windows.sysmon", "field": "process.command_line", "query": "event.code:1 AND process.command_line:*password*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-106c415c5b | check C131 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 297 |  |
| q-a50114e1a8 | check C132 | search | {"dataset": "windows.security", "query": "event.code:4648", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 15 |  |
| q-4291f0f6d5 | check C133 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-2d1154c70a | check C134 | search | {"dataset": "windows.sysmon", "query": "event.code:13 AND registry.path:*Credential*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command… | 11 |  |
| q-1e078c898c | check C135 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND powershell.script_block_text:*Credential*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executab… | 0 |  |
| q-69c6dc0a6b | check C136 | search | {"dataset": "windows.other", "query": "message:*Credential*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "des… | 2 | F22 |
| q-05f0335794 | check C137 | aggregate | {"dataset": "windows.security", "field": "win.ObjectType", "query": "event.code:4656 OR event.code:4663 OR event.code:4670", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 10977 |  |
| q-471eba9bd2 | check C138 | search | {"dataset": "windows.security", "query": "event.code:5140 OR event.code:5145", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 163 | F24 |
| q-95166f0c51 | check C139 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1649 |  |
| q-7a2ab56bce | check C140 | search | {"dataset": "windows.sysmon", "query": "event.code:3 AND (destination.port:445 OR destination.port:139)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable… | 66 | F25 |
| q-d3963dcc90 | check C141 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*445* OR powershell.script_block_text:*WebDAV* OR powershell.script_block_text:*NTLM*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "ob… | 0 |  |
| q-d613523edf | check C142 | search | {"dataset": "windows.other", "query": "message:*445* OR message:*WebDAV*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "sou… | 0 |  |
| q-3b24a8bda6 | check C143 | aggregate | {"dataset": "zeek", "field": "destination.port", "query": "event.action:conn AND (destination.port:445 OR destination.port:139)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 50 |  |
| q-631471dfa1 | check C144 | search | {"dataset": "zeek", "query": "event.action:http AND (http.request.method:PROPFIND OR http.request.method:MOVE OR http.request.method:OPTIONS)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.c… | 36 |  |
| q-30e40e9134 | check C145 | aggregate | {"dataset": "windows.security", "field": "event.code", "query": "event.code:4768 OR event.code:4769 OR event.code:4770", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 42 |  |
| q-7d51845cf6 | check C146 | search | {"dataset": "windows.security", "query": "event.code:4769", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 28 | F28 |
| q-47b0b10c22 | check C147 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-b79ac6ee64 | check C148 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.GrantedAccess:*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line",… | 39283 |  |
| q-66eacf1f47 | check C149 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*Invoke-* OR powershell.script_block_text:*Exploit*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "ev… | 0 |  |
| q-bc3e1c6533 | check C150 | search | {"dataset": "windows.other", "query": "message:*exploit*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destin… | 0 |  |
| q-bfa05ccfb0 | check C151 | search | {"dataset": "zeek", "query": "event.action:notice OR event.action:weird", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "sour… | 14 | F29 |
| q-baf9ab5e50 | check C152 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 460 |  |
| q-48cc433be5 | check C153 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*cookie* OR process.command_line:*Cookie*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.nam… | 5 |  |
| q-35dab1bc3b | check C154 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1649 |  |
| q-72f391002c | check C155 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (win.TargetFilename:*Cookies* OR win.TargetFilename:*cookie*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "pr… | 1 |  |
| q-2ae5a13fda | check C156 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-27107017b5 | check C157 | search | {"dataset": "windows.sysmon", "query": "event.code:2 AND (win.TargetFilename:*Cookies* OR win.TargetFilename:*cookie*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "pro… | 0 |  |
| q-fbebcbaffd | check C158 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*cookie* OR powershell.script_block_text:*Cookie*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "even… | 0 |  |
| q-b81d8a955c | check C159 | search | {"dataset": "windows.other", "query": "message:*cookie*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destina… | 0 |  |
| q-8f5c08ed59 | check C160 | search | {"dataset": "zeek", "query": "event.action:http AND http.request.method:GET", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "… | 2 |  |
| q-c0588029da | check C161 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 460 |  |
| q-b18e9614c0 | check C162 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*password* OR process.command_line:*credential* OR process.command_line:*unattend*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name",… | 0 |  |
| q-c3d69a87b5 | check C163 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1649 |  |
| q-d6c48c860d | check C164 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (win.TargetFilename:*unattend* OR win.TargetFilename:*password* OR win.TargetFilename:*credential*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.da… | 1 |  |
| q-8c25ad449c | check C165 | aggregate | {"dataset": "windows.sysmon", "field": "registry.path", "query": "event.code:13 OR event.code:14", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 17541 |  |
| q-9e80e56cb7 | check C166 | search | {"dataset": "windows.sysmon", "query": "event.code:13 AND (registry.path:*Password* OR registry.path:*Credential*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process… | 17 | F37 |
| q-da051acd3f | check C167 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*password* OR powershell.script_block_text:*credential*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset",… | 0 |  |
| q-1a0758a332 | check C168 | search | {"dataset": "windows.other", "query": "message:*password*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 0 |  |
| q-e563c315cd | check C169 | search | {"dataset": "zeek", "query": "event.action:smb_files", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinatio… | 12 |  |
| q-fde1313a23 | check C170 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 297 |  |
| q-b07c982846 | check C171 | search | {"dataset": "windows.security", "query": "event.code:4648", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 15 |  |
| q-abf6b7787d | check C172 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 447 |  |
| q-025b9a1afe | check C173 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*password* OR process.command_line:*credential* OR process.command_line:*config*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event… | 8 |  |
| q-4f713f60fa | check C174 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1649 |  |
| q-4f6ab869f7 | check C175 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (win.TargetFilename:*.config OR win.TargetFilename:*.xml OR win.TargetFilename:*.txt)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event… | 44 |  |
| q-e9119e1d9a | check C176 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*Get-Content* OR powershell.script_block_text:*Select-String*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dat… | 0 |  |
| q-e8727729bf | check C177 | search | {"dataset": "windows.other", "query": "message:*password*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 0 |  |
| q-0e358265c9 | check C178 | search | {"dataset": "zeek", "query": "event.action:smb_files", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinatio… | 12 |  |
| q-a4484567ea | check C179 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"13\" AND (TO_LOWER(registry.path) LIKE \"*\\\\sam\\\\*\" OR TO_LOWER(registry.path) LIKE \"*\\\\security\\\\*\" OR TO_LOWER(registry.path) LIKE \"*password*\" OR TO_LOWER… | ERROR |  |
| q-1593faaf1a | check C179 (repaired) | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"13\" AND (TO_LOWER(registry.path) LIKE \"*\\\\\\\\sam\\\\\\\\*\" OR TO_LOWER(registry.path) LIKE \"*\\\\\\\\security\\\\\\\\*\" OR TO_LOWER(registry.path) LIKE \"*passwor… | 60 |  |
| q-d596772685 | check C180 | aggregate | {"dataset": "windows.sysmon", "field": "registry.path", "query": "event.code:13", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 17541 |  |
| q-5f7535cc15 | check C181 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*reg query*\" OR TO_LOWER(process.command_line) LIKE \"*reg save*\" OR TO_LOWER(process.command_line) LIKE \"*\\\\sam*\" OR… | ERROR |  |
| q-50b5fa01b8 | check C181 (repaired) | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*reg query*\" OR TO_LOWER(process.command_line) LIKE \"*reg save*\" OR TO_LOWER(process.command_line) LIKE \"*sam*\" OR TO_… | 5 |  |
| q-163c310e1f | check C182 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4663\",\"4656\",\"4670\",\"4658\") AND (TO_LOWER(win.ObjectName) LIKE \"*\\\\sam*\" OR TO_LOWER(win.ObjectName) LIKE \"*\\\\security*\" OR TO_LOWER(win.ObjectName) LIK… | ERROR |  |
| q-a60e99b4ce | check C182 (repaired) | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4663\",\"4656\",\"4670\",\"4658\") AND (TO_LOWER(win.ObjectName) LIKE \"*\\\\\\\\sam*\" OR TO_LOWER(win.ObjectName) LIKE \"*\\\\\\\\security*\" OR TO_LOWER(win.ObjectN… | 500 |  |
| q-4ac5d3ae71 | check C183 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code IN (\"4103\",\"4104\") AND (TO_LOWER(COALESCE(powershell.script_block_text, win.ScriptBlockText, \"\")) LIKE \"*reg query*\" OR TO_LOWER(COALESCE(powershell.script_block_t… | ERROR |  |
| q-5976551044 | check C183 (repaired) | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code IN (\"4103\",\"4104\") AND (TO_LOWER(COALESCE(win.ScriptBlockText, \"\")) LIKE \"*reg query*\" OR TO_LOWER(COALESCE(win.ScriptBlockText, \"\")) LIKE \"*reg save*\" OR TO_L… | 1 |  |
| q-b2986d2f59 | check C184 | esql | {"query": "FROM logs-windows.other-default METADATA _id, _index \| WHERE TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*\\\\sam*\" OR TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*\\\\security*\" OR TO_LOWER(COALESCE(message, win.Message, \"\"… | ERROR |  |
| q-28c10d5ae9 | check C184 (repaired) | esql | {"query": "FROM logs-windows.other-default METADATA _id, _index \| WHERE TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*\\\\\\\\sam*\" OR TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*\\\\\\\\security*\" OR TO_LOWER(COALESCE(message, win.Messa… | 3 |  |
| q-d9a6ec3efd | check C185 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code IN (\"4103\",\"4104\") AND (TO_LOWER(COALESCE(powershell.script_block_text, win.ScriptBlockText, \"\")) LIKE \"*history*\" OR TO_LOWER(COALESCE(powershell.script_block_tex… | ERROR |  |
| q-0f76a07163 | check C185 (repaired) | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code IN (\"4103\",\"4104\") AND (TO_LOWER(COALESCE(win.ScriptBlockText, \"\")) LIKE \"*history*\" OR TO_LOWER(COALESCE(win.ScriptBlockText, \"\")) LIKE \"*consolehost_history*\… | 1 |  |
| q-8643571ca4 | check C186 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*consolehost_history*\" OR TO_LOWER(process.command_line) LIKE \"*psreadline*\" OR TO_LOWER(process.command_line) LIKE \"*h… | 0 |  |
| q-94d1b8c61d | check C187 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*consolehost_history*\" OR TO_LOWER(file.path) LIKE \"*psreadline*\" OR TO_LOWER(file.path) LIKE \"*\\\\history*\" OR TO_LOWER(file.p… | ERROR |  |
| q-f97caaa0c8 | check C187 (repaired) | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*consolehost_history*\" OR TO_LOWER(file.path) LIKE \"*psreadline*\" OR TO_LOWER(file.path) LIKE \"*history*\") \| KEEP @timestamp, h… | 15 |  |
| q-393ba102c2 | check C188 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4663\",\"4656\",\"4658\") AND (TO_LOWER(win.ObjectName) LIKE \"*consolehost_history*\" OR TO_LOWER(win.ObjectName) LIKE \"*psreadline*\" OR TO_LOWER(win.ObjectName) LI… | 0 |  |
| q-526ce7cbac | check C189 | esql | {"query": "FROM logs-windows.other-default METADATA _id, _index \| WHERE TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*history*\" OR TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*psreadline*\" \| KEEP @timestamp, host.name, event.code, messag… | 5 |  |
| q-c7e5cb1351 | check C190 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*.key\" OR TO_LOWER(file.path) LIKE \"*.pgp\" OR TO_LOWER(file.path) LIKE \"*.gpg\" OR TO_LOWER(file.path) LIKE \"*.ppk\" OR TO_LOWER… | 1 |  |
| q-e6e6aa4fe8 | check C191 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*.pem*\" OR TO_LOWER(process.command_line) LIKE \"*.pfx*\" OR TO_LOWER(process.command_line) LIKE \"*.p12*\" OR TO_LOWER(pr… | 0 |  |
| q-b7e5144b7c | check C192 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"5145\" AND (TO_LOWER(win.RelativeTargetName) LIKE \"*.key\" OR TO_LOWER(win.RelativeTargetName) LIKE \"*.pem\" OR TO_LOWER(win.RelativeTargetName) LIKE \"*.pfx\" OR TO_… | 0 |  |
| q-e6a6a92e28 | check C193 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4663\",\"4656\",\"4658\") AND (TO_LOWER(win.ObjectName) LIKE \"*.key\" OR TO_LOWER(win.ObjectName) LIKE \"*.pem\" OR TO_LOWER(win.ObjectName) LIKE \"*.pfx\" OR TO_LOWE… | 0 |  |
| q-45961c0a26 | check C194 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code IN (\"4103\",\"4104\") AND (TO_LOWER(COALESCE(powershell.script_block_text, win.ScriptBlockText, \"\")) LIKE \"*.pem*\" OR TO_LOWER(COALESCE(powershell.script_block_text, … | ERROR |  |
| q-2259366a56 | check C194 (repaired) | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code IN (\"4103\",\"4104\") AND (TO_LOWER(COALESCE(win.ScriptBlockText, \"\")) LIKE \"*.pem*\" OR TO_LOWER(COALESCE(win.ScriptBlockText, \"\")) LIKE \"*.pfx*\" OR TO_LOWER(COAL… | 2 |  |
| q-479378e509 | check C195 | esql | {"query": "FROM logs-windows.other-default METADATA _id, _index \| WHERE TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*.pem*\" OR TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*.pfx*\" OR TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*… | 0 |  |
| q-2b3f9b132c | check C196 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code IN (\"4103\",\"4104\") AND (TO_LOWER(COALESCE(powershell.script_block_text, win.ScriptBlockText, \"\")) LIKE \"*groups.xml*\" OR TO_LOWER(COALESCE(powershell.script_block_… | ERROR |  |
| q-89d8814dc9 | check C196 (repaired) | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code IN (\"4103\",\"4104\") AND (TO_LOWER(COALESCE(win.ScriptBlockText, \"\")) LIKE \"*groups.xml*\" OR TO_LOWER(COALESCE(win.ScriptBlockText, \"\")) LIKE \"*sysvol*\" OR TO_LO… | 32 |  |
| q-4f46c0a60a | check C197 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*sysvol*\" OR TO_LOWER(process.command_line) LIKE \"*groups.xml*\" OR TO_LOWER(process.command_line) LIKE \"*cpassword*\" O… | 0 |  |
| q-4d37bc340e | check C198 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*groups.xml*\" OR TO_LOWER(file.path) LIKE \"*sysvol*\" OR TO_LOWER(file.path) LIKE \"*gpprefdecrypt*\" OR TO_LOWER(file.path) LIKE \… | 22 |  |
| q-a7177abb7f | check C199 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"5145\" AND (TO_LOWER(win.RelativeTargetName) LIKE \"*groups.xml*\" OR TO_LOWER(win.ShareName) LIKE \"*sysvol*\" OR TO_LOWER(win.ShareName) LIKE \"*netlogon*\") \| KEEP … | 56 |  |
| q-b1eb553156 | check C200 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4663\",\"4656\",\"4658\") AND (TO_LOWER(win.ObjectName) LIKE \"*groups.xml*\" OR TO_LOWER(win.ObjectName) LIKE \"*sysvol*\" OR TO_LOWER(win.ObjectName) LIKE \"*gpp*\")… | 0 |  |
| q-21459e52de | check C201 | esql | {"query": "FROM logs-windows.other-default METADATA _id, _index \| WHERE TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*sysvol*\" OR TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*groups.xml*\" OR TO_LOWER(COALESCE(message, win.Message, \"\")) … | 0 |  |
| q-f96d7a8c3f | check C202 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND (TO_LOWER(win.TargetImage) LIKE \"*lsass.exe\" OR TO_LOWER(win.SourceImage) LIKE \"*lsass.exe\") \| KEEP @timestamp, host.name, user.name, win.SourceImage, win.T… | 500 | F41 |
| q-3c71156d7f | check C203 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass.exe", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-50286b7d5a | check C204 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*sekurlsa*\" OR TO_LOWER(process.command_line) LIKE \"*lsadump*\" OR TO_LOWER(process.command_line) LIKE \"*mimikatz*\" OR … | 0 |  |
| q-73d660100d | check C205 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4663\",\"4656\",\"4670\",\"4658\") AND (TO_LOWER(win.ObjectName) LIKE \"*\\\\protect\\\\*\" OR TO_LOWER(win.ObjectName) LIKE \"*credential*\" OR TO_LOWER(win.ObjectNam… | ERROR |  |
| q-d663dd5431 | check C205 (repaired) | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4663\",\"4656\",\"4670\",\"4658\") AND (TO_LOWER(win.ObjectName) LIKE \"*protect*\" OR TO_LOWER(win.ObjectName) LIKE \"*credential*\" OR TO_LOWER(win.ObjectName) LIKE … | 19 |  |
| q-fb0266e930 | check C206 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4688\" AND (TO_LOWER(process.command_line) LIKE \"*sekurlsa*\" OR TO_LOWER(process.command_line) LIKE \"*lsadump*\" OR TO_LOWER(process.command_line) LIKE \"*mimikatz*\… | 0 |  |
| q-b2520365a6 | check C207 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code IN (\"4103\",\"4104\") AND (TO_LOWER(COALESCE(powershell.script_block_text, win.ScriptBlockText, \"\")) LIKE \"*sekurlsa*\" OR TO_LOWER(COALESCE(powershell.script_block_te… | ERROR |  |
| q-2ccaab0271 | check C207 (repaired) | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code IN (\"4103\",\"4104\") AND (TO_LOWER(COALESCE(win.ScriptBlockText, \"\")) LIKE \"*sekurlsa*\" OR TO_LOWER(COALESCE(win.ScriptBlockText, \"\")) LIKE \"*lsadump*\" OR TO_LOW… | 5 |  |
| q-271a4b0f60 | check C208 | esql | {"query": "FROM logs-windows.other-default METADATA _id, _index \| WHERE TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*lsass*\" OR TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*credential*\" OR TO_LOWER(COALESCE(message, win.Message, \"\")) L… | 2 |  |
| q-6872ee550f | check C209 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*login data*\" OR TO_LOWER(process.command_line) LIKE \"*\\\\google\\\\chrome\\\\user data*\" OR TO_LOWER(process.command_l… | ERROR |  |
| q-8fa1f5ad79 | check C209 (repaired) | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*login data*\" OR TO_LOWER(process.command_line) LIKE \"*google*chrome*user data*\" OR TO_LOWER(process.command_line) LIKE … | 0 |  |
| q-0bf63c35b6 | check C210 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*login data*\" OR TO_LOWER(file.path) LIKE \"*logins.json*\" OR TO_LOWER(file.path) LIKE \"*key3.db*\" OR TO_LOWER(file.path) LIKE \"… | ERROR |  |
| q-e2deaefcf5 | check C210 (repaired) | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*login data*\" OR TO_LOWER(file.path) LIKE \"*logins.json*\" OR TO_LOWER(file.path) LIKE \"*key3.db*\" OR TO_LOWER(file.path) LIKE \"… | 0 |  |
| q-6043e6fc18 | check C211 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND (TO_LOWER(win.TargetImage) LIKE \"*chrome.exe\" OR TO_LOWER(win.TargetImage) LIKE \"*firefox.exe\" OR TO_LOWER(win.TargetImage) LIKE \"*msedge.exe\" OR TO_LOWER(… | 0 |  |
| q-fbdc73250c | check C212 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4663\",\"4656\",\"4658\") AND (TO_LOWER(win.ObjectName) LIKE \"*login data*\" OR TO_LOWER(win.ObjectName) LIKE \"*logins.json*\" OR TO_LOWER(win.ObjectName) LIKE \"*ke… | ERROR |  |
| q-83cf81f93a | check C212 (repaired) | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4663\",\"4656\",\"4658\") AND (TO_LOWER(win.ObjectName) LIKE \"*login data*\" OR TO_LOWER(win.ObjectName) LIKE \"*logins.json*\" OR TO_LOWER(win.ObjectName) LIKE \"*ke… | 0 |  |
| q-cc262efdb5 | check C213 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code IN (\"4103\",\"4104\") AND (TO_LOWER(COALESCE(powershell.script_block_text, win.ScriptBlockText, \"\")) LIKE \"*login data*\" OR TO_LOWER(COALESCE(powershell.script_block_… | ERROR |  |
| q-a46243127d | check C213 (repaired) | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code IN (\"4103\",\"4104\") AND (TO_LOWER(COALESCE(win.ScriptBlockText, \"\")) LIKE \"*login data*\" OR TO_LOWER(COALESCE(win.ScriptBlockText, \"\")) LIKE \"*logins.json*\" OR … | 0 |  |
| q-a91baada15 | check C214 | esql | {"query": "FROM logs-windows.other-default METADATA _id, _index \| WHERE TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*login data*\" OR TO_LOWER(COALESCE(message, win.Message, \"\")) LIKE \"*logins.json*\" OR TO_LOWER(COALESCE(message, win.Message, \"… | 0 |  |
| q-26366cbc8c | check C215 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 326 | F42 |
| q-e12dfd6e49 | check C216 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-0ece74b7a3 | check C217 | search | {"dataset": "windows.sysmon", "query": "event.code:15 AND file.path:*Credentials*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 0 |  |
| q-aca40a7111 | check C218 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*vault* OR process.command_line:*Credential* OR process.command_line:*cmdkey*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "eve… | 0 |  |
| q-bdaacc6b6f | check C219 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*Credential* OR powershell.script_block_text:*vault* OR powershell.script_block_text:*cmdkey*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.na… | 0 |  |
| q-cac7cf4939 | check C220 | search | {"dataset": "windows.other", "query": "message:*Credential* OR message:*vault*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line"… | 2 |  |
| q-823ec7325f | check C221 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.executable:*keepass* OR process.executable:*1password* OR process.executable:*bitwarden* OR process.executable:*lastpass* OR process.executable:*dashlane*)", "time_from": null, "time_to": null, … | 0 |  |
| q-efd118a817 | check C222 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*keepass* OR file.path:*1password* OR file.path:*bitwarden* OR file.path:*lastpass*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.datase… | 0 |  |
| q-a22e129488 | check C223 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND (win.TargetImage:*keepass* OR win.TargetImage:*1password* OR win.TargetImage:*bitwarden*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "e… | 0 |  |
| q-4a2ec01247 | check C224 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*keepass* OR process.command_line:*1password* OR process.command_line:*bitwarden* OR process.command_line:*kdbx*)", "time_from": null, "time_to": null, "fields": ["@timestamp",… | 0 |  |
| q-408bfaabd0 | check C225 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*keepass* OR powershell.script_block_text:*kdbx* OR powershell.script_block_text:*1password* OR powershell.script_block_text:*bitwarden*)", "time_from": null, "time_t… | 0 |  |
| q-e3d0d51ad3 | check C226 | search | {"dataset": "windows.other", "query": "message:*keepass* OR message:*1password* OR message:*bitwarden* OR message:*kdbx*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "p… | 0 |  |
| q-5c2d987e11 | check C227 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 326 |  |
| q-846fac8661 | check C228 | aggregate | {"dataset": "windows.sysmon", "field": "win.SourceImage", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-60878c155d | check C229 | search | {"dataset": "windows.sysmon", "query": "event.code:7 AND (win.ImageLoaded:*lsass* OR win.ImageLoaded:*cryptdll* OR win.ImageLoaded:*sam* OR win.ImageLoaded:*msv1_0*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "… | 77 |  |
| q-d827cbdf40 | check C230 | search | {"dataset": "windows.security", "query": "event.code:4657 AND (win.ObjectName:*lsass* OR win.ObjectName:*cryptdll* OR win.ObjectName:*msv1_0* OR win.ObjectName:*sam*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", … | 0 |  |
| q-743a8535f7 | check C231 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*lsass* OR process.command_line:*cryptdll* OR process.command_line:*msv1_0*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event… | 0 |  |
| q-f04a0204b3 | check C232 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*lsass* OR powershell.script_block_text:*cryptdll* OR powershell.script_block_text:*msv1_0* OR powershell.script_block_text:*SecurityPackages*)", "time_from": null, "… | 0 |  |
| q-644911e11e | check C233 | search | {"dataset": "windows.other", "query": "message:*lsass* OR message:*cryptdll* OR message:*msv1_0*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "pro… | 0 |  |
| q-4c7ad0a06f | check C234 | search | {"dataset": "windows.security", "query": "event.code:4624 AND win.LogonType:3", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line",… | 218 | F44 |
| q-d176516007 | check C235 | search | {"dataset": "windows.security", "query": "event.code:4648", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 15 |  |
| q-a769e8a34a | check C236 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4624 OR event.code:4648", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 312 |  |
| q-38eb21da18 | check C237 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 326 |  |
| q-ddd0457bde | check C238 | search | {"dataset": "windows.sysmon", "query": "event.code:7 AND (win.ImageLoaded:*lsass* OR win.ImageLoaded:*cryptdll*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.e… | 33 |  |
| q-2f604b7b7a | check C239 | search | {"dataset": "windows.other", "query": "message:*lsass* OR message:*cryptdll*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", … | 0 |  |
| q-8a835b08eb | check C240 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*lsass* OR powershell.script_block_text:*cryptdll* OR powershell.script_block_text:*Skeleton* OR powershell.script_block_text:*DCShadow*)", "time_from": null, "time_t… | 0 |  |
| q-87991494f5 | check C241 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*System32* AND (file.path:*.dll))", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable"… | 0 |  |
| q-7eb503e509 | check C242 | search | {"dataset": "windows.sysmon", "query": "event.code:7 AND (win.ImageLoaded:*lsass* OR win.ImageLoaded:*cryptdll*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.e… | 33 |  |
| q-903977a202 | check C243 | search | {"dataset": "windows.security", "query": "event.code:4657 AND (win.ObjectName:*Notification\\ Packages* OR win.ObjectName:*Password* OR win.ObjectName:*lsass*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.… | 0 |  |
| q-04d31ac643 | check C244 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*Notification* OR process.command_line:*PasswordFilter*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.co… | 0 |  |
| q-e2c73ce034 | check C245 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*Notification* OR powershell.script_block_text:*PasswordFilter* OR powershell.script_block_text:*lsass*)", "time_from": null, "time_to": null, "fields": ["@timestamp"… | 0 |  |
| q-6b5c26671b | check C246 | search | {"dataset": "windows.other", "query": "message:*Notification* OR message:*PasswordFilter* OR message:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.execu… | 10 |  |
| q-df60009715 | check C247 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*AllowReversiblePasswordEncryption* OR powershell.script_block_text:*ReversibleEncryption* OR powershell.script_block_text:*Set-ADUser*)", "time_from": null, "time_to… | 0 |  |
| q-3778bdc13e | check C248 | search | {"dataset": "windows.powershell", "query": "event.code:4103 AND (message:*AllowReversiblePasswordEncryption* OR message:*ReversibleEncryption*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event… | 0 |  |
| q-1902fbbb17 | check C249 | search | {"dataset": "windows.security", "query": "event.code:4739", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 0 |  |
| q-a27dff5e72 | check C250 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*Reversible* OR process.command_line:*Set-ADUser* OR process.command_line:*dsmod*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", … | 0 |  |
| q-39c0e65627 | check C251 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*Reversible* OR process.command_line:*Set-ADUser* OR process.command_line:*dsmod*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "even… | 0 |  |
| q-e74f8e7d7f | check C252 | search | {"dataset": "windows.other", "query": "message:*Reversible* OR message:*AllowReversiblePasswordEncryption*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executa… | 0 |  |
| q-189e1b3804 | check C253 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(powershell.script_block_text) LIKE \"*set-aduser*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*set-adauthenticationpolicy*\" OR TO_LOWER(powershell.script_block_text)… | ERROR |  |
| q-c146c5b405 | check C253 (repaired) | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*set-aduser*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*set-adauthenticationpolicy*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*strongauthenticati… | 1 |  |
| q-ee6f12e030 | check C254 | count | {"dataset": "windows.security", "query": "event.code:4739", "time_from": null, "time_to": null} | 0 |  |
| q-e63af22227 | check C255 | aggregate | {"dataset": "windows.security", "field": "win.ObjectType", "query": "event.code:5136 OR event.code:4739", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-2689f71634 | check C256 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*set-aduser*\" OR TO_LOWER(process.command_line) LIKE \"*set-adauthenticationpolicy*\" OR TO_LOWER(process.command_line) LI… | 0 |  |
| q-a2314bbb2d | check C257 | search | {"dataset": "windows.other", "query": "event.code:4739 OR event.code:5136 OR event.code:4738", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process… | 0 |  |
| q-2e98b796d3 | check C258 | aggregate | {"dataset": "windows.security", "field": "win.LogonProcessName", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 297 |  |
| q-8fdf0d0bb4 | check C259 | aggregate | {"dataset": "windows.security", "field": "win.AuthenticationPackageName", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 297 |  |
| q-39439cc104 | check C260 | count | {"dataset": "windows.security", "query": "event.code:5136", "time_from": null, "time_to": null} | 0 |  |
| q-60a7a32920 | check C261 | aggregate | {"dataset": "windows.sysmon", "field": "win.ImageLoaded", "query": "event.code:7", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 20259 |  |
| q-81ea337fab | check C262 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(powershell.script_block_text) LIKE \"*connect-msolservice*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*connect-azuread*\" OR TO_LOWER(powershell.script_block_text) L… | ERROR |  |
| q-b0681e1a0c | check C262 (repaired) | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*connect-msolservice*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*connect-azuread*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*new-azuread*\" OR TO… | 0 |  |
| q-41d6c22f33 | check C263 | search | {"dataset": "windows.other", "query": "event.code:5136 OR event.code:4739 OR event.code:4738", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process… | 0 |  |
| q-ab5a01b131 | check C264 | count | {"dataset": "windows.security", "query": "event.code:4657", "time_from": null, "time_to": null} | 36 |  |
| q-fb608aac05 | check C265 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4657\" AND (TO_LOWER(win.ObjectName) LIKE \"*networkprovider*\" OR TO_LOWER(win.ObjectName) LIKE \"*credential*\" OR TO_LOWER(win.ObjectName) LIKE \"*winlogon*\") \| KE… | 0 |  |
| q-3ed4d947e3 | check C266 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*networkprovider*\" OR TO_LOWER(file.path) LIKE \"*system32*credential*\" OR TO_LOWER(file.path) LIKE \"*winlogon*\") \| KEEP @timest… | 1 |  |
| q-aaadfaba9b | check C267 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 39283 |  |
| q-0ea649f661 | check C268 | aggregate | {"dataset": "windows.sysmon", "field": "win.ImageLoaded", "query": "event.code:7", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 20259 |  |
| q-262db92522 | check C269 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(powershell.script_block_text) LIKE \"*networkprovider*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*new-itemproperty*\" OR TO_LOWER(powershell.script_block_text) LIKE… | ERROR |  |
| q-f6b1ba400e | check C269 (repaired) | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*networkprovider*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*new-itemproperty*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*reg add*\" \| KEEP @tim… | 0 |  |
| q-1a2717c970 | check C270 | search | {"dataset": "windows.other", "query": "event.code:4657 OR event.code:11 OR event.code:7", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.comm… | 4 |  |
| q-63e95cab7c | check C271 | aggregate | {"dataset": "windows.security", "field": "win.ObjectType", "query": "event.code:4663 OR event.code:4670 OR event.code:4656", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 10977 |  |
| q-7b60286dc3 | check C272 | aggregate | {"dataset": "windows.security", "field": "win.ProcessName", "query": "event.code:4663 OR event.code:4670 OR event.code:4656", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 10977 |  |
| q-b1bddd0bd4 | check C273 | aggregate | {"dataset": "windows.sysmon", "field": "win.DestinationHostname", "query": "event.code:3", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 1229 |  |
| q-03dd8c6cb6 | check C274 | aggregate | {"dataset": "windows.sysmon", "field": "win.QueryName", "query": "event.code:22", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 81 |  |
| q-c7f25d91a4 | check C275 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(powershell.script_block_text) LIKE \"*responder*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*mitm*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*arpspoof*\" OR… | ERROR |  |
| q-6c6f7907a6 | check C275 (repaired) | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*responder*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*mitm*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*arpspoof*\" OR TO_LOWER(win.ScriptBlockTe… | 0 |  |
| q-74c0daf06f | check C276 | search | {"dataset": "windows.other", "query": "event.code:4663 OR event.code:4670 OR event.code:4656 OR event.code:3 OR event.code:22", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name… | 2 |  |
| q-4d46de9d48 | check C277 | aggregate | {"dataset": "zeek", "field": "zeek.conn_state", "query": "event.action:conn", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 613 |  |
| q-fa6cea9312 | check C278 | aggregate | {"dataset": "zeek", "field": "zeek.service", "query": "event.action:conn", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 613 |  |
| q-da4e350385 | check C279 | count | {"dataset": "windows.security", "query": "event.code:4697", "time_from": null, "time_to": null} | 23 |  |
| q-12ac1fc8c5 | check C280 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4657\" AND TO_LOWER(win.ObjectName) LIKE \"*dnsclient*\" \| KEEP @timestamp, host.name, user.name, win.ObjectName, win.NewValue, _id, _index"} | 0 |  |
| q-fbfcc3dbfc | check C281 | aggregate | {"dataset": "windows.sysmon", "field": "win.DestinationHostname", "query": "event.code:3", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 1229 |  |
| q-9941ef15e2 | check C282 | aggregate | {"dataset": "windows.sysmon", "field": "win.QueryName", "query": "event.code:22", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 81 |  |
| q-03b438ebfb | check C283 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(powershell.script_block_text) LIKE \"*llmnr*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*nbt-ns*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*responder*\" OR … | ERROR |  |
| q-aa00f0480c | check C283 (repaired) | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*llmnr*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*nbt-ns*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*responder*\" OR TO_LOWER(win.ScriptBlockTex… | 0 |  |
| q-729cc5cd83 | check C284 | search | {"dataset": "windows.other", "query": "event.code:4697 OR event.code:4657 OR event.code:3 OR event.code:22", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executa… | 2 |  |
| q-fa91de7e39 | check C285 | aggregate | {"dataset": "zeek", "field": "zeek.id_resp_h", "query": "event.action:conn AND zeek.service:smb", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-161a7f7951 | check C286 | aggregate | {"dataset": "zeek", "field": "zeek.query", "query": "event.action:dns", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 53 |  |
| q-5617abce71 | check C287 | aggregate | {"dataset": "windows.sysmon", "field": "win.DestinationHostname", "query": "event.code:3", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 1229 |  |
| q-bbeb6af7b1 | check C288 | aggregate | {"dataset": "windows.sysmon", "field": "win.QueryName", "query": "event.code:22", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 81 |  |
| q-e361dbfa38 | check C289 | aggregate | {"dataset": "windows.security", "field": "win.ProcessName", "query": "event.code:4663 OR event.code:4670 OR event.code:4656", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 10977 |  |
| q-93bc0e5519 | check C290 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(powershell.script_block_text) LIKE \"*arp*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*netsh interface*\" OR TO_LOWER(powershell.script_block_text) LIKE \"*get-netne… | ERROR |  |
| q-ada0dd2134 | check C290 (repaired) | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*arp*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*netsh interface*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*get-netneighbor*\" OR TO_LOWER(win.S… | 0 |  |
| q-89ff2aa4bf | check C291 | search | {"dataset": "windows.other", "query": "event.code:3 OR event.code:22 OR event.code:4663 OR event.code:4670", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executa… | 2 |  |
| q-a26c1ab931 | check C292 | aggregate | {"dataset": "zeek", "field": "zeek.orig_l2_addr", "query": "event.action:conn", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 613 |  |
| q-93c370a596 | check C293 | aggregate | {"dataset": "zeek", "field": "zeek.resp_l2_addr", "query": "event.action:conn", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 613 |  |
| q-29c7e17e0a | check C294 | search | {"dataset": "windows.other", "query": "event.code:(1341 OR 1342 OR 1020 OR 1063)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_lin… | 0 |  |
| q-579a58d2de | check C295 | aggregate | {"dataset": "windows.other", "field": "event.code", "query": "*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 216 |  |
| q-de8c06a43c | check C296 | search | {"dataset": "windows.security", "query": "event.code:5156 AND win.Direction:Inbound", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_… | 0 |  |
| q-210aa52792 | check C297 | aggregate | {"dataset": "windows.sysmon", "field": "destination.port", "query": "event.code:3", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1229 |  |
| q-4b4cfb20c5 | check C298 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:(*Dhcp* OR *dhcp*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.… | 0 |  |
| q-77570190ca | check C299 | aggregate | {"dataset": "zeek", "field": "event.action", "query": "*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 2140 |  |
| q-3c695f1df0 | check C300 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4672", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 212 |  |
| q-ec54de85ad | check C301 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 297 |  |
| q-fc68cba8af | check C302 | search | {"dataset": "windows.security", "query": "event.code:4634", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 236 |  |
| q-76cea9069a | check C303 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-cafbfda4f6 | check C304 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-6efa43cc80 | check C305 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:(*kerberos* OR *Kerberos* OR *ticket* OR *Ticket*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name",… | 0 |  |
| q-137498d59e | check C306 | search | {"dataset": "windows.other", "query": "event.code:(7045 OR 7040)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip",… | 9 |  |
| q-7e80002a80 | check C307 | aggregate | {"dataset": "zeek", "field": "zeek.request_type", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 35 |  |
| q-d2bc372d3f | check C308 | search | {"dataset": "windows.security", "query": "event.code:4769", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 28 |  |
| q-7de4f65b75 | check C309 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4672", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 212 |  |
| q-cd709252ac | check C310 | aggregate | {"dataset": "windows.security", "field": "win.TicketEncryptionType", "query": "event.code:4769", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 28 |  |
| q-818a57ba8c | check C311 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-12b70c0d12 | check C312 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:(*golden* OR *Golden* OR *krbtgt* OR *KRBTGT*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "pr… | 0 |  |
| q-fb05549447 | check C313 | aggregate | {"dataset": "windows.other", "field": "event.code", "query": "*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 216 |  |
| q-56d76d8e2c | check C314 | aggregate | {"dataset": "zeek", "field": "zeek.request_type", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 35 |  |
| q-1f73241e94 | check C315 | search | {"dataset": "windows.security", "query": "event.code:4769", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 28 |  |
| q-224a57f9d3 | check C316 | aggregate | {"dataset": "windows.security", "field": "win.ServiceName", "query": "event.code:4769", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 28 |  |
| q-970170220b | check C317 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4672", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 212 |  |
| q-cdccd527ce | check C318 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-234362c71c | check C319 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:(*silver* OR *Silver* OR *service ticket* OR *SPN*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name"… | 0 |  |
| q-f63ada6ead | check C320 | search | {"dataset": "windows.other", "query": "event.code:(7045 OR 7040)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip",… | 9 |  |
| q-3948ee8809 | check C321 | aggregate | {"dataset": "zeek", "field": "zeek.request_type", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 35 |  |
| q-d873303ce2 | check C322 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4769", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 28 |  |
| q-1abf694883 | check C323 | aggregate | {"dataset": "windows.security", "field": "win.TicketEncryptionType", "query": "event.code:4769", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 28 |  |
| q-9e11c71fac | check C324 | search | {"dataset": "windows.security", "query": "event.code:4648", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 15 |  |
| q-e735b9ca72 | check C325 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 297 |  |
| q-0b05a2463d | check C326 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetImage", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-5dcda9622e | check C327 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:(*Kerberoast* OR *kerberoast* OR *Invoke-Kerberoast* OR *Rubeus*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code… | 0 |  |
| q-e5c4152c7f | check C328 | aggregate | {"dataset": "windows.other", "field": "event.code", "query": "*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 216 |  |
| q-d100dd39af | check C329 | aggregate | {"dataset": "zeek", "field": "zeek.request_type", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 35 |  |
| q-57fef8bdd6 | check C330 | search | {"dataset": "windows.security", "query": "event.code:4768", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 14 |  |
| q-ccc8fa6537 | check C331 | aggregate | {"dataset": "windows.security", "field": "win.PreAuthType", "query": "event.code:4768", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 14 |  |
| q-e66fe349ae | check C332 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4768", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 14 |  |
| q-4049e56af1 | check C333 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 447 |  |
| q-282b461dee | check C334 | search | {"dataset": "windows.powershell", "query": "powershell.script_block_text:(*AS-REP* OR *asrep* OR *GetNPUsers* OR *DontRequirePreAuth*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "… | 0 |  |
| q-ead771bfda | check C335 | aggregate | {"dataset": "windows.other", "field": "event.code", "query": "*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 216 |  |
| q-7e54992cc1 | check C336 | aggregate | {"dataset": "zeek", "field": "zeek.request_type", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 35 |  |
| q-60c287f89b | check C337 | aggregate | {"dataset": "windows.security", "field": "win.LogonProcessName", "query": "event.code:4624 OR event.code:4648", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 312 |  |
| q-9904cadde9 | check C338 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-ee3d301015 | check C339 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*cookie* OR powershell.script_block_text:*token* OR powershell.script_block_text:*SAML*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "… | 0 |  |
| q-a16b4e80c0 | check C340 | search | {"dataset": "windows.other", "query": "event.code:7045 OR event.code:5857 OR event.code:5858", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process… | 90 | F54 |
| q-3658c152ef | check C341 | aggregate | {"dataset": "zeek", "field": "event.action", "query": "event.action:http OR event.action:ssl OR event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 475 |  |
| q-356e4f54d6 | check C342 | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11 AND (file.path:*cookie* OR file.path:*Cookies*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1 |  |
| q-90450c3b8a | check C343 | aggregate | {"dataset": "windows.security", "field": "win.LogonProcessName", "query": "event.code:4624 OR event.code:4648", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 312 |  |
| q-b9520cefad | check C344 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*cookie* OR powershell.script_block_text:*Set-Cookie* OR powershell.script_block_text:*session*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.… | 0 |  |
| q-d3332bdaf3 | check C345 | search | {"dataset": "windows.other", "query": "event.code:11 OR event.code:16", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source… | 9 |  |
| q-86301929b5 | check C346 | search | {"dataset": "zeek", "query": "event.action:http AND http.request.method:*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "so… | 62 |  |
| q-0798ff400c | check C347 | aggregate | {"dataset": "windows.security", "field": "win.LogonProcessName", "query": "event.code:4624 OR event.code:4648", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 312 |  |
| q-0908b1d179 | check C348 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*SAML* OR powershell.script_block_text:*NotOnOrAfter* OR powershell.script_block_text:*Assertion*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "hos… | 0 |  |
| q-97ba48eaa3 | check C349 | search | {"dataset": "windows.other", "query": "event.code:7045 OR event.code:5857 OR event.code:5858", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process… | 90 | F56 |
| q-59abb15918 | check C350 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*saml* OR process.command_line:*token* OR process.command_line:*cert*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-a2b1a3a006 | check C351 | search | {"dataset": "zeek", "query": "event.action:http AND (url.original:*saml* OR url.original:*adfs* OR url.original:*token*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "p… | 0 |  |
| q-fb74e8c46e | check C352 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-2094249b15 | check C353 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-323bb5b341 | check C354 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*MFA* OR powershell.script_block_text:*2FA* OR powershell.script_block_text:*Authenticator*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name… | 0 |  |
| q-5e32daeef2 | check C355 | search | {"dataset": "windows.other", "query": "event.code:4625 OR event.code:5857 OR event.code:5858", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process… | 85 |  |
| q-4889a5fd03 | check C356 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*login* OR process.command_line:*auth* OR process.command_line:*mfa*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-412016e5c3 | check C357 | search | {"dataset": "zeek", "query": "event.action:http AND (url.original:*login* OR url.original:*auth* OR url.original:*mfa*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "pr… | 0 |  |
| q-18ae524c11 | check C358 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4657", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 36 |  |
| q-83fefdf07c | check C359 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4768", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 14 |  |
| q-62038d9c80 | check C360 | aggregate | {"dataset": "windows.sysmon", "field": "registry.path", "query": "event.code:13 AND (registry.path:*Certificate* OR registry.path:*Crypto* OR registry.path:*Keys*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1133 |  |
| q-bbf9807c33 | check C361 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (powershell.script_block_text:*Certificate* OR powershell.script_block_text:*Export-PfxCertificate* OR powershell.script_block_text:*New-SelfSignedCertificate*)", "time_from": null, "time_to": nul… | 0 |  |
| q-7abbb6a320 | check C362 | search | {"dataset": "windows.other", "query": "event.code:7045 OR event.code:5857 OR event.code:5858", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process… | 90 |  |
| q-a408724bf8 | check C363 | aggregate | {"dataset": "zeek", "field": "zeek.certificate_subject", "query": "event.action:x509", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 378 |  |
| q-3c289654bc | triage T1003 step 1 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTtmJQ5"} | None |  |
| q-3240990215 | triage T1003 step 1 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO9re0C"} | None |  |
| q-a4e5153170 | triage T1003 step 1 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTVGQnT"} | None | F02 |
| q-0dcca098ce | triage T1003 step 1 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKA_"} | None | F01 |
| q-576d799731 | triage T1003 step 2 | search | {"dataset": "windows.security", "query": "event.code:(4656 OR 4663 OR 4670) AND win.ObjectType:(SAM_DOMAIN OR SAM_SERVER OR SAM_ALIAS)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "… | 21 | F03 |
| q-6390187799 | triage T1003 step 2 | search | {"dataset": "windows.security", "query": "user.name:pbeesly AND event.code:(4688 OR 4624 OR 4672)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "pr… | 137 |  |
| q-f00904a76a | triage T1003 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND win.GrantedAccess:(0x1fffff OR 0x1f3fff OR 0x101001 OR 0x1400)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "… | 31 | F01 |
| q-61428e5dac | triage T1003 step 3 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*MiniDump* OR win.ScriptBlockText:*Dump* OR win.ScriptBlockText:*Credential* OR win.ScriptBlockText:*SAM*)", "time_from": null, "time_to": null,… | 3 |  |
| q-8db819feb0 | triage T1003 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gj"} | None | F01 |
| q-900138bbba | triage T1003 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None | F01 |
| q-41f9033a6d | triage T1003 step 4 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZCgBha"} | None | F04 |
| q-2f36b17452 | triage T1003 step 4 | search | {"dataset": "windows.powershell", "query": "user.name:pbeesly AND event.code:4104", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 157 | F04 |
| q-42bbf33fb0 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gj"} | None |  |
| q-039da1b608 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gj"} | None |  |
| q-5e2749bc87 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-c284d41bab | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None |  |
| q-286ff46872 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None |  |
| q-ff67cb5dfc | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKA_"} | None |  |
| q-7d72fdad96 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKA_"} | None |  |
| q-2d5770b03c | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTVGQnT"} | None |  |
| q-f501f8a090 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTVGQnT"} | None |  |
| q-55e8b815c0 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVr3bsA"} | None |  |
| q-a30c3181b4 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVr3bsA"} | None |  |
| q-2602222a36 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVz9KVt"} | None |  |
| q-10457b0895 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZCgBha"} | None |  |
| q-5e3d60f03c | triage T1003 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZCgBha"} | None |  |
| q-fa4ed9d153 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZWqdCw"} | None |  |
| q-bfa947c90c | triage T1040 step 1 | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8TL"} | None | F06 |
| q-9c26071d83 | triage T1040 step 1 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.executable:*NetworkWatcher* OR process.executable:*pcap* OR process.executable:*dump* OR process.executable:*sniff* OR process.executable:*netsh* OR process.executable:*logman*)", "time_fro… | 13 | F05 |
| q-e9f87677cc | triage T1040 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.executable:*netsh* OR process.executable:*NetworkWatcher* OR process.executable:*dump* OR process.executable:*pcap* OR process.executable:*sniff* OR process.executable:*windump* OR process.execu… | 6 | F05, F06 |
| q-ef072fbdbc | triage T1040 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:6 AND (win.Image:*pcap* OR win.Image:*npcap* OR win.Image:*winpcap* OR win.Image:*NetworkWatcher* OR win.Image:*ndis* OR win.Image:*netmon*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host… | 0 |  |
| q-d455125961 | triage T1040 step 3 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.executable:*PSEXESVC* OR process.executable:*PsExec* OR process.executable:*sdelete* OR process.executable:*python*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "… | 19 | F07 |
| q-1697be9997 | triage T1040 step 3 | search | {"dataset": "zeek", "query": "event.action:conn AND network.transport:icmp", "time_from": null, "time_to": null, "fields": ["@timestamp", "event.action", "network.transport", "source.ip", "destination.ip", "destination.port", "zeek.proto", "zeek.service"], "si… | 0 |  |
| q-6659c3bab9 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItPM8kte"} | None |  |
| q-e15d70b0ff | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItPM8kte"} | None |  |
| q-7a6dd1449d | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItPE0PdZ"} | None |  |
| q-988fb13a6f | triage T1040 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVz8aWs"} | None |  |
| q-b23097cda3 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItV19xlz"} | None |  |
| q-2ffedea19d | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItPM8kte"} | None |  |
| q-2e78af201a | triage T1040 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8TL"} | None |  |
| q-d5cf9a0676 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTVGglR"} | None |  |
| q-4b85fabb5a | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTVGQmt"} | None |  |
| q-6e3bee136a | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTpgCep"} | None |  |
| q-479ce50d19 | triage T1056 step 1 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKA_"} | None | F08 |
| q-c3a9d9e88c | triage T1056 step 1 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTtmJQ5"} | None |  |
| q-eebb488307 | triage T1056 step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 10 AND win.TargetImage LIKE \"*lsass*\" \| STATS cnt = COUNT(*) BY process.executable, win.GrantedAccess \| SORT cnt DESC"} | ERROR |  |
| q-d4db0252c3 | triage T1056 step 1 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == 4104 \| KEEP @timestamp, host.name, user.name, win.ScriptBlockText \| LIMIT 20"} | ERROR |  |
| q-e4b3c63807 | triage T1056 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND win.TargetImage LIKE \"*lsass*\" \| STATS cnt = COUNT(*) BY process.executable, win.GrantedAccess \| SORT cnt DESC"} | 15 |  |
| q-03d3467118 | triage T1056 step 2 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" \| KEEP @timestamp, host.name, user.name, win.ScriptBlockText \| LIMIT 15"} | 15 |  |
| q-4186915d9c | triage T1056 step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND user.name == \"pbeesly\" \| KEEP @timestamp, host.name, user.name, win.ScriptBlockText \| LIMIT 10"} | 10 |  |
| q-01685ee0d6 | triage T1056 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND win.TargetImage LIKE \"*lsass*\" AND process.executable LIKE \"*PowerShell*\" \| KEEP @timestamp, host.name, process.executable, win.TargetImage, win.GrantedAcce… | 4 |  |
| q-d234a6e259 | triage T1056 step 4 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTtmJQ5"} | None | F08, F11, F13 |
| q-87efe75e37 | triage T1056 step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND win.ScriptBlockText LIKE \"*GetProcAddress*\" \| KEEP @timestamp, host.name, user.name, win.ScriptBlockText \| LIMIT 5"} | 2 |  |
| q-b6cc871ddf | triage T1056 step 5 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHM31uOFchItTtmJQ5"} | ERROR |  |
| q-49e6c7fcd6 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTtmJQ5"} | None |  |
| q-58303f12a2 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKA_"} | None |  |
| q-0115e4e08d | triage T1056 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKA_"} | None |  |
| q-096703e8f7 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTtmJQ5"} | None |  |
| q-043c753d24 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHM31uOFchItTtmJQ5"} | ERROR |  |
| q-91f8395347 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHM31uOFchItTtmJQ5"} | ERROR |  |
| q-1842e08d3f | triage T1056 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHM31uOFchItTtmJQ5"} | ERROR |  |
| q-87478b98ea | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQE_JuD"} | None |  |
| q-de4ed98889 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVq1T69"} | None |  |
| q-d6a5fc3717 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaD_"} | ERROR |  |
| q-29999d00e1 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTtmJQ5"} | None |  |
| q-635f5c2c54 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHM31uOFchItTtmJQ5"} | ERROR |  |
| q-49342fe564 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTtmJQ5"} | None |  |
| q-01364892a7 | triage T1056 step 7 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND win.ScriptBlockText LIKE \"*GetProcAddress*\" \| KEEP @timestamp, host.name, user.name, _id, _index \| LIMIT 5"} | 2 | F09, F12 |
| q-66afdad619 | triage T1056 step 7 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4656\" AND process.executable LIKE \"*CollectGuestLogs*\" \| KEEP @timestamp, host.name, process.executable, _id, _index \| LIMIT 5"} | 5 | F10 |
| q-e27dcab5c0 | triage T1110 step 1 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-2c3775f19e | triage T1110 step 1 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-1e2dcf3aed | triage T1110 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND (win.GrantedAccess:0x1fffff OR win.GrantedAccess:0x1f3fff OR win.GrantedAccess:0x101001 OR win.GrantedAccess:0x1000000)", "time_from": null, "time_to": null, "fields": ["@tim… | 8 |  |
| q-9a7de7f752 | triage T1110 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND process.executable:*PowerShell*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "process.executable", "process.command_line", "win.GrantedAccess",… | 4 |  |
| q-8bf4561309 | triage T1110 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None | F16 |
| q-4e5c278623 | triage T1110 step 3 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*MiniDump* OR win.ScriptBlockText:*Dump* OR win.ScriptBlockText:*Credential*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "ho… | 3 |  |
| q-c1fb1f406a | triage T1110 step 4 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND process.pid:2976", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "process.executable", "process.command_line", "process.parent.executable", "user.name"], "size": 10, "sort": "… | 1 | F17 |
| q-c5d7686cfe | triage T1110 step 4 | search | {"dataset": "windows.security", "query": "event.code:4663 AND win.ObjectName:SAM", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "win.ObjectName", "win.ProcessName", "win.AccessMask", "user.name"], "size": 15, "sort": "asc"} | 0 |  |
| q-2353556a8d | triage T1110 step 5 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQB61zZ"} | None | F16 |
| q-cf51ff7663 | triage T1110 step 5 | search | {"dataset": "windows.security", "query": "event.code:4663 AND win.ObjectName:*SamSs*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "win.ObjectName", "win.ProcessName", "win.AccessMask", "user.name", "win.AccessList"], "size": 10, … | 0 |  |
| q-014846e402 | triage T1110 step 6 | search | {"dataset": "windows.security", "query": "event.code:4663 AND win.ObjectName:*SAM*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "win.ObjectName", "win.ProcessName", "win.AccessMask", "user.name"], "size": 15, "sort": "asc"} | 0 |  |
| q-37db517e2c | triage T1110 step 6 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZCgBha"} | None | F16 |
| q-fc4b71fb67 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8RS"} | None |  |
| q-0baacbe13a | triage T1110 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8Re"} | None |  |
| q-7420af41f3 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8RY"} | None |  |
| q-9230c32615 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8Rb"} | None |  |
| q-b4772a9727 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-dde1a404bf | triage T1110 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-a34022165b | triage T1110 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-b7e5ffdce2 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQB61zZ"} | None |  |
| q-0953ce4b94 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZCgBha"} | None |  |
| q-ae45b9922d | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ev8p"} | None |  |
| q-4191890aae | triage T1110 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQB61zZ"} | None |  |
| q-313d5cd3e1 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8R_"} | None |  |
| q-dc1b842a9a | triage T1110 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8S-"} | None |  |
| q-5598ca396b | triage T1111 step 1 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ev8p"} | None | F19 |
| q-79dc2eff0b | triage T1111 step 1 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVn01NG"} | None | F19 |
| q-f831a06e6a | triage T1111 step 1 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4648", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 15 |  |
| q-409dc2cea1 | triage T1111 step 1 | aggregate | {"dataset": "windows.security", "field": "win.LogonProcessName", "query": "event.code:4624 AND win.LogonType:2", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 15 |  |
| q-c25d79f2d9 | triage T1111 step 2 | search | {"dataset": "windows.security", "query": "event.code:4624 AND win.LogonType:10", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "win.LogonType", "win.LogonProcessName", "win.AuthenticationPackageName", "win.IpAddress", "… | 2 | F20 |
| q-8d377c620d | triage T1111 step 2 | search | {"dataset": "windows.security", "query": "event.code:4624 AND win.LogonType:2", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "win.LogonType", "win.LogonProcessName", "win.AuthenticationPackageName", "win.IpAddress", "w… | 15 |  |
| q-ef96111808 | triage T1111 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*smartcard* OR process.command_line:*SmartCard* OR process.command_line:*scard* OR process.command_line:*MFA* OR process.command_line:*mfa* OR process.command_line:*token*)", "time_… | 0 |  |
| q-061868d960 | triage T1111 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*Credential* OR file.path:*smartcard* OR file.path:*SmartCard* OR file.path:*scard*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "process.executab… | 0 |  |
| q-3314cb4844 | triage T1111 step 3 | search | {"dataset": "windows.sysmon", "query": "event.code:13 AND (registry.path:*Credential* OR registry.path:*Vault* OR registry.path:*SmartCard* OR registry.path:*scard*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "proc… | 11 | F21 |
| q-6315a23207 | triage T1111 step 3 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.executable:*CredentialEnrollment* OR process.command_line:*CredentialEnrollment* OR process.executable:*vaultcmd* OR process.command_line:*vaultcmd*)", "time_from": null, "time_to": null, "field… | 0 |  |
| q-1269cb8771 | triage T1111 step 3 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "win.ServiceName", "win.ImagePath", "message"], "size": 10, "sort": "asc"} | 5 | F19 |
| q-0cac311dc8 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ev8p"} | None |  |
| q-232e7f20bb | triage T1111 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ev8p"} | None |  |
| q-2940ae6e24 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVn01NG"} | None |  |
| q-6abd5c0191 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrYMQT"} | None |  |
| q-ceb9807c9a | triage T1111 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVn0lP2"} | None |  |
| q-85569855f3 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVn0lP2"} | None |  |
| q-9673d02003 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVn0lP2"} | None |  |
| q-c9aec9234b | triage T1111 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO9rO3Z"} | None |  |
| q-cfdb4b9007 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO9rO3Z"} | None |  |
| q-051fd1825e | triage T1111 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOxeHN4"} | None |  |
| q-df4073dd86 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8R_"} | None |  |
| q-6de615b455 | triage T1187 step 1 | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrYjN"} | None | F23 |
| q-9cd66f00c2 | triage T1187 step 1 | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrYgN"} | None | F23 |
| q-83f3716dc7 | triage T1187 step 1 | aggregate | {"dataset": "zeek", "field": "destination.ip", "query": "event.action:http AND (http.request.method:PROPFIND OR http.request.method:MOVE OR http.request.method:OPTIONS)", "time_from": null, "time_to": null, "size": 20, "sub_field": "user_agent.original"} | 36 |  |
| q-0a066e2b62 | triage T1187 step 1 | aggregate | {"dataset": "zeek", "field": "source.ip", "query": "event.action:conn AND (destination.port:445 OR destination.port:139)", "time_from": null, "time_to": null, "size": 20, "sub_field": "destination.ip"} | 50 |  |
| q-e8e3a5654b | triage T1187 step 2 | search | {"dataset": "zeek", "query": "event.action:conn AND source.ip:10.0.1.4 AND destination.ip:192.168.0.4", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable",… | 16 |  |
| q-ea40d29671 | triage T1187 step 2 | aggregate | {"dataset": "windows.security", "field": "win.ShareName", "query": "event.code:5140 OR event.code:5145", "time_from": null, "time_to": null, "size": 20, "sub_field": "source.ip"} | 163 |  |
| q-bd1fd202f3 | triage T1187 step 2 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4624 AND win.LogonType:3", "time_from": null, "time_to": null, "size": 20, "sub_field": "source.ip"} | 218 |  |
| q-c900f577e7 | triage T1187 step 3 | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrYjF"} | None | F23 |
| q-bb807a7b0c | triage T1187 step 3 | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrYih"} | None | F23 |
| q-d9e09ee0e2 | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrYjF"} | None |  |
| q-ceaeb1b219 | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrYjF"} | None |  |
| q-4ee0dc0b18 | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrYjN"} | None |  |
| q-2600fedf0d | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrYjN"} | None |  |
| q-31904278b1 | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrYgN"} | None |  |
| q-17b2bd955e | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrYgN"} | None |  |
| q-1493d797db | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrYih"} | None |  |
| q-3aa8eadb6a | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrYih"} | None |  |
| q-a495a0718e | triage T1187 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaKWxp4"} | None |  |
| q-399bf09c70 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaKWxp4"} | None |  |
| q-46260a8726 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaFQQtn"} | None |  |
| q-217581f692 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaFQQtn"} | None |  |
| q-fa6b9f48b8 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTqgghU"} | None |  |
| q-7c8492de45 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTqgghU"} | None |  |
| q-08b248ec81 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUKHd9O"} | None |  |
| q-e930aa4340 | triage T1212 step 1 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 326 |  |
| q-0aaf2978d9 | triage T1212 step 1 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 326 |  |
| q-bf1330a018 | triage T1212 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND (win.GrantedAccess:0x1fffff OR win.GrantedAccess:0x1f3fff OR win.GrantedAccess:0x101001 OR win.GrantedAccess:0x1000000 OR win.GrantedAccess:0x3000)", "time_from": null, "time… | 9 | F26, F27 |
| q-041e7323c2 | triage T1212 step 2 | aggregate | {"dataset": "windows.sysmon", "field": "win.SourceImage", "query": "event.code:10 AND win.TargetImage:*lsass* AND win.GrantedAccess:0x1400", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 24 |  |
| q-2c523d891a | triage T1212 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-18c613293a | triage T1212 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gj"} | None |  |
| q-318455af21 | triage T1212 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None |  |
| q-d531e089c4 | triage T1212 step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND host.name == \"scranton.dmevals.local\" \| KEEP @timestamp, host.name, win.ScriptBlockText, _id, _index \| LIMIT 30"} | 30 | F26 |
| q-b6d7f255a3 | triage T1212 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND host.name == \"scranton.dmevals.local\" \| KEEP @timestamp, host.name, process.executable, process.command_line, process.parent.executable, user.name, _id, _index… | 40 |  |
| q-e02603be0f | triage T1212 step 5 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRkUVV"} | None |  |
| q-e668a2090c | triage T1212 step 5 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE host.name == \"nashua.dmevals.local\" AND event.code == \"4104\" \| KEEP @timestamp, host.name, win.ScriptBlockText, _id, _index \| LIMIT 15"} | 11 | F27 |
| q-50248a94ba | triage T1212 step 6 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE host.name == \"scranton.dmevals.local\" AND event.code == \"4104\" AND win.ScriptBlockText LIKE \"*MiniDump*\" \| KEEP @timestamp, host.name, win.ScriptBlockText, _id, _index \| LIMI… | 0 |  |
| q-f53e5a2f7a | triage T1212 step 6 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND host.name == \"nashua.dmevals.local\" AND (process.executable LIKE \"*wsmprovhost*\" OR process.executable LIKE \"*rar*\" OR process.executable LIKE \"*powershell… | 2 |  |
| q-36f1cd7352 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-fd60efc30f | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-e553170d2b | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-0023139309 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gj"} | None |  |
| q-5ff2cfd196 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRkUVV"} | None |  |
| q-40462e2452 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRk1C1"} | None |  |
| q-734b4233bd | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None |  |
| q-0d1e87ad84 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None |  |
| q-91724bb17f | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None |  |
| q-85b9312845 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZLhp5i"} | None |  |
| q-7a4e5adfaf | triage T1212 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKC-"} | None |  |
| q-0c42e9715f | triage T1212 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItV3-aVk"} | None |  |
| q-e60cc5e52e | triage T1212 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrYiq"} | None |  |
| q-0e47d11421 | triage T1212 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrIjg"} | None |  |
| q-6a4da6b762 | triage T1539 step 1 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOVAUl3"} | None | F31 |
| q-42b47bb637 | triage T1539 step 1 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ8Frba"} | None | F30 |
| q-9cf02b556f | triage T1539 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 11 AND (TO_LOWER(win.TargetFilename) LIKE \"*cookies*\" OR TO_LOWER(win.TargetFilename) LIKE \"*login data*\" OR TO_LOWER(win.TargetFilename) LIKE \"*web data*\" OR TO_LOWE… | ERROR |  |
| q-ab820414b6 | triage T1539 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 1 AND (TO_LOWER(process.command_line) LIKE \"*cookie*\" OR TO_LOWER(process.command_line) LIKE \"*login data*\" OR TO_LOWER(process.command_line) LIKE \"*webcache*\" OR TO_… | ERROR |  |
| q-ce88dbfaa6 | triage T1539 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(win.TargetFilename) LIKE \"*cookies*\" OR TO_LOWER(win.TargetFilename) LIKE \"*login data*\" OR TO_LOWER(win.TargetFilename) LIKE \"*web data*\" OR TO_… | 1 |  |
| q-6fc011558f | triage T1539 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*cookie*\" OR TO_LOWER(process.command_line) LIKE \"*login data*\" OR TO_LOWER(process.command_line) LIKE \"*webcache*\" OR… | 5 | F30 |
| q-b3b9e9644a | triage T1539 step 4 | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrog-"} | None | F32 |
| q-4a591af58a | triage T1539 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND TO_LOWER(win.TargetFilename) LIKE \"*python.exe*\" \| KEEP @timestamp, host.name, process.executable, win.TargetFilename, _id, _index"} | 7 |  |
| q-dfa05373d4 | triage T1539 step 5 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE TO_LOWER(win.ObjectName) LIKE \"*cookies*\" OR TO_LOWER(win.ObjectName) LIKE \"*login data*\" OR TO_LOWER(win.ObjectName) LIKE \"*web data*\" \| KEEP @timestamp, host.name, user.name, … | 0 |  |
| q-ef754bed29 | triage T1539 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ8Frba"} | None |  |
| q-1126acc595 | triage T1539 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ8Frba"} | None |  |
| q-9388876ab7 | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTVHe6C"} | None |  |
| q-6c6cc80c29 | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOVAUl3"} | None |  |
| q-deec8cf819 | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOVAUl3"} | None |  |
| q-c6d553626b | triage T1539 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrog-"} | None |  |
| q-53a4515e6d | triage T1539 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrog-"} | None |  |
| q-1c4d30477a | triage T1539 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrog-"} | None |  |
| q-7a4af31a66 | triage T1552 step 1 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTkbkGF"} | None |  |
| q-b09500a1c2 | triage T1552 step 1 | search | {"dataset": "windows.sysmon", "query": "process.executable:*accesschk* OR process.command_line:*accesschk*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executa… | 2 |  |
| q-165a1b2c63 | triage T1552 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND win.TargetFilename:*passwordsDB*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.c… | 1 |  |
| q-0e57a652c5 | triage T1552 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*sysvol* OR process.command_line:*Groups.xml* OR process.command_line:*GptTmpl* OR process.command_line:*cpassword*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "… | 0 |  |
| q-1d343f305c | triage T1552 step 2 | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrYiv"} | None | F36 |
| q-907412db0c | triage T1552 step 2 | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNn1uOFchItY0uF_7"} | None |  |
| q-74ab3dede8 | triage T1552 step 2 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ev8p"} | None |  |
| q-b2ca0e1fd8 | triage T1552 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (win.TargetFilename:*GptTmpl* OR win.TargetFilename:*Groups.xml* OR win.TargetFilename:*SecEdit*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.data… | 5 | F36 |
| q-088e5cdd58 | triage T1552 step 3 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*PsExec* OR process.command_line:*psexec*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "… | 4 | F34 |
| q-dd789f0b7a | triage T1552 step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*password*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*credential*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*get-… | 7 |  |
| q-4ce759caf8 | triage T1552 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" \| WHERE TO_LOWER(process.command_line) LIKE \"*password*\" OR TO_LOWER(process.command_line) LIKE \"*credential*\" OR TO_LOWER(process.command_line) LIKE \"*unattend… | 0 |  |
| q-77c941ede1 | triage T1552 step 4 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None | F33 |
| q-fd932dd1e8 | triage T1552 step 4 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZCgBha"} | None | F34, F35 |
| q-06c46e63fe | triage T1552 step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND user.name == \"pbeesly\" \| KEEP @timestamp, host.name, user.name, win.ScriptBlockText, _id, _index \| LIMIT 40"} | 40 | F33, F35, F38 |
| q-8f529057ef | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-f78c7521d2 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-ee08a34e1a | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRlVDe"} | None |  |
| q-a2da6eef77 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTVGglR"} | None |  |
| q-d357067dbb | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZCgBha"} | None |  |
| q-ee541af348 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZCgBha"} | None |  |
| q-851f93ca5c | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRk1C1"} | None |  |
| q-5df77466e6 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRk1Cy"} | None |  |
| q-2de381fc9c | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZCgBha"} | None |  |
| q-2d1d07605f | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTqhAkt"} | None |  |
| q-98d348014a | triage T1552 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrYiv"} | None |  |
| q-a12031efc0 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItThYt63"} | None |  |
| q-97fa65a835 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO9rO3Z"} | None |  |
| q-e74f1105c8 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRlVDe"} | None |  |
| q-8ad1d825b5 | triage T1555 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZCgBha"} | None |  |
| q-3123768ab3 | triage T1555 step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND win.TargetImage LIKE \"*lsass*\" AND win.GrantedAccess IN (\"0x1fffff\",\"0x101001\",\"0x1f3fff\",\"0x1000000\",\"0x3000\",\"0x1400\") \| KEEP @timestamp, host.n… | 33 | F39 |
| q-a5d60bb221 | triage T1555 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-b3a5ec194f | triage T1555 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None |  |
| q-7d796251b4 | triage T1555 step 2 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code IN (\"4103\",\"4104\") AND (TO_LOWER(COALESCE(win.ScriptBlockText, \"\")) LIKE \"*lsass*\" OR TO_LOWER(COALESCE(win.ScriptBlockText, \"\")) LIKE \"*minidump*\" OR TO_LOWER… | 0 |  |
| q-a056e6e882 | triage T1555 step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code IN (\"4103\",\"4104\") AND (TO_LOWER(COALESCE(win.ScriptBlockText, \"\")) LIKE \"*credential*\" OR TO_LOWER(COALESCE(win.ScriptBlockText, \"\")) LIKE \"*securestring*\" OR… | 6 | F40 |
| q-93b4a26f88 | triage T1555 step 3 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4688\" AND (TO_LOWER(process.command_line) LIKE \"*lsass*\" OR TO_LOWER(process.command_line) LIKE \"*dump*\" OR TO_LOWER(process.command_line) LIKE \"*credential*\" OR… | 0 |  |
| q-fddd0af094 | triage T1555 step 4 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-8136a62c72 | triage T1555 step 4 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4688\" AND (TO_LOWER(process.executable) LIKE \"*powershell*\" OR TO_LOWER(process.executable) LIKE \"*wsmprovhost*\") \| KEEP @timestamp, host.name, user.name, process… | 14 |  |
| q-0d92c22d74 | triage T1555 step 5 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4663\",\"4656\") AND TO_LOWER(win.ObjectName) LIKE \"*lsass*\" AND win.AccessMask IN (\"0x1fffff\",\"0x1f3fff\") \| KEEP @timestamp, host.name, user.name, win.ObjectNa… | 4 | F39, F40 |
| q-b8642f1049 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-c9c8ba2f22 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-ab32397c0e | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None |  |
| q-2bd064f45c | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None |  |
| q-4c4ccd142c | triage T1555 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKB-"} | None |  |
| q-e1131a3c87 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ8FLV1"} | None |  |
| q-571fe4ae29 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKA_"} | None |  |
| q-e8e5e9d50a | triage T1555 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKA_"} | None |  |
| q-190113a794 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKA_"} | None |  |
| q-d74da83857 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-8e548526b0 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOVAkmV"} | None |  |
| q-980f2fbea0 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItQE_JuD"} | ERROR |  |
| q-d0fd2d35a0 | triage T1556 step 1 | aggregate | {"dataset": "windows.sysmon", "field": "win.SourceImage", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": "win.GrantedAccess"} | 326 |  |
| q-261d724fbf | triage T1556 step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND TO_LOWER(win.TargetImage) LIKE \"*lsass*\" AND TO_LOWER(win.SourceImage) LIKE \"*powershell*\" \| KEEP @timestamp, host.name, win.SourceImage, win.TargetImage, w… | 4 |  |
| q-19de71daec | triage T1556 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None | F43 |
| q-8683b7cefa | triage T1556 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gj"} | None | F43 |
| q-08fd99ccb4 | triage T1556 step 2 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*lsass*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*mimikatz*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*invoke-mi… | 0 |  |
| q-3aa96562ea | triage T1556 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND process.pid == \"2976\" \| KEEP @timestamp, host.name, process.executable, process.command_line, process.parent.executable, user.name, _id, _index"} | ERROR |  |
| q-49ef6de651 | triage T1556 step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*lsass*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*credential*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*passwor… | 7 |  |
| q-4b5b6c0f15 | triage T1556 step 4 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZCgBha"} | None |  |
| q-d68c7975fc | triage T1556 step 4 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-a74c6e9d47 | triage T1556 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND process.pid == 2976 \| KEEP @timestamp, host.name, process.executable, process.command_line, process.parent.executable, user.name, _id, _index"} | 1 | F43 |
| q-d2746ea591 | triage T1556 step 5 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ev8p"} | None |  |
| q-d1656bb732 | triage T1556 step 5 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4624\" AND win.LogonType == \"3\" \| STATS c = COUNT(*) BY win.TargetUserName, host.name \| SORT c DESC \| LIMIT 30"} | 10 |  |
| q-4b5ab39a13 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-f6927427f2 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-59cefbf0f4 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gj"} | None |  |
| q-8ae9272d37 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQB61zZ"} | None |  |
| q-f780cdb182 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaKXhpQ"} | None |  |
| q-45ae4d2ca0 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaKXhpQ"} | None |  |
| q-b507d5fc19 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaKXhpQ"} | None |  |
| q-2d8e953a65 | triage T1557 step 1 | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8RT"} | None |  |
| q-2d33b4ea2a | triage T1557 step 1 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"conn\" AND zeek.service LIKE \"*smb*\" \| KEEP @timestamp, source.ip, destination.ip, destination.port, zeek.service, zeek.orig_l2_addr, zeek.resp_l2_addr, zeek.conn_state, _id, … | 16 | F47, F48 |
| q-031dd72982 | triage T1557 step 2 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"conn\" \| STATS cnt = COUNT(*) BY zeek.resp_l2_addr, destination.ip \| SORT cnt DESC \| LIMIT 30"} | 6 |  |
| q-5b84f8e1a5 | triage T1557 step 2 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"conn\" \| STATS cnt = COUNT(*) BY zeek.orig_l2_addr, source.ip \| SORT cnt DESC \| LIMIT 30"} | 3 |  |
| q-f26622abd1 | triage T1557 step 3 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"kerberos\" \| KEEP @timestamp, source.ip, destination.ip, zeek.client, zeek.service, zeek.request_type, zeek.success, zeek.error_msg, _id, _index \| LIMIT 40"} | 35 | F46 |
| q-6d47d1f9f8 | triage T1557 step 3 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"smb_files\" OR event.action == \"smb_mapping\" \| KEEP @timestamp, source.ip, destination.ip, zeek.path, zeek.name, zeek.share_type, zeek.action, _id, _index \| LIMIT 30"} | 23 |  |
| q-582ceeeee2 | triage T1557 step 4 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4697\" \| KEEP @timestamp, host.name, user.name, win.ServiceName, win.ServiceFileName, win.ServiceType, _id, _index \| LIMIT 30"} | 23 | F46 |
| q-f7d74566a1 | triage T1557 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"22\" \| KEEP @timestamp, host.name, process.executable, win.QueryName, win.QueryStatus, _id, _index \| LIMIT 40"} | 40 | F46 |
| q-9bbd9924a8 | triage T1557 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"3\" AND (destination.port == 445 OR destination.port == 139 OR destination.port == 67 OR destination.port == 68) \| KEEP @timestamp, host.name, process.executable, source… | 40 | F45, F48 |
| q-9871ba2423 | triage T1557 step 5 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"5156\" \| STATS cnt = COUNT(*) BY win.Direction, destination.port \| SORT cnt DESC \| LIMIT 20"} | 20 |  |
| q-127d9b8705 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOrW_3E"} | None |  |
| q-d7052d45b6 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOrW_3E"} | None |  |
| q-d892eb50c9 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOrW_3E"} | None |  |
| q-ec1fed7755 | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrYiy"} | None |  |
| q-f864ebeb58 | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrYiy"} | None |  |
| q-55572216c6 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOmQp3C"} | None |  |
| q-33bfbe4937 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7DT5G"} | None |  |
| q-93247496e1 | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgroge"} | None |  |
| q-2bbfd72282 | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgroge"} | None |  |
| q-badd1ede99 | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgroge"} | None |  |
| q-51eb6ba006 | triage T1557 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgroge"} | None |  |
| q-7c0799019e | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOrW_3E"} | None |  |
| q-57c8aa6f20 | triage T1558 step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND win.TargetImage LIKE \"*lsass*\" AND win.GrantedAccess IN (\"0x1fffff\", \"0x101001\", \"0x1f3fff\", \"0x1000000\", \"0x3000\", \"0x1400\") \| KEEP @timestamp, h… | 33 |  |
| q-9785d858da | triage T1558 step 1 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4769\" \| KEEP @timestamp, host.name, user.name, win.ServiceName, win.TicketEncryptionType, win.TicketOptions, source.ip, _id, _index \| SORT @timestamp ASC"} | 28 | F50, F51, F52 |
| q-1b4fb686e2 | triage T1558 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None | F49 |
| q-bd68b78e17 | triage T1558 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gj"} | None | F49 |
| q-46852bbfdf | triage T1558 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None | F49 |
| q-28f685f0bf | triage T1558 step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" \| KEEP @timestamp, host.name, user.name, win.ScriptBlockText, _id, _index \| SORT @timestamp ASC \| LIMIT 30"} | 30 | F49, F53 |
| q-ecc2cd9ff3 | triage T1558 step 3 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4624\" AND win.LogonType IN (\"3\",\"9\",\"10\") \| KEEP @timestamp, host.name, user.name, win.TargetUserName, win.LogonType, win.LogonProcessName, source.ip, _id, _ind… | 40 |  |
| q-0d0f9d8371 | triage T1558 step 4 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4624\" AND win.TargetUserName LIKE \"*pbeesly*\" \| KEEP @timestamp, host.name, win.TargetUserName, win.LogonType, win.LogonProcessName, source.ip, _id, _index \| SORT … | 30 |  |
| q-7416619d53 | triage T1558 step 4 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4672\" \| KEEP @timestamp, host.name, win.TargetUserName, win.PrivilegeList, _id, _index \| SORT @timestamp ASC \| LIMIT 20"} | 20 |  |
| q-5a58f98d98 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-11163ecc6b | triage T1558 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-5539641dc3 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gj"} | None |  |
| q-3791c4eae6 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None |  |
| q-73d69d33ff | triage T1558 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None |  |
| q-0696ca634a | triage T1558 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZWqNA3"} | None |  |
| q-75bdbe8709 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZWqNDf"} | None |  |
| q-c3729e6a00 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZWqdCw"} | None |  |
| q-2cd732fafb | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKC-"} | None |  |
| q-71af122ee2 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKC-"} | None |  |
| q-9185aa4fbd | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKC-"} | None |  |
| q-a92235bb92 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItV3-aXQ"} | None |  |
| q-fb68a1b36f | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItV3-aXQ"} | None |  |
| q-120adbee45 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOaA_"} | None |  |
| q-8d47108309 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOaA_"} | None |  |
| q-81fd96150b | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ8FbW6"} | None |  |
| q-1bfdd8e80e | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ8FbW6"} | None |  |
| q-3771500c36 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZWqdCz"} | None |  |
| q-b8af77d085 | triage T1606 step 1 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8Rl"} | ERROR |  |
| q-91ced9e0e2 | triage T1606 step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 10 AND win.TargetImage LIKE \"*lsass*\" AND win.GrantedAccess IN (\"0x1fffff\",\"0x101001\",\"0x1f3fff\",\"0x1000000\",\"0x3000\",\"0x1400\") \| KEEP @timestamp, host.name,… | ERROR |  |
| q-39749a6e1f | triage T1606 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND win.TargetImage LIKE \"*lsass*\" AND win.GrantedAccess IN (\"0x1fffff\",\"0x101001\",\"0x1f3fff\",\"0x1000000\",\"0x3000\",\"0x1400\") \| KEEP @timestamp, host.n… | 33 |  |
| q-78ef0360b5 | triage T1606 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND file.path:*cookie*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "file.path", "process.executable", "process.command_line", "user.name"], "size": 20, "sort": "asc"} | 0 |  |
| q-df11aa8cea | triage T1606 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-0b3a0e02a2 | triage T1606 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None |  |
| q-44c604f442 | triage T1606 step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" \| KEEP @timestamp, host.name, user.name, win.ScriptBlockText, _id, _index \| LIMIT 20"} | 20 |  |
| q-d357b4f041 | triage T1606 step 4 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND file.path:*INetCookies*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "file.path", "process.executable", "process.command_line", "user.name"], "size": 20, "sort": "asc"} | 1 | F55 |
| q-6ff3bc8b90 | triage T1606 step 5 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRkUVV"} | None | F56 |
| q-81138d1df9 | triage T1606 step 5 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"http\" \| KEEP @timestamp, source.ip, destination.ip, url.original, http.request.method, http.response.status_code, user_agent.original, _id, _index \| LIMIT 30"} | 30 | F54 |
| q-05ffafacd0 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8Rl"} | None |  |
| q-afa07b3e45 | triage T1606 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrYi9"} | None |  |
| q-81873d56e8 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOVAUl3"} | None |  |
| q-214e140156 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOVAUl3"} | None |  |
| q-416b716454 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRkUVV"} | None |  |
| q-cc236e4957 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8Rl"} | None |  |
| q-3119c99bb6 | triage T1621 step 1 | search | {"dataset": "windows.other", "query": "event.code:5857 OR event.code:5858 OR event.code:5860", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "user.name", "message", "win.Operation", "win.ClientMachine"], "size": 10, "s… | 88 | F57 |
| q-679de7267e | triage T1621 step 1 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*mfa*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*authenticator*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*2fa*\"… | 2 |  |
| q-223e739530 | triage T1621 step 2 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*connect-msolservice*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*connect-azuread*\" OR TO_LOWER(win.ScriptBlockTe… | 13 |  |
| q-b3d2925d4d | triage T1621 step 2 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 297 |  |
| q-f6c2f78c1d | triage T1621 step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*mfa*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*multi-factor*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*authent… | 0 |  |
| q-90eb6be6f0 | triage T1621 step 3 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4624\" \| STATS cnt = COUNT(*) BY win.TargetUserName, win.LogonType, host.name \| SORT cnt DESC \| LIMIT 30"} | 23 |  |
| q-5f227202b6 | triage T1621 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" \| WHERE TO_LOWER(process.command_line) LIKE \"*mfa*\" OR TO_LOWER(process.command_line) LIKE \"*authenticator*\" OR TO_LOWER(process.command_line) LIKE \"*otp*\" OR … | 0 |  |
| q-0bf9c8126b | triage T1621 step 4 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"http\" \| KEEP @timestamp, source.ip, destination.ip, url.original, http.request.method, user_agent.original, _id, _index \| LIMIT 30"} | 30 |  |
| q-2fcf330312 | triage T1621 step 5 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4625\" OR event.code == \"4771\" OR event.code == \"4776\" \| STATS cnt = COUNT(*) BY win.TargetUserName, host.name \| SORT cnt DESC \| LIMIT 20"} | 1 |  |
| q-f33575842c | triage T1621 step 5 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*invoke-restmethod*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*invoke-webrequest*\" OR TO_LOWER(win.ScriptBlockTe… | 0 |  |
| q-e93ac4e842 | triage T1621 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8Rl"} | None |  |
| q-964fa94308 | triage T1621 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8Rl"} | None |  |
| q-e8836c7cfa | triage T1621 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8Rl"} | None |  |
| q-6ec969da55 | triage T1649 step 1 | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8Rl"} | None |  |
| q-fed6de7260 | triage T1649 step 1 | search | {"dataset": "windows.security", "query": "event.code:4657 AND win.ObjectName:*SystemCertificates*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "win.ObjectName", "win.OperationType", "win.SubjectUserName", "win.ProcessName", "win.… | 1 | F59 |
| q-91d6aa662f | triage T1649 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:13 AND registry.path:*SystemCertificates*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "registry.path", "process.executable", "user.name", "registry.data.strings"], "size": 30, "… | 19 | F59 |
| q-e2c92fe439 | triage T1649 step 2 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Cert* OR win.ScriptBlockText:*Pfx* OR win.ScriptBlockText:*Crypto*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "process.command… | 1 |  |
| q-1fbb5e0942 | triage T1649 step 2 | search | {"dataset": "windows.security", "query": "event.code:4768", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "win.TargetUserName", "win.IpAddress", "win.TicketEncryptionType", "win.TicketOptions", "win.Status"], "size": 20, "sort": "as… | 14 | F59 |
| q-e6c44cee90 | triage T1649 step 2 | search | {"dataset": "windows.security", "query": "event.code:4657 AND win.ObjectName:*Certificates*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "win.ObjectName", "win.OperationType", "win.SubjectUserName", "win.ProcessName", "win.NewVal… | 1 |  |
| q-959a0e7658 | triage T1649 step 3 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None | F58 |
| q-e98d22506c | triage T1649 step 3 | search | {"dataset": "windows.sysmon", "query": "file.path:*Downloads* AND file.path:*.pfx*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "process.executable", "process.command_line", "file.path", "user.name"], "size": 20, "s… | 2 | F58 |
| q-39115298c8 | triage T1649 step 4 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTWIbqw"} | None | F58 |
| q-c6d3deb8a4 | triage T1649 step 4 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND file.path:*.pfx*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "process.executable", "process.command_line", "file.path", "user.name"], "size": 20, "sort": "a… | 1 |  |
| q-24b3f5fa01 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-91cba593e5 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-35408c2e74 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-b09cf372b3 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-03538b247d | triage T1649 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTkbEF9"} | None |  |
| q-64c8518fb1 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTWIbqw"} | None |  |
| q-568c11ad03 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTWIbqw"} | None |  |
| q-913bcb19d2 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItT2v6oH"} | None |  |
| q-d03abb1419 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItT2v6oH"} | None |  |
| q-e709d30713 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ6CoZN"} | None |  |
| q-80ff695b6a | triage T1649 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ef_w"} | None |  |
| q-add280bd41 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ef_w"} | None |  |
| q-14abb2b257 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gj"} | None |  |
| q-a561d43e9b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gj"} | None |  |
| q-e57814a390 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-e513dcd3a5 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None |  |
| q-7e67dcba1c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None |  |
| q-5a848de2ed | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKA_"} | None |  |
| q-a250c63a69 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKA_"} | None |  |
| q-0682f4f559 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTVGQnT"} | None |  |
| q-f6619d4ad5 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTVGQnT"} | None |  |
| q-b61651f537 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVr3bsA"} | None |  |
| q-2b634cad56 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVr3bsA"} | None |  |
| q-805a29df4c | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVz9KVt"} | None |  |
| q-93a9c17774 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZCgBha"} | None |  |
| q-a73af5f1f7 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZCgBha"} | None |  |
| q-955850b7e9 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZWqdCw"} | None |  |
| q-1591f8280d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItPM8kte"} | None |  |
| q-b6c3747e7f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItPM8kte"} | None |  |
| q-2d8aeb1e86 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItPE0PdZ"} | None |  |
| q-8b66ed1c4e | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVz8aWs"} | None |  |
| q-f28ecac876 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItV19xlz"} | None |  |
| q-6e33f02def | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItPM8kte"} | None |  |
| q-bad0eae866 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8TL"} | None |  |
| q-494571b4ab | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTVGglR"} | None |  |
| q-bee30126af | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTVGQmt"} | None |  |
| q-947ed257a9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTpgCep"} | None |  |
| q-b39d47bf52 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTtmJQ5"} | None |  |
| q-36ee119a2f | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKA_"} | None |  |
| q-518f96b91c | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKA_"} | None |  |
| q-21498b6c4c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTtmJQ5"} | None |  |
| q-bc30ad26cc | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRkUVV"} | None |  |
| q-a39469898f | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRkUVV"} | None |  |
| q-d6e2129ad2 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRkUVV"} | None |  |
| q-b777abe343 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQE_JuD"} | None |  |
| q-879639872c | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVq1T69"} | None |  |
| q-83d39784ba | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItViw21R"} | None |  |
| q-fc400901c0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTtmJQ5"} | None |  |
| q-ac2378a710 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRkUVV"} | None |  |
| q-2e8648d0f8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTtmJQ5"} | None |  |
| q-d4aca7ece6 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8RS"} | None |  |
| q-301f935ec1 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8Re"} | None |  |
| q-bf2ac9c9d2 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8RY"} | None |  |
| q-d344adc761 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8Rb"} | None |  |
| q-201a6d3746 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-7a845427f7 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-c39dafeb93 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-38fbcb5a90 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQB61zZ"} | None |  |
| q-5a7db3c2e9 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZCgBha"} | None |  |
| q-7be58d7c1f | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ev8p"} | None |  |
| q-8fdf776171 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQB61zZ"} | None |  |
| q-54b002629d | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8R_"} | None |  |
| q-3e1f33e065 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8S-"} | None |  |
| q-ca72611d9c | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ev8p"} | None |  |
| q-7c69f5837d | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ev8p"} | None |  |
| q-f4398f700d | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVn01NG"} | None |  |
| q-9239b480b2 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrYMQT"} | None |  |
| q-9e5de80d5d | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVn0lP2"} | None |  |
| q-4d737a4953 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVn0lP2"} | None |  |
| q-a533d4e0e7 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVn0lP2"} | None |  |
| q-8e6d00f1f0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO9rO3Z"} | None |  |
| q-0e4020bd05 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO9rO3Z"} | None |  |
| q-1fff58a731 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOxeHN4"} | None |  |
| q-8acafa03e7 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8R_"} | None |  |
| q-4b90a0705a | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrYjF"} | None |  |
| q-363a55501b | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrYjF"} | None |  |
| q-53a89b6a63 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrYjN"} | None |  |
| q-078efe56a1 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrYjN"} | None |  |
| q-6d36c5d54e | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrYgN"} | None |  |
| q-c6c57d2a21 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrYgN"} | None |  |
| q-8c05ab3c74 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrYih"} | None |  |
| q-784a71e8f0 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrYih"} | None |  |
| q-cc5ae5eb7a | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaKWxp4"} | None |  |
| q-f85589170c | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaKWxp4"} | None |  |
| q-5dc8154a74 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaFQQtn"} | None |  |
| q-b8e3c7cecd | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaFQQtn"} | None |  |
| q-e3bd9f8d4f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTqgghU"} | None |  |
| q-b20108f0fe | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTqgghU"} | None |  |
| q-5f6c296801 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUKHd9O"} | None |  |
| q-f41b994311 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-c1082baf9c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-96837ce195 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-6354ee3262 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gj"} | None |  |
| q-a4ee8a1607 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRkUVV"} | None |  |
| q-9c26ec8655 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRk1C1"} | None |  |
| q-80499927ee | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None |  |
| q-2f5225ad16 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None |  |
| q-d5a99f9686 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None |  |
| q-16718a0689 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZLhp5i"} | None |  |
| q-d9bd6a0ff7 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKC-"} | None |  |
| q-3f75255dd9 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItV3-aVk"} | None |  |
| q-70e8c09003 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrYiq"} | None |  |
| q-fc65d75664 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrIjg"} | None |  |
| q-b3b32b2241 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ8Frba"} | None |  |
| q-854eb014cd | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ8Frba"} | None |  |
| q-c018b7cf2a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTVHe6C"} | None |  |
| q-daf45a7c73 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOVAUl3"} | None |  |
| q-8b0dc734d3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOVAUl3"} | None |  |
| q-5381f3d0c5 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrog-"} | None |  |
| q-c1a75a237c | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrog-"} | None |  |
| q-b59df447e3 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrog-"} | None |  |
| q-74fdbcdbe5 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-10245531f9 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-09de2b5a27 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRlVDe"} | None |  |
| q-b136e7436a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTVGglR"} | None |  |
| q-1ccbafaa89 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZCgBha"} | None |  |
| q-e7dcaa0e25 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZCgBha"} | None |  |
| q-31c781a078 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRk1C1"} | None |  |
| q-d321eaf891 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRk1Cy"} | None |  |
| q-e3baaaf57f | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZCgBha"} | None |  |
| q-53d6ee2a72 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTqhAkt"} | None |  |
| q-957b0d320c | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrYiv"} | None |  |
| q-8c713c4732 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItThYt63"} | None |  |
| q-e0531f6a06 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO9rO3Z"} | None |  |
| q-b09d19f2aa | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRlVDe"} | None |  |
| q-410629d2b0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-4bb772465e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-375828b1d3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None |  |
| q-7e4eeb6dcb | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None |  |
| q-808326a6e4 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKB-"} | None |  |
| q-5b84f8d8c8 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ8FLV1"} | None |  |
| q-0a837b5a27 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKA_"} | None |  |
| q-f03de6b5fe | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKA_"} | None |  |
| q-9f1044dd2e | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKA_"} | None |  |
| q-58378ab62b | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-7d547f3567 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOVAkmV"} | None |  |
| q-53a7fac9ad | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItQE_JuD"} | ERROR |  |
| q-0b43693973 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-740e65e7f1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-7c43de2929 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gj"} | None |  |
| q-35d8b8129a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQB61zZ"} | None |  |
| q-9214a10488 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaKXhpQ"} | None |  |
| q-a1b4f3c61b | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaKXhpQ"} | None |  |
| q-f571bd5601 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaKXhpQ"} | None |  |
| q-b1933c0a86 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOrW_3E"} | None |  |
| q-59e30343cb | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOrW_3E"} | None |  |
| q-1e2fff79aa | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOrW_3E"} | None |  |
| q-59ef0c1a46 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrYiy"} | None |  |
| q-5e3384c24c | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrYiy"} | None |  |
| q-d0f8ef794c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOmQp3C"} | None |  |
| q-494f4016b1 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7DT5G"} | None |  |
| q-12c51abee1 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgroge"} | None |  |
| q-a25c4ac814 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgroge"} | None |  |
| q-51c821d465 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgroge"} | None |  |
| q-014e5966cb | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgroge"} | None |  |
| q-41baa00fad | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOrW_3E"} | None |  |
| q-a32538df56 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-29197eb3ab | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-db06a53566 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gj"} | None |  |
| q-f6ab679c54 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None |  |
| q-78b660097f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None |  |
| q-24637c6208 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZWqNA3"} | None |  |
| q-6b134cdb37 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZWqNDf"} | None |  |
| q-0b9fa3f342 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZWqdCw"} | None |  |
| q-c54221fcf5 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKC-"} | None |  |
| q-568d49280d | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKC-"} | None |  |
| q-d4fd4a9f25 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKC-"} | None |  |
| q-d120947ad9 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItV3-aXQ"} | None |  |
| q-59f6b55902 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItV3-aXQ"} | None |  |
| q-2e67e92bcf | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOaA_"} | None |  |
| q-9fe0a6984e | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOaA_"} | None |  |
| q-8306f8742b | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ8FbW6"} | None |  |
| q-b5559405a3 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ8FbW6"} | None |  |
| q-54353b69bb | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZWqdCz"} | None |  |
| q-9f7a9a8c16 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8Rl"} | None |  |
| q-2a8faede27 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrYi9"} | None |  |
| q-48ba52eaea | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOVAUl3"} | None |  |
| q-95a85bc3ab | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOVAUl3"} | None |  |
| q-939c215f77 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRkUVV"} | None |  |
| q-e4f03860a3 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8Rl"} | None |  |
| q-8a434c4352 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8Rl"} | None |  |
| q-755851105d | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8Rl"} | None |  |
| q-eb176f5c4b | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8Rl"} | None |  |
| q-5d4ee3b52d | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-01d70d0a3d | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-6103fe398d | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-7c1ef0fcc3 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-2de5c89297 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTkbEF9"} | None |  |
| q-b8e8222794 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTWIbqw"} | None |  |
| q-ba722352fc | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTWIbqw"} | None |  |
| q-e784fbb665 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItT2v6oH"} | None |  |
| q-41b9a38001 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItT2v6oH"} | None |  |
| q-3a43f7a7db | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ6CoZN"} | None |  |
| q-9ae5e6ee9e | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ef_w"} | None |  |
| q-c634bcc47d | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ef_w"} | None |  |
| q-e3019c761f | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND host.name:\"nashua.dmevals.local\"", "time_from": "2020-05-02T02:54:29+00:00", "time_to": "2020-05-02T03:30:59+00:00", "size": 100, "sub_field": "process.parent.executable"… | 61 |  |
| q-bc56de3eb6 | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11 AND host.name:\"nashua.dmevals.local\"", "time_from": "2020-05-02T02:54:29+00:00", "time_to": "2020-05-02T03:30:59+00:00", "size": 100, "sub_field": "process.executable"} | 249 |  |
| q-744aff4b13 | pivot seed | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND host.name:\"nashua.dmevals.local\"", "time_from": "2020-05-02T02:54:29+00:00", "time_to": "2020-05-02T03:30:59+00:00", "size": 100, "sub_field": "process.parent.execut… | 63 |  |
| q-2fac72ed43 | pivot seed | aggregate | {"dataset": "windows.powershell", "field": "event.code", "query": "host.name:\"nashua.dmevals.local\"", "time_from": "2020-05-02T02:54:29+00:00", "time_to": "2020-05-02T03:30:59+00:00", "size": 100, "sub_field": null} | 192 |  |
| q-5e6febe478 | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND host.name:\"newyork.dmevals.local\"", "time_from": "2020-05-02T02:49:04+00:00", "time_to": "2020-05-02T03:34:13+00:00", "size": 100, "sub_field": "process.parent.executable… | 18 |  |
| q-5203804dfb | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11 AND host.name:\"newyork.dmevals.local\"", "time_from": "2020-05-02T02:49:04+00:00", "time_to": "2020-05-02T03:34:13+00:00", "size": 100, "sub_field": "process.executable"} | 81 |  |
| q-c4edf43bdb | pivot seed | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND host.name:\"newyork.dmevals.local\"", "time_from": "2020-05-02T02:49:04+00:00", "time_to": "2020-05-02T03:34:13+00:00", "size": 100, "sub_field": "process.parent.execu… | 18 |  |
| q-82cee75034 | pivot seed | aggregate | {"dataset": "windows.powershell", "field": "event.code", "query": "host.name:\"newyork.dmevals.local\"", "time_from": "2020-05-02T02:49:04+00:00", "time_to": "2020-05-02T03:34:13+00:00", "size": 100, "sub_field": null} | 2185 |  |
| q-5f0d7d5668 | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND host.name:\"scranton.dmevals.local\"", "time_from": "2020-05-02T02:41:17+00:00", "time_to": "2020-05-02T03:36:29+00:00", "size": 100, "sub_field": "process.parent.executabl… | 359 |  |
| q-fa13afa569 | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11 AND host.name:\"scranton.dmevals.local\"", "time_from": "2020-05-02T02:41:17+00:00", "time_to": "2020-05-02T03:36:29+00:00", "size": 100, "sub_field": "process.executable"} | 1276 |  |
| q-01e4e88e2b | pivot seed | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND host.name:\"scranton.dmevals.local\"", "time_from": "2020-05-02T02:41:17+00:00", "time_to": "2020-05-02T03:36:29+00:00", "size": 100, "sub_field": "process.parent.exec… | 370 |  |
| q-3d1e7877a8 | pivot seed | aggregate | {"dataset": "windows.powershell", "field": "event.code", "query": "host.name:\"scranton.dmevals.local\"", "time_from": "2020-05-02T02:41:17+00:00", "time_to": "2020-05-02T03:36:29+00:00", "size": 100, "sub_field": null} | 8602 |  |
| q-ef36a07188 | pivot step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND host.name:\"scranton.dmevals.local\" AND (process.executable:*SysinternalsSuite* OR process.executable:*victim* OR process.executable:*hostui* OR process.executable:*sdclt* OR process.executable:*csc.exe… | 15 | F60 |
| q-94c6d52b16 | pivot step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND host.name:\"nashua.dmevals.local\" AND (process.executable:*python* OR process.executable:*Rar* OR process.executable:*sdelete* OR process.executable:*PSEXESVC*)", "time_from": null, "time_to": null, "fi… | 13 |  |
| q-8c6a612add | pivot step 2 | search | {"dataset": "windows.powershell", "query": "host.name:\"nashua.dmevals.local\" AND event.code:4104", "time_from": null, "time_to": null, "fields": ["@timestamp", "event.code", "host.name", "user.name", "powershell.file.script_block_text", "winlog.event_data.Sc… | 11 |  |
| q-ebdbd16072 | pivot step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*pfx OR file.path:*zip OR file.path:*key* OR file.path:*cred* OR file.path:*Rar* OR file.path:*python* OR file.path:*victim*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "h… | 9 |  |
| q-f88e5e7844 | pivot step 3 | search | {"dataset": "windows.powershell", "query": "host.name:\"scranton.dmevals.local\" AND event.code:4104 AND (message:*pfx* OR message:*PrivateKey* OR message:*LSASS* OR message:*lsass* OR message:*Credential* OR message:*keystroke* OR message:*clipboard* OR messa… | 15 | F61, F62 |
| q-932aa1cbbc | pivot step 3 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND (winlog.event_data.TargetImage:*lsass* OR winlog.event_data.TargetImage:*LSASS*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "winlog.event_data.GrantedAcces… | 0 |  |
| q-9217fd3605 | pivot step 4 | get_fields | {"dataset": "windows.sysmon", "prefix": "winlog.event_data"} | None |  |
| q-0ddc0eb684 | pivot step 4 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND winlog.event_data.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "winlog.event_data.GrantedAccess", "process.executable", "user.name", "win… | 0 |  |
| q-d2195c482a | pivot step 5 | get_fields | {"dataset": "windows.sysmon", "prefix": ""} | None |  |
| q-87982d4da8 | pivot step 6 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "win.GrantedAccess", "process.executable", "user.name", "win.TargetImage", "win.CallTrac… | 326 |  |
| q-5e2dde62da | pivot step 6 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTkbEF9"} | None | F61 |
| q-4b96f21ebf | pivot step 7 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND (win.GrantedAccess:0x1fffff OR win.GrantedAccess:0x1f3fff OR win.GrantedAccess:0x143a OR win.GrantedAccess:0x1410)", "time_from": null, "time_to": null, "fields": ["@timestam… | 5 |  |
| q-8300eb152d | pivot step 7 | search | {"dataset": "windows.sysmon", "query": "event.code:13 AND registry.path:*Cache*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "registry.path", "process.executable", "user.name", "registry.data.strings"], "size": 20, … | 6625 |  |
| q-9839ce4ea1 | pivot step 8 | search | {"dataset": "windows.sysmon", "query": "event.code:3 AND (process.executable:*python* OR process.executable:*victim* OR process.executable:*powershell* OR process.executable:*Rar*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "ev… | 373 |  |
| q-40a6c63801 | pivot step 8 | search | {"dataset": "windows.sysmon", "query": "event.code:13 AND registry.path:*SECURITY\\\\Cache*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "registry.path", "process.executable", "user.name", "registry.data.strings"], … | 5 |  |
| q-f226502a28 | pivot step 9 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZCgBha"} | None | F60 |
| q-0da34a0614 | pivot step 9 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND host.name:\"scranton.dmevals.local\" AND (file.path:*victim* OR file.path:*bmp OR file.path:*png OR file.path:*7z OR file.path:*OfficeSupplies*)", "time_from": null, "time_to": null, "fields": ["@timest… | 6 |  |
| q-aa5292dc8e | pivot step 10 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND host.name:\"nashua.dmevals.local\" AND process.executable:*python*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "file.path", "process.executable", "user.name… | 19 |  |
| q-016c99e3cd | pivot step 10 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND file.path:*victim*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "file.path", "process.executable", "user.name"], "size": 10, "sort": "asc"} | 0 |  |
| q-a669fbc0da | pivot verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZCgBha"} | None |  |
| q-2578a8e4f0 | pivot verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZCgBha"} | None |  |
| q-4cbbc0c8e3 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTVGglR"} | None |  |
| q-1560356aea | pivot verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-c95ba8a920 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTkbEF9"} | None |  |
| q-0b82014bd7 | pivot verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRk1C1"} | None |  |
| q-51a1782b7c | pivot verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRk1Cy"} | None |  |
| q-c438c4079e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gj"} | None |  |
| q-2ddfc08981 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gj"} | None |  |
| q-3b430d6d3d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-ce987d1c15 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None |  |
| q-98583c3fa7 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None |  |
| q-025aca5328 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKA_"} | None |  |
| q-5e534195ef | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKA_"} | None |  |
| q-e2fe7e8a5f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTVGQnT"} | None |  |
| q-c2e168b521 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTVGQnT"} | None |  |
| q-df2a8f0b13 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVr3bsA"} | None |  |
| q-7249a64d90 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVr3bsA"} | None |  |
| q-a52a3f203d | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVz9KVt"} | None |  |
| q-fc390079c8 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZCgBha"} | None |  |
| q-b2f882d0af | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZCgBha"} | None |  |
| q-1c575bbd95 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZWqdCw"} | None |  |
| q-b68c69e13e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItPM8kte"} | None |  |
| q-f4cd8039ec | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItPM8kte"} | None |  |
| q-f17d707e80 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItPE0PdZ"} | None |  |
| q-b09cb18d2f | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVz8aWs"} | None |  |
| q-d434562170 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItV19xlz"} | None |  |
| q-014789897e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItPM8kte"} | None |  |
| q-65811155bc | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8TL"} | None |  |
| q-476ffda3ca | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTVGglR"} | None |  |
| q-a8a1734844 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTVGQmt"} | None |  |
| q-87295a4255 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTpgCep"} | None |  |
| q-cfd2f424fd | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTtmJQ5"} | None |  |
| q-926f61b793 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKA_"} | None |  |
| q-a53c8ef4db | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKA_"} | None |  |
| q-6ac17f638a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTtmJQ5"} | None |  |
| q-7a0d415903 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRkUVV"} | None |  |
| q-121058d3ca | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRkUVV"} | None |  |
| q-5c4ef223d0 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRkUVV"} | None |  |
| q-10bf02ea65 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQE_JuD"} | None |  |
| q-2f33014f0e | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVq1T69"} | None |  |
| q-a07035385f | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItViw21R"} | None |  |
| q-f109fd1542 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTtmJQ5"} | None |  |
| q-58ce394538 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRkUVV"} | None |  |
| q-f918dc7c27 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTtmJQ5"} | None |  |
| q-4946abc595 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8RS"} | None |  |
| q-9c822270cb | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8Re"} | None |  |
| q-a4855ecbb2 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8RY"} | None |  |
| q-75256468fe | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8Rb"} | None |  |
| q-ed1fd787de | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-fa226ba06e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-30333efe0e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-b7d09513d3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQB61zZ"} | None |  |
| q-7d78aec6ba | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZCgBha"} | None |  |
| q-337edf58c5 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ev8p"} | None |  |
| q-e9bb3aa01a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQB61zZ"} | None |  |
| q-d73927b71d | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8R_"} | None |  |
| q-df48796c03 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8S-"} | None |  |
| q-4f5b53eac8 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ev8p"} | None |  |
| q-ac18ec1415 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ev8p"} | None |  |
| q-cefda3865f | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVn01NG"} | None |  |
| q-fc38ce4c8f | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrYMQT"} | None |  |
| q-f1eb0d1429 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVn0lP2"} | None |  |
| q-b69423783e | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVn0lP2"} | None |  |
| q-bea9db4ffd | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItVn0lP2"} | None |  |
| q-333799f03f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO9rO3Z"} | None |  |
| q-2578594019 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO9rO3Z"} | None |  |
| q-f8068f9138 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOxeHN4"} | None |  |
| q-cc1404ab40 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8R_"} | None |  |
| q-7665b352ac | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrYjF"} | None |  |
| q-3271c869d0 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrYjF"} | None |  |
| q-0cd52d70f4 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrYjN"} | None |  |
| q-76bf1be66f | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrYjN"} | None |  |
| q-12d21ce827 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrYgN"} | None |  |
| q-0f5398e63f | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrYgN"} | None |  |
| q-f0d176122e | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrYih"} | None |  |
| q-2cea72234e | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrYih"} | None |  |
| q-91efa5e83b | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaKWxp4"} | None |  |
| q-828cb6990c | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaKWxp4"} | None |  |
| q-d8d25a6000 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaFQQtn"} | None |  |
| q-01b8457a3c | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaFQQtn"} | None |  |
| q-1b3f3b33eb | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTqgghU"} | None |  |
| q-5414ef64fb | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTqgghU"} | None |  |
| q-0035c4cc20 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUKHd9O"} | None |  |
| q-3e96e5d198 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-fd6753b9a4 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-65ff9a6a23 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-1679d89486 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gj"} | None |  |
| q-4913932f07 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRkUVV"} | None |  |
| q-ba7eea4e25 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRk1C1"} | None |  |
| q-7de0734fbf | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None |  |
| q-25e45ceb8a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None |  |
| q-edca3e8ecb | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None |  |
| q-6cf28044de | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZLhp5i"} | None |  |
| q-f1132e2d59 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKC-"} | None |  |
| q-9af94a0147 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItV3-aVk"} | None |  |
| q-ab53531c73 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrYiq"} | None |  |
| q-315c52baae | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrIjg"} | None |  |
| q-4d24838d14 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ8Frba"} | None |  |
| q-ffc24c8047 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ8Frba"} | None |  |
| q-34eedf1c9f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTVHe6C"} | None |  |
| q-bf3db8f6f2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOVAUl3"} | None |  |
| q-0d2367d179 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOVAUl3"} | None |  |
| q-0e194695ec | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrog-"} | None |  |
| q-d18599b743 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrog-"} | None |  |
| q-6d6b69cbe3 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrog-"} | None |  |
| q-23f2f3bc85 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-a78a83c661 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-3acd54dc31 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRlVDe"} | None |  |
| q-9ad1e0c530 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTVGglR"} | None |  |
| q-99e39da81a | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZCgBha"} | None |  |
| q-b8f1e1b93e | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZCgBha"} | None |  |
| q-e8c5b14b44 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRk1C1"} | None |  |
| q-55e1988853 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRk1Cy"} | None |  |
| q-4d808b779d | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZCgBha"} | None |  |
| q-6f1ab0c07c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTqhAkt"} | None |  |
| q-f5f317e4c0 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrYiv"} | None |  |
| q-afb03a751c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItThYt63"} | None |  |
| q-a08ace849b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItO9rO3Z"} | None |  |
| q-74d16bb881 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRlVDe"} | None |  |
| q-2cec14e362 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-607abe1c17 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-e5c1a71aef | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None |  |
| q-8df4b76802 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None |  |
| q-48823924da | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKB-"} | None |  |
| q-aa3d233a15 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ8FLV1"} | None |  |
| q-b5bd066e91 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKA_"} | None |  |
| q-fd01f5241e | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKA_"} | None |  |
| q-0df3872196 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKA_"} | None |  |
| q-6c0a73549f | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-4ad1cd9bcc | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOVAkmV"} | None |  |
| q-cb3342cd28 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItQE_JuD"} | ERROR |  |
| q-e26336eb5c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-031f5b3551 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-dc2860cfaa | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gj"} | None |  |
| q-577f09a8bf | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItQB61zZ"} | None |  |
| q-de5be37a6d | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaKXhpQ"} | None |  |
| q-9f6402b247 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaKXhpQ"} | None |  |
| q-cd99f96f77 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaKXhpQ"} | None |  |
| q-912bc236e2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOrW_3E"} | None |  |
| q-98bb143454 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOrW_3E"} | None |  |
| q-eaacaeb527 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOrW_3E"} | None |  |
| q-a181dfb692 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrYiy"} | None |  |
| q-f929a56cd8 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrYiy"} | None |  |
| q-6e94d4a8da | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOmQp3C"} | None |  |
| q-3a964a4442 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7DT5G"} | None |  |
| q-b7dbed73ce | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgroge"} | None |  |
| q-c1dd0843d6 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgroge"} | None |  |
| q-ac97ff637f | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgroge"} | None |  |
| q-aa73d36c6b | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgroge"} | None |  |
| q-bc699353a8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOrW_3E"} | None |  |
| q-b77cbb6b7f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-c6f3aba723 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gm"} | None |  |
| q-c0ec2593a0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTka0Gj"} | None |  |
| q-ca0616a8a4 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None |  |
| q-1b1d8357d7 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHNH1uOFchItUHCTY0"} | None |  |
| q-fe7f94604b | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZWqNA3"} | None |  |
| q-701b3ce134 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZWqNDf"} | None |  |
| q-9b337dd1bf | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZWqdCw"} | None |  |
| q-e10b4545e3 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKC-"} | None |  |
| q-dbb4b6d5c8 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKC-"} | None |  |
| q-84ad477e88 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOKC-"} | None |  |
| q-33b0966752 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItV3-aXQ"} | None |  |
| q-c81a32f0a9 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItV3-aXQ"} | None |  |
| q-4162fae71a | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOaA_"} | None |  |
| q-897c72687e | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItaDOaA_"} | None |  |
| q-8ca825db08 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ8FbW6"} | None |  |
| q-c8fc1468d9 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ8FbW6"} | None |  |
| q-a6f9b1996d | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZWqdCz"} | None |  |
| q-47c1ba010c | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8Rl"} | None |  |
| q-9098f94e08 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.17-000001", "id": "AaFHNX1uOFchItbgrYi9"} | None |  |
| q-cb259d2ba6 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOVAUl3"} | None |  |
| q-19b94309fe | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItOVAUl3"} | None |  |
| q-6a23b34c2b | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRkUVV"} | None |  |
| q-ee58e578a1 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8Rl"} | None |  |
| q-fddf0bf579 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8Rl"} | None |  |
| q-db419be003 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8Rl"} | None |  |
| q-7c85101a09 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.17-000001", "id": "AaFHNH1uOFchItbrX8Rl"} | None |  |
| q-aa8846ad72 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-f69aa35e07 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-08a4b89d9b | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-801ec4947f | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-dbe1d7cd69 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTkbEF9"} | None |  |
| q-f95cc967ca | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTWIbqw"} | None |  |
| q-76827e2dca | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTWIbqw"} | None |  |
| q-6ad4aff5f2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItT2v6oH"} | None |  |
| q-9973907706 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItT2v6oH"} | None |  |
| q-7e6fb5cbfa | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ6CoZN"} | None |  |
| q-f9f5200f92 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ef_w"} | None |  |
| q-83120481f6 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.17-000001", "id": "AaFHNH1uOFchItZ7Ef_w"} | None |  |
| q-a43d7f50b3 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZCgBha"} | None |  |
| q-7c5ba4f983 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZCgBha"} | None |  |
| q-ad491607a3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTVGglR"} | None |  |
| q-3bda9b354e | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZSl2ML"} | None |  |
| q-66985c672a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.17-000001", "id": "AaFHM31uOFchItTkbEF9"} | None |  |
| q-10ff246ea9 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRk1C1"} | None |  |
| q-9de74835d4 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.17-000001", "id": "AaFHNX1uOFchItZRk1Cy"} | None |  |

## Verification

Evidence items cited: 190; confirmed against the stored events: 188; rejected: 2. Each item was re-fetched with get_event; it is confirmed only if the event exists, the cited field holds the cited value, and the cited query_id is a query of this run that returned that event.
Evidence sent back to the agents for correction during the run: 8 item(s) in 4 submission(s) (one correction round each; what still failed was rejected).

## Limitations

- Findings describe what the stored logs show; activity these sources did not log cannot be seen.
- Datasets with non-overlapping time windows (see Data examined) were analysed separately.
- Long field values are shortened in this report; full events are retrievable by _index/_id.
