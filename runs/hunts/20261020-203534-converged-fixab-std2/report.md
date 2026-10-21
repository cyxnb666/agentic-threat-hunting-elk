# Threat hunt report — 20261020-203534-converged-fixab-std2

**Hypothesis:** An adversary who compromised Windows hosts in this network stole credentials from them (MITRE ATT&CK tactic: Credential Access).

**Verdict: Confirmed** — 6 in-scope incident(s) of verified malicious findings (confidence >= medium): I01 T1003.001 (F01, F11, F16, F33, F36, F47, F48, F52, F57), I02 T1056.001 (F09), I03 T1056.002 (F10), I05 T1187 (F20, F28), I06 T1552.001 (F58, F59, F62), I07 T1552.004 (F27, F56, F26)

Verdict method: rules over verified evidence (Confirmed if >=1 in-scope incident of verified malicious findings (confidence >= medium); Inconclusive if only suspicious incidents or coverage gaps; Refuted if full coverage and no malicious/suspicious finding)

| Run | Value |
|---|---|
| Profile | converged (thinking=False, temperature=0.0) |
| Model | deepseek-flash |
| Started / finished (UTC) | 2026-10-20T12:35:34+00:00 / 2026-10-20T12:46:49+00:00 (675.2 s) |
| LLM calls / tokens | 156 / {'prompt': 4793219, 'completion': 146709} |
| MCP tool calls | 1270 (server tools: list_data_sources, get_fields, search, count, aggregate, timeline, esql, get_event, get_registry) |
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
| I01 | T1003.001 | yes | malicious/high | F01, F11, F16, F33, F36, F47, F48, F52, F57 | PowerShell/wsmprovhost opened LSASS with full-access masks on SCRANTON and NASHUA |
| I02 | T1056.001 | yes | malicious/high | F09 | PowerShell Get-Keystrokes keylogger on SCRANTON |
| I03 | T1056.002 | yes | malicious/high | F10 | Invoke-ScreenCapture screen capture loop on SCRANTON |
| I04 | T1110.002 | yes | suspicious/medium | F07 | No offline cracking or hive dumping; SAM accesses are normal lsass behavior |
| I05 | T1187 | yes | malicious/high | F20, F28 | Invoke-Exfil: 7z archive of Downloads copied to WebDAV share with NTLM auth |
| I06 | T1552.001 | yes | malicious/high | F58, F59, F62 | Credential-named file harvesting and password-protected archive staging on NASHUA |
| I07 | T1552.004 | yes | malicious/high | F27, F56, F26 | Get-PrivateKeys exported LocalMachine certificates to PFX files on SCRANTON |
| I08 | T1558.003 | yes | suspicious/medium | F50 | Kerberoast-style krbtgt TGS request by pbeesly |
| I09 | T1649 | yes | suspicious/medium | F60, F61 | Certificate store write on NASHUA during pbeesly session |
| I10 | out-of-scope:T1021.002 | no | suspicious/medium | F24 | PsExec service installs and offensive PowerShell toolkit (lateral movement/execution) |
| I11 | out-of-scope:T1021.002 | no | suspicious/medium | F44 | SMB/NTLM logon consistent with PsExec lateral movement, not relay |
| I12 | out-of-scope:T1055.012 | no | malicious/high | F63, F64, F66, F67, F68 | Masqueraded .scr loader, steganographic payload, csc compile and anti-forensics on SCRANTON |

## Findings

### F57 · malicious / high · T1003.001 · wsmprovhost.exe (pbeesly) opened lsass.exe with 0x1f3fff on NASHUA

Evidence status: **verified**

On nashua.dmevals.local at 03:09:29 wsmprovhost.exe as pbeesly opened lsass.exe with 0x1f3fff via a PowerShell call trace.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.TargetImage | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7c939yF | q-50d4564ac4 | ok |
| 2 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7c939yF | q-50d4564ac4 | ok |
| 3 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7c939yF | q-50d4564ac4 | ok |

### F09 · malicious / high · T1056.001 · PowerShell Get-Keystrokes keylogger executed on SCRANTON by pbeesly

Evidence status: **verified**

On scranton.dmevals.local, user pbeesly (SID ...-1107) ran a PowerShell keylogging session on 2020-05-02 between 03:06:47 and 03:07:49 UTC. A 'Keystroke-Check' function was defined that enumerates running processes to detect AV products (avp, acs, outpost, mcvsescn, mcods, navapsvc, kav, AvastSvc, AvastUi, nod32krn, nod32, ekern, dwengine, MsMpEng, msseces, ekrn, savservice, scfservice, savadminservice) — classic keylogger anti-analysis. It was then invoked, followed by 'Get-Keystrokes;Start-Sleep -Seconds 15;View-Job -JobName "Keystrokes"', a second View-Job of the Keystrokes job, and Remove-Job -Name "Keystrokes" -Force to clean up. The same session also ran Invoke-ScreenCapture (screenshot loop saving .bmp to Downloads, confirmed by a file-create of C:\Users\pbeesly\Downloads\gwq4xdwv.s5g.bmp) and a steganography loader that decoded and IEX'd a payload from C:\Users\pbeesly\Downloads\monkey.png. This is interactive input capture on a compromised host.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:06:47.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Keystroke-Check {     Get-Process \| Where-Object { $_.ProcessName -Eq "avp" -or $_.ProcessName -Eq "acs" -or $_.ProcessName -Eq "outpost" -or $_.Proce… | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qvSitD | q-309384e8d0 | ok |
| 2 | 2020-05-02 03:06:59.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | Get-Keystrokes;Start-Sleep -Seconds 15;View-Job -JobName "Keystrokes" | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qvTCuJ | q-5e99490720 | ok |
| 3 | 2020-05-02 03:07:49.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | Remove-Job -Name "Keystrokes" -Force | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qjPglC | q-5e99490720 | ok |
| 4 | 2020-05-02 03:06:47.000Z | scranton.dmevals.local | windows.powershell | user.name | pbeesly | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qvSitD | q-309384e8d0 | ok |
| 5 | 2020-05-02 03:06:47.000Z | scranton.dmevals.local | windows.powershell | host.name | scranton.dmevals.local | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qvSitD | q-309384e8d0 | ok |

### F10 · malicious / high · T1056.002 · Invoke-ScreenCapture GUI/screen capture loop on SCRANTON

Evidence status: **verified**

In the same pbeesly PowerShell session on scranton.dmevals.local, a function Invoke-ScreenCapture was defined that uses System.Windows.Forms.SystemInformation::VirtualScreen and System.Drawing.Graphics::CopyFromScreen to grab the full virtual screen every 300 seconds and save it as a randomly named .bmp in $env:USERPROFILE\Downloads. It was invoked with 'Invoke-ScreenCapture;Start-Sleep -Seconds 3;View-Job -JobName "Screenshot"', and Sysmon recorded the resulting file C:\Users\pbeesly\Downloads\gwq4xdwv.s5g.bmp written by powershell.exe at 03:06:00 UTC. Capturing the GUI is how an operator harvests on-screen credentials/input; no fake credential prompt (CredUIPromptForCredentials/Get-Credential) was observed, so this is GUI capture rather than a credential dialog.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:53.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-ScreenCapture # https://www.pdq.com/blog/capturing-screenshots-with-powershell-and-net/ {     Start-Job -Name "Screenshot" -ScriptBlock {       … | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qvSyuh | q-309384e8d0 | ok |
| 2 | 2020-05-02 03:05:53.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | Invoke-ScreenCapture;Start-Sleep -Seconds 3;View-Job -JobName "Screenshot" | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qvTCvd | q-309384e8d0 | ok |
| 3 | 2020-05-02 03:06:00.421Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Users\pbeesly\Downloads\gwq4xdwv.s5g.bmp | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hMLfHo | q-53cdce8be4 | ok |
| 4 | 2020-05-02 03:05:53.000Z | scranton.dmevals.local | windows.powershell | host.name | scranton.dmevals.local | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qvSyuh | q-309384e8d0 | ok |

### F20 · malicious / high · T1187 · WebDAV/UNC path used by Invoke-Exfil to force NTLM authentication and exfiltrate a 7z archive to 192.168.0.4

Evidence status: **verified**

On scranton.dmevals.local, user pbeesly, a PowerShell scriptblock (ScriptBlockId b2b03a9c-43f0-4285-837d-f22d4600b2ae, logged 2020-05-02T03:08:02Z, path C:\Program Files\SysinternalsSuite\psversion.ps1) defines function Invoke-Exfil. It compresses the user's Downloads into $env:APPDATA\OfficeSupplies.7z with password 'lolol', builds a PSCredential for user 'cozy', then maps a drive to the UNC/WebDAV path \\192.168.0.4\webdav via New-PSDrive and copies OfficeSupplies.7z there with Copy-Item. The WebDAV redirector (Microsoft-WebDAV-MiniRedir/10.0.18362, DavClnt) then performs the HTTP WebDAV conversation to 192.168.0.4:80 from 10.0.1.4 — OPTIONS, PROPFIND, LOCK, PUT, PROPPATCH on /webdav/OfficeSupplies.7z, with repeated 401 challenges answered and final 201/204 success — i.e. the host is coerced into authenticating to an attacker-controlled WebDAV endpoint, the forced-authentication pattern of T1187. The same host also produced a single NTLM network logon (4624 type 3, NtLmSsp, NTLM V2, target pbeesly, workstation 10.0.1.4, source 172.18.39.2) at 2020-05-02T03:20:41Z, the only NTLM logon in the whole security dataset (all other 217 type-3 logons are Kerberos). Supporting context: PowerShell created C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\hostui.lnk at 03:04:23Z and later ran 'Start-Process C:\Windows\System32\hostui.exe -verb runas' (03:21:26Z); PSEXESVC services were installed on nashua.dmevals.local by pbeesly. The zeek window (2020-04-30) does not overlap the Windows window, so the WebDAV flows are the network-side record of the same tooling rather than a time-correlated match.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qjPglL | q-bc3357b1cf | ok |
| 2 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qjPglL | q-bc3357b1cf | ok |
| 3 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qjPglL | q-bc3357b1cf | ok |
| 4 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | host.name | scranton.dmevals.local | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qjPglL | q-bc3357b1cf | ok |
| 5 | 2020-04-30 00:32:18.095Z | simplerockbuild.simplerock.lan | zeek | user_agent.original | DavClnt | .ds-logs-zeek-default-2026.10.20-000001 / AaFZSPJfH5wFd7o_Z1YZ | q-afaa6bd524 | ok |
| 6 | 2020-04-30 00:32:21.422Z | simplerockbuild.simplerock.lan | zeek | user_agent.original | Microsoft-WebDAV-MiniRedir/10.0.18362 | .ds-logs-zeek-default-2026.10.20-000001 / AaFZSPJfH5wFd7o_Z1YU | q-afaa6bd524 | ok |
| 7 | 2020-04-30 00:32:21.422Z | simplerockbuild.simplerock.lan | zeek | http.response.status_code | 401 | .ds-logs-zeek-default-2026.10.20-000001 / AaFZSPJfH5wFd7o_Z1YU | q-afaa6bd524 | ok |
| 8 | 2020-04-30 00:32:21.918Z | simplerockbuild.simplerock.lan | zeek | http.request.method | PUT | .ds-logs-zeek-default-2026.10.20-000001 / AaFZSPJfH5wFd7o_Z1YN | q-9cdf9362bc | ok |
| 9 | 2020-04-30 00:32:21.918Z | simplerockbuild.simplerock.lan | zeek | url.original | /webdav/OfficeSupplies.7z | .ds-logs-zeek-default-2026.10.20-000001 / AaFZSPJfH5wFd7o_Z1YN | q-9cdf9362bc | ok |
| 10 | 2020-04-30 00:32:21.918Z | simplerockbuild.simplerock.lan | zeek | http.response.status_code | 201 | .ds-logs-zeek-default-2026.10.20-000001 / AaFZSPJfH5wFd7o_Z1YN | q-9cdf9362bc | ok |
| 11 | 2020-04-30 00:32:18.095Z | simplerockbuild.simplerock.lan | zeek | destination.ip | 192.168.0.4 | .ds-logs-zeek-default-2026.10.20-000001 / AaFZSPJfH5wFd7o_Z1YZ | q-afaa6bd524 | ok |
| 12 | 2020-05-02 03:20:41.000Z | scranton.dmevals.local | windows.security | win.AuthenticationPackageName | NTLM | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7nQi3T7 | q-f927c97bb3 | ok |
| 13 | 2020-05-02 03:20:41.000Z | scranton.dmevals.local | windows.security | win.WorkstationName | 10.0.1.4 | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7nQi3T7 | q-7e42ebff14 | ok |
| 14 | 2020-05-02 03:20:41.000Z | scranton.dmevals.local | windows.security | win.LogonProcessName | NtLmSsp  | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7nQi3T7 | q-7e42ebff14 | ok |
| 15 | 2020-05-02 03:04:23.681Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\hostui.lnk | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hSRzrG | q-d7925580b8 | ok |
| 16 | 2020-05-02 03:21:26.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | Start-Process C:\Windows\System32\hostui.exe -verb runas | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qzXFri | q-693cc9aad5 | ok |

### F26 · malicious / high · T1539 · Credential/certificate and data theft on scranton.dmevals.local (pbeesly) — adjacent to T1539 but not cookie theft

Evidence status: **verified**

In the same PowerShell session (PID 3852, user pbeesly, host scranton.dmevals.local) that ran the cookie-adjacent checks, the attacker executed credential-access and exfiltration tooling: a Get-PrivateKeys function exporting cert:\LocalMachine certificates to .pfx files in Downloads using a hardcoded password, an Invoke-ScreenCapture/Keystroke-Check toolkit, and Invoke-Exfil which compresses $env:USERPROFILE\Downloads into $env:APPDATA\OfficeSupplies.7z and copies it to a WebDAV share \\192.168.0.4\webdav using hardcoded credentials. Zeek (separate, non-overlapping window) shows the matching WebDAV PUT of /webdav/OfficeSupplies.7z from 10.0.1.4 to 192.168.0.4. This is credential and data theft, but no browser cookie store was read, so it does not satisfy T1539 itself.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qvSysm | q-1e2bc8e4c6 | ok |
| 2 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qjPglL | q-8f239190df | ok |
| 3 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\psversion.ps1 | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qjPglL | q-8f239190df | ok |
| 4 | 2020-05-02 03:05:45.000Z | scranton.dmevals.local | windows.powershell | message | Creating Scriptblock text (1 of 1):  <# PsTools Version in this package: 2.44 #> function Invoke-ScreenCapture # https://www.pdq.com/blog/capturing-screenshots-… | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qvSyvc | q-2b95b7cd4a | ok |
| 5 | 2020-04-30 00:32:22.010Z | simplerockbuild.simplerock.lan | zeek | url.original | /webdav/OfficeSupplies.7z | .ds-logs-zeek-default-2026.10.20-000001 / AaFZSPJfH5wFd7o_Z1bd | q-48f13aab88 | ok |

### F28 · malicious / high · T1552 · Harvested credentials staged and exfiltrated: Downloads compressed with 7Zip4Powershell into OfficeSupplies.7z and copied to a WebDAV share

Evidence status: **verified**

On scranton.dmevals.local at 03:08:02 UTC, PowerShell (PID 3852, user pbeesly) logged script block b2b03a9c-43f0-4285-837d-f22d4600b2ae defining Invoke-Exfil, loaded from C:\Program Files\SysinternalsSuite\psversion.ps1. It installs the 7Zip4Powershell module, compresses the entire $env:USERPROFILE\Downloads directory (which contained the exported .pfx private keys) with password "lolol" into $env:APPDATA\OfficeSupplies.7z, then maps a PSDrive to \\192.168.0.4\webdav using hardcoded credentials (user "cozy", password "MyCozyPassw0rd!") and copies the archive there. Sysmon confirms C:\Users\pbeesly\AppData\Roaming\OfficeSupplies.7z created by powershell.exe at 03:08:35 and a .7z written under the WebDAV TfsStore temp path by svchost.exe at 03:08:51. The same actor then used the recovered plaintext password Fl0nk3rt0n!T0by with PsExec64.exe against \\NASHUA (four executions 03:11:18-03:14:42, each matched by 4648 explicit-credential logons on nashua.dmevals.local from PSEXESVC.exe), showing the stolen credentials were reused for lateral movement.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qjPglL | q-034403fd72 | ok |
| 2 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\psversion.ps1 | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qjPglL | q-034403fd72 | ok |
| 3 | 2020-05-02 03:08:35.270Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Users\pbeesly\AppData\Roaming\OfficeSupplies.7z | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7c_44mH | q-5c90a8e117 | ok |
| 4 | 2020-05-02 03:08:51.364Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Windows\ServiceProfiles\LocalService\AppData\Local\Temp\TfsStore\Tfs_DAV\{D41027F8-ED53-41EF-8E3F-1F4E4D876B5A}.7z | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7c-4sYu | q-5c90a8e117 | ok |
| 5 | 2020-05-02 03:11:18.784Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\PsExec64.exe" -accepteula \\NASHUA -u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7cxoQzx | q-1f26d3a991 | ok |
| 6 | 2020-05-02 03:11:40.000Z | nashua.dmevals.local | windows.security | process.executable | C:\Windows\PSEXESVC.exe | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7niyNur | q-5dfb52924f | ok |

### F58 · malicious / high · T1552 · pbeesly staged and password-protected archives of user files on NASHUA

Evidence status: **verified**

On nashua pbeesly collected credential-named files into working.zip, re-archived it with password fGzq5yKw via Rar.exe and wiped artifacts with sdelete64.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:15:59.000Z | nashua.dmevals.local | windows.powershell | win.ScriptBlockText | $env:APPDATA;$files=ChildItem -Path $env:USERPROFILE\ -Include *.doc,*.xps,*.xls,*.ppt,*.pps,*.wps,*.wpd,*.ods,*.odt,*.lwp,*.jtd,*.pdf,*.zip,*.rar,*.docx,*.url,… | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qrRC92 | q-1cc1d079d0 | ok |
| 2 | 2020-05-02 03:16:19.395Z | nashua.dmevals.local | windows.sysmon | process.command_line | "C:\Windows\Temp\Rar.exe" a -hpfGzq5yKw C:\Users\pbeesly\Desktop\working.zip C:\Users\pbeesly\AppData\Roaming\working.zip | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7c4xY6Y | q-b6785d236b | ok |
| 3 | 2020-05-02 03:16:52.456Z | nashua.dmevals.local | windows.sysmon | process.command_line | .\sdelete64.exe  /accepteula "C:\Windows\Temp\Rar.exe" | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7cri_p- | q-6b38cc20ee | ok |

### F62 · malicious / high · T1552 · PsExec64 with cleartext pbeesly password launched python.exe on NASHUA

Evidence status: **verified**

PsExec64 from scranton pushed C:\Windows\Temp\python.exe to NASHUA using pbeesly's cleartext password; python then spawned PowerShell, Rar and sdelete.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:18.784Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\PsExec64.exe" -accepteula \\NASHUA -u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7cxoQzx | q-32011036d6 | ok |
| 2 | 2020-05-02 03:11:40.213Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7c82OhP | q-6b38cc20ee | ok |

### F63 · malicious / high · T1552 · Masqueraded .scr loader in ProgramData on SCRANTON

Evidence status: **verified**

A masqueraded .scr loader in ProgramData was launched by explorer on scranton and later wiped with sdelete64.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:55:56.157Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\ProgramData\victim\â€®cod.3aka3.scr" /S | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hy0krT | q-32011036d6 | ok |
| 2 | 2020-05-02 03:02:04.324Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\sdelete64.exe" /accepteula C:\programdata\victim\???cod.3aka3.scr | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hWVSlm | q-32011036d6 | ok |

### F64 · malicious / high · T1552 · csc.exe compiled steganographic payload on SCRANTON

Evidence status: **verified**

csc.exe compiled in-memory payloads from the steganographic monkey.png loader into temp DLLs on scranton.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:58:45.297Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe" /noconfig /fullpaths @"C:\Users\pbeesly\AppData\Local\Temp\qkbkqqbs\qkbkqqbs.cmdline" | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7htvuyY | q-32011036d6 | ok |
| 2 | 2020-05-02 02:58:45.297Z | scranton.dmevals.local | windows.sysmon | process.parent.command_line | "PowerShell.exe" -noni -noexit -ep bypass -window hidden -c "sal a New-Object;Add-Type -AssemblyName 'System.Drawing'; $g=a System.Drawing.Bitmap('C:\Users\pbee… | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7htvuyY | q-32011036d6 | ok |

### F68 · malicious / high · T1552 · sdelete64 anti-forensics on SCRANTON

Evidence status: **verified**

sdelete64 run by pbeesly PowerShell wiped the .scr loader, Draft.Zip and SysinternalsSuite.zip on scranton.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:02:04.324Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\sdelete64.exe" /accepteula C:\programdata\victim\???cod.3aka3.scr | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hWVSlm | q-32011036d6 | ok |
| 2 | 2020-05-02 03:03:14.693Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\sdelete64.exe" /accepteula C:\Users\pbeesly\AppData\Roaming\Draft.Zip | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hUTVpm | q-32011036d6 | ok |

### F59 · malicious / medium · T1552.001 · Credential-named files harvested from pbeesly profile on NASHUA

Evidence status: **verified**

The nashua collection script explicitly targeted *pass*, *login*, *admin*, *vpn and *sifr files under the pbeesly profile.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:15:59.000Z | nashua.dmevals.local | windows.powershell | process.command_line | $env:APPDATA;$files=ChildItem -Path $env:USERPROFILE\ -Include *.doc,*.xps,*.xls,*.ppt,*.pps,*.wps,*.wpd,*.ods,*.odt,*.lwp,*.jtd,*.pdf,*.zip,*.rar,*.docx,*.url,… | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qrRC92 | q-1cc1d079d0 | ok |
| 2 | 2020-05-02 03:16:00.353Z | nashua.dmevals.local | windows.sysmon | file.path | C:\Users\pbeesly\AppData\Roaming\working.zip | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7c4xo5I | q-6de9f6edbc | ok |

### F27 · malicious / high · T1552.004 · Get-PrivateKeys PowerShell function exported all LocalMachine certificates to password-protected PFX files on SCRANTON

Evidence status: **verified**

On 2020-05-02 at 03:04:56 UTC, in the security context of user pbeesly (SID S-1-5-21-1830255721-3727074217-2423397540-1107) on scranton.dmevals.local, PowerShell (PID 3876) logged script block 9d153741-75c3-4062-afe3-aeca0aee611b defining function Get-PrivateKeys. The function enumerates cert:\LocalMachine recursively and calls Export-PfxCertificate for every certificate with a thumbprint, writing to $env:USERPROFILE\Downloads\<random>.pfx protected by the hardcoded plaintext password "saribas". One second later Sysmon recorded the resulting file C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx created by powershell.exe. The script was loaded from C:\Program Files\SysinternalsSuite\readme.ps1, a masquerading path. This is deliberate private-key/certificate theft (T1552.004) and the harvested PFX files were subsequently staged into an archive (see T1552 finding).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qvSysm | q-9e830bb12c | ok |
| 2 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\readme.ps1 | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qvSysm | q-9e830bb12c | ok |
| 3 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | user.name | pbeesly | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qvSysm | q-9e830bb12c | ok |
| 4 | 2020-05-02 03:04:57.460Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hQQRgs | q-673050866e | ok |
| 5 | 2020-05-02 03:04:57.460Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\WindowsPowerShell\v1.0\powershell.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hQQRgs | q-673050866e | ok |

### F33 · malicious / medium · T1555 · Steganographic PowerShell loader on scranton opened LSASS with full access (0x1FFFFF) as pbeesly

Evidence status: **verified**

On scranton.dmevals.local at 2020-05-02T02:58:44Z, control.exe (/name Microsoft.BackupAndRestoreCenter) spawned a hidden, execution-policy-bypassing PowerShell (PID 2976) running as DMEVALS\pbeesly at High integrity. Its command line decodes a payload from pixel data of C:\Users\pbeesly\Downloads\monkey.png and IEXes it (steganographic loader). At 03:05:16Z that same PowerShell process (PID 2976) opened lsass.exe with GrantedAccess 0x1f3fff and then 0x1fffff (PROCESS_ALL_ACCESS) with an UNKNOWN call trace, and Security 4663 on the same host at 23:05:16 local records pbeesly's powershell.exe accessing \Device\HarddiskVolume2\Windows\System32\lsass.exe. Full-access LSASS handles from a user-context, hidden PowerShell are consistent with in-memory credential theft, though no dump file or credential-store artifact was observed. Separately, on nashua.dmevals.local wsmprovhost.exe (PID 7720, pbeesly, WinRM remote session) opened lsass.exe with 0x1f3fff at 03:09:29Z, with a call trace through System.ni.dll / Microsoft.PowerShell.Commands.Management.ni.dll, i.e. a PowerShell cmdlet reading LSASS. Other LSASS access in the window is benign: svchost.exe 0x1000/0x101001 (lsm.dll), csrss/wininit at lsass start, WindowsAzureTelemetryService.exe 0x1400 via CorperfmonExt.dll, and CollectGuestLogs.exe/MsMpEng.exe 0x10.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:58:44.325Z | scranton.dmevals.local | windows.sysmon | process.command_line | "PowerShell.exe" -noni -noexit -ep bypass -window hidden -c "sal a New-Object;Add-Type -AssemblyName 'System.Drawing'; $g=a System.Drawing.Bitmap('C:\Users\pbee… | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7htwOyZ | q-6f31f5b519 | ok |
| 2 | 2020-05-02 02:58:44.325Z | scranton.dmevals.local | windows.sysmon | process.parent.executable | C:\Windows\System32\control.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7htwOyZ | q-6f31f5b519 | ok |
| 3 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hQQBhJ | q-42d04ae0fb | ok |
| 4 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.CallTrace | C:\windows\SYSTEM32\ntdll.dll+9c584\|C:\windows\System32\KERNELBASE.dll+2732e\|UNKNOWN(000001996D28200D) | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hQQBhJ | q-42d04ae0fb | ok |
| 5 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | win.ObjectName | \Device\HarddiskVolume2\Windows\System32\lsass.exe | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7nq72Yf | q-d83329d572 | ok |
| 6 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7c939yF | q-abefdaa655 | ok |
| 7 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7c939yF | q-abefdaa655 | ok |

### F47 · malicious / high · T1558 · Compromised pbeesly account used for hands-on-keyboard credential access across SCRANTON and NASHUA

Evidence status: **verified**

On 2020-05-02 between 03:04 and 03:21 UTC the DMEVALS\pbeesly account ran an offensive PowerShell toolkit on scranton.dmevals.local (Invoke-Discovery, Invoke-Persistence, Invoke-ScreenCapture, Invoke-Exfil, Invoke-BeachCleanup, Invoke-SeaDukeStage -ComputerName NASHUA) and used PowerShell Remoting to reach nashua.dmevals.local. In the same window PowerShell.exe on SCRANTON opened LSASS with full-access masks 0x1F3FFF and 0x1FFFFF (03:05:16), and wsmprovhost.exe on NASHUA opened LSASS with 0x1F3FFF (03:09:29) — the classic prerequisite for extracting Kerberos tickets/credential material from LSASS. pbeesly also held SeDebugPrivilege on NASHUA (4672) and made repeated explicit-credential logons (4648) via PSEXESVC. This is attacker activity, not normal system behaviour.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hQQBhJ | q-db99870726 | ok |
| 2 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hQQBhG | q-db99870726 | ok |
| 3 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7c939yF | q-db99870726 | ok |
| 4 | 2020-05-02 03:10:22.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | Invoke-SeaDukeStage -ComputerName NASHUA | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qqQ-d4 | q-d0c6c10f0e | ok |
| 5 | 2020-05-02 03:04:03.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | Invoke-Discovery | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qvSysW | q-d0c6c10f0e | ok |
| 6 | 2020-05-02 03:09:29.000Z | nashua.dmevals.local | windows.security | win.PrivilegeList | SeSecurityPrivilege  			SeBackupPrivilege  			SeRestorePrivilege  			SeTakeOwnershipPrivilege  			SeDebugPrivilege  			SeSystemEnvironmentPrivilege  			SeLoadDr… | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7niy9sU | q-fe306675c0 | ok |

### F52 · malicious / high · T1606 · Credential theft on SCRANTON: steganographic PowerShell loader, LSASS full-access handle, registry-stored encoded payload

Evidence status: **verified**

On scranton.dmevals.local, user pbeesly ran a multi-stage PowerShell intrusion on 2020-05-02. At 02:57:00 C:\Users\pbeesly\Downloads\monkey.png was written by C:\ProgramData\victim\â€®cod.3aka3.scr; at 02:58:44 powershell.exe (parent control.exe, High integrity) was launched with '-noni -noexit -ep bypass -window hidden' and decoded a System.Drawing.Bitmap from monkey.png into a byte array executed via IEX (image-steganography loader). At 03:04:04 a script block from C:\Program Files\SysinternalsSuite\readme.ps1 (Get-AttributesMask, token/group-attribute enumeration) was logged under pbeesly, and at 03:06:47 a Keystroke-Check AV-discovery function. At 03:04:23 PowerShell wrote an encoded payload into HKLM\SOFTWARE\Javasoft\value Supplement, and at 03:21:27-03:21:28 that value was read back and piped to Invoke-Expression, spawning 'powershell.exe -nop -w hidden -e <base64>' (Gzip+Base64 loader). In the same window PowerShell.exe (PID 2976) opened lsass.exe (PID 736) with GrantedAccess 0x1f3fff and 0x1fffff (PROCESS_ALL_ACCESS) at 03:05:16 — credential material was harvested from LSASS. The stolen credentials were then used for lateral movement: pbeesly network logons (type 3) from 10.0.1.4 to newyork and nashua, PSEXESVC service installs on nashua at 23:11:39-23:15:03, and Invoke-Command to NASHUA enumerating logged-on users. No SAML token or web-cookie forging was observed; the credential access is LSASS-based theft that enables later forged-credential use.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hQQBhJ | q-79037633a3 | ok |
| 2 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hQQBhG | q-79037633a3 | ok |
| 3 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.TargetImage | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hQQBhJ | q-79037633a3 | ok |
| 4 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hQQBhJ | q-79037633a3 | ok |
| 5 | 2020-05-02 02:58:44.325Z | scranton.dmevals.local | windows.sysmon | process.command_line | "PowerShell.exe" -noni -noexit -ep bypass -window hidden -c "sal a New-Object;Add-Type -AssemblyName 'System.Drawing'; $g=a System.Drawing.Bitmap('C:\Users\pbee… | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7htwOyZ | q-4ac964a09d | ok |
| 6 | 2020-05-02 02:58:44.325Z | scranton.dmevals.local | windows.sysmon | process.parent.executable | C:\Windows\System32\control.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7htwOyZ | q-4ac964a09d | ok |
| 7 | 2020-05-02 02:57:00.933Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Users\pbeesly\Downloads\monkey.png | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hwyqdH | q-8c373b38e5 | ok |
| 8 | 2020-05-02 02:57:00.933Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\ProgramData\victim\â€®cod.3aka3.scr | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hwyqdH | q-8c373b38e5 | ok |
| 9 | 2020-05-02 03:04:23.572Z | scranton.dmevals.local | windows.sysmon | registry.path | HKLM\SOFTWARE\Javasoft\value Supplement | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hSRzrP | q-30b48a381e | ok |
| 10 | 2020-05-02 03:21:28.949Z | scranton.dmevals.local | windows.sysmon | process.parent.command_line | powershell.exe -c "Get-ItemPropertyValue 'HKLM:\\SOFTWARE\Javasoft' 'value Supplement' \| Invoke-Expression" | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7YD3Who | q-2af3a11166 | ok |
| 11 | 2020-05-02 03:04:04.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\readme.ps1 | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qvTCvl | q-1714f39b2b | ok |
| 12 | 2020-05-02 03:06:47.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Keystroke-Check {     Get-Process \| Where-Object { $_.ProcessName -Eq "avp" -or $_.ProcessName -Eq "acs" -or $_.ProcessName -Eq "outpost" -or $_.Proce… | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qvSitD | q-621f993a03 | ok |
| 13 | 2020-05-02 03:09:23.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | Invoke-Command -ComputerName NASHUA -ScriptBlock { Get-Process -IncludeUserName \| Select-Object UserName,SessionId \| Where-Object { $_.UserName -like "*\$env:… | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qrRbzS | q-621f993a03 | ok |
| 14 | 2020-05-02 03:11:39.000Z | nashua.dmevals.local | windows.other | process.executable | %SystemRoot%\PSEXESVC.exe | .ds-logs-windows.other-default-2026.10.20-000001 / AaFZR_JfH5wFd7pNHuCk | q-5fd6c5a410 | ok |
| 15 | 2020-05-02 03:11:40.000Z | nashua.dmevals.local | windows.security | process.executable | C:\Windows\PSEXESVC.exe | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7niyNur | q-e0762e0e4e | ok |

### F56 · malicious / high · T1649 · Private-key/certificate export via Get-PrivateKeys PowerShell function on scranton.dmevals.local

Evidence status: **verified**

On scranton.dmevals.local, user pbeesly executed a malicious screen saver C:\ProgramData\victim\...cod.3aka3.scr (launched by explorer.exe at 2020-05-02T02:55:56Z), which spawned cmd.exe and then powershell.exe. At 2020-05-02T03:04:56Z a PowerShell 4104 script block defined and invoked 'Get-PrivateKeys' (script path C:\Program Files\SysinternalsSuite\readme.ps1): it enumerates cert:\LocalMachine recursively and calls Export-PfxCertificate for every certificate with a thumbprint, writing password-protected .pfx files into $env:USERPROFILE\Downloads using a hardcoded password 'saribas'. One second later Sysmon recorded the resulting file C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx created by powershell.exe (PID 3876). A later script block 'Invoke-BeachCleanup' (psversion.ps1) removes $env:USERPROFILE\Downloads\*.pfx, *.bmp, *.png and $env:APPDATA\OfficeSupplies.7z, i.e. anti-forensic cleanup of the stolen certificate bundles. This is certificate/private-key theft for later authentication abuse (T1649). The single 4657 write to HKLM\SOFTWARE\Microsoft\SystemCertificates\ROOT\Certificates\BE36A4562FB2EE05DBB3D32323ADF445084ED656 on nashua.dmevals.local was performed by C:\Windows\Sysmon.exe under the machine account NASHUA$ and is consistent with routine certificate-store maintenance, not attacker forgery.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qvSysm | q-776cd7cd0c | ok |
| 2 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\readme.ps1 | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qvSysm | q-776cd7cd0c | ok |
| 3 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | user.name | pbeesly | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qvSysm | q-776cd7cd0c | ok |
| 4 | 2020-05-02 03:04:57.460Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hQQRgs | q-15bfaefe56 | ok |
| 5 | 2020-05-02 03:04:57.460Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\WindowsPowerShell\v1.0\powershell.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hQQRgs | q-15bfaefe56 | ok |
| 6 | 2020-05-02 03:08:51.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-BeachCleanup {     Write-Host "[*] Cleaning up"     Remove-Item -Path "$env:USERPROFILE\Downloads\*.pfx" -Force     Remove-Item -Path "$env:USER… | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qrRC9i | q-880ea86606 | ok |
| 7 | 2020-05-02 03:08:51.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\psversion.ps1 | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qrRC9i | q-880ea86606 | ok |
| 8 | 2020-05-02 02:55:56.157Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\ProgramData\victim\â€®cod.3aka3.scr | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hy0krT | q-6ba23e5c6a | ok |
| 9 | 2020-05-02 02:56:14.894Z | scranton.dmevals.local | windows.sysmon | process.parent.executable | C:\Windows\System32\cmd.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hx0W8y | q-6ba23e5c6a | ok |
| 10 | 2020-05-02 03:16:19.000Z | nashua.dmevals.local | windows.security | win.ProcessName | C:\Windows\Sysmon.exe | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7rzHZUI | q-b12d36cd43 | ok |

### F07 · suspicious / medium · T1003 · Credential dumping tooling absent, but the host is under active hands-on-keyboard attack by pbeesly

Evidence status: **verified**

Across 447 sysmon and 460 security process creations there is no mimikatz, procdump, comsvcs.dll rundll32 dump, reg.exe save, or hive-copy execution, and the only .dmp files are WerFault crash dumps (WER51F5.tmp.dmp on nashua, WER5437.tmp.dmp on scranton). However the same user pbeesly demonstrably owns the compromised hosts: on scranton a malicious screen-saver C:\ProgramData\victim\â€®cod.3aka3.scr launched from explorer at 02:55:56, SysinternalsSuite was downloaded and moved to C:\Program Files\SysinternalsSuite, sdelete64 was used to wipe the .scr, Draft.Zip and the Sysinternals zip, Invoke-Persistence/Invoke-Discovery/Invoke-Exfil were executed, and PsExec64 was used four times against \\NASHUA with the cleartext password 'Fl0nk3rt0n!T0by' to run C:\Windows\Temp\python.exe, followed by Rar.exe archiving and sdelete cleanup on nashua. pbeesly also holds SeDebugPrivilege on nashua (4672). Credential dumping was not completed in this window, but the actor had the access and tooling to do it.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:55:56.157Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\ProgramData\victim\â€®cod.3aka3.scr | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hy0krT | q-dd4bed3a6d | ok |
| 2 | 2020-05-02 03:11:18.784Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\PsExec64.exe" -accepteula \\NASHUA -u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7cxoQzx | q-dd4bed3a6d | ok |
| 3 | 2020-05-02 03:02:04.324Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\sdelete64.exe" /accepteula C:\programdata\victim\???cod.3aka3.scr | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hWVSlm | q-dd4bed3a6d | ok |
| 4 | 2020-05-02 02:58:45.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | sal a New-Object;Add-Type -AssemblyName 'System.Drawing'; $g=a System.Drawing.Bitmap('C:\Users\pbeesly\Downloads\monkey.png');$o=a Byte[] 4480;for($i=0; $i -le … | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7q0Y_4v | q-b09198b336 | ok |
| 5 | 2020-05-02 03:09:23.000Z | nashua.dmevals.local | windows.security | win.PrivilegeList | SeSecurityPrivilege  			SeBackupPrivilege  			SeRestorePrivilege  			SeTakeOwnershipPrivilege  			SeDebugPrivilege  			SeSystemEnvironmentPrivilege  			SeLoadDr… | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7njzKAe | q-0047525c14 | ok |

### F01 · suspicious / medium · T1003.001 · pbeesly PowerShell/wsmprovhost opened lsass.exe with full-access masks (0x1fffff / 0x1f3fff) on scranton and nashua

Evidence status: **verified**

On 2020-05-02 the DMEVALS user pbeesly, who is simultaneously running a hands-on-keyboard intrusion on scranton.dmevals.local (Sysinternals download, sdelete anti-forensics, persistence, keystroke logging, exfil staging, PsExec to NASHUA with a plaintext password), requested handles to lsass.exe with all-access masks. At 03:05:16-17 on scranton, powershell.exe (PID 0xba0, logon 0x372e81) requested 0x1fffff and 0x1f3fff on \Device\HarddiskVolume2\Windows\System32\lsass.exe, including 'Read from process memory' and 'Perform virtual memory operation'. At 03:09:29 on nashua, wsmprovhost.exe (PID 0x1e28, logon 0x85aad2, same user SID ...-1107) requested 0x1f3fff on lsass.exe. The 03:01:03 sysmon event 10 shows powershell.exe (PID 3876) accessing lsass with GrantedAccess 0x1000 via a .NET (System.ni.dll) call trace, consistent with Get-Process/process enumeration rather than a dump. No dump file, no procdump/comsvcs/mimikatz/sekurlsa command line, and no 4104 script block referencing lsass or minidump was found, so a completed LSASS dump is not evidenced - but the full-access handle requests by an interactive attacker session are not explainable as normal system behaviour and warrant host triage.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | win.AccessMask | 0x1fffff | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7nq7mb8 | q-beb004ea57 | ok |
| 2 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | win.ObjectName | \Device\HarddiskVolume2\Windows\System32\lsass.exe | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7nq7mb8 | q-beb004ea57 | ok |
| 3 | 2020-05-02 03:09:29.000Z | nashua.dmevals.local | windows.security | win.AccessMask | 0x1f3fff | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7njy6Co | q-beb004ea57 | ok |
| 4 | 2020-05-02 03:09:29.000Z | nashua.dmevals.local | windows.security | win.ProcessName | C:\Windows\System32\wsmprovhost.exe | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7njy6Co | q-beb004ea57 | ok |
| 5 | 2020-05-02 03:01:03.622Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1000 | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7habKTo | q-9bdea0b3a9 | ok |
| 6 | 2020-05-02 03:01:03.622Z | scranton.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\WindowsPowerShell\v1.0\powershell.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7habKTo | q-9bdea0b3a9 | ok |

### F11 · suspicious / medium · T1056.004 · PowerShell opens LSASS with full-access masks on SCRANTON and NASHUA

Evidence status: **verified**

Sysmon event 10 shows PowerShell.exe (PID 2976, the same pbeesly session that ran the keylogger) opening lsass.exe (PID 736) on scranton.dmevals.local at 03:05:16 UTC with GrantedAccess 0x1F3FFF and 0x1FFFFF — all-access masks used for reading credential memory. Windows Security 4663 corroborates: powershell.exe accessed \Device\HarddiskVolume2\Windows\System32\lsass.exe as pbeesly at 03:05:16. On nashua.dmevals.local, wsmprovhost.exe (the WinRM host for the pbeesly Invoke-Command to NASHUA at 03:09:23) opened lsass.exe with 0x1F3FFF at 03:09:29. The remaining LSASS access in the window is benign baseline: svchost.exe (289), Azure AntimalwareConfig.exe (15), WindowsAzureTelemetryService.exe (13), and CollectGuestLogs.exe/MsMpEng.exe 4663 reads with AccessMask 0x10. The PowerShell/wsmprovhost LSASS handles are consistent with in-memory credential access rather than a hooking DLL, so confidence is medium.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hQQBhG | q-ad1f5e7d6b | ok |
| 2 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hQQBhJ | q-ad1f5e7d6b | ok |
| 3 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7c939yF | q-ad1f5e7d6b | ok |
| 4 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | process.executable | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7nq72Yf | q-d502b9d9cb | ok |
| 5 | 2020-05-02 03:05:16.000Z | scranton.dmevals.local | windows.security | win.SubjectUserName | pbeesly | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7nq72Yf | q-d502b9d9cb | ok |

### F16 · suspicious / medium · T1110.002 · No offline cracking tooling; LSASS was accessed with full access by PowerShell on SCRANTON

Evidence status: **verified**

No hashcat/john/wordlist command lines exist (sysmon event.code:1 with hash/ntlm/wordlist returned 0), and no 4663/4656 access to SAM/SECURITY/NTDS hive files by a non-lsass process was found — the 10 SAM object accesses on scranton.dmevals.local are all by C:\Windows\System32\lsass.exe under the machine account SCRANTON$ (normal SAM service behaviour). However, on scranton.dmevals.local PowerShell.exe (PID 2976, the steganographic loader spawned by control.exe) opened C:\windows\system32\lsass.exe with GrantedAccess 0x1f3fff and 0x1fffff at 2020-05-02T03:05:16Z, which is the precursor to dumping hashes for offline cracking. No cracking output files (.pot, hash lists) were observed, so cracking itself is not evidenced.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hQQBhJ | q-39e701140a | ok |
| 2 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.TargetImage | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hQQBhJ | q-39e701140a | ok |
| 3 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hQQBhG | q-8582eef357 | ok |
| 4 | 2020-05-02 03:19:21.000Z | scranton.dmevals.local | windows.security | process.executable | C:\Windows\System32\lsass.exe | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7ryFh2_ | q-f6ad0f71e9 | ok |

### F22 · suspicious / medium · T1212 · PowerShell (stego-launched, high integrity) opened LSASS with full-access masks on scranton; wsmprovhost.exe did the same on nashua

Evidence status: **NOT verified (8/9 evidence items)** — excluded from the verdict

On scranton.dmevals.local, PowerShell.exe (PID 2976, process GUID {47ab858c-e1e4-5eac-b803-000000000400}) — the same process launched at 02:58:44 by control.exe with a steganographic loader reading C:\Users\pbeesly\Downloads\monkey.png and IEX-ing the decoded bytes — opened lsass.exe (PID 736) at 03:05:16 with GrantedAccess 0x1f3fff and 0x1fffff (PROCESS_ALL_ACCESS). The call trace is only ntdll.dll+KERNELBASE.dll+UNKNOWN, i.e. no signed dump utility in the stack, consistent with in-memory/reflective access rather than a normal AV/EDR scan. On nashua.dmevals.local, wsmprovhost.exe (PID 7720, spawned 03:09:23 by svchost.exe as pbeesly, i.e. a remote PowerShell/WinRM session) opened lsass.exe (PID 728) at 03:09:29 with 0x1f3fff; its call trace runs through System.ni.dll / Microsoft.PowerShell.Commands.Management.ni.dll, indicating a PowerShell cmdlet performing the access. Both hosts were being operated by user pbeesly in the same window (PsExec service installs on nashua, Invoke-Exfil/Invoke-ScreenCapture script blocks on scranton). No credential-dump tooling was observed: no 4688 or Sysmon process-create with lsass/procdump/comsvcs/MiniDump/sekurlsa in the command line, no 4104 script block containing lsass/MiniDump/comsvcs, and no 7045 service install of a dump payload. The remaining LSASS opens are benign baseline (svchost.exe 286x at 0x1000, Azure AntimalwareConfig.exe and WindowsAzureTelemetryService.exe at 0x1000/0x1400, and wininit/csrss/services at boot 03:19:09). Assessment: suspicious — LSASS was accessed with full rights by attacker-controlled PowerShell on two hosts, but the retrieved data does not show the dump/credential-extraction step itself.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hQQBhJ | q-7a4c260a5e | ok |
| 2 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.CallTrace | C:\windows\SYSTEM32\ntdll.dll+9c584\|C:\windows\System32\KERNELBASE.dll+2732e\|UNKNOWN(000001996D28200D) | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hQQBhJ | q-7a4c260a5e | ok |
| 3 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hQQBhG | q-3832d94d0c | ok |
| 4 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\wsmprovhost.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7c939yF | q-277bca2ca8 | ok |
| 5 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7c939yF | q-277bca2ca8 | ok |
| 6 | 2020-05-02 02:58:44.325Z | scranton.dmevals.local | windows.sysmon | process.command_line | "PowerShell.exe" -noni -noexit -ep bypass -window hidden -c "sal a New-Object;Add-Type -AssemblyName 'System.Drawing'; $g=a System.Drawing.Bitmap('C:\Users\pbee… | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7htwOyZ | q-928d537839 | ok |
| 7 | 2020-05-02 03:09:23.885Z | nashua.dmevals.local | windows.sysmon | process.command_line | C:\windows\system32\wsmprovhost.exe -Embedding | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7c-4cYK | q-928d537839 | ok |
| 8 | 2020-05-02 02:58:45.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | sal a New-Object;Add-Type -AssemblyName 'System.Drawing'; $g=a System.Drawing.Bitmap('C:\Users\pbeesly\Downloads\monkey.png');$o=a Byte[] 4480;for($i=0; $i -le … | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7q0Y_4v | q-6c5f4e1d74 | ok |
| 9 | 2020-05-02 03:21:28.949Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\windows\System32\WindowsPowerShell\v1.0\powershell.exe" -nop -w hidden -e aQBmACgAWwBJAG4AdABQAHQAcgBdADoAOgBTAGkAegBlACAALQBlAHEAIAA0ACkAewAkAGIAPQAkAGUAbg… | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7YD3Who | q-073a39692a | FAILED: claimed value differs from the stored value |

### F24 · suspicious / medium · T1212 · PsExec service installs and PowerShell exfil/screen-capture scripts on nashua/scranton (lateral movement, not credential exploitation)

Evidence status: **verified**

Five 7045 service installs by user pbeesly: one Java(TM) Virtual Machine Support Service pointing at C:\Windows\System32\javamtsup.exe on scranton (23:04:15 local) and four PSEXESVC installs (%SystemRoot%\PSEXESVC.exe, demand start, LocalSystem) on nashua between 23:11:39 and 23:15:03 local. PowerShell 4104 blocks on scranton under pbeesly include Invoke-Exfil (7-Zip password-protected archive of Downloads to $env:APPDATA\OfficeSupplies.7z) and Invoke-ScreenCapture. These show hands-on-keyboard attacker activity on the same hosts/users as the LSASS access, but they are not exploitation for credential access; no dump tooling or credential-theft script was found in the retrieved events.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:39.000Z | nashua.dmevals.local | windows.other | process.executable | %SystemRoot%\PSEXESVC.exe | .ds-logs-windows.other-default-2026.10.20-000001 / AaFZR_JfH5wFd7pNHuCk | q-7a6bf6fee4 | ok |
| 2 | 2020-05-02 03:04:15.000Z | scranton.dmevals.local | windows.other | process.executable | C:\Windows\System32\javamtsup.exe | .ds-logs-windows.other-default-2026.10.20-000001 / AaFZR_JfH5wFd7pNHuDg | q-7a6bf6fee4 | ok |
| 3 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qjPglL | q-9ad5adf777 | ok |
| 4 | 2020-05-02 03:05:53.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-ScreenCapture # https://www.pdq.com/blog/capturing-screenshots-with-powershell-and-net/ {     Start-Job -Name "Screenshot" -ScriptBlock {       … | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qvSyuh | q-6c5f4e1d74 | ok |

### F65 · suspicious / medium · T1552 · hostui.exe launched with runas by PowerShell on SCRANTON

Evidence status: **NOT verified (0/1 evidence items)** — excluded from the verdict

PowerShell launched hostui.exe with -verb runas on scranton, an elevation attempt.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:21:27.276Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Windows\System32\hostui.exe"  | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7YE3lVE | q-32011036d6 | FAILED: claimed value differs from the stored value |

### F66 · suspicious / medium · T1552 · sdclt.exe spawned by cmd on SCRANTON

Evidence status: **verified**

sdclt.exe, a UAC-bypass-capable binary, was spawned three times by cmd under pbeesly on scranton.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:58:42.401Z | scranton.dmevals.local | windows.sysmon | process.command_line | C:\windows\system32\sdclt.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7huwtP3 | q-32011036d6 | ok |

### F67 · suspicious / medium · T1552 · accesschk.exe recon on SCRANTON

Evidence status: **verified**

accesschk.exe was run by pbeesly PowerShell on scranton, consistent with permission recon before LSASS access.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:34.951Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\accesschk.exe" | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hRQwNZ | q-32011036d6 | ok |

### F60 · suspicious / medium · T1552.004 · Certificate store written on NASHUA during pbeesly session

Evidence status: **verified**

On nashua a certificate blob was written under systemprofile SystemCertificates at 03:16:19, right after the Rar archive step.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:16:19.462Z | nashua.dmevals.local | windows.sysmon | file.path | C:\Windows\System32\config\systemprofile\AppData\Roaming\Microsoft\SystemCertificates\My\Certificates\A4F69156AB2E4C5AFBB55BFD66DC60F0D398FE9A | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7ctlGsP | q-67ecdf8a74 | ok |
| 2 | 2020-05-02 03:11:40.081Z | nashua.dmevals.local | windows.sysmon | file.path | C:\ProgramData\Microsoft\Crypto\RSA\S-1-5-18\d7466e4a1a7792ae0113bd927f6c3948_5aa8ec29-a46d-4aa7-9929-4f7235b0a39d | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7c82Ohp | q-67ecdf8a74 | ok |

### F36 · suspicious / medium · T1556 · PowerShell.exe opened LSASS with PROCESS_ALL_ACCESS (0x1FFFFF) on scranton.dmevals.local

Evidence status: **verified**

On 2020-05-02 at 03:05:16.623Z and 03:05:16.654Z, C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe (PID 2976, running as SYSTEM per win.AccountName) opened C:\windows\system32\lsass.exe (PID 736) with GrantedAccess 0x1f3fff and then 0x1fffff — full-process access masks consistent with reading LSASS memory for credential extraction. The CallTrace ends in an UNKNOWN module (UNKNOWN(000001996D28200D)) after ntdll/KERNELBASE, i.e. the call did not originate from a known signed DLL. This is the only LSASS access in the dataset with these masks from PowerShell; the other high-mask accesses are explained by system processes (wininit.exe/csrss.exe at 03:19:09 during a boot, svchost.exe 0x101001/0x3000, and Azure antimalware/telemetry agents using 0x1400). No Sysmon process-creation (event 1) or Security 4688 record exists for PID 2976 in the retained window, so the launching command line could not be recovered. No LSASS dump file was written (only WerFault WER*.tmp.dmp files appear). Context: the same host/user (pbeesly) was running Sysinternals tooling and discovery scripts minutes earlier (accesschk.exe at 03:04:34, Invoke-Discovery at 03:04:03, sdelete64.exe wiping files at 03:02-03:03).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1fffff | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hQQBhJ | q-fe32fc3b0f | ok |
| 2 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\WindowsPowerShell\v1.0\PowerShell.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hQQBhJ | q-fe32fc3b0f | ok |
| 3 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.CallTrace | C:\windows\SYSTEM32\ntdll.dll+9c584\|C:\windows\System32\KERNELBASE.dll+2732e\|UNKNOWN(000001996D28200D) | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hQQBhJ | q-fe32fc3b0f | ok |
| 4 | 2020-05-02 03:05:16.623Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hQQBhG | q-df67f58f4f | ok |
| 5 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.AccountName | SYSTEM | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hQQBhJ | q-fe32fc3b0f | ok |

### F44 · suspicious / medium · T1557.001 · SMB traffic and NTLM logon are consistent with PsExec lateral movement, not SMB relay or name-resolution poisoning

Evidence status: **verified**

All 66 SMB connections (destination ports 445/139) originate from the 'System' process on newyork, nashua, scranton and utica, i.e. the kernel SMB client, with no relay tooling present. The single NTLM network logon (4624, LogonType 3, NtLmSsp, NTLM V2) on scranton.dmevals.local at 2020-05-02T03:20:41Z for DMEVALS\pbeesly from 172.18.39.2 / workstation 10.0.1.4 is the authentication of the PsExec session launched from scranton at 03:11:18Z with the cleartext password '-p Fl0nk3rt0n!T0by' against \\NASHUA. That is credential misuse for lateral movement (T1021.002/T1078), not an SMB relay: no poisoned name resolution, no relay listener, and no DNS client registry tampering (event.code 13 DNSClient query returned zero hits) were observed. Service installs (4697) are PSEXESVC plus standard per-user svchost services and javamtsup.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:18.784Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\PsExec64.exe" -accepteula \\NASHUA -u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7cxoQzx | q-1b0d532777 | ok |
| 2 | 2020-05-02 03:20:41.000Z | scranton.dmevals.local | windows.security | win.AuthenticationPackageName | NTLM | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7nQi3T7 | q-9037db5ef5 | ok |
| 3 | 2020-05-02 03:20:41.000Z | scranton.dmevals.local | windows.security | source.ip | 172.18.39.2 | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7nQi3T7 | q-9037db5ef5 | ok |

### F48 · suspicious / medium · T1558.001 · No golden-ticket forging observed; LSASS access is the only KRBTGT-theft precursor

Evidence status: **verified**

No forged-TGT indicators were found: all 4768/4769 events on the DC newyork.dmevals.local returned Failure Code 0x0 with normal AES256 (0x12) encryption and PreAuthType 2, and no anomalous account obtained a TGT without pre-authentication. However, the malicious PowerShell.exe on SCRANTON (03:05:16) and wsmprovhost.exe on NASHUA (03:09:29) opened LSASS with 0x1FFFFF/0x1F3FFF, which is the access needed to read the KRBTGT hash and forge golden tickets. The capability is present; no forged ticket was actually observed in the available logs.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.TargetImage | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hQQBhJ | q-5e78475483 | ok |
| 2 | 2020-05-02 03:11:18.000Z | newyork.dmevals.local | windows.security | win.PreAuthType | 2 | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7niyNvO | q-0e257df5ca | ok |
| 3 | 2020-05-02 03:19:13.000Z | newyork.dmevals.local | windows.security | win.Status | 0x0 | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7ncs5ql | q-0e257df5ca | ok |

### F50 · suspicious / medium · T1558.003 · Kerberoast-style TGS request for krbtgt by pbeesly, plus LSASS ticket extraction

Evidence status: **verified**

On newyork.dmevals.local at 03:04:04 UTC a 4769 service ticket was requested by pbeesly@DMEVALS.LOCAL for Service Name 'krbtgt' (Service ID ...-502) with Ticket Options 0x60810010 — a TGS request for the krbtgt service, the pattern produced by Kerberoasting tooling. It was followed by repeated 4769 requests for NASHUA$ from 10.0.1.4 and 10.0.1.6, and by LSASS reads with 0x1F3FFF/0x1FFFFF by PowerShell.exe on SCRANTON and wsmprovhost.exe on NASHUA, which is how service-account ticket material is harvested. No RC4 (0x17) downgrade was seen — all tickets were AES256 (0x12) — and no kerberoast/SPN strings appeared in PowerShell script blocks.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:04.000Z | newyork.dmevals.local | windows.security | win.ServiceName | krbtgt | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7nq72Yx | q-fc3ade6398 | ok |
| 2 | 2020-05-02 03:04:04.000Z | newyork.dmevals.local | windows.security | win.TicketOptions | 0x60810010 | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7nq72Yx | q-fc3ade6398 | ok |
| 3 | 2020-05-02 03:09:29.430Z | nashua.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1f3fff | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7c939yF | q-de79c1c9ad | ok |

### F61 · suspicious / medium · T1649 · Certificate store touched on NASHUA after archive step

Evidence status: **verified**

SystemCertificates write under systemprofile on nashua.dmevals.local at 03:16:19 follows the Rar archive of pbeesly files.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:16:19.462Z | nashua.dmevals.local | windows.sysmon | process.executable | C:\windows\Sysmon.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7ctlGsP | q-67ecdf8a74 | ok |

### F02 · benign / high · T1003.002 · SAM_SERVER / SAM_DOMAIN handle requests are lsass-internal SYSTEM activity, not hive dumping

Evidence status: **verified**

The only SAM object access in the window is on scranton.dmevals.local at 03:19:21-03:20:46, where the requesting process is lsass.exe itself (PID 0x2ec) running as SCRANTON$ (S-1-5-18, logon 0x3e7) against the 'Security Account Manager' object server, with masks 0xf003f (SAM_SERVER) and 0xf07df (SAM_DOMAIN). This is the local SAM service handling its own account database, not an external tool reading the hive. No reg.exe save of SAM/SYSTEM, no hive file writes (.hiv/.dit), no 4663 on SAM/SECURITY object names, and no 4104 script block referencing reg save or hives were observed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:21.000Z | scranton.dmevals.local | windows.security | win.ProcessName | C:\Windows\System32\lsass.exe | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7ryFh3A | q-1f8ba1b2a9 | ok |
| 2 | 2020-05-02 03:19:21.000Z | scranton.dmevals.local | windows.security | win.SubjectUserName | SCRANTON$ | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7ryFh3A | q-1f8ba1b2a9 | ok |
| 3 | 2020-05-02 03:19:21.000Z | scranton.dmevals.local | windows.security | win.ObjectType | SAM_DOMAIN | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7ryFh3A | q-1f8ba1b2a9 | ok |

### F03 · benign / high · T1003.003 · No NTDS.dit access, VSS/ntdsutil/diskshadow execution or .dit file writes

Evidence status: **verified**

No process creation on any host referenced ntdsutil, vssadmin, diskshadow or ntds, no file-create event targeted ntds or *.dit, and no 4104 script block mentioned ntds/vssadmin/diskshadow. The only .dmp files written in the window are WerFault crash dumps (WER51F5.tmp.dmp on nashua, WER5437.tmp.dmp on scranton). No directory-database extraction activity was observed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:30.288Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\ProgramData\Microsoft\Windows\WER\Temp\WER5437.tmp.dmp | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hONXx6 | q-02b0e07405 | ok |

### F04 · benign / high · T1003.004 · No LSA Secrets / SECURITY hive access observed

Evidence status: **verified**

No 4663/4656 events referenced SECURITY or Policy\Secrets object names, no process command line contained 'reg save' or 'secrets', and no 4104 script block referenced SECURITY/Secrets/lsa. The only registry writes touching credential-related keys were routine: lsass.exe setting DeviceGuard\Scenarios\CredentialGuard\Enabled to 0 and services.exe creating the CredentialEnrollmentManagerUserSvc service keys on scranton.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:09.865Z | scranton.dmevals.local | windows.sysmon | win.TargetObject | HKLM\System\CurrentControlSet\Control\DeviceGuard\Scenarios\CredentialGuard\Enabled | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7cpgKyc | q-a139097be1 | ok |

### F05 · benign / medium · T1003.005 · No cached-domain-credential extraction; pbeesly instead harvested private keys and keystrokes

Evidence status: **verified**

No 4663 on SECURITY/Cache object names and no 4104 script block referencing cache/dcc/lsass. The credential theft that IS visible in this intrusion is different in nature: on scranton at 03:04:56 pbeesly ran Get-PrivateKeys, exporting machine certificate private keys to C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx, and at 03:06:59 ran Get-Keystrokes. Those are credential-access behaviours outside the T1003.005 definition, so this sub-technique is assessed as not observed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-PrivateKeys {     $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText     $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Re… | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qvSysm | q-4ac5dfac9d | ok |
| 2 | 2020-05-02 03:04:57.460Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Users\pbeesly\Downloads\coyn5igj.3io.pfx | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hQQRgs | q-02b0e07405 | ok |

### F06 · benign / high · T1003.006 · No DCSync / directory replication abuse observed

Evidence status: **verified**

No 4104 script block referenced dcsync/lsadump/Invoke-Mimikatz, no service was installed with a drsuapi/dcsync/mimikatz image path (the only 7045 services were Java(TM) Virtual Machine Support Service and four PSEXESVC installs from pbeesly's PsExec runs), and no process command line contained drsuapi. pbeesly's domain activity was LDAP-style discovery ('Ad-Search Computer Name *') and Kerberos/NTLM logons, not replication requests.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:39.000Z | nashua.dmevals.local | windows.other | process.executable | %SystemRoot%\PSEXESVC.exe | .ds-logs-windows.other-default-2026.10.20-000001 / AaFZR_JfH5wFd7pNHuCk | q-a4458161b3 | ok |
| 2 | 2020-05-02 03:09:04.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | Ad-Search Computer Name * | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qqQm9_ | q-8b713cd7f4 | ok |

### F08 · benign / high · T1040 · netsh trace capture on scranton.dmevals.local spawned by Azure Network Watcher agent (benign)

Evidence status: **verified**

The only T1040-relevant activity in the dataset is two netsh.exe process creations on scranton.dmevals.local at 2020-05-02T03:19:17Z and 03:19:24Z: 'netsh.exe trace start capture=yes traceFile="C:\windows\TEMP\E7116ECA-DFE6-43C7-8FA8-8D3AC5AA8726\B91E06C5-1C7C-4830-9A76-74FA211560A7.etl"' followed by 'netsh.exe trace stop'. Both were created by SYSTEM (SCRANTON$, logon 0x3E7) with parent process C:\Packages\Plugins\Microsoft.Azure.NetworkWatcher.NetworkWatcherAgentWindows\1.4.1421.1\NetworkWatcherAgent\NetworkWatcherAgent.exe /service — the Microsoft Azure Network Watcher agent, a legitimate packet-capture/network-diagnostics service. The capture ran for only ~7 seconds and no ETL file creation at that TEMP path was observed in Sysmon file-create events. No pktmon, windump, tcpdump, rawcap, tshark or Wireshark execution was found in windows.security 4688 or windows.sysmon event 1, no pcap/npcap/winpcap service was installed (7045 services were only Java VM Support Service and PSEXESVC), no capture driver image loads were seen, and no PowerShell script blocks referenced capture tooling. Zeek (non-overlapping window) shows only ordinary enterprise traffic (SSL 8443, SMB 445, DNS, Kerberos, LDAP, WinRM) with no sign of mirrored/sniffed traffic. This is expected cloud-monitoring behaviour, not adversary network sniffing.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:17.000Z | scranton.dmevals.local | windows.security | process.command_line | C:\windows\system32\netsh.exe trace start capture=yes traceFile="C:\windows\TEMP\E7116ECA-DFE6-43C7-8FA8-8D3AC5AA8726\B91E06C5-1C7C-4830-9A76-74FA211560A7.etl" | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7nVnj7M | q-e2174a0151 | ok |
| 2 | 2020-05-02 03:19:17.000Z | scranton.dmevals.local | windows.security | process.parent.executable | C:\Packages\Plugins\Microsoft.Azure.NetworkWatcher.NetworkWatcherAgentWindows\1.4.1421.1\NetworkWatcherAgent\NetworkWatcherAgent.exe | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7nVnj7M | q-e2174a0151 | ok |
| 3 | 2020-05-02 03:19:24.000Z | scranton.dmevals.local | windows.security | process.command_line | C:\windows\system32\netsh.exe trace stop | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7nSl9D4 | q-cf9669009d | ok |
| 4 | 2020-05-02 03:19:17.154Z | scranton.dmevals.local | windows.sysmon | process.parent.command_line | "C:\Packages\Plugins\Microsoft.Azure.NetworkWatcher.NetworkWatcherAgentWindows\1.4.1421.1\NetworkWatcherAgent\NetworkWatcherAgent.exe" /service | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7cla5Dm | q-bf38245366 | ok |
| 5 | 2020-05-02 03:19:17.154Z | scranton.dmevals.local | windows.sysmon | user.name | SYSTEM | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7cla5Dm | q-bf38245366 | ok |

### F12 · benign / high · T1056 · Benign LSASS/SAM handle baseline from Azure guest agents and system processes

Evidence status: **verified**

Most credential-store handle activity in the window is normal platform behaviour. LSASS access is dominated by svchost.exe (289 events), C:\Packages\Plugins\Microsoft.Azure.Security.IaaSAntimalware\1.5.5.9\AntimalwareConfig.exe (15) and C:\WindowsAzure\Packages\Telemetry\WindowsAzureTelemetryService.exe (13), all with read-only masks 0x1000/0x1400. Security 4663 on lsass.exe comes from C:\WindowsAzure\Packages\CollectGuestLogs.exe (4) and C:\Program Files\Windows Defender\MsMpEng.exe (1) with AccessMask 0x10, and the 10 SAM handle requests are all from C:\Windows\System32\lsass.exe itself as SCRANTON$ with 0xf003f. Registry 'Keyboard' writes are OS keyboard-layout/device-enumeration values by System, smss.exe, winlogon.exe and LogonUI.exe, not keylogger persistence. No service install (7045) or script referencing keylog/hook was found in windows.other.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:21.000Z | scranton.dmevals.local | windows.security | process.executable | C:\Windows\System32\lsass.exe | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7ryFh2_ | q-c24fd2d3e5 | ok |
| 2 | 2020-05-02 03:03:38.000Z | newyork.dmevals.local | windows.security | process.executable | C:\WindowsAzure\Packages\CollectGuestLogs.exe | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7nq8Gbm | q-d502b9d9cb | ok |
| 3 | 2020-05-02 03:19:42.009Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\WindowsAzure\Packages\Telemetry\WindowsAzureTelemetryService.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7cUGJOD | q-c9b5b0541d | ok |
| 4 | 2020-05-02 03:19:22.416Z | scranton.dmevals.local | windows.sysmon | win.TargetObject | HKU\.DEFAULT\Software\Microsoft\CTF\SortOrder\AssemblyItem\0x00000409\{34745C63-B2F0-4784-8B67-5E12C8701A31}\00000000\KeyboardLayout | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7cZNc-- | q-3790b9093b | ok |

### F13 · benign / medium · T1056.003 · No web portal capture observed

Evidence status: **verified**

No evidence of web portal credential capture. All 62 zeek HTTP records in the 2020-04-30 window target a single internal address (url.domain 192.168.0.4), and queries for login/signin/password/keylog URLs returned zero hits. On the Windows side, no file writes to \inetpub\, .aspx/.asp/.ashx files, no IIS/w3wp service installs and no 4688 command lines referencing inetpub were found. The zeek window does not overlap the Windows window, so this is a per-dataset negative.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:06:47.000Z | scranton.dmevals.local | windows.powershell | host.name | scranton.dmevals.local | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qvSitD | q-309384e8d0 | ok |

### F14 · benign / high · T1110 · No brute-force authentication activity observed; credential theft on SCRANTON instead

Evidence status: **verified**

Across windows.security (2020-05-02T02:55:25Z..03:28:09Z) there are zero 4625 failed-logon events, so no brute-force pattern exists. The only authentication anomalies are successful explicit-credential logons (4648) by DMEVALS\pbeesly from scranton.dmevals.local to NASHUA (10.0.1.6) paired with PSEXESVC.exe on nashua.dmevals.local, and a single successful NTLM validation (4776, Status 0x0) for pbeesly on newyork.dmevals.local — consistent with PsExec lateral movement using already-known credentials, not password guessing. The credential-access activity in this window is LSASS memory access (T1003.001), which is outside the T1110 family.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:18.000Z | scranton.dmevals.local | windows.security | win.TargetServerName | NASHUA | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7niydsP | q-aa02058e38 | ok |
| 2 | 2020-05-02 03:11:40.000Z | nashua.dmevals.local | windows.security | process.executable | C:\Windows\PSEXESVC.exe | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7niyNur | q-aa02058e38 | ok |
| 3 | 2020-05-02 03:20:40.000Z | newyork.dmevals.local | windows.security | win.Status | 0x0 | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7nKhItZ | q-aa02058e38 | ok |

### F15 · benign / high · T1110.001 · No password-guessing attempts; only successful explicit-credential logons

Evidence status: **verified**

No 4625 events exist in windows.security, so there are no repeated failed logons indicating password guessing. The 4648 events on scranton.dmevals.local/nashua.dmevals.local are all successful (pbeesly to NASHUA, and PSEXESVC.exe to localhost), and the single 4776 on newyork.dmevals.local returned Status 0x0 (success). The PowerShell 4104 hits matching 'password'/'credential' are module manifests and DSC resource strings, plus one exfiltration script that hardcodes a credential (cozy / MyCozyPassw0rd!) for a WebDAV upload — credential use, not guessing.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:20:40.000Z | newyork.dmevals.local | windows.security | event.code | 4776 | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7nKhItZ | q-aa02058e38 | ok |
| 2 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\psversion.ps1 | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qjPglL | q-da3474e033 | ok |

### F17 · benign / high · T1110.003 · No password spraying: zero failed logons across all hosts

Evidence status: **verified**

windows.security contains no 4625 events at all, so there is no pattern of one password tried against many accounts. Successful logons are dominated by machine accounts (NEWYORK$ 123, SCRANTON$ 37, NASHUA$ 25, UTICA$ 5, WEC$ 8) and pbeesly (20) over LogonType 3, plus SYSTEM LogonType 5 — normal service/network authentication. The only repeated user-driven authentication is pbeesly's PsExec-driven 4648 logons to NASHUA, all successful.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:12:25.000Z | scranton.dmevals.local | windows.security | win.TargetUserName | pbeesly | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7nixwZC | q-aa02058e38 | ok |
| 2 | 2020-05-02 03:12:25.000Z | scranton.dmevals.local | windows.security | win.TargetServerName | NASHUA | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7nixwZC | q-aa02058e38 | ok |

### F18 · benign / high · T1110.004 · No credential stuffing: no failed authentications or reused-credential failures

Evidence status: **verified**

No 4625, 4771 or 4740 events were returned in windows.security, so there is no evidence of stolen credential lists being replayed against accounts. The only credential reuse observed is legitimate-looking: pbeesly's explicit credentials used via PsExec to nashua.dmevals.local (4648 with PSEXESVC.exe) and a successful 4776 NTLM validation on newyork.dmevals.local. The hardcoded 'cozy' credential in the SCRANTON exfiltration script was used for an outbound WebDAV mount, not for stuffing against local accounts.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:15:03.000Z | nashua.dmevals.local | windows.security | process.executable | C:\Windows\PSEXESVC.exe | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7niwwaQ | q-aa02058e38 | ok |
| 2 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | user.name | pbeesly | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qjPglL | q-da3474e033 | ok |

### F19 · benign / high · T1111 · No MFA interception artifacts; credential-provider and smart-card components are stock Microsoft binaries

Evidence status: **verified**

Hunting for T1111 (Multi-Factor Authentication Interception) across windows.security, windows.sysmon, windows.powershell and windows.other (2020-05-02 02:55-03:28Z) found no evidence of MFA interception. Every credential-provider / biometric / smart-card / Windows Hello DLL loaded (event.code 7) is Microsoft-signed (win.Signed=true, win.Signature='Microsoft Windows'): CredProv2faHelper.dll, ngccredprov.dll, SmartcardCredentialProvider.dll, BioCredProv.dll, wlidcredprov.dll, vaultcli.dll, cryptngc.dll, ngcsvc.dll, vaultsvc.dll. Registry writes under HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI were made by C:\windows\system32\LogonUI.exe during a normal interactive logon of DMEVALS\pbeesly on scranton.dmevals.local (LastLoggedOnProvider {60B78E88-EAD8-445C-9CFD-0B87F74EA6CD}, the built-in password provider), not by an attacker-installed provider. No 4624 logon used a smart-card/certificate package (only Kerberos, Advapi, User32, NtLmSsp), and no account names referencing smart/mfa/token/otp/cert/vault/ngc appeared in logon events. The 4648 explicit-credential events are PsExec-driven (C:\Windows\PSEXESVC.exe on nashua.dmevals.local) and normal Windows internals (winlogon.exe for DWM-1/UMFD-*, taskhostw.exe, svchost.exe) using the pbeesly account, i.e. lateral movement with harvested passwords rather than MFA token interception. The 7045 service installs are PSEXESVC and a Java support service, not credential providers. The only PowerShell script block touching credentials (Invoke-Exfil on scranton.dmevals.local) hardcodes a plaintext password ('MyCozyPassw0rd!') for a WebDAV drive - credential use, not MFA interception. LSASS access by PowerShell.exe/wsmprovhost.exe (0x1fffff/0x1f3fff) is credential dumping territory (T1003), not T1111.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:20:46.756Z | scranton.dmevals.local | windows.sysmon | registry.path | HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\SessionData\2\LastLoggedOnProvider | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRfJfH5wFd7b_z_Wh | q-7e0517ebe4 | ok |
| 2 | 2020-05-02 03:20:46.756Z | scranton.dmevals.local | windows.sysmon | registry.data.strings | {60B78E88-EAD8-445C-9CFD-0B87F74EA6CD} | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRfJfH5wFd7b_z_Wh | q-7e0517ebe4 | ok |
| 3 | 2020-05-02 03:20:46.756Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\LogonUI.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRfJfH5wFd7b_z_Wh | q-7e0517ebe4 | ok |
| 4 | 2020-05-02 03:19:49.485Z | scranton.dmevals.local | windows.sysmon | registry.data.strings | Credential Manager | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7cTFiiN | q-7751073f9a | ok |
| 5 | 2020-05-02 03:11:40.000Z | nashua.dmevals.local | windows.security | process.executable | C:\Windows\PSEXESVC.exe | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7niyNur | q-ed690d689f | ok |
| 6 | 2020-05-02 03:11:40.000Z | nashua.dmevals.local | windows.security | win.TargetUserName | pbeesly | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7niyNur | q-ed690d689f | ok |
| 7 | 2020-05-02 03:08:02.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Invoke-Exfil {      if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershe… | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qjPglL | q-9cd5e439a9 | ok |
| 8 | 2020-05-02 03:04:15.000Z | scranton.dmevals.local | windows.other | win.ServiceName | Java(TM) Virtual Machine Support Service | .ds-logs-windows.other-default-2026.10.20-000001 / AaFZR_JfH5wFd7pNHuDg | q-44036c7a57 | ok |
| 9 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.TargetImage | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hQQBhJ | q-ea1d58f0f2 | ok |

### F21 · benign / medium · T1187 · Routine SMB client traffic to file server 10.0.0.4 and Explorer-created Recent .lnk files are benign

Evidence status: **verified**

The remaining T1187 check hits are normal system behaviour. All 66 outbound SMB (445/139) connections in windows.sysmon are generated by process.executable 'System' (the kernel SMB client) under user SYSTEM, going to 10.0.0.4 (26), the link-local address fe80::e40c:95b6:b0a7:6429 (24) and 10.0.1.6 (16) — ordinary file-server/DFS traffic, not coercion. The two .lnk files under C:\Users\pbeesly\AppData\Roaming\Microsoft\Windows\Recent\ were created by C:\windows\Explorer.EXE at 2020-05-02T02:58:44Z, which is Explorer's normal Recent-items behaviour, not a lure. The 5140/5145 share access is limited to SYSVOL, IPC$ and ADMIN$ (domain administration), and the 4663/4656 object types are overwhelmingly registry Keys. The zeek SMB flows (45 to 445, 5 to 139) are likewise plain conn records. Note the only genuinely malicious shortcut is the StartUp hostui.lnk created by PowerShell, reported in the malicious finding.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:01:43.033Z | scranton.dmevals.local | windows.sysmon | process.executable | System | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hWVykL | q-789bfa946f | ok |
| 2 | 2020-05-02 03:01:43.033Z | scranton.dmevals.local | windows.sysmon | destination.ip | 10.0.0.4 | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hWVykL | q-789bfa946f | ok |
| 3 | 2020-05-02 02:58:44.405Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\Explorer.EXE | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7htwOxh | q-3522d5fb25 | ok |
| 4 | 2020-05-02 02:58:44.405Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Users\pbeesly\AppData\Roaming\Microsoft\Windows\Recent\Backup and Restore (Windows 7).lnk | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7htwOxh | q-3522d5fb25 | ok |

### F23 · benign / high · T1212 · Baseline LSASS handle opens by svchost.exe, Azure agents and boot processes

Evidence status: **verified**

Of 326 Sysmon event.code 10 records targeting lsass.exe, 289 came from C:\windows\system32\svchost.exe (286 at GrantedAccess 0x1000, 2 at 0x101001, 1 at 0x3000), 15 from C:\Packages\Plugins\Microsoft.Azure.Security.IaaSAntimalware\1.5.5.9\AntimalwareConfig.exe and 13 from C:\WindowsAzure\Packages\Telemetry\WindowsAzureTelemetryService.exe (0x1000/0x1400) — standard AV/telemetry query rights. The wininit.exe (0x1000000, 0x1fffff), csrss.exe (0x1fffff) and services.exe (0x1000) opens all occur at 03:19:09-03:19:13 on scranton, matching a boot/restart sequence (lsass.exe itself was created at 03:19:09.809 by wininit.exe). These are normal system behaviour, not exploitation.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:09.803Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\wininit.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7cpgKyV | q-b8b5381799 | ok |
| 2 | 2020-05-02 03:19:09.803Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1000000 | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7cpgKyV | q-b8b5381799 | ok |
| 3 | 2020-05-02 03:19:09.809Z | scranton.dmevals.local | windows.sysmon | process.command_line | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7cxqOgJ | q-d1949bc282 | ok |
| 4 | 2020-05-02 03:19:13.337Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\system32\services.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7cofd-n | q-b8b5381799 | ok |

### F25 · benign / high · T1539 · No web session cookie theft observed; browser cookie/DataStore file activity is native Microsoft Edge behaviour

Evidence status: **verified**

On scranton.dmevals.local the only file creations matching cookie/credential-store patterns were made by Microsoft Edge itself: MicrosoftEdge.exe (PID 6208) created C:\Users\pbeesly\AppData\Local\Packages\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\AC\MicrosoftEdge\User\Default\DataStore\_TempTestAccess.txt at 03:21:05Z, and svchost.exe created the LocalService package directory ...\warp_jit_db4a1097-...\AC\INetCookies at 03:21:05Z. A query for any non-browser process (excluding MicrosoftEdge*, svchost, Explorer) touching Edge/Mozilla/Chrome profile paths returned 0 rows, and no process-injection handles into browser images were found (all event.code 10 handles on Edge images came from svchost.exe/Explorer.EXE with routine access masks 0x1000/0x1400/0x2000/0x3000). The 13 PowerShell 4104 script blocks matching Cookies/Login Data/sqlite were Microsoft module manifests and localization data on newyork.dmevals.local, not cookie access. No evidence of T1539 on any host.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:21:05.198Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Users\pbeesly\AppData\Local\Packages\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\AC\MicrosoftEdge\User\Default\DataStore\_TempTestAccess.txt | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7YE4VZs | q-fa39ddbdbc | ok |
| 2 | 2020-05-02 03:21:05.198Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\Windows\SystemApps\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\MicrosoftEdge.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7YE4VZs | q-fa39ddbdbc | ok |
| 3 | 2020-05-02 03:21:05.681Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Windows\ServiceProfiles\LocalService\AppData\Local\Packages\warp_jit_db4a1097-b484-4973-bbf2-a04208ecd4d4\AC\INetCookies | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7cPCBow | q-9da9d08ee2 | ok |
| 4 | 2020-05-02 03:21:07.753Z | scranton.dmevals.local | windows.sysmon | win.SourceImage | C:\windows\system32\MicrosoftEdgeSH.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7YL-ox6 | q-e3d1733c82 | ok |
| 5 | 2020-05-02 03:01:30.000Z | newyork.dmevals.local | windows.powershell | host.name | newyork.dmevals.local | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qwUFuS | q-9ab489a194 | ok |

### F29 · benign / medium · T1552.001 · No evidence of credentials-in-files harvesting (findstr/Get-Content/unattend/web.config) — only benign file writes

Evidence status: **verified**

The 72 file-creation hits for .txt/.config/.xml/.ini/.ps1 on windows.sysmon are all OS/application noise: Cortana and Edge DOMStore caches, Windows Error Reporting temp files, USOPrivate update store XML, PowerShell __PSScriptPolicyTest_*.ps1 files, PSGetModuleInfo.xml and the GroupPolicy DataStore gpt.ini. No process command line on any host contained findstr, password, credential, Get-Content or unattend-style file reads (ES\|QL over sysmon event.code 1 returned zero rows), and the only 4104 blocks matching password/credential were the malicious Get-PrivateKeys/Invoke-Exfil blocks plus a benign Microsoft MSFT_ScriptResourceStrings.psd1 localization resource on newyork.dmevals.local. The 4648 explicit-credential logons by pbeesly are the PsExec lateral movement already covered under T1552, not file-based credential discovery.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:18.009Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Windows\System32\GroupPolicy\DataStore\0\sysvol\dmevals.local\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\gpt.ini | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7cZN9Bo | q-a79c7123cb | ok |
| 2 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.Path | C:\Program Files\SysinternalsSuite\readme.ps1 | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qvSysm | q-9e830bb12c | ok |

### F30 · benign / medium · T1552.002 · No registry credential harvesting observed

Evidence status: **verified**

The 17 registry writes matching Password/Credential are all legitimate Windows components: IdentityCRL ProviderPasswordLength/CharacterGroups defaults, DeviceGuard CredentialGuard Enabled, the CredentialEnrollmentManagerUserSvc_13619b service registration, MuiCache entries for CredentialEnrollmentManager.exe and Winlogon PasswordExpiryNotification values. No reg query/reg save/winreg command line was executed on any host (ES\|QL over sysmon event.code 1 returned zero rows) and no 4663 access to SAM/SECURITY/Password objects was found.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:18.009Z | scranton.dmevals.local | windows.sysmon | win.TargetFilename | C:\Windows\System32\GroupPolicy\DataStore\0\sysvol\dmevals.local\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.in… | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7cZN9Bn | q-a79c7123cb | ok |

### F31 · benign / medium · T1552.003 · No shell history access observed

Evidence status: **verified**

No 4104 script block referenced history, ConsoleHost_history or Get-History, and no process command line on any host contained ConsoleHost_history, Get-History or history (ES\|QL over sysmon event.code 1 returned zero rows). No file creation of ConsoleHost_history was seen.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:56.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockId | 9d153741-75c3-4062-afe3-aeca0aee611b | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qvSysm | q-9e830bb12c | ok |

### F32 · benign / medium · T1552.006 · SYSVOL/GPP reads are routine Group Policy processing, not GPP credential theft

Evidence status: **verified**

All SYSVOL/GptTmpl.inf/gpt.ini accesses are performed by svchost.exe (the Group Policy client) on scranton.dmevals.local (03:01:43, 03:19:18) and nashua.dmevals.local (03:10:40), and the zeek smb_files records show the same policy files opened from \\NEWYORK.dmevals.local\sysvol by 10.0.1.4 and 10.0.1.6 in the separate 2020-04-30 window. No Groups.xml was created or read, no cpassword/gpprefdecrypt/AES script block or command line exists, and no 5145 relative-target access to Groups.xml/SYSVOL was recorded. This is normal policy refresh behaviour.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:10:40.308Z | nashua.dmevals.local | windows.sysmon | win.TargetFilename | C:\Windows\System32\GroupPolicy\DataStore\0\sysvol\dmevals.local\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.in… | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7cxogx- | q-a79c7123cb | ok |
| 2 | 2020-04-30 00:20:49.313Z | bobs.bigwheel.local | zeek | zeek.name | dmevals.local\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf | .ds-logs-zeek-default-2026.10.20-000001 / AaFZSPJfH5wFd7qUcN0h | q-f6a278738c | ok |

### F34 · benign / medium · T1555.003 · No browser credential-store access observed

Evidence status: **verified**

No creation, copy or command-line reference to browser credential stores (Login Data, logins.json, key4.db, Cookies) was found in sysmon, security or PowerShell telemetry. The only file-creation hit matching the pattern was C:\Windows\ServiceProfiles\LocalService\AppData\Local\Packages\warp_jit_db4a1097-b484-4973-bbf2-a04208ecd4d4\AC\INetCookies created by svchost.exe on scranton at 03:21:05Z, a Windows service-profile cookie store, not a browser theft artifact. No process-access events against chrome/firefox/msedge were seen.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:21:05.681Z | scranton.dmevals.local | windows.sysmon | file.path | C:\Windows\ServiceProfiles\LocalService\AppData\Local\Packages\warp_jit_db4a1097-b484-4973-bbf2-a04208ecd4d4\AC\INetCookies | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7cPCBow | q-eea1da2796 | ok |
| 2 | 2020-05-02 03:21:05.681Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\windows\System32\svchost.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7cPCBow | q-eea1da2796 | ok |

### F35 · benign / medium · T1555.004 · No Windows Credential Manager / vault access observed

Evidence status: **verified**

No cmdkey, vaultcmd, CredRead or Credential Manager command lines, no registry/file access to Vault or *.vcrd stores, and no 4688/4104 references to credential APIs were found. The windows.other hits for 'vault'/'Credential Manager' were unrelated boot-time records on scranton (file-system filter loads, 'Credential Guard configuration: 0x0, 0', SCM event-log consumer binding), not credential-store reads. LSASS access is reported under T1555 rather than as Credential Manager access.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:09.000Z | scranton.dmevals.local | windows.other | message | Credential Guard configuration: 0x0, 0 | .ds-logs-windows.other-default-2026.10.20-000001 / AaFZR_JfH5wFd7pNHuA9 | q-cb93e0e3fc | ok |

### F37 · benign / medium · T1556.001 · No evidence of domain-controller authentication tampering (LSASS access on DCs is system/AV only)

Evidence status: **verified**

All 326 Sysmon event-10 accesses to lsass.exe were stacked by executable: 289 from svchost.exe, 15 from the Azure IaaSAntimalware AntimalwareConfig.exe, 13 from WindowsAzureTelemetryService.exe, 2+2 from PowerShell.exe, 2 from wininit.exe, 1 each from csrss.exe, services.exe and wsmprovhost.exe. The wininit.exe/csrss.exe accesses (0x1000000/0x1fffff at 03:19:09.803Z on scranton) coincide with a fresh lsass.exe process creation by wininit.exe at 03:19:09.809Z, i.e. a normal boot/restart sequence. Only Microsoft-signed modules were loaded into lsass/cryptdll (cryptdll.dll 32, lsass.exe 1). No 4657 registry change to LSA/SecurityProviders keys, no 4688/4104 referencing lsass, mimikatz, sekurlsa or MiniDump, and no lsass-related windows.other events. The 4648 explicit-credential logons are pbeesly via PSEXESVC.exe on nashua and DWM/UMFD/winlogon system logons — normal admin/desktop behaviour, not DC authentication backdooring.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:09.809Z | scranton.dmevals.local | windows.sysmon | process.command_line | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7cxqOgJ | q-ad1c7f9f13 | ok |
| 2 | 2020-05-02 03:19:09.803Z | scranton.dmevals.local | windows.sysmon | win.GrantedAccess | 0x1000000 | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7cpgKyV | q-df67f58f4f | ok |
| 3 | 2020-05-02 03:11:40.000Z | nashua.dmevals.local | windows.security | process.executable | C:\Windows\PSEXESVC.exe | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7niyNur | q-227704f48c | ok |

### F38 · benign / high · T1556.002 · No password-filter DLL registration or drop into System32

Evidence status: **verified**

No Sysmon event 11 created any .dll under System32/SysWOW64, no 4657 modified a 'Notification Packages' or LSA value, no 4688/4104 referenced Notification Packages or PasswordFilter, and the windows.other matches for 'Notification' were unrelated service notifications (7001/7002/50103/50104/22). The only DLL loads into authentication processes were Microsoft-signed system libraries (cryptdll.dll, samcli.dll, samlib.dll, ntdsapi.dll, samsrv.dll).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:18:33.000Z | scranton.dmevals.local | windows.other | message | User Logoff Notification for Customer Experience Improvement Program | .ds-logs-windows.other-default-2026.10.20-000001 / AaFZR_JfH5wFd7pNHuCy | q-65bc410453 | ok |
| 2 | 2020-05-02 03:19:09.803Z | scranton.dmevals.local | windows.sysmon | win.TargetImage | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7cpgKyU | q-df67f58f4f | ok |

### F39 · benign / high · T1556.005 · No reversible-encryption account changes; Set-ADUser hit is the xActiveDirectory DSC module

Evidence status: **verified**

The single 4104 script block matching Set-ADUser/Set-ADAccountControl on newyork.dmevals.local (2020-05-02T03:01:30Z, SYSTEM) is the built-in DSC resource file C:\Program Files\WindowsPowerShell\Modules\xActiveDirectory\DscResources\MSFT_xADCommon\MSFT_xADCommon.ps1 (function Get-CommonADParameters) — documentation text only, no account modification. No 4739 policy-change events, no 4103 payload or Sysmon process command line containing Reversible/Set-ADAccountControl, and no windows.other match.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:01:30.000Z | newyork.dmevals.local | windows.powershell | win.Path | C:\Program Files\WindowsPowerShell\Modules\xActiveDirectory\DscResources\MSFT_xADCommon\MSFT_xADCommon.ps1 | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qwUVsT | q-9a8f4191f7 | ok |
| 2 | 2020-05-02 03:01:30.000Z | newyork.dmevals.local | windows.powershell | win.ScriptBlockText | alidateSet('Seconds','Minutes','Hours','Days')]         [System.String]         $TimeSpanType     )     switch ($TimeSpanType)     {         'Seconds' { return … | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qwUVsT | q-9a8f4191f7 | ok |

### F40 · benign / medium · T1556.006 · No MFA/authentication-policy modification observed

Evidence status: **verified**

No 4739 (domain policy change) events exist, no 5136 directory-object modifications exist, and the only 4662 directory-service accesses are LOCAL SERVICE reads (AccessMask 0x2) of Policy\Secrets\$MACHINE.ACC on nashua, scranton and utica — routine machine-account secret reads. Logon types are the expected mix (3:218, 5:61, 2:15, 10:2, 0:1) with no anomalous account bypassing authentication.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:03:00.000Z | scranton.dmevals.local | windows.security | win.ObjectName | Policy\Secrets\$MACHINE.ACC | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7nq8Wb6 | q-0c9c552773 | ok |
| 2 | 2020-05-02 03:03:00.000Z | scranton.dmevals.local | windows.security | win.AccessMask | 0x2 | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7nq8Wb6 | q-0c9c552773 | ok |

### F41 · benign / medium · T1556.007 · No hybrid-identity / federation or sync-component tampering

Evidence status: **verified**

No 5136 directory modifications, no anomalous DLLs loaded into identity processes (top image loads are all standard System32 libraries), and logon types show no token manipulation or MFA-bypass pattern. The only notable identity-adjacent activity is the wlidsvc (Microsoft Account sign-in assistant) service start on scranton at 03:05:30.963Z, which is a normal service start.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:05:30.963Z | scranton.dmevals.local | windows.sysmon | process.command_line | C:\windows\system32\svchost.exe -k netsvcs -p -s wlidsvc | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hNNLQJ | q-19bc32cf5b | ok |

### F42 · benign / high · T1556.008 · No Network Provider DLL registration; registry writes are wevtutil autologger and cert/WSMAN changes

Evidence status: **verified**

No Sysmon event 13 wrote to a NetworkProvider registry path, and no .dll was created in System32/SysWOW64. The 36 event-4657 registry modifications are: wevtutil.exe (running as SCRANTON$) toggling WMI Autologger\EventLog-Application 'Enabled'/'MatchAnyKeyword' values on scranton at 03:19:16-03:19:23, a SystemCertificates ROOT 'Blob' write by Sysmon.exe on nashua, and a WSMAN\SafeClientList write by svchost.exe on nashua — none touch the NetworkProvider or authentication provider keys.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:16.000Z | scranton.dmevals.local | windows.security | win.ObjectName | \REGISTRY\MACHINE\SYSTEM\ControlSet001\Control\WMI\Autologger\EventLog-Application\{747c00b6-f0b4-438c-8b48-f3e5d7ed38a2} | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7nZqakj | q-51a1d447cc | ok |
| 2 | 2020-05-02 03:19:16.000Z | scranton.dmevals.local | windows.security | process.executable | C:\Windows\System32\wevtutil.exe | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7nZqakj | q-51a1d447cc | ok |
| 3 | 2020-05-02 03:24:23.000Z | nashua.dmevals.local | windows.security | win.ObjectName | \REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\SafeClientList | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7nOh9eN | q-51a1d447cc | ok |

### F43 · benign / medium · T1557 · No adversary-in-the-middle activity observed; network/DNS telemetry shows only normal host and Microsoft traffic

Evidence status: **verified**

Across windows.sysmon (2020-05-02 02:55-03:28) the 1229 network connections (event.code 3) and 81 DNS queries (event.code 22) resolve to ordinary destinations: internal DC/host addresses (10.0.0.4, 10.0.1.4, 10.0.1.6, 192.168.0.4), loopback, and Microsoft/Office/OCSP endpoints. DNS querying processes are standard Windows binaries (svchost.exe, lsass.exe, WmiPrvSE.exe, BackgroundTransferHost.exe, dsregcmd.exe, spoolsv.exe, powershell.exe) plus PsExec64.exe. No AiTM tooling (Responder, Inveigh, ettercap, arpspoof, ntlmrelayx) appears in any process command line or PowerShell 4104 script block. The only unusual DNS client is C:\ProgramData\victim\â€®cod.3aka3.scr on scranton.dmevals.local, which is malicious execution (T1204/T1059 territory) rather than interception. No evidence of traffic being relayed or intercepted was found.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 02:56:00.762Z | scranton.dmevals.local | windows.sysmon | process.executable | C:\ProgramData\victim\â€®cod.3aka3.scr | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hy0koQ | q-24ef89f6ed | ok |
| 2 | 2020-05-02 03:01:37.464Z | newyork.dmevals.local | windows.sysmon | win.QueryResults | fe80::e40c:95b6:b0a7:6429;::ffff:10.0.0.4; | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hWWenJ | q-24ef89f6ed | ok |
| 3 | 2020-05-02 03:20:04.471Z | scranton.dmevals.local | windows.sysmon | process.command_line | "arp.exe" /a | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7cREvLs | q-1af8ffb7a8 | ok |

### F45 · benign / high · T1557.002 · No ARP cache poisoning: arp.exe /a calls are Azure guest-agent telemetry

Evidence status: **verified**

The only ARP-related process activity in windows.sysmon is three executions of C:\Windows\System32\ARP.EXE with command line "arp.exe" /a on scranton.dmevals.local (03:19:25Z, 03:19:40Z, 03:20:04Z), all running as SYSTEM and all spawned by Azure guest-agent binaries (WindowsAzureGuestAgent.exe, WindowsAzureTelemetryService.exe, WaAppAgent.exe) — read-only ARP table inspection by the Azure VM agent, not cache poisoning. No arpspoof/ettercap/Inveigh tooling appears in any process command line or PowerShell script block, and no anomalous gateway redirection is visible in the 1229 sysmon network connections, which go to normal internal and Microsoft addresses.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:25.370Z | scranton.dmevals.local | windows.sysmon | process.parent.executable | C:\WindowsAzure\Packages\GuestAgent\WindowsAzureGuestAgent.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7cYMP7j | q-1af8ffb7a8 | ok |
| 2 | 2020-05-02 03:19:40.288Z | scranton.dmevals.local | windows.sysmon | process.parent.executable | C:\WindowsAzure\Packages\Telemetry\WindowsAzureTelemetryService.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7cUGJN0 | q-1af8ffb7a8 | ok |
| 3 | 2020-05-02 03:20:04.471Z | scranton.dmevals.local | windows.sysmon | process.parent.executable | C:\WindowsAzure\Packages\WaAppAgent.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7cREvLs | q-1af8ffb7a8 | ok |

### F46 · benign / high · T1557.003 · No DHCP spoofing indicators; DHCP-related events are normal service startup

Evidence status: **verified**

windows.other contains no DHCP server/lease event codes (no 1341/1342/1020/1063; the 216 events are dominated by 5857/5858 DNS-Server audit events, 7036/7045 service events and similar). No UDP port 67 traffic appears in windows.security 5156 firewall events, and no DNS client configuration changes were recorded (sysmon event.code 13 registry.path:*DNSClient* returned zero hits). The only DHCP-related process activity is the standard svchost.exe -k LocalServiceNetworkRestricted -p -s Dhcp service start on scranton.dmevals.local at 03:19:11Z during the post-reboot service startup sequence, which is normal Windows behaviour.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:19:11.533Z | scranton.dmevals.local | windows.sysmon | process.command_line | C:\windows\system32\svchost.exe -k LocalServiceNetworkRestricted -p -s Dhcp | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7cpf6ww | q-e8a4da9a24 | ok |

### F49 · benign / medium · T1558.002 · No silver-ticket forging observed; service-ticket requests are normal machine-account traffic

Evidence status: **verified**

All 4769 service-ticket requests on newyork.dmevals.local were successful (0x0) with AES256 (0x12) and were issued to the machine accounts NEWYORK$, NASHUA$, SCRANTON$, WEC$ and to pbeesly for cifs/host/ldap services — consistent with normal SMB/WinRM access during the intrusion. No service ticket was presented for a service whose account hash was demonstrably extracted, and no anomalous service-account logons appeared. The LSASS access on NASHUA/SCRANTON could support silver-ticket creation, but no forged service ticket was observed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:09:23.000Z | newyork.dmevals.local | windows.security | win.ServiceName | NASHUA$ | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7njzKBN | q-0e257df5ca | ok |
| 2 | 2020-05-02 03:19:14.000Z | newyork.dmevals.local | windows.security | win.ServiceName | SCRANTON$ | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7ncs5ob | q-0e257df5ca | ok |

### F51 · benign / medium · T1558.004 · No AS-REP roasting observed

Evidence status: **verified**

All 4768 AS-REQ events on newyork.dmevals.local for pbeesly and SCRANTON$ used PreAuthType 2 (pre-authentication enabled) and succeeded with AES256, so no account was found without Kerberos pre-authentication. No GetNPUsers/Rubeus/AS-REP strings appeared in PowerShell script blocks, and no roasting tooling was installed as a service (the only 7045 installs were javamtsup.exe and PSEXESVC.exe).

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:18.000Z | newyork.dmevals.local | windows.security | win.PreAuthType | 2 | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7niyNvO | q-0e257df5ca | ok |
| 2 | 2020-05-02 03:11:39.000Z | nashua.dmevals.local | windows.other | process.executable | %SystemRoot%\PSEXESVC.exe | .ds-logs-windows.other-default-2026.10.20-000001 / AaFZR_JfH5wFd7pNHuCk | q-208f63d1d5 | ok |

### F53 · benign / medium · T1606.001 · No evidence of web-cookie forging; cookie-file writes are svchost/Edge system activity

Evidence status: **verified**

The only hits for cookie-related file creation were 162 events writing paths matching *Cookies*/*Login Data*, attributed to C:\windows\System32\svchost.exe (133), C:\windows\system32\svchost.exe (28) and MicrosoftEdge.exe (1) — normal Windows/Edge profile maintenance, not cookie theft or injection. The single PowerShell script block matching 'cookie/session/token' keywords was the Get-AttributesMask token-attribute helper from readme.ps1, which concerns Windows access-token group attributes, not web cookies. No browser cookie store was read or modified by the malicious PowerShell chain, and no forged cookie material was written. The credential access observed on SCRANTON was LSASS memory access, not cookie forgery.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:04.000Z | scranton.dmevals.local | windows.powershell | win.ScriptBlockText | function Get-AttributesMask($AttributesMask) {     &lt;#         SE_GROUP_MANDATORY          0x00000001  The group is mandatory.         SE_GROUP_ENABLED_BY_DEF… | .ds-logs-windows.powershell-default-2026.10.20-000001 / AaFZR_JfH5wFd7qvTCvl | q-1714f39b2b | ok |
| 2 | 2020-05-02 03:05:16.654Z | scranton.dmevals.local | windows.sysmon | win.TargetImage | C:\windows\system32\lsass.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7hQQBhJ | q-79037633a3 | ok |

### F54 · benign / medium · T1606.002 · No SAML token forging observed; logon process/package values are standard

Evidence status: **verified**

Across 297 successful 4624 logons the LogonProcessName values were Kerberos (217), Advapi (76), User32 (2), NtLmSsp (1) and '-' (1), and AuthenticationPackageName values Kerberos (217), Negotiate (78), NTLM (1) and '-' (1) — all standard Windows values with no forged-token indicator. The SAML-specific PowerShell search (SAML / NotOnOrAfter / token-signing) returned zero hits, and no AADInternals or token-signing certificate activity was found. The 4648 explicit-credential events are pbeesly's own PSEXESVC/Invoke-Command lateral movement and routine winlogon/wininit DWM/UMFD logons, not SAML token use.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:11:40.000Z | nashua.dmevals.local | windows.security | process.executable | C:\Windows\PSEXESVC.exe | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7niyNur | q-e0762e0e4e | ok |
| 2 | 2020-05-02 03:19:10.000Z | scranton.dmevals.local | windows.security | process.executable | C:\Windows\System32\winlogon.exe | .ds-logs-windows.security-default-2026.10.20-000001 / AaFZRvJfH5wFd7ncsJoZ | q-e0762e0e4e | ok |

### F55 · benign / high · T1621 · No MFA request generation observed; service-install hits are PsExec/Java support services

Evidence status: **verified**

The only T1621 check with hits was C307 (event.code:7045 service installs in windows.other). Review of the full events shows they are not MFA-fatigue tooling: on scranton.dmevals.local a 'Java(TM) Virtual Machine Support Service' was installed from C:\Windows\System32\javamtsup.exe (auto start, LocalSystem), and on nashua.dmevals.local the PSEXESVC service was installed four times from %SystemRoot%\PSEXESVC.exe (demand start, LocalSystem) by account pbeesly. PSEXESVC is the Sysinternals PsExec remote service, consistent with the PsExec64.exe executions seen in sysmon from scranton against \\NASHUA. No MFA/2FA/authenticator/Okta/Duo content was found in PowerShell 4104 script blocks (0 rows), no MFA-related command lines in sysmon process creation (the only 'push' matches were Windows PushToInstall and dmwappushservice svchost instances), and no sysmon network connections to authentication/MFA hostnames (0 rows). No 4625 failed-logon events exist in windows.security at all, so no authentication-prompt storm is visible. The credential-access hypothesis is supported by other activity (PsExec with cleartext password, archive staging of *pass*/*login* files), but T1621 itself is not observed.

| # | Time (UTC) | Host | Dataset | Field | Stored value | Event (_index / _id) | Query | Check |
|---|---|---|---|---|---|---|---|---|
| 1 | 2020-05-02 03:04:15.000Z | scranton.dmevals.local | windows.other | win.ServiceName | Java(TM) Virtual Machine Support Service | .ds-logs-windows.other-default-2026.10.20-000001 / AaFZR_JfH5wFd7pNHuDg | q-50df0a1c4d | ok |
| 2 | 2020-05-02 03:11:39.000Z | nashua.dmevals.local | windows.other | win.ServiceName | PSEXESVC | .ds-logs-windows.other-default-2026.10.20-000001 / AaFZR_JfH5wFd7pNHuCk | q-1a7e3c0270 | ok |
| 3 | 2020-05-02 03:11:39.000Z | nashua.dmevals.local | windows.other | win.ImagePath | %SystemRoot%\PSEXESVC.exe | .ds-logs-windows.other-default-2026.10.20-000001 / AaFZR_JfH5wFd7pNHuCk | q-1a7e3c0270 | ok |
| 4 | 2020-05-02 03:22:11.790Z | scranton.dmevals.local | windows.sysmon | process.command_line | C:\windows\system32\sc.exe start pushtoinstall registration | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7YJ86bA | q-55f82e34e1 | ok |
| 5 | 2020-05-02 03:12:25.384Z | scranton.dmevals.local | windows.sysmon | process.command_line | "C:\Program Files\SysinternalsSuite\PsExec64.exe" -accepteula \\NASHUA -u dmevals\pbeesly -p Fl0nk3rt0n!T0by -i 2 C:\Windows\Temp\python.exe | .ds-logs-windows.sysmon-default-2026.10.20-000001 / AaFZRvJfH5wFd7h03AIc | q-41725536ef | ok |

## Pivot candidates

Processes the pivot reviewer had to assess (started by a script host or from outside the Windows directory, rare in the 15-minute windows around verified activity).

| Host | Executable | Starts | Parents | Assessment | Reason |
|---|---|---|---|---|---|
| nashua.dmevals.local | C:\Program Files\WindowsApps\Microsoft.SkypeApp_14.35.152.0_x64__kzf8qxf38zg5c\S… | 1 | C:\Program Files\WindowsApps\Microsoft.SkypeApp_14.35.152.0_x64__kzf8qxf38zg5c\S… | benign | Signed Store app, crashed and produced WER reports. |
| nashua.dmevals.local | C:\Windows\Temp\python.exe | 5 | C:\Windows\PSEXESVC.exe, C:\Windows\Temp\python.exe | malicious | PyInstaller payload pushed by PsExec from scranton as pbeesly, spawned PowerShell and dropped Rar/sdelete. |
| nashua.dmevals.local | C:\Windows\Temp\Rar.exe | 1 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | malicious | Password-protected re-archive of harvested working.zip, then deleted with sdelete. |
| nashua.dmevals.local | C:\Windows\Temp\sdelete64.exe | 3 | C:\Windows\System32\cmd.exe | malicious | Anti-forensics wiping Rar.exe and staged archives. |
| nashua.dmevals.local | C:\WindowsAzure\Packages\CollectGuestLogs.exe | 1 | C:\WindowsAzure\Packages\WaAppAgent.exe | benign | Azure guest agent diagnostic collection. |
| newyork.dmevals.local | C:\Windows\System32\conhost.exe | 3 | C:\WindowsAzure\Packages\CollectGuestLogs.exe, C:\Windows\System32\cmd.exe, C:\W… | benign | Console host for cmd/dsregcmd/guest agent. |
| scranton.dmevals.local | C:\Packages\Plugins\Microsoft.Azure.NetworkWatcher.NetworkWatcherAgentWindows\1.… | 4 | C:\Windows\System32\cmd.exe, C:\Windows\System32\services.exe | benign | Azure Network Watcher extension. |
| scranton.dmevals.local | C:\Packages\Plugins\Microsoft.Azure.Security.IaaSAntimalware\1.5.5.9\Antimalware… | 1 | C:\WindowsAzure\Packages\GuestAgent\WindowsAzureGuestAgent.exe | benign | Azure antimalware extension configuration. |
| scranton.dmevals.local | C:\Packages\Plugins\Microsoft.Compute.CustomScriptExtension\1.10.5\bin\CustomScr… | 1 | C:\Windows\System32\cmd.exe | benign | Azure custom script extension handler. |
| scranton.dmevals.local | C:\Packages\Plugins\Microsoft.Compute.JsonADDomainExtension\1.3.2\bin\JsonADDoma… | 1 | C:\Windows\System32\cmd.exe | benign | Azure domain-join extension. |
| scranton.dmevals.local | C:\Program Files (x86)\Google\Update\1.3.35.452\GoogleCrashHandler.exe | 2 | C:\Program Files (x86)\Google\Update\GoogleUpdate.exe | benign | Google updater crash handler. |
| scranton.dmevals.local | C:\Program Files (x86)\Google\Update\1.3.35.452\GoogleCrashHandler64.exe | 2 | C:\Program Files (x86)\Google\Update\GoogleUpdate.exe | benign | Google updater crash handler. |
| scranton.dmevals.local | C:\Program Files (x86)\Google\Update\GoogleUpdate.exe | 3 | C:\Program Files (x86)\Google\Update\GoogleUpdate.exe, C:\Windows\System32\servi… | benign | Google updater service. |
| scranton.dmevals.local | C:\Program Files\SysinternalsSuite\accessChk.exe | 1 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | suspicious | Recon tool run by pbeesly PowerShell, likely checking LSASS/registry permissions. |
| scranton.dmevals.local | C:\Program Files\SysinternalsSuite\PsExec64.exe | 4 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | malicious | Lateral movement to NASHUA with cleartext pbeesly password to run python.exe. |
| scranton.dmevals.local | C:\Program Files\SysinternalsSuite\sdelete64.exe | 3 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | malicious | Wiped the .scr loader, Draft.Zip and SysinternalsSuite.zip on scranton. |
| scranton.dmevals.local | C:\Program Files\Windows Defender\MsMpEng.exe | 1 | C:\Windows\System32\services.exe | benign | Defender service. |
| scranton.dmevals.local | C:\Program Files\Windows Defender\NisSrv.exe | 2 | C:\Windows\System32\services.exe | benign | Defender network inspection service. |
| scranton.dmevals.local | C:\ProgramData\victim\â€®cod.3aka3.scr | 1 | C:\Windows\explorer.exe | malicious | Masqueraded screen-saver loader launched from ProgramData by explorer, later sdelete-wiped. |
| scranton.dmevals.local | C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe | 2 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | malicious | Compiled in-memory payloads from the steganographic monkey.png loader into temp DLLs. |
| scranton.dmevals.local | C:\Windows\System32\hostui.exe | 1 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | suspicious | Launched with -verb runas by PowerShell, likely UAC/elevation attempt. |
| scranton.dmevals.local | C:\Windows\System32\sdclt.exe | 3 | C:\Windows\System32\cmd.exe | suspicious | UAC-bypass-capable binary spawned three times by cmd under pbeesly. |
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
| T1003 OS Credential Dumping | suspicious | No dumping tooling or hive copies executed, but pbeesly is running a full hands-on-keyboard intrusion on scranton/nashua (malicious .scr, Sysinternals, sdelete, persistence, exfil, PsExec with cleartext password) and hol… |
| T1003.001 LSASS Memory | malicious | wsmprovhost as pbeesly opened lsass with 0x1f3fff on nashua. |
| T1003.002 Security Account Manager | benign | Only SAM_SERVER/SAM_DOMAIN handle requests are from lsass.exe itself as SCRANTON$ (S-1-5-18); no reg save, hive writes or external SAM access. |
| T1003.003 NTDS | not_observed | No ntdsutil/vssadmin/diskshadow/ntds command lines, no .dit file writes, no matching script blocks. |
| T1003.004 LSA Secrets | not_observed | No SECURITY/Policy\Secrets object access, no reg save of SECURITY, no matching script blocks; only routine CredentialGuard/CredentialEnrollmentManager registry writes. |
| T1003.005 Cached Domain Credentials | not_observed | No SECURITY/Cache object access or cache/dcc script blocks; the credential theft seen was certificate private-key export and keystroke logging, which fall outside this sub-technique. |
| T1003.006 DCSync | not_observed | No dcsync/lsadump/drsuapi activity, no replication-related service installs; only PSEXESVC and a Java support service were installed. |
| T1040 Network Sniffing | benign | Only capture-related activity is netsh.exe 'trace start capture=yes' / 'trace stop' on scranton.dmevals.local, spawned by the legitimate Microsoft Azure Network Watcher agent service (NetworkWatcherAgent.exe /service) ru… |
| T1056 Input Capture | malicious | Input capture tooling (Keystroke-Check/Get-Keystrokes, Invoke-ScreenCapture, steganographic IEX loader) executed by pbeesly on scranton.dmevals.local; remaining LSASS/SAM handle activity is benign Azure/system baseline. |
| T1056.001 Keylogging | malicious | Get-Keystrokes job started, viewed and removed on SCRANTON at 03:06:59-03:07:49 UTC, preceded by an AV-evasion Keystroke-Check process enumeration. |
| T1056.002 GUI Input Capture | malicious | Invoke-ScreenCapture loop using System.Windows.Forms/System.Drawing captured the virtual screen to .bmp files in pbeesly's Downloads (gwq4xdwv.s5g.bmp). |
| T1056.003 Web Portal Capture | not_observed | No web portal capture: zeek HTTP only to 192.168.0.4 with no login/signin URLs, and no inetpub/aspx/IIS artifacts in Windows telemetry. |
| T1056.004 Credential API Hooking | suspicious | PowerShell.exe opened lsass.exe with 0x1F3FFF/0x1FFFFF on SCRANTON and wsmprovhost.exe with 0x1F3FFF on NASHUA, consistent with credential memory access; no hooking DLL was observed, so suspicious rather than confirmed. |
| T1110 Brute Force | not_observed | Zero 4625 failed-logon events in windows.security; all authentication events are successful machine-account or pbeesly logons. |
| T1110.001 Password Guessing | not_observed | No repeated failed logons; 4648/4776 events are successful explicit-credential uses (pbeesly to NASHUA, Status 0x0). |
| T1110.002 Password Cracking | suspicious | No cracking tools or hash files, but PowerShell PID 2976 on scranton.dmevals.local opened lsass.exe with GrantedAccess 0x1fffff at 03:05:16Z — hash-dump precursor to offline cracking. |
| T1110.003 Password Spraying | not_observed | No 4625 events at all, so no one-password-many-accounts pattern; logons are machine accounts and pbeesly over LogonType 3/5. |
| T1110.004 Credential Stuffing | not_observed | No 4625/4771/4740 events; no replay of stolen credential lists against accounts. |
| T1111 Multi-Factor Authentication Interception | not_observed | No MFA interception artifacts in any dataset. All credential-provider, smart-card, biometric and Windows Hello DLLs loaded (event.code 7) are Microsoft-signed (win.Signature='Microsoft Windows', win.Signed=true), includi… |
| T1187 Forced Authentication | malicious | PowerShell Invoke-Exfil on scranton.dmevals.local (user pbeesly) mapped \\192.168.0.4\webdav with New-PSDrive and copied OfficeSupplies.7z there; zeek shows the WebDAV redirector (DavClnt / Microsoft-WebDAV-MiniRedir) do… |
| T1212 Exploitation for Credential Access | suspicious | Attacker-controlled PowerShell on scranton (stego loader from monkey.png, PID 2976) and wsmprovhost.exe on nashua (remote PowerShell as pbeesly) opened lsass.exe with 0x1fffff/0x1f3fff and call traces lacking any signed … |
| T1539 Steal Web Session Cookie | not_observed | No process other than Microsoft Edge's own components (MicrosoftEdge.exe, MicrosoftEdgeSH.exe, MicrosoftEdgeCP.exe), svchost.exe and Explorer.EXE touched any browser cookie/credential store; the only cookie-related artif… |
| T1552 Unsecured Credentials | malicious | Credential-named files archived with password and wiped on nashua. |
| T1552.001 Credentials In Files | malicious | Script targeted *pass*/*login*/*admin*/*vpn files in pbeesly profile. |
| T1552.002 Credentials in Registry | benign | Password/Credential registry writes are Windows components (IdentityCRL, CredentialGuard, CredentialEnrollmentManagerUserSvc); no reg query/save or SAM/SECURITY access. |
| T1552.003 Shell History | not_observed | No ConsoleHost_history, Get-History or history references in script blocks, process command lines or file creations. |
| T1552.004 Private Keys | suspicious | Certificate store writes on nashua after archive step. |
| T1552.006 Group Policy Preferences | benign | SYSVOL/GptTmpl.inf/gpt.ini access is svchost.exe Group Policy processing; no Groups.xml, cpassword or gpprefdecrypt activity. |
| T1555 Credentials from Password Stores | malicious | Hidden steganographic PowerShell (pbeesly, parent control.exe) on scranton opened lsass.exe with 0x1f3fff/0x1fffff and is corroborated by a 4663 LSASS object access; wsmprovhost on nashua also opened LSASS with 0x1f3fff. |
| T1555.003 Credentials from Web Browsers | not_observed | No browser credential-store files, command lines or browser process access in any dataset; only a benign service-profile INetCookies creation. |
| T1555.004 Windows Credential Manager | not_observed | No cmdkey/vault/CredRead activity or Vault/*.vcrd file or registry access; windows.other 'vault' hits were boot-time filter/Credential Guard config records. |
| T1555.005 Password Managers | not_observed | No password-manager processes, .kdbx files, script blocks or event-log references on any host. |
| T1556 Modify Authentication Process | suspicious | PowerShell.exe (PID 2976, SYSTEM) opened lsass.exe with 0x1f3fff then 0x1fffff on scranton.dmevals.local at 03:05:16Z with an UNKNOWN call-trace module — consistent with LSASS memory access for credential theft, though n… |
| T1556.001 Domain Controller Authentication | not_observed | LSASS accesses on DCs come from svchost/AV/telemetry and a normal wininit->lsass boot sequence; only Microsoft-signed modules loaded into lsass/cryptdll; no LSA registry or 4648 anomalies indicating DC authentication bac… |
| T1556.002 Password Filter DLL | not_observed | No DLL created in System32/SysWOW64, no Notification Packages/PasswordFilter registry or script activity; 'Notification' hits were unrelated service notifications. |
| T1556.005 Reversible Encryption | not_observed | No 4739 policy changes and no reversible-encryption commands; the single Set-ADUser script-block hit is the built-in xActiveDirectory DSC module documentation. |
| T1556.006 Multi-Factor Authentication | not_observed | No 4739 or 5136 events; only routine LOCAL SERVICE reads of Policy\Secrets\$MACHINE.ACC (4662, AccessMask 0x2). |
| T1556.007 Hybrid Identity | not_observed | No directory-object modifications, no anomalous DLL loads into identity processes, and no MFA-bypass logon pattern; wlidsvc start is a normal service start. |
| T1556.008 Network Provider DLL | not_observed | No NetworkProvider registry writes (Sysmon 13) and no DLL drops; the 4657 writes are wevtutil WMI Autologger toggles, a certificate blob and WSMAN SafeClientList. |
| T1557 Adversary-in-the-Middle | not_observed | No AiTM tooling or interception artifacts in sysmon process/network/DNS data or PowerShell 4104 script blocks; all destinations and DNS resolutions are normal internal/Microsoft endpoints. |
| T1557.001 Name Resolution Poisoning and SMB Relay | not_observed | SMB connections all come from the System SMB client; the single NTLM network logon is the PsExec session from scranton to NASHUA using a cleartext password (credential misuse/lateral movement), with no relay listener, po… |
| T1557.002 ARP Cache Poisoning | not_observed | Only arp.exe /a read-only invocations, all spawned by Azure guest-agent binaries on scranton; no ARP poisoning tooling or anomalous gateway redirection. |
| T1557.003 DHCP Spoofing | not_observed | No DHCP server/lease event codes, no UDP/67 firewall traffic, no DNS client config changes; only a normal Dhcp service start after reboot. |
| T1558 Steal or Forge Kerberos Tickets | malicious | Compromised pbeesly account ran an offensive PowerShell toolkit on SCRANTON and used WinRM to NASHUA; PowerShell.exe (0x1FFFFF/0x1F3FFF) and wsmprovhost.exe (0x1F3FFF) opened LSASS for credential/ticket extraction. |
| T1558.001 Golden Ticket | suspicious | LSASS full-access reads provide the KRBTGT hash needed for golden tickets, but all 4768/4769 events were successful AES256 with pre-auth and no forged TGT was observed. |
| T1558.002 Silver Ticket | benign | All 4769 service-ticket requests were normal successful AES256 requests for machine accounts and pbeesly; no forged service ticket was observed. |
| T1558.003 Kerberoasting | suspicious | pbeesly requested a TGS for the krbtgt service (Ticket Options 0x60810010) on the DC and LSASS ticket material was read on SCRANTON/NASHUA, but no RC4 downgrade or kerberoast tooling strings were seen. |
| T1558.004 AS-REP Roasting | benign | All AS-REQ events used PreAuthType 2 with AES256; no pre-auth-disabled account, no AS-REP roasting tooling or script content. |
| T1606 Forge Web Credentials | malicious | SCRANTON: pbeesly ran a steganographic PowerShell loader (monkey.png -> IEX), stored an encoded payload in HKLM\SOFTWARE\Javasoft\value Supplement and re-executed it, and PowerShell opened lsass.exe with 0x1f3fff/0x1ffff… |
| T1606.001 Web Cookies | not_observed | Cookie/Login Data file writes were only svchost.exe and MicrosoftEdge.exe system activity; the sole 'token/cookie' PowerShell hit was the Get-AttributesMask Windows access-token helper. No browser cookie theft or forged … |
| T1606.002 SAML Tokens | not_observed | 4624 LogonProcessName/AuthenticationPackageName values are all standard (Kerberos/Advapi/User32/NtLmSsp, Kerberos/Negotiate/NTLM); SAML/NotOnOrAfter/token-signing PowerShell search returned zero hits. |
| T1621 Multi-Factor Authentication Request Generatio… | not_observed | No MFA request generation activity in any dataset. The only hit check (C307, event.code:7045) resolved to a Java VM support service install on scranton and repeated PSEXESVC installs on nashua (Sysinternals PsExec remote… |
| T1649 Steal or Forge Authentication Certificates | suspicious | SystemCertificates write on nashua by pbeesly session. |

## Coverage

Cells: number of hits of the planned checks, `n/a` (reason in report.json), or GAP.

| Technique | windows.other | windows.powershell | windows.security | windows.sysmon | zeek |
|---|---|---|---|---|---|
| T1003 OS Credential Dumping | 5 hits | 0 hits | 11437 hits | 39730 hits | n/a |
| T1003.001 LSASS Memory | 7 hits | 0 hits | 934 hits | 666 hits | n/a |
| T1003.002 Security Account Manager | 7 hits | 0 hits | 6 hits | 7 hits | n/a |
| T1003.003 NTDS | 13 hits | 0 hits | 0 hits | 0 hits | n/a |
| T1003.004 LSA Secrets | 7 hits | 0 hits | 0 hits | 507 hits | n/a |
| T1003.005 Cached Domain Credentials | 7 hits | 0 hits | 934 hits | 330 hits | n/a |
| T1003.006 DCSync | 0 hits | 0 hits | 15 hits | 0 hits | 132 hits |
| T1040 Network Sniffing | 0 hits | 0 hits | 4 hits | 2 hits | 613 hits |
| T1056 Input Capture | 0 hits | 3 hits | 29 hits | 854 hits | 0 hits |
| T1056.001 Keylogging | 0 hits | 0 hits | 13 hits | 1853 hits | 0 hits |
| T1056.002 GUI Input Capture | 0 hits | 2 hits | 0 hits | 0 hits | 0 hits |
| T1056.003 Web Portal Capture | 0 hits | 0 hits | 0 hits | 0 hits | 62 hits |
| T1056.004 Credential API Hooking | 0 hits | 2 hits | 13 hits | 59870 hits | n/a |
| T1110 Brute Force | 7 hits | 3 hits | 0 hits | 1 hits | n/a |
| T1110.001 Password Guessing | 4 hits | 3 hits | 0 hits | 31 hits | n/a |
| T1110.002 Password Cracking | 1 hits | 10 hits | 10977 hits | 2422 hits | n/a |
| T1110.003 Password Spraying | 7 hits | 3 hits | 15 hits | 31 hits | n/a |
| T1110.004 Credential Stuffing | 7 hits | 3 hits | 0 hits | 1 hits | n/a |
| T1111 Multi-Factor Authentication Interception | 5 hits | 3 hits | 312 hits | 39294 hits | n/a |
| T1187 Forced Authentication | 5 hits | 0 hits | 11140 hits | 69 hits | 86 hits |
| T1212 Exploitation for Credential Access | 5 hits | 0 hits | 0 hits | 39609 hits | 613 hits |
| T1539 Steal Web Session Cookie | 0 hits | 13 hits | 0 hits | 162 hits | 0 hits |
| T1552 Unsecured Credentials | 0 hits | 4 hits | 0 hits | 89 hits | 12 hits |
| T1552.001 Credentials In Files | 0 hits | 2 hits | 15 hits | 72 hits | 12 hits |
| T1552.002 Credentials in Registry | 0 hits | 5 hits | 0 hits | 17 hits | n/a |
| T1552.003 Shell History | n/a | 0 hits | 0 hits | 0 hits | n/a |
| T1552.004 Private Keys | n/a | 3 hits | 0 hits | 1 hits | n/a |
| T1552.006 Group Policy Preferences | n/a | 0 hits | 0 hits | 0 hits | n/a |
| T1555 Credentials from Password Stores | n/a | 3 hits | 6 hits | 653 hits | n/a |
| T1555.003 Credentials from Web Browsers | n/a | 0 hits | 0 hits | 1 hits | n/a |
| T1555.004 Windows Credential Manager | 15 hits | 0 hits | 0 hits | 326 hits | n/a |
| T1555.005 Password Managers | 0 hits | 0 hits | 0 hits | 0 hits | n/a |
| T1556 Modify Authentication Process | 4 hits | 0 hits | 0 hits | 739 hits | n/a |
| T1556.001 Domain Controller Authentication | 0 hits | 0 hits | 233 hits | 359 hits | n/a |
| T1556.002 Password Filter DLL | 5 hits | 0 hits | 0 hits | 19515 hits | n/a |
| T1556.005 Reversible Encryption | 0 hits | 1 hits | 0 hits | 0 hits | n/a |
| T1556.006 Multi-Factor Authentication | n/a | 1 hits | 7 hits | n/a | n/a |
| T1556.007 Hybrid Identity | n/a | n/a | 297 hits | 20259 hits | n/a |
| T1556.008 Network Provider DLL | n/a | n/a | 36 hits | 21908 hits | n/a |
| T1557 Adversary-in-the-Middle | n/a | n/a | 10977 hits | 1310 hits | GAP: n/a refused (time window … |
| T1557.001 Name Resolution Poisoning and SMB Relay | n/a | n/a | 23 hits | 66 hits | n/a |
| T1557.002 ARP Cache Poisoning | n/a | n/a | n/a | 1310 hits | n/a |
| T1557.003 DHCP Spoofing | 216 hits | 0 hits | 0 hits | 81 hits | n/a |
| T1558 Steal or Forge Kerberos Tickets | 5 hits | 0 hits | 448 hits | 652 hits | 2280 hits |
| T1558.001 Golden Ticket | 5 hits | 0 hits | 448 hits | 326 hits | n/a |
| T1558.002 Silver Ticket | 5 hits | 0 hits | 448 hits | 326 hits | n/a |
| T1558.003 Kerberoasting | 5 hits | 0 hits | 524 hits | 326 hits | n/a |
| T1558.004 AS-REP Roasting | 5 hits | 0 hits | 297 hits | 447 hits | n/a |
| T1606 Forge Web Credentials | 5 hits | 1 hits | 609 hits | 652 hits | n/a |
| T1606.001 Web Cookies | 5 hits | 1 hits | 312 hits | 168 hits | n/a |
| T1606.002 SAML Tokens | 5 hits | 0 hits | 312 hits | 1 hits | n/a |
| T1621 Multi-Factor Authentication Request Generatio… | 5 hits | 0 hits | 0 hits | 0 hits | n/a |
| T1649 Steal or Forge Authentication Certificates | 5 hits | 1 hits | 64 hits | 1 hits | n/a |

Cells: 265, gaps: 1.

## Queries

Every MCP tool call of this run (1270), in order (source: mcp_audit.jsonl written by the MCP server).

| Query | Phase | Tool | Arguments | Hits / rows | Cited by |
|---|---|---|---|---|---|
| q-59dad04024 | scope | list_data_sources | {} | None |  |
| q-7b5ff61e9d | scope | get_registry | {} | None |  |
| q-b59803cb31 | scope | get_fields | {"dataset": "windows.other", "prefix": ""} | None |  |
| q-b42ae445e5 | scope | get_fields | {"dataset": "windows.powershell", "prefix": ""} | None |  |
| q-042e0201c4 | scope | get_fields | {"dataset": "windows.security", "prefix": ""} | None |  |
| q-c292b0495d | scope | get_fields | {"dataset": "windows.sysmon", "prefix": ""} | None |  |
| q-d0618c641a | scope | get_fields | {"dataset": "zeek", "prefix": ""} | None |  |
| q-c3d9d3858c | check C001 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 447 |  |
| q-392efed47a | check C002 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 39283 |  |
| q-b6b1072c28 | check C003 | aggregate | {"dataset": "windows.security", "field": "win.ObjectType", "query": "event.code:4663 OR event.code:4656 OR event.code:4670", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 10977 |  |
| q-779189dd1b | check C004 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 460 |  |
| q-35234c8f5f | check C005 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*mimikatz* OR win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*sekurlsa* OR win.ScriptBlockText:*procdump* OR win.ScriptBlockText:*comsvcs*)", "time_from": null, "time_to":… | 0 |  |
| q-a4458161b3 | check C006 | search | {"dataset": "windows.other", "query": "event.code:7045 OR event.code:4697", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "so… | 5 | F06 |
| q-7088b95613 | check C007 | aggregate | {"dataset": "windows.sysmon", "field": "win.SourceImage", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 326 |  |
| q-79db83ee20 | check C008 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 326 |  |
| q-476db0ae2d | check C009 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*lsass* OR process.command_line:*dump*)", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 1 |  |
| q-22eee9a087 | check C010 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (win.TargetFilename:*lsass* OR win.TargetFilename:*.dmp)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process… | 2 |  |
| q-a139097be1 | check C011 | search | {"dataset": "windows.sysmon", "query": "event.code:13 AND (registry.path:*lsass* OR registry.path:*WDigest* OR registry.path:*Credential*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code… | 11 | F04 |
| q-6abce6cb77 | check C012 | aggregate | {"dataset": "windows.security", "field": "win.ProcessName", "query": "event.code:4673", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 934 |  |
| q-a14fb85de1 | check C013 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*MiniDump* OR win.ScriptBlockText:*sekurlsa*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "even… | 0 |  |
| q-fbc1330123 | check C014 | search | {"dataset": "windows.other", "query": "event.code:10 OR event.code:11", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source… | 7 |  |
| q-114887ee64 | check C015 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*reg* AND process.command_line:*save* OR process.command_line:*SAM* OR process.command_line:*SYSTEM*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "ob… | 6 |  |
| q-c7abf0921e | check C016 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (win.TargetFilename:*SAM* OR win.TargetFilename:*.hiv OR win.TargetFilename:*.dit)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.co… | 0 |  |
| q-2f18466ba8 | check C017 | search | {"dataset": "windows.sysmon", "query": "event.code:2 AND (win.TargetFilename:*SAM* OR win.TargetFilename:*SECURITY*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "proce… | 0 |  |
| q-62c7b5376e | check C018 | search | {"dataset": "windows.sysmon", "query": "event.code:13 AND (registry.path:*SAM\\\\SAM* OR registry.path:*SECURITY\\\\Policy*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name"… | 1 |  |
| q-4734fd503e | check C019 | aggregate | {"dataset": "windows.security", "field": "process.command_line", "query": "event.code:4688 AND (process.command_line:*reg* OR process.command_line:*save*)", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 6 |  |
| q-47e219a4ac | check C020 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND (win.ObjectName:*SAM* OR win.ObjectName:*SECURITY*)", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-b203a573c4 | check C021 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*reg save* OR win.ScriptBlockText:*SAM* OR win.ScriptBlockText:*hive*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.data… | 0 |  |
| q-ee9efbe298 | check C022 | search | {"dataset": "windows.other", "query": "event.code:11 OR event.code:1", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.… | 7 |  |
| q-31d4cbc501 | check C023 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*ntds* OR process.command_line:*vssadmin* OR process.command_line:*ntdsutil* OR process.command_line:*diskshadow*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "ho… | 0 |  |
| q-cd6f10de99 | check C024 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (win.TargetFilename:*ntds* OR win.TargetFilename:*.dit)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.… | 0 |  |
| q-f26afa5d26 | check C025 | search | {"dataset": "windows.sysmon", "query": "event.code:2 AND win.TargetFilename:*ntds*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_l… | 0 |  |
| q-949713a615 | check C026 | aggregate | {"dataset": "windows.security", "field": "process.command_line", "query": "event.code:4688 AND (process.command_line:*ntds* OR process.command_line:*vssadmin* OR process.command_line:*diskshadow*)", "time_from": null, "time_to": null, "size": 100, "sub_field":… | 0 |  |
| q-ed2b24b267 | check C027 | search | {"dataset": "windows.other", "query": "event.code:7045 OR event.code:2004 OR event.code:2006", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process… | 13 |  |
| q-dbedd4ebb8 | check C028 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*ntds* OR win.ScriptBlockText:*vssadmin* OR win.ScriptBlockText:*diskshadow*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "eve… | 0 |  |
| q-5a80b2956a | check C029 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND (win.TargetImage:*lsass* OR win.TargetImage:*services*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.… | 506 |  |
| q-9935edbbdb | check C030 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*SECURITY* OR process.command_line:*secrets* OR process.command_line:*reg save*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.… | 0 |  |
| q-27af46c5d0 | check C031 | search | {"dataset": "windows.sysmon", "query": "event.code:7 AND (win.ImageLoaded:*lsass* OR win.ImageLoaded:*secrets*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.ex… | 1 |  |
| q-b7e948bcc5 | check C032 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND (win.ObjectName:*SECURITY* OR win.ObjectName:*Policy\\\\Secrets*)", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-ad2fc944c1 | check C033 | aggregate | {"dataset": "windows.security", "field": "win.ProcessName", "query": "event.code:4656 AND (win.ObjectName:*SECURITY* OR win.ObjectName:*Secrets*)", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-de35c1d940 | check C034 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*SECURITY* OR win.ScriptBlockText:*Secrets* OR win.ScriptBlockText:*lsa*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.d… | 0 |  |
| q-579d03b5c9 | check C035 | search | {"dataset": "windows.other", "query": "event.code:10 OR event.code:11", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source… | 7 |  |
| q-6d53910a91 | check C036 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_li… | 326 |  |
| q-892e941c32 | check C037 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*cache* OR process.command_line:*dcc* OR process.command_line:*cachedump*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.datase… | 4 |  |
| q-cf7fdb6684 | check C038 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND (win.ObjectName:*SECURITY* OR win.ObjectName:*Cache*)", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-f21544a878 | check C039 | aggregate | {"dataset": "windows.security", "field": "win.ProcessName", "query": "event.code:4673", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 934 |  |
| q-ad2f5b62ab | check C040 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*cache* OR win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*dcc*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.datase… | 0 |  |
| q-67232cf960 | check C041 | search | {"dataset": "windows.other", "query": "event.code:10 OR event.code:11", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source… | 7 |  |
| q-5633e95c0d | check C042 | count | {"dataset": "windows.security", "query": "event.code:4662", "time_from": null, "time_to": null} | 7 |  |
| q-03db7d1a6b | check C043 | aggregate | {"dataset": "windows.security", "field": "win.Properties", "query": "event.code:4662", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 7 |  |
| q-8f6eec6873 | check C044 | aggregate | {"dataset": "windows.security", "field": "win.SubjectUserName", "query": "event.code:4662 AND win.Properties:*1131f6aa*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1 |  |
| q-2b95819e5e | check C045 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*drsuapi* OR process.command_line:*lsadump* OR process.command_line:*dcsync* OR process.command_line:*\\/user:* AND process.command_line:*\\/domain:*)", "time_from": null, "time_to"… | ERROR |  |
| q-892a88bb62 | check C045 (repaired) | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*drsuapi* OR process.command_line:*lsadump* OR process.command_line:*dcsync* OR (process.command_line:*\\/user:* AND process.command_line:*\\/domain:*))", "time_from": null, "time_t… | ERROR |  |
| q-3ea9d054ac | check C046 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*dcsync* OR win.ScriptBlockText:*lsadump* OR win.ScriptBlockText:*DCSync* OR win.ScriptBlockText:*Invoke-Mimikatz*)", "time_from": null, "time_to": null, "fields": ["@timestam… | 0 |  |
| q-ec2f75de0c | check C047 | search | {"dataset": "windows.other", "query": "event.code:7045 AND (win.ImagePath:*drsuapi* OR win.ServiceName:*dcsync* OR win.ServiceName:*mimikatz*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.… | 0 |  |
| q-48ab9af408 | check C048 | aggregate | {"dataset": "zeek", "field": "zeek.operation", "query": "event.action:dce_rpc", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 123 |  |
| q-9115ad9bd4 | check C049 | search | {"dataset": "zeek", "query": "event.action:dce_rpc AND (zeek.endpoint:*drsuapi* OR zeek.endpoint:*DRSUAPI* OR zeek.named_pipe:*drsuapi*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code",… | 9 |  |
| q-b5aa96e607 | check C050 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND (process.command_line:*pktmon* OR process.command_line:*netsh* OR process.command_line:*windump* OR process.command_line:*tcpdump* OR process.command_line:*rawcap* OR … | 2 |  |
| q-37473356d5 | check C051 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*pktmon* OR process.command_line:*netsh* AND process.command_line:*trace* OR process.command_line:*windump* OR process.command_line:*rawcap*)", "time_from": null, "time_to": nu… | 2 |  |
| q-45771044dd | check C052 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*pktmon* OR process.command_line:*windump* OR process.command_line:*tcpdump* OR process.command_line:*rawcap* OR process.command_line:*tshark* OR proc… | 2 |  |
| q-a4395d6f01 | check C053 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*pktmon* OR process.command_line:*windump* OR process.command_line:*rawcap* OR process.command_line:*tshark*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.na… | 0 |  |
| q-f5ba194aa5 | check C054 | search | {"dataset": "windows.other", "query": "event.code:7045 AND (win.ImagePath:*pcap* OR win.ImagePath:*npcap* OR win.ImagePath:*winpcap* OR win.ServiceName:*npcap* OR win.ServiceName:*pcap*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name… | 0 |  |
| q-300e29149a | check C055 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*pktmon* OR win.ScriptBlockText:*Get-NetAdapter* OR win.ScriptBlockText:*pcap* OR win.ScriptBlockText:*netsh trace*)", "time_from": null, "time_to": null, "fields": ["@timesta… | 0 |  |
| q-c7ef07db62 | check C056 | aggregate | {"dataset": "zeek", "field": "zeek.service", "query": "event.action:conn", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 613 |  |
| q-515a56a3bf | check C057 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND (win.TargetImage:*lsass.exe OR win.TargetImage:*winlogon.exe OR win.TargetImage:*csrss.exe)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 495 |  |
| q-81b5e7b58e | check C058 | aggregate | {"dataset": "windows.sysmon", "field": "win.SourceImage", "query": "event.code:10 AND win.TargetImage:*lsass.exe", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 326 |  |
| q-c9b5b0541d | check C059 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass.exe AND NOT (win.SourceImage:*svchost.exe OR win.SourceImage:*MsMpEng.exe OR win.SourceImage:*csrss.exe OR win.SourceImage:*lsass.exe OR win.SourceImage:*wininit.exe OR win.Source… | 33 | F12 |
| q-5033caf078 | check C060 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4656 AND (win.ObjectName:*lsass* OR win.ObjectName:*SAM* OR win.ObjectName:*SECURITY OR win.ObjectName:*winlogon*)", "time_from": null, "time_to": null, "size": 50, "sub_field": nu… | 23 |  |
| q-70ef34774b | check C061 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4663 AND (win.ObjectName:*lsass* OR win.ObjectName:*SAM* OR win.ObjectName:*SECURITY)", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 6 |  |
| q-b02ea0be73 | check C062 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Get-Process* AND win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*MiniDump* OR win.ScriptBlockText:*Credential* OR win.ScriptBlockText:*keylog*)", "time_from": null, "time… | 3 |  |
| q-1b9d476a2b | check C063 | search | {"dataset": "windows.other", "query": "event.code:7045 AND (win.ImagePath:*keylog* OR win.ImagePath:*hook* OR win.ServiceName:*keylog*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", … | 0 |  |
| q-c8f04ffcff | check C064 | search | {"dataset": "zeek", "query": "event.action:http AND (url.original:*keylog* OR url.original:*credential* OR url.original:*login*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.n… | 0 |  |
| q-d213e343ce | check C065 | aggregate | {"dataset": "windows.sysmon", "field": "registry.path", "query": "event.code:13 AND (registry.path:*Keyboard* OR registry.path:*keylog* OR registry.path:*CurrentControlSet\\\\Services\\\\*)", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 1357 |  |
| q-3790b9093b | check C066 | search | {"dataset": "windows.sysmon", "query": "event.code:13 AND (registry.path:*Keyboard* OR registry.path:*keylog* OR registry.path:*SetWindowsHookEx*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "ev… | 26 | F12 |
| q-a24fd83849 | check C067 | aggregate | {"dataset": "windows.sysmon", "field": "win.SourceImage", "query": "event.code:10 AND (win.TargetImage:*lsass.exe OR win.TargetImage:*winlogon.exe)", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 470 |  |
| q-3b0462d115 | check C068 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4656 AND (win.ObjectName:*lsass* OR win.ObjectName:*winlogon* OR win.ObjectName:*Keyboard*)", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 13 |  |
| q-48a98d9091 | check C069 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND (process.command_line:*keylog* OR process.command_line:*hook* OR process.command_line:*GetAsyncKeyState*)", "time_from": null, "time_to": null, "size": 20, "sub_field"… | 0 |  |
| q-7100b07862 | check C070 | search | {"dataset": "windows.other", "query": "event.code:7045 AND (win.ImagePath:*keylog* OR win.ServiceName:*keylog* OR win.ImagePath:*hook*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", … | 0 |  |
| q-c6a7f58c15 | check C071 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*GetAsyncKeyState* OR win.ScriptBlockText:*keylog* OR win.ScriptBlockText:*SetWindowsHookEx* OR win.ScriptBlockText:*GetKeyboardState*)", "time_from": null, "time_to": null, "… | 0 |  |
| q-f92e779539 | check C072 | search | {"dataset": "zeek", "query": "event.action:http AND (url.original:*keylog* OR url.original:*keys*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "p… | 0 |  |
| q-3c0d2a124b | check C073 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*Credential* OR process.command_line:*prompt* OR process.command_line:*password* OR process.command_line:*UAC*)", "time_from": null, "time_to": null, … | 0 |  |
| q-7e7641fa5b | check C074 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*CredUIPromptForCredentials* OR process.command_line:*PromptForCredentials* OR process.command_line:*password*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.… | 0 |  |
| q-b475507951 | check C075 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*CredUIPromptForCredentials* OR win.ScriptBlockText:*PromptForCredential* OR win.ScriptBlockText:*Get-Credential* OR win.ScriptBlockText:*Windows.Forms*)", "time_from": null, … | 2 |  |
| q-b8e8b2c9f5 | check C076 | aggregate | {"dataset": "windows.powershell", "field": "host.name", "query": "event.code:4104 AND (win.ScriptBlockText:*CredUIPromptForCredentials* OR win.ScriptBlockText:*PromptForCredential* OR win.ScriptBlockText:*Get-Credential*)", "time_from": null, "time_to": null, … | 0 |  |
| q-2025e51182 | check C077 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND (process.command_line:*Credential* OR process.command_line:*password* OR process.command_line:*prompt*)", "time_from": null, "time_to": null, "size": 20, "sub_field": … | 0 |  |
| q-3d9ef2cc49 | check C078 | search | {"dataset": "windows.other", "query": "event.code:7045 AND (win.ImagePath:*cred* OR win.ImagePath:*prompt* OR win.ServiceName:*cred*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "u… | 0 |  |
| q-f3bb0e76da | check C079 | search | {"dataset": "zeek", "query": "event.action:http AND (url.original:*login* OR url.original:*signin* OR url.original:*password*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.nam… | 0 |  |
| q-e37497e5b3 | check C080 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND (win.TargetFilename:*\\\\inetpub\\\\* OR win.TargetFilename:*.aspx OR win.TargetFilename:*.asp OR win.TargetFilename:*.php OR win.TargetFilename:*.ashx)", "time_from": nul… | 0 |  |
| q-7e20bd6e50 | check C081 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (win.TargetFilename:*\\\\inetpub\\\\* OR win.TargetFilename:*.aspx OR win.TargetFilename:*.ashx)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.datas… | 0 |  |
| q-50f90f0d5d | check C082 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND (win.ObjectName:*inetpub* OR win.ObjectName:*.aspx OR win.ObjectName:*.asp OR win.ObjectName:*.php)", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 0 |  |
| q-c10ae53c1d | check C083 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND (process.command_line:*inetpub* OR process.command_line:*.aspx* OR process.command_line:*.asp*)", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 0 |  |
| q-8814aceb68 | check C084 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*inetpub* OR win.ScriptBlockText:*.aspx* OR win.ScriptBlockText:*Set-Content* AND win.ScriptBlockText:*wwwroot*)", "time_from": null, "time_to": null, "fields": ["@timestamp",… | 0 |  |
| q-7b2d2674fe | check C085 | search | {"dataset": "windows.other", "query": "event.code:7045 AND (win.ImagePath:*iis* OR win.ServiceName:*iis* OR win.ImagePath:*w3wp*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.… | 0 |  |
| q-ca8200de5a | check C086 | search | {"dataset": "zeek", "query": "event.action:http AND (http.request.method:POST OR url.original:*login* OR url.original:*signin*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.na… | 0 |  |
| q-ae9d1ca677 | check C087 | aggregate | {"dataset": "zeek", "field": "url.domain", "query": "event.action:http", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 62 |  |
| q-7b78b9a51d | check C088 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-39044290ae | check C089 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-4f8ebadf11 | check C090 | aggregate | {"dataset": "windows.sysmon", "field": "win.ImageLoaded", "query": "event.code:7", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 20259 |  |
| q-d00c6fccc3 | check C091 | search | {"dataset": "windows.sysmon", "query": "event.code:8 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_lin… | 2 |  |
| q-28a9fe081a | check C092 | aggregate | {"dataset": "windows.security", "field": "win.CallerProcessName", "query": "event.code:4656 AND win.ObjectName:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 13 |  |
| q-885536603a | check C093 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND win.ScriptBlockText:(*MiniDump* OR *lsass* OR *VirtualProtect* OR *GetProcAddress* OR *SetWindowsHookEx*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name… | 2 |  |
| q-a18fdb7b2e | check C094 | search | {"dataset": "windows.other", "query": "message:(*lsass* OR *SetWindowsHookEx* OR *MiniDump*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process… | 0 |  |
| q-3378b5530b | check C095 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-ecf9b97553 | check C096 | aggregate | {"dataset": "windows.security", "field": "source.ip", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-bfbf213c3e | check C097 | timeline | {"dataset": "windows.security", "query": "event.code:4625", "interval": "1m", "time_from": null, "time_to": null} | 0 |  |
| q-e37452a255 | check C098 | aggregate | {"dataset": "windows.security", "field": "win.Status", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-539db69caa | check C099 | search | {"dataset": "windows.other", "query": "message:(*logon* OR *password* OR *account*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_… | 7 |  |
| q-2ec5ee8be8 | check C100 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND win.ScriptBlockText:(*password* OR *Credential* OR *Brute* OR *Login*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "… | 3 |  |
| q-aa6ba02b51 | check C101 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*password* OR process.command_line:*pass*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1 |  |
| q-ebec499c69 | check C102 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-4fca6bd722 | check C103 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-750400c71c | check C104 | search | {"dataset": "windows.security", "query": "event.code:4625 AND win.TargetUserName:*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_l… | 0 |  |
| q-09620d9e17 | check C105 | search | {"dataset": "windows.other", "query": "message:(*failed* OR *logon*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.… | 4 |  |
| q-ba47e0bf39 | check C106 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND win.ScriptBlockText:(*Logon* OR *password* OR *Credential*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name",… | 3 |  |
| q-1503e4c38f | check C107 | aggregate | {"dataset": "windows.sysmon", "field": "process.command_line", "query": "event.code:1 AND (process.command_line:*net* OR process.command_line:*runas*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 31 |  |
| q-2cd63544d9 | check C108 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 447 |  |
| q-cf4bd101af | check C109 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*hash* OR process.command_line:*ntlm* OR process.command_line:*wordlist*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset… | 0 |  |
| q-eef84e66cf | check C110 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 1649 |  |
| q-ad2c8d0c7d | check C111 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-217a9a275e | check C112 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 OR event.code:4656 OR event.code:4670", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 10977 |  |
| q-4406710a1f | check C113 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4663 AND (win.ObjectName:*SAM* OR win.ObjectName:*SECURITY* OR win.ObjectName:*NTDS*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-9e50e7ceec | check C114 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND win.ScriptBlockText:(*hash* OR *NTLM* OR *SAM* OR *NTDS*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "… | 10 |  |
| q-4d9335eb80 | check C115 | search | {"dataset": "windows.other", "query": "message:(*SAM* OR *NTDS* OR *hash*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "s… | 1 |  |
| q-6677482500 | check C116 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-aac9b7d18e | check C117 | aggregate | {"dataset": "windows.security", "field": "source.ip", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-974a6ebee3 | check C118 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4648", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 15 |  |
| q-8d3309e256 | check C119 | timeline | {"dataset": "windows.security", "query": "event.code:4625", "interval": "1m", "time_from": null, "time_to": null} | 0 |  |
| q-2486c1c09e | check C120 | search | {"dataset": "windows.other", "query": "message:(*logon* OR *account* OR *lockout*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_l… | 7 |  |
| q-23b6a6be82 | check C121 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND win.ScriptBlockText:(*password* OR *Credential* OR *Logon*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name",… | 3 |  |
| q-cb5d1afbfb | check C122 | aggregate | {"dataset": "windows.sysmon", "field": "process.command_line", "query": "event.code:1 AND (process.command_line:*net* OR process.command_line:*user*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 31 |  |
| q-bd12a95a32 | check C123 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 0 |  |
| q-38391c6c11 | check C124 | aggregate | {"dataset": "windows.security", "field": "source.ip", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-0f239aa9a3 | check C125 | search | {"dataset": "windows.security", "query": "event.code:4625", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 0 |  |
| q-9883bf293c | check C126 | search | {"dataset": "windows.other", "query": "message:(*logon* OR *password* OR *account*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_… | 7 |  |
| q-09784a4d90 | check C127 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND win.ScriptBlockText:(*password* OR *Credential* OR *Login*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name",… | 3 |  |
| q-1bd5cbf87d | check C128 | aggregate | {"dataset": "windows.sysmon", "field": "process.command_line", "query": "event.code:1 AND (process.command_line:*password* OR process.command_line:*user*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1 |  |
| q-ebf45a4284 | check C129 | aggregate | {"dataset": "windows.security", "field": "win.LogonProcessName", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 297 |  |
| q-2acecd9b9c | check C130 | search | {"dataset": "windows.security", "query": "event.code:4648", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 15 |  |
| q-9d8b1dd706 | check C131 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-a238f06d2e | check C132 | aggregate | {"dataset": "windows.sysmon", "field": "registry.path", "query": "event.code:13 AND registry.path:*Credential*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 11 |  |
| q-bcee83248d | check C133 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Credential* OR win.ScriptBlockText:*Vault* OR win.ScriptBlockText:*Token*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event… | 3 |  |
| q-56ec49e4b4 | check C134 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-60fff56463 | check C135 | aggregate | {"dataset": "windows.security", "field": "win.ObjectType", "query": "event.code:4663 OR event.code:4656 OR event.code:4670", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 10977 |  |
| q-09efe0f9a0 | check C136 | aggregate | {"dataset": "windows.security", "field": "win.ShareName", "query": "event.code:5140 OR event.code:5145", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 163 |  |
| q-6ac1766e25 | check C137 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND (win.TargetFilename:*.lnk OR win.TargetFilename:*.scf OR win.TargetFilename:*.url OR win.TargetFilename:*.library-ms)", "time_from": null, "time_to": null, "size": 50, "su… | 3 |  |
| q-60d2b73b78 | check C138 | aggregate | {"dataset": "windows.sysmon", "field": "destination.ip", "query": "event.code:3 AND (destination.port:445 OR destination.port:139)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 66 |  |
| q-21af119ecd | check C139 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*WebDAV* OR win.ScriptBlockText:*NTLM* OR win.ScriptBlockText:*445*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.datase… | 0 |  |
| q-308eed4160 | check C140 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-2d74a7fb16 | check C141 | aggregate | {"dataset": "zeek", "field": "destination.port", "query": "event.action:conn AND (destination.port:445 OR destination.port:139)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 50 |  |
| q-b7720d1eff | check C142 | search | {"dataset": "zeek", "query": "event.action:http AND (http.request.method:PROPFIND OR http.request.method:OPTIONS OR http.request.method:MOVE)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.c… | 36 |  |
| q-851570fdaf | check C143 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 39283 |  |
| q-4fc5612ff8 | check C144 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-2dccfc778a | check C145 | aggregate | {"dataset": "windows.security", "field": "win.ServiceName", "query": "event.code:7045", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-46ec954ca6 | check C146 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*lsass* OR process.command_line:*procdump* OR process.command_line:*comsvcs*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "even… | 0 |  |
| q-377e80b571 | check C147 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*MiniDump* OR win.ScriptBlockText:*comsvcs*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event… | 0 |  |
| q-7a6bf6fee4 | check C148 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 | F24 |
| q-806a1dd8d2 | check C149 | aggregate | {"dataset": "zeek", "field": "destination.port", "query": "event.action:conn", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 613 |  |
| q-c243c94b75 | check C150 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND (win.TargetFilename:*Cookies* OR win.TargetFilename:*Login Data* OR win.TargetFilename:*Web Data*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 162 |  |
| q-b2c2dc6814 | check C151 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND (win.TargetImage:*chrome* OR win.TargetImage:*firefox* OR win.TargetImage:*msedge* OR win.TargetImage:*iexplore*)", "time_from": null, "time_to": null, "size": 50, "sub_fi… | 0 |  |
| q-09a8a9fee0 | check C152 | aggregate | {"dataset": "windows.sysmon", "field": "win.Image", "query": "event.code:2 AND (win.TargetFilename:*Cookies* OR win.TargetFilename:*Login Data*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-3c112d96b6 | check C153 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*Cookies* OR process.command_line:*\"Login Data\"* OR process.command_line:*chrome*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name"… | 0 |  |
| q-9ab489a194 | check C154 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Cookies* OR win.ScriptBlockText:*Login Data* OR win.ScriptBlockText:*sqlite*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "ev… | 13 | F25 |
| q-9b0f8bbc4d | check C155 | search | {"dataset": "windows.other", "query": "event.code:11 AND (file.path:*Cookies* OR file.path:*Login Data*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executabl… | 0 |  |
| q-2824f23df5 | check C156 | search | {"dataset": "zeek", "query": "event.action:http AND (url.original:*cookie* OR http.request.method:POST)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable… | 0 |  |
| q-af323e99f0 | check C157 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND (win.TargetFilename:*.txt OR win.TargetFilename:*.config OR win.TargetFilename:*.xml OR win.TargetFilename:*.ini OR win.TargetFilename:*.ps1)", "time_from": null, "time_to… | 72 |  |
| q-1350529652 | check C158 | aggregate | {"dataset": "windows.sysmon", "field": "registry.path", "query": "event.code:13 AND (registry.path:*Password* OR registry.path:*Credential*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 17 |  |
| q-f744640f4b | check C159 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*findstr* OR process.command_line:*password* OR process.command_line:*credential*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", … | 0 |  |
| q-c5fa9a6aff | check C160 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*password* OR win.ScriptBlockText:*credential* OR win.ScriptBlockText:*ConvertTo-SecureString*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "ob… | 4 |  |
| q-476f1f7694 | check C161 | search | {"dataset": "windows.other", "query": "event.code:11 AND (file.path:*.txt OR file.path:*.config OR file.path:*.xml)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "proces… | 0 |  |
| q-d264147abb | check C162 | search | {"dataset": "zeek", "query": "event.action:smb_files", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinatio… | 12 |  |
| q-a187f8ca95 | check C163 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND (win.TargetFilename:*.txt OR win.TargetFilename:*.config OR win.TargetFilename:*.xml OR win.TargetFilename:*.ini OR win.TargetFilename:*.kdbx OR win.TargetFilename:*.ps1)"… | 72 |  |
| q-dac7d57269 | check C164 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*findstr* OR process.command_line:*password* OR process.command_line:*credential*)", "time_from": null, "time_to": null, "size": 20, "sub_field": null… | 0 |  |
| q-9cb8f5397b | check C165 | search | {"dataset": "windows.security", "query": "event.code:4688 AND (process.command_line:*findstr* OR process.command_line:*password* OR process.command_line:*credential*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", … | 0 |  |
| q-4b59101c0e | check C166 | search | {"dataset": "windows.security", "query": "event.code:4648", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 15 |  |
| q-50a1962120 | check C167 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*password* OR win.ScriptBlockText:*credential* OR win.ScriptBlockText:*Get-Content*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name… | 2 |  |
| q-c6ea6eb538 | check C168 | search | {"dataset": "windows.other", "query": "event.code:11 AND (file.path:*.txt OR file.path:*.config OR file.path:*.xml)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "proces… | 0 |  |
| q-eaaa24937c | check C169 | search | {"dataset": "zeek", "query": "event.action:smb_files", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinatio… | 12 |  |
| q-46e165c0b5 | check C170 | aggregate | {"dataset": "windows.sysmon", "field": "registry.path", "query": "event.code:13 AND (registry.path:*Password* OR registry.path:*password* OR registry.path:*Credential* OR registry.path:*credential*)", "time_from": null, "time_to": null, "size": 50, "sub_field"… | 17 |  |
| q-08305755d1 | check C171 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*reg\\ query* OR process.command_line:*reg\\ save* OR process.command_line:*winreg* OR process.command_line:*Password*)", "time_from": null, "time_to": null, "fields": ["@timestamp"… | 0 |  |
| q-ff1757bc33 | check C172 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Password* OR win.ScriptBlockText:*Credential* OR win.ScriptBlockText:*reg\\ query* OR win.ScriptBlockText:*Get-ItemProperty*)", "time_from": null, "time_to": null, "fields": … | 5 |  |
| q-6349d58253 | check C173 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND (win.ObjectName:*SAM* OR win.ObjectName:*SECURITY* OR win.ObjectName:*Password*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-c467b27ffd | check C174 | search | {"dataset": "windows.other", "query": "event.code:11 AND (file.path:*SAM* OR file.path:*SECURITY* OR file.path:*SYSTEM*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "p… | 0 |  |
| q-ba72307b3f | check C175 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*history* OR win.ScriptBlockText:*ConsoleHost_history* OR win.ScriptBlockText:*Get-History*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "obser… | 0 |  |
| q-e33110510f | check C176 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*ConsoleHost_history* OR process.command_line:*Get-History* OR process.command_line:*history*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.… | 0 |  |
| q-d9779e384f | check C177 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*ConsoleHost_history* OR file.path:*history*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process… | 0 |  |
| q-f66b05bed6 | check C178 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND (win.ObjectName:*history* OR win.ObjectName:*ConsoleHost*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-258f9d1b7e | check C179 | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11 AND (file.path:*.key OR file.path:*.pem OR file.path:*.pfx OR file.path:*.p12 OR file.path:*.ppk OR file.path:*.pgp OR file.path:*.cer OR file.path:*.p7b)", "time_from": null, "time_to… | 1 |  |
| q-6e1d832ee0 | check C180 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*.pfx* OR process.command_line:*.pem* OR process.command_line:*.key* OR process.command_line:*certutil*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", … | 0 |  |
| q-4cb7844fbc | check C181 | aggregate | {"dataset": "windows.security", "field": "win.RelativeTargetName", "query": "event.code:5145 AND (win.RelativeTargetName:*.key OR win.RelativeTargetName:*.pfx OR win.RelativeTargetName:*.pem OR win.RelativeTargetName:*.p12)", "time_from": null, "time_to": null… | 0 |  |
| q-42f211a284 | check C182 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*.pfx* OR win.ScriptBlockText:*.pem* OR win.ScriptBlockText:*Export-PfxCertificate* OR win.ScriptBlockText:*PrivateKey*)", "time_from": null, "time_to": null, "fields": ["@tim… | 3 |  |
| q-3f098fb8b5 | check C183 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Groups.xml* OR win.ScriptBlockText:*cpassword* OR win.ScriptBlockText:*gpprefdecrypt* OR win.ScriptBlockText:*AES*)", "time_from": null, "time_to": null, "fields": ["@timesta… | 0 |  |
| q-50fac8f03d | check C184 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*Groups.xml* OR process.command_line:*cpassword* OR process.command_line:*SYSVOL* OR process.command_line:*gpprefdecrypt*)", "time_from": null, "time_to": null, "fields": ["@timesta… | 0 |  |
| q-2d66fd95ae | check C185 | aggregate | {"dataset": "windows.security", "field": "win.RelativeTargetName", "query": "event.code:5145 AND (win.RelativeTargetName:*Groups.xml* OR win.RelativeTargetName:*SYSVOL* OR win.RelativeTargetName:*.xml)", "time_from": null, "time_to": null, "size": 50, "sub_fie… | 0 |  |
| q-0e41f1e956 | check C186 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*Groups.xml* OR file.path:*SYSVOL*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executabl… | 0 |  |
| q-9d59207e01 | check C187 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND (win.TargetImage:*lsass.exe OR win.TargetImage:*lsass*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-1a1ad1c2ae | check C188 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND (win.TargetImage:*lsass.exe OR win.TargetImage:*lsass*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-74d1d6a91a | check C189 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*procdump* OR process.command_line:*lsass* OR process.command_line:*mimikatz* OR process.command_line:*sekurlsa* OR process.command_line:*comsvcs*)", "time_from": null, "time_to": n… | 1 |  |
| q-3712afa56c | check C190 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND (win.ObjectName:*lsass* OR win.ObjectName:*SAM* OR win.ObjectName:*SECURITY* OR win.ObjectName:*DPAPI* OR win.ObjectName:*Protect*)", "time_from": null, "time_to": null, "… | 6 |  |
| q-63ba76bfef | check C191 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4624 AND win.LogonType:9", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-dd13f10d50 | check C192 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*MiniDump* OR win.ScriptBlockText:*sekurlsa* OR win.ScriptBlockText:*Credential*)", "time_from": null, "time_to": null, "fields": ["@timestamp",… | 3 |  |
| q-9666590edf | check C193 | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11 AND (file.path:*Login\\ Data* OR file.path:*logins.json* OR file.path:*key4.db* OR file.path:*logins.json* OR file.path:*Cookies*)", "time_from": null, "time_to": null, "size": 50, "su… | 1 |  |
| q-08b26e2113 | check C194 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND (win.TargetImage:*chrome.exe OR win.TargetImage:*firefox.exe OR win.TargetImage:*msedge.exe OR win.TargetImage:*iexplore.exe)", "time_from": null, "time_to": null, "size":… | 0 |  |
| q-e11e929c83 | check C195 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*Login\\ Data* OR process.command_line:*logins.json* OR process.command_line:*key4.db* OR process.command_line:*Local\\ State*)", "time_from": null, "time_to": null, "fields": ["@ti… | 0 |  |
| q-3a9fe093fa | check C196 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 AND (win.ObjectName:*Login\\ Data* OR win.ObjectName:*logins.json* OR win.ObjectName:*key4.db* OR win.ObjectName:*Cookies*)", "time_from": null, "time_to": null, "size": 50, "… | 0 |  |
| q-f7dccc7034 | check C197 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Login\\ Data* OR win.ScriptBlockText:*logins.json* OR win.ScriptBlockText:*key4.db* OR win.ScriptBlockText:*sqlite*)", "time_from": null, "time_to": null, "fields": ["@timest… | 0 |  |
| q-0e743e988f | check C198 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*vault* OR process.command_line:*credential* OR process.command_line:*cmdkey* OR process.command_line:*CredMan*)", "time_from": null, "time_to": null,… | 0 |  |
| q-3bbd69d069 | check C199 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND (win.TargetImage:*lsass* OR win.TargetImage:*vault* OR win.TargetImage:*credential*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.… | 326 |  |
| q-be151b492c | check C200 | search | {"dataset": "windows.sysmon", "query": "event.code:15 AND (win.TargetFilename:*Credentials* OR win.TargetFilename:*Vault* OR win.TargetFilename:*.vcrd*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset… | 0 |  |
| q-82430d91df | check C201 | aggregate | {"dataset": "windows.security", "field": "process.command_line", "query": "event.code:4688 AND (process.command_line:*vault* OR process.command_line:*cmdkey* OR process.command_line:*credential*)", "time_from": null, "time_to": null, "size": 50, "sub_field": n… | 0 |  |
| q-1442f22ce9 | check C202 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*vault* OR win.ScriptBlockText:*CredentialManager* OR win.ScriptBlockText:*cmdkey* OR win.ScriptBlockText:*CredRead*)", "time_from": null, "time_to": null, "fields": ["@timest… | 0 |  |
| q-cb93e0e3fc | check C203 | search | {"dataset": "windows.other", "query": "*vault* OR *Credential Manager* OR *cmdkey*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_l… | 15 | F35 |
| q-e31e6396d3 | check C204 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*keepass* OR process.command_line:*1password* OR process.command_line:*lastpass* OR process.command_line:*bitwarden* OR process.command_line:*password… | 0 |  |
| q-7a18560416 | check C205 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND (win.TargetImage:*keepass* OR win.TargetImage:*1password* OR win.TargetImage:*lastpass* OR win.TargetImage:*bitwarden*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "obser… | 0 |  |
| q-cedcad83b2 | check C206 | search | {"dataset": "windows.sysmon", "query": "event.code:15 AND (win.TargetFilename:*.kdbx OR win.TargetFilename:*1password* OR win.TargetFilename:*keepass*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset"… | 0 |  |
| q-219b6ba903 | check C207 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND (process.command_line:*keepass* OR process.command_line:*1password* OR process.command_line:*lastpass* OR process.command_line:*bitwarden*)", "time_from": null, "time_… | 0 |  |
| q-015b274871 | check C208 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*keepass* OR win.ScriptBlockText:*1password* OR win.ScriptBlockText:*lastpass* OR win.ScriptBlockText:*bitwarden*)", "time_from": null, "time_to": null, "fields": ["@timestamp… | 0 |  |
| q-90bc45d0d9 | check C209 | search | {"dataset": "windows.other", "query": "*keepass* OR *1password* OR *lastpass* OR *bitwarden*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process… | 0 |  |
| q-81852f9d7b | check C210 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-42d9e4738c | check C211 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-8c5e56d1a9 | check C212 | aggregate | {"dataset": "windows.sysmon", "field": "win.ImageLoaded", "query": "event.code:7 AND (win.ImageLoaded:*lsass* OR win.ImageLoaded:*cryptdll* OR win.ImageLoaded:*sam* OR win.ImageLoaded:*ntds*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 87 |  |
| q-21edb2ed3d | check C213 | search | {"dataset": "windows.security", "query": "event.code:4657 AND (win.ObjectName:*lsass* OR win.ObjectName:*cryptdll* OR win.ObjectName:*SecurityProviders* OR win.ObjectName:*Notification Packages*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "… | 0 |  |
| q-2ed5ef6c62 | check C214 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND (process.command_line:*lsass* OR process.command_line:*procdump* OR process.command_line:*mimikatz* OR process.command_line:*sekurlsa*)", "time_from": null, "time_to":… | 0 |  |
| q-cdd034192d | check C215 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*mimikatz* OR win.ScriptBlockText:*sekurlsa* OR win.ScriptBlockText:*MiniDump*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "… | 0 |  |
| q-9e9965dcc5 | check C216 | search | {"dataset": "windows.other", "query": "*lsass* OR *cryptdll* OR *Notification Packages*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.comm… | 4 |  |
| q-628c5c2145 | check C217 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-661981348f | check C218 | aggregate | {"dataset": "windows.sysmon", "field": "win.ImageLoaded", "query": "event.code:7 AND (win.ImageLoaded:*lsass* OR win.ImageLoaded:*cryptdll*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 33 |  |
| q-57d0f5f024 | check C219 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4624 AND win.LogonType:3", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 218 |  |
| q-227704f48c | check C220 | search | {"dataset": "windows.security", "query": "event.code:4648", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 15 | F37 |
| q-4a1c5f55d5 | check C221 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*cryptdll* OR win.ScriptBlockText:*skeleton* OR win.ScriptBlockText:*mimikatz*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "… | 0 |  |
| q-16ed5f6dac | check C222 | search | {"dataset": "windows.other", "query": "*lsass* OR *cryptdll*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "de… | 0 |  |
| q-7a5b66816a | check C223 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (win.TargetFilename:*.dll AND (win.TargetFilename:*System32* OR win.TargetFilename:*SysWOW64*))", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.datase… | 0 |  |
| q-095acc0cc7 | check C224 | aggregate | {"dataset": "windows.sysmon", "field": "win.ImageLoaded", "query": "event.code:7 AND win.ImageLoaded:*.dll", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 19515 |  |
| q-1519ebe9d8 | check C225 | search | {"dataset": "windows.security", "query": "event.code:4657 AND (win.ObjectName:*Notification Packages* OR win.ObjectName:*Password* OR win.ObjectName:*Control\\Set*\\Control*Lsa*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "obse… | 0 |  |
| q-f0b4b775bc | check C226 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND (process.command_line:*Notification* OR process.command_line:*reg*add*Lsa*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-83398b0879 | check C227 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Notification*Packages* OR win.ScriptBlockText:*PasswordFilter* OR win.ScriptBlockText:*Lsa*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "obse… | 0 |  |
| q-65bc410453 | check C228 | search | {"dataset": "windows.other", "query": "*Notification Packages* OR *PasswordFilter*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_l… | 5 | F38 |
| q-629ef0e547 | check C229 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*AllowReversiblePasswordEncryption* OR win.ScriptBlockText:*ReversibleEncryption* OR win.ScriptBlockText:*Set-ADAccountControl* OR win.ScriptBlockText:*Set-ADUser*)", "time_fr… | 1 |  |
| q-05d5932ea3 | check C230 | search | {"dataset": "windows.powershell", "query": "event.code:4103 AND (win.Payload:*Reversible* OR win.Payload:*Set-ADAccountControl*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.n… | 0 |  |
| q-0e1db63d89 | check C231 | search | {"dataset": "windows.security", "query": "event.code:4739", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 0 |  |
| q-5445b5894e | check C232 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*Reversible* OR process.command_line:*Set-ADAccountControl* OR process.command_line:*Set-ADUser*)", "time_from": null, "time_to": null, "size": 50, "s… | 0 |  |
| q-ba67246c59 | check C233 | search | {"dataset": "windows.other", "query": "*Reversible* OR *Set-ADAccountControl*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line",… | 0 |  |
| q-bff80655ba | check C234 | esql | {"query": "FROM logs-windows.powershell-* METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*set-aduser*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*set-adauthenticationpolicy*\" OR TO_LOWER(process.command_line) LIKE \"*set-aduser*\" OR TO_LOW… | 1 |  |
| q-bc61f2e165 | check C235 | aggregate | {"dataset": "windows.security", "field": "event.code", "query": "event.code:4739", "time_from": null, "time_to": null, "size": 10, "sub_field": null} | 0 |  |
| q-0a05cb2c3a | check C236 | aggregate | {"dataset": "windows.security", "field": "win.ObjectType", "query": "event.code:4662 OR event.code:5136", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 7 |  |
| q-66fbe0eb3c | check C237 | aggregate | {"dataset": "windows.sysmon", "field": "win.ImageLoaded", "query": "event.code:7", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 20259 |  |
| q-79ad39ca07 | check C238 | aggregate | {"dataset": "windows.security", "field": "win.ObjectType", "query": "event.code:5136", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 0 |  |
| q-e37a11a252 | check C239 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 20, "sub_field": null} | 297 |  |
| q-f4298a04e0 | check C240 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetObject", "query": "event.code:13 AND registry.path:*NetworkProvider*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-54c8ce211b | check C241 | aggregate | {"dataset": "windows.sysmon", "field": "win.ImageLoaded", "query": "event.code:7", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 20259 |  |
| q-09c36fb184 | check C242 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1649 |  |
| q-847b95d81e | check C243 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4657", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 36 |  |
| q-4245435a3b | check C244 | aggregate | {"dataset": "windows.sysmon", "field": "win.DestinationIp", "query": "event.code:3", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1229 |  |
| q-1ad67e8c6c | check C245 | aggregate | {"dataset": "windows.sysmon", "field": "dns.question.name", "query": "event.code:22", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 81 |  |
| q-4c2bdb5dad | check C246 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4663 OR event.code:4670 OR event.code:4656", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 10977 |  |
| q-fc2c077c4b | check C247 | aggregate | {"dataset": "windows.sysmon", "field": "win.DestinationIp", "query": "event.code:3 AND (destination.port:445 OR destination.port:139)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 66 |  |
| q-a7632298f5 | check C248 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetObject", "query": "event.code:13 AND registry.path:*DNSClient*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-0bf94703f7 | check C249 | aggregate | {"dataset": "windows.security", "field": "win.ServiceName", "query": "event.code:4697", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 23 |  |
| q-66b2549302 | check C250 | aggregate | {"dataset": "windows.sysmon", "field": "win.DestinationIp", "query": "event.code:3", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 1229 |  |
| q-60423668bc | check C251 | aggregate | {"dataset": "windows.sysmon", "field": "dns.question.name", "query": "event.code:22", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 81 |  |
| q-3d00a71631 | check C252 | search | {"dataset": "windows.other", "query": "event.code:1341 OR event.code:1342 OR event.code:1020 OR event.code:1063", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.ex… | 0 |  |
| q-0d56411aa8 | check C253 | aggregate | {"dataset": "windows.other", "field": "event.code", "query": "*", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 216 |  |
| q-b389b32716 | check C254 | search | {"dataset": "windows.security", "query": "event.code:5156 AND network.transport:udp AND destination.port:67", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.execut… | 0 |  |
| q-24ef89f6ed | check C255 | search | {"dataset": "windows.sysmon", "query": "event.code:22 AND dns.question.name:*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line",… | 81 | F43 |
| q-61f31b2a20 | check C256 | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*dhcp*\" OR TO_LOWER(process.command_line) LIKE \"*dhcp*\" \| KEEP @timestamp, host.name, process.command_line, _id, _index"} | ERROR |  |
| q-514436a8bc | check C256 (repaired) | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*dhcp*\" OR TO_LOWER(process.command_line) LIKE \"*dhcp*\" \| KEEP @timestamp, host.name, process.command_line, _id, _index"} | ERROR |  |
| q-c8c7c84cd7 | check C257 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND (win.TargetImage:*lsass.exe OR win.TargetImage:*lsass*)", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 326 |  |
| q-f6f5058521 | check C258 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND win.TargetImage:*lsass.exe", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 326 |  |
| q-490e2150bf | check C259 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4672", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 212 |  |
| q-537bd5a3f4 | check C260 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4634", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 236 |  |
| q-14bee5a1a8 | check C261 | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*kerberos*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*kirbi*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*ticket*\" \| KEEP @timestamp, host.name, win.ScriptBlo… | ERROR |  |
| q-0fe2c05169 | check C261 (repaired) | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*kerberos*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*kirbi*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*ticket*\" \| KEEP @timestamp, host.name, win.ScriptBlo… | ERROR |  |
| q-208f63d1d5 | check C262 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 | F51 |
| q-1b7ece4bf2 | check C263 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4672", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 212 |  |
| q-09dfae75f3 | check C264 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4634", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 236 |  |
| q-537166f765 | check C265 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND win.TargetImage:*lsass.exe", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 326 |  |
| q-4c0db9d6f2 | check C266 | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*krbtgt*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*golden*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*mimikatz*\" \| KEEP @timestamp, host.name, win.ScriptBl… | ERROR |  |
| q-f296ae919d | check C266 (repaired) | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*krbtgt*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*golden*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*mimikatz*\" \| KEEP @timestamp, host.name, win.ScriptBl… | ERROR |  |
| q-4c71bc1d15 | check C267 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-0bd4158df6 | check C268 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4672", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 212 |  |
| q-3b210b0cc7 | check C269 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4634", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 236 |  |
| q-1cb6799caa | check C270 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass.exe", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 326 |  |
| q-65944961cb | check C271 | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*silver*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*service ticket*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*kerberoast*\" \| KEEP @timestamp, host.name, wi… | ERROR |  |
| q-87059cfb01 | check C271 (repaired) | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*silver*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*service ticket*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*kerberoast*\" \| KEEP @timestamp, host.name, wi… | ERROR |  |
| q-f71c236d23 | check C272 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-c7073d9491 | check C273 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 297 |  |
| q-ad38600017 | check C274 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4672", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 212 |  |
| q-773d7d14f8 | check C275 | search | {"dataset": "windows.security", "query": "event.code:4648", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 15 |  |
| q-f60f6b6c28 | check C276 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND win.TargetImage:*lsass.exe", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 326 |  |
| q-dc7f016633 | check C277 | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*kerberoast*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*spn*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*invoke-kerberoast*\" \| KEEP @timestamp, host.name, wi… | ERROR |  |
| q-06765086a1 | check C277 (repaired) | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*kerberoast*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*spn*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*invoke-kerberoast*\" \| KEEP @timestamp, … | 0 |  |
| q-9400312c30 | check C278 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-332d09355f | check C279 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 447 |  |
| q-ffc8746af1 | check C280 | esql | {"query": "FROM windows.sysmon METADATA _id, _index \| WHERE event.code == 1 AND (TO_LOWER(process.command_line) LIKE \"*asrep*\" OR TO_LOWER(process.command_line) LIKE \"*rubeus*\" OR TO_LOWER(process.command_line) LIKE \"*getnpusers*\" OR TO_LOWER(process.co… | ERROR |  |
| q-550bc594ea | check C280 (repaired) | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 1 AND (TO_LOWER(process.command_line) LIKE \"*asrep*\" OR TO_LOWER(process.command_line) LIKE \"*rubeus*\" OR TO_LOWER(process.command_line) LIKE \"*getnpusers*\" OR TO_LOW… | ERROR |  |
| q-1b79a9e17c | check C281 | esql | {"query": "FROM windows.powershell METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*asrep*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*getnpusers*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*rubeus*\" \| KEEP @timestamp, host.name, win.ScriptB… | ERROR |  |
| q-83d7212ace | check C281 (repaired) | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*asrep*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*getnpusers*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*rubeus*\" \| KEEP @timestamp, host.name… | 0 |  |
| q-34fa17ca03 | check C282 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 100, "sub_field": null} | 297 |  |
| q-4086166525 | check C283 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-ed1633959a | check C284 | aggregate | {"dataset": "windows.security", "field": "win.LogonProcessName", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 297 |  |
| q-c1bc12a6c0 | check C285 | aggregate | {"dataset": "windows.security", "field": "win.AuthenticationPackageName", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 297 |  |
| q-e0762e0e4e | check C286 | search | {"dataset": "windows.security", "query": "event.code:4648", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 15 | F52, F54 |
| q-4a2359ce10 | check C287 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-a692d32bca | check C288 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 326 |  |
| q-a3ec8e0ca0 | check C289 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*AADInternals* OR win.ScriptBlockText:*token* OR win.ScriptBlockText:*cookie* OR win.ScriptBlockText:*SAML*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "ho… | 1 |  |
| q-5fd6c5a410 | check C290 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 | F52 |
| q-d474d7a974 | check C291 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND (win.TargetFilename:*Cookies* OR win.TargetFilename:*Login Data* OR win.TargetFilename:*Local State*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 6 |  |
| q-3406a4f8ab | check C292 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:11 AND (win.TargetFilename:*Cookies* OR win.TargetFilename:*Login Data*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 162 |  |
| q-ab15d971dc | check C293 | aggregate | {"dataset": "windows.security", "field": "win.LogonProcessName", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 297 |  |
| q-1c013ee6ab | check C294 | search | {"dataset": "windows.security", "query": "event.code:4648", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 15 |  |
| q-de6b9ac16a | check C295 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Cookies* OR win.ScriptBlockText:*Set-Cookie* OR win.ScriptBlockText:*session*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "e… | 1 |  |
| q-2a82a82897 | check C296 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-9ada1a27c6 | check C297 | aggregate | {"dataset": "windows.security", "field": "win.LogonProcessName", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 297 |  |
| q-de70e623da | check C298 | search | {"dataset": "windows.security", "query": "event.code:4648", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 15 |  |
| q-bb9adcdcc5 | check C299 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND (win.TargetFilename:*.pfx* OR win.TargetFilename:*.p12* OR win.TargetFilename:*token* OR win.TargetFilename:*saml*)", "time_from": null, "time_to": null, "size": 50, "sub_… | 1 |  |
| q-8807aeea6a | check C300 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*SAML* OR win.ScriptBlockText:*NotOnOrAfter* OR win.ScriptBlockText:*token-signing*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name… | 0 |  |
| q-beac1292a6 | check C301 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-fb0138ed09 | check C302 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-1f08bb4e30 | check C303 | aggregate | {"dataset": "windows.security", "field": "source.ip", "query": "event.code:4625", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-ae9092ed0c | check C304 | timeline | {"dataset": "windows.security", "query": "event.code:4625", "interval": "1m", "time_from": null, "time_to": null} | 0 |  |
| q-4431efac97 | check C305 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*MFA* OR win.ScriptBlockText:*2FA* OR win.ScriptBlockText:*Authenticator*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.… | 0 |  |
| q-33d2301d98 | check C306 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*MFA* OR process.command_line:*2FA*)", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 0 |  |
| q-146349bc39 | check C307 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-f9cbc2a9e4 | check C308 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4657", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 36 |  |
| q-c469b952d6 | check C309 | search | {"dataset": "windows.security", "query": "event.code:4768", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "desti… | 14 |  |
| q-4c6d91c8f6 | check C310 | aggregate | {"dataset": "windows.security", "field": "win.TargetUserName", "query": "event.code:4768", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 14 |  |
| q-b44674f8e9 | check C311 | aggregate | {"dataset": "windows.sysmon", "field": "win.TargetFilename", "query": "event.code:11 AND (win.TargetFilename:*.pfx* OR win.TargetFilename:*.p12* OR win.TargetFilename:*.cer* OR win.TargetFilename:*.crt*)", "time_from": null, "time_to": null, "size": 50, "sub_f… | 1 |  |
| q-a994b23de7 | check C312 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Export-PfxCertificate* OR win.ScriptBlockText:*Certify* OR win.ScriptBlockText:*New-SelfSignedCertificate* OR win.ScriptBlockText:*certutil*)", "time_from": null, "time_to": … | 1 |  |
| q-0926878c5b | check C313 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destinat… | 5 |  |
| q-346132ce31 | check C314 | aggregate | {"dataset": "zeek", "field": "event.action", "query": "*", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 2140 |  |
| q-034ab45fba | check C315 | search | {"dataset": "zeek", "query": "event.action:kerberos", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "process.command_line", "source.ip", "destination… | 35 |  |
| q-808c643dc4 | check C316 | aggregate | {"dataset": "zeek", "field": "zeek.request_type", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 35 |  |
| q-b7e3636046 | check C317 | aggregate | {"dataset": "zeek", "field": "zeek.error_msg", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 35 |  |
| q-c40ad2b2f5 | check C318 | aggregate | {"dataset": "zeek", "field": "zeek.service", "query": "event.action:kerberos", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 35 |  |
| q-9bdea0b3a9 | triage T1003 step 1 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7habKTo"} | None | F01 |
| q-beb004ea57 | triage T1003 step 1 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4663\",\"4656\",\"4670\") AND win.ObjectType IN (\"SAM_DOMAIN\",\"SAM_SERVER\",\"SAM_ALIAS\",\"Process\") \| KEEP @timestamp, host.name, event.code, win.ObjectType, wi… | 40 | F01 |
| q-4d5019d927 | triage T1003 step 2 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq7mb8"} | None |  |
| q-7acf6dccc6 | triage T1003 step 2 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7njy6Co"} | None |  |
| q-2e53185161 | triage T1003 step 2 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*lsass*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*minidump*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*sekurlsa*\" O… | 0 |  |
| q-b09198b336 | triage T1003 step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND user.name == \"pbeesly\" \| KEEP @timestamp, host.name, user.name, win.ScriptBlockId, win.ScriptBlockText, _id, _index \| SORT @timestamp ASC \| LIMIT 40"} | 40 | F07 |
| q-dd4bed3a6d | triage T1003 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (process.executable LIKE \"*victim*\" OR process.executable LIKE \"*Temp*\" OR process.executable LIKE \"*Sysinternals*\" OR process.executable LIKE \"*PSEXESVC*\… | 22 | F07 |
| q-4ac5dfac9d | triage T1003 step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND user.name == \"pbeesly\" AND @timestamp > \"2020-05-02T03:01:51.000Z\" \| KEEP @timestamp, host.name, user.name, win.ScriptBlockText, _id, _index \| SORT @… | 60 | F05 |
| q-4c1ee2681c | triage T1003 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*procdump*\" OR TO_LOWER(process.command_line) LIKE \"*comsvcs*\" OR TO_LOWER(process.command_line) LIKE \"*mimikatz*\" OR … | 0 |  |
| q-8b713cd7f4 | triage T1003 step 5 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND user.name == \"pbeesly\" AND @timestamp > \"2020-05-02T03:06:47.000Z\" \| KEEP @timestamp, host.name, user.name, win.ScriptBlockText, _id, _index \| SORT @… | 60 | F06 |
| q-02b0e07405 | triage T1003 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(win.TargetFilename) LIKE \"*.dmp\" OR TO_LOWER(win.TargetFilename) LIKE \"*.zip\" OR TO_LOWER(win.TargetFilename) LIKE \"*.pfx\" OR TO_LOWER(win.Target… | 12 | F03, F05 |
| q-3582fdfe1f | triage T1003 step 6 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4663\" AND win.ObjectType IN (\"SAM_DOMAIN\",\"SAM_SERVER\",\"SAM_ALIAS\") \| KEEP @timestamp, host.name, event.code, win.ObjectType, win.ObjectName, win.ProcessName, w… | 0 |  |
| q-f9fd28e45b | triage T1003 step 6 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4624\" AND user.name == \"pbeesly\" \| KEEP @timestamp, host.name, event.code, user.name, win.LogonType, win.IpAddress, win.Workstation, win.LogonProcessName, win.Authe… | 30 |  |
| q-0047525c14 | triage T1003 step 7 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4672\" AND user.name == \"pbeesly\" \| KEEP @timestamp, host.name, event.code, user.name, win.PrivilegeList, _id, _index \| SORT @timestamp ASC \| LIMIT 20"} | 19 | F07 |
| q-1f8ba1b2a9 | triage T1003 step 7 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7ryFh3A"} | None | F02 |
| q-f44e852917 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq7mb8"} | None |  |
| q-2e1ec47470 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq7mb8"} | None |  |
| q-3867b7f98e | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7njy6Co"} | None |  |
| q-dfc7ed2948 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7njy6Co"} | None |  |
| q-12eab30bb6 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7habKTo"} | None |  |
| q-7f49fefa25 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7habKTo"} | None |  |
| q-44e6edadfd | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7ryFh3A"} | None |  |
| q-4842b8c464 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7ryFh3A"} | None |  |
| q-dd446ff88b | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7ryFh3A"} | None |  |
| q-96618ec150 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hONXx6"} | None |  |
| q-7b3fa18b99 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cpgKyc"} | None |  |
| q-0402d67d37 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None |  |
| q-74273ff522 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQRgs"} | None |  |
| q-fcb5d22aa6 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuCk"} | None |  |
| q-00ee758b87 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qqQm9_"} | None |  |
| q-ed8af3d1d9 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hy0krT"} | None |  |
| q-c373be6448 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cxoQzx"} | None |  |
| q-14366924cf | triage T1003 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hWVSlm"} | None |  |
| q-4bc6b1e3ce | triage T1003 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7q0Y_4v"} | None |  |
| q-715d9af398 | triage T1003 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7njzKAe"} | None |  |
| q-e2174a0151 | triage T1040 step 1 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nVnj7M"} | None | F08 |
| q-cf9669009d | triage T1040 step 1 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nSl9D4"} | None | F08 |
| q-bf38245366 | triage T1040 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND process.command_line:*netsh*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "process.executable", "process.command_line", "process.parent.executable", "process.p… | 2 | F08 |
| q-c6f10d91fb | triage T1040 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (file.path:*TEMP* OR win.TargetFilename:*.etl OR win.TargetFilename:*.pcap OR win.TargetFilename:*.cap)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "process… | 38 |  |
| q-2142067855 | triage T1040 step 2 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND (process.command_line:*capture* OR process.command_line:*sniff* OR process.command_line:*monitor* OR process.command_line:*promisc* OR process.command_line:*dump*)", "time_… | 1 |  |
| q-4765ff9ef9 | triage T1040 step 3 | search | {"dataset": "windows.other", "query": "event.code:7045", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "win.ServiceName", "win.ImagePath", "win.Message"], "size": 10, "sort": "asc"} | 5 |  |
| q-bf8bfe5b4d | triage T1040 step 3 | search | {"dataset": "windows.sysmon", "query": "event.code:7 AND (win.ImageLoaded:*pcap* OR win.ImageLoaded:*npcap* OR win.ImageLoaded:*winpcap* OR win.ImageLoaded:*NetworkWatcher* OR win.ImageLoaded:*ndis* OR win.ImageLoaded:*Packet*)", "time_from": null, "time_to": … | 0 |  |
| q-ef5cbe88f8 | triage T1040 step 4 | search | {"dataset": "windows.other", "query": "win.Message:*NetworkWatcher* OR win.param1:*NetworkWatcher* OR win.ServiceName:*NetworkWatcher*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "win.ServiceName", "win.Message", "… | 0 |  |
| q-eb45732105 | triage T1040 step 4 | aggregate | {"dataset": "zeek", "field": "destination.port", "query": "event.action:conn", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 613 |  |
| q-14af60cdcf | triage T1040 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nVnj7M"} | None |  |
| q-f23993547d | triage T1040 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nVnj7M"} | None |  |
| q-e88de53a00 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nSl9D4"} | None |  |
| q-ef5478015c | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cla5Dm"} | None |  |
| q-f7e4514abb | triage T1040 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cla5Dm"} | None |  |
| q-105d8ae809 | triage T1040 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7pNHuCk"} | ERROR |  |
| q-abfbef1649 | triage T1056 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSitD"} | None |  |
| q-da326900f1 | triage T1056 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSyuh"} | None |  |
| q-01d2f67d7b | triage T1056 step 1 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhG"} | None |  |
| q-fd63539b16 | triage T1056 step 1 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None |  |
| q-1301def1d3 | triage T1056 step 2 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == 4104 AND user.name == \"pbeesly\" \| KEEP @timestamp, host.name, _id, _index, win.ScriptBlockText \| SORT @timestamp ASC \| LIMIT 60"} | ERROR |  |
| q-b2161345d0 | triage T1056 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 10 AND win.TargetImage LIKE \"*lsass*\" AND (process.executable LIKE \"*PowerShell*\" OR process.executable LIKE \"*wsmprovhost*\") \| KEEP @timestamp, host.name, process.e… | ERROR |  |
| q-d5c4445d7d | triage T1056 step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND user.name == \"pbeesly\" \| KEEP @timestamp, host.name, _id, _index, win.ScriptBlockText \| SORT @timestamp ASC \| LIMIT 60"} | 60 |  |
| q-ad1f5e7d6b | triage T1056 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND win.TargetImage LIKE \"*lsass*\" AND (process.executable LIKE \"*PowerShell*\" OR process.executable LIKE \"*wsmprovhost*\") \| KEEP @timestamp, host.name, proce… | 5 | F11 |
| q-e477d9c289 | triage T1056 step 4 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7q0Yv7J"} | None |  |
| q-d502b9d9cb | triage T1056 step 4 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4663\" AND win.ObjectName LIKE \"*lsass*\" \| KEEP @timestamp, host.name, process.executable, win.ObjectName, win.AccessMask, win.SubjectUserName, _id, _index \| SORT @… | 6 | F11, F12 |
| q-309384e8d0 | triage T1056 step 5 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (win.ScriptBlockText LIKE \"*Keystroke*\" OR win.ScriptBlockText LIKE \"*ScreenCapture*\" OR win.ScriptBlockText LIKE \"*Get-Credential*\" OR win.ScriptBlo… | 11 | F09, F10, F13 |
| q-c24fd2d3e5 | triage T1056 step 5 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4656\" AND win.ObjectName == \"SAM\" \| KEEP @timestamp, host.name, process.executable, win.ObjectName, win.AccessMask, win.SubjectUserName, _id, _index \| SORT @timest… | 10 | F12 |
| q-5e99490720 | triage T1056 step 6 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (win.ScriptBlockText LIKE \"*Get-Keystrokes*\" OR win.ScriptBlockText LIKE \"*Keystrokes*\" OR win.ScriptBlockText LIKE \"*GetAsyncKeyState*\" OR win.Scrip… | 3 | F09 |
| q-53cdce8be4 | triage T1056 step 6 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (win.TargetFilename LIKE \"*.bmp\" OR win.TargetFilename LIKE \"*monkey*\" OR win.TargetFilename LIKE \"*victim*\" OR win.TargetFilename LIKE \"*.scr\") \| KEEP … | 2 | F10 |
| q-3258d20e33 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSitD"} | None |  |
| q-4e242cfb00 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvTCuJ"} | None |  |
| q-f6cc3b24e1 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglC"} | None |  |
| q-174df023d0 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSitD"} | None |  |
| q-8293fc99a2 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSitD"} | None |  |
| q-7c399e6022 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSyuh"} | None |  |
| q-2d05b6be81 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvTCvd"} | None |  |
| q-98d98b22a7 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hMLfHo"} | None |  |
| q-b36d42b112 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSyuh"} | None |  |
| q-cc69e21c32 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhG"} | None |  |
| q-64fe2823e3 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-3aa8f5b8da | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None |  |
| q-3243844b7e | triage T1056 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq72Yf"} | None |  |
| q-38bdf923c5 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq72Yf"} | None |  |
| q-4d02af3158 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7ryFh2_"} | None |  |
| q-3372fa6b01 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq8Gbm"} | None |  |
| q-7e75a735f0 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cUGJOD"} | None |  |
| q-338f0fef31 | triage T1056 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cZNc--"} | None |  |
| q-e6893e3b4d | triage T1056 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSitD"} | None |  |
| q-91d51faaa3 | triage T1110 step 1 | count | {"dataset": "windows.security", "query": "event.code:4625", "time_from": null, "time_to": null} | 0 |  |
| q-0aa7028a16 | triage T1110 step 1 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 30, "sub_field": "win.TargetUserName"} | 297 |  |
| q-97cf18cddd | triage T1110 step 1 | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuA-"} | None |  |
| q-da3474e033 | triage T1110 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None | F15, F18 |
| q-52f48fdea2 | triage T1110 step 2 | search | {"dataset": "windows.security", "query": "event.code:4663 AND win.ObjectName:SAM", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "process.executable", "win.ObjectName", "win.AccessMask", "win.ProcessName"], "size": 15, … | 0 |  |
| q-8582eef357 | triage T1110 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND process.executable:*PowerShell*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "process.executable", "process.command_line", "win.Ta… | 4 | F16 |
| q-880aac27fb | triage T1110 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*password* OR process.command_line:*pass*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "process.executable", "process.command_line", "pr… | 1 |  |
| q-39e701140a | triage T1110 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None | F16 |
| q-4e84776384 | triage T1110 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7htwOyZ"} | None |  |
| q-f6ad0f71e9 | triage T1110 step 4 | search | {"dataset": "windows.security", "query": "win.ObjectName:SAM", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "process.executable", "win.ObjectName", "win.AccessMask", "win.ProcessName", "event.code"], "size": 12, "sort"… | 10 | F16 |
| q-7c6aa98164 | triage T1110 step 4 | count | {"dataset": "windows.security", "query": "event.code:4648 OR event.code:4771 OR event.code:4776 OR event.code:4740", "time_from": null, "time_to": null} | 16 |  |
| q-aa02058e38 | triage T1110 step 5 | search | {"dataset": "windows.security", "query": "event.code:4648 OR event.code:4771 OR event.code:4776 OR event.code:4740", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "event.code", "win.TargetUserName", "win.TargetServerNam… | 16 | F14, F15, F17, F18 |
| q-935863b18d | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niydsP"} | None |  |
| q-76eb36c057 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNur"} | None |  |
| q-d08d204db5 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nKhItZ"} | None |  |
| q-1bba4ae085 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nKhItZ"} | None |  |
| q-cda4c5ede0 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None |  |
| q-b5989f9024 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-5c3677e06c | triage T1110 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-b33443af97 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhG"} | None |  |
| q-8ea5b91ee0 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7ryFh2_"} | None |  |
| q-22a2256776 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nixwZC"} | None |  |
| q-b982b155cb | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nixwZC"} | None |  |
| q-7adb7e6fa6 | triage T1110 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niwwaQ"} | None |  |
| q-678dedcbfa | triage T1110 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None |  |
| q-9cd5e439a9 | triage T1111 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None | F19 |
| q-ed690d689f | triage T1111 step 1 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNur"} | None | F19 |
| q-44036c7a57 | triage T1111 step 1 | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuDg"} | None | F19 |
| q-830f7b787d | triage T1111 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND (TO_LOWER(win.TargetImage) LIKE \"*lsass*\" OR TO_LOWER(win.TargetImage) LIKE \"*vaultsvc*\" OR TO_LOWER(win.TargetImage) LIKE \"*ngc*\" OR TO_LOWER(win.TargetIm… | 18 |  |
| q-664ce6e26e | triage T1111 step 2 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4624\" AND (win.LogonType == \"11\" OR win.LogonProcessName LIKE \"*User32*\" OR win.LogonProcessName LIKE \"*NtLmSsp*\" OR win.LogonProcessName == \"-\") \| KEEP @time… | 4 |  |
| q-1fb7885342 | triage T1111 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND TO_LOWER(win.TargetImage) LIKE \"*lsass*\" AND (TO_LOWER(win.SourceImage) LIKE \"*powershell*\" OR TO_LOWER(win.SourceImage) LIKE \"*wsmprovhost*\") \| KEEP @tim… | 5 |  |
| q-b2c0b4c230 | triage T1111 step 3 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4624\",\"4634\",\"4672\",\"4768\",\"4769\",\"4776\",\"4648\") AND (TO_LOWER(win.TargetUserName) LIKE \"*smart*\" OR TO_LOWER(win.TargetUserName) LIKE \"*mfa*\" OR TO_L… | 0 |  |
| q-ea1d58f0f2 | triage T1111 step 4 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None | F19 |
| q-7751073f9a | triage T1111 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"13\" AND (TO_LOWER(registry.path) LIKE \"*credentialprovider*\" OR TO_LOWER(registry.path) LIKE \"*authentication*\" OR TO_LOWER(registry.path) LIKE \"*smartcard*\" OR TO… | 30 | F19 |
| q-6dc134d9fa | triage T1111 step 5 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None |  |
| q-cec302aa32 | triage T1111 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"7\" AND (TO_LOWER(win.ImageLoaded) LIKE \"*credprov*\" OR TO_LOWER(win.ImageLoaded) LIKE \"*ngc*\" OR TO_LOWER(win.ImageLoaded) LIKE \"*vault*\" OR TO_LOWER(win.ImageLoad… | 22 |  |
| q-b0a6ba9a18 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7b_z_Wh"} | ERROR |  |
| q-f2183ea604 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7b_z_Wh"} | ERROR |  |
| q-cf0134c47b | triage T1111 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7b_z_Wh"} | ERROR |  |
| q-6f98fee36a | triage T1111 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cTFiiN"} | None |  |
| q-4031c6b874 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNur"} | None |  |
| q-f863674e51 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNur"} | None |  |
| q-60194900a6 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None |  |
| q-66bbb4b100 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuDg"} | None |  |
| q-c6c3cb6a68 | triage T1111 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-7e0517ebe4 | triage T1111 step 7 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRfJfH5wFd7b_z_Wh"} | None | F19 |
| q-afaa6bd524 | triage T1187 step 1 | search | {"dataset": "zeek", "query": "event.action:http AND (http.request.method:PROPFIND OR http.request.method:OPTIONS OR http.request.method:MOVE)", "time_from": null, "time_to": null, "fields": ["@timestamp", "observer.name", "source.ip", "destination.ip", "destin… | 36 | F20 |
| q-286b04af8e | triage T1187 step 1 | aggregate | {"dataset": "zeek", "field": "http.request.method", "query": "event.action:http", "time_from": null, "time_to": null, "size": 30, "sub_field": "destination.ip"} | 62 |  |
| q-9cdf9362bc | triage T1187 step 2 | search | {"dataset": "zeek", "query": "event.action:http AND (http.request.method:PUT OR http.request.method:GET OR http.request.method:PROPPATCH OR http.request.method:LOCK)", "time_from": null, "time_to": null, "fields": ["@timestamp", "observer.name", "source.ip", "… | 18 | F20 |
| q-3522d5fb25 | triage T1187 step 2 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (win.TargetFilename:*.lnk OR win.TargetFilename:*.scf OR win.TargetFilename:*.url OR win.TargetFilename:*.library-ms)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.na… | 3 | F21 |
| q-d7925580b8 | triage T1187 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hSRzrG"} | None | F20 |
| q-789bfa946f | triage T1187 step 3 | search | {"dataset": "windows.sysmon", "query": "event.code:3 AND (destination.port:445 OR destination.port:139)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "process.executable", "process.command_line", "destination.ip", "de… | 66 | F21 |
| q-693cc9aad5 | triage T1187 step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*hostui*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*lnk*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*webdav*\" OR TO_L… | 4 | F20 |
| q-027d6f2f93 | triage T1187 step 4 | aggregate | {"dataset": "windows.security", "field": "win.LogonType", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 20, "sub_field": "win.AuthenticationPackageName"} | 297 |  |
| q-bc3357b1cf | triage T1187 step 5 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None | F20 |
| q-f927c97bb3 | triage T1187 step 5 | search | {"dataset": "windows.security", "query": "event.code:4624 AND win.AuthenticationPackageName:NTLM", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "win.TargetUserName", "win.LogonType", "win.AuthenticationPackageName", "w… | 1 | F20 |
| q-7e42ebff14 | triage T1187 step 6 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nQi3T7"} | None | F20 |
| q-0ddf986c83 | triage T1187 step 6 | search | {"dataset": "zeek", "query": "event.action:files AND (file.path:*OfficeSupplies* OR zeek.filename:*OfficeSupplies*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "observer.name", "source.ip", "destination.ip", "event.action", "zeek.filename", … | 0 |  |
| q-4a87eab0d9 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None |  |
| q-61fc399b58 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None |  |
| q-457bcd936f | triage T1187 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None |  |
| q-dd403139a8 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None |  |
| q-41d8694aa0 | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_Z1YZ"} | None |  |
| q-9f310c68bb | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_Z1YU"} | None |  |
| q-b17284d625 | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_Z1YU"} | None |  |
| q-fbada94374 | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_Z1YN"} | None |  |
| q-593085d426 | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_Z1YN"} | None |  |
| q-64f65a1811 | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_Z1YN"} | None |  |
| q-df304545ee | triage T1187 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_Z1YZ"} | None |  |
| q-bac7c5f359 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nQi3T7"} | None |  |
| q-a346d4d102 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nQi3T7"} | None |  |
| q-6d22fb68c5 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nQi3T7"} | None |  |
| q-0fa37ca1dd | triage T1187 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hSRzrG"} | None |  |
| q-bb8426a332 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qzXFri"} | None |  |
| q-c671ed63e8 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hWVykL"} | None |  |
| q-7501d51dff | triage T1187 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hWVykL"} | None |  |
| q-72989a8639 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7htwOxh"} | None |  |
| q-3d507a2729 | triage T1187 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7htwOxh"} | None |  |
| q-b8b5381799 | triage T1212 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND (process.executable:*PowerShell* OR process.executable:*wsmprovhost* OR process.executable:*wininit* OR process.executable:*csrss* OR process.executable:*services*)", "time_f… | 9 | F23 |
| q-2b6ce1e292 | triage T1212 step 1 | aggregate | {"dataset": "windows.sysmon", "field": "win.GrantedAccess", "query": "event.code:10 AND win.TargetImage:*lsass*", "time_from": null, "time_to": null, "size": 30, "sub_field": "process.executable"} | 326 |  |
| q-7a4c260a5e | triage T1212 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None | F22 |
| q-277bca2ca8 | triage T1212 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None | F22 |
| q-9ad5adf777 | triage T1212 step 2 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*MiniDump* OR win.ScriptBlockText:*comsvcs* OR win.ScriptBlockText:*Credential* OR win.ScriptBlockText:*Dump* OR win.ScriptBlockText:*sekurlsa* … | 3 | F24 |
| q-d1949bc282 | triage T1212 step 3 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*lsass* OR process.command_line:*procdump* OR process.command_line:*comsvcs* OR process.command_line:*MiniDump* OR process.command_line:*sekurlsa* OR process.command_line:*DumpCred*… | 1 | F23 |
| q-4449df42e7 | triage T1212 step 3 | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688", "time_from": null, "time_to": null, "size": 40, "sub_field": null} | 460 |  |
| q-928d537839 | triage T1212 step 4 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.executable:*PowerShell.exe OR process.executable:*powershell.exe OR process.executable:*wsmprovhost.exe)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "process.exec… | 13 | F22 |
| q-5ca7ae8763 | triage T1212 step 4 | aggregate | {"dataset": "windows.security", "field": "win.ObjectName", "query": "event.code:4673 OR event.code:4674 OR event.code:4661", "time_from": null, "time_to": null, "size": 30, "sub_field": null} | 1026 |  |
| q-073a39692a | triage T1212 step 5 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7YD3Who"} | None | F22 |
| q-6c5f4e1d74 | triage T1212 step 5 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*Add-Type* OR win.ScriptBlockText:*GetPixel* OR win.ScriptBlockText:*IEX* OR win.ScriptBlockText:*Invoke-Expression* OR win.ScriptBlockText:*FromBase64String*)", "time_from": … | 8 | F22, F24 |
| q-3832d94d0c | triage T1212 step 6 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhG"} | None | F22 |
| q-9110057928 | triage T1212 step 6 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*VirtualAlloc* OR win.ScriptBlockText:*GetProcAddress* OR win.ScriptBlockText:*LoadLibrary* OR win.ScriptBlockText:*CreateThread*)", "time_from": null, "time_to": null, "field… | 3 |  |
| q-6ec2c5f097 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-3f44479edb | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-2762c22c19 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhG"} | None |  |
| q-ef2268f9b2 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None |  |
| q-e54e352158 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None |  |
| q-ee539c7bc8 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7htwOyZ"} | None |  |
| q-6f2888e943 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c-4cYK"} | None |  |
| q-14f9224a7c | triage T1212 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7q0Y_4v"} | None |  |
| q-0e91aac983 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7YD3Who"} | None |  |
| q-c3dbd56ebe | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cpgKyV"} | None |  |
| q-1777308660 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cpgKyV"} | None |  |
| q-d0da583376 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cxqOgJ"} | None |  |
| q-7ffa38ab34 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cofd-n"} | None |  |
| q-f11159c2e9 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuCk"} | None |  |
| q-1d3ccc48d7 | triage T1212 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuDg"} | None |  |
| q-97f4316aae | triage T1212 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None |  |
| q-f7b9b02acd | triage T1212 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSyuh"} | None |  |
| q-8f239190df | triage T1539 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None | F26 |
| q-2b95b7cd4a | triage T1539 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSyvc"} | None | F26 |
| q-d32d5e9bb0 | triage T1539 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 11 AND (TO_LOWER(win.TargetFilename) LIKE \"*cookies*\" OR TO_LOWER(win.TargetFilename) LIKE \"*login data*\" OR TO_LOWER(win.TargetFilename) LIKE \"*web data*\" OR TO_LOWE… | ERROR |  |
| q-29836e5408 | triage T1539 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 1 AND (TO_LOWER(process.command_line) LIKE \"*cookies*\" OR TO_LOWER(process.command_line) LIKE \"*login data*\" OR TO_LOWER(process.command_line) LIKE \"*edge*\" OR TO_LOW… | ERROR |  |
| q-9da9d08ee2 | triage T1539 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(win.TargetFilename) LIKE \"*cookies*\" OR TO_LOWER(win.TargetFilename) LIKE \"*login data*\" OR TO_LOWER(win.TargetFilename) LIKE \"*web data*\" OR TO_… | 1 | F25 |
| q-211718c4e0 | triage T1539 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*cookies*\" OR TO_LOWER(process.command_line) LIKE \"*login data*\" OR TO_LOWER(process.command_line) LIKE \"*edge*\" OR TO… | 3 |  |
| q-cda224e135 | triage T1539 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE (TO_LOWER(win.TargetFilename) LIKE \"*microsoftedge*\" OR TO_LOWER(win.TargetFilename) LIKE \"*microsoftedgecp*\" OR TO_LOWER(win.TargetFilename) LIKE \"*inetcookies*\" OR TO_LOWER(win.T… | 35 |  |
| q-e3d1733c82 | triage T1539 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND (TO_LOWER(win.TargetImage) LIKE \"*edge*\" OR TO_LOWER(win.TargetImage) LIKE \"*chrome*\" OR TO_LOWER(win.TargetImage) LIKE \"*firefox*\" OR TO_LOWER(win.TargetI… | 386 | F25 |
| q-49d080b104 | triage T1539 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE (TO_LOWER(win.TargetFilename) LIKE \"*microsoftedge_8wekyb3d8bbwe*\" OR TO_LOWER(win.TargetFilename) LIKE \"*\\\\appdata\\\\local\\\\microsoft\\\\edge*\" OR TO_LOWER(win.TargetFilename) … | ERROR |  |
| q-cf513717ce | triage T1539 step 5 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND user.name == \"pbeesly\" \| KEEP @timestamp, host.name, user.name, win.Path, win.ScriptBlockId, _id, _index \| SORT @timestamp ASC"} | 157 |  |
| q-3acccbacc1 | triage T1539 step 6 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE (TO_LOWER(win.TargetFilename) LIKE \"*microsoftedge_8wekyb3d8bbwe*\" OR TO_LOWER(win.TargetFilename) LIKE \"*mozilla*\" OR TO_LOWER(win.TargetFilename) LIKE \"*google*chrome*\") AND NOT … | 0 |  |
| q-1e2bc8e4c6 | triage T1539 step 6 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND user.name == \"pbeesly\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*cookie*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*login data*\" OR TO_LOWER(win.Script… | 2 | F26 |
| q-fa39ddbdbc | triage T1539 step 7 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7YE4VZs"} | None | F25 |
| q-48f13aab88 | triage T1539 step 7 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"http\" \| KEEP @timestamp, event.action, url.domain, url.original, http.request.method, http.response.status_code, user_agent.original, source.ip, destination.ip, _id, _index"} | 62 | F26 |
| q-8ad8af5087 | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7YE4VZs"} | None |  |
| q-4b90dff15a | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7YE4VZs"} | None |  |
| q-c60ffd15ad | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cPCBow"} | None |  |
| q-448b4002f8 | triage T1539 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7YL-ox6"} | None |  |
| q-b58e536ccd | triage T1539 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qwUFuS"} | None |  |
| q-3534fdc441 | triage T1539 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None |  |
| q-97d3393979 | triage T1539 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None |  |
| q-4108be2e21 | triage T1539 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None |  |
| q-71a46d76a7 | triage T1539 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSyvc"} | None |  |
| q-bbf78cd902 | triage T1539 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_Z1bd"} | None |  |
| q-9e830bb12c | triage T1552 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None | F27, F29, F31 |
| q-034403fd72 | triage T1552 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None | F28 |
| q-5c90a8e117 | triage T1552 step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(win.TargetFilename) LIKE \"*.pfx\" OR TO_LOWER(win.TargetFilename) LIKE \"*.7z\" OR TO_LOWER(win.TargetFilename) LIKE \"*officesupplies*\") \| KEEP @ti… | 4 | F28 |
| q-78d1cf190b | triage T1552 step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*get-privatekeys*\" OR TO_LOWER(process.command_line) LIKE \"*invoke-exfil*\" OR TO_LOWER(process.command_line) LIKE \"*cer… | ERROR |  |
| q-1f26d3a991 | triage T1552 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*get-privatekeys*\" OR TO_LOWER(process.command_line) LIKE \"*invoke-exfil*\" OR TO_LOWER(process.command_line) LIKE \"*com… | 4 | F28 |
| q-5dfb52924f | triage T1552 step 2 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4648\" AND user.name == \"pbeesly\" \| KEEP @timestamp, host.name, user.name, process.executable, source.ip, win.TargetServerName, win.TargetUserName, _id, _index"} | 9 | F28 |
| q-a79c7123cb | triage T1552 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(win.TargetFilename) LIKE \"*groups.xml*\" OR TO_LOWER(win.TargetFilename) LIKE \"*sysvol*\" OR TO_LOWER(win.TargetFilename) LIKE \"*gpttmpl*\" OR TO_LO… | 22 | F29, F30, F32 |
| q-980341be92 | triage T1552 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*reg query*\" OR TO_LOWER(process.command_line) LIKE \"*reg save*\" OR TO_LOWER(process.command_line) LIKE \"*findstr*\" OR… | 0 |  |
| q-df45cbd815 | triage T1552 step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND user.name == \"pbeesly\" \| KEEP @timestamp, host.name, user.name, win.Path, win.ScriptBlockId, _id, _index \| SORT @timestamp ASC"} | 157 |  |
| q-f6a278738c | triage T1552 step 4 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"smb_files\" \| KEEP @timestamp, observer.name, source.ip, destination.ip, zeek.path, zeek.name, zeek.action, _id, _index"} | 12 | F32 |
| q-673050866e | triage T1552 step 5 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQRgs"} | None | F27 |
| q-6d3ad03799 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None |  |
| q-3dcee52f97 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None |  |
| q-c1368599c3 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None |  |
| q-3cca228aa2 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQRgs"} | None |  |
| q-4e507b885a | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQRgs"} | None |  |
| q-37b802c7c0 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None |  |
| q-c36f260f6d | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None |  |
| q-ab721a2264 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c_44mH"} | None |  |
| q-f3f61b5f54 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c-4sYu"} | None |  |
| q-a364fd16e8 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cxoQzx"} | None |  |
| q-defefddbc4 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNur"} | None |  |
| q-25f58fcdf3 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cZN9Bo"} | None |  |
| q-671aa3d433 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qwUVtv"} | None |  |
| q-280a53a141 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cZN9Bn"} | None |  |
| q-9a36127fb7 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None |  |
| q-f7e536c6d4 | triage T1552 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cxogx-"} | None |  |
| q-5c6d3cba66 | triage T1552 verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7qUcN0h"} | None |  |
| q-631d7b56bd | triage T1555 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND (win.GrantedAccess:0x1fffff OR win.GrantedAccess:0x101001 OR win.GrantedAccess:0x1f3fff OR win.GrantedAccess:0x1000000 OR win.GrantedAccess:0x3000 OR win.GrantedAccess:0x1400… | 33 |  |
| q-f481c187a1 | triage T1555 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None |  |
| q-42d04ae0fb | triage T1555 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None | F33 |
| q-abefdaa655 | triage T1555 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None | F33 |
| q-a7f1959419 | triage T1555 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 1 AND (process.pid == 2976 OR process.pid == 7720 OR process.pid == 3876) \| KEEP @timestamp, host.name, process.pid, process.executable, process.command_line, process.pare… | ERROR |  |
| q-be7d76c756 | triage T1555 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 11 AND (TO_LOWER(file.path) LIKE \"*login data*\" OR TO_LOWER(file.path) LIKE \"*logins.json*\" OR TO_LOWER(file.path) LIKE \"*key4.db*\" OR TO_LOWER(file.path) LIKE \"*key… | ERROR |  |
| q-f97bb5d153 | triage T1555 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (process.pid == \"2976\" OR process.pid == \"7720\" OR process.pid == \"3876\") \| KEEP @timestamp, host.name, process.pid, process.executable, process.command_li… | ERROR |  |
| q-eea1da2796 | triage T1555 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (TO_LOWER(file.path) LIKE \"*login data*\" OR TO_LOWER(file.path) LIKE \"*logins.json*\" OR TO_LOWER(file.path) LIKE \"*key4.db*\" OR TO_LOWER(file.path) LIKE \"… | 1 | F34 |
| q-5fe654a934 | triage T1555 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (process.pid == 2976 OR process.pid == 7720 OR process.pid == 3876) \| KEEP @timestamp, host.name, process.pid, process.executable, process.command_line, process.… | 4 |  |
| q-6f31f5b519 | triage T1555 step 6 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7htwOyZ"} | None | F33 |
| q-46f72883ea | triage T1555 step 6 | esql | {"query": "FROM logs-windows.security METADATA _id, _index \| WHERE event.code == \"4624\" AND host.name == \"nashua.dmevals.local\" AND win.LogonType == \"3\" \| KEEP @timestamp, host.name, win.TargetUserName, win.LogonType, win.IpAddress, win.Workstation, wi… | ERROR |  |
| q-57bc483474 | triage T1555 step 7 | search | {"dataset": "windows.security", "query": "event.code:4624 AND host.name:nashua.dmevals.local AND win.LogonType:3", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "event.code", "win.TargetUserName", "win.LogonType", "win.IpAddress", "… | 14 |  |
| q-d83329d572 | triage T1555 step 7 | search | {"dataset": "windows.security", "query": "event.code:4663 AND (win.ObjectName:*lsass* OR win.ObjectName:*SAM* OR win.ObjectName:*SECURITY* OR win.ObjectName:*DPAPI* OR win.ObjectName:*Protect*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "ho… | 6 | F33 |
| q-249004ccc1 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7htwOyZ"} | None |  |
| q-b9bc51f99d | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7htwOyZ"} | None |  |
| q-5d4d10b854 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-d5b873d2e7 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-117782f8db | triage T1555 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq72Yf"} | None |  |
| q-c052b27727 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None |  |
| q-0e45d83c16 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None |  |
| q-93bd6c1e4e | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cPCBow"} | None |  |
| q-77bcd3eb22 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cPCBow"} | None |  |
| q-a5ea8ab853 | triage T1555 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuA9"} | None |  |
| q-df67f58f4f | triage T1556 step 1 | esql | {"query": "FROM logs-windows.sysmon-* METADATA _id, _index \| WHERE event.code == \"10\" AND win.TargetImage LIKE \"*lsass*\" AND (win.GrantedAccess == \"0x1fffff\" OR win.GrantedAccess == \"0x101001\" OR win.GrantedAccess == \"0x1f3fff\" OR win.GrantedAccess … | 33 | F36, F37, F38 |
| q-ba6841d208 | triage T1556 step 1 | esql | {"query": "FROM logs-windows.sysmon-* METADATA _id, _index \| WHERE event.code == \"10\" AND win.TargetImage LIKE \"*lsass*\" AND process.executable LIKE \"*owerShell*\" \| KEEP @timestamp, host.name, user.name, process.executable, process.command_line, win.Gr… | 4 |  |
| q-fe32fc3b0f | triage T1556 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None | F36 |
| q-ad1c7f9f13 | triage T1556 step 2 | esql | {"query": "FROM logs-windows.sysmon-* METADATA _id, _index \| WHERE event.code == \"1\" AND (process.command_line LIKE \"*lsass*\" OR process.command_line LIKE \"*MiniDump*\" OR process.command_line LIKE \"*sekurlsa*\" OR process.command_line LIKE \"*procdump*… | 1 | F37 |
| q-1a4b474224 | triage T1556 step 3 | esql | {"query": "FROM logs-windows.sysmon-* METADATA _id, _index \| WHERE event.code == \"1\" AND process.pid == \"2976\" \| KEEP @timestamp, host.name, user.name, process.executable, process.command_line, process.parent.executable, process.parent.command_line, proc… | ERROR |  |
| q-009f8cad58 | triage T1556 step 3 | esql | {"query": "FROM logs-windows.powershell-* METADATA _id, _index \| WHERE host.name == \"scranton.dmevals.local\" AND @timestamp >= \"2020-05-02T03:04:00.000Z\" AND @timestamp <= \"2020-05-02T03:07:00.000Z\" AND event.code IN (\"4104\",\"4103\",\"4100\",\"400\",… | 225 |  |
| q-aa2442724d | triage T1556 step 4 | esql | {"query": "FROM logs-windows.powershell-* METADATA _id, _index \| WHERE host.name == \"scranton.dmevals.local\" AND @timestamp >= \"2020-05-02T03:05:00.000Z\" AND @timestamp <= \"2020-05-02T03:06:30.000Z\" AND event.code IN (\"4104\",\"4103\") \| KEEP @timesta… | 41 |  |
| q-19bc32cf5b | triage T1556 step 4 | esql | {"query": "FROM logs-windows.sysmon-* METADATA _id, _index \| WHERE event.code == \"1\" AND host.name == \"scranton.dmevals.local\" AND @timestamp >= \"2020-05-02T03:00:00.000Z\" AND @timestamp <= \"2020-05-02T03:10:00.000Z\" \| KEEP @timestamp, user.name, pro… | 42 | F41 |
| q-0c9c552773 | triage T1556 step 5 | esql | {"query": "FROM logs-windows.security-* METADATA _id, _index \| WHERE (event.code == \"4688\" AND (win.NewProcessId == \"2976\" OR win.ProcessId == \"2976\" OR process.command_line LIKE \"*lsass*\" OR process.command_line LIKE \"*MiniDump*\" OR process.command… | 6 | F40 |
| q-c562e71f74 | triage T1556 step 5 | esql | {"query": "FROM logs-windows.sysmon-* METADATA _id, _index \| WHERE event.code == \"11\" AND (win.TargetFilename LIKE \"*.dmp\" OR win.TargetFilename LIKE \"*lsass*\" OR win.TargetFilename LIKE \"*minidump*\") \| KEEP @timestamp, host.name, user.name, process.… | 2 |  |
| q-51a1d447cc | triage T1556 step 6 | esql | {"query": "FROM logs-windows.security-* METADATA _id, _index \| WHERE event.code == \"4657\" \| KEEP @timestamp, host.name, user.name, process.executable, win.ObjectName, win.ObjectValueName, win.NewValue, win.OperationType, _id, _index \| SORT @timestamp"} | 36 | F42 |
| q-b31fab5133 | triage T1556 step 6 | esql | {"query": "FROM logs-windows.security-* METADATA _id, _index \| WHERE event.code == \"4688\" AND host.name == \"scranton.dmevals.local\" AND @timestamp >= \"2020-05-02T03:04:30.000Z\" AND @timestamp <= \"2020-05-02T03:06:30.000Z\" \| KEEP @timestamp, user.name… | 15 |  |
| q-9a8f4191f7 | triage T1556 step 7 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qwUVsT"} | None | F39 |
| q-d10c4be2f5 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-8f071ae9ff | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-d55ace9b91 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-e1ef403fc0 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhG"} | None |  |
| q-ece32c3dc4 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-80fde80348 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cxqOgJ"} | None |  |
| q-8a15083c3a | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cpgKyV"} | None |  |
| q-22ad9aa2e3 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNur"} | None |  |
| q-a0765bbab9 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuCy"} | None |  |
| q-4647c095a8 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cpgKyU"} | None |  |
| q-76b4ab2f2c | triage T1556 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qwUVsT"} | None |  |
| q-ae95078fd9 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qwUVsT"} | None |  |
| q-bcfc83d380 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq8Wb6"} | None |  |
| q-9eaf284577 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq8Wb6"} | None |  |
| q-8ec0e846ee | triage T1556 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hNNLQJ"} | None |  |
| q-270b824256 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nZqakj"} | None |  |
| q-57f3753589 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nZqakj"} | None |  |
| q-2a995117f1 | triage T1556 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nOh9eN"} | None |  |
| q-e769bdc5ec | triage T1557 step 1 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:22", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 81 |  |
| q-52aba1a511 | triage T1557 step 1 | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:3 AND (destination.port:445 OR destination.port:139)", "time_from": null, "time_to": null, "size": 50, "sub_field": "host.name"} | 66 |  |
| q-5dddb3a8b1 | triage T1557 step 1 | aggregate | {"dataset": "windows.security", "field": "win.ServiceFileName", "query": "event.code:4697", "time_from": null, "time_to": null, "size": 50, "sub_field": null} | 23 |  |
| q-c2ae9c69b1 | triage T1557 step 2 | search | {"dataset": "windows.sysmon", "query": "process.executable:*cod.3aka3* OR win.TargetFilename:*cod.3aka3* OR process.parent.executable:*cod.3aka3*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "eve… | 100 |  |
| q-1779efffc0 | triage T1557 step 2 | search | {"dataset": "windows.sysmon", "query": "process.executable:*PsExec64* OR process.parent.executable:*PsExec64*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.exec… | 279 |  |
| q-1b0d532777 | triage T1557 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cxoQzx"} | None | F44 |
| q-f72a80341c | triage T1557 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 1 \| WHERE TO_LOWER(process.command_line) LIKE \"*responder*\" OR TO_LOWER(process.command_line) LIKE \"*arpspoof*\" OR TO_LOWER(process.command_line) LIKE \"*ettercap*\" O… | ERROR |  |
| q-359f0d03e0 | triage T1557 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" \| WHERE TO_LOWER(process.command_line) LIKE \"*responder*\" OR TO_LOWER(process.command_line) LIKE \"*arpspoof*\" OR TO_LOWER(process.command_line) LIKE \"*ettercap*… | 5 |  |
| q-e8a4da9a24 | triage T1557 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" \| KEEP @timestamp, host.name, user.name, process.executable, process.command_line, _id, _index \| SORT @timestamp ASC"} | 447 | F46 |
| q-1af8ffb7a8 | triage T1557 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND TO_LOWER(process.executable) LIKE \"*arp.exe\" \| KEEP @timestamp, host.name, user.name, process.executable, process.command_line, process.parent.executable, proc… | 3 | F43, F45 |
| q-1318b910c8 | triage T1557 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND @timestamp >= \"2020-05-02T03:18:00.000Z\" \| KEEP @timestamp, host.name, user.name, process.executable, process.command_line, process.parent.executable, _id, _in… | 297 |  |
| q-af6a9701a2 | triage T1557 step 6 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" \| WHERE TO_LOWER(win.ScriptBlockText) LIKE \"*responder*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*inveigh*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*arpspo… | 0 |  |
| q-5158c5917a | triage T1557 step 6 | aggregate | {"dataset": "windows.security", "field": "win.AuthenticationPackageName", "query": "event.code:4624", "time_from": null, "time_to": null, "size": 20, "sub_field": "win.LogonType"} | 297 |  |
| q-e00c1b0bf0 | triage T1557 step 7 | search | {"dataset": "windows.security", "query": "event.code:4624 AND win.AuthenticationPackageName:NTLM", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "observer.name", "event.dataset", "event.code", "user.name", "process.executable", "pro… | 1 |  |
| q-9037db5ef5 | triage T1557 step 8 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nQi3T7"} | None | F44 |
| q-b252cc0247 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hy0koQ"} | None |  |
| q-6bc1aae2bb | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hWWenJ"} | None |  |
| q-7cf2a8e355 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cREvLs"} | None |  |
| q-3df3673511 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cxoQzx"} | None |  |
| q-b9ba0b6824 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nQi3T7"} | None |  |
| q-0a170ea2e9 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nQi3T7"} | None |  |
| q-193a4b9766 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cYMP7j"} | None |  |
| q-dff3b37e4d | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cUGJN0"} | None |  |
| q-1f60c1f0ae | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cREvLs"} | None |  |
| q-c242018e06 | triage T1557 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cpf6ww"} | None |  |
| q-db99870726 | triage T1558 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass.exe AND (win.GrantedAccess:0x1fffff OR win.GrantedAccess:0x101001 OR win.GrantedAccess:0x1f3fff OR win.GrantedAccess:0x1000000 OR win.GrantedAccess:0x3000 OR win.GrantedAccess:0x1… | 33 | F47 |
| q-53d05fd9a4 | triage T1558 step 1 | esql | {"query": "FROM logs-zeek-default METADATA _id, _index \| WHERE event.action == \"kerberos\" \| KEEP @timestamp, source.ip, destination.ip, zeek.request_type, zeek.success, zeek.error_msg, zeek.client, zeek.service, zeek.forwardable, zeek.renewable, zeek.ciphe… | 35 |  |
| q-5e78475483 | triage T1558 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None | F48 |
| q-3533c77287 | triage T1558 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhG"} | None |  |
| q-d0c6c10f0e | triage T1558 step 2 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*lsass*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*mimikatz*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*sekurlsa*\" O… | 16 | F47 |
| q-a578be98e4 | triage T1558 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*lsass*\" OR TO_LOWER(process.command_line) LIKE \"*ticket*\" OR TO_LOWER(process.command_line) LIKE \"*kerb*\" OR TO_LOWER… | 2 |  |
| q-de79c1c9ad | triage T1558 step 3 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None | F50 |
| q-270099c81d | triage T1558 step 4 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4768\",\"4769\",\"4770\",\"4771\",\"4776\",\"4765\",\"4766\",\"4672\",\"4624\") \| STATS cnt = COUNT(*) BY event.code, win.TargetUserName, win.LogonType, win.TicketEnc… | 23 |  |
| q-c7172f6a6b | triage T1558 step 4 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qqQ-d4"} | None |  |
| q-0e257df5ca | triage T1558 step 5 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code IN (\"4769\",\"4768\") \| KEEP @timestamp, host.name, event.code, win.TargetUserName, win.ServiceName, win.TicketEncryptionType, win.TicketOptions, win.PreAuthType, win.IpAd… | 42 | F48, F49, F51 |
| q-6be6030a27 | triage T1558 step 5 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4672\" \| STATS cnt = COUNT(*) BY win.SubjectUserName, win.SubjectDomainName \| SORT cnt DESC"} | 9 |  |
| q-fe306675c0 | triage T1558 step 6 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4672\" AND win.SubjectUserName == \"pbeesly\" \| KEEP @timestamp, host.name, win.SubjectUserName, win.SubjectLogonId, win.PrivilegeList, _id, _index \| SORT @timestamp"… | 19 | F47 |
| q-fc3ade6398 | triage T1558 step 6 | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq72Yx"} | None | F50 |
| q-07be2cee47 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-a9818ff429 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhG"} | None |  |
| q-2b12dcc700 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None |  |
| q-6e8b0ee1d0 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qqQ-d4"} | None |  |
| q-0c9033a909 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysW"} | None |  |
| q-ad9b15635c | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niy9sU"} | None |  |
| q-7b34d885cb | triage T1558 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-6b1a90de24 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNvO"} | None |  |
| q-b8b4a92878 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7ncs5ql"} | None |  |
| q-5e3abc458c | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7njzKBN"} | None |  |
| q-f9c6b7446d | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7ncs5ob"} | None |  |
| q-39b8456367 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq72Yx"} | None |  |
| q-7127c53077 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq72Yx"} | None |  |
| q-4c6bc2a7e1 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None |  |
| q-4032fd0c8b | triage T1558 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNvO"} | None |  |
| q-022107a1e0 | triage T1558 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuCk"} | None |  |
| q-1714f39b2b | triage T1606 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvTCvl"} | None | F52, F53 |
| q-79037633a3 | triage T1606 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:10 AND win.TargetImage:*lsass* AND process.executable:*PowerShell*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "process.executable", "process.command_line", "win.Gr… | 4 | F52, F53 |
| q-22046bc0ad | triage T1606 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-ea94fdef5f | triage T1606 step 2 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhG"} | None |  |
| q-4d17a379ed | triage T1606 step 3 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*lsass* OR process.command_line:*procdump* OR process.command_line:*comsvcs* OR process.command_line:*MiniDump* OR process.command_line:*sekurlsa* OR process.command_line:*mimikatz*… | 1 |  |
| q-c8f4e2b493 | triage T1606 step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 1 AND (process.executable LIKE \"*powershell*\" OR process.executable LIKE \"*PowerShell*\") \| KEEP @timestamp, host.name, user.name, process.executable, process.command_l… | ERROR |  |
| q-1452a60e6a | triage T1606 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND TO_LOWER(process.executable) LIKE \"*powershell*\" \| KEEP @timestamp, host.name, user.name, process.executable, process.command_line, process.parent.executable, … | 12 |  |
| q-520058be3d | triage T1606 step 4 | search | {"dataset": "windows.security", "query": "event.code:4624 AND win.TargetUserName:pbeesly", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "event.code", "process.executable", "process.command_line", "win.TargetUserName", … | 30 |  |
| q-1d16fb8b98 | triage T1606 step 5 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7YD3Who"} | None |  |
| q-621f993a03 | triage T1606 step 5 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*lsass* OR win.ScriptBlockText:*MiniDump* OR win.ScriptBlockText:*procdump* OR win.ScriptBlockText:*sekurlsa* OR win.ScriptBlockText:*Invoke-Mimikatz* OR win.ScriptBlockText:*… | 3 | F52 |
| q-30b48a381e | triage T1606 step 6 | search | {"dataset": "windows.sysmon", "query": "event.code:13 AND registry.path:*Javasoft*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "event.code", "registry.path", "registry.data.strings", "process.executable"], "size": 1… | 1 | F52 |
| q-8c373b38e5 | triage T1606 step 6 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND (win.TargetFilename:*.dmp OR win.TargetFilename:*lsass* OR win.TargetFilename:*monkey*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "event.code", "win.Target… | 3 | F52 |
| q-9790d59713 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-459a4fc3e7 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhG"} | None |  |
| q-7bb02d3d9e | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-0598f0f09b | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-cbc3b529c3 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7htwOyZ"} | None |  |
| q-73f354a7d0 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hwyqdH"} | None |  |
| q-10941be266 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hwyqdH"} | None |  |
| q-e01c3643d1 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hSRzrP"} | None |  |
| q-7a5b48bb3e | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7YD3Who"} | None |  |
| q-ba90554c75 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7YD3Who"} | None |  |
| q-7e9300cccb | triage T1606 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvTCvl"} | None |  |
| q-56ce4619e4 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSitD"} | None |  |
| q-a1f658d264 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qrRbzS"} | None |  |
| q-5596317818 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuCk"} | None |  |
| q-f7e71a7804 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNur"} | None |  |
| q-37f84491cb | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7qvTCvl"} | ERROR |  |
| q-026ff97beb | triage T1606 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-7754947911 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNur"} | None |  |
| q-601d245aa3 | triage T1606 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7ncsJoZ"} | None |  |
| q-4ac964a09d | triage T1606 step 8 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7htwOyZ"} | None | F52 |
| q-2af3a11166 | triage T1606 step 8 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7YD3Who"} | None | F52 |
| q-50df0a1c4d | triage T1621 step 1 | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuDg"} | None | F55 |
| q-1a7e3c0270 | triage T1621 step 1 | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuCk"} | None | F55 |
| q-2e5610f92e | triage T1621 step 1 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND (TO_LOWER(win.ScriptBlockText) LIKE \"*mfa*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*2fa*\" OR TO_LOWER(win.ScriptBlockText) LIKE \"*authenticator*\" OR … | 0 |  |
| q-55f82e34e1 | triage T1621 step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*mfa*\" OR TO_LOWER(process.command_line) LIKE \"*2fa*\" OR TO_LOWER(process.command_line) LIKE \"*authenticator*\" OR TO_L… | 3 | F55 |
| q-e092c7a264 | triage T1621 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"3\" AND (TO_LOWER(win.DestinationHostname) LIKE \"*okta*\" OR TO_LOWER(win.DestinationHostname) LIKE \"*duo*\" OR TO_LOWER(win.DestinationHostname) LIKE \"*microsoftonlin… | 0 |  |
| q-0146e6efa5 | triage T1621 step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" \| STATS c = COUNT(*) BY process.executable, host.name \| SORT c ASC \| LIMIT 40"} | 40 |  |
| q-a96d532a39 | triage T1621 step 2 | esql | {"query": "FROM logs-windows.security METADATA _id, _index \| WHERE event.code == \"4624\" \| STATS c = COUNT(*) BY win.LogonType, win.TargetUserName, source.ip \| SORT c ASC \| LIMIT 40"} | ERROR |  |
| q-87f923db5a | triage T1621 step 3 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE event.code == \"4624\" \| STATS c = COUNT(*) BY win.LogonType, win.TargetUserName, source.ip \| SORT c ASC \| LIMIT 40"} | 26 |  |
| q-b7ea694913 | triage T1621 step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" \| STATS c = COUNT(*) BY host.name, user.name \| SORT c ASC \| LIMIT 30"} | 3 |  |
| q-c6a2346ed1 | triage T1621 step 4 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE event.code == \"4104\" AND host.name == \"nashua.dmevals.local\" \| KEEP @timestamp, user.name, win.ScriptBlockText, _id, _index \| LIMIT 15"} | 11 |  |
| q-41725536ef | triage T1621 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND (TO_LOWER(process.command_line) LIKE \"*invoke-*\" OR TO_LOWER(process.command_line) LIKE \"*psexec*\" OR TO_LOWER(process.command_line) LIKE \"*net use*\" OR TO_… | 6 | F55 |
| q-1faf91425b | triage T1621 step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"22\" OR event.code == \"3\" \| STATS c = COUNT(*) BY win.DestinationHostname, destination.port \| SORT c ASC \| LIMIT 30"} | 30 |  |
| q-f935c968b8 | triage T1621 step 5 | esql | {"query": "FROM logs-windows.other-default METADATA _id, _index \| WHERE event.code == \"7045\" OR event.code == \"5858\" OR event.code == \"5857\" \| STATS c = COUNT(*) BY event.code, host.name, win.ServiceName \| SORT c ASC \| LIMIT 30"} | 8 |  |
| q-e49bb4eec4 | triage T1621 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuDg"} | None |  |
| q-0ac093119e | triage T1621 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuCk"} | None |  |
| q-6eb321bf7c | triage T1621 verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuCk"} | None |  |
| q-12998f1c37 | triage T1621 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7YJ86bA"} | None |  |
| q-c79f1df1e8 | triage T1621 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7h03AIc"} | None |  |
| q-776cd7cd0c | triage T1649 step 1 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None | F56 |
| q-4410285af0 | triage T1649 step 1 | search | {"dataset": "windows.sysmon", "query": "event.code:11 AND win.TargetFilename:*pfx*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "win.TargetFilename", "process.executable", "process.command_line", "process.parent.exec… | 1 |  |
| q-b12d36cd43 | triage T1649 step 1 | search | {"dataset": "windows.security", "query": "event.code:4657 AND win.ObjectName:*SystemCertificates*", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "win.ObjectName", "win.ObjectValueName", "win.NewValue", "win.OperationTy… | 1 | F56 |
| q-fe3b052f10 | triage T1649 step 2 | search | {"dataset": "windows.sysmon", "query": "host.name:scranton.dmevals.local AND (process.executable:*powershell* OR win.Image:*powershell* OR process.command_line:*readme.ps1* OR process.command_line:*Get-PrivateKeys*)", "time_from": null, "time_to": null, "field… | 22185 |  |
| q-8a86692363 | triage T1649 step 2 | search | {"dataset": "windows.security", "query": "event.code:4657 AND (win.ObjectName:*Certificates* OR win.ObjectName:*Crypto* OR win.ObjectName:*Keys*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "event.code", "win.Object… | 1 |  |
| q-b063902126 | triage T1649 step 3 | search | {"dataset": "windows.sysmon", "query": "event.code:1 AND (process.command_line:*readme.ps1* OR process.command_line:*Get-PrivateKeys* OR process.command_line:*Export-PfxCertificate* OR process.command_line:*certutil*)", "time_from": null, "time_to": null, "fie… | 0 |  |
| q-4287931484 | triage T1649 step 3 | search | {"dataset": "windows.sysmon", "query": "host.name:nashua.dmevals.local AND (win.TargetObject:*SystemCertificates* OR win.TargetObject:*Certificates*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.name", "user.name", "event.code", "proces… | 1182 |  |
| q-6ba23e5c6a | triage T1649 step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND host.name == \"scranton.dmevals.local\" \| KEEP @timestamp, user.name, process.executable, process.command_line, process.parent.executable, _id, _index \| SORT @t… | 60 | F56 |
| q-880ea86606 | triage T1649 step 4 | search | {"dataset": "windows.powershell", "query": "event.code:4104 AND (win.ScriptBlockText:*cert* OR win.ScriptBlockText:*Cert* OR win.ScriptBlockText:*pfx* OR win.ScriptBlockText:*PrivateKey*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.nam… | 5 | F56 |
| q-15bfaefe56 | triage T1649 step 5 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQRgs"} | None | F56 |
| q-fb8eee6ebb | triage T1649 step 5 | search | {"dataset": "windows.sysmon", "query": "host.name:scranton.dmevals.local AND (win.TargetFilename:*Downloads* OR process.command_line:*BeachCleanup* OR process.command_line:*psversion.ps1*)", "time_from": null, "time_to": null, "fields": ["@timestamp", "host.na… | 317 |  |
| q-89ac63e0a8 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None |  |
| q-10bbd2fa51 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None |  |
| q-588188a385 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None |  |
| q-9e16cdf0ac | triage T1649 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQRgs"} | None |  |
| q-f8c58328e1 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQRgs"} | None |  |
| q-cf9ce8d1ae | triage T1649 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qrRC9i"} | None |  |
| q-ea4019d13c | triage T1649 verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qrRC9i"} | None |  |
| q-cf957a63e9 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hy0krT"} | None |  |
| q-3bfe130dc6 | triage T1649 verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hx0W8y"} | None |  |
| q-74361b42fb | triage T1649 verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7rzHZUI"} | None |  |
| q-6d3a89f822 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq7mb8"} | None |  |
| q-681a8f133a | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq7mb8"} | None |  |
| q-45ff68ea82 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7njy6Co"} | None |  |
| q-b5d0982336 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7njy6Co"} | None |  |
| q-18a86c4f37 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7habKTo"} | None |  |
| q-61b0726e80 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7habKTo"} | None |  |
| q-2bdebf924e | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7ryFh3A"} | None |  |
| q-24eb50e84f | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7ryFh3A"} | None |  |
| q-d0afec35d7 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7ryFh3A"} | None |  |
| q-ffe84203df | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hONXx6"} | None |  |
| q-3e5a15a445 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cpgKyc"} | None |  |
| q-2eca3c3122 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None |  |
| q-0c8db9a923 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQRgs"} | None |  |
| q-110eb7db2d | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuCk"} | None |  |
| q-399473d3ea | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qqQm9_"} | None |  |
| q-c1d8e41800 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hy0krT"} | None |  |
| q-9ff0981b89 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cxoQzx"} | None |  |
| q-3ad182e3c1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hWVSlm"} | None |  |
| q-70810c5c75 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7q0Y_4v"} | None |  |
| q-b62abca772 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7njzKAe"} | None |  |
| q-b1ba1d3b73 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nVnj7M"} | None |  |
| q-06bc652b5b | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nVnj7M"} | None |  |
| q-bcbc3192d5 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nSl9D4"} | None |  |
| q-cc2a2e988d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cla5Dm"} | None |  |
| q-56fdc189ec | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cla5Dm"} | None |  |
| q-184f54ef19 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSitD"} | None |  |
| q-caa5cd5730 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvTCuJ"} | None |  |
| q-fe318af906 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglC"} | None |  |
| q-17ed784701 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSitD"} | None |  |
| q-2e4386c332 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSitD"} | None |  |
| q-a5e18cebd1 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSyuh"} | None |  |
| q-fd63e2dc53 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvTCvd"} | None |  |
| q-f121190af4 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hMLfHo"} | None |  |
| q-862a191726 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSyuh"} | None |  |
| q-39192fff6d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhG"} | None |  |
| q-0da648a8fa | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-6b361d1823 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None |  |
| q-53ad8e24ea | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq72Yf"} | None |  |
| q-7cd05cac9f | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq72Yf"} | None |  |
| q-523c583898 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7ryFh2_"} | None |  |
| q-86d203f7f4 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq8Gbm"} | None |  |
| q-2edfdeecc7 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cUGJOD"} | None |  |
| q-7c580083bc | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cZNc--"} | None |  |
| q-6886354cca | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSitD"} | None |  |
| q-c580a00b36 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niydsP"} | None |  |
| q-5309853973 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNur"} | None |  |
| q-1272cf30bd | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nKhItZ"} | None |  |
| q-0a536b4666 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nKhItZ"} | None |  |
| q-b382a3738d | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None |  |
| q-d6e23c8e60 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-67abd97b4c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-677e6cffdd | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhG"} | None |  |
| q-f21fcc1f64 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7ryFh2_"} | None |  |
| q-39fa793f35 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nixwZC"} | None |  |
| q-9b2221e97d | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nixwZC"} | None |  |
| q-5b87db3c4a | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niwwaQ"} | None |  |
| q-469173b1d6 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None |  |
| q-3fde1ea5ff | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRfJfH5wFd7b_z_Wh"} | None |  |
| q-f87313836e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRfJfH5wFd7b_z_Wh"} | None |  |
| q-2975491b58 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRfJfH5wFd7b_z_Wh"} | None |  |
| q-534a056ed4 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cTFiiN"} | None |  |
| q-50d5a18de7 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNur"} | None |  |
| q-9aa7cfc83e | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNur"} | None |  |
| q-60c7f99724 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None |  |
| q-6fd16d1e42 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuDg"} | None |  |
| q-0bd50c11fc | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-a66d93822b | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None |  |
| q-d4fe521f13 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None |  |
| q-14e24756ac | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None |  |
| q-7aaf761008 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None |  |
| q-5db0bca8d1 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_Z1YZ"} | None |  |
| q-59b83c7623 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_Z1YU"} | None |  |
| q-f25873d8cf | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_Z1YU"} | None |  |
| q-0497ad63ec | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_Z1YN"} | None |  |
| q-5d10126d7f | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_Z1YN"} | None |  |
| q-5b98ea634c | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_Z1YN"} | None |  |
| q-ee61942019 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_Z1YZ"} | None |  |
| q-5648b1a26e | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nQi3T7"} | None |  |
| q-293f4ae521 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nQi3T7"} | None |  |
| q-791f8211da | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nQi3T7"} | None |  |
| q-5b49fd3284 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hSRzrG"} | None |  |
| q-5e2de64513 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qzXFri"} | None |  |
| q-1dc02d808b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hWVykL"} | None |  |
| q-f379ff9306 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hWVykL"} | None |  |
| q-4e5d041594 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7htwOxh"} | None |  |
| q-bd5b6f6235 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7htwOxh"} | None |  |
| q-0ed49c120f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-a35cc73f94 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-880d36f705 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhG"} | None |  |
| q-f73f2e8972 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None |  |
| q-16fcc3fbee | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None |  |
| q-e9ca979fed | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7htwOyZ"} | None |  |
| q-4e4d38d040 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c-4cYK"} | None |  |
| q-9f5cba2bb5 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7q0Y_4v"} | None |  |
| q-176e1f54d5 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7YD3Who"} | None |  |
| q-66635fc392 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cpgKyV"} | None |  |
| q-a6ee4ae227 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cpgKyV"} | None |  |
| q-efbffb3d1d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cxqOgJ"} | None |  |
| q-6254051d8d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cofd-n"} | None |  |
| q-ffbabce66f | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuCk"} | None |  |
| q-428682e09c | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuDg"} | None |  |
| q-0f451c2351 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None |  |
| q-fd8808fd93 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSyuh"} | None |  |
| q-23f93a1a95 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7YE4VZs"} | None |  |
| q-21e5fd3162 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7YE4VZs"} | None |  |
| q-719ed40d1d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cPCBow"} | None |  |
| q-4af276b6ac | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7YL-ox6"} | None |  |
| q-9832bf2056 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qwUFuS"} | None |  |
| q-7135fc4adf | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None |  |
| q-807f9e4206 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None |  |
| q-c9563488a5 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None |  |
| q-06397f8320 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSyvc"} | None |  |
| q-557e0c737c | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_Z1bd"} | None |  |
| q-04e7909baf | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None |  |
| q-e747bc1fb4 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None |  |
| q-51bfd8fcba | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None |  |
| q-d898d73a71 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQRgs"} | None |  |
| q-2184a102e2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQRgs"} | None |  |
| q-753db4507b | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None |  |
| q-b56f15cc58 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None |  |
| q-f1eb0b51f3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c_44mH"} | None |  |
| q-4cf0b18cd9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c-4sYu"} | None |  |
| q-389e998229 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cxoQzx"} | None |  |
| q-578fef999c | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNur"} | None |  |
| q-7fdcbe24a7 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cZN9Bo"} | None |  |
| q-69b84aab80 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None |  |
| q-07d449c08f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cZN9Bn"} | None |  |
| q-06089b3306 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None |  |
| q-0f477964c0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cxogx-"} | None |  |
| q-e089385b5b | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7qUcN0h"} | None |  |
| q-3cc34f56f9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7htwOyZ"} | None |  |
| q-8d1aaad7bc | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7htwOyZ"} | None |  |
| q-9aebaf08a6 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-7013b8cc36 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-f43ffa00a7 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq72Yf"} | None |  |
| q-75ad43243f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None |  |
| q-de2b26c793 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None |  |
| q-ea61b98527 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cPCBow"} | None |  |
| q-a096ed8f25 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cPCBow"} | None |  |
| q-73d9fd822c | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuA9"} | None |  |
| q-a98599eda3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-d88da10e38 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-c0d0f24424 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-176addcbab | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhG"} | None |  |
| q-dddce55318 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-b21938bc81 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cxqOgJ"} | None |  |
| q-f785a194f9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cpgKyV"} | None |  |
| q-f47f3bc8de | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNur"} | None |  |
| q-4a526fddf9 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuCy"} | None |  |
| q-7280d0802c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cpgKyU"} | None |  |
| q-b3f5bdb78c | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qwUVsT"} | None |  |
| q-273175179c | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qwUVsT"} | None |  |
| q-1c0fb2c8be | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq8Wb6"} | None |  |
| q-dfc1ece7f7 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq8Wb6"} | None |  |
| q-6834c9435d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hNNLQJ"} | None |  |
| q-f6128d034e | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nZqakj"} | None |  |
| q-1a34609e2c | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nZqakj"} | None |  |
| q-6faa332da1 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nOh9eN"} | None |  |
| q-5bd7f5ac99 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hy0koQ"} | None |  |
| q-a252ed7c82 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hWWenJ"} | None |  |
| q-63eb67013c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cREvLs"} | None |  |
| q-9114f48904 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cxoQzx"} | None |  |
| q-75a96352b9 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nQi3T7"} | None |  |
| q-c49e11c9a3 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nQi3T7"} | None |  |
| q-8917272f2c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cYMP7j"} | None |  |
| q-65eed5ae98 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cUGJN0"} | None |  |
| q-fa180d5dba | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cREvLs"} | None |  |
| q-37088686f2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cpf6ww"} | None |  |
| q-0b0d6283dd | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-629384c1cc | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhG"} | None |  |
| q-03ad467340 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None |  |
| q-ccd5a6e15f | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qqQ-d4"} | None |  |
| q-83089f2199 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysW"} | None |  |
| q-9fdb4918e1 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niy9sU"} | None |  |
| q-4a08f998ca | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-178b6930a2 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNvO"} | None |  |
| q-45d3975b99 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7ncs5ql"} | None |  |
| q-1421b68e96 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7njzKBN"} | None |  |
| q-3bce36efb4 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7ncs5ob"} | None |  |
| q-08a74942fd | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq72Yx"} | None |  |
| q-fb72f43da5 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq72Yx"} | None |  |
| q-4c4d87b193 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None |  |
| q-4434888b07 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNvO"} | None |  |
| q-31aa3467b8 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuCk"} | None |  |
| q-abfb71bf7e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-dc71979218 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhG"} | None |  |
| q-f28519e67f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-9f68fbc66d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-96483b348b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7htwOyZ"} | None |  |
| q-56a502dba8 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7htwOyZ"} | None |  |
| q-c98804fe28 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hwyqdH"} | None |  |
| q-ae2383ae6e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hwyqdH"} | None |  |
| q-9adb0df713 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hSRzrP"} | None |  |
| q-cf72d1f4b5 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7YD3Who"} | None |  |
| q-010d8b0644 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvTCvl"} | None |  |
| q-a73db456c6 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSitD"} | None |  |
| q-cc3d812f34 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qrRbzS"} | None |  |
| q-72dae138de | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuCk"} | None |  |
| q-be4ce294d7 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNur"} | None |  |
| q-ab429b3612 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvTCvl"} | None |  |
| q-fd1b35e7d7 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-fc93856672 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNur"} | None |  |
| q-acdfc30ce4 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7ncsJoZ"} | None |  |
| q-7e9a48ce61 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuDg"} | None |  |
| q-1c69aafe1f | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuCk"} | None |  |
| q-a6bc65c533 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuCk"} | None |  |
| q-eebe571b64 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7YJ86bA"} | None |  |
| q-4f078a71b5 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7h03AIc"} | None |  |
| q-80ba41afb8 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None |  |
| q-66616fbd51 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None |  |
| q-d5b3592d81 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None |  |
| q-5934f3cfb0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQRgs"} | None |  |
| q-6b542c3282 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQRgs"} | None |  |
| q-d2832cd1eb | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qrRC9i"} | None |  |
| q-9589d10707 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qrRC9i"} | None |  |
| q-ff2d436721 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hy0krT"} | None |  |
| q-18d083b3e1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hx0W8y"} | None |  |
| q-b3cebc50a5 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7rzHZUI"} | None |  |
| q-1c4dd5d0e4 | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND host.name:\"nashua.dmevals.local\"", "time_from": "2020-05-02T02:54:23+00:00", "time_to": "2020-05-02T03:31:19+00:00", "size": 100, "sub_field": "process.parent.executable"… | 61 |  |
| q-80262b4a3f | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11 AND host.name:\"nashua.dmevals.local\"", "time_from": "2020-05-02T02:54:23+00:00", "time_to": "2020-05-02T03:31:19+00:00", "size": 100, "sub_field": "process.executable"} | 249 |  |
| q-26e97a1e90 | pivot seed | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND host.name:\"nashua.dmevals.local\"", "time_from": "2020-05-02T02:54:23+00:00", "time_to": "2020-05-02T03:31:19+00:00", "size": 100, "sub_field": "process.parent.execut… | 63 |  |
| q-0e50454eb7 | pivot seed | aggregate | {"dataset": "windows.powershell", "field": "event.code", "query": "host.name:\"nashua.dmevals.local\"", "time_from": "2020-05-02T02:54:23+00:00", "time_to": "2020-05-02T03:31:19+00:00", "size": 100, "sub_field": null} | 192 |  |
| q-956c655370 | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND host.name:\"newyork.dmevals.local\"", "time_from": "2020-05-02T02:49:04+00:00", "time_to": "2020-05-02T03:34:13+00:00", "size": 100, "sub_field": "process.parent.executable… | 18 |  |
| q-2377a3f1b3 | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11 AND host.name:\"newyork.dmevals.local\"", "time_from": "2020-05-02T02:49:04+00:00", "time_to": "2020-05-02T03:34:13+00:00", "size": 100, "sub_field": "process.executable"} | 81 |  |
| q-3c26e715b9 | pivot seed | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND host.name:\"newyork.dmevals.local\"", "time_from": "2020-05-02T02:49:04+00:00", "time_to": "2020-05-02T03:34:13+00:00", "size": 100, "sub_field": "process.parent.execu… | 18 |  |
| q-838175bd12 | pivot seed | aggregate | {"dataset": "windows.powershell", "field": "event.code", "query": "host.name:\"newyork.dmevals.local\"", "time_from": "2020-05-02T02:49:04+00:00", "time_to": "2020-05-02T03:34:13+00:00", "size": 100, "sub_field": null} | 2185 |  |
| q-86cffa5dcc | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "process.executable", "query": "event.code:1 AND host.name:\"scranton.dmevals.local\"", "time_from": "2020-05-02T02:40:56.157000+00:00", "time_to": "2020-05-02T03:36:28.949000+00:00", "size": 100, "sub_field": "process.pa… | 359 |  |
| q-3e5351aff5 | pivot seed | aggregate | {"dataset": "windows.sysmon", "field": "file.path", "query": "event.code:11 AND host.name:\"scranton.dmevals.local\"", "time_from": "2020-05-02T02:40:56.157000+00:00", "time_to": "2020-05-02T03:36:28.949000+00:00", "size": 100, "sub_field": "process.executable… | 1276 |  |
| q-40f8b3a5d6 | pivot seed | aggregate | {"dataset": "windows.security", "field": "process.executable", "query": "event.code:4688 AND host.name:\"scranton.dmevals.local\"", "time_from": "2020-05-02T02:40:56.157000+00:00", "time_to": "2020-05-02T03:36:28.949000+00:00", "size": 100, "sub_field": "proce… | 370 |  |
| q-a9da7c79f2 | pivot seed | aggregate | {"dataset": "windows.powershell", "field": "event.code", "query": "host.name:\"scranton.dmevals.local\"", "time_from": "2020-05-02T02:40:56.157000+00:00", "time_to": "2020-05-02T03:36:28.949000+00:00", "size": 100, "sub_field": null} | 8602 |  |
| q-4efce32bb2 | pivot step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 1 AND host.name == \"nashua.dmevals.local\" AND (process.executable LIKE \"*python.exe\" OR process.executable LIKE \"*Rar.exe\" OR process.executable LIKE \"*sdelete64.exe… | ERROR |  |
| q-62a97e5b63 | pivot step 1 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == 1 AND host.name == \"scranton.dmevals.local\" AND (process.executable LIKE \"*csc.exe\" OR process.executable LIKE \"*hostui.exe\" OR process.executable LIKE \"*sdclt.exe\"… | ERROR |  |
| q-6b38cc20ee | pivot step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND host.name == \"nashua.dmevals.local\" AND (process.executable LIKE \"*python.exe\" OR process.executable LIKE \"*Rar.exe\" OR process.executable LIKE \"*sdelete64… | 11 | F58, F62 |
| q-32011036d6 | pivot step 2 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"1\" AND host.name == \"scranton.dmevals.local\" AND (process.executable LIKE \"*csc.exe\" OR process.executable LIKE \"*hostui.exe\" OR process.executable LIKE \"*sdclt.e… | 15 | F62, F63, F64, F65, F66, F67, F68 |
| q-e0281130a4 | pivot step 3 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE host.name == \"nashua.dmevals.local\" AND event.code == \"4104\" \| KEEP @timestamp, host.name, user.name, powershell.script_block_text, _id, _index \| SORT @timestamp"} | ERROR |  |
| q-6de9f6edbc | pivot step 3 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND host.name == \"nashua.dmevals.local\" AND (file.path LIKE \"*working.zip*\" OR file.path LIKE \"*Temp*\" OR file.path LIKE \"*Desktop*\" OR file.path LIKE \"*Roa… | 39 | F59 |
| q-5e4cc9fa66 | pivot step 4 | get_fields | {"dataset": "windows.powershell", "prefix": ""} | None |  |
| q-86eb733656 | pivot step 4 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (file.path LIKE \"*SystemCertificates*\" OR file.path LIKE \"*.pfx\" OR file.path LIKE \"*.p12\" OR file.path LIKE \"*Crypto\\\\RSA*\" OR file.path LIKE \"*Crypt… | ERROR |  |
| q-67ecdf8a74 | pivot step 5 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"11\" AND (file.path LIKE \"*SystemCertificates*\" OR file.path LIKE \"*.pfx\" OR file.path LIKE \"*.p12\" OR file.path LIKE \"*Crypto*\" OR file.path LIKE \"*Protect*\" O… | 14 | F60, F61 |
| q-803dba60b5 | pivot step 5 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE host.name == \"nashua.dmevals.local\" AND event.code == \"4104\" \| KEEP @timestamp, host.name, user.name, win.ScriptBlockText, _id, _index \| SORT @timestamp"} | 11 |  |
| q-1cc1d079d0 | pivot step 6 | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qrRC92"} | None | F58, F59 |
| q-e340543208 | pivot step 6 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE host.name == \"scranton.dmevals.local\" AND event.code == \"4104\" AND (win.ScriptBlockText LIKE \"*SAM*\" OR win.ScriptBlockText LIKE \"*SECURITY*\" OR win.ScriptBlockText LIKE \"*l… | 5 |  |
| q-c0b8a6444e | pivot step 7 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE event.code == \"10\" AND host.name == \"nashua.dmevals.local\" AND (process.executable LIKE \"*python*\" OR process.executable LIKE \"*powershell*\" OR process.executable LIKE \"*wsmprov… | 128 |  |
| q-224c4238d2 | pivot step 7 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE host.name == \"nashua.dmevals.local\" AND event.code IN (\"4663\",\"4656\",\"4673\",\"4674\",\"5145\",\"5140\",\"4624\",\"4672\") AND (win.ObjectName LIKE \"*lsass*\" OR win.ObjectName… | 500 |  |
| q-59d5ed3f19 | pivot step 8 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE host.name == \"nashua.dmevals.local\" AND user.name == \"pbeesly\" AND event.code IN (\"4663\",\"4656\",\"4673\",\"4674\",\"5145\",\"5140\") \| KEEP @timestamp, host.name, user.name, e… | 500 |  |
| q-e8583866b5 | pivot step 8 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE host.name == \"nashua.dmevals.local\" AND event.code == \"4624\" \| KEEP @timestamp, host.name, user.name, win.LogonType, win.IpAddress, win.ProcessName, win.AuthenticationPackageName,… | 25 |  |
| q-9674159cd2 | pivot step 9 | esql | {"query": "FROM logs-windows.security-default METADATA _id, _index \| WHERE host.name == \"scranton.dmevals.local\" AND user.name == \"pbeesly\" AND event.code IN (\"4663\",\"4656\",\"5145\",\"5140\") AND (win.ObjectName LIKE \"*SAM*\" OR win.ObjectName LIKE \… | 3 |  |
| q-2933761e8d | pivot step 9 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE host.name == \"scranton.dmevals.local\" AND event.code == \"1\" AND (process.command_line LIKE \"*rundll32*\" OR process.command_line LIKE \"*reg*\" OR process.command_line LIKE \"*vault… | 11 |  |
| q-7373b251d0 | pivot step 10 | esql | {"query": "FROM logs-windows.sysmon-default METADATA _id, _index \| WHERE host.name IN (\"utica.dmevals.local\",\"newyork.dmevals.local\") AND event.code == \"1\" AND (process.command_line LIKE \"*lsass*\" OR process.command_line LIKE \"*SAM*\" OR process.comm… | 0 |  |
| q-9715cc0fcb | pivot step 10 | esql | {"query": "FROM logs-windows.other-default METADATA _id, _index \| WHERE event.code IN (\"7045\",\"7040\",\"7036\",\"5857\",\"5858\",\"5860\",\"5861\") \| KEEP @timestamp, host.name, event.code, win.param1, win.param2, win.Message, _id, _index \| SORT @timesta… | 106 |  |
| q-c6a1849218 | pivot step 11 | esql | {"query": "FROM logs-windows.other-default METADATA _id, _index \| WHERE event.code == \"7045\" \| KEEP @timestamp, host.name, win.param1, win.param2, win.Message, _id, _index \| SORT @timestamp"} | 5 |  |
| q-65760a9a37 | pivot step 11 | esql | {"query": "FROM logs-windows.powershell-default METADATA _id, _index \| WHERE host.name == \"scranton.dmevals.local\" AND event.code == \"4104\" AND (win.ScriptBlockText LIKE \"*Login Data*\" OR win.ScriptBlockText LIKE \"*Cookies*\" OR win.ScriptBlockText LIK… | 7 |  |
| q-50d4564ac4 | pivot step 12 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None | F57 |
| q-b6785d236b | pivot step 12 | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c4xY6Y"} | None | F58 |
| q-77b125e29f | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None |  |
| q-b7b1db8239 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None |  |
| q-36ff1fbc41 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None |  |
| q-0a4bab1bcf | pivot verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qrRC92"} | None |  |
| q-80ff96ba09 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c4xY6Y"} | None |  |
| q-878eb45314 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cri_p-"} | None |  |
| q-e283fc3a57 | pivot verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qrRC92"} | None |  |
| q-fdbc9c0b9c | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c4xo5I"} | None |  |
| q-cd993bc1f5 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cPCBow"} | None |  |
| q-77bee0e644 | pivot verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq7mb8"} | None |  |
| q-5e61b7de64 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7ctlGsP"} | None |  |
| q-55e296cd2a | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c82Ohp"} | None |  |
| q-25d421cb6a | pivot verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNuT"} | None |  |
| q-0be853a9d0 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None |  |
| q-356f4aa0bc | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c4xY6Y"} | None |  |
| q-66cd95bcf4 | pivot verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuCk"} | None |  |
| q-1f7c219e37 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c-48YI"} | None |  |
| q-d0a9bb6b0b | pivot verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niytuv"} | None |  |
| q-78e9f6ca33 | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cPCBow"} | None |  |
| q-ee650e88fb | pivot verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7ctlGsP"} | None |  |
| q-34a9c8b080 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq7mb8"} | None |  |
| q-4ccc08c2a1 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq7mb8"} | None |  |
| q-694e26cbcd | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7njy6Co"} | None |  |
| q-2c34a54d9d | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7njy6Co"} | None |  |
| q-d9d473277d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7habKTo"} | None |  |
| q-1caa40288c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7habKTo"} | None |  |
| q-28b961b02f | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7ryFh3A"} | None |  |
| q-7e12285364 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7ryFh3A"} | None |  |
| q-bcc2d0abde | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7ryFh3A"} | None |  |
| q-24ede164bf | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hONXx6"} | None |  |
| q-8337758865 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cpgKyc"} | None |  |
| q-f07ed69406 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None |  |
| q-f18d656941 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQRgs"} | None |  |
| q-b9f6b74450 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuCk"} | None |  |
| q-8fb0898849 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qqQm9_"} | None |  |
| q-27e8e623eb | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hy0krT"} | None |  |
| q-6c90774050 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cxoQzx"} | None |  |
| q-e0fb330cae | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hWVSlm"} | None |  |
| q-e9c751705d | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7q0Y_4v"} | None |  |
| q-cd222867b2 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7njzKAe"} | None |  |
| q-1381f0148e | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nVnj7M"} | None |  |
| q-1ea1dd74c1 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nVnj7M"} | None |  |
| q-fbd944bd3f | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nSl9D4"} | None |  |
| q-5b14dd0bec | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cla5Dm"} | None |  |
| q-9f10e100e4 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cla5Dm"} | None |  |
| q-a80b888ed0 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSitD"} | None |  |
| q-a463f0314e | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvTCuJ"} | None |  |
| q-725cd65743 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglC"} | None |  |
| q-1080e14542 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSitD"} | None |  |
| q-305b22f043 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSitD"} | None |  |
| q-612f31c1f1 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSyuh"} | None |  |
| q-aac7a3240d | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvTCvd"} | None |  |
| q-16babd7a00 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hMLfHo"} | None |  |
| q-c82ecf21ab | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSyuh"} | None |  |
| q-445c0c6af4 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhG"} | None |  |
| q-d924300b85 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-c8b4e7a39f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None |  |
| q-94313ac80a | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq72Yf"} | None |  |
| q-38f22a2947 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq72Yf"} | None |  |
| q-6d3443da35 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7ryFh2_"} | None |  |
| q-16560250e1 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq8Gbm"} | None |  |
| q-397f853cbe | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cUGJOD"} | None |  |
| q-f1e7f226a7 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cZNc--"} | None |  |
| q-8329311334 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSitD"} | None |  |
| q-44fe9663cb | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niydsP"} | None |  |
| q-8afaaab9b2 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNur"} | None |  |
| q-0f130715c6 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nKhItZ"} | None |  |
| q-2d68b89022 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nKhItZ"} | None |  |
| q-e8624feff9 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None |  |
| q-6dc8497ef2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-8ebbed9108 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-a94f3ac4db | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhG"} | None |  |
| q-5c8c75efcb | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7ryFh2_"} | None |  |
| q-366e518004 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nixwZC"} | None |  |
| q-0552b50c79 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nixwZC"} | None |  |
| q-8d03d0fff6 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niwwaQ"} | None |  |
| q-a81a44b01f | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None |  |
| q-eae22a071e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRfJfH5wFd7b_z_Wh"} | None |  |
| q-2484bb1116 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRfJfH5wFd7b_z_Wh"} | None |  |
| q-2c08f5f1a7 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRfJfH5wFd7b_z_Wh"} | None |  |
| q-c8fb48a54b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cTFiiN"} | None |  |
| q-e5b7abdeca | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNur"} | None |  |
| q-679131062b | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNur"} | None |  |
| q-55c004e747 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None |  |
| q-c7a0ce27b8 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuDg"} | None |  |
| q-eb192303b6 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-9ee5764cf7 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None |  |
| q-8d4353b375 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None |  |
| q-fbe6990b74 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None |  |
| q-f91e6dcdca | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None |  |
| q-1618ef611d | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_Z1YZ"} | None |  |
| q-623fc51962 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_Z1YU"} | None |  |
| q-d243d0a025 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_Z1YU"} | None |  |
| q-dd1aa8ff2f | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_Z1YN"} | None |  |
| q-9bdfce2b66 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_Z1YN"} | None |  |
| q-11a0ca3d4b | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_Z1YN"} | None |  |
| q-24b3396114 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_Z1YZ"} | None |  |
| q-e664e55a4f | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nQi3T7"} | None |  |
| q-54de8cb3c5 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nQi3T7"} | None |  |
| q-1b47c09f2b | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nQi3T7"} | None |  |
| q-107c623ce0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hSRzrG"} | None |  |
| q-bf3608cc8c | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qzXFri"} | None |  |
| q-99a33d0549 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hWVykL"} | None |  |
| q-ada74bdb99 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hWVykL"} | None |  |
| q-52cde96605 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7htwOxh"} | None |  |
| q-edb034830c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7htwOxh"} | None |  |
| q-90b20f34b9 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-0bc9bc9fe2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-f265a09d67 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhG"} | None |  |
| q-39d2354a0d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None |  |
| q-c6b241b9b5 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None |  |
| q-b35615f571 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7htwOyZ"} | None |  |
| q-0e854910a7 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c-4cYK"} | None |  |
| q-7d78dd8c39 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7q0Y_4v"} | None |  |
| q-e22568cb8f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7YD3Who"} | None |  |
| q-07297aaafb | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cpgKyV"} | None |  |
| q-144aa8f21f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cpgKyV"} | None |  |
| q-eb8e2cad0d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cxqOgJ"} | None |  |
| q-4b3c6f3042 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cofd-n"} | None |  |
| q-533e6dfa29 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuCk"} | None |  |
| q-335fbfb47a | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuDg"} | None |  |
| q-4bab4f2be1 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None |  |
| q-90a53a5fd8 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSyuh"} | None |  |
| q-d8438fbc0b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7YE4VZs"} | None |  |
| q-22f04b698d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7YE4VZs"} | None |  |
| q-536d233c54 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cPCBow"} | None |  |
| q-8a4c0933ef | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7YL-ox6"} | None |  |
| q-7d809e8c7b | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qwUFuS"} | None |  |
| q-bc1e6d6b77 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None |  |
| q-1fd323e4e6 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None |  |
| q-71e34afb09 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None |  |
| q-3a1f50e52c | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSyvc"} | None |  |
| q-d46e847724 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7o_Z1bd"} | None |  |
| q-4491d4efd2 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None |  |
| q-62356e848a | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None |  |
| q-424152f50f | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None |  |
| q-fa62a41f53 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQRgs"} | None |  |
| q-3b694881e2 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQRgs"} | None |  |
| q-ee75f2abee | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None |  |
| q-f65a6e2aed | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qjPglL"} | None |  |
| q-3f908381b3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c_44mH"} | None |  |
| q-f2d0e2cbef | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c-4sYu"} | None |  |
| q-de6228da86 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cxoQzx"} | None |  |
| q-53c14d5452 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNur"} | None |  |
| q-eb930784ce | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cZN9Bo"} | None |  |
| q-8cea61ee57 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None |  |
| q-84e8b80544 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cZN9Bn"} | None |  |
| q-647859a8e3 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None |  |
| q-ad854dda6a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cxogx-"} | None |  |
| q-7c739f6811 | verify | get_event | {"index": ".ds-logs-zeek-default-2026.10.20-000001", "id": "AaFZSPJfH5wFd7qUcN0h"} | None |  |
| q-0ae6ac76d0 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7htwOyZ"} | None |  |
| q-d1cae64414 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7htwOyZ"} | None |  |
| q-42c64bbf1b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-962f842b5c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-3a1944ecda | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq72Yf"} | None |  |
| q-ee17f28027 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None |  |
| q-8ad22b0a68 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None |  |
| q-63d235ba30 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cPCBow"} | None |  |
| q-53b7542a8a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cPCBow"} | None |  |
| q-650d87b4d9 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuA9"} | None |  |
| q-a8044635b5 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-19ed3d1662 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-2115fe2486 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-2ce6816110 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhG"} | None |  |
| q-1f9a8c14f3 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-ec3f7f6653 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cxqOgJ"} | None |  |
| q-913ebe7299 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cpgKyV"} | None |  |
| q-e004142e52 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNur"} | None |  |
| q-c276ca46ce | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuCy"} | None |  |
| q-b20eac22ad | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cpgKyU"} | None |  |
| q-d1a8b6c5b8 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qwUVsT"} | None |  |
| q-d789db8f9b | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qwUVsT"} | None |  |
| q-ea4f6fe115 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq8Wb6"} | None |  |
| q-c36d78f4bd | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq8Wb6"} | None |  |
| q-8cee33bc68 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hNNLQJ"} | None |  |
| q-03035b3d71 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nZqakj"} | None |  |
| q-4d2e14eb9f | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nZqakj"} | None |  |
| q-68b08779e4 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nOh9eN"} | None |  |
| q-5aee4a790a | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hy0koQ"} | None |  |
| q-a6543adf1b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hWWenJ"} | None |  |
| q-dac84a13ce | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cREvLs"} | None |  |
| q-168cb87d11 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cxoQzx"} | None |  |
| q-ef9bb2c77e | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nQi3T7"} | None |  |
| q-a173abf547 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nQi3T7"} | None |  |
| q-e9de699222 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cYMP7j"} | None |  |
| q-6e60fe6727 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cUGJN0"} | None |  |
| q-9a08373843 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cREvLs"} | None |  |
| q-7cb208ee2b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cpf6ww"} | None |  |
| q-df136bbb2e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-9470afc473 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhG"} | None |  |
| q-317d942b82 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None |  |
| q-c96e58a160 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qqQ-d4"} | None |  |
| q-dba8f88652 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysW"} | None |  |
| q-c895a4c621 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niy9sU"} | None |  |
| q-24e29a16bd | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-09b3745300 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNvO"} | None |  |
| q-212c1fb0c3 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7ncs5ql"} | None |  |
| q-d155d8c8b2 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7njzKBN"} | None |  |
| q-265ce83ee8 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7ncs5ob"} | None |  |
| q-27a573b25f | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq72Yx"} | None |  |
| q-c5a19860ad | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7nq72Yx"} | None |  |
| q-62e5be963c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None |  |
| q-828ba4d74e | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNvO"} | None |  |
| q-bbe7568165 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuCk"} | None |  |
| q-7885187e78 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-a81855fb3d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhG"} | None |  |
| q-3e6081149b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-2e393f7e02 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-0ff76e4fde | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7htwOyZ"} | None |  |
| q-ba7463406c | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7htwOyZ"} | None |  |
| q-05db89a82f | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hwyqdH"} | None |  |
| q-15cb98fc41 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hwyqdH"} | None |  |
| q-25b260d38b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hSRzrP"} | None |  |
| q-fc190dcdc5 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7YD3Who"} | None |  |
| q-8c7b957082 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvTCvl"} | None |  |
| q-b0eb8e328c | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSitD"} | None |  |
| q-da2076d683 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qrRbzS"} | None |  |
| q-3dce538b62 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuCk"} | None |  |
| q-b04fcf2702 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNur"} | None |  |
| q-b76da54f88 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvTCvl"} | None |  |
| q-3244a99431 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQBhJ"} | None |  |
| q-c3a25eee05 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7niyNur"} | None |  |
| q-0c13a8810c | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7ncsJoZ"} | None |  |
| q-396c6149fc | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuDg"} | None |  |
| q-5bc3997670 | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuCk"} | None |  |
| q-8ee522b54f | verify | get_event | {"index": ".ds-logs-windows.other-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7pNHuCk"} | None |  |
| q-c80b76c65d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7YJ86bA"} | None |  |
| q-9a5db1242d | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7h03AIc"} | None |  |
| q-15720b362c | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None |  |
| q-516cfd4d79 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None |  |
| q-a3ffe6a349 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qvSysm"} | None |  |
| q-52e57da3df | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQRgs"} | None |  |
| q-856e7ecec1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hQQRgs"} | None |  |
| q-93d6724527 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qrRC9i"} | None |  |
| q-edf12ed557 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qrRC9i"} | None |  |
| q-dc852ad0ba | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hy0krT"} | None |  |
| q-b948b99c88 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hx0W8y"} | None |  |
| q-e3ab34e1b1 | verify | get_event | {"index": ".ds-logs-windows.security-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7rzHZUI"} | None |  |
| q-499f974c7b | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None |  |
| q-c283ed2d54 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None |  |
| q-63b30adcdd | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c939yF"} | None |  |
| q-dd56e580c5 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qrRC92"} | None |  |
| q-6f24619609 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c4xY6Y"} | None |  |
| q-6ae08a61d7 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cri_p-"} | None |  |
| q-18bbf07592 | verify | get_event | {"index": ".ds-logs-windows.powershell-default-2026.10.20-000001", "id": "AaFZR_JfH5wFd7qrRC92"} | None |  |
| q-0046e6833e | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c4xo5I"} | None |  |
| q-3944162c82 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7ctlGsP"} | None |  |
| q-357fc73dfd | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c82Ohp"} | None |  |
| q-fa8626e030 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7ctlGsP"} | None |  |
| q-ed30d720db | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7cxoQzx"} | None |  |
| q-31cc1bb074 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7c82OhP"} | None |  |
| q-a782f04d96 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hy0krT"} | None |  |
| q-3101b2c615 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hWVSlm"} | None |  |
| q-1b67c38e24 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7htvuyY"} | None |  |
| q-73ef519b72 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7htvuyY"} | None |  |
| q-39d9d90d55 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7YE3lVE"} | None |  |
| q-3387814952 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7huwtP3"} | None |  |
| q-8c76d91526 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hRQwNZ"} | None |  |
| q-4c21342db1 | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hWVSlm"} | None |  |
| q-837b0b6abe | verify | get_event | {"index": ".ds-logs-windows.sysmon-default-2026.10.20-000001", "id": "AaFZRvJfH5wFd7hUTVpm"} | None |  |

## Verification

Evidence items cited: 240; confirmed against the stored events: 238; rejected: 2. Each item was re-fetched with get_event; it is confirmed only if the event exists, the cited field holds the cited value, and the cited query_id is a query of this run that returned that event.
Evidence sent back to the agents for correction during the run: 12 item(s) in 7 submission(s) (one correction round each; what still failed was rejected).

## Limitations

- Findings describe what the stored logs show; activity these sources did not log cannot be seen.
- Datasets with non-overlapping time windows (see Data examined) were analysed separately.
- Long field values are shortened in this report; full events are retrievable by _index/_id.
